"""
Scan engine: orchestrates crawl -> module execution -> correlation -> storage.
Runs as an asyncio background task so the API never blocks.
"""
import asyncio
import logging
from datetime import datetime
from urllib.parse import urlparse

from app.core.config import settings
from app.database.session import SessionLocal
from app.models.scan import Scan, ScanStatus
from app.models.endpoint import Endpoint
from app.models.parameter import Parameter
from app.models.finding import Finding, Severity, Confidence
from app.models.scan_summary import ScanSummary
from app.scanner.crawler import Crawler
from app.scanner.http_client import SafeHTTPClient
from app.scanner.severity import correlate
from app.services.remediation import (
    generate_finding_fingerprint,
    correlate_scan_remediation,
    record_activity,
)
from app.scanner.scanners import (
    security_headers, cookie_security, directory_listing, sensitive_files,
    information_disclosure, csrf, xss, sql_injection, open_redirect,
)

logger = logging.getLogger("scanner.engine")

# scan_id -> asyncio.Task, used for cancellation
RUNNING_TASKS: dict[str, asyncio.Task] = {}


def _confidence_enum(value: str) -> Confidence:
    for c in Confidence:
        if c.value == value:
            return c
    return Confidence.LOW


def _severity_enum(value: str) -> Severity:
    for s in Severity:
        if s.value == value:
            return s
    return Severity.INFORMATIONAL


async def run_scan(scan_id: str) -> None:
    db = SessionLocal()
    scan = db.get(Scan, scan_id)
    if scan is None:
        db.close()
        return
    try:
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        db.commit()
        logger.info("Scan started scan_id=%s", scan_id)

        target_base = scan.target.base_url if scan.target else "target"
        record_activity(
            db,
            event_type="scan_started",
            title="Scan Started",
            description=f"Security assessment initiated for {target_base}",
            scan_id=scan.id,
            application_id=scan.application_id,
            severity="info",
            metadata={"target_url": target_base},
        )

        modules = set(scan.modules or [])
        depth = min(scan.max_depth, settings.MAX_CRAWL_DEPTH_LIMIT)
        max_urls = min(scan.max_urls, settings.MAX_URLS_LIMIT)
        delay = max(scan.request_delay, 0.0)

        # ---- Crawl ---------------------------------------------------------
        scan.current_module = "crawler"
        db.commit()

        async def on_endpoint(ep):
            scan.urls_discovered = (scan.urls_discovered or 0) + 1
            scan.parameters_found = (scan.parameters_found or 0) + len(ep.parameters)
            row = Endpoint(scan_id=scan_id, url=ep.url, method=ep.method, status_code=ep.status_code,
                           content_type=ep.content_type, redirected_to=ep.redirected_to,
                           response_headers=ep.response_headers, has_form=str(ep.has_form).lower())
            db.add(row)
            db.flush()
            for p in ep.parameters:
                db.add(Parameter(endpoint_id=row.id, name=p.name, location=p.location, sample_value=p.sample_value))
            logger.info("Endpoint discovered url=%s", ep.url)
            db.commit()

        crawler = Crawler(
            scan.target.base_url,
            depth,
            max_urls,
            delay,
            enable_browser_discovery=getattr(scan, "enable_browser_discovery", True),
        )
        endpoints = await crawler.crawl(on_endpoint_discovered=on_endpoint)
        scan.route_summary = crawler.route_metrics
        db.commit()
        logger.info(
            "Crawl finished endpoints=%d routes_discovered=%d",
            len(endpoints),
            len(crawler.route_metrics.get("routes_discovered", [])),
        )

        # ---- Modules ---------------------------------------------------------
        client = SafeHTTPClient(delay)
        all_findings = []
        per_endpoint = [m for m in ("security_headers", "cookie_security", "directory_listing",
                                    "information_disclosure", "csrf", "xss", "sql_injection", "open_redirect")
                        if m in modules]
        total_steps = max(1, len(endpoints) * len(per_endpoint) + (1 if "sensitive_files" in modules else 0))
        step = 0

        for ep in endpoints:
            for module in per_endpoint:
                scan.current_module = module
                if module == "security_headers":
                    found = security_headers.scan(ep)
                elif module == "cookie_security":
                    found = cookie_security.scan(ep)
                elif module == "directory_listing":
                    found = directory_listing.scan(ep)
                elif module == "information_disclosure":
                    found = information_disclosure.scan(ep)
                elif module == "csrf":
                    found = csrf.scan(ep, ep.html)
                elif module == "xss":
                    found = await xss.scan(ep, client)
                elif module == "sql_injection":
                    found = await sql_injection.scan(ep, client)
                else:
                    found = await open_redirect.scan(ep, client)
                if found:
                    logger.warning("Potential finding detected module=%s url=%s count=%d", module, ep.url, len(found))
                all_findings.extend(found)
                step += 1
                scan.progress_percent = round(100 * step / total_steps, 1)
                scan.findings_count = len(all_findings)
            scan.urls_scanned = (scan.urls_scanned or 0) + 1
            db.commit()
            await asyncio.sleep(0)  # yield so cancellation can be delivered

        if "sensitive_files" in modules:
            scan.current_module = "sensitive_files"
            db.commit()
            all_findings.extend(await sensitive_files.scan(scan.target.base_url, client))
        await client.close()

        # ---- Correlate + store -------------------------------------------------
        base_url = scan.target.base_url if scan.target else ""
        final = correlate(all_findings)
        counts = {s: 0 for s in Severity}
        for f in final:
            sev = _severity_enum(f.severity)
            counts[sev] += 1
            fp = generate_finding_fingerprint(
                target_url=base_url,
                finding_type=f.type,
                url=f.url,
                parameter=f.parameter,
                method=f.method,
            )
            db.add(Finding(
                scan_id=scan_id,
                type=f.type,
                category=f.category,
                owasp_category=f.owasp_category,
                url=f.url,
                method=f.method,
                parameter=f.parameter,
                severity=sev,
                confidence=_confidence_enum(f.confidence),
                evidence=f.evidence,
                description=f.description,
                impact=f.impact,
                remediation=f.remediation,
                fingerprint=fp,
                status="open",
            ))
        db.add(ScanSummary(
            scan_id=scan_id,
            total_urls=len(endpoints),
            total_endpoints=len(endpoints),
            total_parameters=scan.parameters_found or 0,
            critical_count=counts[Severity.CRITICAL],
            high_count=counts[Severity.HIGH],
            medium_count=counts[Severity.MEDIUM],
            low_count=counts[Severity.LOW],
            informational_count=counts[Severity.INFORMATIONAL],
        ))
        scan.findings_count = len(final)
        scan.progress_percent = 100.0
        scan.current_module = None
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        db.commit()

        # Run cross-scan remediation correlation
        rem_res = correlate_scan_remediation(db, scan)

        # Log activities
        record_activity(
            db,
            event_type="scan_completed",
            title="Scan Completed",
            description=f"Completed assessment for {base_url} ({len(final)} findings, {scan.urls_scanned} routes tested).",
            scan_id=scan.id,
            application_id=scan.application_id,
            severity="success",
            metadata={"findings_count": len(final), "urls_scanned": scan.urls_scanned},
        )
        if rem_res.get("new_count", 0) > 0:
            record_activity(
                db,
                event_type="vulns_detected",
                title=f"{rem_res['new_count']} New Vulnerabilities Detected",
                description=f"{rem_res['new_count']} new security findings identified in latest scan of {base_url}.",
                scan_id=scan.id,
                application_id=scan.application_id,
                severity="warning",
                metadata={"new_count": rem_res["new_count"]},
            )
        if rem_res.get("resolved_count", 0) > 0:
            record_activity(
                db,
                event_type="vuln_resolved",
                title=f"{rem_res['resolved_count']} Vulnerabilities Resolved",
                description=f"{rem_res['resolved_count']} previous findings verified resolved in {base_url}.",
                scan_id=scan.id,
                application_id=scan.application_id,
                severity="success",
                metadata={"resolved_count": rem_res["resolved_count"]},
            )
        logger.info("Scan completed scan_id=%s findings=%d", scan_id, len(final))

    except asyncio.CancelledError:
        scan.status = ScanStatus.CANCELLED
        scan.completed_at = datetime.utcnow()
        db.commit()
        record_activity(
            db,
            event_type="scan_cancelled",
            title="Scan Cancelled",
            description=f"Scan cancelled for {scan.target.base_url if scan.target else 'target'}",
            scan_id=scan.id,
            application_id=scan.application_id,
            severity="info",
        )
        logger.info("Scan cancelled scan_id=%s", scan_id)
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        scan = db.get(Scan, scan_id)
        scan.status = ScanStatus.FAILED
        scan.error_message = str(exc)[:500]
        scan.completed_at = datetime.utcnow()
        db.commit()
        record_activity(
            db,
            event_type="scan_failed",
            title="Scan Failed",
            description=f"Scan failed for {scan.target.base_url if scan.target else 'target'}: {scan.error_message}",
            scan_id=scan.id,
            application_id=scan.application_id,
            severity="critical",
            metadata={"error": scan.error_message},
        )
        logger.exception("Scan failed scan_id=%s", scan_id)
    finally:
        RUNNING_TASKS.pop(scan_id, None)
        db.close()


def start_scan_task(scan_id: str) -> None:
    task = asyncio.create_task(run_scan(scan_id))
    RUNNING_TASKS[scan_id] = task


def cancel_scan_task(scan_id: str) -> bool:
    task = RUNNING_TASKS.get(scan_id)
    if task and not task.done():
        task.cancel()
        return True
    return False
