"""
Scan engine: orchestrates crawl -> module execution -> correlation -> storage.
Runs as an asyncio background task so the API never blocks.
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Any, Set
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
    security_headers,
    cookie_security,
    directory_listing,
    sensitive_files,
    information_disclosure,
    csrf,
    xss,
    sql_injection,
    open_redirect,
    command_injection,
    ssti,
    path_traversal,
    cors,
    clickjacking,
    auth_security,
    graphql,
)

logger = logging.getLogger("scanner.engine")

# scan_id -> asyncio.Task, used for cancellation
RUNNING_TASKS: dict[str, asyncio.Task] = {}

ALL_KNOWN_MODULES = [
    "sql_injection",
    "xss",
    "csrf",
    "security_headers",
    "cookie_security",
    "directory_listing",
    "sensitive_files",
    "open_redirect",
    "information_disclosure",
    "command_injection",
    "ssti",
    "path_traversal",
    "cors",
    "clickjacking",
    "auth_security",
    "graphql",
]

INPUT_DEPENDENT_MODULES = {
    "sql_injection",
    "xss",
    "command_injection",
    "ssti",
    "path_traversal",
}

MODULE_DISPLAY_NAMES = {
    "sql_injection": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "csrf": "Cross-Site Request Forgery (CSRF)",
    "security_headers": "Security Headers",
    "cookie_security": "Cookie Security",
    "directory_listing": "Directory Listing",
    "sensitive_files": "Sensitive Files & Secrets",
    "open_redirect": "Open Redirect",
    "information_disclosure": "Information Disclosure",
    "command_injection": "Command Injection",
    "ssti": "Server-Side Template Injection (SSTI)",
    "path_traversal": "Path Traversal",
    "cors": "CORS Misconfiguration",
    "clickjacking": "Clickjacking Protection",
    "auth_security": "Authentication & Access Security",
    "graphql": "GraphQL Security",
}


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

        modules = set(scan.modules or ALL_KNOWN_MODULES)
        depth = min(scan.max_depth, settings.MAX_CRAWL_DEPTH_LIMIT)
        max_urls = min(scan.max_urls, settings.MAX_URLS_LIMIT)
        delay = max(scan.request_delay, 0.0)

        # Execution Audit Log
        execution_logs: List[Dict[str, Any]] = []

        # ---- Crawl ---------------------------------------------------------
        scan.current_module = "crawler"
        db.commit()

        async def on_endpoint(ep):
            scan.urls_discovered = (scan.urls_discovered or 0) + 1
            scan.parameters_found = (scan.parameters_found or 0) + len(ep.parameters)
            row = Endpoint(
                scan_id=scan_id,
                url=ep.url,
                method=ep.method,
                status_code=ep.status_code,
                content_type=ep.content_type,
                redirected_to=ep.redirected_to,
                response_headers=ep.response_headers,
                has_form=str(ep.has_form).lower(),
            )
            db.add(row)
            db.flush()
            for p in ep.parameters:
                db.add(Parameter(endpoint_id=row.id, name=p.name, location=p.location, sample_value=p.sample_value))
                execution_logs.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "event": "parameter_discovered",
                    "url": ep.url,
                    "method": ep.method,
                    "parameter": p.name,
                    "location": p.location,
                    "sample_value": (p.sample_value or "")[:30],
                })

            execution_logs.append({
                "timestamp": datetime.utcnow().isoformat(),
                "event": "url_discovered",
                "url": ep.url,
                "method": ep.method,
                "status_code": ep.status_code,
                "content_type": ep.content_type,
                "has_form": ep.has_form,
                "params_count": len(ep.parameters),
            })
            if ep.has_form:
                execution_logs.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "event": "form_discovered",
                    "url": ep.url,
                    "method": ep.method,
                    "form_parameters": [p.name for p in ep.parameters if p.location in ("form", "body")],
                })
            logger.info("Endpoint discovered url=%s method=%s params=%d", ep.url, ep.method, len(ep.parameters))
            db.commit()

        auth_cfg = getattr(scan, "auth_config", None) or {}
        crawler = Crawler(
            scan.target.base_url,
            depth,
            max_urls,
            delay,
            enable_browser_discovery=getattr(scan, "enable_browser_discovery", True),
            auth_config=auth_cfg,
        )
        endpoints = await crawler.crawl(on_endpoint_discovered=on_endpoint)
        scan.route_summary = crawler.route_metrics
        db.commit()

        forms_cnt = crawler.route_metrics.get("forms_discovered", 0)
        params_discovered_cnt = sum(len(e.parameters) for e in endpoints)
        scan.parameters_found = params_discovered_cnt

        logger.info(
            "Crawl finished endpoints=%d routes_discovered=%d forms_discovered=%d parameters_discovered=%d",
            len(endpoints),
            len(crawler.route_metrics.get("routes_discovered", [])),
            forms_cnt,
            params_discovered_cnt,
        )

        # ---- Module Execution Tracking ---------------------------------------
        module_findings_count: Dict[str, int] = {m: 0 for m in ALL_KNOWN_MODULES}
        module_tested_endpoints: Dict[str, int] = {m: 0 for m in ALL_KNOWN_MODULES}
        module_parameters_tested: Dict[str, int] = {m: 0 for m in ALL_KNOWN_MODULES}
        tested_param_keys: Set[str] = set()

        client_headers = auth_cfg.get("headers") if isinstance(auth_cfg, dict) else None
        client_cookies = auth_cfg.get("cookies") if isinstance(auth_cfg, dict) else None
        client = SafeHTTPClient(delay, headers=client_headers, cookies=client_cookies)
        all_findings = []

        per_endpoint_modules = [
            m for m in (
                "security_headers",
                "cookie_security",
                "directory_listing",
                "information_disclosure",
                "csrf",
                "xss",
                "sql_injection",
                "open_redirect",
                "command_injection",
                "ssti",
                "path_traversal",
                "cors",
                "clickjacking",
                "auth_security",
            )
            if m in modules
        ]

        total_steps = max(
            1,
            len(endpoints) * len(per_endpoint_modules)
            + (1 if "sensitive_files" in modules else 0)
            + (1 if "graphql" in modules else 0),
        )
        step = 0

        # ---- Run Per-Endpoint Modules ---------------------------------------
        for ep in endpoints:
            is_auth_required = (
                ep.status_code in (401, 403)
                or ep.response_headers.get("x-zerotrace-auth-status") == "protected"
            )

            # Extract testable parameters for input-dependent modules
            testable_params = [
                p for p in ep.parameters
                if p.name and p.name.lower() not in {"csrf", "token", "_csrf", "_token"}
            ]

            for module in per_endpoint_modules:
                scan.current_module = module
                found = []

                # Check if module requires input parameters
                if module in INPUT_DEPENDENT_MODULES:
                    if is_auth_required:
                        execution_logs.append({
                            "timestamp": datetime.utcnow().isoformat(),
                            "event": "module_skipped",
                            "module": module,
                            "url": ep.url,
                            "reason": "Authentication required (HTTP 401/403 or protected route)",
                        })
                        step += 1
                        continue

                    if not testable_params:
                        execution_logs.append({
                            "timestamp": datetime.utcnow().isoformat(),
                            "event": "module_skipped",
                            "module": module,
                            "url": ep.url,
                            "reason": "No testable input parameters discovered on endpoint",
                        })
                        step += 1
                        continue

                    # Execute input module
                    module_tested_endpoints[module] += 1
                    module_parameters_tested[module] += len(testable_params)
                    for p in testable_params:
                        param_key = f"{ep.method}:{ep.url}:{p.name}:{p.location}"
                        tested_param_keys.add(param_key)

                    if module == "sql_injection":
                        found = await sql_injection.scan(ep, client)
                    elif module == "xss":
                        found = await xss.scan(ep, client)
                    elif module == "command_injection":
                        found = await command_injection.scan(ep, client)
                    elif module == "ssti":
                        found = await ssti.scan(ep, client)
                    elif module == "path_traversal":
                        found = await path_traversal.scan(ep, client)

                    # Log parameter testing results
                    for p in testable_params:
                        p_findings = [f for f in found if f.parameter == p.name]
                        execution_logs.append({
                            "timestamp": datetime.utcnow().isoformat(),
                            "event": "parameter_tested",
                            "module": module,
                            "url": ep.url,
                            "method": ep.method,
                            "parameter": p.name,
                            "location": p.location,
                            "result": f"Finding detected: {p_findings[0].type} ({p_findings[0].severity})" if p_findings else "Safe (No indicators observed)",
                        })

                else:
                    # Non-input dependent endpoint modules
                    module_tested_endpoints[module] += 1

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
                    elif module == "open_redirect":
                        found = await open_redirect.scan(ep, client)
                    elif module == "cors":
                        found = await cors.scan(ep, client)
                    elif module == "clickjacking":
                        found = clickjacking.scan(ep)
                    elif module == "auth_security":
                        found = auth_security.scan(ep)

                    execution_logs.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "event": "endpoint_tested",
                        "module": module,
                        "url": ep.url,
                        "method": ep.method,
                        "result": f"{len(found)} finding(s)" if found else "Clean",
                    })

                if found:
                    module_findings_count[module] += len(found)
                    logger.warning("Finding detected module=%s url=%s count=%d", module, ep.url, len(found))
                    all_findings.extend(found)

                step += 1
                scan.progress_percent = round(100 * step / total_steps, 1)
                scan.findings_count = len(all_findings)

            scan.urls_scanned = (scan.urls_scanned or 0) + 1
            db.commit()
            await asyncio.sleep(0)  # yield for cancellation

        # ---- Target-Level Modules -------------------------------------------
        if "sensitive_files" in modules:
            scan.current_module = "sensitive_files"
            module_tested_endpoints["sensitive_files"] = len(endpoints)
            db.commit()
            s_found = await sensitive_files.scan(scan.target.base_url, client)
            if s_found:
                module_findings_count["sensitive_files"] += len(s_found)
                all_findings.extend(s_found)
            execution_logs.append({
                "timestamp": datetime.utcnow().isoformat(),
                "event": "target_module_tested",
                "module": "sensitive_files",
                "url": scan.target.base_url,
                "result": f"{len(s_found)} sensitive file finding(s)" if s_found else "No exposed files found",
            })

        is_graphql_applicable = False
        if "graphql" in modules:
            scan.current_module = "graphql"
            db.commit()
            g_found, is_graphql_applicable = await graphql.scan(scan.target.base_url, client)
            if is_graphql_applicable:
                module_tested_endpoints["graphql"] = 3
                if g_found:
                    module_findings_count["graphql"] += len(g_found)
                    all_findings.extend(g_found)
                execution_logs.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "event": "target_module_tested",
                    "module": "graphql",
                    "url": scan.target.base_url,
                    "result": f"{len(g_found)} GraphQL issue(s)" if g_found else "GraphQL tested",
                })
            else:
                module_tested_endpoints["graphql"] = 0
                execution_logs.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "event": "target_module_skipped",
                    "module": "graphql",
                    "url": scan.target.base_url,
                    "reason": "No GraphQL endpoints found on target (Not Applicable)",
                })

        await client.close()

        # ---- Build Accurate Coverage Matrix ---------------------------------
        total_unique_params_tested = len(tested_param_keys)
        module_matrix = []

        for m in ALL_KNOWN_MODULES:
            name = MODULE_DISPLAY_NAMES.get(m, m.replace("_", " ").title())
            f_count = module_findings_count.get(m, 0)
            ep_tested = module_tested_endpoints.get(m, 0)
            param_tested = module_parameters_tested.get(m, 0)

            if m not in modules:
                status = "Not Tested"
                reason = "Module not selected in scan configuration"
            elif m == "graphql":
                if is_graphql_applicable:
                    status = "Tested"
                    reason = f"Tested GraphQL introspection across {ep_tested} endpoints"
                else:
                    status = "Not Applicable"
                    reason = "No GraphQL endpoint discovered on target"
            elif m in INPUT_DEPENDENT_MODULES:
                if param_tested > 0:
                    status = "Tested"
                    reason = f"Tested {param_tested} parameter(s) across {ep_tested} endpoint(s)"
                else:
                    status = "Incomplete"
                    reason = "No eligible input parameters discovered on crawled pages"
            else:
                if ep_tested > 0:
                    status = "Tested"
                    reason = f"Tested across {ep_tested} endpoint(s)"
                else:
                    status = "Not Tested"
                    reason = "No applicable endpoints tested"

            module_matrix.append({
                "module": m,
                "name": name,
                "status": status,
                "findings_count": f_count,
                "endpoints_tested": ep_tested,
                "parameters_tested": param_tested,
                "reason": reason,
            })

        tested_cnt = sum(1 for item in module_matrix if item["status"] == "Tested")
        incomplete_cnt = sum(1 for item in module_matrix if item["status"] == "Incomplete")
        not_tested_cnt = sum(1 for item in module_matrix if item["status"] == "Not Tested")
        na_cnt = sum(1 for item in module_matrix if item["status"] == "Not Applicable")
        applicable_total = max(1, len(module_matrix) - na_cnt)
        coverage_pct = round(100.0 * tested_cnt / applicable_total, 1)

        scan.coverage_summary = {
            "modules_total": len(module_matrix),
            "modules_tested": tested_cnt,
            "modules_incomplete": incomplete_cnt,
            "modules_not_tested": not_tested_cnt,
            "modules_not_applicable": na_cnt,
            "endpoints_discovered": len(endpoints),
            "endpoints_tested": scan.urls_scanned or len(endpoints),
            "forms_discovered": forms_cnt,
            "parameters_discovered": params_discovered_cnt,
            "parameters_tested": total_unique_params_tested,
            "coverage_percentage": coverage_pct,
            "module_matrix": module_matrix,
            "execution_logs": execution_logs[-100:],  # preserve latest 100 execution audit records
        }

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
                cwe_id=f.cwe_id,
                mitre_attack=f.mitre_attack,
                detection_status=f.detection_status or "Confirmed",
                raw_instances=getattr(f, "raw_instances", 1) or 1,
                evidence_details=getattr(f, "evidence_details", {}) or {},
            ))

        db.add(ScanSummary(
            scan_id=scan_id,
            total_urls=len(endpoints),
            total_endpoints=len(endpoints),
            total_parameters=params_discovered_cnt,
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
            description=f"Completed assessment for {base_url} ({len(final)} unique findings, {scan.urls_scanned} routes tested, {total_unique_params_tested} parameters tested).",
            scan_id=scan.id,
            application_id=scan.application_id,
            severity="success",
            metadata={"findings_count": len(final), "urls_scanned": scan.urls_scanned, "params_tested": total_unique_params_tested},
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

        logger.info(
            "Scan completed successfully scan_id=%s unique_findings=%d params_tested=%d",
            scan_id,
            len(final),
            total_unique_params_tested,
        )

    except asyncio.CancelledError:
        logger.info("Scan cancelled scan_id=%s", scan_id)
        scan.status = ScanStatus.CANCELLED
        scan.completed_at = datetime.utcnow()
        db.commit()
    except Exception as exc:
        logger.exception("Scan failed scan_id=%s err=%s", scan_id, exc)
        scan.status = ScanStatus.FAILED
        scan.error_message = str(exc)[:500]
        scan.completed_at = datetime.utcnow()
        db.commit()
        if scan.target:
            record_activity(
                db,
                event_type="scan_failed",
                title="Scan Failed",
                description=f"Assessment failed for {scan.target.base_url}: {str(exc)[:120]}",
                scan_id=scan.id,
                application_id=scan.application_id,
                severity="danger",
                metadata={"error": str(exc)[:300]},
            )
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
