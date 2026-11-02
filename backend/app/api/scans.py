from datetime import datetime, timedelta
import logging
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.ssrf_protection import validate_target_url, UnsafeTargetError
from app.database.session import get_db
from app.models.application import Application
from app.models.finding import Finding, Severity, Confidence
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.reports.assessment_summary import build_assessment_summary_pdf
from app.reports.bug_bounty_report import build_complete_website_bug_bounty_pdf
from app.reports.pdf_report import build_report
from app.scanner.engine import start_scan_task, cancel_scan_task
from app.schemas.scan import (
    ScanCreateRequest,
    ScanRenameRequest,
    ScanBulkActionRequest,
    ScanResponse,
    FindingResponse,
    ScanSummaryResponse,
    SecurityPostureResponse,
    ExecutiveOverviewResponse,
)
from app.scanner.severity import extract_header_name, SECURITY_HEADER_RULES, CWE_MITRE_MAP
from app.services.remediation import record_activity
from app.services.security_posture import calculate_security_posture

router = APIRouter(prefix="/api/scans", tags=["scans"])
logger = logging.getLogger("api")


def _scan_response(scan: Scan) -> ScanResponse:
    data = ScanResponse.model_validate(scan)
    data.status = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
    data.name = getattr(scan, "name", None)
    data.is_deleted = bool(getattr(scan, "is_deleted", False))
    data.deleted_at = getattr(scan, "deleted_at", None)
    if scan.target:
        data.target_url = scan.target.base_url
        data.hostname = scan.target.hostname
    if scan.application:
        data.application_name = scan.application.name
    if scan.started_at and scan.completed_at:
        data.duration_seconds = round((scan.completed_at - scan.started_at).total_seconds(), 1)
    if not data.coverage_summary and hasattr(scan, "coverage_summary"):
        data.coverage_summary = scan.coverage_summary

    findings = getattr(scan, "findings", None)
    if findings is not None:
        unique_keys = set()
        raw_total = 0
        for f in findings:
            raw_total += getattr(f, "raw_instances", 1) or 1
            if f.type == "Missing Security Header":
                hname = extract_header_name(f.parameter, f.evidence) or (f.parameter or "generic")
                unique_keys.add((f.type, hname.lower()))
            else:
                path = urlparse(f.url).path if f.url else ""
                unique_keys.add((f.type, path, (f.parameter or "").lower()))
        data.unique_findings_count = len(unique_keys) if unique_keys else (len(findings) if findings else 0)
        data.raw_occurrences_count = raw_total if raw_total > 0 else (len(findings) if findings else 0)
    else:
        data.unique_findings_count = scan.findings_count or 0
        data.raw_occurrences_count = scan.findings_count or 0

    return data


def _finding_response(f: Finding) -> FindingResponse:
    r = FindingResponse.model_validate(f)
    r.severity = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
    r.confidence = f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)
    r.status = f.status or "open"
    if not r.cwe_id or not r.mitre_attack:
        from app.scanner.severity import CWE_MITRE_MAP
        cwe, mitre = CWE_MITRE_MAP.get(r.type, ("CWE-200", "T1190"))
        r.cwe_id = r.cwe_id or cwe
        r.mitre_attack = r.mitre_attack or mitre
    if not r.detection_status:
        if "Potential" in r.type or "Heuristic" in r.type:
            r.detection_status = "Potential"
        elif r.confidence in ("Confirmed", "High confidence"):
            r.detection_status = "Confirmed"
        else:
            r.detection_status = "Requires Manual Verification"
    if not r.raw_instances:
        r.raw_instances = 1
    return r


def group_scan_findings(findings: list[Finding]) -> list[FindingResponse]:
    sev_rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
    groups: dict[str, dict] = {}

    for f in findings:
        ftype = f.type or ""
        furl = f.url or ""
        fparam = (f.parameter or "").strip().lower()
        fevid = (f.evidence or "").strip()
        parsed = urlparse(furl) if furl else None
        path = parsed.path if parsed and parsed.path else furl

        if "header" in ftype.lower():
            hname = extract_header_name(fparam, fevid) or fparam or "generic"
            key = f"header::{hname.lower()}"
        elif "cookie" in ftype.lower():
            key = f"cookie::{ftype.lower()}::{fparam}"
        elif ftype == "Technology Detection":
            key = f"tech::{fevid.lower() or fparam}"
        elif ftype in ("Exposed Sensitive File", "Sensitive File Exposure", "Directory Listing"):
            key = f"file::{ftype.lower()}::{path.lower()}"
        else:
            key = f"vuln::{ftype.lower()}::{path.lower()}::{fparam}"

        f_sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        f_conf_val = f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)

        # Standardize severity for Missing Security Header
        if "header" in ftype.lower():
            hname = extract_header_name(fparam, fevid)
            if hname and hname in SECURITY_HEADER_RULES:
                hrule_sev = SECURITY_HEADER_RULES[hname]["severity"]
                f_sev_val = hrule_sev.value if hasattr(hrule_sev, "value") else str(hrule_sev)

        inst_cnt = getattr(f, "raw_instances", 1) or 1
        existing_ev = getattr(f, "evidence_details", None) or {}
        aff_urls = existing_ev.get("affected_urls", []) if isinstance(existing_ev, dict) else []
        if furl and furl not in aff_urls:
            aff_urls.append(furl)

        occ_list = existing_ev.get("occurrences", []) if isinstance(existing_ev, dict) else []
        if not occ_list and furl:
            occ_list.append({
                "url": furl,
                "method": f.method or "GET",
                "parameter": f.parameter,
                "evidence": f.evidence,
                "severity": f_sev_val,
                "timestamp": f.timestamp.isoformat() if f.timestamp else None,
            })

        if key not in groups:
            groups[key] = {
                "representative": f,
                "type": ftype,
                "severity": f_sev_val,
                "confidence": f_conf_val,
                "parameter": (extract_header_name(fparam, fevid) if "header" in ftype.lower() else f.parameter),
                "instances": inst_cnt,
                "affected_urls": list(aff_urls),
                "occurrences": list(occ_list),
            }
        else:
            g = groups[key]
            g["instances"] += inst_cnt
            for u in aff_urls:
                if u not in g["affected_urls"]:
                    g["affected_urls"].append(u)
            for occ in occ_list:
                g["occurrences"].append(occ)

            if sev_rank.get(f_sev_val, 0) > sev_rank.get(g["severity"], 0):
                g["severity"] = f_sev_val
                g["representative"] = f
            elif sev_rank.get(f_sev_val, 0) == sev_rank.get(g["severity"], 0):
                if f_conf_val in ("Confirmed", "High confidence") and g["confidence"] not in ("Confirmed", "High confidence"):
                    g["confidence"] = f_conf_val
                    g["representative"] = f

    results: list[FindingResponse] = []
    for g in groups.values():
        rep = g["representative"]
        r = _finding_response(rep)
        r.severity = g["severity"]
        r.confidence = g["confidence"]
        if g.get("parameter"):
            r.parameter = g["parameter"]
        r.raw_instances = g["instances"]

        r.evidence_details = {
            "affected_urls": g["affected_urls"],
            "total_affected_endpoints": len(g["affected_urls"]),
            "occurrences": g["occurrences"][:50],
        }
        if "header" in r.type.lower():
            r.evidence_details["header_name"] = r.parameter
            if r.parameter in SECURITY_HEADER_RULES:
                rule = SECURITY_HEADER_RULES[r.parameter]
                r.cwe_id = rule.get("cwe_id", r.cwe_id)
                r.mitre_attack = rule.get("mitre_attack", r.mitre_attack)

        results.append(r)

    results.sort(key=lambda x: (sev_rank.get(x.severity, 0), x.raw_instances or 1), reverse=True)
    return results


def _get_scan(db: Session, scan_id: str, allow_deleted: bool = False) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if not allow_deleted and getattr(scan, "is_deleted", False):
        raise HTTPException(404, "Scan not found or has been moved to Trash")
    return scan


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(req: ScanCreateRequest, db: Session = Depends(get_db)):
    try:
        url = validate_target_url(req.target_url)
    except UnsafeTargetError as exc:
        raise HTTPException(400, str(exc))
    logger.info("Target validated host=%s", urlparse(url).hostname)

    if req.max_depth < 0 or req.max_urls < 1 or req.request_delay < 0:
        raise HTTPException(422, "Invalid crawl limits")

    # Associate with Application
    app = None
    if req.application_id:
        app = db.get(Application, req.application_id)
    elif req.application_name and req.application_name.strip():
        app_name = req.application_name.strip()
        app = db.query(Application).filter(Application.name == app_name).first()
        if not app:
            app = Application(name=app_name, description=f"Monitored application for {url}")
            db.add(app)
            db.flush()
    else:
        # Default application based on netloc (hostname + port)
        parsed_u = urlparse(url)
        default_name = parsed_u.netloc or parsed_u.hostname
        app = db.query(Application).filter(Application.name == default_name).first()
        if not app:
            app = Application(name=default_name, description=f"Monitored application for {url}")
            db.add(app)
            db.flush()

    target = Target(
        base_url=url,
        hostname=urlparse(url).hostname,
        authorization_confirmed=True,
        application_id=app.id if app else None,
        name=app.name if app else None,
    )
    db.add(target)
    db.flush()
    scan = Scan(
        target_id=target.id,
        application_id=app.id if app else None,
        max_depth=req.max_depth,
        max_urls=req.max_urls,
        request_delay=req.request_delay,
        modules=req.modules,
        enable_browser_discovery=req.enable_browser_discovery,
        auth_config=req.auth_config,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    start_scan_task(scan.id)
    return _scan_response(scan)


@router.get("", response_model=list[ScanResponse])
def list_scans(trash_only: bool = False, include_deleted: bool = False, db: Session = Depends(get_db)):
    q = db.query(Scan)
    if trash_only:
        q = q.filter(Scan.is_deleted == True)
    elif not include_deleted:
        q = q.filter((Scan.is_deleted == False) | (Scan.is_deleted == None))
    return [_scan_response(s) for s in q.order_by(Scan.created_at.desc()).all()]


@router.post("/bulk/delete")
def bulk_delete_scans(req: ScanBulkActionRequest, db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.id.in_(req.scan_ids)).all()
    deleted_ids = []
    now = datetime.utcnow()
    for s in scans:
        if s.status == ScanStatus.RUNNING:
            continue
        s.is_deleted = True
        s.deleted_at = now
        deleted_ids.append(s.id)
    db.commit()
    return {"status": "success", "count": len(deleted_ids), "deleted_ids": deleted_ids}


@router.post("/bulk/restore")
def bulk_restore_scans(req: ScanBulkActionRequest, db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.id.in_(req.scan_ids)).all()
    restored_ids = []
    for s in scans:
        if getattr(s, "is_deleted", False):
            s.is_deleted = False
            s.deleted_at = None
            restored_ids.append(s.id)
    db.commit()
    return {"status": "success", "count": len(restored_ids), "restored_ids": restored_ids}


@router.post("/bulk/permanent")
def bulk_permanent_delete_scans(req: ScanBulkActionRequest, db: Session = Depends(get_db)):
    from app.models.activity import Activity
    scans = db.query(Scan).filter(Scan.id.in_(req.scan_ids), Scan.is_deleted == True).all()
    purged_ids = []
    try:
        for s in scans:
            if s.status == ScanStatus.RUNNING:
                continue
            db.query(Activity).filter(Activity.scan_id == s.id).delete(synchronize_session=False)
            db.delete(s)
            purged_ids.append(s.id)
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.exception("Bulk permanent delete failed: %s", exc)
        raise HTTPException(500, f"Bulk permanent delete failed: {str(exc)}")
    return {"status": "success", "count": len(purged_ids), "purged_ids": purged_ids}


@router.get("/stats/executive", response_model=ExecutiveOverviewResponse)
def executive_stats(db: Session = Depends(get_db)):
    from app.api.applications import auto_sync_unassigned_scans
    auto_sync_unassigned_scans(db)

    apps = db.query(Application).all()
    all_scans = db.query(Scan).filter((Scan.is_deleted == False) | (Scan.is_deleted == None)).all()

    total_monitored_websites = len(apps)
    total_scans = len(all_scans)

    scores = []
    websites_with_high_risk = 0
    routes_discovered_total = 0
    routes_tested_total = 0
    routes_auth_total = 0
    routes_failed_total = 0

    cutoff_7d = datetime.utcnow() - timedelta(days=7)
    recently_completed_scans = 0

    for s in all_scans:
        if s.status == ScanStatus.COMPLETED and s.completed_at and s.completed_at >= cutoff_7d:
            recently_completed_scans += 1

    for app in apps:
        latest_scan = (
            db.query(Scan)
            .filter(
                Scan.application_id == app.id,
                Scan.status == ScanStatus.COMPLETED,
                (Scan.is_deleted == False) | (Scan.is_deleted == None),
            )
            .order_by(Scan.created_at.desc())
            .first()
        )
        if latest_scan:
            findings = db.query(Finding).filter(Finding.scan_id == latest_scan.id).all()
            posture = calculate_security_posture(latest_scan, findings)
            scores.append(posture["score"])

            has_high = any(
                (f.severity in (Severity.CRITICAL, Severity.HIGH))
                and (f.status in ("open", "reopened", None))
                for f in findings
            )
            if has_high:
                websites_with_high_risk += 1

            routes_discovered_total += latest_scan.urls_discovered or 0
            routes_tested_total += latest_scan.urls_scanned or 0
            route_sum = latest_scan.route_summary or {}
            if isinstance(route_sum, dict):
                routes_auth = route_sum.get("routes_auth_required", [])
                routes_failed = route_sum.get("routes_failed", [])
                routes_auth_total += len(routes_auth) if isinstance(routes_auth, list) else 0
                routes_failed_total += len(routes_failed) if isinstance(routes_failed, list) else 0

    avg_score = round(sum(scores) / len(scores), 1) if scores else 100.0

    open_high_critical_count = (
        db.query(Finding)
        .filter(
            Finding.severity.in_([Severity.CRITICAL, Severity.HIGH]),
            Finding.status.in_(["open", "reopened"]),
        )
        .count()
    )

    by_sev = {s.value: 0 for s in Severity}
    for sev, n in (
        db.query(Finding.severity, func.count())
        .filter(Finding.status.in_(["open", "reopened"]))
        .group_by(Finding.severity)
        .all()
    ):
        by_sev[sev.value] = n

    by_type = dict(
        db.query(Finding.type, func.count())
        .filter(Finding.status.in_(["open", "reopened"]))
        .group_by(Finding.type)
        .all()
    )

    cov_pct = 0.0
    if routes_discovered_total > 0:
        cov_pct = round((routes_tested_total / routes_discovered_total) * 100, 1)
    elif routes_tested_total > 0:
        cov_pct = 100.0

    coverage_overview = {
        "total_routes_discovered": routes_discovered_total,
        "total_routes_tested": routes_tested_total,
        "routes_auth_required": routes_auth_total,
        "routes_failed": routes_failed_total,
        "coverage_percentage": cov_pct,
    }

    return ExecutiveOverviewResponse(
        total_monitored_websites=total_monitored_websites,
        total_scans=total_scans,
        average_security_score=avg_score,
        websites_with_high_risk=websites_with_high_risk,
        open_high_critical_count=open_high_critical_count,
        recently_completed_scans=recently_completed_scans,
        by_severity=by_sev,
        by_type=by_type,
        coverage_overview=coverage_overview,
    )


@router.get("/stats/overview")
def overview(db: Session = Depends(get_db)):
    active_filter = (Scan.is_deleted == False) | (Scan.is_deleted == None)
    by_sev = {s.value: 0 for s in Severity}
    for sev, n in (
        db.query(Finding.severity, func.count())
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(active_filter)
        .group_by(Finding.severity)
        .all()
    ):
        by_sev[sev.value] = n
    by_type = dict(
        db.query(Finding.type, func.count())
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(active_filter)
        .group_by(Finding.type)
        .all()
    )
    return {
        "total_scans": db.query(Scan).filter(active_filter).count(),
        "urls_scanned": db.query(func.coalesce(func.sum(Scan.urls_scanned), 0)).filter(active_filter).scalar(),
        "endpoints_found": db.query(func.coalesce(func.sum(Scan.urls_discovered), 0)).filter(active_filter).scalar(),
        "by_severity": by_sev,
        "by_type": by_type,
    }


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    return _scan_response(_get_scan(db, scan_id))


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
def get_findings(scan_id: str, severity: str | None = None, confidence: str | None = None,
                 type: str | None = None, url: str | None = None, db: Session = Depends(get_db)):
    _get_scan(db, scan_id)
    raw_findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    grouped = group_scan_findings(raw_findings)

    if severity:
        grouped = [f for f in grouped if f.severity.lower() == severity.lower()]
    if confidence:
        grouped = [f for f in grouped if f.confidence.lower() == confidence.lower()]
    if type:
        grouped = [f for f in grouped if f.type == type]
    if url:
        u_lower = url.lower()
        grouped = [
            f for f in grouped
            if u_lower in (f.url or "").lower() or any(
                u_lower in aff.lower() for aff in (f.evidence_details.get("affected_urls") or [])
            )
        ]
    return grouped


@router.get("/{scan_id}/summary", response_model=ScanSummaryResponse)
def get_summary(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id)
    if not scan.summary:
        raise HTTPException(404, "Summary not available yet")
    return scan.summary


@router.get("/{scan_id}/security-posture", response_model=SecurityPostureResponse)
def get_security_posture(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id)
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return calculate_security_posture(scan, findings)



@router.post("/{scan_id}/cancel")
def cancel(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id)
    if scan.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(409, "Scan is not running")
    cancel_scan_task(scan_id)
    return {"status": "cancelling"}


@router.patch("/{scan_id}", response_model=ScanResponse)
def rename_scan(scan_id: str, req: ScanRenameRequest, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id, allow_deleted=True)
    scan.name = req.name.strip()
    db.commit()
    db.refresh(scan)
    return _scan_response(scan)


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id, allow_deleted=False)
    if scan.status == ScanStatus.RUNNING:
        raise HTTPException(400, "Cannot delete an actively running scan. Stop or cancel the scan first.")
    scan.is_deleted = True
    scan.deleted_at = datetime.utcnow()
    db.commit()
    target_base = scan.target.base_url if scan.target else "target"
    record_activity(
        db,
        event_type="scan_deleted",
        title="Scan Moved to Trash",
        description=f"Scan {scan.id[:8]} for {target_base} moved to Trash.",
        scan_id=scan.id,
        application_id=scan.application_id,
        severity="info",
    )
    return {"status": "deleted", "scan_id": scan_id, "is_deleted": True}


@router.post("/{scan_id}/restore", response_model=ScanResponse)
def restore_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id, allow_deleted=True)
    if not getattr(scan, "is_deleted", False):
        raise HTTPException(400, "Scan is not in Trash.")
    scan.is_deleted = False
    scan.deleted_at = None
    db.commit()
    db.refresh(scan)
    target_base = scan.target.base_url if scan.target else "target"
    record_activity(
        db,
        event_type="scan_restored",
        title="Scan Restored",
        description=f"Scan {scan.id[:8]} for {target_base} restored from Trash.",
        scan_id=scan.id,
        application_id=scan.application_id,
        severity="info",
    )
    return _scan_response(scan)


@router.delete("/{scan_id}/permanent")
def permanent_delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id, allow_deleted=True)
    if scan.status == ScanStatus.RUNNING:
        raise HTTPException(400, "Cannot permanently delete an actively running scan.")
    if not getattr(scan, "is_deleted", False):
        raise HTTPException(400, "Scan must be moved to Trash before permanent deletion.")
    try:
        from app.models.activity import Activity
        db.query(Activity).filter(Activity.scan_id == scan_id).delete(synchronize_session=False)
        db.delete(scan)
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.exception("Failed to permanently delete scan %s: %s", scan_id, exc)
        raise HTTPException(500, f"Failed to permanently delete scan: {str(exc)}")
    return {"status": "permanently_deleted", "scan_id": scan_id}


@router.get("/{scan_id}/report")
def report(scan_id: str, type: str = "summary", db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id)
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(409, "Report is only available for completed scans")

    target_base = scan.target.base_url if scan.target else "target"
    safe_host = "".join(c if c.isalnum() else "-" for c in (urlparse(target_base).hostname or "site")).strip("-")
    report_type = (type or "summary").lower().strip()

    if report_type in ("bug-bounty", "bounty"):
        pdf = build_complete_website_bug_bounty_pdf(scan, scan.findings, scan.summary)
        filename = f"bug-bounty-{safe_host}-{scan_id[:8]}.pdf"
        desc = f"Complete website bug bounty report downloaded for {target_base}."
    elif report_type == "full":
        pdf = build_report(scan, scan.findings, scan.summary)
        filename = f"scan-{scan_id[:8]}-full.pdf"
        desc = f"Full technical security assessment report downloaded for {target_base}."
    else:
        pdf = build_assessment_summary_pdf(scan, scan.findings, scan.summary)
        filename = f"scan-{scan_id[:8]}-summary.pdf"
        desc = f"Security assessment summary report downloaded for {target_base}."

    record_activity(
        db,
        event_type="report_generated",
        title="PDF Report Generated",
        description=desc,
        scan_id=scan.id,
        application_id=scan.application_id,
        severity="info",
        metadata={"target_url": target_base, "findings_count": scan.findings_count, "report_type": report_type},
    )

    return Response(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/{scan_id}/report/bug-bounty")
def report_bug_bounty(scan_id: str, db: Session = Depends(get_db)):
    return report(scan_id, type="bug-bounty", db=db)


@router.get("/{scan_id}/report/summary")
def report_summary(scan_id: str, db: Session = Depends(get_db)):
    return report(scan_id, type="summary", db=db)


@router.get("/{scan_id}/report/full")
def report_full(scan_id: str, db: Session = Depends(get_db)):
    return report(scan_id, type="full", db=db)
