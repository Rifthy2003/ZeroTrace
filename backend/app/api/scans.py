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
from app.reports.pdf_report import build_report
from app.scanner.engine import start_scan_task, cancel_scan_task
from app.schemas.scan import (
    ScanCreateRequest,
    ScanResponse,
    FindingResponse,
    ScanSummaryResponse,
    SecurityPostureResponse,
    ExecutiveOverviewResponse,
)
from app.services.remediation import record_activity
from app.services.security_posture import calculate_security_posture

router = APIRouter(prefix="/api/scans", tags=["scans"])
logger = logging.getLogger("api")


def _scan_response(scan: Scan) -> ScanResponse:
    data = ScanResponse.model_validate(scan)
    data.status = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
    if scan.target:
        data.target_url = scan.target.base_url
        data.hostname = scan.target.hostname
    if scan.application:
        data.application_name = scan.application.name
    if scan.started_at and scan.completed_at:
        data.duration_seconds = round((scan.completed_at - scan.started_at).total_seconds(), 1)
    if not data.coverage_summary and hasattr(scan, "coverage_summary"):
        data.coverage_summary = scan.coverage_summary
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


def _get_scan(db: Session, scan_id: str) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
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
def list_scans(db: Session = Depends(get_db)):
    return [_scan_response(s) for s in db.query(Scan).order_by(Scan.created_at.desc()).all()]


@router.get("/stats/executive", response_model=ExecutiveOverviewResponse)
def executive_stats(db: Session = Depends(get_db)):
    from app.api.applications import auto_sync_unassigned_scans
    auto_sync_unassigned_scans(db)

    apps = db.query(Application).all()
    all_scans = db.query(Scan).all()

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
            .filter(Scan.application_id == app.id, Scan.status == ScanStatus.COMPLETED)
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
    by_sev = {s.value: 0 for s in Severity}
    for sev, n in db.query(Finding.severity, func.count()).group_by(Finding.severity).all():
        by_sev[sev.value] = n
    by_type = dict(db.query(Finding.type, func.count()).group_by(Finding.type).all())
    return {"total_scans": db.query(Scan).count(),
            "urls_scanned": db.query(func.coalesce(func.sum(Scan.urls_scanned), 0)).scalar(),
            "endpoints_found": db.query(func.coalesce(func.sum(Scan.urls_discovered), 0)).scalar(),
            "by_severity": by_sev, "by_type": by_type}


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    return _scan_response(_get_scan(db, scan_id))


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
def get_findings(scan_id: str, severity: str | None = None, confidence: str | None = None,
                 type: str | None = None, url: str | None = None, db: Session = Depends(get_db)):
    _get_scan(db, scan_id)
    q = db.query(Finding).filter(Finding.scan_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == Severity(severity))
    if confidence:
        q = q.filter(Finding.confidence == Confidence(confidence))
    if type:
        q = q.filter(Finding.type == type)
    if url:
        q = q.filter(Finding.url.contains(url))
    return [_finding_response(f) for f in q.all()]


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


@router.get("/{scan_id}/report")
def report(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id)
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(409, "Report is only available for completed scans")
    pdf = build_report(scan, scan.findings, scan.summary)

    target_base = scan.target.base_url if scan.target else "target"
    record_activity(
        db,
        event_type="report_generated",
        title="PDF Report Generated",
        description=f"Security assessment report downloaded for {target_base}.",
        scan_id=scan.id,
        application_id=scan.application_id,
        severity="info",
        metadata={"target_url": target_base, "findings_count": scan.findings_count},
    )

    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=scan-{scan_id[:8]}.pdf"})
