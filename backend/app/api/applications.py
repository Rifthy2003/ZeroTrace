"""
Application and Website Management API router for ZeroTrace.
"""
import logging
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.application import Application
from app.models.finding import Finding, Severity
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.scanner.engine import start_scan_task
from app.schemas.scan import (
    ApplicationCreateRequest,
    ApplicationResponse,
    ApplicationTrendResponse,
    ApplicationUpdateRequest,
    HistoryPointResponse,
    ScanResponse,
)
from app.services.remediation import (
    correlate_scan_remediation,
    generate_finding_fingerprint,
    record_activity,
)
from app.services.security_posture import calculate_security_posture

router = APIRouter(prefix="/api/applications", tags=["applications"])
logger = logging.getLogger("api.applications")


def _build_app_response(app: Application, db: Session) -> ApplicationResponse:
    # Find non-deleted scans for this application
    scans = (
        db.query(Scan)
        .filter(Scan.application_id == app.id)
        .filter((Scan.is_deleted == False) | (Scan.is_deleted.is_(None)))
        .order_by(Scan.created_at.desc())
        .all()
    )
    total_scans = len(scans)
    latest_scan = scans[0] if scans else None

    # Find latest completed scan
    completed_scans = [s for s in scans if s.status == ScanStatus.COMPLETED]
    latest_completed_scan = (
        max(completed_scans, key=lambda s: s.completed_at or s.created_at)
        if completed_scans
        else None
    )

    last_scanned_at = (
        (latest_completed_scan.completed_at or latest_completed_scan.created_at)
        if latest_completed_scan
        else None
    )

    # Determine primary target URL and hostname
    target_url = None
    hostname = None
    ref_scan = latest_completed_scan or latest_scan
    if ref_scan and ref_scan.target:
        target_url = ref_scan.target.base_url
        hostname = ref_scan.target.hostname
    elif app.targets:
        target_url = app.targets[0].base_url
        hostname = app.targets[0].hostname

    latest_scan_id = latest_scan.id if latest_scan else None
    
    # Latest scan status
    latest_scan_status = (
        (latest_scan.status.value if hasattr(latest_scan.status, "value") else str(latest_scan.status))
        if latest_scan
        else None
    )

    # Latest scan date:
    # - If running scan, show start/creation date
    # - If completed scan exists, show completion/creation date
    # - If failed scan and no completed scan, show failed scan date
    latest_scan_date = None
    if latest_scan:
        if latest_scan.status == ScanStatus.RUNNING:
            latest_scan_date = latest_scan.started_at or latest_scan.created_at
        elif latest_completed_scan:
            latest_scan_date = latest_completed_scan.completed_at or latest_completed_scan.created_at
        else:
            latest_scan_date = latest_scan.created_at

    latest_scan_duration = None
    if ref_scan and ref_scan.started_at and ref_scan.completed_at:
        latest_scan_duration = round((ref_scan.completed_at - ref_scan.started_at).total_seconds(), 1)

    # Posture calculations: use latest_completed_scan so running/failed scans don't wipe out scores
    posture_scan = latest_completed_scan or latest_scan
    latest_score = None
    latest_rating = None
    latest_rating_color = None
    is_preliminary = False
    finding_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    discovered_routes_count = 0
    tested_routes_count = 0
    auth_routes_count = 0
    failed_routes_count = 0
    coverage_percentage = 0.0

    if posture_scan:
        discovered_routes_count = posture_scan.urls_discovered or 0
        tested_routes_count = posture_scan.urls_scanned or 0

        route_sum = posture_scan.route_summary or {}
        if isinstance(route_sum, dict):
            auth_routes = route_sum.get("routes_auth_required", [])
            failed_routes = route_sum.get("routes_failed", [])
            auth_routes_count = len(auth_routes) if isinstance(auth_routes, list) else 0
            failed_routes_count = len(failed_routes) if isinstance(failed_routes, list) else 0

        if discovered_routes_count > 0:
            coverage_percentage = round((tested_routes_count / discovered_routes_count) * 100, 1)
        elif tested_routes_count > 0:
            coverage_percentage = 100.0

        # Calculate posture from posture scan findings
        findings = db.query(Finding).filter(Finding.scan_id == posture_scan.id).all()
        posture = calculate_security_posture(posture_scan, findings)
        latest_score = posture["score"]
        latest_rating = posture["rating"]
        latest_rating_color = posture["rating_color"]
        is_preliminary = posture["is_preliminary"]

        for f in findings:
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev_val in finding_counts:
                finding_counts[sev_val] += 1

    return ApplicationResponse(
        id=app.id,
        name=app.name,
        description=app.description,
        target_url=target_url,
        hostname=hostname,
        created_at=app.created_at,
        updated_at=app.updated_at,
        total_scans=total_scans,
        latest_scan_id=latest_scan_id,
        latest_scan_date=latest_scan_date,
        latest_scan_status=latest_scan_status,
        latest_scan_duration=latest_scan_duration,
        latest_score=latest_score,
        latest_rating=latest_rating,
        latest_rating_color=latest_rating_color,
        is_preliminary=is_preliminary,
        finding_counts=finding_counts,
        discovered_routes_count=discovered_routes_count,
        tested_routes_count=tested_routes_count,
        auth_routes_count=auth_routes_count,
        failed_routes_count=failed_routes_count,
        coverage_percentage=coverage_percentage,
        last_scanned_at=last_scanned_at,
    )


def auto_sync_unassigned_scans(db: Session):
    """
    Ensure all scans and targets with scans are grouped into Applications based on netloc/port.
    Handles dynamic localhost ports correctly by creating a dedicated application per port.
    Prevents orphan targets with no scans from creating unwanted applications.
    """
    # Only sync targets that actually have associated scans to prevent orphan demo/test leakage
    targets = (
        db.query(Target)
        .filter(Target.application_id.is_(None))
        .filter(Target.scans.any())
        .all()
    )
    for t in targets:
        netloc = urlparse(t.base_url).netloc or t.hostname
        if not netloc:
            continue
        app = db.query(Application).filter(Application.name == netloc).first()
        if not app:
            app = Application(name=netloc, description=f"Monitored web application on {t.base_url}")
            db.add(app)
            db.flush()
        t.application_id = app.id
        t.name = app.name
        db.query(Scan).filter(Scan.target_id == t.id, Scan.application_id.is_(None)).update(
            {"application_id": app.id}
        )

    # Also associate any orphan scans whose targets already have an application_id or netloc
    unassigned_scans = db.query(Scan).filter(Scan.application_id.is_(None)).all()
    for s in unassigned_scans:
        if s.target and s.target.application_id:
            s.application_id = s.target.application_id
        elif s.target:
            netloc = urlparse(s.target.base_url).netloc or s.target.hostname
            if not netloc:
                continue
            app = db.query(Application).filter(Application.name == netloc).first()
            if not app:
                app = Application(name=netloc, description=f"Monitored web application on {s.target.base_url}")
                db.add(app)
                db.flush()
            s.target.application_id = app.id
            s.target.name = app.name
            s.application_id = app.id
    db.commit()


@router.get("", response_model=List[ApplicationResponse])
def list_applications(db: Session = Depends(get_db)):
    auto_sync_unassigned_scans(db)
    apps = db.query(Application).all()
    app_responses = [_build_app_response(app, db) for app in apps]

    # Filter out empty orphan apps that have 0 scans and no target or are unassociated test fixtures
    valid_apps = [
        a for a in app_responses
        if not (a.total_scans == 0 and not a.target_url and not a.description)
    ]

    # Sorting order according to requirements:
    # 1. Running scans at the absolute top (tier = 2)
    # 2. Most recently scanned targets (last_scanned_at descending) (tier = 1)
    # 3. Never-scanned targets at the bottom (last_scanned_at is None) (tier = 0), sorted by created_at desc
    # Consistent secondary sorting: created_at desc, then id/name
    def sort_key(item: ApplicationResponse):
        is_running = item.latest_scan_status == "running"
        has_completed = item.last_scanned_at is not None
        tier = 2 if is_running else (1 if has_completed else 0)

        if is_running:
            primary_time = item.latest_scan_date or item.created_at
        elif has_completed:
            primary_time = item.last_scanned_at
        else:
            primary_time = item.created_at

        ts = primary_time or datetime.min
        secondary_ts = item.created_at or datetime.min
        name_key = (item.name or "").lower()

        return (tier, ts, secondary_ts, name_key)

    valid_apps.sort(key=sort_key, reverse=True)
    return valid_apps


@router.post("", response_model=ApplicationResponse, status_code=201)
def create_application(req: ApplicationCreateRequest, db: Session = Depends(get_db)):
    name = req.name.strip()
    if not name:
        raise HTTPException(422, "Application name cannot be empty")

    existing = db.query(Application).filter(Application.name == name).first()
    if existing:
        return _build_app_response(existing, db)

    app = Application(name=name, description=req.description)
    db.add(app)
    db.commit()
    db.refresh(app)
    return _build_app_response(app, db)


@router.get("/{app_id}", response_model=ApplicationResponse)
def get_application(app_id: str, db: Session = Depends(get_db)):
    app = db.get(Application, app_id)
    if not app:
        raise HTTPException(404, "Application not found")
    return _build_app_response(app, db)


@router.patch("/{app_id}", response_model=ApplicationResponse)
def update_application(app_id: str, req: ApplicationUpdateRequest, db: Session = Depends(get_db)):
    app = db.get(Application, app_id)
    if not app:
        raise HTTPException(404, "Application not found")

    if req.name is not None and req.name.strip():
        app.name = req.name.strip()
    if req.description is not None:
        app.description = req.description

    app.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(app)
    return _build_app_response(app, db)


@router.post("/{app_id}/associate")
def associate_target_or_scan(
    app_id: str,
    target_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    app = db.get(Application, app_id)
    if not app:
        raise HTTPException(404, "Application not found")

    if scan_id:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        scan.application_id = app.id
        if scan.target:
            scan.target.application_id = app.id
            scan.target.name = app.name

    if target_id:
        target = db.get(Target, target_id)
        if not target:
            raise HTTPException(404, "Target not found")
        target.application_id = app.id
        target.name = app.name
        db.query(Scan).filter(Scan.target_id == target.id).update({"application_id": app.id})

    db.commit()
    return {"status": "associated", "application_id": app.id, "application_name": app.name}


@router.get("/{app_id}/trends", response_model=ApplicationTrendResponse)
def get_application_trends(app_id: str, db: Session = Depends(get_db)):
    app = db.get(Application, app_id)
    if not app:
        raise HTTPException(404, "Application not found")

    scans = (
        db.query(Scan)
        .filter(Scan.application_id == app.id, Scan.status == ScanStatus.COMPLETED, (Scan.is_deleted == False) | (Scan.is_deleted.is_(None)))
        .order_by(Scan.created_at.asc())
        .all()
    )

    history_points: List[HistoryPointResponse] = []
    for s in scans:
        findings = db.query(Finding).filter(Finding.scan_id == s.id).all()
        posture = calculate_security_posture(s, findings)
        duration = None
        if s.started_at and s.completed_at:
            duration = round((s.completed_at - s.started_at).total_seconds(), 1)

        history_points.append(
            HistoryPointResponse(
                scan_id=s.id,
                created_at=s.created_at,
                completed_at=s.completed_at,
                duration_seconds=duration,
                status=s.status.value if hasattr(s.status, "value") else str(s.status),
                score=posture["score"],
                rating=posture["rating"],
                critical_count=posture["unique_counts"]["critical"],
                high_count=posture["unique_counts"]["high"],
                medium_count=posture["unique_counts"]["medium"],
                low_count=posture["unique_counts"]["low"],
                routes_discovered=s.urls_discovered or 0,
                routes_tested=s.urls_scanned or 0,
            )
        )

    target_url = None
    hostname = None
    if scans:
        target_url = scans[-1].target.base_url if scans[-1].target else None
        hostname = scans[-1].target.hostname if scans[-1].target else None
    elif app.targets:
        target_url = app.targets[0].base_url
        hostname = app.targets[0].hostname

    current_score = None
    previous_score = None
    score_delta = None
    new_vulns = []
    resolved_vulns = []
    persistent_vulns = []
    reopened_vulns = []

    if len(history_points) >= 1:
        current_score = history_points[-1].score

    if len(history_points) >= 2:
        previous_score = history_points[-2].score
        score_delta = round(current_score - previous_score, 1)

        latest_scan = scans[-1]
        rem_res = correlate_scan_remediation(db, latest_scan)

        # Retrieve actual finding objects for the lists
        cur_findings = db.query(Finding).filter(Finding.scan_id == latest_scan.id).all()
        cur_by_id = {f.id: f for f in cur_findings}

        for fid in rem_res.get("new_findings", []):
            if fid in cur_by_id:
                f = cur_by_id[fid]
                new_vulns.append({
                    "id": f.id,
                    "type": f.type,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "url": f.url,
                    "parameter": f.parameter,
                    "status": f.status or "open",
                })

        for fid in rem_res.get("persistent_findings", []):
            if fid in cur_by_id:
                f = cur_by_id[fid]
                persistent_vulns.append({
                    "id": f.id,
                    "type": f.type,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "url": f.url,
                    "parameter": f.parameter,
                    "status": f.status or "open",
                })

        for fid in rem_res.get("reopened_findings", []):
            if fid in cur_by_id:
                f = cur_by_id[fid]
                reopened_vulns.append({
                    "id": f.id,
                    "type": f.type,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "url": f.url,
                    "parameter": f.parameter,
                    "status": f.status or "reopened",
                })

        resolved_vulns = rem_res.get("resolved_findings", [])
    elif len(history_points) == 1:
        latest_scan = scans[0]
        cur_findings = db.query(Finding).filter(Finding.scan_id == latest_scan.id).all()
        for f in cur_findings:
            new_vulns.append({
                "id": f.id,
                "type": f.type,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "url": f.url,
                "parameter": f.parameter,
                "status": f.status or "open",
            })

    return ApplicationTrendResponse(
        application_id=app.id,
        application_name=app.name,
        target_url=target_url,
        hostname=hostname,
        latest_score=current_score,
        previous_score=previous_score,
        score_delta=score_delta,
        new_vulnerabilities_count=len(new_vulns),
        resolved_vulnerabilities_count=len(resolved_vulns),
        persistent_vulnerabilities_count=len(persistent_vulns),
        reopened_vulnerabilities_count=len(reopened_vulns),
        new_vulnerabilities=new_vulns,
        resolved_vulnerabilities=resolved_vulns,
        persistent_vulnerabilities=persistent_vulns,
        reopened_vulnerabilities=reopened_vulns,
        history=history_points,
    )


@router.post("/{app_id}/rescan", response_model=ScanResponse, status_code=201)
def rescan_application(app_id: str, db: Session = Depends(get_db)):
    app = db.get(Application, app_id)
    if not app:
        raise HTTPException(404, "Application not found")

    latest_scan = (
        db.query(Scan)
        .filter(Scan.application_id == app.id)
        .order_by(Scan.created_at.desc())
        .first()
    )
    if not latest_scan or not latest_scan.target:
        raise HTTPException(400, "Application has no scan target to rescan")

    # Create new target and scan using previous configuration
    new_target = Target(
        base_url=latest_scan.target.base_url,
        hostname=latest_scan.target.hostname,
        authorization_confirmed=True,
        application_id=app.id,
        name=app.name,
    )
    db.add(new_target)
    db.flush()

    new_scan = Scan(
        target_id=new_target.id,
        application_id=app.id,
        max_depth=latest_scan.max_depth,
        max_urls=latest_scan.max_urls,
        request_delay=latest_scan.request_delay,
        modules=latest_scan.modules,
        enable_browser_discovery=latest_scan.enable_browser_discovery,
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    start_scan_task(new_scan.id)

    res = ScanResponse.model_validate(new_scan)
    res.status = new_scan.status.value
    res.target_url = new_target.base_url
    res.hostname = new_target.hostname
    res.application_id = app.id
    res.application_name = app.name
    return res



@router.delete("/{app_id}")
def delete_application(app_id: str, db: Session = Depends(get_db)):
    """
    Explicitly and safely delete a monitored website/application and its targets,
    scans, and dependent data. Also cleans up any duplicate application entries
    with the identical name to ensure the website does not phantom-reappear.
    """
    app = db.get(Application, app_id)
    if not app:
        raise HTTPException(404, "Application not found")

    app_name = app.name

    # Identify this application and any duplicates with the identical name
    matching_apps = (
        db.query(Application)
        .filter(Application.name == app_name)
        .all()
    )
    if not matching_apps:
        matching_apps = [app]
    elif app not in matching_apps:
        matching_apps.append(app)

    matching_app_ids = [a.id for a in matching_apps]

    # Check for active running scan
    running_scan = (
        db.query(Scan)
        .filter(Scan.application_id.in_(matching_app_ids), Scan.status == ScanStatus.RUNNING)
        .first()
    )
    if running_scan:
        raise HTTPException(400, "Cannot delete website with an actively running scan. Stop or cancel the scan first.")

    try:
        from app.models.activity import Activity
        from app.models.target import Target

        # Collect all scans and targets across all matching applications
        all_scans = (
            db.query(Scan)
            .filter(Scan.application_id.in_(matching_app_ids))
            .all()
        )
        scan_ids = [s.id for s in all_scans]
        if scan_ids:
            db.query(Activity).filter(Activity.scan_id.in_(scan_ids)).delete(synchronize_session=False)
            for s in all_scans:
                db.delete(s)

        # Activities pointing directly to these applications
        db.query(Activity).filter(Activity.application_id.in_(matching_app_ids)).delete(synchronize_session=False)

        # Targets belonging to these applications
        targets = (
            db.query(Target)
            .filter(Target.application_id.in_(matching_app_ids))
            .all()
        )
        for t in targets:
            for ts in list(t.scans):
                db.query(Activity).filter(Activity.scan_id == ts.id).delete(synchronize_session=False)
                db.delete(ts)
            db.delete(t)

        # Orphan targets that share the exact same name or hostname without another application
        orphan_targets = (
            db.query(Target)
            .filter(
                (Target.name == app_name) | (Target.hostname == app_name),
                Target.application_id.is_(None),
            )
            .all()
        )
        for ot in orphan_targets:
            for ts in list(ot.scans):
                db.query(Activity).filter(Activity.scan_id == ts.id).delete(synchronize_session=False)
                db.delete(ts)
            db.delete(ot)

        # Delete all matching applications
        for current_app in matching_apps:
            db.delete(current_app)

        db.commit()
    except Exception as exc:
        db.rollback()
        logger.exception("Failed to delete application %s: %s", app_id, exc)
        raise HTTPException(500, f"Failed to delete website: {str(exc)}")

    return {"status": "deleted", "application_id": app_id, "name": app_name, "deleted_count": len(matching_apps)}
