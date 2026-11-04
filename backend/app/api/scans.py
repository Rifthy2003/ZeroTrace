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
from app.models.profile import ScanProfile, ScanProgram
from app.models.endpoint import Endpoint
from app.scanner.scope_enforcer import validate_url_in_scope, compute_effective_scan_config
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
    FindingStatusHistoryResponse,
    ScanSummaryResponse,
    SecurityPostureResponse,
    ExecutiveOverviewResponse,
    ScanComparisonResponse,
    ComparedFindingItem,
    EndpointCoverageResponse,
    EndpointCoverageItem,
)
from app.scanner.severity import extract_header_name, SECURITY_HEADER_RULES, CWE_MITRE_MAP, classify_finding_group
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

    data.profile_id = getattr(scan, "profile_id", None)
    data.profile_name = getattr(scan, "profile_name", None)
    raw_st = getattr(scan, "scan_type", None) or getattr(scan, "profile_name", None) or "Quick Scan"
    data.scan_type = "Full Scan" if "full" in str(raw_st).lower() else "Quick Scan"
    data.program_id = getattr(scan, "program_id", None)
    data.program_name = getattr(scan, "program_name", None)
    data.effective_restrictions = getattr(scan, "effective_restrictions", None)

    findings = getattr(scan, "findings", None)
    if findings is not None:
        unique_keys = set()
        raw_total = 0
        for f in findings:
            raw_total += getattr(f, "raw_instances", 1) or 1
            ftype_low = (f.type or "").lower()
            if "header" in ftype_low or "csp" in ftype_low:
                hname = extract_header_name(f.parameter, f.evidence) or (f.parameter or "generic")
                unique_keys.add(("header", hname.lower()))
            elif "clickjacking" in ftype_low:
                unique_keys.add(("config", "clickjacking"))
            elif "cors" in ftype_low:
                unique_keys.add(("config", "cors"))
            elif "cookie" in ftype_low:
                unique_keys.add(("cookie", ftype_low, (f.parameter or "").lower()))
            elif f.type in ("Exposed Sensitive File", "Sensitive File Exposure", "Directory Listing"):
                path = urlparse(f.url).path if f.url else ""
                unique_keys.add(("file", ftype_low, path.lower()))
            else:
                path = urlparse(f.url).path if f.url else ""
                unique_keys.add(("vuln", ftype_low, path.lower(), (f.parameter or "").lower()))
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
    r.fingerprint = getattr(f, "fingerprint", None)
    r.status_note = getattr(f, "status_note", None)
    r.status_updated_at = getattr(f, "status_updated_at", None)
    if hasattr(f, "status_history") and f.status_history:
        r.status_history = [
            FindingStatusHistoryResponse.model_validate(h)
            for h in f.status_history
        ]
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

        if "clickjacking" in ftype.lower():
            key = "config::clickjacking"
        elif "header" in ftype.lower() or "csp" in ftype.lower():
            hname = extract_header_name(fparam, fevid) or fparam or "generic"
            key = f"header::{hname.lower()}"
        elif "cors" in ftype.lower():
            key = "config::cors"
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
        r.finding_group = classify_finding_group(r.type, r.category, r.severity)

        r.evidence_details = {
            "finding_group": r.finding_group,
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

    grp_rank = {"critical_vulnerabilities": 3, "other_vulnerabilities": 2, "security_configuration": 1}
    results.sort(
        key=lambda x: (grp_rank.get(x.finding_group, 2), sev_rank.get(x.severity, 0), x.raw_instances or 1),
        reverse=True,
    )
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

    # Resolve scan_type: Quick Scan or Full Scan
    raw_type = (req.scan_type or req.profile_id or "").strip().lower()
    scan_type = "Full Scan" if "full" in raw_type else "Quick Scan"

    # Load ScanProfile (match scan_type: "Full Scan" or "Quick Scan")
    profile = None
    if req.profile_id:
        profile = db.get(ScanProfile, req.profile_id)
    if not profile:
        profile = db.query(ScanProfile).filter(ScanProfile.name == scan_type).first()
    if not profile:
        profile = db.query(ScanProfile).filter(ScanProfile.is_default == True).first()

    # Load ScanProgram (if specified)
    program = None
    if req.program_id:
        program = db.get(ScanProgram, req.program_id)
        if not program:
            raise HTTPException(404, f"Bug bounty program '{req.program_id}' not found")

        # Validate automated scanning restriction
        if not program.allow_automated_scanning:
            raise HTTPException(403, "Automated scanning is prohibited for this bug bounty program.")

        # Validate target URL against program scope
        in_scope, reason = validate_url_in_scope(
            url,
            target_domains=program.target_domains,
            url_patterns=program.url_patterns,
            out_of_scope_paths=program.out_of_scope_paths,
        )
        if not in_scope:
            raise HTTPException(403, f"Target URL is out of scope for program '{program.name}': {reason}")

    effective = compute_effective_scan_config(
        profile=profile,
        program=program,
        user_overrides={
            "scan_type": scan_type,
            "modules": req.modules,
            "max_depth": req.max_depth,
            "max_urls": req.max_urls,
            "request_delay": req.request_delay,
        },
    )

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
        max_depth=effective["max_depth"],
        max_urls=effective["max_urls"],
        request_delay=effective["request_delay"],
        modules=effective["effective_modules"],
        enable_browser_discovery=req.enable_browser_discovery,
        auth_config=req.auth_config,
        profile_id=profile.id if profile else None,
        profile_name=scan_type,
        scan_type=scan_type,
        program_id=program.id if program else None,
        program_name=program.name if program else None,
        effective_restrictions=effective.get("effective_restrictions"),
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


@router.get("/compare", response_model=ScanComparisonResponse)
def compare_scans(base_scan_id: str, target_scan_id: str, db: Session = Depends(get_db)):
    base_scan = _get_scan(db, base_scan_id)
    target_scan = _get_scan(db, target_scan_id)

    # Normalized target domain
    base_url = base_scan.target.base_url if base_scan.target else ""
    target_url = target_scan.target.base_url if target_scan.target else ""
    base_domain = urlparse(base_url).netloc or urlparse(base_url).hostname or ""
    target_domain = urlparse(target_url).netloc or urlparse(target_url).hostname or ""

    # Security scores
    base_posture = calculate_security_posture(db, base_scan.id)
    target_posture = calculate_security_posture(db, target_scan.id)
    base_score = base_posture["score"] if isinstance(base_posture, dict) else getattr(base_posture, "score", 100.0)
    target_score = target_posture["score"] if isinstance(target_posture, dict) else getattr(target_posture, "score", 100.0)
    score_delta = round(target_score - base_score, 1)

    # Group findings
    base_grouped = group_scan_findings(base_scan.findings or [])
    target_grouped = group_scan_findings(target_scan.findings or [])

    # Map by stable key
    def _make_key(f: FindingResponse) -> str:
        if f.fingerprint:
            return f.fingerprint
        if "header" in f.type.lower():
            hname = (f.parameter or "").lower()
            return f"header::{hname}"
        parsed = urlparse(f.url or "")
        path = parsed.path if parsed and parsed.path else (f.url or "")
        return f"{f.type.lower()}::{path.lower()}::{(f.parameter or '').lower()}"

    base_map = {_make_key(f): f for f in base_grouped}
    target_map = {_make_key(f): f for f in target_grouped}

    all_keys = set(base_map.keys()) | set(target_map.keys())
    compared_items: list[ComparedFindingItem] = []

    counts_summary = {"new": 0, "fixed": 0, "recurring": 0, "unchanged": 0}

    for key in all_keys:
        in_base = key in base_map
        in_target = key in target_map

        if in_target and not in_base:
            c_status = "new"
            f_rep = target_map[key]
            base_id = None
            target_id = f_rep.id
        elif in_base and not in_target:
            c_status = "fixed"
            f_rep = base_map[key]
            base_id = f_rep.id
            target_id = None
        else:
            base_item = base_map[key]
            f_rep = target_map[key]
            base_id = base_item.id
            target_id = f_rep.id

            # Check if base item was marked fixed or resolved in status history
            is_resolved = str(base_item.status).lower() in ("fixed", "accepted risk")
            has_fixed_history = False
            if hasattr(base_item, "status_history") and base_item.status_history:
                has_fixed_history = any(str(h.get("new_status")).lower() in ("fixed", "fixed finding") for h in base_item.status_history)

            if is_resolved or has_fixed_history or str(base_item.status).lower() in ("reopened",):
                c_status = "recurring"
            else:
                c_status = "unchanged"

        counts_summary[c_status] += 1

        aff_urls = f_rep.evidence_details.get("affected_urls", []) if f_rep.evidence_details else []
        if not aff_urls and f_rep.url:
            aff_urls = [f_rep.url]

        compared_items.append(
            ComparedFindingItem(
                fingerprint=key,
                type=f_rep.type,
                category=getattr(f_rep, "category", "Vulnerability") or "Vulnerability",
                url=f_rep.url or "",
                method=f_rep.method or "GET",
                parameter=f_rep.parameter,
                severity=f_rep.severity,
                status=f_rep.status,
                comparison_status=c_status,
                base_finding_id=base_id,
                target_finding_id=target_id,
                affected_urls=aff_urls,
                raw_instances=f_rep.raw_instances or 1,
                evidence_snippet=(f_rep.evidence or "")[:200],
            )
        )

    # Sort compared items: status priority (new, recurring, unchanged, fixed), then severity
    status_rank = {"new": 4, "recurring": 3, "unchanged": 2, "fixed": 1}
    sev_rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
    compared_items.sort(
        key=lambda x: (status_rank.get(x.comparison_status, 0), sev_rank.get(x.severity, 0)),
        reverse=True,
    )

    # Severity distribution changes
    sev_keys = ["Critical", "High", "Medium", "Low", "Informational"]
    base_sev = {s: 0 for s in sev_keys}
    target_sev = {s: 0 for s in sev_keys}
    for f in base_grouped:
        if f.severity in base_sev:
            base_sev[f.severity] += 1
    for f in target_grouped:
        if f.severity in target_sev:
            target_sev[f.severity] += 1
    delta_sev = {s: target_sev[s] - base_sev[s] for s in sev_keys}

    severity_changes = {
        "base": base_sev,
        "target": target_sev,
        "delta": delta_sev,
    }

    # Endpoint coverage changes
    base_cov = base_scan.coverage_summary or {}
    target_cov = target_scan.coverage_summary or {}
    coverage_changes = {
        "base_coverage_pct": base_cov.get("coverage_percentage", 0.0),
        "target_coverage_pct": target_cov.get("coverage_percentage", 0.0),
        "coverage_delta": round(target_cov.get("coverage_percentage", 0.0) - base_cov.get("coverage_percentage", 0.0), 1),
        "base_endpoints": base_cov.get("endpoints_discovered", 0),
        "target_endpoints": target_cov.get("endpoints_discovered", 0),
        "endpoints_delta": target_cov.get("endpoints_discovered", 0) - base_cov.get("endpoints_discovered", 0),
        "base_tested": base_cov.get("endpoints_tested", 0),
        "target_tested": target_cov.get("endpoints_tested", 0),
    }

    return ScanComparisonResponse(
        base_scan=_scan_response(base_scan),
        target_scan=_scan_response(target_scan),
        target_domain=target_domain or base_domain,
        base_score=base_score,
        target_score=target_score,
        score_delta=score_delta,
        base_unique_count=len(base_grouped),
        target_unique_count=len(target_grouped),
        count_delta=len(target_grouped) - len(base_grouped),
        severity_changes=severity_changes,
        coverage_changes=coverage_changes,
        findings_summary=counts_summary,
        compared_findings=compared_items,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    return _scan_response(_get_scan(db, scan_id))


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
def get_findings(
    scan_id: str,
    severity: str | None = None,
    confidence: str | None = None,
    type: str | None = None,
    url: str | None = None,
    lifecycle_status: str | None = None,
    detection_status: str | None = None,
    search: str | None = None,
    db: Session = Depends(get_db),
):
    _get_scan(db, scan_id)
    raw_findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    grouped = group_scan_findings(raw_findings)

    if severity:
        grouped = [f for f in grouped if f.severity.lower() == severity.lower()]
    if confidence:
        grouped = [f for f in grouped if f.confidence.lower() == confidence.lower()]
    if type:
        grouped = [f for f in grouped if f.type == type]
    if lifecycle_status:
        grouped = [f for f in grouped if (f.status or "").lower() == lifecycle_status.lower()]
    if detection_status:
        grouped = [f for f in grouped if (f.detection_status or "").lower() == detection_status.lower()]
    if url:
        u_lower = url.lower()
        grouped = [
            f for f in grouped
            if u_lower in (f.url or "").lower() or any(
                u_lower in aff.lower() for aff in (f.evidence_details.get("affected_urls") or [])
            )
        ]
    if search:
        s_lower = search.lower()
        grouped = [
            f for f in grouped
            if s_lower in (f.type or "").lower()
            or s_lower in (f.parameter or "").lower()
            or s_lower in (f.url or "").lower()
            or s_lower in (f.description or "").lower()
            or s_lower in (f.cwe_id or "").lower()
        ]
    return grouped


@router.get("/{scan_id}/comparable-scans", response_model=list[ScanResponse])
def get_comparable_scans(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id)
    hostname = scan.target.hostname if scan.target else None
    app_id = scan.application_id

    q = db.query(Scan).filter(
        Scan.status == ScanStatus.COMPLETED,
        Scan.id != scan_id,
        (Scan.is_deleted == False) | (Scan.is_deleted == None),
    )
    if app_id:
        q = q.filter(Scan.application_id == app_id)
    elif hostname:
        q = q.join(Target, Scan.target_id == Target.id).filter(Target.hostname == hostname)

    return [_scan_response(s) for s in q.order_by(Scan.created_at.desc()).all()]


@router.get("/{scan_id}/coverage", response_model=EndpointCoverageResponse)
def get_scan_coverage(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id)
    endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    disc_pages = sum(1 for e in endpoints if getattr(e, "endpoint_type", "page") == "page")
    disc_endpoints = len(endpoints)
    disc_forms = sum(1 for e in endpoints if str(getattr(e, "has_form", "false")).lower() == "true")
    disc_params = sum(len(e.parameters) for e in endpoints)

    tested_endpoints = sum(1 for e in endpoints if getattr(e, "is_tested", False))
    untested_endpoints = max(0, disc_endpoints - tested_endpoints)

    cov_sum = scan.coverage_summary or {}
    tested_params = cov_sum.get("parameters_tested", sum(len(e.parameters) for e in endpoints if getattr(e, "is_tested", False)))
    untested_params = max(0, disc_params - tested_params)

    succ_reqs = sum(1 for e in endpoints if e.status_code and 200 <= e.status_code < 400)
    failed_reqs = sum(1 for e in endpoints if (e.status_code and e.status_code >= 500) or getattr(e, "testing_status", "") == "failed")
    auth_reqs = sum(1 for e in endpoints if (e.status_code in (401, 403)) or getattr(e, "testing_status", "") == "auth_required")
    skipped_eps = sum(1 for e in endpoints if getattr(e, "testing_status", "") == "skipped" or (not getattr(e, "is_tested", False) and (not e.status_code or e.status_code not in (401, 403))))

    cov_pct = cov_sum.get("coverage_percentage")
    if cov_pct is None:
        cov_pct = round((tested_endpoints / max(1, disc_endpoints)) * 100, 1)

    # Method distribution
    method_dist: dict[str, int] = {}
    for e in endpoints:
        m = (e.method or "GET").upper()
        method_dist[m] = method_dist.get(m, 0) + 1

    module_matrix = cov_sum.get("module_matrix", [])

    endpoint_items: list[EndpointCoverageItem] = []
    for e in endpoints:
        e_path = urlparse(e.url).path if e.url else ""
        matched_findings = [
            {
                "id": f.id,
                "type": f.type,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "parameter": f.parameter,
            }
            for f in findings
            if (f.url == e.url) or (urlparse(f.url).path == e_path and f.method == e.method)
        ]

        endpoint_items.append(
            EndpointCoverageItem(
                id=e.id,
                url=e.url,
                method=e.method or "GET",
                endpoint_type=getattr(e, "endpoint_type", "page") or "page",
                source=getattr(e, "source", "crawler") or "crawler",
                status_code=e.status_code,
                parameters=[
                    {"name": p.name, "location": p.location, "sample_value": p.sample_value}
                    for p in e.parameters
                ],
                testing_status=getattr(e, "testing_status", "untested") or "untested",
                is_tested=bool(getattr(e, "is_tested", False)),
                modules_executed=getattr(e, "modules_executed", []) or [],
                findings_count=len(matched_findings),
                findings=matched_findings,
            )
        )

    target_base = scan.target.base_url if scan.target else ""
    hostname = scan.target.hostname if scan.target else (urlparse(target_base).hostname or "unknown")

    return EndpointCoverageResponse(
        scan_id=scan.id,
        target_url=target_base,
        hostname=hostname,
        scan_status=scan.status.value if hasattr(scan.status, "value") else str(scan.status),
        created_at=scan.created_at,
        discovered_pages=disc_pages,
        discovered_endpoints=disc_endpoints,
        discovered_forms=disc_forms,
        discovered_parameters=disc_params,
        tested_endpoints=tested_endpoints,
        untested_endpoints=untested_endpoints,
        tested_parameters=tested_params,
        untested_parameters=untested_params,
        successful_requests=succ_reqs,
        failed_requests=failed_reqs,
        skipped_endpoints=skipped_eps,
        auth_protected_endpoints=auth_reqs,
        coverage_percentage=cov_pct,
        method_distribution=method_dist,
        module_matrix=module_matrix,
        endpoints=endpoint_items,
    )


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

    if report_type in ("short", "short-report", "bug-bounty", "bounty"):
        pdf = build_complete_website_bug_bounty_pdf(scan, scan.findings, scan.summary)
        filename = f"short-report-{safe_host}-{scan_id[:8]}.pdf" if report_type in ("short", "short-report") else f"bug-bounty-{safe_host}-{scan_id[:8]}.pdf"
        desc = f"Short security assessment report downloaded for {target_base}." if report_type in ("short", "short-report") else f"Complete website bug bounty report downloaded for {target_base}."
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


@router.get("/{scan_id}/report/short")
def report_short(scan_id: str, db: Session = Depends(get_db)):
    return report(scan_id, type="short", db=db)


@router.get("/{scan_id}/report/bug-bounty")
def report_bug_bounty(scan_id: str, db: Session = Depends(get_db)):
    return report(scan_id, type="bug-bounty", db=db)


@router.get("/{scan_id}/report/summary")
def report_summary(scan_id: str, db: Session = Depends(get_db)):
    return report(scan_id, type="summary", db=db)


@router.get("/{scan_id}/report/full")
def report_full(scan_id: str, db: Session = Depends(get_db)):
    return report(scan_id, type="full", db=db)
