import logging
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.ssrf_protection import validate_target_url, UnsafeTargetError
from app.database.session import get_db
from app.models.finding import Finding, Severity, Confidence
from app.models.scan import Scan, ScanStatus
from app.models.target import Target
from app.reports.pdf_report import build_report
from app.scanner.engine import start_scan_task, cancel_scan_task
from app.schemas.scan import ScanCreateRequest, ScanResponse, FindingResponse, ScanSummaryResponse

router = APIRouter(prefix="/api/scans", tags=["scans"])
logger = logging.getLogger("api")


def _scan_response(scan: Scan) -> ScanResponse:
    data = ScanResponse.model_validate(scan)
    data.status = scan.status.value
    return data


def _finding_response(f: Finding) -> FindingResponse:
    r = FindingResponse.model_validate(f)
    r.severity = f.severity.value
    r.confidence = f.confidence.value
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

    target = Target(base_url=url, hostname=urlparse(url).hostname, authorization_confirmed=True)
    db.add(target)
    db.flush()
    scan = Scan(target_id=target.id, max_depth=req.max_depth, max_urls=req.max_urls,
                request_delay=req.request_delay, modules=req.modules)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    start_scan_task(scan.id)
    return _scan_response(scan)


@router.get("", response_model=list[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    return [_scan_response(s) for s in db.query(Scan).order_by(Scan.created_at.desc()).all()]


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
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=scan-{scan_id[:8]}.pdf"})
