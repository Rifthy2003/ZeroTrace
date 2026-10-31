"""
Activity Timeline and Remediation Tracker API Router for ZeroTrace.
"""
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.activity import Activity
from app.models.finding import Finding, Severity
from app.models.scan import Scan
from app.schemas.scan import (
    ActivityResponse,
    FindingResponse,
    FindingStatusUpdateRequest,
)
from app.services.remediation import record_activity

router = APIRouter(tags=["activities_and_remediation"])
logger = logging.getLogger("api.activities")


@router.get("/api/activities", response_model=List[ActivityResponse])
def list_activities(
    limit: int = 50,
    application_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(Activity)
    if application_id:
        q = q.filter(Activity.application_id == application_id)
    activities = q.order_by(Activity.timestamp.desc()).limit(limit).all()

    # If activities table is empty, auto-seed from historical scans
    if not activities and not application_id:
        scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(20).all()
        for s in scans:
            target_url = s.target.base_url if s.target else "Target"
            if s.completed_at:
                record_activity(
                    db,
                    event_type="scan_completed",
                    title="Scan Completed",
                    description=f"Completed vulnerability scan on {target_url} ({s.findings_count} findings).",
                    scan_id=s.id,
                    application_id=s.application_id,
                    severity="success",
                    metadata={"target_url": target_url, "findings_count": s.findings_count},
                )
        activities = db.query(Activity).order_by(Activity.timestamp.desc()).limit(limit).all()

    return [
        ActivityResponse(
            id=a.id,
            event_type=a.event_type,
            title=a.title,
            description=a.description,
            severity=a.severity,
            timestamp=a.timestamp,
            scan_id=a.scan_id,
            application_id=a.application_id,
            metadata=a.activity_metadata or {},
        )
        for a in activities
    ]


@router.patch("/api/findings/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(
    finding_id: str,
    req: FindingStatusUpdateRequest,
    db: Session = Depends(get_db),
):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")

    valid_statuses = {"open", "fixed", "accepted_risk", "reopened"}
    new_status = req.status.lower().strip()
    if new_status not in valid_statuses:
        raise HTTPException(422, f"Status must be one of: {list(valid_statuses)}")

    old_status = finding.status or "open"
    finding.status = new_status
    if req.note is not None:
        finding.status_note = req.note
    finding.status_updated_at = datetime.utcnow()
    db.commit()
    db.refresh(finding)

    scan = finding.scan
    app_id = scan.application_id if scan else None
    target_base = scan.target.base_url if scan and scan.target else "target"

    label = new_status.replace("_", " ").title()
    record_activity(
        db,
        event_type="status_updated",
        title=f"Finding Marked as {label}",
        description=f"Vulnerability '{finding.type}' on {finding.url} updated from {old_status} to {new_status}.",
        scan_id=scan.id if scan else None,
        application_id=app_id,
        severity="info" if new_status != "reopened" else "warning",
        metadata={"finding_id": finding.id, "old_status": old_status, "new_status": new_status, "type": finding.type},
    )

    r = FindingResponse.model_validate(finding)
    r.severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    r.confidence = finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence)
    r.status = finding.status
    return r


@router.get("/api/findings/remediation-tracker")
def list_remediation_findings(
    application_id: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    if application_id:
        q = q.filter(Scan.application_id == application_id)
    if status:
        q = q.filter(Finding.status == status)
    if severity:
        q = q.filter(Finding.severity == Severity(severity))

    findings = q.order_by(Finding.timestamp.desc()).limit(limit).all()
    results = []
    for f in findings:
        r = FindingResponse.model_validate(f)
        r.severity = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        r.confidence = f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)
        r.status = f.status or "open"
        item = r.model_dump()
        item["target_url"] = f.scan.target.base_url if f.scan and f.scan.target else ""
        item["application_id"] = f.scan.application_id if f.scan else None
        item["application_name"] = f.scan.application.name if f.scan and f.scan.application else None
        results.append(item)
    return results

