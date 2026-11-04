"""
Activity Timeline and Remediation Tracker API Router for ZeroTrace.
"""
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.activity import Activity
from app.models.finding import Finding, FindingStatusHistory, Severity
from app.models.scan import Scan
from app.reports.bug_bounty_report import build_bug_bounty_markdown, build_bug_bounty_pdf
from app.schemas.scan import (
    ActivityResponse,
    FindingResponse,
    FindingStatusUpdateRequest,
    FindingStatusHistoryResponse,
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


CANONICAL_LIFECYCLE_MAP = {
    "new": "New",
    "open": "New",
    "confirmed": "Confirmed",
    "requires manual verification": "Requires Manual Verification",
    "requires_manual_verification": "Requires Manual Verification",
    "manual_verification": "Requires Manual Verification",
    "false positive": "False Positive",
    "false_positive": "False Positive",
    "accepted risk": "Accepted Risk",
    "accepted_risk": "Accepted Risk",
    "in progress": "In Progress",
    "in_progress": "In Progress",
    "fixed": "Fixed",
    "reopened": "Reopened",
}
VALID_RESEARCHER_STATUSES = [
    "New",
    "Confirmed",
    "Requires Manual Verification",
    "False Positive",
    "Accepted Risk",
    "In Progress",
    "Fixed",
    "Reopened",
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

    raw_status = (req.status or "").strip().lower()
    canonical_status = CANONICAL_LIFECYCLE_MAP.get(raw_status)
    if not canonical_status:
        raise HTTPException(
            422,
            f"Invalid lifecycle status '{req.status}'. Must be one of: {VALID_RESEARCHER_STATUSES}",
        )

    old_status = finding.status or "New"
    user_name = req.user.strip() if req.user and req.user.strip() else "Security Researcher"

    # Record status transition in audit history
    history_entry = FindingStatusHistory(
        finding_id=finding.id,
        old_status=old_status,
        new_status=canonical_status,
        note=req.note,
        user=user_name,
        timestamp=datetime.utcnow(),
    )
    db.add(history_entry)

    finding.status = canonical_status
    if req.note is not None:
        finding.status_note = req.note
    finding.status_updated_at = datetime.utcnow()
    db.commit()
    db.refresh(finding)

    scan = finding.scan
    app_id = scan.application_id if scan else None

    record_activity(
        db,
        event_type="status_updated",
        title=f"Finding Marked as {canonical_status}",
        description=f"Vulnerability '{finding.type}' on {finding.url} updated from {old_status} to {canonical_status} by {user_name}.",
        scan_id=scan.id if scan else None,
        application_id=app_id,
        severity="info" if canonical_status != "Reopened" else "warning",
        metadata={
            "finding_id": finding.id,
            "old_status": old_status,
            "new_status": canonical_status,
            "type": finding.type,
            "user": user_name,
            "note": req.note,
        },
    )

    r = FindingResponse.model_validate(finding)
    r.severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    r.confidence = finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence)
    r.status = finding.status
    r.status_history = [
        FindingStatusHistoryResponse.model_validate(h).model_dump()
        for h in (finding.status_history or [])
    ]
    return r


@router.get("/api/findings/{finding_id}/history", response_model=List[FindingStatusHistoryResponse])
def get_finding_history(finding_id: str, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")

    history = (
        db.query(FindingStatusHistory)
        .filter(FindingStatusHistory.finding_id == finding_id)
        .order_by(FindingStatusHistory.timestamp.desc())
        .all()
    )
    return history


@router.get("/api/findings/remediation-tracker")
def list_remediation_findings(
    application_id: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    q = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter((Scan.is_deleted == False) | (Scan.is_deleted.is_(None)))
    )
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


@router.get("/api/findings/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    r = FindingResponse.model_validate(finding)
    r.severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    r.confidence = finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence)
    r.status = finding.status or "open"
    if finding.type == "Missing Security Header":
        from app.scanner.severity import extract_header_name, SECURITY_HEADER_RULES
        hname = extract_header_name(finding.parameter, finding.evidence)
        if hname:
            r.parameter = hname
            if hname in SECURITY_HEADER_RULES:
                r.severity = SECURITY_HEADER_RULES[hname]["severity"].value
    if not r.raw_instances:
        r.raw_instances = 1
    r.status_history = [
        FindingStatusHistoryResponse.model_validate(h).model_dump()
        for h in (finding.status_history or [])
    ]
    return r


@router.get("/api/findings/{finding_id}/report")
def get_finding_bug_bounty_report(finding_id: str, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")

    pdf = build_bug_bounty_pdf(finding, finding.scan)
    safe_title = "".join(c if c.isalnum() else "-" for c in (finding.type or "finding").lower()).strip("-")
    filename = f"bounty-report-{safe_title[:24]}-{finding_id[:8]}.pdf"

    scan = finding.scan
    app_id = scan.application_id if scan else None
    record_activity(
        db,
        event_type="bounty_report_generated",
        title="Bug Bounty Report Generated",
        description=f"Exported responsible disclosure report for '{finding.type}' on {finding.url}.",
        scan_id=scan.id if scan else None,
        application_id=app_id,
        severity="info",
        metadata={"finding_id": finding.id, "type": finding.type, "url": finding.url},
    )

    return Response(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/api/findings/{finding_id}/markdown")
def get_finding_bug_bounty_markdown(finding_id: str, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")

    md_content = build_bug_bounty_markdown(finding, finding.scan)
    safe_title = "".join(c if c.isalnum() else "-" for c in (finding.type or "finding").lower()).strip("-")
    filename = f"hackerone-{safe_title[:24]}-{finding_id[:8]}.md"

    return Response(
        md_content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


