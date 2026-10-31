"""
ZeroTrace Vulnerability Lifecycle and Remediation Tracker Service.

Provides:
- Stable fingerprinting across scans based on target, issue type, affected route, and parameter.
- Cross-scan lifecycle tracking (Open, Fixed, Accepted Risk, Reopened).
- Activity logging for security audit timeline.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.activity import Activity
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus

logger = logging.getLogger("remediation")


def generate_finding_fingerprint(
    target_url: str,
    finding_type: str,
    url: str,
    parameter: Optional[str] = None,
    method: Optional[str] = "GET",
) -> str:
    """
    Generate a stable, deterministic fingerprint for a finding.
    Based on target hostname/port, finding type, affected route path, and parameter.
    """
    parsed_target = urlparse(target_url or "")
    parsed_url = urlparse(url or "")

    target_host = (parsed_target.netloc or parsed_url.netloc or "unknown").lower()
    path = (parsed_url.path or "/").strip().lower()
    if not path.startswith("/"):
        path = "/" + path

    type_str = (finding_type or "").strip().lower()
    param_str = (parameter or "").strip().lower()
    method_str = (method or "GET").strip().upper()

    seed = f"{target_host}|{path}|{type_str}|{param_str}|{method_str}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]


def record_activity(
    db: Session,
    event_type: str,
    title: str,
    description: str = "",
    scan_id: Optional[str] = None,
    application_id: Optional[str] = None,
    severity: str = "info",
    metadata: Optional[Dict[str, Any]] = None,
) -> Activity:
    """Record an audit trail activity in the database."""
    try:
        activity = Activity(
            event_type=event_type,
            title=title,
            description=description,
            scan_id=scan_id,
            application_id=application_id,
            severity=severity,
            timestamp=datetime.utcnow(),
            activity_metadata=metadata or {},
        )
        db.add(activity)
        db.commit()
        db.refresh(activity)
        return activity
    except Exception as e:
        logger.error("Failed to record activity %s: %s", event_type, e)
        db.rollback()
        return None


def get_previous_completed_scan(db: Session, current_scan: Scan) -> Optional[Scan]:
    """
    Find the most recent prior COMPLETED scan for the same application or target.
    Does not match unrelated dynamic ports or different hosts.
    """
    q = db.query(Scan).filter(
        Scan.id != current_scan.id,
        Scan.status == ScanStatus.COMPLETED,
        Scan.completed_at.isnot(None),
    )

    if current_scan.application_id:
        q = q.filter(Scan.application_id == current_scan.application_id)
    elif current_scan.target_id:
        q = q.filter(Scan.target_id == current_scan.target_id)
    else:
        return None

    if current_scan.completed_at:
        q = q.filter(Scan.completed_at < current_scan.completed_at)
    else:
        q = q.filter(Scan.created_at < current_scan.created_at)

    return q.order_by(Scan.completed_at.desc(), Scan.created_at.desc()).first()


def correlate_scan_remediation(db: Session, current_scan: Scan) -> Dict[str, Any]:
    """
    Correlate findings between the current scan and the prior completed scan.
    Categorizes findings into:
    - new_vulnerabilities
    - persistent_vulnerabilities
    - reopened_vulnerabilities
    - resolved_vulnerabilities
    """
    current_findings = db.query(Finding).filter(Finding.scan_id == current_scan.id).all()
    target_url = current_scan.target.base_url if current_scan.target else ""

    # Ensure fingerprints are set for current findings
    for f in current_findings:
        if not f.fingerprint:
            f.fingerprint = generate_finding_fingerprint(
                target_url=target_url,
                finding_type=f.type,
                url=f.url,
                parameter=f.parameter,
                method=f.method,
            )

    db.commit()

    prev_scan = get_previous_completed_scan(db, current_scan)
    if not prev_scan:
        return {
            "has_previous_scan": False,
            "previous_scan_id": None,
            "new_count": len(current_findings),
            "persistent_count": 0,
            "reopened_count": 0,
            "resolved_count": 0,
            "new_findings": [f.id for f in current_findings],
            "persistent_findings": [],
            "reopened_findings": [],
            "resolved_findings": [],
        }

    prev_findings = db.query(Finding).filter(Finding.scan_id == prev_scan.id).all()
    prev_by_fp = {p.fingerprint: p for p in prev_findings if p.fingerprint}

    current_fps = set()
    new_ids = []
    persistent_ids = []
    reopened_ids = []

    for f in current_findings:
        fp = f.fingerprint
        current_fps.add(fp)

        if fp in prev_by_fp:
            prev_f = prev_by_fp[fp]
            if prev_f.status == "fixed":
                f.status = "reopened"
                reopened_ids.append(f.id)
            elif prev_f.status == "accepted_risk":
                f.status = "accepted_risk"
                persistent_ids.append(f.id)
            else:
                f.status = "open"
                persistent_ids.append(f.id)
        else:
            if f.status not in ("accepted_risk", "fixed"):
                f.status = "open"
            new_ids.append(f.id)

    # Check for resolved findings: present in previous completed scan, but absent in current scan
    resolved_findings = []
    if current_scan.status == ScanStatus.COMPLETED:
        for fp, prev_f in prev_by_fp.items():
            if fp not in current_fps and prev_f.status in ("open", "reopened"):
                resolved_findings.append({
                    "fingerprint": fp,
                    "type": prev_f.type,
                    "url": prev_f.url,
                    "severity": prev_f.severity.value if hasattr(prev_f.severity, "value") else str(prev_f.severity),
                })

    db.commit()

    return {
        "has_previous_scan": True,
        "previous_scan_id": prev_scan.id,
        "new_count": len(new_ids),
        "persistent_count": len(persistent_ids),
        "reopened_count": len(reopened_ids),
        "resolved_count": len(resolved_findings),
        "new_findings": new_ids,
        "persistent_findings": persistent_ids,
        "reopened_findings": reopened_ids,
        "resolved_findings": resolved_findings,
    }

