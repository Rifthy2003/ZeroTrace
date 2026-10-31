"""
ZeroTrace Security Posture Scoring Service.

Heuristic scoring rules for ZeroTrace:
- Calculates security score (0-100) from actual stored findings.
- Applies severity penalty weights modified by finding confidence.
- Deduplicates repeated findings and correlates equivalent issues before scoring.
- Keeps genuinely different missing security headers as separate findings.
- Excludes informational technology fingerprinting from security penalties.
- Distinguishes confirmed findings from those requiring manual verification.
- Flags ratings as preliminary if scans are incomplete, have insufficient coverage,
  or report zero findings (never blindly claims zero findings means 100% secure).

Note: These are ZeroTrace's own heuristic scoring rules, not an industry-standard certification.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.models.finding import Confidence, Finding, Severity
from app.models.scan import Scan, ScanStatus


# Configurable base penalty weights per severity
DEFAULT_PENALTY_WEIGHTS: Dict[str, float] = {
    Severity.CRITICAL.value: 25.0,
    Severity.HIGH.value: 15.0,
    Severity.MEDIUM.value: 7.0,
    Severity.LOW.value: 3.0,
    Severity.INFORMATIONAL.value: 0.0,
}

# Confidence multipliers:
# - Confirmed: 1.0 (100% penalty) - verified vulnerability
# - High confidence: 0.9 (90% penalty) - strong indicators/multiple heuristics
# - Medium confidence: 0.7 (70% penalty) - single heuristic, requires manual verification
# - Low confidence: 0.4 (40% penalty) - weak heuristic, requires manual verification
# - Informational: 0.0 (0% penalty) - context only
DEFAULT_CONFIDENCE_MULTIPLIERS: Dict[str, float] = {
    Confidence.CONFIRMED.value: 1.0,
    Confidence.HIGH.value: 0.9,
    Confidence.MEDIUM.value: 0.7,
    Confidence.LOW.value: 0.4,
    Confidence.INFORMATIONAL.value: 0.0,
}

# Thresholds:
# STRONG: 85 - 100
# MEDIUM: 60 - 84
# WEAK: 0 - 59
STRONG_THRESHOLD = 85.0
MEDIUM_THRESHOLD = 60.0

SEVERITY_RANK = {
    Severity.CRITICAL.value: 5,
    Severity.HIGH.value: 4,
    Severity.MEDIUM.value: 3,
    Severity.LOW.value: 2,
    Severity.INFORMATIONAL.value: 1,
}

CONFIDENCE_RANK = {
    Confidence.CONFIRMED.value: 5,
    Confidence.HIGH.value: 4,
    Confidence.MEDIUM.value: 3,
    Confidence.LOW.value: 2,
    Confidence.INFORMATIONAL.value: 1,
}


@dataclass
class UniqueFinding:
    dedup_key: str
    finding_type: str
    category: str
    severity: str
    confidence: str
    url: str
    parameter: Optional[str]
    description: Optional[str]
    remediation: Optional[str]
    occurrences: int = 1
    affected_urls: List[str] = field(default_factory=list)
    penalty: float = 0.0
    is_confirmed: bool = False
    requires_manual_verification: bool = False


def _get_val(obj: Any, attr: str, default: Any = None) -> Any:
    if hasattr(obj, attr):
        val = getattr(obj, attr)
        if hasattr(val, "value"):
            return val.value
        return val
    if isinstance(obj, dict):
        val = obj.get(attr, default)
        if hasattr(val, "value"):
            return val.value
        return val
    return default


def _canonical_dedup_key(f: Any) -> str:
    """
    Build a canonical deduplication key for grouping repeated findings.
    - Missing Security Headers: keyed by header name (in parameter), keeping genuinely different headers separate.
    - Cookie flags: keyed by cookie name + issue type.
    - Technology detection: keyed by detected banner/component.
    - Injections/XSS/others: keyed by type + URL path + parameter.
    """
    ftype = str(_get_val(f, "type", "") or "")
    furl = str(_get_val(f, "url", "") or "")
    fparam = str(_get_val(f, "parameter", "") or "").strip().lower()
    fevidence = str(_get_val(f, "evidence", "") or "").strip().lower()

    parsed = urlparse(furl) if furl else None
    path = parsed.path if parsed and parsed.path else furl

    if ftype == "Missing Security Header":
        # Keep genuinely different headers as separate findings, deduplicating across URLs
        header_name = fparam if fparam else fevidence.split(":")[0].strip()
        return f"header::{header_name.lower()}"

    if "Cookie" in ftype:
        return f"cookie::{ftype.lower()}::{fparam}"

    if ftype == "Technology Detection":
        return f"tech::{fevidence or fparam}"

    if ftype in ("Exposed Sensitive File", "Directory Listing"):
        return f"file_or_dir::{ftype.lower()}::{path}"

    # For injections, XSS, CSRF, open redirect, info disclosure
    return f"vuln::{ftype.lower()}::{path.lower()}::{fparam}"


def deduplicate_findings(findings: List[Any]) -> List[UniqueFinding]:
    """
    Deduplicate repeated findings and correlate equivalent issues before scoring.
    Selects the most severe / highest-confidence instance as representative.
    """
    groups: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        key = _canonical_dedup_key(f)
        f_sev = str(_get_val(f, "severity", Severity.INFORMATIONAL.value))
        f_conf = str(_get_val(f, "confidence", Confidence.INFORMATIONAL.value))
        f_url = str(_get_val(f, "url", "") or "")
        f_type = str(_get_val(f, "type", "") or "")
        f_cat = str(_get_val(f, "category", "") or "")
        f_param = _get_val(f, "parameter", None)
        f_desc = _get_val(f, "description", None)
        f_rem = _get_val(f, "remediation", None)

        if key not in groups:
            groups[key] = {
                "key": key,
                "type": f_type,
                "category": f_cat,
                "severity": f_sev,
                "confidence": f_conf,
                "url": f_url,
                "parameter": f_param,
                "description": f_desc,
                "remediation": f_rem,
                "occurrences": 1,
                "affected_urls": [f_url] if f_url else [],
            }
        else:
            g = groups[key]
            g["occurrences"] += 1
            if f_url and f_url not in g["affected_urls"]:
                g["affected_urls"].append(f_url)

            # Choose the higher severity or higher confidence as representative
            current_sev_rank = SEVERITY_RANK.get(g["severity"], 0)
            new_sev_rank = SEVERITY_RANK.get(f_sev, 0)
            current_conf_rank = CONFIDENCE_RANK.get(g["confidence"], 0)
            new_conf_rank = CONFIDENCE_RANK.get(f_conf, 0)

            if new_sev_rank > current_sev_rank or (
                new_sev_rank == current_sev_rank and new_conf_rank > current_conf_rank
            ):
                g["severity"] = f_sev
                g["confidence"] = f_conf
                g["url"] = f_url
                if f_param:
                    g["parameter"] = f_param
                if f_desc:
                    g["description"] = f_desc
                if f_rem:
                    g["remediation"] = f_rem

    unique_list: List[UniqueFinding] = []
    for g in groups.values():
        is_conf = g["confidence"] == Confidence.CONFIRMED.value
        needs_verif = g["confidence"] in (
            Confidence.HIGH.value,
            Confidence.MEDIUM.value,
            Confidence.LOW.value,
        )
        unique_list.append(
            UniqueFinding(
                dedup_key=g["key"],
                finding_type=g["type"],
                category=g["category"],
                severity=g["severity"],
                confidence=g["confidence"],
                url=g["url"],
                parameter=g["parameter"],
                description=g["description"],
                remediation=g["remediation"],
                occurrences=g["occurrences"],
                affected_urls=g["affected_urls"],
                is_confirmed=is_conf,
                requires_manual_verification=needs_verif,
            )
        )

    # Sort by severity descending, then occurrences descending
    unique_list.sort(
        key=lambda u: (SEVERITY_RANK.get(u.severity, 0), u.occurrences),
        reverse=True,
    )
    return unique_list


def calculate_security_posture(
    scan: Any,
    findings: List[Any],
    penalty_weights: Optional[Dict[str, float]] = None,
    confidence_multipliers: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Compute Website Security Posture for a given scan and its findings.
    """
    weights = penalty_weights or DEFAULT_PENALTY_WEIGHTS
    multipliers = confidence_multipliers or DEFAULT_CONFIDENCE_MULTIPLIERS

    unique_findings = deduplicate_findings(findings)

    # Raw counts
    raw_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
        "total": len(findings),
    }
    raw_confirmed = 0
    raw_manual_verification = 0

    for f in findings:
        sev = str(_get_val(f, "severity", "")).lower()
        if sev in raw_counts:
            raw_counts[sev] += 1
        conf = str(_get_val(f, "confidence", ""))
        if conf == Confidence.CONFIRMED.value:
            raw_confirmed += 1
        elif conf in (
            Confidence.HIGH.value,
            Confidence.MEDIUM.value,
            Confidence.LOW.value,
        ):
            raw_manual_verification += 1

    # Unique counts
    unique_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
        "total": len(unique_findings),
    }
    unique_confirmed = 0
    unique_manual_verification = 0

    score_deductions = []
    total_penalty = 0.0

    for u in unique_findings:
        sev_lower = u.severity.lower()
        if sev_lower in unique_counts:
            unique_counts[sev_lower] += 1

        if u.is_confirmed:
            unique_confirmed += 1
        elif u.requires_manual_verification:
            unique_manual_verification += 1

        # Exclude informational technology fingerprinting from penalties
        if (
            u.finding_type == "Technology Detection"
            or u.severity == Severity.INFORMATIONAL.value
            or u.confidence == Confidence.INFORMATIONAL.value
        ):
            penalty = 0.0
        else:
            base_w = weights.get(u.severity, 0.0)
            conf_m = multipliers.get(u.confidence, 1.0)
            penalty = round(base_w * conf_m, 1)

        u.penalty = penalty
        total_penalty += penalty

        if penalty > 0:
            target_desc = (
                f"{u.url} (param: '{u.parameter}')"
                if u.parameter
                else (u.url or "site-wide")
            )
            if u.occurrences > 1:
                target_desc += f" [{u.occurrences} instances]"

            score_deductions.append(
                {
                    "finding_type": u.finding_type,
                    "severity": u.severity,
                    "confidence": u.confidence,
                    "points_deducted": penalty,
                    "occurrences": u.occurrences,
                    "summary": f"-{penalty} pts: {u.severity} — {u.finding_type} on {target_desc} ({u.confidence})",
                }
            )

    total_penalty = round(total_penalty, 1)
    score = max(0.0, min(100.0, round(100.0 - total_penalty, 1)))

    # Determine Rating
    if score >= STRONG_THRESHOLD:
        rating = "STRONG"
        rating_color = "#10b981"  # Emerald
    elif score >= MEDIUM_THRESHOLD:
        rating = "MEDIUM"
        rating_color = "#f59e0b"  # Amber
    else:
        rating = "WEAK"
        rating_color = "#ef4444"  # Red

    # Coverage and preliminary checks
    scan_status = str(_get_val(scan, "status", ScanStatus.COMPLETED.value))
    urls_scanned = int(_get_val(scan, "urls_scanned", 0) or 0)
    urls_discovered = int(_get_val(scan, "urls_discovered", 0) or 0)
    parameters_found = int(_get_val(scan, "parameters_found", 0) or 0)
    max_depth = int(_get_val(scan, "max_depth", 2) or 2)
    max_urls = int(_get_val(scan, "max_urls", 50) or 50)
    modules = _get_val(scan, "modules", []) or []

    is_preliminary = False
    preliminary_reasons: List[str] = []

    if scan_status != ScanStatus.COMPLETED.value:
        is_preliminary = True
        preliminary_reasons.append(
            f"Scan is currently '{scan_status}' (incomplete). Rating reflects findings collected so far."
        )

    if urls_scanned == 0 or urls_discovered == 0:
        is_preliminary = True
        preliminary_reasons.append(
            "Crawl coverage is insufficient (0 pages successfully crawled)."
        )

    if len(findings) == 0:
        is_preliminary = True
        preliminary_reasons.append(
            "No findings were identified within the configured crawl scope. Zero automated findings do not certify that the application is secure."
        )

    # Main reasons for score
    main_reasons: List[str] = []
    if score_deductions:
        for d in score_deductions[:5]:  # Top 5 deductions
            main_reasons.append(d["summary"])
        if len(score_deductions) > 5:
            remaining = len(score_deductions) - 5
            main_reasons.append(f"And {remaining} other finding deduction(s)...")
    else:
        if is_preliminary:
            main_reasons.append(
                "No penalties deducted. Rating is labeled preliminary due to limited scope or incomplete scan."
            )
        else:
            main_reasons.append("No security vulnerabilities detected within evaluated scope.")

    # Prioritized remediation recommendations
    recommendations: List[Dict[str, str]] = []
    seen_rems = set()
    for u in unique_findings:
        if u.remediation and u.remediation not in seen_rems:
            seen_rems.add(u.remediation)
            recommendations.append(
                {
                    "severity": u.severity,
                    "finding_type": u.finding_type,
                    "remediation": u.remediation,
                }
            )

    if not recommendations:
        recommendations.append(
            {
                "severity": "Informational",
                "finding_type": "Proactive Hardening",
                "remediation": "Maintain regular automated audits, implement defense-in-depth security headers, and conduct manual penetration testing for critical workflows.",
            }
        )

    # Target info
    target_obj = _get_val(scan, "target", None)
    target_url = _get_val(target_obj, "base_url", "") or ""
    hostname = _get_val(target_obj, "hostname", "")
    if not hostname and target_url:
        hostname = urlparse(target_url).hostname or target_url

    scan_id = str(_get_val(scan, "id", "") or "")
    started_at = _get_val(scan, "started_at", None)
    completed_at = _get_val(scan, "completed_at", None)
    duration_seconds = None
    if started_at and completed_at and isinstance(started_at, datetime) and isinstance(completed_at, datetime):
        duration_seconds = round((completed_at - started_at).total_seconds(), 1)

    route_summary = _get_val(scan, "route_summary", {}) or {}
    routes_discovered = route_summary.get("routes_discovered", [])
    routes_visited = route_summary.get("routes_visited", [])
    routes_tested = route_summary.get("routes_tested", [])
    routes_failed = route_summary.get("routes_failed", [])
    routes_auth_required = route_summary.get("routes_auth_required", [])

    coverage_limitations = [
        f"Crawl ceiling: max depth {max_depth}, limit {max_urls} URLs.",
        f"Active modules ({len(modules)}): {', '.join(modules) if modules else 'none'}.",
        "Unauthenticated testing: protected user accounts and role-based workflows were not assessed.",
        "ZeroTrace heuristic scoring rules: not an industry-standard compliance certification.",
    ]
    if routes_auth_required:
        coverage_limitations.append(
            f"Authentication required on {len(routes_auth_required)} route(s): {', '.join(routes_auth_required[:5])}. State-changing and authenticated actions were not performed automatically."
        )
    if is_preliminary:
        coverage_limitations.extend(preliminary_reasons)

    coverage_summary = _get_val(scan, "coverage_summary", None)
    if not coverage_summary:
        from app.scanner.engine import ALL_KNOWN_MODULES, MODULE_DISPLAY_NAMES, INPUT_DEPENDENT_MODULES
        mod_set = set(modules or ALL_KNOWN_MODULES)
        matrix = []
        for m in ALL_KNOWN_MODULES:
            reason = ""
            if m not in mod_set:
                status = "Not Tested"
                reason = "Module not selected in scan config"
            elif m == "graphql":
                status = "Not Applicable"
                reason = "No GraphQL endpoint discovered on target"
            elif m in INPUT_DEPENDENT_MODULES:
                if parameters_found > 0:
                    status = "Tested"
                    reason = f"Tested parameters across {urls_scanned} endpoint(s)"
                else:
                    status = "Incomplete"
                    reason = "No eligible input parameters discovered on target"
            else:
                status = "Tested" if urls_scanned > 0 else "Not Tested"
                reason = f"Tested across {urls_scanned} endpoint(s)" if urls_scanned > 0 else "No endpoints scanned"

            matrix.append({
                "module": m,
                "name": MODULE_DISPLAY_NAMES.get(m, m.replace("_", " ").title()),
                "status": status,
                "findings_count": len([
                    f for f in unique_findings
                    if m in f.category.lower() or m.replace("_", " ") in f.finding_type.lower()
                ]),
                "endpoints_tested": urls_scanned if status == "Tested" else 0,
                "parameters_tested": parameters_found if status == "Tested" and m in INPUT_DEPENDENT_MODULES else 0,
                "reason": reason,
            })
        tested_c = sum(1 for item in matrix if item["status"] == "Tested")
        incomplete_c = sum(1 for item in matrix if item["status"] == "Incomplete")
        na_c = sum(1 for item in matrix if item["status"] == "Not Applicable")
        not_t_c = sum(1 for item in matrix if item["status"] == "Not Tested")
        coverage_summary = {
            "modules_total": len(matrix),
            "modules_tested": tested_c,
            "modules_incomplete": incomplete_c,
            "modules_not_tested": not_t_c,
            "modules_not_applicable": na_c,
            "endpoints_discovered": urls_discovered,
            "endpoints_tested": urls_scanned,
            "forms_discovered": route_summary.get("forms_discovered", 0),
            "parameters_discovered": parameters_found,
            "parameters_tested": parameters_found if tested_c > 0 else 0,
            "coverage_percentage": round(100.0 * tested_c / max(1, len(matrix) - na_c), 1),
            "module_matrix": matrix,
        }

    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "hostname": hostname or "unknown",
        "score": score,
        "rating": rating,
        "rating_label": f"{rating} (Preliminary)" if is_preliminary else rating,
        "rating_color": rating_color,
        "is_preliminary": is_preliminary,
        "preliminary_reasons": preliminary_reasons,
        "total_penalty": total_penalty,
        "scan_status": scan_status,
        "raw_counts": raw_counts,
        "unique_counts": unique_counts,
        "confirmed_count": raw_confirmed,
        "manual_verification_count": raw_manual_verification,
        "unique_confirmed_count": unique_confirmed,
        "unique_manual_verification_count": unique_manual_verification,
        "coverage": {
            "urls_scanned": urls_scanned,
            "urls_discovered": urls_discovered,
            "parameters_found": parameters_found,
            "max_depth": max_depth,
            "max_urls": max_urls,
            "modules": modules,
            "duration_seconds": duration_seconds,
            "routes_discovered": routes_discovered,
            "routes_visited": routes_visited,
            "routes_tested": routes_tested,
            "routes_failed": routes_failed,
            "routes_auth_required": routes_auth_required,
            "limitations": coverage_limitations,
            "coverage_summary": coverage_summary,
        },
        "score_deductions": score_deductions,
        "main_reasons": main_reasons,
        "recommendations": recommendations,
        "disclaimer": "These are ZeroTrace's own heuristic scoring rules, not an industry-standard certification.",
    }

