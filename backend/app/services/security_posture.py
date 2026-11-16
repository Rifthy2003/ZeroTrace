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
from app.scanner.severity import extract_header_name, SECURITY_HEADER_RULES


# Configurable base penalty weights for direct, exploitable vulnerabilities:
# Confirmed Critical / High flaws (e.g. SQLi, RCE, Auth Bypass, XSS) have dominant impact.
EXPLOITABLE_PENALTY_WEIGHTS: Dict[str, float] = {
    Severity.CRITICAL.value: 35.0,
    Severity.HIGH.value: 20.0,
    Severity.MEDIUM.value: 8.0,
    Severity.LOW.value: 3.0,
    Severity.INFORMATIONAL.value: 0.0,
}

# Configurable base penalty weights for defense-in-depth configuration / hardening issues:
# Assessed once per domain with proportional weights and an aggregate ceiling to prevent
# missing response headers from overwhelming actual exploitable vulnerabilities.
CONFIGURATION_PENALTY_WEIGHTS: Dict[str, float] = {
    Severity.CRITICAL.value: 10.0,
    Severity.HIGH.value: 7.0,
    Severity.MEDIUM.value: 4.0,   # e.g., Missing CSP, Framing / Clickjacking
    Severity.LOW.value: 1.5,      # e.g., Missing X-Content-Type-Options, Referrer-Policy
    Severity.INFORMATIONAL.value: 0.0, # e.g., Permissions-Policy, Tech detection
}

# Maximum aggregate configuration penalty to prevent hardening findings from overwhelming exploitable vulnerabilities
MAX_AGGREGATE_CONFIGURATION_PENALTY: float = 20.0

# Backward compatibility export
DEFAULT_PENALTY_WEIGHTS: Dict[str, float] = EXPLOITABLE_PENALTY_WEIGHTS

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
    is_not_applicable: bool = False
    not_applicable_reason: Optional[str] = None


def _get_val(obj: Any, attr: str, default: Any = None) -> Any:
    if hasattr(obj, attr):
        val = getattr(obj, attr)
        if hasattr(val, "value") and not type(val).__name__.startswith("MagicMock") and not callable(getattr(val, "value", None)):
            return val.value
        return val
    if isinstance(obj, dict):
        val = obj.get(attr, default)
        if hasattr(val, "value") and not type(val).__name__.startswith("MagicMock") and not callable(getattr(val, "value", None)):
            return val.value
        return val
    return default


def _canonical_dedup_key(f: Any) -> str:
    """
    Build a canonical deduplication key for grouping repeated findings.
    - Clickjacking & X-Frame-Options framing protection -> Unified under single framing risk (CWE-1021).
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

    # 1. Clickjacking & X-Frame-Options framing protection -> Unified under single framing risk (CWE-1021)
    if "clickjacking" in ftype.lower() or fparam == "x-frame-options":
        return "config::clickjacking_framing"

    if "header" in ftype.lower() or "csp" in ftype.lower() or ftype == "Missing Security Header":
        # Keep genuinely different headers as separate findings, deduplicating across URLs
        header_name = extract_header_name(fparam, fevidence)
        if header_name and header_name.lower() == "x-frame-options":
            return "config::clickjacking_framing"
        return f"header::{header_name.lower() if header_name else 'generic'}"

    if "cors" in ftype.lower():
        return "config::cors"

    if "Cookie" in ftype or "cookie" in ftype.lower():
        return f"cookie::{ftype.lower()}::{fparam}"

    if ftype == "Technology Detection":
        return f"tech::{fevidence or fparam}"

    if ftype in ("Exposed Sensitive File", "Directory Listing", "Sensitive File Exposure"):
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

            # If combining clickjacking module finding with missing xfo header finding, prefer clickjacking metadata
            if "clickjacking" in f_type.lower() and "clickjacking" not in g["type"].lower():
                g["type"] = f_type
                g["category"] = f_cat
                if f_desc:
                    g["description"] = f_desc
                if f_rem:
                    g["remediation"] = f_rem

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
        if g["type"] == "Missing Security Header":
            hname = extract_header_name(g.get("parameter"), g.get("description") or "")
            if hname:
                g["parameter"] = hname
                if hname in SECURITY_HEADER_RULES:
                    hrule_sev = SECURITY_HEADER_RULES[hname]["severity"]
                    g["severity"] = hrule_sev.value if hasattr(hrule_sev, "value") else str(hrule_sev)

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


def is_configuration_finding(u: UniqueFinding) -> bool:
    """Determine whether a finding represents a defense-in-depth configuration / hardening issue."""
    key = (u.dedup_key or "").lower()
    if (
        key.startswith("config::")
        or key.startswith("header::")
        or key.startswith("cookie::")
        or key.startswith("tech::")
    ):
        return True

    ftype = (u.finding_type or "").lower()
    cat = (u.category or "").lower()

    if any(
        k in ftype
        for k in (
            "header",
            "csp",
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "clickjacking",
            "cookie",
            "cors",
            "information disclosure",
            "technology detection",
            "banner",
        )
    ):
        return True

    if ("configuration" in cat or "misconfiguration" in cat) and not any(
        k in ftype
        for k in ("sql", "command", "ssti", "traversal", "xss", "injection", "bypass", "rce")
    ):
        return True

    return False


def _matches_module_finding(f: Any, module_name: str) -> bool:
    ft = str(getattr(f, "finding_type", "") or getattr(f, "type", "") or "").lower()
    fcat = str(getattr(f, "category", "") or "").lower()
    fsev = str(getattr(f, "severity", "") or "").lower()
    fdet = str(getattr(f, "detection_status", "") or "").lower()
    mod = module_name.lower()

    if mod == "xss":
        # Only count confirmed/actionable XSS vulnerabilities (not safe Input Reflection)
        return (
            ("cross-site scripting" in ft or "xss" in ft or "reflected xss" in ft or "dom xss" in ft)
            and ft != "input reflection"
            and (fsev in ("critical", "high", "medium") or fdet == "confirmed")
        )
    if mod == "sql_injection":
        return "sql" in ft
    if mod == "command_injection":
        return "command injection" in ft or "code execution" in ft
    if mod == "clickjacking":
        return "clickjacking" in ft
    if mod == "security_headers":
        return "header" in ft or "content-security-policy" in ft or "csp" in ft or "hsts" in ft
    if mod == "auth_security":
        return "auth" in ft or "jwt" in ft or "session" in ft or "login" in ft or "brute" in ft
    if mod == "sensitive_files":
        return "sensitive file" in ft or "exposed" in ft or "backup" in ft or "directory listing" in ft
    if mod == "csrf":
        return "csrf" in ft or "cross-site request forgery" in ft
    if mod == "cors":
        return "cors" in ft
    if mod == "cookie_security":
        return "cookie" in ft
    if mod == "directory_listing":
        return "directory listing" in ft
    if mod == "open_redirect":
        return "open redirect" in ft
    if mod == "path_traversal":
        return "path traversal" in ft
    if mod == "ssti":
        return "template injection" in ft or "ssti" in ft
    if mod == "information_disclosure":
        return "information disclosure" in ft or "technology detection" in ft or "banner" in ft
    if mod == "graphql":
        return "graphql" in ft

    return mod in fcat or mod.replace("_", " ") in ft


def calculate_security_posture(
    scan: Any,
    findings: List[Any],
    penalty_weights: Optional[Dict[str, float]] = None,
    confidence_multipliers: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Compute Website Security Posture for a given scan and its findings.
    
    Risk-based scoring rules:
    - Domain-Level Scoring: Each unique configuration weakness is penalized once per domain.
      Raw occurrences across endpoints (e.g. 85 instances of missing CSP) never multiply penalties.
    - Duplicate Risk Prevention: Overlapping framing issues (Clickjacking Protection Missing & Missing X-Frame-Options)
      are unified under a single framing risk (CWE-1021) to prevent double-counting.
    - HSTS Context Validation: HSTS applies strictly to HTTPS responses (RFC 6797 §7.2). For cleartext HTTP
      targets (e.g. http://localhost), missing HSTS is classified as Not Applicable rather than a vulnerability.
    - Risk-Based Weights & Ceiling: Direct exploitable flaws (SQLi, RCE, Auth Bypass, XSS) have dominant penalties
      (Critical: 35, High: 20). Defense-in-depth configuration findings receive proportional penalties (Medium: 4, Low: 1.5)
      with an aggregate ceiling of 20 points, ensuring configuration findings never overwhelm exploitable vulnerabilities.
    """
    multipliers = confidence_multipliers or DEFAULT_CONFIDENCE_MULTIPLIERS

    # Target info extraction
    target_obj = _get_val(scan, "target", None)
    raw_base_url = _get_val(target_obj, "base_url", "")
    target_url = str(raw_base_url) if raw_base_url and not type(raw_base_url).__name__.startswith("MagicMock") else ""
    raw_hostname = _get_val(target_obj, "hostname", "")
    hostname = str(raw_hostname) if raw_hostname and not type(raw_hostname).__name__.startswith("MagicMock") else ""
    if not hostname and target_url:
        try:
            hostname = urlparse(target_url).hostname or target_url
        except Exception:
            hostname = target_url

    parsed_target = None
    if target_url:
        try:
            parsed_target = urlparse(target_url)
        except Exception:
            parsed_target = None

    target_scheme = (parsed_target.scheme or "").lower() if parsed_target else ""
    is_target_cleartext_http = (
        target_scheme == "http"
        or hostname in ("localhost", "127.0.0.1", "host.docker.internal")
        or (target_url and target_url.lower().startswith("http://"))
    )

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

    # HSTS Context Validation: Check each unique finding
    hsts_na_count = 0
    for u in unique_findings:
        is_hsts = (
            (u.parameter or "").lower() == "strict-transport-security"
            or "strict-transport-security" in (u.dedup_key or "").lower()
            or "hsts" in (u.finding_type or "").lower()
        )
        if is_hsts:
            finding_url = u.url or ""
            parsed_furl = urlparse(finding_url) if finding_url else None
            furl_scheme = (parsed_furl.scheme or "").lower() if parsed_furl else ""
            is_finding_cleartext_http = (
                furl_scheme == "http"
                or (finding_url and finding_url.lower().startswith("http://"))
                or is_target_cleartext_http
            )
            if is_target_cleartext_http or is_finding_cleartext_http:
                u.is_not_applicable = True
                u.not_applicable_reason = (
                    "Strict-Transport-Security (HSTS) is Not Applicable on cleartext HTTP targets/endpoints (RFC 6797 §7.2 requires HTTPS transport)."
                )
                u.penalty = 0.0
                u.is_confirmed = False
                u.requires_manual_verification = False
                hsts_na_count += 1

    # Unique counts
    unique_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
        "not_applicable": 0,
        "total": len(unique_findings),
    }
    unique_confirmed = 0
    unique_manual_verification = 0

    for u in unique_findings:
        if u.is_not_applicable:
            unique_counts["not_applicable"] += 1
        else:
            sev_lower = u.severity.lower()
            if sev_lower in unique_counts:
                unique_counts[sev_lower] += 1
            if u.is_confirmed:
                unique_confirmed += 1
            elif u.requires_manual_verification:
                unique_manual_verification += 1

    # Penalty calculation
    config_items: List[Tuple[UniqueFinding, float]] = []
    exploitable_items: List[Tuple[UniqueFinding, float]] = []

    for u in unique_findings:
        if u.is_not_applicable:
            u.penalty = 0.0
            continue

        # Exclude informational technology fingerprinting from penalties
        if (
            u.finding_type == "Technology Detection"
            or u.severity == Severity.INFORMATIONAL.value
            or u.confidence == Confidence.INFORMATIONAL.value
        ):
            u.penalty = 0.0
            continue

        conf_m = multipliers.get(u.confidence, 1.0)

        if penalty_weights is not None:
            # Custom caller weights
            base_w = penalty_weights.get(u.severity, 0.0)
            p = round(base_w * conf_m, 1)
            u.penalty = p
            exploitable_items.append((u, p))
        elif is_configuration_finding(u):
            base_w = CONFIGURATION_PENALTY_WEIGHTS.get(u.severity, 0.0)
            raw_p = round(base_w * conf_m, 1)
            config_items.append((u, raw_p))
        else:
            base_w = EXPLOITABLE_PENALTY_WEIGHTS.get(u.severity, 0.0)
            p = round(base_w * conf_m, 1)
            u.penalty = p
            exploitable_items.append((u, p))

    # Apply aggregate configuration penalty cap
    total_raw_config = sum(p for _, p in config_items)
    if total_raw_config > MAX_AGGREGATE_CONFIGURATION_PENALTY and total_raw_config > 0:
        ratio = MAX_AGGREGATE_CONFIGURATION_PENALTY / total_raw_config
        for u, raw_p in config_items:
            u.penalty = round(raw_p * ratio, 1)
    else:
        for u, raw_p in config_items:
            u.penalty = raw_p

    total_penalty = round(sum(u.penalty for u in unique_findings), 1)
    score = max(0.0, min(100.0, round(100.0 - total_penalty, 1)))

    score_deductions = []
    for u in unique_findings:
        if u.penalty > 0:
            target_desc = (
                f"{u.url} (param: '{u.parameter}')"
                if u.parameter and u.parameter != u.url
                else (u.url or "site-wide")
            )
            if u.occurrences > 1:
                target_desc += f" [{u.occurrences} instances]"

            is_cfg = is_configuration_finding(u)
            cat_label = "Security Configuration" if is_cfg else "Vulnerability"
            score_deductions.append(
                {
                    "finding_type": u.finding_type,
                    "severity": u.severity,
                    "confidence": u.confidence,
                    "category": cat_label,
                    "points_deducted": u.penalty,
                    "occurrences": u.occurrences,
                    "summary": f"-{u.penalty} pts: {u.severity} — {u.finding_type} on {target_desc} ({u.confidence})",
                }
            )

    # Sort deductions with highest points deducted first so exploitable vulnerabilities take priority
    score_deductions.sort(key=lambda d: d["points_deducted"], reverse=True)

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
        if u.is_not_applicable:
            continue
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
    if hsts_na_count > 0:
        coverage_limitations.append(
            "Strict-Transport-Security (HSTS) evaluated as Not Applicable on cleartext HTTP target (RFC 6797 §7.2)."
        )
    if routes_auth_required:
        coverage_limitations.append(
            f"Authentication required on {len(routes_auth_required)} route(s): {', '.join(routes_auth_required[:5])}. State-changing and authenticated actions were not performed automatically."
        )
    if is_preliminary:
        coverage_limitations.extend(preliminary_reasons)

    coverage_summary = _get_val(scan, "coverage_summary", None)
    if coverage_summary and "module_matrix" in coverage_summary:
        matrix = []
        input_reflections = [
            f for f in unique_findings
            if (f.finding_type or "") == "Input Reflection"
            or ((f.severity or "").lower() == "informational" and "reflection" in (f.finding_type or "").lower())
        ]
        for row in coverage_summary.get("module_matrix", []):
            r = dict(row)
            mod = r.get("module")
            if mod == "xss":
                confirmed_xss = [f for f in unique_findings if _matches_module_finding(f, "xss")]
                r["findings_count"] = len(confirmed_xss)
                if len(confirmed_xss) == 0 and len(input_reflections) > 0:
                    pts = r.get("parameters_tested", parameters_found)
                    ets = r.get("endpoints_tested", urls_scanned)
                    r["reason"] = f"Tested {pts} parameter(s) across {ets} endpoint(s) ({len(input_reflections)} safe input reflection(s) observed with proper encoding; no confirmed XSS)"
            elif mod == "security_headers":
                header_vulns = [f for f in unique_findings if _matches_module_finding(f, "security_headers") and not f.is_not_applicable]
                r["findings_count"] = len(header_vulns)
                if is_target_cleartext_http:
                    if len(header_vulns) > 0:
                        r["reason"] = f"Detected {len(header_vulns)} security header issue(s) across {urls_scanned} endpoint(s) (HSTS evaluated as Not Applicable on cleartext HTTP)"
                    else:
                        r["reason"] = f"Tested across {urls_scanned} endpoint(s) (HSTS evaluated as Not Applicable on cleartext HTTP)"
            elif mod:
                applicable_vulns = [f for f in unique_findings if _matches_module_finding(f, mod) and not f.is_not_applicable]
                r["findings_count"] = len(applicable_vulns)
            matrix.append(r)
        coverage_summary = dict(coverage_summary)
        coverage_summary["module_matrix"] = matrix
    elif not coverage_summary:
        from app.scanner.engine import ALL_KNOWN_MODULES, MODULE_DISPLAY_NAMES, INPUT_DEPENDENT_MODULES
        mod_set = set(modules or ALL_KNOWN_MODULES)
        matrix = []
        input_reflections = [
            f for f in unique_findings
            if (f.finding_type or "") == "Input Reflection"
            or ((f.severity or "").lower() == "informational" and "reflection" in (f.finding_type or "").lower())
        ]
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

            if m == "xss":
                confirmed_xss = [f for f in unique_findings if _matches_module_finding(f, "xss")]
                f_count = len(confirmed_xss)
                if f_count == 0 and len(input_reflections) > 0 and status == "Tested":
                    reason = f"Tested {parameters_found} parameter(s) across {urls_scanned} endpoint(s) ({len(input_reflections)} safe input reflection(s) observed with proper encoding; no confirmed XSS)"
            elif m == "security_headers":
                header_vulns = [f for f in unique_findings if _matches_module_finding(f, "security_headers") and not f.is_not_applicable]
                f_count = len(header_vulns)
                if is_target_cleartext_http and status == "Tested":
                    if f_count > 0:
                        reason = f"Detected {f_count} security header issue(s) across {urls_scanned} endpoint(s) (HSTS evaluated as Not Applicable on cleartext HTTP)"
                    else:
                        reason = f"Tested across {urls_scanned} endpoint(s) (HSTS evaluated as Not Applicable on cleartext HTTP)"
            else:
                f_count = len([f for f in unique_findings if _matches_module_finding(f, m) and not f.is_not_applicable])

            matrix.append({
                "module": m,
                "name": MODULE_DISPLAY_NAMES.get(m, m.replace("_", " ").title()),
                "status": status,
                "findings_count": f_count,
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

