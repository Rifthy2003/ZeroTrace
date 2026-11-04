"""
Scope and safety enforcement engine for ZeroTrace scans.
Enforces program authorizations, domain boundaries, out-of-scope rules,
rate limits, and module permissions.
"""
from __future__ import annotations

import fnmatch
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

ALL_KNOWN_MODULES: List[str] = [
    "security_headers",
    "cookie_security",
    "directory_listing",
    "sensitive_files",
    "information_disclosure",
    "csrf",
    "xss",
    "sql_injection",
    "open_redirect",
    "command_injection",
    "ssti",
    "path_traversal",
    "cors",
    "clickjacking",
    "auth_security",
    "graphql",
]


PASSIVE_MODULES: Set[str] = {
    "security_headers",
    "cookie_security",
    "information_disclosure",
    "directory_listing",
}

QUICK_SCAN_MODULES: List[str] = [
    "sql_injection",
    "xss",
    "clickjacking",
    "command_injection",
]


def _normalize_host(hostname: str) -> str:
    if not hostname:
        return ""
    h = hostname.lower().strip()
    if ":" in h:
        h = h.split(":")[0]
    return h


def match_domain(host: str, pattern: str) -> bool:
    """Matches host against pattern, supporting wildcards like *.example.com."""
    host = _normalize_host(host)
    pat = _normalize_host(pattern)

    if host == pat:
        return True

    if pat.startswith("*."):
        suffix = pat[2:]
        return host == suffix or host.endswith("." + suffix)

    if fnmatch.fnmatch(host, pat):
        return True

    return False


def validate_url_in_scope(
    url: str,
    base_url: str = "",
    target_domains: Optional[List[str]] = None,
    url_patterns: Optional[List[str]] = None,
    out_of_scope_paths: Optional[List[str]] = None,
) -> Tuple[bool, str]:
    """
    Validates that a URL is strictly within the authorized scope of testing.
    Never allows requests to out-of-scope domains or forbidden path patterns.
    """
    if isinstance(base_url, list):
        out_of_scope_paths = url_patterns
        url_patterns = target_domains
        target_domains = base_url
        base_url = ""

    if not url:
        return False, "Empty URL"

    parsed = urlparse(url)
    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        return False, f"Unsupported URL scheme: {parsed.scheme}"

    url_host = _normalize_host(parsed.hostname or "")
    parsed_base = urlparse(base_url) if base_url else None
    base_host = _normalize_host(parsed_base.hostname or "") if parsed_base else ""

    # Domain authorization check
    if target_domains and len(target_domains) > 0:
        in_domain = any(match_domain(url_host, td) for td in target_domains)
        if not in_domain and (not base_host or url_host != base_host):
            return False, f"Host '{url_host}' is outside authorized target domains {target_domains}"
    else:
        # Default strict scope: must match base URL host
        if url_host != base_host:
            return False, f"Host '{url_host}' does not match target host '{base_host}'"

    # Out-of-scope path checks
    path = parsed.path or "/"
    if parsed.query:
        path_with_query = f"{path}?{parsed.query}"
    else:
        path_with_query = path

    if out_of_scope_paths:
        for forbidden in out_of_scope_paths:
            if not forbidden:
                continue
            f_clean = forbidden.strip()
            if fnmatch.fnmatch(path, f_clean) or fnmatch.fnmatch(path_with_query, f_clean):
                return False, f"Path '{path}' matches out-of-scope rule: {forbidden}"
            if f_clean.startswith("/") and path.startswith(f_clean.rstrip("*")):
                return False, f"Path '{path}' matches out-of-scope prefix: {forbidden}"

    # Allowed URL pattern checks (if specified)
    if url_patterns and len(url_patterns) > 0:
        matched_any = False
        for pat in url_patterns:
            if not pat:
                continue
            if fnmatch.fnmatch(url, pat) or fnmatch.fnmatch(path, pat):
                matched_any = True
                break
            try:
                if re.search(pat, url):
                    matched_any = True
                    break
            except re.error:
                pass
        if not matched_any:
            return False, f"URL '{url}' does not match any required scope patterns {url_patterns}"

    return True, "URL is authorized in-scope"


def compute_effective_scan_config(
    profile: Any = None,
    program: Any = None,
    user_overrides: Optional[Dict[str, Any]] = None,
    profile_data: Optional[Dict[str, Any]] = None,
    program_data: Optional[Dict[str, Any]] = None,
    user_modules: Optional[List[str]] = None,
    user_depth: Optional[int] = None,
    user_max_urls: Optional[int] = None,
    user_delay: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Computes effective scan execution settings by intersecting user configuration,
    profile limits, and program restrictions. Strict program safety always overrides.
    """
    def _to_dict(obj: Any) -> Optional[Dict[str, Any]]:
        if obj is None:
            return None
        if isinstance(obj, dict):
            return obj
        res = {}
        for k in (
            "name", "modules", "send_payloads", "max_depth", "max_urls",
            "request_rate", "concurrency", "rate_limit", "target_domains",
            "url_patterns", "out_of_scope_paths", "allowed_modules",
            "prohibited_modules", "max_requests_per_second", "max_concurrency",
            "allow_automated_scanning"
        ):
            if hasattr(obj, k):
                res[k] = getattr(obj, k)
        return res

    p_data = profile_data or _to_dict(profile)
    pr_data = program_data or _to_dict(program)

    if user_overrides:
        if "modules" in user_overrides and user_overrides["modules"] is not None:
            user_modules = user_overrides["modules"]
        if "max_depth" in user_overrides and user_overrides["max_depth"] is not None:
            user_depth = user_overrides["max_depth"]
        if "max_urls" in user_overrides and user_overrides["max_urls"] is not None:
            user_max_urls = user_overrides["max_urls"]
        if "request_delay" in user_overrides and user_overrides["request_delay"] is not None:
            user_delay = user_overrides["request_delay"]

    effective_restrictions: Dict[str, Any] = {
        "dropped_modules": [],
        "rate_limit_capped": False,
        "concurrency_capped": False,
        "scope_rules_applied": False,
    }

    # If program prohibits automated scanning, block scan
    if pr_data and not pr_data.get("allow_automated_scanning", True):
        raise ValueError(
            f"Automated scanning is prohibited by program '{pr_data.get('name', 'Program')}'. "
            "Manual review or responsible disclosure only."
        )

    # 1. Determine base modules
    if user_modules is not None and len(user_modules) > 0:
        initial_modules = list(user_modules)
    elif p_data and p_data.get("modules"):
        initial_modules = list(p_data["modules"])
    else:
        initial_modules = list(ALL_KNOWN_MODULES)

    # 1b. Quick Scan module constraint:
    # Ensure Quick Scan strictly executes only its required modules:
    # SQL Injection, Cross-Site Scripting (XSS), Clickjacking, and Command Injection.
    # Security Headers, Information Disclosure, CSRF, and other deep-scanning modules are dropped.
    is_quick_scan = (
        (p_data and p_data.get("name") == "Quick Scan")
        or (user_overrides and str(user_overrides.get("scan_type", "")).strip().lower() == "quick scan")
    )
    if is_quick_scan:
        quick_allowed = set(p_data.get("modules") if (p_data and p_data.get("modules")) else QUICK_SCAN_MODULES)
        dropped_for_quick = [m for m in initial_modules if m not in quick_allowed]
        if dropped_for_quick:
            effective_restrictions["dropped_modules"].extend(
                [f"{m} (Disabled in Quick Scan - available in Full Scan)" for m in dropped_for_quick]
            )
        initial_modules = [m for m in initial_modules if m in quick_allowed]

    # 2. Passive scan constraint
    send_payloads = True
    if p_data and not p_data.get("send_payloads", True):
        send_payloads = False
        non_passive = [m for m in initial_modules if m not in PASSIVE_MODULES]
        if non_passive:
            effective_restrictions["dropped_modules"].extend(
                [f"{m} (Not Applicable in Passive Scan - no payloads permitted)" for m in non_passive]
            )
        initial_modules = [m for m in initial_modules if m in PASSIVE_MODULES]

    # 3. Program restrictions
    if pr_data:
        effective_restrictions["scope_rules_applied"] = True

        allowed_p_mods = pr_data.get("allowed_modules") or []
        if allowed_p_mods:
            disallowed = [m for m in initial_modules if m not in allowed_p_mods]
            if disallowed:
                effective_restrictions["dropped_modules"].extend(
                    [f"{m} (Disallowed by program policy)" for m in disallowed]
                )
            initial_modules = [m for m in initial_modules if m in allowed_p_mods]

        prohibited_p_mods = pr_data.get("prohibited_modules") or []
        if prohibited_p_mods:
            blocked = [m for m in initial_modules if m in prohibited_p_mods]
            if blocked:
                effective_restrictions["dropped_modules"].extend(
                    [f"{m} (Explicitly prohibited by program)" for m in blocked]
                )
            initial_modules = [m for m in initial_modules if m not in prohibited_p_mods]

    # 4. Limits: Depth, URLs, Rate limit
    depth = user_depth or (p_data.get("max_depth") if p_data else 2) or 2
    if pr_data and pr_data.get("max_depth"):
        depth = min(depth, pr_data["max_depth"])

    max_urls = user_max_urls or (p_data.get("max_urls") if p_data else 50) or 50
    if pr_data and pr_data.get("max_urls"):
        max_urls = min(max_urls, pr_data["max_urls"])

    # Concurrency and Rate limit
    rate_limit = p_data.get("request_rate", 5.0) if p_data else 5.0
    if user_delay is not None and user_delay > 0:
        user_rate = 1.0 / user_delay
        rate_limit = min(rate_limit, user_rate)

    if pr_data and pr_data.get("max_requests_per_second"):
        p_rate = float(pr_data["max_requests_per_second"])
        if p_rate < rate_limit:
            rate_limit = p_rate
            effective_restrictions["rate_limit_capped"] = True

    concurrency = p_data.get("concurrency", 2) if p_data else 2
    if pr_data and pr_data.get("max_concurrency"):
        p_conc = int(pr_data["max_concurrency"])
        if p_conc < concurrency:
            concurrency = p_conc
            effective_restrictions["concurrency_capped"] = True

    request_delay = round(1.0 / max(0.1, rate_limit), 3)

    return {
        "modules": initial_modules,
        "effective_modules": initial_modules,
        "depth": depth,
        "max_depth": depth,
        "max_urls": max_urls,
        "concurrency": concurrency,
        "request_rate": rate_limit,
        "request_delay": request_delay,
        "send_payloads": send_payloads,
        "effective_restrictions": effective_restrictions,
    }
