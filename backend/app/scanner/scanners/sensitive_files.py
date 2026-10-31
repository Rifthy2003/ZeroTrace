"""
Conservative check for commonly-exposed configuration, backup, and debug files.
Only probes a small, fixed list of high-value targets — does not brute force.
Secrets found in any response are redacted before storage.

Includes strict validation against generic HTTP 200 SPA fallback pages
(e.g., Flutter Web, React, Vue, Vite, Next.js catch-all routes).
Validates file-specific evidence, content-types, magic headers, and
fallback-page similarity before creating a finding.
"""
import difflib
import re
from typing import List, Optional
from urllib.parse import urljoin

from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import ScanFinding

CANDIDATE_PATHS = {
    ".env": "Environment/configuration file",
    ".git/config": "Source control configuration artifact",
    "config.php.bak": "Backup file",
    "backup.zip": "Backup file",
    "wp-config.php.bak": "Backup file",
    "debug.log": "Debug/log file",
    ".DS_Store": "Accidental filesystem artifact",
    "web.config.bak": "Backup file",
}

SECRET_RE = re.compile(r"(?i)(password|secret|api[_-]?key|token)\s*[:=]\s*\S+")


def _redact(text: str) -> str:
    return SECRET_RE.sub(lambda m: m.group(0).split("=")[0].split(":")[0] + "=[REDACTED]", text)


def _is_html_content(content_type: str, body_text: str) -> bool:
    """Return True if the response is an HTML page (common in SPA catch-all fallbacks)."""
    if "text/html" in content_type:
        return True
    snippet = body_text[:400].lower().strip()
    return (
        snippet.startswith("<!doctype html")
        or snippet.startswith("<html")
        or "<head>" in snippet
        or "<body" in snippet
    )


def _validate_file_evidence(path: str, response) -> bool:
    """
    Validate that the response contains authentic file-specific structure
    and is not a generic HTML fallback page.
    """
    content_type = (response.headers.get("content-type") or "").lower()
    body_text = response.text or ""
    content_bytes = response.content or b""
    is_html = _is_html_content(content_type, body_text)

    if path == ".env":
        if is_html:
            return False
        # Environment files have KEY=VALUE declarations
        env_pattern = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*.+", re.MULTILINE)
        matches = env_pattern.findall(body_text)
        return len(matches) >= 1

    if path == ".git/config":
        if is_html:
            return False
        return "[core]" in body_text or "repositoryformatversion" in body_text or "[remote " in body_text

    if path in ("config.php.bak", "wp-config.php.bak"):
        return "<?php" in body_text or "define(" in body_text or "$_CONFIG" in body_text or "$db" in body_text

    if path == "backup.zip":
        if is_html:
            return False
        # ZIP magic numbers: PK\x03\x04 or PK\x05\x06
        return content_bytes.startswith(b"PK\x03\x04") or content_bytes.startswith(b"PK\x05\x06")

    if path == "debug.log":
        if is_html:
            return False
        log_patterns = [
            r"\[\d{4}-\d{2}-\d{2}",
            r"\[(INFO|DEBUG|WARN|WARNING|ERROR|FATAL|CRITICAL)\]",
            r"Stack trace:",
            r"Traceback \(most recent call last\):",
            r"\bException\b:",
        ]
        return any(re.search(pat, body_text) for pat in log_patterns)

    if path == ".DS_Store":
        if is_html:
            return False
        return b"\x00\x00\x00\x01Bud1" in content_bytes[:32] or (
            len(content_bytes) >= 16 and b"\x00\x00" in content_bytes[:8]
        )

    if path == "web.config.bak":
        return "<configuration>" in body_text or "<system.webServer>" in body_text

    return not is_html


def _is_spa_fallback_match(
    response,
    canary_bytes: Optional[bytes],
    canary_text: Optional[str],
    root_bytes: Optional[bytes],
    root_text: Optional[str],
) -> bool:
    """
    Check if a candidate response matches an SPA catch-all fallback page.
    """
    content = response.content or b""
    text = response.text or ""

    # Exact byte match to canary or root fallback
    if canary_bytes and content == canary_bytes:
        return True
    if root_bytes and content == root_bytes:
        return True

    # High text similarity (> 85%) to canary or root page
    if canary_text and len(text) > 0 and len(canary_text) > 0:
        ratio = difflib.SequenceMatcher(None, text[:3000], canary_text[:3000]).ratio()
        if ratio > 0.85:
            return True

    if root_text and len(text) > 0 and len(root_text) > 0:
        ratio = difflib.SequenceMatcher(None, text[:3000], root_text[:3000]).ratio()
        if ratio > 0.85:
            return True

    return False


async def scan(base_url: str, client: SafeHTTPClient) -> List[ScanFinding]:
    findings: List[ScanFinding] = []

    # 1. Establish baseline responses: probe root and a known nonexistent canary path
    # to detect SPA catch-all routers that return HTTP 200 for any path.
    canary_url = urljoin(base_url, "__zerotrace_fallback_canary_404__")
    canary_resp = await client.get(canary_url)
    root_resp = await client.get(base_url)

    canary_bytes = canary_resp.content if (canary_resp and canary_resp.status_code == 200) else None
    canary_text = canary_resp.text if (canary_resp and canary_resp.status_code == 200) else None
    root_bytes = root_resp.content if (root_resp and root_resp.status_code == 200) else None
    root_text = root_resp.text if (root_resp and root_resp.status_code == 200) else None

    for path, category in CANDIDATE_PATHS.items():
        url = urljoin(base_url, path)
        response = await client.get(url)
        if response is None or response.status_code != 200:
            continue

        if len(response.content) == 0:
            continue

        # 2. Check for SPA catch-all fallback similarity
        if _is_spa_fallback_match(response, canary_bytes, canary_text, root_bytes, root_text):
            continue

        # 3. Validate file-specific evidence and structure
        if not _validate_file_evidence(path, response):
            continue

        snippet = _redact(response.text[:500])
        findings.append(
            ScanFinding(
                type="Sensitive File Exposure",
                category="Security Misconfiguration",
                owasp_category="A05:2021 - Security Misconfiguration",
                url=url,
                method="GET",
                severity="High",
                confidence="Medium confidence",
                evidence=f"HTTP {response.status_code} returned with valid file structure for {path} ({category}). Snippet (redacted): {snippet[:200]}",
                description=f"A {category.lower()} appears to be publicly accessible at this path.",
                impact="May expose credentials, source code, or internal configuration to unauthenticated users.",
                remediation=f"Remove or restrict access to {path}; ensure build/deploy processes do not ship it publicly.",
            )
        )

    return findings
