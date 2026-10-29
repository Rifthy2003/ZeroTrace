"""
Conservative check for a small, well-known list of commonly-exposed
configuration/backup/debug files. Only probes this fixed list — does not
brute-force. Secrets found in any response are redacted before storage.
"""
import re
from typing import List
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


async def scan(base_url: str, client: SafeHTTPClient) -> List[ScanFinding]:
    findings: List[ScanFinding] = []

    for path, category in CANDIDATE_PATHS.items():
        url = urljoin(base_url, path)
        response = await client.get(url)
        if response is None or response.status_code != 200:
            continue

        # Avoid false positives from catch-all pages that return 200 for everything.
        if len(response.content) == 0:
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
                evidence=f"HTTP {response.status_code} returned for {path} ({category}). Snippet (redacted): {snippet[:200]}",
                description=f"A {category.lower()} appears to be publicly accessible at this path.",
                impact="May expose credentials, source code, or internal configuration to unauthenticated users.",
                remediation=f"Remove or restrict access to {path}; ensure build/deploy processes do not ship it publicly.",
            )
        )

    return findings
