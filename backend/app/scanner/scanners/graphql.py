"""
GraphQL Security scanner module.

Tests if discovered endpoints expose a GraphQL interface and checks whether schema introspection is enabled:
- POST /graphql, /api/graphql with { __schema { types { name } } }
"""
from typing import List, Tuple
from urllib.parse import urljoin

from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import ScanFinding

INTROSPECTION_QUERY = '{"query":"{ __schema { types { name } } }"}'


async def scan(base_url: str, client: SafeHTTPClient) -> Tuple[List[ScanFinding], bool]:
    """
    Returns (findings, is_applicable).
    If GraphQL endpoints are not present (e.g. 404), is_applicable = False.
    """
    findings: List[ScanFinding] = []
    candidate_paths = ["/graphql", "/api/graphql", "/v1/graphql"]
    is_applicable = False

    for path in candidate_paths:
        target_url = urljoin(base_url, path)
        try:
            resp = await client.request(
                "POST",
                target_url,
                headers={"Content-Type": "application/json"},
                content=INTROSPECTION_QUERY,
            )
        except Exception:
            continue

        if resp is None:
            continue

        # If endpoint responded with 200/400 and JSON indicating GraphQL parser presence
        text = resp.text or ""
        if resp.status_code == 200 and "__schema" in text and "types" in text:
            is_applicable = True
            findings.append(ScanFinding(
                type="GraphQL Security Weakness",
                category="Information Disclosure",
                owasp_category="A05:2021 - Security Misconfiguration",
                url=target_url,
                method="POST",
                severity="Medium",
                confidence="Confirmed",
                cwe_id="CWE-200",
                mitre_attack="T1592",
                detection_status="Confirmed",
                evidence=f"GraphQL introspection query succeeded on '{target_url}', returning full schema types.",
                description="The GraphQL API endpoint has introspection enabled in production, exposing the entire data schema, queries, mutations, and field definitions.",
                impact="Attackers can map the entire internal API surface, hidden fields, and relationships to construct targeted exploit queries.",
                remediation="Disable introspection in production environments (e.g. Apollo Server introspection: false).",
            ))
            break
        elif resp.status_code in (200, 400) and ("graphql" in text.lower() or "errors" in text):
            is_applicable = True

    return findings, is_applicable

