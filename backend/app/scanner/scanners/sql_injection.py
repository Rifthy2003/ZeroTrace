"""
Safe, indicator-based SQL injection detection. Uses only non-destructive
inputs (a single quote and boolean-style comparisons), compares against a
baseline, and requires multiple indicators before raising confidence.
"""
import re
from typing import List
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import DiscoveredEndpoint, ScanFinding

SQL_ERRORS = [
    r"you have an error in your sql syntax", r"warning: mysql", r"unclosed quotation mark",
    r"quoted string not properly terminated", r"sqlite3?\.operationalerror", r"sqlstate\[",
    r"pg_query\(\)", r"psycopg2\.errors", r"ora-\d{5}", r"syntax error at or near",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERRORS), re.I)


def _set_param(url, name, value):
    p = urlparse(url)
    q = dict(parse_qsl(p.query))
    q[name] = value
    return urlunparse(p._replace(query=urlencode(q)))


async def scan(endpoint: DiscoveredEndpoint, client: SafeHTTPClient) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    for param in [p for p in endpoint.parameters if p.location == "query"]:
        base_value = param.sample_value or "1"
        baseline = await client.get(_set_param(endpoint.url, param.name, base_value))
        if baseline is None:
            continue

        indicators: List[str] = []

        # Indicator 1: error message after a single quote
        quote_resp = await client.get(_set_param(endpoint.url, param.name, base_value + "'"))
        if quote_resp is not None:
            if SQL_ERROR_RE.search(quote_resp.text) and not SQL_ERROR_RE.search(baseline.text):
                indicators.append("Database error message appeared after adding a single quote.")
            elif quote_resp.status_code >= 500 > baseline.status_code:
                indicators.append("Server error (5xx) triggered by a single quote.")

        # Indicator 2: boolean-style behaviour difference (true vs false condition)
        true_resp = await client.get(_set_param(endpoint.url, param.name, f"{base_value} AND 1=1"))
        false_resp = await client.get(_set_param(endpoint.url, param.name, f"{base_value} AND 1=2"))
        if true_resp is not None and false_resp is not None:
            similar_true = abs(len(true_resp.text) - len(baseline.text)) < 20
            differs_false = abs(len(false_resp.text) - len(baseline.text)) > 20
            if similar_true and differs_false:
                indicators.append("Response matched baseline for a true condition but differed for a false condition.")

        if not indicators:
            continue

        if len(indicators) >= 2:
            confidence, severity = "High confidence", "High"
        else:
            confidence, severity = "Medium confidence", "High"

        findings.append(ScanFinding(
            type="SQL Injection", category="Injection",
            owasp_category="A03:2021 - Injection",
            url=endpoint.url, method="GET", parameter=param.name,
            severity=severity, confidence=confidence,
            evidence=" ".join(indicators),
            description="The parameter's behavior suggests user input may be interpreted as part of a SQL query.",
            impact="Could allow reading or modifying database contents depending on the application and privileges.",
            remediation="Use parameterized queries/prepared statements, validate input, and run the database account with least privilege.",
        ))
    return findings
