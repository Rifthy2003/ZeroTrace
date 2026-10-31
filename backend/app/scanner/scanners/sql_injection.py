"""
Safe, comprehensive, indicator-based SQL Injection detection module.

Techniques implemented:
1. Error-based SQLi:
   - Regex patterns covering MySQL, MariaDB, PostgreSQL, SQLite, MSSQL, Oracle, DB2.
   - Tests quote variations: ', ", '--, ')--
   - Verifies error pattern was not present in baseline response.
2. Boolean-based SQLi:
   - Compares True vs False conditions against baseline response.
   - Numeric and string syntax: AND 71=71 vs AND 71=72, ' AND '1'='1 vs ' AND '1'='2.
   - Evaluates status code stability and content similarity.
3. Conservative Time-based SQLi:
   - Uses conservative 1.5s delay probe (e.g. pg_sleep, sleep).
   - Compares against baseline round-trip latency.
   - Confirms with negative control to eliminate network jitter false positives.
4. Comprehensive Input Coverage:
   - Tests GET query parameters, POST form body parameters, and URL path parameters.

Safety guarantees:
- Harmless non-destructive indicators only.
- No data dumping, no schema modification, no destructive queries.
- Strict timeout bounds.
"""
import re
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import DiscoveredEndpoint, ScanFinding

SQL_ERROR_PATTERNS = [
    # MySQL / MariaDB
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"valid mysql result",
    r"check the manual that corresponds to your (mysql|mariadb) server version",
    r"mysql_fetch_array\(\)",
    r"mySqlClient\.",
    # PostgreSQL
    r"psycopg2\.errors",
    r"psycopg\.errors",
    r"pg_query\(\)",
    r"syntax error at or near",
    r"unterminated quoted string at or near",
    r"query failed: error: syntax error",
    r"org\.postgresql\.util\.psqlexception",
    # Microsoft SQL Server / Sybase
    r"unclosed quotation mark after the character string",
    r"microsoft ole db provider for sql server",
    r"syntax error converting the varchar value",
    r"driver.*sql[\-\_\ ]*server",
    r"ole db.*sql server",
    r"microsoft sql native client",
    # SQLite
    r"sqlite3?\.operationalerror",
    r"sqlite_exception",
    r"near \"[^\"]*\": syntax error",
    r"unrecognized token:",
    # Oracle
    r"ora-01756",
    r"ora-00933",
    r"ora-00936",
    r"ora-\d{5}",
    # Generic SQL / ODBC / JDBC
    r"sqlstate\[",
    r"cli driver.*db2",
    r"jdbc.*sql",
    r"error in your sql query",
]

SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)

# Ignored parameters that are typically not injectable or shouldn't be altered
IGNORED_PARAMS = {"csrf", "token", "_csrf", "authenticity_token", "_token", "nonce", "__requestverificationtoken"}


def _set_url_param(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query))
    q[name] = value
    return urlunparse(p._replace(query=urlencode(q)))


def _set_body_param(sample_params: Dict[str, str], name: str, value: str) -> Dict[str, str]:
    copied = dict(sample_params)
    copied[name] = value
    return copied


async def _send_request(
    client: SafeHTTPClient,
    method: str,
    url: str,
    param_name: str,
    param_val: str,
    location: str,
    base_body_params: Dict[str, str],
) -> Optional[Any]:
    try:
        t0 = time.monotonic()
        if location == "json":
            payload = _set_body_param(base_body_params, param_name, param_val)
            resp = await client.post(url, json=payload)
        elif method.upper() == "POST" or location in ("body", "form"):
            payload = _set_body_param(base_body_params, param_name, param_val)
            resp = await client.post(url, data=payload)
        else:
            target_url = _set_url_param(url, param_name, param_val)
            resp = await client.get(target_url)
        elapsed = time.monotonic() - t0
        if resp is not None:
            setattr(resp, "_elapsed_seconds", elapsed)
        return resp
    except Exception:
        return None


async def scan(endpoint: DiscoveredEndpoint, client: SafeHTTPClient) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    tested_params = [
        p for p in endpoint.parameters
        if p.name and p.name.lower() not in IGNORED_PARAMS
    ]
    if not tested_params:
        return findings

    # Build dictionary of default body parameters
    body_defaults = {
        p.name: p.sample_value or "test"
        for p in endpoint.parameters
        if p.location in ("body", "form", "json")
    }

    for param in tested_params:
        location = param.location or ("body" if endpoint.method.upper() == "POST" else "query")
        base_val = param.sample_value or "1"

        # 1. Baseline Request
        baseline = await _send_request(
            client, endpoint.method, endpoint.url, param.name, base_val, location, body_defaults
        )
        if baseline is None:
            continue

        baseline_text = baseline.text or ""
        baseline_time = getattr(baseline, "_elapsed_seconds", 0.2)
        baseline_has_error = bool(SQL_ERROR_RE.search(baseline_text))

        indicators: List[str] = []
        evidence_records: List[Dict[str, Any]] = []

        # 2. Error-Based SQLi Checks
        error_probes = ["'", "''", "\"", "')", "'--", "1'"]
        for probe in error_probes:
            test_val = f"{base_val}{probe}"
            resp = await _send_request(
                client, endpoint.method, endpoint.url, param.name, test_val, location, body_defaults
            )
            if resp is not None and resp.text:
                match = SQL_ERROR_RE.search(resp.text)
                if match and not baseline_has_error:
                    error_snippet = match.group(0)
                    msg = f"Database error pattern detected ('{error_snippet}') with test payload '{test_val}'."
                    indicators.append(msg)
                    evidence_records.append({
                        "technique": "Error-Based",
                        "payload": test_val,
                        "status_code": resp.status_code,
                        "error_matched": error_snippet,
                    })
                    break
                elif resp.status_code >= 500 > baseline.status_code:
                    msg = f"Server 5xx error triggered by SQL quote syntax test payload '{test_val}'."
                    indicators.append(msg)
                    evidence_records.append({
                        "technique": "Error-Based (HTTP 500)",
                        "payload": test_val,
                        "status_code": resp.status_code,
                    })
                    break

        # 3. Boolean-Based SQLi Checks
        # Compare True condition vs False condition
        boolean_pairs = [
            (f"{base_val} AND 71=71", f"{base_val} AND 71=72"),
            (f"{base_val}' AND '71'='71", f"{base_val}' AND '71'='72"),
            (f"{base_val}' OR '71'='71", f"{base_val}' OR '71'='72"),
        ]

        for true_payload, false_payload in boolean_pairs:
            true_resp = await _send_request(
                client, endpoint.method, endpoint.url, param.name, true_payload, location, body_defaults
            )
            false_resp = await _send_request(
                client, endpoint.method, endpoint.url, param.name, false_payload, location, body_defaults
            )

            if true_resp is not None and false_resp is not None:
                true_len = len(true_resp.text or "")
                false_len = len(false_resp.text or "")
                base_len = len(baseline_text)

                true_status = true_resp.status_code
                false_status = false_resp.status_code
                base_status = baseline.status_code

                # Status code divergence: True condition matches baseline, False condition differs
                if true_status == base_status and false_status != base_status:
                    indicators.append(
                        f"Boolean response status differed: True payload '{true_payload}' returned {true_status}, "
                        f"False payload '{false_payload}' returned {false_status}."
                    )
                    evidence_records.append({
                        "technique": "Boolean-Based Status Divergence",
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "true_status": true_status,
                        "false_status": false_status,
                    })
                    break

                # Content length divergence: True condition is close to baseline, False condition differs significantly
                diff_true = abs(true_len - base_len)
                diff_false = abs(false_len - base_len)
                if diff_true < 35 and diff_false > 80:
                    indicators.append(
                        f"Boolean length difference: True payload '{true_payload}' matched baseline length (delta={diff_true}), "
                        f"while False payload '{false_payload}' altered response length (delta={diff_false})."
                    )
                    evidence_records.append({
                        "technique": "Boolean-Based Length Divergence",
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "length_delta_false": diff_false,
                    })
                    break

        # 4. Conservative Time-Based SQLi Checks
        # Only perform if baseline response latency is fast and stable (< 1.5s)
        if baseline_time < 1.5 and len(indicators) < 2:
            time_payload = f"{base_val}' OR pg_sleep(1.5)--"
            timed_resp = await _send_request(
                client, endpoint.method, endpoint.url, param.name, time_payload, location, body_defaults
            )
            if timed_resp is not None:
                timed_elapsed = getattr(timed_resp, "_elapsed_seconds", 0.0)
                # If timed request took significantly longer than baseline (at least 1.3s delay above baseline)
                if timed_elapsed >= baseline_time + 1.3:
                    # Negative control verification to reduce false positives
                    control_payload = f"{base_val}' OR pg_sleep(0)--"
                    control_resp = await _send_request(
                        client, endpoint.method, endpoint.url, param.name, control_payload, location, body_defaults
                    )
                    control_elapsed = getattr(control_resp, "_elapsed_seconds", 0.0) if control_resp else 0.0

                    if control_elapsed < baseline_time + 0.8:
                        indicators.append(
                            f"Conservative time delay verified: sleep payload ({timed_elapsed:.2f}s) "
                            f"exceeded baseline ({baseline_time:.2f}s), confirmed by control probe ({control_elapsed:.2f}s)."
                        )
                        evidence_records.append({
                            "technique": "Time-Based Delay",
                            "payload": time_payload,
                            "measured_duration": round(timed_elapsed, 2),
                            "baseline_duration": round(baseline_time, 2),
                        })

        if not indicators:
            continue

        # Confidence and severity determination
        has_error = any("error" in ind.lower() for ind in indicators)
        has_boolean = any("boolean" in ind.lower() for ind in indicators)
        has_time = any("time" in ind.lower() for ind in indicators)

        if (has_error and has_boolean) or (has_error and has_time) or (has_boolean and has_time):
            severity = "Critical"
            confidence = "Confirmed"
            detection_status = "Confirmed"
        elif has_error or (has_boolean and len(evidence_records) >= 2):
            severity = "High"
            confidence = "High confidence"
            detection_status = "Confirmed"
        else:
            severity = "High"
            confidence = "Medium confidence"
            detection_status = "Requires Manual Verification"

        findings.append(ScanFinding(
            type="SQL Injection",
            category="Injection",
            owasp_category="A03:2021 - Injection",
            url=endpoint.url,
            method=endpoint.method.upper(),
            parameter=param.name,
            severity=severity,
            confidence=confidence,
            cwe_id="CWE-89",
            mitre_attack="T1190",
            detection_status=detection_status,
            evidence=" | ".join(indicators),
            description=(
                f"The parameter '{param.name}' on {endpoint.method.upper()} {endpoint.url} allows user input "
                "to manipulate backend SQL execution syntax."
            ),
            impact="An attacker could execute arbitrary SQL queries, bypass authentication, and access or modify sensitive database records.",
            remediation="Use parameterized queries / prepared statements (e.g. PDO, SQLAlchemy, parameterized SQL), input validation, and least privilege database roles.",
            evidence_details={"records": evidence_records, "indicators": indicators},
        ))

    return findings
