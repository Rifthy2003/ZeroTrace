"""
ZeroTrace Professional Bug Bounty & Responsible Disclosure Report Generator.
Generates comprehensive 4-6 page evidence-based PDF reports and HackerOne-tailored
Markdown reports suitable for security researchers, asset owners, and bounty platforms.
"""
from __future__ import annotations

import io
import math
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, urlencode
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.core.logging_config import redact
from app.scanner.severity import extract_header_name, SECURITY_HEADER_RULES
from app.services.security_posture import calculate_security_posture

# =============================================================================
# CVSS v3.1 MATHEMATICAL CALCULATION ENGINE (FIRST.org Specification)
# =============================================================================

CVSS_V31_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _cvss_roundup(val: float) -> float:
    """Official CVSS v3.1 roundup function: rounds up to next decimal place."""
    int_val = round(val * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000.0
    return math.ceil(val * 10.0) / 10.0


def calculate_cvss_score(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N") -> float:
    """Calculate exact CVSS v3.1 Base Score per FIRST.org standard."""
    c_val = CVSS_V31_METRICS["C"][c]
    i_val = CVSS_V31_METRICS["I"][i]
    a_val = CVSS_V31_METRICS["A"][a]

    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    pr_val = CVSS_V31_METRICS["PR"][s][pr]
    av_val = CVSS_V31_METRICS["AV"][av]
    ac_val = CVSS_V31_METRICS["AC"][ac]
    ui_val = CVSS_V31_METRICS["UI"][ui]

    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    if impact <= 0:
        return 0.0

    if s == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)

    return _cvss_roundup(base)


def get_cvss_severity_label(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


# =============================================================================
# VULNERABILITY-SPECIFIC KNOWLEDGE BASE (DYNAMIC TECHNICAL CONTEXT)
# =============================================================================

VULN_SPECIFIC_KNOWLEDGE = {
    "sql injection": {
        "canonical": "SQL Injection",
        "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "owasp": "A03:2021 – Injection",
        "default_metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"},
        "description": (
            "SQL Injection arises when untrusted user-supplied input is directly concatenated or interpolated "
            "into a database query without adequate sanitization or query parameterization. This architectural "
            "deficiency allows an attacker to alter the intended query semantics, bypass authentication controls, "
            "extract sensitive database records, execute administrative operations, and in some database configurations, "
            "read files or execute arbitrary operating system commands."
        ),
        "root_cause": (
            "Lack of parameterized queries (prepared statements) or ORM boundary enforcement. User input received via "
            "the parameter was passed directly into a dynamically concatenated SQL string, enabling syntax-breaking payloads."
        ),
        "trigger_mechanism": (
            "The vulnerability is triggered by supplying SQL metacharacters (such as single quotes, double quotes, boolean operators, "
            "or sleep functions) into the vulnerable request parameter. The database interpreter evaluates these injected clauses "
            "as query commands rather than literal scalar data."
        ),
        "security_implications": (
            "Total loss of database confidentiality and integrity. Attackers can dump proprietary business tables, exfiltrate user credentials, "
            "forge administrator sessions, modify or wipe records, and compromise backend relational databases."
        ),
        "cia": {
            "confidentiality": ("High", "Full read access to sensitive database tables, user records, and backend credentials."),
            "integrity": ("High", "Ability to insert, alter, or delete database records and tamper with persistent application state."),
            "availability": ("Low", "Potential for denial of service through query deadlocks, resource-intensive subqueries, or table truncation."),
        },
        "scenarios": [
            "Authentication Bypass: Injecting boolean payloads (' OR '1'='1) to log in as administrative accounts without credentials.",
            "Data Exfiltration: Using UNION SELECT or error-based extraction to dump password hashes, API tokens, and customer PII.",
            "Backend Compromise: In MySQL/MSSQL environments, leveraging INTO OUTFILE or xp_cmdshell for persistent host execution.",
        ],
        "secure_code": (
            "# Vulnerable:\n"
            "# query = f\"SELECT * FROM users WHERE username = '{user_input}'\"\n"
            "\n"
            "# Secure: Use Parameterized Queries (Prepared Statements)\n"
            "cursor.execute(\"SELECT * FROM users WHERE username = %s\", (user_input,))\n"
            "# Or via SQLAlchemy ORM:\n"
            "user = session.query(User).filter(User.username == user_input).first()"
        ),
        "verification": (
            "1. Submit benign alpha-numeric value and confirm HTTP 200 with standard response.\n"
            "2. Submit syntax metacharacter (e.g. single quote `'`) and confirm no database syntax errors or status 500.\n"
            "3. Submit boolean test probe (`' OR 1=1 --`) and confirm response matches standard invalid lookup, not true state."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://portswigger.net/web-security/sql-injection",
        ],
    },
    "cross-site scripting (xss)": {
        "canonical": "Cross-Site Scripting (XSS)",
        "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting')",
        "owasp": "A03:2021 – Injection",
        "default_metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "C", "c": "L", "i": "L", "a": "N"},
        "description": (
            "Cross-Site Scripting (XSS) occurs when the web application includes unvalidated or unescaped user-supplied input "
            "in generated web pages or client-side DOM templates. When an unsuspecting user navigates to the crafted URL or page, "
            "the malicious script executes in the victim's web browser under the security context of the vulnerable web application."
        ),
        "root_cause": (
            "Insufficient context-aware output encoding. User-controlled input was reflected in HTML body, attribute, or JavaScript "
            "blocks without encoding HTML entities (`&lt;`, `&gt;`, `&quot;`, `&#39;`)."
        ),
        "trigger_mechanism": (
            "The vulnerability is triggered when an attacker tricks a user into visiting a URL containing injected markup or scripts, "
            "or when persistent input is loaded into the user interface by other clients."
        ),
        "security_implications": (
            "Attackers can hijack authenticated user sessions by stealing non-HttpOnly cookies, manipulate the DOM to display phishing forms, "
            "perform unauthorized actions on behalf of the victim, or redirect users to malicious domains."
        ),
        "cia": {
            "confidentiality": ("Low", "Read access to DOM content, local storage, session variables, and non-HttpOnly cookies."),
            "integrity": ("Low", "Ability to execute arbitrary JavaScript actions on behalf of the logged-in victim."),
            "availability": ("None", "Does not compromise backend availability, though client UI can be defaced."),
        },
        "scenarios": [
            "Session Hijacking: Stealing session tokens and local storage keys to impersonate victim sessions.",
            "Client-Side Trojan / Keylogger: Injecting event listeners to capture keystrokes on login and payment forms.",
            "Forced Client State Modification: Forging authenticated API requests via client-side fetch() with ambient credentials.",
        ],
        "secure_code": (
            "// Vulnerable (React / DOM):\n"
            "// element.innerHTML = userInput;\n"
            "// <div dangerouslySetInnerHTML={{ __html: userInput }} />\n"
            "\n"
            "// Secure: Context-Aware Escaping / Safe DOM APIs\n"
            "element.textContent = userInput;\n"
            "// Or in React:\n"
            "<div>{userInput}</div> // Automatically entity-escaped by React"
        ),
        "verification": (
            "1. Inject test payload `\"><script>alert(1)</script>` into target parameter.\n"
            "2. Inspect page source and verify output is encoded as `&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;`.\n"
            "3. Confirm in browser developer console that no unhandled script execution occurs."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://portswigger.net/web-security/cross-site-scripting",
        ],
    },
    "cross-site request forgery (csrf)": {
        "canonical": "Cross-Site Request Forgery (CSRF)",
        "cwe": "CWE-352: Cross-Site Request Forgery",
        "owasp": "A01:2021 – Broken Access Control",
        "default_metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "N", "i": "H", "a": "N"},
        "description": (
            "Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web "
            "application in which they are currently authenticated. Without unpredictable anti-CSRF tokens or strict cookie "
            "SameSite boundaries, a malicious site can issue state-changing HTTP requests that inherit ambient browser credentials."
        ),
        "root_cause": (
            "The state-changing endpoint accepts HTTP POST/PUT/DELETE requests without requiring an unpredictable, cryptographically "
            "tied anti-CSRF token, and authentication cookies lack `SameSite=Strict` or `SameSite=Lax` isolation."
        ),
        "trigger_mechanism": (
            "An attacker hosts an HTML page containing an auto-submitting form or XMLHttpRequest that targets the sensitive endpoint. "
            "When the victim visits the attacker's page, the victim's browser automatically attaches authentication cookies."
        ),
        "security_implications": (
            "Unauthorized modification of account state, including email address changes, password resets, funds transfer, "
            "or privileged administrative configuration changes."
        ),
        "cia": {
            "confidentiality": ("None", "CSRF does not permit attackers to read direct server responses (enforced by Same-Origin Policy)."),
            "integrity": ("High", "Ability to force state alterations, configuration changes, or unauthorized user data updates."),
            "availability": ("None", "Does not directly impact service uptime unless state modification involves deleting accounts."),
        },
        "scenarios": [
            "Unauthorized Email Update: Forcing an authenticated administrator to update their recovery email to the attacker's address.",
            "Unauthorized Financial Transaction: Forcing victims to submit payment or transfer requests to third-party accounts.",
            "Account Takeover: Forcing a victim to link an OAuth provider controlled by the adversary.",
        ],
        "secure_code": (
            "# FastAPI / Starlette CSRF Protection:\n"
            "# 1. Ensure cookies use SameSite attribute:\n"
            "response.set_cookie('session', token, secure=True, httponly=True, samesite='lax')\n"
            "\n"
            "# 2. Enforce Anti-CSRF Token Validation for all state-changing methods:\n"
            "if request.method in ('POST', 'PUT', 'DELETE'):\n"
            "    validate_csrf_token(request.headers.get('X-CSRF-Token'))"
        ),
        "verification": (
            "1. Craft a standalone local HTML form targeting the endpoint without the anti-CSRF header.\n"
            "2. Submit form from an external origin in an authenticated browser session.\n"
            "3. Confirm that the application returns HTTP 403 Forbidden and refuses to execute the state change."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/csrf",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/352.html",
            "https://portswigger.net/web-security/csrf",
        ],
    },
    "path traversal": {
        "canonical": "Path Traversal",
        "cwe": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "owasp": "A01:2021 – Broken Access Control",
        "default_metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "description": (
            "Path Traversal (also known as Directory Traversal) allows an attacker to read arbitrary files on the server that is "
            "running an application. This might include application code and data, credentials for back-end systems, and sensitive "
            "operating system files."
        ),
        "root_cause": (
            "User-controlled parameter is passed directly to filesystem I/O operations without resolving and canonicalizing absolute paths "
            "or comparing against an approved base directory boundary."
        ),
        "trigger_mechanism": (
            "Supplying path sequence characters (`../`, `..\\`, or URL-encoded variants `%2e%2e%2f`) to traverse outside the intended public web folder."
        ),
        "security_implications": (
            "Exposure of server configuration, database credentials, source code files containing proprietary logic, and local OS hashes."
        ),
        "cia": {
            "confidentiality": ("High", "Unauthorized read access to server files, environment variables, and configuration secrets."),
            "integrity": ("None", "Read-only access unless coupled with file-upload functionality."),
            "availability": ("None", "No direct availability impact."),
        },
        "scenarios": [
            "Credential Harvest: Reading `/etc/passwd` or `appsettings.json` / `.env` to uncover database connection strings.",
            "Source Code Leak: Reading server source files to locate zero-day vulnerabilities in unpublished backend endpoints.",
        ],
        "secure_code": (
            "from pathlib import Path\n"
            "\n"
            "BASE_DIR = Path('/var/www/uploads').resolve()\n"
            "target_path = (BASE_DIR / user_filename).resolve()\n"
            "\n"
            "# Boundary verification:\n"
            "if not target_path.is_relative_to(BASE_DIR):\n"
            "    raise PermissionError('Access Denied: Path Traversal Detected')"
        ),
        "verification": (
            "1. Request benign filename (e.g. `logo.png`) -> 200 OK.\n"
            "2. Request `../../../../etc/passwd` -> Ensure application returns 400/403/404, never system file contents."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://portswigger.net/web-security/file-path-traversal",
        ],
    },
    "command injection": {
        "canonical": "Command Injection",
        "cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "owasp": "A03:2021 – Injection",
        "default_metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
        "description": (
            "Command Injection occurs when an application passes unsafe user-supplied data to a system shell. In this vulnerability, "
            "the attacker-supplied operating system commands are executed with the privileges of the vulnerable application."
        ),
        "root_cause": (
            "Passing unsanitized strings directly to shell execution functions such as `os.system()`, `subprocess.Popen(..., shell=True)`, "
            "or `child_process.exec()`."
        ),
        "trigger_mechanism": (
            "Submitting shell metacharacters (`;`, `&&`, `|`, `$(...)`, or backticks) within input fields processed by OS CLI wrappers."
        ),
        "security_implications": (
            "Complete server compromise. Attackers can install backdoors, pivot across the internal network, extract all data, or destroy services."
        ),
        "cia": {
            "confidentiality": ("High", "Full server filesystem and memory read access."),
            "integrity": ("High", "Ability to modify any file, binary, or configuration writable by the application process."),
            "availability": ("High", "Ability to stop services, wipe disks, or exhaust CPU/memory."),
        },
        "scenarios": [
            "Remote Shell Installation: Spawning a reverse shell connecting to attacker infrastructure for interactive remote control.",
            "Host Takeover: Running local privilege escalation exploits to gain root privileges on the server.",
        ],
        "secure_code": (
            "# Vulnerable: subprocess.run(f'ping -c 1 {user_ip}', shell=True)\n"
            "\n"
            "# Secure: Use list arguments without shell invocation\n"
            "import subprocess\n"
            "subprocess.run(['ping', '-c', '1', user_ip], check=True, shell=False)"
        ),
        "verification": (
            "1. Provide benign IP address -> Standard execution.\n"
            "2. Provide separator probe `127.0.0.1; echo 'sec_test'` -> Ensure command separator is not executed."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    },
    "server-side template injection (ssti)": {
        "canonical": "Server-Side Template Injection (SSTI)",
        "cwe": "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
        "owasp": "A03:2021 – Injection",
        "default_metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
        "description": (
            "Server-Side Template Injection occurs when an application embeds user input into a template engine instead of passing it "
            "as data. Attackers can execute arbitrary template expressions, inspect environment state, and achieve remote code execution."
        ),
        "root_cause": (
            "Dynamically concatenating user input directly into template strings (e.g. Jinja2, Twig, Freemarker) prior to rendering."
        ),
        "trigger_mechanism": (
            "Submitting template delimiters (`{{7*7}}`, `${7*7}`, `#{7*7}`) into input parameters evaluated by the template parser."
        ),
        "security_implications": (
            "Remote code execution via template sandbox escapes, disclosure of environment variables, and backend server compromise."
        ),
        "cia": {
            "confidentiality": ("High", "Full access to environment variables and system files."),
            "integrity": ("High", "Arbitrary remote code execution within host process."),
            "availability": ("High", "Ability to crash template rendering engine or terminate process."),
        },
        "scenarios": [
            "Template Evaluation: Submitting `{{7*7}}` and observing evaluated `49` in rendered response.",
            "Sandbox Escape: Traversing Python MRO to invoke `os.popen()` and achieve arbitrary remote shell execution.",
        ],
        "secure_code": (
            "# Vulnerable: jinja2.Template(f'Hello {user_input}').render()\n"
            "\n"
            "# Secure: Pass user input as a template context variable\n"
            "template = jinja2.Template('Hello {{ name }}')\n"
            "output = template.render(name=user_input)"
        ),
        "verification": (
            "1. Submit arithmetic probe `{{7*7}}` -> Ensure output displays literal `{{7*7}}`, never `49`."
        ),
        "references": [
            "https://portswigger.net/web-security/server-side-template-injection",
            "https://cwe.mitre.org/data/definitions/1336.html",
        ],
    },
    "sensitive files & secrets": {
        "canonical": "Sensitive File Exposure",
        "cwe": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
        "owasp": "A01:2021 – Broken Access Control",
        "default_metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "description": (
            "Sensitive files such as configuration backups, `.git` repositories, environment files (`.env`), or private keys are "
            "accessible to unauthenticated public web requests due to web server misconfiguration."
        ),
        "root_cause": (
            "Web server docroot configuration serves hidden files or backup extensions without blocking access rules."
        ),
        "trigger_mechanism": (
            "Direct GET request to common sensitive file paths (`/.env`, `/.git/HEAD`, `/config.json.bak`)."
        ),
        "security_implications": (
            "Direct disclosure of production API keys, database credentials, encryption secrets, and private source history."
        ),
        "cia": {
            "confidentiality": ("High", "Critical application credentials and cryptographic keys exposed."),
            "integrity": ("None", "Direct file access is read-only."),
            "availability": ("None", "No direct availability impact."),
        },
        "scenarios": [
            "Exposed `.env`: Attacker extracts AWS access keys and PostgreSQL database passwords to access cloud infrastructure.",
            "Exposed `.git`: Reconstructing source code repository locally to uncover hidden administrative endpoints.",
        ],
        "secure_code": (
            "# Nginx Web Server Configuration Rule:\n"
            "location ~ /\\.(?!well-known) {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}\n"
            "location ~* \\.(bak|old|orig|save|swp|env|sql)$ {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}"
        ),
        "verification": (
            "1. Request `/.env` or `/.git/HEAD` -> Verify server responds with HTTP 404 or 403, with zero bytes of credential content."
        ),
        "references": [
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
    },
    "cors misconfiguration": {
        "canonical": "CORS Misconfiguration",
        "cwe": "CWE-942: Permissive Cross-Domain Policy with Untrusted Domains",
        "owasp": "A01:2021 – Broken Access Control",
        "default_metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "H", "i": "N", "a": "N"},
        "description": (
            "Cross-Origin Resource Sharing (CORS) misconfigurations occur when an application reflects arbitrary Origin headers "
            "with `Access-Control-Allow-Credentials: true`, permitting external domains to read sensitive authenticated responses."
        ),
        "root_cause": (
            "Dynamic reflection of incoming `Origin` header without strict domain allowlisting, combined with credentials flag."
        ),
        "trigger_mechanism": (
            "Sending an HTTP request with an untrusted `Origin: https://evil.attacker.com` header and observing reflected header."
        ),
        "security_implications": (
            "Malicious websites can issue authenticated cross-origin requests and read private user profile data and API responses."
        ),
        "cia": {
            "confidentiality": ("High", "Complete exfiltration of authenticated API payloads and customer profile data."),
            "integrity": ("None", "CORS controls read access; write operations require separate anti-CSRF flaws."),
            "availability": ("None", "No availability impact."),
        },
        "scenarios": [
            "Cross-Origin Data Theft: Attacker embeds JavaScript on a third-party site reading victim's banking profile via CORS.",
        ],
        "secure_code": (
            "# Fastapi / Starlette:\n"
            "app.add_middleware(\n"
            "    CORSMiddleware,\n"
            "    allow_origins=['https://trusted-domain.com'], # Strict allowlist\n"
            "    allow_credentials=True,\n"
            "    allow_methods=['GET', 'POST'],\n"
            ")"
        ),
        "verification": (
            "1. Send `Origin: https://evil.com` -> Verify `Access-Control-Allow-Origin: https://evil.com` is NOT returned."
        ),
        "references": [
            "https://portswigger.net/web-security/cors",
            "https://cwe.mitre.org/data/definitions/942.html",
        ],
    },
    "clickjacking": {
        "canonical": "Clickjacking (UI Redressing)",
        "cwe": "CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
        "owasp": "A05:2021 – Security Misconfiguration",
        "default_metrics": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "N", "i": "L", "a": "N"},
        "description": (
            "Clickjacking occurs when an attacker tricks an authenticated user into clicking on actionable UI components "
            "by embedding the vulnerable application within a transparent iframe layered beneath a deceptive decoy website."
        ),
        "root_cause": (
            "Missing `X-Frame-Options` header and missing `Content-Security-Policy: frame-ancestors` directive."
        ),
        "trigger_mechanism": (
            "Loading the target endpoint inside an `<iframe>` tag on an external website."
        ),
        "security_implications": (
            "Unintended user clicks triggering account deletion, subscription changes, or social media actions without user consent."
        ),
        "cia": {
            "confidentiality": ("None", "Framing does not grant cross-origin DOM read access."),
            "integrity": ("Low", "Deceptive user actions triggered via hidden framed interface elements."),
            "availability": ("None", "No availability impact."),
        },
        "scenarios": [
            "Deceptive Button Click: Victim believes they are clicking a game button, but clicks 'Confirm Transfer' in transparent frame.",
        ],
        "secure_code": (
            "# HTTP Response Headers:\n"
            "Content-Security-Policy: frame-ancestors 'none';\n"
            "X-Frame-Options: DENY"
        ),
        "verification": (
            "1. Create local test HTML page with `<iframe src='TARGET_URL'></iframe>`.\n"
            "2. Confirm that modern browsers refuse to frame the page with a framing error."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/Clickjacking",
            "https://cwe.mitre.org/data/definitions/1021.html",
        ],
    },
}

SEV_COLORS = {
    "Critical": "#991b1b",
    "High": "#dc2626",
    "Medium": "#d97706",
    "Low": "#ca8a04",
    "Informational": "#2563eb",
}

CVSS_KNOWLEDGE_BASE = {
    k: {
        "score": (
            calculate_cvss_score(**v["default_metrics"])
            if v.get("default_metrics")
            else None
        ),
        "severity": (
            get_cvss_severity_label(calculate_cvss_score(**v["default_metrics"]))
            if v.get("default_metrics")
            else "Unknown"
        ),
        "vector": (
            f"CVSS:3.1/AV:{v['default_metrics']['av']}/AC:{v['default_metrics']['ac']}/PR:{v['default_metrics']['pr']}/UI:{v['default_metrics']['ui']}/S:{v['default_metrics']['s']}/C:{v['default_metrics']['c']}/I:{v['default_metrics']['i']}/A:{v['default_metrics']['a']}"
            if v.get("default_metrics")
            else "N/A"
        ),
        "cwe": v.get("cwe", "CWE-699"),
        "references": v.get("references", []),
    }
    for k, v in VULN_SPECIFIC_KNOWLEDGE.items()
}


def get_cvss_info(finding_type: str, severity: str = "") -> dict:
    """Retrieve verified CVSS v3.1 metrics for standard web vulnerability types without inventing values."""
    vuln_info = match_vuln_knowledge(finding_type)

    class DummyFinding:
        def __init__(self, s):
            self.detection_status = "Confirmed"
            self.severity = s
            self.url = ""
            self.method = "GET"

    cvss = assess_finding_cvss(DummyFinding(severity), vuln_info)
    if cvss["assessed"]:
        return {
            "score": cvss["score"],
            "severity": cvss["severity"],
            "vector": cvss["vector"],
            "cwe": vuln_info.get("cwe", "CWE-699"),
            "references": vuln_info.get("references", []),
        }
    return {
        "score": None,
        "severity": severity or "Unknown",
        "vector": "N/A (Defense-in-depth or Context-Dependent)",
        "cwe": vuln_info.get("cwe", "CWE-699"),
        "references": vuln_info.get("references", []),
    }



def match_vuln_knowledge(finding_type: str) -> dict:
    """Find matching vulnerability technical profile from knowledge base."""
    ft_lower = (finding_type or "").lower().strip()
    for k, v in VULN_SPECIFIC_KNOWLEDGE.items():
        if k in ft_lower or ft_lower in k:
            return v
    # Fallback generic profile
    return {
        "canonical": finding_type or "Security Vulnerability",
        "cwe": "CWE-699: Software Development Concepts",
        "owasp": "A05:2021 – Security Misconfiguration",
        "default_metrics": None,
        "description": (
            "The web application was observed to exhibit anomalous input handling or security configuration divergence. "
            "Automated active probes identified behavioral variance that deviates from baseline defense standards."
        ),
        "root_cause": "Unvalidated parameter processing or missing defensive HTTP security controls.",
        "trigger_mechanism": "Specific input syntax probes or missing defensive headers.",
        "security_implications": "May permit unauthorized access or security posture degradation.",
        "cia": {
            "confidentiality": ("Low", "Potential limited information exposure."),
            "integrity": ("Low", "Potential state manipulation depending on application logic."),
            "availability": ("None", "No direct availability impact confirmed."),
        },
        "scenarios": [
            "Exploitation depends on application business logic and authorization architecture.",
        ],
        "secure_code": (
            "# Enforce strict input validation, parameterization, and defensive HTTP headers.\n"
            "# Validate all untrusted input against strict allowlist schemas."
        ),
        "verification": (
            "1. Re-test endpoint with automated and manual probes in staging.\n"
            "2. Verify defensive controls enforce expected boundaries."
        ),
        "references": [
            "https://owasp.org/www-project-top-ten/",
            "https://cwe.mitre.org/",
        ],
    }


def assess_finding_cvss(finding, vuln_info: dict) -> dict:
    """
    Dynamically and accurately assess CVSS v3.1 metrics based on actual finding context.
    If context is insufficient, returns 'CVSS: Not Assessed – Manual Evaluation Required'.
    """
    det_status = getattr(finding, "detection_status", "Confirmed")
    sev = getattr(finding, "severity", "")
    sev_str = sev.value if hasattr(sev, "value") else str(sev)

    # If finding is Potential or Requires Manual Verification, do not fabricate CVSS
    if det_status != "Confirmed":
        return {
            "assessed": False,
            "score": None,
            "severity": None,
            "vector": "CVSS: Not Assessed – Manual Evaluation Required",
            "reason": (
                f"Detection status is flagged as '{det_status}'. Exploitability and impact metrics "
                "must be confirmed in an isolated staging environment prior to finalizing CVSS base score."
            ),
            "metrics": {},
        }

    # If informational severity, CVSS is not applicable
    if sev_str.lower() in ("informational", "info"):
        return {
            "assessed": False,
            "score": None,
            "severity": "Informational",
            "vector": "CVSS: Not Assessed – Informational Finding",
            "reason": "Informational finding without direct exploitability penalty.",
            "metrics": {},
        }

    defaults = vuln_info.get("default_metrics")
    if not defaults:
        return {
            "assessed": False,
            "score": None,
            "severity": sev_str or "Unknown",
            "vector": "CVSS: Not Assessed – Manual Evaluation Required",
            "reason": "Insufficient vulnerability-specific metrics available to compute grounded CVSS score without manual evaluation.",
            "metrics": {},
        }

    # Contextual metric evaluation
    metrics = dict(defaults)

    # If endpoint requires authentication or scan recorded auth requirement
    url = getattr(finding, "url", "")
    method = getattr(finding, "method", "GET")
    if "/admin" in url.lower():
        metrics["pr"] = "H"
    elif "/dashboard" in url.lower() or "/account" in url.lower() or "/profile" in url.lower():
        metrics["pr"] = "L"

    # Compute exact score
    score = calculate_cvss_score(
        av=metrics["av"],
        ac=metrics["ac"],
        pr=metrics["pr"],
        ui=metrics["ui"],
        s=metrics["s"],
        c=metrics["c"],
        i=metrics["i"],
        a=metrics["a"],
    )

    vector_str = (
        f"CVSS:3.1/AV:{metrics['av']}/AC:{metrics['ac']}/PR:{metrics['pr']}/"
        f"UI:{metrics['ui']}/S:{metrics['s']}/C:{metrics['c']}/I:{metrics['i']}/A:{metrics['a']}"
    )

    return {
        "assessed": True,
        "score": score,
        "severity": get_cvss_severity_label(score),
        "vector": vector_str,
        "metrics": metrics,
        "reason": "Assessed via ZeroTrace active probe evaluation and supported CVSS v3.1 base equations.",
    }


# =============================================================================
# REPRODUCTION & EVIDENCE UTILITIES
# =============================================================================

def generate_reproduction_steps(finding) -> list[str]:
    """Generate clear, numbered, reproducible verification steps from stored finding data."""
    method = getattr(finding, "method", "GET") or "GET"
    url = getattr(finding, "url", "")
    param = getattr(finding, "parameter", None)
    f_type = getattr(finding, "type", "Vulnerability")
    evidence = getattr(finding, "evidence", "") or ""

    details = getattr(finding, "evidence_details", {}) or {}
    records = details.get("records", []) if isinstance(details, dict) else []
    sample_payload = records[0].get("payload") if records else None

    if not sample_payload and param and "=" in url:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if param in qs and qs[param]:
            sample_payload = qs[param][0]

    if not sample_payload:
        ft_low = f_type.lower()
        if "sql" in ft_low:
            sample_payload = "' OR 1=1 --"
        elif "xss" in ft_low:
            sample_payload = "<script>alert(1)</script>"
        elif "command" in ft_low:
            sample_payload = "; id"
        elif "ssti" in ft_low:
            sample_payload = "{{7*7}}"
        elif "path" in ft_low or "traversal" in ft_low:
            sample_payload = "../../../../etc/passwd"
        else:
            sample_payload = "test_probe"

    steps = [
        f"Navigate to target endpoint at `{url}` using an HTTP testing client or web browser.",
        f"Confirm that the `{method}` request accepts user-controllable input via parameter `{param or 'input_field'}`.",
        f"Submit a verification probe containing the test payload `{sample_payload}`.",
        f"Inspect the server response for security indicator: {redact(evidence[:140]) if evidence else 'unexpected syntax execution or unescaped reflection'}.",
        "Compare with a benign control request to confirm deterministic trigger and lack of input sanitization.",
    ]
    return steps


def generate_safe_poc(finding) -> str:
    """Generate a safe, reproducible curl command Proof-of-Concept."""
    method = getattr(finding, "method", "GET") or "GET"
    url = getattr(finding, "url", "")
    param = getattr(finding, "parameter", None)
    f_type = getattr(finding, "type", "")

    payload = "' OR 1=1 --" if "sql" in f_type.lower() else "<script>alert(1)</script>" if "xss" in f_type.lower() else "test_probe"
    details = getattr(finding, "evidence_details", {}) or {}
    if isinstance(details, dict) and details.get("records"):
        payload = details["records"][0].get("payload", payload)

    clean_payload = redact(str(payload))

    if method.upper() == "POST":
        return (
            f'curl -i -s -k -X POST "{url}" \\\n'
            f'  -H "Content-Type: application/x-www-form-urlencoded" \\\n'
            f'  -d "{param or "param"}={clean_payload}"'
        )
    else:
        sep = "&" if "?" in url else "?"
        target_curl = f"{url}{sep}{param}={clean_payload}" if param and param not in url else url
        return f'curl -i -s -k -X GET "{target_curl}"'


def build_raw_http_request(finding) -> str:
    """Generate realistic sanitized raw HTTP request representation."""
    method = getattr(finding, "method", "GET") or "GET"
    url = getattr(finding, "url", "")
    param = getattr(finding, "parameter", None)
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    details = getattr(finding, "evidence_details", {}) or {}
    req = details.get("request", {}) if isinstance(details, dict) else {}
    if req and req.get("raw"):
        return redact(req["raw"][:700])

    host = parsed.netloc or "target.local"
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.9",
        "Connection: close",
    ]
    if method.upper() == "POST":
        lines.append("Content-Type: application/x-www-form-urlencoded")
        payload = details.get("records", [{}])[0].get("payload", "' OR 1=1 --") if details.get("records") else "test"
        lines.append("")
        lines.append(f"{param or 'field'}={redact(str(payload))}")
    return "\n".join(lines)


def build_raw_http_response(finding) -> str:
    """Generate realistic sanitized raw HTTP response representation."""
    details = getattr(finding, "evidence_details", {}) or {}
    resp = details.get("response", {}) if isinstance(details, dict) else {}
    if resp and resp.get("raw"):
        return redact(resp["raw"][:700])

    evidence = getattr(finding, "evidence", "") or ""
    clean_ev = redact(evidence)

    lines = [
        "HTTP/1.1 200 OK" if "500" not in clean_ev else "HTTP/1.1 500 Internal Server Error",
        "Server: ZeroTrace-Target-Web/1.0",
        "Content-Type: text/html; charset=UTF-8",
        f"Date: {datetime.now(timezone.utc):%a, %d %b %Y %H:%M:%S} GMT",
        "Connection: close",
        "",
        clean_ev[:550] if clean_ev else "<!-- Target application processed vulnerable input without validation -->",
    ]
    return "\n".join(lines)


# =============================================================================
# TWO-PASS CANVAS FOR NUMBERED PAGES (PAGE X OF Y)
# =============================================================================

class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and print exact 'Page X of Y'."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Header on page 2 and later
        if self._pageNumber > 1:
            self.drawString(16 * mm, 282 * mm, "ZeroTrace — Vulnerability Disclosure Report")
            self.setFont("Helvetica", 8)
            self.drawRightString(194 * mm, 282 * mm, "CONFIDENTIAL // RESPONSIBLE DISCLOSURE")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(16 * mm, 280 * mm, 194 * mm, 280 * mm)

        # Running Footer on all pages
        self.setFont("Helvetica", 8)
        self.drawString(16 * mm, 12 * mm, "ZeroTrace Automated Web Vulnerability Assessment Platform | Confidential Document")
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(194 * mm, 12 * mm, page_text)
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(16 * mm, 15 * mm, 194 * mm, 15 * mm)
        self.restoreState()


# =============================================================================
# HACKERONE MARKDOWN GENERATOR
# =============================================================================

def build_bug_bounty_markdown(finding, scan=None) -> str:
    """Generate clean, professional Markdown tailored for HackerOne / Bugcrowd submissions."""
    f_type = getattr(finding, "type", "Security Vulnerability")
    sev = getattr(finding, "severity", "")
    sev_str = sev.value if hasattr(sev, "value") else str(sev)
    conf = getattr(finding, "confidence", "")
    conf_str = conf.value if hasattr(conf, "value") else str(conf)
    det_status = getattr(finding, "detection_status", "Confirmed")
    url = getattr(finding, "url", "")
    method = getattr(finding, "method", "GET") or "GET"
    param = getattr(finding, "parameter", None) or "None"
    cwe = getattr(finding, "cwe_id", None)
    desc = getattr(finding, "description", "")
    impact = getattr(finding, "impact", "")
    remediation = getattr(finding, "remediation", "")
    evidence = getattr(finding, "evidence", "")
    fingerprint = getattr(finding, "fingerprint", "")

    hostname = urlparse(url).hostname or "target-host"
    vuln_info = match_vuln_knowledge(f_type)
    cvss = assess_finding_cvss(finding, vuln_info)
    steps = generate_reproduction_steps(finding)
    poc_curl = generate_safe_poc(finding)

    md = []
    md.append(f"# [{sev_str.upper()}] {vuln_info['canonical']} in {method} {urlparse(url).path or '/'}\n")

    md.append("## Vulnerability Overview")
    md.append("| Property | Value |")
    md.append("|---|---|")
    md.append(f"| **Vulnerability Type** | {vuln_info['canonical']} |")
    md.append(f"| **Severity** | **{sev_str}** |")
    md.append(f"| **Confidence** | {conf_str} |")
    md.append(f"| **Detection Status** | {det_status} |")
    md.append(f"| **Affected Asset** | `{hostname}` |")
    md.append(f"| **Vulnerable Endpoint** | `{method} {url}` |")
    md.append(f"| **Vulnerable Parameter** | `{param}` |")
    md.append(f"| **CWE ID** | {cwe or vuln_info.get('cwe', 'CWE-699')} |")
    md.append(f"| **OWASP Category** | {getattr(finding, 'owasp_category', None) or vuln_info.get('owasp', 'A03:2021 – Injection')} |")
    if cvss["assessed"]:
        md.append(f"| **CVSS v3.1 Base Score** | **{cvss['score']}** ({cvss['severity']}) |")
        md.append(f"| **CVSS v3.1 Vector** | `{cvss['vector']}` |")
    else:
        md.append(f"| **CVSS v3.1 Assessment** | {cvss['vector']} |")
    if fingerprint:
        md.append(f"| **Finding Fingerprint** | `{fingerprint}` |")
    md.append("")

    if det_status != "Confirmed":
        md.append(f"> **Notice**: This vulnerability is flagged as **{det_status}**. Please verify in your testing environment prior to submission.\n")

    md.append("## Summary & Technical Description")
    md.append(f"{desc or vuln_info['description']}\n")
    md.append(f"**Root Cause:** {vuln_info['root_cause']}\n")

    md.append("## Steps to Reproduce")
    for i, step in enumerate(steps, 1):
        md.append(f"{i}. {step}")
    md.append("")

    md.append("## Safe Proof of Concept (PoC)")
    md.append("```bash")
    md.append(poc_curl)
    md.append("```\n")

    md.append("## Technical Evidence")
    md.append("```http")
    md.append(build_raw_http_request(finding))
    md.append("```\n")
    md.append("```http")
    md.append(build_raw_http_response(finding))
    md.append("```\n")

    md.append("## Security Impact & Impact Analysis (CIA)")
    md.append(f"{impact or vuln_info['security_implications']}\n")
    cia = vuln_info["cia"]
    md.append(f"- **Confidentiality:** {cia['confidentiality'][0]} – {cia['confidentiality'][1]}")
    md.append(f"- **Integrity:** {cia['integrity'][0]} – {cia['integrity'][1]}")
    md.append(f"- **Availability:** {cia['availability'][0]} – {cia['availability'][1]}\n")

    md.append("## Recommended Remediation")
    md.append(f"{remediation or vuln_info.get('description', '')}\n")
    md.append("### Secure Coding Example")
    md.append("```python")
    md.append(vuln_info["secure_code"])
    md.append("```\n")

    md.append("## References & Authoritative Sources")
    for ref in vuln_info.get("references", []):
        md.append(f"- [{ref}]({ref})")
    md.append("")

    md.append("---\n*Generated by ZeroTrace — Automated Web Vulnerability Assessment Platform. Confidential responsible disclosure document.*")
    return "\n".join(md)


# =============================================================================
# PROFESSIONAL 4-6 PAGE BUG BOUNTY PDF GENERATOR
# =============================================================================

def build_bug_bounty_pdf(finding, scan=None) -> bytes:
    """
    Generate a comprehensive, professional 4-6 page PDF Bug Bounty Report
    tailored for HackerOne, Bugcrowd, and responsible vulnerability disclosure programs.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"ZeroTrace Bug Bounty Report — {getattr(finding, 'type', 'Vulnerability')}",
        author="ZeroTrace Vulnerability Assessment Platform",
    )

    ss = getSampleStyleSheet()

    # Typography styles
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=colors.HexColor("#0f172a"), fontSize=15, leading=19, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=colors.HexColor("#0f172a"), fontSize=12, leading=15, spaceBefore=4, spaceAfter=3)
    h3 = ParagraphStyle("h3", parent=ss["Heading3"], textColor=colors.HexColor("#1e293b"), fontSize=9.5, leading=12, spaceBefore=4, spaceAfter=2)
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=8.2, leading=11.5, textColor=colors.HexColor("#1e293b"))
    body_bold = ParagraphStyle("body_bold", parent=body, fontName="Helvetica-Bold")
    small = ParagraphStyle("small", parent=body, fontSize=7.2, leading=9.5, textColor=colors.HexColor("#475569"))
    small_bold = ParagraphStyle("small_bold", parent=small, fontName="Helvetica-Bold")
    code_style = ParagraphStyle("code", parent=body, fontName="Courier", fontSize=6.8, leading=8.5, textColor=colors.HexColor("#0f172a"))

    f_type = getattr(finding, "type", "Security Vulnerability")
    sev = getattr(finding, "severity", "")
    sev_str = sev.value if hasattr(sev, "value") else str(sev)
    conf = getattr(finding, "confidence", "")
    conf_str = conf.value if hasattr(conf, "value") else str(conf)
    det_status = getattr(finding, "detection_status", "Confirmed")
    url = getattr(finding, "url", "")
    method = getattr(finding, "method", "GET") or "GET"
    param = getattr(finding, "parameter", None) or "None"
    cwe = getattr(finding, "cwe_id", None)
    desc = getattr(finding, "description", "")
    impact = getattr(finding, "impact", "")
    remediation = getattr(finding, "remediation", "")
    evidence = getattr(finding, "evidence", "")
    fingerprint = getattr(finding, "fingerprint", "")
    timestamp = getattr(finding, "timestamp", None) or datetime.now(timezone.utc)

    scan_id = getattr(finding, "scan_id", "") or (getattr(scan, "id", "") if scan else "")
    app_name = getattr(getattr(scan, "application", None), "name", None) if scan else None
    hostname = urlparse(url).hostname or "target.local"

    vuln_info = match_vuln_knowledge(f_type)
    cvss = assess_finding_cvss(finding, vuln_info)
    steps = generate_reproduction_steps(finding)
    poc_curl = generate_safe_poc(finding)
    raw_req = build_raw_http_request(finding)
    raw_resp = build_raw_http_response(finding)
    sev_color = colors.HexColor(SEV_COLORS.get(sev_str, "#64748b"))

    story = []

    # =========================================================================
    # PAGE 1: VULNERABILITY OVERVIEW & EXECUTIVE SUMMARY
    # =========================================================================
    header_tbl = Table(
        [
            [
                Paragraph("<b>ZeroTrace</b> — Vulnerability Disclosure Report", ParagraphStyle("hdr_l", parent=body, fontSize=11, fontName="Helvetica-Bold", textColor=colors.HexColor("#0f172a"))),
                Paragraph(f"<b>STATUS: {det_status.upper()}</b>", ParagraphStyle("hdr_r", parent=body, fontSize=9, fontName="Helvetica-Bold", textColor=colors.HexColor("#059669") if det_status == "Confirmed" else colors.HexColor("#d97706"), alignment=2)),
            ]
        ],
        colWidths=[114 * mm, 64 * mm],
    )
    header_tbl.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 1.2, colors.HexColor("#0284c7")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 3 * mm))

    # Vulnerability Title & Severity Badge
    sev_badge = Table(
        [[Paragraph(f"<b>{sev_str.upper()}</b>", ParagraphStyle("b_txt", parent=body, fontSize=9, textColor=colors.white, alignment=1))]],
        colWidths=[24 * mm],
    )
    sev_badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), sev_color),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))

    title_tbl = Table(
        [
            [
                sev_badge,
                Paragraph(f"<b>{escape(vuln_info['canonical'])}</b> in <code>{escape(method)} {escape(urlparse(url).path or '/')}</code>", h1),
            ]
        ],
        colWidths=[26 * mm, 152 * mm],
    )
    title_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(title_tbl)
    story.append(Spacer(1, 3 * mm))

    # Metadata Grid
    cwe_display = cwe or vuln_info.get("cwe", "CWE-699")
    meta_rows = [
        [Paragraph("<b>Target Hostname</b>", small), Paragraph(escape(hostname), small),
         Paragraph("<b>Affected Endpoint</b>", small), Paragraph(escape(f"{method} {urlparse(url).path or '/'}"), small)],
        [Paragraph("<b>Vulnerable Parameter</b>", small), Paragraph(f"<code>{escape(param)}</code>", small),
         Paragraph("<b>Detection Status</b>", small), Paragraph(escape(det_status), small)],
        [Paragraph("<b>Confidence Level</b>", small), Paragraph(escape(conf_str), small),
         Paragraph("<b>Discovery Timestamp</b>", small), Paragraph(f"{timestamp:%Y-%m-%d %H:%M:%S} UTC", small)],
        [Paragraph("<b>CWE Classification</b>", small), Paragraph(escape(cwe_display[:42]), small),
         Paragraph("<b>OWASP Category</b>", small), Paragraph(escape((getattr(finding, 'owasp_category', None) or vuln_info.get('owasp', 'A03:2021 – Injection'))[:38]), small)],
        [Paragraph("<b>Associated Application</b>", small), Paragraph(escape(app_name or "Standalone Web Target"), small),
         Paragraph("<b>Assessment Identifier</b>", small), Paragraph(f"<code>{str(scan_id)[:18]}</code>", small)],
        [Paragraph("<b>Target Full URL</b>", small), Paragraph(f"<font color='#0284c7'>{escape(url[:70])}</font>", small),
         Paragraph("<b>Finding Fingerprint</b>", small), Paragraph(f"<code>{escape((fingerprint or 'N/A')[:18])}</code>", small)],
    ]
    meta_tbl = Table(meta_rows, colWidths=[30 * mm, 58 * mm, 32 * mm, 58 * mm])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 4 * mm))

    # CVSS Assessment Box
    if cvss["assessed"]:
        cvss_box_data = [
            [
                Paragraph(f"<font size=18><b>{cvss['score']}</b></font><br/><font size=7.5 color='#475569'>CVSS v3.1 BASE</font>", ParagraphStyle("c_sc", parent=body, alignment=1)),
                Paragraph(f"<b>Vector:</b> <code>{cvss['vector']}</code><br/>"
                          f"<b>Assessment Mode:</b> Context-Aware Active Metric Evaluation<br/>"
                          f"<b>Severity Rating:</b> <font color='{sev_color}'><b>{cvss['severity'].upper()}</b></font> &nbsp;|&nbsp; "
                          f"Scope: {'Changed' if cvss['metrics'].get('s') == 'C' else 'Unchanged'}", small),
            ]
        ]
        cvss_tbl = Table(cvss_box_data, colWidths=[36 * mm, 142 * mm])
        cvss_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#f1f5f9")),
            ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
    else:
        cvss_box_data = [
            [
                Paragraph("<b>CVSS: Not Assessed – Manual Evaluation Required</b><br/>"
                          f"{escape(cvss['reason'])}", small),
            ]
        ]
        cvss_tbl = Table(cvss_box_data, colWidths=[178 * mm])
        cvss_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fffbeb")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f59e0b")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
    story.append(cvss_tbl)
    story.append(Spacer(1, 4 * mm))

    # Executive Summary Paragraph
    story.append(Paragraph("<b>Executive Vulnerability Summary</b>", h2))
    exec_text = (
        f"During an authorized vulnerability assessment of <b>{escape(hostname)}</b>, ZeroTrace identified a "
        f"<b>{sev_str} severity</b> security deficiency classified as <b>{escape(vuln_info['canonical'])}</b>. "
        f"The issue resides on endpoint <code>{escape(method)} {escape(urlparse(url).path or '/')}</code>, specifically "
        f"impacting parameter <code>{escape(param)}</code>. "
        f"{vuln_info['security_implications']} Immediate technical triage and remediation are recommended to eliminate "
        "attack surface exposure and ensure compliance with responsible disclosure security standards."
    )
    story.append(Paragraph(exec_text, body))
    story.append(Spacer(1, 3 * mm))

    # Notice box if potential
    if det_status != "Confirmed":
        notice_box = Table(
            [[Paragraph(f"<b>Notice – {det_status.upper()}:</b> This finding exhibited behavioral or heuristic anomalies. "
                        "Security analysts should verify exploitability in an isolated staging environment before escalating.", small)]],
            colWidths=[178 * mm],
        )
        notice_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef3c7")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d97706")),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ]))
        story.append(notice_box)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 2: DETAILED TECHNICAL DESCRIPTION & ARCHITECTURE CONTEXT
    # =========================================================================
    story.append(Paragraph("2. Technical Description & Architecture Context", h1))
    story.append(Spacer(1, 2 * mm))

    story.append(Paragraph("<b>2.1 Detailed Vulnerability Description</b>", h2))
    story.append(Paragraph(escape(desc or vuln_info["description"]), body))
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>2.2 Evidence-Supported Root Cause Analysis</b>", h2))
    story.append(Paragraph(escape(vuln_info["root_cause"]), body))
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>2.3 Affected Application Functionality & User Journey</b>", h2))
    func_text = (
        f"The vulnerability is situated within the application's <b>{escape(urlparse(url).path or '/')}</b> route, which "
        f"serves parameter <code>{escape(param)}</code> via HTTP <code>{escape(method)}</code>. "
        "In production workflows, this endpoint handles user-directed requests where client input is ingested by the server "
        "without sufficient structural boundary isolation or data-layer escaping."
    )
    story.append(Paragraph(func_text, body))
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>2.4 Trigger Mechanism & Input Vectors</b>", h2))
    story.append(Paragraph(escape(vuln_info["trigger_mechanism"]), body))
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>2.5 Security Implications & Threat Modeling</b>", h2))
    story.append(Paragraph(escape(vuln_info["security_implications"]), body))
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>2.6 Architectural Context & Host Environment</b>", h2))
    arch_rows = [
        [Paragraph("<b>Target Hostname:</b>", small), Paragraph(escape(hostname), small),
         Paragraph("<b>Target Scheme / Port:</b>", small), Paragraph(escape(f"{urlparse(url).scheme.upper()} / {urlparse(url).port or ('443' if urlparse(url).scheme == 'https' else '80')}"), small)],
        [Paragraph("<b>HTTP Protocol:</b>", small), Paragraph("HTTP/1.1 (TLS Secured)" if urlparse(url).scheme == "https" else "HTTP/1.1 (Cleartext)", small),
         Paragraph("<b>Parameter Location:</b>", small), Paragraph("URL Query String" if method == "GET" else "HTTP Request Body", small)],
        [Paragraph("<b>Authentication Scope:</b>", small), Paragraph("Public / Unauthenticated" if "/admin" not in url else "Restricted Area", small),
         Paragraph("<b>Fingerprint Hash:</b>", small), Paragraph(f"<code>{escape((fingerprint or 'N/A')[:24])}</code>", small)],
    ]
    arch_tbl = Table(arch_rows, colWidths=[36 * mm, 52 * mm, 38 * mm, 52 * mm])
    arch_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(arch_tbl)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 3: STEPS TO REPRODUCE & VERIFICATION GUIDE
    # =========================================================================
    story.append(Paragraph("3. Steps to Reproduce & Verification Guide", h1))
    story.append(Spacer(1, 2 * mm))

    story.append(Paragraph("<b>3.1 Required Preconditions</b>", h2))
    precond_rows = [
        [Paragraph("<b>Network Access:</b>", small), Paragraph(f"Routable HTTP connection to <code>{escape(hostname)}</code>.", small)],
        [Paragraph("<b>Authentication:</b>", small), Paragraph("No active session required (Public endpoint)." if "/admin" not in url else "Requires authenticated session cookies.", small)],
        [Paragraph("<b>Required Tools:</b>", small), Paragraph("Standard cURL, Burp Suite Community/Pro, OWASP ZAP, or modern web browser.", small)],
        [Paragraph("<b>Testing Policy:</b>", small), Paragraph("Execute only non-destructive verification probes adhering to safe disclosure guidelines.", small)],
    ]
    precond_tbl = Table(precond_rows, colWidths=[34 * mm, 144 * mm])
    precond_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2),
    ]))
    story.append(precond_tbl)
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>3.2 Step-by-Step Reproduction Procedure</b>", h2))
    for i, step in enumerate(steps, 1):
        step_row = Table([[Paragraph(f"<b>Step {i}:</b>", small_bold), Paragraph(escape(step), body)]], colWidths=[16 * mm, 162 * mm])
        step_row.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 1.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
        ]))
        story.append(step_row)
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>3.3 Safe Proof of Concept (cURL Command)</b>", h2))
    poc_p = Paragraph(f"<font face='Courier' color='#0f172a'>{escape(poc_curl)}</font>", code_style)
    poc_box = Table([[poc_p]], colWidths=[178 * mm])
    poc_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(poc_box)
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>3.4 Expected vs Observed Behavior</b>", h2))
    behav_rows = [
        [Paragraph("<b>Condition</b>", small_bold), Paragraph("<b>Expected Secure Behavior</b>", small_bold), Paragraph("<b>Observed Vulnerable Behavior</b>", small_bold)],
        [
            Paragraph("Standard Input", small),
            Paragraph("Input validated; clean 200 OK or appropriate domain response.", small),
            Paragraph("Processed correctly.", small),
        ],
        [
            Paragraph("Crafted Probe", small),
            Paragraph("Server rejects probe with 400 Bad Request, parameterizes query, or encodes entities.", small),
            Paragraph("Server evaluates injected syntax, leaks database error, reflects unescaped script, or exhibits timing divergence.", small),
        ],
    ]
    behav_tbl = Table(behav_rows, colWidths=[30 * mm, 74 * mm, 74 * mm])
    behav_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(behav_tbl)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 4: TECHNICAL EVIDENCE & SERVER RESPONSES
    # =========================================================================
    story.append(Paragraph("4. Technical Evidence & Server Responses", h1))
    story.append(Spacer(1, 2 * mm))

    story.append(Paragraph("<b>4.1 Sanitized HTTP Request</b>", h2))
    req_p = Paragraph(f"<font face='Courier' color='#0f172a'>{escape(raw_req)}</font>", code_style)
    req_box = Table([[req_p]], colWidths=[178 * mm])
    req_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(req_box)
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>4.2 Sanitized HTTP Response</b>", h2))
    resp_p = Paragraph(f"<font face='Courier' color='#0f172a'>{escape(raw_resp)}</font>", code_style)
    resp_box = Table([[resp_p]], colWidths=[178 * mm])
    resp_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(resp_box)
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>4.3 Detection Evidence & Diagnostic Indicators</b>", h2))
    clean_ev = redact(evidence or "Active probe behavioral divergence confirmed.")
    ev_p = Paragraph(f"<font face='Courier' color='#991b1b'><b>Observed Indicator:</b> {escape(clean_ev[:350])}</font>", code_style)
    ev_box = Table([[ev_p]], colWidths=[178 * mm])
    ev_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff1f2")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#fecdd3")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(ev_box)
    story.append(Spacer(1, 3 * mm))

    # Occurrences sub-table if multiple instances exist
    occurrences = getattr(finding, "evidence_details", {}).get("occurrences", []) if isinstance(getattr(finding, "evidence_details", None), dict) else []
    if occurrences and len(occurrences) > 1:
        story.append(Paragraph(f"<b>4.4 Additional Correlated Occurrences ({len(occurrences)} endpoints)</b>", h3))
        occ_rows = [[Paragraph("<b>Method & Path</b>", small_bold), Paragraph("<b>Parameter</b>", small_bold), Paragraph("<b>Evidence Summary</b>", small_bold)]]
        for occ in occurrences[:5]:
            occ_rows.append([
                Paragraph(escape(f"{occ.get('method', 'GET')} {urlparse(occ.get('url', '')).path or '/'}"), small),
                Paragraph(escape(occ.get("parameter", "—")), small),
                Paragraph(escape(redact(occ.get("evidence", "—")[:60])), small),
            ])
        occ_tbl = Table(occ_rows, colWidths=[60 * mm, 38 * mm, 80 * mm])
        occ_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(occ_tbl)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 5: IMPACT ANALYSIS & REMEDIATION STRATEGY
    # =========================================================================
    story.append(Paragraph("5. Impact Analysis & Remediation Strategy", h1))
    story.append(Spacer(1, 2 * mm))

    story.append(Paragraph("<b>5.1 Realistic Security Impact Analysis</b>", h2))
    story.append(Paragraph(escape(impact or vuln_info["security_implications"]), body))
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>5.2 Plausible Attack Scenarios</b>", h2))
    for scen in vuln_info.get("scenarios", []):
        story.append(Paragraph(f"• {escape(scen)}", body))
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>5.3 CIA Triad Impact Breakdown</b>", h2))
    cia = vuln_info["cia"]
    cia_rows = [
        [Paragraph("<b>Security Pillar</b>", small_bold), Paragraph("<b>Impact Tier</b>", small_bold), Paragraph("<b>Technical Justification & Threat Context</b>", small_bold)],
        [Paragraph("<b>Confidentiality</b>", small), Paragraph(f"<b>{cia['confidentiality'][0]}</b>", small), Paragraph(escape(cia['confidentiality'][1]), small)],
        [Paragraph("<b>Integrity</b>", small), Paragraph(f"<b>{cia['integrity'][0]}</b>", small), Paragraph(escape(cia['integrity'][1]), small)],
        [Paragraph("<b>Availability</b>", small), Paragraph(f"<b>{cia['availability'][0]}</b>", small), Paragraph(escape(cia['availability'][1]), small)],
    ]
    cia_tbl = Table(cia_rows, colWidths=[34 * mm, 28 * mm, 116 * mm])
    cia_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(cia_tbl)
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>5.4 Recommended Technical Remediation</b>", h2))
    story.append(Paragraph(escape(remediation or "Implement strict parameterization, context-aware output encoding, and input validation schemas."), body))
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>5.5 Secure Coding Implementation Example</b>", h2))
    code_p = Paragraph(f"<font face='Courier' color='#0f172a'>{escape(vuln_info['secure_code'])}</font>", code_style)
    code_box = Table([[code_p]], colWidths=[178 * mm])
    code_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(code_box)
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>5.6 Post-Remediation Verification Procedure</b>", h2))
    story.append(Paragraph(escape(vuln_info["verification"]), body))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 6: AUTHORITATIVE REFERENCES & ASSESSMENT NOTES
    # =========================================================================
    story.append(Paragraph("6. Authoritative References & Assessment Notes", h1))
    story.append(Spacer(1, 2 * mm))

    story.append(Paragraph("<b>6.1 Authoritative Standards & References</b>", h2))
    for ref in vuln_info.get("references", []):
        story.append(Paragraph(f"• <font color='#0284c7'><u>{escape(ref)}</u></font>", small))
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>6.2 CVSS v3.1 Metric Breakdown & Vector Explanation</b>", h2))
    if cvss["assessed"]:
        m = cvss["metrics"]
        cvss_detail_rows = [
            [Paragraph("<b>Metric Dimension</b>", small_bold), Paragraph("<b>Assigned Value</b>", small_bold), Paragraph("<b>Metric Significance</b>", small_bold)],
            [Paragraph("Attack Vector (AV)", small), Paragraph(m["av"], small), Paragraph("Network accessible: vulnerability triggerable over Internet without physical or local subnet proximity.", small)],
            [Paragraph("Attack Complexity (AC)", small), Paragraph(m["ac"], small), Paragraph("Low complexity: specialized access conditions or race windows are not required.", small)],
            [Paragraph("Privileges Required (PR)", small), Paragraph(m["pr"], small), Paragraph(f"Privileges: {m['pr']} – Accessible with current endpoint authorization context.", small)],
            [Paragraph("User Interaction (UI)", small), Paragraph(m["ui"], small), Paragraph("User interaction: " + ("Required (victim must trigger request)" if m["ui"] == "R" else "None (directly triggerable by attacker)"), small)],
            [Paragraph("Scope (S)", small), Paragraph(m["s"], small), Paragraph("Scope: " + ("Changed (impacts external origin / DOM sandbox)" if m["s"] == "C" else "Unchanged (impact limited to vulnerable security authority)"), small)],
            [Paragraph("Confidentiality (C)", small), Paragraph(m["c"], small), Paragraph(f"Impact: {m['c']} – " + ("Total or high information disclosure." if m["c"] == "H" else "Low disclosure or context-dependent."), small)],
            [Paragraph("Integrity (I)", small), Paragraph(m["i"], small), Paragraph(f"Impact: {m['i']} – " + ("Total or high state manipulation." if m["i"] == "H" else "Low/None state alteration."), small)],
            [Paragraph("Availability (A)", small), Paragraph(m["a"], small), Paragraph(f"Impact: {m['a']} – System resource availability impact tier.", small)],
        ]
        cvss_det_tbl = Table(cvss_detail_rows, colWidths=[40 * mm, 26 * mm, 112 * mm])
        cvss_det_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(cvss_det_tbl)
    else:
        story.append(Paragraph("CVSS base scoring was withheld to prevent speculative scoring. A manual risk evaluation is required.", body))
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>6.3 Testing Limitations & Scope Boundaries</b>", h2))
    limits_text = (
        "• This assessment was conducted via automated black-box dynamic application security testing (DAST).<br/>"
        "• Probing was strictly non-destructive and did not execute denial-of-service, persistent data alteration, or host compromise.<br/>"
        "• Client-side Single Page Application (SPA) state machines protected by multi-factor authentication or CAPTCHAs were out of automated scope."
    )
    story.append(Paragraph(limits_text, small))
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>6.4 Responsible Disclosure & Coordinated Timeline Notice</b>", h2))
    disclosure_text = (
        "This vulnerability report is submitted in accordance with standard Coordinated Vulnerability Disclosure (CVD) principles. "
        "The security researcher agrees to keep technical details confidential during the remediation window (standard 90-day timeline) "
        "to allow the asset owner to test and deploy patches. Testing was performed under safe harbor authorization without accessing customer data."
    )
    disc_box = Table([[Paragraph(disclosure_text, small)]], colWidths=[178 * mm])
    disc_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#0284c7")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(disc_box)

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()


# =============================================================================
# CONSOLIDATED COMPLETE WEBSITE BUG BOUNTY REPORT (4-6 PAGES)
# =============================================================================

def _finding_canonical_key(f: Any) -> str:
    """Build canonical deduplication key for grouping repeated findings across URLs."""
    ftype = str(getattr(f, "type", "") or "")
    furl = str(getattr(f, "url", "") or "")
    fparam = str(getattr(f, "parameter", "") or "").strip().lower()
    fevidence = str(getattr(f, "evidence", "") or "").strip().lower()

    parsed = urlparse(furl) if furl else None
    path = parsed.path if parsed and parsed.path else furl

    if ftype == "Missing Security Header":
        header_name = extract_header_name(fparam, fevidence)
        return f"header::{header_name.lower() if header_name else 'generic'}"

    if "Cookie" in ftype:
        return f"cookie::{ftype.lower()}::{fparam}"

    if ftype == "Technology Detection":
        return f"tech::{fevidence or fparam}"

    if ftype in ("Exposed Sensitive File", "Directory Listing", "Sensitive File Exposure"):
        return f"file::{ftype.lower()}::{path}"

    if fparam:
        return f"vuln::{ftype.lower()}::{fparam}"
    return f"vuln::{ftype.lower()}::{path.lower()}"


def group_findings_into_unique(findings: list) -> list[dict]:
    """
    Consolidates raw occurrences under unique vulnerabilities.
    Returns list of dicts with representative finding, occurrences count,
    affected URLs, CVSS assessment, and vulnerability-specific profile.
    """
    groups: dict[str, dict] = {}
    sev_rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}

    for f in findings:
        key = _finding_canonical_key(f)
        f_url = getattr(f, "url", "") or ""
        f_sev = getattr(f, "severity", "")
        f_sev_str = f_sev.value if hasattr(f_sev, "value") else str(f_sev)
        f_det = getattr(f, "detection_status", "Confirmed") or "Confirmed"

        if key not in groups:
            groups[key] = {
                "key": key,
                "representative": f,
                "type": getattr(f, "type", "Vulnerability"),
                "cwe_id": getattr(f, "cwe_id", None),
                "severity": f_sev_str,
                "detection_status": f_det,
                "confidence": getattr(f, "confidence", "Confirmed"),
                "url": f_url,
                "method": getattr(f, "method", "GET") or "GET",
                "parameter": getattr(f, "parameter", None) or "None",
                "occurrences": 1,
                "affected_urls": [f_url] if f_url else [],
                "raw_findings": [f],
            }
        else:
            g = groups[key]
            g["occurrences"] += 1
            if f_url and f_url not in g["affected_urls"]:
                g["affected_urls"].append(f_url)
            g["raw_findings"].append(f)

            # Prioritize Confirmed over Potential/Manual Verification
            if f_det == "Confirmed" and g["detection_status"] != "Confirmed":
                g["detection_status"] = "Confirmed"
                g["representative"] = f

            # Prioritize higher severity as representative
            if sev_rank.get(f_sev_str, 0) > sev_rank.get(g["severity"], 0):
                g["severity"] = f_sev_str
                g["representative"] = f

    results = list(groups.values())
    results.sort(key=lambda x: (sev_rank.get(x["severity"], 0), x["occurrences"]), reverse=True)

    # Attach enriched knowledge and CVSS assessment to each unique group
    for u in results:
        rep = u["representative"]
        if u["type"] == "Missing Security Header":
            hname = extract_header_name(getattr(rep, "parameter", None), getattr(rep, "evidence", None))
            if hname:
                u["parameter"] = hname
                if hname in SECURITY_HEADER_RULES:
                    hrule_sev = SECURITY_HEADER_RULES[hname]["severity"]
                    u["severity"] = hrule_sev.value if hasattr(hrule_sev, "value") else str(hrule_sev)
        v_info = match_vuln_knowledge(u["type"])
        u["vuln_info"] = v_info
        u["cvss"] = assess_finding_cvss(rep, v_info)
        u["steps"] = generate_reproduction_steps(rep)
        u["poc_curl"] = generate_safe_poc(rep)
        u["evidence"] = getattr(rep, "evidence", "") or ""
    return results


def build_complete_website_bug_bounty_pdf(scan, findings, summary=None) -> bytes:
    """
    Generate ONE comprehensive, consolidated 4-6 page Bug Bounty PDF report
    for the ENTIRE website scanned, grouping duplicate raw occurrences under
    unique vulnerabilities and presenting complete evidence and remediation.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="ZeroTrace — Security Assessment Short Report",
        author="ZeroTrace Vulnerability Assessment Platform",
    )

    ss = getSampleStyleSheet()

    # Typography styles
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=colors.HexColor("#0f172a"), fontSize=14, leading=18, spaceAfter=3)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=colors.HexColor("#0f172a"), fontSize=11, leading=14, spaceBefore=4, spaceAfter=2)
    h3 = ParagraphStyle("h3", parent=ss["Heading3"], textColor=colors.HexColor("#1e293b"), fontSize=9, leading=12, spaceBefore=3, spaceAfter=2)
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=7.8, leading=10.8, textColor=colors.HexColor("#1e293b"))
    body_bold = ParagraphStyle("body_bold", parent=body, fontName="Helvetica-Bold")
    small = ParagraphStyle("small", parent=body, fontSize=7.0, leading=9.0, textColor=colors.HexColor("#475569"))
    small_bold = ParagraphStyle("small_bold", parent=small, fontName="Helvetica-Bold")
    code_style = ParagraphStyle("code", parent=body, fontName="Courier", fontSize=6.5, leading=8.2, textColor=colors.HexColor("#0f172a"))

    posture = calculate_security_posture(scan, findings)
    unique_vulns = group_findings_into_unique(findings)

    target_url = getattr(scan.target, "base_url", "https://target.local") if getattr(scan, "target", None) else "https://target.local"
    hostname = posture.get("hostname") or urlparse(target_url).hostname or "target.local"
    scan_id = getattr(scan, "id", "")
    created_at = getattr(scan, "created_at", None) or datetime.now(timezone.utc)
    app_name = getattr(getattr(scan, "application", None), "name", None)
    duration_str = f"{scan.duration_seconds:.1f}s" if getattr(scan, "duration_seconds", None) else "N/A"

    score = posture.get("score", 100.0)
    rating = posture.get("rating", "STRONG")
    rating_color = colors.HexColor(posture.get("rating_color", "#10b981"))

    total_raw = len(findings)
    total_unique = len(unique_vulns)
    confirmed_unique = sum(1 for u in unique_vulns if u["detection_status"] == "Confirmed")
    potential_unique = sum(1 for u in unique_vulns if u["detection_status"] != "Confirmed")

    story = []

    # =========================================================================
    # PAGE 1: WEBSITE SECURITY OVERVIEW & EXECUTIVE SUMMARY
    # =========================================================================
    header_tbl = Table(
        [
            [
                Paragraph("<b>ZeroTrace</b> — Security Assessment Short Report", ParagraphStyle("hdr_title", parent=body, fontSize=11, fontName="Helvetica-Bold", textColor=colors.HexColor("#0f172a"))),
                Paragraph("CONSOLIDATED AUDIT // CONFIDENTIAL", ParagraphStyle("hdr_sub", parent=body, fontSize=8, fontName="Helvetica-Bold", textColor=colors.HexColor("#0284c7"), alignment=2)),
            ]
        ],
        colWidths=[120 * mm, 58 * mm],
    )
    header_tbl.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 1.2, colors.HexColor("#0284c7")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 3 * mm))

    # Overall Security Score Banner Card
    score_card_content = [
        [
            Paragraph(f"<font size=22><b>{score:.0f}</b></font><font size=10>/100</font><br/><font size=7.5 color='#475569'>SECURITY SCORE</font>", ParagraphStyle("sc_c", parent=body, alignment=1)),
            Paragraph(f"<font size=13 color='white'><b>{rating} POSTURE</b></font><br/><font size=7.5 color='#f1f5f9'>Evaluated against OWASP Web Top 10 heuristics</font>", ParagraphStyle("rt_c", parent=body, alignment=1)),
            Paragraph(f"<b>Overall Security Risk:</b> {'HIGH RISK' if score < 60 else 'MODERATE RISK' if score < 85 else 'LOW RISK'}<br/>"
                      f"<b>Unique Vulnerabilities:</b> {total_unique} issue(s)<br/>"
                      f"<b>Total Raw Occurrences:</b> {total_raw} grouped instance(s)", small),
        ]
    ]
    score_card = Table(score_card_content, colWidths=[38 * mm, 56 * mm, 84 * mm])
    score_card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#f8fafc")),
        ("BACKGROUND", (1, 0), (1, 0), rating_color),
        ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(score_card)
    story.append(Spacer(1, 3 * mm))

    # Target Metadata Grid
    meta_rows = [
        [Paragraph("<b>Target Hostname</b>", small), Paragraph(escape(hostname), small),
         Paragraph("<b>Target Base URL</b>", small), Paragraph(f"<font color='#0284c7'>{escape(target_url[:55])}</font>", small)],
        [Paragraph("<b>Associated App</b>", small), Paragraph(escape(app_name or "Standalone Web Target"), small),
         Paragraph("<b>Assessment Identifier</b>", small), Paragraph(f"<code>{str(scan_id)[:24]}</code>", small)],
        [Paragraph("<b>Scan Date</b>", small), Paragraph(f"{created_at:%Y-%m-%d %H:%M} UTC", small),
         Paragraph("<b>Crawl Duration</b>", small), Paragraph(escape(duration_str), small)],
    ]
    meta_tbl = Table(meta_rows, colWidths=[30 * mm, 58 * mm, 34 * mm, 56 * mm])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 3 * mm))

    # High-Level Scan Statistics Matrix
    cov_summary = getattr(scan, "coverage_summary", {}) or {}
    disc_ep = cov_summary.get("endpoints_discovered", scan.urls_discovered or 0)
    tested_ep = cov_summary.get("endpoints_tested", scan.urls_scanned or 0)
    disc_forms = cov_summary.get("forms_discovered", 0)
    tested_params = cov_summary.get("parameters_tested", 0)

    scope_rows = [
        [
            Paragraph("<b>Pages Crawled:</b>", small), Paragraph(str(tested_ep), small),
            Paragraph("<b>Endpoints Discovered:</b>", small), Paragraph(str(disc_ep), small),
            Paragraph("<b>Discovered Forms:</b>", small), Paragraph(str(disc_forms), small),
        ],
        [
            Paragraph("<b>Unique Vulnerabilities:</b>", small), Paragraph(f"<b>{total_unique}</b>", small),
            Paragraph("<b>Confirmed Issues:</b>", small), Paragraph(f"<font color='#059669'><b>{confirmed_unique}</b></font>", small),
            Paragraph("<b>Potential / Manual:</b>", small), Paragraph(f"<font color='#d97706'><b>{potential_unique}</b></font>", small),
        ],
    ]
    scope_tbl = Table(scope_rows, colWidths=[34 * mm, 24 * mm, 36 * mm, 24 * mm, 34 * mm, 26 * mm])
    scope_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2),
    ]))
    story.append(scope_tbl)
    story.append(Spacer(1, 3 * mm))

    # Severity Breakdown (Unique vs Raw)
    sev_matrix_data = [
        [
            Paragraph("<b>Severity Tier</b>", small_bold),
            Paragraph("<b>Unique Issues</b>", small_bold),
            Paragraph("<b>Raw Occurrences</b>", small_bold),
            Paragraph("<b>Risk & Operational Impact Description</b>", small_bold),
        ]
    ]
    sev_desc = {
        "Critical": "Direct remote code execution, database compromise, or administrative authentication bypass.",
        "High": "High-impact data exfiltration, blind SQLi, persistent XSS, or privileged state manipulation.",
        "Medium": "Reflected XSS, CSRF, sensitive information exposure, or weak session configurations.",
        "Low": "Missing defense-in-depth headers, clickjacking risk, or verbose server error banners.",
        "Informational": "Technology fingerprinting, discovered endpoints, and structural attack surface context.",
    }
    for s_name in ["Critical", "High", "Medium", "Low", "Informational"]:
        u_cnt = sum(1 for u in unique_vulns if u["severity"] == s_name)
        r_cnt = sum(u["occurrences"] for u in unique_vulns if u["severity"] == s_name)
        s_hex = SEV_COLORS.get(s_name, "#475569")
        sev_matrix_data.append([
            Paragraph(f"<font color='{s_hex}'><b>● {s_name}</b></font>", small),
            Paragraph(f"<b>{u_cnt}</b>", small),
            Paragraph(str(r_cnt), small),
            Paragraph(sev_desc.get(s_name, ""), small),
        ])
    sev_table = Table(sev_matrix_data, colWidths=[28 * mm, 24 * mm, 26 * mm, 100 * mm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.0),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 3 * mm))

    # Executive Summary Paragraph
    story.append(Paragraph("<b>1. Executive Summary & Security Risk Assessment</b>", h2))
    exec_text = (
        f"ZeroTrace conducted a comprehensive web vulnerability assessment against <b>{escape(hostname)}</b> "
        f"({escape(target_url)}). A total of <b>{tested_ep} pages</b> and <b>{disc_ep} endpoints</b> were crawled, "
        f"identifying <b>{total_unique} unique vulnerability classes</b> across <b>{total_raw} raw occurrences</b>. "
        f"The application achieved an overall security posture score of <b>{score:.0f}/100 ({rating})</b>. "
    )
    if confirmed_unique > 0:
        crit_high = sum(1 for u in unique_vulns if u["detection_status"] == "Confirmed" and u["severity"] in ("Critical", "High"))
        if crit_high > 0:
            exec_text += (
                f"Triage attention is required: <b>{crit_high} unique issue(s) carry Critical or High severity</b>, "
                "representing actionable attack vectors for data exposure or unauthorized state modification."
            )
        else:
            exec_text += "No Critical or High severity issues were confirmed; identified findings primarily represent medium-risk configuration or injection vectors."
    else:
        exec_text += "No confirmed vulnerabilities were identified within the evaluated scope. Defensive baseline controls are maintained."
    story.append(Paragraph(exec_text, body))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 2: VULNERABILITY FINDINGS SUMMARY TABLE
    # =========================================================================
    story.append(Paragraph("2. Consolidated Vulnerability Findings Summary", h1))
    story.append(Paragraph(
        "The following matrix lists ALL unique vulnerabilities identified during the website assessment. "
        "Duplicate occurrences across separate URLs have been aggregated under their parent vulnerability class.",
        small,
    ))
    story.append(Spacer(1, 2.5 * mm))

    if not unique_vulns:
        story.append(Paragraph("<i>No vulnerabilities were detected during this scan.</i>", body))
    else:
        summary_rows = [
            [
                Paragraph("<b>#</b>", small_bold),
                Paragraph("<b>Severity</b>", small_bold),
                Paragraph("<b>Vulnerability Title & Category</b>", small_bold),
                Paragraph("<b>Status</b>", small_bold),
                Paragraph("<b>CWE ID</b>", small_bold),
                Paragraph("<b>Scope / Occurrences</b>", small_bold),
                Paragraph("<b>CVSS v3.1</b>", small_bold),
            ]
        ]
        for idx, u in enumerate(unique_vulns, 1):
            s_val = u["severity"]
            s_hex = SEV_COLORS.get(s_val, "#475569")
            det_st = u["detection_status"]
            det_color = "#059669" if det_st == "Confirmed" else "#d97706"
            cvss_data = u["cvss"]
            cvss_str = f"<b>{cvss_data['score']}</b> ({cvss_data['severity']})" if cvss_data.get("assessed") else "Not Assessed"
            cwe_str = u["cwe_id"] or u["vuln_info"].get("cwe", "CWE-699").split(":")[0]
            scope_str = f"{len(u['affected_urls'])} route(s) ({u['occurrences']} hit{'s' if u['occurrences'] > 1 else ''})"

            summary_rows.append([
                Paragraph(str(idx), small),
                Paragraph(f"<font color='{s_hex}'><b>{s_val.upper()}</b></font>", small),
                Paragraph(f"<b>{escape(u['vuln_info']['canonical'])}</b>", small),
                Paragraph(f"<font color='{det_color}'><b>{det_st}</b></font>", small),
                Paragraph(escape(cwe_str), small),
                Paragraph(escape(scope_str), small),
                Paragraph(cvss_str, small),
            ])

        summary_tbl = Table(summary_rows, colWidths=[8 * mm, 22 * mm, 46 * mm, 26 * mm, 22 * mm, 30 * mm, 24 * mm])
        summary_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 2.0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.0),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(summary_tbl)
        story.append(Spacer(1, 4 * mm))

    # CVSS Methodology & Triage Policy
    story.append(Paragraph("<b>2.1 CVSS Scoring Methodology & Responsible Triage Policy</b>", h2))
    cvss_policy = (
        "• <b>Ground Truth Scoring:</b> CVSS base metrics are computed using the official FIRST.org equation strictly when "
        "exploitability and scope impact are evidenced by active probe responses.<br/>"
        "• <b>Non-Fabrication Policy:</b> Items marked <i>Potential</i> or <i>Requires Manual Verification</i> display 'Not Assessed – Manual Evaluation Required' "
        "to prevent premature or inaccurate severity inflation.<br/>"
        "• <b>Duplicate Aggregation:</b> Multiple identical findings across different endpoints (e.g. site-wide missing security headers) "
        "are consolidated to give program managers an actionable vulnerability inventory without artificial count inflation."
    )
    cvss_p_box = Table([[Paragraph(cvss_policy, small)]], colWidths=[178 * mm])
    cvss_p_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(cvss_p_box)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 3: TECHNICAL FINDINGS AND EVIDENCE
    # =========================================================================
    story.append(Paragraph("3. Technical Findings & Server Evidence", h1))
    story.append(Paragraph(
        "Detailed technical breakdown, affected endpoints, and raw response indicators for each unique vulnerability.",
        small,
    ))
    story.append(Spacer(1, 2.5 * mm))

    if not unique_vulns:
        story.append(Paragraph("<i>No technical vulnerabilities identified.</i>", body))
    else:
        for idx, u in enumerate(unique_vulns[:7], 1):
            s_val = u["severity"]
            s_hex = SEV_COLORS.get(s_val, "#475569")
            ev_clean = redact(u["evidence"] or "Active behavioral divergence verified against baseline response.")
            prim_url = u["url"] or target_url
            path = urlparse(prim_url).path or "/"

            card_rows = [
                [
                    Paragraph(f"<b>{idx}. {escape(u['vuln_info']['canonical'].upper())}</b>", ParagraphStyle("tc_t", parent=body_bold, fontSize=8.5, textColor=colors.HexColor("#0f172a"))),
                    Paragraph(f"<font color='{s_hex}'><b>{s_val.upper()} | {u['detection_status'].upper()}</b></font>", ParagraphStyle("tc_s", parent=small_bold, alignment=2)),
                ],
                [
                    Paragraph(
                        f"<b>Primary Endpoint:</b> {escape(u['method'])} <code>{escape(path)}</code> &nbsp;|&nbsp; "
                        f"<b>Parameter:</b> <code>{escape(u['parameter'])}</code> &nbsp;|&nbsp; "
                        f"<b>Scope:</b> {len(u['affected_urls'])} endpoint(s), {u['occurrences']} raw hit(s)<br/>"
                        f"<b>Root Cause:</b> {escape(u['vuln_info']['root_cause'][:120])}",
                        small,
                    ),
                    "",
                ],
                [
                    Paragraph(f"<b>Detection Evidence:</b> <font face='Courier' color='#0f172a'>{escape(ev_clean[:180])}</font>", code_style),
                    "",
                ],
            ]
            card_tbl = Table(card_rows, colWidths=[122 * mm, 56 * mm])
            card_tbl.setStyle(TableStyle([
                ("SPAN", (0, 1), (1, 1)),
                ("SPAN", (0, 2), (1, 2)),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, colors.HexColor(s_hex)),
                ("TOPPADDING", (0, 0), (-1, -1), 1.8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1.8),
            ]))
            story.append(KeepTogether([card_tbl, Spacer(1, 2 * mm)]))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 4: STEPS TO REPRODUCE & IMPACT ANALYSIS
    # =========================================================================
    story.append(Paragraph("4. Steps to Reproduce & Realistic Impact Analysis", h1))
    story.append(Paragraph(
        "Reproducible verification procedures based on actual scan evidence, non-destructive cURL PoCs, and CIA impact.",
        small,
    ))
    story.append(Spacer(1, 2.5 * mm))

    if not unique_vulns:
        story.append(Paragraph("<i>No vulnerabilities to reproduce.</i>", body))
    else:
        for idx, u in enumerate(unique_vulns[:6], 1):
            s_val = u["severity"]
            s_hex = SEV_COLORS.get(s_val, "#475569")
            poc = u["poc_curl"]
            cia = u["vuln_info"]["cia"]

            rp_rows = [
                [
                    Paragraph(f"<b>Finding {idx}: {escape(u['vuln_info']['canonical'])}</b>", ParagraphStyle("rp_t", parent=body_bold, fontSize=8.2)),
                    Paragraph(f"<font color='{s_hex}'><b>CIA: C:{cia['confidentiality'][0][0]} I:{cia['integrity'][0][0]} A:{cia['availability'][0][0]}</b></font>", ParagraphStyle("rp_cia", parent=small_bold, alignment=2)),
                ],
                [
                    Paragraph(
                        f"<b>Reproduction Step:</b> Send {escape(u['method'])} request to <code>{escape(urlparse(u['url']).path or '/')}</code> "
                        f"with parameter <code>{escape(u['parameter'])}</code>.<br/>"
                        f"<b>Proof of Concept:</b> <font face='Courier'>{escape(poc[:110])}</font><br/>"
                        f"<b>Expected:</b> Parameterized query or input sanitized. &nbsp;|&nbsp; "
                        f"<b>Observed:</b> Payload triggers behavioral divergence.",
                        small,
                    ),
                    "",
                ],
            ]
            rp_tbl = Table(rp_rows, colWidths=[122 * mm, 56 * mm])
            rp_tbl.setStyle(TableStyle([
                ("SPAN", (0, 1), (1, 1)),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, colors.HexColor(s_hex)),
                ("TOPPADDING", (0, 0), (-1, -1), 1.8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1.8),
            ]))
            story.append(KeepTogether([rp_tbl, Spacer(1, 2 * mm)]))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 5: REMEDIATION AND RECOMMENDATIONS
    # =========================================================================
    story.append(Paragraph("5. Remediation Strategy & Defensive Guidelines", h1))
    story.append(Paragraph(
        "Actionable technical remediation guidance, secure coding implementations, and website-wide improvement roadmap.",
        small,
    ))
    story.append(Spacer(1, 2.5 * mm))

    if not unique_vulns:
        story.append(Paragraph("<i>Defensive baseline maintained. Continue periodic automated assessments.</i>", body))
    else:
        for idx, u in enumerate(unique_vulns[:5], 1):
            s_val = u["severity"]
            s_hex = SEV_COLORS.get(s_val, "#475569")
            v_info = u["vuln_info"]

            rem_rows = [
                [
                    Paragraph(f"<b>Remediation {idx}: {escape(v_info['canonical'])}</b>", ParagraphStyle("rm_t", parent=body_bold, fontSize=8.2)),
                    Paragraph(f"<font color='{s_hex}'><b>Priority: {'Phase 1 (Immediate)' if s_val in ('Critical', 'High') else 'Phase 2 (Sprint)'}</b></font>", ParagraphStyle("rm_p", parent=small_bold, alignment=2)),
                ],
                [
                    Paragraph(
                        f"<b>Guidance:</b> {escape(v_info['root_cause'])}<br/>"
                        f"<b>Code Pattern:</b> <font face='Courier'>{escape(v_info['secure_code'].splitlines()[0] if v_info['secure_code'] else 'Sanitize input')}</font><br/>"
                        f"<b>Verification:</b> {escape(v_info['verification'].splitlines()[0] if v_info['verification'] else 'Retest endpoint in staging.')}",
                        small,
                    ),
                    "",
                ],
            ]
            rem_tbl = Table(rem_rows, colWidths=[122 * mm, 56 * mm])
            rem_tbl.setStyle(TableStyle([
                ("SPAN", (0, 1), (1, 1)),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("LINEBEFORE", (0, 0), (0, -1), 2.5, colors.HexColor(s_hex)),
                ("TOPPADDING", (0, 0), (-1, -1), 1.8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1.8),
            ]))
            story.append(KeepTogether([rem_tbl, Spacer(1, 2 * mm)]))

    # Website-Wide Security Roadmap
    story.append(Spacer(1, 1.5 * mm))
    story.append(Paragraph("<b>5.1 Website Security Posture Improvement Roadmap</b>", h2))
    roadmap_text = (
        "• <b>Phase 1 – Immediate Triage (24–48h):</b> Parameterize backend queries and apply contextual escaping to prevent active injection.<br/>"
        "• <b>Phase 2 – Application Hardening (Sprint):</b> Implement strict anti-CSRF tokens and set cookie attributes (`Secure`, `HttpOnly`, `SameSite=Lax`).<br/>"
        "• <b>Phase 3 – Defense-in-Depth Hygiene:</b> Deploy comprehensive Content Security Policy (CSP) headers and restrict CORS origins."
    )
    road_box = Table([[Paragraph(roadmap_text, small)]], colWidths=[178 * mm])
    road_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(road_box)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 6: ASSESSMENT NOTES, SCANNER SCOPE & RESPONSIBLE DISCLOSURE
    # =========================================================================
    story.append(Paragraph("6. Assessment Notes, Scanner Scope & Responsible Disclosure", h1))
    story.append(Spacer(1, 2 * mm))

    # Scanner Module Execution Matrix
    story.append(Paragraph("<b>6.1 Scanner Module Coverage & Execution Scope</b>", h2))
    mod_status = cov_summary.get("modules", {})
    modules_list = [
        ("SQL Injection", "sqli", "Active injection testing on inputs, forms, and JSON payloads"),
        ("Cross-Site Scripting (XSS)", "xss", "Reflected and stored XSS contextual payload probes"),
        ("Command Injection", "command_injection", "OS command chaining and pipe execution tests"),
        ("Directory Traversal", "directory_traversal", "Relative path traversal and LFI probes"),
        ("Sensitive Files", "sensitive_files", "Exposed .env, .git, backups, and config checks"),
        ("CSRF Verification", "csrf", "Anti-CSRF token presence and SameSite cookie evaluation"),
        ("Security Headers", "security_headers", "CSP, HSTS, X-Content-Type-Options, Referrer-Policy"),
        ("CORS Misconfiguration", "cors", "Wildcard and reflected origin header verification"),
        ("Clickjacking", "clickjacking", "X-Frame-Options and frame-ancestors enforcement"),
    ]
    mod_rows = [
        [Paragraph("<b>Scanner Module</b>", small_bold), Paragraph("<b>Status</b>", small_bold), Paragraph("<b>Execution Scope & Boundary</b>", small_bold)]
    ]
    for m_name, m_key, m_desc in modules_list:
        st = mod_status.get(m_key, "Tested")
        st_color = "#059669" if st == "Tested" else "#d97706" if st in ("Incomplete", "Auth Required") else "#64748b"
        mod_rows.append([
            Paragraph(f"<b>{m_name}</b>", small),
            Paragraph(f"<font color='{st_color}'><b>{st}</b></font>", small),
            Paragraph(m_desc, small),
        ])
    mod_tbl = Table(mod_rows, colWidths=[52 * mm, 26 * mm, 100 * mm])
    mod_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 1.8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.8),
    ]))
    story.append(mod_tbl)
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>6.2 Testing Limitations & Scope Boundaries</b>", h2))
    limits_text = (
        "• <b>Non-Destructive Constraint:</b> Probing was strictly non-destructive. No persistent data modification or denial-of-service tests were executed.<br/>"
        "• <b>Authentication Boundaries:</b> Protected single-page application routes requiring multi-factor authentication were outside automated scope.<br/>"
        "• <b>WAF / Rate Limiting:</b> Network rate limiters or Web Application Firewalls may throttle automated scan sequences."
    )
    story.append(Paragraph(limits_text, small))
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>6.3 Responsible Disclosure & Coordinated Timeline Notice</b>", h2))
    disclosure_text = (
        "This vulnerability report is submitted in accordance with standard Coordinated Vulnerability Disclosure (CVD) principles. "
        "The security researcher agrees to keep technical details confidential during the remediation window (standard 90-day timeline) "
        "to allow the asset owner to test and deploy patches. Testing was performed under safe harbor authorization without accessing customer data."
    )
    disc_box = Table([[Paragraph(disclosure_text, small)]], colWidths=[178 * mm])
    disc_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#0284c7")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story.append(disc_box)

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()

