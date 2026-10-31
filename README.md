# ZeroTrace

**Automated Web Vulnerability Scanner**  
*Discover. Analyze. Secure.*

An educational, **authorized-use-only** web security assessment platform. The detection engine is implemented in our own Python modules (no wrapping of external scanners): crawler, Playwright-based Single Page Application (SPA) discovery, parameter discovery, nine vulnerability checks, correlation, severity/confidence engine, Website Security Posture heuristic scoring, React dashboard, and PDF reports.

> ⚠️ Scan only systems you own or have explicit written permission to test. Unauthorized scanning may be illegal.

## Features
- **Dynamic Localhost Port Support**: Scan applications running on arbitrary, dynamic host ports (e.g. `http://localhost:49704/`, `http://localhost:50091/`, `http://localhost:5173/`, `http://localhost:3000/`, `http://localhost:8000/`) from Docker without hardcoded port lists.
- **Client-Side SPA & Flutter Web Discovery**: Optional Playwright-based headless browser discovery to render client-side JavaScript, discover hash-based routes (e.g. `/#/welcome`, `/#/login`, `/#/signup`, `/#/dashboard`), track route accessibility, and honestly report protected pages requiring authentication.
- **Strict SSRF & Redirect Protection**: Local development scanning is disabled by default (`ALLOW_LOCAL_DEV_TARGET=false`). Host targets are safely routed through `host.docker.internal` with DNS validation, cloud metadata blocking (`169.254.169.254`), and destination checks at every redirect hop.
- **Sensitive File False Positive Elimination**: Validates candidate files (`.env`, `.git/config`, `backup.zip`, etc.) against baseline SPA catch-all fallback responses and enforces file-specific signatures (magic bytes, INI headers, environment assignments) so generic HTTP 200 HTML fallback pages are never misreported as sensitive file exposures.
- **9 vulnerability modules**: SQL injection, XSS, CSRF, security headers, directory listing, sensitive files, open redirect, information disclosure, cookie security.
- **Website Security Posture**: Heuristic scoring (0–100) with STRONG, MEDIUM, and WEAK ratings, deduplicated findings correlation, confidence-based penalty weights, score deduction breakdown, route coverage breakdown, and prioritized remediation recommendations.
- **Separate severity & confidence**: severity (impact) and confidence (certainty) with documented rules (`scanner/severity.py`), distinguishing confirmed issues from those requiring manual verification.
- **FastAPI REST API**: background scan jobs (asyncio tasks) with live progress polling, cancellation, and security posture endpoint.
- **React + Tailwind + Recharts dashboard**: filterable findings, interactive severity comparison charts, route coverage breakdown, and security posture card.
- **ReportLab PDF reports**: executive posture summaries, deduction breakdowns, route metrics, severity distribution, and secret redaction.
- **Docker Compose**: frontend, backend, PostgreSQL database, and automated pytest suite.

## Architecture
```
React Dashboard -> FastAPI -> Scan Manager (scanner/engine.py)
   -> Crawler / Playwright Browser Discovery -> Discovery -> [module scanners] -> Correlation -> Security Posture -> DB -> PDF
```
```
backend/app/
  api/ core/ (config, ssrf_protection, rate_limiter, logging) database/ models/ schemas/
  scanner/ crawler.py browser_crawler.py engine.py severity.py http_client.py models.py scanners/*.py
  services/ security_posture.py
  reports/ pdf_report.py
frontend/src/ pages/ components/ services/ hooks/ utils/
```

## Running ZeroTrace with Docker Compose

### 1. Configure Environment
```bash
cp .env.example .env
```

### 2. Start Services
```bash
docker compose up -d --build
```
* **Web Dashboard**: [http://localhost:3000](http://localhost:3000)
* **API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
* **Health Check**: [http://localhost:8000/api/health](http://localhost:8000/api/health)

To stop services:
```bash
docker compose down
```

---

## Dynamic Localhost Port Support & Development Scanning

ZeroTrace runs containerized inside Docker, while your local development servers run on the Windows host. ZeroTrace supports scanning local development projects running on **any dynamic port** (e.g. `http://localhost:49704/`, `http://localhost:50091/`, `http://localhost:5173/`, `http://localhost:3000/`, `http://localhost:8000/`).

Whenever you restart a development server and its port changes, you can simply supply the new port in the target URL. ZeroTrace does not require any fixed allowlist or hardcoded port configuration.

Local development scanning is **disabled by default** to preserve strict production SSRF isolation.

### Enabling Local Development Scanning

Set `ALLOW_LOCAL_DEV_TARGET=true` in your `.env` file:
```ini
ALLOW_LOCAL_DEV_TARGET=true
```

Then restart the containers:
```powershell
docker compose up -d
```

### Entering Targets in the Dashboard
In the **New Scan** screen:
* Enter the URL with your target port:
  * `http://localhost:50091/`
  * `http://localhost:49704/`
  * `http://localhost:5173/`
  * `http://localhost:3000/`
  * `http://localhost:8000/`
* ZeroTrace normalizes `localhost` and `127.0.0.1` targets to `host.docker.internal:<port>`, preserving the exact requested port.
* Check **Enable Browser Discovery (Playwright / SPA)** to uncover client-rendered hash routes (e.g. `/#/welcome`, `/#/login`, `/#/signup`, `/#/dashboard`).
* Confirm test authorization and click **Start Scan**.

### SSRF Protections Enforced
* **Target validation:** Only the user-selected host target and port are allowed. Port sweeps or scans of unselected ports are blocked.
* **Metadata & link-local blocked:** Cloud metadata (`169.254.169.254`) and unauthorized private IP subnets (`10.0.0.0/8`, `192.168.0.0/16`) remain strictly blocked.
* **Redirect verification:** Every redirect hop is checked with `validate_redirect_url`. Redirects from local targets cannot jump to other ports or internal services.
* **Same-origin enforcement:** Crawling stays strictly within the scheme, host, and port of the verified target.

---

## Single Page Application (SPA) & Hash Route Crawling

Modern web frameworks (Flutter Web, React, Vue, Angular) often use client-side routing with hash fragments (`/#/welcome`, `/#/login`, `/#/signup`, `/#/dashboard`). Traditional HTTP crawlers only receive the static HTML shell and miss all client-rendered views.

ZeroTrace solves this with **Browser Discovery**:
* **JavaScript rendering:** Uses Playwright headless Chromium to execute client-side bundles and load the complete UI DOM.
* **Route extraction:** Extracts named routes from script manifests (such as Flutter `MaterialApp.routes`, `onGenerateRoute`, React Router, etc.) and DOM anchors.
* **Route tracking:** Tracks and reports:
  - `routes_discovered`: all identified routes
  - `routes_visited`: routes navigated to
  - `routes_tested`: accessible routes tested by vulnerability modules
  - `routes_auth_required`: protected pages (e.g. `/#/home`, `/#/dashboard`) where unauthenticated access was challenged or redirected
  - `routes_failed`: routes that timed out or errored
* **State safety:** Never automatically submits forms or executes state-changing actions (POST/DELETE/SAVE).
* **Resilient fallback:** If browser automation is unavailable, gracefully falls back to static bundle regex extraction.

---

## Unit & Integration Tests

The test suite is fully self-contained with mock endpoints, unit assertions, and FastAPI `TestClient`. It does not require any external vulnerable application.

### Running Tests in Docker
```powershell
docker compose exec backend pytest -v
```

All 38 test suites verify:
- Dynamic port acceptance across arbitrary ports (`49704`, `50091`, `5173`, `3000`, `8000`)
- Disabled-by-default local development safety rejection
- SSRF metadata and private network blocking
- Redirect validation and port change prevention
- SPA hash route preservation in `normalize_url`
- Sensitive file exposure SPA fallback false-positive rejection
- Genuine `.env` and `.git/config` detection
- Browser crawler route discovery and authentication detection
- Heuristic scoring thresholds, deduplication, and confidence multipliers
- PDF report generation and security posture API responses

---

## Limitations
Automated scanning cannot guess complex multi-step business logic or authenticated workflows, can yield false positives/negatives, and only assesses accessible routes. ZeroTrace security scores are heuristic assessment indicators rather than compliance certifications. Manual verification by qualified analysts is strongly recommended.
