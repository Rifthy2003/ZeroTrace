# Automated Web Vulnerability Scanner

An educational, **authorized-use-only** web security assessment platform. The detection engine is implemented in our own Python modules (no wrapping of external scanners): crawler, parameter discovery, nine vulnerability checks, correlation, severity/confidence engine, React dashboard and PDF reports.

> ⚠️ Scan only systems you own or have explicit written permission to test. Unauthorized scanning may be illegal.

## Features
- Async same-origin crawler (depth / URL / rate limits, URL normalization, dedup, forms + GET/POST parameters)
- 9 modules: SQL injection, XSS, CSRF, security headers, directory listing, sensitive files, open redirect, information disclosure, cookie security
- Separate **severity** (impact) and **confidence** (certainty) with documented rules (`scanner/severity.py`)
- FastAPI REST API, background scan jobs (asyncio tasks) with progress + cancel
- React + Tailwind + Recharts dashboard (8 pages), filterable findings
- ReportLab PDF report with secret redaction
- Docker Compose (frontend, backend, PostgreSQL), pytest suite, deliberately vulnerable local lab app

## Architecture
```
React Dashboard -> FastAPI -> Scan Manager (scanner/engine.py)
   -> Crawler -> Discovery -> [module scanners] -> Correlation -> Severity/Confidence -> DB -> PDF
```
```
backend/app/
  api/ core/ (config, ssrf_protection, rate_limiter, logging) database/ models/ schemas/
  scanner/ crawler.py engine.py severity.py http_client.py models.py scanners/*.py
  reports/pdf_report.py
frontend/src/ pages/ components/ services/ hooks/ utils/
vulnerable-test-app/   (intentionally vulnerable; local lab only)
```

## Quick start (local)
```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload          # http://localhost:8000/docs

# Frontend
cd frontend && npm install && npm run dev   # http://localhost:5173

# Local lab target (separate terminal)
cd vulnerable-test-app && pip install -r requirements.txt && uvicorn app:app --port 9000
# Start the backend with ALLOW_PRIVATE_NETWORK_TARGETS=true to scan http://127.0.0.1:9000
```

## Docker
```bash
cp .env.example .env
docker compose up --build                      # UI: http://localhost:3000  API: http://localhost:8000/docs
# Lab mode (scan the bundled vulnerable app):
ALLOW_PRIVATE_NETWORK_TARGETS=true docker compose --profile lab up --build
# then scan http://vulnerable-test-app:9000
```

## Tests
```bash
cd backend && python -m pytest -q
```

## API
| Method | Path | Purpose |
|---|---|---|
| POST | /api/scans | Start scan (requires `authorization_confirmed: true`) |
| GET | /api/scans | List scans |
| GET | /api/scans/{id} | Scan status/progress |
| GET | /api/scans/{id}/findings | Findings (filters: severity, confidence, type, url) |
| GET | /api/scans/{id}/summary | Severity summary |
| POST | /api/scans/{id}/cancel | Cancel running scan |
| GET | /api/scans/{id}/report | PDF report |
| GET | /api/scans/stats/overview | Dashboard aggregates |

## Detection methodology (interview notes)
- **Crawling**: BFS queue, normalized + deduplicated URLs, depth/URL caps, delay between requests, same-origin only, redirects recorded but not auto-followed.
- **Parameters**: query strings (via `parse_qs`) and HTML form inputs (BeautifulSoup).
- **SQLi**: baseline vs. single-quote error signatures vs. true/false condition length comparison. One indicator = Medium confidence, two = High. Never destructive.
- **XSS**: unique marker + HTML metacharacters; context classification (body/attribute/script/comment); encoded reflection is downgraded to Informational.
- **CSRF**: static analysis of state-changing forms for token fields and SameSite cookies. No requests are submitted.
- **False-positive reduction**: baselines, multi-indicator scoring, severity downgrade on low confidence, dedup/correlation across modules.
- **Severity vs confidence**: severity = impact if real; confidence = how sure the scanner is. A High/Medium finding still needs manual verification.
- **SSRF protection**: scheme allow-list, DNS resolution and rejection of private/loopback/link-local/reserved IPs, cloud-metadata block (always), explicit opt-in for lab use.
- **Scan jobs**: `asyncio.create_task` per scan, tracked in a registry for cancellation; progress persisted to DB and polled by the UI.

## Limitations
Automated scanning cannot understand business logic or authenticated workflows, can yield false positives/negatives, and only sees what the crawler reaches. Playwright browser validation for XSS and authenticated scanning are not implemented (see below). Scan jobs are in-process; use a queue (Celery/RQ) for multi-worker deployments. No user authentication on the API yet (User model exists for future use).

## Future improvements
Playwright-assisted XSS validation, authenticated scans, JWT auth/multi-user, Celery job queue, Alembic migrations, robots.txt policy option, SARIF/JSON export.

## Screenshots
_Add screenshots here: `docs/dashboard.png`, `docs/results.png`, `docs/report.png`._
