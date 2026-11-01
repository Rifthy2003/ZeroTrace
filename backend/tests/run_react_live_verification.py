"""
Live end-to-end demonstration of ZeroTrace scanning against a locally hosted
React SPA application with React Router, controlled components, and REST APIs.
"""
import asyncio
import json
import os
import socket
import sys
import threading
import time
from urllib.parse import urlparse

# Ensure backend root is on Python module path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn
from app.scanner.browser_crawler import BrowserCrawler
from app.scanner.http_client import SafeHTTPClient
from app.scanner.scanners import sql_injection
from tests.vulnerable_react_app import app as react_app


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class UvicornServer(threading.Thread):
    def __init__(self, app, port):
        super().__init__(daemon=True)
        self.app = app
        self.port = port
        self.server = None

    def run(self):
        config = uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error")
        self.server = uvicorn.Server(config)
        self.server.run()

    def stop(self):
        if self.server:
            self.server.should_exit = True


async def run_react_verification():
    print("=" * 75)
    print("ZEROTRACE - REACT SPA CRAWLING & SQL INJECTION SCANNER VERIFICATION")
    print("=" * 75)

    port = find_free_port()
    server = UvicornServer(react_app, port)
    server.start()
    base_url = f"http://127.0.0.1:{port}"

    import httpx
    for _ in range(30):
        try:
            r = httpx.get(f"{base_url}/")
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(0.1)

    print(f"\n[PHASE 1: LIVE PLAYWRIGHT REACT DOM CRAWL & NETWORK MONITORING]")
    print(f"Target: React 18 SPA at {base_url}")

    crawler = BrowserCrawler(
        base_url=base_url,
        max_urls=25,
        request_delay=0.1,
        timeout_seconds=8.0,
    )

    endpoints, metrics = await crawler.crawl()

    print(f"\nResults of React DOM Crawl:")
    print(f"  * Total Routes Discovered:     {len(metrics['routes_discovered'])}")
    print(f"  * Total Routes Visited:        {len(metrics['routes_visited'])}")
    print(f"  * Total Forms Discovered:      {metrics['forms_discovered']}")
    print(f"  * Total Parameters Discovered: {metrics['parameters_discovered']}")
    print(f"  * Captured Network API Calls:  {len(crawler.captured_api_requests)}")

    print(f"\nDiscovered React Router Routes:")
    for r in metrics["routes_discovered"]:
        print(f"  - {r}")

    print(f"\nDiscovered Endpoints & Input Parameters:")
    for ep in endpoints:
        params_str = ", ".join([f"{p.name} ({p.location})" for p in ep.parameters]) or "No parameters"
        print(f"  * {ep.method:4s} {ep.url} -> [{params_str}] (Form: {ep.has_form})")

    print(f"\n[PHASE 2: SQL INJECTION VULNERABILITY AUDIT ON DISCOVERED INPUTS]")
    client = SafeHTTPClient(request_delay=0.0)

    execution_logs = []
    all_findings = []
    parameters_tested_count = 0

    for ep in endpoints:
        testable_params = [
            p for p in ep.parameters
            if p.name and p.name.lower() not in {"csrf", "token", "_csrf", "_token"}
        ]

        if not testable_params:
            execution_logs.append({
                "event": "module_skipped",
                "module": "sql_injection",
                "url": ep.url,
                "reason": "No testable input parameters discovered on endpoint",
            })
            continue

        parameters_tested_count += len(testable_params)
        found = await sql_injection.scan(ep, client)
        all_findings.extend(found)

        for p in testable_params:
            p_findings = [f for f in found if f.parameter == p.name]
            result_str = (
                f"Finding detected: {p_findings[0].type} ({p_findings[0].severity}, {p_findings[0].detection_status})"
                if p_findings else "Safe (No indicators observed)"
            )
            execution_logs.append({
                "event": "parameter_tested",
                "module": "sql_injection",
                "url": ep.url,
                "method": ep.method,
                "parameter": p.name,
                "location": p.location,
                "result": result_str,
            })

    await client.close()
    server.stop()

    print(f"\nParameters Tested: {parameters_tested_count}")
    print(f"Total Findings Detected: {len(all_findings)}")
    for f in all_findings:
        print(f"  [!] VULNERABILITY CONFIRMED: {f.type} [{f.severity}] on {f.method} {f.url}")
        print(f"      - Parameter: {f.parameter}")
        print(f"      - Status:    {f.detection_status}")
        print(f"      - CWE/MITRE: {f.cwe_id} / {f.mitre_attack}")
        print(f"      - Evidence:  {f.evidence}")

    print(f"\n[PHASE 3: STRUCTURED AUDIT EXECUTION LOG]")
    for log in execution_logs:
        ev = log.get("event")
        if ev == "parameter_tested":
            print(f"  [TESTED]  [SQL_INJECTION] {log['method']} {log['url']} -> Param: '{log['parameter']}' ({log['location']}) | Result: {log['result']}")
        elif ev == "module_skipped":
            print(f"  [SKIPPED] [SQL_INJECTION] {log['url']} | Reason: {log['reason']}")

    print(f"\n[PHASE 4: COVERAGE SUMMARY]")
    tested_endpoints = len([ep for ep in endpoints if ep.parameters])
    coverage_summary = {
        "endpoints_discovered": len(endpoints),
        "endpoints_tested": tested_endpoints,
        "forms_discovered": metrics["forms_discovered"],
        "parameters_discovered": metrics["parameters_discovered"],
        "parameters_tested": parameters_tested_count,
        "modules": [
            {
                "module": "sql_injection",
                "name": "SQL Injection",
                "status": "Tested" if parameters_tested_count > 0 else "Incomplete",
                "endpoints_tested": tested_endpoints,
                "parameters_tested": parameters_tested_count,
                "findings": len(all_findings),
                "reason": "Evaluated against discovered target surface" if parameters_tested_count > 0 else "No eligible input parameters discovered on crawled pages",
            }
        ]
    }
    print(json.dumps(coverage_summary, indent=2))


if __name__ == "__main__":
    asyncio.run(run_react_verification())

