"""
Live end-to-end demonstration of the Crawler & Engine execution pipeline
against the safe vulnerable test application.
"""
import asyncio
import json
import os
import sys

# Ensure backend root is on Python module path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from httpx import ASGITransport

from app.scanner.crawler import Crawler
from app.scanner.http_client import SafeHTTPClient
from app.scanner.scanners import sql_injection
from app.scanner.models import DiscoveredEndpoint
from tests.vulnerable_test_app import app


async def run_live_verification():
    print("=" * 70)
    print("ZEROTRACE SCANNER PIPELINE - LIVE VERIFICATION")
    print("=" * 70)

    transport = ASGITransport(app=app)

    # 1. Crawl Phase
    print("\n[PHASE 1: CRAWLER & INPUT DISCOVERY]")
    crawler = Crawler(
        start_url="http://testserver/",
        max_depth=2,
        max_urls=20,
        request_delay=0.0,
        enable_browser_discovery=False,
        transport=transport,
    )
    endpoints = await crawler.crawl()

    print(f"Total Endpoints Discovered: {len(endpoints)}")
    print(f"Total Forms Discovered:     {crawler.total_forms_discovered}")
    print(f"Total Parameters Discovered:{crawler.total_parameters_discovered}")

    print("\nDiscovered Endpoints & Parameters:")
    for ep in endpoints:
        param_desc = ", ".join([f"{p.name} ({p.location})" for p in ep.parameters]) or "None"
        print(f"  * {ep.method:4s} {ep.url} -> Parameters: [{param_desc}] | Form: {ep.has_form}")

    # 2. Scanning Phase
    print("\n[PHASE 2: SQL INJECTION VULNERABILITY AUDIT]")
    client = SafeHTTPClient(request_delay=0.0, transport=transport)

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

    print(f"\nParameters Tested: {parameters_tested_count}")
    print(f"Total Findings Detected: {len(all_findings)}")
    for f in all_findings:
        print(f"  [!] VULNERABILITY CONFIRMED: {f.type} [{f.severity}] on {f.method} {f.url}")
        print(f"    - Parameter: {f.parameter}")
        print(f"    - Status:    {f.detection_status}")
        print(f"    - CWE/MITRE: {f.cwe_id} / {f.mitre_attack}")
        print(f"    - Evidence:  {f.evidence}")

    # 3. Execution Audit Log Samples
    print("\n[PHASE 3: DETAILED SCAN EXECUTION AUDIT LOG]")
    for log in execution_logs:
        ev = log.get("event")
        if ev == "parameter_tested":
            print(f"  [TESTED]  [{log['module'].upper()}] {log['method']} {log['url']} -> Param: '{log['parameter']}' ({log['location']}) | Result: {log['result']}")
        elif ev == "module_skipped":
            print(f"  [SKIPPED] [{log['module'].upper()}] {log['url']} | Reason: {log['reason']}")

    # 4. Coverage Accounting Summary
    print("\n[PHASE 4: COVERAGE SUMMARY]")
    coverage_summary = {
        "endpoints_discovered": len(endpoints),
        "endpoints_tested": len([ep for ep in endpoints if ep.parameters]),
        "forms_discovered": crawler.total_forms_discovered,
        "parameters_discovered": crawler.total_parameters_discovered,
        "parameters_tested": parameters_tested_count,
        "modules": [
            {
                "module": "sql_injection",
                "name": "SQL Injection",
                "status": "Tested" if parameters_tested_count > 0 else "Incomplete",
                "endpoints_tested": len([ep for ep in endpoints if ep.parameters]),
                "parameters_tested": parameters_tested_count,
                "findings": len(all_findings),
                "reason": "Evaluated against discovered target surface" if parameters_tested_count > 0 else "No eligible input parameters discovered on crawled pages",
            }
        ]
    }
    print(json.dumps(coverage_summary, indent=2))


if __name__ == "__main__":
    asyncio.run(run_live_verification())
