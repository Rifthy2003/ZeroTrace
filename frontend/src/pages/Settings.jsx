import React from "react";
import { Card } from "../components/ui";

export default function Settings() {
  return (
    <div className="max-w-2xl space-y-4">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-xs text-slate-400 mt-1">ZeroTrace — Automated Web Vulnerability Scanner &bull; Discover. Analyze. Secure.</p>
      </div>
      <Card title="About ZeroTrace">
        <p className="text-sm text-slate-300">
          <b>ZeroTrace</b> is an authorized defensive web application vulnerability assessment platform with an integrated crawler, multi-indicator vulnerability scanners, and automated website security posture scoring.
        </p>
      </Card>
      <Card title="Server-side safety configuration">
        <p className="text-sm text-slate-300">Safety limits are enforced by the backend and configured through environment variables (see <code>.env.example</code>):</p>
        <ul className="list-disc ml-5 text-sm text-slate-300 mt-2 space-y-1">
          <li><code>ALLOW_PRIVATE_NETWORK_TARGETS</code> — false by default (SSRF protection)</li>
          <li><code>ALLOW_LOCAL_DEV_TARGET</code> — false by default; enables authorized local Windows-host development scanning across user-selected ports (e.g. 49704, 5173, 3000, 8000)</li>
          <li><code>MAX_CRAWL_DEPTH_LIMIT</code> / <code>MAX_URLS_LIMIT</code> — hard crawl ceilings</li>
          <li><code>REQUEST_TIMEOUT_SECONDS</code>, <code>MAX_RESPONSE_BYTES</code></li>
        </ul>
      </Card>
      <Card title="Ethical use"><p className="text-sm text-slate-300">Only scan systems you own or have explicit written authorization to test. Unauthorized scanning may be illegal.</p></Card>
    </div>
  );
}
