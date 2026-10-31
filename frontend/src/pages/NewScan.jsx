import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { createScan, listApplications } from "../services/api";
import { Card } from "../components/ui";

const MODULES = [
  "sql_injection",
  "xss",
  "csrf",
  "security_headers",
  "directory_listing",
  "sensitive_files",
  "open_redirect",
  "information_disclosure",
  "cookie_security",
];

export default function NewScan() {
  const nav = useNavigate();
  const [apps, setApps] = useState([]);
  const [f, setF] = useState({
    target_url: "",
    application_name: "",
    application_id: "",
    max_depth: 2,
    max_urls: 50,
    request_delay: 0.25,
    modules: MODULES,
    authorization_confirmed: false,
    enable_browser_discovery: true,
  });
  const [error, setError] = useState("");

  useEffect(() => {
    listApplications().then(setApps).catch(() => {});
  }, []);

  const set = (k, v) => setF((p) => ({ ...p, [k]: v }));
  const toggle = (m) =>
    set("modules", f.modules.includes(m) ? f.modules.filter((x) => x !== m) : [...f.modules, m]);

  const submit = async () => {
    setError("");
    try {
      const s = await createScan(f);
      nav(`/scan/${s.id}/progress`);
    } catch (e) {
      const d = e.response?.data?.detail;
      setError(Array.isArray(d) ? d.map((x) => x.msg).join("; ") : d || "Failed to start scan");
    }
  };

  const input = "w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm";

  return (
    <div className="max-w-2xl space-y-4">
      <div>
        <h1 className="text-2xl font-bold">New Scan</h1>
        <p className="text-xs text-slate-400 mt-1">
          ZeroTrace — Automated Web Vulnerability Scanner. Discover. Analyze. Secure.
        </p>
      </div>

      <Card>
        <div className="space-y-1">
          <label className="text-sm font-medium">Target URL</label>
          <input
            className={input}
            placeholder="http://localhost:50091/ or https://example.com"
            value={f.target_url}
            onChange={(e) => set("target_url", e.target.value)}
          />
          <p className="text-xs text-slate-400">
            Supports dynamic host ports (e.g. 49704, 50091, 5173, 3000, 8000). Host targets are safely routed with SSRF protection.
          </p>
        </div>

        <div className="space-y-1 mt-4">
          <label className="text-sm font-medium">Website / Application Name (Optional)</label>
          <div className="flex flex-col sm:flex-row gap-2">
            <input
              className={input}
              placeholder="e.g. Hela Govi Web App (leave blank to auto-detect from hostname/port)"
              value={f.application_name || ""}
              onChange={(e) => set("application_name", e.target.value)}
            />
            {apps.length > 0 && (
              <select
                className="bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm text-slate-300"
                onChange={(e) => {
                  if (e.target.value) {
                    const chosen = apps.find((a) => a.id === e.target.value);
                    if (chosen) {
                      set("application_id", chosen.id);
                      set("application_name", chosen.name);
                      if (chosen.target_url && !f.target_url) {
                        set("target_url", chosen.target_url);
                      }
                    }
                  } else {
                    set("application_id", "");
                  }
                }}
              >
                <option value="">Or pick existing app...</option>
                {apps.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name}
                  </option>
                ))}
              </select>
            )}
          </div>
          <p className="text-xs text-slate-400">
            Associates this target with a named website in your Website Security Management Dashboard.
          </p>
        </div>

        <div className="grid grid-cols-3 gap-3 mt-4">
          <div>
            <label className="text-sm">Max depth</label>
            <input
              type="number"
              min="0"
              max="5"
              className={input}
              value={f.max_depth}
              onChange={(e) => set("max_depth", +e.target.value)}
            />
          </div>
          <div>
            <label className="text-sm">Max URLs</label>
            <input
              type="number"
              min="1"
              max="500"
              className={input}
              value={f.max_urls}
              onChange={(e) => set("max_urls", +e.target.value)}
            />
          </div>
          <div>
            <label className="text-sm">Delay (s)</label>
            <input
              type="number"
              step="0.05"
              min="0"
              className={input}
              value={f.request_delay}
              onChange={(e) => set("request_delay", +e.target.value)}
            />
          </div>
        </div>

        <div className="mt-4 p-3 bg-slate-800/60 border border-slate-700 rounded text-xs space-y-2">
          <label className="flex items-start gap-2 cursor-pointer font-medium text-slate-200">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={f.enable_browser_discovery}
              onChange={(e) => set("enable_browser_discovery", e.target.checked)}
            />
            <div>
              <span className="text-emerald-400 font-semibold">Enable Browser Discovery (Playwright / SPA)</span>
              <p className="text-slate-400 font-normal mt-0.5">
                Executes client-side JavaScript to render Single Page Applications (Flutter Web, React, Vue), discover hash-based routes (e.g. <code>/#/welcome</code>, <code>/#/login</code>, <code>/#/signup</code>, <code>/#/dashboard</code>), and identify protected endpoints requiring authentication without submitting forms.
              </p>
            </div>
          </label>
        </div>

        <div className="mt-4">
          <label className="text-sm font-medium">Active Security Modules</label>
          <div className="mt-2 grid grid-cols-2 gap-1.5">
            {MODULES.map((m) => (
              <label key={m} className="text-xs flex gap-2 items-center cursor-pointer text-slate-300">
                <input
                  type="checkbox"
                  checked={f.modules.includes(m)}
                  onChange={() => toggle(m)}
                />
                {m}
              </label>
            ))}
          </div>
        </div>

        <label className="flex gap-2 text-xs mt-4 p-3 bg-amber-950/40 border border-amber-800 rounded text-amber-200">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={f.authorization_confirmed}
            onChange={(e) => set("authorization_confirmed", e.target.checked)}
          />
          <span>
            I confirm that I own this target or have explicit written authorization to perform defensive security assessments on it.
          </span>
        </label>

        {error && <div className="text-red-400 text-sm mt-3 p-2 bg-red-950/30 border border-red-900 rounded">{error}</div>}

        <button
          onClick={submit}
          className="mt-4 bg-emerald-600 hover:bg-emerald-500 px-5 py-2.5 rounded font-semibold text-sm transition-colors w-full sm:w-auto"
        >
          Start Scan
        </button>
      </Card>
    </div>
  );
}
