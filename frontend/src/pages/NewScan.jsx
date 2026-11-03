import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { createScan, listApplications } from "../services/api";
import { Card } from "../components/ui";

const ALL_MODULES = [
  { id: "security_headers", label: "Security Headers (CSP, HSTS, X-Frame)", safe: true },
  { id: "cookie_security", label: "Cookie Security (HttpOnly, Secure, SameSite)", safe: true },
  { id: "directory_listing", label: "Directory Listing & Index Probes", safe: true },
  { id: "sensitive_files", label: "Exposed Sensitive Files (.git, .env, backups)", safe: true },
  { id: "information_disclosure", label: "Information Disclosure & Server Headers", safe: true },
  { id: "csrf", label: "CSRF & Form Security", safe: true },
  { id: "xss", label: "Cross-Site Scripting (XSS)", safe: true },
  { id: "open_redirect", label: "Open Redirect", safe: true },
  { id: "sql_injection", label: "SQL Injection Testing", safe: false },
  { id: "command_injection", label: "Command Injection Testing", safe: false },
  { id: "cors", label: "CORS Misconfiguration", safe: false },
  { id: "clickjacking", label: "Clickjacking / UI Redress", safe: false },
  { id: "path_traversal", label: "Path Traversal & LFI", safe: false },
  { id: "ssti", label: "Server-Side Template Injection (SSTI)", safe: false },
  { id: "auth_security", label: "Authentication & Password Form Security", safe: false },
  { id: "graphql", label: "GraphQL Introspection & Endpoint Probes", safe: false },
];

const QUICK_MODULES = ALL_MODULES.filter((m) => m.safe).map((m) => m.id);
const FULL_MODULES = ALL_MODULES.map((m) => m.id);

export default function NewScan() {
  const nav = useNavigate();
  const [apps, setApps] = useState([]);
  const [scanType, setScanType] = useState("Quick Scan"); // "Quick Scan" or "Full Scan"

  const [f, setF] = useState({
    target_url: "",
    application_name: "",
    application_id: "",
    max_depth: 1,
    max_urls: 25,
    request_delay: 0.3,
    modules: QUICK_MODULES,
    authorization_confirmed: false,
    enable_browser_discovery: true,
  });
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    listApplications().then(setApps).catch(() => {});
  }, []);

  const set = (k, v) => setF((p) => ({ ...p, [k]: v }));
  const toggleModule = (id) =>
    set("modules", f.modules.includes(id) ? f.modules.filter((x) => x !== id) : [...f.modules, id]);

  const handleSelectScanType = (type) => {
    setScanType(type);
    if (type === "Quick Scan") {
      setF((prev) => ({
        ...prev,
        max_depth: 1,
        max_urls: 25,
        request_delay: 0.3,
        modules: QUICK_MODULES,
      }));
    } else {
      setF((prev) => ({
        ...prev,
        max_depth: 3,
        max_urls: 60,
        request_delay: 0.2,
        modules: FULL_MODULES,
      }));
    }
  };

  const submit = async (e) => {
    e?.preventDefault();
    setError("");
    setIsSubmitting(true);
    try {
      const payload = {
        ...f,
        scan_type: scanType,
      };
      const s = await createScan(payload);
      nav(`/scan/${s.id}/progress`);
    } catch (e) {
      const d = e.response?.data?.detail;
      setError(Array.isArray(d) ? d.map((x) => x.msg).join("; ") : d || "Failed to start scan");
    } finally {
      setIsSubmitting(false);
    }
  };

  const inputClass = "w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500";

  return (
    <div className="max-w-3xl space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">New Scan</h1>
        <p className="text-xs text-slate-400 mt-1">
          ZeroTrace — Automated Web Vulnerability Scanner. Select a scan type and start a security assessment.
        </p>
      </div>

      <Card>
        {/* Scan Type Selection Cards */}
        <div className="mb-5">
          <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 block mb-2">
            Scan Type
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {/* Quick Scan Card */}
            <div
              onClick={() => handleSelectScanType("Quick Scan")}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                scanType === "Quick Scan"
                  ? "bg-slate-850 border-emerald-500 ring-1 ring-emerald-500 shadow-md"
                  : "bg-slate-950/60 border-slate-800 hover:border-slate-700"
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 text-lg">⚡</span>
                  <span className="font-bold text-slate-100 text-sm">Quick Scan</span>
                </div>
                <input
                  type="radio"
                  name="scanType"
                  checked={scanType === "Quick Scan"}
                  onChange={() => handleSelectScanType("Quick Scan")}
                  className="text-emerald-500 focus:ring-0 cursor-pointer"
                />
              </div>
              <p className="text-xs text-slate-400">
                Faster execution with limited crawl depth (depth 1, 25 URLs) and essential, low-impact vulnerability checks.
              </p>
              <div className="mt-3 flex flex-wrap gap-1">
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">Depth 1</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">25 URLs</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 font-mono">8 Safe Checks</span>
              </div>
            </div>

            {/* Full Scan Card */}
            <div
              onClick={() => handleSelectScanType("Full Scan")}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                scanType === "Full Scan"
                  ? "bg-slate-850 border-emerald-500 ring-1 ring-emerald-500 shadow-md"
                  : "bg-slate-950/60 border-slate-800 hover:border-slate-700"
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-cyan-400 text-lg">🔍</span>
                  <span className="font-bold text-slate-100 text-sm">Full Scan</span>
                </div>
                <input
                  type="radio"
                  name="scanType"
                  checked={scanType === "Full Scan"}
                  onChange={() => handleSelectScanType("Full Scan")}
                  className="text-emerald-500 focus:ring-0 cursor-pointer"
                />
              </div>
              <p className="text-xs text-slate-400">
                Comprehensive website crawling and exhaustive vulnerability testing across all supported security modules.
              </p>
              <div className="mt-3 flex flex-wrap gap-1">
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">Depth 3</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">60 URLs</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 font-mono">All 16 Modules</span>
              </div>
            </div>
          </div>
        </div>

        {/* Target URL */}
        <div className="space-y-1">
          <label className="text-sm font-medium text-slate-200">Target URL</label>
          <input
            className={inputClass}
            placeholder="http://localhost:50091/ or https://example.com"
            value={f.target_url}
            onChange={(e) => set("target_url", e.target.value)}
          />
          <p className="text-xs text-slate-400">
            Supports dynamic host ports (e.g. 49704, 50091, 5173, 3000, 8000). Host targets are safely routed with SSRF protection.
          </p>
        </div>

        {/* Website / Application Name (Optional) */}
        <div className="space-y-1 mt-4">
          <label className="text-sm font-medium text-slate-200">Website / Application Name (Optional)</label>
          <div className="flex flex-col sm:flex-row gap-2">
            <input
              className={inputClass}
              placeholder="e.g. Hela Govi Web App (leave blank to auto-detect from hostname/port)"
              value={f.application_name || ""}
              onChange={(e) => set("application_name", e.target.value)}
            />
            {apps.length > 0 && (
              <select
                className="bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-emerald-500"
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
        </div>

        {/* Crawl and Request Tuning Parameters */}
        <div className="grid grid-cols-3 gap-3 mt-4">
          <div>
            <label className="text-sm text-slate-300">Max depth</label>
            <input
              type="number"
              min="0"
              max="5"
              className={inputClass}
              value={f.max_depth}
              onChange={(e) => set("max_depth", +e.target.value)}
            />
          </div>
          <div>
            <label className="text-sm text-slate-300">Max URLs</label>
            <input
              type="number"
              min="1"
              max="500"
              className={inputClass}
              value={f.max_urls}
              onChange={(e) => set("max_urls", +e.target.value)}
            />
          </div>
          <div>
            <label className="text-sm text-slate-300">Delay (s)</label>
            <input
              type="number"
              step="0.05"
              min="0"
              className={inputClass}
              value={f.request_delay}
              onChange={(e) => set("request_delay", +e.target.value)}
            />
          </div>
        </div>

        {/* Browser Discovery (Playwright / SPA) */}
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
                Executes client-side JavaScript to render Single Page Applications (Flutter Web, React, Vue), discover hash-based routes (e.g. <code>/#/login</code>, <code>/#/dashboard</code>), and identify protected endpoints requiring authentication without submitting forms.
              </p>
            </div>
          </label>
        </div>

        {/* Active Security Modules */}
        <div className="mt-4">
          <div className="flex items-center justify-between mb-2">
            <label className="text-sm font-medium text-slate-200">
              Active Security Modules ({f.modules.length} selected)
            </label>
            <span className="text-[11px] text-slate-400">
              Configured for {scanType}
            </span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-52 overflow-y-auto p-2.5 bg-slate-950/60 rounded-lg border border-slate-800">
            {ALL_MODULES.map((m) => {
              const isChecked = f.modules.includes(m.id);
              return (
                <label key={m.id} className="text-xs flex items-center gap-2 cursor-pointer text-slate-300 hover:text-white">
                  <input
                    type="checkbox"
                    checked={isChecked}
                    onChange={() => toggleModule(m.id)}
                    className="rounded bg-slate-900 border-slate-700 text-emerald-500 focus:ring-0"
                  />
                  <span className="font-mono text-[11px] truncate" title={m.label}>
                    {m.id}
                  </span>
                </label>
              );
            })}
          </div>
        </div>

        {/* Authorization Confirmation */}
        <label className="flex gap-2 text-xs mt-4 p-3 bg-amber-950/40 border border-amber-800 rounded text-amber-200 cursor-pointer">
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
          disabled={isSubmitting}
          className="mt-4 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 px-5 py-2.5 rounded font-semibold text-sm transition-colors w-full sm:w-auto text-white shadow"
        >
          {isSubmitting ? "Starting Scan..." : `Start ${scanType}`}
        </button>
      </Card>
    </div>
  );
}
