import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { createScan } from "../services/api";
import { Card } from "../components/ui";

const MODULES = ["sql_injection", "xss", "csrf", "security_headers", "directory_listing", "sensitive_files", "open_redirect", "information_disclosure", "cookie_security"];

export default function NewScan() {
  const nav = useNavigate();
  const [f, setF] = useState({ target_url: "", max_depth: 2, max_urls: 50, request_delay: 0.25, modules: MODULES, authorization_confirmed: false });
  const [error, setError] = useState("");
  const set = (k, v) => setF((p) => ({ ...p, [k]: v }));
  const toggle = (m) => set("modules", f.modules.includes(m) ? f.modules.filter((x) => x !== m) : [...f.modules, m]);
  const submit = async () => {
    setError("");
    try { const s = await createScan(f); nav(`/scan/${s.id}/progress`); }
    catch (e) {
      const d = e.response?.data?.detail;
      setError(Array.isArray(d) ? d.map((x) => x.msg).join("; ") : d || "Failed to start scan");
    }
  };
  const input = "w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm";
  return (
    <div className="max-w-2xl space-y-4">
      <h1 className="text-2xl font-bold">New Scan</h1>
      <Card>
        <label className="text-sm">Target URL</label>
        <input className={input} placeholder="https://target.example" value={f.target_url} onChange={(e) => set("target_url", e.target.value)} />
        <div className="grid grid-cols-3 gap-3 mt-3">
          <div><label className="text-sm">Max depth</label><input type="number" min="0" max="5" className={input} value={f.max_depth} onChange={(e) => set("max_depth", +e.target.value)} /></div>
          <div><label className="text-sm">Max URLs</label><input type="number" min="1" max="500" className={input} value={f.max_urls} onChange={(e) => set("max_urls", +e.target.value)} /></div>
          <div><label className="text-sm">Delay (s)</label><input type="number" step="0.05" min="0" className={input} value={f.request_delay} onChange={(e) => set("request_delay", +e.target.value)} /></div>
        </div>
        <div className="mt-3 grid grid-cols-2 gap-1">
          {MODULES.map((m) => (
            <label key={m} className="text-sm flex gap-2"><input type="checkbox" checked={f.modules.includes(m)} onChange={() => toggle(m)} />{m}</label>
          ))}
        </div>
        <label className="flex gap-2 text-sm mt-4 p-3 bg-amber-950/40 border border-amber-800 rounded">
          <input type="checkbox" checked={f.authorization_confirmed} onChange={(e) => set("authorization_confirmed", e.target.checked)} />
          I own this target or have explicit written authorization to test it.
        </label>
        {error && <div className="text-red-400 text-sm mt-3">{error}</div>}
        <button onClick={submit} className="mt-4 bg-emerald-600 hover:bg-emerald-500 px-4 py-2 rounded font-semibold">Start Scan</button>
      </Card>
    </div>
  );
}
