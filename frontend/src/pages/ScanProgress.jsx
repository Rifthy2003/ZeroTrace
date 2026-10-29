import React from "react";
import { useParams, Link } from "react-router-dom";
import { getScan, cancelScan } from "../services/api";
import usePolling from "../hooks/usePolling";
import { Card, Stat, Spinner } from "../components/ui";

const done = (s) => ["completed", "failed", "cancelled"].includes(s.status);

export default function ScanProgress() {
  const { id } = useParams();
  const { data: s } = usePolling(() => getScan(id), [id], 1000, done);
  if (!s) return <Spinner />;
  return (
    <div className="space-y-4 max-w-3xl">
      <h1 className="text-2xl font-bold">Scan Progress</h1>
      <Card>
        <div className="flex justify-between text-sm mb-2"><span>Status: <b>{s.status}</b></span><span>Module: {s.current_module || "—"}</span></div>
        <div className="h-3 bg-slate-800 rounded overflow-hidden"><div className="h-full bg-emerald-500 transition-all" style={{ width: `${s.progress_percent}%` }} /></div>
        <div className="text-right text-xs text-slate-400 mt-1">{s.progress_percent}%</div>
        {s.error_message && <div className="text-red-400 text-sm mt-2">{s.error_message}</div>}
      </Card>
      <div className="grid grid-cols-4 gap-3">
        <Stat label="URLs discovered" value={s.urls_discovered} /><Stat label="URLs scanned" value={s.urls_scanned} />
        <Stat label="Parameters" value={s.parameters_found} /><Stat label="Findings" value={s.findings_count} />
      </div>
      <div className="flex gap-3">
        {!done(s) && <button onClick={() => cancelScan(id)} className="bg-red-700 hover:bg-red-600 px-4 py-2 rounded text-sm">Cancel</button>}
        {s.status === "completed" && <Link to={`/scan/${id}`} className="bg-emerald-600 px-4 py-2 rounded text-sm">View results</Link>}
      </div>
    </div>
  );
}
