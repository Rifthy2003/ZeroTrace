import React, { useEffect, useState } from "react";
import { listScans, reportUrl } from "../services/api";
import { Card, Spinner } from "../components/ui";
import { fmtDate } from "../utils/format";

export default function Reports() {
  const [scans, setScans] = useState(null);
  useEffect(() => { listScans().then((s) => setScans(s.filter((x) => x.status === "completed"))); }, []);
  if (!scans) return <Spinner />;
  return (
    <div className="space-y-4"><h1 className="text-2xl font-bold">Reports</h1>
      <Card>{scans.length === 0 ? <div className="text-slate-400 text-sm">No completed scans yet.</div> :
        <ul className="divide-y divide-slate-800">{scans.map((s) => (
          <li key={s.id} className="py-2 flex justify-between text-sm"><span>{fmtDate(s.created_at)} — {s.findings_count} findings</span>
            <a className="text-emerald-400" href={reportUrl(s.id)}>Download PDF</a></li>))}</ul>}</Card></div>
  );
}
