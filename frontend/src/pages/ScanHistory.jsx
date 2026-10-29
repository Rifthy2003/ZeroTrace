import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listScans } from "../services/api";
import { Card, Spinner } from "../components/ui";
import { fmtDate } from "../utils/format";

export default function ScanHistory() {
  const [scans, setScans] = useState(null);
  useEffect(() => { listScans().then(setScans); }, []);
  if (!scans) return <Spinner />;
  return (
    <div className="space-y-4"><h1 className="text-2xl font-bold">Scan History</h1>
      <Card><table className="w-full text-sm"><thead className="text-left text-slate-400"><tr><th>Created</th><th>Status</th><th>URLs</th><th>Findings</th><th /></tr></thead>
        <tbody>{scans.map((s) => (
          <tr key={s.id} className="border-t border-slate-800"><td className="py-2">{fmtDate(s.created_at)}</td><td>{s.status}</td><td>{s.urls_discovered}</td><td>{s.findings_count}</td>
            <td><Link className="text-emerald-400" to={s.status === "completed" ? `/scan/${s.id}` : `/scan/${s.id}/progress`}>Open</Link></td></tr>))}</tbody></table>
        {scans.length === 0 && <div className="text-slate-400 text-sm py-4">No scans yet.</div>}</Card></div>
  );
}
