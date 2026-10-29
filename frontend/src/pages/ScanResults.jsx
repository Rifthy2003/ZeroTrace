import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { getFindings, getScan, reportUrl } from "../services/api";
import { Card, SeverityBadge, Spinner } from "../components/ui";
import { SEVERITIES } from "../utils/format";

export default function ScanResults() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState(null);
  const [flt, setFlt] = useState({ severity: "", confidence: "", type: "", url: "" });
  useEffect(() => { getScan(id).then(setScan); }, [id]);
  useEffect(() => {
    const params = Object.fromEntries(Object.entries(flt).filter(([, v]) => v));
    getFindings(id, params).then(setFindings);
  }, [id, flt]);
  if (!scan || !findings) return <Spinner />;
  const input = "bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm";
  const types = [...new Set(findings.map((f) => f.type))];
  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Scan Results</h1>
        <a href={reportUrl(id)} className="bg-emerald-600 px-3 py-2 rounded text-sm">Download PDF report</a>
      </div>
      <Card>
        <div className="flex flex-wrap gap-2">
          <select className={input} value={flt.severity} onChange={(e) => setFlt({ ...flt, severity: e.target.value })}>
            <option value="">All severities</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </select>
          <select className={input} value={flt.confidence} onChange={(e) => setFlt({ ...flt, confidence: e.target.value })}>
            <option value="">All confidence</option>{["Confirmed", "High confidence", "Medium confidence", "Low confidence", "Informational"].map((s) => <option key={s}>{s}</option>)}
          </select>
          <select className={input} value={flt.type} onChange={(e) => setFlt({ ...flt, type: e.target.value })}>
            <option value="">All types</option>{types.map((t) => <option key={t}>{t}</option>)}
          </select>
          <input className={input} placeholder="Filter URL" value={flt.url} onChange={(e) => setFlt({ ...flt, url: e.target.value })} />
        </div>
      </Card>
      <Card>
        <table className="w-full text-sm">
          <thead className="text-left text-slate-400"><tr><th>Type</th><th>Severity</th><th>Confidence</th><th>URL</th><th>Param</th></tr></thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} className="border-t border-slate-800 hover:bg-slate-800/50">
                <td className="py-2"><Link className="text-emerald-400" to={`/scan/${id}/finding/${f.id}`}>{f.type}</Link></td>
                <td><SeverityBadge severity={f.severity} /></td><td>{f.confidence}</td>
                <td className="truncate max-w-xs">{f.url}</td><td>{f.parameter || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {findings.length === 0 && <div className="text-slate-400 text-sm py-4">No findings match.</div>}
      </Card>
    </div>
  );
}
