import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { getFindings } from "../services/api";
import { Card, SeverityBadge, Spinner } from "../components/ui";
import { fmtDate } from "../utils/format";

const Row = ({ label, children }) => (<div className="mb-3"><div className="text-xs uppercase text-slate-400">{label}</div><div className="text-sm whitespace-pre-wrap break-words">{children || "—"}</div></div>);

export default function FindingDetails() {
  const { id, fid } = useParams();
  const [f, setF] = useState(null);
  useEffect(() => { getFindings(id).then((all) => setF(all.find((x) => x.id === fid))); }, [id, fid]);
  if (!f) return <Spinner />;
  return (
    <div className="max-w-3xl space-y-4">
      <Link to={`/scan/${id}`} className="text-sm text-emerald-400">← Back to results</Link>
      <h1 className="text-2xl font-bold">{f.type}</h1>
      <div className="flex gap-3 items-center"><SeverityBadge severity={f.severity} /><span className="text-sm">Confidence: {f.confidence}</span></div>
      <Card>
        <Row label="Affected URL">{f.url}</Row><Row label="HTTP method">{f.method}</Row><Row label="Parameter">{f.parameter}</Row>
        <Row label="Evidence">{f.evidence}</Row><Row label="Description">{f.description}</Row><Row label="Potential impact">{f.impact}</Row>
        <Row label="Remediation">{f.remediation}</Row><Row label="OWASP category">{f.owasp_category}</Row><Row label="Detected">{fmtDate(f.timestamp)}</Row>
      </Card>
    </div>
  );
}
