import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { getFindings, updateFindingStatus } from "../services/api";
import { Card, SeverityBadge, LifecycleBadge, Spinner } from "../components/ui";
import { fmtDate } from "../utils/format";

const Row = ({ label, children }) => (
  <div className="mb-3">
    <div className="text-xs uppercase text-slate-400 font-medium">{label}</div>
    <div className="text-sm whitespace-pre-wrap break-words text-slate-200 mt-0.5">{children || "—"}</div>
  </div>
);

export default function FindingDetails() {
  const { id, fid } = useParams();
  const [f, setF] = useState(null);
  const [status, setStatus] = useState("open");
  const [note, setNote] = useState("");
  const [isUpdating, setIsUpdating] = useState(false);
  const [msg, setMsg] = useState("");

  useEffect(() => {
    getFindings(id).then((all) => {
      const match = all.find((x) => x.id === fid);
      if (match) {
        setF(match);
        setStatus(match.status || "open");
        setNote(match.status_note || "");
      }
    });
  }, [id, fid]);

  const handleUpdateStatus = async () => {
    setIsUpdating(true);
    setMsg("");
    try {
      const updated = await updateFindingStatus(fid, { status, note });
      setF((prev) => ({ ...prev, status: updated.status, status_note: updated.status_note }));
      setMsg("Status successfully updated!");
      setTimeout(() => setMsg(""), 3000);
    } catch (err) {
      console.error(err);
      setMsg("Failed to update status.");
    } finally {
      setIsUpdating(false);
    }
  };

  if (!f) return <Spinner />;

  return (
    <div className="max-w-3xl space-y-4">
      <Link to={`/scan/${id}`} className="text-sm text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1">
        &larr; Back to scan results
      </Link>
      <div>
        <h1 className="text-2xl font-bold text-slate-100">{f.type}</h1>
        <div className="flex flex-wrap gap-3 items-center mt-2">
          <SeverityBadge severity={f.severity} />
          <span className="text-sm text-slate-300">Confidence: {f.confidence}</span>
          <LifecycleBadge status={f.status} />
          {f.fingerprint && (
            <span className="text-xs font-mono text-slate-500 bg-slate-800 px-2 py-0.5 rounded">
              FP: {f.fingerprint}
            </span>
          )}
        </div>
      </div>

      {/* Lifecycle Status Management Card */}
      <Card title="Remediation Lifecycle Status">
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <div className="flex-1 w-full sm:w-auto">
            <label className="text-xs text-slate-400 block mb-1">Update Status</label>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500 w-full"
            >
              <option value="open">Open (Vulnerability Active)</option>
              <option value="fixed">Fixed (Remediation Implemented)</option>
              <option value="accepted_risk">Accepted Risk (Business Justification)</option>
              <option value="reopened">Reopened (Issue Recurred)</option>
            </select>
          </div>
          <div className="flex-[2] w-full sm:w-auto">
            <label className="text-xs text-slate-400 block mb-1">Remediation Note / Justification</label>
            <input
              type="text"
              placeholder="e.g. Added input sanitizer; verified in staging"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-full"
            />
          </div>
          <div className="sm:self-end">
            <button
              onClick={handleUpdateStatus}
              disabled={isUpdating}
              className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold disabled:opacity-50 transition-colors"
            >
              {isUpdating ? "Saving…" : "Save Status"}
            </button>
          </div>
        </div>
        {msg && (
          <div className="text-xs text-emerald-400 font-medium mt-2">
            ✓ {msg}
          </div>
        )}
      </Card>

      <Card>
        <Row label="Affected URL">{f.url}</Row>
        <Row label="HTTP method">{f.method}</Row>
        <Row label="Parameter">{f.parameter}</Row>
        <Row label="Evidence">{f.evidence}</Row>
        <Row label="Description">{f.description}</Row>
        <Row label="Potential impact">{f.impact}</Row>
        <Row label="Remediation">{f.remediation}</Row>
        <Row label="OWASP category">{f.owasp_category}</Row>
        <Row label="Detected">{fmtDate(f.timestamp)}</Row>
      </Card>
    </div>
  );
}
