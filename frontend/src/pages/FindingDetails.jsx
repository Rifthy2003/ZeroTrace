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

  const occurrences = f.evidence_details?.occurrences || [];

  return (
    <div className="max-w-4xl space-y-4">
      <Link to={`/scan/${id}`} className="text-sm text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1">
        &larr; Back to scan results
      </Link>
      <div>
        <h1 className="text-2xl font-bold text-slate-100">{f.type}</h1>
        <div className="flex flex-wrap gap-2.5 items-center mt-2.5">
          <SeverityBadge severity={f.severity} />
          <span className="text-xs px-2.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
            Confidence: {f.confidence}
          </span>
          <span
            className={`text-xs px-2.5 py-0.5 rounded font-semibold border ${
              f.detection_status === "Confirmed"
                ? "bg-emerald-950/60 text-emerald-400 border-emerald-800/80"
                : f.detection_status === "Requires Manual Verification"
                ? "bg-amber-950/60 text-amber-400 border-amber-800/80"
                : "bg-blue-950/60 text-blue-400 border-blue-800/80"
            }`}
          >
            {f.detection_status || "Confirmed"}
          </span>
          <LifecycleBadge status={f.status} />
          {f.cwe_id && (
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800/60">
              {f.cwe_id}
            </span>
          )}
          {f.mitre_attack && (
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-800/60">
              MITRE: {f.mitre_attack}
            </span>
          )}
          {f.fingerprint && (
            <span className="text-xs font-mono text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded border border-slate-700">
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

      {/* Technical Details Card */}
      <Card title="Technical Vulnerability Details">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pb-3 mb-3 border-b border-slate-800">
          <Row label="Affected URL">
            <span className="font-mono text-emerald-400 text-xs">{f.url}</span>
          </Row>
          <Row label="HTTP Method & Parameter">
            <span className="font-mono text-slate-300 text-xs">
              {f.method} {f.parameter ? `(param: ${f.parameter})` : ""}
            </span>
          </Row>
          <Row label="OWASP Category">{f.owasp_category || "A05:2021 - Security Misconfiguration"}</Row>
          <Row label="First Detected Date">{fmtDate(f.timestamp)}</Row>
        </div>

        <Row label="Evidence & Detection Explanation">
          <div className="p-3 bg-slate-950/80 rounded border border-slate-800 text-xs font-mono text-amber-300/90 whitespace-pre-wrap">
            {f.evidence || "No request/response evidence captured."}
          </div>
        </Row>

        <Row label="Description">{f.description}</Row>
        <Row label="Potential Impact">{f.impact}</Row>

        <Row label="Recommended Remediation">
          <div className="p-3 bg-emerald-950/30 rounded border border-emerald-900/40 text-xs text-emerald-300/90">
            {f.remediation}
          </div>
        </Row>
      </Card>

      {/* Raw Instances & Occurrences */}
      {occurrences.length > 0 && (
        <Card title={`Raw Occurrences Across Targets (${occurrences.length} instances)`}>
          <p className="text-xs text-slate-400 mb-3">
            This deduplicated vulnerability was observed at the following endpoints:
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-left text-slate-400 uppercase border-b border-slate-800">
                <tr>
                  <th className="py-2 px-2.5">Endpoint URL</th>
                  <th className="py-2 px-2.5">Method</th>
                  <th className="py-2 px-2.5">Parameter</th>
                  <th className="py-2 px-2.5">Evidence Snippet</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {occurrences.map((occ, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40 font-mono text-[11px]">
                    <td className="py-2 px-2.5 truncate max-w-xs text-slate-300">{occ.url}</td>
                    <td className="py-2 px-2.5 text-slate-400">{occ.method || "GET"}</td>
                    <td className="py-2 px-2.5 text-slate-400">{occ.parameter || "—"}</td>
                    <td className="py-2 px-2.5 truncate max-w-sm text-slate-400">{occ.evidence || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
