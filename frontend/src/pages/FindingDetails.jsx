import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  getFindings,
  getFinding,
  updateFindingStatus,
  getFindingHistory,
  bountyReportUrl,
} from "../services/api";
import { Card, SeverityBadge, LifecycleBadge, Spinner } from "../components/ui";
import { ALL_LIFECYCLE_STATUSES, fmtDate } from "../utils/format";

const Row = ({ label, children }) => (
  <div className="mb-3">
    <div className="text-xs uppercase text-slate-400 font-medium">{label}</div>
    <div className="text-sm whitespace-pre-wrap break-words text-slate-200 mt-0.5">{children || "—"}</div>
  </div>
);

export default function FindingDetails() {
  const { id, fid } = useParams();
  const [f, setF] = useState(null);
  const [status, setStatus] = useState("New");
  const [note, setNote] = useState("");
  const [user, setUser] = useState("Security Researcher");
  const [history, setHistory] = useState([]);
  const [isUpdating, setIsUpdating] = useState(false);
  const [msg, setMsg] = useState({ text: "", type: "" });

  const loadFindingData = async () => {
    try {
      const findingData = await getFinding(fid);
      if (findingData) {
        setF(findingData);
        setStatus(findingData.status || "New");
        setNote(findingData.status_note || "");
        if (findingData.status_history) {
          setHistory(findingData.status_history);
        }
      }
    } catch {
      // Fallback to finding from scan
      const all = await getFindings(id);
      const match = all.find((x) => x.id === fid);
      if (match) {
        setF(match);
        setStatus(match.status || "New");
        setNote(match.status_note || "");
      }
    }

    try {
      const hist = await getFindingHistory(fid);
      if (hist && Array.isArray(hist)) {
        setHistory(hist);
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    loadFindingData();
  }, [id, fid]);

  const handleUpdateStatus = async (e) => {
    e?.preventDefault();
    setIsUpdating(true);
    setMsg({ text: "", type: "" });
    try {
      const updated = await updateFindingStatus(fid, {
        status,
        note: note.trim() || undefined,
        user: user.trim() || "Security Researcher",
      });
      setF((prev) => ({
        ...prev,
        status: updated.status,
        status_note: updated.status_note,
        status_updated_at: updated.status_updated_at,
      }));
      setMsg({ text: `Lifecycle status successfully updated to "${updated.status}"!`, type: "success" });
      const hist = await getFindingHistory(fid);
      if (hist) setHistory(hist);
      setTimeout(() => setMsg({ text: "", type: "" }), 4000);
    } catch (err) {
      console.error(err);
      setMsg({ text: err.response?.data?.detail || "Failed to update lifecycle status.", type: "error" });
    } finally {
      setIsUpdating(false);
    }
  };

  if (!f) return <Spinner />;

  const occurrences = f.evidence_details?.occurrences || [];

  return (
    <div className="max-w-4xl space-y-5">
      {/* Navigation and Top Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <Link to={`/scan/${id}`} className="text-sm text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1">
          &larr; Back to scan results
        </Link>
        <div className="flex items-center gap-2">
          <a
            href={bountyReportUrl(f.id)}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white transition-colors shadow-sm"
            title="Download individual 4-6 page Bug Bounty PDF report"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Download Bug Bounty Report (PDF)
          </a>
        </div>
      </div>

      {/* Title & Metadata Badges */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100">{f.type}</h1>
        <div className="flex flex-wrap gap-2.5 items-center mt-2.5">
          <SeverityBadge severity={f.severity} />
          <span className="text-xs px-2.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
            Confidence: {f.confidence}
          </span>

          {/* Explicit separation between Scanner Detection Status and Researcher Lifecycle Status */}
          <div className="flex items-center gap-1.5 text-xs bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
            <span className="text-slate-400">Scanner:</span>
            <span
              className={`font-semibold ${
                f.detection_status === "Confirmed"
                  ? "text-emerald-400"
                  : f.detection_status === "Requires Manual Verification"
                  ? "text-amber-400"
                  : "text-blue-400"
              }`}
            >
              {f.detection_status || "Confirmed"}
            </span>
          </div>

          <div className="flex items-center gap-1.5 text-xs bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
            <span className="text-slate-400">Lifecycle:</span>
            <LifecycleBadge status={f.status || "New"} />
          </div>

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
              FP: {f.fingerprint.slice(0, 16)}...
            </span>
          )}
        </div>
      </div>

      {/* Feature 2: Researcher Lifecycle Management Panel */}
      <Card title="Researcher Lifecycle Management">
        <div className="text-xs text-slate-400 mb-4">
          Manage the vulnerability lifecycle independently from automated scanner findings. Transitions are logged to the audit history timeline below.
        </div>

        <form onSubmit={handleUpdateStatus} className="space-y-3 bg-slate-950/60 p-4 rounded-lg border border-slate-800">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-slate-300 font-medium block mb-1">
                Lifecycle Status <span className="text-rose-400">*</span>
              </label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500 w-full"
              >
                {ALL_LIFECYCLE_STATUSES.map((st) => (
                  <option key={st} value={st}>
                    {st}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-300 font-medium block mb-1">
                Researcher / Reviewer Attribution
              </label>
              <input
                type="text"
                placeholder="e.g. Lead AppSec / Alex Rivera"
                value={user}
                onChange={(e) => setUser(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-full"
              />
            </div>
          </div>

          <div>
            <label className="text-xs text-slate-300 font-medium block mb-1">
              Verification Note / Business Justification
            </label>
            <textarea
              rows={2}
              placeholder="e.g. Re-tested with crafted payload; issue resolved in commit c4f89b or requires staging verification."
              value={note}
              onChange={(e) => setNote(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-full"
            />
          </div>

          <div className="flex items-center justify-between pt-1">
            <div className="text-xs">
              {msg.text && (
                <span className={msg.type === "success" ? "text-emerald-400 font-medium" : "text-rose-400 font-medium"}>
                  {msg.type === "success" ? "✓ " : "⚠ "}
                  {msg.text}
                </span>
              )}
            </div>
            <button
              type="submit"
              disabled={isUpdating}
              className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold disabled:opacity-50 transition-colors shadow"
            >
              {isUpdating ? "Updating..." : "Update Lifecycle Status"}
            </button>
          </div>
        </form>

        {/* Timestamped Audit History Timeline */}
        <div className="mt-5 pt-4 border-t border-slate-800">
          <h4 className="text-xs font-semibold uppercase text-slate-400 tracking-wider mb-3 flex items-center gap-1.5">
            <span>⏱</span> Status Audit History & Review Timeline ({history.length})
          </h4>

          {history.length === 0 ? (
            <div className="text-xs text-slate-500 italic p-3 bg-slate-950/40 rounded border border-slate-800/60">
              No manual status transitions recorded yet. Initial lifecycle status is "{f.status || "New"}".
            </div>
          ) : (
            <div className="relative pl-6 border-l-2 border-slate-800 space-y-4">
              {history.map((h, idx) => (
                <div key={idx} className="relative group">
                  {/* Dot */}
                  <div className="absolute -left-[31px] top-1.5 w-3 h-3 rounded-full bg-emerald-500 border-2 border-slate-900" />
                  <div className="bg-slate-950/60 rounded-lg p-3 border border-slate-800">
                    <div className="flex flex-wrap items-center justify-between gap-1 text-xs mb-1">
                      <div className="flex items-center gap-1.5 font-medium">
                        <span className="text-slate-400">{h.old_status || "Initial"}</span>
                        <span className="text-slate-600">&rarr;</span>
                        <LifecycleBadge status={h.new_status} />
                      </div>
                      <span className="text-slate-500 text-[11px] font-mono">{fmtDate(h.timestamp)}</span>
                    </div>
                    <div className="text-xs text-slate-400 mt-1">
                      <span className="font-semibold text-slate-300">{h.user || "Security Researcher"}</span>
                      {h.note && (
                        <p className="mt-1 text-slate-200 bg-slate-900/80 p-2 rounded border border-slate-800/80 font-sans italic text-xs">
                          "{h.note}"
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </Card>

      {/* Technical Vulnerability Details Card */}
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
