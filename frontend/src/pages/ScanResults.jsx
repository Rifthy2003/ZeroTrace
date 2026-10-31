import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  Legend,
} from "recharts";
import { getFindings, getScan, getSecurityPosture, reportUrl } from "../services/api";
import { Card, SeverityBadge, LifecycleBadge, Spinner } from "../components/ui";
import { SEVERITIES, SEVERITY_COLORS } from "../utils/format";

export default function ScanResults() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState(null);
  const [posture, setPosture] = useState(null);
  const [flt, setFlt] = useState({ severity: "", confidence: "", type: "", url: "" });
  const [showCoverageDetails, setShowCoverageDetails] = useState(false);

  useEffect(() => {
    getScan(id).then(setScan);
    getSecurityPosture(id).then(setPosture).catch((err) => console.error("Posture fetch error:", err));
  }, [id]);

  useEffect(() => {
    const params = Object.fromEntries(Object.entries(flt).filter(([, v]) => v));
    getFindings(id, params).then(setFindings);
  }, [id, flt]);

  if (!scan || !findings) return <Spinner />;

  const input = "bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm";
  const types = [...new Set(findings.map((f) => f.type))];

  // Recharts severity comparison data
  const chartData = posture
    ? SEVERITIES.map((s) => {
      const key = s.toLowerCase();
      return {
        severity: s,
        unique: posture.unique_counts[key] || 0,
        raw: posture.raw_counts[key] || 0,
      };
    })
    : [];

  const ratingBorderColor =
    posture?.rating === "STRONG"
      ? "border-emerald-500/40"
      : posture?.rating === "MEDIUM"
        ? "border-amber-500/40"
        : "border-red-500/40";

  const ratingBadgeBg =
    posture?.rating === "STRONG"
      ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
      : posture?.rating === "MEDIUM"
        ? "bg-amber-500/20 text-amber-300 border-amber-500/40"
        : "bg-red-500/20 text-red-300 border-red-500/40";

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3">
        <div>
          <h1 className="text-2xl font-bold">Scan Results</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Target: <span className="font-mono text-slate-300">{scan.target?.base_url || "Target"}</span>
          </p>
        </div>
        <a
          href={reportUrl(id)}
          className="inline-flex items-center justify-center bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-4 py-2 rounded text-sm transition-colors"
        >
          Download PDF report
        </a>
      </div>

      {/* Website Security Posture Card */}
      {posture && (
        <Card className={`border-2 ${ratingBorderColor} bg-slate-900/90 shadow-xl overflow-hidden`}>
          {/* Posture Header */}
          <div className="flex flex-wrap items-center justify-between pb-3 mb-4 border-b border-slate-800 gap-2">
            <div className="flex items-center gap-2">
              <span className="text-base font-bold text-slate-100">🛡 Website Security Posture</span>
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                {posture.hostname}
              </span>
              <span className="text-xs text-slate-500 font-mono hidden md:inline">
                ID: {posture.scan_id.slice(0, 8)}...
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`text-xs px-2.5 py-0.5 rounded-full border font-semibold uppercase tracking-wider ${posture.scan_status === "completed"
                    ? "bg-slate-800 text-slate-300 border-slate-700"
                    : "bg-amber-500/20 text-amber-300 border-amber-500/30"
                  }`}
              >
                {posture.scan_status}
              </span>
              {posture.is_preliminary && (
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-amber-950/60 text-amber-400 border border-amber-800 font-semibold">
                  ⚠️ Preliminary Rating
                </span>
              )}
            </div>
          </div>

          {/* Main Visual Metrics Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            {/* Score & Rating Pill */}
            <div className="lg:col-span-4 flex flex-col justify-between p-4 rounded-lg bg-slate-950/60 border border-slate-800">
              <div>
                <div className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Security Score</div>
                <div className="flex items-baseline gap-2 mt-2">
                  <span
                    className="text-5xl font-black tracking-tight"
                    style={{ color: posture.rating_color }}
                  >
                    {posture.score}
                  </span>
                  <span className="text-lg text-slate-500 font-medium">/ 100</span>
                </div>
                <div className="mt-3 flex items-center gap-2">
                  <span className={`px-2.5 py-1 rounded text-xs font-bold border ${ratingBadgeBg}`}>
                    {posture.rating}
                  </span>
                  {posture.total_penalty > 0 && (
                    <span className="text-xs text-red-400 font-mono">
                      -{posture.total_penalty} pts penalty
                    </span>
                  )}
                </div>
              </div>

              {posture.is_preliminary && posture.preliminary_reasons?.length > 0 && (
                <div className="mt-3 text-[11px] text-amber-300/90 bg-amber-950/30 p-2 rounded border border-amber-900/50">
                  {posture.preliminary_reasons[0]}
                </div>
              )}
            </div>

            {/* Findings & Verification Counts */}
            <div className="lg:col-span-4 grid grid-cols-2 gap-2">
              <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800 flex flex-col justify-between">
                <span className="text-[11px] text-slate-400 uppercase font-semibold">Unique Issues</span>
                <div className="text-2xl font-bold text-slate-100">{posture.unique_counts.total}</div>
                <span className="text-[11px] text-slate-500">vs {posture.raw_counts.total} raw instances</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800 flex flex-col justify-between">
                <span className="text-[11px] text-slate-400 uppercase font-semibold">Confirmed</span>
                <div className="text-2xl font-bold text-emerald-400">{posture.unique_confirmed_count}</div>
                <span className="text-[11px] text-slate-500">Verified vulnerabilities</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800 flex flex-col justify-between">
                <span className="text-[11px] text-slate-400 uppercase font-semibold">Manual Verification</span>
                <div className="text-2xl font-bold text-amber-400">{posture.unique_manual_verification_count}</div>
                <span className="text-[11px] text-slate-500">Heuristic / requires review</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800 flex flex-col justify-between">
                <span className="text-[11px] text-slate-400 uppercase font-semibold">Pages Scanned</span>
                <div className="text-2xl font-bold text-cyan-400">{posture.coverage.urls_scanned}</div>
                <span className="text-[11px] text-slate-500">of {posture.coverage.urls_discovered} discovered</span>
              </div>
            </div>

            {/* Severity Breakdown Chart (Recharts) */}
            <div className="lg:col-span-4 p-3 rounded-lg bg-slate-950/40 border border-slate-800">
              <div className="text-[11px] text-slate-400 uppercase font-semibold mb-1">
                Findings by Severity (Unique vs Raw)
              </div>
              <div className="h-28 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                    <XAxis dataKey="severity" stroke="#64748b" fontSize={9} tickLine={false} />
                    <YAxis stroke="#64748b" fontSize={9} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", fontSize: 11 }}
                    />
                    <Bar dataKey="unique" fill="#10b981" name="Unique" />
                    <Bar dataKey="raw" fill="#475569" name="Raw" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="flex justify-center gap-4 text-[10px] text-slate-400 mt-1">
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded bg-emerald-500 inline-block" /> Unique
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded bg-slate-500 inline-block" /> Raw
                </span>
              </div>
            </div>
          </div>

          {/* Severity Pills Row */}
          <div className="mt-4 pt-3 border-t border-slate-800 grid grid-cols-2 sm:grid-cols-5 gap-2">
            {SEVERITIES.map((s) => {
              const k = s.toLowerCase();
              const count = posture.unique_counts[k] || 0;
              const rawCount = posture.raw_counts[k] || 0;
              return (
                <div
                  key={s}
                  className="px-2.5 py-1.5 rounded bg-slate-950/70 border border-slate-800/80 flex items-center justify-between"
                >
                  <span className="text-xs font-medium" style={{ color: SEVERITY_COLORS[s] }}>
                    {s}
                  </span>
                  <span className="text-xs font-semibold text-slate-200">
                    {count} <span className="text-[10px] text-slate-500">({rawCount})</span>
                  </span>
                </div>
              );
            })}
          </div>

          {/* Collapsible Coverage & Limitations */}
          <div className="mt-4 pt-3 border-t border-slate-800">
            <button
              onClick={() => setShowCoverageDetails(!showCoverageDetails)}
              className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 font-medium transition-colors"
            >
              <span>{showCoverageDetails ? "▼" : "▶"}</span>
              <span>Coverage Metrics & Assessment Scope ({posture.coverage.modules?.length || 0} modules active)</span>
            </button>

            {showCoverageDetails && (
              <div className="mt-3 p-3 bg-slate-950/60 rounded border border-slate-800 text-xs text-slate-300 space-y-2">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-slate-400 pb-2 border-b border-slate-800/60">
                  <div>Crawl Depth: <b className="text-slate-200">{posture.coverage.max_depth}</b></div>
                  <div>Max URLs: <b className="text-slate-200">{posture.coverage.max_urls}</b></div>
                  <div>Parameters: <b className="text-slate-200">{posture.coverage.parameters_found}</b></div>
                  <div>
                    Duration:{" "}
                    <b className="text-slate-200">
                      {posture.coverage.duration_seconds != null ? `${posture.coverage.duration_seconds}s` : "n/a"}
                    </b>
                  </div>
                </div>
                <div>
                  <span className="font-semibold text-slate-300">Active Modules: </span>
                  <span className="text-slate-400 font-mono text-[11px]">
                    {posture.coverage.modules?.join(", ") || "none"}
                  </span>
                </div>
                {posture.coverage.routes_discovered?.length > 0 && (
                  <div className="pt-2 border-t border-slate-800/60">
                    <span className="font-semibold text-slate-300">Client-Side / SPA Route Discovery:</span>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-2 text-[11px]">
                      <div className="p-2 bg-slate-900 rounded border border-slate-800">
                        <span className="text-slate-400 block">Discovered</span>
                        <b className="text-emerald-400 text-sm">{posture.coverage.routes_discovered.length}</b>
                      </div>
                      <div className="p-2 bg-slate-900 rounded border border-slate-800">
                        <span className="text-slate-400 block">Visited</span>
                        <b className="text-cyan-400 text-sm">{posture.coverage.routes_visited?.length || 0}</b>
                      </div>
                      <div className="p-2 bg-slate-900 rounded border border-slate-800">
                        <span className="text-slate-400 block">Tested</span>
                        <b className="text-blue-400 text-sm">{posture.coverage.routes_tested?.length || 0}</b>
                      </div>
                      <div className="p-2 bg-slate-900 rounded border border-slate-800">
                        <span className="text-slate-400 block">Auth Required</span>
                        <b className="text-amber-400 text-sm">{posture.coverage.routes_auth_required?.length || 0}</b>
                      </div>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                      {posture.coverage.routes_discovered.map((r, i) => {
                        const isAuth = posture.coverage.routes_auth_required?.includes(r);
                        return (
                          <span
                            key={i}
                            className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                              isAuth
                                ? "bg-amber-950/60 border border-amber-800/80 text-amber-300"
                                : "bg-slate-900 border border-slate-700/80 text-slate-300"
                            }`}
                          >
                            {r} {isAuth ? "🔒 [Auth Req]" : ""}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                )}
                {posture.coverage.limitations?.length > 0 && (
                  <div>
                    <span className="font-semibold text-slate-300">Assessment Limitations:</span>
                    <ul className="list-disc ml-4 text-[11px] text-slate-400 mt-1 space-y-0.5">
                      {posture.coverage.limitations.map((lim, idx) => (
                        <li key={idx}>{lim}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Main Reasons & Prioritized Remediation Row */}
          <div className="mt-4 pt-3 border-t border-slate-800 grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Main Reasons */}
            <div className="p-3 bg-slate-950/50 rounded border border-slate-800/80">
              <div className="text-xs font-semibold text-slate-300 uppercase tracking-wide mb-2 flex items-center justify-between">
                <span>Score Breakdown & Reasons</span>
                <span className="text-[10px] text-slate-500 font-normal">Deductions</span>
              </div>
              <ul className="space-y-1.5 text-xs">
                {posture.main_reasons?.map((reason, idx) => (
                  <li key={idx} className="text-slate-300 flex items-start gap-1.5">
                    <span className="text-amber-400/80 mt-0.5">•</span>
                    <span className="leading-relaxed">{reason}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Prioritized Remediation */}
            <div className="p-3 bg-slate-950/50 rounded border border-slate-800/80">
              <div className="text-xs font-semibold text-slate-300 uppercase tracking-wide mb-2 flex items-center justify-between">
                <span>Prioritized Remediation</span>
                <span className="text-[10px] text-emerald-400 font-normal">Action Items</span>
              </div>
              <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                {posture.recommendations?.map((rec, idx) => (
                  <div key={idx} className="text-xs bg-slate-900/80 p-2 rounded border border-slate-800">
                    <div className="flex items-center gap-1.5 mb-1">
                      <SeverityBadge severity={rec.severity} />
                      <span className="font-semibold text-slate-200">{rec.finding_type}</span>
                    </div>
                    <p className="text-[11px] text-slate-300 leading-normal">{rec.remediation}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Heuristic Disclaimer Footer */}
          <div className="mt-4 pt-2 border-t border-slate-800/60 text-[10px] text-slate-500 italic">
            * {posture.disclaimer}
          </div>
        </Card>
      )}

      {/* Filter Bar */}
      <Card>
        <div className="flex flex-wrap gap-2">
          <select
            className={input}
            value={flt.severity}
            onChange={(e) => setFlt({ ...flt, severity: e.target.value })}
          >
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
          <select
            className={input}
            value={flt.confidence}
            onChange={(e) => setFlt({ ...flt, confidence: e.target.value })}
          >
            <option value="">All confidence</option>
            {["Confirmed", "High confidence", "Medium confidence", "Low confidence", "Informational"].map(
              (s) => (
                <option key={s}>{s}</option>
              )
            )}
          </select>
          <select
            className={input}
            value={flt.type}
            onChange={(e) => setFlt({ ...flt, type: e.target.value })}
          >
            <option value="">All types</option>
            {types.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
          <input
            className={input}
            placeholder="Filter URL"
            value={flt.url}
            onChange={(e) => setFlt({ ...flt, url: e.target.value })}
          />
        </div>
      </Card>

      {/* Findings Table */}
      <Card>
        <table className="w-full text-sm">
          <thead className="text-left text-slate-400">
            <tr>
              <th>Type</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Confidence</th>
              <th>URL</th>
              <th>Param</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} className="border-t border-slate-800 hover:bg-slate-800/50">
                <td className="py-2">
                  <Link className="text-emerald-400" to={`/scan/${id}/finding/${f.id}`}>
                    {f.type}
                  </Link>
                </td>
                <td>
                  <SeverityBadge severity={f.severity} />
                </td>
                <td>
                  <LifecycleBadge status={f.status} />
                </td>
                <td>{f.confidence}</td>
                <td className="truncate max-w-xs">{f.url}</td>
                <td>{f.parameter || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {findings.length === 0 && <div className="text-slate-400 text-sm py-4">No findings match.</div>}
      </Card>
    </div>
  );
}
