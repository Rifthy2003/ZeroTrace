import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";
import { getApplicationTrends, reportUrl } from "../../services/api";
import { SeverityBadge, Spinner, RatingBadge, EmptyState } from "../ui";
import { fmtDate, fmtDuration } from "../../utils/format";

export default function WebsiteTrendsModal({ app, onClose }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("overview"); // overview, new, resolved, persistent, reopened, history

  useEffect(() => {
    if (!app?.id) return;
    setLoading(true);
    getApplicationTrends(app.id)
      .then(setData)
      .catch((err) => console.error("Error loading trends:", err))
      .finally(() => setLoading(false));
  }, [app?.id]);

  if (!app) return null;

  const chartData = (data?.history || []).map((h, idx) => ({
    name: `#${idx + 1} (${fmtDate(h.created_at)})`,
    date: fmtDate(h.created_at),
    score: h.score,
    critical: h.critical_count,
    high: h.high_count,
    medium: h.medium_count,
    low: h.low_count,
  }));

  const delta = data?.score_delta;
  const deltaColor =
    delta > 0
      ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
      : delta < 0
      ? "text-rose-400 bg-rose-500/10 border-rose-500/30"
      : "text-slate-400 bg-slate-800 border-slate-700";

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between p-5 border-b border-slate-800 bg-slate-900/90">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xl">📈</span>
              <h2 className="text-lg font-bold text-slate-100">{app.name}</h2>
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                {app.target_url || app.hostname}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Historical Security Posture Trends & Vulnerability Differential
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 text-xl font-bold p-1 rounded hover:bg-slate-800"
          >
            ✕
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {loading ? (
            <Spinner message="Calculating historical posture trends…" />
          ) : !data || data.history.length === 0 ? (
            <EmptyState
              icon="📊"
              title="No Completed Scans Yet"
              description="Once this target completes at least one scan, historical score trends and differential remediation analysis will be charted here."
            />
          ) : (
            <>
              {/* Score Comparison KPI row */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
                  <div className="text-[10px] uppercase font-semibold text-slate-400">Latest Security Score</div>
                  <div className="text-2xl font-bold font-mono mt-1 text-slate-100">
                    {data.latest_score != null ? Math.round(data.latest_score) : "—"}
                    <span className="text-xs text-slate-500 font-normal"> / 100</span>
                  </div>
                </div>

                <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
                  <div className="text-[10px] uppercase font-semibold text-slate-400">Previous Scan Score</div>
                  <div className="text-2xl font-bold font-mono mt-1 text-slate-300">
                    {data.previous_score != null ? Math.round(data.previous_score) : "—"}
                    <span className="text-xs text-slate-500 font-normal"> / 100</span>
                  </div>
                </div>

                <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
                  <div className="text-[10px] uppercase font-semibold text-slate-400">Score Trajectory</div>
                  <div className="mt-1">
                    {delta != null ? (
                      <span className={`px-2 py-0.5 text-xs font-mono font-bold rounded border inline-block ${deltaColor}`}>
                        {delta > 0 ? `+${delta} pts Improved` : delta < 0 ? `${delta} pts Degraded` : "0 pts Unchanged"}
                      </span>
                    ) : (
                      <span className="text-xs text-slate-500 font-mono">Baseline Scan</span>
                    )}
                  </div>
                </div>

                <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3.5">
                  <div className="text-[10px] uppercase font-semibold text-slate-400">Total Completed Scans</div>
                  <div className="text-2xl font-bold font-mono mt-1 text-emerald-400">
                    {data.history.length}
                  </div>
                </div>
              </div>

              {/* Historical Score Trend Chart */}
              <div className="bg-slate-950/40 border border-slate-800 rounded-xl p-4">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                    Historical Security Score (0–100)
                  </h3>
                  <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
                    <span className="flex items-center gap-1">
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" /> Strong (85+)
                    </span>
                    <span className="flex items-center gap-1">
                      <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" /> Medium (60–84)
                    </span>
                    <span className="flex items-center gap-1">
                      <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" /> Weak (&lt;60)
                    </span>
                  </div>
                </div>

                <div className="h-56 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={chartData} margin={{ top: 10, right: 20, left: -20, bottom: 5 }}>
                      <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                      <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                      <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} />
                      <Tooltip
                        contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: 8, fontSize: 12 }}
                        formatter={(val) => [`${val} / 100`, "Security Score"]}
                      />
                      <ReferenceLine y={85} stroke="#10b981" strokeDasharray="2 2" strokeOpacity={0.4} />
                      <ReferenceLine y={60} stroke="#f59e0b" strokeDasharray="2 2" strokeOpacity={0.4} />
                      <Line
                        type="monotone"
                        dataKey="score"
                        stroke="#10b981"
                        strokeWidth={2.5}
                        dot={{ r: 4, fill: "#10b981" }}
                        activeDot={{ r: 6 }}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Differential Comparison Tabs: New, Resolved, Persistent, Reopened */}
              <div>
                <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-2 text-xs">
                  <button
                    onClick={() => setActiveTab("overview")}
                    className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                      activeTab === "overview" ? "bg-slate-800 text-slate-100" : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Vulnerability Differential Summary
                  </button>
                  <button
                    onClick={() => setActiveTab("new")}
                    className={`px-3 py-1.5 rounded-lg font-medium transition-colors flex items-center gap-1 ${
                      activeTab === "new" ? "bg-rose-500/20 text-rose-300 border border-rose-500/30" : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    <span>New</span>
                    <span className="font-mono font-bold">({data.new_vulnerabilities_count})</span>
                  </button>
                  <button
                    onClick={() => setActiveTab("resolved")}
                    className={`px-3 py-1.5 rounded-lg font-medium transition-colors flex items-center gap-1 ${
                      activeTab === "resolved" ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30" : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    <span>Resolved</span>
                    <span className="font-mono font-bold">({data.resolved_vulnerabilities_count})</span>
                  </button>
                  <button
                    onClick={() => setActiveTab("persistent")}
                    className={`px-3 py-1.5 rounded-lg font-medium transition-colors flex items-center gap-1 ${
                      activeTab === "persistent" ? "bg-amber-500/20 text-amber-300 border border-amber-500/30" : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    <span>Persistent</span>
                    <span className="font-mono font-bold">({data.persistent_vulnerabilities_count})</span>
                  </button>
                  <button
                    onClick={() => setActiveTab("reopened")}
                    className={`px-3 py-1.5 rounded-lg font-medium transition-colors flex items-center gap-1 ${
                      activeTab === "reopened" ? "bg-purple-500/20 text-purple-300 border border-purple-500/30" : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    <span>Reopened</span>
                    <span className="font-mono font-bold">({data.reopened_vulnerabilities_count})</span>
                  </button>
                  <button
                    onClick={() => setActiveTab("history")}
                    className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                      activeTab === "history" ? "bg-slate-800 text-slate-100" : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Scan History Records ({data.history.length})
                  </button>
                </div>

                {/* Tab Contents */}
                <div className="pt-4 text-xs">
                  {activeTab === "overview" && (
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div className="bg-rose-950/20 border border-rose-900/30 rounded-xl p-3 text-center">
                        <div className="text-[10px] uppercase font-semibold text-rose-300">New Findings</div>
                        <div className="text-2xl font-bold font-mono text-rose-400 mt-1">{data.new_vulnerabilities_count}</div>
                        <div className="text-[10px] text-slate-400 mt-1">Detected in latest scan</div>
                      </div>
                      <div className="bg-emerald-950/20 border border-emerald-900/30 rounded-xl p-3 text-center">
                        <div className="text-[10px] uppercase font-semibold text-emerald-300">Resolved Findings</div>
                        <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{data.resolved_vulnerabilities_count}</div>
                        <div className="text-[10px] text-slate-400 mt-1">Verified fixed</div>
                      </div>
                      <div className="bg-amber-950/20 border border-amber-900/30 rounded-xl p-3 text-center">
                        <div className="text-[10px] uppercase font-semibold text-amber-300">Persistent Findings</div>
                        <div className="text-2xl font-bold font-mono text-amber-400 mt-1">{data.persistent_vulnerabilities_count}</div>
                        <div className="text-[10px] text-slate-400 mt-1">Still open across scans</div>
                      </div>
                      <div className="bg-purple-950/20 border border-purple-900/30 rounded-xl p-3 text-center">
                        <div className="text-[10px] uppercase font-semibold text-purple-300">Reopened Findings</div>
                        <div className="text-2xl font-bold font-mono text-purple-400 mt-1">{data.reopened_vulnerabilities_count}</div>
                        <div className="text-[10px] text-slate-400 mt-1">Previously fixed issue recurred</div>
                      </div>
                    </div>
                  )}

                  {activeTab === "new" && (
                    <FindingList findings={data.new_vulnerabilities} emptyMsg="No new vulnerabilities introduced in the latest scan." />
                  )}

                  {activeTab === "resolved" && (
                    <FindingList findings={data.resolved_vulnerabilities} emptyMsg="No vulnerabilities resolved compared to previous scan." isResolved />
                  )}

                  {activeTab === "persistent" && (
                    <FindingList findings={data.persistent_vulnerabilities} emptyMsg="No persistent findings across consecutive scans." />
                  )}

                  {activeTab === "reopened" && (
                    <FindingList findings={data.reopened_vulnerabilities} emptyMsg="No previously resolved findings have recurred." />
                  )}

                  {activeTab === "history" && (
                    <div className="border border-slate-800 rounded-xl overflow-hidden">
                      <table className="w-full text-left">
                        <thead className="bg-slate-950/60 text-slate-400 text-[11px] uppercase border-b border-slate-800">
                          <tr>
                            <th className="py-2.5 px-3">Date</th>
                            <th className="py-2.5 px-3">Score & Rating</th>
                            <th className="py-2.5 px-3">Findings</th>
                            <th className="py-2.5 px-3">Routes Tested</th>
                            <th className="py-2.5 px-3">Duration</th>
                            <th className="py-2.5 px-3 text-right">Actions</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                          {data.history.map((h) => (
                            <tr key={h.scan_id} className="hover:bg-slate-800/40">
                              <td className="py-2 px-3 font-mono">{fmtDate(h.created_at)}</td>
                              <td className="py-2 px-3">
                                <RatingBadge rating={h.rating} score={h.score} />
                              </td>
                              <td className="py-2 px-3">
                                <div className="flex gap-1">
                                  <span className="text-red-400 font-mono">C:{h.critical_count}</span>
                                  <span className="text-orange-400 font-mono">H:{h.high_count}</span>
                                  <span className="text-amber-400 font-mono">M:{h.medium_count}</span>
                                </div>
                              </td>
                              <td className="py-2 px-3 font-mono">{h.routes_tested} / {h.routes_discovered}</td>
                              <td className="py-2 px-3 font-mono">{fmtDuration(h.duration_seconds)}</td>
                              <td className="py-2 px-3 text-right">
                                <div className="flex items-center justify-end gap-2">
                                  <Link
                                    to={`/scan/${h.scan_id}`}
                                    className="text-emerald-400 hover:text-emerald-300"
                                  >
                                    Results
                                  </Link>
                                  <a
                                    href={reportUrl(h.scan_id)}
                                    className="text-slate-400 hover:text-slate-200"
                                  >
                                    PDF
                                  </a>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/90 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function FindingList({ findings, emptyMsg, isResolved }) {
  if (!findings || findings.length === 0) {
    return <div className="p-4 text-center text-slate-400 bg-slate-950/40 rounded-xl">{emptyMsg}</div>;
  }

  return (
    <div className="border border-slate-800 rounded-xl overflow-hidden">
      <table className="w-full text-left">
        <thead className="bg-slate-950/60 text-slate-400 text-[11px] uppercase border-b border-slate-800">
          <tr>
            <th className="py-2 px-3">Vulnerability</th>
            <th className="py-2 px-3">Severity</th>
            <th className="py-2 px-3">Affected Route</th>
            <th className="py-2 px-3">Parameter</th>
            <th className="py-2 px-3">Status</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {findings.map((f, i) => (
            <tr key={f.id || i} className="hover:bg-slate-800/40">
              <td className="py-2 px-3 font-medium text-slate-200">{f.type}</td>
              <td className="py-2 px-3">
                <SeverityBadge severity={f.severity} />
              </td>
              <td className="py-2 px-3 font-mono text-slate-300 truncate max-w-xs">{f.url}</td>
              <td className="py-2 px-3 font-mono text-slate-400">{f.parameter || "—"}</td>
              <td className="py-2 px-3">
                {isResolved ? (
                  <span className="px-2 py-0.5 rounded text-xs bg-emerald-500/20 text-emerald-300 font-semibold">
                    Resolved
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-300 uppercase">
                    {f.status || "open"}
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

