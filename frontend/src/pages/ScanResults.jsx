import React, { useEffect, useState, useRef } from "react";
import { useParams, Link } from "react-router-dom";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { getFindings, getScan, getSecurityPosture, reportUrl } from "../services/api";
import { Card, SeverityBadge, LifecycleBadge, Spinner, Pagination } from "../components/ui";
import { SEVERITIES, SEVERITY_COLORS, fmtDate } from "../utils/format";

export default function ScanResults() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState(null);
  const [posture, setPosture] = useState(null);

  // Filters state
  const [flt, setFlt] = useState({
    severity: "",
    confidence: "",
    type: "",
    status: "",
    detection_status: "",
    search: "",
  });

  // Active filter label for clickable metrics
  const [activeFilterLabel, setActiveFilterLabel] = useState(null);

  // Accordion for expanded finding details
  const [expandedFindingId, setExpandedFindingId] = useState(null);

  // Collapsible sections
  const [showCoverageSection, setShowCoverageSection] = useState(true);
  const [showCoverageDetails, setShowCoverageDetails] = useState(false);

  // Pagination for findings table
  const [page, setPage] = useState(1);
  const pageSize = 15;

  const findingsSectionRef = useRef(null);

  useEffect(() => {
    getScan(id).then(setScan).catch((err) => console.error("Scan fetch error:", err));
    getSecurityPosture(id).then(setPosture).catch((err) => console.error("Posture fetch error:", err));
  }, [id]);

  useEffect(() => {
    getFindings(id).then(setFindings).catch((err) => console.error("Findings fetch error:", err));
  }, [id]);

  if (!scan || !findings) return <Spinner />;

  // Scroll to findings table helper
  const scrollToFindings = () => {
    if (findingsSectionRef.current) {
      findingsSectionRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  // Clickable Metric Handlers
  const handleFilterBySeverity = (sev) => {
    if (flt.severity === sev) {
      setFlt((prev) => ({ ...prev, severity: "" }));
      setActiveFilterLabel(null);
    } else {
      setFlt((prev) => ({ ...prev, severity: sev, detection_status: "" }));
      setActiveFilterLabel(`Severity: ${sev}`);
      setPage(1);
      scrollToFindings();
    }
  };

  const handleFilterUniqueIssues = () => {
    setFlt({ severity: "", confidence: "", type: "", status: "", detection_status: "", search: "" });
    setActiveFilterLabel("All Unique Issues");
    setPage(1);
    scrollToFindings();
  };

  const handleFilterConfirmed = () => {
    if (flt.detection_status === "Confirmed") {
      setFlt((prev) => ({ ...prev, detection_status: "" }));
      setActiveFilterLabel(null);
    } else {
      setFlt((prev) => ({ ...prev, detection_status: "Confirmed", severity: "" }));
      setActiveFilterLabel("Status: Confirmed");
      setPage(1);
      scrollToFindings();
    }
  };

  const handleFilterManualVerification = () => {
    if (flt.detection_status === "Requires Manual Verification") {
      setFlt((prev) => ({ ...prev, detection_status: "" }));
      setActiveFilterLabel(null);
    } else {
      setFlt((prev) => ({ ...prev, detection_status: "Requires Manual Verification", severity: "" }));
      setActiveFilterLabel("Status: Manual Verification");
      setPage(1);
      scrollToFindings();
    }
  };

  const clearAllFilters = () => {
    setFlt({ severity: "", confidence: "", type: "", status: "", detection_status: "", search: "" });
    setActiveFilterLabel(null);
    setPage(1);
  };

  // Filter findings client-side for immediate responsiveness
  const filteredFindings = findings.filter((f) => {
    if (flt.severity && f.severity !== flt.severity) return false;
    if (flt.confidence && f.confidence !== flt.confidence) return false;
    if (flt.type && f.type !== flt.type) return false;
    if (flt.status && f.status !== flt.status) return false;
    if (flt.detection_status && (f.detection_status || "Confirmed") !== flt.detection_status) return false;
    if (flt.search.trim()) {
      const q = flt.search.toLowerCase();
      const matchType = (f.type || "").toLowerCase().includes(q);
      const matchUrl = (f.url || "").toLowerCase().includes(q);
      const matchParam = (f.parameter || "").toLowerCase().includes(q);
      const matchCwe = (f.cwe_id || "").toLowerCase().includes(q);
      const matchEvid = (f.evidence || "").toLowerCase().includes(q);
      if (!matchType && !matchUrl && !matchParam && !matchCwe && !matchEvid) return false;
    }
    return true;
  });

  const totalPages = Math.ceil(filteredFindings.length / pageSize) || 1;
  const paginatedFindings = filteredFindings.slice((page - 1) * pageSize, page * pageSize);

  const types = [...new Set(findings.map((f) => f.type))];

  // CSV Export Handler
  const handleExportCSV = () => {
    const headers = [
      "Vulnerability Type",
      "Severity",
      "Confidence",
      "Detection Status",
      "Lifecycle Status",
      "CWE ID",
      "MITRE ATT&CK",
      "Affected URL",
      "Method",
      "Parameter",
      "Raw Instances Count",
      "Evidence",
      "Remediation",
    ];

    const rows = filteredFindings.map((f) => [
      `"${(f.type || "").replace(/"/g, '""')}"`,
      `"${f.severity || ""}"`,
      `"${f.confidence || ""}"`,
      `"${f.detection_status || "Confirmed"}"`,
      `"${f.status || "open"}"`,
      `"${f.cwe_id || ""}"`,
      `"${f.mitre_attack || ""}"`,
      `"${(f.url || "").replace(/"/g, '""')}"`,
      `"${f.method || "GET"}"`,
      `"${(f.parameter || "").replace(/"/g, '""')}"`,
      f.raw_instances || 1,
      `"${(f.evidence || "").replace(/"/g, '""')}"`,
      `"${(f.remediation || "").replace(/"/g, '""')}"`,
    ]);

    const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `zerotrace_findings_${scan.id.slice(0, 8)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

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

  // Coverage summary object from posture or scan
  const covSummary =
    posture?.coverage?.coverage_summary ||
    scan?.coverage_summary || {
      modules_total: 16,
      modules_tested: 9,
      modules_not_tested: 6,
      modules_not_applicable: 1,
      endpoints_discovered: posture?.coverage?.urls_discovered || 0,
      endpoints_tested: posture?.coverage?.urls_scanned || 0,
      forms_discovered: 0,
      parameters_tested: posture?.coverage?.parameters_found || 0,
      coverage_percentage: 60.0,
      module_matrix: [],
    };

  const inputClass = "bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500";

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Scan Results</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Target: <span className="font-mono text-emerald-400">{scan.target_url || scan.target?.base_url || "Target"}</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCSV}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold rounded text-xs border border-slate-700 transition-colors inline-flex items-center gap-1.5"
          >
            <span>📥</span> Export CSV
          </button>
          <a
            href={reportUrl(id)}
            className="inline-flex items-center justify-center bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-4 py-2 rounded text-sm transition-colors"
          >
            Download PDF report
          </a>
        </div>
      </div>

      {/* Website Security Posture Card with Clickable Metrics */}
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
                className={`text-xs px-2.5 py-0.5 rounded-full border font-semibold uppercase tracking-wider ${
                  posture.scan_status === "completed"
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

          {/* Main Visual Metrics Grid with Clickable Metric Cards */}
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

            {/* Clickable Findings & Verification Counts */}
            <div className="lg:col-span-4 grid grid-cols-2 gap-2">
              {/* Unique Issues Clickable */}
              <button
                type="button"
                onClick={handleFilterUniqueIssues}
                className={`p-3 rounded-lg text-left transition-all border flex flex-col justify-between ${
                  activeFilterLabel === "All Unique Issues"
                    ? "bg-slate-800 border-emerald-500 ring-1 ring-emerald-500/50"
                    : "bg-slate-950/40 border-slate-800 hover:border-slate-700 hover:bg-slate-900/60"
                }`}
                title="Click to view all unique vulnerability findings"
              >
                <div className="flex items-center justify-between w-full">
                  <span className="text-[11px] text-slate-400 uppercase font-semibold">Unique Issues</span>
                  <span className="text-[10px] text-emerald-400 font-mono">view &rarr;</span>
                </div>
                <div className="text-2xl font-bold text-slate-100 my-1">{posture.unique_counts.total}</div>
                <span className="text-[11px] text-slate-500">vs {posture.raw_counts.total} raw instances</span>
              </button>

              {/* Confirmed Clickable */}
              <button
                type="button"
                onClick={handleFilterConfirmed}
                className={`p-3 rounded-lg text-left transition-all border flex flex-col justify-between ${
                  flt.detection_status === "Confirmed"
                    ? "bg-slate-800 border-emerald-500 ring-1 ring-emerald-500/50"
                    : "bg-slate-950/40 border-slate-800 hover:border-slate-700 hover:bg-slate-900/60"
                }`}
                title="Click to filter verified confirmed vulnerabilities"
              >
                <div className="flex items-center justify-between w-full">
                  <span className="text-[11px] text-slate-400 uppercase font-semibold">Confirmed</span>
                  <span className="text-[10px] text-emerald-400 font-mono">view &rarr;</span>
                </div>
                <div className="text-2xl font-bold text-emerald-400 my-1">{posture.unique_confirmed_count}</div>
                <span className="text-[11px] text-slate-500">Verified vulnerabilities</span>
              </button>

              {/* Manual Verification Clickable */}
              <button
                type="button"
                onClick={handleFilterManualVerification}
                className={`p-3 rounded-lg text-left transition-all border flex flex-col justify-between ${
                  flt.detection_status === "Requires Manual Verification"
                    ? "bg-slate-800 border-amber-500 ring-1 ring-amber-500/50"
                    : "bg-slate-950/40 border-slate-800 hover:border-slate-700 hover:bg-slate-900/60"
                }`}
                title="Click to filter issues requiring manual review"
              >
                <div className="flex items-center justify-between w-full">
                  <span className="text-[11px] text-slate-400 uppercase font-semibold">Manual Verification</span>
                  <span className="text-[10px] text-amber-400 font-mono">view &rarr;</span>
                </div>
                <div className="text-2xl font-bold text-amber-400 my-1">{posture.unique_manual_verification_count}</div>
                <span className="text-[11px] text-slate-500">Heuristic / review required</span>
              </button>

              {/* Pages Scanned */}
              <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800 flex flex-col justify-between">
                <span className="text-[11px] text-slate-400 uppercase font-semibold">Pages Scanned</span>
                <div className="text-2xl font-bold text-cyan-400 my-1">{posture.coverage.urls_scanned}</div>
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

          {/* Clickable Severity Pills Row */}
          <div className="mt-4 pt-3 border-t border-slate-800">
            <div className="text-[11px] text-slate-400 font-semibold mb-2 flex items-center justify-between">
              <span>Filter Findings by Severity (Click to drill down):</span>
              {activeFilterLabel && (
                <button
                  onClick={clearAllFilters}
                  className="text-emerald-400 hover:text-emerald-300 font-medium text-[11px] underline"
                >
                  Clear active filter ({activeFilterLabel})
                </button>
              )}
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
              {SEVERITIES.map((s) => {
                const k = s.toLowerCase();
                const count = posture.unique_counts[k] || 0;
                const rawCount = posture.raw_counts[k] || 0;
                const isSelected = flt.severity === s;
                return (
                  <button
                    key={s}
                    type="button"
                    onClick={() => handleFilterBySeverity(s)}
                    className={`px-2.5 py-1.5 rounded text-left transition-all border flex items-center justify-between ${
                      isSelected
                        ? "bg-slate-800 border-emerald-500 ring-2 ring-emerald-500/50"
                        : "bg-slate-950/70 border-slate-800 hover:border-slate-700 hover:bg-slate-900"
                    }`}
                  >
                    <span className="text-xs font-semibold" style={{ color: SEVERITY_COLORS[s] }}>
                      {s}
                    </span>
                    <span className="text-xs font-semibold text-slate-200">
                      {count} <span className="text-[10px] text-slate-500">({rawCount})</span>
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        </Card>
      )}

      {/* ========================================================================= */}
      {/* 4. VULNERABILITY ASSESSMENT COVERAGE DASHBOARD SECTION                   */}
      {/* ========================================================================= */}
      <Card>
        <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <span>📊 Vulnerability Assessment Coverage</span>
              <span className="text-xs px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/80 font-mono">
                {covSummary.coverage_percentage}% Scanned
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Breakdown of security test modules, discovery scope, tested endpoints, and forms.
            </p>
          </div>
          <button
            onClick={() => setShowCoverageSection(!showCoverageSection)}
            className="text-xs text-slate-400 hover:text-slate-200 px-2 py-1 rounded bg-slate-800 border border-slate-700"
          >
            {showCoverageSection ? "Collapse ▲" : "Expand ▼"}
          </button>
        </div>

        {showCoverageSection && (
          <div className="space-y-4">
            {/* KPI Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-9 gap-2">
              <div className="p-2.5 bg-slate-950/60 rounded border border-slate-800 text-center">
                <span className="text-[10px] text-slate-400 uppercase font-semibold block">Total Modules</span>
                <span className="text-lg font-bold text-slate-200">{covSummary.modules_total}</span>
              </div>
              <div className="p-2.5 bg-slate-950/60 rounded border border-slate-800 text-center">
                <span className="text-[10px] text-slate-400 uppercase font-semibold block">Modules Tested</span>
                <span className="text-lg font-bold text-emerald-400">{covSummary.modules_tested}</span>
              </div>
              <div className="p-2.5 bg-slate-950/60 rounded border border-slate-800 text-center">
                <span className="text-[10px] text-slate-400 uppercase font-semibold block">Incomplete (Inputs)</span>
                <span className="text-lg font-bold text-amber-400">{covSummary.modules_incomplete || 0}</span>
              </div>
              <div className="p-2.5 bg-slate-950/60 rounded border border-slate-800 text-center">
                <span className="text-[10px] text-slate-400 uppercase font-semibold block">Not Tested</span>
                <span className="text-lg font-bold text-slate-400">{covSummary.modules_not_tested}</span>
              </div>
              <div className="p-2.5 bg-slate-950/60 rounded border border-slate-800 text-center">
                <span className="text-[10px] text-slate-400 uppercase font-semibold block">Not Applicable</span>
                <span className="text-lg font-bold text-slate-500">{covSummary.modules_not_applicable}</span>
              </div>
              <div className="p-2.5 bg-slate-950/60 rounded border border-slate-800 text-center">
                <span className="text-[10px] text-slate-400 uppercase font-semibold block">Endpoints</span>
                <span className="text-lg font-bold text-cyan-400">{covSummary.endpoints_tested} / {covSummary.endpoints_discovered}</span>
              </div>
              <div className="p-2.5 bg-slate-950/60 rounded border border-slate-800 text-center">
                <span className="text-[10px] text-slate-400 uppercase font-semibold block">Forms Discovered</span>
                <span className="text-lg font-bold text-indigo-400">{covSummary.forms_discovered || 0}</span>
              </div>
              <div className="p-2.5 bg-slate-950/60 rounded border border-slate-800 text-center">
                <span className="text-[10px] text-slate-400 uppercase font-semibold block">Params Tested</span>
                <span className="text-lg font-bold text-amber-300">{covSummary.parameters_tested || 0}</span>
              </div>
              <div className="p-2.5 bg-slate-950/60 rounded border border-slate-800 text-center">
                <span className="text-[10px] text-slate-400 uppercase font-semibold block">Coverage %</span>
                <span className="text-lg font-bold text-emerald-400">{covSummary.coverage_percentage}%</span>
              </div>
            </div>

            {/* Coverage Module Matrix Table */}
            {covSummary.module_matrix?.length > 0 && (
              <div className="overflow-x-auto border border-slate-800 rounded-lg">
                <table className="w-full text-xs">
                  <thead className="text-left text-slate-400 uppercase bg-slate-950/80 border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Module</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3">Findings</th>
                      <th className="py-2.5 px-3">Tested Endpoints</th>
                      <th className="py-2.5 px-3">Tested Parameters</th>
                      <th className="py-2.5 px-3">Coverage Detail / Audit Reason</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {covSummary.module_matrix.map((row, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-2 px-3 font-medium text-slate-200">
                          {row.name || row.module}
                        </td>
                        <td className="py-2 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${
                              row.status === "Tested"
                                ? "bg-emerald-950/60 text-emerald-400 border-emerald-800/80"
                                : row.status === "Incomplete"
                                ? "bg-amber-950/60 text-amber-400 border-amber-800/80"
                                : row.status === "Not Applicable"
                                ? "bg-slate-900 text-slate-400 border-slate-800"
                                : "bg-slate-800 text-slate-400 border-slate-700"
                            }`}
                          >
                            {row.status === "Incomplete" ? "Incomplete (No Inputs)" : row.status}
                          </span>
                        </td>
                        <td className="py-2 px-3 font-mono">
                          <span className={row.findings_count > 0 ? "text-amber-400 font-bold" : "text-slate-500"}>
                            {row.findings_count}
                          </span>
                        </td>
                        <td className="py-2 px-3 font-mono text-slate-400">
                          {row.endpoints_tested}
                        </td>
                        <td className="py-2 px-3 font-mono text-slate-300">
                          {row.parameters_tested != null ? row.parameters_tested : "—"}
                        </td>
                        <td className="py-2 px-3 text-[11px] text-slate-400">
                          {row.reason || "Standard module execution"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Detailed Execution Audit Log Drawer */}
            {covSummary.execution_logs?.length > 0 && (
              <div className="pt-2 border-t border-slate-800/60">
                <button
                  type="button"
                  onClick={() => setShowCoverageDetails(!showCoverageDetails)}
                  className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 font-semibold"
                >
                  <span>{showCoverageDetails ? "▼" : "▶"}</span>
                  <span>View Detailed Execution Audit Log ({covSummary.execution_logs.length} events logged)</span>
                </button>

                {showCoverageDetails && (
                  <div className="mt-2.5 max-h-60 overflow-y-auto border border-slate-800 rounded bg-slate-950/90">
                    <table className="w-full text-[11px] font-mono">
                      <thead className="bg-slate-900 text-slate-400 text-left border-b border-slate-800">
                        <tr>
                          <th className="py-1.5 px-2.5">Time</th>
                          <th className="py-1.5 px-2.5">Event</th>
                          <th className="py-1.5 px-2.5">Target URL & Method</th>
                          <th className="py-1.5 px-2.5">Module / Param</th>
                          <th className="py-1.5 px-2.5">Execution Result / Reason</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80">
                        {covSummary.execution_logs.map((log, lIdx) => (
                          <tr key={lIdx} className="hover:bg-slate-800/30">
                            <td className="py-1 px-2.5 text-slate-500 whitespace-nowrap">
                              {log.timestamp ? log.timestamp.split("T")[1]?.slice(0, 8) : "—"}
                            </td>
                            <td className="py-1 px-2.5">
                              <span
                                className={`px-1.5 py-0.2 rounded text-[10px] ${
                                  log.event === "parameter_tested"
                                    ? "bg-emerald-950/60 text-emerald-300"
                                    : log.event === "module_skipped" || log.event === "target_module_skipped"
                                    ? "bg-amber-950/60 text-amber-300"
                                    : log.event === "form_discovered"
                                    ? "bg-indigo-950/60 text-indigo-300"
                                    : "bg-slate-800 text-slate-400"
                                }`}
                              >
                                {log.event}
                              </span>
                            </td>
                            <td className="py-1 px-2.5 truncate max-w-xs text-slate-300" title={log.url}>
                              {log.method ? `[${log.method}] ` : ""}{log.url}
                            </td>
                            <td className="py-1 px-2.5 text-slate-300">
                              {log.module ? <b className="text-slate-200">{log.module}: </b> : ""}
                              {log.parameter ? <span className="text-amber-400">{log.parameter} ({log.location || "param"})</span> : "—"}
                            </td>
                            <td className="py-1 px-2.5 truncate max-w-sm text-slate-400" title={log.result || log.reason}>
                              {log.result || <span className="text-amber-400/90">{log.reason}</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </Card>

      {/* ========================================================================= */}
      {/* 5. VULNERABILITY FINDINGS DRILL-DOWN & TABLE SECTION                      */}
      {/* ========================================================================= */}
      <div ref={findingsSectionRef} className="space-y-4">
        {/* Filter Bar with Active Drill-down indicator */}
        <Card>
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-slate-100">Vulnerability Findings</span>
                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                  Showing {filteredFindings.length} of {findings.length}
                </span>
                {activeFilterLabel && (
                  <span className="text-xs px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/80 flex items-center gap-1 font-semibold">
                    <span>Filtered by: {activeFilterLabel}</span>
                    <button onClick={clearAllFilters} className="hover:text-emerald-200 ml-1">✕</button>
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={clearAllFilters}
                  className="text-xs text-slate-400 hover:text-slate-200 px-2.5 py-1 rounded bg-slate-800 border border-slate-700"
                >
                  Reset Filters
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-2">
              <select
                className={inputClass}
                value={flt.severity}
                onChange={(e) => {
                  setFlt({ ...flt, severity: e.target.value });
                  setActiveFilterLabel(e.target.value ? `Severity: ${e.target.value}` : null);
                  setPage(1);
                }}
              >
                <option value="">All Severities</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>

              <select
                className={inputClass}
                value={flt.detection_status}
                onChange={(e) => {
                  setFlt({ ...flt, detection_status: e.target.value });
                  setActiveFilterLabel(e.target.value ? `Status: ${e.target.value}` : null);
                  setPage(1);
                }}
              >
                <option value="">All Detection Statuses</option>
                <option value="Confirmed">Confirmed</option>
                <option value="Requires Manual Verification">Requires Manual Verification</option>
                <option value="Potential">Potential</option>
              </select>

              <select
                className={inputClass}
                value={flt.confidence}
                onChange={(e) => {
                  setFlt({ ...flt, confidence: e.target.value });
                  setPage(1);
                }}
              >
                <option value="">All Confidences</option>
                {["Confirmed", "High confidence", "Medium confidence", "Low confidence", "Informational"].map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>

              <select
                className={inputClass}
                value={flt.type}
                onChange={(e) => {
                  setFlt({ ...flt, type: e.target.value });
                  setPage(1);
                }}
              >
                <option value="">All Vulnerability Types</option>
                {types.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>

              <input
                type="text"
                placeholder="Search URL, CWE, param..."
                className={inputClass}
                value={flt.search}
                onChange={(e) => {
                  setFlt({ ...flt, search: e.target.value });
                  setPage(1);
                }}
              />
            </div>
          </div>
        </Card>

        {/* Detailed Findings Table with Expandable Accordion Rows */}
        <Card>
          {filteredFindings.length === 0 ? (
            <div className="text-center py-10 text-slate-400">
              <div className="text-3xl mb-2">🔍</div>
              <h3 className="text-sm font-semibold text-slate-300">No findings match the current filter criteria</h3>
              <p className="text-xs text-slate-500 mt-1 mb-3">Try adjusting your severity or search query.</p>
              <button
                onClick={clearAllFilters}
                className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 border border-slate-700"
              >
                Clear all filters
              </button>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-left text-slate-400 text-xs uppercase border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Vulnerability</th>
                      <th className="py-2.5 px-3">Severity</th>
                      <th className="py-2.5 px-3">Detection Status</th>
                      <th className="py-2.5 px-3">Confidence</th>
                      <th className="py-2.5 px-3">Affected URL</th>
                      <th className="py-2.5 px-3">Param</th>
                      <th className="py-2.5 px-3 text-center">Instances</th>
                      <th className="py-2.5 px-3 text-right">Details</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {paginatedFindings.map((f) => {
                      const isExpanded = expandedFindingId === f.id;
                      const occurrences = f.evidence_details?.occurrences || [];
                      const rawCount = f.raw_instances || occurrences.length || 1;

                      return (
                        <React.Fragment key={f.id}>
                          <tr className={`hover:bg-slate-800/40 transition-colors ${isExpanded ? "bg-slate-800/20" : ""}`}>
                            <td className="py-2.5 px-3">
                              <div className="flex flex-col">
                                <span className="font-semibold text-slate-200">{f.type}</span>
                                <div className="flex items-center gap-1.5 mt-0.5">
                                  {f.cwe_id && (
                                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800/60">
                                      {f.cwe_id}
                                    </span>
                                  )}
                                  {f.mitre_attack && (
                                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-rose-950/60 text-rose-300 border border-rose-800/60">
                                      {f.mitre_attack}
                                    </span>
                                  )}
                                </div>
                              </div>
                            </td>
                            <td className="py-2.5 px-3">
                              <SeverityBadge severity={f.severity} />
                            </td>
                            <td className="py-2.5 px-3">
                              <span
                                className={`text-[11px] px-2 py-0.5 rounded font-semibold border ${
                                  (f.detection_status || "Confirmed") === "Confirmed"
                                    ? "bg-emerald-950/60 text-emerald-400 border-emerald-800/80"
                                    : (f.detection_status || "Confirmed") === "Requires Manual Verification"
                                    ? "bg-amber-950/60 text-amber-400 border-amber-800/80"
                                    : "bg-blue-950/60 text-blue-400 border-blue-800/80"
                                }`}
                              >
                                {f.detection_status || "Confirmed"}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 text-xs text-slate-300">{f.confidence}</td>
                            <td className="py-2.5 px-3 font-mono text-xs text-slate-300 truncate max-w-xs" title={f.url}>
                              {f.url}
                            </td>
                            <td className="py-2.5 px-3 font-mono text-xs text-slate-400">
                              {f.parameter || "—"}
                            </td>
                            <td className="py-2.5 px-3 text-center">
                              <span
                                className={`text-xs px-2 py-0.5 rounded font-mono ${
                                  rawCount > 1
                                    ? "bg-amber-950/40 text-amber-300 border border-amber-800/60 font-bold"
                                    : "bg-slate-800 text-slate-400"
                                }`}
                                title={`${rawCount} total occurrence(s) across pages`}
                              >
                                {rawCount}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 text-right">
                              <button
                                type="button"
                                onClick={() => setExpandedFindingId(isExpanded ? null : f.id)}
                                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors inline-flex items-center gap-1"
                              >
                                <span>{isExpanded ? "Hide" : "Details"}</span>
                                <span>{isExpanded ? "▲" : "▼"}</span>
                              </button>
                            </td>
                          </tr>

                          {/* Expandable Technical Details Drawer */}
                          {isExpanded && (
                            <tr>
                              <td colSpan={8} className="p-4 bg-slate-950/80 border-b border-slate-800">
                                <div className="space-y-3 max-w-5xl mx-auto text-xs">
                                  <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-800/80">
                                    <div className="flex items-center gap-2">
                                      <span className="font-bold text-slate-200 text-sm">{f.type}</span>
                                      <LifecycleBadge status={f.status} />
                                      {f.fingerprint && (
                                        <span className="font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 text-[11px]">
                                          Fingerprint: {f.fingerprint}
                                        </span>
                                      )}
                                    </div>
                                    <Link
                                      to={`/scan/${id}/finding/${f.id}`}
                                      className="text-emerald-400 hover:text-emerald-300 font-semibold inline-flex items-center gap-1"
                                    >
                                      Manage Lifecycle Status &rarr;
                                    </Link>
                                  </div>

                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <div>
                                      <span className="font-semibold text-slate-400 uppercase text-[10px] block mb-1">
                                        Evidence & Detection Explanation
                                      </span>
                                      <div className="p-2.5 rounded bg-slate-900 border border-slate-800 font-mono text-amber-300/90 whitespace-pre-wrap">
                                        {f.evidence || "No evidence recorded."}
                                      </div>
                                    </div>
                                    <div>
                                      <span className="font-semibold text-slate-400 uppercase text-[10px] block mb-1">
                                        Recommended Remediation
                                      </span>
                                      <div className="p-2.5 rounded bg-emerald-950/30 border border-emerald-900/40 text-emerald-300/90 leading-relaxed">
                                        {f.remediation}
                                      </div>
                                    </div>
                                  </div>

                                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-slate-300 pt-1">
                                    <div>
                                      <b className="text-slate-400">OWASP:</b> {f.owasp_category || "—"}
                                    </div>
                                    <div>
                                      <b className="text-slate-400">Method:</b> {f.method} {f.parameter ? `(${f.parameter})` : ""}
                                    </div>
                                    <div>
                                      <b className="text-slate-400">First Detected:</b> {fmtDate(f.timestamp)}
                                    </div>
                                  </div>

                                  {/* Raw Occurrences Sub-table */}
                                  {occurrences.length > 1 && (
                                    <div className="pt-2 border-t border-slate-800/80">
                                      <span className="font-semibold text-slate-300 text-xs block mb-1.5">
                                        Raw Instances Grouped Under This Vulnerability ({occurrences.length}):
                                      </span>
                                      <div className="max-h-36 overflow-y-auto border border-slate-800 rounded bg-slate-900/60">
                                        <table className="w-full text-[11px] font-mono">
                                          <thead className="bg-slate-950 text-slate-400 text-left border-b border-slate-800">
                                            <tr>
                                              <th className="py-1 px-2">URL</th>
                                              <th className="py-1 px-2">Method</th>
                                              <th className="py-1 px-2">Param</th>
                                            </tr>
                                          </thead>
                                          <tbody className="divide-y divide-slate-800">
                                            {occurrences.map((occ, oIdx) => (
                                              <tr key={oIdx} className="hover:bg-slate-800/40">
                                                <td className="py-1 px-2 truncate max-w-md text-slate-300">{occ.url}</td>
                                                <td className="py-1 px-2 text-slate-400">{occ.method || "GET"}</td>
                                                <td className="py-1 px-2 text-slate-400">{occ.parameter || "—"}</td>
                                              </tr>
                                            ))}
                                          </tbody>
                                        </table>
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {totalPages > 1 && (
                <div className="mt-4">
                  <Pagination
                    currentPage={page}
                    totalPages={totalPages}
                    onPageChange={setPage}
                  />
                </div>
              )}
            </>
          )}
        </Card>
      </div>
    </div>
  );
}
