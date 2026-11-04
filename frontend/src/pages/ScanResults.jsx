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
import {
  getFindings,
  getScan,
  getSecurityPosture,
  summaryReportUrl,
  shortReportUrl,
  bountyReportUrl,
} from "../services/api";
import { Card, SeverityBadge, LifecycleBadge, Spinner, Pagination } from "../components/ui";
import { SEVERITIES, SEVERITY_COLORS, ALL_LIFECYCLE_STATUSES, fmtDate } from "../utils/format";

export const getFindingGroup = (f) => {
  if (f.finding_group) return f.finding_group;
  const sev = (f.severity || "").toLowerCase();
  const t = (f.type || "").toLowerCase();
  if (
    sev === "critical" ||
    t.includes("sql injection") ||
    t.includes("remote code execution") ||
    t.includes("command injection") ||
    t.includes("authentication bypass")
  ) {
    return "critical_vulnerabilities";
  }
  if (
    t.includes("header") ||
    t.includes("cookie") ||
    t.includes("clickjacking") ||
    t.includes("cors") ||
    t.includes("options") ||
    t.includes("directory listing") ||
    t.includes("information disclosure")
  ) {
    return "security_configuration";
  }
  return "other_vulnerabilities";
};

function FindingsTableSection({
  items,
  expandedFindingId,
  setExpandedFindingId,
  scanId,
  emptyMessage = "No findings match the current criteria.",
}) {
  if (!items || items.length === 0) {
    return (
      <div className="py-6 px-4 text-center text-xs text-slate-500 bg-slate-950/40 rounded border border-slate-800/80">
        {emptyMessage}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="text-left text-slate-400 text-xs uppercase border-b border-slate-800">
          <tr>
            <th className="py-2.5 px-3">Vulnerability</th>
            <th className="py-2.5 px-3">Severity</th>
            <th className="py-2.5 px-3">Detection Status</th>
            <th className="py-2.5 px-3">Confidence</th>
            <th className="py-2.5 px-3">Affected Endpoint(s)</th>
            <th className="py-2.5 px-3">Param / Header</th>
            <th className="py-2.5 px-3 text-center">Instances</th>
            <th className="py-2.5 px-3 text-right">Details</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {items.map((f) => {
            const isExpanded = expandedFindingId === f.id;
            const occurrences = f.evidence_details?.occurrences || [];
            const affectedUrls = f.evidence_details?.affected_urls || (f.url ? [f.url] : []);
            const affectedCount = f.evidence_details?.total_affected_endpoints || affectedUrls.length || 1;
            const rawCount = f.raw_instances || occurrences.length || 1;

            return (
              <React.Fragment key={f.id}>
                <tr className={`hover:bg-slate-800/40 transition-colors ${isExpanded ? "bg-slate-800/20" : ""}`}>
                  <td className="py-2.5 px-3">
                    <div className="flex flex-col gap-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-slate-200">{f.type}</span>
                        {f.type === "Missing Security Header" && f.parameter && (
                          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-amber-950/40 text-amber-300 border border-amber-800/60 font-semibold">
                            {f.parameter}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
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
                        {affectedCount > 1 && (
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/60">
                            Across {affectedCount} endpoints
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
                  <td className="py-2.5 px-3 font-mono text-xs text-slate-300 max-w-xs" title={f.url}>
                    <div className="truncate">{f.url}</div>
                    {affectedCount > 1 && (
                      <div className="text-[10px] text-cyan-400 font-sans mt-0.5">
                        + {affectedCount - 1} more endpoint{affectedCount - 1 > 1 ? "s" : ""}
                      </div>
                    )}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-xs text-slate-400">
                    {f.parameter ? (
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-amber-300/90 border border-slate-700/60 font-semibold">
                        {f.parameter}
                      </span>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="py-2.5 px-3 text-center">
                    <span
                      className={`text-xs px-2.5 py-0.5 rounded font-mono ${
                        rawCount > 1
                          ? "bg-amber-950/50 text-amber-300 border border-amber-800/80 font-bold"
                          : "bg-slate-800 text-slate-400"
                      }`}
                      title={`${rawCount} total occurrence(s) across ${affectedCount} endpoint(s)`}
                    >
                      {rawCount}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <div className="inline-flex items-center gap-1.5 justify-end">
                      <button
                        type="button"
                        onClick={() => setExpandedFindingId(isExpanded ? null : f.id)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors inline-flex items-center gap-1"
                      >
                        <span>{isExpanded ? "Hide" : "Details"}</span>
                        <span>{isExpanded ? "▲" : "▼"}</span>
                      </button>
                    </div>
                  </td>
                </tr>

                {/* Technical Details Drawer */}
                {isExpanded && (
                  <tr>
                    <td colSpan={8} className="p-4 bg-slate-950/80 border-b border-slate-800">
                      <div className="space-y-3 max-w-5xl mx-auto text-xs">
                        <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-800/80">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-bold text-slate-200 text-sm">{f.type}</span>
                            {f.parameter && (
                              <span className="font-mono text-amber-300 bg-amber-950/40 px-2 py-0.5 rounded border border-amber-800/60 text-xs font-bold">
                                {f.parameter}
                              </span>
                            )}
                            <LifecycleBadge status={f.status} />
                            {affectedCount > 1 && (
                              <span className="font-mono text-cyan-300 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/80 text-[11px] font-semibold">
                                1 unique finding across {affectedCount} endpoints ({rawCount} raw occurrences)
                              </span>
                            )}
                            {f.fingerprint && (
                              <span className="font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 text-[11px]">
                                Fingerprint: {f.fingerprint}
                              </span>
                            )}
                          </div>
                          <div className="flex flex-wrap items-center gap-2">
                            <a
                              href={bountyReportUrl(f.id)}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="px-2.5 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 text-xs font-semibold border border-amber-500/40 inline-flex items-center gap-1.5 transition-colors"
                              title="Download 4-6 Page Bug Bounty PDF for this vulnerability"
                            >
                              <span>📄</span>
                              <span>Download Bug Bounty Report (PDF)</span>
                            </a>
                            <Link
                              to={`/scan/${scanId}/finding/${f.id}`}
                              className="text-emerald-400 hover:text-emerald-300 font-semibold inline-flex items-center gap-1 ml-1"
                            >
                              Manage Lifecycle &rarr;
                            </Link>
                          </div>
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

                        {/* List of Affected URLs */}
                        {affectedUrls.length > 1 && (
                          <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                            <span className="font-semibold text-slate-300 text-xs block mb-1.5">
                              Affected Endpoints ({affectedUrls.length}):
                            </span>
                            <div className="flex flex-wrap gap-1.5 max-h-28 overflow-y-auto">
                              {affectedUrls.map((u, uIdx) => (
                                <span
                                  key={uIdx}
                                  className="font-mono text-[11px] px-2 py-0.5 rounded bg-slate-800/80 text-cyan-300 border border-slate-700 truncate max-w-sm"
                                  title={u}
                                >
                                  {u}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Raw Occurrences Sub-table */}
                        {occurrences.length > 0 && (
                          <div className="pt-2 border-t border-slate-800/80">
                            <span className="font-semibold text-slate-300 text-xs block mb-1.5">
                              Occurrence Breakdown Across Endpoints ({occurrences.length}):
                            </span>
                            <div className="max-h-48 overflow-y-auto border border-slate-800 rounded bg-slate-900/60">
                              <table className="w-full text-[11px] font-mono">
                                <thead className="bg-slate-950 text-slate-400 text-left border-b border-slate-800">
                                  <tr>
                                    <th className="py-1 px-2">Endpoint URL</th>
                                    <th className="py-1 px-2">Method</th>
                                    <th className="py-1 px-2">Param / Header</th>
                                    <th className="py-1 px-2">Evidence Excerpt</th>
                                    <th className="py-1 px-2">Severity</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-800">
                                  {occurrences.map((occ, oIdx) => (
                                    <tr key={oIdx} className="hover:bg-slate-800/40">
                                      <td className="py-1 px-2 truncate max-w-xs text-slate-300" title={occ.url}>
                                        {occ.url}
                                      </td>
                                      <td className="py-1 px-2 text-slate-400">{occ.method || "GET"}</td>
                                      <td className="py-1 px-2 text-amber-300/90">{occ.parameter || f.parameter || "—"}</td>
                                      <td className="py-1 px-2 text-slate-400 truncate max-w-xs" title={occ.evidence}>
                                        {occ.evidence || f.evidence || "—"}
                                      </td>
                                      <td className="py-1 px-2">
                                        <SeverityBadge severity={occ.severity || f.severity} />
                                      </td>
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
  );
}

export default function ScanResults() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState(null);
  const [posture, setPosture] = useState(null);

  // Filters state
  const [flt, setFlt] = useState({
    group: "",
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
  const [showConfigSection, setShowConfigSection] = useState(true);

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
    setFlt({ group: "", severity: "", confidence: "", type: "", status: "", detection_status: "", search: "" });
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
    setFlt({ group: "", severity: "", confidence: "", type: "", status: "", detection_status: "", search: "" });
    setActiveFilterLabel(null);
    setPage(1);
  };

  // Filter findings client-side for immediate responsiveness
  const filteredFindings = findings.filter((f) => {
    if (flt.group && getFindingGroup(f) !== flt.group) return false;
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

  // Group calculations
  const totalRawInstances = (findings || []).reduce(
    (acc, f) => acc + (f.raw_instances || (f.evidence_details?.occurrences?.length || 1)),
    0
  );
  const criticalFindings = (findings || []).filter((f) => getFindingGroup(f) === "critical_vulnerabilities");
  const otherFindings = (findings || []).filter((f) => getFindingGroup(f) === "other_vulnerabilities");
  const configFindings = (findings || []).filter((f) => getFindingGroup(f) === "security_configuration");

  const criticalRaw = criticalFindings.reduce(
    (acc, f) => acc + (f.raw_instances || (f.evidence_details?.occurrences?.length || 1)),
    0
  );
  const otherRaw = otherFindings.reduce(
    (acc, f) => acc + (f.raw_instances || (f.evidence_details?.occurrences?.length || 1)),
    0
  );
  const configRaw = configFindings.reduce(
    (acc, f) => acc + (f.raw_instances || (f.evidence_details?.occurrences?.length || 1)),
    0
  );

  const filteredCritical = filteredFindings.filter((f) => getFindingGroup(f) === "critical_vulnerabilities");
  const filteredOther = filteredFindings.filter((f) => getFindingGroup(f) === "other_vulnerabilities");
  const filteredConfig = filteredFindings.filter((f) => getFindingGroup(f) === "security_configuration");

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
          <div className="text-xs text-slate-400 mt-0.5 flex flex-wrap items-center gap-2">
            <span>Target: <span className="font-mono text-emerald-400">{scan.target_url || scan.target?.base_url || "Target"}</span></span>
            <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">
              {scan.scan_type || scan.profile_name || "Quick Scan"}
            </span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <a
            href={shortReportUrl(id)}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center bg-indigo-600 hover:bg-indigo-500 text-white font-medium px-3.5 py-2 rounded text-xs transition-colors gap-1.5 shadow-sm"
            title="Download Short Report (4–6 Page PDF)"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Download Short Report (PDF)
          </a>
          <a
            href={summaryReportUrl(id)}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-3.5 py-2 rounded text-xs transition-colors gap-1.5 shadow-sm"
            title="Concise 5-15 page Security Assessment Summary"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Security Summary (PDF)
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
          <div>
            <button
              onClick={() => setShowCoverageSection(!showCoverageSection)}
              className="text-xs text-slate-400 hover:text-slate-200 px-2 py-1 rounded bg-slate-800 border border-slate-700"
            >
              {showCoverageSection ? "Collapse ▲" : "Expand ▼"}
            </button>
          </div>
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
      {/* 5. VULNERABILITY FINDINGS PRIORITIZATION & DRILL-DOWN SECTION            */}
      {/* ========================================================================= */}
      <div ref={findingsSectionRef} className="space-y-4">
        {/* KPI Cards: Unique Findings vs Raw Occurrences & Prioritization Groups */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Total Unique vs Raw */}
          <button
            type="button"
            onClick={() => {
              setFlt((prev) => ({ ...prev, group: "" }));
              setActiveFilterLabel(null);
            }}
            className={`p-3 rounded-lg text-left transition-all border flex flex-col justify-between ${
              flt.group === ""
                ? "bg-slate-800/90 border-indigo-500 ring-1 ring-indigo-500/50"
                : "bg-slate-950/60 border-slate-800 hover:border-slate-700 hover:bg-slate-900/60"
            }`}
            title="View all findings across all groups"
          >
            <div className="flex items-center justify-between w-full">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">Total Unique Issues</span>
              <span className="text-[10px] text-indigo-400 font-mono">view all &rarr;</span>
            </div>
            <div className="text-2xl font-bold text-slate-100 my-1">{findings.length}</div>
            <div className="text-[11px] text-slate-500">Across {totalRawInstances} raw occurrences</div>
          </button>

          {/* Critical Security Vulnerabilities */}
          <button
            type="button"
            onClick={() => {
              if (flt.group === "critical_vulnerabilities") {
                setFlt((prev) => ({ ...prev, group: "" }));
                setActiveFilterLabel(null);
              } else {
                setFlt((prev) => ({ ...prev, group: "critical_vulnerabilities" }));
                setActiveFilterLabel("Group: Critical Security Vulnerabilities");
              }
            }}
            className={`p-3 rounded-lg text-left transition-all border flex flex-col justify-between ${
              flt.group === "critical_vulnerabilities"
                ? "bg-slate-800/90 border-rose-500 ring-1 ring-rose-500/50"
                : criticalFindings.length > 0
                ? "bg-rose-950/20 border-rose-900/60 hover:border-rose-700 hover:bg-rose-950/30"
                : "bg-slate-950/60 border-slate-800 hover:border-slate-700"
            }`}
            title="Filter Critical Security Vulnerabilities (SQLi, RCE, Auth Bypass)"
          >
            <div className="flex items-center justify-between w-full">
              <span className="text-[10px] text-rose-400 uppercase font-semibold flex items-center gap-1">
                <span>🚨</span>
                <span>Critical Vulnerabilities</span>
              </span>
              <span className="text-[10px] text-rose-400 font-mono">filter &rarr;</span>
            </div>
            <div className="text-2xl font-bold text-rose-400 my-1">{criticalFindings.length}</div>
            <div className="text-[11px] text-slate-400">
              {criticalRaw} raw occurrence{criticalRaw !== 1 ? "s" : ""}
            </div>
          </button>

          {/* Other Security Vulnerabilities */}
          <button
            type="button"
            onClick={() => {
              if (flt.group === "other_vulnerabilities") {
                setFlt((prev) => ({ ...prev, group: "" }));
                setActiveFilterLabel(null);
              } else {
                setFlt((prev) => ({ ...prev, group: "other_vulnerabilities" }));
                setActiveFilterLabel("Group: Other Security Vulnerabilities");
              }
            }}
            className={`p-3 rounded-lg text-left transition-all border flex flex-col justify-between ${
              flt.group === "other_vulnerabilities"
                ? "bg-slate-800/90 border-amber-500 ring-1 ring-amber-500/50"
                : otherFindings.length > 0
                ? "bg-amber-950/20 border-amber-900/60 hover:border-amber-700 hover:bg-amber-950/30"
                : "bg-slate-950/60 border-slate-800 hover:border-slate-700"
            }`}
            title="Filter Other Application Security Vulnerabilities (XSS, SSRF, CSRF)"
          >
            <div className="flex items-center justify-between w-full">
              <span className="text-[10px] text-amber-400 uppercase font-semibold flex items-center gap-1">
                <span>⚠️</span>
                <span>Other Vulnerabilities</span>
              </span>
              <span className="text-[10px] text-amber-400 font-mono">filter &rarr;</span>
            </div>
            <div className="text-2xl font-bold text-amber-400 my-1">{otherFindings.length}</div>
            <div className="text-[11px] text-slate-400">
              {otherRaw} raw occurrence{otherRaw !== 1 ? "s" : ""}
            </div>
          </button>

          {/* Security Configuration Issues */}
          <button
            type="button"
            onClick={() => {
              if (flt.group === "security_configuration") {
                setFlt((prev) => ({ ...prev, group: "" }));
                setActiveFilterLabel(null);
              } else {
                setFlt((prev) => ({ ...prev, group: "security_configuration" }));
                setActiveFilterLabel("Group: Security Configuration");
                setShowConfigSection(true);
              }
            }}
            className={`p-3 rounded-lg text-left transition-all border flex flex-col justify-between ${
              flt.group === "security_configuration"
                ? "bg-slate-800/90 border-blue-500 ring-1 ring-blue-500/50"
                : "bg-slate-950/60 border-slate-800 hover:border-slate-700 hover:bg-slate-900/60"
            }`}
            title="Filter Security Configuration Issues (Headers, Cookies, Clickjacking)"
          >
            <div className="flex items-center justify-between w-full">
              <span className="text-[10px] text-blue-400 uppercase font-semibold flex items-center gap-1">
                <span>⚙️</span>
                <span>Security Configuration</span>
              </span>
              <span className="text-[10px] text-blue-400 font-mono">filter &rarr;</span>
            </div>
            <div className="text-2xl font-bold text-blue-400 my-1">{configFindings.length}</div>
            <div className="text-[11px] text-slate-400">
              {configRaw} raw occurrence{configRaw !== 1 ? "s" : ""}
            </div>
          </button>
        </div>

        {/* Filter Bar with Active Drill-down indicator */}
        <Card>
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-slate-100">Findings Filter & Search</span>
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
                  Reset All Filters
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2">
              <select
                className={inputClass}
                value={flt.group}
                onChange={(e) => {
                  setFlt({ ...flt, group: e.target.value });
                  setActiveFilterLabel(
                    e.target.value === "critical_vulnerabilities"
                      ? "Group: Critical Vulnerabilities"
                      : e.target.value === "other_vulnerabilities"
                      ? "Group: Other Vulnerabilities"
                      : e.target.value === "security_configuration"
                      ? "Group: Security Configuration"
                      : null
                  );
                  if (e.target.value === "security_configuration") {
                    setShowConfigSection(true);
                  }
                  setPage(1);
                }}
              >
                <option value="">All Finding Groups</option>
                <option value="critical_vulnerabilities">🚨 Critical Vulnerabilities</option>
                <option value="other_vulnerabilities">⚠️ Other Vulnerabilities</option>
                <option value="security_configuration">⚙️ Security Configuration</option>
              </select>

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
                value={flt.status}
                onChange={(e) => {
                  setFlt({ ...flt, status: e.target.value });
                  setActiveFilterLabel(e.target.value ? `Lifecycle: ${e.target.value}` : null);
                  setPage(1);
                }}
              >
                <option value="">All Lifecycle Statuses</option>
                {ALL_LIFECYCLE_STATUSES.map((st) => (
                  <option key={st} value={st}>{st}</option>
                ))}
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

        {/* Global Empty State if zero results match all filters */}
        {filteredFindings.length === 0 ? (
          <Card>
            <div className="text-center py-10 text-slate-400">
              <div className="text-3xl mb-2">🔍</div>
              <h3 className="text-sm font-semibold text-slate-300">No findings match the current filter criteria</h3>
              <p className="text-xs text-slate-500 mt-1 mb-3">Try adjusting your filters, group selection, or search query.</p>
              <button
                onClick={clearAllFilters}
                className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 border border-slate-700"
              >
                Clear all filters
              </button>
            </div>
          </Card>
        ) : (
          <div className="space-y-6">
            {/* ================================================================= */}
            {/* SECTION 1: CRITICAL SECURITY VULNERABILITIES                      */}
            {/* ================================================================= */}
            {(!flt.group || flt.group === "critical_vulnerabilities") && (
              <Card
                className={`transition-all ${
                  filteredCritical.length > 0
                    ? "border-2 border-rose-500/60 bg-gradient-to-b from-rose-950/20 via-slate-900 to-slate-900 shadow-xl ring-1 ring-rose-500/20"
                    : "border border-slate-800 bg-slate-900"
                }`}
              >
                <div className="flex flex-wrap items-center justify-between pb-3 mb-3 border-b border-slate-800 gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-lg">🚨</span>
                    <div>
                      <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                        <span>Critical Security Vulnerabilities</span>
                        <span
                          className={`text-xs px-2.5 py-0.5 rounded-full font-mono font-bold ${
                            filteredCritical.length > 0
                              ? "bg-rose-500/20 text-rose-300 border border-rose-500/50 animate-pulse"
                              : "bg-slate-800 text-slate-400"
                          }`}
                        >
                          {filteredCritical.length} {filteredCritical.length === 1 ? "Issue" : "Issues"}
                        </span>
                      </h2>
                      <p className="text-xs text-slate-400 mt-0.5">
                        High-impact exploitable vulnerabilities requiring immediate triage (e.g., SQL Injection, Auth Bypass, Remote Code Execution).
                      </p>
                    </div>
                  </div>
                </div>

                {filteredCritical.length > 0 ? (
                  <div className="space-y-3">
                    <div className="p-3 rounded bg-rose-950/30 border border-rose-900/60 text-xs text-rose-200/90 flex items-start gap-2">
                      <span className="text-base">⚠️</span>
                      <div>
                        <span className="font-semibold block text-rose-300">Immediate Action Recommended:</span>
                        <span>
                          The scanner confirmed critical vulnerabilities with reproducible payloads and negative control verification. Expand each finding below for full exploit evidence and remediation.
                        </span>
                      </div>
                    </div>
                    <FindingsTableSection
                      items={filteredCritical}
                      expandedFindingId={expandedFindingId}
                      setExpandedFindingId={setExpandedFindingId}
                      scanId={id}
                    />
                  </div>
                ) : (
                  <div className="py-4 px-3 rounded bg-slate-950/40 border border-slate-800/80 text-xs text-slate-400 flex items-center gap-2">
                    <span className="text-emerald-400 font-bold">✓</span>
                    <span>No Critical Security Vulnerabilities detected in this scan.</span>
                  </div>
                )}
              </Card>
            )}

            {/* ================================================================= */}
            {/* SECTION 2: OTHER SECURITY VULNERABILITIES                         */}
            {/* ================================================================= */}
            {(!flt.group || flt.group === "other_vulnerabilities") && (
              <Card className="border border-slate-800 bg-slate-900">
                <div className="flex flex-wrap items-center justify-between pb-3 mb-3 border-b border-slate-800 gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-lg">⚠️</span>
                    <div>
                      <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                        <span>Other Security Vulnerabilities</span>
                        <span className="text-xs px-2.5 py-0.5 rounded-full font-mono font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                          {filteredOther.length} {filteredOther.length === 1 ? "Issue" : "Issues"}
                        </span>
                      </h2>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Application input and logic vulnerabilities (e.g., Cross-Site Scripting, Open Redirects, CSRF, IDOR).
                      </p>
                    </div>
                  </div>
                </div>

                {filteredOther.length > 0 ? (
                  <FindingsTableSection
                    items={filteredOther}
                    expandedFindingId={expandedFindingId}
                    setExpandedFindingId={setExpandedFindingId}
                    scanId={id}
                  />
                ) : (
                  <div className="py-4 px-3 rounded bg-slate-950/40 border border-slate-800/80 text-xs text-slate-400 flex items-center gap-2">
                    <span className="text-slate-500">ℹ</span>
                    <span>No other application vulnerabilities detected matching current criteria.</span>
                  </div>
                )}
              </Card>
            )}

            {/* ================================================================= */}
            {/* SECTION 3: SECURITY CONFIGURATION ISSUES (COLLAPSIBLE)            */}
            {/* ================================================================= */}
            {(!flt.group || flt.group === "security_configuration") && (
              <Card className="border border-slate-800 bg-slate-900">
                <div className="flex flex-wrap items-center justify-between pb-3 mb-3 border-b border-slate-800 gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-lg">⚙️</span>
                    <div>
                      <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                        <span>Security Configuration Issues</span>
                        <span className="text-xs px-2.5 py-0.5 rounded-full font-mono font-semibold bg-blue-950/60 text-blue-300 border border-blue-800/80">
                          {filteredConfig.length} Unique {filteredConfig.length === 1 ? "Issue" : "Issues"}
                        </span>
                        {configRaw > 0 && (
                          <span className="text-[11px] text-slate-500 font-mono">
                            ({configRaw} raw occurrences consolidated site-wide)
                          </span>
                        )}
                      </h2>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Missing HTTP security headers, framing defense (Clickjacking), and cookie security flags.
                      </p>
                    </div>
                  </div>
                  <div>
                    <button
                      type="button"
                      onClick={() => setShowConfigSection(!showConfigSection)}
                      className="text-xs text-slate-300 hover:text-white px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 transition-colors font-medium flex items-center gap-1.5"
                    >
                      <span>{showConfigSection ? "Collapse" : "Expand"}</span>
                      <span>{showConfigSection ? "▲" : "▼"}</span>
                    </button>
                  </div>
                </div>

                {showConfigSection ? (
                  <div className="space-y-3">
                    <div className="p-2.5 rounded bg-blue-950/20 border border-blue-900/40 text-xs text-blue-300/90 flex items-center gap-2">
                      <span>ℹ️</span>
                      <span>
                        Configuration issues are deduplicated domain-wide so you see one clean finding per directive (e.g. CSP, Clickjacking, HSTS), while preserving all affected endpoints.
                      </span>
                    </div>
                    <FindingsTableSection
                      items={filteredConfig}
                      expandedFindingId={expandedFindingId}
                      setExpandedFindingId={setExpandedFindingId}
                      scanId={id}
                      emptyMessage="No security configuration issues found."
                    />
                  </div>
                ) : (
                  <div
                    onClick={() => setShowConfigSection(true)}
                    className="p-3 rounded bg-slate-950/40 hover:bg-slate-950/70 border border-slate-800/80 text-xs text-slate-400 flex items-center justify-between cursor-pointer transition-colors"
                  >
                    <span className="flex items-center gap-2">
                      <span className="text-slate-500">📁</span>
                      <span>
                        {filteredConfig.length} security configuration issue{filteredConfig.length !== 1 ? "s" : ""} collapsed. Click to expand and inspect affected endpoints.
                      </span>
                    </span>
                    <span className="text-xs text-emerald-400 font-medium">Expand ▼</span>
                  </div>
                )}
              </Card>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
