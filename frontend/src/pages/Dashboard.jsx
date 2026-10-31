import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
} from "recharts";
import {
  getExecutiveOverview,
  listApplications,
  updateApplication,
  rescanApplication,
} from "../services/api";
import { Card, Stat, Spinner, EmptyState, Pagination } from "../components/ui";
import { SEVERITIES, SEVERITY_COLORS, RATING_COLORS } from "../utils/format";
import WebsiteCard from "../components/dashboard/WebsiteCard";
import WebsiteTrendsModal from "../components/dashboard/WebsiteTrendsModal";
import RemediationTracker from "../components/dashboard/RemediationTracker";
import ActivityTimeline from "../components/dashboard/ActivityTimeline";

export default function Dashboard() {
  const navigate = useNavigate();
  const [executive, setExecutive] = useState(null);
  const [applications, setApplications] = useState([]);
  const [loading, setLoading] = useState(true);

  // Search & Filter state for My Scanned Websites
  const [search, setSearch] = useState("");
  const [ratingFilter, setRatingFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [websitePage, setWebsitePage] = useState(1);

  // Active sub-view tab: "websites" | "remediation" | "timeline"
  const [activeTab, setActiveTab] = useState("websites");

  // Trends modal target
  const [selectedAppForTrends, setSelectedAppForTrends] = useState(null);

  const loadData = () => {
    setLoading(true);
    Promise.all([
      getExecutiveOverview().catch((err) => {
        console.error("Executive overview error:", err);
        return null;
      }),
      listApplications().catch((err) => {
        console.error("List applications error:", err);
        return [];
      }),
    ])
      .then(([execData, appsData]) => {
        setExecutive(execData);
        setApplications(appsData || []);
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRename = async (appId, newName) => {
    try {
      const updated = await updateApplication(appId, { name: newName });
      setApplications((prev) =>
        prev.map((a) => (a.id === appId ? { ...a, name: updated.name } : a))
      );
    } catch (err) {
      console.error("Failed to rename application:", err);
    }
  };

  const handleRescan = async (appId) => {
    try {
      const newScan = await rescanApplication(appId);
      navigate(`/scan/${newScan.id}/progress`);
    } catch (err) {
      console.error("Failed to trigger rescan:", err);
      alert(err.response?.data?.detail || "Failed to trigger rescan");
    }
  };

  if (loading && !executive && applications.length === 0) {
    return <Spinner message="Loading Website Security Management Dashboard…" />;
  }

  // Filtered websites
  const filteredWebsites = applications.filter((app) => {
    if (search) {
      const s = search.toLowerCase();
      const matchName = app.name && app.name.toLowerCase().includes(s);
      const matchUrl = app.target_url && app.target_url.toLowerCase().includes(s);
      const matchHost = app.hostname && app.hostname.toLowerCase().includes(s);
      if (!matchName && !matchUrl && !matchHost) return false;
    }
    if (ratingFilter && app.latest_rating !== ratingFilter) {
      return false;
    }
    if (statusFilter && app.latest_scan_status !== statusFilter) {
      return false;
    }
    return true;
  });

  const websitePageSize = 6;
  const totalWebsitePages = Math.ceil(filteredWebsites.length / websitePageSize) || 1;
  const paginatedWebsites = filteredWebsites.slice(
    (websitePage - 1) * websitePageSize,
    websitePage * websitePageSize
  );

  // Severity Chart Data
  const sevCounts = executive?.by_severity || {};
  const sevData = SEVERITIES.map((s) => ({
    name: s,
    value: sevCounts[s] || 0,
  }));

  // Vulnerability Type Chart Data
  const typeCounts = executive?.by_type || {};
  const typeData = Object.entries(typeCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, value]) => ({ name, value }));

  const cov = executive?.coverage_overview || {};
  const avgScore = executive?.average_security_score ?? 100;
  const avgScoreColor =
    avgScore >= 85 ? "#10b981" : avgScore >= 60 ? "#f59e0b" : "#ef4444";

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-4 pb-2 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-2xl">🛡</span>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100">
              ZeroTrace Security Management
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Discover. Analyze. Secure. &bull; Professional Website Security Management & Remediation Platform
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={loadData}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition-colors"
          >
            <span>🔄</span>
            <span>Refresh</span>
          </button>
          <Link
            to="/scan/new"
            className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-lg shadow-emerald-950 flex items-center gap-1.5 transition-colors"
          >
            <span>+</span>
            <span>New Security Scan</span>
          </Link>
        </div>
      </div>

      {/* 5. Executive Security Overview KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <Stat
          label="Monitored Websites"
          value={executive?.total_monitored_websites ?? applications.length}
          icon="🌐"
        />
        <Stat
          label="Total Scans"
          value={executive?.total_scans ?? 0}
          icon="🔍"
        />
        <Stat
          label="Average Score"
          value={avgScore}
          color={avgScoreColor}
          sublabel={
            avgScore >= 85
              ? "STRONG overall"
              : avgScore >= 60
              ? "MEDIUM overall"
              : "WEAK posture"
          }
          icon="📊"
        />
        <Stat
          label="High-Risk Sites"
          value={executive?.websites_with_high_risk ?? 0}
          color={
            (executive?.websites_with_high_risk ?? 0) > 0 ? "#ef4444" : "#10b981"
          }
          sublabel="Sites with Open Crit/High"
          icon="⚠️"
        />
        <Stat
          label="Open High / Critical"
          value={executive?.open_high_critical_count ?? 0}
          color={
            (executive?.open_high_critical_count ?? 0) > 0 ? "#f97316" : "#10b981"
          }
          sublabel="Unresolved vulnerabilities"
          icon="🚨"
        />
        <Stat
          label="Recent Scans (7d)"
          value={executive?.recently_completed_scans ?? 0}
          icon="📅"
        />
      </div>

      {/* Overview Analytics Grid: Severity Distribution, Vulnerability Types & Scan Coverage */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Severity Distribution */}
        <Card title="Active Findings by Severity">
          <div className="h-48 w-full flex items-center">
            {sevData.some((d) => d.value > 0) ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={sevData}
                    dataKey="value"
                    nameKey="name"
                    outerRadius={65}
                    innerRadius={30}
                    paddingAngle={3}
                  >
                    {sevData.map((d) => (
                      <Cell key={d.name} fill={SEVERITY_COLORS[d.name] || "#64748b"} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      borderColor: "#334155",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-center text-slate-500 text-xs w-full py-8">
                No active vulnerabilities found.
              </div>
            )}
          </div>
          <div className="flex flex-wrap justify-center gap-2 mt-2 pt-2 border-t border-slate-800 text-[11px]">
            {sevData.map((d) => (
              <span key={d.name} className="flex items-center gap-1 font-mono">
                <span
                  className="w-2 h-2 rounded-full inline-block"
                  style={{ backgroundColor: SEVERITY_COLORS[d.name] }}
                />
                <span className="text-slate-400">{d.name}:</span>
                <span className="font-semibold text-slate-200">{d.value}</span>
              </span>
            ))}
          </div>
        </Card>

        {/* Vulnerability Types */}
        <Card title="Common Vulnerability Types">
          <div className="h-56 w-full">
            {typeData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={typeData} layout="vertical" margin={{ left: -10, right: 10 }}>
                  <XAxis type="number" stroke="#64748b" fontSize={10} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={125}
                    stroke="#94a3b8"
                    fontSize={10}
                    tickFormatter={(v) => (v.length > 18 ? v.slice(0, 18) + "…" : v)}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      borderColor: "#334155",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Bar dataKey="value" fill="#10b981" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-center text-slate-500 text-xs w-full py-16">
                No vulnerability categories identified yet.
              </div>
            )}
          </div>
        </Card>

        {/* 6. Scan Coverage Overview */}
        <Card title="Scan Coverage Overview">
          <div className="space-y-3.5 pt-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Total Routes Discovered:</span>
              <span className="font-mono font-bold text-slate-200">
                {cov.total_routes_discovered ?? 0}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Total Routes Tested:</span>
              <span className="font-mono font-bold text-emerald-400">
                {cov.total_routes_tested ?? 0}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Auth-Required Routes:</span>
              <span className="font-mono font-bold text-amber-400">
                {cov.routes_auth_required ?? 0}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Failed / Unreachable Routes:</span>
              <span className="font-mono font-bold text-rose-400">
                {cov.routes_failed ?? 0}
              </span>
            </div>

            {/* Coverage progress bar */}
            <div className="pt-2 border-t border-slate-800">
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="text-slate-400 font-medium">Testing Coverage</span>
                <span className="font-mono font-bold text-emerald-400">
                  {cov.coverage_percentage ?? 0}%
                </span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                <div
                  className="bg-emerald-500 h-2 rounded-full transition-all duration-500"
                  style={{ width: `${Math.min(cov.coverage_percentage || 0, 100)}%` }}
                />
              </div>
              <p className="text-[10px] text-slate-500 mt-1.5">
                Clearly distinguishes discovered routes from successfully tested endpoints.
              </p>
            </div>
          </div>
        </Card>
      </div>

      {/* Main Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-1 text-sm font-semibold">
        <button
          onClick={() => setActiveTab("websites")}
          className={`px-4 py-2 rounded-lg transition-colors flex items-center gap-2 ${
            activeTab === "websites"
              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <span>🌐</span>
          <span>My Scanned Websites</span>
          <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 font-mono">
            {applications.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("remediation")}
          className={`px-4 py-2 rounded-lg transition-colors flex items-center gap-2 ${
            activeTab === "remediation"
              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <span>🛠</span>
          <span>Remediation Tracker</span>
        </button>

        <button
          onClick={() => setActiveTab("timeline")}
          className={`px-4 py-2 rounded-lg transition-colors flex items-center gap-2 ${
            activeTab === "timeline"
              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <span>⏱</span>
          <span>Recent Activity</span>
        </button>
      </div>

      {/* Tab 1: 1. Previously Scanned Websites ("My Scanned Websites") */}
      {activeTab === "websites" && (
        <div className="space-y-4">
          {/* Search and Filters Bar */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
            <div className="flex-1">
              <input
                type="text"
                placeholder="Search websites by name, URL, or host (e.g. localhost:5173)…"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setWebsitePage(1);
                }}
                className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 placeholder-slate-400 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div className="flex items-center gap-2">
              <select
                value={ratingFilter}
                onChange={(e) => {
                  setRatingFilter(e.target.value);
                  setWebsitePage(1);
                }}
                className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
              >
                <option value="">All Ratings</option>
                <option value="STRONG">STRONG (85–100)</option>
                <option value="MEDIUM">MEDIUM (60–84)</option>
                <option value="WEAK">WEAK (&lt;60)</option>
              </select>

              <select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value);
                  setWebsitePage(1);
                }}
                className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
              >
                <option value="">All Statuses</option>
                <option value="completed">Completed</option>
                <option value="running">Running</option>
                <option value="pending">Pending</option>
                <option value="failed">Failed</option>
              </select>

              {(search || ratingFilter || statusFilter) && (
                <button
                  onClick={() => {
                    setSearch("");
                    setRatingFilter("");
                    setStatusFilter("");
                    setWebsitePage(1);
                  }}
                  className="px-2.5 py-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-slate-200 text-xs"
                >
                  Reset
                </button>
              )}
            </div>
          </div>

          {/* Website Cards Grid */}
          {paginatedWebsites.length === 0 ? (
            <EmptyState
              icon="🌐"
              title="No Scanned Websites Found"
              description={
                applications.length === 0
                  ? "No targets have been scanned yet. Launch your first authorized scan to monitor websites."
                  : "No websites match your current filter parameters."
              }
              action={
                applications.length === 0 && (
                  <Link
                    to="/scan/new"
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold inline-block transition-colors"
                  >
                    Start First Scan
                  </Link>
                )
              }
            />
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {paginatedWebsites.map((app) => (
                <WebsiteCard
                  key={app.id}
                  app={app}
                  onRescan={handleRescan}
                  onViewTrends={(targetApp) => setSelectedAppForTrends(targetApp)}
                  onRename={handleRename}
                />
              ))}
            </div>
          )}

          {/* Pagination */}
          <Pagination
            currentPage={websitePage}
            totalPages={totalWebsitePages}
            onPageChange={setWebsitePage}
          />
        </div>
      )}

      {/* Tab 2: 3. Vulnerability Remediation Tracker */}
      {activeTab === "remediation" && (
        <Card>
          <RemediationTracker apps={applications} />
        </Card>
      )}

      {/* Tab 3: 4. Recent Activity Timeline */}
      {activeTab === "timeline" && (
        <Card>
          <ActivityTimeline limit={30} />
        </Card>
      )}

      {/* 2. Security Posture Trends Modal */}
      {selectedAppForTrends && (
        <WebsiteTrendsModal
          app={selectedAppForTrends}
          onClose={() => setSelectedAppForTrends(null)}
        />
      )}
    </div>
  );
}
