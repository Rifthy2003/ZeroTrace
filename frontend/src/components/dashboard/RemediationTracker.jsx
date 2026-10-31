import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { getRemediationFindings, updateFindingStatus } from "../../services/api";
import { SeverityBadge, LifecycleBadge, Spinner, Pagination, EmptyState } from "../ui";
import { SEVERITIES, fmtDate } from "../../utils/format";

export default function RemediationTracker({ apps = [] }) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedApp, setSelectedApp] = useState("");
  const [selectedStatus, setSelectedStatus] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [updatingId, setUpdatingId] = useState(null);

  const fetchFindings = () => {
    setLoading(true);
    const params = {};
    if (selectedApp) params.application_id = selectedApp;
    if (selectedStatus) params.status = selectedStatus;
    if (selectedSeverity) params.severity = selectedSeverity;

    getRemediationFindings(params)
      .then(setFindings)
      .catch((err) => console.error("Error loading remediation tracker:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchFindings();
  }, [selectedApp, selectedStatus, selectedSeverity]);

  const handleStatusChange = async (findingId, newStatus) => {
    setUpdatingId(findingId);
    try {
      const updated = await updateFindingStatus(findingId, { status: newStatus });
      setFindings((prev) =>
        prev.map((f) => (f.id === findingId ? { ...f, status: updated.status, status_updated_at: updated.status_updated_at } : f))
      );
    } catch (err) {
      console.error("Failed to update finding status:", err);
    } finally {
      setUpdatingId(null);
    }
  };

  const filtered = findings.filter((f) => {
    if (!search) return true;
    const s = search.toLowerCase();
    return (
      (f.type && f.type.toLowerCase().includes(s)) ||
      (f.url && f.url.toLowerCase().includes(s)) ||
      (f.parameter && f.parameter.toLowerCase().includes(s)) ||
      (f.application_name && f.application_name.toLowerCase().includes(s))
    );
  });

  const pageSize = 10;
  const totalPages = Math.ceil(filtered.length / pageSize) || 1;
  const paginated = filtered.slice((page - 1) * pageSize, page * pageSize);

  const selectClass = "bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-emerald-500";

  return (
    <div className="space-y-4">
      {/* Header and Filters */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <span>🛡</span> Vulnerability Remediation Tracker
          </h2>
          <p className="text-xs text-slate-400">
            Track vulnerability lifecycle (Open, Fixed, Accepted Risk, Reopened) across websites and scans.
          </p>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            placeholder="Search vulnerabilities, routes…"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-48 sm:w-56"
          />

          {apps.length > 0 && (
            <select
              value={selectedApp}
              onChange={(e) => {
                setSelectedApp(e.target.value);
                setPage(1);
              }}
              className={selectClass}
            >
              <option value="">All Websites</option>
              {apps.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          )}

          <select
            value={selectedStatus}
            onChange={(e) => {
              setSelectedStatus(e.target.value);
              setPage(1);
            }}
            className={selectClass}
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="fixed">Fixed</option>
            <option value="accepted_risk">Accepted Risk</option>
            <option value="reopened">Reopened</option>
          </select>

          <select
            value={selectedSeverity}
            onChange={(e) => {
              setSelectedSeverity(e.target.value);
              setPage(1);
            }}
            className={selectClass}
          >
            <option value="">All Severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <Spinner message="Loading remediation findings…" />
      ) : paginated.length === 0 ? (
        <EmptyState
          icon="📋"
          title="No Matching Vulnerabilities"
          description={findings.length === 0 ? "No vulnerabilities recorded in the system yet." : "Try adjusting your search or filters."}
        />
      ) : (
        <div className="border border-slate-800 rounded-xl overflow-hidden shadow-lg bg-slate-900/60">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 uppercase font-semibold text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Vulnerability Issue</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Website / Target</th>
                  <th className="py-3 px-4">Affected Route & Parameter</th>
                  <th className="py-3 px-4">Current Status</th>
                  <th className="py-3 px-4">Actions / Switch Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {paginated.map((f) => (
                  <tr key={f.id} className="hover:bg-slate-800/40 transition-colors">
                    {/* Vulnerability type & details link */}
                    <td className="py-3 px-4">
                      <Link
                        to={`/scan/${f.scan_id}/finding/${f.id}`}
                        className="font-semibold text-slate-100 hover:text-emerald-400 block transition-colors"
                      >
                        {f.type}
                      </Link>
                      <span className="text-[10px] text-slate-500 font-mono">
                        FP: {f.fingerprint ? f.fingerprint.slice(0, 10) : "—"}
                      </span>
                    </td>

                    {/* Severity */}
                    <td className="py-3 px-4">
                      <SeverityBadge severity={f.severity} />
                    </td>

                    {/* Website Name */}
                    <td className="py-3 px-4">
                      <div className="font-medium text-slate-300">
                        {f.application_name || "Unassigned"}
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono truncate max-w-[180px]">
                        {f.target_url}
                      </div>
                    </td>

                    {/* Route & Parameter */}
                    <td className="py-3 px-4 max-w-xs">
                      <div className="font-mono text-slate-300 truncate" title={f.url}>
                        {f.url}
                      </div>
                      {f.parameter && (
                        <div className="text-[10px] text-slate-400 font-mono">
                          param: <span className="text-slate-300">{f.parameter}</span>
                        </div>
                      )}
                    </td>

                    {/* Current Lifecycle Status */}
                    <td className="py-3 px-4">
                      <LifecycleBadge status={f.status} />
                    </td>

                    {/* Status Changer Dropdown */}
                    <td className="py-3 px-4">
                      <select
                        value={f.status || "open"}
                        disabled={updatingId === f.id}
                        onChange={(e) => handleStatusChange(f.id, e.target.value)}
                        className="bg-slate-800/90 border border-slate-700 hover:border-slate-600 rounded px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-emerald-500 font-medium disabled:opacity-50"
                      >
                        <option value="open">Open</option>
                        <option value="fixed">Fixed</option>
                        <option value="accepted_risk">Accepted Risk</option>
                        <option value="reopened">Reopened</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="p-3 bg-slate-950/40">
            <Pagination
              currentPage={page}
              totalPages={totalPages}
              onPageChange={setPage}
            />
          </div>
        </div>
      )}
    </div>
  );
}

