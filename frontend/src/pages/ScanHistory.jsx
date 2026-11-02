import React, { useEffect, useState, useRef } from "react";
import { Link } from "react-router-dom";
import {
  listScans,
  renameScan,
  deleteScan,
  restoreScan,
  permanentDeleteScan,
  bulkDeleteScans,
  bulkRestoreScans,
  bulkPermanentDeleteScans,
  completeBountyReportUrl,
} from "../services/api";
import { Card, Spinner, StatusBadge, Pagination, EmptyState } from "../components/ui";
import { fmtDate, fmtDuration } from "../utils/format";

export default function ScanHistory() {
  const [activeTab, setActiveTab] = useState("active"); // "active" or "trash"
  const [scans, setScans] = useState([]);
  const [trashScans, setTrashScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [feedback, setFeedback] = useState(null); // { type: "success"|"error", message: "" }

  // Search & Filter States
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [dateFilter, setDateFilter] = useState("all");
  const [sortBy, setSortBy] = useState("newest");
  const [page, setPage] = useState(1);
  const pageSize = 12;

  // Selection & Bulk Actions
  const [selectedIds, setSelectedIds] = useState([]);

  // Three-dot action menu state
  const [activeMenuId, setActiveMenuId] = useState(null);

  // Modals state
  const [deleteModalScan, setDeleteModalScan] = useState(null); // Soft delete modal
  const [permanentModalScan, setPermanentModalScan] = useState(null); // Permanent delete modal
  const [renameModalScan, setRenameModalScan] = useState(null); // Rename modal
  const [renameInputValue, setRenameInputValue] = useState("");
  const [bulkDeleteModalOpen, setBulkDeleteModalOpen] = useState(false);
  const [bulkPermanentModalOpen, setBulkPermanentModalOpen] = useState(false);
  const [actionInProgress, setActionInProgress] = useState(false);

  // Close three-dot menu on outside click
  useEffect(() => {
    const handleOutsideClick = (e) => {
      if (!e.target.closest(".action-menu-container")) {
        setActiveMenuId(null);
      }
    };
    document.addEventListener("mousedown", handleOutsideClick);
    return () => document.removeEventListener("mousedown", handleOutsideClick);
  }, []);

  // Fetch scans for both active and trash
  const fetchAllScans = async () => {
    setLoading(true);
    setError(null);
    try {
      const [activeData, trashData] = await Promise.all([
        listScans({ trash_only: false }),
        listScans({ trash_only: true }),
      ]);
      setScans(activeData || []);
      setTrashScans(trashData || []);
    } catch (err) {
      console.error("Failed to load scans:", err);
      setError(err.message || "Failed to load scan history from backend.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAllScans();
  }, []);

  // Clear selections when switching tabs
  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setSelectedIds([]);
    setPage(1);
    setActiveMenuId(null);
  };

  const showNotification = (message, type = "success") => {
    setFeedback({ message, type });
    setTimeout(() => {
      setFeedback(null);
    }, 4500);
  };

  // Current active list
  const currentList = activeTab === "active" ? scans : trashScans;

  // Filter & Sort Logic
  const filteredScans = currentList.filter((s) => {
    // Search
    if (search.trim()) {
      const q = search.toLowerCase();
      const app = (s.application_name || "").toLowerCase();
      const name = (s.name || "").toLowerCase();
      const host = (s.hostname || "").toLowerCase();
      const url = (s.target_url || "").toLowerCase();
      const id = (s.id || "").toLowerCase();
      if (!app.includes(q) && !name.includes(q) && !host.includes(q) && !url.includes(q) && !id.includes(q)) {
        return false;
      }
    }

    // Status Filter
    if (statusFilter && s.status !== statusFilter) {
      return false;
    }

    // Date Filter
    if (dateFilter !== "all" && s.created_at) {
      const scanDate = new Date(s.created_at).getTime();
      const now = Date.now();
      if (dateFilter === "24h" && now - scanDate > 24 * 60 * 60 * 1000) return false;
      if (dateFilter === "7d" && now - scanDate > 7 * 24 * 60 * 60 * 1000) return false;
      if (dateFilter === "30d" && now - scanDate > 30 * 24 * 60 * 60 * 1000) return false;
    }

    return true;
  });

  // Sort
  filteredScans.sort((a, b) => {
    if (sortBy === "oldest") {
      return new Date(a.created_at) - new Date(b.created_at);
    }
    if (sortBy === "findings") {
      return (b.findings_count || 0) - (a.findings_count || 0);
    }
    // Default newest
    return new Date(b.created_at) - new Date(a.created_at);
  });

  const totalPages = Math.ceil(filteredScans.length / pageSize) || 1;
  const paginatedScans = filteredScans.slice((page - 1) * pageSize, page * pageSize);

  // Selection Handlers
  const handleSelectAll = (e) => {
    if (e.target.checked) {
      const allVisibleIds = paginatedScans.map((s) => s.id);
      setSelectedIds(Array.from(new Set([...selectedIds, ...allVisibleIds])));
    } else {
      const visibleSet = new Set(paginatedScans.map((s) => s.id));
      setSelectedIds(selectedIds.filter((id) => !visibleSet.has(id)));
    }
  };

  const handleSelectRow = (id) => {
    if (selectedIds.includes(id)) {
      setSelectedIds(selectedIds.filter((x) => x !== id));
    } else {
      setSelectedIds([...selectedIds, id]);
    }
  };

  const isAllVisibleSelected =
    paginatedScans.length > 0 && paginatedScans.every((s) => selectedIds.includes(s.id));

  // Single Actions
  const handleOpenRenameModal = (scan) => {
    setRenameModalScan(scan);
    setRenameInputValue(scan.name || scan.target_url || scan.hostname || "");
    setActiveMenuId(null);
  };

  const handleSaveRename = async () => {
    if (!renameModalScan || !renameInputValue.trim()) return;
    setActionInProgress(true);
    try {
      await renameScan(renameModalScan.id, renameInputValue.trim());
      showNotification(`Scan renamed to "${renameInputValue.trim()}"`);
      setRenameModalScan(null);
      await fetchAllScans();
    } catch (err) {
      showNotification(err.response?.data?.detail || err.message, "error");
    } finally {
      setActionInProgress(false);
    }
  };

  const handleConfirmSoftDelete = async () => {
    if (!deleteModalScan) return;
    setActionInProgress(true);
    try {
      await deleteScan(deleteModalScan.id);
      showNotification(`Scan for ${deleteModalScan.target_url || deleteModalScan.hostname} moved to Trash.`);
      setDeleteModalScan(null);
      setSelectedIds((prev) => prev.filter((id) => id !== deleteModalScan.id));
      await fetchAllScans();
    } catch (err) {
      showNotification(err.response?.data?.detail || err.message, "error");
    } finally {
      setActionInProgress(false);
    }
  };

  const handleRestoreScan = async (scan) => {
    setActionInProgress(true);
    try {
      await restoreScan(scan.id);
      showNotification(`Scan for ${scan.target_url || scan.hostname} restored from Trash.`);
      setSelectedIds((prev) => prev.filter((id) => id !== scan.id));
      setActiveMenuId(null);
      await fetchAllScans();
    } catch (err) {
      showNotification(err.response?.data?.detail || err.message, "error");
    } finally {
      setActionInProgress(false);
    }
  };

  const handleConfirmPermanentDelete = async () => {
    if (!permanentModalScan) return;
    setActionInProgress(true);
    try {
      await permanentDeleteScan(permanentModalScan.id);
      showNotification(`Scan permanently deleted.`);
      setPermanentModalScan(null);
      setSelectedIds((prev) => prev.filter((id) => id !== permanentModalScan.id));
      await fetchAllScans();
    } catch (err) {
      showNotification(err.response?.data?.detail || err.message, "error");
    } finally {
      setActionInProgress(false);
    }
  };

  // Bulk Actions
  const handleConfirmBulkDelete = async () => {
    if (selectedIds.length === 0) return;
    setActionInProgress(true);
    try {
      const res = await bulkDeleteScans(selectedIds);
      showNotification(`${res.count || selectedIds.length} scan(s) moved to Trash.`);
      setSelectedIds([]);
      setBulkDeleteModalOpen(false);
      await fetchAllScans();
    } catch (err) {
      showNotification(err.response?.data?.detail || err.message, "error");
    } finally {
      setActionInProgress(false);
    }
  };

  const handleConfirmBulkRestore = async () => {
    if (selectedIds.length === 0) return;
    setActionInProgress(true);
    try {
      const res = await bulkRestoreScans(selectedIds);
      showNotification(`${res.count || selectedIds.length} scan(s) restored successfully.`);
      setSelectedIds([]);
      await fetchAllScans();
    } catch (err) {
      showNotification(err.response?.data?.detail || err.message, "error");
    } finally {
      setActionInProgress(false);
    }
  };

  const handleConfirmBulkPermanentDelete = async () => {
    if (selectedIds.length === 0) return;
    setActionInProgress(true);
    try {
      const res = await bulkPermanentDeleteScans(selectedIds);
      showNotification(`${res.count || selectedIds.length} scan(s) permanently purged.`);
      setSelectedIds([]);
      setBulkPermanentModalOpen(false);
      await fetchAllScans();
    } catch (err) {
      showNotification(err.response?.data?.detail || err.message, "error");
    } finally {
      setActionInProgress(false);
    }
  };

  if (loading && scans.length === 0 && trashScans.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[350px] space-y-3">
        <Spinner />
        <span className="text-xs text-slate-400 font-medium">Loading scan audit logs...</span>
      </div>
    );
  }

  if (error && scans.length === 0 && trashScans.length === 0) {
    return (
      <div className="max-w-6xl mx-auto space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-slate-100">Scan History</h1>
        </div>
        <Card className="border-rose-900/50 bg-rose-950/20 text-center py-10">
          <div className="text-3xl mb-2">⚠️</div>
          <h3 className="text-lg font-semibold text-rose-300">Unable to Load Scans</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto mt-1 mb-4">{error}</p>
          <button
            onClick={fetchAllScans}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
          >
            Retry Connection
          </button>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-4 max-w-6xl mx-auto pb-12">
      {/* Toast Notification */}
      {feedback && (
        <div
          className={`p-3 rounded-lg text-xs font-medium flex items-center justify-between border transition-all ${
            feedback.type === "error"
              ? "bg-rose-950/80 border-rose-800 text-rose-300"
              : "bg-emerald-950/80 border-emerald-800 text-emerald-300"
          }`}
        >
          <div className="flex items-center gap-2">
            <span>{feedback.type === "error" ? "⚠️" : "✓"}</span>
            <span>{feedback.message}</span>
          </div>
          <button onClick={() => setFeedback(null)} className="text-slate-400 hover:text-slate-200 ml-4">
            ✕
          </button>
        </div>
      )}

      {/* Header and Top Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Scan History & Audit Log</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Manage, review, rename, or restore vulnerability assessments across all target applications.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link
            to="/scan/new"
            className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold whitespace-nowrap shadow-sm transition-colors"
          >
            + New Scan
          </Link>
        </div>
      </div>

      {/* Navigation Tabs (Active Scans vs Trash) */}
      <div className="flex items-center border-b border-slate-800">
        <button
          onClick={() => handleTabChange("active")}
          className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === "active"
              ? "border-emerald-500 text-emerald-400"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <span>Active Scans</span>
          <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-300 font-mono">
            {scans.length}
          </span>
        </button>

        <button
          onClick={() => handleTabChange("trash")}
          className={`px-4 py-2.5 text-xs font-semibold border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === "trash"
              ? "border-amber-500 text-amber-400"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <span>Trash</span>
          <span
            className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${
              trashScans.length > 0 ? "bg-amber-950/80 text-amber-400 border border-amber-800/80" : "bg-slate-800 text-slate-400"
            }`}
          >
            {trashScans.length}
          </span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <Card className="p-3 bg-slate-900/90">
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-2.5">
          <div className="relative flex-1">
            <input
              type="text"
              placeholder="Search by target domain, custom name, or scan ID..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
            {search && (
              <button
                onClick={() => setSearch("")}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-xs text-slate-500 hover:text-slate-300"
              >
                ✕
              </button>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
            >
              <option value="">All Statuses</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="pending">Pending</option>
              <option value="failed">Failed</option>
              <option value="cancelled">Cancelled</option>
            </select>

            <select
              value={dateFilter}
              onChange={(e) => {
                setDateFilter(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
            >
              <option value="all">All Dates</option>
              <option value="24h">Past 24 Hours</option>
              <option value="7d">Past 7 Days</option>
              <option value="30d">Past 30 Days</option>
            </select>

            <select
              value={sortBy}
              onChange={(e) => {
                setSortBy(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
            >
              <option value="newest">Sort: Newest First</option>
              <option value="oldest">Sort: Oldest First</option>
              <option value="findings">Sort: Most Findings</option>
            </select>

            {(search || statusFilter || dateFilter !== "all" || sortBy !== "newest") && (
              <button
                onClick={() => {
                  setSearch("");
                  setStatusFilter("");
                  setDateFilter("all");
                  setSortBy("newest");
                  setPage(1);
                }}
                className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 text-xs border border-slate-700 transition-colors"
                title="Reset Filters"
              >
                Reset
              </button>
            )}
          </div>
        </div>
      </Card>

      {/* Bulk Action Toolbar (appears when 1+ selected) */}
      {selectedIds.length > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl bg-slate-900 border border-emerald-500/30 text-xs animate-in fade-in">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-emerald-400">{selectedIds.length}</span>
            <span className="text-slate-300">scan(s) selected</span>
          </div>

          <div className="flex items-center gap-2">
            {activeTab === "active" ? (
              <button
                onClick={() => setBulkDeleteModalOpen(true)}
                className="px-3 py-1.5 rounded-lg bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 border border-rose-800/80 font-medium transition-colors flex items-center gap-1.5"
              >
                <span>🗑️</span> Move Selected to Trash
              </button>
            ) : (
              <>
                <button
                  onClick={handleConfirmBulkRestore}
                  disabled={actionInProgress}
                  className="px-3 py-1.5 rounded-lg bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-800/80 font-medium transition-colors flex items-center gap-1.5"
                >
                  <span>🔄</span> Restore Selected
                </button>
                <button
                  onClick={() => setBulkPermanentModalOpen(true)}
                  className="px-3 py-1.5 rounded-lg bg-rose-950/70 hover:bg-rose-900/90 text-rose-300 border border-rose-800/80 font-medium transition-colors flex items-center gap-1.5"
                >
                  <span>⚠️</span> Delete Permanently
                </button>
              </>
            )}

            <button
              onClick={() => setSelectedIds([])}
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700 transition-colors"
            >
              Clear
            </button>
          </div>
        </div>
      )}

      {/* Main Scan Table Card */}
      <Card className="p-0 overflow-hidden">
        {filteredScans.length === 0 ? (
          <div className="p-6">
            <EmptyState
              icon={activeTab === "trash" ? "🗑️" : "📋"}
              title={
                activeTab === "trash"
                  ? "Trash is Empty"
                  : scans.length === 0
                  ? "No Scans Recorded"
                  : "No Matching Scans Found"
              }
              description={
                activeTab === "trash"
                  ? "Deleted scans will appear here. You can restore them anytime or permanently delete them."
                  : scans.length === 0
                  ? "Start your first web security scan to see history here."
                  : "Try adjusting your search query or filters."
              }
            />
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-slate-400 text-xs uppercase border-b border-slate-800 bg-slate-950/50">
                  <tr>
                    <th className="py-2.5 px-3 w-10 text-center">
                      <input
                        type="checkbox"
                        checked={isAllVisibleSelected}
                        onChange={handleSelectAll}
                        className="rounded bg-slate-900 border-slate-700 text-emerald-500 focus:ring-0 cursor-pointer"
                        title="Select visible scans"
                      />
                    </th>
                    <th className="py-2.5 px-3">Date</th>
                    <th className="py-2.5 px-3">Target / Application</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3">Routes Discovered / Tested</th>
                    <th className="py-2.5 px-3">Findings</th>
                    <th className="py-2.5 px-3">Duration</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {paginatedScans.map((s) => {
                    const isSelected = selectedIds.includes(s.id);
                    const isMenuOpen = activeMenuId === s.id;
                    const uniqueCount = s.unique_findings_count || s.findings_count || 0;
                    const rawCount = s.raw_occurrences_count || s.findings_count || 0;

                    return (
                      <tr
                        key={s.id}
                        className={`hover:bg-slate-800/40 transition-colors ${
                          isSelected ? "bg-slate-800/25" : ""
                        }`}
                      >
                        <td className="py-2.5 px-3 text-center">
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => handleSelectRow(s.id)}
                            className="rounded bg-slate-900 border-slate-700 text-emerald-500 focus:ring-0 cursor-pointer"
                          />
                        </td>

                        <td className="py-2.5 px-3 font-mono text-xs text-slate-300 whitespace-nowrap">
                          {fmtDate(s.created_at)}
                        </td>

                        <td className="py-2.5 px-3">
                          <div className="flex items-center gap-1.5">
                            <span className="font-semibold text-slate-200">
                              {s.name || s.application_name || s.hostname || "Target"}
                            </span>
                            {s.name && (
                              <button
                                onClick={() => handleOpenRenameModal(s)}
                                className="text-slate-500 hover:text-slate-300 text-[10px]"
                                title="Edit scan name"
                              >
                                ✏️
                              </button>
                            )}
                          </div>
                          <div className="font-mono text-slate-400 text-xs truncate max-w-xs mt-0.5">
                            {s.target_url || s.hostname || "—"}
                          </div>
                          <div className="font-mono text-[10px] text-slate-500 truncate max-w-xs">
                            ID: {s.id.slice(0, 8)}...
                          </div>
                        </td>

                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <StatusBadge status={s.status} />
                        </td>

                        <td className="py-2.5 px-3 font-mono text-xs text-slate-300">
                          {s.urls_discovered || 0} / {s.urls_scanned || 0}
                        </td>

                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <span
                              className={`font-mono font-bold ${
                                uniqueCount > 0 ? "text-amber-400" : "text-emerald-400"
                              }`}
                            >
                              {uniqueCount}
                            </span>
                            {rawCount > uniqueCount && (
                              <span className="text-[11px] text-slate-500 font-mono">
                                ({rawCount} hits)
                              </span>
                            )}
                          </div>
                        </td>

                        <td className="py-2.5 px-3 font-mono text-xs text-slate-400 whitespace-nowrap">
                          {fmtDuration(s.duration_seconds)}
                        </td>

                        <td className="py-2.5 px-3 text-right">
                          <div className="inline-flex items-center gap-2 justify-end">
                            {/* Primary Action Button */}
                            {activeTab === "active" ? (
                              <Link
                                className="text-emerald-400 hover:text-emerald-300 font-medium text-xs inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800/80 hover:bg-slate-800 border border-slate-700/80 transition-colors"
                                to={s.status === "completed" ? `/scan/${s.id}` : `/scan/${s.id}/progress`}
                              >
                                <span>{s.status === "completed" ? "Results" : "Track"}</span> &rarr;
                              </Link>
                            ) : (
                              <button
                                onClick={() => handleRestoreScan(s)}
                                className="text-emerald-400 hover:text-emerald-300 font-medium text-xs inline-flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-950/40 hover:bg-emerald-900/60 border border-emerald-800/80 transition-colors"
                                title="Restore scan from Trash"
                              >
                                <span>🔄 Restore</span>
                              </button>
                            )}

                            {/* Three-Dot Action Dropdown Menu */}
                            <div className="relative action-menu-container">
                              <button
                                type="button"
                                onClick={() => setActiveMenuId(isMenuOpen ? null : s.id)}
                                className="p-1 rounded-md text-slate-400 hover:text-slate-100 hover:bg-slate-800 border border-transparent hover:border-slate-700 transition-colors"
                                title="More actions"
                              >
                                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                                  <path d="M10 6a2 2 0 110-4 2 2 0 010 4zM10 12a2 2 0 110-4 2 2 0 010 4zM10 18a2 2 0 110-4 2 2 0 010 4z" />
                                </svg>
                              </button>

                              {isMenuOpen && (
                                <div className="absolute right-0 mt-1 w-52 rounded-xl bg-slate-900 border border-slate-800 shadow-2xl py-1 z-50 text-left animate-in fade-in zoom-in-95">
                                  {activeTab === "active" ? (
                                    <>
                                      <Link
                                        to={s.status === "completed" ? `/scan/${s.id}` : `/scan/${s.id}/progress`}
                                        className="flex items-center gap-2 px-3 py-2 text-xs text-slate-200 hover:bg-slate-800 transition-colors"
                                        onClick={() => setActiveMenuId(null)}
                                      >
                                        <span>👁️</span> View Results
                                      </Link>

                                      {s.status === "completed" && (
                                        <a
                                          href={completeBountyReportUrl(s.id)}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          className="flex items-center gap-2 px-3 py-2 text-xs text-indigo-300 hover:bg-slate-800 transition-colors"
                                          onClick={() => setActiveMenuId(null)}
                                        >
                                          <span>📄</span> Complete Bug Bounty PDF
                                        </a>
                                      )}

                                      <button
                                        type="button"
                                        onClick={() => handleOpenRenameModal(s)}
                                        className="w-full flex items-center gap-2 px-3 py-2 text-xs text-slate-200 hover:bg-slate-800 transition-colors text-left"
                                      >
                                        <span>✏️</span> Rename Scan
                                      </button>

                                      <div className="border-t border-slate-800 my-1" />

                                      <button
                                        type="button"
                                        onClick={() => {
                                          setDeleteModalScan(s);
                                          setActiveMenuId(null);
                                        }}
                                        className="w-full flex items-center gap-2 px-3 py-2 text-xs text-rose-400 hover:bg-rose-950/40 transition-colors text-left font-medium"
                                      >
                                        <span>🗑️</span> Delete Scan
                                      </button>
                                    </>
                                  ) : (
                                    <>
                                      <button
                                        type="button"
                                        onClick={() => handleRestoreScan(s)}
                                        className="w-full flex items-center gap-2 px-3 py-2 text-xs text-emerald-400 hover:bg-slate-800 transition-colors text-left"
                                      >
                                        <span>🔄</span> Restore to Scan History
                                      </button>

                                      <div className="border-t border-slate-800 my-1" />

                                      <button
                                        type="button"
                                        onClick={() => {
                                          setPermanentModalScan(s);
                                          setActiveMenuId(null);
                                        }}
                                        className="w-full flex items-center gap-2 px-3 py-2 text-xs text-rose-400 hover:bg-rose-950/40 transition-colors text-left font-medium"
                                      >
                                        <span>⚠️</span> Delete Permanently
                                      </button>
                                    </>
                                  )}
                                </div>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {totalPages > 1 && (
              <div className="p-3 border-t border-slate-800">
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

      {/* ========================================================================= */}
      {/* MODAL 1: Soft Delete Confirmation Modal                                   */}
      {/* ========================================================================= */}
      {deleteModalScan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 text-slate-200 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <span>🗑️</span> Move Scan to Trash
              </h3>
              <button
                onClick={() => setDeleteModalScan(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to delete this scan? The scan will be moved to the Trash where you can restore it anytime or permanently purge it.
            </p>

            {/* Scan Metadata Card */}
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3.5 space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400 font-medium">Target URL:</span>
                <span className="font-mono text-emerald-400 font-semibold truncate max-w-xs">
                  {deleteModalScan.target_url || deleteModalScan.hostname}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400 font-medium">Scan ID:</span>
                <span className="font-mono text-slate-300">{deleteModalScan.id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400 font-medium">Scan Date & Time:</span>
                <span className="font-mono text-slate-300">{fmtDate(deleteModalScan.created_at)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400 font-medium">Unique Vulnerabilities:</span>
                <span className="font-mono text-amber-400 font-bold">
                  {deleteModalScan.unique_findings_count || deleteModalScan.findings_count || 0}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400 font-medium">Raw Occurrences / Hits:</span>
                <span className="font-mono text-slate-300">
                  {deleteModalScan.raw_occurrences_count || deleteModalScan.findings_count || 0}
                </span>
              </div>
              <div className="flex justify-between items-center pt-1 border-t border-slate-800/80">
                <span className="text-slate-400 font-medium">Status:</span>
                <StatusBadge status={deleteModalScan.status} />
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setDeleteModalScan(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmSoftDelete}
                disabled={actionInProgress}
                className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold transition-colors flex items-center gap-1.5 shadow-sm"
              >
                {actionInProgress && <span className="animate-spin h-3.5 w-3.5 border-2 border-white border-t-transparent rounded-full" />}
                <span>Move to Trash</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 2: Permanent Delete Confirmation Modal                              */}
      {/* ========================================================================= */}
      {permanentModalScan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-lg bg-slate-900 border border-rose-900/60 rounded-2xl shadow-2xl p-6 text-slate-200 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <h3 className="text-base font-bold text-rose-400 flex items-center gap-2">
                <span>⚠️</span> Permanently Delete Scan
              </h3>
              <button
                onClick={() => setPermanentModalScan(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-900/60 text-rose-300 text-xs leading-relaxed">
              <b>Warning:</b> This action is <b>permanent and irreversible</b>. All discovered endpoints, raw logs, vulnerability findings, and generated PDF reports associated with this scan will be permanently purged from the database.
            </div>

            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3.5 space-y-1.5 text-xs font-mono">
              <div className="text-slate-400">Target: <b className="text-slate-200 font-sans">{permanentModalScan.target_url || permanentModalScan.hostname}</b></div>
              <div className="text-slate-400">Scan ID: <span className="text-slate-300">{permanentModalScan.id}</span></div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setPermanentModalScan(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmPermanentDelete}
                disabled={actionInProgress}
                className="px-4 py-2 rounded-lg bg-rose-700 hover:bg-rose-600 text-white text-xs font-semibold transition-colors flex items-center gap-1.5 shadow-sm"
              >
                {actionInProgress && <span className="animate-spin h-3.5 w-3.5 border-2 border-white border-t-transparent rounded-full" />}
                <span>Permanently Delete</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 3: Rename Scan Modal                                                */}
      {/* ========================================================================= */}
      {renameModalScan && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 text-slate-200 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <span>✏️</span> Rename Scan
              </h3>
              <button
                onClick={() => setRenameModalScan(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300">Scan Name / Label</label>
              <input
                type="text"
                value={renameInputValue}
                onChange={(e) => setRenameInputValue(e.target.value)}
                placeholder="e.g. Q4 Production Audit, Sprint 12 Test..."
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
                autoFocus
              />
              <span className="text-[11px] text-slate-500">
                A custom title helps you identify this scan in reports and history.
              </span>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setRenameModalScan(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveRename}
                disabled={actionInProgress || !renameInputValue.trim()}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition-colors disabled:opacity-50"
              >
                {actionInProgress ? "Saving..." : "Save Name"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 4: Bulk Delete Confirmation Modal                                   */}
      {/* ========================================================================= */}
      {bulkDeleteModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 text-slate-200 space-y-4">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <span>🗑️</span> Move {selectedIds.length} Scan(s) to Trash?
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              These {selectedIds.length} scans will be hidden from active history and moved to Trash. Any actively running scans in the selection will be safely skipped.
            </p>
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setBulkDeleteModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmBulkDelete}
                disabled={actionInProgress}
                className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold transition-colors"
              >
                {actionInProgress ? "Moving..." : "Move to Trash"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODAL 5: Bulk Permanent Delete Confirmation Modal                         */}
      {/* ========================================================================= */}
      {bulkPermanentModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-md bg-slate-900 border border-rose-900/60 rounded-2xl shadow-2xl p-6 text-slate-200 space-y-4">
            <h3 className="text-base font-bold text-rose-400 flex items-center gap-2">
              <span>⚠️</span> Permanently Purge {selectedIds.length} Scan(s)?
            </h3>
            <p className="text-xs text-rose-300 leading-relaxed bg-rose-950/40 border border-rose-900/50 p-2.5 rounded-lg">
              This action <b>cannot be undone</b>. All selected scans and their findings will be deleted permanently from the database.
            </p>
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setBulkPermanentModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmBulkPermanentDelete}
                disabled={actionInProgress}
                className="px-4 py-2 rounded-lg bg-rose-700 hover:bg-rose-600 text-white text-xs font-semibold transition-colors"
              >
                {actionInProgress ? "Purging..." : "Permanently Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
