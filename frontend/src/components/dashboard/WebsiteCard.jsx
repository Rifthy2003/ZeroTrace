import React, { useState } from "react";
import { Link } from "react-router-dom";
import { RatingBadge, StatusBadge, SeverityBadge } from "../ui";
import { reportUrl } from "../../services/api";
import { fmtDate, fmtDuration } from "../../utils/format";

export default function WebsiteCard({
  app,
  onRescan,
  onViewTrends,
  onRename,
}) {
  const [isEditing, setIsEditing] = useState(false);
  const [nameInput, setNameInput] = useState(app.name);
  const [isRescanning, setIsRescanning] = useState(false);

  const handleSaveName = (e) => {
    e.preventDefault();
    if (nameInput.trim()) {
      onRename(app.id, nameInput.trim());
      setIsEditing(false);
    }
  };

  const handleRescanClick = async () => {
    setIsRescanning(true);
    try {
      await onRescan(app.id);
    } finally {
      setIsRescanning(false);
    }
  };

  const hasLatestScan = !!app.latest_scan_id;
  const counts = app.finding_counts || {};

  return (
    <div className="bg-slate-900 border border-slate-800 hover:border-slate-700/80 rounded-xl p-5 shadow-lg transition-all duration-200 flex flex-col justify-between group">
      <div>
        {/* Header: Name, Host, Rating */}
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="min-w-0 flex-1">
            {isEditing ? (
              <form onSubmit={handleSaveName} className="flex items-center gap-1.5 mb-1">
                <input
                  type="text"
                  value={nameInput}
                  onChange={(e) => setNameInput(e.target.value)}
                  className="bg-slate-800 border border-emerald-500/50 rounded px-2 py-0.5 text-sm text-slate-100 focus:outline-none w-full"
                  autoFocus
                />
                <button
                  type="submit"
                  className="px-2 py-0.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-medium"
                >
                  Save
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setNameInput(app.name);
                    setIsEditing(false);
                  }}
                  className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-400 rounded text-xs"
                >
                  Cancel
                </button>
              </form>
            ) : (
              <div className="flex items-center gap-2">
                <h3 className="font-semibold text-slate-100 text-base truncate group-hover:text-emerald-400 transition-colors">
                  {app.name}
                </h3>
                <button
                  onClick={() => setIsEditing(true)}
                  title="Rename application"
                  className="text-slate-500 hover:text-slate-300 text-xs opacity-0 group-hover:opacity-100 transition-opacity"
                >
                  ✏️
                </button>
              </div>
            )}
            <div className="flex items-center gap-2 mt-0.5 text-xs text-slate-400">
              <span className="font-mono text-slate-300 truncate max-w-[200px]" title={app.target_url}>
                {app.target_url || app.hostname || "No target URL"}
              </span>
              {app.hostname && (
                <span className="text-[11px] px-1.5 py-0.2 rounded bg-slate-800/80 text-slate-400">
                  {app.hostname}
                </span>
              )}
            </div>
          </div>
          <div>
            {app.latest_rating ? (
              <RatingBadge rating={app.latest_rating} score={app.latest_score} />
            ) : (
              <span className="text-xs text-slate-500 px-2 py-0.5 rounded bg-slate-800 border border-slate-700/50">
                Not Scanned
              </span>
            )}
          </div>
        </div>

        {/* Status & Latest scan metadata */}
        <div className="grid grid-cols-2 gap-2 text-xs py-2.5 my-2 border-y border-slate-800/80 bg-slate-950/40 rounded-lg px-3">
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-medium">Last Scan</span>
            <span className="text-slate-300 font-mono">
              {fmtDate(app.latest_scan_date)}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-medium">Status</span>
            <StatusBadge status={app.latest_scan_status || "pending"} />
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-medium">Scan Duration</span>
            <span className="text-slate-300 font-mono">
              {fmtDuration(app.latest_scan_duration)}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase font-medium">Routes Discovered / Tested</span>
            <span className="text-slate-300 font-mono">
              {app.discovered_routes_count || 0} / {app.tested_routes_count || 0}
              <span className="text-slate-500 text-[10px] ml-1">
                ({app.coverage_percentage || 0}%)
              </span>
            </span>
          </div>
        </div>

        {/* Severity finding count pill badges */}
        <div className="my-3">
          <span className="text-[10px] uppercase text-slate-500 font-medium block mb-1.5">
            Active Findings Breakdown
          </span>
          <div className="flex flex-wrap gap-1.5 text-xs">
            <span
              className={`px-2 py-0.5 rounded font-mono font-semibold flex items-center gap-1 ${
                (counts.Critical || 0) > 0 ? "bg-red-500/20 text-red-300 border border-red-500/30" : "bg-slate-800/60 text-slate-500"
              }`}
            >
              <span className="text-[10px] uppercase">Crit</span> {counts.Critical || 0}
            </span>
            <span
              className={`px-2 py-0.5 rounded font-mono font-semibold flex items-center gap-1 ${
                (counts.High || 0) > 0 ? "bg-orange-500/20 text-orange-300 border border-orange-500/30" : "bg-slate-800/60 text-slate-500"
              }`}
            >
              <span className="text-[10px] uppercase">High</span> {counts.High || 0}
            </span>
            <span
              className={`px-2 py-0.5 rounded font-mono font-semibold flex items-center gap-1 ${
                (counts.Medium || 0) > 0 ? "bg-amber-500/20 text-amber-300 border border-amber-500/30" : "bg-slate-800/60 text-slate-500"
              }`}
            >
              <span className="text-[10px] uppercase">Med</span> {counts.Medium || 0}
            </span>
            <span
              className={`px-2 py-0.5 rounded font-mono font-semibold flex items-center gap-1 ${
                (counts.Low || 0) > 0 ? "bg-blue-500/20 text-blue-300 border border-blue-500/30" : "bg-slate-800/60 text-slate-500"
              }`}
            >
              <span className="text-[10px] uppercase">Low</span> {counts.Low || 0}
            </span>
          </div>
        </div>
      </div>

      {/* Action buttons */}
      <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-2">
          {hasLatestScan ? (
            <Link
              to={`/scan/${app.latest_scan_id}`}
              className="text-emerald-400 hover:text-emerald-300 font-medium inline-flex items-center gap-1"
            >
              View Results &rarr;
            </Link>
          ) : (
            <span className="text-slate-500">No results</span>
          )}

          <button
            onClick={() => onViewTrends(app)}
            className="text-slate-400 hover:text-slate-200 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700/80 transition-colors font-medium"
          >
            📈 Trends & History
          </button>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={handleRescanClick}
            disabled={isRescanning}
            title="Trigger a new scan for this website"
            className="px-2.5 py-1 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 rounded font-medium disabled:opacity-50 inline-flex items-center gap-1 transition-colors"
          >
            <span>🔄</span>
            <span>{isRescanning ? "Starting…" : "Rescan"}</span>
          </button>

          {hasLatestScan && (
            <a
              href={reportUrl(app.latest_scan_id)}
              title="Download latest PDF security report"
              className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-medium inline-flex items-center gap-1 transition-colors"
            >
              <span>📄</span>
              <span className="hidden sm:inline">PDF</span>
            </a>
          )}
        </div>
      </div>
    </div>
  );
}
