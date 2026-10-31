import React from "react";
import { SEVERITY_COLORS, RATING_COLORS, STATUS_COLORS, LIFECYCLE_STATUS_COLORS } from "../utils/format";

export const Card = ({ title, children, className = "", headerRight }) => (
  <div className={`bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg ${className}`}>
    {(title || headerRight) && (
      <div className="flex items-center justify-between mb-4 pb-2 border-b border-slate-800/80">
        {title && <h3 className="text-slate-200 text-sm font-semibold tracking-wide flex items-center gap-2">{title}</h3>}
        {headerRight && <div>{headerRight}</div>}
      </div>
    )}
    {children}
  </div>
);

export const Stat = ({ label, value, color, sublabel, icon }) => (
  <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow flex flex-col justify-between">
    <div className="flex items-center justify-between text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">
      <span>{label}</span>
      {icon && <span className="text-slate-500 text-sm">{icon}</span>}
    </div>
    <div className="text-2xl font-bold font-mono tracking-tight" style={{ color: color || "#f1f5f9" }}>
      {value ?? 0}
    </div>
    {sublabel && <div className="text-[11px] text-slate-500 mt-1">{sublabel}</div>}
  </div>
);

export const SeverityBadge = ({ severity }) => (
  <span
    className="px-2 py-0.5 rounded text-xs font-semibold text-white inline-block shadow-sm"
    style={{ background: SEVERITY_COLORS[severity] || "#64748b" }}
  >
    {severity}
  </span>
);

export const RatingBadge = ({ rating, score }) => {
  const conf = RATING_COLORS[rating] || { bg: "bg-slate-800", border: "border-slate-700", text: "text-slate-300" };
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-xs font-semibold uppercase tracking-wider ${conf.bg} ${conf.border} ${conf.text}`}>
      <span>🛡</span>
      <span>{rating || "UNKNOWN"}</span>
      {score != null && <span className="font-mono opacity-90 font-bold">({Math.round(score)})</span>}
    </span>
  );
};

export const StatusBadge = ({ status }) => {
  const cls = STATUS_COLORS[status] || "bg-slate-800 text-slate-400 border-slate-700";
  return (
    <span className={`px-2 py-0.5 rounded-full text-[11px] font-medium border uppercase tracking-wider ${cls}`}>
      {status || "unknown"}
    </span>
  );
};

export const LifecycleBadge = ({ status }) => {
  const conf = LIFECYCLE_STATUS_COLORS[status] || { bg: "bg-slate-800 text-slate-400 border-slate-700", label: status || "Open" };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium border ${conf.bg}`}>
      {conf.label}
    </span>
  );
};

export const EmptyState = ({ icon = "📂", title = "No data found", description = "No records to display yet.", action }) => (
  <div className="py-12 px-4 text-center border border-dashed border-slate-800 rounded-xl bg-slate-900/40">
    <div className="text-3xl mb-2">{icon}</div>
    <div className="text-slate-200 font-semibold text-base mb-1">{title}</div>
    <div className="text-slate-400 text-sm max-w-sm mx-auto mb-4">{description}</div>
    {action && <div>{action}</div>}
  </div>
);

export const Pagination = ({ currentPage, totalPages, onPageChange }) => {
  if (totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-between pt-3 border-t border-slate-800 text-xs text-slate-400">
      <div>
        Page <span className="text-slate-200 font-semibold">{currentPage}</span> of{" "}
        <span className="text-slate-200 font-semibold">{totalPages}</span>
      </div>
      <div className="flex gap-1">
        <button
          disabled={currentPage === 1}
          onClick={() => onPageChange(currentPage - 1)}
          className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800"
        >
          Previous
        </button>
        <button
          disabled={currentPage >= totalPages}
          onClick={() => onPageChange(currentPage + 1)}
          className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:hover:bg-slate-800"
        >
          Next
        </button>
      </div>
    </div>
  );
};

export const Spinner = ({ message = "Loading…" }) => (
  <div className="flex items-center justify-center p-8 gap-3 text-slate-400 text-sm">
    <svg className="animate-spin h-5 w-5 text-emerald-500" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
    </svg>
    <span>{message}</span>
  </div>
);

