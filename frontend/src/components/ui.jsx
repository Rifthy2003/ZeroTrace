import React from "react";
import { SEVERITY_COLORS } from "../utils/format";

export const Card = ({ title, children, className = "" }) => (
  <div className={`bg-slate-900 border border-slate-800 rounded-lg p-4 ${className}`}>
    {title && <h3 className="text-slate-300 text-sm font-semibold mb-3 uppercase tracking-wide">{title}</h3>}
    {children}
  </div>
);
export const Stat = ({ label, value, color }) => (
  <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
    <div className="text-xs text-slate-400 uppercase">{label}</div>
    <div className="text-2xl font-bold" style={{ color: color || "#e2e8f0" }}>{value ?? 0}</div>
  </div>
);
export const SeverityBadge = ({ severity }) => (
  <span className="px-2 py-0.5 rounded text-xs font-semibold text-white" style={{ background: SEVERITY_COLORS[severity] }}>{severity}</span>
);
export const Spinner = () => <div className="text-slate-400 text-sm">Loading…</div>;
