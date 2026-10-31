export const SEVERITY_COLORS = {
  Critical: "#dc2626",
  High: "#ea580c",
  Medium: "#f59e0b",
  Low: "#3b82f6",
  Informational: "#64748b",
};

export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"];

export const RATING_COLORS = {
  STRONG: { bg: "bg-emerald-500/10", border: "border-emerald-500/40", text: "text-emerald-400", hex: "#10b981" },
  MEDIUM: { bg: "bg-amber-500/10", border: "border-amber-500/40", text: "text-amber-400", hex: "#f59e0b" },
  WEAK: { bg: "bg-rose-500/10", border: "border-rose-500/40", text: "text-rose-400", hex: "#ef4444" },
};

export const STATUS_COLORS = {
  completed: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  running: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  pending: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  failed: "bg-rose-500/20 text-rose-400 border-rose-500/30",
  cancelled: "bg-slate-700 text-slate-400 border-slate-600",
};

export const LIFECYCLE_STATUS_COLORS = {
  open: { bg: "bg-rose-500/15 text-rose-300 border-rose-500/30", label: "Open" },
  fixed: { bg: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30", label: "Fixed" },
  accepted_risk: { bg: "bg-amber-500/15 text-amber-300 border-amber-500/30", label: "Accepted Risk" },
  reopened: { bg: "bg-purple-500/15 text-purple-300 border-purple-500/30", label: "Reopened" },
};

export const fmtDate = (d) => {
  if (!d) return "—";
  try {
    const s = String(d).endsWith("Z") ? d : d + "Z";
    return new Date(s).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return String(d);
  }
};

export const fmtDuration = (sec) => {
  if (sec == null || sec === undefined) return "—";
  if (sec < 60) return `${Math.round(sec)}s`;
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  return `${m}m ${s}s`;
};

