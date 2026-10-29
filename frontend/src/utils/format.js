export const SEVERITY_COLORS = { Critical: "#7f1d1d", High: "#dc2626", Medium: "#ea580c", Low: "#ca8a04", Informational: "#2563eb" };
export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"];
export const fmtDate = (d) => (d ? new Date(d + "Z").toLocaleString() : "—");
