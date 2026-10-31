import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { listActivities } from "../../services/api";
import { Spinner, EmptyState } from "../ui";
import { fmtDate } from "../../utils/format";

export default function ActivityTimeline({ limit = 30 }) {
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listActivities({ limit })
      .then(setActivities)
      .catch((err) => console.error("Error loading activities:", err))
      .finally(() => setLoading(false));
  }, [limit]);

  const getEventIcon = (type, sev) => {
    switch (type) {
      case "scan_started":
        return { icon: "🚀", bg: "bg-blue-500/20 text-blue-400 border-blue-500/30" };
      case "scan_completed":
        return { icon: "✅", bg: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" };
      case "scan_failed":
        return { icon: "❌", bg: "bg-red-500/20 text-red-400 border-red-500/30" };
      case "vulns_detected":
        return { icon: "⚠️", bg: "bg-amber-500/20 text-amber-400 border-amber-500/30" };
      case "vuln_resolved":
        return { icon: "🎉", bg: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" };
      case "report_generated":
        return { icon: "📄", bg: "bg-purple-500/20 text-purple-400 border-purple-500/30" };
      case "status_updated":
        return { icon: "🔄", bg: "bg-sky-500/20 text-sky-400 border-sky-500/30" };
      default:
        return { icon: "📌", bg: "bg-slate-800 text-slate-300 border-slate-700" };
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <span>⏱</span> Recent Security Activity Timeline
          </h2>
          <p className="text-xs text-slate-400">
            Real-time audit log of scans, detected/resolved vulnerabilities, status updates, and reports.
          </p>
        </div>
      </div>

      {loading ? (
        <Spinner message="Loading activity timeline…" />
      ) : activities.length === 0 ? (
        <EmptyState
          icon="⏳"
          title="No Recent Activity"
          description="Security activities like scans, vulnerability detections, remediation updates, and PDF downloads will appear here."
        />
      ) : (
        <div className="relative pl-6 space-y-4 before:content-[''] before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
          {activities.map((a) => {
            const { icon, bg } = getEventIcon(a.event_type, a.severity);
            return (
              <div key={a.id} className="relative flex items-start gap-3 group">
                {/* Icon bubble */}
                <div
                  className={`-ml-6 mt-0.5 w-6 h-6 rounded-full border flex items-center justify-center text-xs shrink-0 z-10 ${bg}`}
                >
                  {icon}
                </div>

                {/* Content */}
                <div className="flex-1 bg-slate-900 border border-slate-800/80 rounded-xl p-3 shadow hover:border-slate-700/80 transition-colors">
                  <div className="flex flex-wrap items-center justify-between gap-1 text-xs mb-1">
                    <span className="font-semibold text-slate-200">{a.title}</span>
                    <span className="text-[11px] text-slate-500 font-mono">{fmtDate(a.timestamp)}</span>
                  </div>
                  <p className="text-xs text-slate-400">{a.description}</p>

                  {/* Context Links */}
                  <div className="mt-2 flex items-center gap-3 text-xs">
                    {a.scan_id && (
                      <Link
                        to={`/scan/${a.scan_id}`}
                        className="text-emerald-400 hover:text-emerald-300 font-medium inline-flex items-center gap-1"
                      >
                        <span>View Scan</span> &rarr;
                      </Link>
                    )}
                    {a.metadata?.target_url && (
                      <span className="text-slate-500 font-mono text-[11px] truncate max-w-xs">
                        {a.metadata.target_url}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

