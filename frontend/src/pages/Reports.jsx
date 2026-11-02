import React, { useEffect, useState } from "react";
import { listScans, summaryReportUrl, fullReportUrl, shortReportUrl, completeBountyReportUrl } from "../services/api";
import { Card, Spinner } from "../components/ui";
import { fmtDate } from "../utils/format";

export default function Reports() {
  const [scans, setScans] = useState(null);

  useEffect(() => {
    listScans().then((s) => setScans(s.filter((x) => x.status === "completed")));
  }, []);

  if (!scans) return <Spinner />;

  return (
    <div className="space-y-4 max-w-5xl">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Assessment Reports</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Download concise executive security summaries (5–15 pages) or comprehensive technical assessment audits.
          </p>
        </div>
      </div>

      <Card>
        {scans.length === 0 ? (
          <div className="text-slate-400 text-sm py-4 text-center">No completed scans yet. Run a scan to generate reports.</div>
        ) : (
          <div className="divide-y divide-slate-800">
            {scans.map((s) => (
              <div key={s.id} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-sm">
                <div>
                  <div className="font-semibold text-slate-200 flex items-center gap-2">
                    <span>{s.target_url || s.hostname || "Target Application"}</span>
                    {s.application_name && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                        {s.application_name}
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-slate-400 mt-0.5 flex flex-wrap gap-3">
                    <span>Date: {fmtDate(s.created_at)}</span>
                    <span>Findings: <b className="text-slate-300">{s.findings_count}</b></span>
                    <span>Endpoints: {s.urls_scanned || 0}/{s.urls_discovered || 0}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <a
                    href={shortReportUrl(s.id)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-colors shadow-sm"
                    title="Download Short Report (4–6 Page PDF)"
                  >
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    Short Report (PDF)
                  </a>
                  <a
                    href={summaryReportUrl(s.id)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white transition-colors shadow-sm"
                    title="Concise 5-15 page Executive & Technical Security Summary"
                  >
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    Security Summary (PDF)
                  </a>
                  <a
                    href={fullReportUrl(s.id)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
                    title="Full Comprehensive Technical PDF with raw payloads and logs"
                  >
                    <svg className="w-3.5 h-3.5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    Full Technical (PDF)
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
