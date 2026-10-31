import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listScans } from "../services/api";
import { Card, Spinner, StatusBadge, Pagination, EmptyState } from "../components/ui";
import { fmtDate, fmtDuration } from "../utils/format";

export default function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 12;

  const fetchScans = () => {
    setLoading(true);
    setError(null);
    listScans()
      .then((data) => {
        setScans(data || []);
      })
      .catch((err) => {
        console.error("Failed to load scans:", err);
        setError(err.message || "Failed to load scan history from backend.");
      })
      .finally(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const filteredScans = scans.filter((s) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    const app = (s.application_name || "").toLowerCase();
    const host = (s.hostname || "").toLowerCase();
    const url = (s.target_url || "").toLowerCase();
    return app.includes(q) || host.includes(q) || url.includes(q);
  });

  const totalPages = Math.ceil(filteredScans.length / pageSize) || 1;
  const paginatedScans = filteredScans.slice((page - 1) * pageSize, page * pageSize);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[350px] space-y-3">
        <Spinner />
        <span className="text-xs text-slate-400 font-medium">Loading scan audit logs...</span>
      </div>
    );
  }

  if (error) {
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
            onClick={fetchScans}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
          >
            Retry Connection
          </button>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-4 max-w-6xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Scan History</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Audit log of all vulnerability scans across targets. Total scans: {scans.length}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Search scans by URL or host..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 w-56"
          />
          <Link
            to="/scan/new"
            className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold whitespace-nowrap"
          >
            + New Scan
          </Link>
        </div>
      </div>

      <Card>
        {filteredScans.length === 0 ? (
          <EmptyState
            icon="📋"
            title={scans.length === 0 ? "No Scans Yet" : "No Matching Scans Found"}
            description={
              scans.length === 0
                ? "Start your first web security scan to see history here."
                : "Try adjusting your search criteria."
            }
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-slate-400 text-xs uppercase border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">Date</th>
                    <th className="py-2.5 px-3">Target / Website</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3">Routes Discovered / Tested</th>
                    <th className="py-2.5 px-3">Findings</th>
                    <th className="py-2.5 px-3">Duration</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {paginatedScans.map((s) => (
                    <tr key={s.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-2.5 px-3 font-mono text-xs text-slate-300">
                        {fmtDate(s.created_at)}
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="font-medium text-slate-200">
                          {s.application_name || s.hostname || "Target"}
                        </div>
                        <div className="font-mono text-slate-400 text-xs truncate max-w-xs">
                          {s.target_url || s.hostname || "—"}
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <StatusBadge status={s.status} />
                      </td>
                      <td className="py-2.5 px-3 font-mono text-xs">
                        {s.urls_discovered || 0} / {s.urls_scanned || 0}
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`font-mono font-bold ${
                            s.findings_count > 0 ? "text-amber-400" : "text-emerald-400"
                          }`}
                        >
                          {s.findings_count || 0}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-xs text-slate-400">
                        {fmtDuration(s.duration_seconds)}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <Link
                          className="text-emerald-400 hover:text-emerald-300 font-medium text-xs inline-flex items-center gap-1"
                          to={s.status === "completed" ? `/scan/${s.id}` : `/scan/${s.id}/progress`}
                        >
                          <span>Open</span> &rarr;
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {totalPages > 1 && (
              <div className="mt-4">
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
    </div>
  );
}
