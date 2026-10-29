import React, { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie, LineChart, Line, CartesianGrid } from "recharts";
import { getOverview, listScans } from "../services/api";
import { Card, Stat, Spinner } from "../components/ui";
import { SEVERITIES, SEVERITY_COLORS } from "../utils/format";

export default function Dashboard() {
  const [ov, setOv] = useState(null);
  const [scans, setScans] = useState([]);
  useEffect(() => { getOverview().then(setOv); listScans().then(setScans); }, []);
  if (!ov) return <Spinner />;
  const sevData = SEVERITIES.map((s) => ({ name: s, value: ov.by_severity[s] || 0 }));
  const typeData = Object.entries(ov.by_type).map(([name, value]) => ({ name, value }));
  const history = [...scans].reverse().map((s, i) => ({ name: `#${i + 1}`, findings: s.findings_count, urls: s.urls_discovered }));
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat label="Total Scans" value={ov.total_scans} />
        <Stat label="URLs Scanned" value={ov.urls_scanned} />
        <Stat label="Endpoints Found" value={ov.endpoints_found} />
        <Stat label="Critical" value={ov.by_severity.Critical} color={SEVERITY_COLORS.Critical} />
        <Stat label="High" value={ov.by_severity.High} color={SEVERITY_COLORS.High} />
        <Stat label="Medium" value={ov.by_severity.Medium} color={SEVERITY_COLORS.Medium} />
        <Stat label="Low" value={ov.by_severity.Low} color={SEVERITY_COLORS.Low} />
        <Stat label="Informational" value={ov.by_severity.Informational} color={SEVERITY_COLORS.Informational} />
      </div>
      <div className="grid md:grid-cols-2 gap-4">
        <Card title="Findings by severity">
          <ResponsiveContainer width="100%" height={220}>
            <PieChart><Pie data={sevData} dataKey="value" nameKey="name" outerRadius={80} label>
              {sevData.map((d) => <Cell key={d.name} fill={SEVERITY_COLORS[d.name]} />)}
            </Pie><Tooltip /></PieChart>
          </ResponsiveContainer>
        </Card>
        <Card title="Findings by vulnerability type">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={typeData} layout="vertical"><XAxis type="number" stroke="#94a3b8" /><YAxis type="category" dataKey="name" width={150} stroke="#94a3b8" fontSize={11} /><Tooltip /><Bar dataKey="value" fill="#10b981" /></BarChart>
          </ResponsiveContainer>
        </Card>
        <Card title="Scan history">
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={history}><CartesianGrid stroke="#1e293b" /><XAxis dataKey="name" stroke="#94a3b8" /><YAxis stroke="#94a3b8" /><Tooltip /><Line dataKey="findings" stroke="#f97316" /></LineChart>
          </ResponsiveContainer>
        </Card>
        <Card title="Endpoint statistics">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={history}><XAxis dataKey="name" stroke="#94a3b8" /><YAxis stroke="#94a3b8" /><Tooltip /><Bar dataKey="urls" fill="#3b82f6" /></BarChart>
          </ResponsiveContainer>
        </Card>
      </div>
    </div>
  );
}
