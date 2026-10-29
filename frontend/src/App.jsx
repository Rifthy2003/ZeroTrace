import React from "react";
import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import NewScan from "./pages/NewScan.jsx";
import ScanProgress from "./pages/ScanProgress.jsx";
import ScanResults from "./pages/ScanResults.jsx";
import FindingDetails from "./pages/FindingDetails.jsx";
import ScanHistory from "./pages/ScanHistory.jsx";
import Reports from "./pages/Reports.jsx";
import Settings from "./pages/Settings.jsx";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan/new" element={<NewScan />} />
        <Route path="/scan/:id/progress" element={<ScanProgress />} />
        <Route path="/scan/:id" element={<ScanResults />} />
        <Route path="/scan/:id/finding/:fid" element={<FindingDetails />} />
        <Route path="/history" element={<ScanHistory />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}
