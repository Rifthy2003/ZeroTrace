import axios from "axios";
const api = axios.create({ baseURL: import.meta.env.VITE_API_URL || "" });

export const createScan = (payload) => api.post("/api/scans", payload).then((r) => r.data);
export const listScans = (params = {}) => api.get("/api/scans", { params }).then((r) => r.data);
export const getScan = (id) => api.get(`/api/scans/${id}`).then((r) => r.data);
export const renameScan = (id, name) => api.patch(`/api/scans/${id}`, { name }).then((r) => r.data);
export const deleteScan = (id) => api.delete(`/api/scans/${id}`).then((r) => r.data);
export const restoreScan = (id) => api.post(`/api/scans/${id}/restore`).then((r) => r.data);
export const permanentDeleteScan = (id) => api.delete(`/api/scans/${id}/permanent`).then((r) => r.data);
export const bulkDeleteScans = (scan_ids) => api.post("/api/scans/bulk/delete", { scan_ids }).then((r) => r.data);
export const bulkRestoreScans = (scan_ids) => api.post("/api/scans/bulk/restore", { scan_ids }).then((r) => r.data);
export const bulkPermanentDeleteScans = (scan_ids) => api.post("/api/scans/bulk/permanent", { scan_ids }).then((r) => r.data);
export const getFindings = (id, params = {}) => api.get(`/api/scans/${id}/findings`, { params }).then((r) => r.data);
export const getSummary = (id) => api.get(`/api/scans/${id}/summary`).then((r) => r.data);
export const getSecurityPosture = (id) => api.get(`/api/scans/${id}/security-posture`).then((r) => r.data);
export const cancelScan = (id) => api.post(`/api/scans/${id}/cancel`).then((r) => r.data);
export const getOverview = () => api.get("/api/scans/stats/overview").then((r) => r.data);
export const getExecutiveOverview = () => api.get("/api/scans/stats/executive").then((r) => r.data);

export const listApplications = () => api.get("/api/applications").then((r) => r.data);
export const createApplication = (payload) => api.post("/api/applications", payload).then((r) => r.data);
export const getApplication = (id) => api.get(`/api/applications/${id}`).then((r) => r.data);
export const updateApplication = (id, payload) => api.patch(`/api/applications/${id}`, payload).then((r) => r.data);
export const associateTarget = (id, payload) => api.post(`/api/applications/${id}/associate`, null, { params: payload }).then((r) => r.data);
export const getApplicationTrends = (id) => api.get(`/api/applications/${id}/trends`).then((r) => r.data);
export const rescanApplication = (id) => api.post(`/api/applications/${id}/rescan`).then((r) => r.data);

export const updateFindingStatus = (id, payload) => api.patch(`/api/findings/${id}/status`, payload).then((r) => r.data);
export const getFinding = (id) => api.get(`/api/findings/${id}`).then((r) => r.data);
export const getRemediationFindings = (params = {}) => api.get("/api/findings/remediation-tracker", { params }).then((r) => r.data);
export const listActivities = (params = {}) => api.get("/api/activities", { params }).then((r) => r.data);

export const reportUrl = (id, type = "summary") => `${api.defaults.baseURL}/api/scans/${id}/report?type=${type}`;
export const summaryReportUrl = (id) => `${api.defaults.baseURL}/api/scans/${id}/report?type=summary`;
export const fullReportUrl = (id) => `${api.defaults.baseURL}/api/scans/${id}/report?type=full`;
export const completeBountyReportUrl = (id) => `${api.defaults.baseURL}/api/scans/${id}/report/bug-bounty`;
export const bountyReportUrl = (fid) => `${api.defaults.baseURL}/api/findings/${fid}/report`;
export const bountyMarkdownUrl = (fid) => `${api.defaults.baseURL}/api/findings/${fid}/markdown`;
export const getBountyMarkdown = (fid) => api.get(`/api/findings/${fid}/markdown`, { responseType: "text" }).then((r) => r.data);

export default api;
