import axios from "axios";
const api = axios.create({ baseURL: import.meta.env.VITE_API_URL || "" });

export const createScan = (payload) => api.post("/api/scans", payload).then((r) => r.data);
export const listScans = () => api.get("/api/scans").then((r) => r.data);
export const getScan = (id) => api.get(`/api/scans/${id}`).then((r) => r.data);
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
export const getRemediationFindings = (params = {}) => api.get("/api/findings/remediation-tracker", { params }).then((r) => r.data);
export const listActivities = (params = {}) => api.get("/api/activities", { params }).then((r) => r.data);

export const reportUrl = (id) => `${api.defaults.baseURL}/api/scans/${id}/report`;
export default api;
