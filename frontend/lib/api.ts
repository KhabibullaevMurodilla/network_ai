import { supabase } from "./supabase";
import { localApi } from "./local/localApi";

// An empty/unset NEXT_PUBLIC_API_URL used to make every call go to the
// frontend's own origin (Next.js then answers 404 for /dashboard/summary).
// Fall back to the local backend and drop any trailing slash.
const API_BASE = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/+$/, "");

async function authedFetch(path: string, options: RequestInit = {}) {
  const { data } = await supabase.auth.getSession();
  const token = data.session?.access_token;
  if (!token) throw new Error("Not authenticated");

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });
  if (!res.ok) throw new Error(`API error ${res.status}: ${await res.text()}`);
  return res.json();
}

// Public, unauthenticated demo endpoints (v6.3) -- no session, no bearer
// token, deliberately a separate object so it's never accidentally reused
// against a real tenant's authenticated routes.
// Static mode (GitHub Pages): no backend exists, so the demo reads JSON
// snapshots saved at build time by backend/scripts/export_demo_snapshot.py.
const STATIC_DEMO = process.env.NEXT_PUBLIC_STATIC_DEMO === "1";
const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH || "";
const STATIC_FILES: Record<string, string> = {
  "/demo/summary": "summary", "/demo/anomalies/recent": "anomalies",
  "/demo/entities": "entities", "/demo/trend": "trend",
};

async function demoFetch(path: string) {
  if (STATIC_DEMO) {
    const file = STATIC_FILES[path.split("?")[0]];
    if (!file) throw new Error(`No static snapshot for ${path}`);
    const r = await fetch(`${BASE_PATH}/demo-data/${file}.json`);
    if (!r.ok) throw new Error(`Snapshot ${file}.json not found (${r.status})`);
    return r.json();
  }
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`API error ${res.status}: ${await res.text()}`);
  return res.json();
}

export const demoApi = {
  getSummary: () => demoFetch("/demo/summary"),
  getRecentAnomalies: () => demoFetch("/demo/anomalies/recent"),
  getEntities: () => demoFetch("/demo/entities"),
  getTrend: (days: number = 14) => demoFetch(`/demo/trend?days=${days}`),
};

const remoteApi = {
  getSummary: () => authedFetch("/dashboard/summary"),
  getRecentAnomalies: (srcIp?: string) =>
    authedFetch(`/dashboard/anomalies/recent${srcIp ? `?src_ip=${encodeURIComponent(srcIp)}` : ""}`),
  getAnomalyDetail: (id: number | string) => authedFetch(`/dashboard/anomalies/${id}`),
  updateTriage: (id: number | string, status: string) =>
    authedFetch(`/dashboard/anomalies/${id}/triage?status=${status}`, { method: "PATCH" }),
  getTrend: (days: number = 14, srcIp?: string) =>
    authedFetch(`/dashboard/trend?days=${days}${srcIp ? `&src_ip=${encodeURIComponent(srcIp)}` : ""}`),
  getEntities: () => authedFetch("/dashboard/entities"),
  getTopology: () => authedFetch("/dashboard/topology"),
  listExternal: (sort = "bytes", flaggedOnly = false) => authedFetch(`/dashboard/external?sort=${sort}${flaggedOnly ? "&flagged_only=true" : ""}`),
  getPhysical: () => authedFetch("/dashboard/physical"),
  listDevices: (role?: string) => authedFetch(`/dashboard/devices${role ? `?role=${encodeURIComponent(role)}` : ""}`),

  // Server-Sent Events can't set an Authorization header, so the session
  // token travels as a query param for this one connection -- resolves the
  // current Supabase session itself since EventSource construction can't
  // await a promise.
  connectStream: async (onEvent: (event: any) => void): Promise<EventSource | null> => {
    const { data } = await supabase.auth.getSession();
    const token = data.session?.access_token;
    if (!token) return null;
    const es = new EventSource(`${API_BASE}/dashboard/stream?token=${encodeURIComponent(token)}`);
    es.onmessage = (e) => {
      try {
        onEvent(JSON.parse(e.data));
      } catch {
        /* heartbeat or malformed frame -- ignore */
      }
    };
    return es;
  },

  createApiKey: (label: string, scope: string = "ingest") =>
    authedFetch("/tenants/api-keys", { method: "POST", body: JSON.stringify({ label, scope }) }),
  listApiKeys: () => authedFetch("/tenants/api-keys"),
  revokeApiKey: (id: string) => authedFetch(`/tenants/api-keys/${id}`, { method: "DELETE" }),
  getMyTenant: () => authedFetch("/tenants/me"),

  listWebhooks: () => authedFetch("/webhooks"),
  createWebhook: (opts: { channel_type: string; url?: string; email_to?: string; min_severity?: string }) =>
    authedFetch("/webhooks", { method: "POST", body: JSON.stringify(opts) }),
  deleteWebhook: (id: string) => authedFetch(`/webhooks/${id}`, { method: "DELETE" }),

  listSuppressions: () => authedFetch("/dashboard/suppressions"),
  createSuppression: (src_ip: string, reason?: string) =>
    authedFetch("/dashboard/suppressions", { method: "POST", body: JSON.stringify({ src_ip, reason }) }),
  deleteSuppression: (id: string) => authedFetch(`/dashboard/suppressions/${id}`, { method: "DELETE" }),
  updateAlertFloor: (alert_min_severity: string) =>
    authedFetch("/tenants/me/alert-settings", { method: "PATCH", body: JSON.stringify({ alert_min_severity }) }),

  // team (v6.4)
  listTeam: () => authedFetch("/team"),
  inviteTeammate: (email: string, role: string, focus: string | null) =>
    authedFetch("/team/invite", { method: "POST", body: JSON.stringify({ email, role, focus }) }),
  updateTeammate: (id: string, patch: { role?: string; focus?: string | null }) =>
    authedFetch(`/team/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  removeTeammate: (id: string) => authedFetch(`/team/${id}`, { method: "DELETE" }),
  setMyFocus: (focus: string | null) => authedFetch("/team/me/focus", { method: "PATCH", body: JSON.stringify({ focus }) }),
  fireResponseAction: (actionId: string, eventId: number) =>
    authedFetch(`/response-actions/${actionId}/fire`, { method: "POST", body: JSON.stringify({ event_id: eventId }) }),

  exportData: () => authedFetch("/privacy/export"),
  eraseData: () => authedFetch("/privacy/erase", { method: "DELETE" }),
  getAuditLog: () => authedFetch("/privacy/audit-log"),

  listIncidents: (status?: string) =>
    authedFetch(`/dashboard/incidents${status ? `?status=${status}` : ""}`),
  getIncidentDetail: (id: string) => authedFetch(`/dashboard/incidents/${id}`),
  updateIncidentStatus: (id: string, status: string) =>
    authedFetch(`/dashboard/incidents/${id}/status?status=${status}`, { method: "PATCH" }),

  listResponseActions: () => authedFetch("/response-actions"),
  createResponseAction: (trigger: string, action_type: string, target_url: string) =>
    authedFetch("/response-actions", { method: "POST", body: JSON.stringify({ trigger, action_type, target_url }) }),
  deleteResponseAction: (id: string) => authedFetch(`/response-actions/${id}`, { method: "DELETE" }),

  getRecentOtEvents: (flaggedOnly: boolean = false) =>
    authedFetch(`/dashboard/ot-events/recent${flaggedOnly ? "?flagged_only=true" : ""}`),

  downloadReportPdf: async (days: number = 30) => {
    const { data } = await supabase.auth.getSession();
    const token = data.session?.access_token;
    if (!token) throw new Error("Not authenticated");
    const res = await fetch(`${API_BASE}/reports/pdf?days=${days}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error(`API error ${res.status}: ${await res.text()}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `network-ai-report-${days}d.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  },
};

// Local mode (NEXT_PUBLIC_LOCAL_MODE=1): no backend and no login; the dashboard
// reads a database kept in this browser (lib/local/store.ts).
export const LOCAL_MODE = process.env.NEXT_PUBLIC_LOCAL_MODE === "1";
export const api: typeof remoteApi = LOCAL_MODE ? (localApi as unknown as typeof remoteApi) : remoteApi;
