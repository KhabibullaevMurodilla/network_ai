/** Drop-in replacement for lib/api.ts `api` that answers from the browser
 *  database (store.ts) instead of the FastAPI backend. Same method names and
 *  response shapes as backend/app/routers/dashboard.py + incidents.py, so the
 *  dashboard pages run unchanged. Anything that needs a server (alert
 *  delivery, API keys, team, billing, PDF report, SNMP physical map, device
 *  discovery, internet endpoints, Modbus events) answers "not available". */
import { getTables, save, audit, nextId, uuid, resetAll, type EventRow, type Tables } from "./store";
import { mitreForReason, mitreForOtReason } from "./mitre";
import { isPublic } from "./netdecode";

const RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const unsupported = (what: string) => (..._a: any[]): Promise<never> => Promise.reject(new Error(`${what} needs a server and is not available in local mode.`));
const withMitre = (e: EventRow) => { const { detector_scores, ...rest } = e; return { ...rest, mitre: mitreForReason(e.escalation_reason) }; };
const IP = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*$/;
const byNewest = (a: EventRow, b: EventRow) => b.created_at.localeCompare(a.created_at) || b.id - a.id;

function anchorMs(t: Tables): number {   // trends count back from the newest event if that is older than now
  let newest = 0;
  for (const e of t.events) { const m = Date.parse(e.created_at); if (m > newest) newest = m; }
  return newest > 0 && newest < Date.now() ? newest + 1000 : Date.now();
}

export const localApi = {
  getSummary: async () => {
    const t = await getTables();
    return {
      total_flows: t.flows.length, total_anomalies: t.events.length,
      critical_anomalies: t.events.filter((e) => e.severity === "critical").length,
      tenant_id: "local", role: "owner", focus: t.settings.focus, user_id: "local-user",
    };
  },
  getRecentAnomalies: async (srcIp?: string) => {
    const t = await getTables();
    return t.events.filter((e) => !srcIp || e.src_ip === srcIp).sort(byNewest).slice(0, 200).map(withMitre);
  },
  getAnomalyDetail: async (id: number | string) => {
    const t = await getTables();
    const e = t.events.find((x) => x.id === Number(id));
    if (!e) throw new Error("Event not found");
    const flow = t.flows.find((f) => f.id === e.flow_id) ?? null;
    const { detector_scores, ...rest } = e;
    return { ...rest, detector_scores, flow, mitre: mitreForReason(e.escalation_reason) };
  },
  updateTriage: async (id: number | string, status: string) => {
    const t = await getTables();
    const e = t.events.find((x) => x.id === Number(id));
    if (!e) throw new Error("Event not found");
    e.triage_status = status as EventRow["triage_status"];
    audit(t, "anomaly.triaged", { event_id: e.id, status });
    await save();
    return withMitre(e);
  },
  getTrend: async (days = 14, srcIp?: string) => {
    const t = await getTables();
    const since = anchorMs(t) - days * 86400000;
    const by = new Map<string, Record<string, number>>();
    for (const e of t.events) {
      if ((srcIp && e.src_ip !== srcIp) || Date.parse(e.created_at) < since) continue;
      const day = e.created_at.slice(0, 10);
      const row = by.get(day) ?? { low: 0, medium: 0, high: 0, critical: 0 };
      row[e.severity]++; by.set(day, row);
    }
    return [...by.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([date, c]) => ({ date, low: c.low, medium: c.medium, high: c.high, critical: c.critical }));
  },
  getEntities: async () => {
    const t = await getTables();
    const flowById = new Map(t.flows.map((f) => [f.id, f]));
    const m = new Map<string, { event_count: number; max_severity: string | null; protocols: Set<string>; last_seen: string | null }>();
    for (const e of t.events) {
      const src = e.src_ip || "unidentified";
      const x = m.get(src) ?? { event_count: 0, max_severity: null, protocols: new Set(), last_seen: null };
      x.event_count++;
      const p = flowById.get(e.flow_id)?.proto; if (p) x.protocols.add(p);
      if (!x.last_seen || e.created_at > x.last_seen) x.last_seen = e.created_at;
      if ((RANK[e.severity] ?? -1) > (RANK[x.max_severity ?? ""] ?? -1)) x.max_severity = e.severity;
      m.set(src, x);
    }
    return [...m.entries()].sort((a, b) => b[1].event_count - a[1].event_count)
      .map(([source, x]) => ({ source, event_count: x.event_count, max_severity: x.max_severity, protocols: [...x.protocols].sort(), last_seen: x.last_seen }));
  },
  getTopology: async () => {
    const t = await getTables();
    const maxNodes = 150;
    const flows = t.flows.filter((f) => f.src_ip && f.dst_ip).slice(-2000).reverse();
    const sev = new Map<string, { event_count: number; max_severity: string | null }>();
    for (const e of t.events) if (e.src_ip) {
      const n = sev.get(e.src_ip) ?? { event_count: 0, max_severity: null };
      n.event_count++; if ((RANK[e.severity] ?? -1) > (RANK[n.max_severity ?? ""] ?? -1)) n.max_severity = e.severity;
      sev.set(e.src_ip, n);
    }
    const ids = new Set<string>(), edges = new Map<string, number>();
    for (const f of flows) {
      const k = `${f.src_ip}\u0000${f.dst_ip}`;
      edges.set(k, (edges.get(k) ?? 0) + 1);
      ids.add(f.src_ip!); ids.add(f.dst_ip!);
      if (ids.size > maxNodes) break;
    }
    const dev = new Map<string, { role: string; hostname: string | null }>();
    for (const d of t.devices) for (const ip of d.ips?.length ? d.ips : d.ip ? [d.ip] : []) dev.set(ip, { role: d.role, hostname: d.hostname });
    const nodes = [...ids].map((id) => ({ id, event_count: sev.get(id)?.event_count ?? 0, max_severity: sev.get(id)?.max_severity ?? null, role: dev.get(id)?.role ?? null, hostname: dev.get(id)?.hostname ?? null }));
    const out = [...edges.entries()].map(([k, flow_count]) => { const [source, target] = k.split("\u0000"); return { source, target, flow_count }; })
      .filter((e) => ids.has(e.source) && ids.has(e.target));
    return { nodes, edges: out, truncated: ids.size >= maxNodes };
  },
  listExternal: async (sort: string = "bytes", flaggedOnly = false, limit = 200) => {
    const t = await getTables();
    const flowById = new Map(t.flows.map((f) => [f.id, f]));
    const flaggedByIp = new Map<string, number>();       // flagged events per public IP, across ports (as dashboard.py)
    for (const e of t.events) {
      const f = flowById.get(e.flow_id); if (!f) continue;
      for (const ip of [f.src_ip, f.dst_ip]) if (ip && isPublic(ip)) flaggedByIp.set(ip, (flaggedByIp.get(ip) ?? 0) + 1);
    }
    const SERVICES: Record<number, string> = { 80: "http", 443: "https", 53: "dns", 22: "ssh", 123: "ntp", 25: "smtp", 587: "smtp", 993: "imaps", 995: "pop3s", 143: "imap", 21: "ftp", 3389: "rdp", 5228: "fcm/play", 8080: "http-alt", 8443: "https-alt", 1883: "mqtt", 8883: "mqtts" };
    let out = t.external.map((r) => ({ ...r, service: SERVICES[r.remote_port] ?? String(r.remote_port), bytes_total: r.bytes_out + r.bytes_in, flagged: flaggedByIp.get(r.remote_ip) ?? 0 }));
    if (flaggedOnly) out = out.filter((r) => r.flagged > 0);
    const key: Record<string, (r: (typeof out)[number]) => number | string> = { bytes: (r) => r.bytes_total, flows: (r) => r.flows, recent: (r) => r.last_seen, flagged: (r) => r.flagged };
    const k = key[sort] ?? key.bytes;
    out.sort((a, b) => (k(a) < k(b) ? 1 : k(a) > k(b) ? -1 : 0));
    return out.slice(0, limit);
  },
  getPhysical: async () => ({ nodes: [] as any[], links: [] as any[] }),
  listDevices: async (role?: string) => {
    const t = await getTables();
    return t.devices.filter((d) => !role || d.role === role).sort((a, b) => b.last_seen.localeCompare(a.last_seen)).slice(0, 500);
  },
  connectStream: async (_cb: (e: any) => void): Promise<EventSource | null> => null,

  getMyTenant: async () => ({ id: "local", name: "This browser", alert_min_severity: "low" }),
  listSuppressions: async () => (await getTables()).suppressions,
  createSuppression: async (src_ip: string, reason?: string) => {
    if (!IP.test(src_ip)) throw new Error(`'${src_ip}' is not a valid IP address`);
    const t = await getTables();
    if (t.suppressions.some((s) => s.src_ip === src_ip)) throw new Error(`'${src_ip}' is already muted`);
    const row = { id: uuid(), src_ip, reason: reason ?? null, created_by: "local-user", created_at: new Date().toISOString() };
    t.suppressions.unshift(row); audit(t, "entity.suppressed", { src_ip }); await save();
    return row;
  },
  deleteSuppression: async (id: string) => {
    const t = await getTables();
    t.suppressions = t.suppressions.filter((s) => s.id !== id); audit(t, "entity.unsuppressed", { id }); await save();
    return { deleted: true };
  },
  setMyFocus: async (focus: string | null) => { const t = await getTables(); t.settings.focus = focus; await save(); return { focus }; },

  listIncidents: async (status?: string) => {
    const t = await getTables();
    return t.incidents.filter((i) => !status || i.status === status).sort((a, b) => b.last_seen.localeCompare(a.last_seen)).slice(0, 200);
  },
  getIncidentDetail: async (id: string) => {
    const t = await getTables();
    const inc = t.incidents.find((i) => i.id === id);
    if (!inc) throw new Error("Incident not found");
    const events = t.events.filter((e) => e.incident_id === id).sort(byNewest)
      .map(({ id, flow_id, score, severity, explanation, consensus_count, escalation_reason, triage_status, created_at }) =>
        ({ id, flow_id, score, severity, explanation, consensus_count, escalation_reason, triage_status, created_at }));
    return { ...inc, events };
  },
  updateIncidentStatus: async (id: string, status: string) => {
    const t = await getTables();
    const inc = t.incidents.find((i) => i.id === id);
    if (!inc) throw new Error("Incident not found");
    inc.status = status as "open" | "closed"; audit(t, "incident.status_changed", { incident_id: id, status }); await save();
    return inc;
  },

  getRecentOtEvents: async (flaggedOnly = false) => {
    const t = await getTables();
    return t.otEvents.filter((e) => !flaggedOnly || e.severity).sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id - a.id).slice(0, 200)
      .map((e) => ({ ...e, mitre: mitreForOtReason(e.reason) }));
  },
  exportData: async () => { const t = await getTables(); return { exported_at: new Date().toISOString(), mode: "local-browser", ...t }; },
  eraseData: async () => { await resetAll(); return { erased: true }; },
  getAuditLog: async () => (await getTables()).audit,

  // needs a server -- see header comment
  createApiKey: (_label: string, _scope?: string): Promise<never> => unsupported("API keys")(), listApiKeys: async () => [] as any[], revokeApiKey: unsupported("API keys"),
  listWebhooks: async () => [] as any[], createWebhook: unsupported("Alert delivery"), deleteWebhook: unsupported("Alert delivery"),
  updateAlertFloor: unsupported("Alert delivery"),
  listTeam: async () => [] as any[], inviteTeammate: unsupported("Team accounts"), updateTeammate: unsupported("Team accounts"), removeTeammate: unsupported("Team accounts"),
  listResponseActions: async () => [] as any[], createResponseAction: unsupported("Response actions"), deleteResponseAction: unsupported("Response actions"),
  fireResponseAction: unsupported("Response actions"),
  downloadReportPdf: unsupported("The PDF report"),
};
export type LocalApi = typeof localApi;
