/** Import pipeline for local mode: flows -> in-browser ensemble (engine.ts)
 *  -> per-source learning period, baseline drift and burst rules (ported from
 *  backend/app/ml/engine.py) -> incident correlation (core/incidents.py) ->
 *  rows in the browser database.
 *
 *  Differences from the server engine, on purpose and stated:
 *  - Detectors are refit on each import's flows (batch), not kept running.
 *  - Per-source baselines DO persist between imports (that is the learning period).
 *  - Baselines use log1p of the 7 raw features (the server uses the scaler's output,
 *    which would shift with every import here).
 *  - Burst needs flow timestamps (pcap, or a ts/timestamp CSV column); without them it is skipped. */
import { analyze, type Progress, type Analysis } from "./engine";
import { NUMERIC_FEATURES, type Flow, type Severity } from "./types";
import { parseCapture } from "./pcap";
import { parseCsv } from "./csv";
import { discoverDevices } from "./discovery";
import { extractEndpoints } from "./endpoints";
import { parseModbus } from "./modbus";
import { evaluateOt, emptyOtState, type OtState } from "./otRules";
import { getTables, save, nextId, uuid, audit, MAX_STORED_FLOWS, type Tables, type EventRow, type FlowRow, type BaselineState, type IncidentRow, type DeviceDbRow, type ExternalDbRow, type OtDbRow } from "./store";

const ORDER: (Severity | null)[] = [null, "low", "medium", "high", "critical"];
const BURST_WINDOW_S = 60, BURST_THRESHOLD = 5, BURST_MIN_SHARE = 0.3;
const BASELINE_MIN_SAMPLES = 20, BASELINE_Z = 5;
const INCIDENT_WINDOW_MS = 30 * 60 * 1000;

const up = (s: Severity | null, n: number): Severity | null => ORDER[Math.min(ORDER.indexOf(s) + n, 4)];
const maxSev = (a: string | null, b: string | null) => (ORDER.indexOf(b as Severity) > ORDER.indexOf(a as Severity) ? b : a);

function features(f: Flow): number[] { return NUMERIC_FEATURES.map((k) => Math.log1p(Math.max(0, f[k]))); }
function deviation(b: BaselineState, x: number[]): number | null {
  if (b.n < BASELINE_MIN_SAMPLES) return null;
  let m = 0;
  for (let j = 0; j < x.length; j++) {
    const std = Math.sqrt(Math.max(b.m2[j] / Math.max(b.n - 1, 1), 1e-6));
    m = Math.max(m, Math.abs((x[j] - b.mean[j]) / std));
  }
  return m;
}
function update(b: BaselineState, x: number[]) {
  b.n++;
  for (let j = 0; j < x.length; j++) { const d = x[j] - b.mean[j]; b.mean[j] += d / b.n; b.m2[j] += d * (x[j] - b.mean[j]); }
}

export interface ImportResult {
  total: number; stored: number; flagged: number; learning: number; sampledFrom: number | null;
  bySeverity: Record<Severity, number>; incidentsTouched: number; burstSkipped: boolean; detectors: number;
}

export async function importFlows(
  flows: Flow[], source: string, opts: { sensitivity?: number; progress?: Progress; now?: number; learningMin?: number; contextFlows?: Flow[] } = {},
): Promise<ImportResult> {
  const t = await getTables();
  // contextFlows: earlier flows the detectors are fitted alongside (live capture), never re-judged or re-stored
  const ctx = opts.contextFlows ?? [];
  const skip = ctx.length;
  const a: Analysis = await analyze(skip ? [...ctx, ...flows] : flows, opts.sensitivity ?? 10, opts.progress);
  if (a.sampledFrom) throw new Error("context + batch exceeded the analysis size limit");
  const now = opts.now ?? Date.now();
  const learningMin = opts.learningMin ?? t.settings.learningMin;
  const haveTs = a.scored.slice(skip).every((r) => r.flow.ts != null);

  // process in time order when we have it (stable on original order)
  const order = a.scored.map((_, i) => i).filter((i) => i >= skip);
  if (haveTs) order.sort((p, q) => (a.scored[p].flow.ts! - a.scored[q].flow.ts!) || p - q);

  const flowWin = new Map<string, number[]>(), flagWin = new Map<string, number[]>();
  const sev: (Severity | null)[] = a.scored.map((r) => r.severity);
  const reason: (string | null)[] = a.scored.map((r) => r.reason);
  const consensus: number[] = a.scored.map((r) => r.consensus);
  const bz: (number | null)[] = a.scored.map(() => null);
  const learning: boolean[] = a.scored.map(() => false);

  for (const i of order) {
    const r = a.scored[i];
    const entity = r.flow.src_ip || "unidentified";
    const base = (t.baselines[entity] ??= { n: 0, mean: new Array(NUMERIC_FEATURES.length).fill(0), m2: new Array(NUMERIC_FEATURES.length).fill(0) });
    const x = features(r.flow);
    if (base.n < learningMin) {                       // learning period: learn, judge nothing
      update(base, x);
      learning[i] = true; sev[i] = null; consensus[i] = 0; reason[i] = null;
      continue;
    }
    const z = deviation(base, x);
    bz[i] = z;
    if (z != null && z >= BASELINE_Z) {
      const promoted = sev[i] ? up(sev[i], 1) : "medium";
      if (sev[i] == null || ORDER.indexOf(promoted) > ORDER.indexOf(sev[i])) { sev[i] = promoted; reason[i] = "entity_baseline_drift"; }
    }
    update(base, x);
    if (haveTs) {
      const now_ = r.flow.ts!, cutoff = now_ - BURST_WINDOW_S;
      const fw = flowWin.get(entity) ?? []; fw.push(now_); while (fw[0] < cutoff) fw.shift(); flowWin.set(entity, fw);
      if (sev[i] != null) {
        const gw = flagWin.get(entity) ?? []; gw.push(now_); while (gw[0] < cutoff) gw.shift(); flagWin.set(entity, gw);
        if (gw.length >= BURST_THRESHOLD && gw.length / Math.max(fw.length, 1) >= BURST_MIN_SHARE && sev[i] !== "critical") {
          sev[i] = "critical"; reason[i] = "entity_burst";
        }
      }
    }
  }

  // ---- store flows (all) and events (flagged only) ----
  const bySeverity: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  const flowRows: FlowRow[] = [], events: EventRow[] = [];
  const receivedAt = new Date(now).toISOString();
  a.scored.forEach((r, i) => {
    if (i < skip) return;
    const f = r.flow;
    const fid = nextId(t);
    flowRows.push({
      id: fid, src_ip: f.src_ip ?? null, dst_ip: f.dst_ip ?? null, proto: f.proto, dur: f.dur, tot_pkts: f.tot_pkts,
      src_bytes: f.src_bytes, dst_bytes: f.dst_bytes, rate: f.rate, load: f.load, s_ttl: f.s_ttl,
      ts: f.ts ?? null, received_at: receivedAt, ...(learning[i] ? { learning: true } : {}),
    });
    if (!sev[i]) return;
    bySeverity[sev[i]!]++;
    const createdMs = f.ts != null ? Math.round(f.ts * 1000) : now + i;     // keep order within a batch
    events.push({
      id: nextId(t), flow_id: fid, detector: "ECOD", score: r.ecodScore, is_anomaly: true, severity: sev[i]!,
      explanation: r.explanation.map((e) => ({ feature: e.feature, z_score: e.z })),
      consensus_count: consensus[i], escalation_reason: reason[i], entity_baseline_z: bz[i],
      src_ip: f.src_ip ?? null, triage_status: "new", created_at: new Date(createdMs).toISOString(), incident_id: null,
      detector_scores: [
        { detector: "ECOD", score: r.ecodScore, is_anomaly: r.votes.ecod },
        { detector: "IsolationForest", score: null, is_anomaly: r.votes.iforest },
        { detector: "LOF", score: null, is_anomaly: r.votes.lof },
        ...(a.detectors === 4 ? [{ detector: "HalfSpaceTrees", score: null, is_anomaly: r.votes.hst }] : []),
      ],
    });
  });

  const touched = correlate(t, events);
  t.flows.push(...flowRows);
  t.events.push(...events);
  prune(t);
  const nLearning = learning.filter(Boolean).length;
  t.settings.imports.unshift({ at: receivedAt, source, flows: a.total - skip, flagged: events.length, learning: nLearning });
  t.settings.imports.length = Math.min(t.settings.imports.length, 50);
  audit(t, "data.imported", { source, flows: a.total, flagged: events.length });
  await save();
  return { total: a.total - skip, stored: flowRows.length, flagged: events.length, learning: nLearning, sampledFrom: a.sampledFrom, bySeverity, incidentsTouched: touched, burstSkipped: !haveTs, detectors: a.detectors };
}

/** Same rule as backend/app/core/incidents.py: events from one source within
 *  30 minutes of an open incident's last activity join it; otherwise a new one. */
type Correlatable = { src_ip: string | null; created_at: string; severity: string | null; incident_id: string | null };
function correlate(t: Tables, events: Correlatable[]): number {
  const touched = new Set<string>();
  const sorted = [...events].sort((p, q) => p.created_at.localeCompare(q.created_at));
  for (const ev of sorted) {
    const entity = ev.src_ip ?? "unidentified";
    const ms = Date.parse(ev.created_at);
    const cand = t.incidents
      .filter((i) => i.status === "open" && (i.src_ip ?? "unidentified") === entity && Date.parse(i.last_seen) >= ms - INCIDENT_WINDOW_MS)
      .sort((p, q) => q.last_seen.localeCompare(p.last_seen))[0];
    let inc: IncidentRow;
    if (cand) {
      inc = cand;
      inc.event_count++; inc.severity = maxSev(inc.severity, ev.severity ?? null);
      if (ev.created_at > inc.last_seen) inc.last_seen = ev.created_at;
    } else {
      inc = { id: uuid(), tenant_id: "local", src_ip: ev.src_ip, title: `Flagged activity from ${entity}`, status: "open", severity: ev.severity ?? null, event_count: 1, first_seen: ev.created_at, last_seen: ev.created_at };
      t.incidents.push(inc);
    }
    ev.incident_id = inc.id; touched.add(inc.id);
  }
  return touched.size;
}

/** Keep the database bounded: drop oldest flows that no event points at. */
function prune(t: Tables) {
  if (t.flows.length <= MAX_STORED_FLOWS) return;
  const keep = new Set(t.events.map((e) => e.flow_id));
  let excess = t.flows.length - MAX_STORED_FLOWS;
  t.flows = t.flows.filter((f) => (excess > 0 && !keep.has(f.id) ? (excess--, false) : true));
}

/* ------------------------------------------------------------------ captures
 * A capture (.pcap/.pcapng) feeds four things, as on the server: flow anomaly
 * detection, passive device discovery, internet endpoints and Modbus/TCP OT rules.
 * Python's per-tenant merge rules (core/devices.py, core/external.py) are mirrored below. */
const ROLE_PRIORITY = ["switch", "router", "access_point", "gateway", "dhcp_server", "dns_server", "server", "client", "unknown"];   // same order as discovery.ts / discovery.py
const MAX_EVIDENCE = 12, MAX_NAMES = 8;
const CONF = ["low", "medium", "high"];
const iso = (ts: number | null | undefined, fallback: number) => new Date(ts ? Math.round(ts * 1000) : fallback).toISOString();
const mergeRole = (o: string, n: string) => (ROLE_PRIORITY.indexOf(ROLE_PRIORITY.includes(o) ? o : "unknown") <= ROLE_PRIORITY.indexOf(ROLE_PRIORITY.includes(n) ? n : "unknown") ? o : n);

export interface CaptureExtras { devices: number; endpoints: number; otMessages: number; otFlagged: number }

export function storeCaptureExtras(t: Tables, bytes: Uint8Array, now = Date.now()): CaptureExtras {
  let devices = 0, endpoints = 0, otMessages = 0, otFlagged = 0;
  try {
    for (const d of discoverDevices(bytes)) {
      const old = t.devices.find((r) => r.device_key === d.device_key);
      if (!old) {
        t.devices.push({ id: nextId(t), device_key: d.device_key, mac: d.mac, ip: d.ip, ips: d.ips, role: d.role, tags: d.tags, hostname: d.hostname, os_hint: d.os_hint,
          services: d.services, mac_randomized: d.mac_randomized, evidence: d.evidence, confidence: d.confidence, first_seen: iso(d.first_seen_ts, now), last_seen: iso(d.last_seen_ts, now) } as DeviceDbRow);
      } else {
        const role = mergeRole(old.role || "unknown", d.role);
        const ips = [...new Set([...(old.ips ?? []), ...d.ips])].sort();
        const ev = [...(old.evidence ?? [])];
        for (const e of d.evidence) if (!ev.includes(e) && ev.length < MAX_EVIDENCE) ev.push(e);
        old.role = role; old.ips = ips; old.ip = old.ip || d.ip || ips[0] || null;
        old.tags = [...new Set([...(old.tags ?? []), ...d.tags, d.role, old.role])].filter((x) => x !== role && x !== "unknown").sort();
        old.hostname = d.hostname || old.hostname; old.os_hint = d.os_hint || old.os_hint;
        old.services = [...new Set([...(old.services ?? []), ...d.services])].sort((a, b) => a - b);
        old.evidence = ev; old.confidence = CONF[Math.max(CONF.indexOf(old.confidence), CONF.indexOf(d.confidence))] as DeviceDbRow["confidence"];
        old.last_seen = iso(d.last_seen_ts, now);
      }
      devices++;
    }
  } catch { /* discovery never fails an import (same as the server) */ }
  try {
    for (const r of extractEndpoints(bytes)) {
      const o = t.external.find((x) => x.remote_ip === r.remote_ip && x.remote_port === r.remote_port && x.proto === r.proto);
      if (o) {
        o.flows += r.flows; o.packets += r.packets; o.bytes_out += r.bytes_out; o.bytes_in += r.bytes_in;
        o.hostnames = [...new Set([...o.hostnames, ...r.hostnames])].sort().slice(0, MAX_NAMES); o.last_seen = iso(r.last_ts, now);
      } else {
        t.external.push({ id: nextId(t), remote_ip: r.remote_ip, remote_port: r.remote_port, proto: r.proto, flows: r.flows, packets: r.packets,
          bytes_out: r.bytes_out, bytes_in: r.bytes_in, hostnames: r.hostnames, first_seen: iso(r.first_ts, now), last_seen: iso(r.last_ts, now) } as ExternalDbRow);
      }
      endpoints++;
    }
  } catch { /* ignored */ }
  try {
    const msgs = parseModbus(bytes);
    if (msgs.length) {
      const { events, state } = evaluateOt(msgs, (t.otState as OtState | null) ?? emptyOtState());
      t.otState = state;
      const rows: OtDbRow[] = events.map((e) => ({ ...e, id: nextId(t), incident_id: null, created_at: e.ts.endsWith("Z") || /[+-]\d\d:\d\d$/.test(e.ts) ? e.ts : e.ts + "Z" }));
      correlate(t, rows.filter((r) => r.severity));
      t.otEvents.push(...rows);
      if (t.otEvents.length > 20000) t.otEvents.splice(0, t.otEvents.length - 20000);
      otMessages = rows.length; otFlagged = rows.filter((r) => r.severity).length;
    }
  } catch { /* ignored */ }
  return { devices, endpoints, otMessages, otFlagged };
}

export interface FileImport extends Partial<ImportResult> { extras: CaptureExtras | null; skippedRows: number; analysisNote: string | null }

/** Import a .pcap/.pcapng or a flow CSV chosen by the user. */
export async function importFile(name: string, bytes: Uint8Array, opts: { sensitivity?: number; learningMin?: number; progress?: Progress } = {}): Promise<FileImport> {
  const looksCsv = /\.(csv|txt)$/i.test(name) || (bytes.length > 0 && bytes[0] < 0x80 && new TextDecoder().decode(bytes.subarray(0, 200)).includes(","));
  const t = await getTables();
  if (looksCsv) {
    const r = parseCsv(new TextDecoder().decode(bytes));
    const res = await importFlows(r.flows, name, opts);
    return { ...res, extras: null, skippedRows: r.skipped, analysisNote: null };
  }
  const flows = parseCapture(bytes);
  let res: ImportResult | undefined, note: string | null = null;
  if (flows.length >= 30) res = await importFlows(flows, name, opts);
  else note = `Only ${flows.length} flows: too few for anomaly detection (needs 30), but devices, endpoints and Modbus events were still extracted.`;
  const extras = storeCaptureExtras(t, bytes);
  const rec = t.settings.imports[0];
  if (res && rec) { rec.devices = extras.devices; rec.endpoints = extras.endpoints; rec.ot = extras.otMessages; }
  else t.settings.imports.unshift({ at: new Date().toISOString(), source: name, flows: flows.length, flagged: 0, learning: 0, devices: extras.devices, endpoints: extras.endpoints, ot: extras.otMessages });
  audit(t, "data.imported_capture_extras", { source: name, ...extras });
  await save();
  return { ...(res ?? {}), extras, skippedRows: 0, analysisNote: note };
}
