/** Local mode checks: import pipeline, learning period, burst/drift rules, incident
 *  correlation, the localApi response shapes the dashboard pages read, and
 *  persistence across a "reload" (fake IndexedDB). Run: npx tsx tests/local/validate_local_mode.ts */
import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { parseCsv } from "../../lib/local/csv";
import { importFlows, importFile } from "../../lib/local/importer";
import { localApi } from "../../lib/local/localApi";
import { getTables, resetAll, saveNow, _forgetMemory, persistent } from "../../lib/local/store";
import type { Flow } from "../../lib/local/types";

let fails = 0;
const ok = (c: boolean, m: string) => { console.log(`${c ? "PASS" : "FAIL"}  ${m}`); if (!c) fails++; };
const csv = parseCsv(readFileSync(new URL("./flows.csv", import.meta.url), "utf8")).flows;

async function main() {
  await resetAll();
  let t = await getTables();
  ok(persistent === true, "IndexedDB (fake) is used for storage");

  // ---- 1. import with default learning period (50 per source)
  t.settings.learningMin = 50;
  const r = await importFlows(csv, "flows.csv");
  t = await getTables();
  ok(t.flows.length === r.total && r.total === csv.length, `all ${r.total} flows stored`);
  ok(t.events.length === r.flagged && r.flagged > 0, `${r.flagged} flagged events stored`);
  const learningIds = new Set(t.flows.filter((f) => f.learning).map((f) => f.id));
  ok(learningIds.size === r.learning && r.learning > 0, `${r.learning} flows marked as learning`);
  ok(t.events.every((e) => !learningIds.has(e.flow_id)), "no learning-period flow was ever flagged");
  const perSrc = new Map<string, number>();
  for (const f of t.flows) { const k = f.src_ip ?? "unidentified"; if (f.learning) perSrc.set(k, (perSrc.get(k) ?? 0) + 1); }
  ok([...perSrc.values()].every((n) => n === 50 || n === csv.filter((c) => (c.src_ip ?? "unidentified") === [...perSrc.keys()][0]).length || n <= 50), "no source has more than 50 learning flows");
  ok([...perSrc.values()].every((n) => n <= 50), "learning period capped at 50 per source");
  ok(t.events.every((e) => e.incident_id && t.incidents.some((i) => i.id === e.incident_id)), "every event is attached to an incident");
  ok(t.incidents.reduce((s, i) => s + i.event_count, 0) === t.events.length, "incident event counts add up to the events");
  const gaps = t.incidents.every((i) => {
    const ts = t.events.filter((e) => e.incident_id === i.id).map((e) => Date.parse(e.created_at)).sort((a, b) => a - b);
    return ts.every((v, k) => k === 0 || v - ts[k - 1] <= 30 * 60 * 1000);
  });
  ok(gaps, "events inside an incident are never >30 min apart");

  // ---- 2. second import keeps baselines (learning not repeated) and appends
  const before = t.flows.length;
  const r2 = await importFlows(csv, "again.csv");
  ok(r2.learning < r.learning, `second import: baselines persisted, fewer flows in learning (${r2.learning} < ${r.learning})`);
  t = await getTables();
  ok(t.flows.length === before + csv.length, "second import appends");

  // ---- 3. localApi shapes
  const s = await localApi.getSummary();
  ok(s.total_flows === t.flows.length && s.total_anomalies === t.events.length && s.role === "owner", "getSummary");
  const ents = await localApi.getEntities();
  ok(ents.reduce((n, e) => n + e.event_count, 0) === t.events.length, "entities event counts add up");
  const trend = await localApi.getTrend(14);
  ok(trend.reduce((n, d) => n + d.low + d.medium + d.high + d.critical, 0) === t.events.length, "trend counts add up (anchored to newest data)");
  const recent = await localApi.getRecentAnomalies();
  ok(recent.length === Math.min(200, t.events.length) && recent[0].created_at >= recent[recent.length - 1].created_at, "recent: newest first, max 200");
  const one = await localApi.getAnomalyDetail(recent[0].id);
  ok(one.flow?.id === recent[0].flow_id && Array.isArray(one.detector_scores) && one.detector_scores.length >= 3, "anomaly detail: flow + detector votes");
  const tri = await localApi.updateTriage(recent[0].id, "acknowledged");
  ok(tri.triage_status === "acknowledged" && (await localApi.getAnomalyDetail(recent[0].id)).triage_status === "acknowledged", "triage persists");
  const topo = await localApi.getTopology();
  ok(topo.nodes.length > 0 && topo.edges.every((e) => topo.nodes.some((n) => n.id === e.source) && topo.nodes.some((n) => n.id === e.target)), "topology edges reference nodes");
  const incs = await localApi.listIncidents("open");
  const det = await localApi.getIncidentDetail(incs[0].id);
  ok(det.events.length === det.event_count, "incident detail lists its events");
  await localApi.updateIncidentStatus(incs[0].id, "closed");
  ok(!(await localApi.listIncidents("open")).some((i) => i.id === incs[0].id), "closing an incident removes it from open");
  await localApi.createSuppression("10.50.0.11", "test");
  ok((await localApi.createSuppression("10.50.0.11").then(() => false, () => true)), "duplicate suppression rejected");
  ok((await localApi.createSuppression("not-an-ip").then(() => false, () => true)), "invalid IP suppression rejected");
  ok((await localApi.createApiKey("x").then(() => false, (e) => /local mode/.test(e.message))), "server-only features say so");
  ok((await localApi.getAuditLog()).some((a) => a.action === "data.imported"), "audit log records imports");

  // ---- 4. persistence across reload
  await saveNow();
  const counts = { f: t.flows.length, e: t.events.length, i: t.incidents.length };
  _forgetMemory();
  const t2 = await getTables();
  ok(t2.flows.length === counts.f && t2.events.length === counts.e && t2.incidents.length === counts.i, "data survives a reload");
  ok(t2.suppressions.length === 1 && t2.settings.focus === null, "suppressions survive a reload");

  // ---- 5. burst rule (needs timestamps): same mild attacker flows, 2 s apart vs 100 s apart
  const mk = (i: number, src: string, k = 0, ts = 1_700_000_000 + i * 3): Flow => ({
    dur: 0.5 + (i % 7) * 0.05 + k * 2, proto: "TCP", tot_pkts: 10 + (i % 5) + k * 30, src_bytes: 400 + (i % 9) * 30 + k * 4000,
    dst_bytes: 900 + (i % 6) * 20, rate: 20 + (i % 4) + k * 15, load: 1000 + (i % 8) * 30 + k * 2000, s_ttl: 64, src_ip: src, dst_ip: "10.0.0.1", ts,
  });
  const burstRun = async (gap: number) => {
    await resetAll(); const tt = await getTables(); tt.settings.learningMin = 0;
    const f: Flow[] = [];
    for (let i = 0; i < 400; i++) f.push(mk(i, `10.0.1.${1 + (i % 20)}`));
    for (let j = 0; j < 12; j++) f.push(mk(j, "10.9.9.9", 0.005 * (j + 1), 1_700_001_300 + j * gap));
    const res = await importFlows(f, "burst.csv");
    return { res, ev: (await getTables()).events };
  };
  const close = await burstRun(2), spaced = await burstRun(100);
  const bursts = close.ev.filter((e) => e.escalation_reason === "entity_burst");
  ok(close.res.burstSkipped === false, "timestamps present: burst rule active");
  ok(bursts.length > 0 && bursts.every((e) => e.severity === "critical" && e.src_ip === "10.9.9.9"), `burst rule fired for the attacker only (${bursts.length} events, all critical)`);
  ok(spaced.ev.filter((e) => e.escalation_reason === "entity_burst").length === 0, "same flows 100 s apart: burst rule does not fire");
  t = await getTables();
  await burstRun(2);
  const bid = (await getTables()).events.find((e) => e.escalation_reason === "entity_burst")!.id;
  ok((await localApi.getAnomalyDetail(bid)).mitre?.technique_id === "T1595", "burst event carries MITRE T1595");

  // ---- 6. baseline drift (learningMin 20, quiet host then one large departure)
  await resetAll(); t = await getTables(); t.settings.learningMin = 20;
  const quiet: Flow[] = [];
  for (let i = 0; i < 400; i++) quiet.push(mk(i, `10.0.1.${1 + (i % 20)}`));   // 20 sources x 20 flows
  for (let i = 0; i < 25; i++) quiet.push(mk(i, "10.7.7.7"));
  quiet.push({ ...mk(0, "10.7.7.7"), tot_pkts: 400, src_bytes: 60000, rate: 200, load: 90000, ts: 1_700_000_900 });
  await importFlows(quiet, "drift.csv");
  t = await getTables();
  const dr = t.events.filter((e) => e.src_ip === "10.7.7.7" && (e.entity_baseline_z ?? 0) >= 5);
  ok(dr.length >= 1 && dr.every((e) => ["medium", "high", "critical"].includes(e.severity)), `drift: ${dr.length} event(s) with baseline z>=5, severity >= medium`);

  // ---- 7. capture extras: devices, internet endpoints, Modbus OT rules
  await resetAll(); t = await getTables(); t.settings.learningMin = 0;
  const fx = (n: string) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)));
  const a1 = await importFile("normal_rw.pcap", fx("normal_rw.pcap"));
  ok(a1.analysisNote !== null && a1.extras!.otMessages > 0, `small capture: anomaly step skipped with a note, ${a1.extras!.otMessages} Modbus messages still stored`);
  ok((await localApi.getRecentOtEvents(true)).length === 0, "normal Modbus traffic: nothing flagged");
  const a2 = await importFile("new_function_code.pcap", fx("new_function_code.pcap"));
  const flagged = await localApi.getRecentOtEvents(true);
  ok(flagged.some((e) => e.reason === "new_function_code" && e.mitre?.technique_id === "T0855"), `baseline carried between imports: new function code flagged (${flagged.length} flagged, MITRE T0855)`);
  t = await getTables();
  ok(t.incidents.some((i) => i.src_ip && flagged.some((e) => e.src_ip === i.src_ip)), "flagged OT events create/attach incidents");
  const d1 = await importFile("disc_dhcp.pcap", fx("disc_dhcp.pcap"));
  const nDev = (await localApi.listDevices()).length;
  ok(d1.extras!.devices > 0 && nDev > 0, `devices discovered from DHCP capture (${nDev})`);
  await importFile("disc_dhcp.pcap", fx("disc_dhcp.pcap"));
  ok((await localApi.listDevices()).length === nDev, "re-importing the same capture merges devices, no duplicates");
  const role = (await localApi.listDevices())[0].role;
  ok((await localApi.listDevices(role)).every((d) => d.role === role), "device role filter");
  await importFile("disc_tls.pcap", fx("disc_tls.pcap"));
  const ext = await localApi.listExternal("bytes");
  ok(ext.length > 0 && ext.every((r) => r.bytes_total === r.bytes_out + r.bytes_in && r.service), `${ext.length} internet endpoints, with service + totals`);
  const f0 = ext[0].flows;
  await importFile("disc_tls.pcap", fx("disc_tls.pcap"));
  ok((await localApi.listExternal("bytes")).find((r) => r.remote_ip === ext[0].remote_ip && r.remote_port === ext[0].remote_port)!.flows === f0 * 2, "endpoint counters are additive across imports");
  const topo2 = await localApi.getTopology();
  ok(Array.isArray(topo2.nodes), "topology still builds with devices present");

  // ---- 7b. batches with context (live capture): only new flows are judged and stored
  await resetAll(); t = await getTables(); t.settings.learningMin = 0;
  const live = parseCsv(readFileSync(new URL("./flows.csv", import.meta.url), "utf8")).flows.slice(0, 600).map((f, i) => ({ ...f, ts: 1_700_000_000 + i }));
  let ctx: Flow[] = [], stored = 0;
  for (let b = 0; b < 4; b++) {
    const batch = live.slice(b * 150, (b + 1) * 150);
    const rb = await importFlows(batch, "live capture", { contextFlows: ctx });
    stored += rb.total; ctx = live.slice(0, (b + 1) * 150);
  }
  t = await getTables();
  ok(stored === 600 && t.flows.length === 600 && new Set(t.flows.map((f) => f.id)).size === 600, "context batches: 600 flows stored once each");
  ok(t.events.every((e) => t.flows.some((f) => f.id === e.flow_id)), "context batches: every event points at a stored flow");
  ok(t.events.length > 0 && t.incidents.length > 0, `context batches: ${t.events.length} events, ${t.incidents.length} incidents`);

  // ---- 8. erase
  await localApi.eraseData();
  const s0 = await localApi.getSummary();
  ok(s0.total_flows === 0 && s0.total_anomalies === 0, "erase empties the database");

  console.log(fails ? `\n${fails} FAILED` : "\nALL PASSED");
  process.exit(fails ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
