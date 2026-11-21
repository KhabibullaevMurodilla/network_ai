/** Live capture driver for the dashboard's local mode. Talks to agent/live_bridge.py
 *  on this computer: completed flows (/flows) are judged by the in-browser ensemble
 *  and stored; raw packets (/packets, a pcap chunk) feed device discovery, internet
 *  endpoints and the Modbus rules. Everything lands in the browser database. */
import { importFlows, storeCaptureExtras } from "./importer";
import { getTables, save } from "./store";
import type { Flow } from "./types";

export interface LiveOptions {
  base: string; token: string; sensitivity: number; learningMin: number;
  isStopped: () => boolean; onInfo: (s: string) => void;
  fetchFn?: typeof fetch; pollMs?: number; minNew?: number; maxWaitMs?: number; contextSize?: number;
}
export interface LiveTotals { flows: number; flagged: number; devices: number; endpoints: number; ot: number; batches: number }

export async function runLive(o: LiveOptions): Promise<LiveTotals> {
  const f = o.fetchFn ?? fetch;
  const base = o.base.replace(/\/$/, "");
  const headers = { Authorization: `Bearer ${o.token.trim()}` };
  const poll = o.pollMs ?? 2000, minNew = o.minNew ?? 10, maxWait = o.maxWaitMs ?? 15000, ctxN = o.contextSize ?? 2000;
  const tot: LiveTotals = { flows: 0, flagged: 0, devices: 0, endpoints: 0, ot: 0, batches: 0 };
  const get = async (path: string) => {
    const r = await f(base + path, { headers, cache: "no-store" });
    if (r.status === 401) throw new Error("Wrong token. Copy the token printed by the helper.");
    if (!r.ok) throw new Error(`Bridge answered ${r.status}`);
    return r;
  };
  let packetsOk = true;
  let nextFlow = 0, nextPkt = 0, pending: Flow[] = [], lastImport = Date.now();
  const flush = async () => {
    const t = await getTables();
    const context: Flow[] = t.flows.slice(-ctxN).map((r) => ({
      dur: r.dur, proto: r.proto, tot_pkts: r.tot_pkts, src_bytes: r.src_bytes, dst_bytes: r.dst_bytes, rate: r.rate, load: r.load, s_ttl: r.s_ttl,
      src_ip: r.src_ip ?? undefined, dst_ip: r.dst_ip ?? undefined, ...(r.ts != null ? { ts: r.ts } : {}),
    }));
    const batch = pending; pending = []; lastImport = Date.now();
    const res = await importFlows(batch, "live capture", { sensitivity: o.sensitivity, learningMin: o.learningMin, contextFlows: context });
    tot.flows += res.total; tot.flagged += res.flagged; tot.batches++;
  };
  while (!o.isStopped()) {
    const st = await (await get("/status")).json();
    const d = await (await get(`/flows?since=${nextFlow}`)).json();
    nextFlow = d.next; pending.push(...(d.flows as Flow[]));
    let bytes = new Uint8Array(0), nxt = nextPkt;
    if (packetsOk) {
      const pr = await f(`${base}/packets?since=${nextPkt}`, { headers, cache: "no-store" });
      if (pr.status === 404) packetsOk = false;           // an older helper without raw-packet support: flows only
      else if (pr.ok) { bytes = new Uint8Array(await pr.arrayBuffer()); nxt = Number(pr.headers.get("X-Next-Seq") ?? nextPkt); }
    }
    if (nxt > nextPkt && bytes.length > 24) {
      const t = await getTables();
      const x = storeCaptureExtras(t, bytes);
      tot.devices += x.devices; tot.endpoints += x.endpoints; tot.ot += x.otMessages;
      await save();
    }
    nextPkt = nxt;
    const t = await getTables();
    const enoughContext = t.flows.length + pending.length >= 30;
    if (pending.length > 0 && enoughContext && (pending.length >= minNew || Date.now() - lastImport >= maxWait)) await flush();
    o.onInfo(`Live · ${Number(st.packets ?? 0).toLocaleString()} packets · ${tot.flows.toLocaleString()} flows judged (${tot.flagged} flagged) · ${pending.length} waiting${enoughContext ? "" : " (need 30 flows before judging)"}${packetsOk ? "" : " · this helper is older: no device/endpoint/Modbus data (download the new one)"} · ${tot.ot} Modbus messages`);
    if (st.mode === "stopped" || st.error) o.onInfo(`Bridge: ${st.mode}. ${st.error ?? ""}`);
    await new Promise((r) => setTimeout(r, poll));
  }
  if (pending.length > 0 && (await getTables()).flows.length + pending.length >= 30) await flush();
  return tot;
}
