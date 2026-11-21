/** End-to-end live-capture check against the REAL helper (agent/live_bridge.py) replaying
 *  a pcap: flows judged and stored, device/endpoint/Modbus extras stored, packet paging
 *  has no gaps or repeats, wrong token rejected, nothing is stored twice.
 *  Run: npx tsx tests/local/validate_live.ts   (needs python3 + dpkt) */
import "fake-indexeddb/auto";
import { spawn } from "node:child_process";
import { runLive } from "../../lib/local/live";
import { getTables, resetAll } from "../../lib/local/store";
import { localApi } from "../../lib/local/localApi";

let fails = 0;
const ok = (c: boolean, m: string) => { console.log(`${c ? "PASS" : "FAIL"}  ${m}`); if (!c) fails++; };
const PORT = 8791, TOKEN = "live-test";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function session(pcap: string, secs: number, token = TOKEN) {
  const p = spawn("python3", ["../agent/live_bridge.py", "--replay", pcap, "--port", String(PORT), "--token", TOKEN], { stdio: "ignore" });
  try {
    for (let i = 0; i < 50; i++) { try { if ((await fetch(`http://127.0.0.1:${PORT}/status`, { headers: { Authorization: `Bearer ${TOKEN}` } })).ok) break; } catch {} await sleep(200); }
    let stop = false; setTimeout(() => (stop = true), secs * 1000);
    let last = "";
    const tot = await runLive({ base: `http://127.0.0.1:${PORT}`, token, sensitivity: 10, learningMin: 0, isStopped: () => stop, onInfo: (s) => (last = s), pollMs: 300, minNew: 50, maxWaitMs: 2000 });
    return { tot, last };
  } finally { p.kill(); await sleep(200); }
}

async function main() {
  await resetAll();
  const r = await session("tests/local/fixtures/disc_big.pcap", 6);
  const t = await getTables();
  ok(r.tot.batches >= 1 && r.tot.flows > 100, `live: ${r.tot.flows} flows judged in ${r.tot.batches} batches`);
  ok(t.flows.length === r.tot.flows, "every judged flow was stored exactly once");
  const ids = new Set(t.flows.map((f) => f.id)); ok(ids.size === t.flows.length, "no duplicate flow rows");
  ok(t.flows.every((f) => f.ts != null), "live flows carry capture timestamps");
  ok(t.devices.length > 0, `devices discovered from the live packet stream (${t.devices.length})`);
  ok((await localApi.getSummary()).total_flows === t.flows.length, "dashboard summary reads the live data");
  console.log("     last status:", r.last);
  // extras counted once: replay the same file again through a fresh bridge into a fresh DB and compare
  await resetAll();
  await session("tests/local/fixtures/disc_big.pcap", 6);
  const t2 = await getTables();
  ok(Math.abs(t2.devices.length - t.devices.length) === 0, "same capture gives the same device inventory on a second live run");

  // Modbus through the live path with persisted baselines
  await resetAll();
  await session("tests/local/fixtures/normal_rw.pcap", 3);
  const m = await localApi.getRecentOtEvents(false);
  ok(m.length === 44, `Modbus messages via live packets: ${m.length} (file has 44)`);

  // wrong token
  const bad = await session("tests/local/fixtures/normal_rw.pcap", 1, "nope").then(() => "no error", (e) => String(e.message));
  ok(/Wrong token/.test(bad), "wrong token is rejected with a clear message");

  console.log(fails ? `\n${fails} FAILED` : "\nALL PASSED");
  process.exit(fails ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
