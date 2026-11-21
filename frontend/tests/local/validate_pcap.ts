// Compares the in-browser pcap/pcapng parser with backend/app/ingestion/pcap.py on identical files.
// Run:  npx tsx tests/local/validate_pcap.ts   (after backend/scripts/export_pcap_reference.py)
import { readFileSync } from "node:fs";
import { parseCapture } from "../../lib/local/pcap";

const dir = new URL(".", import.meta.url).pathname;
const ref = JSON.parse(readFileSync(dir + "pcap_reference.json", "utf8"));
let failed = 0;
for (const [name, file] of [["pcap", "sample.pcap"], ["pcapng", "sample.pcapng"]] as const) {
  const got = parseCapture(new Uint8Array(readFileSync(dir + file)));
  const want = ref[name];
  let ok = got.length === want.length;
  const problems: string[] = [];
  if (!ok) problems.push(`flow count ${got.length} vs ${want.length}`);
  for (let i = 0; ok && i < want.length; i++) {
    for (const k of Object.keys(want[i])) {
      const a = (got[i] as unknown as Record<string, unknown>)[k], b = want[i][k];
      const same = typeof b === "number" ? Math.abs((a as number) - b) <= Math.max(1e-3, Math.abs(b) * 1e-5) : a === b;
      if (!same) problems.push(`flow ${i} ${k}: ${a} vs ${b}`);
    }
  }
  ok = ok && problems.length === 0;
  console.log(`${ok ? "PASS" : "FAIL"}  ${file}: ${got.length} flows match Python parser${ok ? "" : " -- " + problems.join("; ")}`);
  if (!ok) failed++;
}
for (const [label, bytes] of [["garbage", new Uint8Array(100).fill(7)], ["empty-ish", new Uint8Array(10)]] as const) {
  try { parseCapture(bytes); console.log(`FAIL  ${label}: should have thrown`); failed++; }
  catch (e) { console.log(`PASS  ${label} rejected: ${(e as Error).message}`); }
}
process.exit(failed ? 1 : 0);
