// Compares the in-browser Modbus parser + OT rule engine with the Python originals
// (backend/app/ingestion/modbus.py, backend/app/ml/ot_rules.py) on identical capture bytes.
// Run:  npx tsx tests/local/validate_modbus.ts   (after backend/scripts/export_modbus_reference.py)
import { readFileSync } from "node:fs";
import { parseModbus } from "../../lib/local/modbus";
import { evaluateOt, type OtState } from "../../lib/local/otRules";

const dir = new URL(".", import.meta.url).pathname + "fixtures/";
const ref = JSON.parse(readFileSync(dir + "modbus_reference.json", "utf8"));
const load = (f: string) => new Uint8Array(readFileSync(dir + f));
let pass = 0, fail = 0;
const report = (ok: boolean, label: string, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${ok ? "" : " -- " + detail}`);
  ok ? pass++ : fail++;
};

/** Returns the first difference between two record lists, or "" when equal. */
function diff(got: Record<string, unknown>[], want: Record<string, unknown>[], tol: Record<string, number> = { ts: 1e-6 }): string {
  if (got.length !== want.length) return `count ${got.length} vs ${want.length}`;
  for (let i = 0; i < want.length; i++) {
    const keys = new Set([...Object.keys(want[i]), ...Object.keys(got[i])]);
    for (const k of keys) {
      const a = got[i][k], b = want[i][k];
      const same = k in tol && typeof a === "number" && typeof b === "number" ? Math.abs(a - b) <= tol[k] : a === b;
      if (!same) return `#${i} ${k}: ${JSON.stringify(a)} vs ${JSON.stringify(b)}`;
    }
  }
  return "";
}

for (const [key, f] of Object.entries<any>(ref.fixtures)) {
  const msgs = parseModbus(load(f.file), f.port);
  const d = diff(msgs as any, f.messages);
  report(d === "", `parse  ${key}: ${msgs.length} messages`, d);
  const { events } = evaluateOt(msgs);
  const flagged = events.filter(e => e.reason).length;
  const e = diff(events as any, f.events, {});
  report(e === "", `rules  ${key}: ${events.length} events, ${flagged} flagged`, e);
}

// persisted baseline: run first capture, JSON round-trip the state (as storage would), run second
for (const c of ref.carryover) {
  const r1 = evaluateOt(parseModbus(load(c.first)));
  const stored: OtState = JSON.parse(JSON.stringify(r1.state));
  const r2 = evaluateOt(parseModbus(load(c.second)), stored);
  const d1 = diff(r1.events as any, c.events_first, {});
  const d2 = diff(r2.events as any, c.events_second, {});
  report(d1 === "" && d2 === "", `state  ${c.first} -> ${c.second} (${r2.events.filter(e => e.reason).length} flagged in 2nd)`, d1 || d2);
  // without the carried state the second import must differ unless the first added nothing it relies on
}
{ // input state must not be mutated
  const r1 = evaluateOt(parseModbus(load("normal_rw.pcap")));
  const snap = JSON.stringify(r1.state);
  evaluateOt(parseModbus(load("write_outside_range.pcap")), r1.state);
  report(JSON.stringify(r1.state) === snap, "state  evaluateOt does not mutate its input state");
}
{ // carrying state must matter: write outside range is NOT flagged with a fresh baseline
  const fresh = evaluateOt(parseModbus(load("write_outside_range.pcap"))).events.filter(e => e.reason === "unexpected_write_address").length;
  const c = ref.carryover.find((x: any) => x.second === "write_outside_range.pcap");
  const carried = c.events_second.filter((e: any) => e.reason === "unexpected_write_address").length;
  report(carried > 0, `state  baseline carry-over changes the verdict (fresh ${fresh} vs carried ${carried} unexpected_write_address)`);
}
for (const label of ref.rejected) {
  const bytes = label === "empty" ? new Uint8Array(0) : new Uint8Array(100).fill(7);
  try { parseModbus(bytes); report(false, `reject ${label}`, "should have thrown"); }
  catch { report(true, `reject ${label}: throws like Python ValueError`); }
}
console.log(`\n${pass} PASS, ${fail} FAIL`);
process.exit(fail ? 1 : 0);
