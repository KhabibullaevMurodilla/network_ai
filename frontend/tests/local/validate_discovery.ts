// Compares the in-browser device discovery + endpoint extraction with the Python originals
// (backend/app/ingestion/discovery.py, endpoints.py) on identical capture bytes.
// Run:  npx tsx tests/local/validate_discovery.ts   (after backend/scripts/export_discovery_reference.py)
import { readFileSync } from "node:fs";
import { discoverDevices, parseLldp, parseCdp } from "../../lib/local/discovery";
import { extractEndpoints, parseSni } from "../../lib/local/endpoints";
import { isPrivate, isPublic } from "../../lib/local/netdecode";

const dir = new URL(".", import.meta.url).pathname;
const ref = JSON.parse(readFileSync(dir + "fixtures/discovery_reference.json", "utf8"));
let pass = 0, fail = 0;
const report = (ok: boolean, label: string, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${ok ? "" : " -- " + detail}`);
  ok ? pass++ : fail++;
};
const TS_KEYS = new Set(["first_ts", "last_ts", "first_seen_ts", "last_seen_ts"]);
const hex = (h: string) => new Uint8Array(Buffer.from(h, "hex"));

/** First difference between two values (deep, key-set exact, float tolerance on timestamps), or "". */
function diff(a: any, b: any, path = "", key = ""): string {
  if (typeof a === "number" && typeof b === "number")
    return (TS_KEYS.has(key) ? Math.abs(a - b) <= 1e-6 : a === b) ? "" : `${path}: ${a} vs ${b}`;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return `${path}: type ${JSON.stringify(a)} vs ${JSON.stringify(b)}`;
    if (a.length !== b.length) return `${path}: length ${a.length} vs ${b.length}`;
    for (let i = 0; i < a.length; i++) { const d = diff(a[i], b[i], `${path}[${i}]`, key); if (d) return d; }
    return "";
  }
  if (a && b && typeof a === "object" && typeof b === "object") {
    const ks = new Set([...Object.keys(a), ...Object.keys(b)]);
    for (const k of ks) {
      if (!(k in a) || !(k in b)) return `${path}.${k}: key missing (${k in a ? "ref" : "ts"})`;
      const d = diff(a[k], b[k], `${path}.${k}`, k); if (d) return d;
    }
    return "";
  }
  return a === b ? "" : `${path}: ${JSON.stringify(a)} vs ${JSON.stringify(b)}`;
}

for (const [name, want] of Object.entries<any>(ref.files)) {
  const data = new Uint8Array(readFileSync(dir + (name.startsWith("sample") ? "" : "fixtures/") + name));
  let got: any;
  try { got = discoverDevices(data); } catch (e) { report(false, `discover  ${name}`, "threw " + e); got = null; }
  if (got) { const d = diff(got, want.discover); report(d === "", `discover  ${name}: ${got.length} devices`, d); }
  try { got = extractEndpoints(data); } catch (e) { report(false, `endpoints ${name}`, "threw " + e); got = null; }
  if (got) { const d = diff(got, want.endpoints); report(d === "", `endpoints ${name}: ${got.length} rows`, d); }
}

function vectors(label: string, vecs: [string, unknown][], fn: (b: Uint8Array) => unknown) {
  let bad = "", nonNull = 0;
  vecs.forEach(([h, want], i) => {
    let g: unknown;
    try { g = fn(hex(h)); } catch (e) { g = "THREW " + e; }
    if (want !== null) nonNull++;
    const d = diff(g, want, `#${i}`);
    if (d && !bad) bad = d + `  input=${h.slice(0, 80)}`;
  });
  report(bad === "", `${label}: ${vecs.length} vectors (${nonNull} non-null)`, bad);
}
vectors("parse_sni ", ref.parse_sni, parseSni);
vectors("parse_lldp", ref.parse_lldp, parseLldp);
vectors("parse_cdp ", ref.parse_cdp, parseCdp);

const bad = ref.ip_class.filter(([ip, pr, pu]: [string, boolean, boolean]) => isPrivate(ip) !== pr || isPublic(ip) !== pu);
report(bad.length === 0, `ip classify: ${ref.ip_class.length} addresses`, JSON.stringify(bad.slice(0, 3)));

console.log(`\n${pass} PASS, ${fail} FAIL`);
process.exit(fail ? 1 : 0);
