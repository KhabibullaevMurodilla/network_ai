// Compares the in-browser TypeScript detectors with the Python (PyOD) reference.
// Run:  npx tsx tests/local/validate.ts   (after backend/scripts/export_local_reference.py)
import { readFileSync } from "node:fs";
import { parseCsv } from "../../lib/local/csv";
import { buildMatrix, analyze } from "../../lib/local/engine";
import { ecodScores, iforestScores, lofScores } from "../../lib/local/detectors";

const dir = new URL(".", import.meta.url).pathname;
const ref = JSON.parse(readFileSync(dir + "reference.json", "utf8"));
const { flows } = parseCsv(readFileSync(dir + "flows.csv", "utf8"));
const { X } = buildMatrix(flows);
let failed = 0;
const check = (name: string, ok: boolean, detail: string) => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}: ${detail}`); if (!ok) failed++; };

function rank(a: ArrayLike<number>) {
  const idx = Array.from({ length: a.length }, (_, i) => i).sort((p, q) => a[p] - a[q]);
  const r = new Float64Array(a.length);
  for (let s = 0; s < idx.length; ) { let e = s; while (e + 1 < idx.length && a[idx[e + 1]] === a[idx[s]]) e++; for (let t = s; t <= e; t++) r[idx[t]] = (s + e) / 2; s = e + 1; }
  return r;
}
function spearman(a: ArrayLike<number>, b: ArrayLike<number>) {
  const ra = rank(a), rb = rank(b), n = ra.length;
  const ma = ra.reduce((s, v) => s + v, 0) / n, mb = rb.reduce((s, v) => s + v, 0) / n;
  let num = 0, da = 0, db = 0;
  for (let i = 0; i < n; i++) { num += (ra[i] - ma) * (rb[i] - mb); da += (ra[i] - ma) ** 2; db += (rb[i] - mb) ** 2; }
  return num / Math.sqrt(da * db);
}
function topOverlap(a: ArrayLike<number>, b: ArrayLike<number>, frac: number) {
  const k = Math.round(a.length * frac);
  const top = (v: ArrayLike<number>) => new Set(Array.from({ length: v.length }, (_, i) => i).sort((p, q) => v[q] - v[p]).slice(0, k));
  const A = top(a), B = top(b); let c = 0; A.forEach((i) => { if (B.has(i)) c++; });
  return c / k;
}

check("parsed rows", flows.length === ref.n, `${flows.length} == ${ref.n}`);

const e = ecodScores(X);
let maxDiff = 0; for (let i = 0; i < e.length; i++) maxDiff = Math.max(maxDiff, Math.abs(e[i] - ref.ecod[i]));
check("ECOD matches PyOD", maxDiff < 1e-6, `max abs diff ${maxDiff.toExponential(2)}`);

const l = lofScores(X);
const lcorr = spearman(l, ref.lof), lov = topOverlap(l, ref.lof, 0.1);
let lmax = 0; for (let i = 0; i < l.length; i++) lmax = Math.max(lmax, Math.abs(l[i] - ref.lof[i]) / Math.max(1, Math.abs(ref.lof[i])));
check("LOF matches sklearn/PyOD", lcorr > 0.999 && lov > 0.97, `spearman ${lcorr.toFixed(5)}, top-10% overlap ${lov.toFixed(3)}, max rel diff ${lmax.toExponential(2)}`);

const f = iforestScores(X);
const icorr = spearman(f, ref.iforest), iov = topOverlap(f, ref.iforest, 0.1);
check("IForest agrees with sklearn/PyOD (random, so approximate)", icorr > 0.97 && iov > 0.85, `spearman ${icorr.toFixed(4)}, top-10% overlap ${iov.toFixed(3)}`);

async function main() {
const a = await analyze(flows, 10);
const sc = a.selfCheck!;
const recall = sc.attacksFlagged / sc.attacksInFile, fpr = sc.benignFlagged / sc.benign;
const py = ref.python_engine;
console.log(`\nBrowser engine: flagged ${(a.flagged / a.total * 100).toFixed(1)}%, attack recall ${(recall * 100).toFixed(1)}%, benign flagged ${(fpr * 100).toFixed(1)}%  (${a.detectors} detectors)`);
console.log(`Python engine : flagged ${(py.flag_rate * 100).toFixed(1)}%, attack recall ${(py.attack_recall * 100).toFixed(1)}%, benign flagged ${(py.benign_flag_rate * 100).toFixed(1)}%`);
check("browser recall within 10 points of Python engine", Math.abs(recall - py.attack_recall) <= 0.10, `${(recall * 100).toFixed(1)}% vs ${(py.attack_recall * 100).toFixed(1)}%`);
check("browser benign-flag rate within 4 points of Python engine", Math.abs(fpr - py.benign_flag_rate) <= 0.04, `${(fpr * 100).toFixed(1)}% vs ${(py.benign_flag_rate * 100).toFixed(1)}%`);
process.exit(failed ? 1 : 0);
}
main();
