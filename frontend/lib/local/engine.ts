/** In-browser analysis: scale features, run the four detectors, and combine
 *  them the way backend/app/ml/engine.py does (percentile severity tiers,
 *  ensemble-consensus escalation, top-3 feature explanation).
 *
 *  Batch mode: the detectors are fitted on the uploaded capture itself and
 *  then score that same capture. There is no stored history, so there is no
 *  per-device learning period, entity baseline or burst rule here. Because
 *  each detector flags its own top `sensitivity`% by construction, the share
 *  of flagged flows is driven by that setting, not by how bad the traffic is. */
import { ecodScores, iforestScores, lofScores, hstScores, percentile, type Matrix } from "./detectors";
import { NUMERIC_FEATURES, type Flow, type Severity } from "./types";

export const MAX_FLOWS = 30000;
const SEVERITY_ORDER: (Severity | null)[] = [null, "low", "medium", "high", "critical"];
const SEVERITY_PCT = { low: 90, medium: 97, high: 99.5 };

export interface Explanation { feature: string; z: number }
export interface ScoredFlow {
  index: number;
  flow: Flow;
  severity: Severity | null;
  consensus: number;
  votes: { ecod: boolean; iforest: boolean; lof: boolean; hst: boolean };
  reason: "ensemble_consensus" | null;
  ecodScore: number;
  explanation: Explanation[];
}
export interface SourceSummary { source: string; flows: number; flagged: number; worst: Severity | null }
export interface SelfCheck { labelled: number; attacksInFile: number; attacksFlagged: number; benignFlagged: number; benign: number }
export interface Analysis {
  total: number;
  sampledFrom: number | null;
  detectors: number;           // how many of the 4 could run (HST needs >=250 flows)
  sensitivity: number;
  scored: ScoredFlow[];
  flagged: number;
  bySeverity: Record<Severity, number>;
  sources: SourceSummary[];
  selfCheck: SelfCheck | null;
}

export type Progress = (stage: string, fraction: number) => void;
const tick = () => new Promise<void>((r) => setTimeout(r, 0));

export function buildMatrix(flows: Flow[]): { X: Matrix; mean: Float64Array; std: Float64Array } {
  const protos = [...new Set(flows.map((f) => f.proto))].sort();   // LabelEncoder: sorted classes
  const code = new Map(protos.map((p, i) => [p, i]));
  const d = NUMERIC_FEATURES.length + 1;
  const raw: Matrix = flows.map((f) => {
    const r = new Float64Array(d);
    NUMERIC_FEATURES.forEach((k, j) => { r[j] = f[k]; });
    r[d - 1] = code.get(f.proto) ?? 0;
    return r;
  });
  const n = raw.length;
  const mean = new Float64Array(d), std = new Float64Array(d);
  for (let j = 0; j < d; j++) {
    let s = 0; for (let i = 0; i < n; i++) s += raw[i][j];
    mean[j] = s / n;
    let v = 0; for (let i = 0; i < n; i++) v += (raw[i][j] - mean[j]) ** 2;
    std[j] = Math.sqrt(v / n) || 1;          // StandardScaler: population std, constant column -> 1
  }
  const X = raw.map((r) => Float64Array.from(r, (v, j) => (v - mean[j]) / std[j]));
  return { X, mean, std };
}

function toUnitRange(X: Matrix): Matrix {
  const n = X.length, d = X[0].length;
  const lo = new Float64Array(d), hi = new Float64Array(d);
  for (let j = 0; j < d; j++) {
    const col = X.map((r) => r[j]);
    lo[j] = percentile(col, 1); hi[j] = percentile(col, 99);
  }
  return X.map((r) => Float64Array.from(r, (v, j) => (hi[j] > lo[j] ? Math.min(1, Math.max(0, (v - lo[j]) / (hi[j] - lo[j]))) : 0.5)));
}

function escalate(sev: Severity | null, steps: number): Severity | null {
  return SEVERITY_ORDER[Math.min(SEVERITY_ORDER.indexOf(sev) + steps, SEVERITY_ORDER.length - 1)];
}

export async function analyze(input: Flow[], sensitivity = 10, progress: Progress = () => {}): Promise<Analysis> {
  if (input.length < 30) throw new Error("Need at least 30 flows to find what is unusual.");
  let flows = input;
  let sampledFrom: number | null = null;
  if (flows.length > MAX_FLOWS) {            // deterministic even-spaced sample keeps time order
    sampledFrom = flows.length;
    const step = flows.length / MAX_FLOWS;
    flows = Array.from({ length: MAX_FLOWS }, (_, i) => input[Math.floor(i * step)]);
  }
  const n = flows.length;
  progress("Scaling features", 0.02); await tick();
  const { X } = buildMatrix(flows);

  progress("ECOD", 0.1); await tick();
  const ecod = ecodScores(X);
  progress("Isolation Forest", 0.25); await tick();
  const ifo = iforestScores(X);
  progress("Local Outlier Factor", 0.5); await tick();
  const lof = lofScores(X);
  progress("Half-Space Trees", 0.85); await tick();
  const hst = hstScores(toUnitRange(X));
  progress("Combining", 0.95); await tick();

  const cut = (s: ArrayLike<number>) => percentile(s, 100 - sensitivity);
  const cE = cut(ecod), cI = cut(ifo), cL = cut(lof), cH = hst ? cut(hst) : Infinity;
  const sev = { low: percentile(ecod, SEVERITY_PCT.low), medium: percentile(ecod, SEVERITY_PCT.medium), high: percentile(ecod, SEVERITY_PCT.high) };

  const scored: ScoredFlow[] = [];
  const bySeverity: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  for (let i = 0; i < n; i++) {
    const votes = { ecod: ecod[i] > cE, iforest: ifo[i] > cI, lof: lof[i] > cL, hst: hst ? hst[i] >= cH : false };
    const consensus = +votes.ecod + +votes.iforest + +votes.lof + +votes.hst;
    let s: Severity | null =
      ecod[i] < sev.low ? null : ecod[i] < sev.medium ? "low" : ecod[i] < sev.high ? "medium" : ecod[i] < sev.high * 1.3 ? "high" : "critical";
    let reason: ScoredFlow["reason"] = null;
    if (consensus >= 2 && s === null) { s = "low"; reason = "ensemble_consensus"; }
    else if (consensus === 4 && s) { const e = escalate(s, 2); if (e !== s) { s = e; reason = "ensemble_consensus"; } }
    else if (consensus === 3 && s) { const e = escalate(s, 1); if (e !== s) { s = e; reason = "ensemble_consensus"; } }
    const z = NUMERIC_FEATURES.map((k, j) => ({ feature: k as string, z: Math.round(X[i][j] * 100) / 100 }))
      .sort((a, b) => Math.abs(b.z) - Math.abs(a.z)).slice(0, 3);
    if (s) bySeverity[s]++;
    scored.push({ index: i, flow: flows[i], severity: s, consensus, votes, reason, ecodScore: ecod[i], explanation: z });
  }

  const per = new Map<string, SourceSummary>();
  for (const r of scored) {
    const key = r.flow.src_ip ?? "(no source IP)";
    const e = per.get(key) ?? { source: key, flows: 0, flagged: 0, worst: null };
    e.flows++;
    if (r.severity) { e.flagged++; if (SEVERITY_ORDER.indexOf(r.severity) > SEVERITY_ORDER.indexOf(e.worst)) e.worst = r.severity; }
    per.set(key, e);
  }
  const sources = [...per.values()].sort((a, b) => b.flagged - a.flagged || b.flows - a.flows);

  let selfCheck: SelfCheck | null = null;
  const labelled = scored.filter((r) => r.flow.label);
  if (labelled.length === n && n > 0) {
    const isBenign = (l?: string) => (l ?? "").toLowerCase() === "benign" || (l ?? "").toLowerCase() === "normal";
    const attacks = labelled.filter((r) => !isBenign(r.flow.label));
    const benign = labelled.filter((r) => isBenign(r.flow.label));
    selfCheck = {
      labelled: n, attacksInFile: attacks.length, attacksFlagged: attacks.filter((r) => r.severity).length,
      benign: benign.length, benignFlagged: benign.filter((r) => r.severity).length,
    };
  }
  progress("Done", 1);
  return {
    total: n, sampledFrom, detectors: hst ? 4 : 3, sensitivity, scored,
    flagged: scored.filter((r) => r.severity).length, bySeverity, sources, selfCheck,
  };
}

export function resultsToCsv(a: Analysis): string {
  const q = (v: unknown) => { const s = String(v ?? ""); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  const head = ["row", "severity", "consensus", "reason", "top_features", "src_ip", "dst_ip", "proto", "dur", "tot_pkts", "src_bytes", "dst_bytes", "rate", "load", "s_ttl"];
  const rows = a.scored.map((r) => [
    r.index + 1, r.severity ?? "", r.consensus, r.reason ?? "",
    r.explanation.map((e) => `${e.feature} ${e.z > 0 ? "+" : ""}${e.z}σ`).join("; "),
    r.flow.src_ip ?? "", r.flow.dst_ip ?? "", r.flow.proto, r.flow.dur, r.flow.tot_pkts, r.flow.src_bytes, r.flow.dst_bytes, r.flow.rate, r.flow.load, r.flow.s_ttl,
  ].map(q).join(","));
  return [head.join(","), ...rows].join("\n");
}
