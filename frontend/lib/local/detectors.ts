/** Re-implementations of the four detectors the Python engine uses, so the
 *  analysis can run in the browser. They follow the same published algorithms
 *  (ECOD, Isolation Forest, LOF, Half-Space Trees) but are NOT the same code as
 *  PyOD / scikit-learn / River; see tests/validate for how closely they agree. */

export type Matrix = Float64Array[]; // rows

export function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function percentile(values: ArrayLike<number>, p: number): number {
  const a = Float64Array.from(values as ArrayLike<number>).sort();
  if (a.length === 0) return NaN;
  const pos = (p / 100) * (a.length - 1);
  const lo = Math.floor(pos), hi = Math.ceil(pos);
  return a[lo] + (a[hi] - a[lo]) * (pos - lo);
}

/* ---------------------------------------------------------------- ECOD */
export function ecodScores(X: Matrix): Float64Array {
  const n = X.length, d = X[0].length;
  const out = new Float64Array(n);
  for (let j = 0; j < d; j++) {
    const idx = Array.from({ length: n }, (_, i) => i).sort((p, q) => X[p][j] - X[q][j]);
    const Fl = new Float64Array(n), Fr = new Float64Array(n);
    for (let s = 0; s < n; ) {            // runs of equal values share one ECDF value
      let e = s;
      while (e + 1 < n && X[idx[e + 1]][j] === X[idx[s]][j]) e++;
      for (let t = s; t <= e; t++) { Fl[idx[t]] = (e + 1) / n; Fr[idx[t]] = (n - s) / n; }
      s = e + 1;
    }
    let mean = 0;
    for (let i = 0; i < n; i++) mean += X[i][j];
    mean /= n;
    let m2 = 0, m3 = 0;
    for (let i = 0; i < n; i++) { const c = X[i][j] - mean; m2 += c * c; m3 += c * c * c; }
    m2 /= n; m3 /= n;
    const sk = m2 > 1e-300 ? Math.sign(m3 / Math.pow(m2, 1.5)) : 0;
    for (let i = 0; i < n; i++) {
      const ul = -Math.log(Fl[i]), ur = -Math.log(Fr[i]);
      const us = sk < 0 ? ul : sk > 0 ? ur : ul + ur;   // skewness-corrected tail (PyOD's U_skew)
      out[i] += Math.max(ul, ur, us);
    }
  }
  return out;
}

/* -------------------------------------------------------- Isolation Forest */
const EULER = 0.5772156649;
function cFactor(n: number): number {
  if (n <= 1) return 0;
  if (n === 2) return 1;
  return 2 * (Math.log(n - 1) + EULER) - (2 * (n - 1)) / n;
}

interface ITree { feat: Int16Array; thr: Float64Array; left: Int32Array; right: Int32Array; size: Int32Array }

function buildITree(X: Matrix, rows: number[], maxDepth: number, rnd: () => number): ITree {
  const feat: number[] = [], thr: number[] = [], left: number[] = [], right: number[] = [], size: number[] = [];
  const d = X[0].length;
  const make = (ids: number[], depth: number): number => {
    const me = feat.length;
    feat.push(-1); thr.push(0); left.push(-1); right.push(-1); size.push(ids.length);
    if (ids.length <= 1 || depth >= maxDepth) return me;
    // pick a random feature that is not constant in this node
    const cand: number[] = [];
    const lo: number[] = [], hi: number[] = [];
    for (let j = 0; j < d; j++) {
      let a = Infinity, b = -Infinity;
      for (const i of ids) { const v = X[i][j]; if (v < a) a = v; if (v > b) b = v; }
      lo.push(a); hi.push(b);
      if (b > a) cand.push(j);
    }
    if (!cand.length) return me;
    const j = cand[Math.floor(rnd() * cand.length)];
    const t = lo[j] + rnd() * (hi[j] - lo[j]);
    const L: number[] = [], R: number[] = [];
    for (const i of ids) (X[i][j] < t ? L : R).push(i);
    if (!L.length || !R.length) return me;
    feat[me] = j; thr[me] = t;
    left[me] = make(L, depth + 1);
    right[me] = make(R, depth + 1);
    return me;
  };
  make(rows, 0);
  return { feat: Int16Array.from(feat), thr: Float64Array.from(thr), left: Int32Array.from(left), right: Int32Array.from(right), size: Int32Array.from(size) };
}

export function iforestScores(X: Matrix, seed = 42, nTrees = 200, maxSamples = 256): Float64Array {
  const n = X.length;
  const psi = Math.min(maxSamples, n);
  const maxDepth = Math.ceil(Math.log2(Math.max(psi, 2)));
  const rnd = mulberry32(seed);
  const trees: ITree[] = [];
  for (let t = 0; t < nTrees; t++) {
    const ids = Array.from({ length: n }, (_, i) => i);
    for (let i = 0; i < psi; i++) { const k = i + Math.floor(rnd() * (n - i)); [ids[i], ids[k]] = [ids[k], ids[i]]; }
    trees.push(buildITree(X, ids.slice(0, psi), maxDepth, rnd));
  }
  const cPsi = cFactor(psi);
  const out = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    let sum = 0;
    for (const tr of trees) {
      let node = 0, depth = 0;
      while (tr.feat[node] >= 0) { node = X[i][tr.feat[node]] < tr.thr[node] ? tr.left[node] : tr.right[node]; depth++; }
      sum += depth + cFactor(tr.size[node]);
    }
    out[i] = Math.pow(2, -(sum / nTrees) / cPsi);
  }
  return out;
}

/* ------------------------------------------------------------------- LOF */
/** LOF against a reference sample (leave-one-out for rows that are in it). */
export function lofScores(X: Matrix, k = 20, maxRef = 3000, seed = 7): Float64Array {
  const n = X.length, d = X[0].length;
  const rnd = mulberry32(seed);
  let ref = Array.from({ length: n }, (_, i) => i);
  if (n > maxRef) {
    for (let i = 0; i < maxRef; i++) { const j = i + Math.floor(rnd() * (n - i)); [ref[i], ref[j]] = [ref[j], ref[i]]; }
    ref = ref.slice(0, maxRef).sort((a, b) => a - b);
  }
  const m = ref.length;
  const kk = Math.max(1, Math.min(k, m - 1));
  const R = ref.map((i) => X[i]);
  const dist = (a: Float64Array, b: Float64Array) => { let s = 0; for (let j = 0; j < d; j++) { const t = a[j] - b[j]; s += t * t; } return Math.sqrt(s); };

  const knn = (q: Float64Array, self: number) => {  // k nearest in the reference set, excluding index `self`
    const bd = new Float64Array(kk).fill(Infinity), bi = new Int32Array(kk).fill(-1);
    for (let r = 0; r < m; r++) {
      if (r === self) continue;
      const dd = dist(q, R[r]);
      if (dd >= bd[kk - 1]) continue;
      let p = kk - 1;
      while (p > 0 && bd[p - 1] > dd) { bd[p] = bd[p - 1]; bi[p] = bi[p - 1]; p--; }
      bd[p] = dd; bi[p] = r;
    }
    return { bd, bi };
  };

  const kdist = new Float64Array(m), lrd = new Float64Array(m);
  const nbr: { bd: Float64Array; bi: Int32Array }[] = [];
  for (let r = 0; r < m; r++) { const nb = knn(R[r], r); nbr.push(nb); kdist[r] = nb.bd[kk - 1]; }
  for (let r = 0; r < m; r++) {
    let s = 0;
    for (let t = 0; t < kk; t++) s += Math.max(kdist[nbr[r].bi[t]], nbr[r].bd[t]);
    lrd[r] = 1 / (s / kk + 1e-10);
  }
  const refPos = new Map<number, number>(ref.map((v, i) => [v, i]));
  const out = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    const self = refPos.get(i) ?? -1;
    const { bd, bi } = self >= 0 ? nbr[self] : knn(X[i], -1);
    let s = 0, l = 0;
    for (let t = 0; t < kk; t++) { s += Math.max(kdist[bi[t]], bd[t]); l += lrd[bi[t]]; }
    out[i] = (l / kk) / (1 / (s / kk + 1e-10));
  }
  return out;
}

/* ------------------------------------------------------- Half-Space Trees */
/** Batch variant of River's HalfSpaceTrees: learn a reference mass profile from
 *  (up to) 1000 rows in order, then score every row against it. Features must
 *  already be scaled to [0,1]. Returns null if there are fewer than one window
 *  of rows (the model needs a full reference window). */
export function hstScores(X01: Matrix, seed = 11, nTrees = 10, height = 8, windowSize = 250): Float64Array | null {
  const n = X01.length, d = X01[0].length;
  if (n < windowSize) return null;
  const rnd = mulberry32(seed);
  const nodes = (1 << (height + 1)) - 1;
  const trees = Array.from({ length: nTrees }, () => {
    const lo = new Float64Array(d), hi = new Float64Array(d);
    for (let j = 0; j < d; j++) { const s = rnd(), w = 2 * Math.max(s, 1 - s); lo[j] = s - w; hi[j] = s + w; }
    const feat = new Int16Array(nodes), split = new Float64Array(nodes);
    const build = (node: number, depth: number, l: Float64Array, h: Float64Array) => {
      if (depth >= height) return;
      const f = Math.floor(rnd() * d);
      const mid = (l[f] + h[f]) / 2;
      feat[node] = f; split[node] = mid;
      const h2 = h.slice(); h2[f] = mid;
      const l2 = l.slice(); l2[f] = mid;
      build(2 * node + 1, depth + 1, l, h2);
      build(2 * node + 2, depth + 1, l2, h);
    };
    build(0, 0, lo, hi);
    return { feat, split, r: new Float64Array(nodes), l: new Float64Array(nodes) };
  });
  const path = (t: typeof trees[number], x: Float64Array, visit: (node: number, depth: number) => boolean) => {
    let node = 0;
    for (let depth = 0; depth <= height; depth++) {
      if (visit(node, depth) || depth === height) return;
      node = x[t.feat[node]] < t.split[node] ? 2 * node + 1 : 2 * node + 2;
    }
  };
  const learnRows = Math.min(n, 1000);
  const step = n / learnRows;
  let count = 0, swapped = false;
  for (let s = 0; s < learnRows; s++) {
    const x = X01[Math.floor(s * step)];
    for (const t of trees) path(t, x, (node) => { t.l[node]++; return false; });
    if (++count === windowSize) { for (const t of trees) { t.r.set(t.l); t.l.fill(0); } count = 0; swapped = true; }
  }
  if (!swapped) return null;
  const sizeLimit = 0.1 * windowSize;
  const out = new Float64Array(n);
  const denom = nTrees * windowSize * Math.pow(2, height);
  for (let i = 0; i < n; i++) {
    let sc = 0;
    for (const t of trees) path(t, X01[i], (node, depth) => {
      if (depth >= height || t.r[node] <= sizeLimit) { sc += t.r[node] * Math.pow(2, depth); return true; }
      return false;
    });
    out[i] = 1 - sc / denom;
  }
  return out;
}
