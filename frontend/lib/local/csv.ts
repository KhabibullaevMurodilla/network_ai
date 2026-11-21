import type { Flow } from "./types";

// Accepts this project's column names and the Argus-style capitalised ones.
const ALIASES: Record<string, string> = {
  dur: "dur", proto: "proto", tot_pkts: "tot_pkts", totpkts: "tot_pkts",
  src_bytes: "src_bytes", srcbytes: "src_bytes", dst_bytes: "dst_bytes", dstbytes: "dst_bytes",
  rate: "rate", load: "load", s_ttl: "s_ttl", sttl: "s_ttl",
  src_ip: "src_ip", srcaddr: "src_ip", dst_ip: "dst_ip", dstaddr: "dst_ip", label: "label",
  ts: "ts", timestamp: "ts", stime: "ts", start_time: "ts", time: "ts",
};
const REQUIRED = ["dur", "proto", "tot_pkts", "src_bytes", "dst_bytes", "rate", "load", "s_ttl"];

function splitLine(line: string): string[] {
  const out: string[] = [];
  let cur = "", q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') q = false;
      else cur += c;
    } else if (c === '"') q = true;
    else if (c === ",") { out.push(cur); cur = ""; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

export interface CsvResult { flows: Flow[]; skipped: number }

export function parseCsv(text: string): CsvResult {
  const lines = text.replace(/^﻿/, "").split(/\r?\n/).filter((l) => l.trim() !== "");
  if (lines.length < 2) throw new Error("The CSV has no data rows.");
  const header = splitLine(lines[0]).map((h) => ALIASES[h.trim().toLowerCase().replace(/[\s-]/g, "_")] ?? ALIASES[h.trim().toLowerCase()] ?? "");
  const missing = REQUIRED.filter((c) => !header.includes(c));
  if (missing.length) throw new Error(`Missing required column(s): ${missing.join(", ")}`);
  const idx: Record<string, number> = {};
  header.forEach((h, i) => { if (h && !(h in idx)) idx[h] = i; });
  const flows: Flow[] = [];
  let skipped = 0;
  for (let r = 1; r < lines.length; r++) {
    const cells = splitLine(lines[r]);
    const num = (k: string) => Number(cells[idx[k]]);
    const f: Flow = {
      dur: num("dur"), proto: String(cells[idx["proto"]] ?? "").trim().toUpperCase(),
      tot_pkts: num("tot_pkts"), src_bytes: num("src_bytes"), dst_bytes: num("dst_bytes"),
      rate: num("rate"), load: num("load"), s_ttl: num("s_ttl"),
    };
    if (idx.src_ip !== undefined) f.src_ip = (cells[idx.src_ip] ?? "").trim() || undefined;
    if (idx.dst_ip !== undefined) f.dst_ip = (cells[idx.dst_ip] ?? "").trim() || undefined;
    if (idx.ts !== undefined) {
      const raw = (cells[idx.ts] ?? "").trim();
      const n = Number(raw);
      const t = raw === "" ? NaN : Number.isFinite(n) ? (n > 1e11 ? n / 1000 : n) : Date.parse(raw) / 1000;
      if (Number.isFinite(t) && t > 0) f.ts = t;
    }
    if (idx.label !== undefined) f.label = (cells[idx.label] ?? "").trim() || undefined;
    const ok = f.proto !== "" && [f.dur, f.tot_pkts, f.src_bytes, f.dst_bytes, f.rate, f.load, f.s_ttl].every((v) => Number.isFinite(v));
    if (ok) flows.push(f); else skipped++;
  }
  if (!flows.length) throw new Error("No valid rows: every row had a missing or non-numeric value.");
  return { flows, skipped };
}
