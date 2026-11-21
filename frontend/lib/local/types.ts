/** A flow record: the same fields the Python engine scores. */
export interface Flow {
  dur: number;
  proto: string;
  tot_pkts: number;
  src_bytes: number;
  dst_bytes: number;
  rate: number;
  load: number;
  s_ttl: number;
  src_ip?: string;
  dst_ip?: string;
  ts?: number;    // flow start, epoch seconds (when the source has timestamps)
  label?: string; // optional ground truth, only used to show a self-check
}

export const NUMERIC_FEATURES = ["dur", "tot_pkts", "src_bytes", "dst_bytes", "rate", "load", "s_ttl"] as const;
export type Severity = "low" | "medium" | "high" | "critical";
