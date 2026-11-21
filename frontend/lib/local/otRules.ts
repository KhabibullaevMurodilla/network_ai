/** Deterministic OT rule engine for Modbus/TCP, in the browser. Mirrors
 *  backend/app/ml/ot_rules.py (OTRuleEngine.evaluate) rule for rule, and emits
 *  the same record shape routers/ingest.py inserts into ot_protocol_events
 *  (minus tenant_id, which has no meaning in local mode).
 *
 *  The Python engine keeps its baselines in process memory; here they live in
 *  `OtState`, a plain JSON-serialisable object the caller persists and passes
 *  back in on the next import. evaluateOt never mutates the state it is given. */
import type { ModbusMessage } from "./modbus";

export const BASELINE_MIN_MESSAGES = 10;
export const EXCEPTION_FLOOD_WINDOW_SECONDS = 30;
export const EXCEPTION_FLOOD_THRESHOLD = 5;
export const UNIT_SCAN_WINDOW_SECONDS = 30;
export const UNIT_SCAN_DISTINCT_THRESHOLD = 4;

const WRITE_FCS = new Set([5, 6, 15, 16, 22, 23]);

export type OtSeverity = "medium" | "high" | "critical";
export type OtReason = "new_function_code" | "unexpected_write_address" | "exception_flood" | "unit_id_scan";

export interface OtEvent {
  protocol: "modbus_tcp";
  ts: string;                 // ISO-8601 UTC, formatted like pandas Timestamp.isoformat()
  src_ip: string;
  dst_ip: string;
  unit_id: number;
  function_code: number;
  function_name: string;
  is_request: boolean;
  is_exception: boolean;
  exception_code: number | null;
  address: number | null;
  quantity: number | null;
  severity: OtSeverity | null;
  reason: OtReason | null;
  incident_id: null;
}

/** JSON-serialisable baseline. Keys are "src|dst|unit" (devices) and "src|dst". */
export interface OtState {
  version: 1;
  devices: Record<string, { count: number; functionCodes: number[]; writeAddresses: number[] }>;
  exceptionWindows: Record<string, number[]>;
  unitScan: Record<string, Record<string, number>>;
}

export function emptyOtState(): OtState {
  return { version: 1, devices: {}, exceptionWindows: {}, unitScan: {} };
}

/** pandas: pd.Timestamp(ts, unit="s", tz="UTC").isoformat() */
export function isoFromSeconds(ts: number): string {
  let sec = Math.floor(ts);
  let ns = Math.round((ts - sec) * 1e9);
  if (ns >= 1e9) { sec += 1; ns -= 1e9; }
  const d = new Date(sec * 1000);
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  let s = `${p(d.getUTCFullYear(), 4)}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}T${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
  if (ns) s += "." + (ns % 1000 === 0 ? p(ns / 1000, 6) : p(ns, 9));
  return s + "+00:00";
}

export function evaluateOt(messages: ModbusMessage[], state?: OtState | null): { events: OtEvent[]; state: OtState } {
  const st: OtState = state ? JSON.parse(JSON.stringify(state)) : emptyOtState();
  const events: OtEvent[] = [];

  for (const m of messages) {
    const dkey = `${m.src_ip}|${m.dst_ip}|${m.unit_id}`;
    const pkey = `${m.src_ip}|${m.dst_ip}`;
    const dev = (st.devices[dkey] ??= { count: 0, functionCodes: [], writeAddresses: [] });
    let severity: OtSeverity | null = null;
    let reason: OtReason | null = null;

    const fc = m.function_code;
    const isWrite = WRITE_FCS.has(fc);
    const hasAddr = m.address !== null && m.address !== undefined && !Number.isNaN(m.address);

    if (dev.count >= BASELINE_MIN_MESSAGES) {
      if (!dev.functionCodes.includes(fc)) { severity = "medium"; reason = "new_function_code"; }
      if (isWrite && hasAddr && !dev.writeAddresses.includes(m.address as number)) {
        severity = "high"; reason = "unexpected_write_address";   // stronger signal wins
      }
    }

    if (m.is_exception) {
      const w = (st.exceptionWindows[pkey] ??= []);
      w.push(m.ts);
      const cutoff = m.ts - EXCEPTION_FLOOD_WINDOW_SECONDS;
      while (w.length && w[0] < cutoff) w.shift();
      const count = w.length;
      if (count >= EXCEPTION_FLOOD_THRESHOLD) { severity = "critical"; reason = "exception_flood"; }
      else if (count >= Math.max(EXCEPTION_FLOOD_THRESHOLD - 2, 2) && severity === null) { severity = "medium"; reason = "exception_flood"; }
    }

    if (m.is_request) {
      const tr = (st.unitScan[pkey] ??= {});
      tr[String(m.unit_id)] = m.ts;
      const cutoff = m.ts - UNIT_SCAN_WINDOW_SECONDS;
      for (const u of Object.keys(tr)) if (tr[u] < cutoff) delete tr[u];
      if (Object.keys(tr).length > UNIT_SCAN_DISTINCT_THRESHOLD) { severity = "high"; reason = "unit_id_scan"; }
    }

    // judged against history, never against itself: update after evaluating
    dev.count += 1;
    if (!dev.functionCodes.includes(fc)) dev.functionCodes.push(fc);
    if (isWrite && hasAddr && !dev.writeAddresses.includes(m.address as number)) dev.writeAddresses.push(m.address as number);

    events.push({
      protocol: "modbus_tcp", ts: isoFromSeconds(m.ts), src_ip: m.src_ip, dst_ip: m.dst_ip,
      unit_id: m.unit_id, function_code: fc, function_name: m.function_name,
      is_request: m.is_request, is_exception: m.is_exception, exception_code: m.exception_code,
      address: hasAddr ? m.address : null, quantity: m.quantity, severity, reason, incident_id: null,
    });
  }
  return { events, state: st };
}
