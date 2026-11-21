/** Browser-local database for "local mode": the tables the dashboard reads
 *  (flows, anomaly_events, incidents, suppressions, audit log, settings,
 *  per-source baselines) kept in IndexedDB on THIS browser, per origin.
 *  Nothing is sent anywhere. Clearing site data, a private window, or
 *  another browser/device means an empty database; there is no sync.
 *
 *  Implementation: each table is one JSON value in a single IndexedDB object
 *  store, loaded into memory on first use and written back (debounced) after
 *  changes. That is simple and fast enough for tens of thousands of rows; it
 *  is NOT a query engine and not meant for millions. If IndexedDB is not
 *  available the store works in memory only and says so via `persistent`. */

export interface FlowRow {
  id: number; src_ip: string | null; dst_ip: string | null; proto: string;
  dur: number; tot_pkts: number; src_bytes: number; dst_bytes: number; rate: number; load: number; s_ttl: number;
  ts: number | null; received_at: string; learning?: boolean;
}
export interface EventRow {
  id: number; flow_id: number; detector: "ECOD"; score: number; is_anomaly: true; severity: string;
  explanation: { feature: string; z_score: number }[]; consensus_count: number; escalation_reason: string | null;
  entity_baseline_z: number | null; src_ip: string | null; triage_status: "new" | "acknowledged" | "resolved";
  created_at: string; incident_id: string | null;
  detector_scores: { detector: string; score: number | null; is_anomaly: boolean }[];
}
export interface IncidentRow {
  id: string; tenant_id: string; src_ip: string | null; title: string; status: "open" | "closed";
  severity: string | null; event_count: number; first_seen: string; last_seen: string;
}
export interface SuppressionRow { id: string; src_ip: string; reason: string | null; created_by: string; created_at: string }
export interface AuditRow { id: number; actor: string; action: string; detail: any; created_at: string }
export interface DeviceDbRow {
  id: number; device_key: string; mac: string | null; ip: string | null; ips: string[]; role: string; tags: string[];
  hostname: string | null; os_hint: string | null; services: number[]; mac_randomized: boolean; evidence: string[];
  confidence: "low" | "medium" | "high"; first_seen: string; last_seen: string;
}
export interface ExternalDbRow {
  id: number; remote_ip: string; remote_port: number; proto: string; flows: number; packets: number;
  bytes_out: number; bytes_in: number; hostnames: string[]; first_seen: string; last_seen: string;
}
export interface OtDbRow {
  id: number; protocol: string; ts: string; src_ip: string; dst_ip: string; unit_id: number; function_code: number;
  function_name: string; is_request: boolean; is_exception: boolean; exception_code: number | null; address: number | null;
  quantity: number | null; severity: string | null; reason: string | null; incident_id: string | null; created_at: string;
}
export interface BaselineState { n: number; mean: number[]; m2: number[] }
export interface Settings { focus: string | null; learningMin: number; nextId: number; imports: ImportRecord[] }
export interface ImportRecord { at: string; source: string; flows: number; flagged: number; learning: number; devices?: number; endpoints?: number; ot?: number }

export interface Tables {
  flows: FlowRow[]; events: EventRow[]; incidents: IncidentRow[];
  suppressions: SuppressionRow[]; audit: AuditRow[]; baselines: Record<string, BaselineState>; settings: Settings;
  devices: DeviceDbRow[]; external: ExternalDbRow[]; otEvents: OtDbRow[]; otState: unknown | null;
}
const emptyTables = (): Tables => ({
  flows: [], events: [], incidents: [], suppressions: [], audit: [], baselines: {}, devices: [], external: [], otEvents: [], otState: null,
  settings: { focus: null, learningMin: 50, nextId: 1, imports: [] },
});

export const MAX_STORED_FLOWS = 50000;
const DB_NAME = "network-ai-local", STORE = "tables", KEY = "all";

let mem: Tables | null = null;
let loading: Promise<Tables> | null = null;
let timer: ReturnType<typeof setTimeout> | null = null;
export let persistent = false;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") return reject(new Error("IndexedDB unavailable"));
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export function getTables(): Promise<Tables> {
  if (mem) return Promise.resolve(mem);
  if (!loading) {
    loading = (async () => {
      try {
        const db = await openDb();
        const val = await new Promise<Tables | undefined>((res, rej) => {
          const r = db.transaction(STORE).objectStore(STORE).get(KEY);
          r.onsuccess = () => res(r.result as Tables | undefined);
          r.onerror = () => rej(r.error);
        });
        db.close();
        persistent = true;
        mem = { ...emptyTables(), ...(val ?? {}) };
        mem.settings = { ...emptyTables().settings, ...mem.settings };
      } catch {
        persistent = false;
        mem = emptyTables();
      }
      return mem;
    })();
  }
  return loading;
}

async function writeNow() {
  if (!mem || !persistent) return;
  try {
    const db = await openDb();
    await new Promise<void>((res, rej) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(mem, KEY);
      tx.oncomplete = () => res();
      tx.onerror = () => rej(tx.error);
    });
    db.close();
  } catch { /* best effort: stays in memory */ }
}
/** Mark the tables changed; persisted shortly after. */
export function save(): Promise<void> {
  if (timer) clearTimeout(timer);
  return new Promise((resolve) => { timer = setTimeout(() => { timer = null; writeNow().then(resolve); }, 150); });
}
export async function saveNow() { if (timer) { clearTimeout(timer); timer = null; } await writeNow(); }

export function nextId(t: Tables): number { return t.settings.nextId++; }
export function uuid(): string {
  const c = (globalThis as any).crypto;
  if (c?.randomUUID) return c.randomUUID();
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (ch) => { const r = (Math.random() * 16) | 0; return (ch === "x" ? r : (r & 3) | 8).toString(16); });
}
export function audit(t: Tables, action: string, detail: any) {
  t.audit.unshift({ id: nextId(t), actor: "local-user", action, detail, created_at: new Date().toISOString() });
  if (t.audit.length > 1000) t.audit.length = 1000;
}
export async function resetAll(): Promise<void> {
  await getTables();            // open storage first so the empty state is actually persisted
  mem = emptyTables();
  await saveNow();
}
/** Test hook: drop the in-memory copy so the next call reloads from storage. */
export function _forgetMemory() { mem = null; loading = null; }
