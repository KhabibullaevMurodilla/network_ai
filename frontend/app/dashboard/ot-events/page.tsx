"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { severityColor, severityLabel, type Severity } from "@/lib/severity";

type OtEvent = {
  id: number;
  protocol: string;
  ts: string;
  src_ip: string | null;
  dst_ip: string | null;
  unit_id: number | null;
  function_code: number | null;
  function_name: string | null;
  is_request: boolean;
  is_exception: boolean;
  exception_code: number | null;
  address: number | null;
  quantity: number | null;
  severity: Severity;
  reason: string | null;
  incident_id: string | null;
  created_at: string;
  mitre: { technique_id: string; technique: string } | null;
};

const REASON_LABELS: Record<string, string> = {
  new_function_code: "New function code for this device pair",
  unexpected_write_address: "Write to a never-before-seen address",
  exception_flood: "Exception-response flood (scan/probe shape)",
  unit_id_scan: "Many distinct unit IDs from one source (enumeration shape)",
};

const FILTER_KEY = "network-ai-ot-events-flagged-only";

export default function OtEventsPage() {
  const [events, setEvents] = useState<OtEvent[]>([]);
  const [flaggedOnly, setFlaggedOnly] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Remembered per-viewer across visits (localStorage, not shared state).
  useEffect(() => {
    try {
      const saved = localStorage.getItem(FILTER_KEY);
      if (saved !== null) setFlaggedOnly(saved === "true");
    } catch {
      /* per-viewer convenience only */
    }
  }, []);

  function load(flagged: boolean) {
    setLoading(true);
    api
      .getRecentOtEvents(flagged)
      .then(setEvents)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }

  useEffect(() => load(flaggedOnly), [flaggedOnly]);

  function setFlaggedOnlyPersist(v: boolean) {
    setFlaggedOnly(v);
    try {
      localStorage.setItem(FILTER_KEY, String(v));
    } catch {
      /* per-viewer convenience only */
    }
  }

  if (error) return <div style={{ color: "var(--critical)", fontSize: 13 }}>{error}</div>;

  return (
    <div style={{ maxWidth: 1000 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>OT protocol events</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 16, lineHeight: 1.6 }}>
        Modbus/TCP messages evaluated by a deterministic rule engine — separate from the
        statistical ML ensemble above, by design: industrial control traffic is deterministic
        enough that &quot;this device just got written to at an address nothing has ever written to
        before&quot; is a more trustworthy, explainable signal than an anomaly score. Requires pcap
        capture of Modbus/TCP traffic (via the live capture agent or an uploaded capture) on a
        network segment this tenant is monitoring.
      </p>

      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <button
          onClick={() => setFlaggedOnlyPersist(true)}
          style={{ ...toggleStyle, ...(flaggedOnly ? toggleActiveStyle : {}) }}
        >
          Flagged only
        </button>
        <button
          onClick={() => setFlaggedOnlyPersist(false)}
          style={{ ...toggleStyle, ...(!flaggedOnly ? toggleActiveStyle : {}) }}
        >
          All messages
        </button>
      </div>

      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
        <div
          style={{
            display: "flex",
            padding: "9px 16px",
            borderBottom: "1px solid var(--border)",
            fontSize: 11,
            color: "var(--text-dim)",
          }}
        >
          <span style={{ width: 90 }}>Severity</span>
          <span style={{ width: 150 }}>Device pair</span>
          <span style={{ width: 70 }}>Unit</span>
          <span style={{ width: 170 }}>Function</span>
          <span style={{ width: 90 }}>Address</span>
          <span style={{ flex: 1 }}>Reason</span>
          <span className="mono" style={{ width: 90, textAlign: "right" }}>Time</span>
        </div>

        {loading ? (
          <div style={{ padding: "24px 18px", color: "var(--text-dim)", fontSize: 13 }}>Loading…</div>
        ) : events.length === 0 ? (
          <div style={{ padding: "24px 18px", color: "var(--text-dim)", fontSize: 13 }}>
            {flaggedOnly
              ? "No flagged OT events yet. This is expected if no pcap with Modbus/TCP traffic has been ingested for this tenant."
              : "No OT protocol events recorded yet."}
          </div>
        ) : (
          events.map((e) => (
            <div
              key={e.id}
              style={{
                display: "flex",
                alignItems: "center",
                padding: "11px 16px",
                borderBottom: "1px solid var(--border)",
                borderLeft: `3px solid ${severityColor(e.severity)}`,
              }}
            >
              <span
                className="mono"
                style={{ width: 90, fontSize: 11, color: severityColor(e.severity), textTransform: "uppercase" }}
              >
                {severityLabel(e.severity)}
              </span>
              <span className="mono" style={{ width: 150, fontSize: 12 }}>
                {e.src_ip ?? "?"} → {e.dst_ip ?? "?"}
              </span>
              <span className="mono" style={{ width: 70, fontSize: 12, color: "var(--text-muted)" }}>
                {e.unit_id ?? "—"}
              </span>
              <span style={{ width: 170, fontSize: 12 }}>
                {e.function_name ?? `fc=${e.function_code}`}
                {e.is_exception && (
                  <span style={{ color: "var(--critical)" }}> (exception{e.exception_code != null ? ` ${e.exception_code}` : ""})</span>
                )}
                <span style={{ color: "var(--text-dim)" }}>{e.is_request ? " req" : " resp"}</span>
              </span>
              <span className="mono" style={{ width: 90, fontSize: 12, color: "var(--text-muted)" }}>
                {e.address ?? "—"}
              </span>
              <span style={{ flex: 1, fontSize: 12, color: "var(--text-muted)" }}>
                {e.reason ? REASON_LABELS[e.reason] ?? e.reason : "—"}
                {e.mitre && (
                  <span className="mono" style={{ marginLeft: 8, fontSize: 10, color: "var(--signal)", border: "1px solid var(--border-strong)", padding: "1px 5px" }}>
                    {e.mitre.technique_id}
                  </span>
                )}
              </span>
              <span className="mono" style={{ width: 90, fontSize: 11, color: "var(--text-dim)", textAlign: "right" }}>
                {new Date(e.ts).toTimeString().slice(0, 8)}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

const toggleStyle: React.CSSProperties = {
  padding: "6px 12px",
  fontSize: 12,
  background: "var(--bg-panel)",
  border: "1px solid var(--border)",
  borderRadius: 2,
  color: "var(--text-muted)",
  cursor: "pointer",
};

const toggleActiveStyle: React.CSSProperties = {
  color: "var(--text-primary)",
  borderColor: "var(--border-strong)",
  background: "var(--bg-panel-raised)",
};
