"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { incidentHref } from "@/lib/links";
import { severityColor, severityLabel, type Severity } from "@/lib/severity";

type Incident = {
  id: string;
  src_ip: string | null;
  title: string;
  status: "open" | "closed";
  severity: Severity;
  event_count: number;
  first_seen: string;
  last_seen: string;
};

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [filter, setFilter] = useState<"open" | "closed" | "all">("open");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  function load(f: "open" | "closed" | "all") {
    setLoading(true);
    api
      .listIncidents(f === "all" ? undefined : f)
      .then(setIncidents)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }
  useEffect(() => load(filter), [filter]);

  return (
    <div style={{ maxWidth: 900 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>Incidents</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 20 }}>
        Flagged events from the same source within a 30-minute window are correlated into one
        case, so a sustained scan shows up as one incident with many events instead of dozens
        of separate alerts.
      </p>

      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {(["open", "closed", "all"] as const).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            style={{
              fontSize: 12,
              padding: "6px 14px",
              borderRadius: 2,
              cursor: "pointer",
              textTransform: "capitalize",
              border: filter === f ? "1px solid var(--signal)" : "1px solid var(--border-strong)",
              background: filter === f ? "var(--signal-dim)" : "transparent",
              color: filter === f ? "var(--text-primary)" : "var(--text-muted)",
            }}
          >
            {f}
          </button>
        ))}
      </div>

      {error && <div style={{ color: "var(--critical)", fontSize: 13, marginBottom: 16 }}>{error}</div>}

      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
        {loading ? (
          <div style={{ padding: 16, color: "var(--text-dim)", fontSize: 13 }}>Loading…</div>
        ) : incidents.length === 0 ? (
          <div style={{ padding: 16, color: "var(--text-dim)", fontSize: 13 }}>No {filter !== "all" ? filter : ""} incidents.</div>
        ) : (
          incidents.map((inc, idx) => {
            const color = severityColor(inc.severity);
            return (
              <Link
                key={inc.id}
                href={incidentHref(inc.id)}
                style={{
                  display: "flex", alignItems: "center", gap: 16, padding: "12px 16px",
                  borderLeft: `3px solid ${color}`,
                  borderBottom: idx < incidents.length - 1 ? "1px solid var(--border)" : "none",
                  textDecoration: "none", color: "inherit",
                }}
              >
                <span className="mono" style={{ fontSize: 11, color, width: 60, textTransform: "uppercase" }}>{severityLabel(inc.severity)}</span>
                <span style={{ fontSize: 13, flex: 1 }}>{inc.title}</span>
                <span className="mono" style={{ fontSize: 12, color: "var(--text-muted)", width: 90 }}>{inc.event_count} events</span>
                <span className="mono" style={{ fontSize: 11, color: "var(--text-dim)", width: 110 }}>
                  {new Date(inc.last_seen).toISOString().replace("T", " ").slice(0, 16)}
                </span>
                <span
                  className="mono"
                  style={{
                    fontSize: 10, padding: "2px 8px", textTransform: "uppercase",
                    color: inc.status === "open" ? "var(--alert)" : "var(--signal)",
                    border: `1px solid ${inc.status === "open" ? "var(--alert)" : "var(--signal)"}`,
                  }}
                >
                  {inc.status}
                </span>
              </Link>
            );
          })
        )}
      </div>
    </div>
  );
}
