"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useRouteValue, anomalyHref } from "@/lib/links";
import Link from "next/link";
import { api } from "@/lib/api";
import { severityColor, severityLabel, type Severity } from "@/lib/severity";

type IncidentEvent = {
  id: number; score: number | null; severity: Severity; consensus_count: number | null;
  escalation_reason: string | null; triage_status: string; created_at: string;
};
type IncidentDetail = {
  id: string; src_ip: string | null; title: string; status: "open" | "closed";
  severity: Severity; event_count: number; first_seen: string; last_seen: string;
  events: IncidentEvent[];
};

export default function IncidentDetailPage() {
  const id = useRouteValue("id");
  const router = useRouter();
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [error, setError] = useState("");
  const [updating, setUpdating] = useState(false);

  function load() {
    api.getIncidentDetail(id).then(setIncident).catch((e) => setError(e.message));
  }
  useEffect(load, [id]);

  async function toggleStatus() {
    if (!incident) return;
    setUpdating(true);
    try {
      await api.updateIncidentStatus(id, incident.status === "open" ? "closed" : "open");
      load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setUpdating(false);
    }
  }

  if (error) return <div style={{ color: "var(--critical)", fontSize: 13 }}>{error}</div>;
  if (!incident) return <div style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading…</div>;

  const color = severityColor(incident.severity);

  return (
    <div style={{ maxWidth: 820 }}>
      <button
        onClick={() => router.back()}
        style={{ fontSize: 12, color: "var(--text-dim)", background: "none", border: "none", cursor: "pointer", marginBottom: 16, padding: 0 }}
      >
        ← Back to incidents
      </button>

      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4 }}>
        <span className="mono" style={{ fontSize: 11, padding: "3px 8px", border: `1px solid ${color}`, color, textTransform: "uppercase" }}>
          {severityLabel(incident.severity)}
        </span>
        <h1 style={{ fontSize: 18, fontWeight: 600 }}>{incident.title}</h1>
      </div>
      <p className="mono" style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 24 }}>
        First seen {new Date(incident.first_seen).toISOString().replace("T", " ").slice(0, 19)} UTC ·
        {" "}{incident.event_count} correlated events
      </p>

      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "14px 16px", marginBottom: 24, display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{ fontSize: 13, color: "var(--text-muted)" }}>Status:</span>
        <span
          className="mono"
          style={{
            fontSize: 11, padding: "3px 10px", textTransform: "uppercase",
            color: incident.status === "open" ? "var(--alert)" : "var(--signal)",
            border: `1px solid ${incident.status === "open" ? "var(--alert)" : "var(--signal)"}`,
          }}
        >
          {incident.status}
        </span>
        <button
          onClick={toggleStatus}
          disabled={updating}
          style={{
            marginLeft: "auto", fontSize: 12, padding: "6px 14px", borderRadius: 2, cursor: "pointer",
            border: "1px solid var(--border-strong)", background: "var(--bg-panel-raised)", color: "var(--text-primary)",
          }}
        >
          {incident.status === "open" ? "Close incident" : "Reopen incident"}
        </button>
      </div>

      <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 10 }}>Correlated events</div>
      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
        {incident.events.map((e, idx) => {
          const c = severityColor(e.severity);
          return (
            <Link
              key={e.id}
              href={anomalyHref(e.id)}
              style={{
                display: "flex", alignItems: "center", gap: 16, padding: "10px 16px",
                borderLeft: `3px solid ${c}`,
                borderBottom: idx < incident.events.length - 1 ? "1px solid var(--border)" : "none",
                textDecoration: "none", color: "inherit",
              }}
            >
              <span className="mono" style={{ fontSize: 12, color: "var(--text-dim)", width: 150 }}>
                {new Date(e.created_at).toISOString().replace("T", " ").slice(0, 19)}
              </span>
              <span className="mono" style={{ fontSize: 11, color: c, width: 60, textTransform: "uppercase" }}>{severityLabel(e.severity)}</span>
              <span className="mono" style={{ fontSize: 12, color: "var(--text-muted)", width: 50 }}>{e.score != null ? e.score.toFixed(1) : "—"}</span>
              <span style={{ fontSize: 12, color: "var(--text-dim)", flex: 1 }}>
                {e.escalation_reason ? e.escalation_reason.replace(/_/g, " ") : ""}
              </span>
              <span style={{ fontSize: 12, color: "var(--text-muted)", textTransform: "capitalize" }}>{e.triage_status}</span>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
