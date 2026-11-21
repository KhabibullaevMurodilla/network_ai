"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { entityHref } from "@/lib/links";
import { severityColor, severityLabel, type Severity } from "@/lib/severity";

type Entity = {
  source: string;
  event_count: number;
  max_severity: Severity;
  protocols: string[];
  last_seen: string;
};

type Suppression = { id: string; src_ip: string; reason: string | null; created_at: string };

export default function EntitiesPage() {
  const [entities, setEntities] = useState<Entity[]>([]);
  const [suppressions, setSuppressions] = useState<Suppression[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  function load() {
    Promise.all([api.getEntities(), api.listSuppressions()])
      .then(([e, s]) => {
        setEntities(e);
        setSuppressions(s);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }
  useEffect(load, []);

  const suppressedBySource = new Map(suppressions.map((s) => [s.src_ip, s]));

  async function toggleMute(source: string, e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    if (source === "unidentified") return;
    setBusy(source);
    try {
      const existing = suppressedBySource.get(source);
      if (existing) {
        await api.deleteSuppression(existing.id);
      } else {
        await api.createSuppression(source, "muted from entity view");
      }
      load();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  }

  if (loading) return <div style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading…</div>;
  if (error) return <div style={{ color: "var(--critical)", fontSize: 13 }}>{error}</div>;

  return (
    <div style={{ maxWidth: 980 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>Entities</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 24 }}>
        Flagged anomalies grouped by source — which machines are misbehaving, not just which
        flows. A source of &quot;unidentified&quot; means telemetry arrived without an IP attached.
        Muting a source stops it paging your alert channels — it keeps being scored and shown here.
      </p>

      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
        <div style={{ display: "flex", padding: "9px 16px", borderBottom: "1px solid var(--border)", fontSize: 11, color: "var(--text-dim)" }}>
          <span style={{ width: 160 }}>Source</span>
          <span style={{ width: 90 }}>Severity</span>
          <span style={{ width: 70 }}>Events</span>
          <span style={{ flex: 1 }}>Protocols</span>
          <span className="mono" style={{ width: 90, textAlign: "right" }}>Last seen</span>
          <span style={{ width: 80, textAlign: "right" }}>Alerts</span>
        </div>
        {entities.length === 0 ? (
          <div style={{ padding: "24px 18px", color: "var(--text-dim)", fontSize: 13 }}>
            No flagged entities yet.
          </div>
        ) : (
          entities.map((e) => {
            const muted = suppressedBySource.has(e.source);
            return (
              <Link
                key={e.source}
                href={entityHref(e.source)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  padding: "11px 16px",
                  borderBottom: "1px solid var(--border)",
                  borderLeft: `3px solid ${severityColor(e.max_severity)}`,
                  textDecoration: "none",
                  color: "inherit",
                  opacity: muted ? 0.6 : 1,
                }}
              >
                <span className="mono" style={{ width: 160, fontSize: 13 }}>{e.source}</span>
                <span className="mono" style={{ width: 90, fontSize: 11, color: severityColor(e.max_severity), textTransform: "uppercase" }}>
                  {severityLabel(e.max_severity)}
                </span>
                <span className="mono" style={{ width: 70, fontSize: 13 }}>{e.event_count}</span>
                <span style={{ flex: 1, fontSize: 12, color: "var(--text-muted)" }}>{e.protocols.join(", ")}</span>
                <span className="mono" style={{ width: 90, fontSize: 11, color: "var(--text-dim)", textAlign: "right" }}>
                  {new Date(e.last_seen).toTimeString().slice(0, 8)}
                </span>
                <span style={{ width: 80, textAlign: "right" }}>
                  {e.source !== "unidentified" && (
                    <button
                      onClick={(ev) => toggleMute(e.source, ev)}
                      disabled={busy === e.source}
                      style={{
                        fontSize: 11,
                        background: "none",
                        border: `1px solid ${muted ? "var(--signal)" : "var(--border-strong)"}`,
                        borderRadius: 2,
                        color: muted ? "var(--signal)" : "var(--text-dim)",
                        padding: "3px 8px",
                        cursor: "pointer",
                      }}
                    >
                      {muted ? "Unmute" : "Mute"}
                    </button>
                  )}
                </span>
              </Link>
            );
          })
        )}
      </div>
    </div>
  );
}
