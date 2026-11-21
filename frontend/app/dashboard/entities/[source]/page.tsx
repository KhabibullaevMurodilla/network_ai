"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useRouteValue, anomalyHref } from "@/lib/links";
import Link from "next/link";
import { api } from "@/lib/api";
import { severityColor, severityLabel, type Severity } from "@/lib/severity";

type AnomalyRow = {
  id: number; severity: Severity; score: number | null; consensus_count: number | null;
  escalation_reason: string | null; triage_status: string; created_at: string;
};

export default function EntityDetailPage() {
  const source = useRouteValue("source");
  const router = useRouter();
  const decoded = decodeURIComponent(source);
  const [rows, setRows] = useState<AnomalyRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const srcIp = decoded === "unidentified" ? undefined : decoded;
    api
      .getRecentAnomalies(srcIp)
      .then((r: AnomalyRow[]) => setRows(decoded === "unidentified" ? r : r))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [decoded]);

  return (
    <div style={{ maxWidth: 820 }}>
      <button
        onClick={() => router.back()}
        style={{ fontSize: 12, color: "var(--text-dim)", background: "none", border: "none", cursor: "pointer", marginBottom: 16, padding: 0 }}
      >
        ← Back to entities
      </button>
      <h1 className="mono" style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>{decoded}</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 24 }}>
        All flagged events attributed to this source, most recent first.
      </p>

      {error && <div style={{ color: "var(--critical)", fontSize: 13, marginBottom: 16 }}>{error}</div>}

      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
        {loading ? (
          <div style={{ padding: 16, color: "var(--text-dim)", fontSize: 13 }}>Loading…</div>
        ) : rows.length === 0 ? (
          <div style={{ padding: 16, color: "var(--text-dim)", fontSize: 13 }}>No events for this source.</div>
        ) : (
          rows.map((r, idx) => {
            const color = severityColor(r.severity);
            return (
              <Link
                key={r.id}
                href={anomalyHref(r.id)}
                style={{
                  display: "flex", alignItems: "center", gap: 16, padding: "10px 16px",
                  borderLeft: `3px solid ${color}`,
                  borderBottom: idx < rows.length - 1 ? "1px solid var(--border)" : "none",
                  textDecoration: "none", color: "inherit",
                }}
              >
                <span className="mono" style={{ fontSize: 12, color: "var(--text-dim)", width: 150 }}>
                  {new Date(r.created_at).toISOString().replace("T", " ").slice(0, 19)}
                </span>
                <span className="mono" style={{ fontSize: 11, color, width: 60, textTransform: "uppercase" }}>{severityLabel(r.severity)}</span>
                <span className="mono" style={{ fontSize: 12, color: "var(--text-muted)", width: 50 }}>{r.score != null ? r.score.toFixed(1) : "—"}</span>
                <span className="mono" style={{ fontSize: 11, color: "var(--text-dim)", width: 90 }}>
                  {r.consensus_count != null ? `${r.consensus_count}/4 agree` : ""}
                </span>
                <span style={{ fontSize: 12, color: "var(--text-muted)", flex: 1, textTransform: "capitalize" }}>{r.triage_status}</span>
              </Link>
            );
          })
        )}
      </div>
    </div>
  );
}
