"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { entityHref } from "@/lib/links";

type Summary = { total_flows: number; total_anomalies: number; critical_anomalies: number };
type TrendDay = { date: string; low: number; medium: number; high: number; critical: number };
type Entity = { source: string; event_count: number; max_severity: string | null };
type Incident = { id: string; status: string; severity: string | null; title: string };

type Status = "quiet" | "attention" | "elevated";

/** All derived client-side from the same /dashboard/summary, /trend,
 * /entities, /incidents data every other page already reads -- no new
 * backend surface, just a plain-language read of numbers an analyst would
 * otherwise have to piece together themselves across three pages. */
export default function ExecutiveSummaryPage() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [trend, setTrend] = useState<TrendDay[]>([]);
  const [entities, setEntities] = useState<Entity[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api.getSummary(), api.getTrend(14), api.getEntities(), api.listIncidents("open")])
      .then(([s, t, e, i]) => {
        setSummary(s);
        setTrend(t);
        setEntities(e);
        setIncidents(i);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading…</div>;
  if (error) return <div style={{ color: "var(--critical)", fontSize: 13 }}>{error}</div>;
  if (!summary) return null;

  const last7 = trend.slice(-7);
  const prev7 = trend.slice(-14, -7);
  const weighted = (days: TrendDay[]) => days.reduce((sum, d) => sum + d.high * 2 + d.critical * 4 + d.medium, 0);
  const recentScore = weighted(last7);
  const priorScore = weighted(prev7);
  const direction: "improving" | "worsening" | "steady" =
    prev7.length === 0 || priorScore === 0
      ? "steady"
      : recentScore < priorScore * 0.8
      ? "improving"
      : recentScore > priorScore * 1.25
      ? "worsening"
      : "steady";

  const criticalEntities = entities.filter((e) => e.max_severity === "critical" || e.max_severity === "high");
  const openCritical = incidents.filter((i) => i.severity === "critical" || i.severity === "high").length;

  let status: Status = "quiet";
  if (summary.critical_anomalies > 0 || openCritical > 0) status = "elevated";
  else if (criticalEntities.length > 0 || incidents.length > 0) status = "attention";

  const STATUS_COPY: Record<Status, { label: string; color: string; sentence: string }> = {
    quiet: {
      label: "Quiet",
      color: "var(--signal)",
      sentence: "No open critical or high-severity issues. Routine background anomaly volume only.",
    },
    attention: {
      label: "Needs attention",
      color: "#c99a3d",
      sentence: "Nothing critical right now, but there are open items worth an analyst's look this week.",
    },
    elevated: {
      label: "Elevated risk",
      color: "var(--critical)",
      sentence: "There is at least one unresolved critical or high-severity issue that should be triaged now.",
    },
  };
  const copy = STATUS_COPY[status];

  return (
    <div style={{ maxWidth: 860 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>Network health — executive summary</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 24 }}>
        A plain-language read of the current security posture — for a stakeholder who wants the
        headline, not the alert queue.
      </p>

      <div style={{ border: `1px solid ${copy.color}`, background: "var(--bg-panel)", padding: "20px 24px", marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
          <span style={{ width: 10, height: 10, borderRadius: "50%", background: copy.color }} />
          <span style={{ fontSize: 16, fontWeight: 600, color: copy.color }}>{copy.label}</span>
        </div>
        <p style={{ fontSize: 14, lineHeight: 1.6, color: "var(--text-primary)" }}>{copy.sentence}</p>
        <p style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text-muted)", marginTop: 8 }}>
          Flagged-event volume over the last 7 days is{" "}
          <strong style={{ color: "var(--text-primary)" }}>
            {direction === "improving" ? "trending down" : direction === "worsening" ? "trending up" : "roughly steady"}
          </strong>{" "}
          compared to the week before.
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 1, marginBottom: 24 }}>
        <Tile label="Flows monitored" value={summary.total_flows.toLocaleString()} />
        <Tile label="Open incidents" value={incidents.length.toString()} tone={incidents.length > 0 ? "alert" : undefined} />
        <Tile label="Critical entities" value={criticalEntities.length.toString()} tone={criticalEntities.length > 0 ? "critical" : undefined} />
      </div>

      {criticalEntities.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 10 }}>Sources needing a look</div>
          <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
            {criticalEntities.slice(0, 5).map((e, i) => (
              <Link
                key={e.source}
                href={entityHref(e.source)}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  padding: "10px 16px",
                  borderBottom: i < Math.min(criticalEntities.length, 5) - 1 ? "1px solid var(--border)" : "none",
                  textDecoration: "none",
                  color: "inherit",
                  fontSize: 13,
                }}
              >
                <span className="mono">{e.source}</span>
                <span style={{ color: "var(--text-muted)" }}>{e.event_count} flagged events</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      <p style={{ fontSize: 12, color: "var(--text-dim)", lineHeight: 1.6 }}>
        This page summarizes the same detection output shown elsewhere in the dashboard, phrased
        for a non-technical reader — it is not a separate risk model and makes no claim beyond
        what the underlying flagged events and incidents already show.
      </p>
    </div>
  );
}

function Tile({ label, value, tone }: { label: string; value: string; tone?: "alert" | "critical" }) {
  const color = tone === "alert" ? "var(--alert)" : tone === "critical" ? "var(--critical)" : "var(--text-primary)";
  return (
    <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "14px 18px" }}>
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 6 }}>{label}</div>
      <div className="mono" style={{ fontSize: 22, fontWeight: 500, color }}>{value}</div>
    </div>
  );
}
