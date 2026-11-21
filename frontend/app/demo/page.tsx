"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { demoApi } from "@/lib/api";
import { severityColor, severityLabel, type Severity } from "@/lib/severity";

type Summary = { total_flows: number; total_anomalies: number; critical_anomalies: number; is_demo: boolean };
type AnomalyRow = {
  id: number; score: number; severity: Severity; src_ip: string | null;
  explanation: { feature: string; z_score: number }[] | null; consensus_count: number | null; created_at: string;
};
type Entity = { source: string; event_count: number; max_severity: Severity; protocols: string[]; last_seen: string };
type TrendDay = { date: string; low: number; medium: number; high: number; critical: number };

/** Public, read-only, no login -- real synthetic data (see
 * backend/scripts/seed_demo_tenant.py) run through the real detection
 * pipeline, not hand-faked numbers. Deliberately NOT under /dashboard: no
 * Supabase session exists here, every call goes to the unauthenticated
 * /demo/* backend routes. */
export default function PublicDemoPage() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [anomalies, setAnomalies] = useState<AnomalyRow[]>([]);
  const [entities, setEntities] = useState<Entity[]>([]);
  const [trend, setTrend] = useState<TrendDay[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([demoApi.getSummary(), demoApi.getRecentAnomalies(), demoApi.getEntities(), demoApi.getTrend(14)])
      .then(([s, a, e, t]) => {
        setSummary(s);
        setAnomalies(a);
        setEntities(e);
        setTrend(t);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div style={{ minHeight: "100vh", padding: "32px 40px", maxWidth: 1040, margin: "0 auto" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 6 }}>
        <span style={{ fontSize: 14, fontWeight: 600 }}>Network AI — live demo</span>
        {process.env.NEXT_PUBLIC_STATIC_DEMO !== "1" && (
          <Link href="/login" style={{ fontSize: 12, color: "var(--signal)", textDecoration: "none" }}>
            Sign in →
          </Link>
        )}
      </div>
      <p style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 24 }}>
        Synthetic traffic, scored by the real detection pipeline — not a mockup.
        {process.env.NEXT_PUBLIC_STATIC_DEMO === "1" && " This page shows a saved snapshot (no backend is running)."}
        {" "}Read-only, no account needed.
      </p>

      {error && <div style={{ color: "var(--critical)", fontSize: 13, marginBottom: 16 }}>
        {error}. The demo tenant may not be configured on this deployment.
      </div>}

      {loading ? (
        <div style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading…</div>
      ) : summary ? (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 1, marginBottom: 24 }}>
            <Tile label="Flows ingested" value={summary.total_flows.toLocaleString()} />
            <Tile label="Anomalies flagged" value={summary.total_anomalies.toString()} tone="alert" />
            <Tile label="Critical" value={summary.critical_anomalies.toString()} tone="critical" />
          </div>

          <TrendChart trend={trend} />

          <div style={{ display: "grid", gridTemplateColumns: "1.3fr 1fr", gap: 20, marginTop: 24 }}>
            <div>
              <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 10 }}>Recent flagged events</div>
              <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
                {anomalies.filter((a) => a.severity).slice(0, 12).map((a) => (
                  <div
                    key={a.id}
                    style={{ display: "flex", alignItems: "center", gap: 12, padding: "9px 14px", borderLeft: `3px solid ${severityColor(a.severity)}`, borderBottom: "1px solid var(--border)" }}
                  >
                    <span className="mono" style={{ fontSize: 11, color: severityColor(a.severity), width: 58, textTransform: "uppercase" }}>
                      {severityLabel(a.severity)}
                    </span>
                    <span className="mono" style={{ fontSize: 12, color: "var(--text-dim)", width: 90 }}>{a.src_ip ?? "—"}</span>
                    <span style={{ fontSize: 12, color: "var(--text-muted)", flex: 1 }}>
                      {a.explanation?.[0] ? `${a.explanation[0].feature} ${Math.abs(a.explanation[0].z_score).toFixed(1)}σ` : "Deviated from baseline"}
                    </span>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 10 }}>Flagged entities</div>
              <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
                {entities.slice(0, 8).map((e) => (
                  <div key={e.source} style={{ display: "flex", justifyContent: "space-between", padding: "9px 14px", borderBottom: "1px solid var(--border)", borderLeft: `3px solid ${severityColor(e.max_severity)}` }}>
                    <span className="mono" style={{ fontSize: 12 }}>{e.source}</span>
                    <span className="mono" style={{ fontSize: 12, color: "var(--text-dim)" }}>{e.event_count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <p style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 28, lineHeight: 1.6 }}>
            This is a sandbox tenant seeded with synthetic traffic generated to match a published
            5G network-intrusion dataset's statistical shape, scored by the same detection
            pipeline every real tenant runs. It is not live production traffic.
          </p>
        </>
      ) : null}
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

function TrendChart({ trend }: { trend: TrendDay[] }) {
  const SEVS: { key: keyof TrendDay; color: string }[] = [
    { key: "low", color: "var(--text-muted)" },
    { key: "medium", color: "#c99a3d" },
    { key: "high", color: "var(--alert)" },
    { key: "critical", color: "var(--critical)" },
  ];
  const maxTotal = Math.max(...trend.map((d) => d.low + d.medium + d.high + d.critical), 1);
  return (
    <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "16px 20px" }}>
      <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 14 }}>Flagged events — last {trend.length || 14} days</div>
      {trend.length === 0 ? (
        <div style={{ padding: "16px 0", color: "var(--text-dim)", fontSize: 13 }}>No trend data yet.</div>
      ) : (
        <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 100 }}>
          {trend.map((d) => {
            const total = d.low + d.medium + d.high + d.critical;
            return (
              <div key={d.date} title={`${d.date}: ${total} flagged`} style={{ flex: 1, display: "flex", flexDirection: "column-reverse", height: "100%" }}>
                {SEVS.map(({ key, color }) => {
                  const v = d[key] as number;
                  const heightPct = total === 0 ? 0 : (v / maxTotal) * 100;
                  return v > 0 ? <div key={key} style={{ background: color, height: `${heightPct}%`, minHeight: v > 0 ? 2 : 0 }} /> : null;
                })}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
