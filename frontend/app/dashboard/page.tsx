"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { anomalyHref } from "@/lib/links";
import { LOCAL_MODE } from "@/lib/api";
import { severityColor, severityLabel, type Severity } from "@/lib/severity";

type Summary = { total_flows: number; total_anomalies: number; critical_anomalies: number; tenant_id: string; role: string };
type Explanation = { feature: string; z_score: number }[];
type AnomalyRow = {
  id: number; flow_id: number; detector: string; score: number | null; is_anomaly: boolean;
  severity: Severity; explanation: Explanation | null; consensus_count: number | null;
  escalation_reason: string | null; triage_status: "new" | "acknowledged" | "resolved"; created_at: string;
};
type TrendDay = { date: string; low: number; medium: number; high: number; critical: number };

export default function DashboardPage() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [rows, setRows] = useState<AnomalyRow[]>([]);
  const [trend, setTrend] = useState<TrendDay[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [live, setLive] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    Promise.all([api.getSummary(), api.getRecentAnomalies(), api.getTrend(14)])
      .then(([s, a, t]) => {
        setSummary(s);
        setRows(a.reverse()); // chronological for the chart
        setTrend(t);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    let cancelled = false;
    api.connectStream((event) => {
      setRows((prev) => {
        if (prev.some((r) => r.id === event.id)) return prev;
        return [...prev, event];
      });
      setSummary((s) =>
        s
          ? {
              ...s,
              total_anomalies: s.total_anomalies + 1,
              critical_anomalies: event.severity === "critical" ? s.critical_anomalies + 1 : s.critical_anomalies,
            }
          : s
      );
    }).then((es) => {
      if (cancelled || !es) return;
      esRef.current = es;
      es.onopen = () => setLive(true);
      es.onerror = () => setLive(false);
    });
    return () => {
      cancelled = true;
      esRef.current?.close();
    };
  }, []);

  const flagged = useMemo(() => rows.filter((r) => r.is_anomaly).reverse(), [rows]);
  const detectionRate = summary && summary.total_flows > 0
    ? ((summary.total_anomalies / summary.total_flows) * 100).toFixed(1)
    : "—";

  if (loading) {
    return <div style={{ color: "var(--text-muted)", fontSize: 13 }}>Connecting to telemetry stream…</div>;
  }
  if (error) {
    return (
      <div style={{ color: "var(--critical)", fontSize: 13 }}>
        Couldn&apos;t reach the API — {error}. Check NEXT_PUBLIC_API_URL and that the backend is running.
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 1040 }}>
      {LOCAL_MODE && (summary?.total_flows ?? 0) === 0 && (
        <div style={{ border: "1px solid var(--border-strong)", background: "var(--bg-panel)", padding: 16, marginBottom: 16, fontSize: 13 }}>
          Nothing imported in this browser yet. <Link href="/dashboard/import/" style={{ color: "var(--signal)" }}>Import a capture or CSV →</Link>
        </div>
      )}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
        <SignalTrace rows={rows} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 1, marginTop: 24 }}>
        <Tile label="Flows ingested" value={(summary?.total_flows ?? 0).toLocaleString()} />
        <Tile label="Anomalies flagged" value={(summary?.total_anomalies ?? 0).toString()} tone="alert" />
        <Tile label="Critical" value={(summary?.critical_anomalies ?? 0).toString()} tone="critical" />
        <Tile label="Detection rate" value={typeof detectionRate === "string" && detectionRate !== "—" ? `${detectionRate}%` : "—"} tone="signal" />
      </div>

      <TrendChart trend={trend} />

      <EventLog flagged={flagged} live={live} />
    </div>
  );
}

function SignalTrace({ rows }: { rows: AnomalyRow[] }) {
  const w = 980;
  const h = 220;
  const padL = 36;
  const padB = 20;
  // A detector can rarely produce a non-finite score (now sanitized to
  // null by the backend rather than crashing on read -- see ingest.py's
  // _safe_score); treat it as 0 here so the chart stays continuous
  // instead of throwing on null.toFixed().
  const scores = rows.map((r) => r.score ?? 0);
  const maxScore = Math.max(...scores, 10) * 1.1;
  const threshold = scores.length ? [...scores].sort((a, b) => a - b)[Math.floor(scores.length * 0.9)] : 17.5;

  const x = (i: number) => padL + (i / Math.max(rows.length - 1, 1)) * (w - padL - 8);
  const y = (s: number) => h - padB - (s / maxScore) * (h - padB - 16);

  const path = rows.map((r, idx) => `${idx === 0 ? "M" : "L"} ${x(idx).toFixed(1)} ${y(r.score ?? 0).toFixed(1)}`).join(" ");
  const gridLines = [0, 10, 20, 30, 40].filter((v) => v < maxScore);

  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: 2, background: "var(--bg-panel)", padding: "18px 20px 14px", width: "100%" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
        <span style={{ fontSize: 13, color: "var(--text-muted)" }}>Anomaly score — last {rows.length} flows</span>
        <span className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }}>threshold {threshold.toFixed(1)}</span>
      </div>
      {rows.length === 0 ? (
        <div style={{ padding: "40px 0", color: "var(--text-dim)", fontSize: 13, textAlign: "center" }}>
          No flows yet. Connect a telemetry source to see live detection here.
        </div>
      ) : (
        <svg width="100%" viewBox={`0 0 ${w} ${h}`} style={{ display: "block", overflow: "visible" }}>
          {gridLines.map((v) => (
            <g key={v}>
              <line x1={padL} x2={w} y1={y(v)} y2={y(v)} stroke="var(--border)" strokeWidth="1" />
              <text x={0} y={y(v) + 4} className="mono" fontSize="10" fill="var(--text-dim)">{v}</text>
            </g>
          ))}
          <line x1={padL} x2={w} y1={y(threshold)} y2={y(threshold)} stroke="var(--alert)" strokeOpacity="0.5" strokeWidth="1" strokeDasharray="3 4" />
          <path d={path} fill="none" stroke="var(--signal)" strokeWidth="1.4" />
          {rows.map((r, idx) => r.is_anomaly && (
            <circle key={idx} cx={x(idx)} cy={y(r.score ?? 0)} r="2.6" fill="var(--bg-panel)" stroke={severityColor(r.severity)} strokeWidth="1.6" />
          ))}
        </svg>
      )}
    </div>
  );
}

function Tile({ label, value, tone, small }: { label: string; value: string; tone?: "signal" | "alert" | "critical"; small?: boolean }) {
  const color = tone === "signal" ? "var(--signal)" : tone === "alert" ? "var(--alert)" : tone === "critical" ? "var(--critical)" : "var(--text-primary)";
  return (
    <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "14px 18px" }}>
      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 6 }}>{label}</div>
      <div className="mono" style={{ fontSize: small ? 15 : 22, fontWeight: 500, color }}>{value}</div>
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
    <div style={{ marginTop: 24, border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "16px 20px" }}>
      <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 14 }}>Flagged events — last {trend.length || 14} days</div>
      {trend.length === 0 ? (
        <div style={{ padding: "16px 0", color: "var(--text-dim)", fontSize: 13 }}>No trend data yet.</div>
      ) : (
        <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 110 }}>
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
      <div style={{ display: "flex", gap: 16, marginTop: 10 }}>
        {SEVS.map(({ key, color }) => (
          <div key={key} style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <span style={{ width: 8, height: 8, background: color, display: "inline-block" }} />
            <span style={{ fontSize: 11, color: "var(--text-dim)", textTransform: "capitalize" }}>{key}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function explanationText(explanation: Explanation | null): string {
  if (!explanation || explanation.length === 0) return "Deviated from baseline";
  const top = explanation[0];
  const direction = top.z_score > 0 ? "above" : "below";
  const magnitude = Math.abs(top.z_score).toFixed(1);
  const rest = explanation.slice(1, 3).map((e) => e.feature).join(", ");
  const restText = rest ? ` (also: ${rest})` : "";
  return `${top.feature} ${magnitude}σ ${direction} baseline${restText}`;
}

function TriagePill({ status }: { status: string }) {
  const color = status === "resolved" ? "var(--signal)" : status === "acknowledged" ? "var(--alert)" : "var(--text-dim)";
  return (
    <span className="mono" style={{ fontSize: 10, color, border: `1px solid ${color}`, padding: "1px 6px", textTransform: "uppercase" }}>
      {status}
    </span>
  );
}

function EventLog({ flagged, live }: { flagged: AnomalyRow[]; live: boolean }) {
  return (
    <div style={{ marginTop: 28 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
        <span style={{ fontSize: 13, color: "var(--text-muted)" }}>Flagged events ({flagged.length})</span>
        <span style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <span style={{ width: 6, height: 6, borderRadius: "50%", background: live ? "var(--signal)" : "var(--text-dim)", boxShadow: live ? "0 0 0 3px var(--signal-dim)" : "none" }} />
          <span className="mono" style={{ fontSize: 10, color: live ? "var(--signal)" : "var(--text-dim)" }}>{live ? "live" : LOCAL_MODE ? "from this browser" : "connecting…"}</span>
        </span>
      </div>
      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
        {flagged.length === 0 ? (
          <div style={{ padding: "24px 18px", color: "var(--text-dim)", fontSize: 13 }}>
            No anomalies in this window. Connect a telemetry source to see live detections here.
          </div>
        ) : (
          flagged.slice(0, 20).map((f) => {
            const barColor = severityColor(f.severity);
            const time = new Date(f.created_at).toTimeString().slice(0, 8);
            return (
              <Link
                key={f.id}
                href={anomalyHref(f.id)}
                style={{ display: "flex", alignItems: "center", gap: 16, padding: "9px 16px", borderLeft: `3px solid ${barColor}`, borderBottom: "1px solid var(--border)", textDecoration: "none", color: "inherit" }}
              >
                <span className="mono" style={{ fontSize: 12, color: "var(--text-dim)", width: 70 }}>{time}</span>
                <span className="mono" style={{ fontSize: 11, color: barColor, width: 60, textTransform: "uppercase" }}>{severityLabel(f.severity)}</span>
                <span className="mono" style={{ fontSize: 12, color: "var(--text-muted)", width: 50 }}>{f.score != null ? f.score.toFixed(1) : "—"}</span>
                <span style={{ fontSize: 13, color: "var(--text-primary)", flex: 1 }}>
                  {explanationText(f.explanation)}
                  {f.consensus_count != null && f.consensus_count >= 2 && (
                    <span className="mono" style={{ fontSize: 10, color: "var(--signal)", marginLeft: 8 }}>{f.consensus_count}/4 agree</span>
                  )}
                </span>
                <TriagePill status={f.triage_status || "new"} />
                <span className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }}>{f.detector}</span>
              </Link>
            );
          })
        )}
      </div>
    </div>
  );
}
