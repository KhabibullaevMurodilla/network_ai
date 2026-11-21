"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type TrendDay = { date: string; low: number; medium: number; high: number; critical: number };
type Entity = { source: string; event_count: number };

const RANGES = [7, 14, 30, 90];
const FILTER_KEY = "network-ai-trends-filter";

function loadSavedFilter(): { days: number; srcIp: string } {
  try {
    const raw = localStorage.getItem(FILTER_KEY);
    if (!raw) return { days: 14, srcIp: "" };
    const parsed = JSON.parse(raw);
    return { days: RANGES.includes(parsed.days) ? parsed.days : 14, srcIp: typeof parsed.srcIp === "string" ? parsed.srcIp : "" };
  } catch {
    return { days: 14, srcIp: "" };
  }
}

export default function TrendsPage() {
  const [days, setDays] = useState(14);
  const [srcIp, setSrcIp] = useState("");
  const [hydrated, setHydrated] = useState(false);

  // Remembered per-viewer across visits -- a saved filter view, not shared
  // state, so it lives in localStorage rather than being read back here.
  useEffect(() => {
    const saved = loadSavedFilter();
    setDays(saved.days);
    setSrcIp(saved.srcIp);
    setHydrated(true);
  }, []);
  useEffect(() => {
    if (!hydrated) return;
    try {
      localStorage.setItem(FILTER_KEY, JSON.stringify({ days, srcIp }));
    } catch {
      /* per-viewer convenience only */
    }
  }, [days, srcIp, hydrated]);
  const [entities, setEntities] = useState<Entity[]>([]);
  const [trend, setTrend] = useState<TrendDay[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState(false);

  async function handleDownload() {
    setDownloading(true);
    try {
      await api.downloadReportPdf(days);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setDownloading(false);
    }
  }

  useEffect(() => {
    api.getEntities().then(setEntities).catch(() => {});
  }, []);

  useEffect(() => {
    setLoading(true);
    api
      .getTrend(days, srcIp || undefined)
      .then(setTrend)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [days, srcIp]);

  const SEVS: { key: keyof TrendDay; color: string; label: string }[] = [
    { key: "low", color: "var(--text-muted)", label: "Low" },
    { key: "medium", color: "#c99a3d", label: "Medium" },
    { key: "high", color: "var(--alert)", label: "High" },
    { key: "critical", color: "var(--critical)", label: "Critical" },
  ];
  const totals = trend.reduce(
    (acc, d) => ({ low: acc.low + d.low, medium: acc.medium + d.medium, high: acc.high + d.high, critical: acc.critical + d.critical }),
    { low: 0, medium: 0, high: 0, critical: 0 }
  );
  const grandTotal = totals.low + totals.medium + totals.high + totals.critical;
  const maxTotal = Math.max(...trend.map((d) => d.low + d.medium + d.high + d.critical), 1);

  return (
    <div style={{ maxWidth: 1040 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>Trends</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 20 }}>
        Flagged-event volume over time, fleet-wide or narrowed to one entity — whether things are
        getting better or worse, not just what&apos;s flagged right now.
      </p>

      <div style={{ display: "flex", gap: 16, alignItems: "center", marginBottom: 20, flexWrap: "wrap" }}>
        <div style={{ display: "flex", gap: 6 }}>
          {RANGES.map((r) => (
            <button
              key={r}
              onClick={() => setDays(r)}
              style={{
                padding: "6px 12px",
                fontSize: 12,
                background: days === r ? "var(--bg-panel-raised)" : "var(--bg-panel)",
                border: `1px solid ${days === r ? "var(--border-strong)" : "var(--border)"}`,
                borderRadius: 2,
                color: days === r ? "var(--text-primary)" : "var(--text-muted)",
                cursor: "pointer",
              }}
            >
              {r}d
            </button>
          ))}
        </div>
        <select
          value={srcIp}
          onChange={(e) => setSrcIp(e.target.value)}
          style={{ padding: "6px 10px", fontSize: 12, background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 2, color: "var(--text-primary)" }}
        >
          <option value="">All entities (fleet-wide)</option>
          {entities.map((e) => (
            <option key={e.source} value={e.source}>{e.source} ({e.event_count})</option>
          ))}
        </select>
        <button
          onClick={handleDownload}
          disabled={downloading}
          style={{
            marginLeft: "auto",
            padding: "6px 14px",
            fontSize: 12,
            fontWeight: 500,
            background: "var(--bg-panel-raised)",
            border: "1px solid var(--border-strong)",
            borderRadius: 2,
            color: "var(--text-primary)",
            cursor: "pointer",
          }}
        >
          {downloading ? "Generating…" : `Download PDF report (${days}d)`}
        </button>
      </div>

      {error && <div style={{ color: "var(--critical)", fontSize: 13, marginBottom: 16 }}>{error}</div>}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 1, marginBottom: 20 }}>
        {SEVS.map(({ key, color, label }) => (
          <div key={key} style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "14px 18px" }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 6 }}>{label}, last {days}d</div>
            <div className="mono" style={{ fontSize: 22, fontWeight: 500, color }}>{totals[key as "low" | "medium" | "high" | "critical"]}</div>
          </div>
        ))}
      </div>

      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "16px 20px" }}>
        <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 14 }}>
          {grandTotal} flagged events {srcIp ? `from ${srcIp}` : "fleet-wide"} — last {trend.length || days} days
        </div>
        {loading ? (
          <div style={{ padding: "16px 0", color: "var(--text-dim)", fontSize: 13 }}>Loading…</div>
        ) : trend.length === 0 ? (
          <div style={{ padding: "16px 0", color: "var(--text-dim)", fontSize: 13 }}>No trend data for this window.</div>
        ) : (
          <div style={{ display: "flex", alignItems: "flex-end", gap: days > 30 ? 1 : 4, height: 160 }}>
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
          {SEVS.map(({ key, color, label }) => (
            <div key={key} style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{ width: 8, height: 8, background: color, display: "inline-block" }} />
              <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
