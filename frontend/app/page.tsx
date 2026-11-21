import Link from "next/link";

function MiniTrace() {
  const points = [8, 9, 7, 10, 8, 22, 9, 8, 11, 9, 7, 8, 18, 10, 8, 9, 7, 8, 9, 10];
  const w = 420;
  const h = 64;
  const max = 24;
  const x = (i: number) => (i / (points.length - 1)) * w;
  const y = (v: number) => h - (v / max) * h;
  const path = points.map((p, i) => `${i === 0 ? "M" : "L"} ${x(i).toFixed(1)} ${y(p).toFixed(1)}`).join(" ");
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} style={{ display: "block" }}>
      <path d={path} fill="none" stroke="var(--signal)" strokeWidth="1.3" opacity="0.85" />
      {points.map(
        (p, i) =>
          p > 15 && (
            <circle key={i} cx={x(i)} cy={y(p)} r="2.2" fill="var(--bg-base)" stroke="var(--alert)" strokeWidth="1.4" />
          )
      )}
    </svg>
  );
}

export default function Home() {
  return (
    <main
      style={{
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "flex-start",
        justifyContent: "flex-start",
        maxWidth: 560,
        margin: "0 auto",
        padding: "160px 24px 0",
      }}
    >
      <span className="mono" style={{ fontSize: 12, color: "var(--signal)", marginBottom: 16 }}>
        network / ot anomaly detection
      </span>
      <h1 style={{ fontSize: 34, fontWeight: 600, lineHeight: 1.15, marginBottom: 16, letterSpacing: -0.5 }}>
        See the anomaly before it becomes downtime.
      </h1>
      <p style={{ fontSize: 15, color: "var(--text-muted)", lineHeight: 1.6, marginBottom: 32, maxWidth: 440 }}>
        A detection engine trained on private 4G/5G and OT telemetry, watching your network
        for the patterns a rules-based monitor misses.
      </p>
      {process.env.NEXT_PUBLIC_STATIC_DEMO !== "1" && <Link
        href="/login"
        style={{
          padding: "11px 22px",
          fontSize: 14,
          fontWeight: 500,
          background: "var(--signal-dim)",
          border: "1px solid var(--signal)",
          borderRadius: 2,
          textDecoration: "none",
          color: "var(--text-primary)",
          marginBottom: 14,
        }}
      >
        Sign in to dashboard
      </Link>}
      {process.env.NEXT_PUBLIC_LOCAL_MODE === "1" && <Link
        href="/dashboard/import"
        style={{
          display: "inline-block", padding: "11px 22px", fontSize: 14, fontWeight: 500, background: "var(--signal-dim)",
          border: "1px solid var(--signal)", borderRadius: 2, textDecoration: "none", color: "var(--text-primary)", marginBottom: 14,
        }}
      >
        Open the full dashboard — your data stays in this browser
      </Link>}
      <Link
        href="/analyze"
        style={{
          display: "inline-block",
          padding: "11px 22px",
          fontSize: 14,
          fontWeight: 500,
          background: "var(--signal-dim)",
          border: "1px solid var(--signal)",
          borderRadius: 2,
          textDecoration: "none",
          color: "var(--text-primary)",
          marginBottom: 14,
        }}
      >
        Analyze your own capture — runs in your browser
      </Link>
      <Link
        href="/demo"
        style={{
          fontSize: 13,
          color: "var(--text-muted)",
          textDecoration: "underline",
          marginBottom: 56,
        }}
      >
        Or explore a live read-only demo →
      </Link>

      <div style={{ borderTop: "1px solid var(--border)", paddingTop: 20, width: "100%" }}>
        <MiniTrace />
        <div style={{ display: "flex", gap: 24, marginTop: 10 }}>
          <span className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }}>Illustrative signal trace — a static graphic, not live or measured data</span>
        </div>
      </div>
    </main>
  );
}
