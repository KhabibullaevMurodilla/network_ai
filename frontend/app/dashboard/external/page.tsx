"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type Row = {
  id: string; remote_ip: string; remote_port: number; proto: string; service: string; hostnames: string[];
  flows: number; packets: number; bytes_out: number; bytes_in: number; bytes_total: number; flagged: number;
  first_seen: string; last_seen: string;
};

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${u[i]}`;
}

export default function ExternalPage() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [error, setError] = useState("");
  const [sort, setSort] = useState("bytes");
  const [flaggedOnly, setFlaggedOnly] = useState(false);

  useEffect(() => { setRows(null); api.listExternal(sort, flaggedOnly).then(setRows).catch((e) => setError(e.message)); }, [sort, flaggedOnly]);

  if (error) return <div style={{ color: "var(--critical)", fontSize: 13 }}>{error}</div>;
  if (!rows) return <div style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading…</div>;

  const totalOut = rows.reduce((a, r) => a + r.bytes_out, 0), totalIn = rows.reduce((a, r) => a + r.bytes_in, 0);
  const named = rows.filter((r) => r.hostnames.length).length;

  const tab = (key: string, label: string) => (
    <button key={key} onClick={() => setSort(key)} style={{
      fontSize: 12, padding: "5px 12px", cursor: "pointer", borderRadius: 2,
      border: sort === key ? "1px solid var(--signal)" : "1px solid var(--border-strong)",
      background: sort === key ? "var(--signal-dim)" : "transparent",
      color: sort === key ? "var(--text-primary)" : "var(--text-muted)",
    }}>{label}</button>
  );

  return (
    <div style={{ maxWidth: 1100 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>Internet connections</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 16, lineHeight: 1.6 }}>
        Every internet address your devices talked to in the captures you uploaded. Names come from DNS answers and TLS
        handshakes seen in the capture; encrypted DNS (DoH/DoT) and QUIC hide names, so those show an IP only. Nothing here
        probes those servers — it is read from your own traffic. This is browsing-destination data: it is covered by the
        privacy export, erase and retention settings.
      </p>

      <div style={{ display: "flex", gap: 24, marginBottom: 16, fontSize: 13, color: "var(--text-muted)" }}>
        <span><span className="mono" style={{ color: "var(--text-primary)" }}>{rows.length}</span> endpoints</span>
        <span><span className="mono" style={{ color: "var(--text-primary)" }}>{named}</span> with a name</span>
        <span>sent <span className="mono" style={{ color: "var(--text-primary)" }}>{fmtBytes(totalOut)}</span></span>
        <span>received <span className="mono" style={{ color: "var(--text-primary)" }}>{fmtBytes(totalIn)}</span></span>
      </div>

      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 16 }}>
        <span style={{ fontSize: 12, color: "var(--text-dim)" }}>Sort by</span>
        {tab("bytes", "Data")}{tab("flows", "Connections")}{tab("flagged", "Flagged")}{tab("recent", "Most recent")}
        <label style={{ marginLeft: 16, fontSize: 12, color: "var(--text-muted)", display: "flex", gap: 6, alignItems: "center", cursor: "pointer" }}>
          <input type="checkbox" checked={flaggedOnly} onChange={(e) => setFlaggedOnly(e.target.checked)} /> Flagged only
        </label>
      </div>

      {rows.length === 0 ? (
        <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: 24, color: "var(--text-dim)", fontSize: 13 }}>
          {flaggedOnly ? "No flagged internet connections." : "Nothing yet. Upload a packet capture or run the live capture script."}
        </div>
      ) : (
        <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
          <div style={{ display: "grid", gridTemplateColumns: "2.2fr 1.3fr 90px 80px 1fr 1fr 70px", gap: 12, padding: "8px 16px", fontSize: 11, color: "var(--text-dim)", borderBottom: "1px solid var(--border)", textTransform: "uppercase" }}>
            <span>Name</span><span>Address</span><span>Service</span><span>Conns</span><span>Sent</span><span>Received</span><span>Flagged</span>
          </div>
          {rows.map((r, i) => (
            <div key={r.id} style={{ display: "grid", gridTemplateColumns: "2.2fr 1.3fr 90px 80px 1fr 1fr 70px", gap: 12, padding: "9px 16px", fontSize: 13, alignItems: "center", borderBottom: i < rows.length - 1 ? "1px solid var(--border)" : "none" }}>
              <span style={{ wordBreak: "break-all" }} title={r.hostnames.join(", ")}>
                {r.hostnames.length ? r.hostnames[0] : <span style={{ color: "var(--text-dim)" }}>—</span>}
                {r.hostnames.length > 1 && <span style={{ color: "var(--text-dim)", fontSize: 11 }}> +{r.hostnames.length - 1}</span>}
              </span>
              <span className="mono" style={{ fontSize: 12 }}>{r.remote_ip}</span>
              <span className="mono" style={{ fontSize: 12, color: "var(--text-muted)" }}>{r.proto}/{r.service}</span>
              <span className="mono" style={{ fontSize: 12 }}>{r.flows}</span>
              <span className="mono" style={{ fontSize: 12 }}>{fmtBytes(r.bytes_out)}</span>
              <span className="mono" style={{ fontSize: 12 }}>{fmtBytes(r.bytes_in)}</span>
              <span className="mono" style={{ fontSize: 12, color: r.flagged ? "var(--critical)" : "var(--text-dim)" }}>{r.flagged || "—"}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
