"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type AuditRow = { id: number; actor: string; action: string; detail: any; created_at: string };

export default function PrivacyPage() {
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [exporting, setExporting] = useState(false);
  const [erasing, setErasing] = useState(false);
  const [confirmErase, setConfirmErase] = useState(false);
  const [erased, setErased] = useState(false);

  useEffect(() => {
    api.getAuditLog().then(setAudit).catch((e) => setError(e.message)).finally(() => setLoading(false));
  }, []);

  async function handleExport() {
    setExporting(true);
    try {
      const data = await api.exportData();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `network-ai-export-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setExporting(false);
    }
  }

  async function handleErase() {
    setErasing(true);
    try {
      await api.eraseData();
      setErased(true);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setErasing(false);
    }
  }

  if (erased) {
    return (
      <div style={{ maxWidth: 560, color: "var(--text-muted)", fontSize: 13 }}>
        All tenant data has been permanently erased, including this audit trail. There is
        nothing further to show here.
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 760 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>Privacy &amp; audit</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 28, lineHeight: 1.6 }}>
        Every security-relevant action on this tenant — key creation, data export, telemetry
        ingestion — is written to an append-only log below that even an admin can read but
        never alter or delete individually. Row-Level Security in the database enforces that
        no other tenant can ever read these rows, API key material is stored only as a
        SHA-256 hash, and raw telemetry older than your retention window is purged automatically.
      </p>

      {error && <div style={{ color: "var(--critical)", fontSize: 13, marginBottom: 16 }}>{error}</div>}

      <div style={{ display: "flex", gap: 12, marginBottom: 32 }}>
        <button onClick={handleExport} disabled={exporting} style={buttonStyle}>
          {exporting ? "Preparing export…" : "Export all tenant data (.json)"}
        </button>
        {!confirmErase ? (
          <button onClick={() => setConfirmErase(true)} style={dangerOutlineStyle}>
            Erase all tenant data
          </button>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 12, color: "var(--critical)" }}>This cannot be undone.</span>
            <button onClick={handleErase} disabled={erasing} style={dangerFilledStyle}>
              {erasing ? "Erasing…" : "Confirm permanent erasure"}
            </button>
            <button onClick={() => setConfirmErase(false)} style={{ ...buttonStyle, background: "transparent" }}>
              Cancel
            </button>
          </div>
        )}
      </div>

      <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 10 }}>Audit log</div>
      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
        {loading ? (
          <div style={{ padding: 16, color: "var(--text-dim)", fontSize: 13 }}>Loading…</div>
        ) : audit.length === 0 ? (
          <div style={{ padding: 16, color: "var(--text-dim)", fontSize: 13 }}>No actions logged yet.</div>
        ) : (
          audit.slice(0, 50).map((row, idx) => (
            <div
              key={row.id}
              style={{
                display: "flex",
                gap: 16,
                padding: "9px 16px",
                borderBottom: idx < audit.length - 1 ? "1px solid var(--border)" : "none",
                fontSize: 12,
              }}
            >
              <span className="mono" style={{ color: "var(--text-dim)", width: 140 }}>
                {new Date(row.created_at).toISOString().slice(0, 19).replace("T", " ")}
              </span>
              <span className="mono" style={{ color: "var(--signal)", width: 170 }}>{row.action}</span>
              <span style={{ color: "var(--text-muted)", flex: 1 }}>{row.actor}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

const buttonStyle: React.CSSProperties = {
  padding: "9px 16px",
  fontSize: 13,
  fontWeight: 500,
  background: "var(--bg-panel-raised)",
  border: "1px solid var(--border-strong)",
  borderRadius: 2,
  color: "var(--text-primary)",
  cursor: "pointer",
};

const dangerOutlineStyle: React.CSSProperties = {
  ...buttonStyle,
  background: "transparent",
  border: "1px solid var(--critical)",
  color: "var(--critical)",
};

const dangerFilledStyle: React.CSSProperties = {
  ...buttonStyle,
  background: "var(--critical)",
  border: "1px solid var(--critical)",
  color: "#fff",
};
