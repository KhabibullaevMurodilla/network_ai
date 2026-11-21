"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type ApiKey = { id: string; label: string; scope: string; created_at: string; last_used_at: string | null; revoked_at: string | null };

export default function SettingsPage() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [label, setLabel] = useState("");
  const [scope, setScope] = useState("ingest");
  const [newKey, setNewKey] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);

  function loadKeys() {
    api
      .listApiKeys()
      .then((rows: ApiKey[]) => setKeys(rows.filter((k) => !k.revoked_at)))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }

  useEffect(loadKeys, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!label.trim()) return;
    setCreating(true);
    setError("");
    try {
      const res = await api.createApiKey(label.trim(), scope);
      setNewKey(res.api_key);
      setLabel("");
      loadKeys();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setCreating(false);
    }
  }

  async function handleRevoke(id: string) {
    try {
      await api.revokeApiKey(id);
      loadKeys();
    } catch (e: any) {
      setError(e.message);
    }
  }

  return (
    <div style={{ maxWidth: 680 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>API keys</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 28 }}>
        Keys authenticate a telemetry agent sending flow data to{" "}
        <span className="mono" style={{ color: "var(--text-dim)" }}>/ingest/batch</span>. Scope each key
        to the least access it needs — an <span className="mono">ingest</span>-scoped key can send
        telemetry but can&apos;t read anything back.
      </p>

      {error && (
        <div style={{ color: "var(--critical)", fontSize: 13, marginBottom: 16 }}>
          {error}
        </div>
      )}

      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", marginBottom: 24 }}>
        {loading ? (
          <div style={{ padding: "16px", color: "var(--text-dim)", fontSize: 13 }}>Loading…</div>
        ) : keys.length === 0 ? (
          <div style={{ padding: "16px", color: "var(--text-dim)", fontSize: 13 }}>
            No API keys yet. Create one below to start sending telemetry.
          </div>
        ) : (
          keys.map((k, idx) => (
            <div
              key={k.id}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 16,
                padding: "12px 16px",
                borderBottom: idx < keys.length - 1 ? "1px solid var(--border)" : "none",
              }}
            >
              <span style={{ fontSize: 13, flex: 1 }}>{k.label}</span>
              <span className="mono" style={{ fontSize: 11, color: "var(--signal)", textTransform: "uppercase", width: 56 }}>
                {k.scope}
              </span>
              <span className="mono" style={{ fontSize: 11, color: "var(--text-dim)", width: 130 }}>
                {k.last_used_at ? `used ${new Date(k.last_used_at).toISOString().slice(0, 10)}` : "never used"}
              </span>
              <button
                onClick={() => handleRevoke(k.id)}
                style={{
                  fontSize: 12,
                  color: "var(--critical)",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  padding: "4px 8px",
                }}
              >
                Revoke
              </button>
            </div>
          ))
        )}
      </div>

      <form onSubmit={handleCreate} style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input
          placeholder="Key label, e.g. production-agent"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          style={inputStyle}
        />
        <select value={scope} onChange={(e) => setScope(e.target.value)} style={{ ...inputStyle, flex: "none", width: 110 }}>
          <option value="ingest">Ingest</option>
          <option value="read">Read</option>
          <option value="admin">Admin</option>
        </select>
        <button type="submit" disabled={creating} style={buttonStyle}>
          {creating ? "Creating…" : "Create key"}
        </button>
      </form>

      {newKey && (
        <div
          style={{
            border: "1px solid var(--alert)",
            background: "var(--bg-panel)",
            padding: "14px 16px",
            fontSize: 13,
          }}
        >
          <div style={{ color: "var(--alert)", marginBottom: 6 }}>Store this now — it won&apos;t be shown again.</div>
          <div className="mono" style={{ fontSize: 13, wordBreak: "break-all" }}>{newKey}</div>
        </div>
      )}
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  flex: 1,
  padding: "9px 12px",
  fontSize: 13,
  background: "var(--bg-panel)",
  border: "1px solid var(--border)",
  borderRadius: 2,
  color: "var(--text-primary)",
};

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
