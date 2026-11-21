"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type ResponseAction = {
  id: string; trigger: string; action_type: string; target_url: string;
  secret: string; enabled: boolean; created_at: string;
};

const TRIGGERS = ["critical", "entity_burst", "entity_baseline_drift", "ensemble_consensus"];
const ACTION_TYPES = [
  { value: "webhook_block", label: "Block / quarantine directive" },
  { value: "webhook_notify_soar", label: "Notify SOAR / ticketing system" },
];

export default function ResponseActionsPage() {
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [trigger, setTrigger] = useState("critical");
  const [actionType, setActionType] = useState("webhook_block");
  const [targetUrl, setTargetUrl] = useState("");
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState("");
  const [justCreated, setJustCreated] = useState<ResponseAction | null>(null);

  function load() {
    api.listResponseActions().then(setActions).catch((e) => setError(e.message)).finally(() => setLoading(false));
  }
  useEffect(load, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!targetUrl.trim()) return;
    setCreating(true);
    setError("");
    try {
      const created = await api.createResponseAction(trigger, actionType, targetUrl.trim());
      setJustCreated(created);
      setTargetUrl("");
      load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(id: string) {
    try {
      await api.deleteResponseAction(id);
      load();
    } catch (e: any) {
      setError(e.message);
    }
  }

  return (
    <div style={{ maxWidth: 720 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>Response actions</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 12, lineHeight: 1.6 }}>
        Different from alert delivery: a notify webhook tells a person to go look, a response
        action sends your own firewall, NAC, or SOAR platform a signed, structured directive to
        act on automatically.
      </p>
      <p style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 24, lineHeight: 1.6, borderLeft: "2px solid var(--border-strong)", paddingLeft: 12 }}>
        Scoped honestly: this product has no enforcement point of its own and cannot block
        traffic directly. What it sends is a verifiable, HMAC-signed instruction — your own
        systems decide what to do with it.
      </p>

      {error && <div style={{ color: "var(--critical)", fontSize: 13, marginBottom: 16 }}>{error}</div>}

      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", marginBottom: 24 }}>
        {loading ? (
          <div style={{ padding: 16, color: "var(--text-dim)", fontSize: 13 }}>Loading…</div>
        ) : actions.length === 0 ? (
          <div style={{ padding: 16, color: "var(--text-dim)", fontSize: 13 }}>No response actions configured.</div>
        ) : (
          actions.map((a, idx) => (
            <div
              key={a.id}
              style={{
                display: "flex", alignItems: "center", gap: 12, padding: "12px 16px",
                borderBottom: idx < actions.length - 1 ? "1px solid var(--border)" : "none",
              }}
            >
              <span className="mono" style={{ fontSize: 11, color: "var(--critical)", textTransform: "uppercase", width: 150 }}>
                on {a.trigger.replace(/_/g, " ")}
              </span>
              <span className="mono" style={{ fontSize: 12, flex: 1, wordBreak: "break-all" }}>{a.target_url}</span>
              <span className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }}>
                {a.action_type === "webhook_block" ? "block" : "notify SOAR"}
              </span>
              <button
                onClick={() => handleDelete(a.id)}
                style={{ fontSize: 12, color: "var(--critical)", background: "none", border: "none", cursor: "pointer" }}
              >
                Remove
              </button>
            </div>
          ))
        )}
      </div>

      <form onSubmit={handleCreate} style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        <select value={trigger} onChange={(e) => setTrigger(e.target.value)} style={{ ...inputStyle, flex: "none", width: 160 }}>
          {TRIGGERS.map((t) => (
            <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
          ))}
        </select>
        <select value={actionType} onChange={(e) => setActionType(e.target.value)} style={{ ...inputStyle, flex: "none", width: 200 }}>
          {ACTION_TYPES.map((a) => (
            <option key={a.value} value={a.value}>{a.label}</option>
          ))}
        </select>
        <input
          placeholder="https://your-firewall-or-soar.example.com/hook"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          style={{ ...inputStyle, minWidth: 220 }}
        />
        <button type="submit" disabled={creating} style={buttonStyle}>
          {creating ? "Adding…" : "Add"}
        </button>
      </form>

      {justCreated && (
        <div style={{ border: "1px solid var(--alert)", background: "var(--bg-panel)", padding: "14px 16px", fontSize: 13 }}>
          <div style={{ color: "var(--alert)", marginBottom: 6 }}>
            Signing secret — store this now, it won&apos;t be shown again:
          </div>
          <div className="mono" style={{ fontSize: 12, wordBreak: "break-all" }}>{justCreated.secret}</div>
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
