"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

type Webhook = {
  id: string; channel_type: "generic" | "slack" | "teams" | "email";
  url: string | null; email_to: string | null; secret: string;
  min_severity: string; enabled: boolean; created_at: string;
};

const CHANNEL_LABEL: Record<string, string> = {
  generic: "Generic (signed JSON)", slack: "Slack", teams: "Microsoft Teams", email: "Email",
};

export default function AlertsPage() {
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [channelType, setChannelType] = useState("generic");
  const [url, setUrl] = useState("");
  const [emailTo, setEmailTo] = useState("");
  const [minSeverity, setMinSeverity] = useState("critical");
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState("");
  const [justCreated, setJustCreated] = useState<Webhook | null>(null);
  const [floor, setFloor] = useState<string | null>(null);
  const [floorSaving, setFloorSaving] = useState(false);

  function load() {
    api.listWebhooks().then(setWebhooks).catch((e) => setError(e.message)).finally(() => setLoading(false));
    api.getMyTenant().then((t) => setFloor(t.alert_min_severity)).catch(() => {});
  }
  useEffect(load, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (channelType === "email" ? !emailTo.trim() : !url.trim()) return;
    setCreating(true);
    setError("");
    try {
      const wh = await api.createWebhook({
        channel_type: channelType,
        url: channelType === "email" ? undefined : url.trim(),
        email_to: channelType === "email" ? emailTo.trim() : undefined,
        min_severity: minSeverity,
      });
      setJustCreated(wh);
      setUrl("");
      setEmailTo("");
      load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(id: string) {
    try {
      await api.deleteWebhook(id);
      load();
    } catch (e: any) {
      setError(e.message);
    }
  }

  async function handleFloorChange(value: string) {
    setFloor(value);
    setFloorSaving(true);
    try {
      await api.updateAlertFloor(value);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setFloorSaving(false);
    }
  }

  return (
    <div style={{ maxWidth: 680 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>Alert delivery</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 24, lineHeight: 1.6 }}>
        Push anomaly events to your own systems in real time — Slack, Teams, email, or a generic
        HMAC-SHA256-signed JSON POST (header{" "}
        <span className="mono" style={{ color: "var(--text-dim)" }}>X-Signature</span>) you verify
        yourself with the secret shown at creation.
      </p>

      {error && <div style={{ color: "var(--critical)", fontSize: 13, marginBottom: 16 }}>{error}</div>}

      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "14px 16px", marginBottom: 24 }}>
        <div style={{ fontSize: 13, marginBottom: 8 }}>Tenant-wide alert floor</div>
        <p style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 10, lineHeight: 1.5 }}>
          Events below this severity never reach any channel below, regardless of its own
          threshold. Nothing is hidden from the dashboard — this only quiets paging.
        </p>
        <select
          value={floor ?? "low"}
          onChange={(e) => handleFloorChange(e.target.value)}
          disabled={floorSaving}
          style={{ ...inputStyle, flex: "none", width: 160 }}
        >
          <option value="low">Low+</option>
          <option value="medium">Medium+</option>
          <option value="high">High+</option>
          <option value="critical">Critical only</option>
        </select>
      </div>

      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", marginBottom: 24 }}>
        {loading ? (
          <div style={{ padding: 16, color: "var(--text-dim)", fontSize: 13 }}>Loading…</div>
        ) : webhooks.length === 0 ? (
          <div style={{ padding: 16, color: "var(--text-dim)", fontSize: 13 }}>
            No alert channels configured. Critical anomalies currently only show on the dashboard.
          </div>
        ) : (
          webhooks.map((w, idx) => (
            <div
              key={w.id}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                padding: "12px 16px",
                borderBottom: idx < webhooks.length - 1 ? "1px solid var(--border)" : "none",
              }}
            >
              <span className="mono" style={{ fontSize: 10, color: "var(--signal)", border: "1px solid var(--border-strong)", padding: "2px 6px", width: 100, textAlign: "center" }}>
                {CHANNEL_LABEL[w.channel_type] ?? w.channel_type}
              </span>
              <span className="mono" style={{ fontSize: 12, flex: 1, wordBreak: "break-all" }}>
                {w.channel_type === "email" ? w.email_to : w.url}
              </span>
              <span className="mono" style={{ fontSize: 11, color: "var(--alert)", textTransform: "uppercase" }}>
                ≥ {w.min_severity}
              </span>
              <button
                onClick={() => handleDelete(w.id)}
                style={{ fontSize: 12, color: "var(--critical)", background: "none", border: "none", cursor: "pointer" }}
              >
                Remove
              </button>
            </div>
          ))
        )}
      </div>

      <form onSubmit={handleCreate} style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 16 }}>
        <div style={{ display: "flex", gap: 8 }}>
          <select value={channelType} onChange={(e) => setChannelType(e.target.value)} style={{ ...inputStyle, flex: "none", width: 140 }}>
            <option value="generic">Generic webhook</option>
            <option value="slack">Slack</option>
            <option value="teams">Microsoft Teams</option>
            <option value="email">Email</option>
          </select>
          {channelType === "email" ? (
            <input
              placeholder="soc@yourcompany.com"
              value={emailTo}
              onChange={(e) => setEmailTo(e.target.value)}
              style={inputStyle}
            />
          ) : (
            <input
              placeholder={
                channelType === "slack" ? "https://hooks.slack.com/services/…" :
                channelType === "teams" ? "https://outlook.office.com/webhook/…" :
                "https://your-system.example.com/webhook"
              }
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              style={inputStyle}
            />
          )}
          <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)} style={{ ...inputStyle, flex: "none", width: 120 }}>
            <option value="low">Low+</option>
            <option value="medium">Medium+</option>
            <option value="high">High+</option>
            <option value="critical">Critical</option>
          </select>
          <button type="submit" disabled={creating} style={buttonStyle}>
            {creating ? "Adding…" : "Add"}
          </button>
        </div>
      </form>

      {justCreated && justCreated.channel_type === "generic" && (
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
