"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useRouteValue } from "@/lib/links";
import { api } from "@/lib/api";
import { roleAtLeast } from "@/lib/focus";
import { useProfile } from "@/lib/profile";
import { severityColor, severityLabel, type Severity } from "@/lib/severity";

type DetectorScore = { detector: string; score: number | null; is_anomaly: boolean };
type Explanation = { feature: string; z_score: number }[];
type Detail = {
  id: number;
  flow_id: number;
  severity: Severity;
  explanation: Explanation | null;
  consensus_count: number | null;
  escalation_reason: string | null;
  src_ip: string | null;
  triage_status: "new" | "acknowledged" | "resolved";
  created_at: string;
  detector_scores: DetectorScore[];
  flow: Record<string, any> | null;
  mitre: { framework: string; tactic: string; technique_id: string; technique: string; confidence: string; note: string } | null;
};

const ESCALATION_LABEL: Record<string, string> = {
  ensemble_consensus: "Multiple detectors agreed independently",
  entity_burst: "Burst of flagged events from this source",
};

export default function AnomalyDetailPage() {
  const id = useRouteValue("id");
  const router = useRouter();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState("");
  const [updating, setUpdating] = useState(false);

  function load() {
    api.getAnomalyDetail(id).then(setDetail).catch((e) => setError(e.message));
  }
  useEffect(load, [id]);

  async function setTriage(status: string) {
    setUpdating(true);
    try {
      await api.updateTriage(id, status);
      load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setUpdating(false);
    }
  }

  if (error) return <div style={{ color: "var(--critical)", fontSize: 13 }}>{error}</div>;
  if (!detail) return <div style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading…</div>;

  const color = severityColor(detail.severity);

  return (
    <div style={{ maxWidth: 760 }}>
      <button
        onClick={() => router.back()}
        style={{ fontSize: 12, color: "var(--text-dim)", background: "none", border: "none", cursor: "pointer", marginBottom: 16, padding: 0 }}
      >
        ← Back
      </button>

      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4 }}>
        <span className="mono" style={{ fontSize: 11, padding: "3px 8px", border: `1px solid ${color}`, color, textTransform: "uppercase" }}>
          {severityLabel(detail.severity)}
        </span>
        <h1 style={{ fontSize: 18, fontWeight: 600 }}>Event #{detail.id}</h1>
      </div>
      <p className="mono" style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 24 }}>
        {new Date(detail.created_at).toISOString().replace("T", " ").slice(0, 19)} UTC · source {detail.src_ip || "unidentified"}
      </p>

      {error && <div style={{ color: "var(--critical)", fontSize: 13, marginBottom: 16 }}>{error}</div>}

      {/* Triage */}
      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "14px 16px", marginBottom: 20, display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{ fontSize: 13, color: "var(--text-muted)" }}>Triage:</span>
        {(["new", "acknowledged", "resolved"] as const).map((s) => (
          <button
            key={s}
            onClick={() => setTriage(s)}
            disabled={updating || detail.triage_status === s}
            style={{
              fontSize: 12,
              padding: "6px 12px",
              borderRadius: 2,
              cursor: detail.triage_status === s ? "default" : "pointer",
              border: detail.triage_status === s ? "1px solid var(--signal)" : "1px solid var(--border-strong)",
              background: detail.triage_status === s ? "var(--signal-dim)" : "transparent",
              color: detail.triage_status === s ? "var(--text-primary)" : "var(--text-muted)",
              textTransform: "capitalize",
            }}
          >
            {s}
          </button>
        ))}
      </div>

      <RespondPanel eventId={detail.id} />

      {/* Why flagged */}
      {detail.escalation_reason && (
        <div style={{ border: `1px solid ${color}`, background: "var(--bg-panel)", padding: "12px 16px", marginBottom: 20, fontSize: 13 }}>
          <span style={{ color }}>Escalated — </span>
          {ESCALATION_LABEL[detail.escalation_reason] || detail.escalation_reason}
        </div>
      )}

      {detail.mitre && (
        <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "12px 16px", marginBottom: 20, fontSize: 13 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <span className="mono" style={{ fontSize: 10, color: "var(--signal)", border: "1px solid var(--border-strong)", padding: "2px 6px" }}>
              {detail.mitre.framework}
            </span>
            <span className="mono" style={{ fontSize: 12 }}>
              {detail.mitre.technique_id} — {detail.mitre.technique}
            </span>
            <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)", textTransform: "uppercase" }}>
              {detail.mitre.confidence}
            </span>
          </div>
          <div style={{ fontSize: 12, color: "var(--text-dim)" }}>{detail.mitre.tactic} — {detail.mitre.note}</div>
        </div>
      )}

      <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 10 }}>Why this was flagged</div>
      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", marginBottom: 24 }}>
        {(detail.explanation || []).map((e, i) => (
          <div key={i} style={{ display: "flex", justifyContent: "space-between", padding: "10px 16px", borderBottom: i < (detail.explanation?.length || 0) - 1 ? "1px solid var(--border)" : "none" }}>
            <span className="mono" style={{ fontSize: 13 }}>{e.feature}</span>
            <span className="mono" style={{ fontSize: 13, color: Math.abs(e.z_score) >= 4 ? "var(--critical)" : "var(--alert)" }}>
              {e.z_score > 0 ? "+" : ""}{e.z_score.toFixed(2)}σ
            </span>
          </div>
        ))}
      </div>

      {/* Detector consensus */}
      <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 10 }}>
        Detector consensus {detail.consensus_count != null && `(${detail.consensus_count}/4 flagged)`}
      </div>
      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", marginBottom: 24 }}>
        {detail.detector_scores.map((d, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 16, padding: "10px 16px", borderBottom: i < detail.detector_scores.length - 1 ? "1px solid var(--border)" : "none" }}>
            <span style={{ width: 110, fontSize: 13 }}>{d.detector}</span>
            <span className="mono" style={{ width: 70, fontSize: 13, color: "var(--text-muted)" }}>{d.score != null ? d.score.toFixed(2) : "—"}</span>
            <span className="mono" style={{ fontSize: 11, color: d.is_anomaly ? "var(--critical)" : "var(--text-dim)", textTransform: "uppercase" }}>
              {d.is_anomaly ? "flagged" : "normal"}
            </span>
          </div>
        ))}
      </div>

      {/* Raw flow */}
      {detail.flow && (
        <>
          <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 10 }}>Raw flow</div>
          <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: "14px 16px", display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "10px 20px" }}>
            {["dur", "proto", "tot_pkts", "src_bytes", "dst_bytes", "rate", "load", "s_ttl", "src_ip", "dst_ip"]
              .filter((k) => detail.flow![k] !== undefined && detail.flow![k] !== null)
              .map((k) => (
                <div key={k}>
                  <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 2 }}>{k}</div>
                  <div className="mono" style={{ fontSize: 13 }}>{String(detail.flow![k])}</div>
                </div>
              ))}
          </div>
        </>
      )}
    </div>
  );
}

type RAction = { id: string; trigger: string; action_type: string; target_url: string; enabled: boolean };
const OUTCOME_COPY: Record<string, { text: string; ok: boolean }> = {
  sent: { text: "Delivered -- your system acknowledged the directive (2xx).", ok: true },
  failed: { text: "Not delivered -- the endpoint errored or was unreachable.", ok: false },
  blocked_unsafe_target: { text: "Blocked -- the target resolved to a private/unsafe address, nothing was sent.", ok: false },
};

// Interactive counterpart to automatic response actions: an analyst pushes
// the same signed directive for THIS event on demand. Focus only decides
// whether the panel starts open (security) or collapsed (everyone else) --
// the role check is a UI convenience; the server enforces analyst+.
function RespondPanel({ eventId }: { eventId: number }) {
  const me = useProfile();
  const [actions, setActions] = useState<RAction[]>([]);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<Record<string, string>>({});
  const [err, setErr] = useState("");
  const allowed = roleAtLeast(me?.role, "analyst");

  useEffect(() => { setOpen(me?.focus === "security"); }, [me?.focus]);
  useEffect(() => { if (allowed) api.listResponseActions().then((a: RAction[]) => setActions(a.filter((x) => x.enabled !== false))).catch(() => {}); }, [allowed]);

  if (!allowed || actions.length === 0) return null;

  async function fire(a: RAction) {
    if (!confirm(`Send a "${a.action_type === "webhook_block" ? "block / quarantine" : "notify SOAR"}" directive to ${a.target_url} for event #${eventId}?`)) return;
    setBusy(a.id); setErr("");
    try {
      const r = await api.fireResponseAction(a.id, eventId);
      setResult((prev) => ({ ...prev, [a.id]: r.outcome }));
    } catch (e: any) { setErr(e.message); }
    setBusy(null);
  }

  return (
    <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", marginBottom: 20 }}>
      <button onClick={() => setOpen(!open)} style={{ width: "100%", textAlign: "left", padding: "12px 16px", background: "none", border: "none", color: "inherit", cursor: "pointer", fontSize: 13 }}>
        <span style={{ color: "var(--text-muted)" }}>Respond</span> -- push a configured response action for this event {open ? "▾" : "▸"}
      </button>
      {open && (
        <div style={{ borderTop: "1px solid var(--border)" }}>
          {err && <div style={{ color: "var(--critical)", fontSize: 12, padding: "8px 16px" }}>{err}</div>}
          {actions.map((a) => (
            <div key={a.id} style={{ padding: "10px 16px", display: "flex", alignItems: "center", gap: 12, fontSize: 12 }}>
              <span className="mono" style={{ width: 70, color: "var(--critical)", textTransform: "uppercase" }}>{a.action_type === "webhook_block" ? "block" : "notify"}</span>
              <span className="mono" style={{ flex: 1, wordBreak: "break-all" }}>{a.target_url}</span>
              {result[a.id] && <span style={{ color: OUTCOME_COPY[result[a.id]]?.ok ? "var(--signal)" : "var(--critical)" }}>{OUTCOME_COPY[result[a.id]]?.text}</span>}
              <button disabled={busy !== null} onClick={() => fire(a)} style={{ fontSize: 12, padding: "5px 12px", border: "1px solid var(--border-strong)", background: "transparent", color: "inherit", cursor: "pointer" }}>
                {busy === a.id ? "Sending…" : "Fire now"}
              </button>
            </div>
          ))}
          <div style={{ fontSize: 11, color: "var(--text-dim)", padding: "6px 16px 12px" }}>
            Sends a signed directive to your own system; this product can't block traffic itself. The action is recorded in the audit log under your name.
          </div>
        </div>
      )}
    </div>
  );
}
