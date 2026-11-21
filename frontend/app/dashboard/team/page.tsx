"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { FOCUS_OPTIONS, roleAtLeast } from "@/lib/focus";
import { useProfile } from "@/lib/profile";

type Member = { id: string; email: string; role: string; focus: string | null; invited_at: string | null; created_at: string };
const ROLES = ["viewer", "analyst", "admin", "owner"];
const RANK: Record<string, number> = { viewer: 0, analyst: 1, admin: 2, owner: 3 };

export default function TeamPage() {
  const me = useProfile();
  const [members, setMembers] = useState<Member[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("viewer");
  const [focus, setFocus] = useState("");
  const [inviting, setInviting] = useState(false);

  function load() {
    api.listTeam().then(setMembers).catch((e) => setError(e.message)).finally(() => setLoading(false));
  }
  useEffect(load, []);

  if (me && !roleAtLeast(me.role, "admin")) {
    return <div style={{ fontSize: 13, color: "var(--text-muted)" }}>Managing the team requires the admin role. You can change your own focus from the header.</div>;
  }
  const myRank = RANK[me?.role ?? "viewer"] ?? 0;

  async function act(fn: () => Promise<any>, ok = "") {
    setError(""); setNotice("");
    try { await fn(); if (ok) setNotice(ok); load(); } catch (e: any) { setError(e.message); }
  }

  async function invite(e: React.FormEvent) {
    e.preventDefault();
    setInviting(true);
    await act(async () => {
      await api.inviteTeammate(email.trim(), role, focus || null);
      setEmail("");
    }, "Invite sent -- they'll get an email from the auth provider with a link to set their password.");
    setInviting(false);
  }

  const sel = { fontSize: 12, background: "var(--bg-panel)", color: "inherit", border: "1px solid var(--border-strong)", padding: "4px 6px" } as const;

  return (
    <div style={{ maxWidth: 820 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>Team &amp; focus</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", lineHeight: 1.6, marginBottom: 20 }}>
        <b>Role</b> is what someone is allowed to do. <b>Focus</b> is only what they see first -- it never grants or
        removes access. Members can change their own focus any time; admins can set it for them here.
      </p>
      {error && <div style={{ color: "var(--critical)", fontSize: 13, marginBottom: 12 }}>{error}</div>}
      {notice && <div style={{ color: "var(--signal)", fontSize: 13, marginBottom: 12 }}>{notice}</div>}

      <form onSubmit={invite} style={{ display: "flex", gap: 8, marginBottom: 24, flexWrap: "wrap" }}>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="teammate@company.com" type="email" required
          style={{ ...sel, flex: 1, minWidth: 220, padding: "7px 9px", fontSize: 13 }} />
        <select value={role} onChange={(e) => setRole(e.target.value)} style={sel}>
          {ROLES.filter((r) => RANK[r] <= myRank).map((r) => <option key={r}>{r}</option>)}
        </select>
        <select value={focus} onChange={(e) => setFocus(e.target.value)} style={sel}>
          <option value="">focus: they choose</option>
          {FOCUS_OPTIONS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
        </select>
        <button disabled={inviting || !email.trim()} style={{ ...sel, padding: "7px 14px", cursor: "pointer" }}>{inviting ? "Inviting…" : "Invite"}</button>
      </form>

      <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
        {loading ? <div style={{ padding: 16, fontSize: 13, color: "var(--text-dim)" }}>Loading…</div> : members.map((m, i) => {
          const isMe = m.id === me?.userId;
          const locked = isMe || RANK[m.role] > myRank; // server enforces too
          return (
            <div key={m.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "11px 16px", borderBottom: i < members.length - 1 ? "1px solid var(--border)" : "none" }}>
              <span style={{ flex: 1, fontSize: 13 }}>{m.email}{isMe && <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)", marginLeft: 8 }}>you</span>}
                {m.invited_at && <span className="mono" style={{ fontSize: 10, color: "var(--text-dim)", marginLeft: 8 }}>invited {m.invited_at.slice(0, 10)}</span>}
              </span>
              <select disabled={locked} value={m.role} style={sel} onChange={(e) => act(() => api.updateTeammate(m.id, { role: e.target.value }))}>
                {ROLES.filter((r) => RANK[r] <= myRank || r === m.role).map((r) => <option key={r}>{r}</option>)}
              </select>
              <select disabled={isMe} value={m.focus ?? ""} style={sel} onChange={(e) => act(() => api.updateTeammate(m.id, { focus: e.target.value || null }))}>
                <option value="">not chosen yet</option>
                {FOCUS_OPTIONS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
              </select>
              <button disabled={locked} onClick={() => confirm(`Remove ${m.email} from the team?`) && act(() => api.removeTeammate(m.id), "Removed.")}
                style={{ fontSize: 12, color: locked ? "var(--text-dim)" : "var(--critical)", background: "none", border: "none", cursor: locked ? "default" : "pointer" }}>Remove</button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
