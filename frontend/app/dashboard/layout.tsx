"use client";
import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { api, LOCAL_MODE } from "@/lib/api";
import { FOCUS_OPTIONS, focusHome, orderNav, roleAtLeast } from "@/lib/focus";
import { ProfileContext, useProfile, type Profile } from "@/lib/profile";
import { getStoredTheme, setStoredTheme, applyTheme, type Theme } from "@/lib/theme";

function BriefcaseIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <rect x="3.5" y="7.5" width="17" height="12" rx="1" />
      <path d="M8.5 7.5V5.5a1 1 0 0 1 1-1h5a1 1 0 0 1 1 1v2M3.5 12.5h17" />
    </svg>
  );
}
function GaugeIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M4 15a8 8 0 1 1 16 0" />
      <path d="M12 15l4-5" />
      <circle cx="12" cy="15" r="1.2" fill="currentColor" stroke="none" />
    </svg>
  );
}
function KeyIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <circle cx="8" cy="12" r="3.2" />
      <path d="M10.8 12H20M16.5 12v3M20 12v3" />
    </svg>
  );
}
function GridIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <rect x="3.5" y="3.5" width="7" height="7" rx="0.5" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="0.5" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="0.5" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="0.5" />
    </svg>
  );
}
function BellIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M6 10a6 6 0 1 1 12 0c0 4 1.5 5.5 1.5 5.5h-15S6 14 6 10Z" />
      <path d="M10 18.5a2 2 0 0 0 4 0" />
    </svg>
  );
}
function ShieldIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M12 3.5 5 6v5.5c0 4.5 3 7.4 7 9 4-1.6 7-4.5 7-9V6l-7-2.5Z" />
      <path d="m9.2 12 1.9 1.9 3.7-3.7" />
    </svg>
  );
}
function FolderIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M3.5 6.5a1 1 0 0 1 1-1h4.5l1.8 2h8.7a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1h-15a1 1 0 0 1-1-1V6.5Z" />
    </svg>
  );
}
function ZapIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M13 3 5 13.5h6L10.5 21 19 10h-6L13 3Z" strokeLinejoin="round" />
    </svg>
  );
}
function TrendIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M3.5 18 9 11l4 3 7.5-9" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M15.5 5h5v5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
function TopologyIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <circle cx="12" cy="5" r="2.2" />
      <circle cx="5" cy="18" r="2.2" />
      <circle cx="19" cy="18" r="2.2" />
      <path d="M10.3 6.6 6.7 16.1M13.7 6.6l3.6 9.5M7.2 18h9.6" />
    </svg>
  );
}
function CpuIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <rect x="7" y="7" width="10" height="10" rx="0.5" />
      <rect x="3.5" y="3.5" width="17" height="17" rx="1" />
      <path d="M9 2v2M12 2v2M15 2v2M9 20v2M12 20v2M15 20v2M2 9h2M2 12h2M2 15h2M20 9h2M20 12h2M20 15h2" />
    </svg>
  );
}

const NAV = [
  { href: "/dashboard", label: "Overview", icon: GaugeIcon },
  { href: "/dashboard/executive", label: "Executive summary", icon: BriefcaseIcon },
  { href: "/dashboard/trends", label: "Trends", icon: TrendIcon },
  { href: "/dashboard/incidents", label: "Incidents", icon: FolderIcon },
  { href: "/dashboard/entities", label: "Entities", icon: GridIcon },
  { href: "/dashboard/topology", label: "Topology", icon: TopologyIcon },
  { href: "/dashboard/devices", label: "Devices", icon: CpuIcon },
  { href: "/dashboard/external", label: "Internet", icon: TopologyIcon },
  { href: "/dashboard/physical", label: "Physical map", icon: TopologyIcon },
  { href: "/dashboard/ot-events", label: "OT protocol events", icon: CpuIcon },
  { href: "/dashboard/alerts", label: "Alert delivery", icon: BellIcon },
  { href: "/dashboard/response-actions", label: "Response actions", icon: ZapIcon },
  { href: "/dashboard/privacy", label: "Privacy & audit", icon: ShieldIcon },
  { href: "/dashboard/settings", label: "API keys", icon: KeyIcon },
];
const IMPORT_NAV = { href: "/dashboard/import", label: "Import traffic", icon: ZapIcon };
// Pages that need a server (alert delivery, response actions, API keys, SNMP, discovery,
// Modbus rules) are hidden in local mode instead of showing errors.
const SERVER_ONLY = new Set(["/dashboard/alerts", "/dashboard/response-actions", "/dashboard/settings", "/dashboard/physical"]);
const TEAM_NAV = { href: "/dashboard/team", label: "Team & focus", icon: UsersIcon };

function UsersIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <circle cx="9" cy="8.5" r="3" />
      <path d="M3.5 19c0-3 2.5-5 5.5-5s5.5 2 5.5 5M16 6a3 3 0 0 1 0 5.8M17.5 14.3c2 .5 3 2.2 3 4.7" strokeLinecap="round" />
    </svg>
  );
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [profile, setProfile] = useState<Omit<Profile, "reload"> | null>(null);

  function loadProfile() {
    Promise.all([api.getSummary(), api.getMyTenant()])
      .then(([s, t]) => setProfile({ role: s.role, focus: s.focus ?? null, userId: s.user_id, tenantName: t?.name ?? "" }))
      .catch(() => setProfile(null)); // pages surface their own API errors
  }
  useEffect(loadProfile, []);

  // One-time onboarding: nobody has picked a focus yet.
  useEffect(() => {
    if (profile && !profile.focus && pathname !== "/dashboard/onboarding" && !LOCAL_MODE) router.replace("/dashboard/onboarding");
  }, [profile, pathname, router]);

  // Adaptive landing: only the first arrival at /dashboard per browser
  // session is redirected to the focus-specific home, so clicking
  // "Overview" later never bounces you away from where you asked to go.
  useEffect(() => {
    if (!profile?.focus || pathname !== "/dashboard") return;
    try {
      if (sessionStorage.getItem("nai-landed")) return;
      sessionStorage.setItem("nai-landed", "1");
    } catch {}
    const home = focusHome(profile.focus);
    if (home !== "/dashboard") router.replace(home);
  }, [profile, pathname, router]);

  const nav = LOCAL_MODE
    ? [IMPORT_NAV, ...orderNav(NAV.filter((n) => !SERVER_ONLY.has(n.href)), profile?.focus)]
    : orderNav(roleAtLeast(profile?.role, "admin") ? [...NAV, TEAM_NAV] : NAV, profile?.focus);

  return (
    <ProfileContext.Provider value={profile ? { ...profile, reload: loadProfile } : null}>
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <nav
        style={{
          width: 64,
          borderRight: "1px solid var(--border)",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          paddingTop: 20,
          gap: 4,
          flexShrink: 0,
        }}
      >
        <div
          style={{
            width: 32,
            height: 32,
            borderRadius: 2,
            background: "var(--signal-dim)",
            border: "1px solid var(--signal)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            marginBottom: 24,
            color: "var(--signal)",
            fontFamily: "var(--font-mono)",
            fontSize: 13,
            fontWeight: 500,
          }}
        >
          N
        </div>
        {nav.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || (href !== "/dashboard" && pathname.startsWith(href + "/"));
          return (
            <Link
              key={href}
              href={href}
              title={label}
              style={{
                width: 40,
                height: 40,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                borderRadius: 2,
                color: active ? "var(--signal)" : "var(--text-dim)",
                background: active ? "var(--bg-panel-raised)" : "transparent",
                border: active ? "1px solid var(--border-strong)" : "1px solid transparent",
                textDecoration: "none",
              }}
            >
              <Icon />
            </Link>
          );
        })}
      </nav>

      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        <StatusBar tenantName={profile?.tenantName ?? ""} />
        <div style={{ flex: 1, padding: "28px 32px" }}><Suspense fallback={null}>{children}</Suspense></div>
      </div>
    </div>
    </ProfileContext.Provider>
  );
}

function StatusBar({ tenantName }: { tenantName: string }) {
  const me = useProfile();
  const [theme, setTheme] = useState<Theme>("dark");

  useEffect(() => {
    const t = getStoredTheme();
    setTheme(t);
    applyTheme(t);
  }, []);

  function toggleTheme() {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    setStoredTheme(next);
  }

  return (
    <header
      style={{
        height: 52,
        borderBottom: "1px solid var(--border)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 28px",
        flexShrink: 0,
      }}
    >
      <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
        <span style={{ fontSize: 14, fontWeight: 600 }}>Network AI</span>
        <span className="mono" style={{ fontSize: 12, color: "var(--text-dim)" }}>
          {tenantName && `/ ${tenantName}`}
        </span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        {me && (
          <select
            value={me.focus ?? ""}
            title="Your focus: what you see first. Changes nothing about what you can do."
            onChange={async (e) => { await api.setMyFocus(e.target.value || null); me.reload(); }}
            style={{ fontSize: 11, background: "none", border: "1px solid var(--border-strong)", borderRadius: 2, color: "var(--text-dim)", padding: "4px 6px" }}
          >
            {FOCUS_OPTIONS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
          </select>
        )}
        <button
          onClick={toggleTheme}
          title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          style={{
            fontSize: 11,
            background: "none",
            border: "1px solid var(--border-strong)",
            borderRadius: 2,
            color: "var(--text-dim)",
            padding: "4px 9px",
            cursor: "pointer",
          }}
        >
          {theme === "dark" ? "Light" : "Dark"}
        </button>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: "50%",
              background: "var(--signal)",
              boxShadow: "0 0 0 3px var(--signal-dim)",
            }}
          />
          <span className="mono" style={{ fontSize: 12, color: "var(--text-muted)" }}>
            {LOCAL_MODE ? "local" : "live"}
          </span>
        </div>
      </div>
    </header>
  );
}
