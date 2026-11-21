// "focus" = what a person came to the dashboard to look at. Deliberately
// separate from "role" (what they're allowed to do): focus only ever
// changes what is shown FIRST. It is never used to gate a permission --
// the backend enforces role on every write (see routers/team.py).
export type Focus = "security" | "network" | "ot" | "executive";

export const FOCUS_OPTIONS: { value: Focus; label: string; blurb: string; home: string }[] = [
  { value: "security", label: "Security analyst / on-call", blurb: "What's flagged right now, is it real, and what do I do about it.", home: "/dashboard" },
  { value: "network", label: "Network / NOC engineer", blurb: "Is the network healthy over time -- trends, who talks to whom.", home: "/dashboard/trends" },
  { value: "ot", label: "OT / ICS engineer", blurb: "Did anything touch the Modbus / PLC layer.", home: "/dashboard/ot-events" },
  { value: "executive", label: "Executive / CISO", blurb: "One plain-language read: are we okay, better or worse.", home: "/dashboard/executive" },
];

export function focusHome(focus: Focus | null | undefined): string {
  return FOCUS_OPTIONS.find((f) => f.value === focus)?.home ?? "/dashboard";
}

// Which nav items lead for each focus. Everything stays reachable --
// reordering, never hiding: hiding breeds "where did X go" support
// tickets, reordering doesn't.
const LEAD: Record<Focus, string[]> = {
  security: ["/dashboard", "/dashboard/incidents", "/dashboard/entities", "/dashboard/response-actions"],
  network: ["/dashboard/trends", "/dashboard/topology", "/dashboard/devices", "/dashboard/external", "/dashboard/physical", "/dashboard/entities", "/dashboard"],
  ot: ["/dashboard/ot-events", "/dashboard/incidents", "/dashboard/entities", "/dashboard"],
  executive: ["/dashboard/executive", "/dashboard/trends", "/dashboard/incidents"],
};

export function orderNav<T extends { href: string }>(nav: T[], focus: Focus | null | undefined): T[] {
  if (!focus) return nav;
  const lead = LEAD[focus];
  const rank = (href: string) => {
    const i = lead.indexOf(href);
    return i === -1 ? lead.length : i;
  };
  return [...nav].sort((a, b) => rank(a.href) - rank(b.href)); // stable: ties keep original order
}

const ROLE_RANK: Record<string, number> = { viewer: 0, analyst: 1, admin: 2, owner: 3 };
// UI convenience only -- the server is the real gate.
export const roleAtLeast = (role: string | undefined, min: string) => (ROLE_RANK[role ?? ""] ?? -1) >= ROLE_RANK[min];
