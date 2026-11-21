"use client";
import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { layout, W, H } from "@/lib/graphLayout";

type PNode = { id: string; role: string; label: string; ip: string | null; mac: string | null; confidence: string };
type PLink = { id: string; a_key: string; a_port: string; b_key: string; b_port: string | null; source: "lldp" | "cdp" | "fdb"; evidence: string | null; last_seen: string };
const INFRA = new Set(["switch", "router", "access_point", "gateway"]);
const LINK_STYLE: Record<string, { dash?: string; w: number; label: string }> = {
  lldp: { w: 2.2, label: "LLDP neighbour (strong)" },
  cdp: { w: 2.2, label: "CDP neighbour (strong)" },
  fdb: { dash: "4 3", w: 1.2, label: "MAC table, edge port (good, not proof)" },
};

export default function PhysicalPage() {
  const [data, setData] = useState<{ nodes: PNode[]; links: PLink[] } | null>(null);
  const [error, setError] = useState("");
  const [hover, setHover] = useState<string | null>(null);
  useEffect(() => { api.getPhysical().then(setData).catch((e) => setError(e.message)); }, []);

  // Stretch the settled layout to fill the canvas so small networks stay readable.
  const laid = useMemo(() => {
    if (!data) return [];
    const raw = layout(data.nodes, data.links.map((l) => ({ source: l.a_key, target: l.b_key })));
    if (raw.length < 2) return raw;
    const xs = raw.map((n) => n.x), ys = raw.map((n) => n.y);
    const [x0, x1, y0, y1] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
    const fx = (v: number) => (x1 - x0 < 1 ? W / 2 : 90 + ((v - x0) / (x1 - x0)) * (W - 180));
    const fy = (v: number) => (y1 - y0 < 1 ? H / 2 : 50 + ((v - y0) / (y1 - y0)) * (H - 110));
    return raw.map((n) => ({ ...n, x: fx(n.x), y: fy(n.y) }));
  }, [data]);
  const pos = useMemo(() => new Map(laid.map((n) => [n.id, n])), [laid]);

  if (error) return <div style={{ color: "var(--critical)", fontSize: 13 }}>{error}</div>;
  if (!data) return <div style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading…</div>;

  const hoveredLink = data.links.find((l) => l.id === hover);

  return (
    <div style={{ maxWidth: 1040 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>Physical map</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 16, lineHeight: 1.6 }}>
        Real links read from your switches and routers over SNMP (neighbour announcements and MAC tables),
        collected by <span className="mono">agent/snmp_collector.py</span>. Solid lines are LLDP/CDP neighbours;
        dashed lines are hosts learned on an edge port. Ports with many MACs are treated as uplinks and are
        not drawn to individual hosts. Hover a line for the port names.
      </p>
      {data.nodes.length === 0 ? (
        <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: 24, color: "var(--text-dim)", fontSize: 13 }}>
          No SNMP data yet. Run the SNMP collector against your switches (see README, “v6.6”).
        </div>
      ) : (
        <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
          <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ display: "block" }}>
            {data.links.map((l) => {
              const a = pos.get(l.a_key), b = pos.get(l.b_key);
              if (!a || !b) return null;
              const st = LINK_STYLE[l.source];
              return (
                <g key={l.id} onMouseEnter={() => setHover(l.id)} onMouseLeave={() => setHover(null)}>
                  <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="var(--text-dim)" strokeWidth={hover === l.id ? st.w + 1.5 : st.w} strokeDasharray={st.dash} strokeOpacity={0.75} />
                  <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="transparent" strokeWidth={12} />
                </g>
              );
            })}
            {laid.map((n) => {
              const infra = INFRA.has(n.role);
              const r = infra ? 11 : 6;
              return (
                <g key={n.id}>
                  {infra
                    ? <rect x={n.x - r} y={n.y - r} width={r * 2} height={r * 2} fill="var(--bg-panel)" stroke="var(--signal)" strokeWidth={2} />
                    : <circle cx={n.x} cy={n.y} r={r} fill="var(--bg-panel)" stroke="var(--text-dim)" strokeWidth={1.2} />}
                  <text x={n.x} y={n.y + r + 15} textAnchor="middle" className="mono" fontSize="11" fill="var(--text-muted)">
                    {n.label.replace(/^(mac|ip|lldp|cdp):/, "")}{n.ip && n.label !== n.ip ? ` (${n.ip})` : ""}
                  </text>
                </g>
              );
            })}
          </svg>
          <div style={{ minHeight: 38, padding: "10px 16px", borderTop: "1px solid var(--border)", fontSize: 12, color: "var(--text-muted)" }} className="mono">
            {hoveredLink ? hoveredLink.evidence || `${hoveredLink.a_port} ↔ ${hoveredLink.b_port ?? "?"}` : (
              <span style={{ color: "var(--text-dim)", fontFamily: "inherit" }}>
                {Object.values(LINK_STYLE).map((s) => s.label).join(" · ")} · squares = switches/routers/APs
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
