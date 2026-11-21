"use client";
import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { layout, W, H } from "@/lib/graphLayout";
import { severityColor, severityLabel, type Severity } from "@/lib/severity";

type Node = { id: string; event_count: number; max_severity: Severity; role?: string | null; hostname?: string | null };
const INFRA = new Set(["switch", "router", "gateway", "access_point"]);
type Edge = { source: string; target: string; flow_count: number };
type Topology = { nodes: Node[]; edges: Edge[]; truncated: boolean };


export default function TopologyPage() {
  const [data, setData] = useState<Topology | null>(null);
  const [error, setError] = useState("");
  const [hovered, setHovered] = useState<string | null>(null);

  useEffect(() => {
    api.getTopology().then(setData).catch((e) => setError(e.message));
  }, []);

  const laidOut = useMemo(() => (data ? layout(data.nodes, data.edges) : []), [data]);
  const posById = useMemo(() => new Map(laidOut.map((n) => [n.id, n])), [laidOut]);
  const maxFlow = useMemo(() => Math.max(...(data?.edges.map((e) => e.flow_count) ?? [1]), 1), [data]);

  if (error) return <div style={{ color: "var(--critical)", fontSize: 13 }}>{error}</div>;
  if (!data) return <div style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading…</div>;

  return (
    <div style={{ maxWidth: 1040 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>Network topology</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 16, lineHeight: 1.6 }}>
        Who talks to whom, built from ingested flow telemetry. Edge thickness is flow volume between
        a pair; the ring color is that source&apos;s worst flagged severity. Shapes come from passive
        device discovery (see Devices): squares are infrastructure (gateway, router, switch, access
        point), rounded squares are servers, circles are everything else. Roles are inferred from
        captured traffic, not verified cabling.
        {data.truncated && " Showing a capped subset of the busiest recent traffic, not every flow."}
      </p>

      {data.nodes.length === 0 ? (
        <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: 24, color: "var(--text-dim)", fontSize: 13 }}>
          No flow telemetry with IP addresses yet. Connect a telemetry source that includes src_ip/dst_ip to see the graph here.
        </div>
      ) : (
        <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
          <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ display: "block" }}>
            {data.edges.map((e, i) => {
              const s = posById.get(e.source);
              const t = posById.get(e.target);
              if (!s || !t) return null;
              const strokeWidth = 0.6 + (e.flow_count / maxFlow) * 3;
              const dim = hovered && hovered !== e.source && hovered !== e.target;
              return (
                <line
                  key={i}
                  x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                  stroke="var(--border-strong)"
                  strokeOpacity={dim ? 0.12 : 0.5}
                  strokeWidth={strokeWidth}
                />
              );
            })}
            {laidOut.map((node) => {
              const r = 5 + Math.min(node.event_count, 20) * 0.6;
              const color = node.max_severity ? severityColor(node.max_severity) : "var(--text-dim)";
              const dim = hovered && hovered !== node.id;
              return (
                <g
                  key={node.id}
                  onMouseEnter={() => setHovered(node.id)}
                  onMouseLeave={() => setHovered(null)}
                  style={{ cursor: "default" }}
                  opacity={dim ? 0.25 : 1}
                >
                  {node.role && INFRA.has(node.role) ? (
                    <rect x={node.x - r - 2} y={node.y - r - 2} width={(r + 2) * 2} height={(r + 2) * 2} fill="var(--bg-panel)" stroke={color} strokeWidth={node.max_severity ? 2 : 1.6} />
                  ) : node.role === "server" ? (
                    <rect x={node.x - r} y={node.y - r} width={r * 2} height={r * 2} rx={r * 0.5} fill="var(--bg-panel)" stroke={color} strokeWidth={node.max_severity ? 2 : 1.2} />
                  ) : (
                    <circle cx={node.x} cy={node.y} r={r} fill="var(--bg-panel)" stroke={color} strokeWidth={node.max_severity ? 2 : 1.2} />
                  )}
                  {(hovered === node.id || node.event_count > 0 || (node.role && INFRA.has(node.role))) && (
                    <text x={node.x} y={node.y - r - 6} textAnchor="middle" className="mono" fontSize="10" fill="var(--text-muted)">
                      {node.hostname ? `${node.hostname} (${node.id})` : node.id}{node.role && hovered === node.id ? ` · ${node.role}` : ""}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
          <div style={{ display: "flex", gap: 16, padding: "10px 16px", borderTop: "1px solid var(--border)" }}>
            {(["low", "medium", "high", "critical"] as const).map((s) => (
              <div key={s} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <span style={{ width: 9, height: 9, borderRadius: "50%", border: `2px solid ${severityColor(s)}`, display: "inline-block" }} />
                <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{severityLabel(s)}</span>
              </div>
            ))}
            <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{ width: 9, height: 9, borderRadius: "50%", border: "1.2px solid var(--text-dim)", display: "inline-block" }} />
              <span style={{ fontSize: 11, color: "var(--text-dim)" }}>No flagged events</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{ width: 9, height: 9, border: "1.6px solid var(--text-dim)", display: "inline-block" }} />
              <span style={{ fontSize: 11, color: "var(--text-dim)" }}>Infrastructure</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{ width: 9, height: 9, borderRadius: 3, border: "1.2px solid var(--text-dim)", display: "inline-block" }} />
              <span style={{ fontSize: 11, color: "var(--text-dim)" }}>Server</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
