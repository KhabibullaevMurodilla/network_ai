"use client";
import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";

type Device = {
  id: string; device_key: string; mac: string | null; ip: string | null; ips: string[];
  role: string; tags: string[]; hostname: string | null; os_hint: string | null;
  services: number[]; mac_randomized: boolean; evidence: string[]; confidence: "low" | "medium" | "high";
  first_seen: string; last_seen: string;
};

const ROLE_LABEL: Record<string, string> = {
  switch: "Switch", router: "Router", access_point: "Access point", gateway: "Gateway",
  dhcp_server: "DHCP server", dns_server: "DNS server", server: "Server", client: "Client", unknown: "Unknown",
};
const ORDER = Object.keys(ROLE_LABEL);
const CONF_COLOR: Record<string, string> = { high: "var(--signal)", medium: "var(--alert)", low: "var(--text-dim)" };

export default function DevicesPage() {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("all");
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => { api.listDevices().then(setDevices).catch((e) => setError(e.message)); }, []);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    (devices || []).forEach((d) => { c[d.role] = (c[d.role] || 0) + 1; });
    return c;
  }, [devices]);

  if (error) return <div style={{ color: "var(--critical)", fontSize: 13 }}>{error}</div>;
  if (!devices) return <div style={{ color: "var(--text-muted)", fontSize: 13 }}>Loading…</div>;

  const shown = devices
    .filter((d) => filter === "all" || d.role === filter)
    .sort((a, b) => ORDER.indexOf(a.role) - ORDER.indexOf(b.role));

  return (
    <div style={{ maxWidth: 1040 }}>
      <h1 style={{ fontSize: 18, fontWeight: 600, marginBottom: 4 }}>Devices</h1>
      <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 16, lineHeight: 1.6 }}>
        Discovered passively from the packet captures you upload (ARP, DHCP, TCP handshakes, and
        LLDP/CDP announcements). Roles are inferred, each with the evidence behind it — this is not
        verified cabling, and switches only appear if they announce themselves in the capture.
        A capture from a single PC sees that PC, its gateway and local broadcasts, not the whole network.
      </p>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 16 }}>
        {["all", ...ORDER.filter((r) => counts[r])].map((r) => (
          <button key={r} onClick={() => setFilter(r)} style={{
            fontSize: 12, padding: "5px 12px", cursor: "pointer", borderRadius: 2,
            border: filter === r ? "1px solid var(--signal)" : "1px solid var(--border-strong)",
            background: filter === r ? "var(--signal-dim)" : "transparent",
            color: filter === r ? "var(--text-primary)" : "var(--text-muted)",
          }}>
            {r === "all" ? `All (${devices.length})` : `${ROLE_LABEL[r]} (${counts[r]})`}
          </button>
        ))}
      </div>

      {shown.length === 0 ? (
        <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)", padding: 24, color: "var(--text-dim)", fontSize: 13 }}>
          No devices discovered yet. Upload a packet capture (or run the live capture script); devices are learned from each capture.
        </div>
      ) : (
        <div style={{ border: "1px solid var(--border)", background: "var(--bg-panel)" }}>
          {shown.map((d, i) => (
            <div key={d.id} style={{ borderBottom: i < shown.length - 1 ? "1px solid var(--border)" : "none" }}>
              <div onClick={() => setOpen(open === d.id ? null : d.id)} style={{ display: "grid", gridTemplateColumns: "110px 1.2fr 1.4fr 1.2fr 80px", gap: 12, padding: "10px 16px", cursor: "pointer", alignItems: "center", fontSize: 13 }}>
                <span className="mono" style={{ fontSize: 11, textTransform: "uppercase", color: "var(--signal)" }}>{ROLE_LABEL[d.role] || d.role}</span>
                <span className="mono">{d.ip || d.hostname || "—"}{d.ip && d.hostname ? <span style={{ color: "var(--text-dim)" }}> · {d.hostname}</span> : null}</span>
                <span className="mono" style={{ color: "var(--text-muted)", fontSize: 12 }}>
                  {d.mac || "—"}{d.mac_randomized ? " (random MAC)" : ""}
                </span>
                <span style={{ color: "var(--text-dim)", fontSize: 12 }}>
                  {d.os_hint ? d.os_hint.split(" (")[0] : ""}{d.services.length ? ` · ports ${d.services.slice(0, 4).join(", ")}` : ""}
                </span>
                <span className="mono" style={{ fontSize: 11, color: CONF_COLOR[d.confidence], textTransform: "uppercase" }}>{d.confidence}</span>
              </div>
              {open === d.id && (
                <div style={{ padding: "4px 16px 14px 16px", fontSize: 12, color: "var(--text-muted)", lineHeight: 1.7 }}>
                  <div style={{ color: "var(--text-dim)", marginBottom: 4 }}>Why we think so</div>
                  {d.evidence.map((e, j) => <div key={j}>• {e}</div>)}
                  {d.tags.length > 0 && <div style={{ marginTop: 6 }}>Also: {d.tags.map((t) => ROLE_LABEL[t] || t).join(", ")}</div>}
                  <div style={{ marginTop: 6, color: "var(--text-dim)" }}>
                    First seen {new Date(d.first_seen).toISOString().replace("T", " ").slice(0, 19)} UTC · last seen {new Date(d.last_seen).toISOString().replace("T", " ").slice(0, 19)} UTC
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
