/** Passive device discovery from a capture, in the browser. Port of
 *  backend/app/ingestion/discovery.py (discover_devices, parse_lldp, parse_cdp):
 *  same rules, same keys and values. Read that module's docstring for what a
 *  single capture can and cannot reveal -- roles are heuristics with evidence,
 *  not ground truth about cabling. Never throws on a malformed capture. */
import {
  iterPackets, macStr, decodeReplace, decodeEthernet, isPrivate, isPublic, u16, TH_SYN, TH_ACK,
} from "./netdecode";

export interface DeviceRow {
  device_key: string;
  mac: string | null;
  ips: string[];
  ip: string | null;
  role: string;
  tags: string[];
  hostname: string | null;
  os_hint: string | null;
  services: number[];
  mac_randomized: boolean;
  evidence: string[];
  confidence: "low" | "medium" | "high";
  first_seen_ts: number | null;
  last_seen_ts: number | null;
}

export interface LldpInfo {
  chassis: string; port?: string; port_desc?: string; sys_name?: string; sys_desc?: string; caps?: number; enabled?: number;
}
export interface CdpInfo { device_id: string; port?: string; caps?: number; platform?: string }

const ROLE_PRIORITY = ["switch", "router", "access_point", "gateway", "dhcp_server", "dns_server", "server", "client", "unknown"];
const LLDP_ETHERTYPE = 0x88cc;
const CDP_MAC = "01:00:0c:cc:cc:cc";
const MAX_EVIDENCE = 12;
const CONF = ["low", "medium", "high"] as const;
type Conf = typeof CONF[number];

function isUnicastMac(m: string): boolean {
  return !(parseInt(m.slice(0, 2), 16) & 1) && m !== "00:00:00:00:00:00";
}

function osHint(ttl: number): string | null {
  if (ttl >= 33 && ttl <= 64) return "Linux/macOS/Android/iOS-like (initial TTL 64)";
  if (ttl >= 65 && ttl <= 128) return "Windows-like (initial TTL 128)";
  if (ttl >= 129 && ttl <= 255) return "Network device / Unix-like (initial TTL 255)";
  return null;
}

/** LLDPDU TLVs: 7-bit type, 9-bit length. */
export function parseLldp(payload: Uint8Array): LldpInfo | null {
  const out: Partial<LldpInfo> = {};
  let i = 0;
  while (i + 2 <= payload.length) {
    const hdr = u16(payload, i);
    const t = hdr >> 9, ln = hdr & 0x1ff;
    const val = payload.subarray(i + 2, i + 2 + ln);
    i += 2 + ln;
    if (t === 0) break;
    if (t === 1 && val.length >= 2) {
      const v = val.subarray(1);
      out.chassis = val[0] === 4 && v.length === 6 ? macStr(v) : decodeReplace(v);
    } else if (t === 2 && val.length >= 2) {
      out.port = val[0] !== 3 ? decodeReplace(val.subarray(1)) : macStr(val.subarray(1));
    } else if (t === 4) {
      out.port_desc = decodeReplace(val);
    } else if (t === 5) {
      out.sys_name = decodeReplace(val);
    } else if (t === 6) {
      out.sys_desc = Array.from(decodeReplace(val)).slice(0, 120).join(""); // Python slices code points
    } else if (t === 7 && val.length >= 4) {
      out.caps = u16(val, 0);
      out.enabled = u16(val, 2);
    }
  }
  return out.chassis ? (out as LldpInfo) : null;
}

/** CDP over 802.3+LLC/SNAP: frame = eth(14) + LLC/SNAP(8) + CDP. `buf` is the whole frame. */
export function parseCdp(buf: Uint8Array): CdpInfo | null {
  const cdp = buf.subarray(22);
  if (cdp.length < 4) return null;
  let i = 4;
  const out: Partial<CdpInfo> = {};
  while (i + 4 <= cdp.length) {
    const t = u16(cdp, i), ln = u16(cdp, i + 2);
    if (ln < 4) break;
    const val = cdp.subarray(i + 4, i + ln);
    i += ln;
    if (t === 1) out.device_id = decodeReplace(val);
    else if (t === 3) out.port = decodeReplace(val);
    else if (t === 4 && val.length >= 4) out.caps = ((val[0] << 24) | (val[1] << 16) | (val[2] << 8) | val[3]) >>> 0;
    else if (t === 6) out.platform = decodeReplace(val);
  }
  return out.device_id ? (out as CdpInfo) : null;
}

class Dev {
  mac: string | null = null;
  ips = new Set<string>();
  roles = new Set<string>();
  hostname: string | null = null;
  osHint: string | null = null;
  services = new Set<number>();
  evidence: string[] = [];
  confidence: Conf = "low";
  first: number | null = null;
  last: number | null = null;
  constructor(public key: string) {}
  note(text: string, conf?: Conf) {
    if (!this.evidence.includes(text) && this.evidence.length < MAX_EVIDENCE) this.evidence.push(text);
    if (conf && CONF.indexOf(conf) > CONF.indexOf(this.confidence)) this.confidence = conf;
  }
  touch(ts: number) {
    this.first = this.first === null ? ts : Math.min(this.first, ts);
    this.last = this.last === null ? ts : Math.max(this.last, ts);
  }
}

interface L2Info { kind: "LLDP" | "CDP"; ts: number; lldp?: LldpInfo; cdp?: CdpInfo }

/** dpkt.dhcp.DHCP(data): fixed 240-byte header then (code,len,value) options.
 *  Throws where dpkt/the Python caller would raise. Last duplicate option wins. */
function parseDhcpOptions(d: Uint8Array): { chaddr: Uint8Array; opts: Map<number, Uint8Array> } {
  if (d.length < 240) throw new Error("short dhcp");
  const chaddr = d.subarray(28, 44).subarray(0, d[2]);
  const opts = new Map<number, Uint8Array>();
  let b = d.subarray(240);
  while (b.length) {
    const t = b[0];
    if (t === 0xff) break;
    if (t === 0) { b = b.subarray(1); continue; }
    if (b.length < 2) throw new Error("truncated option");
    const n = b[1];
    opts.set(t, b.subarray(2, 2 + n));
    b = b.subarray(2 + n);
  }
  return { chaddr, opts };
}

const addTo = <K, V>(m: Map<K, Set<V>>, k: K, v: V) => { let s = m.get(k); if (!s) m.set(k, s = new Set()); s.add(v); };
const pushTs = (m: Map<string, number[]>, k: string, ts: number) => { const a = m.get(k); if (a) a.push(ts); else m.set(k, [ts]); };

export function discoverDevices(data: Uint8Array): DeviceRow[] {
  const ipMacArp = new Map<string, string>();
  const ipMacsWeak = new Map<string, Set<string>>();
  const macPrivIps = new Map<string, Set<string>>();
  const gwDst = new Map<string, Set<string>>();
  const ipMaxTtl = new Map<string, number>();
  const ipSeenTs = new Map<string, number[]>();
  const synAck = new Map<string, { ip: string; port: number; clients: Set<string> }>();
  const dnsClients = new Map<string, Set<string>>();
  const dhcpServers = new Map<string, string>();
  const hostnamesByMac = new Map<string, string>();
  const initiators = new Set<string>();
  const l2 = new Map<string, L2Info>();

  for (const pkt of iterPackets(data)) {
    const ts = pkt.ts, buf = pkt.data;
    try {
      if (buf.length < 14) continue;
      const smac = macStr(buf.subarray(6, 12)), dmac = macStr(buf.subarray(0, 6));
      const etype = u16(buf, 12);

      if (etype === LLDP_ETHERTYPE) {
        const info = parseLldp(buf.subarray(14));
        if (info) l2.set(smac, { kind: "LLDP", ts, lldp: info });
        continue;
      }
      if (dmac === CDP_MAC && etype < 1536) {
        const info = parseCdp(buf);
        if (info) l2.set(smac, { kind: "CDP", ts, cdp: info });
        continue;
      }

      const eth = decodeEthernet(buf);
      if (eth.arp) {
        const { spa, sha } = eth.arp;
        if (spa !== "0.0.0.0" && isUnicastMac(sha)) {
          ipMacArp.set(spa, sha);
          pushTs(ipSeenTs, spa, ts);
        }
        continue;
      }
      const ip = eth.ip;
      if (!ip) continue;
      const src = ip.src, dst = ip.dst;

      if (isPrivate(src) && isUnicastMac(smac)) {
        addTo(ipMacsWeak, src, smac);
        addTo(macPrivIps, smac, src);
        ipMaxTtl.set(src, Math.max(ipMaxTtl.get(src) ?? 0, ip.ttl));
        pushTs(ipSeenTs, src, ts);
      }
      if (isPrivate(dst)) pushTs(ipSeenTs, dst, ts);
      if (isPublic(dst) && isPrivate(src) && isUnicastMac(dmac)) addTo(gwDst, dmac, dst);
      if (isPublic(src) && isPrivate(dst) && isUnicastMac(smac)) addTo(gwDst, smac, src);

      const l4 = ip.l4;
      if (l4 && l4.kind === "tcp") {
        const isSyn = !!(l4.flags & TH_SYN), isAck = !!(l4.flags & TH_ACK);
        if (isSyn && isAck) {
          const k = `${src}|${l4.sport}`;
          let e = synAck.get(k);
          if (!e) synAck.set(k, e = { ip: src, port: l4.sport, clients: new Set() });
          e.clients.add(dst);
        } else if (isSyn) initiators.add(src);
        if (l4.dport === 53) addTo(dnsClients, dst, src);
      } else if (l4 && l4.kind === "udp") {
        if (l4.dport === 53) addTo(dnsClients, dst, src);
        if ((l4.sport === 67 || l4.sport === 68 || l4.dport === 67 || l4.dport === 68) && l4.data.length) {
          try {
            const { chaddr, opts } = parseDhcpOptions(l4.data);
            const mt = opts.get(53);
            if (mt && mt.length === 0) throw new Error("empty message type"); // b""[0] -> IndexError
            const mtype = mt ? mt[0] : 0;
            if (mtype === 2 || mtype === 5) dhcpServers.set(src, smac);
            const hn = opts.get(12);
            if ((mtype === 1 || mtype === 3) && hn) hostnamesByMac.set(macStr(chaddr.subarray(0, 6)), decodeReplace(hn));
          } catch { /* malformed DHCP is ignored */ }
        }
      }
    } catch {
      continue;
    }
  }

  // ---- gateway inference: the MAC that is the next hop for the most public IPs
  let gatewayMac: string | null = null;
  if (gwDst.size) {
    let cand = "", seen = -1;
    for (const [m, s] of gwDst) if (s.size > seen) { cand = m; seen = s.size; } // first maximum, like max()
    if (seen >= 3) gatewayMac = cand;
  }

  const devices = new Map<string, Dev>();
  const devForMac = (m: string): Dev => {
    const k = "mac:" + m;
    let d = devices.get(k);
    if (!d) devices.set(k, d = new Dev(k));
    return d;
  };
  const macOfIp = (ip: string): string | null => {
    const arp = ipMacArp.get(ip);
    if (arp !== undefined) return arp;
    const macs = ipMacsWeak.get(ip);
    if (macs && macs.size === 1) {
      const m = macs.values().next().value as string;
      // a MAC carrying many private IPs is a router forwarding for them, not their owner
      if (m !== gatewayMac && macPrivIps.get(m)!.size === 1) return m;
    }
    return null;
  };
  const devForIp = (ip: string): Dev => {
    const m = macOfIp(ip);
    let d: Dev;
    if (m) { d = devForMac(m); d.mac = m; }
    else {
      const k = "ip:" + ip;
      d = devices.get(k) ?? new Dev(k);
      devices.set(k, d);
    }
    d.ips.add(ip);
    return d;
  };

  // LLDP / CDP announcements -> infrastructure devices (high confidence)
  for (const [m, info] of l2) {
    const d = devForMac(m);
    d.mac = m;
    d.touch(info.ts);
    d.confidence = "high";
    if (info.kind === "LLDP") {
      const l = info.lldp!;
      d.hostname = l.sys_name || d.hostname;
      const enabled = l.enabled ?? 0;
      if (enabled & 0x04) d.roles.add("switch");
      if (enabled & 0x10) d.roles.add("router");
      if (enabled & 0x08) d.roles.add("access_point");
      d.note(`LLDP announcement: ${l.sys_name || l.chassis}, port ${l.port ?? "?"}`, "high");
      if (l.sys_desc) d.note("LLDP description: " + l.sys_desc);
    } else {
      const c = info.cdp!;
      const caps = c.caps ?? 0;
      d.hostname = c.device_id || d.hostname;
      if ((caps & 0x08) || (caps & 0x02)) d.roles.add("switch");
      if (caps & 0x01) d.roles.add("router");
      d.note(`CDP announcement: ${c.device_id} (${c.platform ?? "unknown platform"}), port ${c.port ?? "?"}`, "high");
    }
  }

  // Gateway
  if (gatewayMac) {
    const d = devForMac(gatewayMac);
    d.mac = gatewayMac;
    d.roles.add("gateway");
    d.note(`Next-hop MAC for traffic to/from ${gwDst.get(gatewayMac)!.size} distinct public IPs`, "medium");
    for (const [ip, m] of ipMacArp) {
      if (m === gatewayMac) { d.ips.add(ip); d.note(`ARP binds ${ip} to this MAC`, "high"); }
    }
  }

  // DHCP servers
  for (const [ip, m] of dhcpServers) {
    const d = devForIp(ip);
    if (!d.mac && isUnicastMac(m) && m !== gatewayMac) d.mac = m;
    d.roles.add("dhcp_server");
    d.note("Sent DHCP OFFER/ACK", "high");
  }

  // DNS servers (private only -- public resolvers are not local devices)
  for (const [ip, clients] of dnsClients) {
    if (isPrivate(ip) && clients.size >= 1) {
      const d = devForIp(ip);
      d.roles.add("dns_server");
      d.note(`Received DNS queries from ${clients.size} host(s)`, "medium");
    }
  }

  // Servers: answered TCP SYNs on a port
  const portsByIp = new Map<string, Map<number, number>>();
  for (const { ip, port, clients } of synAck.values()) {
    if (isPrivate(ip)) {
      let pm = portsByIp.get(ip);
      if (!pm) portsByIp.set(ip, pm = new Map());
      pm.set(port, clients.size);
    }
  }
  for (const [ip, ports] of portsByIp) {
    const d = devForIp(ip);
    d.roles.add("server");
    for (const p of ports.keys()) d.services.add(p);
    const sorted = [...ports.keys()].sort((a, b) => a - b).slice(0, 8);
    d.note("Accepted TCP connections on port(s) " + sorted.join(", "), "medium");
  }

  // Clients / everything else private we saw
  for (const ip of ipSeenTs.keys()) {
    if (!isPrivate(ip)) continue;
    const d = devForIp(ip);
    if (initiators.has(ip)) { d.roles.add("client"); d.note("Initiated TCP connections", "low"); }
    const ttl = ipMaxTtl.get(ip);
    if (ttl !== undefined) d.osHint = d.osHint || osHint(ttl);
    for (const t of ipSeenTs.get(ip)!) d.touch(t);
  }

  for (const [m, name] of hostnamesByMac) {
    const d = devices.get("mac:" + m);
    if (d) { d.hostname = d.hostname || name; d.note(`DHCP hostname '${name}'`, "medium"); }
  }

  const out: DeviceRow[] = [];
  for (const d of devices.values()) {
    const role = ROLE_PRIORITY.find(r => d.roles.has(r)) ?? "unknown";
    if (role === "unknown" && !d.ips.size && !d.mac) continue;
    const ips = [...d.ips].sort();
    out.push({
      device_key: d.key,
      mac: d.mac,
      ips,
      ip: ips.length ? ips[0] : null,
      role,
      tags: [...d.roles].filter(r => r !== role).sort(),
      hostname: d.hostname,
      os_hint: d.osHint,
      services: [...d.services].sort((a, b) => a - b),
      mac_randomized: !!(d.mac && (parseInt(d.mac.slice(0, 2), 16) & 0x02)),
      evidence: d.evidence,
      confidence: d.confidence,
      first_seen_ts: d.first,
      last_seen_ts: d.last,
    });
  }
  out.sort((a, b) => ROLE_PRIORITY.indexOf(a.role) - ROLE_PRIORITY.indexOf(b.role) || cmp(a.ip ?? "", b.ip ?? ""));
  return out;
}

function cmp(a: string, b: string): number { return a < b ? -1 : a > b ? 1 : 0; }
