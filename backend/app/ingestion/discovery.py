"""Passive device discovery from a packet capture (v6.5).

What this can and cannot know -- stated up front because it decides what the
dashboard may honestly claim:

* It learns ONLY from frames present in the capture. A capture taken on one
  PC sees that PC's own traffic plus whatever broadcast/multicast reaches it.
  It does NOT see other hosts' conversations, and a switch never shows up as
  an IP hop, so switches are discoverable only when they announce themselves
  (LLDP / CDP frames) -- which are link-local and normally reach only the
  device plugged directly into the switch port, or a mirror (SPAN) port.
* Roles are heuristics with an evidence list and a confidence label. Nothing
  here is ground truth about physical cabling or which switch port a host is
  on; that needs SNMP/LLDP data from the devices themselves (not built).
* No MAC-vendor (OUI) database is bundled; only the locally-administered
  (randomised-MAC) bit is reported, which is exact.

Sources used: ARP (IP<->MAC), the Ethernet next-hop MAC of packets to/from
public IPs (gateway), LLDP + CDP announcements (switch/router/AP and their
system names), DHCP (server + client hostnames), TCP SYN-ACK senders (servers
and their listening ports), DNS destinations, and the IP TTL as an OS-family
hint.
"""
from __future__ import annotations
import io
import ipaddress
import struct
from collections import defaultdict

import dpkt

from .pcap import _looks_like_classic_pcap, _ip_to_str

ROLE_PRIORITY = ["switch", "router", "access_point", "gateway", "dhcp_server", "dns_server", "server", "client", "unknown"]
LLDP_ETHERTYPE = 0x88CC
CDP_MAC = "01:00:0c:cc:cc:cc"
WELL_KNOWN_SERVER_PORTS = {53, 67, 123, 161}
MAX_EVIDENCE = 12


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private and not (a.is_multicast or a.is_unspecified or a.is_loopback)


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


def _unicast_mac(m: str) -> bool:
    first = int(m[:2], 16)
    return not (first & 1) and m != "00:00:00:00:00:00"


def _os_hint(ttl: int) -> str | None:
    if 33 <= ttl <= 64:
        return "Linux/macOS/Android/iOS-like (initial TTL 64)"
    if 65 <= ttl <= 128:
        return "Windows-like (initial TTL 128)"
    if 129 <= ttl <= 255:
        return "Network device / Unix-like (initial TTL 255)"
    return None


def parse_lldp(payload: bytes) -> dict | None:
    """LLDPDU TLVs: 7-bit type, 9-bit length. Returns a dict or None."""
    out: dict = {}
    i = 0
    try:
        while i + 2 <= len(payload):
            hdr = struct.unpack("!H", payload[i:i + 2])[0]
            t, ln = hdr >> 9, hdr & 0x1FF
            val = payload[i + 2:i + 2 + ln]
            i += 2 + ln
            if t == 0:
                break
            if t == 1 and len(val) >= 2:
                sub, v = val[0], val[1:]
                out["chassis"] = _mac(v) if sub == 4 and len(v) == 6 else v.decode("utf-8", "replace")
            elif t == 2 and len(val) >= 2:
                out["port"] = val[1:].decode("utf-8", "replace") if val[0] != 3 else _mac(val[1:])
            elif t == 4:
                out["port_desc"] = val.decode("utf-8", "replace")
            elif t == 5:
                out["sys_name"] = val.decode("utf-8", "replace")
            elif t == 6:
                out["sys_desc"] = val.decode("utf-8", "replace")[:120]
            elif t == 7 and len(val) >= 4:
                caps, enabled = struct.unpack("!HH", val[:4])
                out["caps"] = caps
                out["enabled"] = enabled
    except Exception:
        return None
    return out if out.get("chassis") else None


def parse_cdp(buf: bytes) -> dict | None:
    """CDP over 802.3+LLC/SNAP: frame = eth(14) + LLC/SNAP(8) + CDP."""
    try:
        cdp = buf[22:]
        if len(cdp) < 4:
            return None
        i, out = 4, {}
        while i + 4 <= len(cdp):
            t, ln = struct.unpack("!HH", cdp[i:i + 4])
            if ln < 4:
                break
            val = cdp[i + 4:i + ln]
            i += ln
            if t == 1:
                out["device_id"] = val.decode("utf-8", "replace")
            elif t == 3:
                out["port"] = val.decode("utf-8", "replace")
            elif t == 4 and len(val) >= 4:
                out["caps"] = struct.unpack("!I", val[:4])[0]
            elif t == 6:
                out["platform"] = val.decode("utf-8", "replace")
        return out if out.get("device_id") else None
    except Exception:
        return None


class _Dev:
    def __init__(self, key: str):
        self.key = key
        self.mac: str | None = None
        self.ips: set[str] = set()
        self.roles: set[str] = set()
        self.hostname: str | None = None
        self.os_hint: str | None = None
        self.services: set[int] = set()
        self.evidence: list[str] = []
        self.confidence = "low"
        self.first_seen: float | None = None
        self.last_seen: float | None = None

    def note(self, text: str, conf: str | None = None):
        if text not in self.evidence and len(self.evidence) < MAX_EVIDENCE:
            self.evidence.append(text)
        if conf and ["low", "medium", "high"].index(conf) > ["low", "medium", "high"].index(self.confidence):
            self.confidence = conf

    def touch(self, ts: float):
        self.first_seen = ts if self.first_seen is None else min(self.first_seen, ts)
        self.last_seen = ts if self.last_seen is None else max(self.last_seen, ts)


def discover_devices(data: bytes) -> list[dict]:
    """Return one dict per discovered LOCAL device (private-range hosts and
    any LLDP/CDP-announcing or inferred gateway device). Never raises on a
    malformed capture -- returns whatever was learned before the damage."""
    try:
        fh = io.BytesIO(data)
        reader = dpkt.pcap.Reader(fh) if _looks_like_classic_pcap(data) else dpkt.pcapng.Reader(fh)
    except Exception:
        return []

    ip_mac_arp: dict[str, str] = {}                       # strong IP->MAC
    ip_macs_weak: dict[str, set[str]] = defaultdict(set)  # from src IP + eth.src
    mac_privips: dict[str, set[str]] = defaultdict(set)
    gw_dst: dict[str, set[str]] = defaultdict(set)        # mac -> distinct public IPs it forwarded for
    ip_max_ttl: dict[str, int] = {}
    ip_seen_ts: dict[str, list[float]] = {}
    syn_ack: dict[tuple[str, int], set[str]] = defaultdict(set)   # (server ip, port) -> clients
    dns_clients: dict[str, set[str]] = defaultdict(set)
    dhcp_servers: dict[str, str] = {}                     # ip -> mac
    hostnames_by_mac: dict[str, str] = {}
    initiators: set[str] = set()
    l2_devices: dict[str, dict] = {}                      # mac -> lldp/cdp info (+ts)

    it = iter(reader)
    while True:
        try:
            ts, buf = next(it)
        except StopIteration:
            break
        except Exception:
            break
        try:
            if len(buf) < 14:
                continue
            smac, dmac = _mac(buf[6:12]), _mac(buf[0:6])
            etype = struct.unpack("!H", buf[12:14])[0]

            if etype == LLDP_ETHERTYPE:
                info = parse_lldp(buf[14:])
                if info:
                    info["_mac"], info["_ts"], info["_kind"] = smac, ts, "LLDP"
                    l2_devices[smac] = info
                continue
            if dmac == CDP_MAC and etype < 1536:
                info = parse_cdp(buf)
                if info:
                    info["_mac"], info["_ts"], info["_kind"] = smac, ts, "CDP"
                    l2_devices[smac] = info
                continue

            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.arp.ARP):
                a = eth.data
                spa = _ip_to_str(a.spa)
                sha = _mac(a.sha)
                if spa != "0.0.0.0" and _unicast_mac(sha):
                    ip_mac_arp[spa] = sha
                    ip_seen_ts.setdefault(spa, []).append(ts)
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            src, dst = _ip_to_str(ip.src), _ip_to_str(ip.dst)

            if _is_private(src) and _unicast_mac(smac):
                ip_macs_weak[src].add(smac)
                mac_privips[smac].add(src)
                ip_max_ttl[src] = max(ip_max_ttl.get(src, 0), ip.ttl)
                ip_seen_ts.setdefault(src, []).append(ts)
            if _is_private(dst):
                ip_seen_ts.setdefault(dst, []).append(ts)
            if _is_public(dst) and _is_private(src) and _unicast_mac(dmac):
                gw_dst[dmac].add(dst)
            if _is_public(src) and _is_private(dst) and _unicast_mac(smac):
                gw_dst[smac].add(src)

            l4 = ip.data
            if isinstance(l4, dpkt.tcp.TCP):
                is_syn, is_ack = bool(l4.flags & dpkt.tcp.TH_SYN), bool(l4.flags & dpkt.tcp.TH_ACK)
                if is_syn and is_ack:
                    syn_ack[(src, l4.sport)].add(dst)
                elif is_syn:
                    initiators.add(src)
                if l4.dport == 53:
                    dns_clients[dst].add(src)
            elif isinstance(l4, dpkt.udp.UDP):
                if l4.dport == 53:
                    dns_clients[dst].add(src)
                if {l4.sport, l4.dport} & {67, 68} and l4.data:
                    try:
                        d = dpkt.dhcp.DHCP(l4.data)
                        opts = {o[0]: o[1] for o in d.opts if isinstance(o, tuple) and len(o) == 2}
                        mtype = opts.get(dpkt.dhcp.DHCP_OPT_MSGTYPE, b"\x00")[0]
                        if mtype in (2, 5):  # OFFER / ACK come from a server
                            dhcp_servers[src] = smac
                        if mtype in (1, 3) and dpkt.dhcp.DHCP_OPT_HOSTNAME in opts:
                            hostnames_by_mac[_mac(d.chaddr[:6])] = opts[dpkt.dhcp.DHCP_OPT_HOSTNAME].decode("utf-8", "replace")
                    except Exception:
                        pass
        except Exception:
            continue

    # ---- gateway inference: the MAC that is the next hop for the most public IPs
    gateway_mac = None
    if gw_dst:
        cand, seen = max(gw_dst.items(), key=lambda kv: len(kv[1]))
        if len(seen) >= 3:
            gateway_mac = cand

    devices: dict[str, _Dev] = {}

    def dev_for_mac(m: str) -> _Dev:
        return devices.setdefault("mac:" + m, _Dev("mac:" + m))

    def mac_of_ip(ip: str) -> str | None:
        if ip in ip_mac_arp:
            return ip_mac_arp[ip]
        macs = ip_macs_weak.get(ip, set())
        if len(macs) == 1:
            m = next(iter(macs))
            # a MAC carrying many private IPs is a router forwarding for them, not their owner
            if m != gateway_mac and len(mac_privips[m]) == 1:
                return m
        return None

    def dev_for_ip(ip: str) -> _Dev:
        m = mac_of_ip(ip)
        if m:
            d = dev_for_mac(m)
            d.mac = m
        else:
            d = devices.setdefault("ip:" + ip, _Dev("ip:" + ip))
        d.ips.add(ip)
        return d

    # LLDP / CDP announcements -> infrastructure devices (high confidence)
    for m, info in l2_devices.items():
        d = dev_for_mac(m)
        d.mac = m
        d.touch(info["_ts"])
        d.confidence = "high"
        if info["_kind"] == "LLDP":
            d.hostname = info.get("sys_name") or d.hostname
            enabled = info.get("enabled", 0)
            if enabled & 0x04:
                d.roles.add("switch")
            if enabled & 0x10:
                d.roles.add("router")
            if enabled & 0x08:
                d.roles.add("access_point")
            d.note(f"LLDP announcement: {info.get('sys_name') or info['chassis']}, port {info.get('port', '?')}", "high")
            if info.get("sys_desc"):
                d.note("LLDP description: " + info["sys_desc"])
        else:
            caps = info.get("caps", 0)
            d.hostname = info.get("device_id") or d.hostname
            if caps & 0x08 or caps & 0x02:
                d.roles.add("switch")
            if caps & 0x01:
                d.roles.add("router")
            d.note(f"CDP announcement: {info['device_id']} ({info.get('platform', 'unknown platform')}), port {info.get('port', '?')}", "high")

    # Gateway
    if gateway_mac:
        d = dev_for_mac(gateway_mac)
        d.mac = gateway_mac
        d.roles.add("gateway")
        d.note(f"Next-hop MAC for traffic to/from {len(gw_dst[gateway_mac])} distinct public IPs", "medium")
        for ip, m in ip_mac_arp.items():
            if m == gateway_mac:
                d.ips.add(ip)
                d.note(f"ARP binds {ip} to this MAC", "high")

    # DHCP servers
    for ip, m in dhcp_servers.items():
        d = dev_for_ip(ip)
        if not d.mac and _unicast_mac(m) and m != gateway_mac:
            d.mac = m
        d.roles.add("dhcp_server")
        d.note("Sent DHCP OFFER/ACK", "high")

    # DNS servers (>= 2 distinct clients; private only -- public resolvers are not local devices)
    for ip, clients in dns_clients.items():
        if _is_private(ip) and len(clients) >= 1:
            d = dev_for_ip(ip)
            d.roles.add("dns_server")
            d.note(f"Received DNS queries from {len(clients)} host(s)", "medium")

    # Servers: answered TCP SYNs on a port
    ports_by_ip: dict[str, dict[int, int]] = defaultdict(dict)
    for (ip, port), clients in syn_ack.items():
        if _is_private(ip):
            ports_by_ip[ip][port] = len(clients)
    for ip, ports in ports_by_ip.items():
        d = dev_for_ip(ip)
        d.roles.add("server")
        d.services |= set(ports)
        d.note("Accepted TCP connections on port(s) " + ", ".join(str(p) for p in sorted(ports)[:8]), "medium")

    # Clients / everything else private we saw
    for ip in set(ip_seen_ts):
        if not _is_private(ip):
            continue
        d = dev_for_ip(ip)
        if ip in initiators:
            d.roles.add("client")
            d.note("Initiated TCP connections", "low")
        if ip in ip_max_ttl:
            d.os_hint = d.os_hint or _os_hint(ip_max_ttl[ip])
        for t in ip_seen_ts[ip]:
            d.touch(t)

    for m, name in hostnames_by_mac.items():
        if "mac:" + m in devices:
            devices["mac:" + m].hostname = devices["mac:" + m].hostname or name
            devices["mac:" + m].note(f"DHCP hostname '{name}'", "medium")

    out = []
    for d in devices.values():
        role = next((r for r in ROLE_PRIORITY if r in d.roles), "unknown")
        if role == "unknown" and not d.ips and not d.mac:
            continue
        out.append({
            "device_key": d.key,
            "mac": d.mac,
            "ips": sorted(d.ips),
            "ip": sorted(d.ips)[0] if d.ips else None,
            "role": role,
            "tags": sorted(d.roles - {role}),
            "hostname": d.hostname,
            "os_hint": d.os_hint,
            "services": sorted(d.services),
            "mac_randomized": bool(d.mac and int(d.mac[:2], 16) & 0x02),
            "evidence": d.evidence,
            "confidence": d.confidence,
            "first_seen_ts": d.first_seen,
            "last_seen_ts": d.last_seen,
        })
    out.sort(key=lambda x: (ROLE_PRIORITY.index(x["role"]), x["ip"] or ""))
    return out
