"""External connection summary from a packet capture (v6.7).

For every TCP/UDP packet between a PRIVATE address (your device) and a PUBLIC
address, aggregate per (remote IP, remote port, protocol): distinct 5-tuple
"flows", packets, bytes out/in (IP length), and the hostnames we can learn
passively:
  * DNS responses (UDP/53, A records): the queried name -> the answer IPs
  * TLS ClientHello SNI (TCP, first handshake record): the requested hostname

What it cannot know: DNS over HTTPS/TLS and QUIC/HTTP3 hide names, so those
connections show an IP only; a ClientHello split across packets is skipped;
IPv6 is not read. Hostnames are what the capture revealed, not a verified
reverse lookup, and a CDN IP can serve many names (all seen names are kept).
This is browsing-destination data and is stored per tenant, listed in the
privacy export/erase, and purged by the retention job.
"""
from __future__ import annotations
import io
import ipaddress
import re
import socket
import struct
from collections import defaultdict

import dpkt

from .pcap import _looks_like_classic_pcap, _ip_to_str

_NAME_RE = re.compile(r"^[a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9_])?$")
MAX_NAMES = 8


def _clean_name(n: str | None) -> str | None:
    if not n:
        return None
    n = n.strip().strip(".").lower()
    return n if _NAME_RE.match(n) else None


def parse_sni(payload: bytes) -> str | None:
    """Server name from a TLS ClientHello, or None. Never raises."""
    try:
        if len(payload) < 48 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        i = 5 + 4 + 2 + 32                       # record hdr, handshake hdr, version, random
        i += 1 + payload[i]                      # session id
        i += 2 + struct.unpack("!H", payload[i:i + 2])[0]   # cipher suites
        i += 1 + payload[i]                      # compression methods
        end = i + 2 + struct.unpack("!H", payload[i:i + 2])[0]
        i += 2
        while i + 4 <= min(end, len(payload)):
            etype, elen = struct.unpack("!HH", payload[i:i + 4])
            if etype == 0:                       # server_name
                # list_len(2) name_type(1) name_len(2) name
                nlen = struct.unpack("!H", payload[i + 7:i + 9])[0]
                return _clean_name(payload[i + 9:i + 9 + nlen].decode("ascii", "ignore"))
            i += 4 + elen
    except Exception:
        return None
    return None


def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private and not (a.is_multicast or a.is_unspecified or a.is_loopback)
    except ValueError:
        return False


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global and not a.is_multicast
    except ValueError:
        return False


def extract_endpoints(data: bytes) -> list[dict]:
    try:
        fh = io.BytesIO(data)
        reader = dpkt.pcap.Reader(fh) if _looks_like_classic_pcap(data) else dpkt.pcapng.Reader(fh)
    except Exception:
        return []

    agg: dict[tuple, dict] = {}
    names: dict[str, set[str]] = defaultdict(set)
    flowsets: dict[tuple, set] = defaultdict(set)

    it = iter(reader)
    while True:
        try:
            ts, buf = next(it)
        except Exception:
            break
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            l4 = ip.data
            if isinstance(l4, dpkt.tcp.TCP):
                proto = "tcp"
            elif isinstance(l4, dpkt.udp.UDP):
                proto = "udp"
            else:
                continue
            src, dst = _ip_to_str(ip.src), _ip_to_str(ip.dst)
            if _is_private(src) and _is_public(dst):
                out, remote, rport, lip, lport = True, dst, l4.dport, src, l4.sport
            elif _is_public(src) and _is_private(dst):
                out, remote, rport, lip, lport = False, src, l4.sport, dst, l4.dport
            else:
                continue

            key = (remote, rport, proto)
            e = agg.get(key)
            if e is None:
                e = agg[key] = {"remote_ip": remote, "remote_port": rport, "proto": proto, "packets": 0,
                                "bytes_out": 0, "bytes_in": 0, "first_ts": ts, "last_ts": ts}
            e["packets"] += 1
            e["bytes_out" if out else "bytes_in"] += ip.len
            e["first_ts"], e["last_ts"] = min(e["first_ts"], ts), max(e["last_ts"], ts)
            flowsets[key].add((lip, lport))

            if proto == "udp" and not out and rport == 53 and l4.data:
                try:
                    d = dpkt.dns.DNS(l4.data)
                    if d.qr == dpkt.dns.DNS_R and d.qd:
                        qn = _clean_name(d.qd[0].name)
                        for rr in d.an:
                            if rr.type == dpkt.dns.DNS_A and qn:
                                names[socket.inet_ntoa(rr.ip)].add(qn)
                except Exception:
                    pass
            elif proto == "tcp" and out and l4.data:
                sni = parse_sni(bytes(l4.data))
                if sni:
                    names[remote].add(sni)
        except Exception:
            continue

    out_rows = []
    for key, e in agg.items():
        e["flows"] = len(flowsets[key])
        e["hostnames"] = sorted(names.get(e["remote_ip"], set()))[:MAX_NAMES]
        out_rows.append(e)
    out_rows.sort(key=lambda r: r["bytes_out"] + r["bytes_in"], reverse=True)
    return out_rows[:2000]
