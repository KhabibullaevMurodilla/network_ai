"""Builds small pcap + pcapng files (TCP with FIN/RST, UDP, ICMP, VLAN tag, a
60 s timeout split) and saves what the Python parser makes of them, so the
TypeScript parser can be compared on identical bytes.
Run from backend/:  python scripts/export_pcap_reference.py"""
import json, os, struct, sys
from pathlib import Path
import dpkt

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))
from app.ingestion.pcap import parse_pcap_bytes  # noqa: E402

OUT = BACKEND.parent / "frontend" / "tests" / "local"


def ip_pkt(src, dst, proto, payload, ttl=64):
    ip = dpkt.ip.IP(src=bytes(map(int, src.split("."))), dst=bytes(map(int, dst.split("."))), p=proto, ttl=ttl)
    ip.data = payload
    ip.len = 20 + len(bytes(payload))
    return ip


def tcp(sp, dp, flags, data=b""):
    t = dpkt.tcp.TCP(sport=sp, dport=dp, flags=flags)
    t.data = data
    return t


def eth(ip, vlan=False):
    e = dpkt.ethernet.Ethernet(dst=b"\x00" * 6, src=b"\x01" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    raw = bytes(e)
    if vlan:  # insert an 802.1Q tag
        raw = raw[:12] + b"\x81\x00\x00\x64" + raw[12:]
    return raw


pk = []  # (ts, frame)
t0 = 1_700_000_000.0
A, B, C = "10.0.0.5", "10.0.0.9", "192.168.1.7"
# tcp conversation A:40000 <-> B:80 closed by two FINs
seq = [(A, B, 40000, 80, 0x02, b""), (B, A, 80, 40000, 0x12, b""), (A, B, 40000, 80, 0x10, b"x" * 100),
       (B, A, 80, 40000, 0x18, b"y" * 900), (A, B, 40000, 80, 0x11, b""), (B, A, 80, 40000, 0x11, b"")]
for i, (s, d, sp, dp, fl, data) in enumerate(seq):
    pk.append((t0 + i * 0.01, eth(ip_pkt(s, d, 6, tcp(sp, dp, fl, data), ttl=64 if s == A else 55))))
# tcp reset
pk.append((t0 + 1, eth(ip_pkt(C, B, 6, tcp(5555, 22, 0x02)))))
pk.append((t0 + 1.2, eth(ip_pkt(B, C, 6, tcp(22, 5555, 0x04)))))
# udp with vlan tag, two directions
pk.append((t0 + 2, eth(ip_pkt(A, B, 17, dpkt.udp.UDP(sport=5000, dport=53, data=b"q" * 40, ulen=48)), vlan=True)))
pk.append((t0 + 2.05, eth(ip_pkt(B, A, 17, dpkt.udp.UDP(sport=53, dport=5000, data=b"r" * 120, ulen=128)), vlan=True)))
# icmp
pk.append((t0 + 3, eth(ip_pkt(A, C, 1, dpkt.icmp.ICMP(type=8, code=0, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"z" * 32))))))
# same udp 5-tuple again after >60 s -> new flow
pk.append((t0 + 100, eth(ip_pkt(A, B, 17, dpkt.udp.UDP(sport=5000, dport=53, data=b"q" * 40, ulen=48)))))
# arp-ish non-ip frame (must be skipped)
pk.append((t0 + 4, b"\xff" * 6 + b"\x02" * 6 + b"\x08\x06" + b"\x00" * 28))
pk.sort(key=lambda x: x[0])

import io
buf = io.BytesIO()
w = dpkt.pcap.Writer(buf)
for ts, fr in pk:
    w.writepkt(fr, ts)
classic = buf.getvalue()


def blk(btype, body):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack("<II", btype, total) + body + b"\0" * pad + struct.pack("<I", total)


shb = blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
idb = blk(1, struct.pack("<HHI", 1, 0, 65535))
ng = shb + idb
for ts, fr in pk:
    us = int(round(ts * 1e6))
    ng += blk(6, struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF, len(fr), len(fr)) + fr)

(OUT / "sample.pcap").write_bytes(classic)
(OUT / "sample.pcapng").write_bytes(ng)
py = parse_pcap_bytes(classic)
py_ng = parse_pcap_bytes(ng)
cols = ["dur", "proto", "tot_pkts", "src_bytes", "dst_bytes", "rate", "load", "s_ttl", "src_ip", "dst_ip"]
(OUT / "pcap_reference.json").write_text(json.dumps({"pcap": py[cols].to_dict("records"), "pcapng": py_ng[cols].to_dict("records")}))
print("python flows:", len(py), len(py_ng))
print(py[cols].to_string())
