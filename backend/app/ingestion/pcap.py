"""Real packet-capture ingestion: turns an actual .pcap/.pcapng file into
the same flow-record schema the engine scores (see ml/engine.py FEATURES
and routers/ingest.py's FlowRecord) -- the same shape the synthetic
generator produces, but computed from real packets this time.

Honest scope: this is flow aggregation from a *capture file* a customer
hands over (a SPAN-port dump, a tcpdump export, a pilot partner's pcap) --
not a live packet-tap agent running at their network edge. A live capture
agent (sniffing a real interface in real time and streaming flows out)
is a different, larger piece of work (an on-prem collector process,
privileged packet access, its own deployment story) that this module does
not attempt. What it does solve is the actual bottleneck for proving the
detector against real traffic shapes rather than synthetic ones: point it
at a real pcap and get real flow records out, with the exact same
features the ECOD/IForest/LOF/HalfSpaceTrees ensemble was built around.

Flow definition (standard bidirectional-flow aggregation, same concept
Argus/5G-NIDD-style datasets use): packets are grouped by the unordered
5-tuple {src_ip, dst_ip, src_port, dst_port, proto} -- so A->B and B->A
packets land in the same flow -- with the side that sent the first packet
of the flow treated as "src" for src_bytes/dst_bytes/s_ttl purposes. A
flow closes on FLOW_TIMEOUT_SECONDS of inactivity (a new packet on the
same 5-tuple after that starts a fresh flow) or immediately on a TCP
FIN/RST, whichever comes first -- both are standard NetFlow/Argus
flow-termination rules, not something invented for this module.
"""
from __future__ import annotations
import io
import socket
from dataclasses import dataclass, field

import pandas as pd

try:
    import dpkt
except ImportError as e:  # pragma: no cover - surfaced to the caller as a clear error
    raise ImportError(
        "pcap ingestion requires the 'dpkt' package (pip install dpkt)"
    ) from e

FLOW_TIMEOUT_SECONDS = 60.0  # standard Argus/NetFlow-style inactivity timeout

_PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}


def _ip_to_str(raw: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET, raw) if len(raw) == 4 else socket.inet_ntop(socket.AF_INET6, raw)
    except Exception:
        return "0.0.0.0"


@dataclass
class _FlowAccum:
    first_ts: float
    last_ts: float = 0.0
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    proto: str = "OTHER"
    tot_pkts: int = 0
    src_bytes: int = 0
    dst_bytes: int = 0
    s_ttl: int = 64
    fin_sides: set = field(default_factory=set)
    rst_seen: bool = False

    def add(self, ts: float, src_ip: str, length: int, ttl: int, is_fin: bool, is_rst: bool, src_port: int = 0):
        self.last_ts = ts
        self.tot_pkts += 1
        # Direction is decided by (IP, port), not IP alone: on loopback or
        # host-to-itself traffic both ends share one IP, and an IP-only test
        # counted every byte as "src" and never saw the second FIN.
        forward = (src_ip, src_port) == (self.src_ip, self.src_port)
        if forward:
            self.src_bytes += length
        else:
            self.dst_bytes += length
        if is_fin:
            self.fin_sides.add(forward)
        if is_rst:
            self.rst_seen = True

    def should_close(self) -> bool:
        # RST tears down a TCP connection unilaterally and immediately --
        # one side resetting is a complete close, unlike FIN. A proper FIN
        # close is a two-way handshake (each side FINs its own direction),
        # so closing on the first FIN alone would truncate a flow mid-way
        # through a normal teardown and fabricate a second, spurious
        # near-empty flow out of the other side's FIN/ACK -- a real bug
        # caught by testing against constructed packets with distinct
        # src/dst IPs (loopback capture can't surface it: both "sides" of a
        # loopback flow share one IP, so direction-dependent bugs like this
        # are invisible there).
        return self.rst_seen or len(self.fin_sides) >= 2

    def to_record(self) -> dict:
        dur = max(self.last_ts - self.first_ts, 0.0)
        tot_bytes = self.src_bytes + self.dst_bytes
        # Rate: packets/sec over the flow's own duration -- a single-packet
        # flow has no meaningful rate, so it's reported as the packet count
        # itself (consistent with generate_telemetry.py's scan-flow shapes,
        # which also show near-instant single/few-packet flows as a rate
        # roughly proportional to packet count, not an undefined division).
        rate = self.tot_pkts / dur if dur > 0 else float(self.tot_pkts)
        # Load: throughput in bits/sec, the Argus "Load" definition.
        load = (tot_bytes * 8) / dur if dur > 0 else float(tot_bytes * 8)
        return {
            "dur": round(dur, 6),
            "proto": self.proto,
            "tot_pkts": self.tot_pkts,
            "src_bytes": float(self.src_bytes),
            "dst_bytes": float(self.dst_bytes),
            "rate": round(rate, 4),
            "load": round(load, 4),
            "s_ttl": self.s_ttl,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "source_label": "pcap_import",
        }


def _flow_key(src_ip, dst_ip, src_port, dst_port, proto):
    """Unordered key so both directions of one conversation map to the same
    flow, regardless of which side's packet arrived first in this call."""
    a, b = (src_ip, src_port), (dst_ip, dst_port)
    if a <= b:
        return (a, b, proto)
    return (b, a, proto)


def parse_pcap_bytes(data: bytes) -> pd.DataFrame:
    """Parse raw pcap/pcapng bytes into a flow-record DataFrame matching
    routers/ingest.py's FlowRecord schema. Raises ValueError on a file
    dpkt can't recognize as pcap/pcapng -- callers should surface that as
    a 400, not swallow it, since a silently-empty result on a bad file is
    worse than a clear rejection."""
    try:
        fh = io.BytesIO(data)
        reader = dpkt.pcap.Reader(fh) if _looks_like_classic_pcap(data) else dpkt.pcapng.Reader(fh)
    except Exception as e:
        raise ValueError(f"Not a recognizable pcap/pcapng file: {e}") from e

    active: dict[tuple, _FlowAccum] = {}
    completed: list[dict] = []

    def _close(key):
        acc = active.pop(key, None)
        if acc is not None and acc.tot_pkts > 0:
            completed.append(acc.to_record())

    # Manual iteration, not `for ts, buf in reader:` -- a real finding from
    # adversarial testing: dpkt's reader can raise mid-stream (dpkt.NeedData,
    # dpkt.UnpackError) when the record-length framing itself is truncated
    # or corrupted partway through the file, not just on a per-packet
    # malformed frame (which the inner try/except below already handles).
    # That exception happens on the *iterator's* next(), outside a for-loop
    # body's try/except, so it previously propagated all the way to an
    # unhandled 500. Caught here and treated the same way a pcap that
    # simply ends mid-record would be: stop reading, keep what was already
    # parsed, rather than aborting the whole request.
    reader_iter = iter(reader)
    while True:
        try:
            ts, buf = next(reader_iter)
        except StopIteration:
            break
        except Exception:
            break

        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue  # non-IP (ARP, etc.) carries no flow-feature meaning here
        except Exception:
            continue  # malformed frame -- skip, don't abort the whole capture

        src_ip = _ip_to_str(ip.src)
        dst_ip = _ip_to_str(ip.dst)
        ttl = ip.ttl
        length = len(ip)
        proto_num = ip.p
        proto = _PROTO_NAMES.get(proto_num, "OTHER")

        is_fin = is_rst = False
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            src_port, dst_port = tcp.sport, tcp.dport
            is_fin = bool(tcp.flags & dpkt.tcp.TH_FIN)
            is_rst = bool(tcp.flags & dpkt.tcp.TH_RST)
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            src_port, dst_port = udp.sport, udp.dport
        else:
            src_port = dst_port = 0

        key = _flow_key(src_ip, dst_ip, src_port, dst_port, proto)

        acc = active.get(key)
        if acc is not None and (ts - acc.last_ts) > FLOW_TIMEOUT_SECONDS:
            _close(key)
            acc = None
        if acc is None:
            acc = _FlowAccum(
                first_ts=ts, last_ts=ts, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port, proto=proto, s_ttl=ttl,
            )
            active[key] = acc

        acc.add(ts, src_ip, length, ttl, is_fin, is_rst, src_port)
        if acc.should_close():
            _close(key)

    for key in list(active.keys()):
        _close(key)

    if not completed:
        return pd.DataFrame(columns=[
            "dur", "proto", "tot_pkts", "src_bytes", "dst_bytes",
            "rate", "load", "s_ttl", "src_ip", "dst_ip", "source_label",
        ])
    return pd.DataFrame(completed)


def _looks_like_classic_pcap(data: bytes) -> bool:
    """Classic pcap vs. pcapng are distinguished by magic number -- dpkt
    needs to be told which reader to use, it doesn't sniff this itself."""
    if len(data) < 4:
        return True
    magic = data[:4]
    return magic in (
        b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
    )
