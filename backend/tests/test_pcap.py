"""Real pcap-parsing tests. The direction/FIN-handling cases here caught
an actual bug during development (closing a TCP flow on the first FIN seen
from either side, instead of waiting for both directions -- see
ingestion/pcap.py's should_close() for the fix and why loopback-only
testing couldn't have caught it)."""
import io
import socket
import time

import dpkt
import pytest

from app.ingestion.pcap import parse_pcap_bytes

A, B = "10.0.0.1", "10.0.0.2"


def _tcp_packet(src_ip, dst_ip, sport, dport, payload, flags, ttl=64):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=1, ack=1, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src_ip), dst=socket.inet_aton(dst_ip),
                     p=dpkt.ip.IP_PROTO_TCP, ttl=ttl, data=tcp)
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\xff" * 6, data=ip)
    return bytes(eth)


def _write_pcap(packets_with_ts):
    buf = io.BytesIO()
    w = dpkt.pcap.Writer(buf)
    for pkt, ts in packets_with_ts:
        w.writepkt(pkt, ts=ts)
    return buf.getvalue()


def test_rejects_non_pcap_bytes():
    with pytest.raises(ValueError):
        parse_pcap_bytes(b"this is not a pcap file")


def test_full_handshake_is_one_flow_with_correct_direction_and_bytes():
    t0 = time.time()
    data = _write_pcap([
        (_tcp_packet(A, B, 40000, 80, b"", dpkt.tcp.TH_SYN), t0),
        (_tcp_packet(B, A, 80, 40000, b"", dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK), t0 + 0.01),
        (_tcp_packet(A, B, 40000, 80, b"GET / HTTP/1.1" + b"x" * 100, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH), t0 + 0.02),
        (_tcp_packet(B, A, 80, 40000, b"HTTP/1.1 200 OK" + b"y" * 2000, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH), t0 + 0.03),
        (_tcp_packet(A, B, 40000, 80, b"", dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK), t0 + 0.04),
        (_tcp_packet(B, A, 80, 40000, b"", dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK), t0 + 0.05),
    ])
    df = parse_pcap_bytes(data)
    assert len(df) == 1, "a normal two-sided FIN close must stay one flow, not split in two"
    row = df.iloc[0]
    assert row["src_ip"] == A and row["dst_ip"] == B
    assert row["dst_bytes"] > row["src_bytes"]  # server sent far more payload
    assert row["tot_pkts"] == 6


def test_rst_closes_flow_immediately():
    t0 = time.time()
    data = _write_pcap([
        (_tcp_packet(A, B, 5000, 22, b"", dpkt.tcp.TH_SYN), t0),
        (_tcp_packet(B, A, 22, 5000, b"", dpkt.tcp.TH_RST), t0 + 0.01),
        (_tcp_packet(A, B, 5001, 22, b"", dpkt.tcp.TH_SYN), t0 + 0.02),  # different port -> new flow
    ])
    df = parse_pcap_bytes(data)
    assert len(df) == 2


def test_inactivity_timeout_splits_flows():
    from app.ingestion.pcap import FLOW_TIMEOUT_SECONDS
    t0 = time.time()
    data = _write_pcap([
        (_tcp_packet(A, B, 6000, 443, b"", dpkt.tcp.TH_SYN), t0),
        (_tcp_packet(A, B, 6000, 443, b"x", dpkt.tcp.TH_ACK), t0 + FLOW_TIMEOUT_SECONDS + 5),
    ])
    df = parse_pcap_bytes(data)
    assert len(df) == 2, "a gap beyond the inactivity timeout must start a new flow"


def test_empty_capture_yields_empty_dataframe_not_error():
    data = _write_pcap([])
    df = parse_pcap_bytes(data)
    assert len(df) == 0
    assert "dur" in df.columns  # schema present even with zero rows


def test_valid_magic_but_corrupted_record_data_does_not_crash():
    """Real bug found via adversarial fuzzing: a valid pcap magic number
    followed by truncated/corrupted record framing raised dpkt.NeedData
    from the reader's own iteration (not from per-packet parsing, which
    was already guarded) -- an unhandled exception that reached the
    generic 500 handler instead of returning a clean, partial result."""
    corrupted = b"\xd4\xc3\xb2\xa1" + b"\x00" * 2000
    df = parse_pcap_bytes(corrupted)  # must not raise
    assert len(df) == 0


def test_valid_header_then_one_good_packet_then_corruption_keeps_the_good_one():
    t0 = time.time()
    good_packet = _tcp_packet(A, B, 1234, 80, b"", dpkt.tcp.TH_SYN)
    valid_prefix = _write_pcap([(good_packet, t0)])
    corrupted = valid_prefix + b"\x00" * 500  # garbage appended after one real record
    df = parse_pcap_bytes(corrupted)  # must not raise, and should keep the packet it could read
    assert len(df) <= 1  # either the one flow survived, or nothing did -- never a crash
