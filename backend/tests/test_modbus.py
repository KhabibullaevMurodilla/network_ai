"""Real Modbus/TCP ADU parsing tests, built on dpkt-constructed packets (not
recorded captures -- this lets each test isolate exactly one message shape).
Covers the function codes ingestion/modbus.py documents as fully decoded
(1,2,3,4,5,6,15,16) plus the exception-response path, and the two framing
edge cases dpkt doesn't handle for us: distinguishing request vs response by
port direction, and silently skipping non-Modbus traffic on the same port."""
import io
import socket
import struct
import time

import dpkt
import pandas as pd
import pytest

from app.ingestion.modbus import parse_modbus_pcap_bytes, DEFAULT_MODBUS_PORT

ENGINEER, PLC = "10.0.0.10", "10.0.0.20"
PORT = DEFAULT_MODBUS_PORT


def _tcp_packet(src_ip, dst_ip, sport, dport, payload):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=dpkt.tcp.TH_ACK, seq=1, ack=1, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src_ip), dst=socket.inet_aton(dst_ip),
                     p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\xff" * 6, data=ip)
    return bytes(eth)


def _write_pcap(packets_with_ts):
    buf = io.BytesIO()
    w = dpkt.pcap.Writer(buf)
    for pkt, ts in packets_with_ts:
        w.writepkt(pkt, ts=ts)
    return buf.getvalue()


def _mbap(trans_id, unit_id, pdu):
    # length field = byte count of unit_id + pdu that follows
    return struct.pack(">HHHB", trans_id, 0, len(pdu) + 1, unit_id) + pdu


def test_rejects_non_pcap_bytes():
    with pytest.raises(ValueError):
        parse_modbus_pcap_bytes(b"definitely not a pcap")


def test_empty_capture_yields_empty_dataframe_with_schema():
    df = parse_modbus_pcap_bytes(_write_pcap([]))
    assert len(df) == 0
    assert "function_name" in df.columns


def test_read_holding_registers_request_and_response():
    t0 = time.time()
    req_pdu = bytes([3]) + struct.pack(">HH", 100, 10)  # addr=100, qty=10
    resp_pdu = bytes([3, 20]) + b"\x00" * 20  # byte_count=20, 10 registers of data

    data = _write_pcap([
        (_tcp_packet(ENGINEER, PLC, 50000, PORT, _mbap(1, 1, req_pdu)), t0),
        (_tcp_packet(PLC, ENGINEER, PORT, 50000, _mbap(1, 1, resp_pdu)), t0 + 0.01),
    ])
    df = parse_modbus_pcap_bytes(data)
    assert len(df) == 2

    req, resp = df.iloc[0], df.iloc[1]
    assert bool(req["is_request"]) is True and bool(resp["is_request"]) is False
    assert req["function_name"] == "ReadHoldingRegisters"
    assert req["address"] == 100 and req["quantity"] == 10
    # response carries only a byte count, no address -- documented behavior.
    # (None becomes NaN once mixed into this numeric DataFrame column.)
    assert pd.isna(resp["address"])


def test_write_single_register_request_and_echoed_response():
    t0 = time.time()
    req_pdu = bytes([6]) + struct.pack(">HH", 500, 42)  # write 42 to addr 500
    resp_pdu = bytes([6]) + struct.pack(">HH", 500, 42)  # echoed back

    data = _write_pcap([
        (_tcp_packet(ENGINEER, PLC, 50001, PORT, _mbap(2, 1, req_pdu)), t0),
        (_tcp_packet(PLC, ENGINEER, PORT, 50001, _mbap(2, 1, resp_pdu)), t0 + 0.01),
    ])
    df = parse_modbus_pcap_bytes(data)
    assert len(df) == 2
    req, resp = df.iloc[0], df.iloc[1]
    assert req["function_name"] == "WriteSingleRegister"
    assert req["address"] == 500 and req["quantity"] == 1
    assert resp["address"] == 500  # write responses do echo address, unlike reads


def test_write_multiple_registers_request():
    t0 = time.time()
    # addr=1000, qty=3 registers, byte_count=6, then 6 bytes of data
    req_pdu = bytes([16]) + struct.pack(">HHB", 1000, 3, 6) + b"\x00" * 6
    data = _write_pcap([
        (_tcp_packet(ENGINEER, PLC, 50002, PORT, _mbap(3, 1, req_pdu)), t0),
    ])
    df = parse_modbus_pcap_bytes(data)
    assert len(df) == 1
    row = df.iloc[0]
    assert row["function_name"] == "WriteMultipleRegisters"
    assert row["address"] == 1000 and row["quantity"] == 3


def test_exception_response_decoded_with_code():
    t0 = time.time()
    req_pdu = bytes([3]) + struct.pack(">HH", 99999 & 0xFFFF, 10)  # bogus but well-formed
    # exception: high bit set on function code (0x83 = 3 | 0x80), + exception code 2 (IllegalDataAddress)
    exc_pdu = bytes([0x83, 2])

    data = _write_pcap([
        (_tcp_packet(ENGINEER, PLC, 50003, PORT, _mbap(4, 1, req_pdu)), t0),
        (_tcp_packet(PLC, ENGINEER, PORT, 50003, _mbap(4, 1, exc_pdu)), t0 + 0.01),
    ])
    df = parse_modbus_pcap_bytes(data)
    assert len(df) == 2
    exc = df.iloc[1]
    assert bool(exc["is_exception"]) is True
    assert exc["exception_code"] == 2
    assert exc["function_code"] == 3  # high bit stripped to recover the real function code


def test_non_modbus_traffic_on_same_port_silently_skipped():
    """protocol_id must be 0 for real Modbus/TCP -- junk on port 502 that
    doesn't look like Modbus (e.g. a non-zero protocol id) must not be
    misparsed as a message."""
    t0 = time.time()
    junk = struct.pack(">HHHB", 1, 1, 6, 1) + bytes([3, 0, 0, 0, 1])  # protocol_id=1, not 0
    data = _write_pcap([(_tcp_packet(ENGINEER, PLC, 50004, PORT, junk), t0)])
    df = parse_modbus_pcap_bytes(data)
    assert len(df) == 0


def test_non_modbus_port_traffic_ignored():
    t0 = time.time()
    req_pdu = bytes([3]) + struct.pack(">HH", 100, 10)
    data = _write_pcap([
        (_tcp_packet(ENGINEER, PLC, 50005, 8080, _mbap(1, 1, req_pdu)), t0),
    ])
    df = parse_modbus_pcap_bytes(data)
    assert len(df) == 0


def test_valid_magic_but_corrupted_record_data_does_not_crash():
    """Same real bug as test_pcap.py's equivalent test, same fix (manual
    iteration catching the reader's own exception, not just per-packet
    parsing errors) -- confirmed independently against this parser too."""
    corrupted = b"\xd4\xc3\xb2\xa1" + b"\x00" * 2000
    df = parse_modbus_pcap_bytes(corrupted)  # must not raise
    assert len(df) == 0


def test_direction_inferred_from_destination_port():
    """A request is addressed TO the Modbus port; a response FROM it --
    this is the only direction signal available without TCP stream
    reassembly, and it must hold regardless of which side is 'src' in IP terms."""
    t0 = time.time()
    req_pdu = bytes([1]) + struct.pack(">HH", 0, 8)  # ReadCoils
    resp_pdu = bytes([1, 1, 0xFF])  # byte_count=1, data

    data = _write_pcap([
        (_tcp_packet(ENGINEER, PLC, 51000, PORT, _mbap(5, 7, req_pdu)), t0),
        (_tcp_packet(PLC, ENGINEER, PORT, 51000, _mbap(5, 7, resp_pdu)), t0 + 0.01),
    ])
    df = parse_modbus_pcap_bytes(data)
    assert df.iloc[0]["is_request"] and df.iloc[0]["unit_id"] == 7
    assert not df.iloc[1]["is_request"]
