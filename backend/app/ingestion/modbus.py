"""Modbus/TCP protocol parsing -- the first OT/ICS protocol this platform
actually understands at the protocol level, rather than just seeing bytes
on a wire. Modbus/TCP is the obvious starting point: no authentication,
no encryption, minimal framing, and still the single most common
industrial protocol in service today (PLCs, RTUs, HMIs) -- which is
exactly why it's worth watching closely and exactly why it's a tractable
first protocol to parse correctly.

Frame format (ADU = MBAP header + PDU), per the official Modbus
Application Protocol spec:
  MBAP header (7 bytes): transaction id (2B), protocol id (2B, always 0
  for Modbus), length (2B, byte count of unit-id + PDU that follows),
  unit id (1B).
  PDU: function code (1B) + function-specific data. A function code with
  the high bit set (fc & 0x80) is an exception response, followed by a
  1-byte exception code.

This module extracts one record per Modbus message (request or
response), not per flow -- OT anomaly detection cares about individual
function-code/address-level behavior (did this PLC just get a write to
an address nothing has ever written to before?), which a flow-level
aggregate would average away.

Honest scope: decodes the common read/write function codes (1,2,3,4,5,6,
15,16) with address/quantity extraction. Less common function codes
(22 Mask Write, 23 Read/Write Multiple, vendor-specific 65-72/100-110)
are recorded with their function code and name but without
address/quantity decoding -- extending that list is mechanical, not
attempted exhaustively here. This is Modbus/TCP specifically, not
Modbus/RTU-over-serial or Modbus/ASCII (different framing, no IP capture
to parse from) and not other OT protocols (DNP3, IEC 61850/GOOSE,
OPC-UA, Profinet) -- each of those is its own protocol with its own
framing and would be its own module.
"""
from __future__ import annotations
import io
import socket
import struct
from dataclasses import dataclass

import pandas as pd

try:
    import dpkt
except ImportError as e:
    raise ImportError("Modbus parsing requires the 'dpkt' package (pip install dpkt)") from e

DEFAULT_MODBUS_PORT = 502

FUNCTION_NAMES = {
    1: "ReadCoils", 2: "ReadDiscreteInputs", 3: "ReadHoldingRegisters",
    4: "ReadInputRegisters", 5: "WriteSingleCoil", 6: "WriteSingleRegister",
    7: "ReadExceptionStatus", 8: "Diagnostics", 11: "GetCommEventCounter",
    15: "WriteMultipleCoils", 16: "WriteMultipleRegisters",
    17: "ReportSlaveId", 20: "ReadFileRecord", 21: "WriteFileRecord",
    22: "MaskWriteRegister", 23: "ReadWriteMultipleRegisters",
    24: "ReadFIFOQueue", 43: "EncapsulatedInterfaceTransport",
}

WRITE_FUNCTION_CODES = {5, 6, 15, 16, 22, 23}
READ_FUNCTION_CODES = {1, 2, 3, 4, 23}

EXCEPTION_NAMES = {
    1: "IllegalFunction", 2: "IllegalDataAddress", 3: "IllegalDataValue",
    4: "SlaveDeviceFailure", 5: "Acknowledge", 6: "SlaveDeviceBusy",
    8: "MemoryParityError", 10: "GatewayPathUnavailable",
    11: "GatewayTargetDeviceFailedToRespond",
}


@dataclass
class ModbusMessage:
    ts: float
    src_ip: str
    dst_ip: str
    unit_id: int
    function_code: int
    function_name: str
    is_request: bool  # True if addressed TO the Modbus port (a request), False if FROM it (a response)
    is_exception: bool
    exception_code: int | None
    address: int | None
    quantity: int | None


def _ip_to_str(raw: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET, raw)
    except Exception:
        return "0.0.0.0"


def _decode_pdu(pdu: bytes, is_request: bool) -> tuple[int, str, bool, int | None, int | None, int | None]:
    """Returns (function_code, function_name, is_exception, exception_code, address, quantity)."""
    if not pdu:
        return 0, "Empty", False, None, None, None
    raw_fc = pdu[0]
    is_exception = bool(raw_fc & 0x80)
    fc = raw_fc & 0x7F
    name = FUNCTION_NAMES.get(fc, f"Unknown({fc})")

    if is_exception:
        exc_code = pdu[1] if len(pdu) > 1 else None
        return fc, name, True, exc_code, None, None

    address = None
    quantity = None
    try:
        if is_request and fc in (1, 2, 3, 4) and len(pdu) >= 5:
            # Read request: [fc][addr_hi addr_lo][qty_hi qty_lo]
            address, quantity = struct.unpack(">HH", pdu[1:5])
        elif is_request and fc in (5, 6) and len(pdu) >= 5:
            # Write single coil/register: [fc][addr_hi addr_lo][value_hi value_lo]
            address = struct.unpack(">H", pdu[1:3])[0]
            quantity = 1
        elif is_request and fc in (15, 16) and len(pdu) >= 5:
            # Write multiple: [fc][addr_hi addr_lo][qty_hi qty_lo][byte_count]...
            address, quantity = struct.unpack(">HH", pdu[1:5])
        elif not is_request and fc in (1, 2, 3, 4) and len(pdu) >= 2:
            # Read response carries only a byte count + data, no address --
            # the address lives on the matching request, not this message.
            pass
        elif not is_request and fc in (5, 6) and len(pdu) >= 5:
            # Write single response echoes back address + value.
            address = struct.unpack(">H", pdu[1:3])[0]
            quantity = 1
        elif not is_request and fc in (15, 16) and len(pdu) >= 5:
            # Write multiple response echoes back address + quantity.
            address, quantity = struct.unpack(">HH", pdu[1:5])
    except struct.error:
        pass  # truncated/malformed PDU -- keep the function code, skip address/quantity

    return fc, name, False, None, address, quantity


def parse_modbus_pcap_bytes(data: bytes, port: int = DEFAULT_MODBUS_PORT) -> pd.DataFrame:
    """Extracts Modbus/TCP messages from pcap bytes. Non-Modbus traffic in
    the same capture is silently skipped (this is meant to run alongside
    the generic flow parser in ingestion/pcap.py against the same
    capture, not replace it)."""
    try:
        fh = io.BytesIO(data)
        magic = data[:4] if len(data) >= 4 else b""
        classic = magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        reader = dpkt.pcap.Reader(fh) if classic else dpkt.pcapng.Reader(fh)
    except Exception as e:
        raise ValueError(f"Not a recognizable pcap/pcapng file: {e}") from e

    # Reassembles each TCP segment independently rather than tracking
    # stream reassembly/sequence numbers -- fine for the common case where
    # one TCP segment carries exactly one Modbus ADU (true for the
    # overwhelming majority of real Modbus/TCP traffic, since messages are
    # small and typically sent as individual writes), but a message split
    # across two TCP segments would be missed. Stated here rather than
    # silently assumed.
    messages: list[ModbusMessage] = []
    # Manual iteration, not `for ts, buf in reader:` -- same real finding
    # as ingestion/pcap.py's parse_pcap_bytes: dpkt can raise mid-stream
    # (dpkt.NeedData, dpkt.UnpackError) on truncated/corrupted record
    # framing, which happens on the iterator's next() itself and so
    # bypasses a for-loop body's try/except entirely. Caught here instead
    # of propagating to an unhandled 500; stops reading and keeps whatever
    # was already parsed, same as a capture that simply ends mid-record.
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
            if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
        except Exception:
            continue

        if tcp.sport != port and tcp.dport != port:
            continue
        payload = bytes(tcp.data)
        if len(payload) < 8:  # shorter than the smallest possible MBAP + function code
            continue

        try:
            transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", payload[:7])
        except struct.error:
            continue
        if protocol_id != 0:
            continue  # not actually Modbus (protocol id is always 0 for Modbus/TCP)

        pdu = payload[7:7 + max(length - 1, 0)]
        is_request = tcp.dport == port  # addressed TO the Modbus port = a request

        fc, name, is_exc, exc_code, address, quantity = _decode_pdu(pdu, is_request)
        if fc == 0:
            continue

        messages.append(ModbusMessage(
            ts=ts, src_ip=_ip_to_str(ip.src), dst_ip=_ip_to_str(ip.dst),
            unit_id=unit_id, function_code=fc, function_name=name,
            is_request=is_request, is_exception=is_exc, exception_code=exc_code,
            address=address, quantity=quantity,
        ))

    if not messages:
        return pd.DataFrame(columns=[
            "ts", "src_ip", "dst_ip", "unit_id", "function_code", "function_name",
            "is_request", "is_exception", "exception_code", "address", "quantity",
        ])
    return pd.DataFrame([m.__dict__ for m in messages])
