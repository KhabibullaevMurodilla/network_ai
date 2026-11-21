"""Builds synthetic Modbus/TCP captures (pcap + pcapng) covering normal traffic,
a new function code, a write outside the learned range, an exception flood, a
unit-id scan, malformed frames and a non-502 port, then records what the Python
parser (ingestion/modbus.py) and rule engine (ml/ot_rules.py) make of them, so
the TypeScript port can be compared on identical bytes.
Run from backend/:  python scripts/export_modbus_reference.py"""
import io
import json
import math
import struct
import sys
from pathlib import Path

import pandas as pd

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))
from app.ingestion.modbus import parse_modbus_pcap_bytes  # noqa: E402
from app.ml.ot_rules import OTRuleEngine  # noqa: E402

OUT = BACKEND.parent / "frontend" / "tests" / "local" / "fixtures"
OUT.mkdir(parents=True, exist_ok=True)

MASTER, PLC, PLC2 = "10.1.0.5", "10.1.0.20", "10.1.0.21"
T0 = 1_700_000_000.0


def ip4(s):
    return bytes(map(int, s.split(".")))


def tcp_seg(sp, dp, payload, off_words=5):
    opts = b"\x01" * ((off_words - 5) * 4)
    return struct.pack(">HHIIBBHHH", sp, dp, 1, 1, off_words << 4, 0x18, 8192, 0, 0) + opts + payload


def ip_pkt(src, dst, proto, l4, total=None, frag=0, ihl_words=5):
    opts = b"\x01" * ((ihl_words - 5) * 4)
    hl = ihl_words * 4
    tl = hl + len(l4) if total is None else total
    return struct.pack(">BBHHHBBH4s4s", (4 << 4) | ihl_words, 0, tl, 1, frag, 64, proto, 0, ip4(src), ip4(dst)) + opts + l4


def eth(ip, vlan=False, etype=0x0800):
    if vlan:
        return b"\x00" * 6 + b"\x01" * 6 + b"\x81\x00\x00\x64" + struct.pack(">H", etype) + ip
    return b"\x00" * 6 + b"\x01" * 6 + struct.pack(">H", etype) + ip


def adu(tid, unit, pdu, proto=0, length=None):
    ln = len(pdu) + 1 if length is None else length
    return struct.pack(">HHHB", tid, proto, ln, unit) + pdu


def frame(src, dst, sp, dp, payload, **kw):
    vlan = kw.pop("vlan", False)
    off_words = kw.pop("off_words", 5)
    return eth(ip_pkt(src, dst, 6, tcp_seg(sp, dp, payload, off_words), **kw), vlan=vlan)


class Cap:
    def __init__(self, port=502):
        self.pk, self.t, self.tid, self.port = [], T0, 0, port

    def at(self, t):
        self.t = T0 + t
        return self

    def raw(self, fr, dt=0.1):
        self.t += dt
        self.pk.append((self.t, fr))

    def req(self, pdu, unit=1, src=MASTER, dst=PLC, dt=0.1, **kw):
        self.tid += 1
        self.raw(frame(src, dst, 40001, self.port, adu(self.tid, unit, pdu), **kw), dt)

    def resp(self, pdu, unit=1, src=PLC, dst=MASTER, dt=0.05, **kw):
        self.raw(frame(src, dst, self.port, 40001, adu(self.tid, unit, pdu), **kw), dt)


def rd(fc, addr, qty): return struct.pack(">BHH", fc, addr, qty)
def wr1(fc, addr, val): return struct.pack(">BHH", fc, addr, val)
def wrn(fc, addr, qty): return struct.pack(">BHHB", fc, addr, qty, qty * 2) + b"\x00" * (qty * 2)
def rd_resp(fc, n): return struct.pack(">BB", fc, n * 2) + b"\x00" * (n * 2)
def exc(fc, code): return bytes([fc | 0x80, code])


def baseline(c, n=6):
    for _ in range(n):
        c.req(rd(3, 100, 10)); c.resp(rd_resp(3, 10))
        c.req(wr1(6, 200, 7)); c.resp(wr1(6, 200, 7))


def build():
    caps = {}

    c = Cap()
    # rare function codes first, while the pair is still inside its baseline window (no flags expected)
    c.req(rd(1, 0, 8)); c.resp(rd_resp(1, 1))
    c.req(rd(2, 0, 8)); c.resp(rd_resp(2, 1))
    c.req(rd(4, 5, 2)); c.resp(rd_resp(4, 2))
    c.req(wr1(5, 3, 0xFF00)); c.resp(wr1(5, 3, 0xFF00))
    c.req(wrn(15, 10, 8)); c.resp(struct.pack(">BHH", 15, 10, 8))
    c.req(wrn(16, 300, 4)); c.resp(struct.pack(">BHH", 16, 300, 4))
    baseline(c, 8)
    caps["normal_rw"] = (c, 502)

    c = Cap(); baseline(c, 6)
    c.req(rd(4, 100, 10)); c.resp(rd_resp(4, 10))                 # new fc (read, no write address)
    c.req(rd(43, 0, 0)[:2] + b"\x0e\x01\x00"); c.resp(b"\x2b\x0e\x01")  # fc 43
    c.req(b"\x63" + b"\x00" * 4); c.resp(exc(0x63, 1))            # unknown fc 99
    caps["new_function_code"] = (c, 502)

    c = Cap(); baseline(c, 6)
    c.req(wr1(6, 9001, 1)); c.resp(wr1(6, 9001, 1))               # write outside learned range
    c.req(wr1(6, 200, 1)); c.resp(wr1(6, 200, 1))                 # known address, fine
    c.req(wrn(16, 300, 4)); c.resp(struct.pack(">BHH", 16, 300, 4))
    c.req(wr1(5, 200, 0)); c.resp(wr1(5, 200, 0))                 # fc 5 new fc, address already seen
    c.req(b"\x16" + struct.pack(">HHH", 5, 0xFFFF, 0))            # fc 22: write fc, no address decoded
    c.req(b"\x17" + b"\x00" * 9)                                  # fc 23: write+read, no address decoded
    caps["write_outside_range"] = (c, 502)

    c = Cap(); baseline(c, 6)
    c.at(10)
    for i in range(7):
        c.req(rd(3, 5000 + i, 1), dt=0.2); c.resp(exc(3, 2), dt=0.1)   # burst of exceptions
    c.at(100)
    for i in range(4):
        c.req(rd(3, 6000 + i, 1), dt=1.0); c.resp(exc(3, 2 if i % 2 else 11), dt=1.0)  # window expired, slower
    c.resp(b"\x83", dt=1.0)                                       # exception, no code
    c.resp(b"\x80\x01", dt=1.0)                                   # fc 0 | 0x80 -> skipped
    caps["exception_flood"] = (c, 502)

    c = Cap()
    c.at(1)
    for u in range(1, 9):
        c.req(rd(3, 0, 1), unit=u, dt=1.0); c.resp(exc(3, 11), unit=u, dt=0.1)
    c.at(200)
    for u in (1, 2):
        c.req(rd(3, 0, 1), unit=u, dt=1.0)
    for u in (3, 4, 5):                                           # fresh window: stays under threshold until 5th
        c.req(rd(3, 0, 1), unit=u, dt=1.0)
    c.req(rd(3, 0, 1), unit=6, dt=1.0)
    c.req(rd(3, 0, 1), unit=1, src="10.1.0.99", dst=PLC2, dt=1.0)  # other pair, separate tracker
    caps["unit_id_scan"] = (c, 502)

    c = Cap()
    c.req(rd(3, 100, 10)); c.resp(rd_resp(3, 10))                 # sane
    c.raw(frame(MASTER, PLC, 40001, 502, b"\x00\x01\x00\x00\x00\x02\x01"))   # 7 byte payload (<8)
    c.raw(frame(MASTER, PLC, 40001, 502, b""))                    # empty payload
    c.raw(frame(MASTER, PLC, 40001, 502, adu(9, 1, rd(3, 1, 1), proto=1)))   # protocol id != 0
    c.raw(frame(MASTER, PLC, 40001, 502, adu(9, 1, rd(3, 1, 1), length=1)))  # length says empty PDU
    c.raw(frame(MASTER, PLC, 40001, 502, adu(9, 1, rd(3, 1, 1), length=0)))  # length 0
    c.raw(frame(MASTER, PLC, 40001, 502, adu(9, 1, rd(3, 1, 1), length=200)))  # length > payload
    c.raw(frame(MASTER, PLC, 40001, 502, adu(9, 1, rd(3, 77, 5), length=4)))   # length cuts PDU short (3 bytes): no address
    c.raw(frame(MASTER, PLC, 40001, 502, adu(9, 1, b"\x03\x00\x01")))          # fc 3 request with truncated PDU
    c.raw(frame(MASTER, PLC, 40001, 502, adu(9, 1, b"\x06\x00\x01\x00")))      # fc 6 request, 4 byte PDU
    c.raw(frame(PLC, MASTER, 502, 40001, adu(9, 1, b"\x03\x02\x00")))          # fc3 response
    c.raw(frame(PLC, MASTER, 502, 40001, adu(9, 1, b"\x00\x00\x00\x00\x00")))  # fc 0 -> skipped
    c.raw(frame(MASTER, PLC, 40001, 502, adu(9, 1, rd(3, 1, 1)) + adu(10, 1, rd(3, 2, 1))))  # two ADUs: only first
    c.raw(frame(MASTER, PLC, 40001, 502, adu(11, 1, rd(3, 4, 1)) + b"\xde\xad\xbe\xef", total=None))  # trailing junk
    c.raw(frame(MASTER, PLC, 40001, 502, adu(12, 1, rd(3, 8, 1)), off_words=8))   # TCP options
    c.raw(frame(MASTER, PLC, 40001, 502, adu(13, 1, rd(3, 9, 1)), vlan=True))     # VLAN tag
    c.raw(frame(MASTER, PLC, 40001, 502, adu(14, 1, rd(3, 10, 1))))
    fr = frame(MASTER, PLC, 40001, 502, adu(15, 1, rd(3, 11, 1))); c.raw(fr + b"\x00" * 6)  # eth padding beyond IP len
    c.raw(frame(MASTER, PLC, 40001, 502, adu(16, 1, rd(3, 12, 1)), frag=0x2000))   # MF set, offset 0 (first frag)
    c.raw(frame(MASTER, PLC, 40001, 502, adu(17, 1, rd(3, 13, 1)), frag=0x0010))   # nonzero frag offset
    c.raw(eth(ip_pkt(MASTER, PLC, 17, struct.pack(">HHHH", 40001, 502, 8 + 12, 0) + adu(18, 1, rd(3, 14, 1)))))  # UDP
    c.raw(eth(b"\x00" * 28, etype=0x0806))                        # ARP-ish
    c.raw(b"\x00" * 10)                                           # runt frame
    c.raw(frame(MASTER, PLC, 502, 502, adu(19, 1, rd(3, 15, 1))))  # both ports 502 -> request
    c.raw(frame("10.1.0.30", "10.1.0.31", 1000, 2000, adu(20, 1, rd(3, 16, 1))))  # unrelated port
    c.raw(frame(MASTER, PLC, 40001, 502, adu(21, 1, rd(3, 17, 1)), ihl_words=6))   # IP options
    c.raw(frame(MASTER, PLC, 40001, 502, adu(22, 1, rd(3, 18, 1)), total=20 + 20 + 9))  # IP total len truncates payload
    caps["malformed"] = (c, 502)

    c = Cap(port=1502); baseline(c, 3)
    c.req(rd(3, 100, 10)); c.resp(rd_resp(3, 10))
    caps["nonstd_port_1502"] = (c, 1502)
    return caps


def to_pcap(pk, truncate_tail=False):
    buf = io.BytesIO()
    buf.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, fr in pk:
        sec = int(math.floor(ts)); usec = int(round((ts - sec) * 1e6))
        buf.write(struct.pack("<IIII", sec, usec, len(fr), len(fr)) + fr)
    out = buf.getvalue()
    if truncate_tail:
        out += struct.pack("<IIII", int(T0) + 999, 0, 200, 200) + b"\x00" * 30  # record claims 200 bytes, has 30
    return out


def blk(btype, body):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack("<II", btype, total) + body + b"\0" * pad + struct.pack("<I", total)


def to_pcapng(pk):
    ng = blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)) + blk(1, struct.pack("<HHI", 1, 0, 65535))
    for ts, fr in pk:
        us = int(round(ts * 1e6))
        ng += blk(6, struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF, len(fr), len(fr)) + fr)
    return ng


def rows(df):
    recs = []
    for r in df.to_dict("records"):
        r = {k: (None if (isinstance(v, float) and math.isnan(v)) else v) for k, v in r.items()}
        for k in ("exception_code", "address", "quantity"):
            if r[k] is not None:
                r[k] = int(r[k])
        r["unit_id"] = int(r["unit_id"]); r["function_code"] = int(r["function_code"])
        r["is_request"] = bool(r["is_request"]); r["is_exception"] = bool(r["is_exception"])
        recs.append(r)
    return recs


def events(scored, tenant="ref"):
    """Same record shape routers/ingest.py inserts into ot_protocol_events (minus tenant_id)."""
    out = []
    for _, row in scored.iterrows():
        def n(v, cast=None):
            if v is None or (not isinstance(v, str) and pd.isna(v)):
                return None
            return cast(v) if cast else v
        out.append({
            "protocol": "modbus_tcp",
            "ts": pd.Timestamp(row["ts"], unit="s", tz="UTC").isoformat(),
            "src_ip": row["src_ip"], "dst_ip": row["dst_ip"],
            "unit_id": int(row["unit_id"]), "function_code": int(row["function_code"]),
            "function_name": row["function_name"], "is_request": bool(row["is_request"]),
            "is_exception": bool(row["is_exception"]), "exception_code": n(row["exception_code"], int),
            "address": n(row["address"], int), "quantity": n(row["quantity"], int),
            "severity": n(row["severity"]), "reason": n(row["reason"]), "incident_id": None,
        })
    return out


def main():
    ref = {"fixtures": {}, "carryover": []}
    caps = build()
    files = {}
    for name, (cap, port) in caps.items():
        files[name + ".pcap"] = to_pcap(cap.pk, truncate_tail=(name == "malformed"))
        files[name + ".pcapng"] = to_pcapng(cap.pk)
    # malformed capture whose last record is cut short (python stops reading, keeps what it has)
    for fname, data in files.items():
        (OUT / fname).write_bytes(data)
        name = fname.rsplit(".", 1)[0]
        port = caps[name][1]
        ports = [port] if name != "nonstd_port_1502" else [port, 502]
        for p in ports:
            df = parse_modbus_pcap_bytes(data, port=p)
            key = f"{fname}@{p}"
            entry = {"file": fname, "port": p, "messages": rows(df)}
            if p == 502 or True:
                entry["events"] = events(OTRuleEngine("ref").evaluate(df))
            ref["fixtures"][key] = entry
    # not-a-capture inputs: python raises ValueError
    ref["rejected"] = ["garbage", "empty"]
    for label, data in (("garbage", b"\x07" * 100), ("empty", b"")):
        try:
            parse_modbus_pcap_bytes(data); raise SystemExit(f"python accepted {label}")
        except ValueError:
            pass
    # carry-over: run baseline capture, then the attack capture, on ONE engine (the persisted-state case)
    for first, second in (("normal_rw", "write_outside_range"), ("normal_rw", "new_function_code"),
                          ("unit_id_scan", "unit_id_scan"), ("exception_flood", "exception_flood")):
        eng = OTRuleEngine("carry")
        d1 = parse_modbus_pcap_bytes(files[first + ".pcap"]); d2 = parse_modbus_pcap_bytes(files[second + ".pcap"])
        e1 = events(eng.evaluate(d1)); e2 = events(eng.evaluate(d2))
        ref["carryover"].append({"first": first + ".pcap", "second": second + ".pcap", "events_first": e1, "events_second": e2})
    (OUT / "modbus_reference.json").write_text(json.dumps(ref, indent=1))
    for k, v in ref["fixtures"].items():
        sev = {}
        for e in v["events"]:
            if e["reason"]:
                sev[e["reason"]] = sev.get(e["reason"], 0) + 1
        print(f"{k:42s} msgs={len(v['messages']):3d} flags={sev}")


if __name__ == "__main__":
    main()
