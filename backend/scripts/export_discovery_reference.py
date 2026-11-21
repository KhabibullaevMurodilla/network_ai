"""Builds small synthetic captures (struct-packed, so malformed variants are
possible) that exercise every branch of backend/app/ingestion/discovery.py and
endpoints.py, runs the Python implementations over them plus the existing
sample.pcap/sample.pcapng, and saves the results so the TypeScript ports
(frontend/lib/local/discovery.ts, endpoints.ts) can be compared on identical
bytes. Everything is deterministic (fixed timestamps, seeded fuzzing), so
re-running rewrites byte-identical files.

Run from backend/:  python scripts/export_discovery_reference.py
Needs: pip install dpkt pandas   (pcap.py, imported by the modules, uses pandas)
"""
import json, platform, random, struct, sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))
from app.ingestion.discovery import discover_devices, parse_lldp, parse_cdp, _is_private, _is_public  # noqa: E402
from app.ingestion.endpoints import extract_endpoints, parse_sni  # noqa: E402

TESTS = BACKEND.parent / "frontend" / "tests" / "local"
FIX = TESTS / "fixtures"
FIX.mkdir(parents=True, exist_ok=True)

T0 = 1_700_000_000.0


# ---------------------------------------------------------------- builders
def mac(s):
    return bytes.fromhex(s.replace(":", ""))


def ipb(s):
    return bytes(map(int, s.split(".")))


def eth(dst, src, etype, payload):
    return mac(dst) + mac(src) + struct.pack("!H", etype) + payload


def ip4(src, dst, proto, payload, ttl=64, total="auto", frag=0, ihl=5, opts=b""):
    hdr_len = ihl * 4
    tl = hdr_len + len(payload) if total == "auto" else total
    h = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, tl, 1, frag, ttl, proto, 0, ipb(src), ipb(dst))
    return h + opts + payload


def tcp(sp, dp, flags, data=b"", doff=5):
    return struct.pack("!HHIIBBHHH", sp, dp, 1, 1, doff << 4, flags, 8192, 0, 0) + b"\x00" * ((doff - 5) * 4 if doff > 5 else 0) + data


def udp(sp, dp, data=b""):
    return struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data


def arp(op, sha, spa, tha, tpa):
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, mac(sha), ipb(spa), mac(tha), ipb(tpa))


SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08
BC = "ff:ff:ff:ff:ff:ff"


def frame_tcp(smac, dmac, src, dst, sp, dp, flags, data=b"", ttl=64, **kw):
    return eth(dmac, smac, 0x0800, ip4(src, dst, 6, tcp(sp, dp, flags, data), ttl=ttl, **kw))


def frame_udp(smac, dmac, src, dst, sp, dp, data=b"", ttl=64, **kw):
    return eth(dmac, smac, 0x0800, ip4(src, dst, 17, udp(sp, dp, data), ttl=ttl, **kw))


def write_pcap(path, frames, endian="<", nano=False, linktype=1):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for ts, fr in frames:
        sec = int(ts)
        frac = round((ts - sec) * (1e9 if nano else 1e6))
        out += struct.pack(endian + "IIII", sec, frac, len(fr), len(fr)) + fr
    path.write_bytes(out)


def _pad4(b):
    return b + b"\x00" * (-len(b) % 4)


def write_pcapng(path, frames, le=True, tsresol=None, link=1):
    e = "<" if le else ">"

    def block(btype, body):
        total = 12 + len(body)
        return struct.pack(e + "II", btype, total) + body + struct.pack(e + "I", total)

    shb = block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    opts = b""
    div = 1e6
    if tsresol is not None:
        opts = struct.pack(e + "HH", 9, 1) + _pad4(bytes([tsresol])) + struct.pack(e + "HH", 0, 0)
        div = 10.0 ** tsresol if not tsresol & 0x80 else 2.0 ** (tsresol & 0x7F)
    idb = block(1, struct.pack(e + "HHI", link, 0, 65535) + opts)
    out = shb + idb
    for ts, fr in frames:
        t = int(round(ts * div))
        body = struct.pack(e + "IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(fr), len(fr)) + _pad4(fr)
        out += block(6, body)
    path.write_bytes(out)


def seq(frames, start=T0, step=0.01):
    return [(start + i * step, f) for i, f in enumerate(frames)]


# ---------------------------------------------------------------- L2 payloads
def tlv_lldp(t, val):
    return struct.pack("!H", (t << 9) | len(val)) + val


def lldp_pdu(chassis=(4, "aa:bb:cc:00:00:01"), port=(5, b"Gi1/0/1"), ttl=120, port_desc=None, sys_name=None,
             sys_desc=None, caps=None, end=True, extra=b""):
    b = b""
    if chassis is not None:
        sub, v = chassis
        b += tlv_lldp(1, bytes([sub]) + (mac(v) if sub == 4 else v))
    if port is not None:
        sub, v = port
        b += tlv_lldp(2, bytes([sub]) + (mac(v) if sub == 3 else v))
    b += tlv_lldp(3, struct.pack("!H", ttl))
    if port_desc is not None:
        b += tlv_lldp(4, port_desc)
    if sys_name is not None:
        b += tlv_lldp(5, sys_name)
    if sys_desc is not None:
        b += tlv_lldp(6, sys_desc)
    if caps is not None:
        b += tlv_lldp(7, struct.pack("!HH", *caps))
    b += extra
    if end:
        b += tlv_lldp(0, b"")
    return b


LLDP_DST = "01:80:c2:00:00:0e"
CDP_DST = "01:00:0c:cc:cc:cc"


def lldp_frame(src, pdu, pad=True, etype=0x88CC, dst=LLDP_DST):
    f = eth(dst, src, etype, pdu)
    return f + b"\x00" * (60 - len(f)) if pad and len(f) < 60 else f


def cdp_tlv(t, val):
    return struct.pack("!HH", t, 4 + len(val)) + val


def cdp_frame(src, device_id=b"sw-edge-1", port=b"GigabitEthernet0/1", caps=0x08, platform=b"cisco WS-C2960", dst=CDP_DST,
              raw_tail=b"", length=None, version=2):
    body = struct.pack("!BBH", version, 180, 0)
    if device_id is not None:
        body += cdp_tlv(1, device_id)
    if port is not None:
        body += cdp_tlv(3, port)
    if caps is not None:
        body += cdp_tlv(4, struct.pack("!I", caps))
    if platform is not None:
        body += cdp_tlv(6, platform)
    body += raw_tail
    llc = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
    payload = llc + body
    return eth(dst, src, len(payload) if length is None else length, payload)


# ---------------------------------------------------------------- DHCP
def dhcp_pkt(op, chaddr, opts, hln=6, xid=0x1234, tail=b"", yi="0.0.0.0", noend=False):
    h = struct.pack("!BBBBIHH4s4s4s4s16s64s128sI", op, 1, hln, 0, xid, 0, 0, ipb("0.0.0.0"), ipb(yi), ipb("0.0.0.0"),
                    ipb("0.0.0.0"), mac(chaddr) + b"\x00" * 10, b"", b"", 0x63825363)
    o = b""
    for t, v in opts:
        o += bytes([t, len(v)]) + v
    if not noend:
        o += b"\xff"
    return h + o + tail


# ---------------------------------------------------------------- DNS / TLS
def dns_name(name, ptr_to=None):
    if ptr_to is not None:
        return struct.pack("!H", 0xC000 | ptr_to)
    out = b""
    for lab in name.split("."):
        if lab:
            b = lab.encode("utf-8") if isinstance(lab, str) else lab
            out += bytes([len(b)]) + b
    return out + b"\x00"


def dns_q(name, qtype=1):
    return dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_rr(name_wire, rtype, rdata, ttl=60, rlen=None):
    return name_wire + struct.pack("!HHIH", rtype, 1, ttl, len(rdata) if rlen is None else rlen) + rdata


def dns_msg(qname, answers=(), qr=True, qd=1, ns=(), ar=(), ident=0x1111, qdcount=None, op=None):
    flags = (0x8180 if qr else 0x0100) if op is None else op
    q = dns_q(qname) if qd else b""
    an = b"".join(answers)
    return (struct.pack("!HHHHHH", ident, flags, qd if qdcount is None else qdcount, len(answers), len(ns), len(ar))
            + q + an + b"".join(ns) + b"".join(ar))


QNAME_PTR = 12  # compression pointer to the question name at offset 12


def a_rr(ip, name_wire=None, ttl=60):
    return dns_rr(name_wire or dns_name("", ptr_to=QNAME_PTR), 1, ipb(ip), ttl)


def client_hello(sni=b"example.com", ext_before=b"", pre_ext_len_pad=0, handshake_type=1, rec_type=0x16, sni_name_type=0,
                 session=b"", ciphers=b"\x13\x01\x13\x02", comp=b"\x00", ext_after=b"", extra_sni_ext=b"", raw_sni_ext=None):
    if raw_sni_ext is not None:
        sn = raw_sni_ext
    else:
        nm = struct.pack("!BH", sni_name_type, len(sni)) + sni
        sn = struct.pack("!HHH", 0, 2 + len(nm), len(nm)) + nm
    exts = ext_before + sn + ext_after
    body = b"\x03\x03" + b"\x11" * 32 + bytes([len(session)]) + session + struct.pack("!H", len(ciphers)) + ciphers \
        + bytes([len(comp)]) + comp + struct.pack("!H", len(exts)) + exts
    hs = bytes([handshake_type]) + struct.pack("!I", len(body))[1:] + body
    return bytes([rec_type]) + b"\x03\x01" + struct.pack("!H", len(hs)) + hs


EXT_SUPPORTED_GROUPS = struct.pack("!HH", 10, 4) + b"\x00\x02\x00\x1d"
EXT_ALPN = struct.pack("!HH", 16, 5) + b"\x00\x03\x02h2" + b"\x00"[:0]


# ---------------------------------------------------------------- mutation (fuzz)
def mutate(rng, b):
    b = bytearray(b)
    kind = rng.choice(["flip", "flip", "flip2", "trunc", "ins", "del", "set_ff"])
    if not b:
        return bytes(b)
    if kind == "flip":
        b[rng.randrange(len(b))] = rng.randrange(256)
    elif kind == "flip2":
        for _ in range(3):
            b[rng.randrange(len(b))] = rng.randrange(256)
    elif kind == "trunc":
        b = b[:rng.randrange(len(b))]
    elif kind == "ins":
        i = rng.randrange(len(b))
        b[i:i] = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 4)))
    elif kind == "del":
        i = rng.randrange(len(b))
        del b[i:i + rng.randrange(1, 4)]
    else:
        b[rng.randrange(len(b))] = 0xFF
    return bytes(b)


# ================================================================ fixtures
FILES = {}  # name -> (writer kwargs..., frames) we write then run


def add(name, frames, **kw):
    path = FIX / name
    if name.endswith(".pcapng"):
        write_pcapng(path, frames, **kw)
    else:
        write_pcap(path, frames, **kw)
    FILES[name] = path


GW = "00:11:22:33:44:01"
H1, H2, H3, H4 = "00:11:22:33:44:11", "00:11:22:33:44:12", "00:11:22:33:44:13", "02:11:22:33:44:14"  # H4 randomised bit

# ---- 1. LLDP --------------------------------------------------------------
long_desc = ("Switch \U0001F600 " + "x" * 110 + "\U0001F600\U0001F600 tail beyond the cut")  # crosses 120 code points, non-BMP
lldp = [
    lldp_frame("aa:bb:cc:00:00:01", lldp_pdu(sys_name=b"core-sw1", sys_desc=long_desc.encode(), port_desc=b"uplink",
                                            caps=(0x0014, 0x0014))),                      # switch + router
    lldp_frame("aa:bb:cc:00:00:02", lldp_pdu(chassis=(7, b"ap-lobby-chassis"), port=(3, "aa:bb:cc:00:00:99"),
                                            sys_name=b"ap-lobby", caps=(0x0008, 0x0008))),  # access point, port subtype 3 (MAC)
    lldp_frame("aa:bb:cc:00:00:03", lldp_pdu(chassis=None, sys_name=b"no-chassis")),        # rejected: no chassis TLV
    lldp_frame("02:bb:cc:00:00:04", lldp_pdu(sys_name=b"bad\xff\xfe-utf8\xc3", port=(5, b"p\xe2\x82"))),  # invalid UTF-8, randomised MAC
    lldp_frame("aa:bb:cc:00:00:05", lldp_pdu(port=None, sys_name=b"", caps=(0x0004, 0x0000))),  # empty sys_name, no port, caps but not enabled
    lldp_frame("aa:bb:cc:00:00:06", lldp_pdu(chassis=(4, "aa:bb:cc:00:00:06")) [:-2] + b"\x0e\x20abc"),  # truncated trailing TLV, no end TLV
    lldp_frame("aa:bb:cc:00:00:01", lldp_pdu(sys_name=b"core-sw1-renamed", caps=(0x0014, 0x0004))),  # same MAC again: replaces earlier info
    lldp_frame("aa:bb:cc:00:00:07", lldp_pdu(chassis=(4, "aa:bb:cc:00:00:07"), sys_name=b"after-end",
                                            extra=b"")[:-2] + tlv_lldp(0, b"") + tlv_lldp(5, b"ignored-after-end")),  # TLVs after End are ignored
    lldp_frame("aa:bb:cc:00:00:08", lldp_pdu(chassis=(4, "aa:bb:cc:00:00:08"), caps=(0x0010, 0x0010), sys_name="bücher-sw".encode())),
    lldp_frame("aa:bb:cc:00:00:09", b"\x02\x01"),                                           # too short
    lldp_frame("aa:bb:cc:00:00:0a", lldp_pdu(chassis=(4, "aa:bb:cc:00:00:0a"), sys_name=b"vlan-tagged"), etype=0x8100),  # ethertype 8100 -> not LLDP
    lldp_frame("aa:bb:cc:00:00:0b", b"\xef\xbb\xbf" + b"", etype=0x88CC),                  # junk
    lldp_frame("aa:bb:cc:00:00:0c", lldp_pdu(chassis=(6, b"\xef\xbb\xbfBOM-chassis"), sys_name=b"\xef\xbb\xbfBOM-name")),  # leading BOM preserved by Python
]
add("disc_lldp.pcap", seq(lldp))

# ---- 2. CDP ---------------------------------------------------------------
cdp = [
    cdp_frame("aa:bb:cc:01:00:01"),                                                       # switch (0x08)
    cdp_frame("aa:bb:cc:01:00:02", device_id=b"rtr-1", caps=0x01, platform=None),         # router, platform missing
    cdp_frame("aa:bb:cc:01:00:03", device_id=b"sw-igmp", caps=0x02, port=None),          # 0x02 -> switch, port missing
    cdp_frame("aa:bb:cc:01:00:04", device_id=b"rtr-sw", caps=0x09),                      # router + switch
    cdp_frame("aa:bb:cc:01:00:05", device_id=None),                                       # no device id -> rejected
    cdp_frame("aa:bb:cc:01:00:06", device_id=b""),                                        # empty device id -> rejected
    cdp_frame("aa:bb:cc:01:00:07", device_id=b"bad-utf8-\xff\xfe", caps=0x08),            # invalid UTF-8
    cdp_frame("aa:bb:cc:01:00:08", device_id=b"short-caps", caps=None, raw_tail=cdp_tlv(4, b"\x01\x02")),  # caps TLV <4 bytes ignored
    cdp_frame("aa:bb:cc:01:00:09", device_id=b"len-lt-4", raw_tail=struct.pack("!HH", 9, 2) + b"zzzz"),     # TLV length < 4 stops parsing
    cdp_frame("aa:bb:cc:01:00:0a", device_id=b"trunc", raw_tail=struct.pack("!HH", 9, 40) + b"abc"),        # TLV overruns the frame
    cdp_frame("aa:bb:cc:01:00:0b", dst="01:00:0c:cc:cc:cd"),                              # wrong destination MAC -> not CDP
    eth(CDP_DST, "aa:bb:cc:01:00:0c", 0x0800, b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + b"\x02\xb4\x00\x00" + cdp_tlv(1, b"ethertype-ip")),  # etype >= 1536
    eth(CDP_DST, "aa:bb:cc:01:00:0d", 10, b"\xaa\xaa\x03\x00\x00\x0c\x20\x00\x02"),     # CDP body < 4 bytes
    cdp_frame("aa:bb:cc:01:00:01", device_id=b"sw-edge-1-v2", caps=0x08, platform=b"WS-C3850"),  # same MAC again
    cdp_frame("aa:bb:cc:01:00:0e", device_id=b"with-fcs-pad", length=60),                  # length field disagrees with payload
]
add("disc_cdp.pcap", seq(cdp))

# ---- 3. ARP + gateway inference -------------------------------------------
PUBLICS = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "142.250.1.1", "151.101.1.1"]
g = []
g.append(eth(BC, GW, 0x0806, arp(2, GW, "192.168.1.1", "00:00:00:00:00:00", "192.168.1.255")))       # gateway ARP: ARP binds
g.append(eth(BC, H1, 0x0806, arp(1, H1, "192.168.1.10", "00:00:00:00:00:00", "192.168.1.1")))
g.append(eth(BC, H2, 0x0806, arp(1, "01:00:5e:00:00:01", "192.168.1.11", "00:00:00:00:00:00", "192.168.1.1")))  # multicast sha: ignored
g.append(eth(BC, H2, 0x0806, arp(1, H2, "0.0.0.0", "00:00:00:00:00:00", "192.168.1.11")))                    # probe: spa 0.0.0.0 ignored
g.append(eth(BC, "00:00:00:00:00:00", 0x0806, arp(1, "00:00:00:00:00:00", "192.168.1.99", BC, "192.168.1.1")))  # zero MAC ignored
for i, p in enumerate(PUBLICS):                                                                        # next-hop MAC for 5 public IPs
    g.append(frame_tcp(H1, GW, "192.168.1.10", p, 40000 + i, 443, SYN, ttl=64))
    g.append(frame_tcp(GW, H1, p, "192.168.1.10", 443, 40000 + i, SYN | ACK, ttl=57))                  # inbound via gateway
g.append(frame_udp(H2, GW, "192.168.1.11", "8.8.8.8", 5000, 53, b"x", ttl=128))                         # H2 ttl 128 (Windows hint)
g.append(frame_udp(H2, GW, "192.168.1.11", "8.8.4.4", 5001, 53, b"x", ttl=120))                         # lower ttl later: max kept
g.append(frame_udp(H3, GW, "192.168.1.12", "8.8.8.8", 5000, 53, b"x", ttl=255))                         # network-device hint
g.append(frame_udp(H4, GW, "192.168.1.13", "8.8.8.8", 5000, 53, b"x", ttl=20))                          # ttl <33: no hint; randomised MAC
g.append(frame_udp(H3, GW, "192.168.1.12", "192.168.1.14", 5000, 9999, b"x", ttl=40))                   # dst-only private host (ip: device)
# a second router-like MAC forwarding for many private IPs but only 2 publics: not the gateway; its private IPs are not "owned"
RT = "00:11:22:33:44:77"
for i in range(3):
    g.append(frame_udp(RT, "00:11:22:33:44:01", f"10.9.0.{i + 1}", "9.9.9.9", 6000, 6000, b"x", ttl=61))
add("disc_gateway_arp.pcap", seq(g))

# ---- 4. DHCP --------------------------------------------------------------
DHCPS = "00:aa:00:00:00:01"
d = []
CL1, CL2, CL3 = "00:cc:00:00:00:01", "00:cc:00:00:00:02", "00:cc:00:00:00:03"
d.append(frame_udp(CL1, BC, "0.0.0.0", "255.255.255.255", 68, 67, dhcp_pkt(1, CL1, [(53, b"\x01"), (12, b"laptop-01")])))
d.append(frame_udp(DHCPS, CL1, "192.168.50.1", "192.168.50.20", 67, 68, dhcp_pkt(2, CL1, [(53, b"\x02")], yi="192.168.50.20")))
d.append(frame_udp(CL1, BC, "0.0.0.0", "255.255.255.255", 68, 67, dhcp_pkt(1, CL1, [(53, b"\x03"), (12, b"laptop-01-renamed")])))  # REQUEST, new name
d.append(frame_udp(DHCPS, CL1, "192.168.50.1", "192.168.50.20", 67, 68, dhcp_pkt(2, CL1, [(53, b"\x05")], yi="192.168.50.20")))   # ACK
d.append(frame_tcp(CL1, DHCPS, "192.168.50.20", "192.168.50.1", 50000, 80, SYN))                      # maps CL1's IP->MAC, makes it a client
d.append(frame_udp(CL2, BC, "0.0.0.0", "255.255.255.255", 68, 67, dhcp_pkt(1, CL2, [(53, b"\x03"), (12, b"phone-\xff\xfe")])))  # invalid UTF-8 hostname, no device by MAC later -> unused
d.append(frame_udp(CL3, BC, "0.0.0.0", "255.255.255.255", 68, 67, dhcp_pkt(1, CL3, [(53, b"\x01")])))  # no hostname option
d.append(frame_udp(CL3, BC, "0.0.0.0", "255.255.255.255", 68, 67, dhcp_pkt(1, CL3, [(12, b"no-msgtype")])))  # hostname but no message type (-> 0)
d.append(frame_tcp(CL3, DHCPS, "192.168.50.30", "192.168.50.1", 50001, 80, SYN))
d.append(frame_udp(CL3, BC, "0.0.0.0", "255.255.255.255", 68, 67, dhcp_pkt(1, CL3, [(53, b"\x03"), (12, b""), ])))  # empty hostname option
# server whose MAC carries >1 private IP: MAC not attributed via weak map, falls back to d.mac = server mac
SRV2 = "00:aa:00:00:00:02"
d.append(frame_udp(SRV2, CL1, "192.168.60.1", "192.168.60.50", 67, 68, dhcp_pkt(2, CL1, [(53, b"\x02")])))
d.append(frame_udp(SRV2, CL1, "192.168.60.2", "192.168.60.50", 67, 68, dhcp_pkt(2, CL1, [(53, b"\x01")])))   # DISCOVER type from a server port: not a server msg
# DHCP "server" that is actually the gateway MAC (m == gateway_mac): mac not copied
for i, p in enumerate(PUBLICS[:4]):
    d.append(frame_tcp("00:aa:00:00:00:03", GW, "192.168.70.5", p, 41000 + i, 443, SYN))
d.append(frame_udp(GW, CL1, "192.168.70.1", "192.168.70.9", 67, 68, dhcp_pkt(2, CL1, [(53, b"\x05")])))
d.append(frame_udp(GW, CL1, "192.168.70.1", "192.168.70.9", 67, 68, dhcp_pkt(2, CL1, [(53, b"\x05")])))
# malformed DHCP
d.append(frame_udp(DHCPS, CL1, "192.168.50.77", "192.168.50.20", 67, 68, dhcp_pkt(2, CL1, [(53, b"\x02")])[:100]))       # short header
d.append(frame_udp(DHCPS, CL1, "192.168.50.78", "192.168.50.20", 67, 68, dhcp_pkt(2, CL1, [(53, b"\x02")], noend=True) + b"\x35"))  # dangling option byte -> IndexError
d.append(frame_udp(DHCPS, CL1, "192.168.50.79", "192.168.50.20", 67, 68, dhcp_pkt(2, CL1, [(53, b"")])))                # empty msg-type option -> IndexError
d.append(frame_udp(DHCPS, CL1, "192.168.50.80", "192.168.50.20", 67, 68, dhcp_pkt(2, CL1, [(0, b"")])[:-1] + b"\x00\x00" + bytes([53, 1, 2, 255])))  # pad bytes then msg type 2 (hand-built)
d.append(frame_udp(DHCPS, CL1, "192.168.50.81", "192.168.50.20", 67, 68, dhcp_pkt(2, CL1, [(53, b"\x05"), (53, b"\x01")])))  # duplicate option: last wins -> DISCOVER -> not a server
d.append(frame_udp(DHCPS, CL1, "192.168.50.82", "192.168.50.20", 1234, 4321, dhcp_pkt(2, CL1, [(53, b"\x02")])))        # not on port 67/68
d.append(frame_udp(DHCPS, CL1, "192.168.50.83", "192.168.50.20", 68, 9999, dhcp_pkt(2, CL1, [(53, b"\x02")])))          # source port 68 counts
d.append(frame_udp(CL3, BC, "192.168.50.31", "255.255.255.255", 68, 67, dhcp_pkt(1, CL3, [(53, b"\x01"), (12, b"hln-small")], hln=3)))  # hln=3 -> chaddr[:3]
d.append(frame_tcp(CL3, DHCPS, "192.168.50.31", "192.168.50.1", 50002, 80, SYN))
d.append(frame_udp("00:cc:00:00:00:09", BC, "192.168.50.40", "255.255.255.255", 68, 67, dhcp_pkt(1, "00:cc:00:00:00:09", [(53, b"\x01"), (12, b"hln-big")], hln=20)))
d.append(frame_udp("00:cc:00:00:00:09", BC, "192.168.50.40", "255.255.255.255", 68, 67, b""))  # empty UDP payload
add("disc_dhcp.pcap", seq(d))

# ---- 5. servers + DNS clients ---------------------------------------------
s = []
SV1, SV2, SV3, CLA, CLB = "00:5e:00:00:00:01", "00:5e:00:00:00:02", "00:5e:00:00:00:03", "00:cc:00:00:01:01", "00:cc:00:00:01:02"
ports = [443, 22, 80, 8080, 3306, 5432, 6379, 9200, 9300, 27017, 11211]  # 11 ports: only the first 8 (sorted) are listed
for p in ports:
    s.append(frame_tcp(CLA, SV1, "10.10.0.5", "10.10.0.10", 51000 + p % 1000, p, SYN))
    s.append(frame_tcp(SV1, CLA, "10.10.0.10", "10.10.0.5", p, 51000 + p % 1000, SYN | ACK, ttl=64))
s.append(frame_tcp(CLB, SV1, "10.10.0.6", "10.10.0.10", 52000, 443, SYN))
s.append(frame_tcp(SV1, CLB, "10.10.0.10", "10.10.0.6", 443, 52000, SYN | ACK))                # 2 distinct clients on 443
s.append(frame_tcp(SV2, CLA, "10.10.0.11", "10.10.0.5", 22, 53000, SYN | ACK))                    # server also resolver:
s.append(frame_udp(CLA, SV2, "10.10.0.5", "10.10.0.11", 54000, 53, b"q"))                        # dns_server outranks server
s.append(frame_udp(CLB, SV2, "10.10.0.6", "10.10.0.11", 54001, 53, b"q"))
s.append(frame_tcp(CLB, SV3, "10.10.0.6", "10.10.0.12", 54002, 53, SYN))                          # DNS over TCP
s.append(frame_udp(CLA, GW, "10.10.0.5", "8.8.8.8", 54003, 53, b"q"))                            # public resolver: not local
s.append(frame_tcp(GW, CLA, "93.184.216.34", "10.10.0.5", 80, 54004, SYN | ACK))                  # SYN-ACK from a public host: ignored
s.append(frame_tcp(CLA, SV3, "10.10.0.5", "10.10.0.12", 54005, 8000, SYN | ACK))                  # SYN-ACK *to* a private from a private
s.append(frame_tcp(CLA, SV3, "10.10.0.5", "10.10.0.12", 54006, 9000, SYN | ACK | FIN))            # extra flags
s.append(frame_tcp(CLA, SV3, "10.10.0.5", "10.10.0.12", 54007, 9001, ACK))                        # plain ACK: nothing
s.append(frame_tcp(CLA, SV3, "10.10.0.5", "10.10.0.12", 54008, 9002, SYN | RST))                  # SYN+RST counts as SYN (initiator)
s.append(frame_tcp(CLA, SV3, "10.10.0.5", "10.10.0.12", 54008, 9002, 0x1C2 & 0xFF))              # odd flags
s.append(frame_tcp("00:cc:00:00:01:03", SV3, "172.16.5.5", "172.16.5.6", 1000, 2000, SYN))       # 172.16/12
s.append(frame_tcp("00:cc:00:00:01:04", SV3, "172.32.5.5", "172.32.5.6", 1000, 2000, SYN))       # outside 172.16/12 -> public
s.append(frame_tcp("00:cc:00:00:01:05", SV3, "169.254.1.1", "169.254.1.2", 1000, 2000, SYN | ACK))  # link-local private
s.append(frame_tcp("00:cc:00:00:01:06", SV3, "100.64.1.1", "100.64.1.2", 1000, 2000, SYN))      # CGNAT: neither
add("disc_servers_dns.pcap", seq(s))

# ---- 6. frame-level edge cases (shared by discovery + endpoints) -----------
e = []
ok_syn = frame_tcp(H1, GW, "10.20.0.5", "10.20.0.9", 40000, 80, SYN | ACK)
e.append(b"\x00" * 10)                                                                           # < 14 bytes
e.append(eth(BC, H1, 0x86DD, b"\x60" + b"\x00" * 39))                                            # IPv6
e.append(eth(BC, H1, 0x9999, b"zz"))                                                             # unknown ethertype
e.append(eth(BC, H1, 100, b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + ip4("10.20.0.5", "10.20.0.9", 6, tcp(1, 2, SYN | ACK))))  # 802.3 length field
v1 = eth("00:11:22:33:44:aa", H1, 0x8100, struct.pack("!HH", 100, 0x0800) + ip4("10.20.0.21", "10.20.0.22", 6, tcp(8080, 5555, SYN | ACK)))
e.append(v1)                                                                                     # VLAN tagged server
e.append(eth("00:11:22:33:44:aa", H2, 0x88A8, struct.pack("!HH", 200, 0x8100) + struct.pack("!HH", 100, 0x0800)
             + ip4("10.20.0.31", "10.20.0.32", 6, tcp(8443, 5555, SYN | ACK))))                   # QinQ (S-tag + C-tag)
e.append(eth("00:11:22:33:44:aa", H2, 0x9100, struct.pack("!HH", 200, 0x0800) + ip4("10.20.0.33", "10.20.0.34", 6, tcp(8444, 5555, SYN | ACK))))  # 0x9100 tag
e.append(eth("00:11:22:33:44:aa", H2, 0x8100, b"\x00"))                                          # truncated VLAN tag
e.append(eth("00:11:22:33:44:aa", H2, 0x8100, struct.pack("!HH", 1, 0x0806) + arp(2, H2, "10.20.0.41", H1, "10.20.0.1")))  # ARP inside VLAN
e.append(eth("00:11:22:33:44:aa", H2, 0x0806, arp(2, H3, "10.20.0.42", H1, "10.20.0.1")[:20]))   # truncated ARP
e.append(eth("00:11:22:33:44:aa", H2, 0x0800, ip4("10.20.0.51", "10.20.0.52", 6, tcp(9, 9, SYN | ACK))[:19]))   # IP header < 20
e.append(eth("00:11:22:33:44:aa", H2, 0x0800, ip4("10.20.0.53", "10.20.0.54", 6, tcp(9, 9, SYN | ACK), ihl=4)))    # ihl < 5
e.append(eth("00:11:22:33:44:aa", H2, 0x0800, ip4("10.20.0.55", "10.20.0.56", 6, tcp(9, 9, SYN | ACK, doff=5), ihl=6, opts=b"\x01\x01\x01\x00")))  # IP options
e.append(eth("00:11:22:33:44:aa", H2, 0x0800, ip4("10.20.0.57", "10.20.0.58", 6, tcp(9, 9, SYN | ACK), frag=0x00B9)))  # non-first fragment
e.append(eth("00:11:22:33:44:aa", H2, 0x0800, ip4("10.20.0.59", "10.20.0.60", 6, tcp(9, 9, SYN | ACK), frag=0x2000)))  # first fragment (MF)
e.append(eth("00:11:22:33:44:aa", H2, 0x0800, ip4("10.20.0.61", "10.20.0.62", 6, tcp(7, 9, SYN | ACK), total=0)))   # IP total length 0 (TSO)
e.append(eth("00:11:22:33:44:aa", H2, 0x0800, ip4("10.20.0.63", "10.20.0.64", 6, tcp(6, 9, SYN | ACK) + b"trailing-bytes", total=40)))  # truncating total length
e.append(eth("00:11:22:33:44:aa", H2, 0x0800, ip4("10.20.0.65", "10.20.0.66", 6, tcp(5, 9, SYN | ACK), total=10)))   # total length < header
e.append(eth("00:11:22:33:44:aa", H2, 0x0800, ip4("10.20.0.67", "10.20.0.68", 6, tcp(5, 9, SYN | ACK, doff=4))))  # tcp data offset 4
e.append(eth("00:11:22:33:44:aa", H2, 0x0800, ip4("10.20.0.69", "10.20.0.70", 6, tcp(5, 9, SYN | ACK)[:19])))     # tcp < 20 bytes
e.append(eth("00:11:22:33:44:aa", H2, 0x0800, ip4("10.20.0.71", "10.20.0.72", 17, udp(5, 53, b"")[:7])))          # udp < 8 bytes
e.append(eth("00:11:22:33:44:aa", H2, 0x0800, ip4("10.20.0.73", "10.20.0.74", 1, b"\x08\x00\x00\x00\x00\x00\x00\x00")))  # ICMP
e.append(eth("00:11:22:33:44:aa", H2, 0x0800, ip4("10.20.0.75", "10.20.0.76", 47, b"\x00" * 8)))                   # GRE
e.append(frame_tcp(H3, GW, "10.20.0.80", "10.20.0.81", 80, 1, SYN | ACK, ttl=0))                  # ttl 0
e.append(frame_tcp(H3, "01:00:5e:00:00:05", "10.20.0.80", "224.0.0.5", 80, 1, SYN))                # multicast dst
e.append(frame_udp(H3, "01:00:5e:00:00:fb", "10.20.0.80", "224.0.0.251", 5353, 5353, b"mdns"))
e.append(frame_udp(H3, GW, "127.0.0.1", "127.0.0.2", 5353, 5353, b"loop"))                         # loopback not private/public
e.append(frame_udp(H3, GW, "0.0.0.0", "255.255.255.255", 68, 67, b"x"))
e.append(frame_udp(H3, GW, "10.20.0.80", "10.20.0.255", 138, 138, b"nbns"))
e.append(frame_udp("00:11:22:33:44:99", GW, "10.20.0.90", "1.2.3.4", 1, 1, b"\x00" * 40, total=0))
e.append(ok_syn)
add("disc_edge_frames.pcap", seq(e))

# ---- 7. address classification boundaries ----------------------------------
BOUND = ["0.0.0.0", "0.255.255.255", "1.0.0.0", "9.255.255.255", "10.0.0.0", "10.255.255.255", "11.0.0.0", "100.63.255.255",
         "100.64.0.0", "100.127.255.255", "100.128.0.0", "126.255.255.255", "127.0.0.1", "128.0.0.0", "169.253.255.255",
         "169.254.0.0", "169.254.255.255", "169.255.0.0", "172.15.255.255", "172.16.0.0", "172.31.255.255", "172.32.0.0",
         "191.255.255.255", "192.0.0.0", "192.0.0.8", "192.0.0.9", "192.0.0.10", "192.0.0.11", "192.0.0.169", "192.0.0.170",
         "192.0.0.171", "192.0.1.0", "192.0.2.0", "192.0.2.255", "192.0.3.0", "192.167.255.255", "192.168.0.0",
         "192.168.255.255", "192.169.0.0", "198.17.255.255", "198.18.0.0", "198.19.255.255", "198.20.0.0", "198.51.99.255",
         "198.51.100.0", "198.51.100.255", "198.51.101.0", "203.0.112.255", "203.0.113.0", "203.0.113.255", "203.0.114.0",
         "223.255.255.255", "224.0.0.0", "239.255.255.255", "240.0.0.0", "254.255.255.255", "255.255.255.254",
         "255.255.255.255"]
ic = [frame_tcp(H1, GW, "10.0.0.2", ip, 1000 + i, 443, SYN) for i, ip in enumerate(BOUND)]
ic += [frame_tcp(GW, H1, ip, "10.0.0.2", 443, 2000 + i, SYN | ACK) for i, ip in enumerate(BOUND)]
ic += [frame_tcp(H2, GW, ip, "172.16.0.9", 3000 + i, 25, SYN) for i, ip in enumerate(BOUND[::3])]       # boundary as *sources* of private-ish traffic
add("disc_ipclass.pcap", seq(ic))

rng_ip = random.Random(7)
RANDOM_IPS = [".".join(str(rng_ip.randrange(256)) for _ in range(4)) for _ in range(400)]

# ---- 8. DNS responses (endpoints) -----------------------------------------
SRVDNS = "8.8.8.8"
H = "00:11:22:33:44:55"
V = []  # visited remote hosts so the answer IPs become endpoint rows


def dns_resp(payload, dst="192.168.1.10", srv=SRVDNS, sport=53, dport=33333, smac=GW, dmac=H):
    return frame_udp(smac, dmac, srv, dst, sport, dport, payload)


dns = []
VIS = [f"52.0.0.{i}" for i in range(1, 40)]
for i, vip in enumerate(VIS):
    dns.append(frame_tcp(H, GW, "192.168.1.10", vip, 40000 + i, 443, SYN))
D = dns.append
D(dns_resp(dns_msg("www.example.com", [a_rr("52.0.0.1")])))                                              # plain
D(dns_resp(dns_msg("Mixed.Case.Example.COM.", [a_rr("52.0.0.2"), a_rr("52.0.0.3")])))                    # case + trailing dot + 2 A
D(dns_resp(dns_msg("cname.example.com", [dns_rr(dns_name("", ptr_to=12), 5, dns_name("target.example.net")),
                                          a_rr("52.0.0.4", dns_name("target.example.net"))])))          # CNAME then A under another name
D(dns_resp(dns_msg("ptrloop.example.com", [dns_rr(dns_name("", ptr_to=12), 5, struct.pack("!H", 0xC000 | 60))])))  # forward pointer -> error
D(dns_resp(dns_msg("many.example.com", [a_rr("52.0.0.5"), a_rr("52.0.0.5"), a_rr("52.0.0.6")])))        # duplicates
D(dns_resp(dns_msg("aaaa.example.com", [dns_rr(dns_name("", ptr_to=12), 28, b"\x20\x01" + b"\x00" * 14), a_rr("52.0.0.7")])))  # AAAA then A
D(dns_resp(dns_msg("https-rr.example.com", [a_rr("52.0.0.8"), dns_rr(dns_name("", ptr_to=12), 65, b"\x00\x01\x00")])))  # HTTPS type -> whole response dropped
D(dns_resp(dns_msg("rrsig.example.com", [a_rr("52.0.0.9")], ar=[dns_rr(dns_name("", ptr_to=12), 46, b"\x00" * 20)])))  # RRSIG in additional -> dropped
D(dns_resp(dns_msg("opt.example.com", [a_rr("52.0.0.10")], ar=[dns_rr(b"\x00", 41, b"")])))             # OPT in additional is fine
D(dns_resp(dns_msg("bad-a.example.com", [a_rr("52.0.0.11"), dns_rr(dns_name("", ptr_to=12), 1, b"\x01\x02\x03\x04\x05")])))  # 5-byte A: inet_ntoa error after first name added
D(dns_resp(dns_msg("short-a.example.com", [dns_rr(dns_name("", ptr_to=12), 1, b"\x01\x02\x03")])))       # 3-byte A
D(dns_resp(dns_msg("badtxt.example.com", [a_rr("52.0.0.12")], ns=[dns_rr(dns_name("", ptr_to=12), 16, b"\x03\xff\xfe\xfd")])))  # TXT invalid utf-8 -> dropped
D(dns_resp(dns_msg("txt.example.com", [a_rr("52.0.0.13")], ns=[dns_rr(dns_name("", ptr_to=12), 16, b"\x03abc\x02de")])))      # TXT ok
D(dns_resp(dns_msg("mx.example.com", [a_rr("52.0.0.14")], ns=[dns_rr(dns_name("", ptr_to=12), 15, b"\x00\x0a" + dns_name("mail.example.com"))])))
D(dns_resp(dns_msg("mxshort.example.com", [a_rr("52.0.0.15")], ns=[dns_rr(dns_name("", ptr_to=12), 15, b"\x00")])))           # MX rdata < 2
D(dns_resp(dns_msg("soa.example.com", [a_rr("52.0.0.16")], ns=[dns_rr(dns_name("", ptr_to=12), 6, dns_name("ns1.example.com") + dns_name("host.example.com") + struct.pack("!IIIII", 1, 2, 3, 4, 5))])))
D(dns_resp(dns_msg("soashort.example.com", [a_rr("52.0.0.17")], ns=[dns_rr(dns_name("", ptr_to=12), 6, dns_name("ns1.example.com") + dns_name("host.example.com") + b"\x00" * 19)])))  # short SOA
D(dns_resp(dns_msg("srv.example.com", [a_rr("52.0.0.18")], ar=[dns_rr(dns_name("", ptr_to=12), 33, struct.pack("!HHH", 1, 2, 3) + dns_name("target.example.com"))])))
D(dns_resp(dns_msg("srvshort.example.com", [a_rr("52.0.0.19")], ar=[dns_rr(dns_name("", ptr_to=12), 33, b"\x00\x01\x00\x02\x00")])))  # SRV rdata < 6
D(dns_resp(dns_msg("ns.example.com", [a_rr("52.0.0.20")], ns=[dns_rr(dns_name("", ptr_to=12), 2, dns_name("ns9.example.org"))])))
D(dns_resp(dns_msg("ptr.example.com", [a_rr("52.0.0.21")], ar=[dns_rr(dns_name("", ptr_to=12), 12, dns_name("host.example.org"))])))
D(dns_resp(dns_msg("null.example.com", [a_rr("52.0.0.22")], ar=[dns_rr(dns_name("", ptr_to=12), 10, b"\x00\x01")])))             # NULL type
D(dns_resp(dns_msg("hinfo.example.com", [a_rr("52.0.0.23")], ar=[dns_rr(dns_name("", ptr_to=12), 13, b"\x03cpu\x02os")])))        # HINFO
D(dns_resp(dns_msg("query.example.com", [a_rr("52.0.0.24")], qr=False)))                                                       # a query, not a response
D(dns_resp(dns_msg("noq.example.com", [a_rr("52.0.0.25")], qd=0)))                                                              # no question
D(dns_resp(dns_msg("sport.example.com", [a_rr("52.0.0.26")]), sport=5353))                                                      # from port != 53
D(dns_resp(dns_msg("empty.example.com", [])))                                                                                   # no answers
D(dns_resp(b"\x00\x01\x81\x80\x00"))                                                                                              # short header
D(dns_resp(dns_msg("under_score.exam-ple.com", [a_rr("52.0.0.27")])))                                                            # _ and - ok
D(dns_resp(dns_msg("-leading-dash.example.com", [a_rr("52.0.0.28")])))                                                           # fails regex
D(dns_resp(dns_msg("sp ace.example.com", [a_rr("52.0.0.29")])))                                                                   # space inside -> rejected
D(dns_resp(dns_msg("bücher.example.com", [a_rr("52.0.0.30")])))                                                                  # non-ASCII label -> rejected
D(dns_resp(dns_msg("." + "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 60, [a_rr("52.0.0.31")])))                      # long name, near 255-byte limit
D(dns_resp(dns_msg("x." + "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 63, [a_rr("52.0.0.32")])))                     # name_length > 255 -> error
D(dns_resp(dns_msg("a" * 63 + ".com", [a_rr("52.0.0.33")])))                                                                    # 63-char label, valid
D(dns_resp(b"\x00\x02\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + b"\x04abc\xff\x00\x00\x01\x00\x01" + a_rr("52.0.0.34")))         # invalid UTF-8 in qname -> error
D(dns_resp(b"\x00\x02\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + b"\x40" + b"x" * 64 + b"\x00\x00\x01\x00\x01" + a_rr("52.0.0.35")))  # label length 0x40 -> error
D(dns_resp(dns_msg("count-lie.example.com", [a_rr("52.0.0.36")]) [:12].replace(b"\x00\x01\x00\x01\x00\x00\x00\x00", b"\x00\x01\x00\x05\x00\x00\x00\x00") + dns_q("count-lie.example.com") + a_rr("52.0.0.36")))  # answer count 5, only 1 present
D(dns_resp(dns_msg("trunc-rr.example.com", [a_rr("52.0.0.37")])[:-2]))                                                           # rdata cut short (A with 2 bytes)
D(dns_resp(dns_msg("1.example.com", [a_rr("52.0.0.38")]), dst="192.168.1.10", srv="52.0.0.38"))                                   # response from an endpoint we also contact
D(frame_udp(H, GW, "192.168.1.10", "8.8.8.8", 33333, 53, dns_msg("req.example.com", [a_rr("52.0.0.39")], qr=True)))             # response *sent* to the resolver: out, ignored
D(frame_udp(GW, H, "8.8.4.4", "192.168.1.10", 53, 33334, b""))                                                                    # empty UDP payload
D(frame_udp(GW, H, "8.8.4.4", "192.168.1.10", 53, 33334, dns_msg("case.example.com", [a_rr("52.0.0.39")], op=0x8180 | 0x0200)))  # truncated bit set
D(frame_udp(GW, H, "8.8.4.4", "192.168.1.10", 53, 33334, dns_msg("a" + " " + ".example.com", [a_rr("52.0.0.39")])))  # NBSP inside -> rejected
D(frame_udp(GW, H, "8.8.4.4", "192.168.1.10", 53, 33334, dns_msg("\x1fpadded.example.com\x1f", [a_rr("52.0.0.39")])))     # \x1f whitespace stripped by Python
D(frame_udp(GW, H, "8.8.4.4", "192.168.1.10", 53, 33334, dns_msg(" strip.example.com", [a_rr("52.0.0.39")])))
D(frame_udp(GW, H, "8.8.4.4", "192.168.1.10", 53, 33334, dns_msg("Kelvin.example.com", [a_rr("52.0.0.39")])))         # Kelvin sign lowercases to ASCII k
D(frame_udp(GW, H, "8.8.4.4", "192.168.1.10", 53, 33334, dns_msg("...", [a_rr("52.0.0.39")])))                              # only dots
add("disc_dns.pcap", seq(dns))

# ---- 9. TLS ClientHello SNI (endpoints) ------------------------------------
T = []
HS = "00:11:22:33:44:55"
TLS_HOSTS = [f"34.0.0.{i}" for i in range(1, 30)]


def tls_pkt(i, payload, flags=PSH | ACK, src="192.168.1.10", sp=None, dport=443, host=None):
    return frame_tcp(HS, GW, src, host or TLS_HOSTS[i], sp or 41000 + i, dport, flags, payload)


hellos = [
    client_hello(b"example.com"),
    client_hello(b"Upper.Case.EXAMPLE.org", ext_before=EXT_SUPPORTED_GROUPS),
    client_hello(b"after-alpn.example.net", ext_before=EXT_SUPPORTED_GROUPS + struct.pack("!HH", 16, 5) + b"\x00\x03\x02h2\x00"),
    client_hello(b"with-session.example.com", session=b"\xaa" * 32, ciphers=b"\x13\x01" * 20),
    client_hello(b"trailing-dot.example.com."),
    client_hello(b"bad name!.example.com"),
    client_hello(b"b\xc3\xbccher.example.com"),                    # non-ASCII bytes dropped, then cleaned
    client_hello(b""),                                            # empty SNI
    client_hello(b"nosni", raw_sni_ext=struct.pack("!HH", 0x0017, 0)),  # no server_name ext (extended_master_secret only)
    client_hello(b"x", handshake_type=2),                         # ServerHello type -> None
    client_hello(b"x", rec_type=0x17),                            # application data
    client_hello(b"short.example.com")[:47],                      # < 48 bytes -> None
    client_hello(b"cut-in-name.example.com")[:-8],                # truncated inside name
    client_hello(b"two-exts.example.com", ext_after=struct.pack("!HH", 0, 14) + b"\x00\x0c\x00\x00\x09second.com"),
    client_hello(b"sni-first-only.example.com", ext_before=b"" , ext_after=struct.pack("!HH", 43, 3) + b"\x02\x03\x04"),
    client_hello(b"name-type-1.example.com", sni_name_type=1),    # name type is not checked
    client_hello(b"ext-len-lie.example.com", ext_before=struct.pack("!HH", 10, 400) + b"\x00\x02\x00\x1d"),  # ext length runs past the end
    client_hello(b"x", comp=b"\x00\x01\x02"),                     # more compression methods
    client_hello(b"ok-session-31.example.com", session=b"\x01" * 31),
    client_hello(b"a" * 253),                                     # long name, valid
    client_hello(b"a" * 254),                                     # too long for regex
    client_hello(b"UPPER_under.example.com"),
    client_hello(b"\xef\xbb\xbfbom.example.com"),                 # BOM byte dropped by ascii/ignore
    client_hello(b"  spaced.example.com  "),
]
for i, h in enumerate(hellos):
    T.append(tls_pkt(i, h))
# same host, several names -> sorted, max 8
for k in range(11):
    T.append(tls_pkt(0, client_hello(f"n{k:02d}.multi.example.com".encode()), host="34.0.1.1", sp=42000 + k))
T.append(tls_pkt(0, client_hello(b"inbound.example.com"), host="34.0.1.2"))                  # outbound for name
T.append(frame_tcp(GW, HS, "34.0.1.3", "192.168.1.10", 443, 43000, PSH | ACK, client_hello(b"inbound-only.example.com")))  # inbound: ignored
T.append(frame_udp(HS, GW, "192.168.1.10", "34.0.1.4", 43001, 443, client_hello(b"quic-like.example.com")))           # UDP: ignored
T.append(frame_tcp(HS, GW, "192.168.1.10", "34.0.1.5", 43002, 8443, PSH | ACK, client_hello(b"alt-port.example.com")))  # any dport
T.append(tls_pkt(0, b"", host="34.0.1.6"))                                                   # no payload
T.append(frame_tcp(HS, GW, "192.168.1.10", "34.0.1.7", 43003, 443, SYN, client_hello(b"on-syn.example.com")))
T.append(frame_tcp(HS, GW, "192.168.1.10", "34.0.1.8", 43004, 443, PSH | ACK, client_hello(b"tcp-opts.example.com"), ))
T.append(eth(GW, HS, 0x0800, ip4("192.168.1.10", "34.0.1.9", 6, tcp(43005, 443, PSH | ACK, client_hello(b"tcp-doff8.example.com"), doff=8))))
add("disc_tls.pcap", seq(T))

# ---- 10. aggregation / ordering -------------------------------------------
A = []
t = T0
LH = "192.168.1.10"
AGG = []


def agg(ts, f):
    AGG.append((ts, f))


agg(T0 + 5, frame_tcp(H, GW, LH, "20.0.0.1", 40000, 443, SYN, b""))
agg(T0 + 1, frame_tcp(H, GW, LH, "20.0.0.1", 40001, 443, PSH | ACK, b"a" * 100))               # out of time order: first_ts = min
agg(T0 + 9, frame_tcp(GW, H, "20.0.0.1", LH, 443, 40000, PSH | ACK, b"b" * 500))
agg(T0 + 2, frame_tcp(GW, H, "20.0.0.1", LH, 443, 40001, ACK, b""))
agg(T0 + 3, frame_tcp(H, GW, LH, "20.0.0.1", 40001, 443, PSH | ACK, b"c" * 10))                 # same flow again (flows counts 5-tuples)
agg(T0 + 3, frame_udp(H, GW, LH, "20.0.0.1", 40001, 443, b"quic"))                              # udp is a separate key
agg(T0 + 4, frame_udp(GW, H, "20.0.0.1", LH, 443, 40001, b"quic-reply" * 20))
for i in range(6):                                                                              # ties: equal byte totals keep insertion order
    agg(T0 + 10 + i, frame_tcp(H, GW, LH, f"20.0.1.{i}", 40100 + i, 80, PSH | ACK, b"z" * 50))
for i in range(4):
    agg(T0 + 20 + i, frame_tcp(GW, H, f"20.0.2.{i}", LH, 80, 40200 + i, PSH | ACK, b"z" * (10 * (4 - i))))
agg(T0 + 30, frame_tcp(H, GW, LH, "20.0.3.1", 40300, 25, SYN, b"", total=0))                   # IP len 0 -> bytes 0
agg(T0 + 31, frame_tcp(H, GW, "8.8.8.8", "1.1.1.1", 1, 2, SYN))                                # public <-> public
agg(T0 + 32, frame_tcp(H, GW, "10.0.0.1", "10.0.0.2", 1, 2, SYN))                              # private <-> private
agg(T0 + 33, frame_udp(H, GW, "10.0.0.1", "239.1.1.1", 1, 2, b"x"))                            # multicast
agg(T0 + 34, eth(GW, H, 0x0800, ip4(LH, "20.0.4.1", 1, b"\x08\x00" + b"\x00" * 6)))            # ICMP
agg(T0 + 35, frame_tcp(H, GW, LH, "20.0.5.1", 40400, 443, SYN, b"p" * 1400))
agg(T0 + 36, frame_tcp(H, GW, "172.20.9.9", "20.0.5.1", 40401, 443, SYN, b"p" * 10))           # second local host, same remote: flows=2
agg(T0 + 37, frame_tcp(H, GW, "100.64.3.3", "20.0.5.1", 40402, 443, SYN, b"p" * 10))           # CGNAT local: neither side private -> ignored
agg(T0 + 38, frame_tcp(H, GW, "192.0.0.9", "20.0.5.1", 40403, 443, SYN, b"p" * 10))            # 192.0.0.9: global, not private
add("disc_agg.pcap", AGG)

# ---- 11. > 2000 endpoints --------------------------------------------------
big = []
for i in range(2100):
    big.append(frame_tcp(H, GW, LH, f"44.{(i >> 8) + 1}.{i & 255}.1", 50000, 443, SYN, b"x" * (i % 3)))
add("disc_big.pcap", seq(big, step=0.001))

# ---- 12. fuzz ---------------------------------------------------------------
rng = random.Random(20240601)
seed_dns = [
    dns_msg("www.example.com", [a_rr("52.0.0.1")]),
    dns_msg("c.example.com", [dns_rr(dns_name("", ptr_to=12), 5, dns_name("t.example.net")), a_rr("52.0.0.2", dns_name("t.example.net"))]),
    dns_msg("m.example.com", [a_rr("52.0.0.3")], ns=[dns_rr(dns_name("", ptr_to=12), 15, b"\x00\x0a" + dns_name("mail.example.com"))],
            ar=[dns_rr(b"\x00", 41, b"")]),
    dns_msg("s.example.com", [a_rr("52.0.0.4"), a_rr("52.0.0.5")], ns=[dns_rr(dns_name("", ptr_to=12), 6, dns_name("ns1.example.com") + dns_name("h.example.com") + struct.pack("!IIIII", 1, 2, 3, 4, 5))]),
    dns_msg("t.example.com", [a_rr("52.0.0.6")], ar=[dns_rr(dns_name("", ptr_to=12), 16, b"\x03abc\x02de"), dns_rr(dns_name("", ptr_to=12), 33, struct.pack("!HHH", 1, 2, 3) + dns_name("x.example.com"))]),
    dns_msg("many.example.com", [a_rr(f"52.0.0.{i}") for i in range(7, 14)]),
]
fz = [frame_tcp(H, GW, "192.168.1.10", f"52.0.0.{i}", 40000 + i, 443, SYN) for i in range(0, 256)]
for k in range(480):
    base = seed_dns[k % len(seed_dns)]
    payload = base if k < len(seed_dns) else mutate(rng, base)
    if k > 300 and rng.random() < 0.5:
        payload = mutate(rng, payload)
    fz.append(frame_udp(GW, H, f"9.9.{k // 250}.{k % 250 + 1}", "192.168.1.10", 53, 33000 + k, payload))
add("disc_fuzz_dns.pcap", seq(fz))

seed_dhcp = [
    dhcp_pkt(2, CL1, [(53, b"\x02"), (54, b"\x01\x02\x03\x04"), (1, b"\xff\xff\xff\x00")], yi="10.1.1.5"),
    dhcp_pkt(2, CL1, [(53, b"\x05"), (12, b"srv-name")]),
    dhcp_pkt(1, CL2, [(53, b"\x03"), (12, b"client-host"), (55, b"\x01\x03\x06")]),
    dhcp_pkt(1, CL3, [(53, b"\x01"), (12, b"another-host")], hln=6),
]
fd = []
for k in range(160):
    base = seed_dhcp[k % len(seed_dhcp)]
    payload = base if k < len(seed_dhcp) else mutate(rng, base)
    if k % 3 == 0 and k >= len(seed_dhcp):
        payload = mutate(rng, payload)
    sm = f"00:dd:00:00:{k >> 8:02x}:{k & 255:02x}"
    fd.append(frame_udp(sm, BC, f"10.77.{k >> 8}.{k & 255}", f"10.77.{k >> 8}.250", 67 if k % 2 else 68, 68 if k % 2 else 67, payload))
    if k % 4 == 1:
        fd.append(frame_tcp(sm, BC, f"10.77.{k >> 8}.{k & 255}", "10.77.0.250", 4000 + k, 80, SYN))
add("disc_fuzz_dhcp.pcap", seq(fd))

# ---- 13. mixed capture in several container formats ------------------------
mixed = []
mixed.append(lldp_frame("aa:bb:cc:00:10:01", lldp_pdu(sys_name=b"mixed-sw", caps=(0x0014, 0x0004))))
mixed.append(cdp_frame("aa:bb:cc:00:10:02", device_id=b"mixed-cdp"))
mixed.append(eth(BC, GW, 0x0806, arp(2, GW, "192.168.9.1", "00:00:00:00:00:00", "192.168.9.2")))
for i, p in enumerate(PUBLICS):
    mixed.append(frame_tcp(H1, GW, "192.168.9.10", p, 40000 + i, 443, SYN, client_hello(f"site{i}.example.org".encode()), ttl=64))
    mixed.append(frame_tcp(GW, H1, p, "192.168.9.10", 443, 40000 + i, SYN | ACK, ttl=55))
mixed.append(frame_udp(H1, GW, "192.168.9.10", "8.8.8.8", 5000, 53, dns_q("site0.example.org")))
mixed.append(frame_udp(GW, H1, "8.8.8.8", "192.168.9.10", 53, 5000, dns_msg("site0.example.org", [a_rr("8.8.8.8")])))
mixed.append(frame_udp(DHCPS, H1, "192.168.9.1", "192.168.9.10", 67, 68, dhcp_pkt(2, H1, [(53, b"\x05")])))
mixed.append(frame_udp(H1, BC, "0.0.0.0", "255.255.255.255", 68, 67, dhcp_pkt(1, H1, [(53, b"\x03"), (12, b"mixed-host")])))
add("disc_mixed_be.pcap", seq(mixed, start=T0 + 0.123456), endian=">")
add("disc_mixed_nano.pcap", seq(mixed, start=T0 + 0.123456789), nano=True)
add("disc_mixed.pcapng", seq(mixed, start=T0 + 0.123456))
add("disc_mixed_be.pcapng", seq(mixed, start=T0 + 0.123456), le=False)
add("disc_mixed_ns.pcapng", seq(mixed, start=T0 + 0.123456789), tsresol=9)
add("disc_mixed_ms.pcapng", seq(mixed, start=T0 + 0.123), tsresol=3)

# ---- 14. broken containers -------------------------------------------------
(FIX / "disc_garbage.pcap").write_bytes(bytes(random.Random(5).randrange(256) for _ in range(300)))
(FIX / "disc_empty.pcap").write_bytes(b"")
(FIX / "disc_shorthdr.pcap").write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 8)
(FIX / "disc_badmagic.pcapng").write_bytes(b"\x0a\x0d\x0d\x0b" + b"\x00" * 40)
(FIX / "disc_nopackets.pcap").write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
good = (FIX / "disc_mixed.pcapng").read_bytes()
(FIX / "disc_pcapng_noidb.pcapng").write_bytes(good[:good.index(struct.pack("<I", 1), 28)] if False else good[:28])  # SHB only
for n in ("disc_garbage.pcap", "disc_empty.pcap", "disc_shorthdr.pcap", "disc_badmagic.pcapng", "disc_nopackets.pcap", "disc_pcapng_noidb.pcapng"):
    FILES[n] = FIX / n

# existing captures
for n in ("sample.pcap", "sample.pcapng"):
    FILES[n] = TESTS / n


# ================================================================ run python
def num(x):
    return float(x) if not isinstance(x, (int, float)) else x


def norm(rows):
    out = []
    for r in rows:
        r = dict(r)
        for k in ("first_ts", "last_ts", "first_seen_ts", "last_seen_ts"):
            if r.get(k) is not None:
                r[k] = float(r[k])
        out.append(r)
    return out


ref = {"python": platform.python_version(), "files": {}}
for name in sorted(FILES):
    data = FILES[name].read_bytes()
    ref["files"][name] = {"discover": norm(discover_devices(data)), "endpoints": norm(extract_endpoints(data))}

# helper-level vectors ---------------------------------------------------------
ips = BOUND + RANDOM_IPS + ["not-an-ip", "1.2.3", "01.2.3.4"][:0]
ref["ip_class"] = [[ip, _is_private(ip), _is_public(ip)] for ip in ips]

vr = random.Random(99)
sni_seeds = [h for h in hellos] + [client_hello(b"fuzz.example.com", ext_before=EXT_SUPPORTED_GROUPS)]
sni_vec = []
for i in range(1200):
    base = sni_seeds[i % len(sni_seeds)]
    p = base if i < len(sni_seeds) else mutate(vr, base)
    if i % 2:
        p = mutate(vr, p)
    sni_vec.append([p.hex(), parse_sni(p)])
ref["parse_sni"] = sni_vec

lldp_seeds = [f[14:] for f in lldp[:9]] + [lldp_pdu(sys_name=b"fuzz", sys_desc=b"d" * 150, port_desc=b"pd", caps=(0x1c, 0x14))]
lv = []
for i in range(1200):
    base = lldp_seeds[i % len(lldp_seeds)]
    p = base if i < len(lldp_seeds) else mutate(vr, base)
    if i % 2:
        p = mutate(vr, p)
    lv.append([p.hex(), parse_lldp(p)])
ref["parse_lldp"] = lv

cdp_seeds = [f for f in cdp[:10]] + [cdp_frame("aa:bb:cc:99:00:01", device_id=b"fuzz", platform=b"P" * 30)]
cv = []
for i in range(1200):
    base = cdp_seeds[i % len(cdp_seeds)]
    p = base if i < len(cdp_seeds) else mutate(vr, base)
    if i % 2:
        p = mutate(vr, p)
    cv.append([p.hex(), parse_cdp(p)])
ref["parse_cdp"] = cv

(FIX / "discovery_reference.json").write_text(json.dumps(ref, indent=1, sort_keys=True, ensure_ascii=True) + "\n")
n_dev = sum(len(v["discover"]) for v in ref["files"].values())
n_ep = sum(len(v["endpoints"]) for v in ref["files"].values())
print(f"wrote {len(ref['files'])} files; {n_dev} device rows, {n_ep} endpoint rows; "
      f"{len(ref['parse_sni'])}+{len(ref['parse_lldp'])}+{len(ref['parse_cdp'])} parser vectors")
