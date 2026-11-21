"""Passive discovery on synthetic frames built byte-for-byte (not a real
network capture): proves the parsing/inference logic, not field accuracy."""
import io, struct
import dpkt
from app.ingestion.discovery import discover_devices, parse_lldp

GW, PC, SRV = "aa:bb:cc:00:00:01", "02:11:22:33:44:55", "aa:bb:cc:00:00:09"


def mb(m): return bytes(int(x, 16) for x in m.split(":"))
def ipb(s): return bytes(int(x) for x in s.split("."))


def ip_frame(smac, dmac, sip, dip, l4, proto, ttl=64):
    ip = dpkt.ip.IP(src=ipb(sip), dst=ipb(dip), p=proto, ttl=ttl, data=l4)
    ip.len = len(bytes(ip))
    return bytes(dpkt.ethernet.Ethernet(src=mb(smac), dst=mb(dmac), type=dpkt.ethernet.ETH_TYPE_IP, data=bytes(ip)))


def tcp(sport, dport, flags):
    return dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags)


def udp(sport, dport, data=b"x"):
    u = dpkt.udp.UDP(sport=sport, dport=dport, data=data); u.ulen = 8 + len(data); return u


def arp(smac, sip, op=2):
    a = dpkt.arp.ARP(sha=mb(smac), spa=ipb(sip), tha=mb("00:00:00:00:00:00"), tpa=ipb("192.168.1.1"), op=op)
    return bytes(dpkt.ethernet.Ethernet(src=mb(smac), dst=mb("ff:ff:ff:ff:ff:ff"), type=dpkt.ethernet.ETH_TYPE_ARP, data=bytes(a)))


def lldp_frame(smac, sysname, enabled):
    def tlv(t, v): return struct.pack("!H", (t << 9) | len(v)) + v
    body = (tlv(1, b"\x04" + mb(smac)) + tlv(2, b"\x05" + b"Gi1/0/7") + tlv(3, b"\x00\x78")
            + tlv(5, sysname.encode()) + tlv(7, struct.pack("!HH", 0x14, enabled)) + tlv(0, b""))
    return mb("01:80:c2:00:00:0e") + mb(smac) + b"\x88\xcc" + body


def cdp_frame(smac, devid, caps):
    def tlv(t, v): return struct.pack("!HH", t, len(v) + 4) + v
    cdp = b"\x02\xb4\x00\x00" + tlv(1, devid.encode()) + tlv(3, b"Fa0/3") + tlv(4, struct.pack("!I", caps)) + tlv(6, b"cisco WS-C2960")
    llc = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
    payload = llc + cdp
    return mb("01:00:0c:cc:cc:cc") + mb(smac) + struct.pack("!H", len(payload)) + payload


def make_pcap(frames):
    buf = io.BytesIO(); w = dpkt.pcap.Writer(buf)
    for i, f in enumerate(frames):
        w.writepkt(f, ts=1000.0 + i)
    return buf.getvalue()


def by_key(devs): return {d["device_key"]: d for d in devs}


def test_gateway_inferred_from_next_hop_mac():
    frames = [arp(GW, "192.168.1.1"), arp(PC, "192.168.1.50")]
    for i in range(6):
        frames.append(ip_frame(PC, GW, "192.168.1.50", f"8.8.{i}.8", tcp(40000 + i, 443, dpkt.tcp.TH_SYN), 6, ttl=128))
    devs = by_key(discover_devices(make_pcap(frames)))
    gw = devs["mac:" + GW]
    assert gw["role"] == "gateway" and gw["ip"] == "192.168.1.1"
    assert gw["confidence"] in ("medium", "high")
    pc = devs["mac:" + PC]
    assert pc["role"] == "client" and "Windows" in pc["os_hint"] and pc["mac_randomized"] is True


def test_lldp_switch_and_cdp_router():
    sw = "00:1b:2c:3d:4e:5f"; rt = "00:aa:bb:cc:dd:ee"
    devs = by_key(discover_devices(make_pcap([lldp_frame(sw, "core-sw1", 0x04), cdp_frame(rt, "edge-rt1", 0x01)])))
    s, r = devs["mac:" + sw], devs["mac:" + rt]
    assert s["role"] == "switch" and s["hostname"] == "core-sw1" and s["confidence"] == "high"
    assert any("Gi1/0/7" in e for e in s["evidence"])
    assert r["role"] == "router" and r["hostname"] == "edge-rt1" and r["confidence"] == "high"


def test_server_detected_from_syn_ack_with_ports():
    frames = [arp(SRV, "192.168.1.20"), arp(PC, "192.168.1.50")]
    frames.append(ip_frame(SRV, PC, "192.168.1.20", "192.168.1.50", tcp(443, 50000, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK), 6))
    frames.append(ip_frame(SRV, PC, "192.168.1.20", "192.168.1.51", tcp(443, 50001, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK), 6))
    d = by_key(discover_devices(make_pcap(frames)))["mac:" + SRV]
    assert d["role"] == "server" and 443 in d["services"]


def test_dns_server_tag():
    frames = [arp(SRV, "192.168.1.2")]
    frames.append(ip_frame(PC, SRV, "192.168.1.50", "192.168.1.2", udp(53000, 53), 17))
    d = by_key(discover_devices(make_pcap(frames)))["mac:" + SRV]
    assert "dns_server" in ({d["role"]} | set(d["tags"]))


def test_router_multiple_private_ips_not_assigned_to_clients():
    # gateway forwards for two routed private subnets: its MAC must not become their identity
    frames = [arp(GW, "192.168.1.1")]
    for i in range(4):
        frames.append(ip_frame(PC, GW, "192.168.1.50", f"1.1.{i}.1", tcp(40000, 80, dpkt.tcp.TH_SYN), 6))
    frames.append(ip_frame(GW, PC, "10.9.0.5", "192.168.1.50", udp(1, 2), 17))
    frames.append(ip_frame(GW, PC, "10.9.0.6", "192.168.1.50", udp(1, 2), 17))
    devs = by_key(discover_devices(make_pcap(frames)))
    assert devs["mac:" + GW]["role"] == "gateway"
    assert "ip:10.9.0.5" in devs and "ip:10.9.0.6" in devs  # kept as IP-only, MAC unknown


def test_garbage_and_truncated_never_raise():
    assert discover_devices(b"not a pcap") == []
    good = make_pcap([arp(PC, "192.168.1.50")])
    assert isinstance(discover_devices(good[:-5]), list)


def test_lldp_parser_rejects_empty():
    assert parse_lldp(b"") is None
