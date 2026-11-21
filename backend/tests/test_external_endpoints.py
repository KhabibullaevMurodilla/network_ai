import struct, dpkt
from fastapi.testclient import TestClient
from app.main import app
from app.core.auth import require_user
from app.core.external import store_endpoints
from app.ingestion.endpoints import extract_endpoints, parse_sni
from tests.fake_db import FakeDB
import tests.test_discovery as t

PCIP, GWIP = "192.168.1.50", "192.168.1.1"
T = "t-ext"


def client_hello(host: str) -> bytes:
    name = host.encode()
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    ext = struct.pack("!HH", 0, len(sni)) + sni
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def tcp_payload(sport, dport, payload, flags=dpkt.tcp.TH_ACK):
    return dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=payload)


def dns_response(qname, answer_ip):
    d = dpkt.dns.DNS(id=1, qr=dpkt.dns.DNS_R, opcode=dpkt.dns.DNS_QUERY, rcode=0,
                     qd=[dpkt.dns.DNS.Q(name=qname, type=dpkt.dns.DNS_A)],
                     an=[dpkt.dns.DNS.RR(name=qname, type=dpkt.dns.DNS_A, ttl=60, ip=bytes(int(x) for x in answer_ip.split(".")))])
    return bytes(d)


def capture():
    frames = [
        # DNS answer for example.org -> 93.184.216.34 (from public resolver 8.8.8.8, to the PC)
        t.ip_frame(t.GW, t.PC, "8.8.8.8", PCIP, t.udp(53, 40000, dns_response("example.org", "93.184.216.34")), 17),
        # TLS to 93.184.216.34:443 with SNI cdn.example.org, 2 distinct local ports -> 2 flows
        t.ip_frame(t.PC, t.GW, PCIP, "93.184.216.34", tcp_payload(50001, 443, client_hello("cdn.example.org")), 6),
        t.ip_frame(t.PC, t.GW, PCIP, "93.184.216.34", tcp_payload(50002, 443, b"x" * 200), 6),
        t.ip_frame(t.GW, t.PC, "93.184.216.34", PCIP, tcp_payload(443, 50001, b"y" * 1000), 6),
        # private-to-private and multicast must be ignored
        t.ip_frame(t.PC, t.GW, PCIP, "192.168.1.9", tcp_payload(50003, 80, b"z"), 6),
        t.ip_frame(t.PC, t.GW, PCIP, "224.0.0.251", t.udp(5353, 5353), 17),
    ]
    return t.make_pcap(frames)


def test_parse_sni_and_garbage():
    assert parse_sni(client_hello("Cdn.Example.org")) == "cdn.example.org"
    assert parse_sni(b"") is None and parse_sni(b"\x16\x03\x01\x00\x05\x01") is None
    assert parse_sni(client_hello("bad name!")) is None


def test_extract_aggregates_names_bytes_and_flows():
    rows = {(r["remote_ip"], r["remote_port"], r["proto"]): r for r in extract_endpoints(capture())}
    r = rows[("93.184.216.34", 443, "tcp")]
    assert r["flows"] == 2 and r["packets"] == 3
    assert r["bytes_in"] > 1000 and r["bytes_out"] > 200
    assert set(r["hostnames"]) == {"example.org", "cdn.example.org"}
    assert ("192.168.1.9", 80, "tcp") not in rows and not any(k[0] == "224.0.0.251" for k in rows)
    dns = rows[("8.8.8.8", 53, "udp")]
    assert dns["bytes_in"] > 0


def test_garbage_capture_never_raises():
    assert extract_endpoints(b"junk") == []
    assert isinstance(extract_endpoints(capture()[:-7]), list)


def _env(monkeypatch):
    fake = FakeDB()
    import app.routers.dashboard as dash
    monkeypatch.setattr(dash, "get_db", lambda: fake)
    app.dependency_overrides[require_user] = lambda: {"user_id": "u", "tenant_id": T, "role": "viewer", "focus": None}
    return fake, TestClient(app)


def test_store_is_additive_and_api_ranks_and_counts_flagged(monkeypatch):
    fake, c = _env(monkeypatch)
    rows = extract_endpoints(capture())
    store_endpoints(fake, T, rows); store_endpoints(fake, T, rows)
    row = next(r for r in fake._store["external_endpoints"] if r["remote_ip"] == "93.184.216.34")
    assert row["flows"] == 4 and set(row["hostnames"]) == {"example.org", "cdn.example.org"}
    # one flagged flow towards 93.184.216.34
    fake.seed("telemetry_flows", [{"id": 7, "tenant_id": T, "src_ip": PCIP, "dst_ip": "93.184.216.34"},
                                  {"id": 8, "tenant_id": T, "src_ip": PCIP, "dst_ip": "8.8.8.8"}])
    fake.seed("anomaly_events", [{"tenant_id": T, "flow_id": 7, "detector": "ECOD", "severity": "high", "is_anomaly": True},
                                 {"tenant_id": T, "flow_id": 8, "detector": "ECOD", "severity": None, "is_anomaly": False}])
    out = c.get("/dashboard/external").json()
    assert out[0]["remote_ip"] == "93.184.216.34" and out[0]["service"] == "https" and out[0]["flagged"] == 1
    assert [r["remote_ip"] for r in c.get("/dashboard/external?flagged_only=true").json()] == ["93.184.216.34"]
    assert c.get("/dashboard/external?sort=bogus").status_code == 422
    app.dependency_overrides.clear()


def test_external_is_tenant_scoped(monkeypatch):
    fake, c = _env(monkeypatch)
    store_endpoints(fake, "someone-else", extract_endpoints(capture()))
    assert c.get("/dashboard/external").json() == []
    app.dependency_overrides.clear()
