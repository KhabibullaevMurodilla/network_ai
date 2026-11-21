import io, dpkt
from fastapi.testclient import TestClient
from app.main import app
from app.core import db as dbmod
from app.core.devices import store_devices
from app.core.auth import require_user
from tests.fake_db import FakeDB
import tests.test_discovery as t

TENANT = "t-dev"


def _setup(monkeypatch):
    fake = FakeDB()
    monkeypatch.setattr(dbmod, "get_db", lambda: fake)
    import app.routers.dashboard as dash
    import app.routers.ingest as ing
    monkeypatch.setattr(dash, "get_db", lambda: fake)
    monkeypatch.setattr(ing, "get_db", lambda: fake)
    app.dependency_overrides[require_user] = lambda: {"user_id": "u", "tenant_id": TENANT, "role": "viewer", "focus": None}
    return fake


def _devs():
    frames = [t.arp(t.GW, "192.168.1.1")]
    for i in range(5):
        frames.append(t.ip_frame(t.PC, t.GW, "192.168.1.50", f"9.9.{i}.9", t.tcp(40000, 443, dpkt.tcp.TH_SYN), 6))
    return t.discover_devices(t.make_pcap(frames))


def test_store_merges_and_never_downgrades(monkeypatch):
    fake = _setup(monkeypatch)
    devs = _devs()
    assert store_devices(fake, TENANT, devs) == len(devs)
    n_rows = len(fake._store["network_devices"])
    # second pass with weaker info for the same device must not duplicate or downgrade
    weak = [dict(d, role="client", confidence="low", evidence=["x"]) for d in devs]
    store_devices(fake, TENANT, weak)
    rows = fake._store["network_devices"]
    assert len(rows) == n_rows
    gw = next(r for r in rows if r["device_key"] == "mac:" + t.GW)
    assert gw["role"] == "gateway" and gw["confidence"] in ("medium", "high")
    app.dependency_overrides.clear()


def test_devices_endpoint_tenant_scoped(monkeypatch):
    fake = _setup(monkeypatch)
    store_devices(fake, TENANT, _devs())
    store_devices(fake, "other-tenant", _devs())
    c = TestClient(app)
    r = c.get("/dashboard/devices")
    assert r.status_code == 200
    assert r.json() and all(d["device_key"].startswith(("mac:", "ip:")) for d in r.json())
    assert len(r.json()) == len([x for x in fake._store["network_devices"] if x["tenant_id"] == TENANT])
    assert len(c.get("/dashboard/devices?role=gateway").json()) == 1
    app.dependency_overrides.clear()


def test_topology_carries_role(monkeypatch):
    fake = _setup(monkeypatch)
    store_devices(fake, TENANT, _devs())
    fake.seed("telemetry_flows", [{"tenant_id": TENANT, "src_ip": "192.168.1.50", "dst_ip": "192.168.1.1", "proto": "TCP", "received_at": "2026-01-01T00:00:00"}])
    r = TestClient(app).get("/dashboard/topology").json()
    by = {n["id"]: n for n in r["nodes"]}
    assert by["192.168.1.1"]["role"] == "gateway" and by["192.168.1.50"]["role"] == "client"
    app.dependency_overrides.clear()
