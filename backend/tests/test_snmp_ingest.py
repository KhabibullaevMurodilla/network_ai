import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agent"))
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core import db as dbmod
from app.core.auth import hash_key, require_user
from tests.fake_db import FakeDB
import snmp_collector as sc

T = "t-snmp"


def _lab_report():
    # same lab as agent/tests/sim_data.py, built via the real collector code path
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agent", "tests"))
    from sim_data import lab_raw
    return sc.build_report("192.168.1.2", lab_raw(), now=1000.0)


@pytest.fixture
def env(monkeypatch):
    fake = FakeDB()
    import app.routers.ingest as ing, app.routers.dashboard as dash, app.core.auth as au, app.core.audit as aud
    for m in (ing, dash, au, aud):
        monkeypatch.setattr(m, "get_db", lambda: fake)
    fake.seed("api_keys", [{"id": "k1", "tenant_id": T, "key_hash": hash_key("good"), "scope": "ingest", "revoked_at": None},
                           {"id": "k2", "tenant_id": T, "key_hash": hash_key("readonly"), "scope": "read", "revoked_at": None}])
    app.dependency_overrides[require_user] = lambda: {"user_id": "u", "tenant_id": T, "role": "viewer", "focus": None}
    yield fake, TestClient(app)
    app.dependency_overrides.clear()


def test_snmp_report_round_trip_and_physical_map(env):
    fake, c = env
    r = c.post("/ingest/snmp", headers={"X-API-Key": "good"}, json=_lab_report())
    assert r.status_code == 200 and r.json()["links"] == 3 and r.json()["devices"] == 5
    again = c.post("/ingest/snmp", headers={"X-API-Key": "good"}, json=_lab_report()).json()   # idempotent
    assert len(fake._store["network_links"]) == 3 and len(fake._store["network_devices"]) == 5
    ph = c.get("/dashboard/physical").json()
    ids = {n["id"] for n in ph["nodes"]}
    assert "mac:00:1b:2c:3d:4e:5f" in ids and "mac:00:aa:bb:cc:00:02" in ids
    assert {(l["source"], l["a_port"]) for l in ph["links"]} == {("lldp", "Gi1/0/1"), ("lldp", "Gi1/0/4"), ("fdb", "Gi1/0/2")}


def test_requires_ingest_key(env):
    _, c = env
    assert c.post("/ingest/snmp", json=_lab_report()).status_code == 422
    assert c.post("/ingest/snmp", headers={"X-API-Key": "nope"}, json=_lab_report()).status_code == 401
    assert c.post("/ingest/snmp", headers={"X-API-Key": "readonly"}, json=_lab_report()).status_code == 403


def test_rejects_malformed_payloads(env):
    _, c = env
    h = {"X-API-Key": "good"}
    bad_key = {"devices": [{"device_key": "<script>"}], "links": []}
    assert c.post("/ingest/snmp", headers=h, json=bad_key).status_code == 422
    bad_ip = {"devices": [{"device_key": "ip:1.1.1.1", "ip": "999.1.1.1"}], "links": []}
    assert c.post("/ingest/snmp", headers=h, json=bad_ip).status_code == 422
    bad_src = {"devices": [], "links": [{"a_key": "ip:1.1.1.1", "b_key": "ip:2.2.2.2", "source": "magic"}]}
    assert c.post("/ingest/snmp", headers=h, json=bad_src).status_code == 422


def test_tenant_isolation_of_links(env):
    fake, c = env
    c.post("/ingest/snmp", headers={"X-API-Key": "good"}, json=_lab_report())
    fake.seed("network_links", [{"tenant_id": "other", "a_key": "mac:aa:aa:aa:aa:aa:aa", "a_port": "x", "b_key": "mac:bb:bb:bb:bb:bb:bb", "source": "lldp", "last_seen": "2026-01-01"}])
    ph = c.get("/dashboard/physical").json()
    assert all(l["a_key"] != "mac:aa:aa:aa:aa:aa:aa" for l in ph["links"])


def test_store_links_dedups_both_directions(env):
    fake, c = env
    link = {"a_key": "mac:00:1b:00:00:00:01", "a_port": "Gi1", "b_key": "mac:00:aa:00:00:00:02", "b_port": "Gi24", "source": "lldp"}
    rev = {"a_key": link["b_key"], "a_port": "Gi24", "b_key": link["a_key"], "b_port": "Gi1", "source": "lldp"}
    for l in (link, rev):
        r = c.post("/ingest/snmp", headers={"X-API-Key": "good"}, json={"devices": [], "links": [l]})
        assert r.status_code == 200
    assert len(fake._store["network_links"]) == 1
