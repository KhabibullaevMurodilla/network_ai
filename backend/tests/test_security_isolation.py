"""Multi-tenant isolation tests focused on the bulk/list and privacy
(export/erase) endpoints -- test_security_auth.py already covers by-ID
IDOR attempts; this file covers the two things that would be the most
damaging if they leaked: a listing endpoint silently including another
tenant's rows, and /privacy/erase (irreversible) touching the wrong
tenant's data."""
import time

import jwt
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from tests.fake_db import FakeDB

JWT_SECRET = "test-jwt-secret-not-real"
TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"
USER_A_ADMIN = "aaaa-admin"
USER_B_ADMIN = "bbbb-admin"


def make_token(sub: str) -> str:
    return jwt.encode({"sub": sub, "aud": "authenticated", "exp": int(time.time()) + 3600}, JWT_SECRET, algorithm="HS256")


@pytest.fixture
def db():
    fake = FakeDB()
    fake.seed("profiles", [
        {"id": USER_A_ADMIN, "tenant_id": TENANT_A, "role": "admin"},
        {"id": USER_B_ADMIN, "tenant_id": TENANT_B, "role": "admin"},
    ])
    fake.seed("tenants", [
        {"id": TENANT_A, "name": "tenant-a"},
        {"id": TENANT_B, "name": "tenant-b"},
    ])
    fake.seed("telemetry_flows", [
        {"id": 1, "tenant_id": TENANT_A, "src_ip": "10.0.0.1"},
        {"id": 2, "tenant_id": TENANT_B, "src_ip": "10.0.0.2"},
    ])
    fake.seed("anomaly_events", [
        {"id": 1, "tenant_id": TENANT_A, "severity": "high", "detector": "ECOD"},
        {"id": 2, "tenant_id": TENANT_B, "severity": "critical", "detector": "ECOD"},
    ])
    fake.seed("ot_protocol_events", [
        {"id": 1, "tenant_id": TENANT_A, "src_ip": "10.1.0.1", "function_name": "ReadHoldingRegisters"},
        {"id": 2, "tenant_id": TENANT_B, "src_ip": "10.1.0.2", "function_name": "WriteSingleRegister"},
    ])
    fake.seed("incidents", [
        {"id": "inc-a", "tenant_id": TENANT_A, "title": "tenant A incident", "status": "open"},
        {"id": "inc-b", "tenant_id": TENANT_B, "title": "tenant B incident", "status": "open"},
    ])
    fake.seed("response_actions", [
        {"id": "ra-a", "tenant_id": TENANT_A, "target_url": "https://a.example.com", "secret": "secret-a"},
        {"id": "ra-b", "tenant_id": TENANT_B, "target_url": "https://b.example.com", "secret": "secret-b"},
    ])
    fake.seed("webhook_configs", [
        {"id": "wh-a", "tenant_id": TENANT_A, "url": "https://hook-a.example.com"},
        {"id": "wh-b", "tenant_id": TENANT_B, "url": "https://hook-b.example.com"},
    ])
    fake.seed("api_keys", [
        {"id": "key-a", "tenant_id": TENANT_A, "label": "a-key", "scope": "ingest", "created_at": "x", "last_used_at": None, "revoked_at": None},
        {"id": "key-b", "tenant_id": TENANT_B, "label": "b-key", "scope": "ingest", "created_at": "x", "last_used_at": None, "revoked_at": None},
    ])
    fake.seed("audit_log", [
        {"id": 1, "tenant_id": TENANT_A, "actor": "x", "action": "x", "created_at": "x"},
        {"id": 2, "tenant_id": TENANT_B, "actor": "x", "action": "x", "created_at": "x"},
    ])

    targets = [
        "app.core.auth.get_db",
        "app.routers.dashboard.get_db",
        "app.routers.incidents.get_db",
        "app.routers.privacy.get_db",
        "app.core.audit.get_db",
    ]
    patches = [patch(t, return_value=fake) for t in targets]
    for p in patches:
        p.start()
    try:
        yield fake
    finally:
        for p in patches:
            p.stop()


@pytest.fixture
def client(db):
    return TestClient(app)


def auth(sub: str) -> dict:
    return {"Authorization": f"Bearer {make_token(sub)}"}


# --- listing endpoints never leak another tenant's rows --------------------

def test_recent_anomalies_scoped_to_own_tenant(client, db):
    r = client.get("/dashboard/anomalies/recent", headers=auth(USER_A_ADMIN))
    assert r.status_code == 200
    ids = {row["id"] for row in r.json()}
    assert ids == {1}  # tenant A's row only, never tenant B's id=2


def test_recent_ot_events_scoped_to_own_tenant(client, db):
    r = client.get("/dashboard/ot-events/recent", headers=auth(USER_B_ADMIN))
    assert r.status_code == 200
    ids = {row["id"] for row in r.json()}
    assert ids == {2}  # tenant B's row only


def test_incident_list_scoped_to_own_tenant(client, db):
    r = client.get("/dashboard/incidents", headers=auth(USER_A_ADMIN))
    assert r.status_code == 200
    titles = {row["title"] for row in r.json()}
    assert titles == {"tenant A incident"}


# --- /privacy/export: completeness AND isolation ----------------------------

def test_export_includes_all_tenant_scoped_tables(client, db):
    """Regression test for the real gap found in review: incidents,
    response_actions, and ot_protocol_events were missing from the export
    entirely."""
    r = client.get("/privacy/export", headers=auth(USER_A_ADMIN))
    assert r.status_code == 200
    body = r.json()
    for key in ("telemetry_flows", "anomaly_events", "ot_protocol_events",
                "incidents", "response_actions", "webhook_configs", "api_keys", "audit_log"):
        assert key in body, f"export is missing '{key}' entirely"


def test_export_never_includes_another_tenants_rows(client, db):
    r = client.get("/privacy/export", headers=auth(USER_A_ADMIN))
    body = r.json()
    assert all(row["id"] != 2 for row in body["anomaly_events"])
    assert all(row["id"] != "inc-b" for row in body["incidents"])
    assert all(row["id"] != "ra-b" for row in body["response_actions"])
    assert all(row["id"] != "wh-b" for row in body["webhook_configs"])
    assert all(row["id"] != "key-b" for row in body["api_keys"])


# --- /privacy/erase: the one that would be catastrophic if wrong -----------

def test_erase_removes_every_scoped_table_for_own_tenant(client, db):
    r = client.delete("/privacy/erase", headers=auth(USER_A_ADMIN))
    assert r.status_code == 200
    for table in ("telemetry_flows", "anomaly_events", "ot_protocol_events",
                  "incidents", "response_actions", "webhook_configs", "api_keys", "audit_log"):
        remaining = db.table(table).eq("tenant_id", TENANT_A).execute().data
        assert remaining == [], f"erase left rows behind in '{table}'"
    assert db.table("tenants").eq("id", TENANT_A).execute().data == []
    assert db.table("profiles").eq("tenant_id", TENANT_A).execute().data == []


def test_erase_never_touches_another_tenants_data(client, db):
    """The single most damaging possible bug in this endpoint: tenant A
    requesting erasure must never delete so much as one row belonging to
    tenant B."""
    r = client.delete("/privacy/erase", headers=auth(USER_A_ADMIN))
    assert r.status_code == 200

    assert db.table("telemetry_flows").eq("tenant_id", TENANT_B).execute().data
    assert db.table("anomaly_events").eq("tenant_id", TENANT_B).execute().data
    assert db.table("ot_protocol_events").eq("tenant_id", TENANT_B).execute().data
    assert db.table("incidents").eq("tenant_id", TENANT_B).execute().data
    assert db.table("response_actions").eq("tenant_id", TENANT_B).execute().data
    assert db.table("webhook_configs").eq("tenant_id", TENANT_B).execute().data
    assert db.table("api_keys").eq("tenant_id", TENANT_B).execute().data
    assert db.table("tenants").eq("id", TENANT_B).execute().data
    assert db.table("profiles").eq("tenant_id", TENANT_B).execute().data


# --- v6.5-6.7 tables (devices / links / external endpoints) ------------------

def test_new_tables_are_exported_and_erased_for_own_tenant_only(client, db):
    for tname, extra in (("network_devices", {"device_key": "mac:aa"}), ("network_links", {"a_key": "x", "b_key": "y", "source": "lldp"}),
                         ("external_endpoints", {"remote_ip": "1.1.1.1", "remote_port": 443, "proto": "tcp"})):
        db.seed(tname, [{"id": f"{tname}-a", "tenant_id": TENANT_A, **extra}, {"id": f"{tname}-b", "tenant_id": TENANT_B, **extra}])
    body = client.get("/privacy/export", headers=auth(USER_A_ADMIN)).json()
    for tname in ("network_devices", "network_links", "external_endpoints"):
        assert [r["id"] for r in body[tname]] == [f"{tname}-a"]
    assert client.delete("/privacy/erase", headers=auth(USER_A_ADMIN)).status_code == 200
    for tname in ("network_devices", "network_links", "external_endpoints"):
        assert [r["id"] for r in db.table(tname).execute().data] == [f"{tname}-b"]
