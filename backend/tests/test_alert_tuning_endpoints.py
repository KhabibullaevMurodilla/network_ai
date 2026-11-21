"""Endpoint-level tests for v6.3 self-service alert tuning: entity
suppression CRUD and the tenant-wide alert_min_severity setting. The gate
behavior itself (suppressed/below-floor events never reaching a webhook)
is covered in test_alert_channels.py against core.webhooks directly; this
file covers the HTTP surface -- role enforcement, validation, tenant
scoping -- a tenant admin/analyst actually uses."""
from unittest.mock import patch

import pytest
import jwt
from fastapi.testclient import TestClient

from app.main import app
from tests.fake_db import FakeDB

JWT_SECRET = "test-jwt-secret-not-real"
TENANT_A = "55555555-5555-5555-5555-555555555555"
TENANT_B = "66666666-6666-6666-6666-666666666666"
ANALYST_A = "aaaaaaaa-0000-0000-0000-000000000001"
VIEWER_A = "aaaaaaaa-0000-0000-0000-000000000002"
ADMIN_A = "aaaaaaaa-0000-0000-0000-000000000003"
ANALYST_B = "bbbbbbbb-0000-0000-0000-000000000001"


def make_token(sub: str) -> str:
    return jwt.encode({"sub": sub, "aud": "authenticated", "exp": 9999999999}, JWT_SECRET, algorithm="HS256")


def auth(sub: str) -> dict:
    return {"Authorization": f"Bearer {make_token(sub)}"}


@pytest.fixture
def db():
    fake = FakeDB()
    fake.seed("profiles", [
        {"id": ANALYST_A, "tenant_id": TENANT_A, "role": "analyst", "email": "a@x.com"},
        {"id": VIEWER_A, "tenant_id": TENANT_A, "role": "viewer", "email": "v@x.com"},
        {"id": ADMIN_A, "tenant_id": TENANT_A, "role": "admin", "email": "ad@x.com"},
        {"id": ANALYST_B, "tenant_id": TENANT_B, "role": "analyst", "email": "b@x.com"},
    ])
    fake.seed("tenants", [
        {"id": TENANT_A, "alert_min_severity": "low"},
        {"id": TENANT_B, "alert_min_severity": "low"},
    ])
    targets = [
        "app.core.auth.get_db", "app.routers.dashboard.get_db", "app.routers.tenants.get_db",
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


def test_analyst_can_create_suppression(client, db):
    r = client.post("/dashboard/suppressions", headers=auth(ANALYST_A), json={"src_ip": "10.0.0.5", "reason": "known scanner"})
    assert r.status_code == 200
    assert r.json()["src_ip"] == "10.0.0.5"


def test_viewer_cannot_create_suppression(client, db):
    r = client.post("/dashboard/suppressions", headers=auth(VIEWER_A), json={"src_ip": "10.0.0.5"})
    assert r.status_code == 403


def test_invalid_ip_rejected(client, db):
    r = client.post("/dashboard/suppressions", headers=auth(ANALYST_A), json={"src_ip": "not-an-ip"})
    assert r.status_code == 400


def test_duplicate_suppression_rejected_cleanly(client, db):
    client.post("/dashboard/suppressions", headers=auth(ANALYST_A), json={"src_ip": "10.0.0.7"})
    r = client.post("/dashboard/suppressions", headers=auth(ANALYST_A), json={"src_ip": "10.0.0.7"})
    assert r.status_code == 409


def test_tenant_b_cannot_see_tenant_a_suppressions(client, db):
    client.post("/dashboard/suppressions", headers=auth(ANALYST_A), json={"src_ip": "10.0.0.8"})
    r = client.get("/dashboard/suppressions", headers=auth(ANALYST_B))
    assert r.status_code == 200
    assert r.json() == []


def test_tenant_b_cannot_delete_tenant_a_suppression(client, db):
    created = client.post("/dashboard/suppressions", headers=auth(ANALYST_A), json={"src_ip": "10.0.0.9"}).json()
    client.delete(f"/dashboard/suppressions/{created['id']}", headers=auth(ANALYST_B))
    still_there = client.get("/dashboard/suppressions", headers=auth(ANALYST_A)).json()
    assert any(s["src_ip"] == "10.0.0.9" for s in still_there)


def test_owner_or_admin_can_update_alert_floor(client, db):
    r = client.patch("/tenants/me/alert-settings", headers=auth(ADMIN_A), json={"alert_min_severity": "high"})
    assert r.status_code == 200
    assert r.json()["alert_min_severity"] == "high"


def test_analyst_cannot_update_alert_floor(client, db):
    r = client.patch("/tenants/me/alert-settings", headers=auth(ANALYST_A), json={"alert_min_severity": "high"})
    assert r.status_code == 403


def test_invalid_severity_value_rejected(client, db):
    r = client.patch("/tenants/me/alert-settings", headers=auth(ADMIN_A), json={"alert_min_severity": "extreme"})
    assert r.status_code == 400
