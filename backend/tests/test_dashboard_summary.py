"""GET /dashboard/summary had zero test coverage before this file -- found
while building real screenshots for v6.3 (it crashed with
AttributeError: 'FakeResult' object has no attribute 'count' the first
time it was actually exercised against the FakeDB harness, because
select(..., count="exact") wasn't supported there). Fixed by adding real
count="exact" support to tests/fake_db.py rather than rewriting the
endpoint -- the real Supabase client supports it, so the fake should too."""
from unittest.mock import patch

import jwt
import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.fake_db import FakeDB

JWT_SECRET = "test-jwt-secret-not-real"
TENANT = "ff333333-3333-3333-3333-333333333333"
USER = "cc333333-3333-3333-3333-333333333333"


def auth() -> dict:
    token = jwt.encode({"sub": USER, "aud": "authenticated", "exp": 9999999999}, JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def db():
    fake = FakeDB()
    fake.seed("profiles", [{"id": USER, "tenant_id": TENANT, "role": "viewer", "email": "v@x.com"}])
    fake.seed("telemetry_flows", [{"tenant_id": TENANT} for _ in range(5)])
    fake.seed("anomaly_events", [
        {"tenant_id": TENANT, "detector": "ECOD", "is_anomaly": True, "severity": "high"},
        {"tenant_id": TENANT, "detector": "ECOD", "is_anomaly": True, "severity": "critical"},
        {"tenant_id": TENANT, "detector": "ECOD", "is_anomaly": False, "severity": None},
        {"tenant_id": TENANT, "detector": "IsolationForest", "is_anomaly": True, "severity": None},  # not ECOD -- must not be counted
    ])
    with patch("app.core.auth.get_db", return_value=fake), patch("app.routers.dashboard.get_db", return_value=fake):
        yield fake


@pytest.fixture
def client(db):
    return TestClient(app)


def test_summary_returns_real_counts(client, db):
    r = client.get("/dashboard/summary", headers=auth())
    assert r.status_code == 200
    body = r.json()
    assert body["total_flows"] == 5
    assert body["total_anomalies"] == 2  # ECOD + is_anomaly=True only
    assert body["critical_anomalies"] == 1
    assert body["tenant_id"] == TENANT
    assert body["role"] == "viewer"
    assert body["focus"] is None  # v6.4: onboarding not completed yet
    assert body["user_id"] == USER


def test_summary_requires_auth(client, db):
    r = client.get("/dashboard/summary")
    assert r.status_code in (401, 422)
