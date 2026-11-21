"""v6.3: GET /dashboard/trend's optional src_ip filter -- narrows the
fleet-wide daily trend to one entity's own trend, the backend half of the
new /dashboard/trends page's per-entity view."""
from datetime import datetime, timezone
from unittest.mock import patch

import jwt
import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.fake_db import FakeDB

JWT_SECRET = "test-jwt-secret-not-real"
TENANT = "77777777-7777-7777-7777-777777777777"
USER = "cccccccc-0000-0000-0000-000000000001"


def auth() -> dict:
    token = jwt.encode({"sub": USER, "aud": "authenticated", "exp": 9999999999}, JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def db():
    fake = FakeDB()
    fake.seed("profiles", [{"id": USER, "tenant_id": TENANT, "role": "viewer", "email": "v@x.com"}])
    now = datetime.now(timezone.utc).isoformat()
    fake.seed("anomaly_events", [
        {"tenant_id": TENANT, "detector": "ECOD", "severity": "high", "created_at": now, "src_ip": "10.0.0.5"},
        {"tenant_id": TENANT, "detector": "ECOD", "severity": "critical", "created_at": now, "src_ip": "10.0.0.5"},
        {"tenant_id": TENANT, "detector": "ECOD", "severity": "low", "created_at": now, "src_ip": "10.0.0.9"},
    ])
    with patch("app.core.auth.get_db", return_value=fake), patch("app.routers.dashboard.get_db", return_value=fake):
        yield fake


@pytest.fixture
def client(db):
    return TestClient(app)


def test_trend_fleet_wide_includes_all_entities(client, db):
    r = client.get("/dashboard/trend?days=14", headers=auth())
    assert r.status_code == 200
    day = r.json()[0]
    assert day["high"] == 1
    assert day["critical"] == 1
    assert day["low"] == 1


def test_trend_filtered_to_one_entity_excludes_others(client, db):
    r = client.get("/dashboard/trend?days=14&src_ip=10.0.0.5", headers=auth())
    assert r.status_code == 200
    day = r.json()[0]
    assert day["high"] == 1
    assert day["critical"] == 1
    assert day["low"] == 0


def test_trend_filtered_to_unknown_entity_is_empty(client, db):
    r = client.get("/dashboard/trend?days=14&src_ip=10.0.0.250", headers=auth())
    assert r.status_code == 200
    assert r.json() == []
