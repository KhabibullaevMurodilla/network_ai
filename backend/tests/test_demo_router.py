"""v6.3: the public, unauthenticated /demo router. Covers the two things
that matter for an endpoint with no login wall: it fails closed when
DEMO_TENANT_ID isn't configured (never guesses a tenant), and it only ever
serves that one fixed tenant's data (never anything from the request)."""
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.fake_db import FakeDB

DEMO_TENANT = "ee111111-1111-1111-1111-111111111111"
OTHER_TENANT = "ee222222-2222-2222-2222-222222222222"


@pytest.fixture
def db():
    fake = FakeDB()
    fake.seed("telemetry_flows", [
        {"id": 90001, "tenant_id": DEMO_TENANT, "src_ip": "10.50.0.5", "dst_ip": "10.50.0.2"},
        {"id": 90002, "tenant_id": OTHER_TENANT, "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"},
    ])
    fake.seed("anomaly_events", [
        {"tenant_id": DEMO_TENANT, "detector": "ECOD", "is_anomaly": True, "severity": "critical", "src_ip": "10.50.0.5", "flow_id": 90001, "created_at": "2026-01-01T00:00:00Z"},
        {"tenant_id": OTHER_TENANT, "detector": "ECOD", "is_anomaly": True, "severity": "critical", "src_ip": "192.168.1.1", "flow_id": 90002, "created_at": "2026-01-01T00:00:00Z"},
    ])
    with patch("app.routers.demo.get_db", return_value=fake):
        yield fake


@pytest.fixture
def client(db):
    return TestClient(app)


def test_demo_404s_when_not_configured(client, db):
    with patch("app.routers.demo.settings.DEMO_TENANT_ID", ""):
        r = client.get("/demo/summary")
    assert r.status_code == 404


def test_demo_summary_requires_no_auth(client, db):
    with patch("app.routers.demo.settings.DEMO_TENANT_ID", DEMO_TENANT):
        r = client.get("/demo/summary")  # no Authorization header at all
    assert r.status_code == 200
    assert r.json()["is_demo"] is True
    assert r.json()["total_flows"] == 1


def test_demo_never_serves_another_tenants_data(client, db):
    with patch("app.routers.demo.settings.DEMO_TENANT_ID", DEMO_TENANT):
        r = client.get("/demo/entities")
    sources = {e["source"] for e in r.json()}
    assert "192.168.1.1" not in sources
    assert "10.50.0.5" in sources


def test_demo_has_no_mutation_routes():
    """No POST/PATCH/DELETE exists under /demo at all -- not 'blocked',
    genuinely absent from the route table."""
    demo_routes = [r for r in app.routes if getattr(r, "path", "").startswith("/demo")]
    methods = {m for r in demo_routes for m in getattr(r, "methods", set())}
    assert methods <= {"GET", "HEAD", "OPTIONS"}


def test_demo_is_rate_limited(client, db):
    from app.core.limiter import limiter
    limiter.reset()  # isolate from the budget earlier tests in this file already spent
    with patch("app.routers.demo.settings.DEMO_TENANT_ID", DEMO_TENANT):
        codes = [client.get("/demo/summary").status_code for _ in range(35)]
    assert codes.count(200) == 30
    assert codes.count(429) == 5
