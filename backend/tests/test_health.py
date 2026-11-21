"""Liveness/readiness contract tests -- these are what an orchestrator or
load balancer actually depends on, so they're worth pinning down exactly:
liveness never depends on downstream services, readiness does and must
return a real non-200 status (not just a string buried in the body) when
a dependency is down, and nothing from an internal exception ever reaches
the (unauthenticated) response body."""
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app


def test_liveness_always_ok():
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_readiness_503_when_supabase_unreachable():
    client = TestClient(app)
    r = client.get("/health/ready")
    # No real Supabase in the test environment -> must be reported as
    # not ready, with a 503 a load balancer actually acts on.
    assert r.status_code == 503
    assert r.json()["status"] == "not_ready"


def test_readiness_never_leaks_exception_internals():
    with patch("app.routers.health.get_db", side_effect=RuntimeError("db_password=hunter2")):
        client = TestClient(app, raise_server_exceptions=False)
        r = client.get("/health/ready")
        assert "hunter2" not in r.text
        assert "RuntimeError" not in r.text


def test_unhandled_exception_returns_generic_500_not_traceback():
    """Exercises main.py's top-level exception_handler(Exception) directly,
    via a route (ingest) that does NOT catch its own DB errors -- unlike
    health.py's readiness check, an unexpected failure here must still be
    sanitized by the app-wide handler, not leak a traceback by accident."""
    from app.core.auth import require_ingest_key

    app.dependency_overrides[require_ingest_key] = lambda: {"tenant_id": "t1", "id": "k1"}
    try:
        with patch("app.routers.ingest.get_db", side_effect=RuntimeError("boom: secret_token=abc123")):
            client = TestClient(app, raise_server_exceptions=False)
            r = client.post("/ingest/batch", json={"flows": [{
                "dur": 1.0, "proto": "TCP", "tot_pkts": 5, "src_bytes": 100.0,
                "dst_bytes": 200.0, "rate": 5.0, "load": 10.0, "s_ttl": 60,
            }]})
            assert r.status_code == 500
            assert r.json() == {"detail": "Internal server error"}
            assert "secret_token" not in r.text
            assert "RuntimeError" not in r.text
            assert "Traceback" not in r.text
    finally:
        app.dependency_overrides.pop(require_ingest_key, None)
