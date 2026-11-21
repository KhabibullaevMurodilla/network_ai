"""Confirms the security-headers middleware actually attaches headers to
real responses -- not just that the middleware class exists in main.py."""
from fastapi.testclient import TestClient
from app.main import app


def test_security_headers_present_on_a_real_response():
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert r.headers.get("referrer-policy") == "no-referrer"
    assert "max-age=31536000" in r.headers.get("strict-transport-security", "")
    assert r.headers.get("cache-control") == "no-store"


def test_security_headers_present_even_on_an_error_response():
    """Headers must apply uniformly -- including to a 404/4xx/5xx, not
    just the happy path, since those are exactly the responses more likely
    to get cached or embedded somewhere unexpected."""
    client = TestClient(app)
    r = client.get("/this-route-does-not-exist")
    assert r.status_code == 404
    assert r.headers.get("x-content-type-options") == "nosniff"
