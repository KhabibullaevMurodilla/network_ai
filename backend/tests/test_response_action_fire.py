"""v6.4 manual fire. The outbound POST to the customer's endpoint is
mocked at httpx; signing, SSRF re-check call, tenant scoping, role gate,
outcome reporting and audit logging are real."""
from unittest.mock import patch, AsyncMock, MagicMock

import jwt
import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.fake_db import FakeDB

SECRET = "test-jwt-secret-not-real"
T1, T2 = "d1000000-0000-0000-0000-000000000001", "d2000000-0000-0000-0000-000000000002"
ANALYST, VIEWER = "e1000000-0000-0000-0000-000000000001", "e1000000-0000-0000-0000-000000000002"


def auth(uid):
    return {"Authorization": "Bearer " + jwt.encode({"sub": uid, "aud": "authenticated", "exp": 9999999999}, SECRET, algorithm="HS256")}


@pytest.fixture
def db():
    f = FakeDB()
    f.seed("profiles", [
        {"id": ANALYST, "tenant_id": T1, "role": "analyst", "email": "a@x.com"},
        {"id": VIEWER, "tenant_id": T1, "role": "viewer", "email": "v@x.com"},
    ])
    f.seed("response_actions", [
        {"id": "ra1", "tenant_id": T1, "action_type": "webhook_block", "target_url": "https://fw.example.com/h", "secret": "s3cret", "trigger": "critical", "enabled": True},
        {"id": "ra2", "tenant_id": T2, "action_type": "webhook_block", "target_url": "https://other.example.com/h", "secret": "x", "trigger": "critical", "enabled": True},
    ])
    f.seed("anomaly_events", [
        {"id": 501, "tenant_id": T1, "detector": "ECOD", "flow_id": 1, "severity": "critical", "escalation_reason": "entity_burst", "consensus_count": 3, "src_ip": "10.0.0.9"},
        {"id": 502, "tenant_id": T2, "detector": "ECOD", "flow_id": 2, "severity": "high", "src_ip": "1.1.1.1"},
    ])
    ps = [patch(t, return_value=f) for t in ("app.core.auth.get_db", "app.routers.response_actions.get_db", "app.core.audit.get_db")]
    [p.start() for p in ps]
    yield f
    [p.stop() for p in ps]


@pytest.fixture
def client(db):
    from app.core.limiter import limiter
    limiter.reset()
    return TestClient(app)


def _http(status):
    inst = MagicMock()
    inst.post = AsyncMock(return_value=MagicMock(status_code=status))
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=inst)
    cm.__aexit__ = AsyncMock(return_value=False)
    return patch("app.core.response_actions.httpx.AsyncClient", return_value=cm), inst


def test_fire_sends_signed_directive_and_audits(client, db):
    cm, inst = _http(200)
    with cm, patch("app.core.response_actions.resolve_and_check", AsyncMock(return_value=True)):
        r = client.post("/response-actions/ra1/fire", headers=auth(ANALYST), json={"event_id": 501})
    assert r.json() == {"outcome": "sent"}
    kwargs = inst.post.call_args.kwargs
    assert kwargs["headers"]["X-Signature"]  # HMAC present
    import json as _j
    body = _j.loads(kwargs["content"])
    assert body["triggered_by"] == "manual" and body["event"]["src_ip"] == "10.0.0.9"
    audit = db.table("audit_log").select("*").eq("action", "response_action.manually_fired").execute().data
    assert audit and audit[0]["actor"] == ANALYST and audit[0]["detail"]["outcome"] == "sent"


def test_customer_endpoint_error_is_reported_not_swallowed(client):
    cm, _ = _http(502)
    with cm, patch("app.core.response_actions.resolve_and_check", AsyncMock(return_value=True)):
        assert client.post("/response-actions/ra1/fire", headers=auth(ANALYST), json={"event_id": 501}).json() == {"outcome": "failed"}


def test_unsafe_target_blocked_and_nothing_sent(client):
    cm, inst = _http(200)
    with cm, patch("app.core.response_actions.resolve_and_check", AsyncMock(return_value=False)):
        r = client.post("/response-actions/ra1/fire", headers=auth(ANALYST), json={"event_id": 501})
    assert r.json() == {"outcome": "blocked_unsafe_target"}
    inst.post.assert_not_called()


def test_viewer_cannot_fire(client):
    assert client.post("/response-actions/ra1/fire", headers=auth(VIEWER), json={"event_id": 501}).status_code == 403


def test_cross_tenant_action_or_event_is_404(client):
    assert client.post("/response-actions/ra2/fire", headers=auth(ANALYST), json={"event_id": 501}).status_code == 404
    assert client.post("/response-actions/ra1/fire", headers=auth(ANALYST), json={"event_id": 502}).status_code == 404
