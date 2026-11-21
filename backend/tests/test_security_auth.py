"""Real adversarial tests against the live FastAPI app (TestClient, not
mocked route logic) -- JWT forgery, API-key abuse, RBAC bypass, and
cross-tenant IDOR. Two real tenants with real seeded rows; every
cross-tenant attempt goes through the actual router code, not a stub.

Why this file exists: the backend authenticates with Supabase's
service-role key, which bypasses Row-Level Security entirely. That means
every tenant_id scoping check in this codebase is application code, not a
database guarantee -- these tests are what actually proves that scoping
holds, rather than trusting the RLS policies in schema.sql (which this
backend's own requests never go through)."""
import time

import jwt
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from app.core.auth import hash_key
from tests.fake_db import FakeDB

JWT_SECRET = "test-jwt-secret-not-real"  # matches conftest.py's SUPABASE_JWT_SECRET

TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"
USER_A_VIEWER = "aaaaaaaa-0000-0000-0000-000000000001"
USER_A_ANALYST = "aaaaaaaa-0000-0000-0000-000000000002"
USER_A_ADMIN = "aaaaaaaa-0000-0000-0000-000000000003"
USER_A_OWNER = "aaaaaaaa-0000-0000-0000-000000000004"
USER_B_VIEWER = "bbbbbbbb-0000-0000-0000-000000000001"


def make_token(sub: str, extra: dict | None = None, secret: str = JWT_SECRET, alg: str = "HS256") -> str:
    payload = {"sub": sub, "aud": "authenticated", "exp": int(time.time()) + 3600}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, secret, algorithm=alg)


@pytest.fixture
def db():
    fake = FakeDB()
    fake.seed("profiles", [
        {"id": USER_A_VIEWER, "tenant_id": TENANT_A, "role": "viewer"},
        {"id": USER_A_ANALYST, "tenant_id": TENANT_A, "role": "analyst"},
        {"id": USER_A_ADMIN, "tenant_id": TENANT_A, "role": "admin"},
        {"id": USER_A_OWNER, "tenant_id": TENANT_A, "role": "owner"},
        {"id": USER_B_VIEWER, "tenant_id": TENANT_B, "role": "viewer"},
    ])
    fake.seed("tenants", [
        {"id": TENANT_A, "name": "tenant-a"},
        {"id": TENANT_B, "name": "tenant-b"},
    ])
    fake.seed("api_keys", [
        {"id": "key-a-ingest", "tenant_id": TENANT_A, "key_hash": hash_key("raw-a-ingest"), "scope": "ingest", "revoked_at": None},
        {"id": "key-a-read", "tenant_id": TENANT_A, "key_hash": hash_key("raw-a-read"), "scope": "read", "revoked_at": None},
        {"id": "key-a-revoked", "tenant_id": TENANT_A, "key_hash": hash_key("raw-a-revoked"), "scope": "ingest", "revoked_at": "2026-01-01T00:00:00Z"},
    ])
    fake.seed("anomaly_events", [
        {"id": 500, "tenant_id": TENANT_A, "flow_id": 1, "detector": "ECOD", "severity": "high",
         "triage_status": "new", "score": 0.9, "is_anomaly": True, "explanation": {}, "src_ip": "10.0.0.5"},
    ])
    fake.seed("incidents", [
        {"id": "inc-a-1", "tenant_id": TENANT_A, "status": "open", "severity": "high", "event_count": 1,
         "src_ip": "10.0.0.5", "title": "x", "last_seen": "2026-01-01T00:00:00Z"},
    ])
    fake.seed("webhook_configs", [
        {"id": "wh-a-1", "tenant_id": TENANT_A, "url": "https://example.com/hook", "secret": "s", "min_severity": "critical", "enabled": True},
    ])
    fake.seed("response_actions", [
        {"id": "ra-a-1", "tenant_id": TENANT_A, "trigger": "critical", "action_type": "webhook_block",
         "target_url": "https://example.com/action", "secret": "s", "enabled": True},
    ])

    targets = [
        "app.core.auth.get_db",
        "app.routers.dashboard.get_db",
        "app.routers.incidents.get_db",
        "app.routers.tenants.get_db",
        "app.routers.webhooks.get_db",
        "app.routers.response_actions.get_db",
        "app.routers.privacy.get_db",
        "app.routers.ingest.get_db",
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


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# --- JWT forgery -------------------------------------------------------

def test_valid_token_works(client, db):
    token = make_token(USER_A_VIEWER)
    r = client.get("/tenants/me", headers=auth(token))
    assert r.status_code == 200


def test_token_signed_with_wrong_secret_rejected(client, db):
    token = make_token(USER_A_VIEWER, secret="attacker-controlled-secret")
    r = client.get("/tenants/me", headers=auth(token))
    assert r.status_code == 401


def test_alg_none_token_rejected(client, db):
    """The classic JWT 'alg: none' bypass -- an unsigned token must never
    be accepted even if the server has a secret configured."""
    unsigned = jwt.encode(
        {"sub": USER_A_VIEWER, "aud": "authenticated", "exp": int(time.time()) + 3600},
        key="", algorithm="none",
    )
    r = client.get("/tenants/me", headers={"Authorization": f"Bearer {unsigned}"})
    assert r.status_code == 401


def test_expired_token_rejected(client, db):
    token = jwt.encode(
        {"sub": USER_A_VIEWER, "aud": "authenticated", "exp": int(time.time()) - 60},
        JWT_SECRET, algorithm="HS256",
    )
    r = client.get("/tenants/me", headers=auth(token))
    assert r.status_code == 401


def test_wrong_audience_rejected(client, db):
    token = jwt.encode(
        {"sub": USER_A_VIEWER, "aud": "some-other-service", "exp": int(time.time()) + 3600},
        JWT_SECRET, algorithm="HS256",
    )
    r = client.get("/tenants/me", headers=auth(token))
    assert r.status_code == 401


def test_token_without_sub_claim_rejected_cleanly_not_500(client, db):
    """A validly-signed token missing 'sub' must fail as a clean 401, not
    crash into an unhandled 500 (the global handler would mask this as a
    generic error, but the underlying bug -- an unguarded dict access --
    is still worth not having)."""
    token = jwt.encode(
        {"aud": "authenticated", "exp": int(time.time()) + 3600},  # no "sub"
        JWT_SECRET, algorithm="HS256",
    )
    r = client.get("/tenants/me", headers=auth(token))
    assert r.status_code == 401, f"expected a clean 401, got {r.status_code}: {r.text}"


def test_token_without_exp_claim_rejected(client, db):
    """A validly-signed token with no expiry would otherwise be valid
    forever if the signing secret were ever compromised -- exp is now a
    required claim, not just checked-if-present."""
    token = jwt.encode({"sub": USER_A_VIEWER, "aud": "authenticated"}, JWT_SECRET, algorithm="HS256")
    r = client.get("/tenants/me", headers=auth(token))
    assert r.status_code == 401


def test_token_for_nonexistent_user_rejected(client, db):
    token = make_token("00000000-dead-beef-0000-000000000000")
    r = client.get("/tenants/me", headers=auth(token))
    assert r.status_code == 403  # "No profile/tenant for this user"


def test_missing_authorization_header_rejected(client, db):
    r = client.get("/tenants/me")
    assert r.status_code in (401, 422)  # FastAPI's required-Header 422, not a silent pass


def test_malformed_bearer_scheme_rejected(client, db):
    token = make_token(USER_A_VIEWER)
    r = client.get("/tenants/me", headers={"Authorization": token})  # no "Bearer " prefix
    assert r.status_code == 401


# --- API key abuse -------------------------------------------------------

def test_valid_ingest_key_works(client, db):
    r = client.post("/ingest/batch", headers={"X-API-Key": "raw-a-ingest"}, json={"flows": []})
    assert r.status_code == 200


def test_garbage_api_key_rejected(client, db):
    r = client.post("/ingest/batch", headers={"X-API-Key": "not-a-real-key' OR '1'='1"}, json={"flows": []})
    assert r.status_code == 401


def test_revoked_api_key_rejected(client, db):
    r = client.post("/ingest/batch", headers={"X-API-Key": "raw-a-revoked"}, json={"flows": []})
    assert r.status_code == 401


def test_read_scoped_key_cannot_ingest(client, db):
    """Scope enforcement: a 'read' key must not be usable to inject data,
    even though it's a valid, non-revoked key for the right tenant."""
    r = client.post("/ingest/batch", headers={"X-API-Key": "raw-a-read"}, json={"flows": []})
    assert r.status_code == 403


def test_missing_api_key_rejected(client, db):
    r = client.post("/ingest/batch", json={"flows": []})
    assert r.status_code in (401, 422)


# --- RBAC bypass ---------------------------------------------------------

def test_viewer_cannot_triage(client, db):
    token = make_token(USER_A_VIEWER)
    r = client.patch("/dashboard/anomalies/500/triage?status=acknowledged", headers=auth(token))
    assert r.status_code == 403


def test_analyst_can_triage(client, db):
    token = make_token(USER_A_ANALYST)
    r = client.patch("/dashboard/anomalies/500/triage?status=acknowledged", headers=auth(token))
    assert r.status_code == 200


def test_analyst_cannot_create_api_key(client, db):
    """api-key creation is admin-only -- an analyst (who can triage alerts)
    must not be able to mint new credentials."""
    token = make_token(USER_A_ANALYST)
    r = client.post("/tenants/api-keys", headers=auth(token), json={"label": "x", "scope": "admin"})
    assert r.status_code == 403


def test_admin_cannot_start_billing_checkout(client, db):
    """Billing changes are owner-only, stricter than admin -- confirms the
    4-tier hierarchy's top boundary actually holds, not just the bottom."""
    token = make_token(USER_A_ADMIN)
    r = client.post("/billing/create-checkout-session?plan=starter", headers=auth(token))
    assert r.status_code == 403


def test_owner_can_attempt_billing_checkout(client, db):
    token = make_token(USER_A_OWNER)
    r = client.post("/billing/create-checkout-session?plan=nonexistent-plan", headers=auth(token))
    # Not configured in this test env, but must get PAST the role check (400, not 403).
    assert r.status_code == 400


def test_analyst_cannot_erase_tenant_data():
    pass  # covered in test_security_isolation.py alongside the admin-only path


# --- Cross-tenant IDOR -----------------------------------------------------

def test_tenant_b_cannot_read_tenant_a_anomaly(client, db):
    token = make_token(USER_B_VIEWER)
    r = client.get("/dashboard/anomalies/500", headers=auth(token))
    assert r.status_code == 404  # not 403 -- existence isn't confirmed either


def test_tenant_b_cannot_triage_tenant_a_anomaly(client, db):
    token = make_token(USER_B_VIEWER)
    r = client.patch("/dashboard/anomalies/500/triage?status=resolved", headers=auth(token))
    assert r.status_code in (403, 404)  # blocked either by role or by tenant scoping
    # confirm it genuinely didn't change, regardless of which status code fired
    assert db.table("anomaly_events").eq("id", 500).execute().data[0]["triage_status"] == "new"


def test_tenant_b_cannot_read_tenant_a_incident(client, db):
    token = make_token(USER_B_VIEWER)
    r = client.get("/dashboard/incidents/inc-a-1", headers=auth(token))
    assert r.status_code == 404


def test_tenant_b_admin_cannot_revoke_tenant_a_api_key(client, db):
    fake_admin_b_token = make_token(USER_B_VIEWER)  # no admin in tenant B seeded; prove via direct revoke attempt below instead
    # Seed a tenant-B admin inline for this one test.
    db.seed("profiles", [{"id": "bbbb-admin", "tenant_id": TENANT_B, "role": "admin"}])
    token = make_token("bbbb-admin")
    r = client.delete("/tenants/api-keys/key-a-ingest", headers=auth(token))
    assert r.status_code == 200  # endpoint doesn't 404 on a no-op (see finding notes)
    # The real assertion: tenant A's key must still be unrevoked afterward.
    row = db.table("api_keys").eq("id", "key-a-ingest").execute().data[0]
    assert row["revoked_at"] is None, "cross-tenant API key revocation must not actually apply"


def test_tenant_b_admin_cannot_delete_tenant_a_webhook(client, db):
    db.seed("profiles", [{"id": "bbbb-admin-2", "tenant_id": TENANT_B, "role": "admin"}])
    token = make_token("bbbb-admin-2")
    client.delete("/webhooks/wh-a-1", headers=auth(token))
    assert db.table("webhook_configs").eq("id", "wh-a-1").execute().data, \
        "cross-tenant webhook deletion must not actually remove tenant A's row"


def test_tenant_b_admin_cannot_delete_tenant_a_response_action(client, db):
    db.seed("profiles", [{"id": "bbbb-admin-3", "tenant_id": TENANT_B, "role": "admin"}])
    token = make_token("bbbb-admin-3")
    client.delete("/response-actions/ra-a-1", headers=auth(token))
    assert db.table("response_actions").eq("id", "ra-a-1").execute().data, \
        "cross-tenant response-action deletion must not actually remove tenant A's row"
