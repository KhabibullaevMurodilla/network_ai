"""Real burst tests confirming rate limiting actually fires -- not just
that the decorator is present in the source. Sends real bursts through a
real TestClient against the real app and counts actual 200/429 responses.

Note on how this is tested: `@limiter.limit(settings.INGEST_RATE_LIMIT)`
reads the configured limit string at decoration time (module import),
not per-request, so these tests exercise the real configured default
(120/minute) with a real burst past it, rather than a monkeypatched
smaller value that wouldn't actually be wired to the decorator."""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from app.core.auth import hash_key
from tests.fake_db import FakeDB

TENANT = "44444444-4444-4444-4444-444444444444"
RAW_KEY = "raw-rate-limit-test-key"


@pytest.fixture
def db():
    fake = FakeDB()
    fake.seed("api_keys", [
        {"id": "key-rl", "tenant_id": TENANT, "key_hash": hash_key(RAW_KEY), "scope": "ingest", "revoked_at": None},
    ])
    targets = [
        "app.core.auth.get_db",
        "app.routers.ingest.get_db",
        "app.core.webhooks.get_db",
        "app.core.response_actions.get_db",
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


def test_ingest_rate_limit_actually_triggers_past_the_real_configured_limit(client, db):
    """120/minute is the real default (core/config.py's INGEST_RATE_LIMIT);
    sends 125 real requests with the same API key and confirms the 121st
    onward is actually rejected with 429, not silently allowed through."""
    codes = []
    for _ in range(125):
        r = client.post("/ingest/batch", headers={"X-API-Key": RAW_KEY}, json={"flows": []})
        codes.append(r.status_code)
    assert codes.count(200) == 120
    assert codes.count(429) == 5
    assert all(c in (200, 429) for c in codes)  # never a 500 under load


def test_rate_limit_is_scoped_per_key_not_global(client, db):
    """A second, different API key must not be affected by the first key's
    exhausted limit -- confirms the bucket is keyed by credential, not
    shared across all ingestion globally."""
    for _ in range(120):
        client.post("/ingest/batch", headers={"X-API-Key": RAW_KEY}, json={"flows": []})
    exhausted = client.post("/ingest/batch", headers={"X-API-Key": RAW_KEY}, json={"flows": []})
    assert exhausted.status_code == 429

    db.seed("api_keys", [
        {"id": "key-rl-2", "tenant_id": TENANT, "key_hash": hash_key("raw-second-key"), "scope": "ingest", "revoked_at": None},
    ])
    fresh = client.post("/ingest/batch", headers={"X-API-Key": "raw-second-key"}, json={"flows": []})
    assert fresh.status_code == 200


# --- the real gap found in review: JWT-authenticated routes had NO rate
# limiting at all until this review added it (core/limiter.py's
# user_key_func, applied to api-key creation, billing checkout, privacy
# export/erase, webhook/response-action creation) ---------------------------

def test_api_key_creation_is_rate_limited_per_user(db):
    """A stolen/abused admin JWT must not be able to mint unlimited API
    key credentials -- confirmed against the real configured 20/minute
    limit, not a monkeypatched one (same reasoning as the ingest test
    above: the decorator reads its limit string at import time)."""
    import time
    import jwt as _pyjwt
    from fastapi.testclient import TestClient
    from app.main import app
    from app.core.config import settings

    user_id = "admin-rl-test"
    db.seed("profiles", [{"id": user_id, "tenant_id": TENANT, "role": "admin"}])
    token = _pyjwt.encode(
        {"sub": user_id, "aud": "authenticated", "exp": int(time.time()) + 3600},
        settings.SUPABASE_JWT_SECRET, algorithm="HS256",
    )
    with patch("app.routers.tenants.get_db", return_value=db):
        client = TestClient(app)
        codes = []
        for _ in range(25):
            r = client.post(
                "/tenants/api-keys", headers={"Authorization": f"Bearer {token}"},
                json={"label": "x", "scope": "ingest"},
            )
            codes.append(r.status_code)
        assert codes.count(200) == 20
        assert codes.count(429) == 5
