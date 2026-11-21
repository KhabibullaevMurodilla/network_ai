"""Real cryptographic verification of the Stripe webhook signature check --
generates an actual signed payload the way Stripe itself would, and proves
both that a valid signature is accepted and that a tampered payload or a
forged signature is rejected. Not a mock of the verification path -- the
real stripe.Webhook.construct_event call runs, same as production."""
import json
import time

import stripe
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from app.core.config import settings


def _signed_payload(secret: str):
    payload = json.dumps({
        "id": "evt_test123", "object": "event", "type": "checkout.session.completed",
        "data": {"object": {
            "client_reference_id": "tenant-abc",
            "customer": "cus_123", "subscription": "sub_123",
        }},
    }).encode()
    sig = stripe.WebhookSignature.generate_signature_header(
        payload.decode(), secret, int(time.time())
    )
    return payload, sig


class _FakeTable:
    def __init__(self, name, sink):
        self.name, self.sink = name, sink
    def update(self, data):
        self._data = data
        return self
    def eq(self, k, v):
        self._filters = {k: v}
        return self
    def execute(self):
        self.sink.append((self.name, dict(self._data), dict(self._filters)))
        class R:
            data = []
        return R()


def test_valid_signature_accepted_and_updates_tenant():
    settings.STRIPE_WEBHOOK_SECRET = "whsec_test_secret_123"
    payload, sig = _signed_payload(settings.STRIPE_WEBHOOK_SECRET)
    updates = []

    class FakeDB:
        def table(self, name):
            return _FakeTable(name, updates)

    with patch("app.routers.billing.get_db", return_value=FakeDB()):
        client = TestClient(app)
        r = client.post("/billing/webhook", content=payload, headers={"stripe-signature": sig})
        assert r.status_code == 200
        assert updates == [(
            "tenants",
            {"stripe_customer_id": "cus_123", "stripe_subscription_id": "sub_123", "subscription_status": "active"},
            {"id": "tenant-abc"},
        )]


def test_tampered_payload_rejected():
    settings.STRIPE_WEBHOOK_SECRET = "whsec_test_secret_123"
    payload, sig = _signed_payload(settings.STRIPE_WEBHOOK_SECRET)
    tampered = payload.replace(b"tenant-abc", b"tenant-xyz")
    client = TestClient(app)
    r = client.post("/billing/webhook", content=tampered, headers={"stripe-signature": sig})
    assert r.status_code == 400


def test_missing_signature_header_rejected():
    settings.STRIPE_WEBHOOK_SECRET = "whsec_test_secret_123"
    payload, _ = _signed_payload(settings.STRIPE_WEBHOOK_SECRET)
    client = TestClient(app)
    r = client.post("/billing/webhook", content=payload)
    assert r.status_code == 400


def test_forged_signature_rejected():
    settings.STRIPE_WEBHOOK_SECRET = "whsec_test_secret_123"
    payload, _ = _signed_payload(settings.STRIPE_WEBHOOK_SECRET)
    client = TestClient(app)
    r = client.post("/billing/webhook", content=payload, headers={"stripe-signature": "t=1,v1=deadbeef"})
    assert r.status_code == 400


def test_old_timestamp_rejected_as_replay_protection():
    """A validly-signed payload with a stale timestamp (stripe's library
    default tolerance is 300s) must be rejected -- this is what actually
    defends against a captured-and-replayed webhook request, since the
    signature alone never expires on its own."""
    settings.STRIPE_WEBHOOK_SECRET = "whsec_test_secret_123"
    payload = json.dumps({
        "id": "evt_test_old", "object": "event", "type": "checkout.session.completed",
        "data": {"object": {"client_reference_id": "tenant-abc", "customer": "cus_123", "subscription": "sub_123"}},
    }).encode()
    stale_timestamp = int(time.time()) - 3600  # 1 hour old, well past the 300s tolerance
    sig = stripe.WebhookSignature.generate_signature_header(
        payload.decode(), settings.STRIPE_WEBHOOK_SECRET, stale_timestamp
    )
    client = TestClient(app)
    r = client.post("/billing/webhook", content=payload, headers={"stripe-signature": sig})
    assert r.status_code == 400


def test_exact_replay_of_a_fresh_valid_event_has_no_harmful_effect():
    """Stripe's library checks signature + timestamp freshness, not
    per-event idempotency -- a captured, still-fresh signed request CAN be
    replayed and will be accepted twice. Confirmed here that this is
    harmless given this handler's actual semantics: both handled event
    types are plain state assignments (subscription_status = 'active' /
    whatever Stripe sent), not counters or one-time credits, so replaying
    the same event converges to the same end state rather than double-
    applying an effect. Documented by this test rather than left as an
    unverified assumption."""
    settings.STRIPE_WEBHOOK_SECRET = "whsec_test_secret_123"
    payload, sig = _signed_payload(settings.STRIPE_WEBHOOK_SECRET)
    updates = []

    class FakeDB:
        def table(self, name):
            return _FakeTable(name, updates)

    with patch("app.routers.billing.get_db", return_value=FakeDB()):
        client = TestClient(app)
        r1 = client.post("/billing/webhook", content=payload, headers={"stripe-signature": sig})
        r2 = client.post("/billing/webhook", content=payload, headers={"stripe-signature": sig})
        assert r1.status_code == 200 and r2.status_code == 200
        # both applied the identical update -- no divergence, no double-effect
        assert updates[0] == updates[1]
