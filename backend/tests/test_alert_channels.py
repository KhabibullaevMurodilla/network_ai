"""v6.3: native Slack/Teams/email alert-delivery channels, plus the
self-service alert-tuning gates (entity suppression, tenant-wide severity
floor) that sit in front of every channel. Exercises core.webhooks.
dispatch_critical_alert directly against a FakeDB, with the outbound HTTP/
SMTP calls themselves mocked (this is not a test of real Slack/SMTP
delivery -- it's a test of this codebase producing the right payload shape
and respecting the right gates before handing off to them)."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.fake_db import FakeDB
from app.core import webhooks as webhooks_mod

TENANT = "44444444-4444-4444-4444-444444444444"


@pytest.fixture
def db():
    fake = FakeDB()
    fake.seed("tenants", [{"id": TENANT, "alert_min_severity": "low"}])
    with patch("app.core.webhooks.get_db", return_value=fake):
        yield fake


CRITICAL_EVENT = {"severity": "critical", "src_ip": "10.0.0.5", "escalation_reason": "entity_burst", "consensus_count": 3}


async def _dispatch_with_mocked_http(db, event, status_ok=True):
    """Runs dispatch_critical_alert with resolve_and_check forced True (SSRF
    re-check is covered exhaustively by test_url_safety.py already; this
    file is about channel formatting/gating, not re-proving SSRF) and the
    actual httpx POST replaced with a recording mock."""
    mock_post = AsyncMock()
    with patch("app.core.webhooks.resolve_and_check", new=AsyncMock(return_value=True)):
        with patch("httpx.AsyncClient.post", new=mock_post):
            await webhooks_mod.dispatch_critical_alert(TENANT, event)
    return mock_post


@pytest.mark.asyncio
async def test_generic_channel_still_sends_hmac_signed_json(db):
    db.seed("webhook_configs", [{
        "tenant_id": TENANT, "channel_type": "generic", "url": "https://example.com/hook",
        "email_to": None, "secret": "s3cr3t", "min_severity": "critical", "enabled": True,
    }])
    mock_post = await _dispatch_with_mocked_http(db, CRITICAL_EVENT)
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == "https://example.com/hook"
    assert "X-Signature" in kwargs["headers"]
    body = json.loads(kwargs["content"])
    assert body["event"]["src_ip"] == "10.0.0.5"


@pytest.mark.asyncio
async def test_slack_channel_sends_text_payload_not_signed_json(db):
    db.seed("webhook_configs", [{
        "tenant_id": TENANT, "channel_type": "slack", "url": "https://hooks.slack.example/T000/B000/xyz",
        "email_to": None, "secret": "s3cr3t", "min_severity": "critical", "enabled": True,
    }])
    mock_post = await _dispatch_with_mocked_http(db, CRITICAL_EVENT)
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert "json" in kwargs
    assert "text" in kwargs["json"]
    assert "CRITICAL" in kwargs["json"]["text"]
    assert "10.0.0.5" in kwargs["json"]["text"]


@pytest.mark.asyncio
async def test_teams_channel_sends_messagecard_shape(db):
    db.seed("webhook_configs", [{
        "tenant_id": TENANT, "channel_type": "teams", "url": "https://outlook.office.example/webhook/xyz",
        "email_to": None, "secret": "s3cr3t", "min_severity": "critical", "enabled": True,
    }])
    mock_post = await _dispatch_with_mocked_http(db, CRITICAL_EVENT)
    args, kwargs = mock_post.call_args
    card = kwargs["json"]
    assert card["@type"] == "MessageCard"
    facts = {f["name"]: f["value"] for f in card["sections"][0]["facts"]}
    assert facts["Source"] == "10.0.0.5"
    assert facts["Severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_email_channel_calls_smtp_with_configured_recipient(db):
    db.seed("webhook_configs", [{
        "tenant_id": TENANT, "channel_type": "email", "url": None,
        "email_to": "soc@customer.example", "secret": "s3cr3t", "min_severity": "critical", "enabled": True,
    }])
    mock_smtp_instance = MagicMock()
    mock_smtp_cm = MagicMock()
    mock_smtp_cm.__enter__ = MagicMock(return_value=mock_smtp_instance)
    mock_smtp_cm.__exit__ = MagicMock(return_value=False)
    with patch("app.core.webhooks.settings.SMTP_HOST", "smtp.example.com"):
        with patch("smtplib.SMTP", return_value=mock_smtp_cm) as mock_smtp_cls:
            with patch("app.core.webhooks.resolve_and_check", new=AsyncMock(return_value=True)):
                await webhooks_mod.dispatch_critical_alert(TENANT, CRITICAL_EVENT)
    mock_smtp_cls.assert_called_once()
    sent_msg = mock_smtp_instance.send_message.call_args[0][0]
    assert sent_msg["To"] == "soc@customer.example"
    assert "CRITICAL" in sent_msg["Subject"]


@pytest.mark.asyncio
async def test_email_channel_is_a_silent_noop_when_smtp_not_configured(db):
    """settings.SMTP_HOST defaults to '' -- an email-channel webhook with no
    SMTP configured must not crash ingestion, it just doesn't send."""
    db.seed("webhook_configs", [{
        "tenant_id": TENANT, "channel_type": "email", "url": None,
        "email_to": "soc@customer.example", "secret": "s3cr3t", "min_severity": "critical", "enabled": True,
    }])
    with patch("app.core.webhooks.settings.SMTP_HOST", ""):
        with patch("smtplib.SMTP") as mock_smtp_cls:
            await webhooks_mod.dispatch_critical_alert(TENANT, CRITICAL_EVENT)
    mock_smtp_cls.assert_not_called()


# --- self-service alert tuning gates ---------------------------------------

@pytest.mark.asyncio
async def test_suppressed_entity_never_reaches_a_webhook(db):
    db.seed("webhook_configs", [{
        "tenant_id": TENANT, "channel_type": "slack", "url": "https://hooks.slack.example/x",
        "email_to": None, "secret": "s", "min_severity": "low", "enabled": True,
    }])
    db.seed("entity_suppressions", [{"tenant_id": TENANT, "src_ip": "10.0.0.5", "reason": "known scanner"}])
    mock_post = await _dispatch_with_mocked_http(db, CRITICAL_EVENT)
    mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_unsuppressed_entity_still_alerts(db):
    db.seed("webhook_configs", [{
        "tenant_id": TENANT, "channel_type": "slack", "url": "https://hooks.slack.example/x",
        "email_to": None, "secret": "s", "min_severity": "low", "enabled": True,
    }])
    db.seed("entity_suppressions", [{"tenant_id": TENANT, "src_ip": "10.0.0.99", "reason": "unrelated host"}])
    mock_post = await _dispatch_with_mocked_http(db, CRITICAL_EVENT)
    mock_post.assert_called_once()


@pytest.mark.asyncio
async def test_event_below_tenant_alert_floor_is_not_dispatched(db):
    db._store["tenants"][0]["alert_min_severity"] = "critical"
    db.seed("webhook_configs", [{
        "tenant_id": TENANT, "channel_type": "slack", "url": "https://hooks.slack.example/x",
        "email_to": None, "secret": "s", "min_severity": "low", "enabled": True,
    }])
    high_event = {"severity": "high", "src_ip": "10.0.0.5", "escalation_reason": None, "consensus_count": 1}
    mock_post = await _dispatch_with_mocked_http(db, high_event)
    mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_event_at_or_above_tenant_floor_still_dispatches(db):
    db._store["tenants"][0]["alert_min_severity"] = "high"
    db.seed("webhook_configs", [{
        "tenant_id": TENANT, "channel_type": "slack", "url": "https://hooks.slack.example/x",
        "email_to": None, "secret": "s", "min_severity": "low", "enabled": True,
    }])
    mock_post = await _dispatch_with_mocked_http(db, CRITICAL_EVENT)  # critical >= high floor
    mock_post.assert_called_once()
