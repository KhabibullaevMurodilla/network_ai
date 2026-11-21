"""Real-time alert delivery. The original 'generic' channel is an
HMAC-SHA256 signed JSON POST (X-Signature header), the same pattern
Stripe/GitHub use, so a receiver can verify a request actually came from
us. v6.3 adds three more channel types a tenant can pick without having to
run their own bridge: 'slack' and 'teams' POST to an incoming-webhook URL
in that platform's own payload shape (still through the same SSRF-guarded
dispatch path as generic), and 'email' sends over SMTP instead of HTTP.

Self-service alert tuning (v6.3, same adversarial-review pass that found
the SSRF gap this module already closes): before any of this fires, a
flagged event is checked against the tenant's muted entities
(entity_suppressions) and the tenant-wide alert_min_severity floor. Muting
an entity or raising the floor only quiets *paging* -- the event is still
scored, stored, and visible in every dashboard list regardless; this
function is the one place that visibility and notification diverge."""
import asyncio
import hashlib
import hmac
import json
import smtplib
from email.message import EmailMessage

import httpx

from .config import settings
from .db import get_db
from .url_safety import resolve_and_check

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _is_suppressed(db, tenant_id: str, src_ip: str | None) -> bool:
    if not src_ip:
        return False
    res = (
        db.table("entity_suppressions")
        .select("id")
        .eq("tenant_id", tenant_id)
        .eq("src_ip", src_ip)
        .limit(1)
        .execute()
    )
    return bool(res.data)


def _below_tenant_floor(db, tenant_id: str, event_rank: int) -> bool:
    res = db.table("tenants").select("alert_min_severity").eq("id", tenant_id).limit(1).execute()
    if not res.data:
        return False
    floor = res.data[0].get("alert_min_severity") or "low"
    return event_rank < SEVERITY_RANK.get(floor, 0)


def _slack_text(tenant_id: str, event: dict) -> str:
    sev = (event.get("severity") or "unknown").upper()
    src = event.get("src_ip") or "unidentified source"
    reason = event.get("escalation_reason")
    reason_txt = f" ({reason})" if reason else ""
    return f":rotating_light: *{sev}* anomaly from `{src}`{reason_txt} — tenant `{tenant_id}`"


def _teams_card(tenant_id: str, event: dict) -> dict:
    sev = (event.get("severity") or "unknown").upper()
    src = event.get("src_ip") or "unidentified source"
    color = {"CRITICAL": "C4314B", "HIGH": "E8A33D", "MEDIUM": "DCCB4B"}.get(sev, "767676")
    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": f"{sev} anomaly — {src}",
        "themeColor": color,
        "title": f"{sev} anomaly detected",
        "sections": [{
            "facts": [
                {"name": "Tenant", "value": tenant_id},
                {"name": "Source", "value": src},
                {"name": "Severity", "value": sev},
                {"name": "Escalation reason", "value": event.get("escalation_reason") or "—"},
            ],
        }],
    }


def _send_email_sync(to_addr: str, tenant_id: str, event: dict) -> None:
    """Synchronous smtplib send -- run via asyncio.to_thread so it never
    blocks the event loop ingestion itself runs on. A no-op, not a crash,
    when SMTP isn't configured (same posture as the optional REDIS_URL
    fallback elsewhere in this codebase)."""
    if not settings.SMTP_HOST:
        return
    sev = (event.get("severity") or "unknown").upper()
    src = event.get("src_ip") or "unidentified source"
    msg = EmailMessage()
    msg["Subject"] = f"[Network AI] {sev} anomaly — {src}"
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to_addr
    msg.set_content(
        f"{sev} anomaly detected for tenant {tenant_id}.\n\n"
        f"Source: {src}\n"
        f"Escalation reason: {event.get('escalation_reason') or '—'}\n"
        f"Consensus: {event.get('consensus_count')}\n"
    )
    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=5) as s:
        if settings.SMTP_USE_TLS:
            s.starttls()
        if settings.SMTP_USER:
            s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        s.send_message(msg)


async def dispatch_critical_alert(tenant_id: str, event: dict):
    """Fire-and-forget delivery to every enabled webhook configured for this
    tenant whose min_severity is at or below this event's severity. Failures
    are logged but never raised -- a broken customer endpoint must not take
    down ingestion."""
    event_rank = SEVERITY_RANK.get(event.get("severity"), -1)
    if event_rank < 0:
        return

    db = get_db()
    if _is_suppressed(db, tenant_id, event.get("src_ip")):
        return
    if _below_tenant_floor(db, tenant_id, event_rank):
        return

    res = (
        db.table("webhook_configs")
        .select("channel_type, url, email_to, secret, min_severity")
        .eq("tenant_id", tenant_id)
        .eq("enabled", True)
        .execute()
    )
    targets = [w for w in res.data if SEVERITY_RANK.get(w["min_severity"], 99) <= event_rank]
    if not targets:
        return

    generic_body = json.dumps({"type": "anomaly.detected", "tenant_id": tenant_id, "event": event}).encode()

    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
        for w in targets:
            channel = w.get("channel_type", "generic")

            if channel == "email":
                try:
                    await asyncio.to_thread(_send_email_sync, w["email_to"], tenant_id, event)
                except Exception:
                    pass
                continue

            # http-based channels (generic/slack/teams) all go through the
            # same SSRF re-check right before sending -- a URL that passed
            # validation at creation time can have its DNS record
            # repointed to an internal address since then (rebinding); this
            # is the check that actually closes that gap, not the one at
            # creation time alone. follow_redirects=False above matters
            # too: a redirect to an internal URL would otherwise bypass
            # this check entirely on the hop.
            if not await resolve_and_check(w["url"]):
                continue
            try:
                if channel == "slack":
                    await client.post(w["url"], json={"text": _slack_text(tenant_id, event)})
                elif channel == "teams":
                    await client.post(w["url"], json=_teams_card(tenant_id, event))
                else:
                    await client.post(
                        w["url"],
                        content=generic_body,
                        headers={
                            "Content-Type": "application/json",
                            "X-Signature": _sign(w["secret"], generic_body),
                        },
                    )
            except Exception:
                # Deliberately swallow -- a customer's endpoint being down
                # must never break telemetry ingestion for every tenant.
                pass
