"""Automated response hooks -- distinct from the notify-webhooks in
core/webhooks.py. A notify webhook tells a human "something happened, go
look." A response action tells the customer's own infrastructure what to
*do* about it: call their firewall/NAC/SOAR API to quarantine a host, open
a ticket with a specific severity, whatever their own system knows how to
act on. This project doesn't own a firewall or NAC and can't actually
block traffic itself -- what it can honestly provide is a signed,
structured directive the customer's own automation receives and acts on.

Scoped honestly: "automated response" here means "fires a verifiable,
structured instruction your systems can act on," not "we block the
attacker for you." Representing it as the latter to a prospect would be
false -- this product has no network enforcement point of its own.
"""
import hashlib
import hmac
import json
import httpx
from .db import get_db
from .url_safety import resolve_and_check

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


async def dispatch_response_actions(tenant_id: str, event: dict):
    """Fire-and-forget: for every enabled response_action configured for
    this tenant whose trigger matches this event (either its escalation
    reason, or 'critical' for a critical-severity event regardless of
    reason), POST a signed directive. Failures are swallowed -- same
    reasoning as dispatch_critical_alert: a broken customer endpoint must
    never take down ingestion for every tenant."""
    severity = event.get("severity")
    reason = event.get("escalation_reason")
    if severity is None:
        return

    triggers = {reason} if reason else set()
    if severity == "critical":
        triggers.add("critical")
    if not triggers:
        return

    db = get_db()
    res = (
        db.table("response_actions")
        .select("id, action_type, target_url, secret, trigger")
        .eq("tenant_id", tenant_id)
        .eq("enabled", True)
        .in_("trigger", list(triggers))
        .execute()
    )
    if not res.data:
        return

    for action in res.data:
        outcome = await send_directive(action, tenant_id, event, triggered_by=action["trigger"])
        log_dispatch(db, tenant_id, action["id"], event, outcome)


async def send_directive(action: dict, tenant_id: str, event: dict, triggered_by: str) -> str:
    """Builds and sends one signed directive; returns the real outcome
    ('sent' | 'failed' | 'blocked_unsafe_target'). Shared by the automatic
    path above (which swallows the outcome into the audit log) and the
    manual fire endpoint (which returns it to the analyst who clicked --
    a human pushing an external action needs to know whether it landed).
    'sent' means the request completed with a 2xx; a 4xx/5xx from the
    customer's endpoint is reported as 'failed', not silently treated as
    delivered."""
    payload = {
        "type": "network_ai.response_action",
        "action": action["action_type"],
        "tenant_id": tenant_id,
        "triggered_by": triggered_by,
        "event": {
            "flow_id": event.get("flow_id"),
            "severity": event.get("severity"),
            "escalation_reason": event.get("escalation_reason"),
            "consensus_count": event.get("consensus_count"),
            "src_ip": event.get("src_ip"),
        },
    }
    body = json.dumps(payload).encode()
    # Re-resolve and re-check right before sending, same reasoning as
    # core/webhooks.py -- closes the DNS-rebinding gap the creation-time
    # check alone can't.
    if not await resolve_and_check(action["target_url"]):
        return "blocked_unsafe_target"
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            resp = await client.post(
                action["target_url"],
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Signature": _sign(action["secret"], body),
                },
            )
        return "sent" if 200 <= resp.status_code < 300 else "failed"
    except Exception:
        return "failed"


def log_dispatch(db, tenant_id: str, action_id: str, event: dict, outcome: str):
    """Best-effort audit trail of what was actually dispatched and whether
    delivery succeeded -- an analyst asking "did we actually tell the
    firewall to block this?" needs an answer, not just a webhook fired into
    the void."""
    try:
        db.table("audit_log").insert({
            "tenant_id": tenant_id,
            "actor": "system",
            "action": "response_action.dispatched",
            "detail": {"response_action_id": action_id, "flow_id": event.get("flow_id"), "outcome": outcome},
        }).execute()
    except Exception:
        pass
