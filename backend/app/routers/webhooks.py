"""CRUD for a tenant's alert-delivery webhooks. The signing secret is
generated server-side and shown once at creation, same pattern as an API
key -- it is never stored in recoverable form, only used at send-time
(read from the DB row, which the backend's service role can access but a
dashboard user cannot, since webhook_configs' RLS policy is select-only
for the secret's own row... actually the secret IS visible to the tenant
via the select policy, since they need it to verify signatures on their
receiving end. This is intentional and different from an API key: the
webhook secret is HMAC key material the tenant must have to validate our
requests, not a bearer credential that grants access to us."""
import re
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from ..core.auth import require_admin, require_user
from ..core.db import get_db
from ..core.audit import log_action
from ..core.url_safety import validate_url_or_raise
from ..core.limiter import limiter, user_key_func

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class CreateWebhookRequest(BaseModel):
    channel_type: str = "generic"  # 'generic' | 'slack' | 'teams' | 'email'
    url: str | None = None
    email_to: str | None = None
    min_severity: str = "critical"


@router.post("")
@limiter.limit("20/minute", key_func=user_key_func)
async def create_webhook(request: Request, req: CreateWebhookRequest, user=Depends(require_admin)):
    if req.min_severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=400, detail="min_severity must be low/medium/high/critical")
    if req.channel_type not in ("generic", "slack", "teams", "email"):
        raise HTTPException(status_code=400, detail="channel_type must be generic, slack, teams, or email")

    if req.channel_type == "email":
        if not req.email_to or not EMAIL_RE.match(req.email_to):
            raise HTTPException(status_code=400, detail="A valid email_to address is required for the email channel")
        url = None
    else:
        if not req.url:
            raise HTTPException(status_code=400, detail="url is required for generic/slack/teams channels")
        try:
            validate_url_or_raise(req.url)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        url = req.url

    db = get_db()
    secret = secrets.token_hex(32)
    res = db.table("webhook_configs").insert({
        "tenant_id": user["tenant_id"],
        "channel_type": req.channel_type,
        "url": url,
        "email_to": req.email_to if req.channel_type == "email" else None,
        "secret": secret,
        "min_severity": req.min_severity,
    }).execute()
    log_action(
        user["tenant_id"], actor=user["user_id"], action="webhook.created",
        detail={"channel_type": req.channel_type, "url": url, "email_to": req.email_to},
    )
    return res.data[0]


@router.get("")
async def list_webhooks(user=Depends(require_user)):
    db = get_db()
    res = (
        db.table("webhook_configs")
        .select("*")
        .eq("tenant_id", user["tenant_id"])
        .execute()
    )
    return res.data


@router.delete("/{webhook_id}")
async def delete_webhook(webhook_id: str, user=Depends(require_admin)):
    db = get_db()
    db.table("webhook_configs").delete().eq("id", webhook_id).eq("tenant_id", user["tenant_id"]).execute()
    log_action(user["tenant_id"], actor=user["user_id"], action="webhook.deleted", detail={"id": webhook_id})
    return {"deleted": True}
