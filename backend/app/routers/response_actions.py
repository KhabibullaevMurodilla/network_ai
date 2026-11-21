"""CRUD for a tenant's automated response actions -- see core/response_actions.py
for the dispatch side and the scoping disclaimer. Same secret-handling
pattern as webhooks.py: generated server-side, returned once at creation,
and visible on subsequent reads (not hashed) because the tenant's own
receiving system needs it to verify the HMAC signature on what we send
them -- it's signing key material we both hold, not a bearer credential
that grants access back to us."""
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from ..core.auth import require_admin, require_user, require_analyst
from ..core.db import get_db
from ..core.audit import log_action
from ..core.url_safety import validate_url_or_raise
from ..core.limiter import limiter, user_key_func
from ..core.response_actions import send_directive

router = APIRouter(prefix="/response-actions", tags=["response-actions"])

VALID_TRIGGERS = ("critical", "entity_burst", "entity_baseline_drift", "ensemble_consensus")
VALID_ACTION_TYPES = ("webhook_block", "webhook_notify_soar")


class CreateResponseActionRequest(BaseModel):
    trigger: str = "critical"
    action_type: str = "webhook_block"
    target_url: str


@router.post("")
@limiter.limit("20/minute", key_func=user_key_func)
async def create_response_action(request: Request, req: CreateResponseActionRequest, user=Depends(require_admin)):
    if req.trigger not in VALID_TRIGGERS:
        raise HTTPException(status_code=400, detail=f"trigger must be one of {VALID_TRIGGERS}")
    if req.action_type not in VALID_ACTION_TYPES:
        raise HTTPException(status_code=400, detail=f"action_type must be one of {VALID_ACTION_TYPES}")
    try:
        validate_url_or_raise(req.target_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    db = get_db()
    secret = secrets.token_hex(32)
    res = db.table("response_actions").insert({
        "tenant_id": user["tenant_id"],
        "trigger": req.trigger,
        "action_type": req.action_type,
        "target_url": req.target_url,
        "secret": secret,
    }).execute()
    log_action(user["tenant_id"], actor=user["user_id"], action="response_action.created",
               detail={"trigger": req.trigger, "action_type": req.action_type})
    return res.data[0]


@router.get("")
async def list_response_actions(user=Depends(require_user)):
    db = get_db()
    res = (
        db.table("response_actions")
        .select("*")
        .eq("tenant_id", user["tenant_id"])
        .order("created_at", desc=True)
        .execute()
    )
    return res.data


@router.delete("/{action_id}")
async def delete_response_action(action_id: str, user=Depends(require_admin)):
    db = get_db()
    db.table("response_actions").delete().eq("id", action_id).eq("tenant_id", user["tenant_id"]).execute()
    log_action(user["tenant_id"], actor=user["user_id"], action="response_action.deleted", detail={"id": action_id})
    return {"deleted": True}


class FireRequest(BaseModel):
    event_id: int | str


@router.post("/{action_id}/fire")
@limiter.limit("30/minute", key_func=user_key_func)
async def fire_response_action(request: Request, action_id: str, req: FireRequest, user=Depends(require_analyst)):
    """Manual, on-demand fire of a configured response action against one
    specific anomaly event (v6.4) -- the interactive counterpart to the
    automatic trigger-based dispatch. Same signed directive, same SSRF
    re-check, but synchronous: the analyst who clicked gets the real
    outcome back ('sent' / 'failed' / 'blocked_unsafe_target') instead of
    a fire-and-forget. Both the action and the event are looked up scoped
    to the caller's tenant, so neither id can reach across tenants. Still
    only a signed directive to the customer's own system -- this product
    has no enforcement point of its own."""
    db = get_db()
    action = (
        db.table("response_actions").select("*")
        .eq("id", action_id).eq("tenant_id", user["tenant_id"]).limit(1).execute()
    ).data
    if not action:
        raise HTTPException(status_code=404, detail="No such response action")
    event = (
        db.table("anomaly_events")
        .select("id, flow_id, severity, escalation_reason, consensus_count, src_ip")
        .eq("id", req.event_id).eq("tenant_id", user["tenant_id"]).eq("detector", "ECOD").limit(1).execute()
    ).data
    if not event:
        raise HTTPException(status_code=404, detail="No such event")
    outcome = await send_directive(action[0], user["tenant_id"], event[0], triggered_by="manual")
    log_action(
        user["tenant_id"], actor=user["user_id"], action="response_action.manually_fired",
        detail={"response_action_id": action_id, "event_id": req.event_id, "outcome": outcome},
    )
    return {"outcome": outcome}
