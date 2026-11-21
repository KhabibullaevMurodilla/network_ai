"""Tenant + API key management -- creating a new tenant, issuing/revoking
scoped API keys for the telemetry ingestion path."""
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from ..core.auth import require_user, require_admin, hash_key
from ..core.db import get_db
from ..core.audit import log_action
from ..core.limiter import limiter, user_key_func

router = APIRouter(prefix="/tenants", tags=["tenants"])


class CreateApiKeyRequest(BaseModel):
    label: str = "default"
    scope: str = "ingest"  # 'ingest' | 'read' | 'admin' -- least privilege by default


@router.post("/api-keys")
@limiter.limit("20/minute", key_func=user_key_func)
async def create_api_key(request: Request, req: CreateApiKeyRequest, user=Depends(require_admin)):
    if req.scope not in ("ingest", "read", "admin"):
        raise HTTPException(status_code=400, detail="scope must be ingest, read, or admin")

    raw_key = f"nai_{secrets.token_urlsafe(32)}"  # shown once, never stored raw
    db = get_db()
    row = db.table("api_keys").insert({
        "tenant_id": user["tenant_id"],
        "key_hash": hash_key(raw_key),
        "label": req.label,
        "scope": req.scope,
    }).execute()

    log_action(
        user["tenant_id"], actor=user["user_id"], action="api_key.created",
        detail={"label": req.label, "scope": req.scope, "key_id": row.data[0]["id"]},
    )
    return {"api_key": raw_key, "scope": req.scope, "warning": "Store this now -- it will not be shown again."}


@router.get("/api-keys")
async def list_api_keys(user=Depends(require_user)):
    """Lists this tenant's keys by label/scope/dates only -- raw keys are
    never stored, so a listing can never show the key value again after
    creation."""
    db = get_db()
    res = (
        db.table("api_keys")
        .select("id, label, scope, created_at, last_used_at, revoked_at")
        .eq("tenant_id", user["tenant_id"])
        .order("created_at", desc=True)
        .execute()
    )
    return res.data


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: str, user=Depends(require_admin)):
    db = get_db()
    db.table("api_keys").update({"revoked_at": "now()"}).eq("id", key_id).eq(
        "tenant_id", user["tenant_id"]
    ).execute()
    log_action(user["tenant_id"], actor=user["user_id"], action="api_key.revoked", detail={"key_id": key_id})
    return {"revoked": True}


@router.get("/me")
async def my_tenant(user=Depends(require_user)):
    db = get_db()
    res = db.table("tenants").select("*").eq("id", user["tenant_id"]).single().execute()
    return res.data


class AlertSettingsRequest(BaseModel):
    alert_min_severity: str


@router.patch("/me/alert-settings")
@limiter.limit("20/minute", key_func=user_key_func)
async def update_alert_settings(request: Request, req: AlertSettingsRequest, user=Depends(require_admin)):
    """Self-service alert tuning (v6.3): the tenant-wide floor below which
    a flagged event never reaches a notify webhook or response action,
    regardless of any individual webhook's own (per-channel) min_severity.
    Does not affect what's stored or visible in the dashboard -- only
    paging. See core/webhooks.py's _below_tenant_floor for the enforcement
    point."""
    if req.alert_min_severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=400, detail="alert_min_severity must be low/medium/high/critical")
    db = get_db()
    res = (
        db.table("tenants")
        .update({"alert_min_severity": req.alert_min_severity})
        .eq("id", user["tenant_id"])
        .execute()
    )
    log_action(
        user["tenant_id"], actor=user["user_id"], action="tenant.alert_settings_updated",
        detail={"alert_min_severity": req.alert_min_severity},
    )
    return res.data[0] if res.data else {"alert_min_severity": req.alert_min_severity}
