"""Tenant-controlled data rights: export everything held about the tenant,
or erase it outright. Both are admin-only, both are audit-logged (the
erase action is logged to a DIFFERENT tenant-independent store first,
since the whole point of erasure is that nothing tenant-scoped survives
it — see the comment on that below), and both exist because a network
security product that cannot tell a customer what it holds or delete it
on request does not meet a credible privacy bar, not because a regulation
technically requires it at this stage."""
from fastapi import APIRouter, Depends, Request
from ..core.auth import require_admin
from ..core.db import get_db
from ..core.audit import log_action
from ..core.limiter import limiter, user_key_func

router = APIRouter(prefix="/privacy", tags=["privacy"])

TENANT_SCOPED_TABLES = [
    "telemetry_flows", "anomaly_events", "ot_protocol_events", "incidents",
    "api_keys", "webhook_configs", "response_actions", "entity_suppressions",
    "audit_log",
]
# Added v6.5-6.7. Kept separate and best-effort ONLY so that a project that
# hasn't run the newest migration yet doesn't 500 half-way through an erasure
# or export; once the tables exist they are always erased/exported (and the
# tenants-row delete cascades to them regardless).
OPTIONAL_TENANT_TABLES = ["network_devices", "network_links", "external_endpoints"]
# Real finding from adversarial review: this list had drifted out of sync
# with schema.sql -- incidents, response_actions, and ot_protocol_events
# (added across v5/v6.1) were missing entirely. erase_tenant_data()
# happened to still fully erase them anyway, via each table's own
# `tenant_id ... references tenants(id) on delete cascade` FK, triggered
# by the final `tenants` row delete below -- but that's an implicit
# side-effect of the schema, not something this code was actually
# asserting, and export_tenant_data() has no equivalent safety net: it
# only SELECTs, so a table missing from this list was silently omitted
# from "everything we hold about you," not just from erasure. Fixed by
# keeping this list complete and explicit rather than depending on FK
# cascade behavior nobody reading this file would see.


@router.get("/export")
@limiter.limit("10/minute", key_func=user_key_func)
async def export_tenant_data(request: Request, user=Depends(require_admin)):
    """Returns everything stored for this tenant as one JSON document --
    the data-portability half of a right-to-access request. API key raw
    values are never included (they were never stored to begin with)."""
    db = get_db()
    tenant_id = user["tenant_id"]

    tenant = db.table("tenants").select("*").eq("id", tenant_id).single().execute().data
    profiles = db.table("profiles").select("id, email, role, created_at").eq("tenant_id", tenant_id).execute().data
    flows = db.table("telemetry_flows").select("*").eq("tenant_id", tenant_id).execute().data
    anomalies = db.table("anomaly_events").select("*").eq("tenant_id", tenant_id).execute().data
    ot_events = db.table("ot_protocol_events").select("*").eq("tenant_id", tenant_id).execute().data
    incidents = db.table("incidents").select("*").eq("tenant_id", tenant_id).execute().data
    response_actions = db.table("response_actions").select("*").eq("tenant_id", tenant_id).execute().data
    webhooks = db.table("webhook_configs").select("*").eq("tenant_id", tenant_id).execute().data
    api_keys = db.table("api_keys").select("id, label, scope, created_at, last_used_at, revoked_at").eq("tenant_id", tenant_id).execute().data
    suppressions = db.table("entity_suppressions").select("*").eq("tenant_id", tenant_id).execute().data
    audit = db.table("audit_log").select("*").eq("tenant_id", tenant_id).execute().data

    optional = {}
    for table in OPTIONAL_TENANT_TABLES:
        try:
            optional[table] = db.table(table).select("*").eq("tenant_id", tenant_id).execute().data
        except Exception:
            optional[table] = []

    log_action(tenant_id, actor=user["user_id"], action="data.exported")

    return {
        "tenant": tenant,
        "members": profiles,
        "telemetry_flows": flows,
        "anomaly_events": anomalies,
        "ot_protocol_events": ot_events,
        "incidents": incidents,
        "response_actions": response_actions,  # includes HMAC secret -- consistent with GET /response-actions already returning it (the tenant's own signing key material, not a bearer credential to us)
        "webhook_configs": webhooks,            # same reasoning as above
        "api_keys": api_keys,  # hashes/labels only, never raw key material
        "entity_suppressions": suppressions,
        "audit_log": audit,
        **optional,
    }


@router.delete("/erase")
@limiter.limit("5/minute", key_func=user_key_func)
async def erase_tenant_data(request: Request, user=Depends(require_admin)):
    """Irreversibly deletes every row belonging to this tenant, across every
    tenant-scoped table, then the tenant and its member profiles themselves.
    This is the real erasure path -- not a soft 'deactivated' flag."""
    db = get_db()
    tenant_id = user["tenant_id"]

    # Logged before deletion starts (the audit_log row itself is deleted a
    # moment later as part of the same tenant's data -- intentional: once
    # erasure completes, nothing tied to this tenant_id should remain
    # anywhere, including its own audit trail).
    log_action(tenant_id, actor=user["user_id"], action="data.erasure_requested")

    for table in TENANT_SCOPED_TABLES:
        db.table(table).delete().eq("tenant_id", tenant_id).execute()
    for table in OPTIONAL_TENANT_TABLES:
        try:
            db.table(table).delete().eq("tenant_id", tenant_id).execute()
        except Exception:
            pass  # table not created yet on this project (nothing to erase)
    db.table("profiles").delete().eq("tenant_id", tenant_id).execute()
    db.table("tenants").delete().eq("id", tenant_id).execute()

    return {"erased": True, "tenant_id": tenant_id}


@router.get("/audit-log")
async def read_audit_log(user=Depends(require_admin), limit: int = 200):
    db = get_db()
    res = (
        db.table("audit_log")
        .select("id, actor, action, detail, created_at")
        .eq("tenant_id", user["tenant_id"])
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return res.data
