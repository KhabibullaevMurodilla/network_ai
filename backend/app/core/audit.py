"""Append-only security audit trail. Every call here is a write a tenant
admin can later read (via GET /privacy/audit-log) but, by RLS policy,
never edit or delete — see supabase/schema.sql's audit_log table."""
from .db import get_db


def log_action(tenant_id: str, actor: str, action: str, detail: dict | None = None):
    """actor is the Supabase user id for a dashboard action, or
    f"api_key:{key_id}" for an ingestion-path action, or "system" for an
    automated one (e.g. a retention purge)."""
    try:
        db = get_db()
        db.table("audit_log").insert({
            "tenant_id": tenant_id,
            "actor": actor,
            "action": action,
            "detail": detail or {},
        }).execute()
    except Exception:
        # Audit logging must never break the request it's observing --
        # a logging failure degrades traceability, not availability.
        pass
