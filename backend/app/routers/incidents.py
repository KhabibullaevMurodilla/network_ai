"""Read + status-transition endpoints for incidents -- the correlated view
built by core/incidents.py at ingest time. See that module for the
correlation rule itself; this router just exposes it to the dashboard."""
from fastapi import APIRouter, Depends, HTTPException, Query
from ..core.auth import require_user, require_analyst
from ..core.db import get_db
from ..core.audit import log_action

router = APIRouter(prefix="/dashboard/incidents", tags=["incidents"])


@router.get("")
async def list_incidents(status: str | None = Query(None, pattern="^(open|closed)$"), user=Depends(require_user)):
    db = get_db()
    q = db.table("incidents").select("*").eq("tenant_id", user["tenant_id"])
    if status:
        q = q.eq("status", status)
    res = q.order("last_seen", desc=True).limit(200).execute()
    return res.data


@router.get("/{incident_id}")
async def incident_detail(incident_id: str, user=Depends(require_user)):
    db = get_db()
    incident = (
        db.table("incidents")
        .select("*")
        .eq("tenant_id", user["tenant_id"])
        .eq("id", incident_id)
        .limit(1)
        .execute()
    ).data
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    events = (
        db.table("anomaly_events")
        .select("id, flow_id, score, severity, explanation, consensus_count, escalation_reason, triage_status, created_at")
        .eq("tenant_id", user["tenant_id"])
        .eq("incident_id", incident_id)
        .eq("detector", "ECOD")
        .order("created_at", desc=True)
        .execute()
    ).data

    return {**incident[0], "events": events}


@router.patch("/{incident_id}/status")
async def update_incident_status(incident_id: str, status: str = Query(..., pattern="^(open|closed)$"), user=Depends(require_analyst)):
    db = get_db()
    res = (
        db.table("incidents")
        .update({"status": status})
        .eq("tenant_id", user["tenant_id"])
        .eq("id", incident_id)
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Incident not found")
    log_action(user["tenant_id"], actor=user["user_id"], action="incident.status_changed",
               detail={"incident_id": incident_id, "status": status})
    return res.data[0]
