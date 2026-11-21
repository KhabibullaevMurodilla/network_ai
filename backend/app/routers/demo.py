"""Public, unauthenticated, read-only demo (v6.3) -- lets a prospect click
around on real (synthetic) data instead of trusting screenshots in a pitch
deck. Scoped hard: every route in this file only ever reads
settings.DEMO_TENANT_ID, never anything derived from the request, and the
whole router 404s if that setting isn't configured (fail closed, not "show
whatever tenant happens to exist"). No mutation routes exist here at all --
not "mutations require auth," there simply are none, so there's no
triage/mute/export/erase surface to abuse without a login.

Rate-limited per IP (no API key or session to bucket by, since this is
intentionally unauthenticated) -- tighter than any authenticated route in
this codebase, since an open, no-login endpoint is the one with the least
natural throttle on who can hit it."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query, Request

from ..core.config import settings
from ..core.db import get_db
from ..core.limiter import limiter

router = APIRouter(prefix="/demo", tags=["demo"])


def _require_demo_tenant() -> str:
    if not settings.DEMO_TENANT_ID:
        raise HTTPException(status_code=404, detail="Demo not configured")
    return settings.DEMO_TENANT_ID


@router.get("/summary")
@limiter.limit("30/minute")
async def demo_summary(request: Request):
    tenant_id = _require_demo_tenant()
    db = get_db()
    flows = db.table("telemetry_flows").select("id").eq("tenant_id", tenant_id).execute().data
    anomalies = (
        db.table("anomaly_events").select("id")
        .eq("tenant_id", tenant_id).eq("detector", "ECOD").eq("is_anomaly", True).execute()
    ).data
    critical = (
        db.table("anomaly_events").select("id")
        .eq("tenant_id", tenant_id).eq("detector", "ECOD").eq("severity", "critical").execute()
    ).data
    return {
        "total_flows": len(flows),
        "total_anomalies": len(anomalies),
        "critical_anomalies": len(critical),
        "is_demo": True,
    }


@router.get("/anomalies/recent")
@limiter.limit("30/minute")
async def demo_recent_anomalies(request: Request, limit: int = Query(50, le=200)):
    tenant_id = _require_demo_tenant()
    db = get_db()
    res = (
        db.table("anomaly_events")
        .select("id, score, is_anomaly, severity, explanation, consensus_count, escalation_reason, src_ip, created_at")
        .eq("tenant_id", tenant_id).eq("detector", "ECOD")
        .order("created_at", desc=True).limit(limit).execute()
    )
    return res.data


@router.get("/entities")
@limiter.limit("30/minute")
async def demo_entities(request: Request):
    tenant_id = _require_demo_tenant()
    db = get_db()
    anomalies = (
        db.table("anomaly_events").select("flow_id, score, severity, created_at")
        .eq("tenant_id", tenant_id).eq("detector", "ECOD").eq("is_anomaly", True)
        .order("created_at", desc=True).limit(500).execute()
    ).data
    if not anomalies:
        return []
    flow_ids = [a["flow_id"] for a in anomalies if a["flow_id"] is not None]
    flows = (
        db.table("telemetry_flows").select("id, src_ip, dst_ip, proto")
        .eq("tenant_id", tenant_id).in_("id", flow_ids).execute()
    ).data
    flow_by_id = {f["id"]: f for f in flows}

    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    entities = defaultdict(lambda: {"event_count": 0, "max_severity": None, "protocols": set(), "last_seen": None})
    for a in anomalies:
        flow = flow_by_id.get(a["flow_id"], {})
        src = flow.get("src_ip") or "unidentified"
        e = entities[src]
        e["event_count"] += 1
        if flow.get("proto"):
            e["protocols"].add(flow["proto"])
        seen = a.get("created_at")
        if seen is not None and (e["last_seen"] is None or seen > e["last_seen"]):
            e["last_seen"] = seen
        if severity_rank.get(a["severity"], -1) > severity_rank.get(e["max_severity"], -1):
            e["max_severity"] = a["severity"]

    return [
        {"source": src, "event_count": e["event_count"], "max_severity": e["max_severity"],
         "protocols": sorted(e["protocols"]), "last_seen": e["last_seen"]}
        for src, e in sorted(entities.items(), key=lambda kv: kv[1]["event_count"], reverse=True)
    ]


@router.get("/trend")
@limiter.limit("30/minute")
async def demo_trend(request: Request, days: int = Query(14, le=30)):
    tenant_id = _require_demo_tenant()
    db = get_db()
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = (
        db.table("anomaly_events").select("severity, created_at")
        .eq("tenant_id", tenant_id).eq("detector", "ECOD")
        .not_.is_("severity", "null").gte("created_at", since).execute()
    ).data
    by_day: dict[str, dict[str, int]] = defaultdict(lambda: {"low": 0, "medium": 0, "high": 0, "critical": 0})
    for r in rows:
        created = r.get("created_at")
        if not created:
            continue
        day = created[:10]
        sev = r["severity"]
        if sev in by_day[day]:
            by_day[day][sev] += 1
    return [{"date": day, **counts} for day, counts in sorted(by_day.items())]
