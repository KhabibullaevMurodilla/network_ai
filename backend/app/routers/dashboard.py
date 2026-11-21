"""Read endpoints for the frontend dashboard. Auth via logged-in user's
Supabase session (require_user) -- tenant scoping comes from their profile,
not from anything the client can pass in, so one tenant can never read
another's data even if it guesses an ID."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import ipaddress

from fastapi import APIRouter, Depends, Query, HTTPException, Request
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from ..core.auth import require_user, require_user_from_query_token, require_analyst
from ..core.db import get_db
from ..core.audit import log_action
from ..core.stream import event_stream
from ..core.mitre import mitre_for_anomaly_event, mitre_for_ot_event

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

ANOMALY_FIELDS = (
    "id, flow_id, detector, score, is_anomaly, severity, explanation, "
    "consensus_count, escalation_reason, entity_baseline_z, src_ip, triage_status, created_at"
)


@router.get("/anomalies/recent")
async def recent_anomalies(limit: int = Query(200, le=1000), src_ip: str | None = Query(None), user=Depends(require_user)):
    db = get_db()
    q = (
        db.table("anomaly_events")
        .select(ANOMALY_FIELDS)
        .eq("tenant_id", user["tenant_id"])
        .eq("detector", "ECOD")
    )
    if src_ip:
        q = q.eq("src_ip", src_ip)
    res = q.order("created_at", desc=True).limit(limit).execute()
    return [{**row, "mitre": mitre_for_anomaly_event(row.get("escalation_reason"))} for row in res.data]


OT_EVENT_FIELDS = (
    "id, protocol, ts, src_ip, dst_ip, unit_id, function_code, function_name, "
    "is_request, is_exception, exception_code, address, quantity, severity, reason, "
    "incident_id, created_at"
)


@router.get("/ot-events/recent")
async def recent_ot_events(limit: int = Query(200, le=1000), flagged_only: bool = Query(False), user=Depends(require_user)):
    """Modbus/TCP protocol events (ml/ot_rules.py's output) -- a separate
    feed from /anomalies/recent because these are message-level, rule-based
    OT events, not flow-level ML detector output. flagged_only=true filters
    to rows with a non-null severity (the ones an analyst actually needs to
    look at; most OT traffic is normal and unflagged by design)."""
    db = get_db()
    q = db.table("ot_protocol_events").select(OT_EVENT_FIELDS).eq("tenant_id", user["tenant_id"])
    if flagged_only:
        q = q.not_.is_("severity", "null")
    res = q.order("created_at", desc=True).limit(limit).execute()
    return [{**row, "mitre": mitre_for_ot_event(row.get("reason"))} for row in res.data]


@router.get("/anomalies/{event_id}")
async def anomaly_detail(event_id: int, user=Depends(require_user)):
    """Drill-down for one flagged event: the primary (ECOD) row plus the
    sibling IsolationForest/LOF scores for the same flow, and the raw flow
    record itself -- everything an analyst needs to decide whether this is
    real, without leaving the page."""
    db = get_db()
    primary = (
        db.table("anomaly_events")
        .select(ANOMALY_FIELDS)
        .eq("tenant_id", user["tenant_id"])
        .eq("id", event_id)
        .limit(1)
        .execute()
    ).data
    if not primary:
        raise HTTPException(status_code=404, detail="Event not found")
    event = primary[0]

    siblings = (
        db.table("anomaly_events")
        .select("detector, score, is_anomaly")
        .eq("tenant_id", user["tenant_id"])
        .eq("flow_id", event["flow_id"])
        .execute()
    ).data

    flow = (
        db.table("telemetry_flows")
        .select("*")
        .eq("tenant_id", user["tenant_id"])
        .eq("id", event["flow_id"])
        .limit(1)
        .execute()
    ).data
    flow = flow[0] if flow else None

    return {**event, "detector_scores": siblings, "flow": flow, "mitre": mitre_for_anomaly_event(event.get("escalation_reason"))}


@router.patch("/anomalies/{event_id}/triage")
async def update_triage(event_id: int, status: str = Query(..., pattern="^(new|acknowledged|resolved)$"), user=Depends(require_analyst)):
    """Alert triage workflow -- an analyst (or higher) can move a flagged
    event through new -> acknowledged -> resolved. Logged to the audit
    trail like every other state-changing action."""
    db = get_db()
    res = (
        db.table("anomaly_events")
        .update({"triage_status": status})
        .eq("tenant_id", user["tenant_id"])
        .eq("id", event_id)
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Event not found")
    log_action(user["tenant_id"], actor=user["user_id"], action="anomaly.triaged", detail={"event_id": event_id, "status": status})
    return res.data[0]


@router.get("/trend")
async def trend(
    days: int = Query(14, le=90),
    src_ip: str | None = Query(None),
    user=Depends(require_user),
):
    """Daily flagged-event counts by severity for the last N days -- the
    trend-over-time view a SOC dashboard is judged on as much as any single
    alert list. Optional src_ip narrows this to one entity's own trend
    (e.g. "is this specific host getting worse"), the same filter the
    entity detail view uses elsewhere."""
    db = get_db()
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    q = (
        db.table("anomaly_events")
        .select("severity, created_at")
        .eq("tenant_id", user["tenant_id"])
        .eq("detector", "ECOD")
        .not_.is_("severity", "null")
        .gte("created_at", since)
    )
    if src_ip:
        q = q.eq("src_ip", src_ip)
    rows = q.execute().data

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


@router.get("/stream")
async def stream(request: Request, token: str = Query(...)):
    """Server-Sent Events: pushes each newly flagged anomaly to any open
    dashboard tab the moment ingest.py scores it, instead of the dashboard
    polling on a timer. EventSource can't set an Authorization header, so
    the session token travels as a query parameter here specifically --
    the one deliberate exception to header-based auth in this API."""
    user = await require_user_from_query_token(token)
    return EventSourceResponse(event_stream(user["tenant_id"]))


@router.get("/summary")
async def summary(user=Depends(require_user)):
    db = get_db()
    total_flows = (
        db.table("telemetry_flows")
        .select("id", count="exact")
        .eq("tenant_id", user["tenant_id"])
        .execute()
    )
    anomalies = (
        db.table("anomaly_events")
        .select("id", count="exact")
        .eq("tenant_id", user["tenant_id"])
        .eq("detector", "ECOD")
        .eq("is_anomaly", True)
        .execute()
    )
    critical = (
        db.table("anomaly_events")
        .select("id", count="exact")
        .eq("tenant_id", user["tenant_id"])
        .eq("detector", "ECOD")
        .eq("severity", "critical")
        .execute()
    )
    return {
        "total_flows": total_flows.count or 0,
        "total_anomalies": anomalies.count or 0,
        "critical_anomalies": critical.count or 0,
        "tenant_id": user["tenant_id"],
        "role": user["role"],
        "focus": user.get("focus"),
        "user_id": user["user_id"],
    }


@router.get("/entities")
async def entity_view(limit: int = Query(500, le=2000), user=Depends(require_user)):
    """Groups recent flagged anomalies by source IP -- 'which machines are
    misbehaving' instead of a flat list of individual flows. Flows with no
    src_ip (a tenant that chose not to send real IPs) are grouped under
    'unidentified' rather than silently dropped."""
    db = get_db()

    anomalies = (
        db.table("anomaly_events")
        .select("flow_id, score, severity, created_at")
        .eq("tenant_id", user["tenant_id"])
        .eq("detector", "ECOD")
        .eq("is_anomaly", True)
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    ).data

    if not anomalies:
        return []

    flow_ids = [a["flow_id"] for a in anomalies if a["flow_id"] is not None]
    flows = (
        db.table("telemetry_flows")
        .select("id, src_ip, dst_ip, proto")
        .eq("tenant_id", user["tenant_id"])
        .in_("id", flow_ids)
        .execute()
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
        cur_rank = severity_rank.get(e["max_severity"], -1)
        new_rank = severity_rank.get(a["severity"], -1)
        if new_rank > cur_rank:
            e["max_severity"] = a["severity"]

    return [
        {
            "source": src,
            "event_count": e["event_count"],
            "max_severity": e["max_severity"],
            "protocols": sorted(e["protocols"]),
            "last_seen": e["last_seen"],
        }
        for src, e in sorted(entities.items(), key=lambda kv: kv[1]["event_count"], reverse=True)
    ]


@router.get("/devices")
async def devices(role: str | None = Query(None), user=Depends(require_user)):
    """Passively discovered devices (see ingestion/discovery.py). Roles are
    heuristics with evidence + confidence, not verified physical topology."""
    q = db_devices_query(user["tenant_id"])
    if role:
        q = q.eq("role", role)
    try:
        return q.order("last_seen", desc=True).limit(500).execute().data
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Device inventory table missing -- run the 'network_devices' section of supabase/schema.sql (v6.5) in the Supabase SQL editor.",
        )


_SERVICES = {80: "http", 443: "https", 53: "dns", 22: "ssh", 123: "ntp", 25: "smtp", 587: "smtp", 993: "imaps", 995: "pop3s",
             143: "imap", 21: "ftp", 3389: "rdp", 5228: "fcm/play", 8080: "http-alt", 8443: "https-alt", 1883: "mqtt", 8883: "mqtts"}


@router.get("/external")
async def external(
    sort: str = Query("bytes", pattern="^(bytes|flows|recent|flagged)$"),
    flagged_only: bool = False, limit: int = Query(200, ge=1, le=1000), user=Depends(require_user),
):
    """Internet endpoints this tenant's devices talk to (from uploaded
    captures), with hostnames seen in DNS/TLS and how many flagged events
    involved each remote IP (counted per IP, across ports)."""
    db = get_db()
    tid = user["tenant_id"]
    try:
        rows = db.table("external_endpoints").select("*").eq("tenant_id", tid).limit(5000).execute().data
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="External-endpoints table missing -- run network_devices_migration.sql (v6.7) in the Supabase SQL editor.",
        )
    # flagged events (primary ECOD row carries the severity) -> their flows -> the public side
    flagged_by_ip: dict[str, int] = {}
    ev = (
        db.table("anomaly_events").select("flow_id").eq("tenant_id", tid).eq("detector", "ECOD")
        .not_.is_("severity", "null").limit(5000).execute().data
    )
    ids = [e["flow_id"] for e in ev if e.get("flow_id") is not None]
    for i in range(0, len(ids), 200):
        for f in db.table("telemetry_flows").select("id, src_ip, dst_ip").eq("tenant_id", tid).in_("id", ids[i:i + 200]).execute().data:
            for ip in (f.get("src_ip"), f.get("dst_ip")):
                if ip and not _is_private_ip(ip):
                    flagged_by_ip[ip] = flagged_by_ip.get(ip, 0) + 1
    out = []
    for r in rows:
        r["service"] = _SERVICES.get(r["remote_port"], str(r["remote_port"]))
        r["bytes_total"] = (r.get("bytes_out") or 0) + (r.get("bytes_in") or 0)
        r["flagged"] = flagged_by_ip.get(r["remote_ip"], 0)
        out.append(r)
    if flagged_only:
        out = [r for r in out if r["flagged"] > 0]
    key = {"bytes": lambda r: r["bytes_total"], "flows": lambda r: r["flows"], "recent": lambda r: r["last_seen"], "flagged": lambda r: r["flagged"]}[sort]
    out.sort(key=key, reverse=True)
    return out[:limit]


def _is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return not a.is_global
    except ValueError:
        return True


@router.get("/physical")
async def physical(user=Depends(require_user)):
    """Physical map: devices that take part in at least one SNMP-learned link
    (plus every switch/router/AP), and the links between them."""
    try:
        links = (
            get_db().table("network_links").select("id, a_key, a_port, b_key, b_port, source, evidence, last_seen")
            .eq("tenant_id", user["tenant_id"]).limit(2000).execute().data
        )
        devs = db_devices_query(user["tenant_id"]).limit(2000).execute().data
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Link tables missing -- run network_devices_migration.sql (v6.6) in the Supabase SQL editor.",
        )
    in_links = {l["a_key"] for l in links} | {l["b_key"] for l in links}
    infra = {"switch", "router", "access_point", "gateway"}
    nodes = [
        {"id": d["device_key"], "role": d["role"], "label": d.get("hostname") or d.get("ip") or d["device_key"],
         "ip": d.get("ip"), "mac": d.get("mac"), "confidence": d["confidence"]}
        for d in devs if d["device_key"] in in_links or d["role"] in infra
    ]
    known = {n["id"] for n in nodes}
    for k in in_links - known:  # link endpoints with no device row yet
        nodes.append({"id": k, "role": "unknown", "label": k.split(":", 1)[-1], "ip": None, "mac": None, "confidence": "low"})
    return {"nodes": nodes, "links": links}


def db_devices_query(tenant_id: str):
    return (
        get_db().table("network_devices")
        .select("id, device_key, mac, ip, ips, role, tags, hostname, os_hint, services, mac_randomized, evidence, confidence, first_seen, last_seen")
        .eq("tenant_id", tenant_id)
    )


@router.get("/topology")
async def topology(
    limit: int = Query(2000, le=5000),
    max_nodes: int = Query(150, le=500),
    user=Depends(require_user),
):
    """Node-link graph of recent traffic: nodes are IPs seen as a flow
    source or destination, edges are (src, dst) pairs weighted by flow
    count. Anomaly counts/severity are joined in per source node from the
    same entity aggregation /entities uses, so a node's color on the graph
    matches its row in the entity table. Deliberately source data for a
    visual, not a full topology discovery tool -- it only knows about IPs
    that showed up in ingested flow telemetry, nothing from SNMP/LLDP/ARP,
    and `limit` bounds how much of that telemetry one request scans."""
    db = get_db()

    flows = (
        db.table("telemetry_flows")
        .select("src_ip, dst_ip, proto")
        .eq("tenant_id", user["tenant_id"])
        .not_.is_("src_ip", "null")
        .not_.is_("dst_ip", "null")
        .order("received_at", desc=True)
        .limit(limit)
        .execute()
    ).data

    anomalies = (
        db.table("anomaly_events")
        .select("src_ip, severity")
        .eq("tenant_id", user["tenant_id"])
        .eq("detector", "ECOD")
        .eq("is_anomaly", True)
        .not_.is_("src_ip", "null")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    ).data

    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    node_anomalies: dict[str, dict] = defaultdict(lambda: {"event_count": 0, "max_severity": None})
    for a in anomalies:
        na = node_anomalies[a["src_ip"]]
        na["event_count"] += 1
        if severity_rank.get(a["severity"], -1) > severity_rank.get(na["max_severity"], -1):
            na["max_severity"] = a["severity"]

    edge_counts: dict[tuple[str, str], int] = defaultdict(int)
    node_ids: set[str] = set()
    for f in flows:
        src, dst = f["src_ip"], f["dst_ip"]
        edge_counts[(src, dst)] += 1
        node_ids.add(src)
        node_ids.add(dst)
        if len(node_ids) > max_nodes:
            break  # bounded for render sanity -- this is a visual, not a full inventory

    # Role/hostname from passive discovery, when available. The table is
    # new in v6.5: if the migration hasn't been run yet, the topology must
    # still render, just without roles.
    roles: dict[str, dict] = {}
    try:
        for d in db_devices_query(user["tenant_id"]).limit(1000).execute().data:
            for ip in set((d.get("ips") or []) + ([d["ip"]] if d.get("ip") else [])):
                roles[ip] = {"role": d["role"], "hostname": d.get("hostname")}
    except Exception:
        roles = {}

    nodes = [
        {
            "id": ip,
            "event_count": node_anomalies[ip]["event_count"],
            "max_severity": node_anomalies[ip]["max_severity"],
            "role": roles.get(ip, {}).get("role"),
            "hostname": roles.get(ip, {}).get("hostname"),
        }
        for ip in node_ids
    ]
    edges = [
        {"source": src, "target": dst, "flow_count": count}
        for (src, dst), count in edge_counts.items()
        if src in node_ids and dst in node_ids
    ]
    return {"nodes": nodes, "edges": edges, "truncated": len(node_ids) >= max_nodes}


class SuppressionRequest(BaseModel):
    src_ip: str
    reason: str | None = None


@router.get("/suppressions")
async def list_suppressions(user=Depends(require_user)):
    db = get_db()
    res = (
        db.table("entity_suppressions")
        .select("id, src_ip, reason, created_by, created_at")
        .eq("tenant_id", user["tenant_id"])
        .order("created_at", desc=True)
        .execute()
    )
    return res.data


@router.post("/suppressions")
async def create_suppression(req: SuppressionRequest, user=Depends(require_analyst)):
    """Self-service alert tuning (v6.3): mute a known-noisy source so it
    stops reaching notify webhooks/response actions. Does NOT hide the
    entity from anomalies/entities views or stop it being scored -- see
    core/webhooks.py's dispatch-time check, the only place this is
    enforced. analyst-or-higher (same bar as alert triage), not
    admin-only: quieting noise is a SOC workflow action, not a tenant
    configuration change."""
    try:
        ipaddress.ip_address(req.src_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{req.src_ip}' is not a valid IP address")
    db = get_db()
    # Checked in application code (not left to the DB's unique(tenant_id,
    # src_ip) constraint alone) so the duplicate case is a clean, specific
    # 409 under every backend this runs against, not whatever shape a raw
    # constraint-violation exception happens to take.
    existing = (
        db.table("entity_suppressions")
        .select("id")
        .eq("tenant_id", user["tenant_id"])
        .eq("src_ip", req.src_ip)
        .limit(1)
        .execute()
    )
    if existing.data:
        raise HTTPException(status_code=409, detail=f"'{req.src_ip}' is already muted")
    res = db.table("entity_suppressions").insert({
        "tenant_id": user["tenant_id"],
        "src_ip": req.src_ip,
        "reason": req.reason,
        "created_by": user["user_id"],
    }).execute()
    log_action(user["tenant_id"], actor=user["user_id"], action="entity.suppressed", detail={"src_ip": req.src_ip})
    return res.data[0]


@router.delete("/suppressions/{suppression_id}")
async def delete_suppression(suppression_id: str, user=Depends(require_analyst)):
    db = get_db()
    db.table("entity_suppressions").delete().eq("id", suppression_id).eq("tenant_id", user["tenant_id"]).execute()
    log_action(user["tenant_id"], actor=user["user_id"], action="entity.unsuppressed", detail={"id": suppression_id})
    return {"deleted": True}
