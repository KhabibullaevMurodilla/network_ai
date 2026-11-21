"""Incident correlation: turns "47 separate alerts from the same host over
an hour" into "1 incident, 47 events, still open" -- the correlation a real
SOC tool is judged on as much as detection accuracy itself. An analyst
triaging a flat alert list for a sustained scan has to manually notice the
47 rows share a source; an analyst looking at incidents sees it as one
thing from the start.

Correlation rule, stated plainly because it's intentionally simple rather
than a learned/clustering approach: flagged events from the same source IP
(or "unidentified" if none was sent) within a rolling time window attach to
the same open incident; a source with no recent open incident gets a new
one. This is a real, useful first correlation heuristic -- not a claim of
sophisticated multi-entity attack-chain reconstruction, which would need
much more signal (and manual rule curation, or training data this project
doesn't have) than one tenant's early telemetry can support.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timedelta, timezone

INCIDENT_CORRELATION_WINDOW_MINUTES = 30
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _higher_severity(a: str | None, b: str | None) -> str | None:
    return max([a, b], key=lambda s: SEVERITY_RANK.get(s, -1) if s else -1)


def correlate_incidents(db, tenant_id: str, flagged_rows: list[dict]) -> None:
    """Mutates each dict in flagged_rows in place, adding "incident_id".
    Called before those same dicts are inserted into anomaly_events, so the
    foreign key is already set on first write -- no follow-up update pass
    needed on the anomaly rows themselves."""
    if not flagged_rows:
        return

    by_entity: dict[str, list[dict]] = defaultdict(list)
    for row in flagged_rows:
        entity = row.get("src_ip") or "unidentified"
        by_entity[entity].append(row)

    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=INCIDENT_CORRELATION_WINDOW_MINUTES)).isoformat()

    for entity, rows in by_entity.items():
        q = (
            db.table("incidents")
            .select("id, severity, event_count")
            .eq("tenant_id", tenant_id)
            .eq("status", "open")
            .gte("last_seen", cutoff)
        )
        q = q.is_("src_ip", "null") if entity == "unidentified" else q.eq("src_ip", entity)
        existing = q.order("last_seen", desc=True).limit(1).execute().data

        batch_severity = None
        for r in rows:
            batch_severity = _higher_severity(batch_severity, r.get("severity"))

        if existing:
            inc = existing[0]
            db.table("incidents").update({
                "event_count": inc["event_count"] + len(rows),
                "severity": _higher_severity(inc["severity"], batch_severity),
                "last_seen": "now()",
            }).eq("id", inc["id"]).execute()
            incident_id = inc["id"]
        else:
            created = db.table("incidents").insert({
                "tenant_id": tenant_id,
                "src_ip": None if entity == "unidentified" else entity,
                "title": f"Flagged activity from {entity}",
                "status": "open",
                "severity": batch_severity,
                "event_count": len(rows),
            }).execute().data[0]
            incident_id = created["id"]

        for row in rows:
            row["incident_id"] = incident_id
