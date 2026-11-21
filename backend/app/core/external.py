"""Persist external-endpoint aggregates (additive across uploads)."""
from datetime import datetime, timezone

from ..ingestion.endpoints import MAX_NAMES


def _iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def store_endpoints(db, tenant_id: str, rows: list[dict]) -> int:
    n = 0
    for r in rows:
        ex = (
            db.table("external_endpoints").select("*").eq("tenant_id", tenant_id)
            .eq("remote_ip", r["remote_ip"]).eq("remote_port", r["remote_port"]).eq("proto", r["proto"]).limit(1).execute()
        ).data
        if ex:
            o = ex[0]
            db.table("external_endpoints").update({
                "flows": (o.get("flows") or 0) + r["flows"], "packets": (o.get("packets") or 0) + r["packets"],
                "bytes_out": (o.get("bytes_out") or 0) + r["bytes_out"], "bytes_in": (o.get("bytes_in") or 0) + r["bytes_in"],
                "hostnames": sorted(set(o.get("hostnames") or []) | set(r["hostnames"]))[:MAX_NAMES],
                "last_seen": _iso(r["last_ts"]),
            }).eq("id", o["id"]).execute()
        else:
            db.table("external_endpoints").insert({
                "tenant_id": tenant_id, "remote_ip": r["remote_ip"], "remote_port": r["remote_port"], "proto": r["proto"],
                "flows": r["flows"], "packets": r["packets"], "bytes_out": r["bytes_out"], "bytes_in": r["bytes_in"],
                "hostnames": r["hostnames"], "first_seen": _iso(r["first_ts"]), "last_seen": _iso(r["last_ts"]),
            }).execute()
        n += 1
    return n
