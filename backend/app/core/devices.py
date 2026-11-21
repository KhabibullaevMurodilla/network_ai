"""Persist discovered devices (merge, never overwrite better evidence)."""
from datetime import datetime, timezone

from ..ingestion.discovery import ROLE_PRIORITY, MAX_EVIDENCE

_CONF = ["low", "medium", "high"]


def _iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else datetime.now(timezone.utc).isoformat()


def _merge_role(old: str, new: str) -> str:
    return old if ROLE_PRIORITY.index(old if old in ROLE_PRIORITY else "unknown") <= ROLE_PRIORITY.index(new if new in ROLE_PRIORITY else "unknown") else new


def store_devices(db, tenant_id: str, devices: list[dict]) -> int:
    """Upsert by (tenant_id, device_key). Returns number of devices written."""
    if not devices:
        return 0
    keys = [d["device_key"] for d in devices]
    existing = {
        r["device_key"]: r
        for r in db.table("network_devices").select("*").eq("tenant_id", tenant_id).in_("device_key", keys).execute().data
    }
    n = 0
    for d in devices:
        old = existing.get(d["device_key"])
        if old is None:
            db.table("network_devices").insert({
                "tenant_id": tenant_id, "device_key": d["device_key"], "mac": d["mac"], "ip": d["ip"],
                "ips": d["ips"], "role": d["role"], "tags": d["tags"], "hostname": d["hostname"],
                "os_hint": d["os_hint"], "services": d["services"], "mac_randomized": d["mac_randomized"],
                "evidence": d["evidence"], "confidence": d["confidence"],
                "first_seen": _iso(d["first_seen_ts"]), "last_seen": _iso(d["last_seen_ts"]),
            }).execute()
        else:
            role = _merge_role(old.get("role") or "unknown", d["role"])
            ips = sorted(set(old.get("ips") or []) | set(d["ips"]))
            ev = list(old.get("evidence") or [])
            for e in d["evidence"]:
                if e not in ev and len(ev) < MAX_EVIDENCE:
                    ev.append(e)
            conf = max(old.get("confidence") or "low", d["confidence"], key=_CONF.index)
            db.table("network_devices").update({
                "role": role, "ips": ips, "ip": old.get("ip") or d["ip"] or (ips[0] if ips else None),
                "tags": sorted((set(old.get("tags") or []) | set(d["tags"]) | {d["role"], old.get("role") or "unknown"}) - {role, "unknown"}),
                "hostname": d["hostname"] or old.get("hostname"), "os_hint": d["os_hint"] or old.get("os_hint"),
                "services": sorted(set(old.get("services") or []) | set(d["services"])),
                "evidence": ev, "confidence": conf, "last_seen": _iso(d["last_seen_ts"]),
            }).eq("id", old["id"]).execute()
        n += 1
    return n


def store_links(db, tenant_id: str, links: list[dict]) -> int:
    """Upsert by (tenant_id, a_key, a_port, b_key); refresh last_seen/evidence."""
    n = 0
    now = datetime.now(timezone.utc).isoformat()
    for l in links:
        a, b = (l["a_key"], l.get("a_port") or ""), (l["b_key"], l.get("b_port") or "")
        if a > b:  # same cable seen from the other end -> same row
            l = {**l, "a_key": l["b_key"], "a_port": l.get("b_port"), "b_key": l["a_key"], "b_port": l.get("a_port")}
        a_port = l.get("a_port") or ""
        existing = (
            db.table("network_links").select("id").eq("tenant_id", tenant_id)
            .eq("a_key", l["a_key"]).eq("a_port", a_port).eq("b_key", l["b_key"]).limit(1).execute()
        ).data
        row = {"b_port": l.get("b_port"), "source": l["source"], "evidence": l.get("evidence"), "last_seen": now}
        if existing:
            db.table("network_links").update(row).eq("id", existing[0]["id"]).execute()
        else:
            db.table("network_links").insert({"tenant_id": tenant_id, "a_key": l["a_key"], "a_port": a_port, "b_key": l["b_key"], **row}).execute()
        n += 1
    return n
