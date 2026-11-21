"""Operator script: seeds the public read-only demo tenant (v6.3) with
real, scored telemetry -- run once against your actual deployed Supabase
project + backend, not executed against production from this sandbox
(this sandbox has no real Supabase project to seed). It is exercised in
CI against the FakeDB test harness instead (see
tests/test_seed_demo_tenant.py), which proves the seeding logic itself is
correct without claiming a real production run happened here.

What it does, and why it goes through the real ingest endpoint rather than
inserting rows directly: a demo that skips detector.score() and shows
hand-faked severities isn't proof of anything. This generates synthetic
flow data with ml/generate_telemetry.py (the same 5G-NIDD-shaped generator
the per-tenant bootstrap already uses), assigns it believable source/
destination IPs so the entity view and topology map have real structure to
show, and POSTs it through POST /ingest/batch with a real ingest API key
-- the exact same code path a paying customer's telemetry agent uses.

Usage (against your real deployment):
    SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... SUPABASE_JWT_SECRET=... \\
    DEMO_TENANT_ID=<a fixed uuid you choose> \\
    python3 scripts/seed_demo_tenant.py

Prints the ingest key it generates (store it if you want to re-seed later
without creating a new one) and the final ingested/flagged counts. Safe to
re-run -- each run adds another batch of synthetic traffic on top, it does
not reset the tenant.
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from fastapi.testclient import TestClient

from app.main import app
from app.core.auth import hash_key
from app.core.db import get_db
from app.ml.generate_telemetry import generate

COLUMN_MAP = {
    "Dur": "dur", "Proto": "proto", "TotPkts": "tot_pkts", "SrcBytes": "src_bytes",
    "DstBytes": "dst_bytes", "Rate": "rate", "Load": "load", "sTtl": "s_ttl",
}

# A handful of named "hosts" so the entity view / topology map tell a story
# instead of showing a wall of random addresses -- a demo visitor should be
# able to look at this and go "oh, .17 is clearly up to something."
BENIGN_SOURCES = [f"10.50.0.{i}" for i in (5, 6, 7, 8, 9, 10, 11, 12)]
ATTACKER_BY_LABEL = {
    "ICMPFlood": "10.50.0.201", "UDPFlood": "10.50.0.202", "SYNFlood": "10.50.0.203",
    "HTTPFlood": "10.50.0.204", "SlowrateDoS": "10.50.0.205",
    "SYNScan": "10.50.0.206", "TCPConnectScan": "10.50.0.207", "UDPScan": "10.50.0.208",
}
SERVER_IP = "10.50.0.2"


def _flow_records(df) -> list[dict]:
    records = []
    rng = np.random.default_rng(7)
    for _, row in df.iterrows():
        rec = {dst: (float(row[src]) if dst != "proto" else row[src]) for src, dst in COLUMN_MAP.items()}
        rec["tot_pkts"] = int(rec["tot_pkts"])
        rec["s_ttl"] = int(rec["s_ttl"])
        label = row["Label"]
        if label == "Benign":
            rec["src_ip"] = BENIGN_SOURCES[rng.integers(0, len(BENIGN_SOURCES))]
        else:
            rec["src_ip"] = ATTACKER_BY_LABEL.get(label, "10.50.0.200")
        rec["dst_ip"] = SERVER_IP
        rec["source_label"] = "demo-segment"
        records.append(rec)
    return records


def seed_demo_tenant(tenant_id: str, client: TestClient | None = None, n_benign: int = 1200, attack_frac: float = 0.12) -> dict:
    """Core seeding logic, factored out so tests can run it against a
    FakeDB-backed TestClient without a real Supabase project."""
    db = get_db()
    existing = db.table("tenants").select("id").eq("id", tenant_id).limit(1).execute().data
    if not existing:
        db.table("tenants").insert({
            "id": tenant_id, "name": "Demo — Acme Manufacturing (sandbox)", "plan": "pro",
        }).execute()

    raw_key = f"nai_demo_{uuid.uuid4().hex}"
    db.table("api_keys").insert({
        "tenant_id": tenant_id, "key_hash": hash_key(raw_key), "label": "demo-seed", "scope": "ingest",
        "revoked_at": None,
    }).execute()

    df = generate(n_benign=n_benign, attack_frac=attack_frac, seed=123)
    flows = _flow_records(df)

    client = client or TestClient(app)
    BATCH = 2000
    total_ingested, total_flagged = 0, 0
    for i in range(0, len(flows), BATCH):
        chunk = flows[i:i + BATCH]
        resp = client.post("/ingest/batch", headers={"X-API-Key": raw_key}, json={"flows": chunk})
        resp.raise_for_status()
        body = resp.json()
        total_ingested += body["ingested"]
        total_flagged += body["anomalies_detected"]

    return {"tenant_id": tenant_id, "ingest_key": raw_key, "ingested": total_ingested, "flagged": total_flagged}


if __name__ == "__main__":
    tenant_id = os.environ.get("DEMO_TENANT_ID") or str(uuid.uuid4())
    if not os.environ.get("DEMO_TENANT_ID"):
        print(f"DEMO_TENANT_ID not set -- generated {tenant_id}. Set it as an env var on your backend "
              f"deployment (so the /demo router knows which tenant to serve) and re-run this script "
              f"with the same value to add more synthetic traffic later.")
    result = seed_demo_tenant(tenant_id)
    print(f"Seeded demo tenant {result['tenant_id']}: {result['ingested']} flows ingested, "
          f"{result['flagged']} flagged. Ingest key (only needed to re-seed): {result['ingest_key']}")
