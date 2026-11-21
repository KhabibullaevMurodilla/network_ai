"""v6.3: proves scripts/seed_demo_tenant.py's seeding logic is correct --
run here against the FakeDB harness since this sandbox has no real
Supabase project to seed for real (see that script's own docstring for the
honest disclosure on what is and isn't actually verified). What this test
DOES prove: the script creates a tenant, mints a real ingest key, and
drives real synthetic flows through the real POST /ingest/batch path
(real pydantic validation, real detector scoring, real anomaly storage) --
not a shortcut that hand-writes fake-looking rows."""
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from seed_demo_tenant import seed_demo_tenant  # noqa: E402

from app.main import app
from tests.fake_db import FakeDB

DEMO_TENANT = "dd000000-0000-0000-0000-000000000001"


@pytest.fixture
def db():
    fake = FakeDB()
    targets = [
        "seed_demo_tenant.get_db",
        "app.core.auth.get_db",
        "app.routers.ingest.get_db",
        "app.core.webhooks.get_db",
        "app.core.response_actions.get_db",
        "app.core.audit.get_db",
    ]
    patches = [patch(t, return_value=fake) for t in targets]
    for p in patches:
        p.start()
    try:
        yield fake
    finally:
        for p in patches:
            p.stop()


def test_seed_creates_tenant_and_ingest_key(db):
    result = seed_demo_tenant(DEMO_TENANT, client=TestClient(app), n_benign=50, attack_frac=0.2)
    tenant_rows = db.table("tenants").select("id").eq("id", DEMO_TENANT).execute().data
    assert len(tenant_rows) == 1
    key_rows = db.table("api_keys").select("tenant_id, scope").eq("tenant_id", DEMO_TENANT).execute().data
    assert len(key_rows) == 1
    assert key_rows[0]["scope"] == "ingest"
    assert result["ingest_key"].startswith("nai_demo_")


def test_seed_actually_ingests_and_scores_real_flows(db):
    result = seed_demo_tenant(DEMO_TENANT, client=TestClient(app), n_benign=50, attack_frac=0.2)
    assert result["ingested"] > 0
    stored_flows = db.table("telemetry_flows").select("id").eq("tenant_id", DEMO_TENANT).execute().data
    assert len(stored_flows) == result["ingested"]
    # Real anomaly rows exist (one per flow per detector -- 4 rows/flow),
    # not just a count returned by the function.
    stored_anomalies = db.table("anomaly_events").select("id").eq("tenant_id", DEMO_TENANT).execute().data
    assert len(stored_anomalies) == result["ingested"] * 4


def test_seed_produces_a_mix_of_named_entities_not_random_noise(db):
    """The point of assigning fixed IPs per attack label is a demo visitor
    sees a coherent story (named 'hosts') on the entity/topology views --
    this pins that the flow data actually has that shape."""
    seed_demo_tenant(DEMO_TENANT, client=TestClient(app), n_benign=200, attack_frac=0.3)
    flows = db.table("telemetry_flows").select("src_ip").eq("tenant_id", DEMO_TENANT).execute().data
    distinct_sources = {f["src_ip"] for f in flows}
    # At least one benign host and one of the fixed attacker IPs should appear.
    assert any(src.startswith("10.50.0.") for src in distinct_sources)
    assert len(distinct_sources) >= 2


def test_demo_endpoints_serve_real_seeded_rows_without_crashing(db):
    """Regression: every other test in this file (and in test_demo_router.py)
    seeds anomaly_events rows by hand with an explicit created_at, which
    hid a real bug -- app code reading real post-ingest rows (never hand-
    seeded) indexed row["created_at"] directly. The real Postgres schema
    gives that column `default now()`, so it's never actually missing in
    production, but it also was never set by ingest.py's own insert dicts,
    and FakeDB (unlike Postgres) didn't simulate that default either --
    so a row written via the real POST /ingest/batch path and then read
    back through /demo/entities or /demo/trend 500'd with a bare KeyError,
    found only by actually running the live server and hitting these
    routes, not by any of the hand-seeded tests above. Both gaps are now
    closed (FakeDB.insert() sets created_at like Postgres does; the
    routers also no longer assume the key exists). This test exercises
    the real path end to end -- seed via the real ingest endpoint, then
    read via /demo/entities and /demo/trend -- so a regression in either
    fix would be caught here, not just inferred from the fix itself."""
    with patch("app.routers.demo.get_db", return_value=db), \
         patch("app.routers.demo.settings.DEMO_TENANT_ID", DEMO_TENANT):
        seed_demo_tenant(DEMO_TENANT, client=TestClient(app), n_benign=40, attack_frac=0.2)
        client = TestClient(app)
        entities_resp = client.get("/demo/entities")
        trend_resp = client.get("/demo/trend")
    assert entities_resp.status_code == 200
    entities = entities_resp.json()
    assert len(entities) > 0
    assert all(e["last_seen"] for e in entities)  # real timestamp, not missing/None
    assert trend_resp.status_code == 200


def test_seed_is_idempotent_and_additive_on_rerun(db):
    first = seed_demo_tenant(DEMO_TENANT, client=TestClient(app), n_benign=30, attack_frac=0.2)
    second = seed_demo_tenant(DEMO_TENANT, client=TestClient(app), n_benign=30, attack_frac=0.2)
    tenant_rows = db.table("tenants").select("id").eq("id", DEMO_TENANT).execute().data
    assert len(tenant_rows) == 1  # not duplicated on rerun
    all_flows = db.table("telemetry_flows").select("id").eq("tenant_id", DEMO_TENANT).execute().data
    assert len(all_flows) == first["ingested"] + second["ingested"]  # additive, not reset
