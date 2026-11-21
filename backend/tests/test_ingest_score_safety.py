"""Regression for a real bug found while generating screenshots for v6.3
(not caught by any prior test): a NaN/inf detector score stored as-is by
POST /ingest/batch succeeds (200), but every subsequent read of that row
-- GET /dashboard/anomalies/recent, /demo/anomalies/recent, /demo/entities
-- 500'd, because Starlette's JSONResponse rejects NaN/Infinity per strict
JSON. escalation_reason and entity_baseline_z were already guarded with
pd.isna(...) before storage; the four score columns (ecod_score,
iforest_score, lof_score, hst_score) weren't. We could not get a bad
detector fit to reproduce the NaN reliably in isolation (tried dozens of
random bootstrap seeds), so this test doesn't reproduce the exact trigger
-- it forces the condition directly (a NaN ecod_score from the real
scoring path) and proves the system now degrades gracefully instead of
crashing, which is the actual guarantee that matters."""
from unittest.mock import patch

import jwt
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app.core.auth import hash_key
from app.main import app
from app.ml.engine import TenantDetector
from app.ml.generate_telemetry import generate
from tests.fake_db import FakeDB

JWT_SECRET = "test-jwt-secret-not-real"
TENANT = "ab000000-0000-0000-0000-000000000001"
USER = "ab000000-0000-0000-0000-000000000002"
RAW_KEY = "nai_test_score_safety_key"


def auth_header() -> dict:
    token = jwt.encode({"sub": USER, "aud": "authenticated", "exp": 9999999999}, JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def db():
    fake = FakeDB()
    fake.seed("profiles", [{"id": USER, "tenant_id": TENANT, "role": "viewer", "email": "v@x.com"}])
    fake.seed("tenants", [{"id": TENANT, "name": "t", "plan": "pro", "alert_min_severity": "low"}])
    fake.seed("api_keys", [{"id": 900001, "tenant_id": TENANT, "key_hash": hash_key(RAW_KEY), "scope": "ingest", "revoked_at": None}])
    targets = [
        "app.core.auth.get_db", "app.routers.ingest.get_db", "app.routers.dashboard.get_db",
        "app.core.webhooks.get_db", "app.core.response_actions.get_db", "app.core.audit.get_db",
    ]
    patches = [patch(t, return_value=fake) for t in targets]
    for p in patches:
        p.start()
    try:
        yield fake
    finally:
        for p in patches:
            p.stop()


@pytest.fixture
def client(db):
    return TestClient(app)


ONE_FLOW = {
    "flows": [{
        "dur": 1.0, "proto": "tcp", "tot_pkts": 10, "src_bytes": 100.0, "dst_bytes": 50.0,
        "rate": 10.0, "load": 1.0, "s_ttl": 64, "src_ip": "10.1.1.5", "dst_ip": "10.1.1.1",
    }],
}


def test_nan_detector_score_does_not_crash_ingest_or_later_reads(client, db):
    original_score = TenantDetector.score

    def score_with_injected_nan(self, flows_df):
        scored = original_score(self, flows_df)
        scored.loc[scored.index[0], "ecod_score"] = float("nan")
        scored.loc[scored.index[0], "iforest_score"] = float("inf")
        return scored

    with patch.object(TenantDetector, "score", score_with_injected_nan):
        ingest_resp = client.post("/ingest/batch", headers={"X-API-Key": RAW_KEY}, json=ONE_FLOW)
    assert ingest_resp.status_code == 200  # ingest itself never touches JSON-serializing the stored row

    # The real bug: reading it back used to 500 (Starlette rejects NaN/Infinity).
    read_resp = client.get("/dashboard/anomalies/recent", headers=auth_header())
    assert read_resp.status_code == 200
    rows = read_resp.json()
    assert len(rows) == 1
    assert rows[0]["score"] is None  # sanitized to null, not a crash

    stored = db.table("anomaly_events").select("detector, score").eq("tenant_id", TENANT).execute().data
    by_detector = {r["detector"]: r["score"] for r in stored}
    assert by_detector["ECOD"] is None       # was NaN
    assert by_detector["IsolationForest"] is None  # was +inf
    assert by_detector["LOF"] is not None    # untouched, still a real finite score


def test_nonanomalous_row_severity_is_null_not_nan(client, db):
    """The actual root cause found live (not an injected/mocked edge case --
    this reproduces through the real, unmodified scoring path): pandas'
    DataFrame.iterrows() picks a per-ROW dtype across all of that row's
    columns, not a per-column dtype. A flow that *wasn't* flagged has
    severity=None sitting next to several float/bool/int columns
    (ecod_score, is_anomaly, consensus_count) in the same row -- so when
    app/routers/ingest.py reads row["severity"] out of that per-row Series,
    pandas has already silently upcast that row to float64 and turned the
    None into float('nan'). escalation_reason and entity_baseline_z were
    already guarded against exactly this (pd.isna(...) -> None); severity
    wasn't, so it stored a literal NaN severity on every single
    non-anomalous row (the majority of any real batch, not a rare
    scenario), and reading any of them back 500'd. This test ingests a
    realistic mixed batch (benign + attack traffic, no mocking) through
    the real POST /ingest/batch, then reads the *unfiltered* list endpoint
    (the one real bug report: /dashboard/anomalies/recent, which -- unlike
    /demo/entities -- does not filter to is_anomaly=True, so a corrupted
    non-anomalous row is actually on the response path)."""
    df = generate(n_benign=60, attack_frac=0.2, seed=7)
    flows = [{
        "dur": float(r["Dur"]), "proto": r["Proto"], "tot_pkts": int(r["TotPkts"]),
        "src_bytes": float(r["SrcBytes"]), "dst_bytes": float(r["DstBytes"]), "rate": float(r["Rate"]),
        "load": float(r["Load"]), "s_ttl": int(r["sTtl"]), "src_ip": "10.1.1.5", "dst_ip": "10.1.1.1",
    } for _, r in df.iterrows()]

    ingest_resp = client.post("/ingest/batch", headers={"X-API-Key": RAW_KEY}, json={"flows": flows})
    assert ingest_resp.status_code == 200

    read_resp = client.get("/dashboard/anomalies/recent?limit=1000", headers=auth_header())
    assert read_resp.status_code == 200  # the real crash: used to 500 here
    rows = read_resp.json()
    assert len(rows) == len(flows)
    non_anomalous = [r for r in rows if not r["is_anomaly"]]
    assert len(non_anomalous) > 0  # contamination < 100% -- some flows are always unflagged
    # severity is null or a real tier -- never NaN. (It may legitimately be a tier
    # even when ECOD alone did not flag the row: ensemble consensus can promote it.)
    assert all(r["severity"] is None or r["severity"] in ("low", "medium", "high", "critical") for r in non_anomalous)

    stored = db.table("anomaly_events").select("severity, is_anomaly").eq("tenant_id", TENANT).eq("detector", "ECOD").execute().data
    for r in stored:
        assert not (isinstance(r["severity"], float) and r["severity"] != r["severity"])  # never NaN
        assert r["severity"] is None or isinstance(r["severity"], str)
