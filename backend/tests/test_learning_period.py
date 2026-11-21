"""Per-source learning period: a source seen for the first time is learned,
not judged, until it has ENTITY_LEARNING_MIN_FLOWS flows."""
import numpy as np
import pandas as pd
from app.ml import engine
from app.ml.engine import TenantDetector
from tests.test_real_traffic_calibration import _real_df


def _det(monkeypatch, n=50, **kw):
    monkeypatch.setattr(engine, "ENTITY_LEARNING_MIN_FLOWS", n)
    for k, v in kw.items():
        monkeypatch.setattr(engine, k, v)
    return TenantDetector("t-learn")


def test_new_source_not_judged_until_learned(monkeypatch):
    d = _det(monkeypatch, 50)
    out = d.score(_real_df(80, seed=1, ip="10.0.0.7"))
    assert out["learning"].iloc[:50].all() and not out["learning"].iloc[50:].any()
    first = out.iloc[:50]
    assert first["severity"].isna().all()
    assert not first[["ecod_is_anomaly", "iforest_is_anomaly", "lof_is_anomaly", "hst_is_anomaly"]].any().any()
    assert (first["consensus_count"] == 0).all()


def test_obvious_attack_during_learning_not_flagged_after_it_is(monkeypatch):
    d = _det(monkeypatch, 30)
    d.score(_real_df(30, seed=2, ip="10.0.0.8"))          # learning done
    bad = _real_df(5, seed=3, ip="10.0.0.8")
    for c in ("src_bytes", "dst_bytes", "rate", "load"):
        bad[c] = bad[c] * 500
    out = d.score(bad)
    assert not out["learning"].any()
    assert out["severity"].notna().sum() >= 1             # judging has started


def test_sources_learn_independently(monkeypatch):
    d = _det(monkeypatch, 20)
    d.score(_real_df(25, seed=4, ip="10.0.0.1"))
    out = d.score(_real_df(10, seed=5, ip="10.0.0.2"))     # brand-new second source
    assert out["learning"].all() and out["severity"].isna().all()


def test_refit_after_graduation_is_throttled_and_needs_pool(monkeypatch):
    d = _det(monkeypatch, 20, LEARNING_REFIT_MIN_POOL=100, LEARNING_REFIT_MIN_INTERVAL_S=3600)
    d.score(_real_df(30, seed=6, ip="10.0.0.1"))
    assert d._graduated_pending == 1 and not d.learning_refit_due()   # pool too small (30 < 100)
    d.score(_real_df(120, seed=7, ip="10.0.0.1"))
    assert d.learning_refit_due()
    assert d.is_bootstrapped_on_synthetic
    assert d.refit_after_learning() is True
    assert d.is_bootstrapped_on_synthetic is False
    # a second source graduating right away is throttled by the interval
    d.score(_real_df(25, seed=8, ip="10.0.0.2"))
    assert d._graduated_pending == 1 and not d.learning_refit_due()


def test_disabled_when_zero(monkeypatch):
    d = _det(monkeypatch, 0)
    out = d.score(_real_df(40, seed=9, ip="10.0.0.3"))
    assert not out["learning"].any()


def test_old_checkpoint_without_pool_still_scores(monkeypatch):
    d = _det(monkeypatch, 0)
    del d._pool, d._graduated_pending, d._last_learning_refit
    out = d.score(_real_df(10, seed=10))
    assert len(out) == 10


# ---- end to end through POST /ingest/batch (FakeDB) --------------------------
from tests.test_ingest_score_safety import db, client, RAW_KEY, TENANT  # noqa: E402,F401


def test_ingest_reports_learning_and_stores_no_verdicts(monkeypatch, client, db):
    monkeypatch.setattr(engine, "ENTITY_LEARNING_MIN_FLOWS", 10)
    flows = [{"dur": 1.0 + i * 0.01, "proto": "tcp", "tot_pkts": 10 + i, "src_bytes": 100.0 + i,
              "dst_bytes": 50.0, "rate": 10.0, "load": 1.0, "s_ttl": 64,
              "src_ip": "10.99.9.9", "dst_ip": "10.1.1.1"} for i in range(15)]
    r = client.post("/ingest/batch", headers={"X-API-Key": RAW_KEY}, json={"flows": flows})
    assert r.status_code == 200, r.text
    assert r.json()["learning_flows"] == 10
    ev = db.table("anomaly_events").select("flow_id, detector, is_anomaly, severity") \
        .eq("tenant_id", TENANT).eq("detector", "ECOD").execute().data
    assert len(ev) == 15
    learned = sorted(ev, key=lambda e: e["flow_id"])[:10]
    assert not any(e["is_anomaly"] or e["severity"] for e in learned)
