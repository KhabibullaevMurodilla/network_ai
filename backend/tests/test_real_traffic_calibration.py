"""Two real-traffic fixes: (1) refit on the tenant's own flows once enough
exist (refit_on_real was never called); (2) entity burst needs a real
concentration of flagged flows, not merely a busy host."""
import asyncio
import numpy as np
import pandas as pd
import pytest
from app.ml import engine
from app.ml.engine import TenantDetector
from app.routers import ingest
from tests.fake_db import FakeDB


def _real_df(n, seed=0, ip="10.0.0.5"):
    r = np.random.default_rng(seed)
    return pd.DataFrame({
        "dur": r.exponential(0.5, n), "proto": r.choice(["tcp", "udp"], n),
        "tot_pkts": r.integers(1, 40, n), "src_bytes": r.lognormal(6, 1, n),
        "dst_bytes": r.lognormal(7, 1, n), "rate": r.exponential(50, n),
        "load": r.exponential(5000, n), "s_ttl": r.choice([64, 128], n), "src_ip": ip,
    })


def test_refit_makes_real_traffic_look_normal():
    df = _real_df(1500)
    d = TenantDetector("t-cal")
    before = d.score(df.iloc[:300].copy())["severity"].notna().mean()
    d2 = TenantDetector("t-cal2")
    d2.refit_on_real(df.iloc[300:])
    after = d2.score(df.iloc[:300].copy())["severity"].notna().mean()
    assert after < before and after < 0.35


def test_maybe_refit_requires_enough_real_flows(monkeypatch):
    monkeypatch.setattr(ingest, "MIN_REAL_FLOWS_TO_REFIT", 200)
    db = FakeDB(); d = TenantDetector("t1")
    assert d.is_bootstrapped_on_synthetic
    db.seed("telemetry_flows", [{"tenant_id": "t1", "received_at": f"2026-01-01T00:00:{i%60:02d}", **r}
                                for i, r in enumerate(_real_df(50).drop(columns="src_ip").to_dict("records"))])
    assert asyncio.run(ingest._maybe_refit_on_real(db, "t1", d)) is False
    assert d.is_bootstrapped_on_synthetic
    db.seed("telemetry_flows", [{"tenant_id": "t1", "received_at": "2026-01-02T00:00:00", **r}
                                for r in _real_df(400, seed=2).drop(columns="src_ip").to_dict("records")])
    assert asyncio.run(ingest._maybe_refit_on_real(db, "t1", d)) is True
    assert d.is_bootstrapped_on_synthetic is False
    assert asyncio.run(ingest._maybe_refit_on_real(db, "t1", d)) is False  # only once


def test_busy_host_is_not_burst_critical():
    d = TenantDetector("t-burst")
    d.refit_on_real(_real_df(2000, seed=3))
    out = d.score(_real_df(600, seed=4))
    assert (out["escalation_reason"] == "entity_burst").sum() == 0


def test_real_concentration_still_triggers_burst():
    d = TenantDetector("t-burst2")
    d.refit_on_real(_real_df(2000, seed=3))
    bad = _real_df(12, seed=5, ip="10.0.0.99")
    for c in ("src_bytes", "dst_bytes", "rate", "load"):
        bad[c] = bad[c] * 4  # clearly unusual, but not so extreme that ensemble alone makes it critical
    out = d.score(bad)
    assert (out["escalation_reason"] == "entity_burst").sum() >= 1
    assert (out["severity"] == "critical").sum() >= 6
