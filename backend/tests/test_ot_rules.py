"""Deterministic OT rule-engine tests -- formalizes the four manually-verified
scenarios (baseline establishment with no false positives, new-write-address
priority over new-function-code, exception-flood severity escalation, and
unit-ID scan detection) plus the no-false-positive-on-legitimate-repeat-
traffic guarantee the engine's whole trust model depends on."""
import time

import pandas as pd
import pytest

from app.ml.ot_rules import (
    OTRuleEngine,
    OTRuleRegistry,
    BASELINE_MIN_MESSAGES,
    EXCEPTION_FLOOD_THRESHOLD,
    UNIT_SCAN_DISTINCT_THRESHOLD,
)

SRC, DST = "10.0.0.10", "10.0.0.20"


def _row(ts, fc, function_name, is_request=True, is_exception=False,
         exception_code=None, address=None, quantity=None, unit_id=1,
         src_ip=SRC, dst_ip=DST):
    return {
        "ts": ts, "src_ip": src_ip, "dst_ip": dst_ip, "unit_id": unit_id,
        "function_code": fc, "function_name": function_name,
        "is_request": is_request, "is_exception": is_exception,
        "exception_code": exception_code, "address": address, "quantity": quantity,
    }


@pytest.fixture
def engine():
    return OTRuleEngine("test-tenant-ot")


def test_empty_dataframe_handled():
    engine = OTRuleEngine("empty-test")
    df = pd.DataFrame(columns=["ts", "src_ip", "dst_ip", "unit_id", "function_code",
                                "function_name", "is_request", "is_exception",
                                "exception_code", "address", "quantity"])
    out = engine.evaluate(df)
    assert len(out) == 0
    assert "severity" in out.columns and "reason" in out.columns


def test_baseline_period_establishes_with_no_false_positives(engine):
    """Repeated, identical reads during the baseline window must never be
    flagged -- an engine that flags its own baseline traffic is useless."""
    t0 = time.time()
    rows = [_row(t0 + i, 3, "ReadHoldingRegisters", address=100, quantity=10)
            for i in range(BASELINE_MIN_MESSAGES)]
    out = engine.evaluate(pd.DataFrame(rows))
    assert out["severity"].isna().all()


def test_unexpected_write_address_takes_priority_over_new_function_code(engine):
    """A write to a never-before-seen address is both a new function code
    (reads only in the baseline) and a new write address -- the engine must
    report the stronger, more specific reason, not the weaker generic one."""
    t0 = time.time()
    baseline = [_row(t0 + i, 3, "ReadHoldingRegisters", address=100, quantity=10)
                for i in range(BASELINE_MIN_MESSAGES + 2)]
    out = engine.evaluate(pd.DataFrame(baseline))
    assert out["severity"].isna().all()

    sabotage = _row(t0 + 100, 6, "WriteSingleRegister", address=9001, quantity=1)
    out2 = engine.evaluate(pd.DataFrame([sabotage]))
    row = out2.iloc[0]
    assert row["severity"] == "high"
    assert row["reason"] == "unexpected_write_address"


def test_new_function_code_flagged_when_no_address_involved(engine):
    """A function code change that isn't a write to a new address (e.g. a
    device that has only ever been read via fc=3 is suddenly read via fc=4)
    should still be flagged, just at the weaker new_function_code severity."""
    t0 = time.time()
    baseline = [_row(t0 + i, 3, "ReadHoldingRegisters", address=100, quantity=10)
                for i in range(BASELINE_MIN_MESSAGES + 1)]
    engine.evaluate(pd.DataFrame(baseline))

    new_fc = _row(t0 + 50, 4, "ReadInputRegisters", address=100, quantity=10)
    out = engine.evaluate(pd.DataFrame([new_fc]))
    row = out.iloc[0]
    assert row["severity"] == "medium"
    assert row["reason"] == "new_function_code"


def test_no_false_positive_on_legitimate_repeat_write(engine):
    """Repeated writes to an address already established in the baseline
    must never be flagged -- this is the core trust guarantee: the rule
    fires on novelty, not on writes in general."""
    t0 = time.time()
    baseline = [_row(t0 + i, 6, "WriteSingleRegister", address=200, quantity=1)
                for i in range(BASELINE_MIN_MESSAGES)]
    engine.evaluate(pd.DataFrame(baseline))

    repeat = _row(t0 + 50, 6, "WriteSingleRegister", address=200, quantity=1)
    out = engine.evaluate(pd.DataFrame([repeat]))
    assert out.iloc[0]["severity"] is None


def test_exception_flood_escalates_to_critical(engine):
    t0 = time.time()
    rows = [
        _row(t0 + i * 0.5, 3, "ReadHoldingRegisters", is_request=False,
             is_exception=True, exception_code=2)
        for i in range(EXCEPTION_FLOOD_THRESHOLD + 1)
    ]
    out = engine.evaluate(pd.DataFrame(rows))
    assert out.iloc[-1]["severity"] == "critical"
    assert out.iloc[-1]["reason"] == "exception_flood"
    # first couple exceptions in the window shouldn't yet be critical
    assert out.iloc[0]["severity"] != "critical"


def test_unit_id_scan_detected(engine):
    """One source querying many distinct unit IDs against one destination
    in a short window looks like enumeration (the Modbus analogue of a
    port scan), not a real operator's fixed device list."""
    t0 = time.time()
    rows = [
        _row(t0 + i, 3, "ReadHoldingRegisters", address=0, quantity=1, unit_id=i + 1)
        for i in range(UNIT_SCAN_DISTINCT_THRESHOLD + 3)
    ]
    out = engine.evaluate(pd.DataFrame(rows))
    scan_flags = out[out["reason"] == "unit_id_scan"]
    assert len(scan_flags) > 0
    assert (scan_flags["severity"] == "high").all()


def test_registry_returns_same_engine_instance_per_tenant():
    registry = OTRuleRegistry()
    a = registry.get("tenant-a")
    a_again = registry.get("tenant-a")
    b = registry.get("tenant-b")
    assert a is a_again
    assert a is not b
