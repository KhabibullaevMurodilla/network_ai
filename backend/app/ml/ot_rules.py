"""Deterministic, allowlist-style anomaly detection for Modbus/TCP --
deliberately NOT the same statistical-ensemble approach as ml/engine.py.

This is a considered design choice, not a shortcut: industrial control
traffic is highly deterministic (a given PLC talks to a given set of
addresses with a given set of function codes, essentially forever, unless
someone changes the control logic), and OT security teams trust
explainable, rule-based detection over opaque ML scores for exactly this
kind of traffic -- "this device just got written to at an address nothing
has ever written to before" is a sentence a control engineer can act on
immediately; "anomaly score 0.83" is not, and in a safety-critical
environment the gap between those two matters more than it does for IT
network traffic. The generic ensemble in ml/engine.py is still the right
tool for flow-level IT traffic; this module is Modbus-specific, operating
on individual protocol messages (ingestion/modbus.py), not flow
aggregates.

Four rules, each independently triggerable and each with its own severity
and reason, mirroring the pattern ml/engine.py already uses
(escalation_reason, severity) so the rest of the platform (incidents,
response actions, dashboard) can treat an OT event the same shape as a
flow-based one:

  1. new_function_code -- a device pair (src, dst, unit_id) issues/
     receives a function code never seen on that pair before, after a
     baseline period. A PLC that has only ever been read from (fc 3/4)
     suddenly receiving a write (fc 6/16) is exactly the kind of change
     worth flagging even if the write itself looks "valid" Modbus.
  2. unexpected_write_address -- a write targets an address never
     written to before on that device pair, after baseline. Floored at
     "high": an unsolicited write to a previously-untouched register in
     a control system is a stronger, more specific signal than a flow
     anomaly ever is -- this is the pattern real ICS sabotage looks like
     (Stuxnet-class attacks modify specific, previously-static control
     registers).
  3. exception_flood -- a device returning exception responses faster
     than a short rolling-window threshold allows, usually a scan/probe
     walking addresses or function codes that mostly don't exist.
  4. unit_id_scan -- one source address querying more distinct unit IDs
     against one destination within a short window than real operational
     traffic would -- the Modbus equivalent of a port scan (a real HMI or
     SCADA master talks to a small, fixed set of unit IDs; enumerating
     many in a short window is reconnaissance, not control).

Honest scope: like ml/engine.py's DetectorRegistry, this registry's
baselines live in process memory only -- the same cross-instance
checkpointing story (ml/persistence.py) applies here conceptually but
has NOT been extended to cover OT baselines in this pass. Noted as a
follow-up, not silently assumed solved.
"""
from __future__ import annotations
from collections import deque

import pandas as pd

# Baseline period: how many messages on a device pair before its
# function-code/address history is trusted enough to flag a deviation.
# Too low and ordinary startup variety looks anomalous; too high and a
# genuinely new pair goes unwatched for a long time.
BASELINE_MIN_MESSAGES = 10

EXCEPTION_FLOOD_WINDOW_SECONDS = 30
EXCEPTION_FLOOD_THRESHOLD = 5

UNIT_SCAN_WINDOW_SECONDS = 30
UNIT_SCAN_DISTINCT_THRESHOLD = 4  # more than this many distinct unit ids from
# one source against one destination in the window looks like enumeration,
# not a real operator's fixed device list.


class _DevicePairBaseline:
    __slots__ = ("message_count", "seen_function_codes", "seen_write_addresses")

    def __init__(self):
        self.message_count = 0
        self.seen_function_codes: set[int] = set()
        self.seen_write_addresses: set[int] = set()

    @property
    def is_established(self) -> bool:
        return self.message_count >= BASELINE_MIN_MESSAGES


class OTRuleEngine:
    """One instance per tenant, mirroring ml/engine.py's TenantDetector/
    DetectorRegistry split (see ot_registry at the bottom of this file)."""

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self._device_baselines: dict[tuple[str, str, int], _DevicePairBaseline] = {}
        self._exception_events: dict[tuple[str, str], deque[float]] = {}
        self._unit_scan_tracker: dict[tuple[str, str], dict[int, float]] = {}

    def _device_key(self, row) -> tuple[str, str, int]:
        return (row["src_ip"], row["dst_ip"], int(row["unit_id"]))

    def _check_exception_flood(self, src_ip: str, dst_ip: str, ts: float) -> int:
        key = (src_ip, dst_ip)
        dq = self._exception_events.setdefault(key, deque())
        dq.append(ts)
        cutoff = ts - EXCEPTION_FLOOD_WINDOW_SECONDS
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def _check_unit_scan(self, src_ip: str, dst_ip: str, unit_id: int, ts: float) -> int:
        key = (src_ip, dst_ip)
        tracker = self._unit_scan_tracker.setdefault(key, {})
        tracker[unit_id] = ts
        cutoff = ts - UNIT_SCAN_WINDOW_SECONDS
        stale = [u for u, last_ts in tracker.items() if last_ts < cutoff]
        for u in stale:
            del tracker[u]
        return len(tracker)

    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            out = df.copy()
            out["severity"] = []
            out["reason"] = []
            return out

        severities: list[str | None] = []
        reasons: list[str | None] = []

        for _, row in df.iterrows():
            device_key = self._device_key(row)
            baseline = self._device_baselines.setdefault(device_key, _DevicePairBaseline())
            severity: str | None = None
            reason: str | None = None

            fc = int(row["function_code"])
            is_write = fc in (5, 6, 15, 16, 22, 23)
            is_exception = bool(row["is_exception"])
            address = row["address"]
            has_address = address is not None and not pd.isna(address)

            if baseline.is_established:
                if fc not in baseline.seen_function_codes:
                    severity, reason = "medium", "new_function_code"
                if is_write and has_address and int(address) not in baseline.seen_write_addresses:
                    # Takes priority over new_function_code if both fire --
                    # an unexpected write address is the stronger signal.
                    severity, reason = "high", "unexpected_write_address"

            if is_exception:
                count = self._check_exception_flood(row["src_ip"], row["dst_ip"], row["ts"])
                if count >= EXCEPTION_FLOOD_THRESHOLD:
                    severity, reason = "critical", "exception_flood"
                elif count >= max(EXCEPTION_FLOOD_THRESHOLD - 2, 2) and severity is None:
                    severity, reason = "medium", "exception_flood"

            if row["is_request"]:
                distinct_units = self._check_unit_scan(row["src_ip"], row["dst_ip"], int(row["unit_id"]), row["ts"])
                if distinct_units > UNIT_SCAN_DISTINCT_THRESHOLD:
                    severity, reason = "high", "unit_id_scan"

            # Update baseline AFTER evaluating -- a message is judged
            # against history, never against itself (same principle
            # ml/engine.py's HalfSpaceTrees scoring follows).
            baseline.message_count += 1
            baseline.seen_function_codes.add(fc)
            if is_write and has_address:
                baseline.seen_write_addresses.add(int(address))

            severities.append(severity)
            reasons.append(reason)

        out = df.copy()
        out["severity"] = severities
        out["reason"] = reasons
        return out


class OTRuleRegistry:
    def __init__(self):
        self._engines: dict[str, OTRuleEngine] = {}

    def get(self, tenant_id: str) -> OTRuleEngine:
        if tenant_id not in self._engines:
            self._engines[tenant_id] = OTRuleEngine(tenant_id)
        return self._engines[tenant_id]


ot_registry = OTRuleRegistry()
