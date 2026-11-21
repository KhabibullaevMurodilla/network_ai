"""POST /ingest — a customer's telemetry agent (or a one-off CSV upload)
sends flow records here. Each batch is scored live (with per-flow severity
and an explanation of which features drove the score) and both the raw
flows and the resulting anomaly events are written to Supabase. Critical
events are pushed to any configured webhook in the same request.

Security posture on this router specifically:
  - require_ingest_key enforces the key's scope (ingest/admin only — a
    read-scoped key cannot be used to inject data).
  - Rate-limited per API key (see core/limiter.py) to blunt abuse from a
    leaked key.
  - Every batch is attributed in the audit log to the specific key that
    sent it, not just "the tenant" -- so a compromised key's blast radius
    is traceable.
"""
from fastapi import APIRouter, Depends, UploadFile, File, Request, HTTPException
from pydantic import BaseModel, Field, field_validator
import asyncio
import re
import logging
import ipaddress
import pandas as pd
import io

from ..core.auth import require_ingest_key
from ..core.db import get_db
from ..core.audit import log_action
from ..core.webhooks import dispatch_critical_alert
from ..core.limiter import limiter
from ..core.config import settings
from ..core.stream import publish_event
from ..core.incidents import correlate_incidents
from ..core.response_actions import dispatch_response_actions
from ..ml.engine import registry, MIN_REAL_FLOWS_TO_REFIT
from ..ml.ot_rules import ot_registry
from ..ingestion.pcap import parse_pcap_bytes
from ..ingestion.modbus import parse_modbus_pcap_bytes
from ..ingestion.discovery import discover_devices
from ..core.devices import store_devices, store_links
from ..core.external import store_endpoints
from ..ingestion.endpoints import extract_endpoints

router = APIRouter(prefix="/ingest", tags=["ingest"])


def _safe_score(value) -> float | None:
    """Detector decision_function scores are almost always finite, but
    found live (not in any prior test): a NaN/inf score from one of the
    four detectors slipping through float(...) uncaught, then blowing up
    json.dumps (Starlette's JSONResponse disallows NaN/Infinity, per strict
    JSON) the next time anyone *read* that row back -- a 500 on every
    dashboard list/demo endpoint touching that flow, well after ingest had
    already returned 200. escalation_reason and entity_baseline_z already
    got this guard; the four score columns hadn't. We did not get this to
    reproduce reliably in isolation (looked for a bad bootstrap-fit seed
    across dozens of trials, found none) -- it surfaced only once, running
    two tenants' cold-start bootstraps back to back in one process. Rather
    than chase a rare, non-reproduced numerical edge case in three
    different anomaly-detection libraries, this makes the failure mode
    itself impossible: a non-finite score is stored as null instead of
    crashing every subsequent read of that row."""
    f = float(value)
    return f if f == f and f not in (float("inf"), float("-inf")) else None

# Deliberately generous (a real capture can run large) but bounded -- an
# unauthenticated-size upload would otherwise let one request exhaust this
# process's memory parsing an arbitrarily large file before any flow-count
# or rate limit even applies.
MAX_PCAP_BYTES = 150 * 1024 * 1024  # 150 MB

# Real finding from adversarial review: the CSV path had NO size cap at
# all (unlike pcap's MAX_PCAP_BYTES above), and the JSON batch path had no
# cap on flow count -- either lets a holder of a valid ingest key (the
# minimum bar, not a privileged credential) submit an arbitrarily large
# request and force this process to build and score a huge DataFrame
# synchronously inside one request, exhausting memory/CPU. Both are now
# bounded the same way the pcap path already was.
MAX_CSV_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_BATCH_FLOWS = 10_000  # generous for a real agent's polling interval, bounded against abuse

REQUIRED_FLOW_COLUMNS = ["dur", "proto", "tot_pkts", "src_bytes", "dst_bytes", "rate", "load", "s_ttl"]


class FlowRecord(BaseModel):
    dur: float
    proto: str
    tot_pkts: int
    src_bytes: float
    dst_bytes: float
    rate: float
    load: float
    s_ttl: int
    src_ip: str | None = None   # optional -- a tenant may choose not to send real IPs
    dst_ip: str | None = None
    source_label: str = "unknown"

    # Real finding from adversarial review: telemetry_flows.src_ip/dst_ip
    # are Postgres `inet` columns (schema.sql), but nothing previously
    # validated the string shape before it reached the DB insert -- a
    # malformed value here would fail against a real Supabase with an
    # unhandled "invalid input syntax for type inet" error (caught only by
    # the generic 500 handler), instead of a clean, specific 400 at the API
    # boundary where the actual problem is.
    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _validate_ip_or_none(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address")
        return v


class IngestBatch(BaseModel):
    flows: list[FlowRecord] = Field(max_length=MAX_BATCH_FLOWS)


@router.post("/batch")
@limiter.limit(settings.INGEST_RATE_LIMIT)
async def ingest_batch(request: Request, batch: IngestBatch, key=Depends(require_ingest_key)):
    """JSON ingestion path — for a lightweight telemetry agent posting live flows."""
    df = pd.DataFrame([f.model_dump() for f in batch.flows])
    return await _process_and_store(key["tenant_id"], key["id"], df)


@router.post("/csv")
@limiter.limit(settings.INGEST_RATE_LIMIT)
async def ingest_csv(request: Request, file: UploadFile = File(...), key=Depends(require_ingest_key)):
    """CSV upload path — for a pilot partner handing over a telemetry export
    instead of standing up a live agent. Expects columns: dur, proto, tot_pkts,
    src_bytes, dst_bytes, rate, load, s_ttl, and optionally src_ip, dst_ip."""
    content = await file.read()
    if len(content) > MAX_CSV_BYTES:
        raise HTTPException(status_code=413, detail=f"CSV exceeds {MAX_CSV_BYTES // (1024*1024)}MB limit")
    try:
        df = pd.read_csv(io.BytesIO(content))
    except Exception as e:
        # Malformed CSV (unparseable, encoding error, etc.) -- a clean 400
        # rather than a 500 from an uncaught pandas parser exception.
        raise HTTPException(status_code=400, detail=f"Could not parse CSV: {e}")
    if len(df) > MAX_BATCH_FLOWS:
        raise HTTPException(status_code=413, detail=f"CSV exceeds {MAX_BATCH_FLOWS} row limit per upload")
    return await _process_and_store(key["tenant_id"], key["id"], df)


@router.post("/pcap")
@limiter.limit(settings.INGEST_RATE_LIMIT)
async def ingest_pcap(request: Request, file: UploadFile = File(...), key=Depends(require_ingest_key)):
    """Real packet-capture ingestion -- a .pcap/.pcapng file (a SPAN-port
    dump, a tcpdump export, a pilot partner's capture) is parsed into
    bidirectional flow records (see ingestion/pcap.py) and scored exactly
    like any other batch. This is the path that proves the detector
    against real traffic shapes rather than synthetic ones.

    The same capture is also run through the Modbus/TCP parser
    (ingestion/modbus.py) and the deterministic OT rule engine
    (ml/ot_rules.py) -- independent of, and in addition to, the generic
    flow-level scoring above. A capture with no Modbus traffic simply
    yields zero OT events; this never blocks or fails the flow-level path."""
    content = await file.read()
    if len(content) > MAX_PCAP_BYTES:
        raise HTTPException(status_code=413, detail=f"pcap exceeds {MAX_PCAP_BYTES // (1024*1024)}MB limit")
    try:
        df = parse_pcap_bytes(content)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    flow_result = (
        {"ingested": 0, "anomalies_detected": 0, "note": "no IPv4 flows found in capture"}
        if df.empty
        else await _process_and_store(key["tenant_id"], key["id"], df)
    )
    ot_result = await _process_ot_events(key["tenant_id"], key["id"], content)

    # Passive device discovery (ARP/LLDP/CDP/DHCP/gateway inference). Never
    # allowed to fail or slow the flow-scoring path it rides along with.
    devices_found = 0
    try:
        devices_found = store_devices(get_db(), key["tenant_id"], discover_devices(content))
    except Exception:
        logging.getLogger(__name__).exception("device discovery failed (ignored)")

    endpoints_found = 0
    try:
        endpoints_found = store_endpoints(get_db(), key["tenant_id"], extract_endpoints(content))
    except Exception:
        logging.getLogger(__name__).exception("external endpoint summary failed (ignored)")

    return {**flow_result, "ot": ot_result, "devices_discovered": devices_found, "external_endpoints": endpoints_found}


async def _process_ot_events(tenant_id: str, key_id: str, pcap_bytes: bytes) -> dict:
    """Parses Modbus/TCP messages out of the same capture and evaluates
    them with the OT rule engine. Failures here are logged and reported in
    the response but never raised -- a capture that happens to confuse the
    Modbus parser (e.g. non-Modbus traffic on port 502) must not fail the
    flow-level ingestion this function is called alongside."""
    try:
        ot_df = parse_modbus_pcap_bytes(pcap_bytes)
    except ValueError:
        return {"ingested": 0, "flagged": 0, "note": "not parseable as pcap for Modbus scan"}
    if ot_df.empty:
        return {"ingested": 0, "flagged": 0}

    engine = ot_registry.get(tenant_id)
    scored = engine.evaluate(ot_df)

    db = get_db()
    rows = []
    flagged_events = []
    for _, row in scored.iterrows():
        severity = row["severity"]
        severity = None if pd.isna(severity) else severity
        reason = row["reason"]
        reason = None if pd.isna(reason) else reason
        exception_code = row["exception_code"]
        exception_code = None if pd.isna(exception_code) else int(exception_code)
        address = row["address"]
        address = None if pd.isna(address) else int(address)
        quantity = row["quantity"]
        quantity = None if pd.isna(quantity) else int(quantity)

        record = {
            "tenant_id": tenant_id, "protocol": "modbus_tcp",
            "ts": pd.Timestamp(row["ts"], unit="s", tz="UTC").isoformat(),
            "src_ip": row["src_ip"], "dst_ip": row["dst_ip"],
            "unit_id": int(row["unit_id"]), "function_code": int(row["function_code"]),
            "function_name": row["function_name"], "is_request": bool(row["is_request"]),
            "is_exception": bool(row["is_exception"]), "exception_code": exception_code,
            "address": address, "quantity": quantity,
            "severity": severity, "reason": reason, "incident_id": None,
        }
        rows.append(record)
        if severity is not None:
            flagged_events.append(record)

    correlate_incidents(db, tenant_id, flagged_events)
    db.table("ot_protocol_events").insert(rows).execute()

    log_action(
        tenant_id, actor=f"api_key:{key_id}", action="ot_telemetry.ingested",
        detail={"messages": len(rows), "flagged": len(flagged_events)},
    )

    for event in flagged_events:
        await publish_event(tenant_id, {**event, "source": "ot_protocol_events"})
    for event in flagged_events:
        if event["severity"] == "critical":
            await dispatch_critical_alert(tenant_id, event)

    return {"ingested": len(rows), "flagged": len(flagged_events)}


async def _maybe_refit_on_real(db, tenant_id: str, detector) -> bool:
    """A new tenant starts on a model fitted to SYNTHETIC traffic, so real
    traffic looks foreign and gets flagged wholesale. Once the tenant has
    MIN_REAL_FLOWS_TO_REFIT real flows stored, refit once on their own most
    recent flows so "normal" means THEIR normal. (refit_on_real existed but
    was never called anywhere before this.) Returns True if a refit ran.
    Caveat: the training window may itself contain some attacks; the
    ensemble's contamination prior covers that, it is not filtered out."""
    if not getattr(detector, "is_bootstrapped_on_synthetic", False):
        return False
    count = (
        db.table("telemetry_flows").select("id", count="exact").eq("tenant_id", tenant_id).limit(1).execute()
    ).count or 0
    if count < MIN_REAL_FLOWS_TO_REFIT:
        return False
    rows = (
        db.table("telemetry_flows")
        .select("dur, proto, tot_pkts, src_bytes, dst_bytes, rate, load, s_ttl")
        .eq("tenant_id", tenant_id).order("received_at", desc=True).limit(5000).execute()
    ).data
    real_df = pd.DataFrame(rows).dropna()
    if len(real_df) < MIN_REAL_FLOWS_TO_REFIT:
        return False
    await asyncio.to_thread(detector.refit_on_real, real_df)
    return True


async def _process_and_store(tenant_id: str, key_id: str, df: pd.DataFrame) -> dict:
    if df.empty:
        return {"ingested": 0, "anomalies_detected": 0}

    # Real finding from adversarial review: a malformed CSV (or, in theory,
    # a pcap producing an unexpected shape) missing one of the engine's
    # required feature columns previously flowed straight into
    # detector.score(), which would raise a KeyError/TypeError deep inside
    # the ML pipeline -- caught only by the generic 500 handler, not a
    # clean, actionable error. The JSON batch path can't hit this (pydantic
    # already enforces every FlowRecord field), but CSV upload has no
    # schema enforcement at parse time, so it's checked explicitly here.
    missing = [c for c in REQUIRED_FLOW_COLUMNS if c not in df.columns]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required column(s): {', '.join(missing)}")

    # Same reasoning, for type rather than presence: a CSV with a
    # non-numeric value in a numeric column (confirmed via direct testing
    # to raise deep inside detector.score() -- "could not convert string
    # to float") previously crashed into a 500. Coerced explicitly here so
    # a malformed upload gets a clean, specific 400 instead.
    numeric_cols = [c for c in REQUIRED_FLOW_COLUMNS if c != "proto"]
    for col in numeric_cols:
        coerced = pd.to_numeric(df[col], errors="coerce")
        if coerced.isna().any() and not df[col].isna().any():
            # isna() after coercion but NOT before -- the original value
            # wasn't already a legitimate null, it just didn't parse.
            raise HTTPException(status_code=400, detail=f"Column '{col}' contains a non-numeric value")
        df[col] = coerced
    if df[numeric_cols].isna().any().any():
        raise HTTPException(status_code=400, detail="One or more required numeric columns contain missing values")

    # Same reasoning as FlowRecord's validator, for the CSV path which
    # bypasses pydantic entirely: telemetry_flows.src_ip/dst_ip are
    # Postgres `inet` columns, so a malformed value must be caught here,
    # not left to surface as an unhandled DB-layer error.
    for col in ("src_ip", "dst_ip"):
        if col not in df.columns:
            continue
        for val in df[col].dropna().unique():
            try:
                ipaddress.ip_address(str(val))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Column '{col}' contains an invalid IP address: '{val}'")

    db = get_db()

    # 1. Store raw flows
    flow_rows = df.assign(tenant_id=tenant_id).to_dict(orient="records")
    flow_insert = db.table("telemetry_flows").insert(flow_rows).execute()
    inserted_flows = flow_insert.data  # includes generated ids

    # 2. Score with this tenant's detector (loads a Redis checkpoint from
    # another instance on a cache miss -- see ml/persistence.py)
    detector = await registry.get(tenant_id)
    await _maybe_refit_on_real(db, tenant_id, detector)
    scored = detector.score(df)
    learning_flows = int(scored["learning"].sum()) if "learning" in scored else 0
    # A source that just finished its learning period is now part of "normal":
    # refit the tenant's models on the real-flow pool (throttled; see engine).
    if detector.learning_refit_due():
        try:
            await asyncio.to_thread(detector.refit_after_learning)
        except Exception:
            logging.getLogger(__name__).exception("refit after learning period failed (scoring unaffected)")

    # 3. Store anomaly events (one row per detector, per flow). The primary
    # row (ECOD) carries severity, explanation, consensus and escalation
    # reason -- the ensemble/entity-burst logic that can promote severity
    # beyond what ECOD's own threshold would have given it.
    anomaly_rows = []
    critical_events = []
    flagged_events = []
    for i, row in scored.iterrows():
        flow_id = inserted_flows[i]["id"]
        escalation_reason = row["escalation_reason"]
        escalation_reason = None if pd.isna(escalation_reason) else escalation_reason
        entity_baseline_z = row["entity_baseline_z"]
        entity_baseline_z = None if pd.isna(entity_baseline_z) else float(entity_baseline_z)
        # Real bug, found live: `severity` is a str | None per flow
        # (TenantDetector.score() builds it as a plain Python list). When a
        # WHOLE batch happens to have zero flagged flows -- every element
        # None, no string ever appears -- pandas' dtype inference on
        # `out["severity"] = severities` upcasts that all-None column to
        # float64, silently turning every None into float('nan') instead
        # of keeping it a column of Nones. escalation_reason and
        # entity_baseline_z already guarded against exactly this
        # (pd.isna(...) -> None); severity didn't, so a calm batch (not a
        # rare ML edge case -- any tenant's quiet traffic window hits this)
        # stored a literal NaN severity on every row, which then crashed
        # every dashboard/demo read of that tenant's data (Starlette's
        # JSONResponse rejects NaN/Infinity) -- not just the flagged rows,
        # every row, because the whole column was coerced together.
        severity = row["severity"]
        severity = None if pd.isna(severity) else severity
        primary_row = {
            "tenant_id": tenant_id, "flow_id": flow_id, "detector": "ECOD",
            "score": _safe_score(row["ecod_score"]), "is_anomaly": bool(row["ecod_is_anomaly"]),
            "severity": severity, "explanation": row["explanation"],
            "consensus_count": int(row["consensus_count"]), "escalation_reason": escalation_reason,
            "entity_baseline_z": entity_baseline_z, "incident_id": None,
            "src_ip": row.get("src_ip"),
        }
        anomaly_rows.append(primary_row)
        for detector_name, score_col, anomaly_col in [
            ("IsolationForest", "iforest_score", "iforest_is_anomaly"),
            ("LOF", "lof_score", "lof_is_anomaly"),
            ("HalfSpaceTrees", "hst_score", "hst_is_anomaly"),
        ]:
            anomaly_rows.append({
                "tenant_id": tenant_id, "flow_id": flow_id, "detector": detector_name,
                "score": _safe_score(row[score_col]), "is_anomaly": bool(row[anomaly_col]),
                "severity": None, "explanation": None, "consensus_count": None,
                "escalation_reason": None, "entity_baseline_z": None, "incident_id": None,
                "src_ip": row.get("src_ip"),
            })
        if severity is not None:
            flagged_events.append(primary_row)
        if severity == "critical":
            critical_events.append(primary_row)

    # 2b. Correlate flagged events into incidents BEFORE inserting -- this
    # mutates each primary_row in place with its incident_id, so the FK is
    # already set on first write rather than needing a follow-up update.
    correlate_incidents(db, tenant_id, flagged_events)

    inserted_anomalies = db.table("anomaly_events").insert(anomaly_rows).execute()

    anomalies_detected = len(flagged_events)

    log_action(
        tenant_id, actor=f"api_key:{key_id}", action="telemetry.ingested",
        detail={"flows": len(df), "anomalies": anomalies_detected},
    )

    # 4. Live push to any open dashboard (SSE), any configured notify
    # webhook for critical events, and any configured automated response
    # action -- none of these are awaited against ingestion's own success:
    # a slow/broken subscriber, webhook, or response endpoint must not make
    # ingestion itself slow or fail.
    for event in flagged_events:
        await publish_event(tenant_id, event)
    for event in critical_events:
        await dispatch_critical_alert(tenant_id, event)
    for event in flagged_events:
        await dispatch_response_actions(tenant_id, event)

    # 5. Periodic cross-instance checkpoint (no-op if this batch hasn't
    # crossed CHECKPOINT_EVERY_FLOWS yet, and no-op entirely if REDIS_URL
    # isn't set). Same fire-and-forget posture as the dispatch loops above.
    await registry.checkpoint_if_due(detector)

    return {"ingested": len(df), "anomalies_detected": anomalies_detected, "critical": len(critical_events),
            "learning_flows": learning_flows}


# ---- SNMP discovery report (agent/snmp_collector.py) -------------------------
# The collector runs on the customer's side (credentials never reach us) and
# posts what it learned. Everything is validated and bounded: a valid ingest
# key is the minimum bar, not a privileged credential.
_ROLES = {"switch", "router", "access_point", "gateway", "dhcp_server", "dns_server", "server", "client", "unknown"}
_SOURCES = {"lldp", "cdp", "fdb"}
_KEY_RE = re.compile(r"^(mac|ip|cdp|lldp):[0-9A-Za-z:._\-/ ]{1,120}$")


class SnmpDevice(BaseModel):
    device_key: str
    mac: str | None = Field(None, max_length=17)
    ip: str | None = None
    ips: list[str] = Field(default_factory=list, max_length=32)
    role: str = "unknown"
    tags: list[str] = Field(default_factory=list, max_length=8)
    hostname: str | None = Field(None, max_length=255)
    os_hint: str | None = Field(None, max_length=255)
    services: list[int] = Field(default_factory=list, max_length=64)
    mac_randomized: bool = False
    evidence: list[str] = Field(default_factory=list, max_length=12)
    confidence: str = "low"
    first_seen_ts: float | None = None
    last_seen_ts: float | None = None

    @field_validator("device_key")
    @classmethod
    def _key(cls, v):
        if not _KEY_RE.match(v):
            raise ValueError("invalid device_key")
        return v

    @field_validator("role")
    @classmethod
    def _role(cls, v):
        return v if v in _ROLES else "unknown"

    @field_validator("confidence")
    @classmethod
    def _conf(cls, v):
        return v if v in ("low", "medium", "high") else "low"

    @field_validator("ip")
    @classmethod
    def _ip(cls, v):
        if v is not None:
            ipaddress.ip_address(v)
        return v

    @field_validator("ips")
    @classmethod
    def _ips(cls, v):
        for x in v:
            ipaddress.ip_address(x)
        return v

    @field_validator("evidence")
    @classmethod
    def _ev(cls, v):
        return [str(e)[:300] for e in v]


class SnmpLink(BaseModel):
    a_key: str
    a_port: str | None = Field(None, max_length=120)
    b_key: str
    b_port: str | None = Field(None, max_length=120)
    source: str
    evidence: str | None = Field(None, max_length=400)

    @field_validator("a_key", "b_key")
    @classmethod
    def _k(cls, v):
        if not _KEY_RE.match(v):
            raise ValueError("invalid device key")
        return v

    @field_validator("source")
    @classmethod
    def _s(cls, v):
        if v not in _SOURCES:
            raise ValueError("source must be one of lldp, cdp, fdb")
        return v


class SnmpReport(BaseModel):
    devices: list[SnmpDevice] = Field(max_length=5000)
    links: list[SnmpLink] = Field(max_length=10000)


@router.post("/snmp")
@limiter.limit("30/minute")
async def ingest_snmp(request: Request, report: SnmpReport, key=Depends(require_ingest_key)):
    """Store an SNMP discovery report (devices + physical links)."""
    db = get_db()
    import time as _t
    now = _t.time()
    devs = []
    for d in report.devices:
        x = d.model_dump()
        x["first_seen_ts"] = x["first_seen_ts"] or now
        x["last_seen_ts"] = x["last_seen_ts"] or now
        x["ips"] = x["ips"] or ([x["ip"]] if x["ip"] else [])
        devs.append(x)
    n_dev = store_devices(db, key["tenant_id"], devs)
    n_link = store_links(db, key["tenant_id"], [l.model_dump() for l in report.links])
    log_action(key["tenant_id"], actor=f"api_key:{key['id']}", action="snmp.ingested", detail={"devices": n_dev, "links": n_link})
    return {"devices": n_dev, "links": n_link}
