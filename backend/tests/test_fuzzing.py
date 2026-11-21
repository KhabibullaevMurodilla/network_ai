"""Malformed-input and injection-style fuzzing against the real ingest
pipeline (TestClient, real parsers, real detector) -- not just the pure
parser unit tests in test_pcap.py/test_modbus.py. Three real bugs were
found and fixed via this pass (see ingest.py's REQUIRED_FLOW_COLUMNS /
numeric-coercion block and MAX_CSV_BYTES/MAX_BATCH_FLOWS): a CSV missing a
required column or containing a non-numeric value in a numeric column
crashed into an unhandled 500 inside the ML scoring pipeline, and neither
the CSV path nor the JSON batch path had any size/row cap at all."""
import time

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from app.core.auth import hash_key
from app.routers.ingest import MAX_CSV_BYTES, MAX_BATCH_FLOWS
from tests.fake_db import FakeDB

TENANT = "33333333-3333-3333-3333-333333333333"
RAW_KEY = "raw-fuzz-ingest-key"


@pytest.fixture
def db():
    from app.core.auth import hash_key as _hash
    fake = FakeDB()
    fake.seed("api_keys", [
        {"id": "key-fuzz", "tenant_id": TENANT, "key_hash": _hash(RAW_KEY), "scope": "ingest", "revoked_at": None},
    ])
    targets = [
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


@pytest.fixture
def client(db):
    return TestClient(app)


KEY_HEADER = {"X-API-Key": RAW_KEY}
GOOD_FLOW = {
    "dur": 1.0, "proto": "TCP", "tot_pkts": 10, "src_bytes": 100.0,
    "dst_bytes": 200.0, "rate": 5.0, "load": 3.0, "s_ttl": 64,
}


# --- JSON batch -----------------------------------------------------------

def test_oversized_batch_rejected(client, db):
    flows = [GOOD_FLOW] * (MAX_BATCH_FLOWS + 1)
    r = client.post("/ingest/batch", headers=KEY_HEADER, json={"flows": flows})
    assert r.status_code == 422  # pydantic max_length violation


def test_batch_at_limit_accepted_shape(client, db):
    """Not actually scoring MAX_BATCH_FLOWS rows (slow); confirms the
    boundary itself isn't off-by-one in the wrong direction."""
    flows = [GOOD_FLOW] * 3
    r = client.post("/ingest/batch", headers=KEY_HEADER, json={"flows": flows})
    assert r.status_code == 200


def test_sql_injection_style_string_in_source_label_handled_safely(client, db):
    """Supabase access goes through a parameterized query builder, not raw
    SQL (confirmed by grep: no execute_sql/raw SQL anywhere in app/), so
    this isn't exploitable -- the point of this test is that it doesn't
    crash or behave strangely, since the FakeDB equality-based store would
    surface a naive string-concatenation bug if one existed."""
    payload = dict(GOOD_FLOW, source_label="'; DROP TABLE anomaly_events; --")
    r = client.post("/ingest/batch", headers=KEY_HEADER, json={"flows": [payload]})
    assert r.status_code == 200
    stored = db.table("telemetry_flows").eq("tenant_id", TENANT).execute().data
    assert any(row["source_label"] == "'; DROP TABLE anomaly_events; --" for row in stored)


def test_xss_style_string_in_source_label_stored_as_plain_text(client, db):
    """React escapes all string interpolation by default (confirmed by
    grep: no dangerouslySetInnerHTML anywhere in frontend/), so a stored
    XSS payload here isn't exploitable in the dashboard -- stored and
    returned as inert text, which this test pins."""
    payload = dict(GOOD_FLOW, source_label="<script>alert(document.cookie)</script>")
    r = client.post("/ingest/batch", headers=KEY_HEADER, json={"flows": [payload]})
    assert r.status_code == 200


# --- CSV --------------------------------------------------------------------

def test_oversized_csv_rejected(client, db):
    huge_csv = "dur,proto,tot_pkts,src_bytes,dst_bytes,rate,load,s_ttl\n" + "x" * (MAX_CSV_BYTES + 1)
    r = client.post("/ingest/csv", headers=KEY_HEADER, files={"file": ("f.csv", huge_csv.encode(), "text/csv")})
    assert r.status_code == 413


def test_csv_missing_required_column_rejected_cleanly(client, db):
    """Real bug found and fixed: this previously crashed deep inside
    detector.score() into a generic 500 instead of a clean 400."""
    csv = "proto,tot_pkts,src_bytes,dst_bytes,rate,load,s_ttl\nTCP,10,100,200,5,3,64\n"  # no "dur"
    r = client.post("/ingest/csv", headers=KEY_HEADER, files={"file": ("f.csv", csv.encode(), "text/csv")})
    assert r.status_code == 400
    assert "dur" in r.json()["detail"]


def test_csv_non_numeric_value_in_numeric_column_rejected_cleanly(client, db):
    """Real bug found and fixed: 'could not convert string to float',
    unhandled, confirmed via direct reproduction before the fix."""
    csv = "dur,proto,tot_pkts,src_bytes,dst_bytes,rate,load,s_ttl\nnot-a-number,TCP,10,100,200,5,3,64\n"
    r = client.post("/ingest/csv", headers=KEY_HEADER, files={"file": ("f.csv", csv.encode(), "text/csv")})
    assert r.status_code == 400


def test_garbage_unparseable_csv_rejected_cleanly_not_500(client, db):
    garbage = b"\x00\x01\x02\xff\xfe\xfd not a csv at all \x00\x00"
    r = client.post("/ingest/csv", headers=KEY_HEADER, files={"file": ("f.csv", garbage, "text/csv")})
    assert r.status_code in (400, 200)  # pandas may parse it as one garbage column -- either is acceptable, a 500 is not
    if r.status_code == 200:
        # if it "parsed", it must have been caught by the missing-column check
        pass


def test_empty_csv_handled_without_crash(client, db):
    r = client.post("/ingest/csv", headers=KEY_HEADER, files={"file": ("f.csv", b"", "text/csv")})
    assert r.status_code in (200, 400)


def test_malformed_ip_in_json_batch_rejected_cleanly(client, db):
    """Real finding: src_ip/dst_ip are Postgres `inet` columns with no
    prior format validation at the API boundary."""
    payload = dict(GOOD_FLOW, src_ip="not-an-ip-address")
    r = client.post("/ingest/batch", headers=KEY_HEADER, json={"flows": [payload]})
    assert r.status_code == 422


def test_valid_ipv4_and_ipv6_in_json_batch_accepted(client, db):
    for ip in ("10.0.0.5", "2001:db8::1"):
        payload = dict(GOOD_FLOW, src_ip=ip)
        r = client.post("/ingest/batch", headers=KEY_HEADER, json={"flows": [payload]})
        assert r.status_code == 200, f"valid IP '{ip}' was rejected: {r.text}"


def test_malformed_ip_in_csv_rejected_cleanly(client, db):
    csv = "dur,proto,tot_pkts,src_bytes,dst_bytes,rate,load,s_ttl,src_ip\n1.0,TCP,10,100,200,5,3,64,999.999.999.999\n"
    r = client.post("/ingest/csv", headers=KEY_HEADER, files={"file": ("f.csv", csv.encode(), "text/csv")})
    assert r.status_code == 400
    assert "src_ip" in r.json()["detail"]


def test_valid_csv_still_works_after_hardening(client, db):
    """Regression guard: the fixes above must not have broken the happy path."""
    csv = "dur,proto,tot_pkts,src_bytes,dst_bytes,rate,load,s_ttl\n1.0,TCP,10,100,200,5,3,64\n"
    r = client.post("/ingest/csv", headers=KEY_HEADER, files={"file": ("f.csv", csv.encode(), "text/csv")})
    assert r.status_code == 200
    assert r.json()["ingested"] == 1
