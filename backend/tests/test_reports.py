"""v6.3: exportable PDF security-posture report. Verifies real PDF bytes
come back (not a stub/placeholder) by checking the PDF magic header and
that reportlab's own parser can walk the page content, plus the HTTP
surface (auth required, rate limited, correct content-type)."""
from datetime import datetime, timezone
from unittest.mock import patch

import jwt
import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader
import io

from app.main import app
from app.core.reports import generate_pdf_bytes
from tests.fake_db import FakeDB

JWT_SECRET = "test-jwt-secret-not-real"
TENANT = "aa111111-1111-1111-1111-111111111111"
USER = "ee000000-0000-0000-0000-000000000001"
RATE_LIMIT_USER = "ee000000-0000-0000-0000-000000000099"


def auth(sub: str = USER) -> dict:
    token = jwt.encode({"sub": sub, "aud": "authenticated", "exp": 9999999999}, JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def db():
    now = datetime.now(timezone.utc).isoformat()
    fake = FakeDB()
    fake.seed("profiles", [
        {"id": USER, "tenant_id": TENANT, "role": "viewer", "email": "v@x.com"},
        {"id": RATE_LIMIT_USER, "tenant_id": TENANT, "role": "viewer", "email": "rl@x.com"},
    ])
    fake.seed("tenants", [{"id": TENANT, "name": "Acme Logistics", "plan": "pro"}])
    fake.seed("telemetry_flows", [
        {"tenant_id": TENANT, "received_at": now},
        {"tenant_id": TENANT, "received_at": now},
    ])
    fake.seed("anomaly_events", [
        {"tenant_id": TENANT, "detector": "ECOD", "is_anomaly": True, "severity": "critical", "src_ip": "10.0.0.5", "created_at": now},
        {"tenant_id": TENANT, "detector": "ECOD", "is_anomaly": True, "severity": "high", "src_ip": "10.0.0.5", "created_at": now},
        {"tenant_id": TENANT, "detector": "ECOD", "is_anomaly": True, "severity": "low", "src_ip": "10.0.0.9", "created_at": now},
    ])
    fake.seed("incidents", [
        {"tenant_id": TENANT, "status": "closed", "created_at": now},
        {"tenant_id": TENANT, "status": "open", "created_at": now},
    ])
    with patch("app.core.auth.get_db", return_value=fake), \
         patch("app.core.reports.get_db", return_value=fake), \
         patch("app.core.audit.get_db", return_value=fake):
        yield fake


def test_generate_pdf_bytes_produces_a_real_pdf(db):
    pdf = generate_pdf_bytes(TENANT, days=30)
    assert pdf[:5] == b"%PDF-"
    reader = PdfReader(io.BytesIO(pdf))
    assert len(reader.pages) >= 1
    text = reader.pages[0].extract_text()
    assert "Acme Logistics" in text
    assert "Security Posture Report" in text


def test_pdf_reflects_real_counts_not_placeholder_zeros(db):
    pdf = generate_pdf_bytes(TENANT, days=30)
    text = PdfReader(io.BytesIO(pdf)).pages[0].extract_text()
    assert "10.0.0.5" in text  # the busiest flagged entity
    assert "Critical" in text


@pytest.fixture
def client(db):
    return TestClient(app)


def test_endpoint_requires_auth(client, db):
    r = client.get("/reports/pdf")
    assert r.status_code in (401, 422)


def test_endpoint_returns_a_pdf_with_correct_content_type(client, db):
    r = client.get("/reports/pdf", headers=auth())
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-"


def test_endpoint_is_rate_limited(client, db):
    codes = [client.get("/reports/pdf", headers=auth(RATE_LIMIT_USER)).status_code for _ in range(12)]
    assert codes.count(200) == 10
    assert codes.count(429) == 2
