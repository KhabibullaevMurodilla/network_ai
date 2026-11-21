"""v6.3: GET /dashboard/topology -- node-link graph built from recent flow
telemetry (nodes = IPs seen as src or dst, edges = (src,dst) pairs weighted
by flow count), with anomaly severity joined in per source node."""
from unittest.mock import patch

import jwt
import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.fake_db import FakeDB

JWT_SECRET = "test-jwt-secret-not-real"
TENANT = "88888888-8888-8888-8888-888888888888"
OTHER_TENANT = "99999999-9999-9999-9999-999999999999"
USER = "dddddddd-0000-0000-0000-000000000001"


def auth() -> dict:
    token = jwt.encode({"sub": USER, "aud": "authenticated", "exp": 9999999999}, JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def db():
    fake = FakeDB()
    fake.seed("profiles", [{"id": USER, "tenant_id": TENANT, "role": "viewer", "email": "v@x.com"}])
    fake.seed("telemetry_flows", [
        {"tenant_id": TENANT, "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "proto": "TCP", "received_at": "2026-01-01T00:00:03Z"},
        {"tenant_id": TENANT, "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "proto": "TCP", "received_at": "2026-01-01T00:00:02Z"},
        {"tenant_id": TENANT, "src_ip": "10.0.0.9", "dst_ip": "10.0.0.1", "proto": "UDP", "received_at": "2026-01-01T00:00:01Z"},
        # no src_ip -- a tenant that chose not to send real IPs; must not produce a node
        {"tenant_id": TENANT, "src_ip": None, "dst_ip": None, "proto": "TCP", "received_at": "2026-01-01T00:00:00Z"},
        # other tenant's flow -- must never leak into TENANT's graph
        {"tenant_id": OTHER_TENANT, "src_ip": "10.0.0.5", "dst_ip": "192.168.1.1", "proto": "TCP", "received_at": "2026-01-01T00:00:04Z"},
    ])
    fake.seed("anomaly_events", [
        {"tenant_id": TENANT, "detector": "ECOD", "is_anomaly": True, "src_ip": "10.0.0.5", "severity": "critical", "created_at": "2026-01-01T00:00:03Z"},
    ])
    with patch("app.core.auth.get_db", return_value=fake), patch("app.routers.dashboard.get_db", return_value=fake):
        yield fake


@pytest.fixture
def client(db):
    return TestClient(app)


def test_topology_returns_nodes_and_weighted_edges(client, db):
    r = client.get("/dashboard/topology", headers=auth())
    assert r.status_code == 200
    body = r.json()
    node_ids = {n["id"] for n in body["nodes"]}
    assert node_ids == {"10.0.0.5", "10.0.0.1", "10.0.0.9"}
    edge = next(e for e in body["edges"] if e["source"] == "10.0.0.5" and e["target"] == "10.0.0.1")
    assert edge["flow_count"] == 2


def test_topology_joins_anomaly_severity_onto_the_source_node(client, db):
    r = client.get("/dashboard/topology", headers=auth())
    nodes = {n["id"]: n for n in r.json()["nodes"]}
    assert nodes["10.0.0.5"]["max_severity"] == "critical"
    assert nodes["10.0.0.5"]["event_count"] == 1
    assert nodes["10.0.0.1"]["max_severity"] is None  # never a source, no anomalies attributed to it


def test_topology_never_leaks_another_tenants_flows(client, db):
    r = client.get("/dashboard/topology", headers=auth())
    node_ids = {n["id"] for n in r.json()["nodes"]}
    assert "192.168.1.1" not in node_ids


def test_topology_respects_max_nodes_cap(client, db):
    r = client.get("/dashboard/topology?max_nodes=1", headers=auth())
    body = r.json()
    assert len(body["nodes"]) <= 2  # the pair that produced the first edge before the cap stopped growth
    assert body["truncated"] is True
