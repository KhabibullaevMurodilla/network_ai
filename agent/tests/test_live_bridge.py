import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import live_bridge as lb

LOCAL = Path(__file__).resolve().parents[2] / "frontend" / "tests" / "local"
TOKEN = "test-token"


def feed(path, **kw):
    out = []
    agg = lb.FlowAggregator(on_flow=out.append, **kw)
    with open(path, "rb") as f:
        lb.feed_pcap_stream(f, agg, threading.Event())
    agg.flush()
    return out


def test_aggregator_matches_backend_parser_on_sample():
    ref = json.loads((LOCAL / "pcap_reference.json").read_text())["pcap"]
    got = feed(LOCAL / "sample.pcap", idle=1e9, active=1e9, packet_timeout=60.0)
    assert len(got) == len(ref) == 5
    for g, r in zip(got, ref):
        for k, v in r.items():
            assert (abs(g[k] - v) <= max(1e-3, abs(v) * 1e-5)) if isinstance(v, (int, float)) else g[k] == v, (k, g, r)


def test_long_flow_is_cut_into_segments():
    # sample.pcap's TCP flow lasts 0.05 s; an active timeout of 0.02 s must split it
    got = feed(LOCAL / "sample.pcap", idle=1e9, active=0.02, packet_timeout=60.0)
    assert len(got) > 5 and sum(g["tot_pkts"] for g in got) == 12


def _server(port):
    store = lb.Store()
    agg = lb.FlowAggregator(on_flow=store.add)
    srv = lb.ThreadingHTTPServer(("127.0.0.1", port), lb.make_handler(store, agg, TOKEN, port))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return store, srv


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(port, path, token=TOKEN, host=None, method="GET"):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Host": host or f"127.0.0.1:{port}"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    c.request(method, path, headers=h)
    r = c.getresponse()
    body = r.read()
    return r.status, dict(r.getheaders()), (json.loads(body) if body else None)


def test_http_requires_token_and_valid_host():
    port = _free_port()
    store, srv = _server(port)
    try:
        for i in range(3):
            store.add({"n": i})
        assert _get(port, "/flows", token=None)[0] == 401
        assert _get(port, "/flows", token="wrong")[0] == 401
        assert _get(port, "/flows", host="evil.example.com")[0] == 403          # DNS-rebinding guard
        st, _, body = _get(port, "/flows?since=0")
        assert st == 200 and [f["n"] for f in body["flows"]] == [0, 1, 2] and body["next"] == 3
        st, _, body = _get(port, "/flows?since=2")
        assert [f["n"] for f in body["flows"]] == [2] and body["next"] == 3
        st, _, body = _get(port, "/flows?since=3")
        assert body["flows"] == [] and body["next"] == 3
        st, hdr, _ = _get(port, "/flows", method="OPTIONS", token=None)         # CORS preflight needs no token
        assert st == 204 and hdr.get("Access-Control-Allow-Private-Network") == "true"
        assert _get(port, "/status")[2]["flows_total"] == 3
    finally:
        srv.shutdown()


def test_replay_end_to_end_via_cli():
    port = _free_port()
    p = subprocess.Popen([sys.executable, str(Path(lb.__file__)), "--replay", str(LOCAL / "sample.pcap"),
                          "--port", str(port), "--token", TOKEN], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        flows = []
        for _ in range(50):
            try:
                st, _, body = _get(port, "/flows?since=0")
                flows = body["flows"]
                if len(flows) >= 5:
                    break
            except OSError:
                pass
            time.sleep(0.2)
        assert len(flows) == 5 and {f["proto"] for f in flows} == {"TCP", "UDP", "ICMP"}
    finally:
        p.terminate()
        p.wait(5)


@pytest.mark.skipif(not (shutil.which("tcpdump") and hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs tcpdump and root to capture")
def test_real_loopback_capture():
    """Real packets: capture 'lo' with tcpdump while a local TCP exchange happens."""
    port, svc = _free_port(), _free_port()
    p = subprocess.Popen([sys.executable, str(Path(lb.__file__)), "--interface", "lo", "--port", str(port),
                          "--token", TOKEN, "--idle", "1"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        time.sleep(1.5)                                   # let tcpdump attach
        srv = socket.socket(); srv.bind(("127.0.0.1", svc)); srv.listen(1)
        threading.Thread(target=lambda: (lambda c: (c.recv(4096), c.sendall(b"R" * 5000), c.close()))(srv.accept()[0]), daemon=True).start()
        c = socket.create_connection(("127.0.0.1", svc)); c.sendall(b"Q" * 300); c.recv(10000); c.close()
        hit = None
        for _ in range(40):
            try:
                _, _, body = _get(port, "/flows?since=0")
                hit = next((f for f in body["flows"] if f["tot_pkts"] >= 6), None)
                if hit:
                    break
            except OSError:
                pass
            time.sleep(0.25)
        assert hit and hit["proto"] == "TCP" and hit["src_bytes"] > 300 and hit["dst_bytes"] > 5000, hit
    finally:
        p.terminate()
        p.wait(5)


def test_packets_endpoint_serves_a_valid_pcap_chunk_and_pages():
    import dpkt, io
    with open(LOCAL / "sample.pcap", "rb") as f:
        original = [(ts, bytes(b)) for ts, b in dpkt.pcap.Reader(f)]
    port = _free_port()
    p = subprocess.Popen([sys.executable, str(Path(lb.__file__)), "--replay", str(LOCAL / "sample.pcap"),
                          "--port", str(port), "--token", TOKEN], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        def raw(path, token=TOKEN):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            c.request("GET", path, headers={"Authorization": f"Bearer {token}"})
            r = c.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        for _ in range(50):
            try:
                st, hd, body = raw("/packets?since=0")
                if st == 200 and int(hd["X-Next-Seq"]) >= len(original):
                    break
            except OSError:
                pass
            time.sleep(0.2)
        got = [(ts, bytes(b)) for ts, b in dpkt.pcap.Reader(io.BytesIO(body))]
        assert len(got) == len(original) and [b for _, b in got] == [b for _, b in original]
        assert all(abs(a[0] - b[0]) < 2e-6 for a, b in zip(got, original))
        # paging: asking from the last sequence returns a header-only pcap
        st, hd, body2 = raw(f"/packets?since={hd['X-Next-Seq']}")
        assert st == 200 and len(list(dpkt.pcap.Reader(io.BytesIO(body2)))) == 0 and hd["X-Next-Seq"] == str(len(original))
        assert raw("/packets?since=0", token="wrong")[0] == 401
        assert all("ts" in f for f in _get(port, "/flows?since=0")[2]["flows"])
    finally:
        p.terminate()
        p.wait(5)


def test_packet_store_is_bounded():
    ps = lb.PacketStore(max_bytes=1000)
    for i in range(100):
        ps.add(1.0 + i, b"x" * 100)
    assert ps.bytes <= 1000 and len(ps.buf) == 10 and ps.buf[0][0] == 91
