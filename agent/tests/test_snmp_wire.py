"""Real SNMP over UDP: snmpsim serves the lab data, the real pysnmp client
walks it. Skipped unless SNMPSIM_BIN points at snmpsim-command-responder
(install snmpsim-lextudio in a SEPARATE venv: it pins an old pysnmp)."""
import asyncio, os, shutil, socket, subprocess, tempfile, time
import pytest
import snmp_collector as sc
from tests.sim_data import lab_raw

BIN = os.environ.get("SNMPSIM_BIN")
pytestmark = pytest.mark.skipif(not (BIN and os.path.exists(BIN)), reason="SNMPSIM_BIN not set")


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


@pytest.fixture(scope="module")
def sim():
    d = tempfile.mkdtemp()
    rows = sorted((tuple(int(x) for x in o.split(".")), o, v) for lst in lab_raw().values() for o, v in lst)
    with open(os.path.join(d, "public.snmprec"), "w") as f:
        for _, o, v in rows:
            f.write(f"{o}|4x|{v.hex()}\n" if isinstance(v, bytes) else f"{o}|2|{v}\n")
    os.chmod(d, 0o755); os.chmod(os.path.join(d, "public.snmprec"), 0o644)
    port = _free_port()
    p = subprocess.Popen([BIN, f"--data-dir={d}", f"--agent-udpv4-endpoint=127.0.0.1:{port}",
                          "--process-user=nobody", "--process-group=nogroup"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(4)
    yield port
    p.terminate(); shutil.rmtree(d, ignore_errors=True)


def test_real_udp_poll_matches_expected_topology(sim):
    r = asyncio.run(sc.poll_target({"host": "127.0.0.1", "port": sim, "version": "2c", "community": "public"}, 3, 3.0))
    keys = {d["device_key"] for d in r["devices"]}
    assert "mac:00:1b:2c:3d:4e:5f" in keys and "mac:00:aa:bb:cc:00:02" in keys
    assert {(l["source"], l["a_port"]) for l in r["links"]} == {("lldp", "Gi1/0/1"), ("lldp", "Gi1/0/4"), ("fdb", "Gi1/0/2")}


def test_wrong_community_fails_clearly(sim):
    with pytest.raises(RuntimeError, match="no SNMP answer"):
        asyncio.run(sc.poll_target({"host": "127.0.0.1", "port": sim, "version": "2c", "community": "wrong"}, 3, 1.0))


def test_discover_finds_responding_device_and_ignores_silent_ones(sim):
    tmpl = {"port": sim, "version": "2c", "community": "public"}
    found = asyncio.run(sc.discover_targets("127.0.0.1/32", tmpl, timeout=2.0))
    assert [t["host"] for t in found] == ["127.0.0.1"]
    assert asyncio.run(sc.discover_targets("127.0.0.1/32", {**tmpl, "community": "wrong"}, timeout=1.0)) == []
