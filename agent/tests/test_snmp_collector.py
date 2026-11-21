import snmp_collector as sc
from tests.sim_data import lab_raw, SW, H1, H2, TRUNK


def report():
    return sc.build_report("192.168.1.2", lab_raw(), now=1000.0)


def by_key(r): return {d["device_key"]: d for d in r["devices"]}


def test_polled_device_identity_and_role():
    d = by_key(report())["mac:" + SW]
    assert d["role"] == "switch" and d["hostname"] == "core-sw1" and d["ip"] == "192.168.1.2"
    assert d["confidence"] == "high"


def test_lldp_neighbours_become_links_with_ports():
    r = report()
    l = [x for x in r["links"] if x["source"] == "lldp"]
    sw2 = next(x for x in l if x["b_key"] == "mac:00:aa:bb:cc:00:02")
    assert sw2["a_key"] == "mac:" + SW and sw2["a_port"] == "Gi1/0/1" and sw2["b_port"] == "Gi0/24"
    assert by_key(r)["mac:00:aa:bb:cc:00:02"]["role"] == "switch"
    assert by_key(r)["mac:00:aa:bb:cc:00:03"]["role"] == "access_point"


def test_access_port_gets_host_link_but_trunk_and_neighbour_ports_do_not():
    r = report()
    fdb = {(x["a_port"], x["b_key"]) for x in r["links"] if x["source"] == "fdb"}
    assert ("Gi1/0/2", "mac:" + H1) in fdb
    assert not any(p == "Gi1/0/3" for p, _ in fdb)          # 5 MACs -> trunk
    assert not any(b == "mac:" + H2 for _, b in fdb)         # Gi1/0/4 has an LLDP neighbour
    assert not any(b == "mac:00:aa:bb:cc:00:02" for _, b in fdb)
    assert any("Uplink/trunk" in e and "Gi1/0/3 (5 MACs)" in e for e in by_key(r)["mac:" + SW]["evidence"])


def test_arp_enriches_hosts_with_ips():
    d = by_key(report())
    assert d["mac:" + H1]["ip"] == "10.20.0.11"
    assert d["mac:" + H2]["ip"] == "10.20.0.12"


def test_edge_max_is_configurable():
    r = sc.build_report("192.168.1.2", lab_raw(), edge_max=10)
    assert sum(1 for x in r["links"] if x["source"] == "fdb" and x["a_port"] == "Gi1/0/3") == 5


def test_sysservices_fallback_when_no_lldp_caps():
    raw = lab_raw(); raw["lldpLocCaps"] = []; raw["sysServices"] = [("x", 78)]  # L3+L2+L7 bits
    assert by_key(sc.build_report("1.1.1.1", raw))["mac:" + SW]["role"] == "switch"
    raw["sysServices"] = [("x", 4)]
    assert by_key(sc.build_report("1.1.1.1", raw))["mac:" + SW]["role"] == "router"


def test_missing_bridge_mac_falls_back_to_ip_key():
    raw = lab_raw(); raw["bridgeAddr"] = []
    assert "ip:192.168.1.2" in by_key(sc.build_report("192.168.1.2", raw))


def test_cdp_neighbour():
    raw = lab_raw()
    raw["cdpCache"] = [("1.3.6.1.4.1.9.9.23.1.2.1.1.6.2.1", b"edge-rt1"), ("1.3.6.1.4.1.9.9.23.1.2.1.1.7.2.1", b"Fa0/3"),
                       ("1.3.6.1.4.1.9.9.23.1.2.1.1.8.2.1", b"cisco 2911")]
    r = sc.build_report("192.168.1.2", raw)
    l = next(x for x in r["links"] if x["source"] == "cdp")
    assert l["b_key"] == "cdp:edge-rt1" and l["a_port"] == "Gi1/0/2" and l["b_port"] == "Fa0/3"


def test_empty_or_garbage_raw_does_not_crash():
    r = sc.build_report("9.9.9.9", {})
    assert len(r["devices"]) == 1 and r["links"] == []


def test_merge_dedups_links_and_keeps_best_confidence():
    a, b = report(), report()
    m = sc.merge_reports([a, b])
    assert len(m["links"]) == len(a["links"])
    assert len({d["device_key"] for d in m["devices"]}) == len(m["devices"])


def test_cable_seen_from_both_ends_is_one_link():
    a = {"a_key": "mac:00:1b", "a_port": "Gi1/0/1", "b_key": "mac:00:aa", "b_port": "Gi0/24", "source": "lldp", "evidence": "x"}
    b = {"a_key": "mac:00:aa", "a_port": "Gi0/24", "b_key": "mac:00:1b", "b_port": "Gi1/0/1", "source": "lldp", "evidence": "y"}
    rep = lambda l: {"devices": [], "links": [l]}
    assert len(sc.merge_reports([rep(a), rep(b)])["links"]) == 1


def test_discover_refuses_public_and_huge_ranges():
    import asyncio, pytest
    with pytest.raises(ValueError, match="not a private range"):
        asyncio.run(sc.discover_targets("8.8.8.0/24", {"version": "2c", "community": "x"}))
    with pytest.raises(ValueError, match="limit"):
        asyncio.run(sc.discover_targets("10.0.0.0/16", {"version": "2c", "community": "x"}))
