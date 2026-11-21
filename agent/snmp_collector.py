#!/usr/bin/env python3
"""Network AI SNMP collector (v6.6) -- READ-ONLY discovery of physical links.

Why this is a collector you run yourself and not part of the cloud backend:
your switches' SNMP credentials never leave your network, and the backend
(which may be in Docker or the cloud) usually cannot reach your switches
anyway. This script polls ONLY the devices you list (it never sweeps a
subnet), turns the answers into a small JSON report, and POSTs it to
`/ingest/snmp` with an ingest API key.

What it reads (all standard MIBs, GET/GETNEXT/walk only -- it never writes):
  * SNMPv2-MIB / IF-MIB   system name/description, interface names, own MACs
  * LLDP-MIB              local capabilities + the neighbour table (real links)
  * CISCO-CDP-MIB         neighbour table, where the device is Cisco
  * BRIDGE-MIB/Q-BRIDGE   the MAC address table (which MAC sits on which port)
  * IP-MIB                the ARP table (IP <-> MAC) on routers / L3 switches

How a link is decided:
  * LLDP/CDP neighbour entry            -> link, source "lldp"/"cdp" (strong)
  * A MAC learned on a port with no neighbour behind it and <= --edge-max
    MACs on that port                    -> access link, source "fdb" (good)
  * A port with more MACs than that, or any port that has an LLDP/CDP
    neighbour, is an uplink/trunk: its MACs are NOT linked to this switch.

Config file (JSON). Use a READ-ONLY community / SNMPv3 user:
  [
    {"host": "192.168.1.2", "version": "2c", "community": "public"},
    {"host": "192.168.1.3", "version": "3", "user": "monitor",
     "auth_key": "...", "auth_proto": "SHA", "priv_key": "...", "priv_proto": "AES"}
  ]
Keep this file private (chmod 600): it holds credentials.

Run:  python snmp_collector.py --config targets.json --api-url http://localhost:8000 \
          --api-key YOUR_INGEST_KEY [--interval 300] [--dry-run]
"""
from __future__ import annotations
import argparse
import asyncio
import json
import sys
import time

OID = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysServices": "1.3.6.1.2.1.1.7.0",
    "bridgeAddr": "1.3.6.1.2.1.17.1.1.0",
    "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifPhys": "1.3.6.1.2.1.2.2.1.6",
    "lldpLocChassis": "1.0.8802.1.1.2.1.3.2.0",
    "lldpLocCaps": "1.0.8802.1.1.2.1.3.6.0",
    "lldpLocPortDesc": "1.0.8802.1.1.2.1.3.7.1.4",
    "lldpRem": "1.0.8802.1.1.2.1.4.1.1",
    "cdpCache": "1.3.6.1.4.1.9.9.23.1.2.1.1",
    "fdbPort": "1.3.6.1.2.1.17.4.3.1.2",
    "fdbStatus": "1.3.6.1.2.1.17.4.3.1.3",
    "qFdbPort": "1.3.6.1.2.1.17.7.1.2.2.1.2",
    "basePortIf": "1.3.6.1.2.1.17.1.4.1.2",
    "arpMac": "1.3.6.1.2.1.4.22.1.2",
}

DEFAULT_EDGE_MAX = 3
MAX_ARP_DEVICES = 2000


# --------------------------------------------------------------------------
# Pure normalisation: raw SNMP answers -> devices + links (fully unit-tested)
# --------------------------------------------------------------------------
def _mac(b) -> str | None:
    if isinstance(b, (bytes, bytearray)) and len(b) == 6 and any(b):
        return ":".join(f"{x:02x}" for x in b)
    return None


def _text(v) -> str:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("utf-8", "replace").strip("\x00 \r\n")
    return "" if v is None else str(v)


def _tail(oid: str, base: str) -> list[int]:
    if not oid.startswith(base + "."):
        return []
    return [int(x) for x in oid[len(base) + 1:].split(".") if x.isdigit()]


def _mac_from_index(parts: list[int]) -> str | None:
    return _mac(bytes(parts)) if len(parts) == 6 and all(0 <= p < 256 for p in parts) else None


def _first(raw: dict, name: str):
    rows = raw.get(name) or []
    return rows[0][1] if rows else None


def build_report(host: str, raw: dict, edge_max: int = DEFAULT_EDGE_MAX, now: float | None = None) -> dict:
    """raw maps an OID-name (see OID) to a list of (oid_string, value)."""
    now = now or time.time()
    sys_name = _text(_first(raw, "sysName"))
    sys_descr = _text(_first(raw, "sysDescr"))
    services = _first(raw, "sysServices") or 0

    # --- identity: prefer the bridge/chassis MAC so neighbours' LLDP chassis ids match
    base_mac = _mac(_first(raw, "bridgeAddr")) or _mac(_first(raw, "lldpLocChassis"))
    if not base_mac:
        for _, v in raw.get("ifPhys") or []:
            if _mac(v):
                base_mac = _mac(v)
                break
    self_key = ("mac:" + base_mac) if base_mac else "ip:" + host

    # --- role: LLDP capability bits (BITS: bit0 = 0x80 of the first octet), else sysServices
    role = "unknown"
    caps = _first(raw, "lldpLocCaps")
    if isinstance(caps, (bytes, bytearray)) and caps:
        if caps[0] & 0x20:
            role = "switch"
        elif caps[0] & 0x08:
            role = "router"
        elif caps[0] & 0x10:
            role = "access_point"
    if role == "unknown":
        role = "switch" if services & 0x02 else ("router" if services & 0x04 else "unknown")
    tags = []
    if isinstance(caps, (bytes, bytearray)) and caps and (caps[0] & 0x08) and role != "router":
        tags.append("router")

    # --- interface names
    if_names = {}
    for oid, v in raw.get("ifDescr") or []:
        t = _tail(oid, OID["ifDescr"])
        if t:
            if_names[t[0]] = _text(v)
    for oid, v in raw.get("ifName") or []:
        t = _tail(oid, OID["ifName"])
        if t and _text(v):
            if_names[t[0]] = _text(v)
    lldp_port_desc = {}
    for oid, v in raw.get("lldpLocPortDesc") or []:
        t = _tail(oid, OID["lldpLocPortDesc"])
        if t:
            lldp_port_desc[t[0]] = _text(v)

    base_to_if = {}
    for oid, v in raw.get("basePortIf") or []:
        t = _tail(oid, OID["basePortIf"])
        if t:
            base_to_if[t[0]] = int(v)

    def bridge_port_name(bp: int) -> str:
        return if_names.get(base_to_if.get(bp, -1)) or f"port{bp}"

    evidence = [f"SNMP poll of {host}" + (f" (sysName {sys_name})" if sys_name else "")]
    if sys_descr:
        evidence.append("sysDescr: " + sys_descr[:100])

    devices: dict[str, dict] = {}
    links: list[dict] = []

    def add_device(key, mac, ip, role_, hostname, ev, conf, os_hint=None, tags_=None):
        d = devices.get(key)
        if d is None:
            devices[key] = {
                "device_key": key, "mac": mac, "ip": ip, "ips": [ip] if ip else [], "role": role_,
                "tags": tags_ or [], "hostname": hostname, "os_hint": os_hint, "services": [],
                "mac_randomized": bool(mac and int(mac[:2], 16) & 0x02), "evidence": list(ev),
                "confidence": conf, "first_seen_ts": now, "last_seen_ts": now,
            }
        else:
            if ip and ip not in d["ips"]:
                d["ips"].append(ip)
                d["ip"] = d["ip"] or ip
            d["hostname"] = d["hostname"] or hostname
            for e in ev:
                if e not in d["evidence"] and len(d["evidence"]) < 12:
                    d["evidence"].append(e)

    add_device(self_key, base_mac, host, role, sys_name or None, evidence, "high", os_hint=sys_descr[:120] or None, tags_=tags)

    # --- LLDP neighbours: .<col>.<timeMark>.<localPort>.<remIndex>
    lldp_cols: dict[tuple, dict] = {}
    for oid, v in raw.get("lldpRem") or []:
        t = _tail(oid, OID["lldpRem"])
        if len(t) >= 4:
            lldp_cols.setdefault(tuple(t[1:4]), {})[t[0]] = v
    neighbour_ports: set[str] = set()
    for (_, local_port, _), cols in lldp_cols.items():
        chassis = cols.get(5)
        rmac = _mac(chassis) if isinstance(chassis, (bytes, bytearray)) else None
        rkey = ("mac:" + rmac) if rmac else ("lldp:" + _text(chassis)) if _text(chassis) else None
        if not rkey:
            continue
        lport = lldp_port_desc.get(local_port) or if_names.get(local_port) or f"port{local_port}"
        rport = _text(cols.get(8)) or _text(cols.get(7))
        rname = _text(cols.get(9))
        rcaps = cols.get(12)
        rrole = "unknown"
        if isinstance(rcaps, (bytes, bytearray)) and rcaps:
            rrole = "switch" if rcaps[0] & 0x20 else "router" if rcaps[0] & 0x08 else "access_point" if rcaps[0] & 0x10 else "unknown"
        add_device(rkey, rmac, None, rrole, rname or None, [f"LLDP neighbour of {sys_name or host} on {lport}"], "high")
        links.append({"a_key": self_key, "a_port": lport, "b_key": rkey, "b_port": rport or None,
                      "source": "lldp", "evidence": f"LLDP: {sys_name or host} {lport} <-> {rname or rkey} {rport}".strip()})
        neighbour_ports.add(lport)

    # --- CDP neighbours: .<col>.<ifIndex>.<devIndex>
    cdp: dict[tuple, dict] = {}
    for oid, v in raw.get("cdpCache") or []:
        t = _tail(oid, OID["cdpCache"])
        if len(t) >= 3:
            cdp.setdefault((t[1], t[2]), {})[t[0]] = v
    for (ifidx, _), cols in cdp.items():
        devid = _text(cols.get(6))
        if not devid:
            continue
        lport = if_names.get(ifidx, f"if{ifidx}")
        rkey = "cdp:" + devid
        add_device(rkey, None, None, "unknown", devid, [f"CDP neighbour of {sys_name or host} on {lport}"], "high",
                   os_hint=_text(cols.get(8)) or None)
        links.append({"a_key": self_key, "a_port": lport, "b_key": rkey, "b_port": _text(cols.get(7)) or None,
                      "source": "cdp", "evidence": f"CDP: {sys_name or host} {lport} <-> {devid} {_text(cols.get(7))}".strip()})
        neighbour_ports.add(lport)

    # --- MAC address table -> access links
    fdb: dict[str, int] = {}
    status = {}
    for oid, v in raw.get("fdbStatus") or []:
        m = _mac_from_index(_tail(oid, OID["fdbStatus"]))
        if m:
            status[m] = int(v)
    for oid, v in raw.get("fdbPort") or []:
        m = _mac_from_index(_tail(oid, OID["fdbPort"]))
        if m and status.get(m, 3) == 3 and int(v) > 0:
            fdb[m] = int(v)
    for oid, v in raw.get("qFdbPort") or []:
        t = _tail(oid, OID["qFdbPort"])
        m = _mac_from_index(t[1:]) if len(t) == 7 else None
        if m and int(v) > 0:
            fdb.setdefault(m, int(v))
    by_port: dict[str, list[str]] = {}
    for m, bp in fdb.items():
        by_port.setdefault(bridge_port_name(bp), []).append(m)
    uplinks = {}
    for pname, macs in by_port.items():
        if pname in neighbour_ports or len(macs) > edge_max:
            uplinks[pname] = len(macs)
            continue
        for m in macs:
            if m == base_mac:
                continue
            key = "mac:" + m
            add_device(key, m, None, "unknown", None, [f"Learned on {sys_name or host} port {pname} (MAC table)"], "medium")
            links.append({"a_key": self_key, "a_port": pname, "b_key": key, "b_port": None,
                          "source": "fdb", "evidence": f"MAC table: {m} on {sys_name or host} {pname}"})
    if uplinks:
        devices[self_key]["evidence"].append(
            "Uplink/trunk ports (not linked to individual hosts): " + ", ".join(f"{p} ({n} MACs)" for p, n in sorted(uplinks.items())))

    # --- ARP table (routers / L3 switches): IP <-> MAC, enriches hosts only
    n_arp = 0
    for oid, v in raw.get("arpMac") or []:
        t = _tail(oid, OID["arpMac"])
        rmac = _mac(v)
        if len(t) == 5 and rmac and n_arp < MAX_ARP_DEVICES:
            ip = ".".join(str(x) for x in t[1:])
            add_device("mac:" + rmac, rmac, ip, "unknown", None, [f"ARP entry on {sys_name or host}: {ip}"], "medium")
            n_arp += 1

    return {"devices": list(devices.values()), "links": links}


def canonical_link(l: dict) -> dict:
    """A cable seen from both ends must be ONE link: order the endpoints."""
    a = (l["a_key"], l.get("a_port") or "")
    b = (l["b_key"], l.get("b_port") or "")
    if a <= b:
        return l
    return {**l, "a_key": l["b_key"], "a_port": l.get("b_port"), "b_key": l["a_key"], "b_port": l.get("a_port")}


def merge_reports(reports: list[dict]) -> dict:
    devices: dict[str, dict] = {}
    links: dict[tuple, dict] = {}
    for r in reports:
        for d in r["devices"]:
            old = devices.get(d["device_key"])
            if old is None:
                devices[d["device_key"]] = d
            else:
                rank = {"low": 0, "medium": 1, "high": 2}
                if rank[d["confidence"]] > rank[old["confidence"]]:
                    old["confidence"] = d["confidence"]
                if old["role"] == "unknown":
                    old["role"] = d["role"]
                old["hostname"] = old["hostname"] or d["hostname"]
                old["ip"] = old["ip"] or d["ip"]
                old["ips"] = sorted(set(old["ips"]) | set(d["ips"]))
                old["evidence"] = (old["evidence"] + [e for e in d["evidence"] if e not in old["evidence"]])[:12]
        for l in map(canonical_link, r["links"]):
            links.setdefault((l["a_key"], l["a_port"] or "", l["b_key"]), l)
    return {"devices": list(devices.values()), "links": list(links.values())}


# --------------------------------------------------------------------------
# SNMP transport (pysnmp 7.x) -- thin; everything above is pure
# --------------------------------------------------------------------------
class SnmpClient:
    def __init__(self, target: dict, timeout: float = 3.0, retries: int = 1):
        from pysnmp.hlapi.v3arch.asyncio import (
            SnmpEngine, CommunityData, UsmUserData, ContextData, UdpTransportTarget,
            usmHMACSHAAuthProtocol, usmHMACMD5AuthProtocol, usmAesCfb128Protocol, usmDESPrivProtocol,
        )
        self.host = target["host"]
        self.port = int(target.get("port", 161))
        self.timeout, self.retries = timeout, retries
        self.engine = SnmpEngine()
        self.ctx = ContextData()
        ver = str(target.get("version", "2c"))
        if ver in ("2c", "2", "1"):
            self.auth = CommunityData(target["community"], mpModel=1 if ver != "1" else 0)
        elif ver == "3":
            auth_p = {"SHA": usmHMACSHAAuthProtocol, "MD5": usmHMACMD5AuthProtocol}[target.get("auth_proto", "SHA").upper()]
            priv_p = {"AES": usmAesCfb128Protocol, "DES": usmDESPrivProtocol}[target.get("priv_proto", "AES").upper()]
            kw = {}
            if target.get("auth_key"):
                kw.update(authKey=target["auth_key"], authProtocol=auth_p)
            if target.get("priv_key"):
                kw.update(privKey=target["priv_key"], privProtocol=priv_p)
            self.auth = UsmUserData(target["user"], **kw)
        else:
            raise ValueError(f"unsupported SNMP version {ver!r}")
        self._transport = None

    async def _target(self):
        from pysnmp.hlapi.v3arch.asyncio import UdpTransportTarget
        if self._transport is None:
            self._transport = await UdpTransportTarget.create((self.host, self.port), timeout=self.timeout, retries=self.retries)
        return self._transport

    @staticmethod
    def _py(v):
        from pyasn1.type import univ
        from pysnmp.proto.rfc1902 import OctetString, ObjectIdentifier
        if isinstance(v, OctetString):
            return v.asOctets()
        if isinstance(v, ObjectIdentifier):
            return str(v)
        try:
            return int(v)
        except Exception:
            return str(v)

    async def get(self, oid: str):
        from pysnmp.hlapi.v3arch.asyncio import get_cmd, ObjectType, ObjectIdentity
        err, status, _, vbs = await get_cmd(self.engine, self.auth, await self._target(), self.ctx, ObjectType(ObjectIdentity(oid)))
        if err or status:
            return None
        v = vbs[0][1]
        if v.__class__.__name__ in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
            return None
        return self._py(v)

    async def walk(self, oid: str, max_rows: int = 20000):
        from pysnmp.hlapi.v3arch.asyncio import walk_cmd, ObjectType, ObjectIdentity
        out = []
        async for err, status, _, vbs in walk_cmd(
            self.engine, self.auth, await self._target(), self.ctx, ObjectType(ObjectIdentity(oid)), lexicographicMode=False
        ):
            if err or status:
                break
            for name, val in vbs:
                out.append((str(name.get_oid()) if hasattr(name, "get_oid") else str(name), self._py(val)))
            if len(out) >= max_rows:
                break
        return out

    def close(self):
        try:
            self.engine.close_dispatcher()
        except Exception:
            pass


async def collect_raw(client) -> dict:
    raw: dict[str, list] = {}
    for name in ("sysDescr", "sysName", "sysServices", "bridgeAddr", "lldpLocChassis", "lldpLocCaps"):
        v = await client.get(OID[name])
        raw[name] = [(OID[name], v)] if v is not None else []
    for name in ("ifName", "ifDescr", "ifPhys", "lldpLocPortDesc", "lldpRem", "cdpCache",
                 "fdbPort", "fdbStatus", "qFdbPort", "basePortIf", "arpMac"):
        raw[name] = await client.walk(OID[name])
    return raw


async def poll_target(target: dict, edge_max: int, timeout: float) -> dict:
    client = SnmpClient(target, timeout=timeout)
    try:
        raw = await collect_raw(client)
    finally:
        client.close()
    if not raw["sysName"] and not raw["sysDescr"]:
        raise RuntimeError(f"{target['host']}: no SNMP answer (wrong host, community/credentials, or SNMP disabled)")
    return build_report(target["host"], raw, edge_max=edge_max)


async def run_once(targets: list[dict], edge_max: int, timeout: float) -> dict:
    results = await asyncio.gather(*(poll_target(t, edge_max, timeout) for t in targets), return_exceptions=True)
    reports = []
    for t, r in zip(targets, results):
        if isinstance(r, Exception):
            print(f"[snmp] {t['host']}: FAILED -- {r}", file=sys.stderr)
        else:
            print(f"[snmp] {t['host']}: {len(r['devices'])} devices, {len(r['links'])} links")
            reports.append(r)
    return merge_reports(reports)


async def discover_targets(cidr: str, template: dict, concurrency: int = 64, timeout: float = 1.5,
                           allow_public: bool = False, max_hosts: int = 1024) -> list[dict]:
    """OPT-IN active sweep: ask every address in `cidr` for sysName using the
    credentials in `template` and return the ones that answer. Only ever runs
    when --discover is given, and refuses public ranges and huge ranges unless
    explicitly overridden. Scan only networks you own or are authorised to test."""
    import ipaddress
    net = ipaddress.ip_network(cidr, strict=False)
    if not allow_public and not (net.is_private or net.is_loopback):
        raise ValueError(f"{cidr} is not a private range; pass --allow-public only if you are authorised to scan it")
    hosts = [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
    if len(hosts) > max_hosts:
        raise ValueError(f"{cidr} has {len(hosts)} hosts (limit {max_hosts}); use a smaller range")
    sem = asyncio.Semaphore(concurrency)

    async def probe(h: str):
        async with sem:
            t = {**template, "host": h}
            c = None
            try:
                c = SnmpClient(t, timeout=timeout, retries=0)
                return t if await c.get(OID["sysName"]) is not None else None
            except Exception:
                return None
            finally:
                if c:
                    c.close()

    found = [t for t in await asyncio.gather(*(probe(h) for h in hosts)) if t]
    print(f"[discover] {cidr}: {len(found)} SNMP device(s) of {len(hosts)} address(es) probed")
    return found


def post_report(api_url: str, api_key: str, report: dict) -> dict:
    import requests
    resp = requests.post(api_url.rstrip("/") + "/ingest/snmp", json=report, headers={"X-API-Key": api_key}, timeout=60)
    resp.raise_for_status()
    return resp.json()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Read-only SNMP discovery -> Network AI")
    ap.add_argument("--host", help="poll one device without a config file (use with --community)")
    ap.add_argument("--community", help="read-only SNMP v2c community for --host")
    ap.add_argument("--config", help="targets JSON; with --discover, its FIRST entry is the credential template")
    ap.add_argument("--discover", metavar="CIDR", help="also sweep this range (e.g. 192.168.1.0/24) for devices answering SNMP; opt-in active scan")
    ap.add_argument("--allow-public", action="store_true", help="allow --discover on non-private ranges (only if authorised)")
    ap.add_argument("--api-url", default="http://localhost:8000")
    ap.add_argument("--api-key")
    ap.add_argument("--interval", type=int, default=0, help="seconds between polls; 0 = once")
    ap.add_argument("--edge-max", type=int, default=DEFAULT_EDGE_MAX)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--dry-run", action="store_true", help="print the report instead of uploading")
    a = ap.parse_args(argv)
    if a.host:
        if not a.community:
            ap.error("--host needs --community")
        targets = [{"host": a.host, "version": "2c", "community": a.community}]
    elif not a.config:
        ap.error("give either --host and --community, or --config targets.json")
    else:
      try:
        targets = json.load(open(a.config))
      except FileNotFoundError:
        ap.error(f"{a.config} not found. Copy snmp_targets.example.json to {a.config} and put your device IPs and read-only SNMP credentials in it.")
      except json.JSONDecodeError as e:
        ap.error(f"{a.config} is not valid JSON ({e}). Compare it with snmp_targets.example.json.")
    if not isinstance(targets, list) or not targets:
        ap.error(f"{a.config} must be a JSON list with at least one device entry")
    if not a.dry_run and not a.api_key:
        ap.error("--api-key is required unless --dry-run")
    while True:
        run_targets = list(targets)
        if a.discover:
            known = {(t["host"], int(t.get("port", 161))) for t in run_targets}
            tmpl = {k: v for k, v in targets[0].items() if k != "host"}
            for t in asyncio.run(discover_targets(a.discover, tmpl, allow_public=a.allow_public)):
                if (t["host"], int(t.get("port", 161))) not in known:
                    run_targets.append(t)
        report = asyncio.run(run_once(run_targets, a.edge_max, a.timeout))
        if a.dry_run:
            print(json.dumps(report, indent=2))
        elif report["devices"]:
            try:
                print("[upload]", post_report(a.api_url, a.api_key, report))
            except Exception as e:
                print(f"[upload] FAILED -- {e}", file=sys.stderr)
        if not a.interval:
            return 0
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())
