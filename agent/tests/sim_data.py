"""Raw SNMP answers for a small lab, shared by the unit tests and the
snmpsim wire test. Lab: core-sw1 (bridge MAC 00:1b:2c:3d:4e:5f) has
 - Gi1/0/1 -> LLDP neighbour edge-sw2 (chassis 00:aa:bb:cc:00:02)
 - Gi1/0/2 -> one host MAC 3c:52:82:bb:00:0b (access link)
 - Gi1/0/3 -> 5 MACs (looks like an unmanaged switch / trunk: no host links)
 - Gi1/0/4 -> host 3c:52:82:bb:00:0c, but ALSO an LLDP neighbour (MACs behind it must not link here)
 plus an ARP table giving IPs."""

def mac_b(s): return bytes(int(x, 16) for x in s.split(":"))
def idx(s): return ".".join(str(int(x, 16)) for x in s.split(":"))

SW = "00:1b:2c:3d:4e:5f"
H1, H2 = "3c:52:82:bb:00:0b", "3c:52:82:bb:00:0c"
TRUNK = [f"3c:52:82:cc:00:{i:02x}" for i in range(1, 6)]

def lab_raw():
    ln = "1.0.8802.1.1.2.1.4.1.1"
    raw = {
        "sysDescr": [("1.3.6.1.2.1.1.1.0", b"Acme Switch OS 4.2 24-port")],
        "sysName": [("1.3.6.1.2.1.1.5.0", b"core-sw1")],
        "sysServices": [("1.3.6.1.2.1.1.7.0", 6)],
        "bridgeAddr": [("1.3.6.1.2.1.17.1.1.0", mac_b(SW))],
        "lldpLocChassis": [], "lldpLocCaps": [("1.0.8802.1.1.2.1.3.6.0", b"\x20\x00")],
        "ifName": [(f"1.3.6.1.2.1.31.1.1.1.1.{i}", f"Gi1/0/{i}".encode()) for i in range(1, 5)],
        "ifDescr": [], "ifPhys": [],
        "lldpLocPortDesc": [(f"1.0.8802.1.1.2.1.3.7.1.4.{i}", f"Gi1/0/{i}".encode()) for i in range(1, 5)],
        "lldpRem": [
            (f"{ln}.5.0.1.1", mac_b("00:aa:bb:cc:00:02")), (f"{ln}.7.0.1.1", b"Gi0/24"),
            (f"{ln}.9.0.1.1", b"edge-sw2"), (f"{ln}.12.0.1.1", b"\x20\x00"),
            (f"{ln}.5.0.4.1", mac_b("00:aa:bb:cc:00:03")), (f"{ln}.9.0.4.1", b"ap-lobby"),
            (f"{ln}.12.0.4.1", b"\x10\x00"),
        ],
        "cdpCache": [],
        "basePortIf": [(f"1.3.6.1.2.1.17.1.4.1.2.{i}", i) for i in range(1, 5)],
        "fdbPort": [], "fdbStatus": [], "qFdbPort": [],
        "arpMac": [
            (f"1.3.6.1.2.1.4.22.1.2.1.10.20.0.11", mac_b(H1)),
            (f"1.3.6.1.2.1.4.22.1.2.1.10.20.0.12", mac_b(H2)),
        ],
    }
    for m, port in [(H1, 2), (H2, 4), ("00:aa:bb:cc:00:02", 1)] + [(t, 3) for t in TRUNK]:
        raw["fdbPort"].append((f"1.3.6.1.2.1.17.4.3.1.2.{idx(m)}", port))
        raw["fdbStatus"].append((f"1.3.6.1.2.1.17.4.3.1.3.{idx(m)}", 3))
    return raw
