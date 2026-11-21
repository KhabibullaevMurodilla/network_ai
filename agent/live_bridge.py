#!/usr/bin/env python3
"""Live-capture bridge for the in-browser analyzer (/analyze).

A web page cannot sniff packets, so this small program runs on YOUR computer:
it captures with dumpcap (Wireshark) or tcpdump, turns packets into flows, and
serves them on http://127.0.0.1:<port>. The analyze page connects to that
address and runs the detectors inside your browser. Nothing is sent to any
server of ours; the flows only travel from this process to your own browser.

    python live_bridge.py --list
    python live_bridge.py --interface 4            # number from --list (Windows/dumpcap)
    python live_bridge.py --interface eth0         # Linux/macOS (tcpdump)
    python live_bridge.py --replay capture.pcap    # no capture rights needed (testing)

It prints a one-time token; paste it into the page. Requests without the token
are rejected, the server binds to 127.0.0.1 only, and requests whose Host header
is not 127.0.0.1/localhost are refused (DNS-rebinding guard).

Flow rules (NetFlow-style): bidirectional 5-tuple; a flow ends on RST, on FIN
from both sides, after IDLE seconds without packets, or is cut into segments
after ACTIVE seconds so long transfers still show up while they run.
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Iterable, Optional
from urllib.parse import parse_qs, urlparse

import dpkt

PROTO = {6: "TCP", 17: "UDP", 1: "ICMP"}


def _ip(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET, raw)


class _Acc:
    __slots__ = ("first", "last", "wall", "src", "dst", "sport", "proto", "pkts", "sb", "db", "ttl", "fins", "rst")

    def __init__(self, ts: float, src: str, dst: str, sport: int, proto: str, ttl: int):
        self.first = self.last = ts
        self.sport = sport
        self.wall = time.monotonic()
        self.src, self.dst, self.proto, self.ttl = src, dst, proto, ttl
        self.pkts = self.sb = self.db = 0
        self.fins: set[str] = set()
        self.rst = False

    def record(self) -> dict:
        dur = max(self.last - self.first, 0.0)
        tot = self.sb + self.db
        return {
            "dur": round(dur, 6), "proto": self.proto, "tot_pkts": self.pkts,
            "src_bytes": float(self.sb), "dst_bytes": float(self.db),
            "rate": round(self.pkts / dur if dur > 0 else float(self.pkts), 4),
            "load": round(tot * 8 / dur if dur > 0 else float(tot * 8), 4),
            "s_ttl": self.ttl, "src_ip": self.src, "dst_ip": self.dst, "ts": round(self.first, 6),
        }


class FlowAggregator:
    """Packet stream -> closed flow records. Thread-safe."""

    def __init__(self, idle: float = 15.0, active: float = 30.0, packet_timeout: Optional[float] = None,
                 on_flow: Optional[Callable[[dict], None]] = None):
        self.idle, self.active = idle, active
        self.packet_timeout = packet_timeout  # offline-style gap rule (tests); None = wall-clock sweep only
        self.on_flow = on_flow or (lambda r: None)
        self.flows: dict[tuple, _Acc] = {}
        self.lock = threading.Lock()
        self.packets = 0

    def _close(self, key):
        a = self.flows.pop(key, None)
        if a is not None and a.pkts > 0:
            self.on_flow(a.record())

    def add(self, ts: float, ip: dpkt.ip.IP) -> None:
        src, dst = _ip(ip.src), _ip(ip.dst)
        proto = PROTO.get(ip.p, "OTHER")
        sp = dp = 0
        fin = rst = False
        if isinstance(ip.data, dpkt.tcp.TCP):
            sp, dp = ip.data.sport, ip.data.dport
            fin, rst = bool(ip.data.flags & dpkt.tcp.TH_FIN), bool(ip.data.flags & dpkt.tcp.TH_RST)
        elif isinstance(ip.data, dpkt.udp.UDP):
            sp, dp = ip.data.sport, ip.data.dport
        a_, b_ = (src, sp), (dst, dp)
        key = (a_, b_, proto) if a_ <= b_ else (b_, a_, proto)
        with self.lock:
            self.packets += 1
            acc = self.flows.get(key)
            if acc is not None and (
                (self.packet_timeout is not None and ts - acc.last > self.packet_timeout)
                or (ts - acc.first) > self.active
            ):
                self._close(key)
                acc = None
            if acc is None:
                acc = self.flows[key] = _Acc(ts, src, dst, sp, proto, ip.ttl)
            acc.last = ts
            acc.wall = time.monotonic()
            acc.pkts += 1
            fwd = (src, sp) == (acc.src, acc.sport)   # IP *and* port: loopback has one IP on both ends
            if fwd:
                acc.sb += ip.len
            else:
                acc.db += ip.len
            if fin:
                acc.fins.add(fwd)
            if rst:
                acc.rst = True
            if acc.rst or len(acc.fins) >= 2:
                self._close(key)

    def sweep(self) -> None:
        """Close flows with no packets for `idle` wall-clock seconds."""
        now = time.monotonic()
        with self.lock:
            for key in [k for k, a in self.flows.items() if now - a.wall > self.idle]:
                self._close(key)

    def flush(self) -> None:
        with self.lock:
            for key in list(self.flows):
                self._close(key)


def ip_from_frame(datalink: int, buf: bytes) -> Optional[dpkt.ip.IP]:
    try:
        if datalink == 1:
            pkt = dpkt.ethernet.Ethernet(buf).data
        elif datalink == 113:
            pkt = dpkt.sll.SLL(buf).data
        elif datalink in (101, 228):
            pkt = dpkt.ip.IP(buf)
        elif datalink == 0:
            pkt = dpkt.ip.IP(buf[4:])
        else:
            return None
        return pkt if isinstance(pkt, dpkt.ip.IP) else None
    except Exception:
        return None


def feed_pcap_stream(stream, agg: FlowAggregator, stop: threading.Event, pace: float = 0.0, packets: Optional["PacketStore"] = None) -> None:
    """Read a classic-pcap byte stream (a pipe or a file) packet by packet.
    If `packets` is given, every raw frame is also kept (bounded) so the page can
    run device discovery / endpoint / Modbus decoding on it."""
    reader = dpkt.pcap.Reader(stream)
    dl = reader.datalink()
    if packets is not None:
        packets.datalink = dl
    prev = None
    for ts, buf in reader:
        if stop.is_set():
            return
        if pace and prev is not None and ts > prev:
            time.sleep(min((ts - prev) / pace, 0.5))
        prev = ts
        if packets is not None:
            packets.add(ts, buf)
        ip = ip_from_frame(dl, buf)
        if ip is not None:
            agg.add(ts, ip)


class Store:
    def __init__(self, maxlen: int = 50000):
        self.buf: deque = deque(maxlen=maxlen)
        self.seq = 0
        self.lock = threading.Lock()
        self.status = {"mode": "starting", "error": None, "started": time.time()}

    def add(self, rec: dict) -> None:
        with self.lock:
            self.seq += 1
            self.buf.append((self.seq, rec))

    def since(self, n: int, limit: int = 20000):
        """Flows with sequence > n (oldest first) and the sequence to ask for next."""
        with self.lock:
            pairs = [(s, r) for s, r in self.buf if s > n][:limit]
        return {"next": pairs[-1][0] if pairs else n, "flows": [r for _, r in pairs]}


class PacketStore:
    """Bounded ring of raw frames (default 32 MB). Oldest frames are dropped first, so a
    page that polls too slowly loses packets rather than the bridge growing without limit."""
    def __init__(self, max_bytes: int = 32 * 1024 * 1024):
        self.buf: deque = deque()
        self.bytes = 0
        self.max_bytes = max_bytes
        self.seq = 0
        self.datalink = 1
        self.lock = threading.Lock()

    def add(self, ts: float, frame: bytes) -> None:
        with self.lock:
            self.seq += 1
            self.buf.append((self.seq, ts, bytes(frame)))
            self.bytes += len(frame)
            while self.bytes > self.max_bytes and self.buf:
                self.bytes -= len(self.buf.popleft()[2])

    def chunk(self, since: int, max_bytes: int = 4 * 1024 * 1024):
        """(classic little-endian pcap bytes, next sequence) for frames with seq > since."""
        out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, self.datalink)]
        size, nxt = 0, since
        with self.lock:
            items = [x for x in self.buf if x[0] > since]
        for seq, ts, frame in items:
            if size + len(frame) + 16 > max_bytes:
                break
            sec = int(ts)
            out.append(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(frame), len(frame)))
            out.append(frame)
            size += len(frame) + 16
            nxt = seq
        return b"".join(out), nxt


def make_handler(store: Store, agg: FlowAggregator, token: str, port: int, packets: Optional[PacketStore] = None):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep the console quiet
            pass

        def _cors(self):
            self.send_header("Access-Control-Allow-Origin", "*")  # safe: every data route needs the token
            self.send_header("Access-Control-Allow-Headers", "Authorization")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Expose-Headers", "X-Next-Seq")

        def _send(self, code: int, body: dict):
            data = json.dumps(body).encode()
            self.send_response(code)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_OPTIONS(self):
            if self.headers.get("Host") not in allowed_hosts:
                return self._send(403, {"error": "bad host"})
            self.send_response(204)
            self._cors()
            self.end_headers()

        def do_GET(self):
            if self.headers.get("Host") not in allowed_hosts:
                return self._send(403, {"error": "bad host"})
            supplied = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            if not hmac.compare_digest(supplied.encode(), token.encode()):
                return self._send(401, {"error": "missing or wrong token"})
            u = urlparse(self.path)
            if u.path == "/status":
                with store.lock:
                    st = dict(store.status)
                st.update({"flows_total": store.seq, "packets": agg.packets, "active_flows": len(agg.flows)})
                return self._send(200, st)
            if u.path == "/flows":
                try:
                    since = int(parse_qs(u.query).get("since", ["0"])[0])
                except ValueError:
                    since = 0
                return self._send(200, store.since(since))
            if u.path == "/packets" and packets is not None:
                try:
                    since = int(parse_qs(u.query).get("since", ["0"])[0])
                except ValueError:
                    since = 0
                data, nxt = packets.chunk(since)
                self.send_response(200)
                self._cors()
                self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("X-Next-Seq", str(nxt))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
                return
            self._send(404, {"error": "not found"})

    return H


def _capture_cmd(interface: str, bpf: str, snaplen: int) -> list[str]:
    dumpcap = shutil.which("dumpcap") or next(
        (p for p in (r"C:\Program Files\Wireshark\dumpcap.exe", "/usr/bin/dumpcap", "/Applications/Wireshark.app/Contents/MacOS/dumpcap") if os.path.exists(p)), None)
    if dumpcap:
        cmd = [dumpcap, "-i", interface, "-q", "-F", "pcap", "-s", str(snaplen), "-w", "-"]
        return cmd + (["-f", bpf] if bpf else [])
    tcpdump = shutil.which("tcpdump")
    if tcpdump:
        return [tcpdump, "-i", interface, "-n", "-U", "-s", str(snaplen), "-w", "-"] + ([bpf] if bpf else [])
    raise SystemExit("Neither dumpcap (install Wireshark) nor tcpdump was found.")


def list_interfaces() -> None:
    dumpcap = shutil.which("dumpcap") or r"C:\Program Files\Wireshark\dumpcap.exe"
    tcpdump = shutil.which("tcpdump")
    for tool in ([dumpcap] if os.path.exists(dumpcap) else []) + ([tcpdump] if tcpdump else []):
        print(f"Interfaces via {tool}:")
        subprocess.run([tool, "-D"])
        return
    print("Neither dumpcap (install Wireshark) nor tcpdump was found.")


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Live capture bridge for the in-browser analyzer")
    ap.add_argument("--list", action="store_true", help="list capture interfaces and exit")
    ap.add_argument("--interface", "-i", help="interface name/number to capture")
    ap.add_argument("--replay", help="replay a .pcap file instead of capturing (testing)")
    ap.add_argument("--speed", type=float, default=0.0, help="replay speed multiplier (0 = as fast as possible)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--filter", default="", help="extra capture filter (BPF), e.g. 'not port 53'")
    ap.add_argument("--snaplen", type=int, default=1600, help="bytes kept per packet; device discovery, TLS names and Modbus need more than headers")
    ap.add_argument("--idle", type=float, default=15.0)
    ap.add_argument("--active", type=float, default=30.0)
    ap.add_argument("--token", help="use this token instead of a random one (testing)")
    interactive = argv is None and len(sys.argv) == 1 and sys.stdin is not None and sys.stdin.isatty()
    args = ap.parse_args(list(argv) if argv is not None else None)
    if interactive:  # double-clicked / run with no arguments: ask instead of failing
        print("Network AI live bridge\n")
        list_interfaces()
        choice = input("\nType the interface number or name to capture (or press Enter to quit): ").strip()
        if not choice:
            return 0
        args.interface = choice

    if args.list:
        list_interfaces()
        return 0
    if not args.interface and not args.replay:
        ap.error("give --interface (see --list) or --replay FILE")

    token = args.token or secrets.token_urlsafe(12)
    store = Store()
    packets = PacketStore()
    agg = FlowAggregator(idle=args.idle, active=args.active, on_flow=store.add)
    stop = threading.Event()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(store, agg, token, args.port, packets))
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def sweeper():
        while not stop.wait(2.0):
            agg.sweep()
    threading.Thread(target=sweeper, daemon=True).start()

    print(f"Live bridge listening on http://127.0.0.1:{args.port}")
    print(f"Token (paste into the page): {token}")
    print("Only this computer can connect, and only with the token. Ctrl+C to stop.")
    proc = None
    try:
        if args.replay:
            store.status.update(mode="replay")
            with open(args.replay, "rb") as f:
                feed_pcap_stream(f, agg, stop, pace=args.speed, packets=packets)
            agg.flush()
            store.status.update(mode="replay finished")
            print("Replay finished; still serving flows. Ctrl+C to stop.")
            while not stop.wait(1.0):
                pass
        else:
            # keep the bridge's own traffic out of the capture
            own = f"not port {args.port}"
            bpf = f"({args.filter}) and {own}" if args.filter else own
            cmd = _capture_cmd(args.interface, bpf, args.snaplen)
            store.status.update(mode="capturing", interface=args.interface)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            threading.Thread(target=lambda: store.status.update(error=proc.stderr.read().decode(errors="replace")[-400:] or None),
                             daemon=True).start()
            feed_pcap_stream(proc.stdout, agg, stop, packets=packets)
            rc = proc.wait()
            msg = store.status.get("error") or f"capture program exited with code {rc}"
            store.status.update(mode="stopped", error=msg)
            print(f"Capture ended: {msg}\n(Wrong interface? On Windows run PowerShell as Administrator; on Linux/macOS use sudo.)")
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        if proc and proc.poll() is None:
            proc.terminate()
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
