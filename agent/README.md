# Network AI live capture agent

Runs on a host with access to real traffic — a SPAN/mirror port, a tap, or
just a monitored interface — and streams it into the platform
continuously. This is what closes the gap `POST /ingest/pcap` had on its
own: that endpoint could only ever process a capture file someone
manually uploaded. This agent is the thing that captures and uploads on
a loop, unattended.

## How it works

Each cycle: run `tcpdump` on the given interface for `--interval` seconds
(default 30), write the result to a temp pcap file, `POST` that file to
`/ingest/pcap` with the configured API key, delete the temp file, repeat.
It deliberately reuses the backend's own already-verified pcap parser and
ingestion path rather than inventing a second one — this agent is a
scheduling/transport layer around that, not a second detection pipeline.

**Verified end-to-end in this build**: ran the agent against a real
loopback interface while generating real TCP traffic during the capture
window, pointed it at a real running backend instance, and confirmed the
flow was actually captured, parsed, scored, and stored (`window
ingested: flows=1 anomalies=1 critical=0` from a real HTTP response, not
a mock). Also verified: graceful shutdown (SIGINT/SIGTERM interrupts an
in-progress capture within ~0.5s, not after a false start — this was a
real bug, see below), retry/backoff on a network failure, and a clear
error on a bad interface name.

**Two real bugs were caught and fixed while testing this**, worth being
upfront about:
1. A failed capture window (bad interface, permissions error) never
   incremented the internal window counter, so `--max-windows` was
   silently ignored on persistent failure — the agent would spin
   indefinitely rather than stopping as configured. Fixed to count
   failed windows too.
2. The original implementation blocked on a single `tcpdump.wait(timeout=
   interval)` call, so sending SIGINT mid-capture logged "shutting down"
   immediately but the process didn't actually exit until the full
   remaining window elapsed (confirmed: still running 10+ seconds after
   SIGINT with a 30s interval). Fixed to poll in 0.5s increments and
   interrupt the capture promptly on a shutdown signal.

## Install

```bash
pip install -r requirements.txt
```

Needs `tcpdump` on the host (`apt install tcpdump` / `yum install tcpdump`).

## Permissions

Live packet capture needs elevated privileges. Two options, in order of
preference:

1. **Capability grant (preferred over running as root)**:
   ```bash
   sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)
   ```
   Then the agent itself doesn't need to run as root — only `tcpdump`
   needs the capability. This is what `network-ai-agent.service.example`
   assumes via `AmbientCapabilities`.
2. **Run as root.** Simpler, broader privilege than necessary — fine for
   a quick pilot, not recommended for a long-running production agent.

## Run it

```bash
export NETWORK_AI_API_KEY=<an ingest-scoped API key from the dashboard>
python3 network_ai_agent.py \
    --interface eth0 \
    --api-url https://api.yourdomain.com \
    --interval 30
```

- `--interval`: seconds per capture window. Shorter = lower latency
  before an attack shows up in the dashboard, more HTTP overhead. 30s is
  a reasonable starting point; tune per deployment.
- `--filter`: a BPF filter (default `"ip"` — all IPv4 traffic). Narrow
  this if the interface sees traffic you don't want ingested (e.g.
  `"ip and not port 22"` to exclude SSH management traffic).
- `--max-windows`: mainly for testing — stop after N windows instead of
  running forever.

For a persistent deployment, see `network-ai-agent.service.example` —
copy it to `/etc/systemd/system/network-ai-agent.service`, adjust the
paths/interface/URL, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now network-ai-agent
```

## Known limitations (v1, stated plainly)

- **No local buffering/replay queue.** If the upload fails after 3
  retries (network blip, backend down), that window's flows are logged
  and dropped — not queued for later retry. A durable local spill-to-disk
  queue is real follow-up work, not attempted here.
- **One agent, one interface.** Monitoring several interfaces or several
  hosts means running several agent instances (each with its own API
  key recommended, so a compromised agent's blast radius is traceable
  via the audit log — see the backend's own API-key-scoping design).
- **No encrypted-traffic-specific handling.** The agent captures and
  forwards whatever the interface sees; the backend's flow-level features
  work the same regardless of payload encryption, but there's no
  TLS-fingerprinting-specific extraction yet (see the project roadmap).

## Live bridge for the in-browser analyzer (`live_bridge.py`)

**No Python needed:** download the program for your OS from the repo's Releases page (built by the
`Build live-capture helper` workflow; push a tag like `v1.0.0` to publish one), run it, pick your network
interface when it asks, and paste the token it prints into the page. On Windows/macOS install Wireshark first
(the helper uses its `dumpcap`); on Linux it uses `tcpdump`. The Windows exe is unsigned, so SmartScreen will warn.

A web page cannot capture packets. `live_bridge.py` runs on your computer, captures with
dumpcap (Wireshark) or tcpdump, builds flows, and serves them on `http://127.0.0.1:8765` to
the `/analyze` page, where the detectors run in your browser. No backend, account or API key.

```
pip install -r requirements.txt            # needs dpkt
python live_bridge.py --list               # show interfaces
python live_bridge.py --interface 4        # Windows/dumpcap: the number from --list
sudo python live_bridge.py --interface eth0   # Linux/macOS (tcpdump)
python live_bridge.py --replay some.pcap   # no capture rights: replay a file (testing)
```
It prints a one-time token; paste it into the Live capture box on the page.

Safety: binds to 127.0.0.1 only; every data route needs the token; requests with another
Host header are refused (DNS-rebinding guard); the bridge's own port is excluded from the capture.
Flows end on RST, FIN from both sides, 15 s idle, or are cut after 30 s (NetFlow-style).

**Verified:** aggregator output equals the backend pcap parser on a test capture; HTTP token/host
checks; end-to-end replay; a REAL capture of loopback traffic with tcpdump (found and fixed a
direction bug when both ends share one IP); the page analysing that live capture in headless Chromium.
**Also verified:** the compiled Linux program (PyInstaller one-file build) answers replay and a real loopback capture correctly, and its no-argument interface prompt appears.
**NOT verified:** the Windows and macOS builds (made only by the GitHub workflow), dumpcap/Npcap on Windows; Chrome's "access devices on your network" prompt and Safari
(blocks http://127.0.0.1 from an https page) with the page served over HTTPS; sustained high-rate
traffic (Python parsing is probably limited to some tens of thousands of packets/s).
