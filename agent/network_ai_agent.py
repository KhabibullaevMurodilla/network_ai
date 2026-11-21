#!/usr/bin/env python3
"""Network AI live capture agent.

Runs on a customer's own edge host (something with a SPAN/mirror port, or
an inline tap) and streams real traffic into the platform continuously,
closing the gap the platform had through v6: `POST /ingest/pcap` could
only ever process a capture file someone manually handed over. This agent
is what turns that into something that runs unattended.

How it actually works, honestly: this is NOT a packet-parsing engine of
its own -- it deliberately reuses the exact same `POST /ingest/pcap` path
and `ingestion/pcap.py` parser already verified in the backend, rather
than inventing a second, divergent capture->flow pipeline. What this
agent adds is the *scheduling* layer around that: it shells out to
`tcpdump` for each short time window, captures to a small pcap file, and
POSTs that file to the backend, on a loop, with retry/backoff and clean
shutdown. Using `tcpdump` rather than re-implementing packet capture
(e.g. via a raw socket or scapy sniff loop) is deliberate -- it's the
most portable, battle-tested way to actually get packets off a live
interface across different Linux distributions and permission models,
without this agent needing its own BPF/capture-privilege code path.

Known, stated limitation (v1): there is no local buffering/replay queue.
If the POST to the backend fails (network blip, backend down) after
retries are exhausted, that window's flows are logged as dropped and the
agent moves on to the next window -- it does not persist and retry
indefinitely. A durable local queue (e.g. spill to disk, replay on
reconnect) is real follow-up work, not pretended to be solved here.
"""
from __future__ import annotations
import argparse
import logging
import os
import signal
import subprocess
import sys
import tempfile
import time
import json

import requests

logger = logging.getLogger("network_ai_agent")

DEFAULT_INTERVAL_SECONDS = 30
DEFAULT_BPF_FILTER = "ip"
MAX_POST_RETRIES = 3
POST_RETRY_BACKOFF_SECONDS = 2.0
TCPDUMP_SHUTDOWN_GRACE_SECONDS = 3.0

_shutdown_requested = False


def _handle_signal(signum, _frame):
    global _shutdown_requested
    logger.info("received signal %s, shutting down after current window", signum)
    _shutdown_requested = True


SHUTDOWN_POLL_INTERVAL_SECONDS = 0.5


def capture_window(interface: str, duration_seconds: int, bpf_filter: str, out_path: str) -> bool:
    """Runs tcpdump for up to `duration_seconds`, writing to out_path.
    Returns True if tcpdump produced a readable pcap file (even an empty
    one -- no traffic in a window is a valid, normal outcome, not a
    failure). tcpdump is sent SIGTERM (not killed) when the window ends
    so it flushes its pcap writer and exits with a valid file, not a
    truncated one -- `kill -9` would corrupt the capture on the last
    packet.

    Polls in short increments rather than blocking on a single
    `proc.wait(timeout=duration_seconds)` call so a SIGINT/SIGTERM to
    this agent (operator stopping the service) ends the in-progress
    capture within ~0.5s instead of waiting out however long is left in
    the window -- a real bug caught by testing: with a single long
    `wait()`, sending SIGINT mid-capture logged "shutting down" but the
    process kept running for the rest of the window (confirmed via a
    30s-interval test where the process was still alive 10+ seconds
    after SIGINT), which is exactly the kind of thing that makes a
    `systemctl stop` hang or get force-killed by its own timeout."""
    cmd = ["tcpdump", "-i", interface, "-w", out_path, bpf_filter]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except FileNotFoundError:
        logger.error("tcpdump not found on PATH -- install tcpdump (apt install tcpdump / yum install tcpdump)")
        return False

    deadline = time.monotonic() + duration_seconds
    exited_early = False
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            exited_early = True
            break
        if _shutdown_requested:
            logger.info("shutdown requested mid-capture, ending this window early")
            break
        time.sleep(min(SHUTDOWN_POLL_INTERVAL_SECONDS, max(deadline - time.monotonic(), 0)))

    if exited_early:
        stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        if proc.returncode != 0:
            logger.warning("tcpdump exited early (code %s): %s", proc.returncode, stderr.strip())
    else:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=TCPDUMP_SHUTDOWN_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            logger.warning("tcpdump did not exit cleanly after SIGTERM, forcing -- this capture window may be truncated")
            proc.kill()
            proc.wait()

    if not os.path.exists(out_path):
        logger.error("tcpdump produced no output file -- check interface name and capture permissions "
                     "(tcpdump needs CAP_NET_RAW/CAP_NET_ADMIN or root; see agent/README.md)")
        return False
    return True


def post_pcap(api_url: str, api_key: str, pcap_path: str) -> dict | None:
    """POSTs one capture window to the backend with bounded retries.
    Returns the parsed JSON response on success, None if every attempt
    failed (caller logs this window's flows as dropped, per the stated
    v1 no-replay-queue limitation)."""
    url = api_url.rstrip("/") + "/ingest/pcap"
    last_error = None
    for attempt in range(1, MAX_POST_RETRIES + 1):
        try:
            with open(pcap_path, "rb") as f:
                resp = requests.post(
                    url,
                    headers={"X-API-Key": api_key},
                    files={"file": (os.path.basename(pcap_path), f, "application/vnd.tcpdump.pcap")},
                    timeout=30,
                )
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 429:
                # Rate-limited -- the backend's own per-key limit (see
                # core/limiter.py). Back off longer than a transient
                # network error would warrant.
                logger.warning("rate limited by backend (429), backing off")
                time.sleep(POST_RETRY_BACKOFF_SECONDS * attempt * 3)
                continue
            last_error = f"HTTP {resp.status_code}: {resp.text[:300]}"
            logger.warning("ingest attempt %d/%d failed: %s", attempt, MAX_POST_RETRIES, last_error)
        except requests.exceptions.RequestException as e:
            last_error = str(e)
            logger.warning("ingest attempt %d/%d failed: %s", attempt, MAX_POST_RETRIES, last_error)
        if attempt < MAX_POST_RETRIES:
            time.sleep(POST_RETRY_BACKOFF_SECONDS * attempt)
    logger.error("giving up on this capture window after %d attempts (%s) -- its flows are dropped, not queued",
                 MAX_POST_RETRIES, last_error)
    return None


def run(interface: str, api_url: str, api_key: str, interval: int, bpf_filter: str, max_windows: int | None = None):
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    logger.info("starting capture: interface=%s interval=%ss filter=%r api=%s",
                interface, interval, bpf_filter, api_url)

    windows_done = 0
    while not _shutdown_requested:
        if max_windows is not None and windows_done >= max_windows:
            logger.info("reached max_windows=%d, stopping", max_windows)
            break

        with tempfile.TemporaryDirectory() as tmp:
            pcap_path = os.path.join(tmp, "window.pcap")
            ok = capture_window(interface, interval, bpf_filter, pcap_path)
            if not ok:
                # A failed window still counts toward windows_done -- a
                # persistently broken interface (wrong name, permissions)
                # must not spin an unbounded loop ignoring --max-windows,
                # which is exactly what happened before this fix (caught
                # by testing with a nonexistent interface: the agent
                # looped indefinitely and only stopped when killed by an
                # external timeout, never respecting max_windows=1).
                windows_done += 1
                time.sleep(min(interval, 5))
                continue

            size = os.path.getsize(pcap_path)
            if size <= 24:  # just the global pcap header, no packets captured
                logger.debug("empty capture window (no matching traffic), skipping upload")
                windows_done += 1
                continue

            result = post_pcap(api_url, api_key, pcap_path)
            if result is not None:
                logger.info(
                    "window ingested: flows=%s anomalies=%s critical=%s",
                    result.get("ingested"), result.get("anomalies_detected"), result.get("critical"),
                )
            windows_done += 1

    logger.info("agent stopped after %d windows", windows_done)


def main():
    parser = argparse.ArgumentParser(description="Network AI live capture agent")
    parser.add_argument("--interface", required=True, help="network interface to capture on, e.g. eth0")
    parser.add_argument("--api-url", required=True, help="backend base URL, e.g. https://api.yourdomain.com")
    parser.add_argument("--api-key", default=os.environ.get("NETWORK_AI_API_KEY"),
                        help="ingest-scoped API key (or set NETWORK_AI_API_KEY env var)")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_SECONDS,
                        help=f"seconds per capture window (default {DEFAULT_INTERVAL_SECONDS})")
    parser.add_argument("--filter", default=DEFAULT_BPF_FILTER,
                        help=f"BPF capture filter (default {DEFAULT_BPF_FILTER!r})")
    parser.add_argument("--max-windows", type=int, default=None,
                        help="stop after this many windows (mainly for testing; default: run forever)")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not args.api_key:
        logger.error("no API key provided (--api-key or NETWORK_AI_API_KEY)")
        sys.exit(1)

    run(args.interface, args.api_url, args.api_key, args.interval, args.filter, args.max_windows)


if __name__ == "__main__":
    main()
