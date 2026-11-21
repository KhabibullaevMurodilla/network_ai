"""Tests for the capture agent's own logic (not tcpdump itself -- that's
exercised directly in README.md's stated end-to-end verification, which
needs real root/capability access this test environment may not have).
These pin the two real bugs caught during manual testing: failed windows
not counting toward --max-windows, and retry/backoff behavior on a
network failure."""
import os
import sys
import time
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import network_ai_agent as agent


def test_failed_capture_window_still_counts_toward_max_windows():
    """Regression test for the bug where a persistently failing capture
    (bad interface, permissions) spun forever, ignoring --max-windows,
    because the window counter only incremented on success."""
    with patch.object(agent, "capture_window", return_value=False):
        agent._shutdown_requested = False
        start = time.monotonic()
        agent.run("fake-iface", "http://127.0.0.1:1", "key", interval=1, bpf_filter="ip", max_windows=2)
        elapsed = time.monotonic() - start
    # Two failed windows, each sleeping min(interval, 5) = 1s -> ~2s, not
    # an unbounded loop.
    assert elapsed < 10, f"expected the loop to stop after 2 failed windows, ran for {elapsed:.1f}s"


def test_post_pcap_retries_then_gives_up_gracefully(tmp_path):
    """A persistent network failure must retry MAX_POST_RETRIES times and
    then return None (caller logs and drops the window) -- never raise."""
    pcap_file = tmp_path / "window.pcap"
    pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)  # minimal fake pcap header

    call_count = {"n": 0}

    def fake_post(*args, **kwargs):
        call_count["n"] += 1
        raise agent.requests.exceptions.ConnectionError("simulated failure")

    with patch.object(agent.requests, "post", side_effect=fake_post), \
         patch.object(agent.time, "sleep"):  # don't actually wait during the test
        result = agent.post_pcap("http://127.0.0.1:1", "key", str(pcap_file))

    assert result is None
    assert call_count["n"] == agent.MAX_POST_RETRIES


def test_post_pcap_succeeds_on_first_try(tmp_path):
    pcap_file = tmp_path / "window.pcap"
    pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {"ingested": 5, "anomalies_detected": 1, "critical": 0}

    with patch.object(agent.requests, "post", return_value=fake_response) as mock_post:
        result = agent.post_pcap("http://127.0.0.1:8000", "key", str(pcap_file))

    assert result == {"ingested": 5, "anomalies_detected": 1, "critical": 0}
    assert mock_post.call_count == 1
    # Confirms the API key travels as X-API-Key, matching backend's
    # require_ingest_key dependency (core/auth.py).
    assert mock_post.call_args.kwargs["headers"]["X-API-Key"] == "key"


def test_post_pcap_backs_off_longer_on_rate_limit(tmp_path):
    pcap_file = tmp_path / "window.pcap"
    pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    rate_limited = MagicMock(status_code=429, text="rate limited")
    ok = MagicMock(status_code=200)
    ok.json.return_value = {"ingested": 1}

    sleep_calls = []
    with patch.object(agent.requests, "post", side_effect=[rate_limited, ok]), \
         patch.object(agent.time, "sleep", side_effect=lambda s: sleep_calls.append(s)):
        result = agent.post_pcap("http://127.0.0.1:8000", "key", str(pcap_file))

    assert result == {"ingested": 1}
    assert sleep_calls, "expected a backoff sleep after the 429 before retrying"


def test_shutdown_signal_sets_flag():
    agent._shutdown_requested = False
    agent._handle_signal(2, None)
    assert agent._shutdown_requested is True
    agent._shutdown_requested = False  # reset for other tests
