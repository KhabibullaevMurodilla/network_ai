"""Real SSRF-guard tests. This module exists because webhooks.py and
response_actions.py let a tenant admin supply a URL the backend itself
later makes a server-side request to -- without validation, that's a
confused-deputy SSRF primitive reachable by anyone holding an admin
session. Covers both halves: creation-time rejection of the obvious cases,
and dispatch-time re-resolution that catches DNS rebinding."""
import pytest

from app.core.url_safety import validate_url_or_raise, resolve_and_check


# --- validate_url_or_raise (creation-time, synchronous) --------------------

@pytest.mark.parametrize("url", [
    "http://127.0.0.1/hook",
    "https://127.0.0.1:8080/hook",
    "http://localhost/hook",
    "http://localhost.localdomain/hook",
    "http://169.254.169.254/latest/meta-data/",          # AWS/GCP/Azure metadata
    "http://10.0.0.5/internal",
    "http://172.16.0.1/internal",
    "http://192.168.1.1/internal",
    "http://[::1]/hook",                                   # IPv6 loopback
    "http://0.0.0.0/hook",
])
def test_rejects_internal_and_metadata_targets(url):
    with pytest.raises(ValueError):
        validate_url_or_raise(url)


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.com/",
    "gopher://example.com/",
    "javascript:alert(1)",
    "",
    "not-a-url-at-all",
])
def test_rejects_non_http_schemes_and_garbage(url):
    with pytest.raises(ValueError):
        validate_url_or_raise(url)


@pytest.mark.parametrize("url", [
    "https://example.com/webhook",
    "https://hooks.slack.com/services/XXX/YYY/ZZZ",
    "http://example.com:8443/hook",
])
def test_accepts_plausible_public_targets(url):
    validate_url_or_raise(url)  # must not raise


# --- resolve_and_check (dispatch-time, async, re-resolves DNS) -------------

@pytest.mark.asyncio
async def test_resolve_and_check_blocks_literal_internal_ip():
    assert await resolve_and_check("http://127.0.0.1/hook") is False
    assert await resolve_and_check("http://169.254.169.254/latest/meta-data/") is False


@pytest.mark.asyncio
async def test_resolve_and_check_blocks_unresolvable_host():
    """A hostname that fails to resolve must be treated as unsafe (fail
    closed), never as 'no opinion, send it anyway'."""
    assert await resolve_and_check("http://this-definitely-does-not-resolve.invalid/hook") is False


@pytest.mark.asyncio
async def test_resolve_and_check_rejects_non_http_scheme():
    assert await resolve_and_check("file:///etc/passwd") is False
