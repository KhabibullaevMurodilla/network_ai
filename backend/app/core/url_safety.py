"""SSRF guard for tenant-supplied outbound URLs (alert webhooks in
webhooks.py, response-action targets in response_actions.py).

Any URL a tenant admin sets here becomes a server-side request this
backend itself makes (core/webhooks.py, core/response_actions.py) on every
matching anomaly. Without validation, the backend is a confused deputy: an
admin role (or anyone holding a stolen admin session/JWT) can point it at
an internal service, a cloud metadata endpoint (169.254.169.254), or
localhost -- and get the backend to make that request on their behalf,
with no further network access needed. This is a standard, expected check
for any SaaS product that accepts a customer-supplied webhook URL (Stripe,
GitHub and Slack all do some version of this); its absence is exactly the
kind of finding a real security review flags immediately.

Two checks, both required, because one alone is incomplete:
  1. validate_url_or_raise() -- called at webhook/response-action CREATE
     time. Rejects a non-http(s) scheme and a literal private/loopback/
     link-local/reserved IP in the hostname outright. Cheap, synchronous,
     catches the obvious cases immediately with a clear 400 at creation.
  2. resolve_and_check() -- called at DISPATCH time, right before each
     actual outbound request. Re-resolves the hostname and checks the
     resolved IP too. This closes the DNS-rebinding gap check #1 alone
     can't: a hostname that resolved to a public IP at creation time (and
     so passed validation) can be repointed to an internal IP by the time
     dispatch actually happens, since nothing stops the tenant from
     controlling that DNS record. Re-checking at the moment of the real
     request is the only way to close that gap.

Honest scope: this blocks the standard private/loopback/link-local/
multicast/reserved IPv4 and IPv6 ranges (covering AWS/GCP/Azure metadata,
which all live in link-local space). It does not defend against a TOCTOU
race between resolve_and_check's resolution and httpx's own connection a
moment later -- closing that fully needs pinning the resolved IP and
connecting to it directly (bypassing a second DNS lookup), which httpx
doesn't expose cleanly without a custom transport. Noted as a further
hardening step, not silently assumed solved.
"""
from __future__ import annotations
import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable -- fail closed
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local       # covers 169.254.169.254 cloud metadata
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_url_or_raise(url: str) -> None:
    """Synchronous, creation-time check. Raises ValueError with a clear
    reason on rejection. Does not resolve DNS (cheap, no network call) --
    that happens again, for real, at dispatch time via resolve_and_check."""
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValueError(f"Could not parse URL: {e}") from e

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"URL scheme must be http or https, got '{parsed.scheme or '(none)'}'")
    if not parsed.hostname:
        raise ValueError("URL has no hostname")

    # If the hostname IS a literal IP, check it directly -- the common
    # case someone pointing this at an internal address writes it as
    # http://127.0.0.1/... or http://169.254.169.254/..., not a hostname.
    try:
        literal_ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal_ip = None
    if literal_ip is not None and _is_blocked_ip(str(literal_ip)):
        raise ValueError(f"URL resolves to a private/internal/reserved address ({literal_ip}), which is not allowed")

    if parsed.hostname.lower() in ("localhost", "localhost.localdomain"):
        raise ValueError("localhost is not allowed as a webhook/response-action target")


async def resolve_and_check(url: str) -> bool:
    """Dispatch-time check: re-resolves the hostname right now and
    confirms every resolved address is public. Returns True if safe to
    call, False if it should be blocked. Never raises -- a DNS failure is
    treated as unsafe (fail closed), not as "no opinion"."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
        return False

    try:
        literal_ip = ipaddress.ip_address(parsed.hostname)
        addrs = [str(literal_ip)]
    except ValueError:
        try:
            loop = asyncio.get_event_loop()
            infos = await loop.getaddrinfo(parsed.hostname, None)
            addrs = {info[4][0] for info in infos}
        except (socket.gaierror, OSError):
            return False  # couldn't resolve -- fail closed, don't send

    if not addrs:
        return False
    return not any(_is_blocked_ip(a) for a in addrs)
