"""Shared rate limiter instance. Keyed by API key (not just IP, which is
useless behind a shared NAT/proxy and doesn't scope the limit to the actual
credential being abused).

Real finding from adversarial review: every /ingest/* route was rate
limited this way, but every JWT-authenticated dashboard/admin route
(api-key creation, billing checkout, privacy export/erase, webhook and
response-action CRUD) had NO rate limiting at all -- a valid admin session
(or one JWT stolen via XSS/leak/phishing) could otherwise hammer
POST /tenants/api-keys to mint unlimited credentials, spam Stripe via
/billing/create-checkout-session, or just hammer the expensive
/privacy/export query with no limit whatsoever. _user_key_func below
closes that: it extracts the JWT's own 'sub' claim (NOT verified here --
this is a rate-limit bucket key, not an auth decision; an attacker
crafting a bogus token just falls back to IP-based limiting, no worse than
having no per-user key at all) so each authenticated user gets their own
bucket, independent of IP (which is often shared/NATed in a real office)."""
from slowapi import Limiter
from fastapi import Request
import jwt as _pyjwt


def _key_func(request: Request) -> str:
    return request.headers.get("x-api-key", request.client.host if request.client else "unknown")


def _user_key_func(request: Request) -> str:
    """For JWT-authenticated routes: buckets by the token's own 'sub'
    claim when present, falling back to client IP. Deliberately does NOT
    verify the signature -- that's require_user's job, which still runs
    as a separate dependency and will reject a forged token regardless of
    what bucket this limiter put it in."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth.removeprefix("Bearer ").strip()
        try:
            payload = _pyjwt.decode(token, options={"verify_signature": False})
            sub = payload.get("sub")
            if isinstance(sub, str) and sub:
                return f"user:{sub}"
        except _pyjwt.PyJWTError:
            pass
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=_key_func)

# Convenience: authenticated-user routes pass this to @limiter.limit(...,
# key_func=user_key_func) rather than each redefining the same override --
# a single Limiter instance (matching app.state.limiter in main.py), just
# bucketed differently per route. Two separate Limiter() instances would
# work too, but slowapi's rate-limit-exceeded handler reads
# request.app.state.limiter specifically, so keeping one real Limiter and
# varying key_func per-route avoids relying on undocumented behavior for
# how a second instance's exceptions get formatted.
user_key_func = _user_key_func
