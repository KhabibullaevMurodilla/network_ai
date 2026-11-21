"""Two auth paths:
  1. API-key auth — used by a customer's telemetry agent POSTing flow data.
     Key is sent as `X-API-Key`; we look up its hash in api_keys to find
     tenant_id and enforce its scope (ingest / read / admin).
  2. Supabase JWT auth — used by the dashboard (logged-in user), verified
     against SUPABASE_JWT_SECRET (HS256) or the project's JWKS (ES256/RS256); tenant_id comes from the profiles table.
"""
import hashlib
import jwt
from fastapi import Header, HTTPException, Depends
from .config import settings
from .db import get_db


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def _lookup_api_key(x_api_key: str) -> dict:
    db = get_db()
    key_hash = hash_key(x_api_key)
    res = (
        db.table("api_keys")
        .select("id, tenant_id, scope, revoked_at")
        .eq("key_hash", key_hash)
        .limit(1)
        .execute()
    )
    if not res.data or res.data[0]["revoked_at"] is not None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    row = res.data[0]
    # best-effort last-used stamp; failure here must not block the request
    try:
        db.table("api_keys").update({"last_used_at": "now()"}).eq("id", row["id"]).execute()
    except Exception:
        pass
    return row


async def require_api_key(x_api_key: str = Header(...)) -> str:
    """Returns tenant_id for any valid, non-revoked API key (scope-agnostic).
    Use require_ingest_key / require_read_key where the route needs a
    specific scope enforced."""
    row = await _lookup_api_key(x_api_key)
    return row["tenant_id"]


async def require_ingest_key(x_api_key: str = Header(...)) -> dict:
    row = await _lookup_api_key(x_api_key)
    if row["scope"] not in ("ingest", "admin"):
        raise HTTPException(status_code=403, detail="This key is not scoped for ingestion")
    return row


_JWKS_ALGS = ("ES256", "RS256")
_jwks_client = None


def _get_jwks_client():
    """Lazily-built client for the project's public signing keys (cached by
    PyJWT). Newer Supabase projects sign user tokens with an asymmetric key
    (ES256/RS256) instead of the legacy shared HS256 'JWT secret'."""
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = jwt.PyJWKClient(
            settings.SUPABASE_URL.rstrip("/") + "/auth/v1/.well-known/jwks.json", cache_keys=True,
        )
    return _jwks_client


def _decode_supabase_jwt(token: str) -> dict:
    """Pick the verification path from the token's *header* alg, but only
    among a fixed allow-list -- never 'none', and an HS256 token is only ever
    checked against the shared secret (so a token can't pick a public key
    and trick us into HMAC-verifying with it)."""
    alg = jwt.get_unverified_header(token).get("alg")
    opts = {"require": ["exp", "sub"]}
    if alg == "HS256":
        return jwt.decode(token, settings.SUPABASE_JWT_SECRET, algorithms=["HS256"],
                          audience="authenticated", options=opts)
    if alg in _JWKS_ALGS:
        key = _get_jwks_client().get_signing_key_from_jwt(token).key
        return jwt.decode(token, key, algorithms=list(_JWKS_ALGS),
                          audience="authenticated", options=opts)
    raise jwt.InvalidAlgorithmError(f"Unsupported token algorithm: {alg}")


async def _verify_jwt(token: str) -> dict:
    """Shared by both the header-based dependency below and the SSE stream
    route, which can't set custom headers (EventSource doesn't support
    them) and so receives its token as a query parameter instead."""
    try:
        payload = _decode_supabase_jwt(token)
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    # Defense in depth beyond the `require` option above: a validly-signed
    # token with an empty/non-string "sub" must still fail cleanly as 401,
    # not flow into a DB lookup with a nonsense value or crash elsewhere.
    user_id = payload.get("sub")
    if not isinstance(user_id, str) or not user_id:
        raise HTTPException(status_code=401, detail="Invalid token: missing or empty sub claim")

    db = get_db()
    res = db.table("profiles").select("tenant_id, role, focus").eq("id", user_id).limit(1).execute()
    if not res.data:
        raise HTTPException(status_code=403, detail="No profile/tenant for this user")
    # focus is carried for display/adaptation only -- never consulted by
    # require_role or any permission check (see routers/team.py).
    return {
        "user_id": user_id, "tenant_id": res.data[0]["tenant_id"],
        "role": res.data[0]["role"], "focus": res.data[0].get("focus"),
    }


async def require_user(authorization: str = Header(...)) -> dict:
    """Returns {"user_id": ..., "tenant_id": ..., "role": ...} for a valid
    Supabase session JWT (sent as `Authorization: Bearer <token>`)."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    return await _verify_jwt(token)


async def require_user_from_query_token(token: str) -> dict:
    """Same verification as require_user, for the one route (the SSE event
    stream) that can't send an Authorization header."""
    return await _verify_jwt(token)


# Role hierarchy for enterprise-grade access control: owner > admin > analyst
# > viewer. Each role's allowed actions are a strict superset of the one
# below it, enforced via require_role(...) rather than scattered string
# checks, so the ranking lives in exactly one place.
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2, "owner": 3}


def require_role(minimum: str):
    """FastAPI dependency factory: require_role("admin") accepts admin or
    owner, rejects analyst/viewer. Replaces the old binary admin/member
    check with the four-tier model enterprise buyers expect (an analyst can
    triage alerts but not export/erase tenant data or manage billing; only
    owner can manage other owners)."""
    async def _dep(user: dict = Depends(require_user)) -> dict:
        if ROLE_RANK.get(user["role"], -1) < ROLE_RANK.get(minimum, 99):
            raise HTTPException(status_code=403, detail=f"This action requires the {minimum} role or higher")
        return user
    return _dep


# Back-compat alias: existing routes depend on require_admin by name.
require_admin = require_role("admin")
require_owner = require_role("owner")
require_analyst = require_role("analyst")
