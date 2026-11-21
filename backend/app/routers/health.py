"""Liveness vs. readiness, the distinction a real orchestrator (k8s, ECS,
a load balancer health check) actually needs:

  - GET /health        liveness: "is this process up and able to answer
                        HTTP at all". Always 200 if the process is running
                        -- it does NOT touch Supabase or Redis, on purpose,
                        because a liveness probe that depends on a
                        downstream service causes exactly the failure mode
                        it's meant to prevent (the orchestrator kills and
                        restarts healthy instances because a database had
                        a blip, which doesn't fix the database and now
                        there's also no backend).
  - GET /health/ready   readiness: "is this instance actually able to do
                        its job right now" -- pings Supabase and Redis
                        (if configured) with short timeouts and reports
                        per-dependency status. This is what should gate
                        whether a load balancer sends traffic to this
                        instance, and it's allowed to fail independently
                        of liveness.
"""
from __future__ import annotations
import asyncio
import logging
import time

from fastapi import APIRouter, Response

from ..core.config import settings
from ..core.db import get_db

router = APIRouter(tags=["health"])
logger = logging.getLogger("network_ai.health")

DEPENDENCY_TIMEOUT_SECONDS = 2.0


@router.get("/health")
async def health():
    return {"status": "ok"}


async def _check_supabase() -> dict:
    """/health/ready is unauthenticated by design (an orchestrator's health
    probe doesn't carry a session token), which means its response is
    public. A raw exception string from a DB/cache client can embed a
    connection string, host, or credential fragment -- so the full detail
    is logged server-side (where an operator with log access can act on
    it) and never put in the HTTP response, which gets only a sanitized
    status and a timing number."""
    start = time.monotonic()
    try:
        db = get_db()
        # Cheapest possible real round-trip: a 0-row select, not a full
        # table scan. Proves the service-role credential and connectivity
        # actually work, not just that the client object constructed.
        await asyncio.to_thread(
            lambda: db.table("tenants").select("id").limit(1).execute()
        )
        return {"status": "ok", "latency_ms": round((time.monotonic() - start) * 1000, 1)}
    except Exception:
        logger.warning("readiness check: supabase unreachable", exc_info=True)
        return {"status": "error", "latency_ms": round((time.monotonic() - start) * 1000, 1)}


async def _check_redis() -> dict | None:
    if not settings.REDIS_URL:
        return None  # not configured -- not a failure, just not applicable
    start = time.monotonic()
    try:
        import redis.asyncio as redis
        client = redis.from_url(settings.REDIS_URL, socket_connect_timeout=DEPENDENCY_TIMEOUT_SECONDS)
        await client.ping()
        await client.aclose()
        return {"status": "ok", "latency_ms": round((time.monotonic() - start) * 1000, 1)}
    except Exception:
        logger.warning("readiness check: redis unreachable", exc_info=True)
        return {"status": "error", "latency_ms": round((time.monotonic() - start) * 1000, 1)}


@router.get("/health/ready")
async def readiness(response: Response):
    try:
        supabase_check, redis_check = await asyncio.wait_for(
            asyncio.gather(_check_supabase(), _check_redis()),
            timeout=DEPENDENCY_TIMEOUT_SECONDS + 1,
        )
    except asyncio.TimeoutError:
        response.status_code = 503
        return {"status": "not_ready", "detail": "dependency check timed out"}

    checks = {"supabase": supabase_check}
    if redis_check is not None:
        checks["redis"] = redis_check

    # Supabase is load-bearing (nothing works without it); Redis is
    # optional infrastructure (see core/stream.py, ml/persistence.py) that
    # degrades gracefully to in-process-only behavior when absent, so a
    # Redis failure alone does not fail readiness -- only make the
    # dashboard/checkpoint features it backs less effective.
    ready = checks["supabase"]["status"] == "ok"
    # 503 on not-ready is what makes this usable by a real load
    # balancer/orchestrator health check -- a 200 with a "not_ready" string
    # buried in the body is invisible to anything that only looks at the
    # status code, which is how most of them are configured.
    response.status_code = 200 if ready else 503
    return {"status": "ready" if ready else "not_ready", "checks": checks}
