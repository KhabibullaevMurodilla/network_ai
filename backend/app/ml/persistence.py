"""Cross-instance detector-state persistence.

engine.py's own docstring is explicit about what was NOT yet solved as of
v5: DetectorRegistry's per-tenant model state (fitted ECOD/IForest/LOF,
the HalfSpaceTrees online model, adaptive thresholds, entity burst
windows, per-entity Welford baselines) lived only in one process's memory.
That's fine for a single backend instance; it breaks the moment you run
more than one (a load balancer sending a tenant's flows to whichever
instance is least busy would have each instance scoring against a
different, incomplete view of that tenant's history).

What this module actually does, honestly stated:

  - Periodic checkpointing: every CHECKPOINT_EVERY_FLOWS flows scored, a
    tenant's full detector state is pickled and written to Redis with a
    TTL. This is cross-instance *recovery*, not live replication -- it's
    what lets a second instance (or a restarted first one) pick up
    reasonably fresh state instead of cold-bootstrapping on synthetic
    data again.
  - On a cache miss (a tenant this process hasn't seen yet), the registry
    checks Redis for a recent checkpoint before falling back to a fresh
    synthetic bootstrap. A fleet of N instances therefore converges on
    roughly-shared state within one checkpoint interval of each other,
    not instantly.

What this does NOT do, and why that's the honest scope rather than a gap
I'm hiding: it does not make concurrent instances see exactly the same
state on every single flow. True per-flow consistency for a stateful
streaming model across concurrent writers needs either (a) a single
writer per tenant at any given time, or (b) a distributed consensus
protocol over the model state itself -- both real engineering efforts
well beyond "add Redis". The standard, proven way production systems
solve this for exactly this class of problem (keyed streaming state --
see Flink, Kafka Streams) is sticky routing: route all of one tenant's
traffic to the same instance via consistent hashing on tenant_id at the
load balancer, so there is only ever one active writer for that tenant's
state at a time, with the Redis checkpoint as the failover/recovery path
if that instance dies or is rebalanced. DEPLOY.md documents how to
configure that at the ingress. Claiming anything stronger than that here
would be describing a distributed-systems feature this codebase doesn't
actually have.
"""
from __future__ import annotations
import logging
import pickle

from .engine import TenantDetector
from ..core.config import settings

logger = logging.getLogger(__name__)

CHECKPOINT_KEY_PREFIX = "network_ai:detector_checkpoint:"
CHECKPOINT_TTL_SECONDS = 7 * 24 * 3600  # a checkpoint older than a week is
# more likely to mislead (stale thresholds/baselines) than help -- better
# to cold-bootstrap fresh than warm-start from a week-stale model.

_redis_client = None
_redis_init_failed = False


def _get_redis():
    """Lazy singleton, mirroring core/stream.py's own pattern. Returns None
    (never raises) when Redis isn't configured or isn't reachable, so every
    caller in this module degrades to "no persistence" rather than crashing
    the request that triggered it."""
    global _redis_client, _redis_init_failed
    if _redis_client is not None:
        return _redis_client
    if _redis_init_failed or not settings.REDIS_URL:
        return None
    try:
        import redis.asyncio as redis
        _redis_client = redis.from_url(settings.REDIS_URL, decode_responses=False)
        return _redis_client
    except Exception:
        logger.warning("Redis unavailable for detector-state persistence; "
                        "falling back to in-process-only state.", exc_info=True)
        _redis_init_failed = True
        return None


def _key(tenant_id: str) -> str:
    return f"{CHECKPOINT_KEY_PREFIX}{tenant_id}"


async def save_checkpoint(detector: TenantDetector) -> bool:
    """Fire-and-forget from the caller's perspective: a failed checkpoint
    degrades cross-instance freshness, never the ingestion request that
    triggered it. Returns whether the write actually happened, for tests."""
    client = _get_redis()
    if client is None:
        return False
    try:
        blob = pickle.dumps(detector, protocol=pickle.HIGHEST_PROTOCOL)
        await client.set(_key(detector.tenant_id), blob, ex=CHECKPOINT_TTL_SECONDS)
        return True
    except Exception:
        logger.warning("Checkpoint save failed for tenant %s", detector.tenant_id, exc_info=True)
        return False


async def load_checkpoint(tenant_id: str) -> TenantDetector | None:
    client = _get_redis()
    if client is None:
        return None
    try:
        blob = await client.get(_key(tenant_id))
        if blob is None:
            return None
        detector = pickle.loads(blob)
        if not isinstance(detector, TenantDetector) or detector.tenant_id != tenant_id:
            # Defensive: a corrupt or cross-tenant blob must never be used
            # silently -- treat it as a miss and let a fresh bootstrap happen.
            logger.warning("Checkpoint for tenant %s failed integrity check; discarding.", tenant_id)
            return None
        return detector
    except Exception:
        logger.warning("Checkpoint load failed for tenant %s", tenant_id, exc_info=True)
        return None
