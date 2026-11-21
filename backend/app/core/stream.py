"""Live event push to open dashboards via Server-Sent Events (SSE).

Why SSE over a full WebSocket: it's one-directional (server -> browser,
which is all a dashboard needs), rides plain HTTP so it passes through
ordinary proxies/load balancers without special config, and the browser
EventSource API reconnects automatically on its own -- less moving parts
for the same practical result (sub-second push instead of polling).

Two bus implementations, selected automatically by whether REDIS_URL is
set:

  - InMemoryEventBus: an asyncio.Queue per subscriber, all in this
    process. Zero extra infrastructure, but only reaches subscribers
    connected to the SAME backend instance that received the ingest call
    -- flagged honestly in earlier versions as the scale limitation that
    blocks running more than one backend instance behind a load balancer.
  - RedisEventBus (v5): publishes to a Redis pub/sub channel per tenant
    instead of an in-process queue; each subscriber runs its own
    redis.asyncio PubSub listener. This is what actually closes the gap --
    an event published by the instance that handled the ingest call
    reaches a dashboard connected to a *different* instance, because both
    are listening to the same Redis channel rather than holding separate
    in-memory state. Verified against a real local Redis instance (see the
    test in this session), not just mocked.

Either way, publish is fire-and-forget from ingest.py's perspective and a
slow/dead subscriber can't block ingestion: in-memory queues are bounded
and drop their oldest entry rather than backing up the publisher; Redis
pub/sub has no persistent backlog at all, so a disconnected subscriber
just misses messages sent while it was gone (acceptable here -- the
dashboard's initial REST fetch already has the full history; SSE is only
for what happens after the page is open).
"""
from __future__ import annotations
import asyncio
import json
import logging
from abc import ABC, abstractmethod
from collections import defaultdict

from .config import settings

logger = logging.getLogger(__name__)

MAX_QUEUE_PER_SUBSCRIBER = 50
REDIS_CHANNEL_PREFIX = "network-ai:tenant-events:"


def _json_safe(event: dict) -> dict:
    """Anomaly rows can carry numpy scalars / None in odd spots -- make sure
    what we hand to json.dumps for the SSE wire format is plain Python."""
    safe = {}
    for k, v in event.items():
        if hasattr(v, "item"):  # numpy scalar
            safe[k] = v.item()
        else:
            safe[k] = v
    return safe


class EventBus(ABC):
    @abstractmethod
    async def publish(self, tenant_id: str, event: dict): ...

    @abstractmethod
    def subscribe(self, tenant_id: str): ...  # returns an async context manager yielding an async iterator of events


class InMemoryEventBus(EventBus):
    """Single-process fallback -- used automatically when REDIS_URL isn't
    configured, so local dev and this project's default deployment still
    get real-time push with zero extra infrastructure."""

    def __init__(self):
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)

    async def publish(self, tenant_id: str, event: dict):
        for q in list(self._subscribers.get(tenant_id, ())):
            if q.full():
                try:
                    q.get_nowait()  # drop oldest so a slow tab doesn't block ingestion
                except asyncio.QueueEmpty:
                    pass
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    def subscribe(self, tenant_id: str):
        return _InMemorySubscription(self, tenant_id)


class _InMemorySubscription:
    def __init__(self, bus: InMemoryEventBus, tenant_id: str):
        self.bus = bus
        self.tenant_id = tenant_id
        self.q: asyncio.Queue = asyncio.Queue(maxsize=MAX_QUEUE_PER_SUBSCRIBER)

    async def __aenter__(self):
        self.bus._subscribers[self.tenant_id].add(self.q)
        return self._events()

    async def __aexit__(self, *exc):
        self.bus._subscribers[self.tenant_id].discard(self.q)
        if not self.bus._subscribers[self.tenant_id]:
            self.bus._subscribers.pop(self.tenant_id, None)

    async def _events(self):
        while True:
            try:
                yield await asyncio.wait_for(self.q.get(), timeout=15.0)
            except asyncio.TimeoutError:
                yield None  # heartbeat


class RedisEventBus(EventBus):
    """Distributed event bus: publishes to a Redis pub/sub channel keyed by
    tenant, so any backend instance's subscriber receives events published
    by any other instance -- the piece that actually enables running more
    than one backend process behind a load balancer."""

    def __init__(self, redis_url: str):
        import redis.asyncio as redis
        self._redis = redis.from_url(redis_url, decode_responses=True)

    def _channel(self, tenant_id: str) -> str:
        return f"{REDIS_CHANNEL_PREFIX}{tenant_id}"

    async def publish(self, tenant_id: str, event: dict):
        try:
            await self._redis.publish(self._channel(tenant_id), json.dumps(event))
        except Exception:
            logger.warning("Redis publish failed for tenant %s", tenant_id, exc_info=True)

    def subscribe(self, tenant_id: str):
        return _RedisSubscription(self._redis, self._channel(tenant_id))


class _RedisSubscription:
    def __init__(self, redis_client, channel: str):
        self._redis = redis_client
        self._channel = channel
        self._pubsub = None

    async def __aenter__(self):
        self._pubsub = self._redis.pubsub()
        await self._pubsub.subscribe(self._channel)
        return self._events()

    async def __aexit__(self, *exc):
        if self._pubsub is not None:
            await self._pubsub.unsubscribe(self._channel)
            await self._pubsub.aclose()

    async def _events(self):
        while True:
            message = await self._pubsub.get_message(ignore_subscribe_messages=True, timeout=15.0)
            if message is None:
                yield None  # heartbeat
                continue
            try:
                yield json.loads(message["data"])
            except (KeyError, TypeError, json.JSONDecodeError):
                continue


def _build_bus() -> EventBus:
    """redis.from_url() only parses the URL and builds a lazy client -- it
    doesn't actually connect yet, so a malformed URL is caught here (falls
    back to in-memory) but an unreachable Redis host is NOT: that only
    surfaces when publish/subscribe is actually attempted. publish() already
    swallows connection errors (ingestion must never break on a Redis
    outage, same reasoning as the webhook/response-action dispatch paths);
    subscribe() does not, so an SSE connection attempt will fail loudly if
    REDIS_URL is set but unreachable -- that's a single request failing
    (the browser's EventSource retries automatically), not a server crash."""
    if settings.REDIS_URL:
        try:
            return RedisEventBus(settings.REDIS_URL)
        except Exception:
            logger.warning("Could not initialize Redis event bus, falling back to in-memory", exc_info=True)
    return InMemoryEventBus()


bus = _build_bus()


async def publish_event(tenant_id: str, event: dict):
    await bus.publish(tenant_id, _json_safe(event))


async def event_stream(tenant_id: str):
    """Async generator yielding SSE-formatted frames for one subscriber,
    against whichever bus implementation is active. A heartbeat comment
    line every 15s keeps intermediary proxies from timing out an idle
    connection."""
    async with bus.subscribe(tenant_id) as events:
        async for event in events:
            if event is None:
                yield ": heartbeat\n\n"
            else:
                yield f"data: {json.dumps(event)}\n\n"
