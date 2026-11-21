import os

class Settings:
    SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
    SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET", "")
    STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
    STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    # Plan -> Stripe Price ID mapping (fill in once Stripe products are created)
    STRIPE_PRICE_IDS = {
        "starter": os.environ.get("STRIPE_PRICE_STARTER", ""),
        "pro": os.environ.get("STRIPE_PRICE_PRO", ""),
    }

    # Comma-separated list of exact origins allowed to call this API, e.g.
    # "https://app.yourdomain.com,https://yourdomain.netlify.app". No wildcard
    # default on purpose -- an unset value fails closed (empty allow-list)
    # rather than silently allowing every origin, which is what "*" does.
    ALLOWED_ORIGINS = [
        o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()
    ]

    # Ingestion rate limit, per API key. Generous enough for a real telemetry
    # agent batching flows, tight enough to blunt a leaked-key abuse case.
    INGEST_RATE_LIMIT = os.environ.get("INGEST_RATE_LIMIT", "120/minute")

    # Optional: when set, the real-time event bus (core/stream.py) uses
    # Redis pub/sub instead of in-process queues, which is what lets SSE
    # events reach a dashboard connected to a different backend instance
    # than the one that handled ingestion. Unset by default -- the engine
    # falls back to the in-memory bus, which is fine for a single instance
    # and needs no extra infrastructure to run.
    REDIS_URL = os.environ.get("REDIS_URL", "")

    # Optional: outbound SMTP for the 'email' alert-delivery channel type
    # (core/webhooks.py). Unset by default -- an email-channel webhook
    # configured with no SMTP_HOST set is a known, logged no-op rather than
    # a crash, same posture as REDIS_URL being optional above.
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM = os.environ.get("SMTP_FROM", "alerts@network-ai.example")
    SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() != "false"

    # Fixed tenant_id of the seeded read-only public demo tenant (v6.3). If
    # unset, the /demo router returns 404 for every route rather than
    # guessing or exposing the first tenant it finds.
    DEMO_TENANT_ID = os.environ.get("DEMO_TENANT_ID", "")

settings = Settings()
