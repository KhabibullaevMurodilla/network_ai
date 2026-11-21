"""Supabase client wrapper. Uses the service-role key (server-side only,
never exposed to the frontend) so the backend can write telemetry/anomaly
rows regardless of RLS, while the dashboard reads via the user's own
authenticated session and RLS.
"""
from supabase import create_client, Client
from .config import settings

_client: Client | None = None

def get_db() -> Client:
    global _client
    if _client is None:
        if not settings.SUPABASE_URL or not settings.SUPABASE_SERVICE_ROLE_KEY:
            raise RuntimeError(
                "SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY not set. "
                "Create a Supabase project, run supabase/schema.sql, and set these env vars."
            )
        _client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)
    return _client
