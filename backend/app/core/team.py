"""Team invites, via Supabase Auth's own admin invite API -- not a
hand-rolled email/token system. `get_db()` already returns a service-role
client (see core/db.py), which is what the Supabase Auth admin API
requires; we never send or store an invite token ourselves, Supabase does
that and emails the person a real "set your password" link.

Deliberately NOT a Postgres trigger on auth.users: this codebase already
does every other piece of cross-table logic (incident correlation,
severity escalation, webhook dispatch) in application code, not database
triggers, so a new user's profiles row is created here, in the same
request that calls the Auth API, right after we get back the new user's
id -- same style as the rest of the backend, and a lot easier to test
without a real Postgres instance to attach a trigger to.

This module exists mainly so the one real network call (Supabase's own
invite-by-email) is isolated behind a single function, the same pattern
core/webhooks.py already uses for its SMTP send -- tests patch
invite_user() directly rather than mocking the whole supabase-py client,
and this sandbox genuinely never sends an email (no real Supabase project
exists here), which is disclosed in the README rather than implied by a
passing test."""
from .db import get_db


class InviteError(Exception):
    """Raised for a real, actionable problem with the invite itself (e.g.
    that email already has a pending or active account) -- callers turn
    this into a clean 409, not a generic 500."""


def invite_user(email: str) -> str:
    """Creates the Supabase Auth user and returns its id. Supabase sends
    the actual invite email; we never see or store a token. Raises
    InviteError on a duplicate email (Supabase's admin API error for this
    doesn't have a single stable shape across client versions, so this
    deliberately catches broadly and re-raises a clean, specific error
    rather than leaking whatever the underlying exception's message
    happens to be)."""
    client = get_db()
    try:
        result = client.auth.admin.invite_user_by_email(email)
    except Exception as e:
        raise InviteError(f"Could not invite {email}: {e}") from e
    user = getattr(result, "user", None) or result
    user_id = getattr(user, "id", None) or (user.get("id") if isinstance(user, dict) else None)
    if not user_id:
        raise InviteError(f"Invite for {email} did not return a user id")
    return user_id
