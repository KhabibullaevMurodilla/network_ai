# Enterprise readiness (v4)

What changed to make this credible to an enterprise/OT security buyer, and
what's genuinely still configuration rather than code.

## Role-based access control

Replaced the earlier binary admin/viewer split with a four-tier model,
enforced server-side on every route (`require_role(...)` in
`backend/app/core/auth.py`), not just hidden in the UI:

| Role    | Can do |
|---------|--------|
| viewer  | Read dashboard, entities, trends, audit log |
| analyst | + triage alerts (new → acknowledged → resolved) |
| admin   | + manage API keys & webhooks, export/erase tenant data |
| owner   | + manage billing, manage other owners |

This maps onto how a real SOC team splits responsibility: analysts
triaging alerts all day shouldn't also be able to export or erase the
tenant's entire dataset; that stays admin+. Billing is owner-only so a
day-to-day security admin can't accidentally (or maliciously) change what
the org is paying for.

## Single sign-on (SSO/SAML)

**What's real:** the backend's auth already runs entirely on Supabase Auth
JWTs (`core/auth.py`), so nothing in this codebase hardcodes
email/password as the only login path — any identity provider Supabase
Auth can issue a session for works here unchanged.

**What's configuration, not code, and genuinely needs doing before a
customer can use it:** Supabase Auth supports SAML 2.0 SSO as a paid add-on
on Supabase's own Pro/Enterprise plans. Turning it on for a customer is:
1. Enable SSO in the Supabase project's Auth settings.
2. Register the customer's IdP (Okta, Azure AD, Google Workspace, etc.) —
   this needs their IdP metadata XML and is done per-customer, since SSO is
   inherently tied to one organization's identity provider.
3. Map the IdP's group/role claims to this app's `profiles.role` on first
   login (a small `on_auth_user_created` trigger or Edge Function — not yet
   written, flagged here as the next concrete step).

Said plainly: SSO isn't "built" in the sense of shipped, tested code — it's
a real, supported path that needs one customer's IdP and a Supabase
Enterprise-tier setting to actually turn on. Don't represent it as done
until that mapping function exists and has been tested against a real IdP.

## SOC2-style control mapping

Not a certification — no audit has happened — but mapped against the
Trust Services Criteria an auditor would ask about, so it's clear what
already has a real control and what doesn't yet:

| Criterion | Control | Status |
|---|---|---|
| Logical access | API keys scoped least-privilege, 4-tier RBAC, JWT session auth | Implemented |
| Change tracking | Append-only audit log, insert-only for tenant admins | Implemented |
| Data isolation | Postgres RLS on every tenant-scoped table | Implemented |
| Encryption in transit | TLS everywhere (Supabase + HTTPS deploy targets) | Implemented (platform-level) |
| Encryption at rest | Supabase default at-rest encryption | Implemented (platform-level) |
| Data minimization | Optional src/dst IP, configurable retention window | Implemented |
| Retention enforcement | `purge_expired_telemetry()` | Written, **not yet scheduled** — needs pg_cron or external cron |
| Availability monitoring | — | **Not built** — no uptime monitoring/alerting on the backend itself yet |
| Incident response process | — | **Not written** — no documented IR runbook yet |
| Vendor/sub-processor list | Supabase, Stripe, (webhook receivers the customer configures) | Documented here, not yet a formal DPA-ready doc |
| Penetration testing | — | **Not done** |
| Backup/disaster recovery | Supabase automated backups (platform default) | Partial — no tested restore runbook for this app specifically |

Treat the "Not built" / "Not done" rows as the real backlog before anyone
represents this as SOC2-ready to a prospect, not as boxes to check off a
marketing page.

## SLA / uptime posture

**What's true today:** none. This runs on Railway/Render free or low
tiers with no redundancy, no health-check-triggered failover, and no
status page. There is no SLA to offer a customer honestly right now.

**What a credible first SLA tier would need**, roughly in order:
1. A paid tier on the hosting platform with multiple instances + a load
   balancer (which also means solving the in-memory `DetectorRegistry` and
   `TenantEventBus` single-instance limitations flagged in `engine.py` and
   `core/stream.py` — both need a shared store before running >1 instance).
2. Health checks wired to the hosting platform's auto-restart.
3. A public status page (e.g. a free-tier Better Uptime/UptimeRobot
   monitor hitting `/health`) before promising any uptime number.
4. A written incident communication process — who tells the customer what,
   how fast, through which channel, when something breaks.

None of this is hard, but none of it exists yet either — listed here so
"enterprise-ready" doesn't quietly come to mean "has an RBAC table."
