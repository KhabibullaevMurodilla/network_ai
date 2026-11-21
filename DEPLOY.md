# Deploying Network AI

This gets the platform running against **your own** infrastructure
(Supabase project, optional Redis, your own domain, your own Stripe
account). Nothing here runs automatically — every step below is something
you do once, with your own credentials, the first time you go live.

**Honest scope before you start:** this document and the Dockerfiles it
references were written and tested as far as the sandbox they were built
in allows. Specifically:

- Every piece of application logic referenced below (detection engine,
  pcap ingestion, incident correlation, Redis checkpointing, Stripe
  webhook verification, health checks) was actually run and verified —
  against a real local Redis, a real captured pcap, and real
  cryptographically-signed Stripe payloads. See `README.md` for what was
  tested and how.
- The **Dockerfiles' syntax** was validated (`docker build` parses them,
  resolves build stages, and gets as far as pulling the base image) but
  the sandbox this was built in blocks every container registry (Docker
  Hub, ECR Public, Microsoft Container Registry, GHCR were all tried and
  all policy-denied) — so a full `docker build && docker run` could not
  be completed end-to-end here. Before relying on this in production,
  run `docker compose up --build` yourself once in an environment with
  normal registry access and confirm all three services come up healthy.
  The Dockerfiles follow standard, unexotic patterns (multi-stage build,
  non-root user, healthcheck, Next.js standalone output) — there's no
  reason to expect surprises, but "should work" and "verified working"
  are different claims, and this README doesn't blur them.

---

## 1. Supabase (database + auth)

1. Create a project at [supabase.com](https://supabase.com).
2. Open the SQL editor and run the entire contents of `supabase/schema.sql`.
   This creates every table, RLS policy, and the `audit_log`/`incidents`/
   `response_actions` tables v5–v6 added.
3. From **Project Settings → API**, copy:
   - `Project URL` → `SUPABASE_URL`
   - **Publishable key** (`sb_publishable_…`; called `anon public` on older
     projects) → `NEXT_PUBLIC_SUPABASE_ANON_KEY` (frontend)
   - **Secret key** (`sb_secret_…`; called `service_role` on older projects)
     → `SUPABASE_SERVICE_ROLE_KEY` (backend **only** — never ship this to
     the frontend; it bypasses RLS)
   - Both live under **Project Settings → API Keys** (older projects may
     show the legacy keys on a "Legacy API keys" tab).
   - `SUPABASE_JWT_SECRET` is **optional**. Newer projects sign logins with
     an asymmetric key and the backend verifies them from `SUPABASE_URL`
     automatically. Only if your project still uses the legacy shared
     secret, paste it from **Project Settings → JWT Keys → Legacy JWT Secret**.
   - *Not verified against a live Supabase project -- if a label differs on
     your screen, the Project URL + one browser-safe key + one backend-only
     key are what matters.*
4. Create your first tenant and owner user (a one-time bootstrap; every
   later teammate is added from the dashboard's **Team & focus** page).
   The login page only *signs in* -- it has no signup form -- so:
   1. Supabase dashboard -> **Authentication -> Users -> Add user ->
      Create new user**. Enter an email and password and tick **Auto
      Confirm User**. Copy the new user's **UID**.
   2. In the **SQL editor**, run (replace the email and the UID):

      ```sql
      with t as (
        insert into tenants (name, plan) values ('Your Company', 'starter')
        returning id
      )
      insert into profiles (id, tenant_id, role, email)
      select 'PASTE-THE-USER-UID-HERE', t.id, 'owner', 'you@yourcompany.com' from t;
      ```
   3. Sign in on the dashboard with that email/password. You'll be asked
      once to pick a focus, then land on the matching page.
5. **Inviting teammates (v6.4)** uses Supabase's own invite email. In
   **Authentication -> URL Configuration** set *Site URL* to your
   frontend's address, or the link in the invite email won't land
   anywhere useful. This was never exercised against a real Supabase
   project from the sandbox this was built in -- send yourself the first
   invite and confirm the email arrives and the link works.
6. **Upgrading an existing database** that predates v6.4 (a fresh
   `schema.sql` run already includes this):

   ```sql
   alter table profiles
     add column if not exists focus text check (focus in ('security','network','ot','executive')),
     add column if not exists invited_by uuid references profiles(id) on delete set null,
     add column if not exists invited_at timestamptz;
   ```
   (The v6.3 additions -- `entity_suppressions`, `webhook_configs.channel_type`,
   `tenants.alert_min_severity` -- need equivalent `alter`/`create` statements
   if you set up before v6.3; copy them from `schema.sql`.)

## 2. Redis (optional, recommended beyond a single instance)

Only needed if you're running more than one backend instance, or more
than one `uvicorn` worker in one instance (`backend/Dockerfile`'s default
`--workers 2` already counts as "more than one" — two workers are two
separate OS processes with separate memory). Without `REDIS_URL` set, the
backend works fine single-instance; see `backend/app/ml/persistence.py`
and `backend/app/core/stream.py` for exactly what Redis does and doesn't
give you across instances (periodic checkpoint-based recovery, not live
per-flow replication — sticky routing by tenant is what you want for
true per-flow consistency, see §5 below).

Any managed Redis works (Upstash, Redis Cloud, AWS ElastiCache, or the
`redis` service in `docker-compose.yml` for a single-host deploy). Set
`REDIS_URL=redis://...` on the backend.

## 3. Stripe (optional — billing is inert until configured)

1. Create two Products/Prices in the Stripe dashboard (Starter, Pro).
2. Set `STRIPE_SECRET_KEY`, `STRIPE_PRICE_STARTER`, `STRIPE_PRICE_PRO`.
3. Add a webhook endpoint in the Stripe dashboard pointing at
   `https://your-api-domain/billing/webhook`, subscribed to
   `checkout.session.completed`, `customer.subscription.updated`,
   `customer.subscription.deleted`. Copy its signing secret into
   `STRIPE_WEBHOOK_SECRET`.
4. `backend/tests/test_billing_webhook.py` verifies the signature-checking
   code path itself works correctly (valid signatures accepted, tampered
   payloads and forged signatures rejected) — it does not and cannot
   verify your specific Stripe account's webhook delivery without a real
   account, which is why step 3 matters.

## 4. Environment variables

**Docker Compose:** copy the root `.env.example` to `.env` and fill in the
six required values (compose refuses to start without them -- that is
deliberate, not a bug). **Running without Docker:** copy
`backend/.env.example` → `backend/.env` and `frontend/.env.example` →
`frontend/.env.local`. Every variable is documented inline.

## 5. Running it

### Single host, Docker Compose (simplest)

```bash
cp backend/.env.example .env   # fill in real values at the repo root —
                                 # docker-compose.yml reads from here
docker compose up --build
```

This brings up Redis, the backend (port 8000), and the frontend (port
3000). `docker compose config` was used to validate the compose file's
structure and variable substitution in this build — the actual
`up --build` needs to be run in an environment with registry access (see
the scope note at the top of this file).

### Multiple instances / a real platform (Fly.io, Render, ECS, k8s, …)

- Backend: build `backend/Dockerfile`, deploy it as a standard container
  service. Point its liveness probe at `GET /health` (always 200 if the
  process is up — never touches Supabase/Redis, so a downstream blip
  doesn't cause a false restart) and its readiness probe at
  `GET /health/ready` (returns 503 when Supabase is unreachable, which is
  what should gate whether traffic is sent to this instance).
- Frontend: build `frontend/Dockerfile`. Remember `NEXT_PUBLIC_*` vars are
  baked in at **build** time (pass them as Docker build args, not runtime
  env vars — see the Dockerfile's own comment on this).
- **If you run more than one backend instance and set `REDIS_URL`**: for
  true per-flow consistency of the live detector state (not just
  checkpoint-based recovery — see §2), configure your load balancer to
  route by a stable key so one tenant's traffic always lands on the same
  instance between checkpoints. Concretely: hash on the `X-API-Key`
  header (or a tenant ID header your ingestion agent sets) rather than
  round-robin. This is a standard pattern for keyed streaming state (the
  same idea Kafka Streams/Flink use), not something specific to this
  codebase — most load balancers support consistent-hash routing
  natively (e.g. nginx's `hash $http_x_api_key consistent;`, or an ALB
  target group with a Lambda-based router for more complex cases).
  Without this, the system still works correctly — HalfSpaceTrees, the
  adaptive thresholds, and the entity baselines just converge to a
  roughly-shared view within one checkpoint interval (`CHECKPOINT_EVERY_FLOWS`
  = 500 flows) of each other, rather than being instantly identical.

## 6. CI

`.github/workflows/ci.yml` runs on every push/PR: the backend's full
pytest suite (36 tests — engine behavior, real pcap parsing, real Modbus/TCP
parsing, the OT rule engine, real Stripe signature verification,
health-check contracts), a FastAPI import sanity check, the agent's own
pytest suite (retry/backoff and shutdown-handling logic), and the
frontend's typecheck + production build. It does not build or push Docker
images (no registry credentials are assumed) — add that as a follow-up
once you have a container registry to push to.

## Optional v6.3 settings

Both are genuinely optional — the backend runs fine with neither set.

- **Email alert channel**: set `SMTP_HOST` (plus `SMTP_PORT`, `SMTP_USER`,
  `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_USE_TLS`) to enable the `email`
  webhook channel type. Unset, a tenant creating an email-channel alert
  gets a logged no-op at send time, not an error at creation time.
- **Public demo**: pick a fixed UUID, set it as `DEMO_TENANT_ID` on the
  backend, then run `python3 backend/scripts/seed_demo_tenant.py` once
  against your real deployment (with `SUPABASE_URL` /
  `SUPABASE_SERVICE_ROLE_KEY` / `SUPABASE_JWT_SECRET` pointed at your real
  project) to seed it with synthetic traffic before linking `/demo`
  publicly. This has only been verified against this repo's FakeDB test
  harness, not run against a live Supabase project from this sandbox —
  check the seeded tenant's data in the dashboard (or `/demo` itself)
  before treating it as pitch-ready. Unset, `/demo/*` routes 404.

## Security notes (read before going live)

- `frontend/package.json` pins `next@^14.2.35` (the latest available
  14.x patch at the time this was built). `npm audit` still flags one
  critical and one high advisory — both are fixed only in Next.js 15/16,
  a breaking major-version jump that wasn't attempted in this pass. The
  specific vulnerable surfaces (Server Actions, `next/image` optimization,
  custom middleware, i18n routing) are **not used anywhere in this
  codebase** (`grep` confirms zero matches), so the practical exposure
  from staying on 14.2.x is low, but it is not zero, and it should be
  tracked as a real follow-up — either a careful Next 15 migration or
  periodic re-checking for a 14.x security backport.
- `ALLOWED_ORIGINS` has no default — an unset value fails closed (no
  browser origin is allowed to call the API at all). Set it explicitly to
  your real frontend origin(s) before anything will work from a browser.
- The `service_role` Supabase key bypasses RLS entirely. It belongs only
  on the backend, only as a server-side environment variable, never in
  any frontend bundle or client-visible config.
