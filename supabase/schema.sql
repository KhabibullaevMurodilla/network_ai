-- Network AI Anomaly Detection — multi-tenant schema (Supabase/Postgres)
-- Run this in the Supabase SQL editor on a fresh project.
--
-- Security/privacy posture this schema enforces:
--  - Row-Level Security on every tenant-scoped table: a dashboard user can
--    only ever read rows belonging to their own tenant_id, enforced by
--    Postgres itself, not just application code.
--  - API keys are stored as SHA-256 hashes only; the raw key exists for one
--    response at creation time and is never recoverable afterward.
--  - Every security-relevant action (key create/revoke, data export, data
--    erasure) is written to an append-only audit_log a tenant admin can
--    read but never edit or delete.
--  - A configurable per-tenant data_retention_days controls how long raw
--    telemetry is kept (see purge_expired_telemetry() below) — minimizing
--    stored data is itself a privacy control, not just a cost control.

-- 1. Tenants ------------------------------------------------------------
create table if not exists tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  plan text not null default 'trial' check (plan in ('trial', 'starter', 'pro', 'enterprise')),
  stripe_customer_id text,
  stripe_subscription_id text,
  subscription_status text default 'trialing',
  data_retention_days integer not null default 90,  -- raw telemetry older than this is purged
  -- v6.3: self-service alert tuning -- the floor below which a flagged
  -- event never reaches a notify webhook or response action, regardless of
  -- any individual webhook's own min_severity (that field can only raise
  -- the bar further per-channel, never lower it below this tenant-wide
  -- floor). Defaults to 'low' -- i.e. no floor beyond what already has to
  -- clear the detector's own threshold to be flagged at all.
  alert_min_severity text not null default 'low' check (alert_min_severity in ('low', 'medium', 'high', 'critical')),
  created_at timestamptz not null default now()
);

-- 2. Users --------------------------------------------------------------
-- Supabase Auth already provides auth.users; this extends it with tenant + role.
create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  tenant_id uuid not null references tenants(id) on delete cascade,
  -- Four-tier role model (v4), replacing the earlier binary admin/viewer:
  --   viewer  - read-only dashboard access
  --   analyst - viewer + can triage alerts (new/acknowledged/resolved)
  --   admin   - analyst + key/webhook management, data export/erasure
  --   owner   - admin + billing and managing other owners
  -- Enforced server-side via require_role(...) in core/auth.py, not just
  -- hidden in the UI.
  role text not null default 'viewer' check (role in ('owner', 'admin', 'analyst', 'viewer')),
  email text not null,
  -- v6.4: "focus" is a separate axis from role -- role says what you're
  -- ALLOWED to do, focus says what you actually came here to look at
  -- (a SOC analyst and an OT engineer can both be role='analyst' but want
  -- completely different default views). Null means onboarding hasn't
  -- asked yet; the dashboard prompts for it once, then it's
  -- self-serve-changeable (or admin-assignable via /team) at any time.
  focus text check (focus in ('security', 'network', 'ot', 'executive')),
  -- Set at invite time (by /team/invite) so the team page can show "invited
  -- by whom, when" without a separate audit-log query. Null for whoever
  -- created the tenant itself (not invited by anyone).
  invited_by uuid references profiles(id) on delete set null,
  invited_at timestamptz,
  created_at timestamptz not null default now()
);

-- 3. API keys (per tenant, used by a customer's telemetry agent to POST data)
create table if not exists api_keys (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  key_hash text not null unique,          -- SHA-256 hash only, raw key never stored
  label text not null default 'default',
  scope text not null default 'ingest' check (scope in ('ingest', 'read', 'admin')),
  -- ingest: can only POST telemetry. read: can only GET via key auth (not
  -- used by the dashboard, which uses user JWTs, but available for a
  -- server-to-server read integration). admin: can do both -- issue sparingly.
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);

-- 4. Raw telemetry flows --------------------------------------------------
create table if not exists telemetry_flows (
  id bigint generated always as identity primary key,
  tenant_id uuid not null references tenants(id) on delete cascade,
  received_at timestamptz not null default now(),
  dur double precision,
  proto text,
  tot_pkts integer,
  src_bytes double precision,
  dst_bytes double precision,
  rate double precision,
  load double precision,
  s_ttl integer,
  src_ip inet,                              -- nullable: entity/asset view needs this,
  dst_ip inet,                              -- but a tenant can choose not to send real IPs
  source_label text default 'unknown'       -- which site/segment this came from
);
create index if not exists telemetry_flows_tenant_id_received_at_idx on telemetry_flows (tenant_id, received_at desc);
create index if not exists telemetry_flows_tenant_id_src_ip_idx on telemetry_flows (tenant_id, src_ip);

-- 4b. Incidents (v5) — correlates related flagged events into one case ---
-- "47 separate alerts from the same host over an hour" is noise; an
-- analyst should see "1 incident, 47 events, still open." Built by
-- core/incidents.py at ingest time: events from the same source within a
-- rolling correlation window attach to the same open incident instead of
-- each standing alone. Created before anomaly_events since that table
-- holds a foreign key to this one.
create table if not exists incidents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  src_ip inet,                             -- null means 'unidentified' source
  title text not null,
  status text not null default 'open' check (status in ('open', 'closed')),
  severity text check (severity in ('low', 'medium', 'high', 'critical')),
  event_count integer not null default 0,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  created_at timestamptz not null default now()
);
create index if not exists incidents_tenant_id_status_last_seen_idx on incidents (tenant_id, status, last_seen desc);
create index if not exists incidents_tenant_id_src_ip_idx on incidents (tenant_id, src_ip);

-- 5. Anomaly events (output of the detection engine) ---------------------
create table if not exists anomaly_events (
  id bigint generated always as identity primary key,
  tenant_id uuid not null references tenants(id) on delete cascade,
  flow_id bigint references telemetry_flows(id) on delete cascade,
  detector text not null,                  -- 'ECOD' | 'IsolationForest' | 'LOF' | 'HalfSpaceTrees'
  score double precision not null,
  is_anomaly boolean not null,
  severity text check (severity in ('low', 'medium', 'high', 'critical')),
  explanation jsonb,                       -- top contributing features + their z-scores
  -- v4/v5 ensemble/entity-burst/baseline fields -- only populated on the primary (ECOD) row:
  consensus_count integer,                 -- how many of the 4 detectors flagged this flow
  escalation_reason text check (escalation_reason in ('ensemble_consensus', 'entity_burst', 'entity_baseline_drift') or escalation_reason is null),
  entity_baseline_z double precision,      -- max |z| vs this source's OWN running mean/variance (v5), null until it has ≥20 flows of history
  src_ip inet,                             -- denormalized from telemetry_flows for fast entity queries
  triage_status text not null default 'new' check (triage_status in ('new', 'acknowledged', 'resolved')),
  incident_id uuid references incidents(id) on delete set null,  -- v5: which incident this event was correlated into, if any
  created_at timestamptz not null default now()
);
create index if not exists anomaly_events_tenant_id_created_at_idx on anomaly_events (tenant_id, created_at desc);
create index if not exists anomaly_events_tenant_id_is_anomaly_idx on anomaly_events (tenant_id, is_anomaly);
create index if not exists anomaly_events_tenant_id_severity_idx on anomaly_events (tenant_id, severity);
create index if not exists anomaly_events_tenant_id_triage_status_idx on anomaly_events (tenant_id, triage_status);
create index if not exists anomaly_events_tenant_id_src_ip_idx on anomaly_events (tenant_id, src_ip);
create index if not exists anomaly_events_tenant_id_incident_id_idx on anomaly_events (tenant_id, incident_id);

-- 5b. OT protocol events (v6.1) — Modbus/TCP messages evaluated by the
-- deterministic rule engine (backend/app/ml/ot_rules.py), separate from
-- anomaly_events because this is message-level (per Modbus PDU), not
-- flow-level, and uses rule-based reasons rather than detector scores.
-- See ingestion/modbus.py for parsing scope and ml/ot_rules.py for the
-- four rules this severity/reason pair can come from.
create table if not exists ot_protocol_events (
  id bigint generated always as identity primary key,
  tenant_id uuid not null references tenants(id) on delete cascade,
  protocol text not null default 'modbus_tcp',
  ts timestamptz not null,
  src_ip inet,
  dst_ip inet,
  unit_id integer,
  function_code integer,
  function_name text,
  is_request boolean not null,
  is_exception boolean not null default false,
  exception_code integer,
  address integer,
  quantity integer,
  severity text check (severity in ('low', 'medium', 'high', 'critical')),
  reason text check (reason in ('new_function_code', 'unexpected_write_address', 'exception_flood', 'unit_id_scan') or reason is null),
  incident_id uuid references incidents(id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists ot_protocol_events_tenant_id_created_at_idx on ot_protocol_events (tenant_id, created_at desc);
create index if not exists ot_protocol_events_tenant_id_severity_idx on ot_protocol_events (tenant_id, severity);
create index if not exists ot_protocol_events_tenant_id_src_ip_dst_ip_idx on ot_protocol_events (tenant_id, src_ip, dst_ip);

-- 6. Audit log — append-only record of security-relevant actions ---------
create table if not exists audit_log (
  id bigint generated always as identity primary key,
  tenant_id uuid not null references tenants(id) on delete cascade,
  actor text not null,                     -- user id, or 'api_key:<id>', or 'system'
  action text not null,                    -- e.g. 'api_key.created', 'data.exported'
  detail jsonb,
  created_at timestamptz not null default now()
);
create index if not exists audit_log_tenant_id_created_at_idx on audit_log (tenant_id, created_at desc);

-- 7. Webhook configs — where to push real-time alerts ---------------------
-- v6.3: channel_type lets a tenant pick the delivery shape without having
-- to run their own bridge. 'generic' is the original HMAC-signed JSON
-- POST; 'slack'/'teams' POST to an incoming-webhook URL in that platform's
-- own payload shape; 'email' has no url at all (email_to instead) and is
-- dispatched over SMTP, not HTTP.
create table if not exists webhook_configs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  channel_type text not null default 'generic' check (channel_type in ('generic', 'slack', 'teams', 'email')),
  url text,                                -- required for generic/slack/teams, null for email
  email_to text,                           -- required for email, null otherwise
  secret text not null,                    -- used to HMAC-sign generic-channel payloads so the
                                            -- receiver can verify it came from us; generated even
                                            -- for slack/teams/email for schema uniformity, unused there
  min_severity text not null default 'critical' check (min_severity in ('low', 'medium', 'high', 'critical')),
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  constraint webhook_url_or_email check (
    (channel_type = 'email' and email_to is not null) or
    (channel_type != 'email' and url is not null)
  )
);

-- 7b. Response actions (v5) — automated directives, not just notifications
-- Distinct from webhook_configs: a notify webhook tells a human "go look";
-- a response action tells the tenant's own firewall/NAC/SOAR what to do
-- about it. This product has no enforcement point of its own -- it can
-- only send a signed, structured directive for the tenant's systems to
-- act on, never claim to block traffic itself.
create table if not exists response_actions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  trigger text not null check (trigger in ('critical', 'entity_burst', 'entity_baseline_drift', 'ensemble_consensus')),
  action_type text not null default 'webhook_block' check (action_type in ('webhook_block', 'webhook_notify_soar')),
  target_url text not null,
  secret text not null,                    -- HMAC key, same pattern as webhook_configs
  enabled boolean not null default true,
  created_at timestamptz not null default now()
);
create index if not exists response_actions_tenant_id_trigger_enabled_idx on response_actions (tenant_id, trigger, enabled);

-- 7c. Entity suppressions (v6.3) — self-service alert tuning. Muting a
-- known-noisy source stops it reaching a notify webhook or response
-- action (alert fatigue is a real SOC-tool complaint); it does NOT stop
-- the entity's flows being scored and stored, so an analyst reviewing
-- /dashboard/entities or /dashboard/anomalies still sees everything --
-- this mutes paging, it never hides data.
create table if not exists entity_suppressions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  src_ip inet not null,
  reason text,
  created_by uuid references profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  unique (tenant_id, src_ip)
);
create index if not exists entity_suppressions_tenant_id_src_ip_idx on entity_suppressions (tenant_id, src_ip);


-- 7b. Network devices (v6.5) -- passive discovery from captures -----------
-- One row per discovered local device, keyed by MAC when known (else IP).
-- Written by ingestion/discovery.py via /ingest/pcap; roles are heuristics
-- with an evidence list, never ground truth about physical cabling.
create table if not exists network_devices (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  device_key text not null,
  mac text,
  ip text,
  ips jsonb not null default '[]',
  role text not null default 'unknown',
  tags jsonb not null default '[]',
  hostname text,
  os_hint text,
  services jsonb not null default '[]',
  mac_randomized boolean not null default false,
  evidence jsonb not null default '[]',
  confidence text not null default 'low',
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  created_at timestamptz not null default now(),
  unique (tenant_id, device_key)
);
create index if not exists network_devices_tenant on network_devices (tenant_id, role);
alter table network_devices enable row level security;
drop policy if exists "own tenant only - network devices" on network_devices;
create policy "own tenant only - network devices"
  on network_devices for select using (
    tenant_id in (select tenant_id from profiles where id = auth.uid())
  );


-- 7c. Network links (v6.6) -- physical links from SNMP (LLDP/CDP/MAC table)
-- Written by POST /ingest/snmp (agent/snmp_collector.py). source is how the
-- link was learned: lldp/cdp = neighbour announcement (strong), fdb = a MAC
-- learned on an edge port of a switch (good, not proof).
create table if not exists network_links (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  a_key text not null,
  a_port text not null default '',
  b_key text not null,
  b_port text,
  source text not null,
  evidence text,
  last_seen timestamptz not null default now(),
  created_at timestamptz not null default now(),
  unique (tenant_id, a_key, a_port, b_key)
);
create index if not exists network_links_tenant on network_links (tenant_id);
alter table network_links enable row level security;
drop policy if exists "own tenant only - network links" on network_links;
create policy "own tenant only - network links"
  on network_links for select using (
    tenant_id in (select tenant_id from profiles where id = auth.uid())
  );


-- 7d. External endpoints (v6.7) -- who this tenant's devices talk to on the internet
-- Aggregated per (remote ip, port, proto) from uploaded captures. This is
-- browsing-destination data (incl. hostnames seen in DNS/TLS SNI): it is part
-- of the privacy export/erase and is purged by purge_expired_telemetry().
create table if not exists external_endpoints (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references tenants(id) on delete cascade,
  remote_ip text not null,
  remote_port integer not null,
  proto text not null,
  flows bigint not null default 0,
  packets bigint not null default 0,
  bytes_out bigint not null default 0,
  bytes_in bigint not null default 0,
  hostnames jsonb not null default '[]',
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  unique (tenant_id, remote_ip, remote_port, proto)
);
create index if not exists external_endpoints_tenant on external_endpoints (tenant_id, last_seen desc);
alter table external_endpoints enable row level security;
drop policy if exists "own tenant only - external endpoints" on external_endpoints;
create policy "own tenant only - external endpoints"
  on external_endpoints for select using (
    tenant_id in (select tenant_id from profiles where id = auth.uid())
  );

-- 8. Row-Level Security: every tenant only ever sees its own rows --------
alter table tenants enable row level security;
alter table profiles enable row level security;
alter table api_keys enable row level security;
alter table telemetry_flows enable row level security;
alter table anomaly_events enable row level security;
alter table audit_log enable row level security;
alter table webhook_configs enable row level security;
alter table incidents enable row level security;
alter table response_actions enable row level security;
alter table ot_protocol_events enable row level security;
alter table entity_suppressions enable row level security;

drop policy if exists "own tenant only - profiles" on profiles;
create policy "own tenant only - profiles"
  on profiles for select using (id = auth.uid());

drop policy if exists "own tenant only - tenants" on tenants;
create policy "own tenant only - tenants"
  on tenants for select using (
    id in (select tenant_id from profiles where id = auth.uid())
  );

drop policy if exists "own tenant only - telemetry" on telemetry_flows;
create policy "own tenant only - telemetry"
  on telemetry_flows for select using (
    tenant_id in (select tenant_id from profiles where id = auth.uid())
  );

drop policy if exists "own tenant only - anomalies" on anomaly_events;
create policy "own tenant only - anomalies"
  on anomaly_events for select using (
    tenant_id in (select tenant_id from profiles where id = auth.uid())
  );

drop policy if exists "own tenant only - audit log" on audit_log;
create policy "own tenant only - audit log"
  on audit_log for select using (
    tenant_id in (select tenant_id from profiles where id = auth.uid())
  );
-- Deliberately no insert/update/delete policy for authenticated users on
-- audit_log: it is written only by the backend's service role, so even a
-- tenant admin can read it but can never alter or erase their own trail.

drop policy if exists "own tenant only - webhook configs" on webhook_configs;
create policy "own tenant only - webhook configs"
  on webhook_configs for select using (
    tenant_id in (select tenant_id from profiles where id = auth.uid())
  );

drop policy if exists "own tenant only - incidents" on incidents;
create policy "own tenant only - incidents"
  on incidents for select using (
    tenant_id in (select tenant_id from profiles where id = auth.uid())
  );
-- Status transitions (open/closed) go through the backend's /dashboard
-- endpoints under the analyst-or-higher role check, same pattern as
-- anomaly_events.triage_status -- not a direct client update policy here.

drop policy if exists "own tenant only - response actions" on response_actions;
create policy "own tenant only - response actions"
  on response_actions for select using (
    tenant_id in (select tenant_id from profiles where id = auth.uid())
  );

drop policy if exists "own tenant only - ot protocol events" on ot_protocol_events;
create policy "own tenant only - ot protocol events"
  on ot_protocol_events for select using (
    tenant_id in (select tenant_id from profiles where id = auth.uid())
  );

drop policy if exists "own tenant only - entity suppressions" on entity_suppressions;
create policy "own tenant only - entity suppressions"
  on entity_suppressions for select using (
    tenant_id in (select tenant_id from profiles where id = auth.uid())
  );

-- Note: inserts to telemetry_flows / anomaly_events / audit_log happen via
-- the backend service role (API-key authenticated ingestion, or an
-- authenticated admin action), which bypasses RLS by design — the backend
-- is the only writer, the dashboard is read-only via the authenticated
-- user's session and RLS.

-- 9. Data retention: purge raw telemetry past each tenant's retention window
-- Run this on a schedule (Supabase's pg_cron, or an external scheduled job
-- hitting a backend endpoint that calls this) -- not wired to run
-- automatically by this schema alone; see README "Data retention" section.
create or replace function purge_expired_telemetry() returns void as $$
begin
  delete from telemetry_flows tf
  using tenants t
  where tf.tenant_id = t.id
    and tf.received_at < now() - (t.data_retention_days || ' days')::interval;

  delete from ot_protocol_events oe
  using tenants t
  where oe.tenant_id = t.id
    and oe.ts < now() - (t.data_retention_days || ' days')::interval;

  delete from external_endpoints ee
  using tenants t
  where ee.tenant_id = t.id
    and ee.last_seen < now() - (t.data_retention_days || ' days')::interval;
end;
$$ language plpgsql security definer set search_path = public;

-- The function runs with its owner's rights, so it must not be callable by
-- everyone (Supabase exposes public functions as /rpc endpoints). Only the
-- backend's service role (and the SQL editor / pg_cron) may run it.
revoke execute on function purge_expired_telemetry() from public, anon, authenticated;
grant execute on function purge_expired_telemetry() to service_role;
