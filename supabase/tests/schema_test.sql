-- Behavioural tests for supabase/schema.sql. Run after the schema is applied:
--   psql -v ON_ERROR_STOP=1 -f supabase/tests/schema_test.sql
-- Every check raises an exception on failure. Everything runs in one
-- transaction that is rolled back, so it leaves no data behind.
begin;

create or replace function pg_temp.fail(msg text) returns void language plpgsql as $$ begin raise exception 'FAILED: %', msg; end $$;

-- fixtures (as the superuser, like the backend's service role) ---------------
insert into tenants (id, name, data_retention_days) values
  ('aaaaaaaa-0000-0000-0000-000000000001', 'Tenant A', 30),
  ('bbbbbbbb-0000-0000-0000-000000000002', 'Tenant B', 90);
insert into auth.users (id, email) values
  ('a1000000-0000-0000-0000-000000000001', 'a@example.com'),
  ('b1000000-0000-0000-0000-000000000002', 'b@example.com');
insert into profiles (id, tenant_id, role, email) values
  ('a1000000-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000001', 'owner', 'a@example.com'),
  ('b1000000-0000-0000-0000-000000000002', 'bbbbbbbb-0000-0000-0000-000000000002', 'viewer', 'b@example.com');
insert into telemetry_flows (tenant_id, proto, tot_pkts, src_ip) values
  ('aaaaaaaa-0000-0000-0000-000000000001', 'TCP', 5, '10.0.0.1'),
  ('aaaaaaaa-0000-0000-0000-000000000001', 'UDP', 2, '10.0.0.2'),
  ('bbbbbbbb-0000-0000-0000-000000000002', 'TCP', 9, '10.9.9.9');
insert into network_devices (tenant_id, device_key, role)
  values ('bbbbbbbb-0000-0000-0000-000000000002', 'mac:00:11:22:33:44:55', 'switch');
insert into external_endpoints (tenant_id, remote_ip, remote_port, proto)
  values ('bbbbbbbb-0000-0000-0000-000000000002', '93.184.216.34', 443, 'TCP');

-- 1. tenant isolation: user A sees only tenant A, on every tenant-scoped table
set local role authenticated;
select set_config('request.jwt.claim.sub', 'a1000000-0000-0000-0000-000000000001', true);
do $$ declare t text; n int; begin
  select count(*) into n from telemetry_flows;
  if n <> 2 then perform pg_temp.fail('user A should see exactly 2 own flows, saw ' || n); end if;
  select count(*) into n from tenants;
  if n <> 1 then perform pg_temp.fail('user A should see exactly 1 tenant, saw ' || n); end if;
  select count(*) into n from profiles;
  if n <> 1 then perform pg_temp.fail('user A should see only their own profile, saw ' || n); end if;
  select count(*) into n from network_devices;
  if n <> 0 then perform pg_temp.fail('user A must not see tenant B devices, saw ' || n); end if;
  select count(*) into n from external_endpoints;
  if n <> 0 then perform pg_temp.fail('user A must not see tenant B external endpoints, saw ' || n); end if;
end $$;

-- 2. a logged-in user cannot write (the backend writes with the service role)
do $$ begin
  begin
    insert into telemetry_flows (tenant_id, proto) values ('aaaaaaaa-0000-0000-0000-000000000001', 'TCP');
    perform pg_temp.fail('authenticated user was able to INSERT telemetry');
  exception when insufficient_privilege then null;   -- RLS "new row violates policy" is this class
  end;
  update telemetry_flows set proto = 'X';
  if found then perform pg_temp.fail('authenticated user was able to UPDATE telemetry'); end if;
  delete from telemetry_flows;
  if found then perform pg_temp.fail('authenticated user was able to DELETE telemetry'); end if;
end $$;
reset role;

-- 3. a logged-out visitor sees nothing at all
set local role anon;
select set_config('request.jwt.claim.sub', '', true);
do $$ declare n int; begin
  select count(*) into n from telemetry_flows;
  if n <> 0 then perform pg_temp.fail('anon saw ' || n || ' telemetry rows'); end if;
  select count(*) into n from tenants;
  if n <> 0 then perform pg_temp.fail('anon saw tenants'); end if;
end $$;
reset role;

-- 4. value constraints: accept everything the code writes, reject nonsense
do $$ declare f bigint; begin
  select id into f from telemetry_flows where tenant_id = 'aaaaaaaa-0000-0000-0000-000000000001' limit 1;
  -- unflagged flow / learning-period flow: severity and reason are NULL
  insert into anomaly_events (tenant_id, flow_id, detector, score, is_anomaly, severity, escalation_reason)
    values ('aaaaaaaa-0000-0000-0000-000000000001', f, 'ECOD', 0.1, false, null, null);
  -- every reason the detector can emit
  insert into anomaly_events (tenant_id, flow_id, detector, score, is_anomaly, severity, escalation_reason) values
    ('aaaaaaaa-0000-0000-0000-000000000001', f, 'ECOD', 9, true, 'critical', 'ensemble_consensus'),
    ('aaaaaaaa-0000-0000-0000-000000000001', f, 'ECOD', 9, true, 'critical', 'entity_burst'),
    ('aaaaaaaa-0000-0000-0000-000000000001', f, 'ECOD', 9, true, 'high', 'entity_baseline_drift');
  begin
    insert into anomaly_events (tenant_id, flow_id, detector, score, is_anomaly, severity) values ('aaaaaaaa-0000-0000-0000-000000000001', f, 'ECOD', 1, true, 'bogus');
    perform pg_temp.fail('bogus severity was accepted');
  exception when check_violation then null; end;
  begin
    insert into anomaly_events (tenant_id, flow_id, detector, score, is_anomaly, escalation_reason) values ('aaaaaaaa-0000-0000-0000-000000000001', f, 'ECOD', 1, true, 'learning');
    perform pg_temp.fail('unknown escalation_reason was accepted');
  exception when check_violation then null; end;
  begin
    insert into profiles (id, tenant_id, role, email) values (gen_random_uuid(), 'aaaaaaaa-0000-0000-0000-000000000001', 'superadmin', 'x@example.com');
    perform pg_temp.fail('bogus role was accepted');
  exception when check_violation or foreign_key_violation then null; end;
end $$;

-- 5. retention: only data older than the tenant's own window is purged, and
--    only the backend (service role) may run the purge
insert into telemetry_flows (tenant_id, received_at, proto) values
  ('aaaaaaaa-0000-0000-0000-000000000001', now() - interval '40 days', 'OLD-A'),   -- A keeps 30 days: purged
  ('bbbbbbbb-0000-0000-0000-000000000002', now() - interval '40 days', 'KEEP-B');  -- B keeps 90 days: kept
set local role anon;
do $$ begin
  begin perform purge_expired_telemetry(); perform pg_temp.fail('anon could execute purge_expired_telemetry');
  exception when insufficient_privilege then null; end;
end $$;
reset role;
set local role authenticated;
do $$ begin
  begin perform purge_expired_telemetry(); perform pg_temp.fail('a logged-in user could execute purge_expired_telemetry');
  exception when insufficient_privilege then null; end;
end $$;
reset role;
set local role service_role;
select purge_expired_telemetry();
reset role;
do $$ begin
  if exists (select 1 from telemetry_flows where proto = 'OLD-A') then perform pg_temp.fail('expired tenant-A flow was not purged'); end if;
  if not exists (select 1 from telemetry_flows where proto = 'KEEP-B') then perform pg_temp.fail('tenant-B flow inside its retention window was purged'); end if;
  if not exists (select 1 from telemetry_flows where proto = 'TCP' and tot_pkts = 5) then perform pg_temp.fail('recent flow was purged'); end if;
end $$;

-- 6. erasing a tenant removes everything it owns
delete from tenants where id = 'bbbbbbbb-0000-0000-0000-000000000002';
do $$ begin
  if exists (select 1 from telemetry_flows where tenant_id = 'bbbbbbbb-0000-0000-0000-000000000002')
     or exists (select 1 from network_devices where tenant_id = 'bbbbbbbb-0000-0000-0000-000000000002')
     or exists (select 1 from external_endpoints where tenant_id = 'bbbbbbbb-0000-0000-0000-000000000002')
  then perform pg_temp.fail('tenant delete left child rows behind'); end if;
end $$;

rollback;
\echo ALL SCHEMA TESTS PASSED
