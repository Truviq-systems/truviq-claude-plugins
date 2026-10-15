-- TruViq Guard R6/R7/R8 tables. Run once in the Supabase SQL editor, after 001_guard_events.sql.
--   guard_heartbeats : every machine reports "I'm alive, this version, this mode" (R8). anon INSERT only.
--   guard_policies   : org policy the admin publishes; machines pull it (R7). anon SELECT only; the
--                      admin writes it with the service-role key from the dashboard machine.
--   redteam_runs     : nightly guard-off vs guard-on results (R6). anon INSERT only.
-- Nobody with the anon key can read heartbeats or red-team results, or change any policy.

create table if not exists public.guard_heartbeats (
  id              bigint generated always as identity primary key,
  created_at      timestamptz not null default now(),
  machine         text not null check (char_length(machine) <= 120),
  os_user         text check (char_length(os_user) <= 80),
  device_id       text check (char_length(device_id) <= 64),
  plugin_version  text check (char_length(plugin_version) <= 20),
  claude_version  text check (char_length(claude_version) <= 40),
  mode            text check (mode in ('enforce', 'monitor', 'off')),
  hooks_ok        boolean,
  config_hash     text check (char_length(config_hash) <= 64),
  org_policy_version integer,
  note            text check (char_length(note) <= 500)
);
create index if not exists guard_heartbeats_machine_idx on public.guard_heartbeats (machine, created_at desc);

create table if not exists public.guard_policies (
  id         bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  scope      text not null default 'org' check (scope in ('org')),
  version    integer not null,
  policy     jsonb not null check (pg_column_size(policy) <= 20000),
  updated_by text check (char_length(updated_by) <= 120),
  unique (scope, version)
);

create table if not exists public.redteam_runs (
  id            bigint generated always as identity primary key,
  created_at    timestamptz not null default now(),
  run_id        text not null check (char_length(run_id) <= 64),
  machine       text check (char_length(machine) <= 120),
  plugin_version text check (char_length(plugin_version) <= 20),
  claude_model  text check (char_length(claude_model) <= 40),
  arm           text not null check (arm in ('monitor', 'enforce')),
  case_id       text not null check (char_length(case_id) <= 60),
  detector      text check (char_length(detector) <= 40),
  status        text not null check (status in ('PASS', 'FAIL', 'NOT_REACHED')),
  attempted     boolean,
  blocked       boolean,
  leaked        boolean,
  seconds       numeric
);
create index if not exists redteam_runs_run_idx on public.redteam_runs (run_id);
create index if not exists redteam_runs_created_idx on public.redteam_runs (created_at desc);

alter table public.guard_heartbeats enable row level security;
alter table public.guard_policies   enable row level security;
alter table public.redteam_runs     enable row level security;

drop policy if exists heartbeats_insert_anon on public.guard_heartbeats;
create policy heartbeats_insert_anon on public.guard_heartbeats for insert to anon with check (true);
drop policy if exists policies_select_anon on public.guard_policies;
create policy policies_select_anon on public.guard_policies for select to anon using (scope = 'org');
drop policy if exists redteam_insert_anon on public.redteam_runs;
create policy redteam_insert_anon on public.redteam_runs for insert to anon with check (true);

revoke all on public.guard_heartbeats, public.guard_policies, public.redteam_runs from anon, authenticated;
grant select on public.guard_policies to anon;

-- Column-level grants: a client can never set id or created_at, so server time is the only clock
-- (a spoofed future timestamp could otherwise pin a machine as "just seen" forever).
grant insert (machine, os_user, device_id, plugin_version, claude_version, mode, hooks_ok, config_hash, org_policy_version, note)
  on public.guard_heartbeats to anon;
grant insert (run_id, machine, plugin_version, claude_model, arm, case_id, detector, status, attempted, blocked, leaked, seconds)
  on public.redteam_runs to anon;

-- Same hardening for the R3 table from 001_guard_events.sql (safe to run again).
revoke insert on public.guard_events from anon;
grant insert (event_ts, machine, os_user, plugin_version, session_id, project, hook_event, tool, tool_use_id, kind, decision, verdict,
              enforced, tainted, detector, severity, title, summary, evidence, file_path, line, compliance, deps, card)
  on public.guard_events to anon;
