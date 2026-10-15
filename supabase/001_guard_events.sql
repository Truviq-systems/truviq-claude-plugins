-- TruViq Guard central events (Release 3).
-- Run once in the Supabase dashboard: SQL Editor → New query → paste → Run.
-- Machines with the plugin use the ANON key and may only INSERT. Nobody can read with the anon key.
-- The dashboard reads with the SERVICE ROLE key, which stays on the dashboard machine.

create table if not exists public.guard_events (
  id             bigint generated always as identity primary key,
  created_at     timestamptz not null default now(),
  event_ts       timestamptz,
  machine        text not null check (char_length(machine) <= 120),
  os_user        text check (char_length(os_user) <= 80),
  plugin_version text check (char_length(plugin_version) <= 20),
  session_id     text check (char_length(session_id) <= 120),
  project        text check (char_length(project) <= 200),
  hook_event     text check (char_length(hook_event) <= 40),
  tool           text check (char_length(tool) <= 120),
  tool_use_id    text check (char_length(tool_use_id) <= 120),
  kind           text not null check (kind in ('finding', 'outcome')),
  decision       text check (decision in ('deny', 'ask', 'warn', 'log', 'allow', '')),
  verdict        text check (char_length(verdict) <= 20),
  enforced       boolean default true,
  tainted        boolean default false,
  detector       text check (char_length(detector) <= 20),
  severity       text check (severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', '')),
  title          text check (char_length(title) <= 200),
  summary        text check (char_length(summary) <= 2000),
  evidence       text check (char_length(evidence) <= 1000),
  file_path      text check (char_length(file_path) <= 500),
  line           integer,
  compliance     jsonb default '{}'::jsonb check (pg_column_size(compliance) <= 4000),
  deps           jsonb default '[]'::jsonb check (pg_column_size(deps) <= 8000),
  card           text check (char_length(card) <= 4000)
);

create index if not exists guard_events_created_at_idx on public.guard_events (created_at desc);
create index if not exists guard_events_machine_idx    on public.guard_events (machine);
create index if not exists guard_events_detector_idx   on public.guard_events (detector);
create index if not exists guard_events_tool_use_idx   on public.guard_events (tool_use_id);

alter table public.guard_events enable row level security;

-- Insert-only for the plugin (anon). No select/update/delete policies exist for anon or authenticated.
drop policy if exists guard_events_insert_anon on public.guard_events;
create policy guard_events_insert_anon on public.guard_events
  for insert to anon
  with check (kind in ('finding', 'outcome'));

revoke select, update, delete on public.guard_events from anon, authenticated;
grant insert on public.guard_events to anon;
