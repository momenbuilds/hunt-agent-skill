-- NOTE (drill): VULNERABLE — privilege escalation via user-editable metadata.
-- user_metadata is writable by the user themselves (auth.updateUser), so any
-- user can set {"is_admin": true} and pass this policy.
-- SECURE alternative: check app_metadata or a server-controlled roles table.

create table public.admin_audit_log (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid not null,
  action text not null,
  created_at timestamptz not null default now()
);

alter table public.admin_audit_log enable row level security;

create policy "admins can read audit log" on public.admin_audit_log
  for select
  to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'is_admin') = 'true');
