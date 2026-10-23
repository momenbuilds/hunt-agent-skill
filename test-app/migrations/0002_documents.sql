-- NOTE (drill): VULNERABLE — RLS is enabled but the select policy is
-- USING (true), so any authenticated user reads every tenant's documents.
-- INSERT/UPDATE have no WITH CHECK, so a user can write rows owned by others.

create table public.documents (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  title text not null,
  body text,
  created_at timestamptz not null default now()
);

alter table public.documents enable row level security;

create policy "anyone authenticated can read" on public.documents
  for select
  to authenticated
  using (true);

create policy "insert any" on public.documents
  for insert
  to authenticated
  with check (true);

-- missing: select/update/delete policies bound to auth.uid()
-- missing: with check on any update policy
