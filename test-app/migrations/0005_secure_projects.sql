-- SECURE — reference migration: RLS on, policies bound to auth.uid(),
-- WITH CHECK on writes, least-privilege grants. An auditor should NOT flag
-- anything in this file.

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default (select auth.uid()),
  name text not null,
  created_at timestamptz not null default now()
);

alter table public.projects enable row level security;
revoke all on table public.projects from anon, authenticated;
grant select, insert, update, delete on table public.projects to authenticated;

create policy "owners select" on public.projects
  for select to authenticated
  using ((select auth.uid()) = user_id);

create policy "owners insert" on public.projects
  for insert to authenticated
  with check ((select auth.uid()) = user_id);

create policy "owners update" on public.projects
  for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create policy "owners delete" on public.projects
  for delete to authenticated
  using ((select auth.uid()) = user_id);

-- Secure storage policy: uploads confined to the caller's own folder.
create policy "users upload to own folder" on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'project-assets'
    and (storage.foldername(name))[1] = (select auth.uid())
  );
