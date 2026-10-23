-- NOTE (drill): VULNERABLE — table in the public schema with NO row level
-- security. With the anon key (public by design), any client can
-- select/insert/update/delete every row.

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  content text not null,
  created_at timestamptz not null default now()
);

grant all on table public.notes to anon, authenticated;
-- missing: alter table public.notes enable row level security;
-- missing: policies
