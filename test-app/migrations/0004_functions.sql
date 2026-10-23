-- NOTE (drill): MIXED —
--   VULN-1: get_all_profiles() is SECURITY DEFINER, unfiltered, and
--           executable by anon + authenticated. It becomes a public RPC
--           endpoint (/rest/v1/rpc/get_all_profiles) that dumps every row.
--   SECURE-1: current_user_document() filters by auth.uid(), pins
--             search_path, and revokes execute from anon/public.

create or replace function public.get_all_profiles()
returns setof public.profiles
language sql
security definer
as $$
  select * from public.profiles;
$$;
-- default ACLs grant execute widely; nothing revokes it here

create or replace function public.current_user_document(doc_id uuid)
returns setof public.documents
language sql
stable
security definer
set search_path = ''
as $$
  select * from public.documents
  where id = doc_id and user_id = (select auth.uid());
$$;

revoke execute on function public.current_user_document(uuid) from public, anon;
grant execute on function public.current_user_document(uuid) to authenticated;
