# Database, SQL Injection & Supabase RLS

Covers OWASP A03 (injection) for SQL, API Security Top 10 API1 (via the data layer), and the Supabase-specific control plane. With Supabase, the database is a public API surface — the anon key is public, so **RLS is the real authorization layer**.

## 1. SQL injection

**Vulnerable patterns:**

```ts
// String concatenation / template interpolation into SQL
db.query(`SELECT * FROM users WHERE id = ${userId}`);
db.query("SELECT * FROM users WHERE email = '" + email + "'");
await prisma.$queryRawUnsafe(`SELECT * FROM docs WHERE id = ${id}`);
await knex.raw(`SELECT * FROM t WHERE name = '${name}'`);
```

```sql
-- In Postgres functions: dynamic SQL built by concatenation
EXECUTE 'SELECT * FROM docs WHERE id = ' || quote_literal(user_input); -- still risky if misused
EXECUTE format('SELECT * FROM docs WHERE id = %s', user_input);         -- %s injects, use %I/%L correctly
```

**Secure:**

```ts
db.query("SELECT * FROM users WHERE id = $1", [userId]);           // parameterized
await prisma.$queryRaw`SELECT * FROM docs WHERE id = ${id}`;        // tagged template = parameterized
supabase.from("docs").select().eq("id", id);                        // query builder
```

**Detection:** search for SQL keywords (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `WHERE`) inside template literals or `+` concatenation that include a variable. Then check whether that variable traces to request input. ORM `.raw(`, `$queryRawUnsafe`, `.where(raw(...))`, `orderBy(userInput)` (identifier injection — allowlist column names).

**Identifier injection note:** `orderBy(req.query.sort)` lets attackers reference arbitrary columns; fix is an allowlist map. Flag Medium unless it clearly exposes sensitive columns.

**What NOT to flag:** parameterized raw SQL (`$1` placeholders, tagged templates), query builders, static SQL strings with no variables.

## 2. Supabase RLS fundamentals (what to check on every table)

Facts an auditor must apply:

- **RLS disabled** on a `public` schema table = any client with the URL + anon key can CRUD it (grants permitting) → **Critical** if the table holds user data.
- **RLS enabled + no policies** = deny all through the API (safe, but usually an app-breaking mistake, not a security hole).
- New public tables on existing projects get full grants to `anon`/`authenticated` — policies filter rows, grants allow operations.
- `service_role` bypasses RLS entirely — leaking that key defeats everything.

### Audit each table in migrations / SQL files

For every `create table` in an exposed schema, confirm:

1. `alter table ... enable row level security;` is present
2. Policies exist for each operation the app performs
3. Policies bind to `auth.uid()` (or org membership), not `true`
4. `WITH CHECK` is present on INSERT and UPDATE policies
5. Roles are named (`to authenticated`), not left open to `anon` unless intentional
6. Grants are minimized (`revoke all ... from anon, authenticated; grant select ... to authenticated;`)

**Vulnerable migrations:**

```sql
-- No RLS at all
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  content text
);
grant all on table public.notes to anon, authenticated; -- exposed!
```

```sql
-- RLS on, but policy is a no-op
alter table public.documents enable row level security;
create policy "everyone reads" on public.documents
  for select to authenticated using (true);
```

```sql
-- INSERT/UPDATE without WITH CHECK — user can write rows owned by others
create policy "own update" on public.notes
  for update to authenticated
  using ((select auth.uid()) = user_id);
  -- missing: with check ((select auth.uid()) = user_id)
```

**Secure migration:**

```sql
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default (select auth.uid()),
  content text not null
);

alter table public.notes enable row level security;
revoke all on table public.notes from anon, authenticated;
grant select, insert, update, delete on table public.notes to authenticated;

create policy "owners can select" on public.notes
  for select to authenticated
  using ((select auth.uid()) = user_id);

create policy "owners can insert" on public.notes
  for insert to authenticated
  with check ((select auth.uid()) = user_id);

create policy "owners can update" on public.notes
  for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create policy "owners can delete" on public.notes
  for delete to authenticated
  using ((select auth.uid()) = user_id);
```

## 3. Supabase-specific RLS mistakes

### 3a. Policies trusting user-editable metadata — Critical

```sql
-- VULNERABLE: user runs auth.updateUser({ data: { is_admin: true } }) and passes
create policy "admins read all" on public.docs
  for select to authenticated
  using ((auth.jwt()->'user_metadata'->>'is_admin') = 'true');
```

Secure: check a server-controlled roles table, or `app_metadata` (only the backend can write it):

```sql
using ((auth.jwt()->'app_metadata'->>'role') = 'admin')
```

Detection: grep migrations/policies for `user_metadata`, `raw_user_meta_data`.

### 3b. SECURITY DEFINER functions exposed via RPC — High/Critical

Postgres functions with `security definer` run as the owner (often `postgres`, which bypasses RLS). Every function is an RPC endpoint (`/rest/v1/rpc/<name>`) if EXECUTE is granted — and defaults often grant it widely.

**Vulnerable:**

```sql
create or replace function public.get_all_notes()
returns setof public.notes
language sql security definer
as $$ select * from public.notes $$;
-- anon/authenticated can execute → dumps every tenant's notes
```

**Secure:**

```sql
create or replace function public.my_notes()
returns setof public.notes
language sql stable security definer
set search_path = ''
as $$
  select * from public.notes where user_id = (select auth.uid());
$$;

revoke execute on function public.my_notes() from public, anon;
grant execute on function public.my_notes() to authenticated;
```

Detection: `security definer` functions that read tables without filtering by `auth.uid()`, that lack `set search_path = ''`, or that are granted to `anon`/`public`. Also flag any definer function whose body uses concatenation for dynamic SQL.

### 3c. Views bypassing RLS — High

Views execute with the view owner's rights by default (security definer behavior) and bypass underlying table RLS unless `security_invoker = true`.

```sql
-- VULNERABLE: exposes auth.users emails; bypasses RLS on underlying tables
create view public.all_profiles as
  select * from public.profiles;

-- SECURE
create view public.my_profile
  with (security_invoker = true)
  as select id, display_name from public.profiles
  where user_id = (select auth.uid());
```

Also flag: views over `auth.users` (PII), materialized views and foreign tables with grants to `anon`/`authenticated` (they cannot use RLS at all).

### 3d. Storage bucket policies — High

Policies live on `storage.objects`. A `with check (true)` insert policy lets any authenticated user write to any path.

```sql
-- VULNERABLE
create policy "open upload" on storage.objects
  for insert to authenticated with check (true);

-- SECURE: own folder only
create policy "uploads own folder" on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'documents'
    and (storage.foldername(name))[1] = (select auth.uid())
  );
```

Check: public buckets holding private data (invoices, IDs); missing folder scoping; delete/update policies that aren't scoped to the owner.

### 3e. Exposed schemas and Data API surface

- Check `supabase/config.toml` (or notes) for `[api] extra_search_path` / exposed schemas. Anything beyond `public` (and intentionally `api`) increases surface.
- If the app never uses the client-side Supabase client and only talks to the DB server-side, note "Data API exposure unverified / possibly unnecessary" — recommend reviewing dashboard settings (not visible in code).

## 4. Code-level data access patterns (all stacks)

**Vulnerable (app layer bypasses everything):**

```ts
// Server code using service-role/admin client for a user-scoped operation
const supabase = createAdminClient(); // service role, bypasses RLS
const { data } = await supabase.from("documents").select().eq("id", id);
// If the id came from the request and there's no user check → IDOR at Critical power
```

Service-role client in a user-request handler is not automatically a bug (background jobs need it) — but in a request handler it demands a strict ownership/permission check that RLS would otherwise provide. Missing check = Critical.

## Verification steps

1. For each table: `rg -i "create table" migrations/` → find matching `enable row level security` and policies. Missing RLS on a user-data table = Confirmed Critical (evidence: the migration).
2. For `USING (true)` policies: check what data the table holds and which roles the policy targets. Public read of intentionally public data (announcements) with writes revoked = not a finding; read of user data = High.
3. For SECURITY DEFINER: read the function body; if it returns rows without an `auth.uid()` filter and is executable by `anon`/`authenticated` = Confirmed High/Critical.
4. Cross-check app queries: `from("table")` in code → does a policy exist for that table? Table with app queries but no RLS = Critical regardless of app-layer checks.
5. If a live authorized staging environment is available, an anon-key probe (`GET /rest/v1/<table>` with only the publishable key) is the strongest confirmation — run only with explicit permission.

## What NOT to flag

- The anon/publishable key existing in client code
- RLS enabled with narrow `auth.uid()` policies and matching grants — good
- `service_role` used in scripts, migrations, or clearly server-only job code with its own authorization logic
- Extension-owned tables (e.g., PostGIS `spatial_ref_sys`) that can't enable RLS — known false positive even in Supabase's own advisor
- Views created by Supabase internals (`auth`, `storage`, `realtime` schemas)
