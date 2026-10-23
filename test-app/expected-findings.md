# Expected Findings (ground truth)

An auditor running HUNT against this fixture should find **every** item in
section 1 and must **not** flag anything in section 2. IDs are stable so
drill results can be diffed (`HUNT-01`…).

All secrets in this fixture are fake; they are realistic in *shape* only.

## 1. Must find

| ID | Sev | Name | Location | Why |
|----|-----|------|----------|-----|
| HUNT-01 | Critical | Service-role key exposed to the browser | `lib/supabase.ts` (imported by `app/page.tsx` `"use client"`) | Service-role client in a module reachable from a client component; key bypasses RLS |
| HUNT-02 | Critical | Secret key committed in tracked `.env.local` | `.env.local` (includes `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`, `sk_live_…`) | Tracked env file with real-shaped secrets + `NEXT_PUBLIC_` secret |
| HUNT-03 | Critical | RLS disabled on `public.notes` | `migrations/0001_notes.sql` | Public-schema table, full grants, no `enable row level security` |
| HUNT-04 | High | Missing authentication on notes API | `app/api/notes/route.ts` GET | Unauthenticated list of all notes |
| HUNT-05 | High | IDOR + SQLi on note fetch | `app/api/notes/[id]/route.ts` → `lib/db.ts` | No auth; id interpolated into raw SQL via service-role client |
| HUNT-06 | High | IDOR / BOLA on document fetch | `app/api/documents/[id]/route.ts` GET | Authenticated but no ownership predicate; table policy is `USING (true)` |
| HUNT-07 | High | Broken function-level authorization (admin route) | `app/api/admin/users/route.ts` | No role check; service-role client; enumerates all users |
| HUNT-08 | High | SQL injection in raw query helpers | `lib/db.ts` `searchNotes` / `findNoteById` | Template-literal SQL with request-derived input (root cause of HUNT-05's sink) |
| HUNT-09 | High | Stripe webhook without signature verification | `app/api/webhooks/stripe/route.ts` | Accepts forged events that activate paid plans |
| HUNT-10 | High | Stored XSS via unsanitized `dangerouslySetInnerHTML` | `app/page.tsx` | User bio rendered as HTML with no sanitizer |
| HUNT-11 | High | RLS policy `USING (true)` on documents | `migrations/0002_documents.sql` | Any authenticated user reads all rows; insert `with check (true)` |
| HUNT-12 | High | Privilege escalation via `user_metadata` RLS policy | `migrations/0003_admin_audit.sql` | Policy trusts user-writable `user_metadata.is_admin` |
| HUNT-13 | High | SECURITY DEFINER function dumps table via RPC | `migrations/0004_functions.sql` `get_all_profiles` | Unfiltered definer function, execute granted by default |
| HUNT-14 | High | Mass assignment + client-trusted ownership in server action | `app/actions.ts` `updateProfile` | Spreads attacker JSON into update; trusts form-supplied `userId` |
| HUNT-15 | Medium | SSRF: server fetches caller-supplied URL | `app/api/fetch-preview/route.ts` | No scheme/host validation |
| HUNT-16 | Low | Missing security headers | `next.config.js` | No HSTS / nosniff / frame protection for an app with sessions |

Grouping is allowed per the report rules (e.g., HUNT-05+HUNT-08 as one SQLi
finding if root-caused together; HUNT-01+HUNT-02 as one secret-exposure
finding). Missing groups must still cover all rows.

## 2. Must NOT flag (false-positive traps)

| Item | Location | Why it's secure |
|------|----------|-----------------|
| Anon key in `.env.local` as `NEXT_PUBLIC_SUPABASE_ANON_KEY` | `.env.local` | Publishable key by design (the finding is the *service-role* lines, not this one) |
| `.env.example` placeholders | `.env.example` | Fake placeholders |
| Secure profile endpoint | `app/api/profile/route.ts` | `getUser()` + `.eq("id", user.id)` + explicit columns |
| Public health endpoint | `app/api/health/route.ts` | Intentionally public, no secrets/data |
| Sanitized HTML component | `app/components/SafeHtml.tsx` | DOMPurify with allowlist |
| Parameterized/builder queries | `lib/queries.ts` | `.eq()` / `.ilike()` with bound values |
| Server-only admin client | `lib/supabase-server.ts` | `import "server-only"`, env-read key, not client-imported *by itself* (note: `page.tsx` imports the *other* file) |
| Stripe webhook with `constructEvent` | `app/api/webhooks/stripe-secure/route.ts` | Raw body + signature verified |
| Secure RLS migration | `migrations/0005_secure_projects.sql` | `auth.uid()` policies + `WITH CHECK` + scoped storage policy |
| Secure definer function | `migrations/0004_functions.sql` `current_user_document` | Filters by `auth.uid()`, pins `search_path`, revokes anon |
| Middleware matcher limited to `/dashboard` | `middleware.ts` | Context for endpoint findings; not a standalone vuln |
| `isomorphic-dompurify` / `stripe` deps | `package.json` | No known-critical CVE asserted without an audit run |

## 3. Optional / informational (nice to find, not required)

- `searchNotes` in `lib/db.ts` is defined but not called by a route — SQLi root cause still real via `findNoteById` usage.
- `NEXT_PUBLIC_` prefix on a secret-shaped name in `.env.local` is part of HUNT-02.
- No rate limiting on webhook or auth routes (no auth routes exist here) — mention in coverage if noticed.

## How this fixture is used

1. Point HUNT at `test-app/` as if it were a user project.
2. Compare the produced report against this file.
3. Every HUNT-xx must appear as Confirmed (or Suspected only if the agent
   genuinely could not trace it — investigate reference gaps if so).
4. No false positives from section 2.
5. If something is missed or mis-flagged, improve the reference docs and rerun.
