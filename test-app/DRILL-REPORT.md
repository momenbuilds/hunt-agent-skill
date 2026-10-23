# Security Audit — hunt-drill-app (HUNT drill run)

Date: 2026-10-23
Scope: `test-app/` static fixture, full tree
Method: HUNT skill workflow (recon → attack-surface map → domain audits → verification)

> This is a **drill report** produced by running HUNT against the fixture in
> this folder. Ground truth: [`expected-findings.md`](./expected-findings.md).

## Executive summary

This application has multiple **critical** problems that would let an
attacker take over user accounts and read or modify every customer's data
without logging in. The service-role database key (which bypasses all access
rules) is exposed to the browser and committed to the repository. Several
database tables have no working row-level security, several API routes skip
authorization entirely, a payment webhook accepts forged events, and a raw
SQL helper is injectable. Fix the three critical items and the IDOR/authz
route issues before anything else; rotate every key that was ever committed.

## Confirmed findings

### [CRITICAL] Service-role key exposed to the browser
- **Where:** `lib/supabase.ts` (`createClient` with `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`), imported by `app/page.tsx` (`"use client"`)
- **What's wrong:** A Client Component imports a module that constructs a Supabase client with the service-role key. Client Component imports are bundled and sent to every visitor's browser.
- **Impact:** Anyone can open devtools (or view the JS bundle) and extract a key that bypasses row-level security on every table — full read/write access to all user data.
- **Evidence:** Source→sink: `app/page.tsx` (line 7, `"use client"`) imports `@/lib/supabase`; `lib/supabase.ts` lines 6–9 pass `process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` into `createClient`. `NEXT_PUBLIC_*` values are inlined at build time. Reachable by: every visitor.
- **OWASP:** A01:2021 Broken Access Control · **CWE:** CWE-798
- **Fix:** Delete `lib/supabase.ts`. Browser code may only use a client created with the publishable/anon key. Keep the service-role client in a `server-only` module (`lib/supabase-server.ts` already does this correctly) and never import it from `"use client"` files.
- **Status:** Confirmed

### [CRITICAL] Secrets committed in a tracked `.env.local`
- **Where:** `.env.local` (lines 4–7)
- **What's wrong:** An environment file with real-shaped secrets (`sb_secret_…`, `sk_live_…`, plus a `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`) is present in the repository tree.
- **Impact:** Anyone with repo access (or anyone, once public) holds live credentials. Assume compromise; rotating is mandatory, not optional.
- **Evidence:** `scripts/secret-scan.sh` hits on `.env.local:4–7`. The `NEXT_PUBLIC_`-prefixed service-role line would also ship in the client bundle.
- **OWASP:** A02:2021 Cryptographic Failures · **CWE:** CWE-540
- **Fix:** Remove the file from the tree and git history (`git rm --cached`, history rewrite or rotation), add `.env*` to `.gitignore` (allowing `.env.example`), rotate every exposed key in the Supabase and Stripe dashboards, and use platform secret storage for deploys.
- **Status:** Confirmed

### [CRITICAL] RLS disabled on `public.notes`
- **Where:** `migrations/0001_notes.sql`
- **What's wrong:** The `notes` table lives in the exposed `public` schema, grants full privileges to `anon` and `authenticated`, and never enables row-level security.
- **Impact:** With only the public anon key, any visitor can `select/insert/update/delete` every note of every user through the Supabase Data API (`/rest/v1/notes`) — no app code involved.
- **Evidence:** The migration contains `grant all on table public.notes to anon, authenticated;` and no `enable row level security`. RLS-off tables in exposed schemas are directly reachable by the anon key.
- **OWASP:** API1:2023 BOLA · **CWE:** CWE-862
- **Fix:**
  ```sql
  alter table public.notes enable row level security;
  revoke all on table public.notes from anon, authenticated;
  grant select, insert, update, delete on table public.notes to authenticated;
  -- add policies using (select auth.uid()) = user_id for each command
  ```
- **Status:** Confirmed

### [HIGH] Notes list endpoint has no authentication
- **Where:** `app/api/notes/route.ts` — `GET /api/notes`
- **What's wrong:** The handler queries `notes` with the shared client and never establishes a user.
- **Impact:** Unauthenticated callers receive the contents of all notes (compounded by HUNT-03: no RLS backstop).
- **Evidence:** Handler body contains no `getUser()`/session check; `lib/supabase.ts` client is service-role (bypasses RLS even if it existed). Middleware `matcher` covers only `/dashboard`, so nothing else gates this route.
- **OWASP:** A01:2021 · **CWE:** CWE-306
- **Fix:** Authenticate with `getUser()`, return 401 when absent, query only the caller's rows (and enable RLS on the table).
- **Status:** Confirmed

### [HIGH] SQL injection + no auth on single-note fetch
- **Where:** `app/api/notes/[id]/route.ts` → `lib/db.ts` `findNoteById()`
- **What's wrong:** The route has no authentication, and the id path parameter is interpolated into a raw SQL string executed with a service-role client.
- **Impact:** Unauthenticated attackers can read arbitrary rows (or worse, depending on the RPC's privileges) via classic SQL injection payloads in the id, e.g. `' union select … --`.
- **Evidence:** Source: `params.id` (attacker-controlled URL segment). Path: `route.ts` line 11 → `findNoteById(id)` → `lib/db.ts` line 16 builds `` `SELECT * FROM notes WHERE id = '${id}'` ``. Sink: `supabase.rpc("query", { q })` executes it. No sanitization or parameterization anywhere on the path.
- **OWASP:** A03:2021 Injection · **CWE:** CWE-89
- **Fix:** Delete the raw-SQL helper. Use the query builder with bound values (see `lib/queries.ts` for the correct pattern) and enforce authentication + ownership in the route.
- **Status:** Confirmed

### [HIGH] Raw SQL helpers interpolate request-derived input
- **Where:** `lib/db.ts` — `searchNotes()`, `findNoteById()`
- **What's wrong:** Both helpers build SQL with template literals (`'${userId}'`, `'${term}%'`).
- **Impact:** Any caller-controlled value reaching these helpers is an injection point (currently reached by HUNT-05's route; `searchNotes` is a loaded gun awaiting a caller).
- **Evidence:** Lines 7 and 16 of `lib/db.ts`. Root cause of HUNT-05's sink; same fix.
- **OWASP:** A03:2021 · **CWE:** CWE-89
- **Fix:** Replace with parameterized/query-builder access (`lib/queries.ts` pattern). (Group with HUNT-05 if reporting one root-cause finding.)
- **Status:** Confirmed

### [HIGH] IDOR: authenticated users can read any document
- **Where:** `app/api/documents/[id]/route.ts` — `GET /api/documents/[id]`
- **What's wrong:** The handler verifies login (`getUser()`) but never checks that the document belongs to the caller before returning it.
- **Impact:** Any logged-in user can enumerate document ids and read every other tenant's documents. The table's own policy is `USING (true)` (HUNT-11), so the database does not stop it either.
- **Evidence:** Source: `params.id`. Check present: authentication only. Missing: `.eq("user_id", user.id)` (or equivalent). Confirmed against `migrations/0002_documents.sql`, whose select policy is `using (true)` — both layers fail.
- **OWASP:** API1:2023 BOLA · **CWE:** CWE-639
- **Fix:** Add `.eq("user_id", user.id)` to the query, and replace the table's policy with `using ((select auth.uid()) = user_id)`.
- **Status:** Confirmed

### [HIGH] Admin user list callable without any role check
- **Where:** `app/api/admin/users/route.ts` — `GET /api/admin/users`
- **What's wrong:** The route returns every user's id, email, and role using the service-role client, with no authentication or role check.
- **Impact:** Anyone can enumerate all users and their email addresses; with no auth at all, this is a full user-directory disclosure.
- **Evidence:** Handler body (lines 8–15) has no `getUser()`, no role gate, and uses `createAdminClient()` (service role, bypasses RLS). Middleware does not cover `/api`.
- **OWASP:** API5:2023 BFLA · **CWE:** CWE-862
- **Fix:** Require authentication, then verify a server-controlled admin role (roles table or `app_metadata` — not `user_metadata`) before listing; return 403 otherwise.
- **Status:** Confirmed

### [HIGH] Stripe webhook accepts forged events (no signature verification)
- **Where:** `app/api/webhooks/stripe/route.ts` — `POST /api/webhooks/stripe`
- **What's wrong:** The handler parses the JSON body and activates paid subscriptions with no `stripe-signature` verification.
- **Impact:** Anyone can POST a fabricated `checkout.session.completed` event and grant themselves (or any email) a paid plan.
- **Evidence:** Body → `req.json()` → event-type switch → `subscriptions.upsert(... plan: "pro", active: true)`. No `constructEvent`/HMAC compare anywhere on the path (contrast with the secure variant in `webhooks/stripe-secure/route.ts`).
- **OWASP:** A08:2021 · **CWE:** CWE-347
- **Fix:** Verify with `stripe.webhooks.constructEvent(rawBody, signature, process.env.STRIPE_WEBHOOK_SECRET)` as in the secure sibling route; reject with 400 on failure.
- **Status:** Confirmed

### [HIGH] Stored XSS via unsanitized `dangerouslySetInnerHTML`
- **Where:** `app/page.tsx` (line 25)
- **What's wrong:** The page loads a user-editable `bio` field and injects it as raw HTML.
- **Impact:** A user who sets their bio to a script payload executes JavaScript in every visitor's session — session theft, UI rewriting, and with the exposed keys (HUNT-01) likely full account takeover.
- **Evidence:** Source: `profiles.bio` (user-controlled via profile updates). Sink: `dangerouslySetInnerHTML={{ __html: bio }}` with no sanitizer. The repo contains the correct pattern in `app/components/SafeHtml.tsx` (DOMPurify + allowlist) but this page does not use it.
- **OWASP:** A03:2021 · **CWE:** CWE-79
- **Fix:** Render through `SafeHtml` (DOMPurify with the existing allowlist) or drop HTML rendering entirely.
- **Status:** Confirmed

### [HIGH] RLS policy `USING (true)` on documents
- **Where:** `migrations/0002_documents.sql`
- **What's wrong:** Select policy allows all authenticated users to read all rows; the insert policy has `with check (true)`; no owner-bound update/delete policies exist.
- **Impact:** Horizontal privilege escalation at the database layer — any authenticated user reads and inserts rows for any tenant directly through the Data API, independent of app code.
- **Evidence:** Policy `"anyone authenticated can read"` … `using (true)`; policy `"insert any"` … `with check (true)`.
- **OWASP:** API1:2023 · **CWE:** CWE-863
- **Fix:** Bind all policies to `(select auth.uid()) = user_id`, add `with check` on writes, revoke unnecessary grants.
- **Status:** Confirmed

### [HIGH] Privilege escalation through `user_metadata` in an RLS policy
- **Where:** `migrations/0003_admin_audit.sql`
- **What's wrong:** The audit-log policy trusts `auth.jwt()->'user_metadata'->>'is_admin'`. Users can write `user_metadata` themselves via `auth.updateUser`.
- **Impact:** Any user sets `{"is_admin": true}` in their metadata and gains read access to the admin audit log (and any future policies copying this pattern).
- **Evidence:** Policy qual references `user_metadata` (user-writable), not `app_metadata` or a roles table. Matches Supabase's own linter rule for this exact mistake.
- **OWASP:** A01:2021 · **CWE:** CWE-639
- **Fix:** Authorize against `app_metadata` (backend-writable only) or a server-controlled `user_roles` table joined by `auth.uid()`.
- **Status:** Confirmed

### [HIGH] SECURITY DEFINER function exposes full table via RPC
- **Where:** `migrations/0004_functions.sql` — `get_all_profiles()`
- **What's wrong:** A `security definer` function returns every row of `profiles` with no `auth.uid()` filter. Nothing revokes execute; default grants make it callable by `anon` and `authenticated` at `/rest/v1/rpc/get_all_profiles`.
- **Impact:** Unauthenticated data dump of the profiles table, bypassing RLS (definer functions run as the owner).
- **Evidence:** Function body is `select * from public.profiles;` with `security definer` and no execute revocation in the file. The same file contains a correctly written definer function (`current_user_document`) proving the pattern is known — this one just wasn't written that way.
- **OWASP:** A01:2021 · **CWE:** CWE-200
- **Fix:** Filter by `(select auth.uid())`, pin `set search_path = ''`, `revoke execute … from public, anon`, grant only to `authenticated` — as done for `current_user_document` in the same file.
- **Status:** Confirmed

### [HIGH] Server action: mass assignment + client-trusted ownership
- **Where:** `app/actions.ts` — `updateProfile()`
- **What's wrong:** The action trusts a form-supplied `userId` as the row to update and spreads attacker-controlled JSON directly into the update.
- **Impact:** Any caller can overwrite any user's profile and set privileged columns (e.g. `role: "admin"`) — account takeover / privilege escalation. Server Actions are POST endpoints callable directly, bypassing the UI.
- **Evidence:** Source: `formData.get("userId")` and `JSON.parse(formData.get("profile"))`. Sink: `.update(body).eq("id", userId)`. No `getUser()`, no field allowlist. `profiles` has a `role` column (visible in the admin route's select).
- **OWASP:** API3:2023 mass assignment + API1 BOLA · **CWE:** CWE-915
- **Fix:** Derive the user from `getUser()`; allowlist columns (`display_name`, `avatar_url`, …) with a schema (zod `.omit({ role: true, id: true })`); never accept `userId` from the client.
- **Status:** Confirmed

### [MEDIUM] SSRF: server fetches caller-supplied URL
- **Where:** `app/api/fetch-preview/route.ts` — `POST /api/fetch-preview`
- **What's wrong:** The `url` field from the request body is passed straight to `fetch()` with no scheme or host validation.
- **Impact:** An attacker can make the server request internal services or cloud metadata endpoints (`http://169.254.169.254/…`) and read up to 5 KB of the response. Reachability of internal targets depends on deployment network — unauthenticated either way.
- **Evidence:** Source: `req.json().url`. Sink: `await fetch(url)`; response text returned to caller. No allowlist, no private-IP block, no https enforcement.
- **OWASP:** A10:2021 · **CWE:** CWE-918
- **Fix:** Restrict to `https:`, resolve and reject private/link-local/metadata addresses, prefer a fixed host allowlist, disable or re-validate redirects, and add a timeout.
- **Status:** Confirmed (internal reachability depends on deployment; the code defect is certain)

### [LOW] Missing security headers
- **Where:** `next.config.js`
- **What's wrong:** No `Strict-Transport-Security`, `X-Content-Type-Options`, or frame protection configured for an app that uses sessions.
- **Impact:** Weakened defenses against clickjacking, MIME sniffing, and downgrade attacks. Not directly exploitable alone.
- **Evidence:** `next.config.js` contains no `headers()` configuration; no header middleware present.
- **OWASP:** A05:2021 · **CWE:** CWE-693
- **Fix:** Add HSTS, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: SAMEORIGIN` (or CSP `frame-ancestors`) via `headers()` in `next.config.js`.
- **Status:** Confirmed

## Suspected findings

None. Every candidate above was fully traced in code.

## Could not complete

| Check | Reason |
|---|---|
| Live Data API probe (anon-key `GET /rest/v1/notes`) | No running Supabase project; static fixture only |
| Dependency CVE audit (`npm audit`) | No lockfile / npm install in fixture |
| Production client-bundle inspection | No built assets; exposure proven by import-graph tracing instead |

## Coverage

| Area | Status | Notes |
|---|---|---|
| API route handlers | Checked (10/10) | 8 issues found across 6 routes |
| Server actions | Checked (1) | Mass assignment found |
| Supabase RLS (5 tables) | Checked | notes: RLS off; documents: true-policy; admin_audit_log: metadata policy; projects: clean; profiles: policies not in fixture (app-layer only) |
| SECURITY DEFINER / RPC | Checked (2 functions) | 1 vulnerable, 1 secure |
| Storage policies | Checked (1) | Secure example only |
| Secrets / env | Checked | Scanner + manual verification |
| XSS sinks | Checked | 1 vulnerable, 1 secure |
| Webhooks | Checked (2) | 1 vulnerable, 1 secure |
| SSRF sinks | Checked | 1 vulnerable |
| Payments logic | Partial | Webhook verified; no checkout route in fixture |
| Dependencies | Not run | No lockfile |
| Rate limiting | Not applicable | No auth endpoints in fixture |
| Headers/config | Checked | Missing headers (Low) |

## Recommended order of fixes

1. Rotate all committed keys; remove `.env.local` from the repo (HUNT-01, HUNT-02)
2. Remove service-role client from browser graph (HUNT-01)
3. Enable RLS on `notes`; fix `documents` policies; fix metadata policy; lock down `get_all_profiles` (HUNT-03, HUNT-11, HUNT-12, HUNT-13)
4. Delete raw-SQL helpers; parameterize (HUNT-05, HUNT-08)
5. Add authn/authz to notes, documents, admin routes (HUNT-04, HUNT-06, HUNT-07)
6. Verify Stripe webhook signatures (HUNT-09)
7. Sanitize HTML rendering (HUNT-10)
8. Fix `updateProfile` allowlist (HUNT-14)
9. SSRF URL validation (HUNT-15)
10. Security headers (HUNT-16)

## Notes

- No production systems were contacted; no customer data was accessed. This was a static code review of the fixture.
- False-positive traps in this fixture (secure profile route, health endpoint, DOMPurify component, builder queries, secure webhook, secure migration, secure definer function, anon key usage) were reviewed and intentionally **not** flagged.
- This audit is point-in-time and cannot prove the absence of other vulnerabilities.
