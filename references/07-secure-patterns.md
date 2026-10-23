# Secure Patterns — What NOT to Flag

False positives destroy trust in a security report. Before filing any finding, check this list. If the code matches a secure pattern here (in spirit, not just by keyword), it is not a finding.

## Access control

| Do not flag | Why it's fine |
|---|---|
| `supabase.from("docs").select().eq("id", id).eq("user_id", user.id)` with matching RLS policy | Correct defense in depth |
| Ownership check in code when RLS also enforces it | Both layers are correct |
| A shared `org_id` predicate where membership was validated server-side | Org scoping IS the ownership model |
| Public reads of intentionally public data (published posts, public profiles, status pages) | By design; verify writes are still protected |
| `getUser()` returning null → 401 before data access | Correct unauthenticated handling |
| Admin check reading a server-controlled `roles` table | Server-controlled = trustworthy |
| Admin check reading `app_metadata` role claim | `app_metadata` is backend-writable only (Supabase) |

## Authentication

| Do not flag | Why it's fine |
|---|---|
| Password hashing done by Supabase Auth / Auth.js / Clerk | Provider's responsibility |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` / publishable key in client code | Designed to be public |
| Stripe `pk_live_...` / `pk_test_...` publishable keys in client code | Designed to be public |
| Google Maps browser key restricted by HTTP referrer | Standard pattern |
| `getSession()` used only to toggle UI (show login button) | Not a security gate |
| Missing MFA on a small app with no admin/payments config surfaces | Informational at most |

## Database & Supabase

| Do not flag | Why it's fine |
|---|---|
| Parameterized raw SQL (`$1` placeholders, Prisma tagged templates) | Correct |
| Query builders (`.eq()`, Drizzle, Knex without `.raw`) | Correct |
| RLS enabled + policies bound to `auth.uid()` with `WITH CHECK` | Correct |
| `service_role` used in migration scripts, seeders, background jobs with their own authz | Server-only by nature |
| Extension-owned tables (PostGIS `spatial_ref_sys`) lacking RLS | Cannot enable RLS; known advisor false positive |
| Views/functions in `auth`, `storage`, `realtime`, `graphql` schemas | Supabase internals |
| RLS enabled with no policies (deny-all) when the app doesn't use that table via API | Safe default, not a vulnerability (note as observation) |

## Secrets & config

| Do not flag | Why it's fine |
|---|---|
| Placeholder values in `.env.example`, `.env.sample`, docs (`your-key-here`, `sk_test_xxx`) | Not real secrets |
| `.env.local` present on disk but correctly gitignored | Normal local development |
| `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SITE_URL`, other non-secret public config | Intentionally public |
| Test-fixture JWTs with obviously fake payloads | Not credentials |
| Same-origin API responses with no CORS headers | Default = same-origin only = safe |

## Injection & web

| Do not flag | Why it's fine |
|---|---|
| `dangerouslySetInnerHTML` with DOMPurify/sanitize-html + explicit allowlist | Sanitized correctly |
| React `{userInput}` interpolation | Auto-escaped |
| `JSON.parse` of untrusted input followed by schema validation (zod, etc.) | Standard pattern |
| Outbound `fetch` to hardcoded provider URLs (api.stripe.com, api.openai.com) | No user-controlled URL |
| Stripe webhook using `constructEvent(rawBody, sig, secret)` | Correct verification |
| Server Actions relying on Next.js same-origin checks **plus** in-action authz | Framework + app both correct |
| Relative-path redirect validation (`startsWith("/") && !startsWith("//")`) | Blocks open redirects |

## Process notes

- One secure control does not excuse a missing one elsewhere. An endpoint with a perfect ownership check still needs the table's RLS enabled when the Supabase anon key exists.
- "It's only in dev" — if the file is in the repo and would ship in a prod build, it counts. Note environment context in severity, don't drop the finding.
- When unsure, downgrade to **Suspected** with an explicit question, rather than guessing in either direction.
