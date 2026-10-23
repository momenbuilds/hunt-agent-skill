# Secrets & Configuration

Covers OWASP A02 (cryptographic failures — exposure side), A05 (misconfiguration), and secret leakage. Run `scripts/secret-scan.sh` from the skill root (or `rg` with the patterns below) as the first pass, then manually verify every hit.

## 1. Hardcoded secrets in source

**Patterns to search:**

```
sk_live_  sk_test_           Stripe secret keys
sb_secret_  sb_publishable_  Supabase new-format keys
SUPABASE_SERVICE_ROLE  service_role  serviceRoleKey
eyJ[A-Za-z0-9_-]{10,}\.       JWT-shaped literals (verify before flagging — could be a test fixture)
AKIA[0-9A-Z]{16}              AWS access keys
ghp_  gho_  github_pat_       GitHub tokens
xox[baprs]-                   Slack tokens
AIza[0-9A-Za-z_-]{35}         Google API keys
-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----
postgres(ql)?://[^:]+:[^@]+@   DB URLs with embedded passwords
password\s*=\s*["']
```

**Vulnerable:**

```ts
const stripe = new Stripe("sk_live_REDACTED-FOR-DOCS-ONLY"); // in app code
```

**Secure:** `const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)` — with the var defined only in server env (not `.env` committed, not `NEXT_PUBLIC_`).

**Handling:** a hardcoded live key = Critical (assume compromised; recommend rotation). Test keys (`sk_test_`, dummy placeholders in `.env.example`) = not a finding unless committed alongside real-looking values. JWT literals in tests/fixtures: verify they're fake (no valid signature/issuer) before flagging.

## 2. Secrets in client-reachable code — Critical

Anything imported by a `"use client"` file, or any file in a client component's import graph, ships to the browser.

**Vulnerable:**

```ts
// lib/supabase.ts — imported by Client Components!
import { createClient } from "@supabase/supabase-js";
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!, // BUNDLED TO BROWSER
);
```

**Secure:**

```ts
// lib/supabase-client.ts ("use client" safe)
import { createBrowserClient } from "@supabase/ssr";
export const supabase = createBrowserClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, // publishable by design
);

// lib/supabase-server.ts — imported only by route handlers/actions
import "server-only";
import { createServerClient } from "@supabase/ssr";
export async function createSupabaseServerClient() {
  return createServerClient(url, process.env.SUPABASE_SECRET_KEY!, { /* cookies */ });
}
```

**Detection:**

- `service_role`, `serviceRoleKey`, `SUPABASE_SECRET`, `sb_secret_` in any file that a client component imports or that lacks server-only guards
- Trace imports: open each `"use client"` file, follow its imports at least one level
- Next.js: anything named `NEXT_PUBLIC_*` is inlined into the browser bundle — a secret with that prefix is Critical even if only referenced in server code

## 3. Environment variable misconfigurations

**Check:**

| Pattern | Verdict |
|---|---|
| `.env` or `.env.local` tracked in git (`git ls-files \| grep env`) | High — contains or once contained secrets; rotate + remove from history |
| `.env.example` with placeholder values (`sk_test_xxx`, `your-key-here`) | Fine |
| `NEXT_PUBLIC_*` name containing `SECRET`, `TOKEN`, `KEY`, `PRIVATE`, `PASSWORD` | Critical — verify value isn't actually sensitive |
| Secrets documented in README with real values | Critical |
| Same secret committed in multiple files | High — rotation must cover all copies |

**What NOT to flag:** `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` / `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, `NEXT_PUBLIC_SITE_URL`, publishable Stripe keys (`pk_...`), Stripe `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` — all intentionally public.

## 4. Secrets in logs and errors

**Vulnerable:**

```ts
console.log("auth header:", req.headers.authorization);
console.log("login attempt", email, password);
console.log(process.env); // dumps everything
res.status(500).json({ error: err.stack, env: process.env });
```

**Secure:** log event names + non-sensitive ids (`{ event: "login.failed", userId, ip }`); return generic 500s in production; error tracking (Sentry) configured with beforeSend scrubbing.

**Detection:** `console.log`/`logger` statements near auth, payment, or webhook code that print headers, bodies, or env. Error handlers that serialize the error object wholesale in production paths.

## 5. CORS

**Vulnerable:**

```ts
// Reflects any origin — plus credentials = any site can make authenticated calls
res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
res.setHeader("Access-Control-Allow-Credentials", "true");
// or config: Access-Control-Allow-Origin: * with credentials (invalid but revealing intent)
```

**Secure:**

```ts
const allowed = new Set(["https://app.example.com"]);
const origin = req.headers.origin;
if (origin && allowed.has(origin)) {
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");
}
```

**What NOT to flag:** default Next.js same-origin behavior (no CORS headers = same-origin only = fine); `*` on a genuinely public, read-only, cookie-less API.

## 6. CSRF

Next.js Server Actions get framework-level same-origin checks; Route Handlers with cookie auth do **not** automatically.

**Vulnerable:** cookie-authenticated state-changing Route Handler with no CSRF token, no origin check, and `SameSite=None` (or missing sameSite in a custom cookie).

**Secure:** `SameSite=Lax`/`Strict` cookies + origin check on mutations, or double-submit CSRF tokens, or Bearer-token auth (no cookies → no classic CSRF). Signature-verified webhooks (Stripe) are exempt.

**Detection:** for each cookie-auth POST/PATCH/PUT/DELETE handler: is there a token or origin check? SameSite=Lax + POST-only forms is decent but flag missing origin checks on JSON APIs called with cookies as Low/Medium depending on cookie config.

## 7. Security headers

Check `next.config.*` `headers()` or middleware for:

| Header | Recommendation |
|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` in production |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` / `frame-ancestors` | `SAMEORIGIN` or CSP `frame-ancestors 'none'` |
| `Content-Security-Policy` | Start with a report; tighten to nonce-based. Missing CSP on an app with user content = Medium (pairs with XSS) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |

Missing headers on an app with sessions = Low/Medium (one grouped finding, not ten). Don't nitpick a static blog.

## 8. Dependency vulnerabilities

If a package manager lockfile exists and tools are available, run (read-only):

```
npm audit --production
pnpm audit --prod
yarn npm audit --production
pip-audit
```

Report High/Critical advisories with the package@version and whether the vulnerable code path is imported. If tools aren't available, list "dependencies not audited" in the coverage section — do not invent CVEs.

## 9. Debug and admin surfaces in production

- Routes like `/api/debug`, `/api/dev`, `/__inspect`, `/metrics`, `/actuator` without auth
- `DEBUG=next:*` or `NODE_ENV !== "production"` checks that branch into verbose output — verify what ships in the prod build
- Swagger/OpenAPI UI on the public prod host without auth

## Verification steps

1. Run `scripts/secret-scan.sh .` (or equivalent `rg`). For each hit: is it a placeholder/test value or real-looking? Is the file client-reachable?
2. For suspected client-bundled secrets: trace the import graph from every `"use client"` file. Confirmed if a secret-bearing module is reachable.
3. `git ls-files | rg -i '\.env'` — any tracked env file with real values = Confirmed High.
4. For CORS: find every `Access-Control-Allow-Origin`; confirm whether the origin is reflected from the request and whether credentials are allowed.
5. Headers: read `next.config` / middleware; missing HSTS+nosniff+frame protection on a session app = single Low/Medium finding.

## What NOT to flag

- Publishable/anon keys in client code (Supabase anon, Stripe `pk_`, Google Maps browser keys with HTTP referrer restrictions — note referrer-restricted keys as fine)
- Placeholder values in `.env.example` / `.env.sample` / docs
- `.env` files that are correctly gitignored (verify with `git check-ignore` / `git ls-files`, not just filesystem presence)
- Test fixture JWTs that are clearly fake (check payload isn't signed/valid)
