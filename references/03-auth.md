# Authentication & Sessions

Covers OWASP A07:2021 and API Security Top 10 API2. Focus on how the app proves identity and manages sessions. If the app uses a managed provider (Supabase Auth, Auth.js, Clerk), audit the app's *usage* of it, not the provider's internals.

## 1. Verifying identity on the server

**Rule:** server code must verify identity with the provider's server-side check.

| Provider | Server-verified check | Weaker check (flag sole reliance) |
|---|---|---|
| Supabase | `supabase.auth.getUser()` | `getSession()` alone, reading `Authorization` header and decoding JWT manually |
| Auth.js | `auth()` / `getServerSession` | Reading the session cookie without verification |
| Custom JWT | `jwt.verify(token, secret, { algorithms: ["HS256"] })` | `jwt.decode(token)` — NO signature check |

**Vulnerable (custom JWT decode without verify):**

```ts
const payload = jwt.decode(token); // trusts attacker-controlled claims!
if (payload.role === "admin") { /* ... */ }
```

**Vulnerable (Supabase — trusting client-sent identity):**

```ts
const userId = req.headers.get("x-user-id"); // attacker-controlled header
```

**Secure:** derive user from `getUser()` or verified JWT only; never from custom headers, body fields, or unverified cookies.

## 2. JWT handling issues

Check any manual JWT code for:

- `jwt.decode` without `jwt.verify`
- `verify` missing a pinned algorithm list (`algorithms: ["HS256"]`) — alg-confusion / `none` attacks
- `ignoreExpiration: true`
- Keys taken from the token header (`jku`, `jwk`, `x5u`) or from a request header
- Missing `iss` / `aud` validation when tokens cross services
- Secrets that are short strings (< 32 bytes) or hardcoded

Supabase's own access tokens: the app should not hand-roll verification; use `getUser()`. If the app verifies Supabase JWTs manually against a hardcoded secret, flag as Suspected and check the secret's strength.

## 3. Session cookies

**Vulnerable:**

```ts
res.setHeader("Set-Cookie", `session=${token}`); // no flags
// or Next.js: cookies: { session: { httpOnly: false } }
```

**Secure:**

```ts
cookies: {
  session: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
  },
}
```

**Check:** every custom cookie write for `httpOnly` (blocks JS theft), `secure` (HTTPS only), `sameSite` (CSRF defense). Missing `httpOnly` on a session cookie = High. Missing `secure` in production = Medium.

## 4. Login and signup

Look at the login/signup handlers for:

- **Rate limiting:** no limiter on `/api/login`, `/api/signup`, OTP request/verify = Medium (High if the app is a high-value target). Check for `@upstash/ratelimit`, `ratelimit`, `slow-down`, WAF rules, or custom counters.
- **User enumeration:** different error messages or timing for "unknown email" vs "wrong password". Generic "Invalid credentials" = good.
- **Password storage:** if the app stores passwords itself (not via a provider): plaintext or fast hashes (`md5`, `sha256`, unsalted) = Critical; bcrypt cost < 10 = Medium; argon2id or bcrypt ≥ 10 = fine. If Supabase Auth/Auth.js/Clerk manages passwords, out of scope — don't flag the provider.
- **Weak password policy:** `password.length >= 1` with no other rules = Low/Medium depending on context.

## 5. Password reset / account recovery

**Vulnerable:**

```ts
const token = Math.random().toString(36); // predictable
await db.query(`UPDATE users SET password = '${newPw}' WHERE reset_token = '${token}'`); // also SQLi
if (!user) return res.status(404).json({ error: "No such user" }); // enumeration
```

**Secure:**

```ts
const token = crypto.randomBytes(32).toString("hex");
const tokenHash = sha256(token); // store only the hash
// same 200 response whether or not the email exists
// token: single-use (deleted on apply), short expiry (≤ 15–60 min), rate-limited request endpoint
```

**Check:** token randomness, single-use, expiry, identical response for unknown emails, rate limit on the request endpoint, token not logged or placed in a URL that ends up in referrer headers (prefer one-time links handled by the provider).

If Supabase Auth handles reset (`auth.resetPasswordForEmail`), the provider covers token mechanics — audit only rate limiting, CAPTCHA, and custom steps the app adds.

## 6. OAuth

**Check the callback handler for:**

- `state` parameter: generated, stored server-side, verified on callback (CSRF). Missing = High.
- `redirect_uri`: hardcoded/exact match — never echoed from the query string
- ID token verification: signature verified against provider JWKS with pinned algorithms; `iss`/`aud`/`exp` checked. `jwt.decode` on the ID token = Critical.
- Tokens not logged; tokens not placed in URLs for server-side flows
- PKCE for public clients (mobile/SPA)

Auth.js and Supabase Auth implement these correctly — flag only the app's custom wrapper code if it bypasses them.

## 7. Logout and session invalidation

**Vulnerable:** logout clears a client-side cookie/state only; refresh token still valid.

**Secure (Supabase):** `supabase.auth.signOut()` revokes server-side sessions.

**Check:** logout handler exists; it calls the provider's sign-out; changing a password or email invalidates existing sessions (provider default for Supabase — verify custom flows).

## 8. Privilege escalation

**Look for:**

- User profile update accepting `role`, `is_admin`, `plan`, `tier` (mass assignment — see references/02-access-control.md)
- RLS policies or app checks reading `user_metadata` (user-editable via `updateUser`) instead of `app_metadata` or a roles table
- Admin functions reachable without a server-side role check (BFLA — references/02-access-control.md)
- Invitation/upgrade flows that trust a client-supplied plan or seat count

## 9. Multi-factor authentication

Absence of MFA is not automatically a vulnerability for a small SaaS — report as informational/Low unless the app handles high-value actions (admin consoles, payments config) where step-up would be expected. If MFA exists, check that sensitive routes actually require `aal2` (Supabase: `(select auth.jwt()->>'aal') = 'aal2'` in policy or app check).

## Verification steps

1. Trace one login request end-to-end: where is the password/token compared? Is the identity later derived server-side?
2. For any custom JWT: list the verify options; missing `algorithms` pin or `decode`-only = confirmed.
3. For reset flows: can you show enumeration (different responses) or a predictable token in code?
4. Check cookies written anywhere: grep `Set-Cookie`, `cookies().set`, `cookies: {`.

## What NOT to flag

- Supabase/Auth.js/Clerk handling of password hashing, token signing, brute-force storage internals — that's the provider's job
- `NEXT_PUBLIC_SUPABASE_ANON_KEY` in the browser — by design
- Missing MFA on a hobby-tier app without admin surfaces — informational only
- `getSession()` usage in *non-security* UI code (showing a login button) — only flag when it's the sole gate before a sensitive server-side operation
