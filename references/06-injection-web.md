# Injection, XSS, SSRF, Uploads, Webhooks & Payments

Covers OWASP A03 (injection/XSS), A08 (integrity — webhooks/deserialization), A10 (SSRF), API10 (unsafe third-party consumption), and payment authorization.

## 1. Cross-site scripting (XSS)

React escapes `{userInput}` by default — that is safe. Flag only explicit HTML sinks or URL attributes fed untrusted data.

**Vulnerable:**

```tsx
<div dangerouslySetInnerHTML={{ __html: userContent }} />        // stored XSS
<div dangerouslySetInnerHTML={{ __html: comment }} />            // comment from DB
element.innerHTML = searchParams.get("q") ?? "";                 // DOM XSS
<a href={userProvidedUrl}>click</a>                              // javascript: URL
```

**Secure:**

```tsx
import DOMPurify from "isomorphic-dompurify";
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent, { ALLOWED_TAGS: ["b", "i", "em", "strong", "p", "br"] }) }} />
```

**Detection:** `rg "dangerouslySetInnerHTML|innerHTML|outerHTML|insertAdjacentHTML|document\.write"`. For each hit, trace the value: DB/user input unsanitized = High (stored) / Medium (reflected). Sanitized with a real library + allowlist = not a finding. Also check `href={x}` / `src={x}` with user data (scheme allowlist `https:`).

Server-rendered HTML with string interpolation (`res.send(\`<h1>${name}</h1>\`)`) = same class.

## 2. SSRF — server fetching user-supplied URLs

**Vulnerable:**

```ts
export async function POST(req: Request) {
  const { url } = await req.json();
  const res = await fetch(url); // attacker points at 169.254.169.254 or internal services
  return new Response(await res.text());
}
```

**Secure:**

```ts
const parsed = new URL(url);
if (parsed.protocol !== "https:") throw new Error("only https");
// Resolve and check the IP: block loopback, RFC1918, link-local, metadata
// Prefer an allowlist of hosts; disable or re-validate redirects
```

**Detection:** `fetch(`, `axios.get`, `got(`, `request(` where the URL argument traces to request input, a user-stored webhook URL fetched server-side, or an "import from URL" feature. Fixed integrations (`https://api.stripe.com/...`) are fine.

**What NOT to flag:** outbound calls to hardcoded provider URLs; image optimization config (`images.remotePatterns`) with fixed hosts.

## 3. Open redirects

```ts
// VULNERABLE
return redirect(searchParams.get("next") ?? "/");
// SECURE
const next = searchParams.get("next");
return redirect(next && next.startsWith("/") && !next.startsWith("//") ? next : "/");
```

Detection: `redirect(`, `router.push(`, `Location:` headers with request-derived values. Relative-path validation or allowlist = fine.

## 4. Command injection & code injection

```ts
// VULNERABLE
exec(`convert ${userFilename} out.png`);      // child_process
eval(req.body.expression);
new Function(userCode)();
await import(dynamicSpecifier);               // specifier from input
```

Any of these with request-derived input = Critical (RCE). Grep `child_process|exec(|execSync|spawn(.*shell|eval(|new Function|vm\.`.

## 5. Unsafe deserialization

```ts
// VULNERABLE
unserialize(cookieValue);
const obj = nodeSerialize.unserialize(userInput);
yaml.load(input);          // unsafe YAML with custom tags
// SECURE
JSON.parse(input) + schema validation (zod);
yaml.load(input, { schema: CORE_SCHEMA }); // or safeLoad
```

JSON.parse alone is not a finding.

## 6. File uploads

**Vulnerable:**

```ts
const file = formData.get("file") as File;
const buf = Buffer.from(await file.arrayBuffer());
await fs.writeFile(`uploads/${file.name}`, buf); // path traversal + no type/size checks
```

**Secure checklist:**
- Size cap enforced server-side
- Extension + content-type allowlist (and/or magic-byte sniff)
- Random storage name (UUID) — never the client filename for the path
- Stored outside the web root or in private storage (Supabase private bucket) served via signed URL / `Content-Disposition: attachment`
- Re-encode images (e.g., sharp) if user content must render inline

Missing type validation + user-controlled filename = High. Missing size cap only = Medium.

## 7. Webhooks — signature verification is mandatory

**Vulnerable (Stripe):**

```ts
export async function POST(req: Request) {
  const event = await req.json(); // NO verification — anyone can POST fake events
  if (event.type === "checkout.session.completed") {
    await activateSubscription(event.data.object.customer);
  }
  return Response.json({ received: true });
}
```

**Secure:**

```ts
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
const payload = await req.text(); // RAW body
const sig = req.headers.get("stripe-signature");
try {
  const event = stripe.webhooks.constructEvent(
    payload, sig!, process.env.STRIPE_WEBHOOK_SECRET!
  );
  // optional: if (await alreadyProcessed(event.id)) return ...
  switch (event.type) { /* handle */ }
} catch {
  return new Response("Invalid signature", { status: 400 });
}
```

**Check every webhook handler for:**
1. Signature verification against a secret from env (Stripe `constructEvent` on the **raw body**, Svix, GitHub HMAC `x-hub-signature-256`, etc.)
2. Raw body — re-serializing parsed JSON breaks HMAC verification (if you see `constructEvent(JSON.stringify(...))`, flag it: verification will fail or was copy-pasted wrong)
3. Only the expected event types handled; unknown types acknowledged but ignored
4. Event id dedupe/idempotency for state-changing events
5. CSRF exempt only because the signature check runs first — otherwise the route must be protected like any endpoint

Missing verification on a webhook that changes state (subscription status, credits, access) = High/Critical.

## 8. Payments & subscriptions

Beyond webhooks, check:

- **Price/amount from the client?** Server must recompute price from its own catalog. `const { price } = await req.json(); await charge(price)` = Critical business-logic flaw.
- **Plan/tier updates** only via verified webhook, not a client-callable endpoint (`POST /api/upgrade` that just sets `plan = "pro"` without going through Stripe = Critical).
- **Checkout success without webhook verification:** client says "I paid" and server grants access = Critical. Access must derive from webhook-verified state.
- **Coupon/quota logic** trusting client-supplied counts.

## 9. Unsafe consumption of third-party APIs

- `http://` (non-TLS) calls to partner APIs = Medium
- No timeout on outbound calls (`AbortSignal.timeout(...)`) = Low/Medium (availability)
- Third-party response fields written to DB or rendered as HTML without validation (poisoned-upstream injection) = Medium/High depending on sink
- Blindly following redirects on outbound fetches when fetching user-influenced URLs (SSRF via redirect)

## 10. Mass assignment reminder

Object spreads into DB writes are covered in `references/02-access-control.md` §4 — don't duplicate the finding; cross-reference.

## Verification steps

1. XSS: for each `dangerouslySetInnerHTML`, name the value's origin and whether a sanitizer runs. Origin = DB/user and no sanitizer = Confirmed.
2. SSRF: draw the taint path from request field to `fetch`. If none exists (URL is hardcoded), drop it.
3. Webhook: show the handler code with no `constructEvent` / HMAC compare before the state change. Confirmed High. If verification exists but uses re-serialized JSON, Confirmed (broken verification).
4. Payments: find where the granted entitlement is set; trace what event triggers it. Client-controlled = Confirmed Critical.

## What NOT to flag

- `dangerouslySetInnerHTML` with DOMPurify/sanitize-html + allowlist
- React's default `{variable}` escaping
- Fixed outbound API calls to known providers
- Webhook handlers that verify signatures correctly on the raw body
- JSON.parse of untrusted input with schema validation
- Public file downloads from an allowlisted set of static assets
