# Access Control & IDOR (Broken Object/Function-Level Authorization)

Covers OWASP A01:2021 and API Security Top 10 API1 (BOLA), API3 (property-level authz / mass assignment / excessive data exposure), API5 (BFLA). This is the highest-yield domain for SaaS apps.

## Core principle

Every request that reads, updates, or deletes an object must check that the **authenticated caller owns that object or has an explicit permission to it**. The check must use server-derived identity (session/JWT), never a client-supplied user id.

## 1. Missing authentication on an endpoint

**Vulnerable** — no identity check at all:

```ts
// app/api/notes/route.ts
export async function GET(request: Request) {
  const supabase = createClient(); // anon client
  const { data } = await supabase.from("notes").select("*");
  return Response.json(data);
}
```

**Secure:**

```ts
export async function GET(request: Request) {
  const supabase = await createServerClient(); // reads session cookie
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  const { data } = await supabase.from("notes").select("*"); // RLS scopes rows
  return Response.json(data);
}
```

**Detection:** every `route.ts`, `pages/api/*`, server action, and Express/Fastify handler — does it establish identity before touching data? With Supabase, `getUser()` (server-verified) is the check; a bare anon client with no user is not.

**Note:** `getUser()` vs `getSession()`: `getSession()` reads the (possibly client-writable) session cookie without server verification. On the server, prefer `getUser()` which verifies with the auth server. Flag sole reliance on `getSession()` in security-sensitive paths as Suspected (High), not Confirmed, unless you can show a concrete bypass.

## 2. IDOR / BOLA — authenticated but no ownership check

The classic SaaS bug: endpoint checks "is logged in?" then fetches by client-supplied id.

**Vulnerable:**

```ts
// app/api/documents/[id]/route.ts
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const supabase = await createServerClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });

  const { id } = await params;
  // BUG: no .eq("user_id", user.id) and (with Supabase) RLS must also enforce it
  const { data } = await supabase.from("documents").select("*").eq("id", id).single();
  return Response.json(data);
}
```

**Secure (defense in depth — app check AND RLS):**

```ts
const { data } = await supabase
  .from("documents").select("*")
  .eq("id", id).eq("user_id", user.id).single();
// Plus an RLS policy: using ((select auth.uid()) = user_id) — see references/04-database.md
```

**Detection pattern:** handler reads `params.id` / `req.query.id` / body id → queries by that id → no ownership predicate (`.eq("user_id", …)`, `where userId = …`, policy check) in code AND no RLS policy covering the table. With Supabase, check both layers (see Phase 4 note in SKILL.md).

**Same bug in other shapes:**

```ts
// Server action — trusts client-supplied userId (attacker swaps it)
export async function deleteNote(formData: FormData) {
  const id = formData.get("id");
  const owner = formData.get("userId"); // ATTACKER CONTROLLED
  await supabase.from("notes").delete().eq("id", id).eq("user_id", owner);
}

// Express
app.get("/api/orders/:id", async (req, res) => {
  const order = await db.order.findUnique({ where: { id: req.params.id } });
  res.json(order); // no owner check
});
```

## 3. Broken function-level authorization (BFLA) — admin endpoints open to everyone

**Vulnerable:**

```ts
// app/api/admin/users/route.ts
export async function GET() {
  const supabase = await createAdminClient(); // service role!
  const { data } = await supabase.from("users").select("*");
  return Response.json(data); // no role check
}
```

**Secure:**

```ts
export async function GET() {
  const supabase = await createServerClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  const { data: roleRow } = await supabase
    .from("user_roles").select("role").eq("user_id", user.id).single();
  if (roleRow?.role !== "admin") return new Response("Forbidden", { status: 403 });
  // ...then list users
}
```

**Detection:**
- Paths matching `admin`, `internal`, `debug`, `metrics`, `staff`, `impersonate` without a server-side role check
- Role read from `user_metadata` in the JWT or from the request body (user-editable!) instead of a server-controlled table or `app_metadata`
- Hidden only in the UI (conditional render) with no server check
- Method asymmetry: GET protected, DELETE/PUT on the same path not protected

## 4. Mass assignment — client controls privileged fields

**Vulnerable:**

```ts
export async function PATCH(req: Request) {
  const body = await req.json(); // { name, bio, role: "admin" }
  await supabase.from("profiles").update(body).eq("id", userId);
}
```

**Secure:**

```ts
const body = await req.json();
const { name, bio } = body; // explicit allowlist
await supabase.from("profiles").update({ name, bio }).eq("id", user.id);
// or zod: schema.omit({ role: true, id: true }).parse(body)
```

**Detection:** spread of `req.body` / `formData` wholesale into `.update()`, `.insert()`, `Object.assign`, Prisma `.update({ data: body })`. Ask: does the table have privileged columns (`role`, `is_admin`, `email_verified`, `balance`, `approved`) a user shouldn't write? If yes and the body is spread → High/Critical.

## 5. Excessive data exposure

**Vulnerable:**

```ts
const { data } = await supabase.from("profiles").select("*"); // includes password_hash? internal notes?
return Response.json(data);
```

**Secure:** select explicit columns, or map to a DTO before returning.

**Detection:** `select("*")` on tables with sensitive columns (`*_hash`, `ssn`, `internal_*`, `role`, `stripe_customer_id`); returning full ORM records to the client; Server Components passing full DB rows as props to Client Components (props are serialized into the browser payload).

## Verification steps

1. For a suspected IDOR: describe the two-account test — user A creates a record; user B requests the same id. 200 + data = confirmed BOLA. (Only run this live on authorized staging.)
2. Confirm the DB layer: read RLS policies for the table (see references/04-database.md). App-layer check without RLS = partial protection only.
3. For BFLA: confirm the role source is server-controlled. `user_metadata` or request body = spoofable.
4. For mass assignment: list privileged columns on the table; if any exist and input isn't allowlisted, confirmed.

## What NOT to flag

- Endpoints that intentionally return public data (blog posts published, public profiles by design) — verify the schema suggests intentional public reads
- Multi-tenant apps where a shared org id IS the ownership check — verify membership is validated, then it's fine
- An ownership `.eq()` in code when RLS is also enabled — that's correct defense in depth
