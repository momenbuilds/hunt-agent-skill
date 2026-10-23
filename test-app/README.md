# HUNT Drill App — intentionally vulnerable + secure fixtures

This is a **static code fixture**, not a runnable app. It exists so the HUNT
skill can be tested: an auditor should flag every item in
[`expected-findings.md`](./expected-findings.md) and must NOT flag the secure
examples.

All keys, URLs, and data here are **fake**. The `.env.local` secret is a
realistic-looking placeholder for drill purposes only.

## Structure

```
app/api/...        Route handlers (vulnerable + secure pairs)
app/actions.ts     Server action with mass assignment + IDOR
app/page.tsx       Stored XSS via dangerouslySetInnerHTML
lib/               Shared clients/queries (secret leak + SQLi + secure versions)
migrations/        Supabase SQL: RLS mistakes + one correct migration
```

See `expected-findings.md` for the ground-truth list.
