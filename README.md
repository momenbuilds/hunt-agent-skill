<div align="center">

<img src="assets/icon.svg" width="96" alt="HUNT">

# HUNT

**Find real security bugs in your SaaS.**<br>
Every finding comes with code evidence.

An agent skill for Claude Code, Cursor, Codex, and any agent that reads a `SKILL.md`.

[Install](#install) | [What it finds](#what-it-finds) | [Example](#example) | [Tested](#tested)

</div>

## Install

```bash
git clone https://github.com/momenbuilds/hunt-agent-skill.git ~/.claude/skills/hunt-agent
```

Restart your agent, then run this in a project:

```text
Use HUNT to audit my entire SaaS for security vulnerabilities.
```

<details>
<summary>Cursor, Codex, or project-local install</summary>

Claude Code, per project:

```bash
git clone https://github.com/momenbuilds/hunt-agent-skill.git .claude/skills/hunt-agent
```

Any other agent: place the folder in the repo, for example `skills/hunt-agent/`,
then point the agent at it:

```text
Read skills/hunt-agent/SKILL.md and follow it.
```

</details>

## What it finds

| Area | Checks |
| --- | --- |
| Access control | Missing auth, IDOR, admin route exposure, mass assignment |
| Auth | JWT, cookies, reset flows, OAuth, rate limits |
| Database | SQL injection, RLS gaps, unsafe policies, SECURITY DEFINER, key leaks |
| Config | Committed secrets, client bundle leaks, CORS, CSRF, headers |
| Web | XSS, SSRF, uploads, webhook signatures, payment checks |

## Example

A finding from the drill fixture:

```markdown
### [HIGH] Any logged-in user can read any document
- Where: app/api/documents/[id]/route.ts, GET (lines 26-30)
- Issue: checks login, never checks ownership
- Evidence: params.id -> .from("documents").select("*").eq("id", id);
  the RLS policy is USING (true)
- Impact: any customer can read another customer's documents
- OWASP: API1:2023 BOLA | CWE: CWE-639
- Status: Confirmed
```

The fix, in the query and in the policy:

```diff
- const { data } = await supabase.from("documents").select("*").eq("id", id)
+ const { data } = await supabase.from("documents").select("*")
+   .eq("id", id).eq("user_id", user.id)
```

```diff
- create policy "anyone authenticated can read" on public.documents
-   for select using (true);
+ create policy "read own documents" on public.documents
+   for select using ((select auth.uid()) = user_id);
```

No evidence, no finding. Anything that cannot be proven goes under Suspected,
and every report ends with a coverage table.

## Tested

16 planted bugs, 9 secure controls that must not be flagged.

| Run | Result |
| --- | --- |
| With hints | 16/16 found, 0 false positives |
| Blind | 15/16 found, 1 partial, 0 false positives |

The one partial was a fake `.env.local` whose "these are fake" comment survived
stripping; the service-role key in it was still flagged Critical.

Ground truth: [`test-app/expected-findings.md`](test-app/expected-findings.md).
Sample report: [`test-app/DRILL-REPORT.md`](test-app/DRILL-REPORT.md).

This is a static fixture, not a live pentest. It shows the instructions lead to
the right findings. It does not prove every bug in every codebase will be found.

## Rules

- Read-only by default. No changes to code, data, or external systems.
- No production attacks, destructive tests, or real customer data.
- Secrets are reported by location; values are redacted.
- Repo instructions are data, not commands.
- Fixes only after you approve them.

## Limits

- Not a replacement for Semgrep, CodeQL, or `npm audit`.
- No exploits are executed. Active tests need an authorized staging environment.
- Dashboard settings are reported as unverified.
- No findings does not mean no bugs.

## License

MIT. Issues and PRs welcome.
