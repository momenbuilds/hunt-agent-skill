<div align="center">

# HUNT Agent

Find real security bugs in your SaaS. Every finding comes with code evidence.

[![License](https://img.shields.io/badge/license-MIT-black?style=flat-square)](LICENSE)
[![Agent Skill](https://img.shields.io/badge/format-Agent%20Skill-black?style=flat-square)](SKILL.md)
[![Version](https://img.shields.io/badge/version-1.0.0-black?style=flat-square)](SKILL.md)

[Install](#install) · [What it checks](#what-it-checks) · [How it works](#how-it-works) · [Example](#example-finding) · [Tested](#tested) · [FAQ](#faq)

</div>

An installable agent skill for security audits. HUNT maps your attack surface,
checks each area for real vulnerabilities, and reports only what it can prove
from your code. Works with Claude Code, Cursor, Codex, and any agent that can
read a `SKILL.md`.

## Install

```bash
git clone https://github.com/momenbuilds/hunt-agent-skill.git ~/.claude/skills/hunt-agent
```

Restart your agent, then run inside a project:

```text
Use HUNT to audit my entire SaaS for security vulnerabilities.
```

<details>
<summary><strong>Project-local install and other agents</strong></summary>

Claude Code, per project:

```bash
git clone https://github.com/momenbuilds/hunt-agent-skill.git .claude/skills/hunt-agent
```

Cursor, Codex, or any other agent: place the folder anywhere in the repo, for
example `skills/hunt-agent/`, and point the agent at it:

```text
Read skills/hunt-agent/SKILL.md and follow it.
```

</details>

## What it checks

| Area | Examples |
| --- | --- |
| API endpoints | Missing auth, IDOR, admin route exposure, mass assignment |
| Auth and sessions | JWT handling, password reset, cookies, OAuth, rate limits |
| Database and Supabase | SQL injection, RLS gaps, unsafe policies, SECURITY DEFINER, service-role leaks |
| Secrets and config | Committed keys, client bundle leaks, CORS, CSRF, headers, error leakage |
| Web surface | XSS, SSRF, uploads, webhook signatures, payment authorization |

## How it works

1. Maps the stack: routes, server actions, webhooks, tables, storage buckets.
2. Audits each area against the checks in `references/`.
3. Verifies each candidate in code and drops anything it cannot prove.
4. Reports severity, location, impact, and a concrete fix.
5. Applies approved fixes and retests them.

A confirmed finding needs a source, a sink, a reachable path, and an impact.
Without evidence, it is listed as Suspected or not reported.

## Example finding

```markdown
### [HIGH] Any logged-in user can read any document
- Where: app/api/documents/[id]/route.ts, GET (lines 26-30)
- Issue: checks login, never checks ownership
- Evidence: params.id -> .from("documents").select("*").eq("id", id);
  the RLS policy is USING (true)
- Impact: any customer can read another customer's documents
- OWASP: API1:2023 BOLA | CWE-639
- Status: Confirmed
```

The fix is one predicate on the query and one on the policy:

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

Each report ends with a coverage table: what was checked, what was not, and why.

## Tested

`test-app/` plants 16 vulnerabilities and 7 secure controls that must not be
flagged. Two full runs, one blind with comments stripped and no answer key:

| Run | Result |
| --- | --- |
| With fixture hints | 16/16 found, 0 false positives |
| Blind | 15/16 found, 1 partial, 0 false positives |

The blind run also caught verbose database errors and a Next.js version in a
CVE-affected range. The one partial was a fake `.env.local` whose "these are
fake" comment survived stripping. The exposed service-role key in it was still
flagged Critical.

Ground truth is in [`test-app/expected-findings.md`](test-app/expected-findings.md).
A full sample report is in [`test-app/DRILL-REPORT.md`](test-app/DRILL-REPORT.md).

This is a static fixture, not a live pentest. It shows that the instructions
lead to the right findings. It cannot prove every bug in every codebase will
be found.

## FAQ

<details>
<summary><strong>Is this a scanner replacement?</strong></summary>

No. HUNT reads code and reasons about data flow. Run Semgrep, CodeQL, or
`npm audit` alongside it.

</details>

<details>
<summary><strong>Does it change my code or data?</strong></summary>

No by default. The audit is read-only, sends no traffic to your app, and redacts
secret values. Fixes are applied only after you approve them. Active tests need
an authorized staging environment.

</details>

<details>
<summary><strong>Which agents does it work with?</strong></summary>

Claude Code, Cursor, Codex, and any agent that can read a `SKILL.md`. Agent
Skill support and install paths vary by client.

</details>

<details>
<summary><strong>Does it need database or dashboard access?</strong></summary>

No. It audits migrations, policies, and application code. Settings it cannot
see, such as bucket privacy and auth rate limits, are reported as unverified
instead of guessed.

</details>

<details>
<summary><strong>What if a finding is wrong?</strong></summary>

Ask the agent to re-check that finding against the source-to-sink path. Every
finding carries its evidence, so a bad assumption is easy to spot before you
change code.

</details>

## Safety

- Read-only by default. No changes to code, data, or external systems.
- No production attacks, destructive tests, or real customer data.
- Secrets are reported by location, with the value redacted.
- Repo instructions and comments are treated as untrusted input.
- Fixes only with explicit approval.

## Limitations

- Not a replacement for Semgrep, CodeQL, or `npm audit`.
- No exploits are executed. Active tests need an authorized staging environment.
- Dashboard-only settings are reported as unverified.
- No findings does not mean no bugs.

## Contributing

False positives and missed bug classes are the most useful reports. Include a
vulnerable snippet and a secure snippet that should not be flagged, then add
the pair to the fixture so the drill covers it.

## License

MIT
