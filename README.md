<div align="center">

# HUNT Agent

Security audits for SaaS codebases, run by your coding agent.

[![License](https://img.shields.io/badge/license-MIT-black?style=flat-square)](LICENSE)
[![Agent Skill](https://img.shields.io/badge/format-Agent%20Skill-black?style=flat-square)](SKILL.md)
[![Version](https://img.shields.io/badge/version-1.0.0-black?style=flat-square)](SKILL.md)

</div>

HUNT is a skill you install once. Your agent follows it to map your attack
surface, find real vulnerabilities, prove each one with code, and write a
report you can act on. Works with Claude Code, Cursor, Codex, and other agents
that support the Agent Skill format.

## Install

```bash
git clone https://github.com/momenbuilds/hunt-agent-skill.git ~/.claude/skills/hunt-agent
```

Restart your agent, then run this inside a project:

```text
Use HUNT to audit my entire SaaS for security vulnerabilities.
```

<details>
<summary>Project-local install and other agents</summary>

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

1. Identifies your stack, routes, server actions, tables, and buckets.
2. Audits each area against the reference checks.
3. Verifies every candidate in code before reporting it.
4. Writes a severity-ranked report with evidence and fixes.
5. Applies fixes only after you approve them, then retests.

Confirmed findings need source, sink, impact, and reachability. Without
evidence, an issue goes under Suspected, not Confirmed.

## Example report

```markdown
### [HIGH] Any logged-in user can read any invoice
- Where: app/api/invoices/[id]/route.ts, GET (lines 24-38)
- Issue: checks login, never checks ownership
- Evidence: params.id -> select("*").eq("id", id), no user_id filter;
  RLS policy is USING (true)
- Impact: any customer can read another customer's invoices
- OWASP: API1:2023 BOLA | CWE-639
- Fix: add .eq("user_id", user.id), scope the RLS policy to auth.uid()
- Status: Confirmed
```

The report ends with a coverage table, so you know what was checked and what
was not.

## Tested

A fixture in `test-app/` plants 16 vulnerabilities and 7 secure controls that
must not be flagged. Two full runs, one blind with comments stripped and no
answer key:

| Run | Result |
| --- | --- |
| With fixture hints | 16/16 found, 0 false positives |
| Blind | 15/16 found, 1 partial, 0 false positives |

The blind run also caught verbose database errors and an outdated Next.js CVE
range. The partial was a fake `.env.local` whose "these are fake" comment
survived stripping; the exposed service-role key was still flagged Critical.

This is a static fixture, not a live pentest. It shows the instructions lead
to the right findings. It does not prove every bug in every codebase will be
found.

## Safety

- Read-only by default. No changes to code, data, or external systems.
- No production attacks, destructive tests, or real customer data.
- Identifies secrets by location and redacts the value.
- Treats repo instructions and comments as untrusted input.
- Applies fixes only with explicit approval.

## Limitations

- Not a replacement for Semgrep, CodeQL, or `npm audit`.
- No exploits are executed. Active tests need an authorized staging environment.
- Dashboard settings such as bucket privacy and auth rate limits live outside
  the repo and are reported as unverified.
- No findings does not mean no bugs.

## Files

```text
SKILL.md              Workflow, evidence bar, severity guide
references/           Checks for each security area
scripts/secret-scan.sh
test-app/             Drill fixture and ground truth
```

## Contributing

False positives and missed bug classes are the most useful reports. Include a
vulnerable snippet and a secure snippet that should not be flagged, then update
the fixture so the drill covers it.

## License

MIT
