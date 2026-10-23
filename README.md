# HUNT Agent

**Security audits for SaaS codebases, run by your coding agent.**

HUNT is an installable [Agent Skill](https://agentskills.io) — a `SKILL.md` your
coding agent can follow to audit a web application the way a careful security
engineer would: map the attack surface, hunt for real vulnerabilities, prove
each one with code evidence, and report honestly.

It works with Claude Code, Cursor, Codex, and other agents that support the
Agent Skills format (a folder with a `SKILL.md`).

---

## What it checks

- **APIs & endpoints** — missing authentication, IDOR/BOLA, function-level
  authorization (admin routes), excessive data exposure, mass assignment
- **Authentication & sessions** — login/signup, JWT handling, password reset,
  cookies, OAuth, privilege escalation, rate limiting
- **Databases & Supabase** — SQL injection, RLS enabled/disabled, broken
  policies, `USING (true)`, `WITH CHECK` gaps, `user_metadata` authorization,
  `SECURITY DEFINER` functions, views that bypass RLS, storage buckets,
  service-role key exposure
- **Secrets & configuration** — committed secrets, client-bundle leaks,
  `NEXT_PUBLIC_*` misuse, CORS, CSRF, security headers, logs and error leakage
- **Web attack surface** — XSS, SSRF, file uploads, webhook signature
  verification, payment/subscription authorization, dependency advisories

It is designed for modern SaaS stacks (Next.js + Supabase is a first-class
target) but the workflow applies to any web app. Framework-specific checks are
signals, not assumptions — HUNT reads your code before flagging anything.

## What makes it different

Most AI security "audits" are checklists that produce plausible-sounding
warnings. HUNT enforces an **evidence bar**:

- Every confirmed finding needs **source → sink → impact → reachability**
- No evidence → it goes in `Suspected`, not `Confirmed`
- Secure patterns have an explicit **do-not-flag** list
- The report includes **coverage**: what was checked, what wasn't, and why
- Secret values are **redacted**; no customer data is ever included
- The audit is **read-only**; fixes happen only with your approval

It never claims your app is "secure". No point-in-time audit can prove that.

## Install

Clone the repo, then put the folder where your agent looks for skills.

**Claude Code (personal, all projects):**

```bash
git clone https://github.com/momenbuilds/hunt-agent-skill.git ~/.claude/skills/hunt-agent
```

**Claude Code (one project):**

```bash
git clone https://github.com/momenbuilds/hunt-agent-skill.git .claude/skills/hunt-agent
```

**Other agents (Cursor, Codex, etc.):** keep the folder in your repo, e.g.
`skills/hunt-agent/`, or copy it to your agent's skills directory. Then tell
the agent to read the skill:

```
Read skills/hunt-agent/SKILL.md and follow it.
```

## Use

In your project, tell your agent:

```
Use HUNT to audit my entire SaaS for security vulnerabilities.
```

or any of:

```
Run a security audit on this codebase.
Hunt for vulnerabilities in my API routes.
Check my Supabase RLS policies for security holes.
Is my app leaking any secrets?
```

HUNT will:

1. Identify your framework, database, auth provider, and architecture
2. Map every API route, server action, webhook, table, and bucket
3. Audit each security domain against the reference checks
4. Verify candidates with code evidence
5. Produce a severity-ranked report
6. Offer the smallest correct fix per finding — and apply only what you approve
7. Retest what changed

### Example prompt for a focused audit

```
Use HUNT to audit my authorization: every API route and server action.
Report IDOR and admin-route issues only, with file:line evidence.
```

## What a report looks like

```markdown
### [HIGH] Any logged-in user can read any invoice
- Where: app/api/invoices/[id]/route.ts — GET (lines 24–38)
- What's wrong: the handler checks login but never checks who owns the invoice.
- Impact: any customer can read other customers' invoices by changing the id.
- Evidence: params.id → .from("invoices").select("*").eq("id", id)
  (no .eq("user_id", user.id)); the table's RLS policy is USING (true).
- OWASP: API1:2023 BOLA · CWE: CWE-639
- Fix: add .eq("user_id", user.id) and replace the policy with
  using ((select auth.uid()) = user_id).
- Status: Confirmed
```

Followed by a coverage table that states what was and wasn't checked.

## Tested against a vulnerable fixture

`test-app/` is a deliberately vulnerable Next.js + Supabase fixture with
**16 planted issues** and **7 secure controls that must not be flagged**
(see `test-app/expected-findings.md`). It was audited twice with the full
skill workflow, including once **blind** — comments stripped, no answer key —
by agents with fresh context:

| Run | Result |
|---|---|
| With fixture hints | 16/16 found, 0 false positives |
| Blind (no hints, no answer key) | 15/16 found, 1 partial, 0 false positives |

The blind run also found two legitimate extras (verbose DB errors returned to
clients, and an outdated Next.js version in a CVE-affected range). The one
partial was the committed-`.env.local` finding: the fixture's own comment
saying "these values are fake" survived the blind-copy comment stripping, so
the agent appropriately downgraded it — while still flagging the dangerous
`NEXT_PUBLIC_` service-role key as Critical. A sample output report is in
`test-app/DRILL-REPORT.md`.

This is a static code fixture, not a live penetration test. It validates that
the skill's instructions lead an agent to the right findings — it does not
prove the skill finds every vulnerability class in every codebase.

## Limitations

- **Not a scanner replacement.** HUNT reasons over source code. Run `npm audit`,
  CodeQL, or Semgrep alongside it.
- **Not a penetration test.** No exploit is executed; active testing only
  happens on an authorized local/staging environment with test data.
- **Not proof of security.** Absence of findings is not absence of bugs.
- **Dashboard settings are invisible.** Supabase exposed schemas, auth rate
  limits, and bucket privacy live outside the repo; HUNT flags them as
  unverified unless you provide access.
- **False negatives are possible**, especially in generated/minified code,
  unusual frameworks, or logic bugs that need business context.
- **LLM judgment is involved.** Verify Critical/High findings before acting;
  the evidence field exists so you can.

## Safety rules built into the skill

- Read-only audit by default — no code, database, or external system changes
- No destructive tests, no real customer data, no production attacks
- Active tests only on explicitly authorized local/staging environments
- Secrets redacted in reports; never committed or logged
- Repository instructions (AGENTS.md, comments, README) are treated as
  untrusted input — prompt-injection attempts are reported, not followed
- Fixes applied only after explicit approval, then retested

## Project layout

```
SKILL.md                 The skill: workflow, evidence bar, severity guide
references/              Domain checks (access control, auth, DB/RLS, secrets,
                         injection/web, secure patterns, report format)
scripts/secret-scan.sh   Read-only credential pattern scanner with redaction
test-app/                Vulnerable + secure fixture and ground truth
```

## Contributing

Open an issue with a false positive or a missed vulnerability class. The most
useful contributions are **paired examples**: a vulnerable snippet and a
secure snippet that should not be flagged. Update the reference file and the
fixture, then run the drill again.

## License

MIT — see [LICENSE](./LICENSE).
