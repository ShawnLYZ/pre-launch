# pre-launch

**A security pass for your finished app, before real users (and attackers) show up.**

`pre-launch` is an [Agent Skill](https://agentskills.io) for Claude Code, Codex, Cursor and other coding agents. It makes your agent act like a senior application security engineer. The agent maps your app, finds the gaps, fixes them in the code and proves each fix with "try to break it" tests. It then hands you a `SECURITY_REPORT.md` you can trust.

It is built for apps made fast, often with AI tools like Lovable, Bolt, v0, Cursor, Replit, Codex or Claude Code. Those apps usually *work*. What they're missing are the protections you can't see, because nothing looks broken when a protection is absent.

```bash
npx skills add ShawnLYZ/pre-launch
```

Then ask your agent something like: *"Make sure nobody can hack my app before I launch."*

---

## Contents

- [What it does](#what-it-does)
- [Install](#install)
- [Usage](#usage)
- [The 27 checks](#the-27-checks)
- [How it works](#how-it-works)
- [What you get](#what-you-get)
- [Helper scripts](#helper-scripts)
- [Ground rules the agent follows](#ground-rules-the-agent-follows)
- [Test results](#test-results)
- [Repository layout](#repository-layout)
- [Limits](#limits)
- [Contributing](#contributing)
- [License](#license)

---

## What it does

- **Covers all 27 checks:** authentication, hidden API keys, database rules, HTTPS, password hashing, server-side validation, XSS, logging, admin routes, parameterized queries, environment variables, rate limiting, CORS, security headers, session cookies, CSRF, password-reset expiry, file uploads, prices and payments, debug mode, vulnerable and unused dependencies, exposed files, secrets in Git history, key rotation, a full attacker-style review, and testing.
- **Fixes the riskiest things first.** The "priority eight" cause most stolen data, drained API credits and surprise bills in AI-built apps.
- **Changes the code**, not just a list of advice. Every fix is small and aimed at the root cause.
- **Proves each fix** with automated tests: a signed-out visitor, user A, user B and an admin, all trying to break in.
- **Never prints your secrets.** Any key it finds is masked to its first 4 characters.
- **Lists what only you can do**, with click-by-click steps. That covers key rotation, dashboard settings, Supabase and Firebase rules, Stripe, and spending caps.
- **Is honest about coverage.** Every check gets a row in the report: Passed, Fixed & re-tested, Open, Needs your action or N/A, each with evidence.

## Install

### Any agent: `skills` command (recommended)

```bash
npx skills add ShawnLYZ/pre-launch
```

This uses the open [`skills`](https://github.com/vercel-labs/skills) command. It finds `skills/pre-launch/SKILL.md` in this repo and installs it for the agents you choose (Claude Code, Codex, Cursor and others). Useful options:

```bash
npx skills add ShawnLYZ/pre-launch -g              # install for your user, in every project
npx skills add ShawnLYZ/pre-launch -a claude-code  # install for one specific agent
```

### Claude Code plugin

Run inside Claude Code:

```
/plugin marketplace add ShawnLYZ/pre-launch
/plugin install pre-launch@pre-launch
```

### Codex plugin

```bash
codex plugin marketplace add ShawnLYZ/pre-launch
```

Then open `/plugins` in Codex and install **Pre-Launch Security**.

### Manual install

Copy the `skills/pre-launch` folder into your agent's skills directory:

| Agent | Per project | For every project |
|---|---|---|
| Claude Code | `.claude/skills/pre-launch/` | `~/.claude/skills/pre-launch/` |
| Codex and other agents | `.agents/skills/pre-launch/` | `~/.agents/skills/pre-launch/` |

```bash
git clone https://github.com/ShawnLYZ/pre-launch.git
cp -r pre-launch/skills/pre-launch ~/.claude/skills/
```

**Requirements:** a coding agent that supports skills, and Python 3.8 or newer for the helper scripts, which use only the standard library. Optional extras: [gitleaks](https://github.com/gitleaks/gitleaks) or [trufflehog](https://github.com/trufflesecurity/trufflehog) make the Git-history secret scan more thorough, and the skill uses them automatically if they're installed.

## Usage

Open your project in your agent and describe what you want in plain words. The skill starts on its own when you ask for things like these:

- "Make sure nobody can hack my app before I post it on Product Hunt."
- "Is my app safe to launch? I'm worried about the OpenAI key and the Supabase stuff."
- "Run a full security audit of this repo and give me a report of findings and fixes."
- "Harden my Flask API before I deploy: auth, rate limiting, CORS, headers, secrets, all of it."
- "I think I committed my `.env` at some point. Check the Git history and fix anything dangerous."
- "Pre-launch security pass, please."

In Claude Code you can also call it directly with `/pre-launch`.

**Short on time?** Say so, for example *"we launch in 2 days, just the essentials"*. The agent then does the map, the red flags and the priority eight, and tests and reports only those. Every other check is marked "Open: not yet reviewed", so the report never pretends to cover more than it did.

**It's the wrong tool for** fixing one isolated bug, changing a single endpoint, or explaining a security concept. Just ask your agent normally for those.

## The 27 checks

| # | Check | Severity |
|---|---|---|
| 01 | Set up proper authentication (server-side) | Critical |
| 02 | Hide API keys (nothing secret in front-end code) | Critical |
| 03 | Secure the database (RLS, security rules, no IDOR) | Critical |
| 04 | Enforce HTTPS (redirects, HSTS) | High |
| 05 | Hash passwords (bcrypt, argon2) | Critical |
| 06 | Validate forms server-side | High |
| 07 | Protect against XSS | High |
| 08 | Log and monitor suspicious activity | Medium |
| 09 | Lock down admin routes | Critical |
| 10 | Use parameterized queries | Critical |
| 11 | Check environment variables | Critical |
| 12 | Add rate limiting | High |
| 13 | Restrict CORS | Medium |
| 14 | Add security headers (CSP, frame, nosniff...) | Medium |
| 15 | Secure session cookies (HttpOnly, Secure, SameSite) | High |
| 16 | Add CSRF protection | High |
| 17 | Make password-reset links expire (single use) | High |
| 18 | Restrict file upload types and sizes | High |
| 19 | Verify prices and payments on the server (webhooks) | Critical |
| 20 | Disable production debug mode | High |
| 21 | Update vulnerable dependencies | High |
| 22 | Remove unused packages | Medium |
| 23 | Check for exposed files (`/.env`, `/.git`, dumps, source maps) | Critical |
| 24 | Scan Git history for leaked secrets | Critical |
| 25 | Revoke and replace compromised keys | Critical |
| 26 | Thorough security review (business logic, multi-tenant, SSRF...) | Review |
| 27 | Test the protections and report | Verify |

**Bonus checks**, applied when your app has the matching feature:

- B1: AI and LLM features (prompt injection, usage limits)
- B2: SSRF
- B3: Backups
- B4: Securing your own accounts (MFA)
- B5: Spending caps
- B6: Privacy
- B7: Email domain (SPF, DKIM, DMARC)

An incident-response playbook is also included.

## How it works

```
Phase 0  Map         Read the code, write SECURITY_MAP.md, run the scanners,
                     flag red flags, report the top 5 concerns. Nothing is changed yet.
Phase 1  Priority 8  02 API keys → 11 Env vars → 24 Git history → 25 Rotate keys
                     → 03 Database → 01 Auth → 09 Admin routes → 19 Payments
Phase 2  The rest    All remaining checks 01–25: audit → fix → note how to verify
Phase 3  Review      Attacker-style pass for what checklists miss → SECURITY_REVIEW.md
Phase 4  Test        Try-to-break-it tests, run until green → SECURITY_REPORT.md
```

**Red flags.** If the agent finds any of these, it stops and fixes them first:

- A secret key in front-end code
- Supabase or Firebase with no RLS or security rules
- Changing an ID in a URL shows someone else's data
- An admin page "protected" only by hiding its link
- A price trusted from the browser
- A committed or downloadable `.env`
- An AI endpoint with no login or usage limit
- Stack traces visible on the live site

**Before it edits anything,** the agent makes a way back: a new branch (`security/pre-launch`) or a commit. If your project isn't under Git yet, it offers to set that up first.

**On large codebases,** the audit can be split across parallel subagents, one per area. The fixes and the final review stay with the main agent, so changes remain consistent.

## What you get

The agent leaves these files in your project:

| File | What's in it |
|---|---|
| `SECURITY_MAP.md` | Your stack, data, auth, every entry point, third-party services, environment variable names (never values) and risky features |
| `SECURITY_REVIEW.md` | The attacker-style review: business logic, tenant isolation, SSRF, open redirects, prompt injection |
| `SECURITY_REPORT.md` | Summary counts, one row for each check 01–27 with status and evidence, findings with file:line and proof, open items, your manual-actions checklist, and how to run the tests |
| Security tests | Automated "try to break it" tests in your existing test framework, or a minimal setup if you have none (Jest or Vitest with supertest, pytest...) |
| Code fixes | Small, reviewable changes, preferably one shared helper per concern (`requireUser()`, `requireAdmin()`, one validator, one `logSecurityEvent()`) |

It also ends with a short chat summary:

- headline counts
- the most serious fixes
- what you still need to do yourself, key rotations first
- where the files are

## Helper scripts

These live in `skills/pre-launch/scripts/`. They need only Python 3.8+ (standard library) and are safe to run yourself:

```bash
# Risky code patterns with file:line, grouped by check number
python skills/pre-launch/scripts/scan_code.py ./my-app

# Secret-looking strings (masked) in the working tree, full Git history and a build folder
python skills/pre-launch/scripts/scan_secrets.py ./my-app --history --build ./my-app/dist

# Read-only probe of YOUR OWN deployed site: HTTPS redirect, headers, CORS, ~35 exposed paths
python skills/pre-launch/scripts/check_live.py https://your-domain.com --api-path /api/health
```

| Script | Checks it supports |
|---|---|
| `scan_code.py` | 02, 05, 07, 10, 11, 13, 19, 20 |
| `scan_secrets.py` | 02, 11, 24, 25 |
| `check_live.py` | 04, 13, 14, 20, 23 |

Script output is a list of leads, not verdicts. The agent confirms each hit by reading the code. It also looks for what patterns can't catch, like missing auth checks, IDOR and webhook logic.

## Ground rules the agent follows

- **Never prints secret values.** It names keys by variable and masks any value it finds (`sk_l****`), and it never asks you to paste a secret into chat.
- **Checkpoints first.** It works on a branch or after a commit, and never commits or pushes for you unless you ask.
- **Audits before fixing.** It fixes Critical and High issues with the smallest safe change at the root cause.
- **Asks before changes your users would notice**, such as logging everyone out, stricter cookies, new rate limits or changing a flow. If you aren't around, it lists them under "Needs your decision".
- **Never weakens anything to make progress:** no disabled protections, no deleted or loosened tests, no `// TODO: secure later`.
- **Checks new packages.** For each one it adds, it names it, says why, and confirms it's the real package on the official registry. AI tools sometimes invent package names, and attackers register them.
- **Tests safely:** only against localhost or staging with test accounts. Live probes are read-only and only against your own domain.
- **Is honest.** "Everything looks secure!" without evidence is not allowed. Anything it couldn't verify is labelled as such.

## Test results

The skill was built with Anthropic's `skill-creator` process. Each sample app was run twice by the same model, once with the skill and once without:

| Test app | With skill | Without skill |
|---|---|---|
| Express + vanilla JS app with a leaked key, IDOR, client-side prices and a committed `.env` | 12/12 checks passed, 41 security tests | 10/12, 19 tests (no per-check report; printed a secret in its output) |
| Flask notes app, casual "lock it down" request | 12/12, 30 tests | 11/12, 15 tests (no report file) |
| Same Express app, "short on time" mode | 7/7, 18 tests | 7/7, 5 tests |

The skill's main value is deeper testing, a complete per-check report and careful handling of secrets. Runs with the skill take longer (about 2×), because they test much more.

In a trigger test, the skill started for 10 out of 10 prompts asking for a whole-app security pass. It stayed off for 10 out of 10 similar requests that weren't, such as one bug, one endpoint, explaining a concept, or a PR review.

## Repository layout

```
.
├── skills/
│   └── pre-launch/
│       ├── SKILL.md                    # Main workflow (what the agent reads first)
│       ├── references/                 # Detailed guidance, loaded only when needed
│       │   ├── identity-access.md          # 01, 05, 09, 15, 17
│       │   ├── secrets-keys.md             # 02, 11, 24, 25
│       │   ├── data-inputs.md              # 03, 06, 07, 10, 18, 19
│       │   ├── network-browser.md          # 04, 12, 13, 14, 16
│       │   ├── deployment-supply-chain.md  # 20, 21, 22, 23
│       │   ├── monitoring-review-testing.md# 08, 26, 27 + test list
│       │   ├── bonus-checks.md             # B1–B7, incident response
│       │   └── report-template.md          # SECURITY_REPORT.md template
│       └── scripts/
│           ├── scan_code.py
│           ├── scan_secrets.py
│           └── check_live.py
├── .claude-plugin/
│   ├── plugin.json                     # Claude Code plugin manifest
│   └── marketplace.json                # Lets Claude Code add this repo as a marketplace
├── .codex-plugin/
│   └── plugin.json                     # Codex plugin manifest
├── .agents/plugins/
│   └── marketplace.json                # Lets Codex add this repo as a marketplace
├── LICENSE                             # Apache-2.0
└── README.md
```

Each check in the reference files has five parts: **audit** (what to look for), **fix**, **verify**, **done when**, and **watch out** (stack-specific traps for Next.js, Supabase, Firebase, Express, Django, Flask, FastAPI, Stripe and others).

## Limits

- **AI reviews can miss things.** Tests prove only what they test. If your app handles payments, health data, children's data or many users, get a professional penetration test as well.
- **Some fixes happen outside your code.** Rotating keys, hosting and DNS settings, database consoles, Stripe and GitHub settings all need you. The skill gives exact steps, but it can't click them for you.
- **It only probes systems you own.** The live checks are read-only and meant for your own domain. Don't point them at sites you don't control.

## Contributing

Issues and pull requests are welcome, for example:

- new stack-specific traps
- better scanner patterns, with fewer false positives
- fixes to wording that confused your agent

Please keep the helper scripts dependency-free (standard library only), and never commit real secrets, even in test fixtures.

## License

[Apache License 2.0](LICENSE)
