# SECURITY_REPORT.md template

Use this structure for the final report. Fill every section; write "None" rather than dropping a section. The "Checks" table has exactly one row per check, 01 through 30 in order, including N/A and not-yet-reviewed ones. (Exception: for a targeted request, list only the checks in scope and add the line "Other checks not reviewed. Ask for a full pre-launch audit to cover them.") Don't merge checks into one row (e.g. "14/04") or replace the table with a findings list: the person reads this table to see coverage at a glance. Findings go in their own section below it.

```markdown
# Security Report: <App name>

_Date: <YYYY-MM-DD> · Branch/commit: <...> · Scope: <repo path, environments tested>_

## Summary
| Checks run | Passed | Fixed & re-tested | Open | Needs your action | N/A |
|---|---|---|---|---|---|
| 30 | n | n | n | n | n |

<3–5 plain-English sentences: overall state, the most serious problems found, whether it is safe to launch and what must happen first.>

## Checks
| # | Check | Severity | Status | Evidence | Notes |
|---|---|---|---|---|---|
| 01 | Set up proper authentication | CRITICAL | Fixed & re-tested | `tests/security/auth.test.js` (14 endpoints → 401) | requireUser() added to all API routes |
| 02 | Hide API keys | CRITICAL | ... | ... | ... |
| 03 | Secure my database | CRITICAL | | | |
| 04 | Enforce HTTPS | HIGH | | | |
| 05 | Hash passwords | CRITICAL | | | |
| 06 | Validate forms server-side | HIGH | | | |
| 07 | Protect against XSS | HIGH | | | |
| 08 | Log and monitor suspicious activity | MEDIUM | | | |
| 09 | Lock down admin routes | CRITICAL | | | |
| 10 | Use parameterized queries | CRITICAL | | | |
| 11 | Check environment variables | CRITICAL | | | |
| 12 | Add rate limiting | HIGH | | | |
| 13 | Restrict CORS | MEDIUM | | | |
| 14 | Add security headers | MEDIUM | | | |
| 15 | Secure session cookies | HIGH | | | |
| 16 | Add CSRF protection | HIGH | | | |
| 17 | Make password-reset links expire | HIGH | | | |
| 18 | Restrict file upload types and sizes | HIGH | | | |
| 19 | Verify prices and payments | CRITICAL | | | |
| 20 | Disable production debug mode | HIGH | | | |
| 21 | Update vulnerable dependencies | HIGH | | | |
| 22 | Remove unused packages | MEDIUM | | | |
| 23 | Check for exposed files | CRITICAL | | | |
| 24 | Scan Git history for leaked secrets | CRITICAL | | | |
| 25 | Revoke and replace compromised keys | CRITICAL | | | |
| 26 | Thorough security review | REVIEW | | `SECURITY_REVIEW.md` | |
| 27 | Test the protections | VERIFY | | `<test command>`: n passed / n failed | |
| 28 | Encrypt sensitive data | HIGH | | | |
| 29 | Trim API responses | HIGH | | | |
| 30 | Add bot protection | MEDIUM | | | |
| B1–B7 | Bonus checks (list those that applied) | | | | |

Status values: **Passed** (was already fine, evidence shows it) · **Fixed & re-tested** · **Open: <next step>** · **Needs your action** · **N/A: <reason>**.
Evidence is a test name, a command and its result, or file:line. "Written, not executed" if a test couldn't run.

## Findings and fixes
For each finding, most severe first:
### F1 <Title> (CRITICAL)
- **What was wrong:** <plain English + how an attacker would use it>
- **Where:** `path/file.js:42`
- **Fix:** <what changed> (files: ...)
- **Proof:** <test name / command> → <result>

## Open items
| Item | Risk | Why it's open | Exact next step |
|---|---|---|---|

## Manual actions only you can do
Ordered by urgency. Key rotations first.
- [ ] Rotate <KEY_NAME> (exposed in <where>): <dashboard path> → create new → update <env locations> → redeploy → revoke old → confirm old returns 401
- [ ] Enable GitHub secret scanning + push protection: Settings → Code security
- [ ] Set spending caps on <provider>
- [ ] Turn on MFA for <services>
- [ ] ...

## How to run the security tests
<exact commands, e.g. `npm install && npm test`>
Recommendation: run these in CI on every push (example workflow snippet if useful).

## Limits of this review
AI-assisted reviews can miss issues and tests only prove what they test. <List anything not verifiable from code.> If the app handles payments, health data, children's data or many users, get a professional penetration test before launch.
```

**A good report has:** every check listed (including N/A) · evidence for every "Passed" · specific next steps for open items · a clear manual-actions list.

**Never produce:** "Everything looks secure!" without evidence · tests deleted or weakened to pass · findings with no file, line or endpoint · Critical items quietly marked N/A.
