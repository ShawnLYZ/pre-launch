# Monitoring, Review & Testing: checks 08, 26, 27

Contents: [08 Logging & monitoring](#08-log-and-monitor-suspicious-activity) · [26 Thorough review](#26-run-a-thorough-security-review) · [27 Test & report](#27-test-the-protections-and-report)

---

## 08 Log and monitor suspicious activity
**MEDIUM.** If something bad happens, you find out in minutes, not months. Logs are a security camera, but logs containing passwords or tokens become a breach of their own.

**Audit**
1. Current logging: what, where (console, Vercel/Netlify logs, Sentry, Datadog, Axiom, Better Stack...), retention, who can read it.
2. Any log line or error report containing passwords, tokens, session IDs, API keys, reset links, card numbers, or full request bodies with personal data?

**Fix**
1. Structured (JSON) security events through one small helper, e.g. `logSecurityEvent(event, details)`. Events: login success/failure, logout, sign-up, password change, reset requested/completed, email change, MFA changes, permission denied (401/403), admin actions and role changes, rate-limit hits (429), payment and webhook events (incl. signature failures), file uploads, API key creation, unexpected 5xx.
2. Each event: UTC timestamp, event name, user ID (if known), IP, user agent, request ID, outcome. Put the request ID in error responses so a user report maps to a log line.
3. Redact passwords, tokens, cookies, Authorization headers, API keys, card data everywhere, including the error tracker's scrubbing config. Strip newlines from user-supplied values before logging (log injection).
4. Alerts (or exact setup steps in their provider) for: >10 failed logins per account or IP in 5 min; spikes in 401/403/429/5xx; any new admin or role change; webhook signature failures.
5. Recommend retention and restrict log access to the team.

**Deliver:** a one-page `SECURITY_RUNBOOK.md`: where logs are, how to search one user's activity, what each alert means, first three things to do when one fires.

**Watch out:** log IDs, not full profiles (privacy). Serverless console logs vanish quickly on some hosts; ship them to a log service with retention.

---

## 26 Run a thorough security review
**REVIEW.** One full pass across the whole app, like an attacker. Each check looks at one area; this catches what checklists miss, especially business-logic flaws unique to this app (e.g. an "invite a teammate" endpoint that lets anyone add themselves to any team by guessing its ID).

Don't change code during the review itself; write the report, then fix.

**Phase 1 Map the attack surface:** use `SECURITY_MAP.md`; summarise stack, hosting, data and sensitivity, roles, every entry point, third parties, and trust boundaries (what the browser controls vs. what the server decides).

**Phase 2 Review each area**, listing what you checked and what you found:
1. Auth: server checks on every endpoint, sessions, password reset, OAuth/redirects, admin MFA.
2. Access control: IDOR on every ID-based endpoint, admin routes, multi-tenant/team isolation, role changes.
3. Secrets: client bundle, env vars, Git history, logs, exposed files.
4. Data: RLS/rules, least privilege, sensitive fields in responses, backups.
5. Inputs: validation, mass assignment, SQL/NoSQL/command injection, XSS (incl. AI output), open redirects, SSRF in anything that fetches a URL, email header injection.
6. Files: upload type/size/content, storage privacy, serving.
7. Payments: server-side pricing, webhook verification, idempotency, entitlements, coupons, race conditions.
8. Network: HTTPS/HSTS, CORS, headers, cookies, CSRF, rate limiting (esp. paid/AI endpoints).
9. Packages & deployment: vulnerable/suspicious deps, debug mode, error leakage, source maps, preview deployments.
10. Business logic: abuse of free trials, referrals, credits, invites, quotas; state transitions (can steps be skipped or repeated?); race conditions; anything unique to this app.
11. AI features: prompt injection via user content/documents, tools the model can trigger, cross-user data leaks, cost abuse (see B1).

**Phase 3 `SECURITY_REVIEW.md`:**
- Executive summary in plain English (≤5 lines).
- Findings table sorted by severity: ID · title · severity (Critical/High/Medium/Low) · location (file:line or endpoint) · how an attacker would exploit it, step by step · recommended fix · effort (S/M/L) · confidence · status.
- What was checked and found fine (so coverage is visible).
- What could NOT be verified from code (dashboards, hosting config), with exact steps for the person.

Rate severity honestly; say how confident you are in each finding. Then fix new Critical/High findings in severity order and update the status column.

---

## 27 Test the protections and report
**VERIFY.** Every fix is proven by a test that tries to break it. A protection that "was added" but only runs in the page layout and not the API is exactly what this step catches.

**Rules**
- Only localhost or staging; never destructive tests against production or real customer data. Test accounts: signed-out visitor, user A, user B, admin.
- Real, repeatable automated tests in the project's existing framework (Vitest/Jest + supertest, Playwright, pytest + httpx/test client). If none exists, create a minimal setup and document how to run it. Prefer in-process test clients (supertest against the exported app, Flask `app.test_client()`, FastAPI `TestClient`): no server or network needed.
- If the app can't be started (missing deps, no DB), make the smallest stub needed (e.g. an in-memory SQLite DB, mocked provider SDK) rather than skipping tests; if that's impossible, write the tests anyway and mark them "written, not executed".

**Step 1 "Try to break it" tests**, for every protection that applies:
| # | Test |
|---|---|
| 01 | Every protected endpoint returns 401 signed out |
| 03 | User A can't read/update/delete user B's resources (403/404); public key alone reads nothing private |
| 04 | HTTP→HTTPS redirect; HSTS present (staging/prod URL, or production-mode app config) |
| 05 | Stored hashes are Argon2id/bcrypt/scrypt; no password in logs or responses |
| 06 | Negative/oversized/wrong-type/extra-field inputs rejected; `"role":"admin"` ignored |
| 07 | XSS payloads render as text |
| 08 | A failed login produces a log event without secrets |
| 09 | Normal user gets 403 on every admin page and endpoint |
| 10 | Injection payloads return normal empty/400 responses |
| 02/11 | Production build / client files contain no secret patterns |
| 12 | The N+1th request returns 429 |
| 13 | Unknown origin gets no `Access-Control-Allow-Origin` |
| 14 | All required security headers present |
| 15 | Session cookie has HttpOnly, Secure, SameSite; logged-out session rejected |
| 16 | State-changing request with foreign Origin / no token rejected |
| 17 | Used, expired and superseded reset tokens fail; real and fake emails get identical responses |
| 18 | Disguised HTML, script SVG, oversized file and `../` filename rejected |
| 19 | Tampered price, negative quantity, reused coupon, success URL without payment, unsigned and duplicate webhooks all fail safely |
| 20 | Error responses contain no stack traces, paths or queries |
| 23 | Sensitive paths return 404 |
| 25 | Old keys rejected (manual; give the commands) |

**Step 2 Fix and re-test:** for each failure explain the cause, apply the smallest correct fix, re-run until it passes. Never weaken or delete a test to pass it; if a test itself was wrong, say why you changed it.

**Step 3 Report:** write `SECURITY_REPORT.md` from `references/report-template.md`. Recommend running the security tests in CI on every push.

**Watch out:** green tests ≠ perfectly secure; they prove what they test. Re-run 26 as the app grows.
