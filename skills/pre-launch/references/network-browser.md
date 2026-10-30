# Network & Browser: checks 04, 12, 13, 14, 16

Contents: [04 HTTPS](#04-enforce-https) · [12 Rate limiting](#12-add-rate-limiting) · [13 CORS](#13-restrict-cors) · [14 Security headers](#14-add-security-headers) · [16 CSRF](#16-add-csrf-protection)

If a live/staging URL exists, `scripts/check_live.py` checks 04, 13 and 14 from the outside in one go.

---

## 04 Enforce HTTPS
**HIGH.** Every byte encrypted, no plain-HTTP side doors. One old `http://` API call sends a session token in clear text across café Wi-Fi.

**Audit**
1. Where hosted, how TLS is handled (platform-managed, Cloudflare, nginx/Caddy, load balancer).
2. Every HTTP request (apex, www, all subdomains, all paths) permanently redirected (301/308) to HTTPS.
3. Hard-coded `http://` URLs in code and env values: API calls, images, scripts, fonts, iframes, webhooks, OAuth callbacks, email links, redirects. (localhost in dev is fine.)
4. Outgoing server connections (DB, Redis, email, APIs) use TLS (Postgres `sslmode=require`).
5. Cookies marked `Secure`.
6. Behind a proxy: the app reads the original protocol (Express `app.set('trust proxy', 1)`, Django `SECURE_PROXY_SSL_HEADER`, Werkzeug `ProxyFix`) so HTTPS detection and redirects work without loops.

**Fix**
- HTTP→HTTPS redirect at the host/proxy level (or app middleware in production if the host doesn't).
- `Strict-Transport-Security: max-age=63072000; includeSubDomains` (includeSubDomains only if every subdomain serves HTTPS). Do NOT add `preload` unless the person explicitly confirms; it's hard to undo.
- Replace insecure URLs with `https://` or relative URLs; enforce TLS on DB/service connections.

**Verify:** `curl -sI http://domain` shows a 301/308 to https; `curl -sI https://domain | grep -i strict-transport` shows HSTS; DevTools Console has no "Mixed Content" warnings; SSL Labs grade A.

**Watch out:** forgotten subdomains (staging, blog, docs) often still serve HTTP.

---

## 12 Add rate limiting
**HIGH.** Nobody hammers login, forms or paid APIs thousands of times a minute. AI endpoints without quotas are the #1 surprise bill for vibe-coded apps.

**Audit**
1. Endpoints needing limits, grouped: auth (login, sign-up, reset, OTP/MFA, magic links) · expensive/paid (AI/LLM, email/SMS, file processing, search, exports) · user content (comments, contact forms) · general API.
2. What exists today, and would it work on this hosting? **In-memory counters don't work on serverless or multiple instances.**

**Fix**
1. Propose a limits table, starting from:
   - Login: 5/min per IP+email, increasing delays after repeated failures
   - Sign-up: 5/hour per IP
   - Password reset / magic link: 3/hour per email, 10/hour per IP
   - OTP/MFA: 5 attempts per code, then invalidate the code
   - AI/LLM: per-user per-minute limit PLUS a daily quota per user/plan
   - Email/SMS: strict per-user and global caps
   - General API: generous per-IP limit (e.g. 100/min)
2. A shared store that works on the hosting (Upstash Redis + `@upstash/ratelimit`, Redis, the DB, or platform features like Vercel WAF / Cloudflare rate limiting). For a single long-running server, `express-rate-limit` / `flask-limiter` with memory storage is acceptable for launch but note it in the report. Key by user ID when signed in, IP otherwise.
3. Get the client IP correctly for the host; don't trust a raw client-spoofable `X-Forwarded-For`.
4. 429 with `Retry-After` and a friendly message; never reveal whether an account exists.
5. Log rate-limit hits (08).
6. For paid APIs, give steps to set hard spending limits in each provider dashboard (B5).
- New limits on a live app can block real users: ask first and pick generous starting values.

**Verify:** a script/test firing requests at each limited endpoint on localhost/staging, showing the switch to 429.

**Watch out:** SMS endpoints are a fraud magnet ("SMS pumping"); cap them hard and restrict destination countries.

---

## 13 Restrict CORS
**MEDIUM.** Only your own sites can read your API's responses from a browser. Reflecting any origin with `Allow-Credentials: true` lets a malicious page read a logged-in user's data. CORS is not authentication; curl ignores it entirely, so the API still needs 01 and 09.

**Audit**
1. Every place CORS is configured: `cors()` middleware, flask-cors, framework config (`next.config.js` headers, `vercel.json`, `netlify.toml`/`_headers`), routes setting `Access-Control-*` manually, Supabase Edge Functions, API gateways, storage-bucket CORS (S3, R2, GCS, Firebase Storage).
2. For each: allowed origins, credentials, methods, headers.
3. Flag: `Access-Control-Allow-Origin: *`; origins reflected without checking (`origin: true`, `callback(null, true)`); `null` allowed; wildcard + credentials; loose matching (`endsWith("app.com")` matches `evilapp.com`; unanchored regex).
4. Is the API even called cross-origin? Same origin may need no CORS at all.

**Fix:** explicit allowlist from an env var (production domains; localhost only in dev), exact string matches; credentials only if needed and never with a wildcard; restrict methods/headers to what the front end uses. Public, read-only, non-personalised endpoints may use `*` but never with cookies.

**Verify:** `curl -sI -H "Origin: https://evil.example" https://app/api/x` returns no `Access-Control-Allow-Origin`; an allowed origin does.

---

## 14 Add security headers
**MEDIUM.** A few headers switch on strong browser protections: CSP limits what scripts run (blunting XSS), frame protection stops clickjacking.

**Audit:** which headers are sent today and where they're configured (framework config, middleware, helmet, flask-talisman, `vercel.json`, netlify `_headers`, nginx/Caddy). List every legitimate third-party origin (analytics, fonts, Stripe, Supabase, auth provider, image CDN, AI API, maps) from the code, since the CSP needs them.

**Fix** (all routes, in the single most appropriate place; `helmet` for Express and `flask-talisman` for Flask are well-known options):
- `Content-Security-Policy`, starting from: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests`. Add only the specific third-party origins found. Avoid `'unsafe-inline'`/`'unsafe-eval'` for scripts; use nonces/hashes if the framework needs inline scripts. Explain any unsafe value you keep.
- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY` (SAMEORIGIN if the app frames its own pages)
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()` (enable only what's used)
- `Cross-Origin-Opener-Policy: same-origin` (`same-origin-allow-popups` if OAuth/payment popups break)
- Remove `X-Powered-By` and server version headers.
- `Cache-Control: no-store` on authenticated pages and API responses with personal data.

**Rollout:** a CSP can silently break payments, OAuth and analytics. For a live app, ship it first as `Content-Security-Policy-Report-Only`, list what would be blocked on main pages (login, checkout, OAuth, uploads, embeds), adjust, then enforce. Tell the person which pages to click through.

**Verify:** `curl -sI https://app` shows every header; securityheaders.com grade A. Verify on the live URL; headers set in framework config don't apply in every host setup.

---

## 16 Add CSRF protection
**HIGH.** Browsers attach cookies automatically, so a hidden form on another site can post to "change email" as the logged-in user, and the attacker then resets the password.

**Audit**
1. How are requests authenticated? Cookies (including provider-managed session cookies) → CSRF applies. Only a bearer token in an `Authorization` header added by JS → low risk; say so and confirm no cookie path exists.
2. Every state-changing endpoint (POST/PUT/PATCH/DELETE, server actions, form handlers) and every GET that changes state (`/delete?id=`, `/logout`, `/subscribe`).
3. Existing protection: framework CSRF (Django, Rails, Laravel built-in; Flask-WTF `CSRFProtect`), Next.js Server Actions' Origin/Host check (and whether `serverActions.allowedOrigins` is loosened), SameSite settings, custom token or Origin checks.
4. JSON endpoints that also accept form-encoded or `text/plain` bodies can be sent cross-site without a preflight.

**Fix**
- Move state-changing GETs to POST/DELETE.
- Use built-in framework CSRF and make sure it isn't disabled. For Express/custom servers, a maintained synchronizer or signed double-submit token library (`csurf` is deprecated; e.g. `csrf-csrf`).
- Origin check on every state-changing request as defence in depth: reject when `Origin` (or `Referer` if Origin absent) is present and isn't the app's own origin.
- JSON endpoints require `Content-Type: application/json`.
- Auth cookies `SameSite=Lax` or Strict (15).
- Exempt only webhooks, which verify signatures instead (19).
- High-risk actions (change email/password, delete account, payouts) require the current password or recent re-login.

**Verify:** test that a state-changing request with a foreign Origin and no token is rejected, and the real UI flow still works.

**Watch out:** SameSite alone isn't complete (subdomains you don't control, older browsers). Login CSRF is real too; protect the login form.
