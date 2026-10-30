# Identity & Access: checks 01, 05, 09, 15, 17

Contents: [01 Authentication](#01-set-up-proper-authentication) · [05 Hash passwords](#05-hash-passwords) · [09 Admin routes](#09-lock-down-admin-routes) · [15 Session cookies](#15-secure-session-cookies) · [17 Reset links](#17-make-password-reset-links-expire)

---

## 01 Set up proper authentication
**CRITICAL.** Prove who every user is, on the server, on every request. A login screen and a hidden menu are just UI; if `/api/plants` never checks the session, anyone who copies the URL into curl gets everything.

**Audit**
1. Identify the auth method (Supabase Auth, Clerk, Auth.js/NextAuth, Firebase Auth, custom JWT, server sessions). If it's hand-rolled, say so and say whether moving to a proven provider is wiser.
2. List EVERY server entry point: API routes, server actions, route handlers, edge/serverless functions, GraphQL resolvers, RPC/database functions, webhooks, cron routes. For each: does it need a signed-in user, and is that checked **on the server inside the handler** (not only in the UI, a client route guard, or middleware alone)?
3. Identity is verified properly: sessions looked up server-side, or JWTs verified with a library (signature, expiry, issuer, audience). Flag tokens that are decoded without verification, acceptance of `alg: none`, hard-coded or weak signing secrets.
4. The user ID used for reads and writes comes from the verified session, never from the body, query, URL or a client-controlled header.
5. Sign-up/login: generic errors ("Invalid email or password") that don't reveal whether an account exists; email verification before sensitive actions; sessions invalidated on logout and password change; sensible lifetime.
6. OAuth / magic links: `state` parameter used; callback URLs are an exact allowlist; any `?next=` / `?redirect=` / `?returnTo=` only allows relative paths on the same site (no open redirect: reject `//evil.com`, `https://...`, `/\evil.com`).

**Fix**
- One reusable server helper (`requireUser()` / `getCurrentUser()`) called at the top of every protected handler; return 401 without a valid session.
- Remove security decisions that live only in client code.
- Supabase on the server: use `getUser()` / `getClaims()` (re-validates with the auth server), not `getSession()` which trusts the cookie as-is.

**Verify:** for each protected endpoint, a request with no credentials → 401; a request for another user's resource → 403/404.

**Done when:** every protected endpoint returns 401 without a session · user ID always comes from the session · logout and password change kill sessions · login errors don't reveal registered emails · redirect params only allow own paths.

**Watch out**
- Middleware is not enough. In 2025 a Next.js flaw (CVE-2025-29927) let attackers skip middleware entirely. Check inside each handler too.
- Next.js server actions are public endpoints; anyone can call them directly. Each needs its own auth check.
- Don't roll your own password storage, sessions or tokens when a provider will do it.

---

## 05 Hash passwords
**CRITICAL.** Store passwords so that even someone who steals the database can't read them. Plain text or fast hashes mean a breach of your app becomes your users' stolen accounts everywhere (password reuse).

**Audit**
1. Find every place passwords are handled: sign-up, login, change, reset, admin "create user", invites, seed scripts, imports, tests.
2. How are they stored? If a provider handles it, confirm this app doesn't ALSO store, log or forward passwords (own users table, analytics, logs, emails, error tracking).
3. If the app stores them: plain text, reversible encryption, MD5, SHA-1, SHA-256 or any unsalted/fast hash is **Critical**.
4. Compared with the library's verify function (constant-time), not `==` on hashes.
5. Request loggers, error handlers and error trackers (Sentry etc.) never record bodies containing passwords.
6. No API response or client state includes a password or hash (`/api/me`, admin user lists, `SELECT *` results); never stored in localStorage or cookies.

**Fix**
- Argon2id (OWASP minimum: 19 MiB memory, 2 iterations, parallelism 1) via a maintained library, or bcrypt cost 12 (minimum 10). bcrypt only uses the first 72 bytes: cap the password length accordingly. Good stored values look like `$argon2id$...`, `$2b$12$...`, `$scrypt$...`.
- Weak existing hashes: migrate on next successful login (verify with old scheme, immediately re-hash with the new one). Propose what to do about users who never return (force reset).
- Password policy (NIST style): minimum 8 (12+ recommended), allow at least 64, allow all characters including spaces, no forced symbol rules. Optional: block breached passwords via the Have I Been Pwned range API (k-anonymity).
- Redact password fields from all logs and error reports. Never email a password.

**Verify:** show what a stored hash looks like now; test that the correct password logs in, a wrong one fails, and the plain password appears in no log output or response.

**Watch out:** encryption is not hashing; if you can decrypt it, so can an attacker with the key. Full-body request loggers happily log passwords.

---

## 09 Lock down admin routes
**CRITICAL.** Hiding the Admin button isn't security. A normal user who types `/admin` or calls `POST /api/admin/delete-user` (visible in the JS bundle) must get 403, checked on the server.

**Audit**
1. List every admin, staff, internal or privileged route: pages, API routes, server actions, GraphQL mutations, DB functions, cron/job endpoints, and any seed/test/debug/migration routes (`/api/seed`, `/api/test`, `/api/reset-db`).
2. For each: is the role checked **on the server inside the handler**, for the page AND every data endpoint it calls?
3. Where does the role come from? OK: a roles column/table in your DB, or server-only provider metadata (Supabase `app_metadata`, Clerk `publicMetadata`, Firebase custom claims). NOT OK: Supabase `user_metadata` (user-editable), localStorage, a client-set cookie, a request parameter, a hard-coded email check in front-end code.
4. Admin emails or admin endpoint names exposed in the client bundle?

**Fix**
- One server helper `requireAdmin()` that loads the verified user AND checks the role from a trusted source → 403 otherwise. Call it at the top of every admin handler, not only in middleware or layouts.
- Deny by default: new admin routes are protected unless explicitly public.
- Cron/webhook/internal endpoints: a long random secret in a header compared in constant time (`crypto.timingSafeEqual`, `hmac.compare_digest`), or the platform's built-in cron auth.
- Remove seed/test/debug endpoints from production or block them by environment.
- Log every admin action (who, what, when, target) via check 08's logger.
- Give the steps to require MFA for admin accounts in their auth provider.

**Verify:** signed-out → 401; normal user → 403 on every admin page and endpoint; admin → allowed; a user can't make themselves admin by editing their own profile/metadata (mass assignment, see 06).

**Watch out:** "Nobody knows the URL" is not protection; URLs end up in bundles, logs and history.

---

## 15 Secure session cookies
**HIGH.** Whoever holds the session cookie *is* the user. A token in localStorage can be stolen by any XSS bug and replayed for its whole lifetime.

**Audit**
1. Where does session state live: server session store, cookies (which library), JWTs, localStorage/sessionStorage, provider SDK? List every cookie set and its flags.
2. Each auth cookie: `HttpOnly`, `Secure`, `SameSite=Lax` (or Strict), `Path=/`, no unnecessarily broad `Domain`, sensible `Max-Age`.
3. Lifecycle: session ID regenerated on login and privilege change (prevents session fixation)? Destroyed server-side on logout? Idle timeout and absolute max lifetime? All sessions revoked after password change/reset?
4. Tokens in localStorage/sessionStorage: explain the risk; does the provider support cookie sessions instead?
5. JWTs: short-lived access tokens with refresh-token rotation; how revocation works; no sensitive data in the payload (it's readable by anyone).

**Fix**
- `HttpOnly; Secure; SameSite=Lax` on all auth cookies (Strict for extra-sensitive apps if it doesn't break login flows). Use the `__Host-` prefix where the framework allows.
- Regenerate on login, destroy on logout, "log out of all devices" that also runs automatically after password change.
- Sensible lifetimes (e.g. 7–30 days with idle timeout for consumer apps; shorter for admins). Explain the choice.
- If the provider manages cookies, confirm its defaults are secure and the code doesn't override them insecurely.
- Never put secrets or personal data in readable cookies; sign/encrypt any cookie holding data, with a strong secret. Make sure `express-session` / `cookie-session` / Flask `SECRET_KEY` etc. aren't a guessable default.
- Changing cookie settings or the session secret logs users out: ask first if the app is live.

**Verify:** list final cookies with flags; test that a cookie from a logged-out session no longer works.

**Watch out:** some SDKs store tokens in localStorage by default; acceptable only with a strong CSP and a conscious decision. `SameSite=Strict` can break login redirects from emails/OAuth; Lax is the usual default.

---

## 17 Make password-reset links expire
**HIGH.** A reset link is a temporary master key. It must be random, single-use, short-lived, and die when a newer one is issued. Same rules for magic-login links, email verification, email-change confirmation and invites.

**Audit:** for each flow: how the token is generated, stored, how long it lasts, single-use or not, what invalidates it, what the user sees for unknown emails, how the link URL is built.

**Fix** (if a provider like Supabase/Clerk/Firebase handles it, give the provider settings to check and change only code the person owns)
1. Tokens from a CSPRNG, at least 32 bytes (`crypto.randomBytes(32)`, `secrets.token_urlsafe(32)`). No timestamps, user IDs, UUIDv1 or `Math.random`.
2. Store only a SHA-256 hash of the token.
3. Expiry: 15–30 min for reset and magic links, up to 24 h for email verification, up to 7 days for invites.
4. Single use; and invalidate all outstanding tokens for the user when a new one is requested or the password changes.
5. Same message and similar response time whether or not the email exists ("If an account exists, we've sent a link").
6. Rate-limit per email and per IP (check 12).
7. Build the link from a configured `APP_URL` env var, **never** from the request's Host header (Host-header poisoning sends reset links to an attacker's domain).
8. Reset page: `Referrer-Policy: no-referrer`, no third-party scripts (analytics) that could see the token in the URL.
9. After reset: normal password policy and hashing (05), revoke all sessions, email a "your password was changed" notice.
10. Allowlist post-flow redirect URLs.

**Verify:** a used token fails; an expired token fails; an older token fails after a newer one is issued; real and fake emails get identical responses; a forged Host header doesn't change the link domain.
