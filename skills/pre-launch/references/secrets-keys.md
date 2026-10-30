# Secrets & Keys: checks 02, 11, 24, 25

Contents: [02 Hide API keys](#02-hide-api-keys) · [11 Environment variables](#11-check-environment-variables) · [24 Git history](#24-scan-git-history-for-leaked-secrets) · [25 Rotate keys](#25-revoke-and-replace-compromised-keys)

Throughout: never print a secret value. Mask to the first 4 characters. Keep one running **rotation list** across these four checks (and 23): every secret that was ever in client code, a public file, Git history or logs goes on it.

---

## 02 Hide API keys
**CRITICAL.** Anything the browser can see, every visitor can see. Minified bundles are trivially searchable. A copied AI key can run up thousands of dollars overnight.

**Audit**
1. Search the whole codebase including config for hard-coded keys: `sk_`, `sk-`, `sk-ant-`, `pk_`, `rk_`, `AKIA`, `ghp_`, `github_pat_`, `xox`, `AIza`, `Bearer`, `api_key`, `apiKey`, `secret`, `token`, `password`, `service_role`, `private_key`, long random strings. (`scripts/scan_secrets.py` does this.)
2. List every third-party service: which key, called from client or server, and is the key PUBLISHABLE or SECRET?
   - Usually publishable: Stripe `pk_`, Supabase anon/publishable key (safe only with RLS on, see 03), Firebase web config, Google Maps browser keys restricted by domain.
   - Always secret: Stripe `sk_`/`rk_`, OpenAI/Anthropic/any AI key, Supabase `service_role`/secret key, database URLs, email/SMS provider keys, webhook secrets, JWT secrets, cloud credentials.
3. Every env var exposed through a public prefix (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `PUBLIC_`, `NUXT_PUBLIC_`): flag any that hold a secret.
4. Build for production if you can and scan the output (`scan_secrets.py --build dist`), so you know what actually ships. Mobile bundles (iOS/Android/Expo) count too.

**Fix**
- Move every secret into server-only env vars.
- Replace each client call that needs a secret with a server route / server action / edge function that requires sign-in where appropriate, validates input, is rate-limited, and performs **only the one operation the UI needs**. Do NOT build a generic proxy that forwards any URL or body; that makes the server an open relay.
- For publishable keys that stay public, say which dashboard restrictions to add (allowed domains/referrers, allowed APIs, read-only scopes).
- Removing a key from code doesn't un-leak it → rotation list (25).

**Done when:** a production build scan finds no secrets · no secret uses a public prefix · all secret-needing calls go through the server · publishable keys are restricted · rotation list exists.

**Watch out:** Lovable, Bolt and v0 projects often put keys in front-end code during prototyping.

---

## 11 Check environment variables
**CRITICAL.** Build tools ship any public-prefixed variable straight to the browser. Classics: `PUBLIC_PAY_SECRET`, a committed `.env`, `JWT_SECRET || "dev-secret"` silently used in production.

**Audit**
1. Every env var the code reads (`process.env`, `import.meta.env`, `os.environ`, `os.getenv`, `Deno.env`, config files) and every `.env*` file. Table: NAME · used where (client/server/both) · public-safe or SECRET · notes. **Names only.**
2. Flag every SECRET with a public prefix or read in client-side code.
3. `.gitignore` covers `.env`, `.env.local`, `.env.*.local`, `.env.production` etc. Is any `.env` tracked now (`git ls-files | grep -i env`) or in the past (24)?
4. Insecure fallbacks: `|| "secret"`, `?? "changeme"`, `os.getenv("X", "default-key")`, defaults that silently use test values in production.
5. Secrets exposed via other routes: `/api/config`, `/api/health`, error messages, client logs, server-rendered page props (`getServerSideProps` returning env), Docker images/build args, CI logs.
6. Dev and production use separate values (Stripe test keys in dev, live only in prod; separate dev DB).

**Fix**
- Rename/move secrets so none are public; move secret-using code to the server.
- Add `.env.example` with every name and a safe placeholder; update `.gitignore`.
- Start-up validation (Zod schema, t3-env, envalid, pydantic-settings) so the app fails fast with a clear message if a required var is missing, without printing its value.
- Remove insecure fallbacks. Signing secrets must be ≥32 random bytes; give the command: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` or `python -c "import secrets; print(secrets.token_hex(32))"`.

**Report:** every variable that may have been exposed (public prefix, committed file, logs) → rotation list.

**Watch out:** adding `.env` to `.gitignore` doesn't remove it from history (24). Changing an env var on most hosts needs a redeploy.

---

## 24 Scan Git history for leaked secrets
**CRITICAL.** Every commit is kept forever. A key committed for five minutes and deleted in the next commit is still there, and bots scan public GitHub for fresh keys within minutes.

**Audit**
1. Scan the FULL history, all branches and tags: `gitleaks git -v` (older: `gitleaks detect -v`) or `trufflehog git file://. --only-verified`. If neither is installed, `python scripts/scan_secrets.py <repo> --history` does a pattern scan of every commit and lists every `.env*` ever committed.
2. Manual fallback: `git log --all -p -S "<pattern>"` and `git log --all --full-history -- "**/.env*"` for `sk_live_`, `sk_test_`, `rk_live_`, `sk-`, `sk-ant-`, `AKIA`, `ghp_`, `github_pat_`, `xoxb-`, `xoxp-`, `AIza`, `-----BEGIN PRIVATE KEY-----`, `service_role`, `postgres://user:pass@`, `mongodb+srv://user:pass@`, `api_key=`, `secret=`, `password=`.
3. Report each: secret type · file · commit hash · date · branch · still in current code? Mask values (first 4 chars).
4. Other hiding places: notebooks, test fixtures, CI config, Dockerfiles, docs, screenshots.

**Fix**
1. FIRST: everything found goes on the rotation list (25). Rewriting history does NOT make a leaked key safe; forks, clones and caches keep copies.
2. Remove secrets still in current code; load from env vars.
3. Prevention: a pre-commit hook running gitleaks (or the pre-commit framework with a secrets hook), a CI step scanning each push, and the steps to enable GitHub Secret scanning + Push protection (Settings → Code security).
4. Only AFTER rotation, and only if the person wants it: explain purging with `git filter-repo`, the impact (rewritten hashes, force-push, every collaborator re-clones) and asking GitHub to clear cached views for public repos. Don't run it yourself without explicit approval; it's destructive.

**Watch out:** private repos aren't safe storage. They get shared, forked, cloned onto laptops and connected to third-party tools.

---

## 25 Revoke and replace compromised keys
**CRITICAL.** Any key that was ever exposed is treated as stolen. Only the person can do the dashboard steps, so you are their guide; you update code and config.

**Step 1 Inventory:** every credential: third-party API keys (AI, payments, email, SMS, maps), DB passwords/connection strings, Supabase service_role, JWT/session signing secrets, OAuth client secrets, webhook signing secrets, cloud keys/service-account files, deploy/CI tokens, SMTP creds. For each: where stored (host env per environment, CI, local `.env`, other services) and evidence of exposure (from 02, 11, 23, 24).

**Step 2 Prioritise by blast radius:** payments and cloud/infra first → database and service_role → AI and messaging (cost abuse) → the rest.

**Step 3 Runbook per key, in this order:**
a) Where to create the new key (dashboard path), with minimum scopes, IP/domain restrictions and spending limits where available.
b) Every place to update it (each host environment, CI secrets, local `.env`, teammates, other services).
c) Redeploy and confirm the app works with the new key.
d) Revoke/delete the old key.
e) Confirm the old key now fails, with a safe read-only test request (e.g. `curl https://api.openai.com/v1/models -H "Authorization: Bearer $OLD_KEY"` → 401).
f) Check provider logs/usage for misuse during the exposure window.
g) Side effects: rotating a JWT/session secret logs everyone out; rotating a DB password means updating every connecting service; rotating a webhook secret means updating the provider's endpoint config.

**Step 4 Harden:** read every credential from env vars, no fallbacks, and add `SECRETS.md` (name, purpose, owner, where stored, last rotated; **never values**).

**Watch out:** deploy the new key before revoking the old one or you cause your own outage. Exception: for an actively leaked payment, cloud or AI key, revoke immediately; a few minutes of downtime is cheaper.
