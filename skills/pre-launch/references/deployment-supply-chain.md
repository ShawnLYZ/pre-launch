# Deployment & Supply Chain: checks 20, 21, 22, 23

Contents: [20 Debug mode](#20-disable-production-debug-mode) · [21 Vulnerable deps](#21-update-vulnerable-dependencies) · [22 Unused packages](#22-remove-unused-packages) · [23 Exposed files](#23-check-for-exposed-files)

---

## 20 Disable production debug mode
**HIGH.** Users see "something went wrong" plus a reference ID; you see everything else, privately. A debug page can reveal DB host, secrets, file paths and SQL. The Flask/Werkzeug debugger lets anyone run code on the server.

**Audit**
1. Framework production settings:
   - Django: `DEBUG = False`, `ALLOWED_HOSTS` set. Flask: debug off (`app.run(debug=True)`, `FLASK_DEBUG=1` are RCE in production). FastAPI: `debug=False`; `/docs`, `/redoc`, `/openapi.json` disabled or protected if the API is private.
   - Node/Express: `NODE_ENV=production`; an error handler that never sends `err.stack` or internal `err.message`.
   - Next.js/Vite/React: production build deployed (not a dev server); no detailed errors in API responses.
   - Laravel `APP_DEBUG=false` · Rails `consider_all_requests_local = false` · Spring Actuator restricted.
   - GraphQL: introspection and playground/GraphiQL off in production unless intentionally public.
2. Every error path: catch blocks returning `error.message` or raw DB errors, 404/500 pages, validation errors.
3. Public source maps, directory listing, verbose headers (`X-Powered-By`, server versions), debug/test routes, health/status endpoints revealing versions/env/deps, client `console.log` of sensitive data.

**Fix**
- Debug off in production **through env config**, so it can't be forgotten (e.g. `debug = os.getenv("FLASK_DEBUG") == "1"`, default off).
- A global error handler: generic message + request ID to users; full details only to server logs/error tracker (08).
- Map DB and third-party errors to generic messages.
- No public source maps (or upload them privately to the error tracker).
- Disable directory listing; remove debug-only routes and noisy console logs.

**Verify:** trigger a 404, a 500 and a validation error; none reveal stack traces, paths, queries or versions.

**Watch out:** preview/staging deployments are often public with debug on; protect them with a password or platform auth. `return res.status(500).json({error: err.message})` is a sneaky leak; DB errors include table and column names.

---

## 21 Update vulnerable dependencies
**HIGH.** Known vulnerabilities are published with affected versions, and attackers scan for apps still running them. Also make sure every package is real: AI tools invent package names, and attackers register those names with malware ("slopsquatting").

**Audit**
1. Run the right tool: `npm audit --omit=dev` / `pnpm audit --prod` / `yarn npm audit`, `pip-audit`, `bundle audit`, `cargo audit`, `composer audit`, or `osv-scanner` for anything. If you can't run it (no network, not installed), say exactly what to run and evaluate versions against what you know, clearly labelled as unverified.
2. Table: package · installed · fixed version · severity · direct/transitive · prod or dev-only · what it's used for.
3. Core framework and runtime (Node.js, Python, Next.js, React, Django, Flask, Express...) on supported, patched versions.
4. Supply-chain sanity for every DIRECT dependency: exists on the official registry, is the well-known one (not a near-identical typo-squat), has a real repo and reasonable downloads, no recent suspicious ownership change. Flag anything an AI may have invented. Flag unexpected install scripts (`postinstall`).
5. Lockfile committed; CI installs from it (`npm ci`, `pnpm install --frozen-lockfile`, pip with hashes or a lock tool).

**Fix**
- Upgrade production Critical/High first with the smallest bump containing the fix.
- Major upgrades: read the changelog, list breaking changes affecting this code, fix them.
- Vulnerable transitive deps: upgrade the parent or use `overrides`/`resolutions`; explain why.
- Never run `npm audit fix --force` blindly.
- Rebuild and run tests after each group of upgrades.
- Set up Dependabot or Renovate (grouped updates) and GitHub security alerts.

**Report:** what was upgraded, what remains (with reasons: "no fix available", "dev-only, not shipped"), anything suspicious.

---

## 22 Remove unused packages
**MEDIUM.** Less shipped code means fewer things to break, leak or exploit. Abandoned experiments leave dependencies and, worse, forgotten routes like `/api/import-legacy` with no auth.

**Audit**
1. Unused dependencies: `npx knip` or `npx depcheck` (JS/TS), `deptry` (Python), or careful manual search. Double-check each candidate: dynamic imports, config usage (build tools, PostCSS, Tailwind, Babel, ESLint, test setup), CLI usage in package.json scripts, peer deps, type packages.
2. Dev-only tools in production dependencies (types, linters, test/build tools).
3. Dead code still deployed: unused routes/server actions, pages for removed features, old webhooks, test/demo/seed routes, abandoned admin tools, unused files in `public/`.
4. Unused env vars, third-party scripts (old analytics, chat widgets), OAuth apps and API keys tied to removed features.

**Fix:** remove unused deps; move dev-only ones to devDependencies; delete dead routes/pages/files (**if unsure, list them for the person instead of deleting**); remove unused scripts and env vars; rebuild, test, and start the app.

**Report:** table: item · type (package/route/file/script/env var/key) · evidence it's unused · action taken. List keys/OAuth apps to revoke in dashboards.

**Watch out:** unused-dependency detectors have false positives; always build and test after removing.

---

## 23 Check for exposed files
**CRITICAL.** Scanners request `/.env`, `/.git/config`, `/backup.zip` on millions of sites daily. One exposed `.env` leaks every key; an exposed `.git` folder leaks the entire source and history.

**Audit**
1. Inspect `public/`, `static/`, `assets/`, build output (`dist/`, `build/`, `out/`, `.next/static`) and anything the server serves directly (e.g. `express.static('.')` or `express.static(__dirname)` serves the whole project). List anything that shouldn't be public: `.env` files and backups, `.git`, DB files/dumps (`.sql`, `.sqlite`, `.db`), archives, logs, `.vscode`/`.idea`, `.DS_Store`, configs with internal details, private docs, fixtures with real data.
2. Server/host config for directory listing and dotfile serving.
3. `robots.txt`/`sitemap.xml` don't advertise private paths (robots.txt is public and is NOT protection).
4. Cloud buckets (S3, R2, GCS, Supabase/Firebase Storage): which are public, are they listable?
5. `.dockerignore` / `.vercelignore` etc. keep secrets out of images and deployments.

**Fix**
- Delete or move sensitive files out of public locations; serve only a dedicated public folder.
- Deny rules so dotfiles and backup/dump extensions always 404 (host config, nginx `location` rules, or middleware); disable directory listing.
- Buckets private unless they must be public; disable listing on public ones.
- If an exposed file contained secrets → rotation list (25).

**Deliver:** a re-runnable check. Point the person to `python <skill-dir>/scripts/check_live.py https://their-domain` (or copy it into the project as `scripts/check_exposed.py`). It requests ~35 sensitive paths and highlights any 200. Only against their own domain. Re-run after every major deploy, since a new build step can re-introduce files.

**Watch out:** if `.env` was ever publicly reachable, treat every key in it as compromised (25).
