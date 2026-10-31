# Data Protection: checks 28, 29

Contents: [28 Encrypt sensitive data](#28-encrypt-sensitive-data) · [29 Trim API responses](#29-trim-api-responses)

Both checks answer the same question from two sides. If someone gets a copy of the database, what can they read (28)? If someone simply uses the API, what does it hand them that the screen never shows (29)?

---

## 28 Encrypt sensitive data
**HIGH** (CRITICAL for government IDs, health, financial or children's data). Disk encryption at the host protects against a stolen hard drive. It does nothing against the far more common leaks: a SQL injection, a leaked DB URL, a backup in a public bucket, a support tool with too much access. For the few fields that would really hurt if they leaked, encrypt them in the application so a database dump shows ciphertext.

**Audit**
1. Classify every column, document field and file from `SECURITY_MAP.md`:
   - **Encrypt at field level:** government IDs (SSN, national ID, passport, tax ID), bank/IBAN/account numbers, health and medical details, precise location history, third-party OAuth access/refresh tokens and API keys that *users* give the app (it must call those services later, so it needs them back), private messages or notes when the product promises privacy, 2FA/TOTP secrets.
   - **Hash, don't encrypt** (the app never needs the original back): passwords (05), reset/magic/invite tokens (17), the app's own API keys for its users (store a SHA-256 of the key, show it once).
   - **Never store:** full card numbers and CVV (use the payment provider's hosted fields and keep only its token, last 4 and brand), anything the app doesn't need (B6).
   - **Fine as normal columns:** most names, emails and display data, protected by 03 and at-rest disk encryption.
2. For anything already encrypted: which algorithm and mode, where the key lives, is the IV/nonce random per value, can the key be rotated? Flag: ECB mode, fixed or zero IVs, AES-CBC without authentication, home-made XOR or "base64 = encryption", the key stored in the same table or committed to the repo, the key hard-coded in source.
3. At rest and in transit at the platform level: managed DB storage encryption on (most managed Postgres/MySQL/Mongo hosts do this by default, so confirm and say so), DB connections over TLS (`sslmode=require`, see 04), backups and exports encrypted, storage buckets with server-side encryption.
4. Where else does the sensitive value go? Logs, error trackers, analytics, caches (Redis), search indexes, emails, CSV exports, AI prompts. Encrypting the column doesn't help if the value is also logged in plain text.

**Fix**
- **One small helper**, `encryptField(plaintext)` / `decryptField(ciphertext)`, used everywhere. Use **authenticated encryption**: AES-256-GCM (Node `crypto.createCipheriv('aes-256-gcm', ...)` with a random 12-byte IV per value, storing `version:iv:authTag:ciphertext`), or a vetted high-level library: Python `cryptography` (`Fernet` or `AESGCM`), libsodium `crypto_secretbox` / `sodium-native` / `tweetnacl`, Rails `encrypts`, Laravel `encrypted` casts, Django `django-fernet-fields`-style fields only if maintained. Prefer the stack's built-in or most widely used option over a new package.
- **Key:** 32 random bytes from a server-only env var (`DATA_ENCRYPTION_KEY`), or better a managed KMS (AWS KMS, GCP KMS, Azure Key Vault, Supabase Vault) for larger apps. Never in the DB, never in the repo, never with a fallback. Generate with `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"` or `python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"`.
- **Key versioning:** prefix each ciphertext with a key ID (`v1:`) so a new key can be added and old rows re-encrypted gradually. Explain the rotation procedure in `SECURITY_RUNBOOK.md` or `SECRETS.md`.
- **Lookups:** encrypted values can't be searched with `WHERE ssn = ?`. If the app needs exact-match lookup, add a separate **blind index** column: `HMAC-SHA256(lookupKey, normalizedValue)` with a *different* key. Don't fall back to deterministic encryption without saying why.
- **Migration** for existing plaintext rows: add the new column, back-fill with a script that encrypts in batches, switch reads, verify, then drop the plaintext column. Remind the person that old backups still contain plaintext and need to age out or be re-made. Running this on a live DB is a change users could notice (downtime, failed reads); ask first.
- **Supabase:** `pgsodium`/Vault for secrets the DB itself uses; for app data, encrypting in server code or an Edge Function is usually simpler. Never put the encryption key in the browser, because then it isn't secret (02).
- Show decrypted values only to the owner and roles that need them; mask elsewhere (`•••-••-1234`). Redact these fields in logs and error trackers (08).

**Verify:** a test that writes a record and then reads the raw column straight from the DB: it must not contain the plaintext, and the app still returns the right value to the owner. A second test that tampering with one byte of the ciphertext makes decryption fail (proves the encryption is authenticated). Search logs from the test run for the plaintext: none.

**Done when:** every field classified · sensitive fields encrypted with authenticated encryption via one helper · key server-only with no fallback and a rotation plan · plaintext copies removed from logs, exports and caches · platform at-rest encryption and TLS confirmed.

**Watch out:** encrypting with a key stored next to the data is theatre. `crypto.createCipher` (no IV) is deprecated and insecure. Base64 is encoding, not encryption. Encryption doesn't replace access control: if the API decrypts and returns the field to anyone who asks, 03 and 29 are still broken.

---

## 29 Trim API responses
**HIGH.** The UI showing three fields means nothing if the API returns thirty. Anyone can open DevTools → Network and read the full JSON. Classics: `/api/users/me` returning `password_hash`, `reset_token` and `stripe_customer_id`; a public profile endpoint returning the user's email and phone; `/api/posts` embedding the full author object, including the author's email, for every post; an error that echoes the whole DB row.

**Audit**
1. For every endpoint, server action, GraphQL type and server-rendered page prop (`getServerSideProps`, loaders, `+page.server.ts`, Remix `json()`), compare **what is returned** with **what the UI actually uses**. Hit the endpoint (or read the code) for each role: signed-out, user A looking at A, user A looking at B, admin.
2. Flag the usual leak patterns (`scripts/scan_code.py` lists leads):
   - Whole ORM/DB objects sent back: `res.json(user)`, `return user`, `jsonify(user.__dict__)`, `Model.find()` / `findMany()` / `findAll()` without `select` / `attributes`, `SELECT *`, Supabase `.select('*')` or `.select()` on a table with private columns, Mongoose docs without `.select()` / `toJSON` transform.
   - Relations included wholesale (`include: { author: true }`, `populate('owner')`, Django serializers with `fields = '__all__'`, DRF `depth`).
   - Sensitive fields: password hashes, reset/verification tokens, session IDs, API keys, MFA secrets, internal flags (`is_admin`, `role`, `banned`, `fraud_score`), provider IDs (`stripe_customer_id`), other users' emails/phones/addresses/IPs, soft-deleted rows, internal notes.
   - **Lists** that leak more than details: search, autocomplete, "people you may know", leaderboards, comments with author info, admin list endpoints reachable by normal users.
   - **Bulk endpoints** with no pagination or a client-controlled `limit=100000`.
   - Errors and debug fields: DB errors, stack traces (20), `debug`/`_raw` fields, timing or existence oracles ("no user with that email").
   - Server-rendered pages embedding full objects into HTML (`__NEXT_DATA__`, hydration JSON) that the visitor shouldn't see.
   - Supabase/Firebase direct client access: RLS restricts *rows*, not *columns*. If a private column sits in a table the browser can read, it leaks. Fix with a view exposing safe columns (with `security_invoker = true`), column-level `GRANT`, or by moving private columns to a separate table with stricter policies.
3. GraphQL: field-level authorization on sensitive fields, query depth/complexity limits, introspection off in production (20).

**Fix**
- **Explicit allowlists of fields per response**, never deny-lists ("delete `password` before sending" breaks the day someone adds `api_key`). Use one serializer/DTO per audience: `toPublicUser()`, `toSelfUser()`, `toAdminUser()`. Examples: Prisma `select: {...}`, Drizzle column objects, Sequelize `attributes: [...]`, Mongoose `.select('name avatar')` plus `select: false` on secret schema fields, Django REST serializers with explicit `fields`, Pydantic `response_model` in FastAPI, Supabase `.select('id, name, avatar_url')`.
- Different shapes for different viewers: the owner can see their own email; other users see display name and avatar only.
- Paginate every list (default ~20, server-side max ~100). Cap `limit`.
- Generic error responses with a request ID (20); identical responses for "no such user" and "wrong password" (01).
- For direct-to-DB clients: views or column grants as above, and keep secrets out of client-readable tables entirely.

**Verify:** tests that call each changed endpoint as each role and assert the **exact set of keys** returned (e.g. `expect(Object.keys(body)).toEqual(['id','name','avatarUrl'])`), and that no response anywhere contains `password`, `hash`, `token`, `secret` or another user's email. A test that `?limit=100000` returns at most the server max.

**Done when:** every endpoint returns only allowlisted fields for its audience · no secrets or internal flags in any response · lists paginated with a server max · error responses generic.

**Watch out:** `toJSON` overrides and `select: false` can be bypassed by raw queries or a `.lean()` call; tests on the actual HTTP response are the proof. Caching layers (CDN, `Cache-Control: public`) can serve one user's trimmed-for-owner response to another (see 14's `Cache-Control: no-store`).
