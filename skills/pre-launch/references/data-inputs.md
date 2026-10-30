# Data & Inputs: checks 03, 06, 07, 10, 18, 19

Contents: [03 Database](#03-secure-the-database) · [06 Validation](#06-validate-forms-server-side) · [07 XSS](#07-protect-against-xss) · [10 Parameterized queries](#10-use-parameterized-queries) · [18 Uploads](#18-restrict-file-upload-types-and-sizes) · [19 Payments](#19-verify-prices-and-payments)

---

## 03 Secure the database
**CRITICAL.** Users read and change only their own data, even if they talk to the DB directly. The classic bug is IDOR: Ana changes `/orders/18` to `/orders/22` and sees Ben's address. Or a Supabase table without RLS lets anyone with the public anon key download every row.

**Audit**
1. Every table/collection and storage bucket: who should read, create, update, delete (owner, team, admin, public)?
2. How the app reaches the DB: server code only, or directly from the browser (Supabase client, Firebase SDK)?
3. If the browser talks to the DB directly:
   - **Supabase/Postgres:** RLS ENABLED on every table in exposed schemas. Separate SELECT/INSERT/UPDATE/DELETE policies based on `auth.uid()`. INSERT and UPDATE need `WITH CHECK` so users can't create rows owned by others or change `owner_id`. Views bypass RLS unless `security_invoker = true`; `SECURITY DEFINER` functions bypass RLS and must check permissions themselves. Never base policies on `user_metadata` (user-editable).
   - **Firebase:** per-path rules on `request.auth.uid` that validate written fields. Remove `allow read, write: if true` and date-based "test mode" rules.
   - **Storage buckets:** private by default, policies so users access only their own files.
4. Server-side access: every query that fetches/updates/deletes by ID also checks ownership. List endpoints where an ID comes from the client and the query isn't scoped to the current user (`WHERE id = ?` must become `WHERE id = ? AND user_id = ?`).
5. `service_role`/admin key and DB connection string used ONLY in server code.
6. DB user isn't a superuser; DB not open to the internet (no `0.0.0.0/0`); TLS on connections; automated backups on.
7. Responses never include sensitive columns (password hashes, tokens, other users' emails, internal flags). Select only fields the UI needs; avoid `SELECT *` / returning whole ORM objects.

**Fix:** write the missing policies/rules and ownership checks. Show every policy in full SQL/rules syntax with a one-line plain-English explanation. Return 404 (not 403) for other users' resources if you don't want to reveal existence.

**Verify:** a test or script with two users proving A can't read, update or delete B's rows or files, and a signed-out visitor with only the public key gets nothing private.

**Watch out:** RLS enabled with no policies blocks everything; disabled allows everything. MongoDB Atlas open to `0.0.0.0/0` with a weak password is a common breach.

---

## 06 Validate forms server-side
**HIGH.** Browser validation is UX; server validation is security. Classics: `quantity: -3` creates a negative total; a profile update that saves the whole body lets a user add `"role": "admin"`.

**Audit**
1. Every endpoint, server action, form handler, webhook and job that accepts outside input (body, query, URL params, headers, cookies, file metadata). Table with the fields each accepts.
2. Validated on the server today? How?
3. **Mass assignment:** the body (or a spread: `{...req.body}`, `**data`, `Object.assign(user, req.body)`, `Model.create(req.body)`, `update(request.json)`) passed straight into a DB write. Flag server-controlled fields: `id`, `user_id`/`owner_id`, `role`, `is_admin`, `price`, `amount`, `status`, `credits`, `balance`, `plan`, `is_verified`, `email_verified`, `created_at`.

**Fix**
- ONE validation library fitting the stack (Zod/Valibot for TS, Pydantic/Marshmallow for Python, Joi or express-validator if already present) at the very start of every handler.
- Per field: type, required/optional, number min/max, **max length on every string**, enums where possible, formats (email, URL, UUID, date), money as integers in minor units.
- Reject unknown fields (strict mode); copy only allowed fields into writes. Server-controlled fields never come from client input.
- Normalise (trim, lowercase emails).
- Consistent 400 with field-level messages, never a stack trace. Max request body size.

**Verify:** tests sending a negative quantity, a 100,000-char string, a wrong type, a missing field and an extra `"role":"admin"`: each rejected or ignored, nothing invalid reaches the DB.

**Watch out:** TypeScript types don't exist at runtime. Valid text can still contain HTML (07).

---

## 07 Protect against XSS
**HIGH.** User text is always shown as text, never run as code. A comment containing `<img src=x onerror=...>` rendered with innerHTML runs for every reader, including the admin, and acts as them.

**Audit** (`scripts/scan_code.py` finds most sinks)
1. Dangerous sinks, each with file:line and data source:
   - React `dangerouslySetInnerHTML` · Vue `v-html` · Svelte `{@html}` · Angular `[innerHTML]` / `bypassSecurityTrust*`
   - DOM `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()`/`.append()` with strings
   - Server templates: `|safe`, `mark_safe`, `autoescape off`, `Markup()`, `render_template_string` with user input, EJS `<%- %>`, Handlebars `{{{ }}}`, `raw()`
   - Code execution: `eval`, `new Function`, `setTimeout`/`setInterval` with a string
2. User-controlled URLs in `href`, `src`, `action`, `window.location`: only `http:`, `https:`, `mailto:`; block `javascript:` and `data:`.
3. User data inside `<script>` tags, inline event handlers, style attributes, or JSON embedded in HTML (escape `</script>`).
4. Markdown/rich text (raw HTML allowed?), rich-text editors, SVG uploads, HTML emails/PDFs with user content.
5. AI/LLM output is untrusted input too; sanitise if rendered as HTML/Markdown.

**Fix:** prefer the framework's escaped rendering (`{value}` in JSX, `{{ }}`, `textContent`). Where HTML is genuinely needed, sanitise with DOMPurify (browser) or a maintained server sanitiser (sanitize-html, bleach/nh3) with a strict allowlist. Validate URL schemes. HttpOnly cookies (15) and CSP (14) as second lines of defence.

**Verify:** tests submitting `<img src=x onerror=alert(1)>`, `"><svg onload=alert(1)>`, `javascript:alert(1)` through each affected input and asserting they render as harmless text.

**Watch out:** sanitise on output, not just input; data enters the DB from imports, APIs and old versions. Stored XSS in admin panels can hand over the whole app.

---

## 10 Use parameterized queries
**CRITICAL.** Query structure is fixed; input is only data. `WHERE name = '${input}'` plus `' OR '1'='1` returns every row.

**Audit**
1. Every query built from variables via concatenation, template literals, f-strings, `.format()` or `%`.
2. ORM escape hatches with untrusted input: Prisma `$queryRawUnsafe`/`$executeRawUnsafe`/`Prisma.raw` (the tagged ``$queryRaw`...${x}` `` IS safe), Sequelize `literal()` and raw queries, Knex `raw()` with interpolation, TypeORM `query()` with strings, SQLAlchemy `text()` built with f-strings, Django `raw()`/`extra()`, Drizzle `sql.raw()`.
3. Dynamic identifiers that can't be parameterized: ORDER BY column, sort direction, table/column names, LIMIT from input.
4. NoSQL: request JSON straight into a query allows operator injection (`{"$ne": null}`, `{"$gt": ""}`).
5. Supabase/PostgREST: filter strings from input (``.or(`name.eq.${input}`)``), `.rpc()` functions using dynamic `EXECUTE`.
6. Command injection: `exec`, `spawn` with `shell: true`, `os.system`, `subprocess(..., shell=True)`, any shell command including input.

**Fix:** bound parameters / safe query builders; dynamic identifiers mapped through a hard-coded allowlist (`sort=price` → `"price"`); type-check NoSQL inputs (strings must be strings); argument arrays without a shell; least-privilege DB user.

**Verify:** tests sending `' OR '1'='1`, `'; DROP TABLE users; --`, `{"$ne": null}` to every affected input → normal empty/400 responses, never extra data or DB errors.

**Watch out:** `$queryRaw` vs `$queryRawUnsafe` look almost identical. DB error messages help attackers; hide them (20).

---

## 18 Restrict file upload types and sizes
**HIGH.** Uploads are among the riskiest features: malware, HTML/SVG that runs script on your domain, huge files that eat storage, filenames like `../../app.js`.

**Audit**
1. Every upload path: forms, avatars, attachments, CSV/Excel imports, drag-and-drop, presigned/direct-to-storage (S3, R2, Supabase Storage, Firebase Storage, UploadThing, Cloudinary), AI features accepting files.
2. For each: auth required? checks (client only or server)? storage location? naming? how served (domain, Content-Type, Content-Disposition)? public?

**Fix** (enforced on the server or in storage policies, never only in the browser)
1. **Type:** allowlist per feature (avatars: jpeg, png, webp). Check extension AND real content via magic bytes (e.g. `file-type`, `python-magic`, or checking the header bytes); don't trust client Content-Type. Block HTML, SVG, XML, JS and executables unless truly needed.
2. **Size:** max per file (e.g. 5 MB images) server-side (multer `limits`, `MAX_CONTENT_LENGTH`) and in presigned conditions (`content-length-range`) or bucket limits; max files per request; per-user quota.
3. **Names/paths:** random names (UUID). Never use the user's filename in a storage path (path traversal). Keep the original only as escaped display text.
4. **Storage:** object storage or a folder outside the web root, private by default; serve private files via short-lived signed URLs after an authorization check.
5. **Serving:** correct Content-Type, `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment` for anything that isn't a displayed image. Ideally a separate domain for user files.
6. **Images:** re-encode with sharp/Pillow (strips payloads and EXIF/GPS); cap pixel dimensions (decompression bombs).
7. **Archives/CSV:** cap uncompressed size and file count; for CSV exports prefix cells starting with `=`, `+`, `-`, `@` (formula injection).
8. Files shared between users: malware scanning or a recommended service.

**Verify:** tests uploading a renamed `.html`, a script-bearing `.svg`, an oversized file and a `../` filename → all rejected or neutralised.

**Watch out:** presigned uploads skip your server, so limits must live in the presigned policy or bucket rules. Public buckets are often listable.

---

## 19 Verify prices and payments
**CRITICAL.** The server decides what things cost, and only a verified payment unlocks anything. Classics: the checkout request edited from $49.00 to $1.00; visiting `/checkout/success` marks the order paid; a fake webhook upgrades an account to Pro.

**Audit:** trace the whole money flow: product/plan pages → cart → checkout → provider (Stripe, Lemon Squeezy, Paddle, PayPal, Razorpay, RevenueCat...) → success page → webhook → fulfilment/entitlement → refunds/cancellations. At each step: what does the client send, what does the server trust?

**Fix**
1. **Prices:** client sends only product/plan IDs and quantities. Server looks up prices from the DB or provider price IDs and computes every total, tax, shipping and discount. Ignore any client price/amount/currency/total.
2. **Quantities:** integers, min 1, sensible max.
3. **Money as integers in minor units**, never floats.
4. **Coupons/credits:** validated server-side (exists, not expired, usage limits, per-user limits, eligible products) and applied in a DB transaction so parallel requests can't double-use them.
5. **Fulfilment ONLY from verified webhooks** (Stripe `checkout.session.completed`, `payment_intent.succeeded`, `invoice.paid`), never from the success redirect. The success page only shows status.
6. **Webhooks:** verify the signature on the RAW body with the endpoint secret (`stripe.webhooks.constructEvent`); reject failures. Store processed event IDs (idempotency); handle out-of-order events; check amount and currency paid match the order.
7. **Subscriptions/entitlements:** access decided server-side from webhook-stored status, never a client flag or `?plan=pro`. Handle cancellations, failed payments, refunds, disputes.
8. **Balances/credits/stock:** atomic updates in transactions (no race-condition double spend).
9. Card data never touches the server; use hosted checkout/elements.
10. Test keys in dev, live only in prod. Webhook route exempt from CSRF but signature-verified.

**Verify:** tests for a tampered price, negative quantity, reused coupon, success URL without paying, unsigned/forged webhook, the same webhook twice. Give the provider CLI steps (`stripe listen --forward-to localhost:3000/api/webhook`, `stripe trigger checkout.session.completed`).

**Watch out:** parsing the webhook body as JSON before verifying breaks signature checks; many frameworks need raw-body config on that route (`express.raw({type: 'application/json'})`). Free trials and referral logic leak money too; make sure they can't be reused endlessly with new emails.
