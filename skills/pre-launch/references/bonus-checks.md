# Bonus checks B1–B7 and incident response

Apply B1, B2 and B5 when the app has the matching feature (they include code changes). B3, B4, B6 and B7 are mostly checklists for the person; summarise them into the report's "Manual actions" section, tailored to the services this app actually uses.

---

## B1 Secure AI features (HIGH), for any LLM call
Users can hijack an LLM with prompt injection, extract the system prompt, trigger actions they shouldn't, or run up the bill. Text in uploaded documents or fetched web pages carries the same attacks.
1. List each AI call: model, where the key lives (server-only), what user content/documents go into the prompt, what the output is used for.
2. Prompt injection: assume any user text, file, email or page fed to the model is hostile. The model must not see secrets or other users' data, must not access data beyond the current user's permissions, and must not trigger tools/actions beyond that user's permissions. Destructive or costly actions need explicit user confirmation.
3. Model output is untrusted: sanitise before rendering as HTML/Markdown (07); validate before using in queries, URLs, code or commands.
4. Cost abuse: auth required, per-user rate limits and daily quotas, max input and output tokens, provider-side monthly spending cap.
5. Privacy: send only the personal data needed; log prompts carefully or not at all.

## B2 Block SSRF (HIGH), for any server-side fetch of a user-influenced URL
Link previews, "import from URL", image-from-URL, outgoing webhooks, PDF/screenshot generation, AI browsing tools. These can be pointed at internal networks or the cloud metadata service (169.254.169.254) to steal credentials.
- Allow only http/https. Resolve the hostname and block private, loopback, link-local and internal ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1, fc00::/7, 0.0.0.0) for the initial request AND every redirect (or disable redirects).
- Domain allowlist where possible; short timeouts; max response size; no raw internal error details.
- Use a maintained SSRF-protection library if one fits. Add tests with internal addresses.

## B3 Backups you can restore (HIGH)
What's backed up (DB, files, config), how often, where, how long; point-in-time recovery available? Are backups protected from production credentials (so one mistake or attacker can't delete both)? Offer to write `RESTORE.md` with step-by-step restore to a new environment and a test-restore procedure. Give exact dashboard steps for the minimum setup on their plan.

## B4 Lock down your own accounts (CRITICAL)
One phished password on GitHub, the host, the domain registrar, the DB dashboard, Stripe or email bypasses every check. From the codebase, list every service the person depends on (code hosting, deploy, DNS/registrar, DB, auth, payments, email, AI, analytics, error tracking, app stores). Checklist per service: MFA on (authenticator app or passkey, not SMS) · remove team members who don't need access · least-privilege roles · review connected OAuth apps/integrations · review active API keys and deploy tokens · login/security alerts on · domain lock at the registrar.

## B5 Spending caps and abuse alarms (HIGH), for usage-billed services
The most likely "attack" on a vibe-coded app is a surprise bill. For each usage-billed service (hosting, serverless, DB, storage, bandwidth, AI, email, SMS, maps, search): how to set (1) a billing alert, (2) a hard cap/quota if supported, (3) per-key usage limits. For SMS, restrict destination countries. Add app-level per-user quotas on the most expensive features and a daily usage summary log line.

## B6 Privacy and data minimisation (MEDIUM)
Map personal data: where stored, who sees it, which third parties receive it (analytics, AI providers, email, error tracking), retention. Flag unneeded data; keep personal data out of analytics/error tracking; implement or plan account deletion (DB, storage, third parties) and data export; list what the privacy policy must mention. GDPR, India's DPDP Act and CCPA may require these. Note which items need legal review.

## B7 Protect the email domain (MEDIUM)
Without SPF, DKIM and DMARC, anyone can send "reset your password" phishing that looks like it's from the app's domain. Based on the email providers used: SPF (one record listing all senders), DKIM (from each provider), DMARC (start `p=none` with a reporting address, then quarantine/reject once reports are clean). Emails shouldn't include unnecessary sensitive data; links use the configured `APP_URL`. Verify with a free checker (e.g. MXToolbox).

---

## Incident response: if something has already gone wrong

If, during the pass, you find evidence the app may already be compromised (a key exposed publicly for a long time, unexplained admin users, odd data), tell the person immediately, and don't bury it in the report.

1. **Keep evidence.** Don't delete logs, users or the repo.
2. **Stop the bleeding.** Rotate exposed keys (25): payments, cloud and DB first. For an actively leaked payment/cloud/AI key, revoke immediately even before a replacement is deployed. Maintenance mode for the affected feature if needed.
3. **Kill sessions.** Rotate session/JWT secrets or revoke sessions; force password resets for affected accounts.
4. **Investigate.** App logs, DB logs, provider dashboards: when it started, what was accessed, which accounts.
5. **Close the hole.** Fix, add a test proving it's fixed (27), deploy.
6. **Check data.** Read, changed, deleted? Backups intact (B3)?
7. **Tell people.** If personal data was affected, tell users honestly. GDPR (72-hour regulator notice), India's DPDP Act and others may require formal notification; get legal advice.
8. **Learn.** Short post-mortem: cause, impact, fix, prevention.

## After launch: re-run checks when adding...
| Adding | Re-run |
|---|---|
| Login or sign-up | 01, 05, 12, 15, 16, 17, 30 |
| A new table | 03, 06, 10, 28 |
| A new API route / server action | 01, 03, 06, 09, 12, 29 |
| Sensitive personal data (IDs, health, finance) | 28, 29, B6 |
| A public form (contact, waitlist, invites) | 06, 12, 30 |
| Comments, profiles, any user text | 06, 07, 12 |
| Payments or subscriptions | 06, 12, 19, 08 |
| File uploads | 18, 03, 12 |
| A new third-party API / key | 02, 11, B5 |
| An admin tool | 09, 08, 07 |
| AI / LLM features | 02, 07, 12, B1, B5 |
| Fetching user-supplied URLs | B2, 06 |
| A new package | 21 (check it's real first) |
| Before every launch | 23, 20, 26, 27 |

Suggest adding a short security section to the project's `CLAUDE.md` / `.cursorrules` so new code is written safely, e.g.: "Every API route must call requireUser() and validate input with Zod. Never use secret keys in client code. Never trust prices from the client. All new tables need RLS policies. Return only allowlisted fields. Encrypt sensitive fields with encryptField(). Ask before adding packages."
