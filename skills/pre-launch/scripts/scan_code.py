#!/usr/bin/env python3
"""Find risky code patterns, grouped by pre-launch check number.

These are LEADS, not verdicts: confirm each one by reading the code. The script cannot see
logic bugs (missing auth checks, IDOR, webhook flows), so it never replaces the manual audit.

Usage:
  python scan_code.py <project-dir>          # human-readable, grouped by check
  python scan_code.py <project-dir> --json
"""
import argparse
import json
import os
import re
import sys
from collections import defaultdict

# (check, label, regex, file-extension filter or None)
JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".astro"}
PY = {".py"}
TPL = {".html", ".jinja", ".jinja2", ".j2", ".ejs", ".hbs", ".handlebars", ".njk", ".erb", ".php"}
ANY = None

RULES = [
    # 07 XSS
    ("07", "dangerouslySetInnerHTML", r"dangerouslySetInnerHTML", JS),
    ("07", "innerHTML / outerHTML assignment", r"\.(?:inner|outer)HTML\s*\+?=", JS),
    ("07", "insertAdjacentHTML / document.write", r"insertAdjacentHTML|document\.write\s*\(", JS),
    ("07", "Vue v-html / Svelte {@html}", r"v-html=|\{@html", JS),
    ("07", "jQuery .html() with value", r"\.html\(\s*[^)\s]", JS),
    ("07", "Template autoescape bypass", r"\|\s*safe\b|mark_safe\(|Markup\(|autoescape\s+(?:false|off)|<%-|\{\{\{", TPL | PY),
    ("07", "render_template_string (SSTI/XSS risk)", r"render_template_string\(", PY),
    ("07", "eval / new Function / string timers", r"\beval\s*\(|new\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*['\"`]", JS),
    # 10 Injection
    ("10", "SQL built with template literal", r"`\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b[^`]*\$\{", JS),
    ("10", "SQL built with + concatenation", r"(?i)['\"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*['\"]\s*\+", ANY),
    ("10", "SQL built with f-string / format / %", r"(?i)\bf(['\"])\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b.*\{|['\"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*['\"]\s*(?:%|\.format\()", PY),
    ("10", "ORM raw escape hatch", r"\$queryRawUnsafe|\$executeRawUnsafe|Prisma\.raw|sequelize\.literal|\.literal\(|knex\.raw\(|sql\.raw\(|\.extra\(|\.raw\(\s*f['\"]|text\(\s*f['\"]", ANY),
    ("10", "Shell command execution", r"child_process|\bexecSync?\s*\(|shell\s*:\s*true|os\.system\(|shell\s*=\s*True|subprocess\.(?:call|run|Popen)\([^)]*shell", ANY),
    ("10", "NoSQL query from raw request object", r"\.find(?:One)?\(\s*req\.(?:body|query)", JS),
    # 05 Password hashing
    ("05", "Weak/fast hash (md5/sha1/sha256) - check if used for passwords",
     r"(?i)createHash\(\s*['\"](?:md5|sha1|sha256)['\"]|hashlib\.(?:md5|sha1|sha256)\(|\bmd5\(|\bsha1\(", ANY),
    ("05", "Plain password comparison", r"(?i)password\s*===?\s*|==\s*\w*password\b", ANY),
    # 11 / 02 env and secrets
    ("11", "Insecure env fallback", r"(?i)process\.env\.\w*(?:SECRET|KEY|TOKEN|PASS)\w*\s*(?:\|\||\?\?)\s*['\"`]|os\.(?:environ\.get|getenv)\(\s*['\"]\w*(?:SECRET|KEY|TOKEN|PASS)\w*['\"]\s*,\s*['\"][^'\"]+['\"]", ANY),
    ("02", "Public-prefixed env var that looks secret",
     r"(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|PUBLIC_)\w*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|TOKEN|SK_|_KEY)\w*", ANY),
    ("02", "Secret-looking key literal", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{8,}|\bsk-(?:ant-|proj-)?[0-9A-Za-z_\-]{20,}|\bAKIA[0-9A-Z]{16}\b", ANY),
    # 15 sessions
    ("15", "Token stored in localStorage/sessionStorage", r"(?i)(?:local|session)Storage\.setItem\(\s*['\"][^'\"]*(?:token|jwt|session|auth)", JS),
    ("15", "Cookie flags weakened", r"httpOnly\s*:\s*false|secure\s*:\s*false|SESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False|sameSite\s*:\s*['\"]none", ANY),
    ("15", "Hard-coded session/JWT secret", r"(?i)(?:secret|SECRET_KEY|jwtSecret)\s*[:=]\s*['\"][^'\"]{1,40}['\"]", ANY),
    ("01", "JWT decoded without verification", r"jwt\.decode\(|jwtDecode\(|verify_signature['\"]?\s*:\s*False|algorithms\s*=\s*\[\s*['\"]none", ANY),
    # 13 CORS
    ("13", "Wildcard or reflected CORS", r"cors\(\s*\)|origin\s*:\s*(?:['\"]\*['\"]|true)|Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*|CORS\(\s*app\s*\)|origins\s*=\s*['\"]\*", ANY),
    # 16 CSRF
    ("16", "State change via GET route", r"\.get\(\s*['\"][^'\"]*(?:delete|remove|logout|update|cancel|subscribe|upgrade)[^'\"]*['\"]|@app\.route\([^)]*(?:delete|remove|logout)[^)]*\)", ANY),
    ("16", "CSRF protection disabled", r"(?i)csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|csrf\s*:\s*false", ANY),
    # 19 payments
    ("19", "Price/amount read from client request", r"(?:req\.body|request\.(?:json|form|get_json\(\)))\s*(?:\.|\[['\"])\s*(?:price|amount|total|unit_amount|cost)", ANY),
    ("19", "Fulfilment on success/redirect page", r"(?i)['\"][^'\"]*(?:/success|/thank-?you|payment[_-]?success)[^'\"]*['\"]", ANY),
    ("19", "Webhook without signature verification? (check)", r"(?i)['\"][^'\"]*webhook[^'\"]*['\"]", ANY),
    # 20 debug
    ("20", "Debug mode on", r"debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|APP_DEBUG\s*=\s*true|FLASK_DEBUG\s*=\s*1", ANY),
    ("20", "Error details sent to client", r"(?:err|error|e)\.stack|res\.(?:status\(\d+\)\.)?(?:json|send)\([^)]*(?:err|error|e)\.message|traceback\.format_exc\(\)|str\(e\)", ANY),
    ("20", "X-Powered-By not disabled (Express)", r"express\(\)", JS),
    # 23 exposed files
    ("23", "Static serving of project root", r"express\.static\(\s*(?:__dirname|['\"]\.?/?['\"]|process\.cwd\(\))\s*\)|static_folder\s*=\s*['\"]\.?['\"]", ANY),
    # 18 uploads
    ("18", "File upload handling (check type/size/name)", r"multer\(|upload\.(?:single|array|fields)\(|request\.files|formidable|busboy|UploadFile", ANY),
    ("18", "User filename used in path", r"originalname|file\.filename|secure_filename", ANY),
    # 17 reset tokens
    ("17", "Weak token generation", r"Math\.random\(\)|uuid\.uuid1\(|Date\.now\(\)\.toString|random\.random\(\)|random\.randint\(", ANY),
    ("17", "Link built from Host header", r"req\.(?:headers\.host|get\(['\"]host['\"]\))|request\.host(?:_url)?\b|request\.headers\[['\"]Host", ANY),
    # 04 HTTPS
    ("04", "Hard-coded http:// URL (non-localhost)", r"['\"`]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|www\.w3\.org)[^'\"`\s]+", ANY),
    # 03 / 06 Field tampering (mass assignment)
    ("06", "Request body spread/passed straight into a write (field tampering)",
     r"\.\.\.\s*req\.body|Object\.assign\(\s*\w+\s*,\s*req\.body|\.(?:create|update|insert|upsert|updateOne|findByIdAndUpdate|findOneAndUpdate|save)\(\s*(?:\{\s*data\s*:\s*)?req\.body\b|\*\*\s*(?:request\.(?:json|form|get_json\(\))|data|payload|body)\b|\.update\(\s*request\.(?:json|form)", ANY),
    ("03", "Supabase/Firebase privileged key name (must be server-only)",
     r"(?i)service_role|SUPABASE_SECRET|sb_secret_|SERVICE_ACCOUNT|firebase-admin|FIREBASE_PRIVATE_KEY", JS),
    ("03", "Table created without RLS? (check every table has ENABLE ROW LEVEL SECURITY)",
     r"(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?\w+", {".sql"}),
    ("03", "RLS disabled / permissive rule", r"(?i)disable\s+row\s+level\s+security|using\s*\(\s*true\s*\)|allow\s+read\s*,\s*write\s*:\s*if\s+true|allow\s+(?:read|write)\s*:\s*if\s+request\.time", ANY),
    # 28 Encrypt sensitive data
    ("28", "Sensitive field name (check it's encrypted at field level)",
     r"(?i)\b(?:ssn|social_?security|national_?id|passport(?:_?(?:no|number))?|tax_?id|tin_number|iban|account_?number|routing_?number|card_?number|cvv|cvc|date_?of_?birth|\bdob\b|diagnosis|medical|health_?record|totp_?secret|mfa_?secret|refresh_?token|access_?token)\b\s*[:=(]|\b(?:ssn|card_number|account_number|date_of_birth|diagnosis|totp_secret)\s+(?:text|varchar|string|char)", ANY),
    ("28", "Weak or broken encryption", r"createCipher\(|aes-\d+-ecb|AES\.MODE_ECB|DES\.new\(|des-ede|\bRC4\b|createCipheriv\(\s*['\"]aes-\d+-cbc|Buffer\.alloc\(\s*16\s*(?:,\s*0)?\s*\)|iv\s*=\s*b?['\"]0+", ANY),
    ("28", "Base64 used as if it were encryption? (check)", r"(?i)(?:encrypt|cipher|secure)\w*\s*[=:(][^\n]*(?:btoa\(|b64encode\(|toString\(['\"]base64)", ANY),
    # 29 Trim API responses
    ("29", "Whole object/row returned to client (check fields are allowlisted)",
     r"res\.(?:status\(\d+\)\.)?(?:json|send)\(\s*(?:user|users|account|profile|row|rows|result|results|doc|docs|record|records|data)\s*\)|return\s+(?:jsonify|JsonResponse|Response)\(\s*\w+\.__dict__|jsonify\(\s*(?:user|users|row|rows|result)\s*\)|model_to_dict\(|fields\s*=\s*['\"]__all__['\"]", ANY),
    ("29", "SELECT * / select('*') (check no private columns reach the client)", r"(?i)select\s+\*\s+from|\.select\(\s*['\"]\*['\"]\s*\)", ANY),
    ("29", "Relation included wholesale (check the related object's fields)", r"include\s*:\s*\{\s*\w+\s*:\s*true|\.populate\(\s*['\"]\w+['\"]\s*\)|depth\s*=\s*\d", ANY),
    ("29", "Client-controlled limit/page size (check server max)", r"(?:req\.query|request\.args|searchParams\.get\()\s*(?:\.|\[['\"]|\(['\"])\s*(?:limit|per_?page|page_?size|take|count)", ANY),
    # 30 Bot protection
    ("30", "Public sign-up/contact/reset handler (check bot protection, verified server-side)",
     r"(?i)(?:\.post\(|@\w+\.(?:post|route)\(|path\(|route\()\s*['\"][^'\"]*(?:sign-?up|register|contact|feedback|waitlist|newsletter|forgot|reset-password|magic-link|send-?(?:otp|sms|code)|invite|comment)", ANY),
    ("30", "CAPTCHA widget/verify call (confirm token is checked on the server)",
     r"(?i)turnstile|hcaptcha|recaptcha|siteverify|friendlycaptcha|app_?check|botid", ANY),
    # B2 SSRF
    ("B2", "Server fetch of possibly user-supplied URL", r"(?:fetch|axios\.get|requests\.get|urllib\.request\.urlopen|httpx\.get)\(\s*(?:req\.|request\.|url\b|body\.)", ANY),
    # B1 AI
    ("B1", "LLM API call (check auth, quotas, output handling)", r"openai|anthropic|generativeai|chat\.completions|messages\.create", ANY),
]
COMPILED = [(c, l, re.compile(p), e) for c, l, p, e in RULES]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", ".next", ".nuxt", "dist", "build",
             "out", "coverage", ".pytest_cache", "vendor", ".turbo", ".claude"}
CODE_EXT = JS | PY | TPL | {".json", ".yml", ".yaml", ".toml", ".env", ".rb", ".go", ".java", ".cs", ".php", ".sql"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    root = os.path.abspath(a.root)

    hits = defaultdict(list)
    files_scanned = 0
    env_files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            ext = os.path.splitext(fn)[1].lower()
            if fn.startswith(".env"):
                env_files.append(rel)
                ext = ".env"
            if ext not in CODE_EXT or fn in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.read().splitlines()
            except OSError:
                continue
            files_scanned += 1
            for i, line in enumerate(lines, 1):
                if len(line) > 3000:
                    continue  # minified
                for check, label, rx, exts in COMPILED:
                    if exts is not None and ext not in exts:
                        continue
                    if rx.search(line):
                        hits[(check, label)].append({"file": rel, "line": i, "code": line.strip()[:160]})

    if a.json:
        print(json.dumps({"files_scanned": files_scanned, "env_files": env_files,
                          "hits": [{"check": c, "label": l, "matches": m} for (c, l), m in sorted(hits.items())]}, indent=2))
        return
    print(f"Scanned {files_scanned} files under {root}")
    if env_files:
        print(f"\n.env-style files present: {', '.join(env_files)}  (check 11/23: are they gitignored? served publicly?)")
    for (check, label), matches in sorted(hits.items()):
        print(f"\n[{check}] {label}: {len(matches)}")
        for m in matches[:25]:
            print(f"   {m['file']}:{m['line']}  {m['code']}")
        if len(matches) > 25:
            print(f"   ... {len(matches) - 25} more")
    print("\nThese are leads. Confirm each by reading the code; then audit what no regex can see:"
          " auth on every handler (01), ownership checks/IDOR (03), admin role checks (09), webhook flow (19),"
          " which response fields the UI really needs (29), whether a CAPTCHA token is verified server-side (30).")


if __name__ == "__main__":
    sys.exit(main())
