#!/usr/bin/env python3
"""Read-only external check of YOUR OWN deployed site (checks 04, 13, 14, 20, 23).

Only run this against a domain you own or are authorised to test. It sends a few dozen
ordinary GET/HEAD requests; it does not attack anything.

Usage:
  python check_live.py https://yourapp.com
  python check_live.py https://yourapp.com --api-path /api/me     # CORS probe on an API route
  python check_live.py http://localhost:3000 --no-https            # local run: skip HTTPS checks
"""
import argparse
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

EXPOSED_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.backup", "/.env.bak", "/.env.old",
    "/.git/config", "/.git/HEAD", "/.gitignore", "/.DS_Store", "/.vscode/settings.json", "/.idea/workspace.xml",
    "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql", "/database.sql", "/database.sqlite", "/data.db",
    "/db.sqlite3", "/config.json", "/config.yml", "/docker-compose.yml", "/.npmrc", "/phpinfo.php",
    "/server-status", "/swagger.json", "/openapi.json", "/docs", "/graphql", "/package.json", "/server.js",
    "/app.py", "/.htpasswd", "/debug", "/console",
]
REQUIRED_HEADERS = {
    "strict-transport-security": "HSTS (check 04/14)",
    "content-security-policy": "CSP (check 14)",
    "x-content-type-options": "nosniff (check 14)",
    "x-frame-options": "anti-clickjacking (check 14; or CSP frame-ancestors)",
    "referrer-policy": "Referrer-Policy (check 14)",
    "permissions-policy": "Permissions-Policy (check 14)",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


CTX = ssl.create_default_context()
OPENER = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=CTX))


def req(url, method="GET", headers=None):
    r = urllib.request.Request(url, method=method, headers={"User-Agent": "pre-launch-check/1.0", **(headers or {})})
    try:
        resp = OPENER.open(r, timeout=10)
        body = resp.read(4096) if method == "GET" else b""
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(4096) if method == "GET" else b""
    except Exception as e:  # network errors
        return None, {}, str(e).encode()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base")
    ap.add_argument("--api-path", default="/", help="path used for the CORS probe")
    ap.add_argument("--no-https", action="store_true", help="skip HTTPS/HSTS checks (local testing)")
    a = ap.parse_args()
    base = a.base.rstrip("/")
    u = urllib.parse.urlparse(base)
    problems = 0

    def bad(msg):
        nonlocal problems
        problems += 1
        print(f"  [FAIL] {msg}")

    def ok(msg):
        print(f"  [ OK ] {msg}")

    print(f"== Target: {base}  (only test domains you own) ==")

    # 04 HTTPS redirect
    if not a.no_https:
        print("\n-- 04 HTTPS --")
        http_url = f"http://{u.netloc}/"
        s, h, _ = req(http_url)
        loc = h.get("location", "")
        if s in (301, 308) and loc.startswith("https://"):
            ok(f"http:// redirects permanently ({s}) to {loc}")
        elif s in (302, 307) and loc.startswith("https://"):
            bad(f"http:// redirects with temporary {s}; use 301/308")
        elif s is None:
            print(f"  [ ?? ] could not reach {http_url}")
        else:
            bad(f"http:// returned {s} without redirecting to https")

    # 14 headers
    print("\n-- 14 Security headers --")
    s, h, body = req(base + "/")
    if s is None:
        print(f"  could not reach {base}: {body.decode(errors='ignore')}")
        return 1
    for name, label in REQUIRED_HEADERS.items():
        if name == "strict-transport-security" and a.no_https:
            continue
        if name in h:
            ok(f"{name}: {h[name][:90]}")
        elif name == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""):
            ok("frame-ancestors set in CSP")
        else:
            bad(f"missing {name} ({label})")
    if "unsafe-inline" in h.get("content-security-policy", "") or "unsafe-eval" in h.get("content-security-policy", ""):
        print("  [WARN] CSP contains unsafe-inline/unsafe-eval; justify or replace with nonces/hashes")
    for leak in ("x-powered-by", "server"):
        if leak in h and any(ch.isdigit() for ch in h[leak]) or leak == "x-powered-by" and leak in h:
            bad(f"{leak} reveals stack/version: {h[leak]} (check 20)")
    sc = h.get("set-cookie", "")
    if sc:
        flags = sc.lower()
        for f in ("httponly", "secure", "samesite"):
            (ok if f in flags else bad)(f"cookie flag {f} {'present' if f in flags else 'missing'} (check 15)")

    # 13 CORS
    print("\n-- 13 CORS --")
    evil = "https://evil.example"
    s, h, _ = req(base + a.api_path, headers={"Origin": evil})
    acao = h.get("access-control-allow-origin")
    acac = h.get("access-control-allow-credentials", "").lower() == "true"
    if acao == evil:
        bad(f"reflects arbitrary Origin {evil}" + (" WITH credentials" if acac else ""))
    elif acao == "*" and acac:
        bad("wildcard origin together with credentials")
    elif acao == "*":
        print(f"  [WARN] Access-Control-Allow-Origin: * on {a.api_path}; fine only for public, cookie-less data")
    else:
        ok(f"foreign origin not allowed on {a.api_path} (ACAO={acao})")
    s, h, _ = req(base + a.api_path, headers={"Origin": "null"})
    if h.get("access-control-allow-origin") == "null":
        bad("Origin: null is allowed")

    # 20 debug / 404 leakage
    print("\n-- 20 Error leakage --")
    s, h, body = req(base + "/this-page-should-not-exist-9f3a")
    text = body.decode(errors="ignore").lower()
    markers = ["traceback", "stack", "at object.", "werkzeug", "sqlstate", "syntax error", "node_modules", "/home/", "c:\\"]
    found = [m for m in markers if m in text]
    (bad if found else ok)(f"404 page {'leaks: ' + ', '.join(found) if found else 'looks generic'}")

    # 23 exposed files
    print("\n-- 23 Exposed files (anything 200 is a problem) --")
    for p in EXPOSED_PATHS:
        s, h, body = req(base + p)
        if s == 200:
            snippet = body[:60].decode(errors="ignore").replace("\n", " ")
            # SPAs often return index.html for every path: flag but note it.
            if b"<!doctype html" in body[:200].lower() or b"<html" in body[:200].lower():
                print(f"  [WARN] {p} -> 200 but looks like the SPA index page (probably fine, confirm)")
            else:
                bad(f"{p} -> 200  starts with: {snippet!r}")
        else:
            print(f"  [ OK ] {p} -> {s}")

    print(f"\n== {problems} problem(s) found ==")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
