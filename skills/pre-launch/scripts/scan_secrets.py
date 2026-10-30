#!/usr/bin/env python3
"""Find secret-looking strings in a project, its Git history, and its build output.

Values are always masked (first 4 characters only) so the output is safe to show.

Usage:
  python scan_secrets.py <project-dir>                    # working tree only
  python scan_secrets.py <project-dir> --history          # + every commit on every branch
  python scan_secrets.py <project-dir> --build dist       # + a production build folder
  python scan_secrets.py <project-dir> --history --json   # machine-readable output

If gitleaks or trufflehog is installed, --history also tells you the command to run with it,
because those tools have far larger rule sets. This script is the always-available fallback.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

# (name, regex). Keep patterns specific enough to avoid drowning the user in noise.
PATTERNS = [
    ("Stripe secret key", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{10,}"),
    ("Stripe webhook secret", r"\bwhsec_[0-9A-Za-z]{10,}"),
    ("Anthropic API key", r"\bsk-ant-[0-9A-Za-z_\-]{20,}"),
    ("OpenAI API key", r"\bsk-(?:proj-|svcacct-)?[0-9A-Za-z_\-]{20,}"),
    ("AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{30,}|\bgithub_pat_[0-9A-Za-z_]{40,}"),
    ("Slack token", r"\bxox[abposr]-[0-9A-Za-z\-]{10,}"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}"),
    ("SendGrid key", r"\bSG\.[0-9A-Za-z_\-]{16,}\.[0-9A-Za-z_\-]{16,}"),
    ("Twilio key", r"\bSK[0-9a-fA-F]{32}\b"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("DB URL with password", r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@'\"]+:[^\s@'\"]{3,}@[^\s'\"]+"),
    ("JWT", r"\beyJ[0-9A-Za-z_\-]{10,}\.eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}"),
    ("Supabase service_role mention", r"service_role"),
    # Generic assignment: name contains secret-ish word and value is a long-ish literal.
    ("Generic secret assignment",
     r"(?i)\b[\w\-]*(?:secret|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|private[_\-]?key|password|passwd|client[_\-]?secret)[\w\-]*\b"
     r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"),
]
COMPILED = [(n, re.compile(p)) for n, p in PATTERNS]

# Values that are obviously placeholders, not real secrets.
PLACEHOLDER = re.compile(
    r"(?i)(your[_\-]?|example|placeholder|changeme|xxxx|\*\*\*|<.*>|\$\{|process\.env|os\.environ|getenv|import\.meta|dummy|test123|redacted)"
)

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", ".next", ".nuxt",
             "dist", "build", "out", "coverage", ".pytest_cache", ".mypy_cache", "vendor", ".turbo"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".woff",
            ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".lock", ".exe", ".dll", ".so", ".pyc"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}


def mask(value: str) -> str:
    value = value.strip()
    return value[:4] + "****" if len(value) > 4 else "****"


def scan_text(text, where, findings, commit=None):
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 20000:  # minified bundles: scan a prefix, don't explode
            line = line[:20000]
        specific_hit = False
        for name, rx in COMPILED:
            for m in rx.finditer(line):
                val = m.group(1) if m.groups() else m.group(0)
                if name == "Generic secret assignment":
                    # Skip placeholders, code expressions, and lines a specific rule already caught.
                    if specific_hit or PLACEHOLDER.search(val) or val.startswith("{") or "(" in val:
                        continue
                elif name != "Supabase service_role mention":
                    specific_hit = True
                if name == "Supabase service_role mention":
                    val = "service_role"
                findings.append({
                    "type": name,
                    "file": where,
                    "line": lineno,
                    "commit": commit,
                    "masked": mask(val) if name != "Supabase service_role mention" else "(keyword)",
                })


def walk_files(root, skip_dirs=SKIP_DIRS):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            if fn in SKIP_FILES or os.path.splitext(fn)[1].lower() in SKIP_EXT:
                continue
            path = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(path) > 5_000_000:
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    yield path, f.read()
            except OSError:
                continue


def git(args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="ignore")


def scan_history(root, findings):
    if git(["rev-parse", "--is-inside-work-tree"], root).returncode != 0:
        return {"error": "not a git repository"}
    info = {}
    # Every .env-like file ever committed, on any branch.
    r = git(["log", "--all", "--diff-filter=A", "--name-only", "--pretty=format:%H %ad", "--date=short"], root)
    ever = {}
    current = None
    for line in r.stdout.splitlines():
        if re.match(r"^[0-9a-f]{40} ", line):
            current = line.split(" ", 1)
        elif line.strip() and re.search(r"(^|/)\.env(\.|$)|\.pem$|id_rsa|credentials\.json$|service[-_]?account.*\.json$", line):
            if not line.endswith(".example") and not line.endswith(".sample"):
                ever.setdefault(line.strip(), current)
    info["sensitive_files_ever_committed"] = [
        {"file": f, "first_commit": c[0][:10] if c else None, "date": c[1] if c else None} for f, c in ever.items()
    ]
    tracked = git(["ls-files"], root).stdout.splitlines()
    info["sensitive_files_tracked_now"] = [f for f in tracked if f in ever]

    # Pattern scan of every added line in every commit.
    r = git(["log", "--all", "-p", "--no-color", "--unified=0", "--pretty=format:@@COMMIT %H %ad", "--date=short"], root)
    commit, date, fname, lineno = None, None, None, 0
    for raw in r.stdout.splitlines():
        if raw.startswith("@@COMMIT "):
            _, commit, date = raw.split(" ", 2)
        elif raw.startswith("+++ b/"):
            fname = raw[6:]
        elif raw.startswith("@@ "):
            m = re.search(r"\+(\d+)", raw)
            lineno = int(m.group(1)) - 1 if m else 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            lineno += 1
            if fname and (os.path.basename(fname) in SKIP_FILES or os.path.splitext(fname)[1].lower() in SKIP_EXT):
                continue
            before = len(findings)
            scan_text(raw[1:], fname, findings, commit=f"{commit[:10]} ({date})")
            for f in findings[before:]:
                f["line"] = lineno
    return info


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--history", action="store_true", help="scan every commit on every branch")
    ap.add_argument("--build", action="append", default=[], help="build output folder to scan (repeatable)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    root = os.path.abspath(a.root)

    tree, hist, build = [], [], []
    for path, text in walk_files(root):
        scan_text(text, os.path.relpath(path, root), tree)
    for b in a.build:
        bdir = b if os.path.isabs(b) else os.path.join(root, b)
        for path, text in walk_files(bdir, skip_dirs={".git", "node_modules"}):
            scan_text(text, os.path.relpath(path, root), build)
    hist_info = scan_history(root, hist) if a.history else None

    # Deduplicate history hits by (type, masked, file) keeping the earliest seen.
    seen, hist_dedup = set(), []
    for f in reversed(hist):
        k = (f["type"], f["masked"], f["file"])
        if k not in seen:
            seen.add(k)
            hist_dedup.append(f)
    hist_dedup.reverse()

    tools = {t: bool(shutil.which(t)) for t in ("gitleaks", "trufflehog")}
    result = {"working_tree": tree, "build_output": build, "git_history": hist_dedup,
              "git_history_info": hist_info, "external_tools_available": tools}
    if a.json:
        print(json.dumps(result, indent=2))
        return

    def show(title, items):
        print(f"\n== {title}: {len(items)} hit(s) ==")
        for f in items:
            c = f" commit {f['commit']}" if f.get("commit") else ""
            print(f"  [{f['type']}] {f['file']}:{f['line']}{c}  value={f['masked']}")

    show("Working tree", tree)
    if a.build:
        show("Build output (this is what ships to browsers)", build)
    if a.history:
        if hist_info and hist_info.get("error"):
            print(f"\n== Git history: skipped ({hist_info['error']}) ==")
        else:
            show("Git history (all branches, earliest occurrence)", hist_dedup)
            print("\n== Sensitive files ever committed ==")
            for f in hist_info["sensitive_files_ever_committed"] or []:
                print(f"  {f['file']}  first added {f['first_commit']} ({f['date']})")
            if not hist_info["sensitive_files_ever_committed"]:
                print("  none")
            if hist_info["sensitive_files_tracked_now"]:
                print("  STILL TRACKED NOW:", ", ".join(hist_info["sensitive_files_tracked_now"]))
    if any(tools.values()):
        print("\nTip: deeper scan available:",
              "gitleaks git -v" if tools["gitleaks"] else "", "trufflehog git file://. --only-verified" if tools["trufflehog"] else "")
    print("\nAnything real found here goes on the rotation list (check 25). Deleting it from code or history does not un-leak it.")


if __name__ == "__main__":
    sys.exit(main())
