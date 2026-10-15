#!/usr/bin/env python3
"""Export a clean copy of this marketplace for publishing to GitHub (R7).

  python3 release/export_marketplace.py OUT_DIR

Copies the marketplace, plugin, SQL, docs, tests and tooling. Never copies .env files, caches, logs or git data.
Then scans the exported tree for secrets and refuses (exit 1) if it finds any, so a key can't be published by mistake.
Next: cd OUT_DIR && git init && git add -A && git commit -m "TruViq Guard" && git remote add origin <repo> && git push
"""
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "plugins", "truviq-guard"))

from truviq_guard import secret_scan  # noqa: E402

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".claude", "runs", ".next", ".impeccable"}
SKIP_REL_DIRS = {os.path.join("dashboard-app", "out")}  # build output; the plugin already ships the built dashboard
SKIP_REL_FILES = {os.path.join("docs", "TruViq_Guard_Release_Verification_Report.pdf")}  # internal report, not for the public repo
SKIP_FILES = {".DS_Store"}
SKIP_SUFFIX = (".pyc", ".log", ".tmp", ".lock", ".bak", ".pem", ".key", ".env", ".tfvars", ".p12", ".pfx", ".tsbuildinfo")
SKIP_NAMES = {"guard.env", "credentials.json", "device.json", "enroll.json", "org_policy.json"}


def skip(name: str, is_dir: bool) -> bool:
    if is_dir:
        return name in SKIP_DIRS
    return (name in SKIP_FILES or name in SKIP_NAMES or name.startswith("service-account") or name.startswith("id_rsa")
            or (name.startswith(".env") and name != ".env.example") or name.endswith(SKIP_SUFFIX))


def export(out: str) -> tuple[int, list[str]]:
    out = os.path.abspath(out)
    if os.path.exists(out) and os.listdir(out):
        raise SystemExit(f"{out} is not empty; choose a new folder")
    copied = 0
    for d, dirs, files in os.walk(ROOT):
        rel = os.path.relpath(d, ROOT)
        dirs[:] = [x for x in dirs if not skip(x, True) and not os.path.islink(os.path.join(d, x))
                   and os.path.normpath(os.path.join(rel, x)) not in SKIP_REL_DIRS]
        if os.path.commonpath([os.path.abspath(d), out]) == out:
            continue
        for f in files:
            if skip(f, False) or os.path.islink(os.path.join(d, f)) or os.path.normpath(os.path.join(rel, f)) in SKIP_REL_FILES:  # a symlink could point at a file outside the tree
                continue
            dst = os.path.join(out, rel, f) if rel != "." else os.path.join(out, f)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(os.path.join(d, f), dst)
            copied += 1
    problems = []
    for d, _, files in os.walk(out):
        for f in files:
            p = os.path.join(d, f)
            try:
                with open(p, encoding="utf-8") as fh:
                    text = fh.read(2_000_000)
            except (UnicodeDecodeError, OSError):
                continue
            for hit in secret_scan.find(text):
                problems.append(f"{os.path.relpath(p, out)}:{hit['line']}: {hit['type']}")
    return copied, problems


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
        print(__doc__)
        return 2
    try:
        n, problems = export(sys.argv[1])
    except SystemExit as e:
        print(e)
        return 2
    if problems:
        shutil.rmtree(os.path.abspath(sys.argv[1]), ignore_errors=True)
        print("REFUSED: the export contains secrets, so it was deleted:\n  " + "\n  ".join(problems[:20]))
        return 1
    print(f"Exported {n} files to {os.path.abspath(sys.argv[1])} (no .env files, no secrets found).")
    print('Next: cd there, `git init`, commit, add your GitHub remote, push. Then others run:\n'
          '  /plugin marketplace add <owner>/<repo>\n  /plugin install truviq-guard@truviq')
    return 0


if __name__ == "__main__":
    sys.exit(main())
