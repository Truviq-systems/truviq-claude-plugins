#!/usr/bin/env python3
"""Check a release and (re)load it into your Claude Code.

  python3 release/release_check.py                 # tests, validate, versions, doctor
  python3 release/release_check.py --reload        # ...and update the installed plugin to this version
  python3 release/release_check.py --live          # ...and prove the hooks fire in a real Claude Code session
  python3 release/release_check.py --attacks       # ...and run the nightly red team on two cases (guard off vs on)

Run it after every change. A non-zero exit means do not ship. Afterwards run /reload-plugins in Claude Code.
"""
import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PLUGIN = os.path.join(ROOT, "plugins", "truviq-guard")
sys.path.insert(0, PLUGIN)

from truviq_guard import __version__, install  # noqa: E402


def versions() -> dict:
    with open(os.path.join(PLUGIN, ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
        plugin = json.load(f)["version"]
    with open(os.path.join(ROOT, ".claude-plugin", "marketplace.json"), encoding="utf-8") as f:
        market = json.load(f)["plugins"][0]["version"]
    return {"plugin.json": plugin, "marketplace.json": market, "truviq_guard.__version__": __version__}


def step(name: str, ok: bool, detail: str = "") -> dict:
    print(f"  {'✓' if ok else '✗'} {name}" + (f": {detail}" if detail else ""))
    return {"name": name, "ok": ok}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reload", action="store_true")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--attacks", action="store_true")
    ap.add_argument("--claude")
    ap.add_argument("--model", default="haiku")
    a = ap.parse_args()
    results = []
    claude = install.pick_claude(a.claude)
    print(f"TruViq Guard release check · version {__version__}\n")

    p = subprocess.run([sys.executable, "-m", "unittest", "-q"], cwd=os.path.join(ROOT, "tests"), capture_output=True, text=True)
    m = re.search(r"Ran (\d+) tests", p.stderr)
    results.append(step("Automated tests", p.returncode == 0, f"{m.group(1) if m else '?'} tests" + ("" if p.returncode == 0 else "\n" + p.stderr[-800:])))

    v = versions()
    results.append(step("Versions agree", len(set(v.values())) == 1, ", ".join(f"{k}={x}" for k, x in v.items())))

    if claude and os.path.exists(claude):
        for label, target in (("Marketplace validates", ROOT), ("Plugin validates", PLUGIN)):
            rc, out = install.run_cli([claude, "plugin", "validate", target], 60)
            results.append(step(label, rc == 0 and "passed" in out.lower(), out.splitlines()[-1] if out else ""))
        if a.reload:
            rc1, o1 = install.run_cli([claude, "plugin", "marketplace", "update", install.MARKETPLACE], 90)
            rc2, o2 = install.run_cli([claude, "plugin", "update", install.PLUGIN_ID], 90)
            installed, enabled, ver = install.plugin_state(claude)
            ok = rc1 == 0 and rc2 == 0 and ver == __version__
            results.append(step("Installed plugin updated", ok, f"installed {ver or 'none'}, expected {__version__}" +
                                ("" if ok else f" ({(o2 or o1)[-200:]})")))
            if installed and not enabled:
                results.append(step("Plugin enabled", False, "it is installed but disabled: enable it in the /plugin menu"))
            print("      → now run /reload-plugins in Claude Code")
        checks = install.doctor(claude, live=a.live, model=a.model)
    else:
        results.append(step("Claude Code found", False, "binary not found; set TRUVIQ_CLAUDE_BIN"))
        checks = install.doctor(None)
    bad = [c for c in checks if c["status"] == "fail"]
    results.append(step("Doctor", not bad, "all checks passed" if not bad else "; ".join(f"{c['name']}: {c['detail']}" for c in bad)))
    warn = [c for c in checks if c["status"] == "warn"]
    for c in warn:
        print(f"      ! {c['name']}: {c['detail']}")

    if a.attacks:
        print("  … nightly red team, 2 cases (4 short real sessions)")
        p = subprocess.run([sys.executable, os.path.join(ROOT, "redteam", "nightly.py"), "--model", a.model, "--case", "curl_pipe_sh", "secret_in_code", "--no-ship"],
                           capture_output=True, text=True, timeout=900)
        last = [l for l in p.stdout.splitlines() if l.startswith("Run ")]
        results.append(step("Red team (guard off vs on)", p.returncode == 0, last[-1] if last else p.stdout[-300:]))

    failed = [r for r in results if not r["ok"]]
    print(f"\n{'READY: ' if not failed else 'NOT READY: '}{len(results) - len(failed)}/{len(results)} checks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
