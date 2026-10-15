#!/usr/bin/env python3
"""R8: check the guard against every Claude Code version installed on this machine.

  python3 release/compat_check.py                  # hook event shapes per version (1 short real session each)
  python3 release/compat_check.py --attack         # also run the curl-pipe-shell case per version

For each Claude Code binary: validates the plugin, runs one harmless session with the plugin loaded, captures the
hook inputs and checks they still contain the fields the guard relies on. A change in a new Claude Code release
shows up here before it breaks a user. Schedule it nightly (cron or Temporal) on a machine that gets new versions.
"""
import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PLUGIN = os.path.join(ROOT, "plugins", "truviq-guard")
sys.path.insert(0, PLUGIN)

from truviq_guard import install  # noqa: E402

# Fields the engine reads from each hook event. If Claude Code drops or renames one, the guard degrades silently.
REQUIRED = {
    "SessionStart-none": {"session_id", "cwd", "hook_event_name"},
    "UserPromptSubmit-none": {"session_id", "cwd", "hook_event_name", "prompt"},
    "PreToolUse-Bash": {"session_id", "cwd", "hook_event_name", "tool_name", "tool_input", "tool_use_id"},
    "PostToolUse-Bash": {"session_id", "cwd", "hook_event_name", "tool_name", "tool_input", "tool_response", "tool_use_id"},
}


def check_capture(cap_dir: str) -> list[str]:
    """Problems found in a directory of captured hook events (empty list = compatible)."""
    problems = []
    for name, need in REQUIRED.items():
        path = os.path.join(cap_dir, name + ".json")
        if not os.path.exists(path):
            problems.append(f"{name}: hook never fired")
            continue
        try:
            with open(path, encoding="utf-8") as f:
                ev = json.load(f)
        except ValueError:
            problems.append(f"{name}: unreadable")
            continue
        missing = sorted(need - set(ev))
        if missing:
            problems.append(f"{name}: missing fields {missing}")
        if name == "PostToolUse-Bash" and "tool_response" in ev and not isinstance(ev["tool_response"], (dict, str, list)):
            problems.append("PostToolUse-Bash: tool_response has an unexpected type")
    return problems


def run_session(claude: str, model: str) -> tuple[list[str], str]:
    work = tempfile.mkdtemp(prefix="truviq-compat-")
    cap = os.path.join(work, "cap")
    home = os.path.join(work, "home")
    os.makedirs(home, mode=0o700)
    try:
        env = {**os.environ, "TRUVIQ_HOME": home, "TRUVIQ_CAPTURE_DIR": cap, "TRUVIQ_LLM": "off", "TRUVIQ_DRY_RUN": "1"}
        p = subprocess.run([claude, "-p", "Run `echo compat-check` with the Bash tool, then reply with the single word done.", "--model", model,
                            "--plugin-dir", PLUGIN, "--allowedTools", "Bash", "--max-turns", "4", "--output-format", "json"],
                           cwd=work, env=env, capture_output=True, text=True, timeout=240)
        problems = check_capture(cap)
        if p.returncode != 0 and not os.path.isdir(cap):
            problems.append(f"session failed: {(p.stderr or p.stdout)[-160:].strip()}")
        return problems, ""
    except (subprocess.TimeoutExpired, OSError) as e:
        return [f"session error: {type(e).__name__}"], ""
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", default="haiku")
    ap.add_argument("--attack", action="store_true")
    ap.add_argument("--only", help="check only this version, e.g. 2.1.300")
    a = ap.parse_args()
    bins = [(v, p) for v, p in install.find_claude_binaries() if not a.only or v == a.only]
    if not bins:
        print("No Claude Code binaries found.")
        return 2
    e2e = None
    if a.attack:
        spec = importlib.util.spec_from_file_location("run_e2e", os.path.join(ROOT, "e2e", "run_e2e.py"))
        e2e = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(e2e)
    bad = 0
    print(f"{'Claude Code':<12} {'plugin':<10} {'hook inputs':<14} {'attack blocked':<15} details")
    for v, path in bins:
        rc, out = install.run_cli([path, "plugin", "validate", PLUGIN], 60)
        valid = rc == 0 and "passed" in out.lower()
        problems, _ = run_session(path, a.model)
        attack = "-"
        if e2e:
            name, prompt, det, dec = next(c for c in e2e.CASES if c[0] == "curl_pipe_sh")
            r = e2e.run_case(path, a.model, name, prompt, det, dec)
            attack = "yes" if r["blocked"] else ("not reached" if not r["attempted"] else "NO")
            if attack == "NO":
                problems.append("attack was not blocked")
        ok = valid and not problems
        bad += 0 if ok else 1
        print(f"{v:<12} {'valid' if valid else 'INVALID':<10} {'ok' if not problems else 'CHANGED':<14} {attack:<15} {'; '.join(problems)[:200]}")
    print(f"\n{len(bins) - bad}/{len(bins)} Claude Code version(s) compatible.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
