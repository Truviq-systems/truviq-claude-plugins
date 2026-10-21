"""R7: customer onboarding. `install`, `doctor`, `uninstall`.

Nothing here patches Claude Code. Install = `claude plugin marketplace add` + `claude plugin install`;
uninstall reverses exactly that. The Claude Code binary is found on PATH, in the IDE extension folders, or via
the TRUVIQ_CLAUDE_BIN variable (also how the tests substitute a fake one).
"""
from __future__ import annotations

import glob
import json
import ntpath
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

from . import alerts, config, fleet, paths, quality, sink

PLUGIN_ID = "truviq-guard@truviq"
MARKETPLACE = "truviq"
HOOK_MARK = "# truviq-guard pre-commit"
EXT_DIRS = ("~/.antigravity-ide-server/extensions", "~/.vscode-server/extensions", "~/.vscode/extensions",
            "~/.cursor-server/extensions", "~/.windsurf-server/extensions")


def default_source() -> str:
    """The marketplace root that contains this plugin (works for a local checkout)."""
    return os.path.dirname(os.path.dirname(config.PLUGIN_ROOT))


def _ver(s: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", s)[:4])


def find_claude_binaries() -> list[tuple[str, str]]:
    """[(version, path)] newest first. PATH and TRUVIQ_CLAUDE_BIN are included."""
    found: dict[str, str] = {}
    env = os.environ.get("TRUVIQ_CLAUDE_BIN")
    if env and os.path.exists(env):
        found[os.path.realpath(env)] = "env"
    on_path = shutil.which("claude")
    if on_path:
        found.setdefault(os.path.realpath(on_path), "path")
    for base in EXT_DIRS:
        for p in glob.glob(os.path.join(os.path.expanduser(base), "anthropic.claude-code-*", "resources", "native-binary", "claude")):
            found.setdefault(os.path.realpath(p), "ext")
    out = []
    for p, origin in found.items():
        m = re.search(r"claude-code-(\d+(?:\.\d+)+)", p)
        out.append((m.group(1) if m else (claude_version(p) or "0"), p))
    return sorted(out, key=lambda x: _ver(x[0]), reverse=True)


def pick_claude(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    env = os.environ.get("TRUVIQ_CLAUDE_BIN")
    if env:
        return env
    bins = find_claude_binaries()
    return bins[0][1] if bins else None


def run_cli(cmd: list[str], timeout: int = 90) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)  # noqa: S603 - fixed argv, no shell
        return p.returncode, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, f"{type(e).__name__}: {e}"


def claude_version(claude: str) -> str | None:
    rc, out = run_cli([claude, "--version"], 15)
    m = re.search(r"\d+\.\d+\.\d+", out)
    return m.group(0) if rc == 0 and m else None


def _step(name: str, ok: bool, detail: str = "") -> dict:
    return {"name": name, "ok": ok, "detail": detail}


def plugin_state(claude: str) -> tuple[bool, bool, str]:
    """(installed, enabled, version) as reported by `claude plugin list`."""
    rc, out = run_cli([claude, "plugin", "list"], 30)
    if rc != 0 or "truviq-guard" not in out:
        return False, False, ""
    block = out[out.index("truviq-guard"):]
    block = block.split("\n\n", 1)[0] if "\n\n" in block else block[:400]
    m = re.search(r"Version:\s*([\d.]+)", block)
    return True, "enabled" in block.lower() and "disabled" not in block.lower(), (m.group(1) if m else "")


# ------------------------------------------------------------------ install / uninstall

def install(claude: str, source: str | None = None, git_repo: str | None = None, pull_policy: bool = True) -> list[dict]:
    source = source or default_source()
    steps: list[dict] = []
    rc, out = run_cli([claude, "plugin", "marketplace", "list"], 30)
    if rc == 0 and re.search(r"(?m)^\s*(?:❯\s*)?" + MARKETPLACE + r"\s*$", out):
        steps.append(_step("marketplace", True, f"'{MARKETPLACE}' already added"))
    else:
        rc, out = run_cli([claude, "plugin", "marketplace", "add", source], 120)
        steps.append(_step("marketplace", rc == 0, out.splitlines()[-1] if out else f"added {source}"))
        if rc != 0:
            return steps
    installed, _en, ver = plugin_state(claude)
    if installed:
        rc, out = run_cli([claude, "plugin", "update", PLUGIN_ID], 120)
        steps.append(_step("plugin", rc == 0, f"already installed ({ver}); " + (out.splitlines()[-1] if out else "updated")))
    else:
        rc, out = run_cli([claude, "plugin", "install", PLUGIN_ID], 120)
        steps.append(_step("plugin", rc == 0, out.splitlines()[-1] if out else "installed"))
    if git_repo:
        steps.append(install_git_hook(git_repo))
    steps.append(install_launcher())
    if pull_policy:
        ok, msg = fleet.pull_org_policy(config.load_secrets())
        steps.append(_step("org policy", ok or "not configured" in msg, msg))
    return steps


def _hook_target(repo: str) -> tuple[str | None, str]:
    """(path of the pre-commit hook, or None) and an error text. Refuses anything a repository could redirect."""
    repo = os.path.realpath(repo)
    rc, common = run_cli(["git", "-C", repo, "rev-parse", "--git-common-dir"], 15)
    if rc != 0:
        return None, f"{repo} is not a git repository"
    git_dir = os.path.realpath(os.path.join(repo, common))
    rc, hp = run_cli(["git", "-C", repo, "config", "--get", "core.hooksPath"], 15)
    if rc == 0 and hp.strip():
        return None, f"core.hooksPath is set ({hp.strip()[:80]}); not touching hooks outside .git"
    hooks_dir = os.path.join(git_dir, "hooks")
    if os.path.islink(hooks_dir) or (os.path.exists(hooks_dir) and os.path.realpath(hooks_dir) != hooks_dir):
        return None, f"{hooks_dir} is a symlink; refusing to write through it"
    target = os.path.join(hooks_dir, "pre-commit")
    if os.path.islink(target):
        return None, f"{target} is a symlink; refusing to write through it"
    return target, ""


def install_git_hook(repo: str) -> dict:
    target, err = _hook_target(repo)
    if not target:
        return _step("git hook", False, err)
    if os.path.exists(target):
        with open(target, encoding="utf-8", errors="replace") as f:
            if HOOK_MARK not in f.read():
                return _step("git hook", False, f"{target} exists and is not ours; not overwritten")
    cli = os.path.join(config.PLUGIN_ROOT, "bin", "truviq.py")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o755)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(f"#!/bin/sh\n{HOOK_MARK}\nexec python3 \"{cli}\" scan-staged\n")
    return _step("git hook", True, target)


def uninstall(claude: str | None, purge: bool = False, git_repo: str | None = None) -> list[dict]:
    steps: list[dict] = []
    if claude:
        rc, out = run_cli([claude, "plugin", "uninstall", PLUGIN_ID], 60)
        steps.append(_step("plugin", rc == 0 or "not installed" in out.lower() or "not found" in out.lower(), out.splitlines()[-1] if out else "removed"))
        rc, out = run_cli([claude, "plugin", "marketplace", "remove", MARKETPLACE], 60)
        steps.append(_step("marketplace", rc == 0 or "not found" in out.lower() or "no marketplace" in out.lower(), out.splitlines()[-1] if out else "removed"))
    else:
        steps.append(_step("claude", False, "Claude Code binary not found; remove the plugin from the /plugin menu"))
    if git_repo:
        target, err = _hook_target(git_repo)
        if not target:
            steps.append(_step("git hook", False, err))
        elif os.path.exists(target):
            with open(target, encoding="utf-8", errors="replace") as f:
                ours = HOOK_MARK in f.read()
            if ours:
                os.remove(target)
            steps.append(_step("git hook", True, "removed" if ours else "left in place (not ours)"))
    steps.append(remove_launcher())
    if purge:
        home = paths.guard_home()
        real = os.path.realpath(home)
        marker = os.path.join(real, ".truviq-home")
        if os.path.islink(home):
            steps.append(_step("purge", False, f"{home} is a symlink; refusing to delete through it"))
        elif real in ("/", os.path.realpath(paths.home())) or not (os.path.basename(real) == ".truviq" or os.path.exists(marker)):
            steps.append(_step("purge", False, f"refusing to delete {real}: not a TruViq folder (expected a folder named .truviq, or one containing .truviq-home)"))
        else:
            shutil.rmtree(real, ignore_errors=True)
            gone = not os.path.exists(real)
            steps.append(_step("purge", gone, f"deleted {real} (keys, policy, logs, queue)" if gone else f"could not delete everything in {real}"))
    else:
        steps.append(_step("kept", True, f"{paths.guard_home()} (keys, policy, logs) left in place; add --purge to delete it"))
    return steps


# ------------------------------------------------------------------ doctor

def _check(name: str, status: str, detail: str, fix: str = "") -> dict:
    return {"name": name, "status": status, "detail": detail, "fix": fix}


def hook_selftest(plugin_root: str | None = None) -> list[dict]:
    """Run synthetic events through the real hook script in an isolated guard home. Harmless commands only."""
    root = plugin_root or config.PLUGIN_ROOT
    hook = os.path.join(root, "bin", "guard_hook.py")
    work = tempfile.mkdtemp(prefix="truviq-doctor-")
    home = os.path.join(work, "home")
    os.makedirs(os.path.join(work, "repo", ".git"))
    os.makedirs(home, mode=0o700)
    fake_key = "AKIA" + "Q3EGTXXJ6WCFUA7V"
    cases = [("blocks a destructive command (rm -rf ~)", {"tool_name": "Bash", "tool_input": {"command": "rm -rf ~"}}, "deny"),
             ("allows a normal command (ls -la)", {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}, "allow"),
             ("blocks a secret written into code",
              {"tool_name": "Write", "tool_input": {"file_path": os.path.join(work, "repo", "settings.py"), "content": f'KEY = "{fake_key}"\n'}}, "deny")]
    out = []
    try:
        for name, ev, want in cases:
            ev = {"hook_event_name": "PreToolUse", "session_id": "doctor", "cwd": os.path.join(work, "repo"), **ev}
            env = {**{k: v for k, v in os.environ.items() if not k.startswith(("TRUVIQ_", "SUPABASE_", "RESEND_"))},
                   "TRUVIQ_HOME": home, "TRUVIQ_LLM": "off", "TRUVIQ_OFFLINE": "1", "TRUVIQ_DRY_RUN": "1"}
            t0 = time.time()
            try:
                p = subprocess.run([sys.executable, hook], input=json.dumps(ev), env=env, capture_output=True, text=True, timeout=30)  # noqa: S603
                reply = json.loads(p.stdout) if p.stdout.strip() else {}
                got = (reply.get("hookSpecificOutput") or {}).get("permissionDecision") or "allow"
                ms = int((time.time() - t0) * 1000)
                ok = got == want and p.returncode == 0
                out.append(_check(name, "ok" if ok else "fail", f"{got} in {ms} ms" if ok else f"expected {want}, got {got} (exit {p.returncode}) {p.stderr[-120:]}",
                                  "" if ok else "Reinstall the plugin: truviq.py uninstall && truviq.py install"))
            except (ValueError, subprocess.TimeoutExpired, OSError) as e:
                out.append(_check(name, "fail", f"{type(e).__name__}: {e}", "Reinstall the plugin"))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return out


def _mode_of(path: str) -> int | None:
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return None


def windows_checks(which=shutil.which, environ=None, exists=os.path.exists) -> list[dict]:
    """Native Windows only: hooks need Git Bash, and the guard_fetch MCP server needs `sh` on PATH (Claude Code starts it directly)."""
    env = os.environ if environ is None else environ
    checks = []
    bash = [env.get("CLAUDE_CODE_GIT_BASH_PATH", ""), r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files (x86)\Git\bin\bash.exe"]
    git = which("git")
    if git:
        bash.append(os.path.join(os.path.dirname(os.path.dirname(git)), "bin", "bash.exe"))
    found = next((b for b in bash if b and exists(b)), "")
    checks.append(_check("Git Bash (runs the hooks)", "ok" if found else "fail", found or "not found",
                         "" if found else "Install Git for Windows (git-scm.com), then restart Claude Code. Without it the guard's hooks cannot run."))
    sh = which("sh") or ""  # the MCP server runs `sh bin/run-python.sh`; Git for Windows keeps sh.exe in Git\bin, off PATH by default
    git_bin = ntpath.dirname(found) if found else r"C:\Program Files\Git\bin"
    checks.append(_check("sh for safe web fetch", "ok" if sh else "warn", sh or "`sh` is not on PATH",
                         "" if sh else f"The guard_fetch tool cannot start, so web fetches are refused. Add {git_bin} to your user PATH, "
                                       'then restart Claude Code, or set "webfetch": "scan" in ~/.truviq/policy.json'))
    return checks


def doctor(claude: str | None = None, online: bool = False, live: bool = False, model: str = "haiku") -> list[dict]:
    checks: list[dict] = []
    v = sys.version_info
    checks.append(_check("Python", "ok" if v >= (3, 8) else "fail", f"{v.major}.{v.minor}.{v.micro}", "Install Python 3.8 or newer" if v < (3, 8) else ""))
    root = config.PLUGIN_ROOT
    missing = [f for f in fleet.HOOK_FILES if not os.path.exists(os.path.join(root, f))]
    checks.append(_check("Plugin files", "ok" if not missing else "fail", "hooks, hook script and engine present" if not missing else f"missing {missing}",
                         "Reinstall the plugin" if missing else ""))
    home = paths.guard_home()
    hm = _mode_of(home)
    checks.append(_check("Guard folder", "ok" if hm is not None and hm & 0o077 == 0 else ("warn" if hm is not None else "warn"),
                         f"{home} mode {oct(hm) if hm is not None else 'missing'}",
                         f"chmod 700 {home}" if hm is not None and hm & 0o077 else ("run: truviq.py setup" if hm is None else "")))
    env_path = os.path.join(home, "guard.env")
    em = _mode_of(env_path)
    checks.append(_check("Secrets file", "ok" if em is not None and em & 0o077 == 0 else "warn",
                         f"{env_path} mode {oct(em) if em is not None else 'missing'}",
                         f"chmod 600 {env_path}" if em is not None and em & 0o077 else ("run: truviq.py setup --import-env .env" if em is None else "")))

    claude = claude or pick_claude()
    if not claude or not os.path.exists(claude):
        checks.append(_check("Claude Code", "fail", "binary not found", "Install Claude Code, or set TRUVIQ_CLAUDE_BIN"))
    else:
        cv = claude_version(claude)
        checks.append(_check("Claude Code", "ok" if cv else "warn", f"{cv or 'unknown version'} at {claude}"))
        installed, enabled, pv = plugin_state(claude)
        checks.append(_check("Plugin installed", "ok" if installed and enabled else "fail",
                             f"truviq-guard {pv} enabled" if installed and enabled else ("installed but disabled" if installed else "not installed"),
                             "" if installed and enabled else ("Enable it in the /plugin menu in Claude Code, then /reload-plugins" if installed
                                                                else "Run: truviq.py install")))
    checks += hook_selftest()
    lok, ldetail = launcher_status()
    checks.append(_check("`truviq` command", "ok" if lok else "warn", ldetail, "" if lok else "Run: truviq.py install (adds ~/.local/bin/truviq)"))

    pol = config.load_policy(os.getcwd())
    sec = config.load_secrets()
    checks.append(_check("Mode", "ok" if pol["mode"] == "enforce" else "warn", pol["mode"],
                         "" if pol["mode"] == "enforce" else 'Set "mode": "enforce" in ~/.truviq/policy.json'))
    if os.name == "nt":
        checks += windows_checks()
    lr = quality.logic_review_status(pol, sec)
    checks.append(_check("Code logic review", lr[0], lr[1], lr[2]))
    org = fleet.org_policy()
    checks.append(_check("Org policy", "ok" if org else "warn", f"v{org.get('version')} applied" if org else "none applied",
                         "" if org else "Run: truviq.py policy-sync (an admin must publish one first)"))
    checks.append(_check("Email alerts", "ok" if alerts.configured(sec) else "warn", "configured" if alerts.configured(sec) else "not configured",
                         "" if alerts.configured(sec) else "Add RESEND_API_KEY and TRUVIQ_ALERT_TO to ~/.truviq/guard.env"))
    checks.append(_check("Central dashboard", "ok" if sink.configured(sec) else "warn", "Supabase configured" if sink.configured(sec) else "not configured",
                         "" if sink.configured(sec) else "Add SUPABASE_URL and SUPABASE_ANON_KEY to ~/.truviq/guard.env"))
    checks.append(_check("Enrolled", "ok" if fleet.enrolled() else "warn", fleet.enrolled().get("org", "") and f"org {fleet.enrolled()['org']}" or "not enrolled",
                         "" if fleet.enrolled() else "Run: truviq.py enroll --org <name>"))
    if online:
        ok, msg = fleet.send_heartbeat(sec, pol, note="doctor")
        checks.append(_check("Heartbeat to Supabase", "ok" if ok else "fail", msg, "" if ok else "Check SUPABASE_URL/ANON_KEY and run supabase/002_fleet_policy_redteam.sql"))
    if live and claude and os.path.exists(claude):
        checks.append(_live_check(claude, model))
    return checks


def _live_check(claude: str, model: str) -> dict:
    """A real, harmless Claude Code session: proves the hooks actually fire inside Claude Code."""
    work = tempfile.mkdtemp(prefix="truviq-doctor-live-")
    cap = os.path.join(work, "cap")
    home = os.path.join(work, "home")
    os.makedirs(home, mode=0o700)
    try:
        env = {**os.environ, "TRUVIQ_HOME": home, "TRUVIQ_CAPTURE_DIR": cap, "TRUVIQ_LLM": "off", "TRUVIQ_DRY_RUN": "1"}
        p = subprocess.run([claude, "-p", "Run `echo truviq-selftest` with the Bash tool, then reply with the single word done.",  # noqa: S603
                            "--model", model, "--plugin-dir", config.PLUGIN_ROOT, "--allowedTools", "Bash", "--max-turns", "4",
                            "--output-format", "json"], cwd=work, env=env, capture_output=True, text=True, timeout=180)
        seen = sorted(f.replace(".json", "") for f in os.listdir(cap)) if os.path.isdir(cap) else []
        need = {"SessionStart-none", "UserPromptSubmit-none", "PreToolUse-Bash", "PostToolUse-Bash"}
        ok = need <= set(seen)
        return _check("Hooks fire in real Claude Code", "ok" if ok else "fail",
                      "SessionStart, UserPromptSubmit, PreToolUse, PostToolUse all received" if ok else f"missing {sorted(need - set(seen))}; saw {seen}",
                      "" if ok else "Run /reload-plugins, or reinstall the plugin")
    except (subprocess.TimeoutExpired, OSError) as e:
        return _check("Hooks fire in real Claude Code", "fail", f"{type(e).__name__}: {e}", "Check Claude Code login and network")
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ------------------------------------------------------------------ `truviq` launcher on PATH

LAUNCHER_MARK = "# truviq-guard launcher"
LAUNCHER = """#!/bin/sh
{mark}
# Runs the newest installed TruViq Guard, so plugin updates never change this command.
P=$(ls -d "$HOME"/.claude/plugins/cache/truviq/truviq-guard/*/bin/truviq.py 2>/dev/null | sort -V | tail -n 1)
[ -n "$P" ] || P="{fallback}"
if [ ! -f "$P" ]; then
  echo "truviq: TruViq Guard is not installed. Install it with /plugin install truviq-guard@truviq" >&2
  exit 1
fi
R="$(dirname "$P")/run-python.sh"
[ -f "$R" ] && exec sh "$R" "$P" "$@"   # finds Python on Windows too
exec python3 "$P" "$@"
"""


def default_bin_dir() -> str:
    return os.environ.get("TRUVIQ_BIN_DIR") or os.path.join(paths.home(), ".local", "bin")


def install_launcher(bin_dir: str | None = None) -> dict:
    bin_dir = bin_dir or default_bin_dir()
    target = os.path.join(bin_dir, "truviq")
    if os.path.islink(target):
        return _step("launcher", False, f"{target} is a symlink; not touching it")
    if os.path.exists(target):
        with open(target, encoding="utf-8", errors="replace") as f:
            if LAUNCHER_MARK not in f.read():
                return _step("launcher", False, f"{target} exists and is not ours; not overwritten")
    os.makedirs(bin_dir, exist_ok=True)
    body = LAUNCHER.format(mark=LAUNCHER_MARK, fallback=os.path.join(config.PLUGIN_ROOT, "bin", "truviq.py").replace('"', ""))
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o755)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(body)
    os.chmod(target, 0o755)
    on_path = os.path.realpath(bin_dir) in {os.path.realpath(p) for p in os.environ.get("PATH", "").split(os.pathsep) if p}
    return _step("launcher", True, target + ("" if on_path else f"  (add {bin_dir} to your PATH to type `truviq`)"))


def remove_launcher(bin_dir: str | None = None) -> dict:
    target = os.path.join(bin_dir or default_bin_dir(), "truviq")
    if not os.path.exists(target) or os.path.islink(target):
        return _step("launcher", True, "not present")
    with open(target, encoding="utf-8", errors="replace") as f:
        ours = LAUNCHER_MARK in f.read()
    if ours:
        os.remove(target)
    return _step("launcher", True, "removed" if ours else "left in place (not ours)")


def launcher_status(bin_dir: str | None = None) -> tuple[bool, str]:
    target = os.path.join(bin_dir or default_bin_dir(), "truviq")
    if not os.path.exists(target):
        return False, "not installed"
    with open(target, encoding="utf-8", errors="replace") as f:
        return LAUNCHER_MARK in f.read(), target
