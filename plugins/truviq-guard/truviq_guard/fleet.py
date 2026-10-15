"""R7/R8: device identity, org policy sync, heartbeats and the fleet watchdog.

R7  device id + `enroll`; org policy published by an admin (service-role key) and pulled by every machine
    (anon key, read-only) into ~/.truviq/org_policy.json, which load_policy() layers under the user policy.
R8  every session start sends a throttled heartbeat (machine, versions, mode, hooks present, config hash).
    The watchdog (admin machine) reads the heartbeats and flags: stopped reporting, guard switched to
    monitor/off, hooks missing, old plugin version, org policy not applied. It emails the Resend inbox.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sys
import time
import uuid

from . import __version__, config, paths, sink

BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "truviq.py")
HEARTBEAT_EVERY = 3600          # seconds between heartbeats per machine
ORG_FILE = "org_policy.json"
MAX_ORG_POLICY_BYTES = 20000
HOOK_FILES = ("hooks/hooks.json", "bin/guard_hook.py", "truviq_guard/engine.py")


def _p(name: str) -> str:
    return os.path.join(paths.ensure_private_dir(paths.guard_home()), name)


def _write_private(path: str, obj) -> None:
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


def _read(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


# ------------------------------------------------------------------ R7: identity and enrollment

def device_id() -> str:
    path = _p("device.json")
    did = _read(path).get("device_id")
    if did:
        return str(did)
    did = uuid.uuid4().hex
    _write_private(path, {"device_id": did, "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    return did


def enroll(org: str) -> dict:
    info = {"device_id": device_id(), "org": org[:80], "machine": socket.gethostname(),
            "enrolled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    _write_private(_p("enroll.json"), info)
    return info


def enrolled() -> dict:
    return _read(_p("enroll.json"))


# ------------------------------------------------------------------ R7: org policy

def _clean_policy(policy) -> tuple[dict, list[str]]:
    """(policy that can only add protection, names of dropped settings)."""
    if not isinstance(policy, dict):
        raise ValueError("policy must be a JSON object")
    if len(json.dumps(policy)) > MAX_ORG_POLICY_BYTES:
        raise ValueError("policy is too large")
    with open(config.DEFAULT_POLICY, encoding="utf-8") as f:
        defaults = json.load(f)
    return config.sanitize_org_policy({k: v for k, v in policy.items() if not str(k).startswith("_")}, defaults)


def org_policy() -> dict:
    return _read(_p(ORG_FILE))


def pull_org_policy(secrets: dict) -> tuple[bool, str]:
    """Machines use the anon key: it can read guard_policies and nothing else."""
    if not sink.configured(secrets):
        return False, "Supabase not configured"
    try:
        rows = sink._request(secrets["SUPABASE_URL"].rstrip("/") +
                             "/rest/v1/guard_policies?select=version,policy&scope=eq.org&order=version.desc&limit=1",
                             secrets["SUPABASE_ANON_KEY"], timeout=10)
    except OSError as e:
        return False, f"could not reach Supabase ({getattr(e, 'code', '') or type(e).__name__})"
    if not rows:
        return True, "no org policy published yet"
    try:
        policy, dropped = _clean_policy(rows[0]["policy"])
        version = int(rows[0]["version"])
    except (ValueError, KeyError, TypeError) as e:
        return False, f"ignored invalid org policy: {e}"
    cur = org_policy().get("version")
    _write_private(_p(ORG_FILE), {"version": version, "policy": policy, "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    return True, f"org policy v{version} applied" + ("" if cur != version else " (unchanged)") + \
        (f"; ignored settings that would weaken the guard: {', '.join(dropped[:6])}" if dropped else "")


def publish_org_policy(path: str, secrets: dict, who: str) -> tuple[bool, str]:
    """Admin machine only (service-role key). Publishes the next version."""
    try:
        with open(path, encoding="utf-8") as f:
            policy, dropped = _clean_policy(json.load(f))
    except (OSError, ValueError) as e:
        return False, f"cannot read policy: {e}"
    if dropped:
        return False, ("refusing to publish: these settings would weaken the guard and every machine would ignore them: "
                       + ", ".join(dropped[:10]) + ". Remove them and publish again.")
    try:
        top = sink.fetch_table("guard_policies", secrets, "select=version&scope=eq.org&order=version.desc&limit=1")
        version = (int(top[0]["version"]) + 1) if top else 1
        sink._request(secrets["SUPABASE_URL"].rstrip("/") + "/rest/v1/guard_policies", secrets["SUPABASE_SERVICE_ROLE_KEY"], "POST",
                      {"scope": "org", "version": version, "policy": policy, "updated_by": who[:120]}, timeout=10)
    except (OSError, RuntimeError) as e:
        return False, f"publish failed: {getattr(e, 'code', '') or e}"
    return True, f"published org policy v{version}"


# ------------------------------------------------------------------ R8: heartbeats

def config_hash(policy: dict) -> str:
    """Fingerprint of the settings that decide what the guard blocks (not secrets, not paths of this machine)."""
    keep = {k: policy.get(k) for k in ("mode", "severity_actions", "detectors", "secret_paths", "protected_paths",
                                       "egress_allow_hosts", "dependencies", "webfetch")}
    return hashlib.sha256(json.dumps(keep, sort_keys=True).encode()).hexdigest()[:16]


def snapshot(policy: dict, claude_version: str | None = None, note: str = "") -> dict:
    root = config.PLUGIN_ROOT
    return {"machine": socket.gethostname()[:120], "os_user": (os.environ.get("USER") or os.environ.get("USERNAME") or "unknown")[:80],
            "device_id": device_id(), "plugin_version": __version__, "claude_version": (claude_version or "")[:40] or None,
            "mode": policy.get("mode", "enforce"), "hooks_ok": all(os.path.exists(os.path.join(root, f)) for f in HOOK_FILES),
            "config_hash": config_hash(policy), "org_policy_version": org_policy().get("version"), "note": note[:500] or None}


def heartbeat_due() -> bool:
    try:
        return time.time() - os.path.getmtime(_p("last_heartbeat")) > HEARTBEAT_EVERY
    except OSError:
        return True


def send_heartbeat(secrets: dict, policy: dict, claude_version: str | None = None, note: str = "") -> tuple[bool, str]:
    ok, msg = sink.post_rows("guard_heartbeats", [snapshot(policy, claude_version, note)], secrets)
    if ok:
        with open(_p("last_heartbeat"), "w", encoding="utf-8") as f:
            f.write(str(int(time.time())))
        os.chmod(_p("last_heartbeat"), 0o600)
    return ok, msg


def queue_heartbeat_if_due(secrets: dict) -> bool:
    """Called from the SessionStart hook. Never waits: starts a detached `truviq.py heartbeat`."""
    if not sink.configured(secrets) or not heartbeat_due():
        return False
    with open(_p("last_heartbeat"), "w", encoding="utf-8") as f:  # claim the slot so parallel sessions don't all send
        f.write(str(int(time.time())))
    if os.environ.get("TRUVIQ_DRY_RUN") == "1":
        return True
    import subprocess
    kw = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "close_fds": True}
    if os.name == "nt":
        kw["creationflags"] = 0x00000008 | 0x00000200
    else:
        kw["start_new_session"] = True
    subprocess.Popen([sys.executable, BIN, "heartbeat", "--pull-policy"], **kw)  # noqa: S603 - fixed argv, no shell
    return True


# ------------------------------------------------------------------ R8: watchdog

def _epoch(s: str) -> float:
    m = re.match(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)", s or "")
    if not m:
        return 0.0
    import calendar
    return float(calendar.timegm(tuple(int(x) for x in m.groups()) + (0, 0, 0)))


def _ver(v: str | None) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "0")[:4])


def evaluate(rows: list[dict], latest_org_version: int | None = None, required_mode: str = "enforce",
             stale_hours: float = 36.0, now: float | None = None) -> dict:
    """Pure function: heartbeat rows -> per-machine status and problems."""
    now = now if now is not None else time.time()
    latest: dict[str, dict] = {}
    for r in rows:
        m = r.get("device_id") or r.get("machine") or "?"  # two laptops both called "localhost" must not hide each other
        if m not in latest or _epoch(r.get("created_at", "")) > _epoch(latest[m].get("created_at", "")):
            latest[m] = r
    newest = max((_ver(r.get("plugin_version")) for r in latest.values()), default=())
    machines, problems = [], []
    for _key, r in sorted(latest.items(), key=lambda kv: kv[1].get("machine") or ""):
        m = r.get("machine") or "?"
        age_h = max(0.0, (now - _epoch(r.get("created_at", ""))) / 3600)
        probs = []
        if age_h > stale_hours:
            probs.append(("stale", f"no heartbeat for {age_h:.0f} h: the guard may be off, uninstalled or the machine is offline"))
        if r.get("mode") != required_mode and r.get("mode"):
            probs.append(("mode", f"guard mode is {r.get('mode')!r}, organisation requires {required_mode!r}"))
        if r.get("hooks_ok") is False:
            probs.append(("hooks", "plugin hook files are missing or damaged"))
        if newest and _ver(r.get("plugin_version")) < newest:
            probs.append(("version", f"plugin {r.get('plugin_version')} is older than {'.'.join(map(str, newest))}"))
        if latest_org_version and (r.get("org_policy_version") or 0) < latest_org_version:
            probs.append(("policy", f"org policy v{r.get('org_policy_version') or 0} applied, v{latest_org_version} is published"))
        machines.append({"machine": m, "os_user": r.get("os_user"), "last_seen": r.get("created_at"), "age_hours": round(age_h, 1),
                         "plugin_version": r.get("plugin_version"), "claude_version": r.get("claude_version"), "mode": r.get("mode"),
                         "hooks_ok": r.get("hooks_ok"), "org_policy_version": r.get("org_policy_version"),
                         "config_hash": r.get("config_hash"), "problems": [{"kind": k, "detail": d} for k, d in probs]})
        problems += [{"machine": m, "os_user": r.get("os_user"), "kind": k, "detail": d} for k, d in probs]
    return {"machines": machines, "problems": problems, "required_mode": required_mode}


def fleet_report(secrets: dict, policy: dict, stale_hours: float = 36.0, required_mode: str = "enforce") -> dict:
    """required_mode comes from the caller (default enforce), never from the org policy: a bad policy must not silence the watchdog."""
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 14 * 86400))
    rows = sink.fetch_table("guard_heartbeats", secrets, f"select=*&created_at=gte.{since}&order=id.desc&limit=20000")
    top = sink.fetch_table("guard_policies", secrets, "select=version&scope=eq.org&order=version.desc&limit=1")
    return evaluate(rows, int(top[0]["version"]) if top else None, required_mode if required_mode in ("enforce", "monitor") else "enforce", stale_hours)


def notify(problems: list[dict], secrets: dict, dedupe_hours: float = 24.0) -> tuple[int, str]:
    """Email new problems (once per machine+kind per dedupe window). Returns (emails_sent, message)."""
    from . import alerts
    if not alerts.configured(secrets):
        return 0, "email not configured"
    path = _p("fleet_alerts.json")
    sent = _read(path)
    now = time.time()
    fresh = [p for p in problems if now - float(sent.get(f"{p['machine']}|{p['kind']}", 0)) > dedupe_hours * 3600]
    if not fresh:
        return 0, "nothing new to report"
    alert = {"session_id": "fleet-watchdog", "cwd": "-", "project_root": "-", "hook_event": "Watchdog", "tool": None, "decision": "warn",
             **alerts.context(), "ts": time.strftime("%Y-%m-%d %H:%M:%S %Z"), "taint_sources": [],
             "findings": [{"detector": "G-FLEET-001", "severity": "HIGH", "title": f"Guard problem on {p['machine']}",
                           "summary": f"{p['machine']} ({p.get('os_user') or '?'}): {p['detail']}", "evidence": p["kind"]} for p in fresh[:20]]}
    ok, info = alerts.send(alert, secrets)
    if ok:
        for p in fresh:
            sent[f"{p['machine']}|{p['kind']}"] = now
        _write_private(path, sent)
    return (len(fresh) if ok else 0), ("sent" if ok else info)
