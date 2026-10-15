"""Policy and secrets loading.

Policy layers, lowest to highest:
  1. plugin default:   <plugin>/policy/default_policy.json
  2. user policy:      ~/.truviq/policy.json   (full control; the agent cannot write here)
  3. project policy:   <repo>/.truviq/policy.json   (TIGHTEN ONLY)

A project policy ships with the repository, so an attacker controls it when
the repository is malicious. It may only add entries to the lists below and
raise detector severities. Anything else in it is ignored.

Secrets (API keys) are read from ~/.truviq/guard.env, never from the plugin.
"""
from __future__ import annotations

import copy
import json
import os
import re

from . import paths
from .catalog import SEVERITIES, severity_rank

PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_POLICY = os.path.join(PLUGIN_ROOT, "policy", "default_policy.json")

PROJECT_EXTENDABLE_LISTS = ("secret_paths", "protected_paths", "production_markers", "instruction_files")
MODES = ("enforce", "monitor", "off")


def _read_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _apply_project(policy: dict, project: dict) -> tuple[dict, list[str]]:
    ignored = []
    for k, v in project.items():
        if k in PROJECT_EXTENDABLE_LISTS and isinstance(v, list):
            policy[k] = list(policy.get(k, [])) + [x for x in v if isinstance(x, str) and not x.startswith("!")]
        elif k == "detectors" and isinstance(v, dict):
            # A project may only set a severity FLOOR (min_severity). It can never lower anything.
            for det, cfg in v.items():
                sev = cfg.get("severity") or cfg.get("min_severity") if isinstance(cfg, dict) else None
                if sev not in SEVERITIES or (isinstance(cfg, dict) and set(cfg) - {"severity", "min_severity"}):
                    ignored.append(f"detectors.{det}")
                    continue
                cur = policy.setdefault("detectors", {}).setdefault(det, {})
                if severity_rank(sev) > severity_rank(cur.get("min_severity", "INFO")):
                    cur["min_severity"] = sev
        else:
            ignored.append(k)
    return policy, ignored


# --- organisation policy: published centrally, so it is held to the same rule as a repository policy:
# it may add protection and tune settings, but it can never weaken what the plugin ships with.
ORG_ALLOWED_KEYS = {"mode", "severity_actions", "detectors", "egress_allow_hosts", "secret_paths", "protected_paths", "instruction_files",
                    "production_markers", "webfetch", "dependencies", "llm", "alerts", "quality", "show_messages_in_monitor_mode"}
ORG_EXTEND_ONLY = ("secret_paths", "protected_paths", "instruction_files", "production_markers")
_ACTION_RANK = {"allow": -1, "log": 0, "warn": 1, "ask": 2, "deny": 3}


def sanitize_org_policy(org: dict, defaults: dict) -> tuple[dict, list[str]]:
    """(safe policy, dropped keys). Never lets the organisation policy loosen the shipped defaults."""
    clean: dict = {}
    dropped: list[str] = []
    for k, v in (org or {}).items():
        if k not in ORG_ALLOWED_KEYS:
            dropped.append(k)
        elif k == "mode":
            if v in ("enforce", "monitor"):  # "off" is a decision for one machine's owner, not for the organisation
                clean[k] = v
            else:
                dropped.append("mode")
        elif k in ORG_EXTEND_ONLY:
            if isinstance(v, list):
                base = list(defaults.get(k, []))
                clean[k] = base + [x for x in v if isinstance(x, str) and not x.startswith("!") and x not in base][:200]
            else:
                dropped.append(k)
        elif k == "severity_actions":
            keep = {sev: act for sev, act in (v or {}).items()
                    if sev in defaults.get("severity_actions", {}) and act in _ACTION_RANK
                    and _ACTION_RANK[act] >= _ACTION_RANK.get(defaults["severity_actions"][sev], 0)} if isinstance(v, dict) else {}
            clean[k] = {**defaults.get("severity_actions", {}), **keep}
            dropped += [f"severity_actions.{s}" for s in (v or {}) if isinstance(v, dict) and s not in keep]
        elif k == "detectors":
            det: dict = {}
            for name, cfg in (v or {}).items() if isinstance(v, dict) else []:
                if not isinstance(cfg, dict):
                    continue
                ok = {}
                if cfg.get("action") in ("ask", "deny"):
                    ok["action"] = cfg["action"]
                if cfg.get("min_severity") in SEVERITIES:
                    ok["min_severity"] = cfg["min_severity"]
                if set(cfg) - set(ok):
                    dropped.append(f"detectors.{name}")
                if ok:
                    det[name] = {**defaults.get("detectors", {}).get(name, {}), **ok}
            clean[k] = {**defaults.get("detectors", {}), **det}
        elif k == "egress_allow_hosts":
            if isinstance(v, list):
                clean[k] = [x.lower() for x in v if isinstance(x, str) and re.match(r"^[A-Za-z0-9.\-]{1,253}$", x)][:100]
            else:
                dropped.append(k)
        elif k == "webfetch":
            if v in ("redirect", "scan"):
                clean[k] = v
        elif k in ("dependencies", "llm", "alerts", "quality"):
            if isinstance(v, dict):
                clean[k] = {**defaults.get(k, {}), **v}
        elif k == "show_messages_in_monitor_mode":
            if isinstance(v, bool):
                clean[k] = v
    return clean, dropped


def find_project_root(cwd: str) -> str:
    d = os.path.abspath(cwd or os.getcwd())
    while True:
        if os.path.isdir(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return os.path.abspath(cwd or os.getcwd())
        d = parent


def load_policy(cwd: str) -> dict:
    policy = _read_json(DEFAULT_POLICY)
    defaults = copy.deepcopy(policy)
    org = _read_json(os.path.join(paths.guard_home(), "org_policy.json"))  # published by the admin, pulled by `truviq.py policy-sync`
    if isinstance(org.get("policy"), dict):
        policy = _deep_merge(policy, sanitize_org_policy(org["policy"], defaults)[0])  # re-checked on every load, whatever is in the file
    policy["_org_policy_version"] = org.get("version")
    user = _read_json(os.path.join(paths.guard_home(), "policy.json"))
    policy = _deep_merge(policy, user)
    root = find_project_root(cwd)
    project = _read_json(os.path.join(root, ".truviq", "policy.json"))
    policy, ignored = _apply_project(policy, project)
    gh = paths.guard_home()
    policy["protected_paths"] = list(policy.get("protected_paths", [])) + [gh, gh + "/**"]
    if policy.get("mode") not in MODES:
        policy["mode"] = "enforce"
    policy["_project_root"] = root
    policy["_project_ignored_keys"] = ignored
    return policy


def load_secrets() -> dict:
    """KEY=VALUE pairs from ~/.truviq/guard.env, overridden by real env vars."""
    vals: dict[str, str] = {}
    path = os.path.join(paths.guard_home(), "guard.env")
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                vals[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    for k in ("GROQ_API_KEY", "GROQ_API_KEYS_POOL", "GOOGLE_API_KEY", "RESEND_API_KEY",
              "TRUVIQ_ALERT_TO", "TRUVIQ_ALERT_FROM", "TRUVIQ_LLM", "SUPABASE_URL", "SUPABASE_ANON_KEY",
              "SUPABASE_SERVICE_ROLE_KEY"):
        if os.environ.get(k):
            vals[k] = os.environ[k]
    return vals
