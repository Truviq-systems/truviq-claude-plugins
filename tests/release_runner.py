"""Runs the release test cases (tests/release_cases.json) through a guard hook exactly as Claude Code does.

Used by tests/test_release_cases.py (source plugin) and release/release_check.py (installed plugin).
Each case gets its own throwaway guard home and git repo. LLM, registry lookups and all sending
(email, Supabase) are off: alerts and Supabase rows are written to the outbox and inspected instead.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "release_cases.json")
SOURCE_PLUGIN = os.path.join(os.path.dirname(HERE), "plugins", "truviq-guard")

# Fake secrets are assembled here so no file in the repo contains a real-looking key.
SUBST = {
    "{FAKE_AWS}": "AKIA" + "Q3EGTXXJ6WCFUA7V",
    "{FAKE_GOOGLE}": "AIza" + "SyQ9xL2mN7vB4cT8kD1fH6jR3pW5zY0aE2g",
    "{FAKE_GH}": "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
}
TAG_RX = re.compile(r"\{TAG:([^}]*)\}")


def load_cases(path: str = CASES) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)["cases"]


def _fill(obj, repo: str):
    if isinstance(obj, str):
        s = obj.replace("{REPO}", repo)
        for k, v in SUBST.items():
            s = s.replace(k, v)
        return TAG_RX.sub(lambda m: "".join(chr(0xE0000 + ord(c)) for c in m.group(1)), s)
    if isinstance(obj, list):
        return [_fill(x, repo) for x in obj]
    if isinstance(obj, dict):
        return {k: _fill(v, repo) for k, v in obj.items()}
    return obj


def _decision(out: dict) -> str:
    hso = out.get("hookSpecificOutput") or {}
    if hso.get("permissionDecision"):
        return hso["permissionDecision"]
    if out.get("decision") == "block":
        return "block"
    if out.get("systemMessage") or hso.get("additionalContext"):
        return "warn"
    return "allow"


def _read_lines(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as f:
            return f.readlines()
    except OSError:
        return []


def _outbox(home: str) -> dict[str, list[str]]:
    d = os.path.join(home, "outbox")
    names = sorted(os.listdir(d)) if os.path.isdir(d) else []
    return {"ship": [n for n in names if n.startswith("ship-") and n.endswith(".json")],
            "alert": [n for n in names if n.endswith(".json") and not n.startswith("ship-")]}


def run_case(case: dict, plugin_dir: str = SOURCE_PLUGIN) -> dict:
    hook = os.path.join(plugin_dir, "bin", "guard_hook.py")
    cli = os.path.join(plugin_dir, "bin", "truviq.py")
    tmp = tempfile.mkdtemp(prefix=f"truviq-rel-{case['id']}-")
    home, repo = os.path.join(tmp, "home"), os.path.join(tmp, "repo")
    os.makedirs(home, mode=0o700)
    os.makedirs(repo)
    opts = case.get("env", {})
    failures: list[str] = []
    t0 = time.time()
    try:
        if case.get("git"):
            subprocess.run(["git", "init", "-q", repo], check=True)
            subprocess.run(["git", "-C", repo, "config", "user.email", "t@example.invalid"], check=True)
            subprocess.run(["git", "-C", repo, "config", "user.name", "t"], check=True)
        else:
            os.makedirs(os.path.join(repo, ".git"))
        for rel, content in _fill(case.get("files", {}), repo).items():
            p = os.path.join(repo, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)
        if opts.get("policy"):
            with open(os.path.join(home, "policy.json"), "w", encoding="utf-8") as f:
                json.dump(opts["policy"], f)

        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("TRUVIQ_", "SUPABASE_", "RESEND_", "GROQ_", "GOOGLE_API"))}
        env.update({"TRUVIQ_HOME": home, "TRUVIQ_LLM": "off", "TRUVIQ_OFFLINE": "1", "TRUVIQ_DRY_RUN": "1",
                    "PYTHONDONTWRITEBYTECODE": "1"})
        if opts.get("supabase"):
            env.update({"SUPABASE_URL": "https://example.invalid", "SUPABASE_ANON_KEY": "anon-test"})
        if opts.get("email"):
            env.update({"RESEND_API_KEY": "re_test", "TRUVIQ_ALERT_TO": "security@example.invalid"})
        if opts.get("broken_home"):
            broken = os.path.join(tmp, "not-a-dir")
            open(broken, "w").close()
            env["TRUVIQ_HOME"] = broken
            home = broken

        for i, step in enumerate(_fill(case["steps"], repo)):
            label = f"step {i + 1}"
            exp = step.get("expect", {})
            if "cli" in step:
                for rel, content in step.get("git_add", {}).items():
                    p = os.path.join(repo, rel)
                    os.makedirs(os.path.dirname(p), exist_ok=True)
                    with open(p, "w", encoding="utf-8") as f:
                        f.write(content)
                    subprocess.run(["git", "-C", repo, "add", "-f", rel], check=True)
                p = subprocess.run([sys.executable, cli, *step["cli"]], cwd=repo, env=env, capture_output=True, text=True, timeout=60)
                if "exit" in exp and p.returncode != exp["exit"]:
                    failures.append(f"{label}: exit {p.returncode}, expected {exp['exit']} ({p.stdout.strip()[:200]})")
                for s in exp.get("stdout_contains", []):
                    if s not in p.stdout:
                        failures.append(f"{label}: stdout lacks {s!r}")
                continue

            events_path = os.path.join(home, "logs", "events.jsonl")
            n_before = len(_read_lines(events_path))
            box_before = _outbox(home) if os.path.isdir(home) else {"ship": [], "alert": []}
            ev = {"hook_event_name": step["hook"], "session_id": f"rel-{case['id']}", "cwd": repo,
                  "transcript_path": "/dev/null", "permission_mode": "default"}
            if step.get("tool"):
                ev["tool_name"] = step["tool"]
                ev["tool_input"] = step.get("input", {})
            for k in ("tool_response", "prompt", "tool_use_id", "source"):
                if k in step:
                    ev[k] = step[k]
            p = subprocess.run([sys.executable, hook], input=json.dumps(ev), env=env, capture_output=True, text=True, timeout=60)
            try:
                out = json.loads(p.stdout) if p.stdout.strip() else {}
            except ValueError:
                failures.append(f"{label}: hook printed invalid JSON: {p.stdout[:200]!r}")
                continue
            if p.returncode != 0:
                failures.append(f"{label}: hook exit code {p.returncode}: {p.stderr[-300:]}")
            decision = _decision(out)
            text = json.dumps(out, ensure_ascii=False)
            new_records = [json.loads(l) for l in _read_lines(events_path)[n_before:] if l.strip()]
            detectors = {f["detector"] for r in new_records for f in r.get("findings", [])}

            if "decision" in exp and decision != exp["decision"]:
                failures.append(f"{label}: decision {decision!r}, expected {exp['decision']!r} | {out.get('systemMessage', '')[:160]}")
            for d in exp.get("detectors", []):
                if d not in detectors:
                    failures.append(f"{label}: detector {d} missing (got {sorted(detectors)})")
            for d in exp.get("absent_detectors", []):
                if d in detectors:
                    failures.append(f"{label}: detector {d} should not fire")
            for s in exp.get("message_contains", []):
                if s not in text:
                    failures.append(f"{label}: reply lacks {s!r}")
            for s in exp.get("message_not_contains", []):
                if s in text or s in "".join(_read_lines(events_path)):
                    failures.append(f"{label}: {s[:12]!r}… leaked into the reply or log")
            if exp.get("no_system_message") and out.get("systemMessage"):
                failures.append(f"{label}: unexpected chat message")
            if "state" in exp:
                safe = re.sub(r"[^A-Za-z0-9_.-]", "_", ev["session_id"])
                try:
                    with open(os.path.join(home, "state", safe + ".json"), encoding="utf-8") as f:
                        st = json.load(f)
                except OSError:
                    st = {}
                for k, v in exp["state"].items():
                    if st.get(k) != v:
                        failures.append(f"{label}: state {k}={st.get(k)!r}, expected {v!r}")

            box_after = _outbox(home) if os.path.isdir(home) else {"ship": [], "alert": []}
            new_ship = [n for n in box_after["ship"] if n not in box_before["ship"]]
            new_alert = [n for n in box_after["alert"] if n not in box_before["alert"]]
            rows = []
            for n in new_ship:
                with open(os.path.join(home, "outbox", n), encoding="utf-8") as f:
                    rows += json.load(f)
            if "ship" in exp:
                want = exp["ship"]
                if want is False and rows:
                    failures.append(f"{label}: rows were queued for Supabase but should not be")
                elif isinstance(want, dict) and not any(all(str(r.get(k)) == str(v) if k != "card_contains" else v in (r.get("card") or "")
                                                            for k, v in want.items()) for r in rows):
                    failures.append(f"{label}: no Supabase row matching {want} (rows: {[(r.get('kind'), r.get('verdict'), r.get('detector')) for r in rows]})")
            for s in exp.get("ship_not_contains", []):
                if s in json.dumps(rows):
                    failures.append(f"{label}: {s[:12]!r}… leaked into Supabase rows")
            if "alert" in exp and bool(new_alert) != exp["alert"]:
                failures.append(f"{label}: alert queued={bool(new_alert)}, expected {exp['alert']}")
    except Exception as e:  # noqa: BLE001 - a broken case is a failed case
        failures.append(f"runner error: {type(e).__name__}: {e}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return {"id": case["id"], "release": case["release"], "feature": case.get("feature", ""), "title": case["title"],
            "passed": not failures, "failures": failures, "ms": int((time.time() - t0) * 1000)}


def run_all(plugin_dir: str = SOURCE_PLUGIN, only_release: str | None = None) -> list[dict]:
    return [run_case(c, plugin_dir) for c in load_cases() if not only_release or c["release"] == only_release]


if __name__ == "__main__":
    plugin = sys.argv[1] if len(sys.argv) > 1 else SOURCE_PLUGIN
    results = run_all(plugin)
    for r in results:
        print(f"{'PASS' if r['passed'] else 'FAIL'}  {r['id']:<8} {r['release']}  {r['title']}")
        for f in r["failures"]:
            print(f"        - {f}")
    print(f"\n{sum(r['passed'] for r in results)}/{len(results)} release cases passed")
    sys.exit(0 if all(r["passed"] for r in results) else 1)
