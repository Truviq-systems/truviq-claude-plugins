"""Shared test setup: import path, isolated guard home, LLM and email off by default."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PLUGIN = os.path.join(ROOT, "plugins", "truviq-guard")
HOOK = os.path.join(PLUGIN, "bin", "guard_hook.py")
CLI = os.path.join(PLUGIN, "bin", "truviq.py")
MCP = os.path.join(PLUGIN, "bin", "mcp_server.py")
sys.path.insert(0, PLUGIN)

# Fake secrets are assembled at runtime so this repo's own secret scanner does not flag the test files.
FAKE_AWS = "AKIA" + "Q3EGTXXJ6WCFUA7V"
FAKE_GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
TAG = lambda s: "".join(chr(0xE0000 + ord(c)) for c in s)  # noqa: E731 - invisible Unicode tag text


class GuardTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="truviq-home-")
        self.work = tempfile.mkdtemp(prefix="truviq-repo-")
        os.makedirs(os.path.join(self.work, ".git"))
        self._env = {k: os.environ.get(k) for k in ("TRUVIQ_HOME", "TRUVIQ_LLM", "RESEND_API_KEY", "TRUVIQ_ALERT_TO", "TRUVIQ_OFFLINE",
                                                     "SUPABASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY")}
        os.environ["TRUVIQ_HOME"] = self.home
        os.environ["TRUVIQ_LLM"] = "off"
        os.environ["TRUVIQ_OFFLINE"] = "1"  # no registry/OSV lookups unless a test mocks them
        self._bin_env = os.environ.get("TRUVIQ_BIN_DIR")
        os.environ["TRUVIQ_BIN_DIR"] = os.path.join(self.home, "bin")  # never touch the real ~/.local/bin
        for k in ("RESEND_API_KEY", "TRUVIQ_ALERT_TO", "SUPABASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY"):
            os.environ.pop(k, None)

    def tearDown(self):
        if self._bin_env is None:
            os.environ.pop("TRUVIQ_BIN_DIR", None)
        else:
            os.environ["TRUVIQ_BIN_DIR"] = self._bin_env
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.home, ignore_errors=True)
        shutil.rmtree(self.work, ignore_errors=True)

    # --- helpers
    def write(self, rel, text):
        p = os.path.join(self.work, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def user_policy(self, data):
        with open(os.path.join(self.home, "policy.json"), "w", encoding="utf-8") as f:
            json.dump(data, f)

    def event(self, name, tool=None, tool_input=None, session="sess-1", **extra):
        ev = {"hook_event_name": name, "session_id": session, "cwd": self.work,
              "transcript_path": "/dev/null", "permission_mode": "default"}
        if tool:
            ev["tool_name"] = tool
            ev["tool_input"] = tool_input or {}
        ev.update(extra)
        return ev

    def handle(self, ev):
        from truviq_guard import engine
        reply, code = engine.handle(ev)
        self.assertEqual(code, 0)
        return reply or {}

    def decision(self, reply):
        return (reply.get("hookSpecificOutput") or {}).get("permissionDecision")

    def run_hook(self, ev, env_extra=None):
        env = {**os.environ, **(env_extra or {})}
        p = subprocess.run([sys.executable, HOOK], input=json.dumps(ev), capture_output=True, text=True, env=env, timeout=30)
        return p.returncode, (json.loads(p.stdout) if p.stdout.strip() else {}), p.stderr
