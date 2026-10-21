"""Windows support: hooks find Python without `python3`, paths with spaces, doctor checks, export contents."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from helpers import CLI, PLUGIN, ROOT, GuardTest

from truviq_guard import install, shell

LAUNCHER = os.path.join(PLUGIN, "bin", "run-python.sh")
HOOK = os.path.join(PLUGIN, "bin", "guard_hook.py")
EVENT = json.dumps({"hook_event_name": "PreToolUse", "session_id": "w", "cwd": "/tmp", "tool_name": "Bash",
                    "tool_input": {"command": "rm -rf ~"}})
SH = shutil.which("sh") or "/bin/sh"


class LauncherTest(GuardTest):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp(prefix="truviq-win-")
        self.stub_dir = os.path.join(self.tmp, "AppData", "Local", "Microsoft", "WindowsApps")
        self.real_dir = os.path.join(self.tmp, "pyorg")
        os.makedirs(self.stub_dir)
        os.makedirs(self.real_dir)
        stub = os.path.join(self.stub_dir, "python3")
        with open(stub, "w") as f:  # the Microsoft Store placeholder: prints a hint and exits 9009
            f.write("#!/bin/sh\necho 'Python was not found; run without arguments to install from the Microsoft Store' >&2\nexit 9009\n")
        os.chmod(stub, 0o755)
        os.symlink(sys.executable, os.path.join(self.real_dir, "python"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        super().tearDown()

    def run_launcher(self, path_env, launcher=LAUNCHER, hook=HOOK):
        env = {**os.environ, "PATH": path_env}
        return subprocess.run([SH, launcher, hook], input=EVENT, capture_output=True, text=True, env=env, timeout=30)

    def test_normal_python3(self):
        p = self.run_launcher(os.environ["PATH"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_store_placeholder_is_skipped_for_real_python(self):
        p = self.run_launcher(f"{self.stub_dir}{os.pathsep}{self.real_dir}")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_no_python_gives_a_clear_non_blocking_error(self):
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        p = self.run_launcher(empty)
        self.assertEqual(p.returncode, 1)
        self.assertIn("no working Python 3.8+ found", p.stderr)
        self.assertEqual(p.stdout, "")

    def test_install_path_with_a_space(self):
        spaced = os.path.join(self.tmp, "Jane Doe", "plugin")
        shutil.copytree(PLUGIN, spaced, ignore=shutil.ignore_patterns("dashboard", "__pycache__"))
        p = self.run_launcher(os.environ["PATH"], os.path.join(spaced, "bin", "run-python.sh"), os.path.join(spaced, "bin", "guard_hook.py"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("deny", p.stdout)

    def test_mcp_server_uses_the_launcher(self):
        with open(os.path.join(PLUGIN, ".mcp.json")) as f:
            srv = json.load(f)["mcpServers"]["truviq"]
        self.assertEqual(srv["command"], "sh")
        self.assertEqual(srv["args"], ["${CLAUDE_PLUGIN_ROOT}/bin/run-python.sh", "${CLAUDE_PLUGIN_ROOT}/bin/mcp_server.py"])

    def test_mcp_server_starts_past_the_store_placeholder(self):
        init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})
        p = subprocess.run([SH, LAUNCHER, os.path.join(PLUGIN, "bin", "mcp_server.py")], input=init + "\n", capture_output=True, text=True,
                           env={**os.environ, "PATH": f"{self.stub_dir}{os.pathsep}{self.real_dir}"}, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["result"]["serverInfo"]["name"], "truviq-guard")

    def test_every_hook_uses_the_launcher_with_quoted_paths(self):
        with open(os.path.join(PLUGIN, "hooks", "hooks.json")) as f:
            hooks = json.load(f)["hooks"]
        self.assertIn("Stop", hooks)
        for event, groups in hooks.items():
            for g in groups:
                for h in g["hooks"]:
                    self.assertEqual(h["command"], 'sh "${CLAUDE_PLUGIN_ROOT}/bin/run-python.sh" "${CLAUDE_PLUGIN_ROOT}/bin/guard_hook.py"', event)


class WindowsTamperTest(GuardTest):
    def kinds(self, cmd):
        findings, _ = shell.analyze(cmd, self.work, {"protected_paths": [], "secret_paths": [], "egress_allow_hosts": []}, {})
        return {f["detector"] for f in findings if f["severity"] == "CRITICAL"}

    def test_py_launcher_cannot_run_guard_admin_commands(self):
        for cmd in (f"py -3 {CLI} uninstall --purge", f"py.exe {CLI} enroll --org x", f"sh {LAUNCHER} {CLI} policy-sync",
                    'py -c "import truviq_guard.config"'):
            self.assertIn("G-PRIV-001", self.kinds(cmd), cmd)

    def test_read_only_commands_through_the_launcher_stay_allowed(self):
        self.assertEqual(self.kinds(f"sh {LAUNCHER} {CLI} status"), set())
        self.assertEqual(self.kinds(f"py -3 {CLI} report --last 5"), set())


class WindowsDoctorTest(unittest.TestCase):
    def test_git_bash_found_and_python3_ok(self):
        checks = install.windows_checks(which=lambda n: {"git": r"C:\Program Files\Git\cmd\git.exe", "sh": r"C:\Program Files\Git\bin\sh.exe"}.get(n),
                                        environ={}, exists=lambda p: p.endswith(os.path.join("Git", "bin", "bash.exe")) or "Git\\bin\\bash.exe" in p)
        self.assertEqual([c["status"] for c in checks], ["ok", "ok"])

    def test_missing_git_bash_and_sh(self):
        checks = install.windows_checks(which=lambda n: None, environ={}, exists=lambda p: False)
        self.assertEqual(checks[0]["status"], "fail")
        self.assertIn("Git for Windows", checks[0]["fix"])
        self.assertEqual(checks[1]["status"], "warn")
        self.assertIn(r"Git\bin", checks[1]["fix"])
        self.assertIn('"webfetch": "scan"', checks[1]["fix"])

    def test_sh_missing_but_git_bash_installed_points_at_its_folder(self):
        checks = install.windows_checks(which=lambda n: None, environ={"CLAUDE_CODE_GIT_BASH_PATH": r"D:\Tools\Git\bin\bash.exe"},
                                        exists=lambda p: p == r"D:\Tools\Git\bin\bash.exe")
        self.assertEqual([c["status"] for c in checks], ["ok", "warn"])
        self.assertIn(r"D:\Tools\Git\bin", checks[1]["fix"])


class LauncherScriptsTest(GuardTest):
    def test_truviq_command_and_git_hook_use_the_launcher(self):
        bin_dir = os.path.join(self.home, "bin")
        install.install_launcher(bin_dir)
        with open(os.path.join(bin_dir, "truviq")) as f:
            text = f.read()
        self.assertIn('run-python.sh', text)
        self.assertIn('exec python3 "$P" "$@"', text, "older installed versions without the launcher still work")
        subprocess.run(["git", "init", "-q", self.work], check=True)
        p = subprocess.run([sys.executable, CLI, "install-git-hook"], cwd=self.work, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(os.path.join(self.work, ".git", "hooks", "pre-commit")) as f:
            self.assertIn("run-python.sh", f.read())


class ExportTest(unittest.TestCase):
    def test_export_leaves_out_build_output_and_the_internal_report(self):
        out = tempfile.mkdtemp(prefix="truviq-export-")
        shutil.rmtree(out)
        try:
            p = subprocess.run([sys.executable, os.path.join(ROOT, "release", "export_marketplace.py"), out], capture_output=True, text=True, timeout=120)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            files = {os.path.relpath(os.path.join(d, f), out) for d, _, fs in os.walk(out) for f in fs}
            self.assertIn(os.path.join("plugins", "truviq-guard", "bin", "run-python.sh"), files)
            self.assertIn(os.path.join("plugins", "truviq-guard", "dashboard", "index.html"), files)
            for bad in (".next", os.path.join("dashboard-app", "out"), ".impeccable", "Verification_Report.pdf", ".tsbuildinfo"):
                self.assertFalse(any(bad in f for f in files), bad)
        finally:
            shutil.rmtree(out, ignore_errors=True)

    def test_help_flag_is_not_treated_as_a_folder(self):
        p = subprocess.run([sys.executable, os.path.join(ROOT, "release", "export_marketplace.py"), "--help"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertFalse(os.path.exists(os.path.join(os.getcwd(), "--help")))


if __name__ == "__main__":
    unittest.main()


class SetupKeysTest(GuardTest):
    """`truviq setup --keys`: each key typed in the terminal (hidden), saved to ~/.truviq/guard.env with mode 600."""

    def cli_module(self):
        import argparse
        import importlib.util
        spec = importlib.util.spec_from_file_location("truviq_cli", CLI)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod, argparse

    def test_keys_are_asked_hidden_and_saved_privately(self):
        from unittest import mock
        mod, argparse = self.cli_module()
        typed = iter(["gsk_" + "x" * 40, "", "re_" + "y" * 20, "me@example.com", "", "", ""])
        asked_hidden = []

        def fake_getpass(prompt):
            asked_hidden.append(prompt.split("[")[0].split()[-1])
            return next(typed)
        with mock.patch("getpass.getpass", side_effect=fake_getpass), \
                mock.patch("builtins.input", side_effect=lambda prompt: next(typed)), \
                mock.patch.object(mod.sys.stdin, "isatty", return_value=True):
            rc = mod.cmd_setup(argparse.Namespace(import_env=None, with_service_key=False, keys=True))
        self.assertEqual(rc, 0)
        env = os.path.join(self.home, "guard.env")
        self.assertEqual(os.stat(env).st_mode & 0o777, 0o600)
        text = open(env).read()
        self.assertIn("GROQ_API_KEY=gsk_" + "x" * 40, text)
        self.assertIn("TRUVIQ_ALERT_TO=me@example.com", text)
        self.assertIn("GROQ_API_KEY", asked_hidden)
        self.assertNotIn("TRUVIQ_ALERT_TO", asked_hidden, "an email address is not a secret")
        self.assertNotIn("SUPABASE_SERVICE_ROLE_KEY", asked_hidden, "only asked on the dashboard machine")

    def test_enter_keeps_an_existing_key(self):
        from unittest import mock
        mod, argparse = self.cli_module()
        with open(os.path.join(self.home, "guard.env"), "w") as f:
            f.write("GOOGLE_API_KEY=AIza-existing-value-123\n")
        with mock.patch("getpass.getpass", return_value=""), mock.patch("builtins.input", return_value=""), \
                mock.patch.object(mod.sys.stdin, "isatty", return_value=True):
            mod.cmd_setup(argparse.Namespace(import_env=None, with_service_key=True, keys=True))
        self.assertIn("GOOGLE_API_KEY=AIza-existing-value-123", open(os.path.join(self.home, "guard.env")).read())

    def test_refuses_without_a_terminal(self):
        p = subprocess.run([sys.executable, CLI, "setup", "--keys"], input="gsk_piped\n", capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertFalse(os.path.exists(os.path.join(self.home, "guard.env")))
