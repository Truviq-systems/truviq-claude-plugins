"""Step S2: replay real hook inputs captured from Claude Code 2.1.295 (benign session)."""
import json
import os
import unittest

from helpers import HERE, GuardTest

FIXTURES = os.path.join(HERE, "fixtures", "hook_inputs")


class RealFixtureReplayTest(GuardTest):
    def load(self, name):
        with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
            s = f.read().replace("{REPO}", self.work).replace("{HOME}", os.path.expanduser("~"))
        return json.loads(s)

    def test_all_captured_events_are_allowed(self):
        self.write("docs/CLEAN.md", "# Architecture\n\nThe service has an HTTP layer, a refunds module and a Postgres store.\n")
        names = sorted(os.listdir(FIXTURES))
        self.assertGreaterEqual(len(names), 6)
        for name in names:
            reply = self.handle(self.load(name))
            self.assertEqual(reply, {}, f"{name} should pass silently, got {reply}")

    def test_captured_shape_carries_fields_we_rely_on(self):
        post_read = self.load("PostToolUse-Read.json")
        self.assertIn("content", post_read["tool_response"]["file"])
        post_bash = self.load("PostToolUse-Bash.json")
        self.assertIn("stdout", post_bash["tool_response"])
        for name in os.listdir(FIXTURES):
            ev = self.load(name)
            for k in ("session_id", "cwd", "hook_event_name"):
                self.assertIn(k, ev, name)


if __name__ == "__main__":
    unittest.main()
