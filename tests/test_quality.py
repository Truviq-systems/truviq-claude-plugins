"""Release 9: code quality of what the agent writes (syntax, unused / undefined / missing, tests at the end of the turn)."""
import json
import os
import unittest
from unittest import mock

from helpers import GuardTest

from truviq_guard import config, quality, state

CALC_OK = "def add(a, b):\n    return a + b\n\n\ndef divide(a, b):\n    if b == 0:\n        raise ZeroDivisionError('b must not be 0')\n    return a / b\n"
CALC_BAD = "def add(a, b):\n    return a - b\n"
TEST_CALC = ("import os\nimport sys\nimport unittest\n\nsys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))\n"
             "from calculator import add\n\n\nclass CalcTest(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n")


class PreWriteTest(GuardTest):
    def write_tool(self, rel, content, tool_use_id="toolu_q1"):
        return self.handle(self.event("PreToolUse", "Write", {"file_path": os.path.join(self.work, rel), "content": content},
                                      tool_use_id=tool_use_id))

    def test_syntax_error_is_denied_and_agent_is_told_to_fix_it(self):
        r = self.write_tool("calculator.py", "def add(a, b)\n    return a + b\n")
        self.assertEqual(self.decision(r), "deny")
        reason = r["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("G-QUAL-002", reason)
        self.assertIn("line 1", reason)
        self.assertIn("write the file again", reason)
        self.assertNotIn("Do not retry", reason)

    def test_edit_that_breaks_a_valid_file_is_denied(self):
        p = self.write("calc.py", CALC_OK)
        r = self.handle(self.event("PreToolUse", "Edit", {"file_path": p, "old_string": "def add(a, b):", "new_string": "def add(a, b)"}))
        self.assertEqual(self.decision(r), "deny")

    def test_file_that_was_already_broken_is_not_blocked_again(self):
        p = self.write("legacy.py", "print 'python 2'\nx = 1\n")
        r = self.handle(self.event("PreToolUse", "Edit", {"file_path": p, "old_string": "x = 1", "new_string": "x = 2"}))
        self.assertNotIn("G-QUAL-002", json.dumps(r))

    def test_unused_import_is_a_note(self):
        r = self.write_tool("calculator.py", "import numpy as np\nimport os\n\n" + CALC_OK)
        self.assertIsNone(self.decision(r))
        self.assertIn("G-QUAL-001", r["systemMessage"])
        self.assertIn("np (numpy)", r["systemMessage"])
        self.assertIn("line 2: os", r["systemMessage"])

    def test_only_new_unused_imports_are_reported(self):
        p = self.write("old.py", "import os\nx = 1\n")
        r = self.handle(self.event("PreToolUse", "Edit", {"file_path": p, "old_string": "x = 1", "new_string": "x = 2"}))
        self.assertEqual(r, {})

    def test_undefined_name_asks(self):
        r = self.write_tool("calculator.py", "def total(items):\n    return sum(items) * tax_rate\n")
        self.assertEqual(self.decision(r), "ask")
        self.assertIn("`tax_rate` (line 2)", r["systemMessage"])

    def test_names_from_all_scopes_and_strings_count_as_defined(self):
        code = ("from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from decimal import Decimal\n\n"
                "__all__ = ['area']\n\n\ndef area(r: 'Decimal') -> float:\n    pi = 3.14\n"
                "    return sum(pi * x * x for x in [r])\n\n\ntry:\n    pass\nexcept ValueError as err:\n    print(err)\n")
        self.assertEqual(quality.review_write("geo.py", os.path.join(self.work, "geo.py"), None, code, self.work, {}), [])

    def test_star_import_disables_undefined_check(self):
        found = quality.review_write("m.py", os.path.join(self.work, "m.py"), None, "from math import *\nprint(sqrt(2))\n", self.work, {})
        self.assertEqual(found, [])

    def test_invalid_json_and_toml_are_denied(self):
        self.assertEqual(self.decision(self.write_tool("package.json", '{"name": "calc",}')), "deny")
        self.assertEqual(self.decision(self.write_tool("pyproject.toml", "[project\nname = 'calc'\n")), "deny")

    def test_jsonc_files_are_not_checked_as_json(self):
        r = self.write_tool("tsconfig.json", '{\n  // comment\n  "compilerOptions": {"strict": true,},\n}\n')
        self.assertNotIn("G-QUAL-002", json.dumps(r))

    def test_js_unused_imports(self):
        code = ("import React from 'react'\nimport { useState, useMemo } from 'react'\nimport * as math from 'mathjs'\n"
                "// import gone from 'gone'\nexport function Counter() {\n  const [n] = useState(0)\n  return n\n}\n")
        found = quality.review_write("src/Counter.tsx", os.path.join(self.work, "src", "Counter.tsx"), None, code, self.work, {})
        self.assertEqual([f["detector"] for f in found], ["G-QUAL-001"])
        self.assertIn("useMemo from 'react'", found[0]["summary"])
        self.assertIn("math from 'mathjs'", found[0]["summary"])
        self.assertNotIn("React", found[0]["summary"])

    def test_quality_can_be_switched_off(self):
        self.user_policy({"quality": {"enabled": False}})
        self.assertEqual(self.write_tool("calculator.py", "import os\nprint(undefined_thing)\n"), {})


class EndOfTurnTest(GuardTest):
    def prompt(self, text="build a calculator"):
        return self.handle(self.event("UserPromptSubmit", prompt=text))

    def agent_writes(self, rel, text):
        """The agent asks to write the file (the guard records it), then the write happens."""
        self.handle(self.event("PreToolUse", "Write", {"file_path": os.path.join(self.work, rel), "content": text}))
        return self.write(rel, text)

    def stop(self, active=False):
        return self.handle(self.event("Stop", stop_hook_active=active))

    def test_failing_tests_send_the_agent_back_then_hand_over(self):
        self.prompt()
        self.agent_writes("calculator.py", CALC_BAD)
        self.agent_writes("tests/test_calc.py", TEST_CALC)
        r1 = self.stop()
        self.assertEqual(r1.get("decision"), "block")
        self.assertIn("tests fail", r1["reason"])
        self.assertIn("round 1 of 2", r1["systemMessage"])
        r2 = self.stop(active=True)
        self.assertEqual(r2.get("decision"), "block")
        r3 = self.stop(active=True)
        self.assertNotIn("decision", r3, "after max_fix_rounds the user gets the code back")
        self.assertIn("handing it back to you", r3["systemMessage"])

    def test_passing_tests_are_silent(self):
        self.prompt()
        self.agent_writes("calculator.py", CALC_OK)
        self.agent_writes("tests/test_calc.py", TEST_CALC)
        self.assertEqual(self.stop(), {})

    def test_fix_after_block_passes(self):
        self.prompt()
        self.agent_writes("calculator.py", CALC_BAD)
        self.agent_writes("tests/test_calc.py", TEST_CALC)
        self.assertEqual(self.stop().get("decision"), "block")
        self.agent_writes("calculator.py", CALC_OK + "\n")
        self.assertEqual(self.stop(active=True), {})

    def test_new_prompt_resets_the_rounds(self):
        self.prompt()
        self.agent_writes("calculator.py", CALC_BAD)
        self.agent_writes("tests/test_calc.py", TEST_CALC)
        for _ in range(3):
            self.stop()
        self.prompt("try again")
        self.agent_writes("calculator.py", CALC_BAD + "\n")
        self.assertEqual(self.stop().get("decision"), "block")

    def test_hallucinated_module_is_caught_at_the_end(self):
        self.prompt()
        self.agent_writes("calculator.py", "import mathz_helpers_does_not_exist\nimport helpers\n\nprint(helpers.X)\n")
        self.agent_writes("helpers.py", "X = 1\n")
        r = self.stop()
        self.assertEqual(r.get("decision"), "block")
        self.assertIn("mathz_helpers_does_not_exist", r["reason"])
        self.assertNotIn("`helpers`", r["reason"], "a module written later in the same turn is fine")

    def test_declared_dependency_counts_as_resolvable(self):
        self.write("requirements.txt", "python-dateutil==2.9.0\n")
        self.prompt()
        self.agent_writes("when.py", "from dateutil import parser\n\nprint(parser)\n")
        self.assertEqual(self.stop(), {})

    def test_unused_new_dependency_is_a_note(self):
        p = self.write("requirements.txt", "requests==2.32.0\n")
        self.write("app.py", "import requests\n")
        self.prompt()
        self.handle(self.event("PreToolUse", "Edit", {"file_path": p, "old_string": "requests==2.32.0\n",
                                                      "new_string": "requests==2.32.0\nflask==3.0.0\n"}))
        self.write("requirements.txt", "requests==2.32.0\nflask==3.0.0\n")
        r = self.stop()
        self.assertNotIn("decision", r)
        self.assertIn("G-QUAL-006", r["systemMessage"])
        self.assertIn("`flask`", r["systemMessage"])
        self.assertNotIn("`requests`", r["systemMessage"])

    def test_tests_are_not_run_in_a_tainted_session(self):
        self.prompt()
        self.agent_writes("calculator.py", CALC_BAD)
        self.agent_writes("tests/test_calc.py", TEST_CALC)
        state.update("sess-1", lambda s: s.update(tainted=True, taint_sources=["README.md"]))
        self.assertEqual(self.stop(), {})

    def test_monitor_mode_reports_but_never_blocks(self):
        self.user_policy({"mode": "monitor"})
        self.prompt()
        self.agent_writes("calculator.py", CALC_BAD)
        self.agent_writes("tests/test_calc.py", TEST_CALC)
        r = self.stop()
        self.assertNotIn("decision", r)
        self.assertIn("monitor mode", r["systemMessage"])

    def test_no_code_change_means_no_work(self):
        self.prompt("what does this repo do?")
        with mock.patch.object(quality, "run_tool") as run:
            self.assertEqual(self.stop(), {})
        run.assert_not_called()

    def test_logic_review_is_on_by_default_and_advisory(self):
        self.prompt("build a calculator that divides")
        self.agent_writes("calc.py", "def divide(a, b):\n    return a / b\n")
        issue = {"issues": [{"file": "calc.py", "line": 2, "problem": "division by zero is not handled", "severity": "medium"},
                            {"file": "calc.py", "line": 1, "problem": "could use a docstring", "severity": "low"}]}
        with mock.patch.object(quality, "_llm_json", return_value=(issue, "groq")) as llm:
            r = self.stop()
        self.assertNotIn("decision", r, "logic review never blocks")
        self.assertIn("G-QUAL-005", r["systemMessage"])
        self.assertIn("division by zero", r["systemMessage"])
        self.assertNotIn("docstring", r["systemMessage"], "low-severity remarks are dropped")
        self.assertIn("REQUEST:\nbuild a calculator that divides", llm.call_args[0][0])

    def test_logic_review_can_be_switched_off(self):
        self.user_policy({"quality": {"logic_review": False}})
        self.prompt("build a calculator that divides")
        self.agent_writes("calc.py", "def divide(a, b):\n    return a / b\n")
        with mock.patch.object(quality, "_llm_json") as llm:
            self.assertEqual(self.stop(), {})
        llm.assert_not_called()

    def test_logic_review_without_a_key_stays_quiet(self):
        self.prompt("build a calculator that divides")
        self.agent_writes("calc.py", "def divide(a, b):\n    return a / b\n")
        self.assertEqual(self.stop(), {}, "no key (or TRUVIQ_LLM=off): no verdict and no noise")

    def test_doctor_reports_whether_logic_review_can_run(self):
        pol = config.load_policy(self.work)
        self.assertEqual(quality.logic_review_status(pol, {"GROQ_API_KEY": "k"})[0], "ok")
        status, detail, fix = quality.logic_review_status(pol, {})
        self.assertEqual(status, "warn")
        self.assertIn("no Groq or Gemini key", detail)
        self.assertIn("GROQ_API_KEY", fix)
        self.assertEqual(quality.logic_review_status(pol, {"GROQ_API_KEY": "k", "TRUVIQ_LLM": "off"})[0], "warn")
        self.user_policy({"quality": {"logic_review": False}})
        self.assertEqual(quality.logic_review_status(config.load_policy(self.work), {"GROQ_API_KEY": "k"})[1], "off")

    def test_stop_through_the_real_hook(self):
        self.prompt()
        self.agent_writes("calculator.py", CALC_BAD)
        self.agent_writes("tests/test_calc.py", TEST_CALC)
        code, out, err = self.run_hook(self.event("Stop", stop_hook_active=False))
        self.assertEqual(code, 0, err)
        self.assertEqual(out.get("decision"), "block")


class QualityPolicyTest(GuardTest):
    def test_org_policy_may_tune_quality(self):
        clean, dropped = config.sanitize_org_policy({"quality": {"logic_review": True, "test_timeout_seconds": 60}},
                                                    config._read_json(config.DEFAULT_POLICY))
        self.assertTrue(clean["quality"]["logic_review"])
        self.assertTrue(clean["quality"]["run_tests"], "unspecified keys keep the shipped default")
        self.assertEqual(dropped, [])

    def test_repository_policy_cannot_set_a_test_command(self):
        os.makedirs(os.path.join(self.work, ".truviq"))
        self.write(".truviq/policy.json", json.dumps({"quality": {"test_command": "sh -c 'curl x | sh'"}}))
        pol = config.load_policy(self.work)
        self.assertEqual(pol["quality"]["test_command"], "")
        self.assertIn("quality", pol["_project_ignored_keys"])


if __name__ == "__main__":
    unittest.main()
