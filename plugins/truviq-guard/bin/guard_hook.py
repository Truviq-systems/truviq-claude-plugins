#!/usr/bin/env python3
"""Claude Code hook entry point for TruViq Guard.

Reads one hook event (JSON) from stdin, prints the reply JSON, exits 0.
Fail-safe (feature 1.8): if the guard itself errors, commands and file writes
are blocked (fail-closed) and everything else is allowed (fail-open).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FAIL_CLOSED = {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit"}
BUDGET_SECONDS = 10  # below the 15 s hook timeout, so a slow scan fails CLOSED instead of timing out OPEN
STOP_BUDGET_SECONDS = 200  # end-of-turn check runs the project's tests; below the 240 s Stop hook timeout


class BudgetExceeded(Exception):
    """Not an OSError subclass, so library `except OSError` blocks cannot swallow it."""


def _arm_budget(seconds: int = BUDGET_SECONDS):
    try:
        import signal

        def _expired(signum, frame):
            raise BudgetExceeded(f"guard exceeded its {seconds}s budget")
        signal.signal(signal.SIGALRM, _expired)
        signal.alarm(seconds)
    except (ImportError, AttributeError, ValueError):
        pass  # Windows: no SIGALRM


def main() -> int:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw or "{}")
    except ValueError:
        event = {}
    capture = os.environ.get("TRUVIQ_CAPTURE_DIR")
    if capture and event:
        try:
            os.makedirs(capture, exist_ok=True)
            name = f"{event.get('hook_event_name', 'x')}-{event.get('tool_name', 'none')}.json".replace("/", "_")
            with open(os.path.join(capture, name), "w", encoding="utf-8") as f:
                json.dump(event, f, indent=2)
        except OSError:
            pass
    try:
        _arm_budget(STOP_BUDGET_SECONDS if event.get("hook_event_name") == "Stop" else BUDGET_SECONDS)
        from truviq_guard import engine
        reply, code = engine.handle(event)
    except Exception as exc:  # noqa: BLE001 - any guard failure must hit the fail-safe
        try:
            from truviq_guard import eventlog
            eventlog.write_error(f"hook failure on {event.get('hook_event_name')}/{event.get('tool_name')}")
        except Exception:  # noqa: BLE001
            pass
        if event.get("hook_event_name") == "PreToolUse" and event.get("tool_name") in FAIL_CLOSED:
            msg = (f"🛡 TruViq Guard error ({type(exc).__name__}); blocking {event.get('tool_name')} to stay safe. "
                   "Check ~/.truviq/logs/guard-errors.log, or set \"mode\": \"off\" in ~/.truviq/policy.json to disable.")
            reply = {"systemMessage": msg,
                     "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                            "permissionDecisionReason": "TruViq Guard failed internally and is failing closed. "
                                                                        "Tell the user the guard needs attention."}}
            code = 0
        else:
            return 0
    if reply:
        sys.stdout.write(json.dumps(reply))
    return code


if __name__ == "__main__":
    sys.exit(main())
