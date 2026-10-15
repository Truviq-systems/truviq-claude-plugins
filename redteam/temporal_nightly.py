#!/usr/bin/env python3
"""R6: run the nightly guard red team on your Temporal server (separate task queue, separate schedule).

This file is independent of the AI Sentinel worker: it uses its own task queue and schedule id, so it never
touches the existing workflows. Needs `pip install temporalio` (only on the machine that runs this worker).

  python3 redteam/temporal_nightly.py worker                 # run the worker (keep it running)
  python3 redteam/temporal_nightly.py schedule --hour 2      # create/replace the nightly 02:00 schedule
  python3 redteam/temporal_nightly.py run-now                # start one run immediately
  python3 redteam/temporal_nightly.py delete                 # remove the schedule

Host comes from TEMPORAL_HOST (env var, or the .env next to this folder). No Temporal? Use cron instead:
  0 2 * * *  cd /path/to/truviq_guard_for_coding_agents && python3 redteam/nightly.py --model haiku
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TASK_QUEUE = "truviq-guard-redteam"
SCHEDULE_ID = "truviq-guard-nightly-redteam"
WORKFLOW_ID = "truviq-guard-redteam-manual"

try:
    from temporalio import activity, workflow
    from temporalio.client import Client, Schedule, ScheduleActionStartWorkflow, ScheduleSpec
    from temporalio.worker import Worker
    HAVE_TEMPORAL = True
except ImportError:  # keeps the file importable (and testable) without the SDK
    HAVE_TEMPORAL = False
    activity = workflow = None


def _host() -> str:
    host = os.environ.get("TEMPORAL_HOST")
    if host:
        return host
    try:
        with open(os.path.join(ROOT, ".env"), encoding="utf-8") as f:
            for line in f:
                if line.startswith("TEMPORAL_HOST="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    raise SystemExit("Set TEMPORAL_HOST (host:port of your Temporal server)")


async def run_nightly(model: str = "haiku") -> dict:
    """Run redteam/nightly.py as a subprocess and return its summary."""
    import tempfile
    fd, out_path = tempfile.mkstemp(prefix="truviq-redteam-", suffix=".json")  # unpredictable and created by us
    os.close(fd)
    proc = await asyncio.create_subprocess_exec(
        sys.executable, os.path.join(HERE, "nightly.py"), "--model", model, "--out", out_path,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    stdout, _ = await proc.communicate()
    tail = stdout.decode("utf-8", "replace")[-1500:]
    try:
        with open(out_path, encoding="utf-8") as f:
            summary = json.load(f)["summary"]
    except (OSError, ValueError, KeyError):
        summary = {"verdict": "ERROR", "detail": tail}
    summary["exit_code"] = proc.returncode
    try:
        os.remove(out_path)
    except OSError:
        pass
    return summary


if HAVE_TEMPORAL:
    @activity.defn(name="truviq_guard_redteam_run")
    async def run_nightly_activity(model: str) -> dict:
        return await run_nightly(model)

    @workflow.defn(name="NightlyGuardRedTeam")
    class NightlyGuardRedTeam:
        @workflow.run
        async def run(self, model: str = "haiku") -> dict:
            return await workflow.execute_activity(
                run_nightly_activity, model, start_to_close_timeout=timedelta(hours=1),
                schedule_to_close_timeout=timedelta(hours=2))


async def _client() -> "Client":
    return await Client.connect(_host())


async def cmd_worker() -> None:
    client = await _client()
    print(f"Worker on {TASK_QUEUE} ({_host()}). Ctrl+C to stop.")
    await Worker(client, task_queue=TASK_QUEUE, workflows=[NightlyGuardRedTeam], activities=[run_nightly_activity]).run()


async def cmd_schedule(hour: int, model: str) -> None:
    client = await _client()
    try:
        await client.get_schedule_handle(SCHEDULE_ID).delete()
    except Exception:  # noqa: BLE001 - nothing to replace
        pass
    await client.create_schedule(SCHEDULE_ID, Schedule(
        action=ScheduleActionStartWorkflow(NightlyGuardRedTeam.run, model, id="truviq-guard-redteam-nightly", task_queue=TASK_QUEUE),
        spec=ScheduleSpec(cron_expressions=[f"0 {hour} * * *"])))
    print(f"Schedule {SCHEDULE_ID}: every day at {hour:02d}:00 (server time), model {model}")


async def cmd_run_now(model: str) -> None:
    client = await _client()
    result = await client.execute_workflow(NightlyGuardRedTeam.run, model, id=WORKFLOW_ID + "-" + str(os.getpid()), task_queue=TASK_QUEUE)
    print(json.dumps(result, indent=2))


async def cmd_delete() -> None:
    await (await _client()).get_schedule_handle(SCHEDULE_ID).delete()
    print("Schedule deleted")


def main() -> int:
    if not HAVE_TEMPORAL:
        print("temporalio is not installed. Run: pip install temporalio   (or use cron, see the file header)")
        return 2
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    args = sys.argv[2:]
    model = args[args.index("--model") + 1] if "--model" in args else "haiku"
    hour = int(args[args.index("--hour") + 1]) if "--hour" in args else 2
    if cmd == "worker":
        asyncio.run(cmd_worker())
    elif cmd == "schedule":
        asyncio.run(cmd_schedule(hour, model))
    elif cmd == "run-now":
        asyncio.run(cmd_run_now(model))
    elif cmd == "delete":
        asyncio.run(cmd_delete())
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
