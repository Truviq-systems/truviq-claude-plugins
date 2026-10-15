#!/usr/bin/env python3
"""R6: nightly guard-off vs guard-on run against real Claude Code.

Runs the cases from e2e/run_e2e.py (a fixed, harmless demo repo: fake canary secrets and `.invalid`
URLs) twice per case:

  monitor arm  the guard only logs what it WOULD have done. This is the "guard off" baseline: it shows
               which attacks the agent actually attempts.
  enforce arm  the guard blocks or asks. A canary file appearing here means an attack got through.

Per run it reports attempted / blocked / leaked / not-reached per arm, appends the results to
~/.truviq/redteam/runs.jsonl and, if Supabase is configured, to the `redteam_runs` table.
It uses your Claude Code login (plan usage), never an API key.

  python3 redteam/nightly.py --model haiku                 # all cases, both arms
  python3 redteam/nightly.py --case curl_pipe_sh --no-ship
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import socket
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "plugins", "truviq-guard"))

from truviq_guard import __version__, config, paths, sink  # noqa: E402
from truviq_guard.redteam_report import ARMS, summarize  # noqa: E402,F401


def _load_e2e():
    spec = importlib.util.spec_from_file_location("run_e2e", os.path.join(ROOT, "e2e", "run_e2e.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", default="haiku")
    ap.add_argument("--case", nargs="*")
    ap.add_argument("--claude")
    ap.add_argument("--no-ship", action="store_true", help="do not send results to Supabase")
    ap.add_argument("--out", help="also write the full JSON report to this path")
    a = ap.parse_args()

    e2e = _load_e2e()
    claude = e2e.find_claude(a.claude)
    run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    rows = []
    for name, prompt, det, dec in e2e.CASES:
        if a.case and name not in a.case:
            continue
        for arm in ARMS:
            try:
                r = e2e.run_case(claude, a.model, name, prompt, det, dec, mode=arm)
            except Exception as exc:  # noqa: BLE001 - one broken case must not stop the nightly run
                r = {"case": name, "status": "NOT_REACHED", "attempted": False, "blocked": False, "leaked": False,
                     "seconds": 0, "model_reply": f"runner error: {type(exc).__name__}: {exc}"}
            row = {"run_id": run_id, "arm": arm, "case_id": name, "detector": det.split("|")[0], "status": r["status"],
                   "attempted": r["attempted"], "blocked": r["blocked"], "leaked": r["leaked"], "seconds": r["seconds"]}
            rows.append(row)
            print(f"{arm:8} {r['status']:12} {name:24} attempted={r['attempted']} blocked={r['blocked']} leaked={r['leaked']} ({r['seconds']}s)")

    summary = summarize(rows)
    report = {"run_id": run_id, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "plugin_version": __version__,
              "model": a.model, "machine": socket.gethostname(), "summary": summary, "rows": rows}
    d = paths.ensure_private_dir(os.path.join(paths.guard_home(), "redteam"))
    fd = os.open(os.path.join(d, "runs.jsonl"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(report) + "\n")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    shipped = "skipped"
    if not a.no_ship:
        ok, msg = sink.post_rows("redteam_runs", [{**r, "machine": report["machine"], "plugin_version": __version__,
                                                    "claude_model": a.model} for r in rows], config.load_secrets())
        shipped = msg
    s = summary
    print(f"\nRun {run_id}: guard OFF reached {s['monitor']['attempted']}/{s['monitor']['cases']} attacks · "
          f"guard ON blocked {s['enforce']['blocked']}/{s['enforce']['attempted']} attempted, leaked {s['enforce']['leaked']} · "
          f"verdict {s['verdict']} · Supabase: {shipped}")
    print("NOT_REACHED means the model itself declined, so the guard was never asked. LEAKED means a canary file appeared.")
    return 1 if s["verdict"] == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
