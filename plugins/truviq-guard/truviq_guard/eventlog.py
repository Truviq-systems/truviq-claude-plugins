"""Local JSONL decision log (~/.truviq/logs/events.jsonl). Evidence is redacted before writing."""
from __future__ import annotations

import json
import os
import time

from . import paths
from .secret_scan import redact

MAX_BYTES = 10 * 1024 * 1024


def _logdir() -> str:
    return paths.ensure_private_dir(os.path.join(paths.guard_home(), "logs"))


def _append(name: str, line: str) -> None:
    p = os.path.join(_logdir(), name)
    try:
        if os.path.exists(p) and os.path.getsize(p) > MAX_BYTES:
            os.replace(p, p + ".1")
    except OSError:
        pass
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def events_path() -> str:
    return os.path.join(_logdir(), "events.jsonl")


def write_event(record: dict) -> None:
    rec = dict(record)
    rec["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for f in rec.get("findings", []):
        f["evidence"] = redact(str(f.get("evidence", "")))[:500]
    _append("events.jsonl", json.dumps(rec, ensure_ascii=False))


def write_error(context: str) -> None:
    import traceback

    _append("guard-errors.log", time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime()) + context + "\n" + traceback.format_exc())


def read_events(limit: int = 20, session_id: str | None = None, findings_only: bool = True) -> list[dict]:
    out = []
    try:
        with open(events_path(), encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if session_id and rec.get("session_id") != session_id:
                    continue
                if findings_only and not rec.get("findings"):
                    continue
                out.append(rec)
    except OSError:
        return []
    return out[-limit:]
