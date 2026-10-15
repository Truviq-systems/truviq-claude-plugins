"""Per-session state (taint tracking), stored as one JSON file per Claude Code session.

Hooks for one session can run in parallel, so updates take an exclusive file lock.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import time

from . import paths

try:
    import fcntl
except ImportError:  # Windows: no locking; last writer wins
    fcntl = None

EMPTY = {"tainted": False, "taint_sources": [], "private_data_touched": False, "secret_sources": [],
         "egress_hosts": [], "asked_reads": [], "alerts_sent": {}, "pending_asks": {}, "findings": 0, "turn": {}}


def _dir() -> str:
    return paths.ensure_private_dir(os.path.join(paths.guard_home(), "state"))


def _file(session_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", session_id or "unknown")[:100].lstrip(".") or "unknown"
    return os.path.join(_dir(), safe + ".json")


@contextlib.contextmanager
def _locked(path: str):
    fd = os.open(path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if fcntl:
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        merged = {**EMPTY, **data} if isinstance(data, dict) else EMPTY
        return json.loads(json.dumps(merged))  # deep copy: never share EMPTY's nested dicts/lists
    except (OSError, ValueError):
        return json.loads(json.dumps(EMPTY))


def load(session_id: str) -> dict:
    return _read(_file(session_id))


def update(session_id: str, fn) -> dict:
    """Apply fn(state) under the lock and save. Returns the new state."""
    path = _file(session_id)
    with _locked(path):
        st = _read(path)
        fn(st)
        for k in ("taint_sources", "secret_sources", "egress_hosts", "asked_reads"):
            st[k] = list(dict.fromkeys(st[k]))[-50:]
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(st, f)
        os.replace(tmp, path)
    return st


def cleanup(max_age_days: int = 7) -> None:
    cutoff = time.time() - max_age_days * 86400
    d = _dir()
    for name in os.listdir(d):
        p = os.path.join(d, name)
        try:
            if os.path.getmtime(p) < cutoff:
                os.remove(p)
        except OSError:
            pass
