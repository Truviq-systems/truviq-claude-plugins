"""Central event sink (R3): redacted guard events → Supabase table `guard_events`.

- Machines with the plugin use only SUPABASE_URL + SUPABASE_ANON_KEY. Row-level security lets the
  anon role INSERT and nothing else (see supabase/001_guard_events.sql).
- The dashboard reads with SUPABASE_SERVICE_ROLE_KEY, which only the dashboard machine holds.
- The hook never waits: rows go to ~/.truviq/outbox/ship-*.json and a detached `truviq.py ship`
  sends them. Failed sends stay in the outbox and are retried by the next ship.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
import uuid

from . import __version__, paths
from .cards import verdict_of
from .secret_scan import redact

BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "truviq.py")
TABLE = "guard_events"


def configured(secrets: dict) -> bool:
    return bool(secrets.get("SUPABASE_URL") and secrets.get("SUPABASE_ANON_KEY"))


def _outbox() -> str:
    return paths.ensure_private_dir(os.path.join(paths.guard_home(), "outbox"))


def rows_from_record(record: dict, project_root: str = "", card: str = "", kind: str = "finding") -> list[dict]:
    base = {
        "event_ts": record.get("ts") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "machine": socket.gethostname()[:120],
        "os_user": (os.environ.get("USER") or os.environ.get("USERNAME") or "unknown")[:80],
        "plugin_version": __version__,
        "session_id": str(record.get("session_id", ""))[:120],
        "project": os.path.basename(project_root or record.get("cwd", "") or "")[:200],
        "hook_event": str(record.get("hook_event", ""))[:40],
        "tool": str(record.get("tool") or "")[:120],
        "tool_use_id": str(record.get("tool_use_id") or "")[:120],
        "kind": kind,
        "decision": record.get("decision", ""),
        "verdict": verdict_of(record.get("decision", "")) if kind == "finding" else str(record.get("outcome", "")).upper(),
        "enforced": bool(record.get("enforced", True)),
        "tainted": bool(record.get("tainted", False)),
        "card": redact(card or record.get("card") or "")[:4000],
    }
    if kind == "outcome":
        return [{**base, "detector": "", "severity": "", "title": "User decision", "summary": record.get("summary", "")[:2000],
                 "evidence": "", "file_path": str(record.get("file_path", ""))[:500], "line": None, "compliance": {}, "deps": []}]
    rows = []
    for f in record.get("findings", []):
        rows.append({**base,
                     "detector": f.get("detector", ""), "severity": f.get("severity", ""), "title": f.get("title", "")[:200],
                     "summary": redact(str(f.get("summary", "")))[:2000], "evidence": redact(str(f.get("evidence", "")))[:1000],
                     "file_path": str(f.get("file") or "")[:500], "line": f.get("line") if isinstance(f.get("line"), int) else None,
                     "compliance": f.get("compliance", {}), "deps": record.get("deps", [])[:50]})
    return rows


def queue(rows: list[dict]) -> None:
    if not rows:
        return
    p = os.path.join(_outbox(), f"ship-{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}.json")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(rows, f)
    if os.environ.get("TRUVIQ_DRY_RUN") == "1":  # release tests: keep the rows in the outbox, send nothing
        return
    import subprocess
    kw = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "close_fds": True}
    if os.name == "nt":
        kw["creationflags"] = 0x00000008 | 0x00000200
    else:
        kw["start_new_session"] = True
    subprocess.Popen([sys.executable, BIN, "ship"], **kw)  # noqa: S603 - fixed argv, no shell


def _request(url: str, key: str, method: str = "GET", body=None, timeout: float = 15):
    import re
    import urllib.request
    if not (url.startswith("https://") or re.match(r"http://(?:localhost|127\.0\.0\.1)(?::\d+)?/", url)):
        raise OSError("SUPABASE_URL must use https")  # keys and policy must never cross the network in clear text
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"apikey": key, "Authorization": f"Bearer {key}", "Content-Type": "application/json",
                                          "Prefer": "return=minimal", "User-Agent": f"truviq-guard/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - configured Supabase URL
        data = r.read()
        return json.loads(data) if data else None


def ship_pending(secrets: dict, max_files: int = 50) -> tuple[int, str]:
    """Send queued rows. Returns (rows_sent, message). Only one shipper runs at a time."""
    if not configured(secrets):
        return 0, "Supabase not configured"
    lock_fd = os.open(os.path.join(_outbox(), ".ship.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            import fcntl
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:
            pass
        except OSError:
            return 0, "another shipper is running"
        files = sorted(f for f in os.listdir(_outbox()) if f.startswith("ship-") and f.endswith(".json"))[:max_files]
        sent = 0
        url = secrets["SUPABASE_URL"].rstrip("/") + f"/rest/v1/{TABLE}"
        for name in files:
            p = os.path.join(_outbox(), name)
            try:
                with open(p, encoding="utf-8") as f:
                    rows = json.load(f)
                _request(url, secrets["SUPABASE_ANON_KEY"], "POST", rows)
                os.remove(p)
                sent += len(rows)
            except ValueError:
                os.replace(p, p + ".bad")
            except OSError as e:
                return sent, f"send failed ({getattr(e, 'code', '') or type(e).__name__}); {len(files)} file(s) kept for retry"
        return sent, "ok"
    finally:
        os.close(lock_fd)


def fetch_rows(secrets: dict, limit: int = 1000, since_id: int = 0) -> list[dict]:
    """Dashboard read (service role key; never sent to the browser)."""
    key = secrets.get("SUPABASE_SERVICE_ROLE_KEY")
    if not (secrets.get("SUPABASE_URL") and key):
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are needed to read the central dashboard")
    q = f"select=*&order=id.desc&limit={int(limit)}" + (f"&id=gt.{int(since_id)}" if since_id else "")
    return _request(secrets["SUPABASE_URL"].rstrip("/") + f"/rest/v1/{TABLE}?{q}", key) or []


def post_rows(table: str, rows: list[dict], secrets: dict) -> tuple[bool, str]:
    """Synchronous insert for low-volume tables (red-team runs, heartbeats). Anon key, insert-only."""
    if not configured(secrets):
        return False, "Supabase not configured"
    if os.environ.get("TRUVIQ_DRY_RUN") == "1":
        return True, "dry run"
    try:
        _request(secrets["SUPABASE_URL"].rstrip("/") + f"/rest/v1/{table}", secrets["SUPABASE_ANON_KEY"], "POST", rows, timeout=10)
        return True, "ok"
    except OSError as e:
        return False, f"{getattr(e, 'code', '') or type(e).__name__}"


def fetch_table(table: str, secrets: dict, query: str = "select=*&order=id.desc&limit=500") -> list[dict]:
    """Read a table with the service-role key (dashboard machine only)."""
    key = secrets.get("SUPABASE_SERVICE_ROLE_KEY")
    if not (secrets.get("SUPABASE_URL") and key):
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are needed to read " + table)
    return _request(secrets["SUPABASE_URL"].rstrip("/") + f"/rest/v1/{table}?{query}", key) or []
