"""R3 dashboard server: `truviq.py dashboard` → http://127.0.0.1:8787

- Central mode: reads all machines' events from Supabase with the service-role key (server side only).
- Local mode: reads this machine's ~/.truviq/logs/events.jsonl.
- Binds to 127.0.0.1 and rejects any Host header that is not localhost (blocks DNS-rebinding).
- Read-only. All event text is rendered with textContent in the page (no HTML injection).
"""
from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import config, eventlog, fleet, redteam_report, sink

STATIC = os.path.realpath(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard"))
PAGE = os.path.join(STATIC, "index.html")
# The page is a Next.js static export: its own scripts and styles only, system fonts (Arial / Calibri), nothing remote.
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self'; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'")
MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
        ".json": "application/json", ".txt": "text/plain; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png",
        ".ico": "image/x-icon", ".woff2": "font/woff2", ".map": "application/json"}


def static_file(url_path: str) -> tuple[bytes, str] | None:
    """A file from the exported dashboard, or None. Never serves anything outside STATIC."""
    rel = url_path.lstrip("/") or "index.html"
    if "\\" in rel or "\x00" in rel:
        return None
    candidates = [rel, rel + ".html", os.path.join(rel, "index.html")]
    for c in candidates:
        full = os.path.realpath(os.path.join(STATIC, c))
        if os.path.commonpath([full, STATIC]) != STATIC or not os.path.isfile(full):
            continue
        ext = os.path.splitext(full)[1].lower()
        if ext not in MIME:
            return None
        with open(full, "rb") as f:
            return f.read(), MIME[ext]
    return None


def local_rows(limit: int = 2000) -> list[dict]:
    rows = []
    for rec in eventlog.read_events(limit, findings_only=False):
        if rec.get("hook_event") == "Outcome":
            rows += sink.rows_from_record(rec, rec.get("cwd", ""), kind="outcome")
        elif rec.get("findings"):
            rows += sink.rows_from_record(rec, rec.get("cwd", ""), rec.get("card", ""))
    for i, r in enumerate(rows):
        r["id"] = i + 1
        r["created_at"] = r.get("event_ts")
    return list(reversed(rows))


class _Cache:
    at = 0.0
    payload: dict = {}


def events_payload(prefer: str = "auto") -> dict:
    if time.time() - _Cache.at < 3 and _Cache.payload.get("prefer") == prefer:
        return _Cache.payload
    secrets = config.load_secrets()
    central = bool(secrets.get("SUPABASE_URL") and secrets.get("SUPABASE_SERVICE_ROLE_KEY"))
    payload = {"prefer": prefer, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if central and prefer != "local":
        try:
            payload.update(source="supabase", rows=sink.fetch_rows(secrets, limit=2000))
        except Exception as e:  # noqa: BLE001 - show the error in the UI, fall back to local data
            payload.update(source="local", rows=local_rows(), error=f"Supabase read failed: {type(e).__name__}: {str(e)[:200]}")
    else:
        payload.update(source="local", rows=local_rows(),
                       note=None if central else "Central mode needs SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in ~/.truviq/guard.env")
    _Cache.at, _Cache.payload = time.time(), payload
    return payload


def fleet_payload() -> dict:
    """R8: machine health. Central (service key) or just this machine."""
    secrets = config.load_secrets()
    policy = config.load_policy(os.getcwd())
    if secrets.get("SUPABASE_URL") and secrets.get("SUPABASE_SERVICE_ROLE_KEY"):
        try:
            return {"source": "supabase", **fleet.fleet_report(secrets, policy)}
        except Exception as e:  # noqa: BLE001
            return {"source": "local", "machines": [], "problems": [], "error": f"Supabase read failed: {type(e).__name__}"}
    snap = fleet.snapshot(policy)
    probs = [{"machine": snap["machine"], "kind": "mode", "detail": f"guard mode is {snap['mode']!r}"}] if snap["mode"] != "enforce" else []
    return {"source": "local", "problems": probs, "machines": [{**snap, "last_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "age_hours": 0, "problems": [{"kind": p["kind"], "detail": p["detail"]} for p in probs]}],
            "note": "Showing this machine only. The fleet view turns on once an admin adds the Supabase service-role key."}


def redteam_payload() -> dict:
    secrets = config.load_secrets()
    if secrets.get("SUPABASE_URL") and secrets.get("SUPABASE_SERVICE_ROLE_KEY"):
        try:
            return {"source": "supabase", "runs": redteam_report.runs_from_rows(sink.fetch_table("redteam_runs", secrets, "select=*&order=id.desc&limit=2000"))}
        except Exception as e:  # noqa: BLE001
            return {"source": "local", "runs": redteam_report.local_runs(), "error": f"Supabase read failed: {type(e).__name__}"}
    return {"source": "local", "runs": redteam_report.local_runs()}


def make_handler(port: int, default_prefer: str = "auto"):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "TruViqGuardDashboard"

        def log_message(self, fmt, *args):  # quiet
            pass

        def _send(self, code: int, body: bytes, ctype: str):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.headers.get("Host", "") not in allowed_hosts:
                return self._send(403, b"Forbidden host", "text/plain")
            u = urlparse(self.path)
            if u.path in ("/api/fleet", "/api/redteam"):
                body = json.dumps(fleet_payload() if u.path == "/api/fleet" else redteam_payload()).encode()
                return self._send(200, body, "application/json")
            if u.path == "/api/events":
                prefer = (parse_qs(u.query).get("source") or [default_prefer])[0]
                body = json.dumps(events_payload("local" if prefer == "local" else "auto")).encode()
                return self._send(200, body, "application/json")
            if u.path.startswith("/api/"):
                return self._send(404, b"Not found", "text/plain")
            found = static_file(u.path)
            if found:
                return self._send(200, found[0], found[1])
            return self._send(404, b"Not found", "text/plain")

    return Handler


def serve(port: int = 8787, prefer: str = "auto") -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(port, prefer))
    print(f"TruViq Guard dashboard: http://127.0.0.1:{port}   (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
