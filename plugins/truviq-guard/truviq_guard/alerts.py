"""Email alerts through the Resend API.

The hook never waits for email: it writes the alert to ~/.truviq/outbox/ and
starts a detached `truviq.py send-alert <file>` process.
"""
from __future__ import annotations

import html
import json
import os
import socket
import sys
import time
import uuid

from . import paths
from .catalog import DETECTORS, compliance_tags

RESEND_URL = "https://api.resend.com/emails"
DEFAULT_FROM = "TruViq Guard <onboarding@resend.dev>"
BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "truviq.py")


def configured(secrets: dict) -> bool:
    return bool(secrets.get("RESEND_API_KEY") and secrets.get("TRUVIQ_ALERT_TO"))


def queue(alert: dict) -> str:
    outbox = paths.ensure_private_dir(os.path.join(paths.guard_home(), "outbox"))
    path = os.path.join(outbox, f"{int(time.time())}-{uuid.uuid4().hex[:8]}.json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(alert, f)
    if os.environ.get("TRUVIQ_DRY_RUN") == "1":  # release tests: keep the alert file, send nothing
        return path
    import subprocess

    kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "close_fds": True}
    if os.name == "nt":
        kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen([sys.executable, BIN, "send-alert", path], **kwargs)  # noqa: S603 - fixed argv, no shell
    return path


def build_email(alert: dict) -> tuple[str, str, str]:
    f0 = alert["findings"][0]
    repo = os.path.basename(alert.get("project_root") or alert.get("cwd") or "") or "unknown repo"
    verb = {"deny": "blocked", "ask": "needs approval", "warn": "warning"}.get(alert.get("decision"), alert.get("decision", ""))
    subject = f"[TruViq Guard] {f0['severity']}: {f0['title']} ({verb}) in {repo}"
    rows = []
    text_lines = [subject, "", f"When: {alert.get('ts')}", f"Machine: {alert.get('host')}  User: {alert.get('user')}",
                  f"Repository: {alert.get('cwd')}", f"Session: {alert.get('session_id')}",
                  f"Hook: {alert.get('hook_event')} / {alert.get('tool') or '-'}", f"Decision: {alert.get('decision')}", ""]
    for f in alert["findings"]:
        tags = compliance_tags(f["detector"])
        tag_txt = " · ".join(f"{k.upper()} {', '.join(v)}" for k, v in tags.items() if v)
        rows.append(
            f"<tr><td style='padding:8px;border-bottom:1px solid #ddd'><b>{html.escape(f['detector'])}</b><br>{html.escape(f['severity'])}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #ddd'><b>{html.escape(f['title'])}</b><br>{html.escape(f['summary'])}"
            f"<br><code style='font-size:12px'>{html.escape(str(f.get('evidence', ''))[:300])}</code>"
            f"<br><span style='color:#555;font-size:12px'>{html.escape(tag_txt)}</span>"
            f"<br><i style='font-size:12px'>{html.escape(DETECTORS.get(f['detector'], {}).get('remediation', ''))}</i></td></tr>")
        text_lines += [f"- {f['detector']} {f['severity']}: {f['title']} — {f['summary']}",
                       f"  evidence: {str(f.get('evidence', ''))[:300]}", f"  {tag_txt}", ""]
    if alert.get("taint_sources"):
        text_lines.append("Untrusted content seen in this session: " + ", ".join(alert["taint_sources"]))
    body = (f"<div style='font-family:system-ui,sans-serif;max-width:680px'>"
            f"<h2 style='margin:0 0 8px'>🛡 TruViq Guard {html.escape(verb)} an action</h2>"
            f"<p style='margin:0 0 12px;color:#444'>{html.escape(str(alert.get('cwd')))} · {html.escape(str(alert.get('ts')))} · "
            f"{html.escape(str(alert.get('user')))}@{html.escape(str(alert.get('host')))}</p>"
            f"<table style='border-collapse:collapse;width:100%'>{''.join(rows)}</table>"
            + (f"<p><b>Untrusted content seen in this session:</b> {html.escape(', '.join(alert['taint_sources']))}</p>" if alert.get("taint_sources") else "")
            + f"<p style='color:#777;font-size:12px'>Session {html.escape(str(alert.get('session_id')))} · "
              f"hook {html.escape(str(alert.get('hook_event')))} / {html.escape(str(alert.get('tool') or '-'))}. "
              f"Secret values are redacted. Details: ~/.truviq/logs/events.jsonl</p></div>")
    return subject, body, "\n".join(text_lines)


def send(alert: dict, secrets: dict) -> tuple[bool, str]:
    import urllib.error
    import urllib.request

    subject, body, text = build_email(alert)
    to = [x.strip() for x in secrets.get("TRUVIQ_ALERT_TO", "").split(",") if x.strip()]
    payload = {"from": secrets.get("TRUVIQ_ALERT_FROM") or DEFAULT_FROM, "to": to,
               "subject": subject, "html": body, "text": text}
    req = urllib.request.Request(RESEND_URL, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {secrets['RESEND_API_KEY']}",
                                          "Content-Type": "application/json", "User-Agent": "truviq-guard/0.2"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310 - fixed https endpoint
            return True, r.read().decode("utf-8", "replace")[:300]
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:300]}"
    except OSError as e:
        return False, f"network error: {e}"


def context() -> dict:
    return {"host": socket.gethostname(), "user": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"}
