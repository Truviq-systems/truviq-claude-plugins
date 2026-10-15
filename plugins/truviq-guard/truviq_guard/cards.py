"""The DENY / ASK / APPROVE card shown in the Claude Code chat (systemMessage) and stored for the dashboard."""
from __future__ import annotations

import textwrap

from .catalog import severity_rank
from .secret_scan import redact

VERDICT = {"deny": "DENY", "ask": "ASK", "warn": "APPROVE", "log": "APPROVE", "allow": "APPROVE"}
ICON = {"DENY": "⛔", "ASK": "❓", "APPROVE": "✅"}
HINT = {
    "DENY": "Blocked. Claude was told why and must not retry it another way.",
    "ASK": "Your call: choose Yes to accept this change, No to reject it. Your answer is recorded on the dashboard.",
    "APPROVE": "Allowed, with the notes above. Claude was told about them.",
}
WIDTH = 74


def verdict_of(decision: str) -> str:
    return VERDICT.get(decision, "APPROVE")


def render(decision: str, tool: str, target: str, findings: list[dict], dep_lines: list[str] | None = None,
           enforced: bool = True) -> str:
    v = verdict_of(decision)
    head = f"{ICON[v]} TruViq Guard · {v}" + ("" if enforced else " (monitor mode: not enforced)")
    meta = f"{tool} · {target}" if target else tool
    shown = sorted([f for f in findings if severity_rank(f["severity"]) >= severity_rank("MEDIUM")],
                   key=lambda f: -severity_rank(f["severity"]))[:5]
    lines = [f"┌─ {head} " + "─" * max(2, WIDTH - len(head) - 4), f"│ {meta}"[:WIDTH + 2]]
    for f in shown:
        lines.append(f"│ {f['severity']:<8} {f['detector']:<10} {f.get('title', '')}")
        wrapped = textwrap.wrap(redact(f["summary"]), WIDTH - 10) or [""]
        lines += [f"│          {w}" for w in wrapped[:3]]
        if len(wrapped) > 3:
            lines[-1] = lines[-1][:-1] + "…"
        ev = str(f.get("evidence") or "").strip()
        if ev and f["detector"] not in ("G-CODE-001", "G-SEC-002", "G-DEP-003"):
            lines.append(f"│          ▸ {redact(ev)[:WIDTH - 12]}")
    if dep_lines:
        lines.append("│ Dependencies changed:")
        lines += [f"│   {d[:WIDTH - 4]}" for d in dep_lines[:8]]
        if len(dep_lines) > 8:
            lines.append(f"│   … and {len(dep_lines) - 8} more")
    tags = []
    for f in shown:
        c = f.get("compliance", {})
        tags += [f"OWASP {x}" for x in c.get("owasp_llm", [])] + c.get("cwe", [])
    if tags:
        lines.append("│ " + " · ".join(dict.fromkeys(tags))[:WIDTH])
    lines.append(f"│ {HINT[v]}")
    lines.append("└" + "─" * (WIDTH + 1))
    return "\n".join(lines)


def compact(decision: str, target: str, findings: list[dict], dep_lines: list[str] | None = None) -> str:
    """Single-paragraph version for the native approval prompt (permissionDecisionReason)."""
    v = verdict_of(decision)
    top = sorted(findings, key=lambda f: -severity_rank(f["severity"]))[:3]
    parts = [f"TruViq Guard {v}: {target}" if target else f"TruViq Guard {v}"]
    parts += [f"{f['severity']} {f['detector']} {redact(f['summary'])}" for f in top]
    if dep_lines:
        parts.append("Dependencies: " + ", ".join(dep_lines[:6]))
    return " | ".join(parts)
