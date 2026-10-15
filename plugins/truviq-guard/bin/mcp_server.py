#!/usr/bin/env python3
"""TruViq MCP server (stdio, JSON-RPC 2.0, newline-delimited). Tools: guard_fetch, guard_scan."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from truviq_guard import injection, secret_scan, web  # noqa: E402

PROTOCOL = "2025-06-18"
TOOLS = [
    {"name": "guard_fetch",
     "description": "Fetch a web page safely. Hidden HTML, comments, scripts and invisible characters are removed and the "
                    "result is marked as untrusted data. Use this instead of WebFetch.",
     "inputSchema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "http(s) URL to fetch"},
         "max_chars": {"type": "integer", "description": "Maximum characters to return (default 20000)"}},
         "required": ["url"]}},
    {"name": "guard_scan",
     "description": "Scan a local file for hidden text, instructions aimed at AI agents, and hardcoded secrets. "
                    "Returns findings only (never the secret values).",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
]


def _scan_file(path: str) -> str:
    p = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(p):
        return f"Not a file: {p}"
    with open(p, "rb") as f:
        text = f.read(2_000_000).decode("utf-8", "replace")
    r = injection.scan(text)
    lines = [f"Scan of {p}:"]
    lines += [f"- HIDDEN TEXT ({o['severity']}) line {o['line']}: {secret_scan.redact(o['summary'])}" for o in r["obf"]]
    lines += [f"- AI-DIRECTED INSTRUCTION ({i['severity']}) line {i['line']}: {i['summary']}" for i in r["inj"]]
    lines += [f"- POSSIBLE AI-DIRECTED TEXT (unclear): {secret_scan.redact(w)[:160]}" for w in r["weak"]]
    lines += [f"- SECRET ({s['type']}) line {s['line']}" for s in secret_scan.find(text)]
    return "\n".join(lines) if len(lines) > 1 else f"{p}: no findings."


def _call(name: str, args: dict) -> dict:
    try:
        if name == "guard_fetch":
            text = web.fetch(str(args.get("url", "")), int(args.get("max_chars") or 20000))
        elif name == "guard_scan":
            text = _scan_file(str(args.get("path", "")))
        else:
            return {"content": [{"type": "text", "text": f"Unknown tool {name}"}], "isError": True}
        return {"content": [{"type": "text", "text": text}], "isError": False}
    except Exception as e:  # noqa: BLE001 - report every failure to the client as a tool error
        return {"content": [{"type": "text", "text": f"{name} failed: {type(e).__name__}: {e}"}], "isError": True}


def handle(msg: dict):
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:
        return None  # notification
    if method == "initialize":
        ver = (msg.get("params") or {}).get("protocolVersion") or PROTOCOL
        result = {"protocolVersion": ver, "capabilities": {"tools": {}},
                  "serverInfo": {"name": "truviq-guard", "version": "0.2.0"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        p = msg.get("params") or {}
        result = _call(p.get("name", ""), p.get("arguments") or {})
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        else:
            resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
