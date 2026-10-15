---
description: Open the TruViq Guard dashboard (blocks, approvals, fleet health) in your browser
allowed-tools: Bash
---
Start the TruViq Guard dashboard for the user.

1. Run this with the Bash tool **in the background** (it is a long-running local web server):
   `truviq dashboard`
   If `truviq` is not found, use:
   `B="$(ls -d ~/.claude/plugins/cache/truviq/truviq-guard/*/bin | sort -V | tail -n 1)"; sh "$B/run-python.sh" "$B/truviq.py" dashboard`
2. Wait two seconds, then check it answers: `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8787/`
3. Tell the user to open **http://127.0.0.1:8787**. If the port is busy, say so and offer `--port 8788`.

Explain in one line what they will see: their own machine's events, or every machine's if this computer has the Supabase service-role key.
Do not read or print `~/.truviq/guard.env`.
