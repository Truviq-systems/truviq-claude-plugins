---
description: Check that TruViq Guard is installed, enabled and blocking correctly
allowed-tools: Bash
---
Run the TruViq Guard self-test and explain the result.

1. Run: `truviq doctor`
   If `truviq` is not found, use:
   `B="$(ls -d ~/.claude/plugins/cache/truviq/truviq-guard/*/bin | sort -V | tail -n 1)"; sh "$B/run-python.sh" "$B/truviq.py" doctor`
2. Summarise for the user: what passed, and for each ✗ or ! the one-line fix that doctor printed.
3. If the fix is to install, uninstall, enroll or change settings, tell the user to run that command **themselves in a terminal**.
   The guard blocks the agent from changing the guard.

Do not read or print `~/.truviq/guard.env`.
