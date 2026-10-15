#!/bin/sh
# Run a TruViq Guard Python script with the first working Python 3.8+.
# Usage: sh run-python.sh <script.py> [args...]   (standard input is passed through untouched)
#
# Windows often has no `python3`, or only the Microsoft Store placeholder that opens the Store
# instead of running Python, so this tries python3, then python, then the py launcher.
for name in python3 python py; do
  exe=$(command -v "$name" 2>/dev/null) || continue
  flag=""
  [ "$name" = py ] && flag="-3"
  if [ "$name" = python3 ]; then
    case "$exe" in
      *WindowsApps*) ;;            # may be the Store placeholder: check it below
      *) exec "$exe" "$@" ;;       # Linux, macOS, WSL: the fast path, no extra process
    esac
  fi
  if "$exe" $flag -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' </dev/null >/dev/null 2>&1; then
    exec "$exe" $flag "$@"
  fi
done
echo "TruViq Guard: no working Python 3.8+ found (tried python3, python, py). Install Python from python.org, then restart Claude Code." >&2
exit 1
