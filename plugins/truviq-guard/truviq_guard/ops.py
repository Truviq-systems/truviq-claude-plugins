"""R7 operations: install, doctor (self-test), uninstall.

Nothing here runs inside the hook. These are commands a person runs in a terminal.
"""
from __future__ import annotations

import glob
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import time

from . import __version__, config, paths

PLUGIN_ID = "truviq-guard@truviq"
MARKETPLACE = "truviq"
MARKETPLACE_ROOT = os.path.dirname(os.path.dirname(config.PLUGIN_ROOT))
HOOK_MARK = "# truviq-guard pre-commit"


# ------------------------------------------------------------------ helpers

def find_claude() -> str | None:
    """The Claude Code binary: PATH first, then IDE extension folders (newest version)."""
    on_path = shutil.which("claude")
    if on_path:
        return on_path
    found = []
    for base in ("~/.antigravity-ide-server/extensions", "~/.vscode-server/extensions", "~/.vscode/extensions",
                 "~/.cursor-server/extensions", "~/.cursor/extensions"):
        found += glob.glob(os.path.join(os.path.expanduser(base), "anthropic.claude-code-*", "resources", "native-binary", "claude"))
    def ver(p):
        v = os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(p)))).split("-")[2:3]
        return tuple(int(x) for x in (v[0].split(".") if v else []) if x.isdigit())
    return max(found, key=ver) if found else None


def _run(argv: list[str], timeout: int = 120) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=