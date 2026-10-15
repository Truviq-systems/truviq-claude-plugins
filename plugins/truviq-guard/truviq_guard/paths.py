"""Path helpers: home dir, guard dir, and glob matching with `**` support."""
from __future__ import annotations

import os
import re

_GLOB_CACHE: dict[str, re.Pattern] = {}


def home() -> str:
    return os.path.expanduser("~")


def guard_home() -> str:
    return os.environ.get("TRUVIQ_HOME") or os.path.join(home(), ".truviq")


def ensure_private_dir(path: str) -> str:
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def _glob_to_regex(pattern: str) -> re.Pattern:
    if pattern in _GLOB_CACHE:
        return _GLOB_CACHE[pattern]
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    rx = re.compile("^" + "".join(out) + "$")
    _GLOB_CACHE[pattern] = rx
    return rx


def normalize(path: str, cwd: str) -> str:
    """Absolute, normalised path. `~` expanded. Symlinks are NOT resolved here."""
    p = os.path.expanduser(path.strip().strip("'\""))
    if not os.path.isabs(p):
        p = os.path.join(cwd or os.getcwd(), p)
    return os.path.normpath(p)


def candidates(path: str, cwd: str) -> list[str]:
    """The normalised path plus its symlink-resolved form (defeats symlink tricks)."""
    p = normalize(path, cwd)
    out = [p]
    try:
        rp = os.path.realpath(p)
        if rp != p:
            out.append(rp)
    except OSError:
        pass
    return out


def matches_any(path: str, patterns: list[str], cwd: str) -> str | None:
    """Return the first pattern that matches `path`, else None.

    Patterns without a slash match the basename (like .gitignore).
    Patterns starting with `~` are expanded to the home directory.
    Other patterns with a slash match anywhere in the path (`**/` is implied).
    """
    for cand in candidates(path, cwd):
        base = os.path.basename(cand)
        for pat in patterns:
            if pat.startswith("!"):
                continue
            if "/" not in pat:
                if _glob_to_regex(pat).match(base):
                    if not _negated(cand, patterns):
                        return pat
                continue
            full = os.path.expanduser(pat) if pat.startswith("~") else pat
            rx = _glob_to_regex(full if full.startswith("/") else "**/" + full)
            if rx.match(cand) and not _negated(cand, patterns):
                return pat
    return None


def _fixed_prefix(pattern: str) -> str:
    """The part of a glob before its first wildcard, without a trailing slash: '.git/hooks/**' -> '.git/hooks'."""
    cut = min([i for i, c in enumerate(pattern) if c in "*?["] or [len(pattern)])
    return pattern[:cut].rstrip("/")


def protects_ancestor(path: str, patterns: list[str], cwd: str) -> str | None:
    """True if `path` IS, or CONTAINS, a protected location (so moving/replacing it would bypass the guard).

    `mv ~/.truviq x` or `cp -r evil/. .git/hooks` hit even though the glob `~/.truviq/**`
    only matches files inside the directory. Home and `/` themselves are not counted.
    """
    home_dir = home()
    for cand in candidates(path, cwd):
        if cand in ("/", home_dir):
            continue
        for pat in patterns:
            if pat.startswith("!"):
                continue
            prefix = _fixed_prefix(pat)
            if not prefix:
                continue
            if prefix.startswith("~") or prefix.startswith("/"):
                p = os.path.normpath(os.path.expanduser(prefix))
                if cand == p or is_under(p, cand):
                    return pat
            else:
                parts = prefix.split("/")
                # cand ends with a leading run of the pattern's parts: '/repo/.git' for '.git/hooks'
                for n in range(1, len(parts) + 1):
                    if cand.endswith("/" + "/".join(parts[:n])):
                        return pat
    return None


def _negated(path: str, patterns: list[str]) -> bool:
    base = os.path.basename(path)
    for pat in patterns:
        if pat.startswith("!") and _glob_to_regex(pat[1:]).match(base):
            return True
    return False


def is_under(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == os.path.abspath(root)
    except ValueError:
        return False
