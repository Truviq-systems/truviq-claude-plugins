"""Secret detection and redaction (G-CODE-001, and redaction for logs/emails)."""
from __future__ import annotations

import math
import os
import re

# (name, regex). Keep regexes linear: no nested quantifiers.
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws_?secret_?access_?key\s*[=:]\s*['\"]?[A-Za-z0-9/+]{40}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("stripe_live_key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("groq_api_key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}")),
    ("resend_api_key", re.compile(r"\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("db_url_password", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/@]+:([^@\s]{4,})@")),
    ("generic_secret_assignment", re.compile(
        r"(?i)\b[A-Z0-9_]*(?:password|passwd|secret|api_?key|access_?token|auth_?token|private_?key)[A-Z0-9_]*"
        r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]")),
]

PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|\*+|\.+|changeme|change_me|password|secret|example\w*|dummy\w*|test\w*|sample\w*|placeholder\w*"
    r"|your[_-]?\w*|<[^>]*>|\$\{[^}]*\}|\$[A-Z_]+|\{\{[^}]*\}\}|none|null|redacted\w*|fake\w*|todo)$")

# Files where writing a real secret is expected (they are git-ignored by convention).
SECRET_FILE_OK = re.compile(r"(?:^|/)\.env(?:\.(?!example$|sample$|template$)[\w.-]+)?$")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def find(text: str) -> list[dict]:
    """Return [{type, line, match}] for each secret-looking value in text."""
    hits = []
    for name, rx in PATTERNS:
        for m in rx.finditer(text):
            value = m.group(1) if m.groups() and m.group(1) else m.group(0)
            if name in ("generic_secret_assignment", "db_url_password"):
                if PLACEHOLDER.match(value) or _entropy(value) < 3.0:
                    continue
            if name == "jwt" and "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIi" in m.group(0):
                continue  # the jwt.io sample token
            line = text.count("\n", 0, m.start()) + 1
            hits.append({"type": name, "line": line, "match": m.group(0)})
    return hits


def write_allowed(file_path: str) -> bool:
    return bool(SECRET_FILE_OK.search(file_path.replace(os.sep, "/")))


def redact(text: str) -> str:
    if not text:
        return text
    for name, rx in PATTERNS:
        text = rx.sub(f"«REDACTED:{name}»", text)
    return text
