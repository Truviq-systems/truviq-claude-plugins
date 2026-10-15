"""Generated-code review (R4): insecure patterns, insecure infrastructure/CI, weakened tests.

Only the lines the agent ADDS are checked, so existing code is not re-flagged on every edit.
Rules are regexes per language with a CWE and a one-line fix. Linear, bounded patterns only.
"""
from __future__ import annotations

import difflib
import os
import re

PY = {".py", ".pyw"}
JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
GO = {".go"}
JAVA = {".java", ".kt"}
ANY = None
CODE_EXTS = PY | JS | GO | JAVA | {".rb", ".php", ".cs", ".rs", ".c", ".cc", ".cpp", ".h", ".sh", ".bash", ".scala", ".swift"}


# (detector, severity, extensions or ANY, regex, what, cwe)
RULES = [
    # --- injection-prone code (G-CODE-002)
    ("G-CODE-002", "HIGH", PY, r"\b(?:eval|exec)\s*\((?!\s*['\"])", "eval/exec on dynamic input", "CWE-95"),
    ("G-CODE-002", "HIGH", PY, r"\bsubprocess\.\w+\([^)\n]{0,300}shell\s*=\s*True", "subprocess with shell=True", "CWE-78"),
    ("G-CODE-002", "HIGH", PY, r"\bos\.(?:system|popen)\(\s*(?:f['\"]|[^'\")\n]{0,200}[+%]|[A-Za-z_][\w.]*\s*\))", "os.system/popen with built string", "CWE-78"),
    ("G-CODE-002", "HIGH", PY, r"\.(?:execute|executemany|raw|executescript)\(\s*(?:f['\"]|['\"][^'\"\n]{0,300}['\"]\s*(?:%|\.format\(|\+))",
     "SQL built from string formatting", "CWE-89"),
    ("G-CODE-002", "HIGH", PY, r"\b(?:pickle|cPickle|dill|shelve)\.loads?\(", "unsafe deserialisation (pickle)", "CWE-502"),
    ("G-CODE-002", "HIGH", PY, r"\byaml\.load\((?![^)\n]{0,200}Loader\s*=\s*(?:yaml\.)?C?SafeLoader)", "yaml.load without SafeLoader", "CWE-502"),
    ("G-CODE-002", "HIGH", PY, r"\bverify\s*=\s*False\b|\bssl\._create_unverified_context\b|\bCERT_NONE\b", "TLS certificate verification disabled", "CWE-295"),
    ("G-CODE-002", "HIGH", PY, r"verify_signature['\"]?\s*:\s*False", "JWT signature verification disabled", "CWE-347"),
    ("G-CODE-002", "HIGH", JS, r"\beval\s*\(|\bnew\s+Function\s*\(", "eval / new Function", "CWE-95"),
    ("G-CODE-002", "HIGH", JS, r"\b(?:exec|execSync)\s*\(\s*(?:`[^`\n]{0,300}\$\{|[^'\"`)\n]{1,200}\+)", "child_process exec with built string", "CWE-78"),
    ("G-CODE-002", "HIGH", JS, r"\.(?:query|execute|raw|\$queryRawUnsafe)\(\s*(?:`[^`\n]{0,300}\$\{|['\"][^'\"\n]{0,300}['\"]\s*\+)", "SQL built from string interpolation", "CWE-89"),
    ("G-CODE-002", "HIGH", JS, r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*\]?\s*=\s*['\"]?0", "TLS certificate verification disabled", "CWE-295"),
    ("G-CODE-002", "HIGH", GO, r"InsecureSkipVerify\s*:\s*true", "TLS certificate verification disabled", "CWE-295"),
    ("G-CODE-002", "HIGH", GO, r"\.(?:Query|QueryRow|Exec|QueryContext|ExecContext)\(\s*(?:ctx\s*,\s*)?fmt\.Sprintf\(", "SQL built with fmt.Sprintf", "CWE-89"),
    ("G-CODE-002", "HIGH", GO, r"exec\.Command\(\s*\"(?:sh|bash)\"\s*,\s*\"-c\"", "shell command with sh -c", "CWE-78"),
    ("G-CODE-002", "HIGH", JAVA, r"\.(?:executeQuery|executeUpdate|execute)\(\s*\"[^\"\n]{0,300}\"\s*\+", "SQL built by string concatenation", "CWE-89"),
    ("G-CODE-002", "HIGH", JAVA, r"Runtime\.getRuntime\(\)\.exec\(", "Runtime.exec", "CWE-78"),
    # --- weak practices (G-CODE-003)
    ("G-CODE-003", "MEDIUM", PY, r"\bhashlib\.(?:md5|sha1)\(", "MD5/SHA-1 hashing", "CWE-327"),
    ("G-CODE-003", "MEDIUM", PY, r"(?i)(?:token|secret|password|otp|salt|nonce)\w*\s*=\s*[^\n]{0,120}\brandom\.(?:random|randint|choice|choices|randrange|getrandbits)\(",
     "random module used for a secret value", "CWE-338"),
    ("G-CODE-003", "MEDIUM", PY, r"\.run\([^)\n]{0,200}debug\s*=\s*True|\bDEBUG\s*=\s*True\b", "debug mode enabled", "CWE-489"),
    ("G-CODE-003", "MEDIUM", PY, r"\btempfile\.mktemp\(", "insecure temp file (mktemp)", "CWE-377"),
    ("G-CODE-003", "MEDIUM", JS, r"\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\(", "raw HTML injection point (XSS)", "CWE-79"),
    ("G-CODE-003", "MEDIUM", JS, r"createHash\(\s*['\"](?:md5|sha1)['\"]", "MD5/SHA-1 hashing", "CWE-327"),
    ("G-CODE-003", "MEDIUM", JS, r"(?i)(?:token|secret|password|otp|nonce)\w*\s*=\s*[^\n]{0,120}Math\.random\(", "Math.random used for a secret value", "CWE-338"),
    ("G-CODE-003", "MEDIUM", ANY, r"(?i)Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]|origin\s*:\s*['\"]\*['\"]", "CORS allows any origin", "CWE-942"),
]

IAC_RULES = [
    # (filename regex, severity, regex, what, cwe)
    (r"\.tf$", "HIGH", r"cidr_blocks\s*=\s*\[[^\]\n]{0,200}\"0\.0\.0\.0/0\"|ipv6_cidr_blocks\s*=\s*\[[^\]\n]{0,200}\"::/0\"", "open to the whole internet (0.0.0.0/0)", "CWE-284"),
    (r"\.tf$", "HIGH", r"acl\s*=\s*\"public-read(?:-write)?\"|block_public_acls\s*=\s*false|publicly_accessible\s*=\s*true", "publicly accessible storage/database", "CWE-732"),
    (r"\.tf$", "MEDIUM", r"(?:encrypted|storage_encrypted|enable_encryption)\s*=\s*false", "encryption disabled", "CWE-311"),
    (r"\.ya?ml$", "HIGH", r"privileged:\s*true|hostNetwork:\s*true|hostPID:\s*true|hostIPC:\s*true", "privileged / host-namespace container", "CWE-250"),
    (r"\.ya?ml$", "MEDIUM", r"allowPrivilegeEscalation:\s*true|runAsUser:\s*0\b|runAsNonRoot:\s*false", "container may run as / escalate to root", "CWE-250"),
    (r"(?:^|/)Dockerfile[^/]*$|\.dockerfile$", "HIGH", r"(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:ba)?sh\b", "pipes a download into a shell in the image", "CWE-494"),
    (r"(?:^|/)Dockerfile[^/]*$|\.dockerfile$", "MEDIUM", r"^\s*USER\s+root\s*$|^\s*ADD\s+https?://", "runs as root / ADD from URL", "CWE-250"),
    (r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", "HIGH",
     r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|head_commit|discussion)\.[\w.]*(?:title|body|message|name|ref|label)\w*\s*\}\}",
     "untrusted event text interpolated into a workflow (script injection)", "CWE-78"),
    (r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", "MEDIUM", r"pull_request_target|permissions:\s*write-all", "privileged workflow trigger/permissions", "CWE-284"),
]

TEST_FILE = re.compile(r"(?:^|/)(?:tests?/|__tests__/)|(?:^|/)test_[^/]+\.py$|_test\.(?:py|go)$|\.(?:test|spec)\.[jt]sx?$")
SKIP_RX = re.compile(r"@pytest\.mark\.(?:skip|xfail)\b|@unittest\.skip|\bpytest\.skip\(|\b(?:it|test|describe)\.skip\(|\bx(?:it|describe|test)\(|\bt\.Skip\(")
ASSERT_RX = re.compile(r"\bassert\b|\bexpect\s*\(|\bself\.assert\w+\(|\bassert\w*\(|\bt\.(?:Error|Fatal|Fail)")
SILENCE_RX = re.compile(r"#\s*nosec\b|\bNOSONAR\b|//\s*eslint-disable(?:-next-line)?\s+[^\n]*security|#\s*noqa:\s*S\d")
THRESHOLD_RX = re.compile(r"(?:fail_under|fail-under|--cov-fail-under|coverageThreshold|minimum_coverage|branches|lines|statements|functions)\D{0,20}(\d{1,3}(?:\.\d+)?)")


def added_lines(before: str | None, after: str) -> list[tuple[int, str]]:
    """(line_no_in_after, text) for lines added by the change."""
    if not before:
        return [(i + 1, l) for i, l in enumerate(after.splitlines())]
    a, b = before.splitlines(), after.splitlines()
    out = []
    for tag, _i1, _i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag in ("insert", "replace"):
            out += [(j + 1, b[j]) for j in range(j1, j2)]
    return out


def _ext(path: str) -> str:
    return os.path.splitext(path)[1].lower()


def check(path: str, before: str | None, after: str) -> list[dict]:
    """Findings for the change before→after of `path` (path relative or absolute)."""
    p = path.replace(os.sep, "/")
    ext = _ext(p)
    lines = added_lines(before, after)[:5000]
    findings: list[dict] = []
    seen = set()

    def add(det, sev, what, cwe, ln, text):
        key = (det, what)
        if key in seen:
            return
        seen.add(key)
        findings.append({"detector": det, "severity": sev, "file": path, "line": ln,
                         "summary": f"{what} ({cwe}) at line {ln}", "evidence": text.strip()[:200]})

    for det, sev, exts, rx, what, cwe in RULES:
        if exts is not ANY and ext not in exts:
            continue
        crx = re.compile(rx)
        for ln, text in lines:
            if len(text) < 2000 and crx.search(text):
                add(det, sev, what, cwe, ln, text)
                break
    for frx, sev, rx, what, cwe in IAC_RULES:
        if not re.search(frx, p):
            continue
        crx = re.compile(rx, re.M)
        for ln, text in lines:
            if len(text) < 2000 and crx.search(text):
                add("G-IAC-001", sev, what, cwe, ln, text)
                break

    # --- weakened tests and checks (G-VER-001)
    if TEST_FILE.search(p):
        for ln, text in lines:
            if SKIP_RX.search(text):
                add("G-VER-001", "HIGH", "test skipped or marked expected-to-fail", "CWE-1164", ln, text)
                break
        if before:
            removed = len(ASSERT_RX.findall(before)) - len(ASSERT_RX.findall(after))
            if removed > 0 and len(after) <= len(before) * 1.2:
                add("G-VER-001", "HIGH", f"removes {removed} assertion(s) from a test file", "CWE-1164", 0, f"{removed} fewer assertions")
    for ln, text in lines if ext in CODE_EXTS else []:  # docs that merely mention "# nosec" are fine
        if SILENCE_RX.search(text):
            add("G-VER-001", "MEDIUM", "silences a security check (nosec / security lint disabled)", "CWE-1164", ln, text)
            break
    if before and re.search(r"(?:setup\.cfg|pyproject\.toml|\.coveragerc|jest\.config\.[jt]s|package\.json|tox\.ini|pytest\.ini|codecov\.ya?ml)$", p):
        old = [float(x) for x in THRESHOLD_RX.findall(before)]
        new = [float(x) for x in THRESHOLD_RX.findall(after)]
        if old and new and min(new) < min(old):
            add("G-VER-001", "HIGH", f"lowers a coverage/quality threshold ({min(old):g} → {min(new):g})", "CWE-1164", 0, "threshold lowered")
    return findings


def apply_edit(before: str, old: str, new: str, replace_all: bool = False) -> str:
    if not old:
        return before + new
    return before.replace(old, new) if replace_all else before.replace(old, new, 1)
