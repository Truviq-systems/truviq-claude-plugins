"""Bash command analysis: G-CMD-001/002, G-EXF-001/002, G-SEC-001, G-PRIV-001/002.

Regex + shlex only (no bash parser dependency). Patterns are checked against the
raw command too, so `bash -c "rm -rf ~"` and `$(...)` payloads are still seen.
"""
from __future__ import annotations

import glob
import os
import re
import shlex
import sys

from . import paths

SEPARATORS = {"|", "||", "&&", ";", "&", "|&", ";;", "(", ")"}
PREFIX_WORDS = {"sudo", "command", "nohup", "time", "exec", "builtin", "nice", "doas"}
DEV_NET = re.compile(r"/dev/(?:tcp|udp)/([^/\s'\"]+)/")
MAX_COMMAND = 16_000
EGRESS_CMDS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "scp", "sftp", "rsync", "ssh", "ftp",
               "telnet", "nslookup", "dig", "host", "http", "https", "xh", "iwr", "invoke-webrequest",
               "invoke-restmethod"}
ENV_DUMP = re.compile(r"(?:^|[\s;&|(`])(?:printenv|env|export\s+-p|declare\s+-x|set)(?=\s*(?:$|[|;&>)`]))")
UPLOAD_FLAG = re.compile(r"(?:^|\s)(?:-d|--data(?:-\w+)?|-F|--form|-T|--upload-file|--post-data|--post-file|-X\s*(?:POST|PUT|PATCH))(?=\s|=|$)|@-")
URL_HOST = re.compile(r"\bhttps?://(?:[^/\s'\"@]*@)?([A-Za-z0-9.\-]+|\[[0-9a-fA-F:]+\])", re.I)
SECRET_ENV_REF = re.compile(r"\$\{?[A-Za-z_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z_]*\}?", re.I)
SUBST = re.compile(r"\$\(|`")

SHELLS = r"(?:\S*/)?(?:ba|z|da|k|fi)?sh\b"
INTERPRETERS = r"(?:\S*/)?(?:python[0-9.]*|node|perl|ruby|php)\b"
DOWNLOAD_EXEC = [
    re.compile(r"\b(?:curl|wget|fetch)\b[^;&\n]{0,512}?\|\s*(?:sudo\s+)?(?:env\s+\S+\s+)?" + SHELLS, re.I),
    re.compile(r"\b(?:curl|wget)\b[^;&\n]{0,512}?\|\s*(?:sudo\s+)?" + INTERPRETERS, re.I),
    re.compile(r"(?:^|[\s;&|(])(?:" + SHELLS + r"|eval|source|\.)\s+(?:-c\s+)?[\"']?\s*(?:<\(|\$\()\s*(?:curl|wget)\b", re.I),
    re.compile(INTERPRETERS + r"\s+(?:-\s+)?<\(\s*(?:curl|wget)\b", re.I),
    re.compile(r"\b(?:iex|invoke-expression)\b.{0,512}?\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b", re.I),
    re.compile(r"\bbase64\s+(?:-d|--decode|-D)\b[^;&\n]{0,512}?\|\s*(?:sudo\s+)?" + SHELLS, re.I),
]

DESTRUCTIVE = [
    (re.compile(r"\bgit\s+push\b[^;&|\n]{0,512}(?:\s--force(?:-with-lease)?\b|\s-f\b|\s\+[\w/.-]+)"), "HIGH", "force-push rewrites remote history"),
    (re.compile(r"\bgit\s+push\b[^;&|\n]{0,512}\s(?:HEAD:)?(?:main|master)(?=$|\s|;|&|\|)"), "HIGH", "push directly to main/master"),
    (re.compile(r"\bgit\s+reset\s+--hard\b"), "MEDIUM", "git reset --hard discards local changes"),
    (re.compile(r"\bgit\s+clean\s+-[a-zA-Z]*f"), "MEDIUM", "git clean deletes untracked files"),
    (re.compile(r"\bterraform\s+(?:destroy\b|apply\b[^;&|\n]{0,512}\s-destroy\b)"), "HIGH", "terraform destroy"),
    (re.compile(r"\bkubectl\s+delete\s+(?:ns|namespaces?|pv|pvc|deployments?|deploy|statefulsets?|sts|all)\b|\bkubectl\s+delete\b[^;&|\n]{0,512}\s--all\b"), "HIGH", "kubectl delete of cluster resources"),
    (re.compile(r"\bhelm\s+(?:uninstall|delete)\b"), "HIGH", "helm uninstall"),
    (re.compile(r"\b(?:drop\s+(?:database|schema|table)|truncate\s+table)\b", re.I), "HIGH", "SQL DROP/TRUNCATE"),
    (re.compile(r"\bdropdb\b"), "HIGH", "dropdb"),
    (re.compile(r"\bmkfs(?:\.\w+)?\b"), "CRITICAL", "mkfs formats a disk"),
    (re.compile(r"\bdd\b[^;&|\n]{0,512}\bof=/dev/(?:sd|nvme|hd|xvd|disk|mmcblk)"), "CRITICAL", "dd onto a disk device"),
    (re.compile(r">\s*/dev/(?:sd|nvme|hd|xvd|disk)"), "CRITICAL", "write onto a disk device"),
    (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "CRITICAL", "fork bomb"),
    (re.compile(r"\bchmod\s+(?:-R|--recursive)\s+0?777\b"), "HIGH", "recursive chmod 777"),
    (re.compile(r"\bfind\s+(?:/|~|\$HOME)(?:\s|$)[^;&|\n]{0,512}(?:-delete\b|-exec\s+rm\b)"), "CRITICAL", "find -delete from / or home"),
    (re.compile(r"\bdocker\s+(?:system\s+prune\b[^;&|\n]{0,512}\s-a|volume\s+(?:rm|prune)\b)"), "MEDIUM", "docker prune/volume removal"),
    (re.compile(r"\bcrontab\s+-r\b"), "HIGH", "crontab -r removes all cron jobs"),
]
POWER_CMDS = {"shutdown", "reboot", "halt", "poweroff"}
DEPLOY_RX = re.compile(
    r"\b(?:kubectl\s+(?:apply|rollout\s+restart|set\s+image|scale|replace|patch)|helm\s+(?:upgrade|install)|terraform\s+apply|"
    r"pulumi\s+up|(?:serverless|sls)\s+deploy|vercel\b[^;&|\n]{0,200}--prod|netlify\s+deploy\b[^;&|\n]{0,200}--prod|"
    r"fly(?:ctl)?\s+deploy|gcloud\s+(?:app|run|functions)\s+deploy|aws\s+(?:cloudformation\s+deploy|ecs\s+update-service|"
    r"lambda\s+update-function-code)|eb\s+deploy|cdk\s+deploy|firebase\s+deploy|git\s+push\s+heroku|docker\s+push)\b")
PROD_WORD = re.compile(r"(?i)(?:^|[\s=:/_.-])(?:prod|production|prd|live)(?:$|[\s=:/_.-])")

TAMPER = [
    (re.compile(r"(?:^|\s)--no-verify\b"), "skips git hooks (--no-verify)"),
    (re.compile(r"\bgit\s+commit\b[^;&|\n]{0,512}\s-[a-zA-Z]*n\b"), "skips git hooks (git commit -n)"),
    (re.compile(r"\bcore\.hooksPath\b"), "changes git hooksPath"),
    (re.compile(r"\bgit\b[^;&|\n]{0,512}(?:\bconfig\b|\s-c\s)[^;&|\n]{0,512}\b(?:core\.fsmonitor|core\.sshCommand|core\.pager|core\.editor|"
                r"core\.askPass|credential\.helper|alias\.|include\.path|includeIf\.|filter\.\w+\.(?:clean|smudge|process)|diff\.\w+\.textconv)", re.I),
     "sets a git config key that runs programs"),
    (re.compile(r"\b(?:pkill|killall|kill)\b[^;&|\n]{0,512}(?:truviq|guard_hook)", re.I), "kills the guard"),
    (re.compile(r"\bclaude\s+plugins?\s+(?:disable|uninstall|remove|rm)\b[^;&|\n]{0,512}truviq", re.I), "disables the TruViq plugin"),
    # Real assignments only (command prefix, export/env), not the text "TRUVIQ_X=" inside a heredoc or string.
    (re.compile(r"(?:^|[;&|(`]\s*|\b(?:export|env|declare\s+-x|typeset\s+-x|setenv)\s+)(?:[A-Za-z_]\w*=\S*\s+)*TRUVIQ_[A-Z_]+="),
     "changes guard environment variables"),
]
WRITE_CMDS = {"rm", "mv", "cp", "tee", "truncate", "chmod", "chown", "ln", "install", "dd", "unlink", "shred"}
SYSTEM_DIRS = {"/etc", "/usr", "/var", "/bin", "/sbin", "/boot", "/lib", "/lib64", "/opt", "/root", "/srv",
               "/sys", "/proc", "/home", "/dev", "/mnt", "/media"}
TMP_DIRS = ("/tmp", "/var/tmp")


def _tokens(command: str) -> list[str]:
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        return command.split()


def _segments(tokens: list[str]) -> list[list[str]]:
    segs, cur = [], []
    for t in tokens:
        if t in SEPARATORS or (t and set(t) <= set("|&;()")):
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def _command_word(seg: list[str]) -> tuple[str, list[str], bool]:
    i, used_sudo = 0, False
    while i < len(seg) and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[i]) or seg[i] in PREFIX_WORDS):
        if seg[i] in ("sudo", "doas"):
            used_sudo = True
        i += 1
    if i >= len(seg):
        return "", [], used_sudo
    return os.path.basename(seg[i]).lower(), seg[i + 1:], used_sudo


def host_allowed(host: str, allow: list[str]) -> bool:
    host = host.lower().strip("[]")
    return any(host == h or host.endswith("." + h) for h in allow)


def _expand(tok: str, cwd: str) -> list[str]:
    """A token plus what it expands to if it contains shell glob characters (cat .en? -> .env)."""
    if not any(c in tok for c in "*?["):
        return [tok]
    pat = os.path.expanduser(tok)
    if not os.path.isabs(pat):
        pat = os.path.join(cwd, pat)
    kw = {"include_hidden": True} if sys.version_info >= (3, 11) else {}
    try:
        return [tok] + glob.glob(pat, **kw)[:50]
    except (OSError, ValueError, re.error):
        return [tok]


def _rm_findings(command: str, cwd: str) -> list[dict]:
    out = []
    home = paths.home()
    for m in re.finditer(r"(?:^|[\s;&|(`'\"])rm\s+([^;&|)`'\"]*)", command):
        args = _tokens(m.group(1))
        flags = [a for a in args if a.startswith("-")]
        recursive = any(f == "--recursive" or (not f.startswith("--") and ("r" in f or "R" in f)) for f in flags)
        if not recursive:
            continue
        for t in (a for a in args if not a.startswith("-")):
            sev, why = _classify_rm_target(t, cwd, home)
            if sev:
                out.append({"detector": "G-CMD-001", "severity": sev,
                            "summary": f"recursive delete of {t} ({why})", "evidence": m.group(0).strip()})
    return out


def _classify_rm_target(t: str, cwd: str, home: str) -> tuple[str | None, str]:
    raw = t.replace("${HOME}", "~").replace("$HOME", "~")
    if raw in ("/*", "~/*", "/", "~", "~/"):
        return "CRITICAL", "root or home directory"
    if "$" in raw:
        return "MEDIUM", "target depends on a variable"
    p = paths.normalize(raw, cwd)
    if p in ("/", home) or p in SYSTEM_DIRS:
        return "CRITICAL", "root, home or system directory"
    if raw in (".", "./", "*", "..", "../", "./*") or p == os.path.abspath(cwd) or paths.is_under(cwd, p):
        return "HIGH", "the whole project or a parent of it"
    if os.path.basename(p) == ".git":
        return "HIGH", "git history"
    if paths.is_under(p, cwd) or any(paths.is_under(p, d) for d in TMP_DIRS):
        return None, ""
    return "HIGH", "outside the project directory"


# Commands of the guard's own CLI that change or remove the guard. A person runs these in a terminal; the agent must not.
GUARD_ADMIN_SUBCOMMANDS = {"uninstall", "install", "enroll", "setup", "policy-sync", "policy-publish", "heartbeat", "watchdog",
                           "install-git-hook", "send-alert"}
RUNNERS = ("bash", "sh", "zsh", "dash", "env", "exec", "nohup", "time", "sudo", "node")
READ_ONLY_CMDS = {"cat", "ls", "head", "tail", "grep", "egrep", "fgrep", "rg", "wc", "stat", "file", "less", "more", "diff", "cmp", "echo",
                  "printf", "pwd", "cd", "pushd", "popd", "test", "[", "realpath", "readlink", "du", "sort", "uniq", "cut", "tr", "jq",
                  "find", "tree", "sha256sum", "md5sum", "date", "true", ":"}


def _mentions_guard_state(tok: str, guard_home: str) -> bool:
    return ".truviq" in tok or "org_policy" in tok or (guard_home and guard_home in tok)


def _is_python(cmd: str) -> bool:
    """python, python3.12, python.exe, and the Windows `py` launcher."""
    return cmd.startswith("python") or cmd in ("py", "py.exe")


def _guard_state_tamper(segs: list[list[str]], guard_home: str) -> list[dict]:
    """The agent may READ the guard's folder (logs, status) but may not write it, `cd` into it and write, or run its admin commands."""
    out: list[dict] = []
    cd_into = False
    for seg in segs:
        cmd, args, _sudo = _command_word(seg)
        # 1. guard admin commands: `python3 .../truviq.py uninstall`
        if cmd == "truviq":  # the launcher installed on PATH by `truviq.py install`
            plain = [a for a in args if not a.startswith("-")]
            if plain and plain[0] in GUARD_ADMIN_SUBCOMMANDS:
                out.append({"detector": "G-PRIV-001", "severity": "CRITICAL",
                            "summary": f"runs the guard's own admin command ({plain[0]}); run it yourself in a terminal", "evidence": " ".join(seg)[:200]})
        if _is_python(cmd) or cmd in RUNNERS or cmd.endswith(("truviq.py", "run-python.sh")):
            rest = ([cmd] if cmd.endswith("truviq.py") else []) + [a for a in args]
            plain = [a for a in rest if not a.startswith("-")]
            for i, a in enumerate(plain):
                if a.endswith("truviq.py"):
                    sub = plain[i + 1] if i + 1 < len(plain) else ""
                    if sub in GUARD_ADMIN_SUBCOMMANDS:
                        out.append({"detector": "G-PRIV-001", "severity": "CRITICAL",
                                    "summary": f"runs the guard's own admin command ({sub}); run it yourself in a terminal", "evidence": " ".join(seg)[:200]})
                    break
        # 2. python -c / -m that imports the guard's modules
        if _is_python(cmd) and any(a in ("-c", "-m") or (a.startswith("-") and not a.startswith("--") and a[-1] in "cm") for a in args) \
                and any("truviq_guard" in a for a in args):
            out.append({"detector": "G-PRIV-001", "severity": "CRITICAL", "summary": "runs code that imports the guard's own modules", "evidence": " ".join(seg)[:200]})
        # 3. cd into the guard folder, or any non-read-only command that names it
        if cmd in ("cd", "pushd") and any(_mentions_guard_state(a, guard_home) for a in args):
            cd_into = True
            continue
        names_it = any(_mentions_guard_state(tok, guard_home) for tok in seg)
        writes = any(tok in (">", ">>", ">|", "&>") for tok in seg)
        dangerous_find = cmd == "find" and any(a in ("-delete", "-exec", "-execdir", "-fprint", "-fls", "-ok") for a in args)
        if (names_it or cd_into) and cmd and (cmd not in READ_ONLY_CMDS or dangerous_find or (cd_into and writes) or (names_it and writes)):
            out.append({"detector": "G-PRIV-001", "severity": "CRITICAL",
                        "summary": "changes the guard's own folder (policy, org policy, identity, queue or logs)", "evidence": " ".join(seg)[:200]})
    return out[:3]


def analyze(command: str, cwd: str, policy: dict, state: dict) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    if len(command) > MAX_COMMAND:
        return ([{"detector": "G-GUARD-ERR", "severity": "HIGH",
                  "summary": f"command is {len(command)} characters, too long to analyse safely; review it before allowing",
                  "evidence": command}], {"secret_read": [], "egress_hosts": []})
    tokens = _tokens(command)
    segs = _segments(tokens)
    allow = policy.get("egress_allow_hosts", [])
    tainted = bool(state.get("tainted"))

    # --- G-CMD-002 download and execute
    for rx in DOWNLOAD_EXEC:
        m = rx.search(command)
        if m:
            findings.append({"detector": "G-CMD-002", "severity": "CRITICAL",
                             "summary": "downloads code and runs it without review", "evidence": m.group(0)})
            break

    # --- G-CMD-001 destructive
    findings += _rm_findings(command, cwd)
    for rx, sev, why in DESTRUCTIVE:
        m = rx.search(command)
        if m:
            findings.append({"detector": "G-CMD-001", "severity": sev, "summary": why, "evidence": m.group(0)})
    words = [_command_word(s) for s in segs]
    for w, _args, _ in words:
        if w in POWER_CMDS:
            findings.append({"detector": "G-CMD-001", "severity": "HIGH", "summary": f"{w} stops the machine", "evidence": w})
    if any(m in command for m in policy.get("production_markers", [])):
        for f in findings:
            if f["detector"] == "G-CMD-001":
                f["severity"] = "CRITICAL"
                f["summary"] += " (production target)"

    findings += _guard_state_tamper(segs, os.path.realpath(paths.guard_home()))

    # --- G-DEP-002 production deploy
    m = DEPLOY_RX.search(command)
    if m and (any(x in command for x in policy.get("production_markers", [])) or PROD_WORD.search(command)):
        findings.append({"detector": "G-DEP-002", "severity": "HIGH",
                         "summary": f"deploys to production ({m.group(0).strip()})", "evidence": command})

    # --- G-PRIV-001 tampering / G-PRIV-002 sudo
    for rx, why in TAMPER:
        m = rx.search(command)
        if m:
            findings.append({"detector": "G-PRIV-001", "severity": "CRITICAL", "summary": why, "evidence": m.group(0)})
    protected = policy.get("protected_paths", [])
    redirect_targets = [tokens[i + 1] for i, t in enumerate(tokens[:-1]) if t in (">", ">>", ">|", "&>")]
    write_targets = list(redirect_targets)
    for w, args, _ in words:
        if w in WRITE_CMDS or (w in ("sed", "perl") and any(a.startswith("-i") for a in args)):
            write_targets += [a for a in args if not a.startswith("-")]
    for t in write_targets:
        hit = paths.matches_any(t, protected, cwd) or paths.protects_ancestor(t, protected, cwd)
        if hit:
            findings.append({"detector": "G-PRIV-001", "severity": "CRITICAL",
                             "summary": f"modifies a protected path ({hit})", "evidence": t})
            break
    if any(sudo for _, _, sudo in words):
        findings.append({"detector": "G-PRIV-002", "severity": "HIGH", "summary": "runs a command as root (sudo)", "evidence": "sudo"})

    # --- secrets and egress
    secret_paths = policy.get("secret_paths", [])
    secret_reads = []
    for t in tokens:
        if t in SEPARATORS or t.startswith("-") or t in redirect_targets:
            continue
        tt = t.lstrip("@<")
        if tt and any(paths.matches_any(x, secret_paths, cwd) for x in _expand(tt, cwd)):
            secret_reads.append(tt)
    for m in re.finditer(r"[\w~./-]*(?:\.env|\.ssh/|\.aws/|/proc/[\w]+/environ)[\w.-]*", command):
        if m.group(0) not in secret_reads and paths.matches_any(m.group(0), secret_paths, cwd):
            secret_reads.append(m.group(0))
    env_dump = bool(ENV_DUMP.search(command))

    egress_words = [w for w, _, _ in words if w in EGRESS_CMDS]
    hosts = [h.lower() for h in URL_HOST.findall(command)]
    for w, args, _ in words:
        if w in ("scp", "rsync", "sftp"):
            hosts += [a.split("@")[-1].split(":")[0] for a in args if ":" in a and not a.startswith("-") and "://" not in a]
        elif w in ("ssh", "nc", "ncat", "netcat", "telnet", "nslookup", "dig", "host", "ftp"):
            plain = [a for a in args if not a.startswith("-")]
            if plain:
                hosts.append(plain[0].split("@")[-1].lower())
    dev_hosts = DEV_NET.findall(command)
    hosts += [h.lower() for h in dev_hosts]
    script_egress = bool(re.search(r"\b(?:python[0-9.]*|node|ruby|perl)\s+-[ce]\b", command)) and bool(URL_HOST.search(command))
    has_egress = bool(egress_words) or script_egress or bool(dev_hosts)
    foreign = [h for h in hosts if not host_allowed(h, allow)]
    uploads = bool(UPLOAD_FLAG.search(command))

    env_ref = SECRET_ENV_REF.search(command)
    env_ref_sent = env_ref and (re.search(r"\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)\w*\}?[^|;&\n]{0,512}\|", command, re.I)
                                or re.search(r"(?:-d|--data[\w-]*|-F|--form|--post-data)[=\s]+[\"']?[^\s\"']*\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", command, re.I)
                                or re.search(r"https?://[^\s'\"]*\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", command, re.I))
    if has_egress and (secret_reads or env_dump):
        what = ", ".join(secret_reads) if secret_reads else "the environment variables"
        findings.append({"detector": "G-EXF-001", "severity": "CRITICAL",
                         "summary": f"reads {what} and sends data over the network", "evidence": command})
    elif has_egress and env_ref and foreign and (env_ref_sent or tainted):
        findings.append({"detector": "G-EXF-001", "severity": "CRITICAL",
                         "summary": f"sends secret variable {env_ref.group(0)} to {', '.join(foreign)}", "evidence": command})
    elif has_egress and env_ref and foreign:
        findings.append({"detector": "G-EXF-002", "severity": "HIGH",
                         "summary": f"uses secret variable {env_ref.group(0)} in a call to {', '.join(foreign)}; check this host should receive it",
                         "evidence": command})
    elif has_egress and tainted and state.get("private_data_touched") and foreign:
        findings.append({"detector": "G-EXF-001", "severity": "CRITICAL",
                         "summary": f"network call to {', '.join(foreign)} after untrusted content and secret access in this session",
                         "evidence": command})
    elif has_egress:
        smuggle = [w for w in egress_words if w in ("nslookup", "dig", "host")] and SUBST.search(command)
        url_subst = re.search(r"https?://[^\s'\"]*(?:\$\(|`)", command)
        if smuggle or url_subst:
            findings.append({"detector": "G-EXF-002", "severity": "HIGH",
                             "summary": "command output is embedded in a URL or DNS name (data smuggling)", "evidence": command})
        elif tainted and foreign:
            sev = "HIGH" if uploads else "MEDIUM"
            findings.append({"detector": "G-EXF-002", "severity": sev,
                             "summary": f"network call to {', '.join(foreign)} after untrusted content was read", "evidence": command})

    if secret_reads and tainted and not has_egress:
        findings.append({"detector": "G-SEC-001", "severity": "HIGH",
                         "summary": f"reads {', '.join(secret_reads)} after untrusted content was read in this session",
                         "evidence": command})

    effects = {"secret_read": secret_reads or (["<environment>"] if env_dump else []), "egress_hosts": foreign}
    return findings, effects
