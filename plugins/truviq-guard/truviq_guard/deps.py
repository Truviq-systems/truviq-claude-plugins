"""Dependency review (R4): what libraries did the agent add or change, and are they safe?

Inputs: a manifest file before/after an edit (requirements.txt, pyproject.toml, Pipfile,
package.json, go.mod, Cargo.toml, Gemfile) or an install command (pip/npm/yarn/pnpm/...).
Checks per added/changed package: registry existence (hallucinated names), look-alike of a
popular package (typosquat), very new package, known vulnerabilities (OSV) for a pinned
version, non-registry sources (git/url/file), and new npm install scripts.

Network lookups are cached for 24 h and time out fast. A failed lookup is reported as
"could not verify", never treated as safe. Set TRUVIQ_OFFLINE=1 to skip lookups.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.parse

from . import paths

PYPI_POPULAR = """requests urllib3 boto3 botocore numpy pandas setuptools wheel pip six python-dateutil pyyaml certifi
idna charset-normalizer typing-extensions packaging cryptography attrs pydantic jinja2 markupsafe click flask django
fastapi uvicorn starlette sqlalchemy psycopg2 psycopg2-binary pytest pluggy coverage tox virtualenv filelock scipy
matplotlib pillow lxml beautifulsoup4 soupsieve aiohttp httpx anyio sniffio h11 httpcore websockets grpcio protobuf
google-api-core googleapis-common-protos rsa pyasn1 oauthlib requests-oauthlib jsonschema rich tqdm colorama pygments
docutils sphinx black isort flake8 pylint mypy ruff pre-commit openai anthropic langchain transformers torch tensorflow
keras scikit-learn joblib redis celery kombu gunicorn werkzeug itsdangerous marshmallow pymysql mysqlclient pymongo
paramiko pynacl bcrypt passlib pyjwt python-jose python-dotenv toml tomli orjson ujson simplejson regex tabulate
openpyxl xlrd sentry-sdk structlog loguru alembic dnspython email-validator networkx sympy seaborn plotly streamlit
gradio selenium playwright scrapy tenacity backoff cachetools pytz tzdata arrow pendulum freezegun faker hypothesis
mock responses moto docker kubernetes ansible pexpect psutil watchdog deepeval deepteam temporalio supabase""".split()

NPM_POPULAR = """react react-dom next vue nuxt angular svelte express koa fastify axios node-fetch lodash underscore
moment dayjs date-fns chalk commander yargs inquirer debug dotenv uuid nanoid classnames clsx prop-types redux
react-redux zustand mobx jquery typescript ts-node tsx eslint prettier jest vitest mocha chai sinon webpack vite
rollup esbuild babel-loader @babel/core @babel/preset-env tailwindcss postcss autoprefixer sass less styled-components
@emotion/react mongoose sequelize prisma @prisma/client pg mysql2 sqlite3 redis ioredis socket.io ws jsonwebtoken
bcrypt bcryptjs passport cors helmet body-parser cookie-parser morgan winston pino zod yup joi ajv graphql apollo-server
@apollo/client rxjs ramda immer cheerio puppeteer playwright @playwright/test cross-env rimraf concurrently nodemon
husky lint-staged semver glob minimist chokidar fs-extra openai @anthropic-ai/sdk langchain three d3 chart.js
recharts framer-motion @tanstack/react-query @tanstack/react-router react-router react-router-dom""".split()

MANIFESTS = {
    "requirements": re.compile(r"(?:^|/)(?:requirements[\w.-]*\.txt|constraints\.txt)$"),
    "pyproject": re.compile(r"(?:^|/)pyproject\.toml$"),
    "pipfile": re.compile(r"(?:^|/)Pipfile$"),
    "package.json": re.compile(r"(?:^|/)package\.json$"),
    "go.mod": re.compile(r"(?:^|/)go\.mod$"),
    "cargo": re.compile(r"(?:^|/)Cargo\.toml$"),
    "gemfile": re.compile(r"(?:^|/)Gemfile$"),
}
ECOSYSTEM = {"requirements": "PyPI", "pyproject": "PyPI", "pipfile": "PyPI", "package.json": "npm",
             "go.mod": "Go", "cargo": "crates.io", "gemfile": "RubyGems"}
NAME_OK = {"PyPI": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,100}$"),
           "npm": re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]{0,213}$")}
NON_REGISTRY = re.compile(r"^(?:git\+|git://|github:|https?://|file:|link:|\.{0,2}/)|\s@\s|(?:^|\s)(?:git|path|url)\s*=", re.I)
NPM_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")


def manifest_kind(path: str) -> str | None:
    p = path.replace(os.sep, "/")
    for kind, rx in MANIFESTS.items():
        if rx.search(p):
            return kind
    return None


def _norm(name: str, eco: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "PyPI" else name.lower()


# ------------------------------------------------------------------ parsing

def parse(kind: str, text: str) -> tuple[dict[str, str], dict]:
    """Return ({name: spec}, extras). extras may hold npm scripts."""
    deps: dict[str, str] = {}
    extras: dict = {}
    if kind == "requirements":
        for line in text.splitlines():
            line = line.split(" #")[0].strip()
            if not line or line.startswith(("#", "-r", "-c", "--")):
                continue
            if line.startswith("-e ") or NON_REGISTRY.search(line):
                m = re.search(r"#egg=([\w.-]+)", line) or re.match(r"([A-Za-z0-9][\w.-]*)\s*@", line)
                deps[m.group(1) if m else line[:80]] = line
                continue
            m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)", line)
            if m:
                deps[m.group(1)] = (m.group(3) or "").strip()
    elif kind == "package.json":
        try:
            data = json.loads(text or "{}")
        except ValueError:
            return deps, {"unparsable": True}
        for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for k, v in (data.get(sec) or {}).items():
                deps[k] = str(v)
        extras["scripts"] = {k: v for k, v in (data.get("scripts") or {}).items() if k in NPM_INSTALL_SCRIPTS}
    elif kind in ("pyproject", "pipfile", "cargo"):
        section = None
        for raw in text.splitlines():
            line = raw.strip()
            h = re.match(r"^\[([^\]]+)\]", line)
            if h:
                section = h.group(1)
                continue
            dep_section = section in ("tool.poetry.dependencies", "tool.poetry.dev-dependencies", "packages", "dev-packages",
                                      "dependencies", "dev-dependencies", "build-dependencies") or \
                (section or "").startswith(("tool.poetry.group.", "target."))
            if dep_section:
                m = re.match(r'^"?([A-Za-z0-9][\w.-]*)"?\s*=\s*(.+)$', line)
                if m and m.group(1).lower() != "python":
                    deps[m.group(1)] = m.group(2).strip()
            if section == "project" or (section or "").startswith("project.optional-dependencies"):
                for q in re.findall(r'"([A-Za-z0-9][^"]*)"', line) if ("dependencies" in line or line.startswith('"')) else []:
                    m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)", q)
                    if m and not line.startswith(("name", "version", "description")):
                        deps[m.group(1)] = (m.group(3) or "").strip()
    elif kind == "go.mod":
        for m in re.finditer(r"^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]{2,}/[^\s]+)\s+(v[^\s]+)", text, re.M):
            deps[m.group(1)] = m.group(2)
    elif kind == "gemfile":
        for m in re.finditer(r"""^\s*gem\s+['"]([^'"]+)['"](.*)$""", text, re.M):
            deps[m.group(1)] = m.group(2).strip(" ,")
    return deps, extras


def diff(kind: str, before: str, after: str) -> dict:
    eco = ECOSYSTEM[kind]
    old, old_x = parse(kind, before or "")
    new, new_x = parse(kind, after or "")
    oldn = {_norm(k, eco): (k, v) for k, v in old.items()}
    newn = {_norm(k, eco): (k, v) for k, v in new.items()}
    added = [{"name": newn[k][0], "spec": newn[k][1]} for k in newn if k not in oldn]
    removed = [{"name": oldn[k][0], "spec": oldn[k][1]} for k in oldn if k not in newn]
    changed = [{"name": newn[k][0], "from": oldn[k][1], "to": newn[k][1]} for k in newn if k in oldn and oldn[k][1] != newn[k][1]]
    scripts = {k: v for k, v in (new_x.get("scripts") or {}).items() if (old_x.get("scripts") or {}).get(k) != v}
    return {"ecosystem": eco, "added": added, "removed": removed, "changed": changed, "new_install_scripts": scripts}


INSTALL_RX = re.compile(
    r"(?:^|[;&|]\s*|\s)(?P<tool>pip3?|python[0-9.]*\s+-m\s+pip|uv\s+pip|uv|poetry|pipenv|npm|pnpm|yarn|bun|cargo|go|gem)\s+"
    r"(?P<verb>install|i|add|get)\b(?P<args>[^;&|]*)", re.I)
TOOL_ECO = {"pip": "PyPI", "pip3": "PyPI", "uv": "PyPI", "poetry": "PyPI", "pipenv": "PyPI", "npm": "npm", "pnpm": "npm",
            "yarn": "npm", "bun": "npm", "cargo": "crates.io", "go": "Go", "gem": "RubyGems"}


def from_install_command(command: str) -> list[dict]:
    """[{ecosystem, name, spec, raw}] for packages named in install commands (not `-r file` / bare `npm install`)."""
    out = []
    for m in INSTALL_RX.finditer(command):
        tool = m.group("tool").lower().split()[0]
        tool = "pip" if tool.startswith("python") else tool
        eco = TOOL_ECO.get(tool, "PyPI")
        if tool in ("go",) and m.group("verb").lower() != "get":
            continue
        args = m.group("args").split()
        skip_next = False
        for a in args:
            if skip_next:
                skip_next = False
                continue
            if a in ("-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-t", "--target", "--index-url", "-i", "--registry"):
                skip_next = True
                continue
            if a.startswith("-") or a in (".", "..") or a.endswith((".txt", ".toml", ".lock")):
                continue
            raw = a.strip("'\"")
            if eco == "npm":
                m2 = re.match(r"^(@?[^@\s]+)(?:@(.+))?$", raw)
                name, spec = (m2.group(1), m2.group(2) or "") if m2 else (raw, "")
            elif eco == "PyPI":
                m2 = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(.*)$", raw)
                name, spec = (m2.group(1), m2.group(3)) if m2 else (raw, "")
            else:
                name, spec = (raw.split("@")[0], raw.split("@")[1] if "@" in raw else "")
            out.append({"ecosystem": eco, "name": name, "spec": spec, "raw": raw})
    return out


# ------------------------------------------------------------------ checks

def _lev(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def lookalike(name: str, eco: str) -> str | None:
    pool = PYPI_POPULAR if eco == "PyPI" else NPM_POPULAR if eco == "npm" else []
    n = _norm(name, eco)
    normalized = {_norm(p, eco) for p in pool}
    if n in normalized or len(n) < 4:
        return None
    for p in pool:
        pn = _norm(p, eco)
        if _lev(n, pn, 2) <= (1 if len(pn) < 7 else 2):
            return p
        if n.replace("-", "") == pn.replace("-", "") or n in (pn + "s", pn + "-js", pn + "-py", "py" + pn, pn + "2"):
            return p
    return None


def _cache_file() -> str:
    return os.path.join(paths.ensure_private_dir(os.path.join(paths.guard_home(), "cache")), "registry.json")


def _cache() -> dict:
    try:
        with open(_cache_file(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _cache_save(data: dict) -> None:
    if len(data) > 2000:
        data = dict(list(data.items())[-2000:])
    p = _cache_file()
    fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(p + ".tmp", p)


def _get_json(url: str, timeout: float, body: dict | None = None) -> tuple[int, dict | None]:
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body else None, method="POST" if body else "GET",
                                 headers={"User-Agent": "truviq-guard/0.3", "Accept": "application/json",
                                          **({"Content-Type": "application/json"} if body else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - fixed public registries
            return r.status, json.loads(r.read(3_000_000).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, None


def registry_info(name: str, eco: str, timeout: float) -> dict:
    """{exists: True/False/None, created: epoch|None, error?}. None = could not verify."""
    if eco not in NAME_OK or not NAME_OK[eco].match(name):
        return {"exists": None, "error": "name not checkable"}
    key = f"{eco}:{_norm(name, eco)}"
    cache = _cache()
    hit = cache.get(key)
    if hit and time.time() - hit.get("checked", 0) < 86400:
        return hit
    try:
        if eco == "PyPI":
            code, data = _get_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json", timeout)
            created = None
            if data:
                times = [f.get("upload_time_iso_8601") for files in (data.get("releases") or {}).values() for f in files]
                times = sorted(t for t in times if t)
                created = _iso_epoch(times[0]) if times else None
        else:
            code, data = _get_json("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"), timeout)
            created = _iso_epoch(((data or {}).get("time") or {}).get("created", "")) if data else None
        if code == 404:
            info = {"exists": False}
        elif code == 200:
            info = {"exists": True, "created": created}
        else:
            return {"exists": None, "error": f"HTTP {code}"}
    except (OSError, ValueError) as e:
        return {"exists": None, "error": type(e).__name__}
    info["checked"] = time.time()
    cache[key] = info
    _cache_save(cache)
    return info


def osv_vulns(name: str, eco: str, version: str, timeout: float) -> list[str] | None:
    if not version or eco not in ("PyPI", "npm", "Go", "crates.io", "RubyGems"):
        return []
    try:
        code, data = _get_json("https://api.osv.dev/v1/query", timeout,
                               {"package": {"name": name, "ecosystem": eco}, "version": version})
    except (OSError, ValueError):
        return None
    if code != 200:
        return None
    return [v.get("id", "?") for v in (data or {}).get("vulns", [])][:10]


def _iso_epoch(s: str) -> float | None:
    try:
        import datetime
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def _pinned(spec: str) -> str | None:
    m = re.match(r"^\s*(?:==|=)?\s*v?(\d+(?:\.\d+){0,3}[\w.+-]*)\s*$", spec or "")
    return m.group(1) if m and ("==" in (spec or "") or re.match(r"^\s*v?\d", spec or "")) else None


def review(packages: list[dict], policy: dict, where: str) -> list[dict]:
    """Findings for a list of {ecosystem, name, spec, change}. `where` describes the file or command."""
    cfg = policy.get("dependencies", {})
    offline = os.environ.get("TRUVIQ_OFFLINE") == "1" or not cfg.get("registry_check", True)
    timeout = float(cfg.get("timeout_seconds", 2))
    new_days = float(cfg.get("new_package_days", 30))
    findings = []
    for p in packages[:25]:
        eco, name, spec = p["ecosystem"], p["name"], p.get("spec", "")
        if NON_REGISTRY.search(spec or "") or NON_REGISTRY.search(name):
            findings.append({"detector": "G-DEP-004", "severity": "HIGH", "file": where,
                             "summary": f"{name} comes from outside the package registry ({spec or name})", "evidence": f"{name} {spec}"})
            continue
        similar = lookalike(name, eco)
        if similar:
            findings.append({"detector": "G-DEP-001", "severity": "HIGH", "file": where,
                             "summary": f"{name} looks like a misspelling of the popular package {similar} (typosquat risk)",
                             "evidence": f"{name} {spec}"})
        if offline or eco not in NAME_OK:
            continue
        info = registry_info(name, eco, timeout)
        if info.get("exists") is False:
            findings.append({"detector": "G-DEP-001", "severity": "CRITICAL", "file": where,
                             "summary": f"{name} does not exist on {eco}: likely hallucinated, and anyone could register it (slopsquatting)",
                             "evidence": f"{name} {spec}"})
            continue
        if info.get("exists") is None:
            findings.append({"detector": "G-DEP-001", "severity": "LOW", "file": where,
                             "summary": f"could not verify {name} on {eco} ({info.get('error')})", "evidence": name})
        elif info.get("created") and time.time() - info["created"] < new_days * 86400:
            age = int((time.time() - info["created"]) / 86400)
            findings.append({"detector": "G-DEP-001", "severity": "HIGH", "file": where,
                             "summary": f"{name} was first published {age} day(s) ago; new packages are a common malware vector",
                             "evidence": f"{name} {spec}"})
        ver = _pinned(spec)
        if ver and cfg.get("vulnerability_check", True):
            vulns = osv_vulns(name, eco, ver, timeout)
            if vulns:
                findings.append({"detector": "G-DEP-001", "severity": "HIGH", "file": where,
                                 "summary": f"{name} {ver} has known vulnerabilities: {', '.join(vulns[:4])}", "evidence": f"{name}=={ver}"})
    return findings


def describe(d: dict) -> list[str]:
    """Human lines for a manifest diff: '+ name spec', '~ name a → b', '- name'."""
    out = [f"+ {a['name']} {a['spec']}".rstrip() for a in d.get("added", [])]
    out += [f"~ {c['name']} {c['from'] or '(any)'} → {c['to'] or '(any)'}" for c in d.get("changed", [])]
    out += [f"- {r['name']}" for r in d.get("removed", [])]
    out += [f"! new install script \"{k}\": {v[:60]}" for k, v in d.get("new_install_scripts", {}).items()]
    return out
