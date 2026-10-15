# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Next.js (user's choice), built as a static export so it ships inside the Claude Code plugin and is served by the plugin's existing Python standard-library server (`truviq.py dashboard`, `127.0.0.1:8787`). End users must not need Node.js. The server already provides `/api/events`, `/api/fleet` and `/api/redteam`.

## Users

Primary: a security lead responsible for many developers' machines that run Claude Code with TruViq Guard. Checks the dashboard a few times a day to see what was blocked or asked about across the team, which machines are unhealthy, and how the nightly red team performed. Secondary: an individual developer looking at their own machine after a block (local mode, no central data).

## Product Purpose

TruViq Guard is a Claude Code plugin that watches every prompt, tool call and tool result of a coding agent in real time. It blocks dangerous commands, secret theft and prompt-injection-driven actions, reviews generated code and dependency changes, and shows its decision in the chat as a DENY / ASK / APPROVE card. The dashboard is where those decisions from every machine come together. Success: the security lead sees within seconds what needs attention, and can show a customer or auditor clear, compliance-tagged evidence of what the guard did.

## Positioning

The guard sits inside the coding agent's own loop (hooks before and after each action), so its evidence is per action: the exact command, file and line, dependency diff, the verdict, whether a human approved it, and the compliance controls it maps to. A generic SIEM or LLM-firewall dashboard does not have this per-action, per-machine coding-agent record.

## Operating Context

- Data: findings with detector IDs (G-CMD-*, G-EXF-*, G-INJ-*, G-OBF-*, G-CODE-*, G-DEP-*, G-IAC-*, G-VER-*, G-PRIV-*, G-SEC-*), severity (CRITICAL/HIGH/MEDIUM/LOW), verdict (DENY/ASK/APPROVE), ASK outcomes (approved, not approved, waiting), dependency change lines, the chat card text, compliance tags (OWASP LLM, OWASP Agentic, MITRE ATLAS, CWE, SOC 2, ISO 27001), machine, user, project, tool, file and line.
- Fleet health per machine: plugin and Claude Code version, mode (enforce/monitor/off), hook files present, last heartbeat, org policy version, problems (stale, mode, hooks, version, policy).
- Nightly red team runs: guard-off vs guard-on, attempted / blocked / leaked per run, verdict PASS / FAIL / INCONCLUSIVE.
- Sources: central (Supabase, all machines, admin machine with the service-role key) or local (this machine's log). The page refreshes every few seconds.
- Runs on localhost only; read-only.

## Capabilities and Constraints

- Read-only. No approve/deny actions from the dashboard: ASK decisions are made in Claude Code's own prompt.
- Must render all event text as plain text (event content can be attacker-controlled).
- Strict CSP from the Python server; no external scripts; fonts are system fonts.
- Must work offline on a laptop (no CDN).

## Brand Commitments

- Name: TruViq Guard (product of TruViq).
- User-pinned visual constraints: professional and neatly organised; fonts Arial and Calibri only; **no purple, no gradients, no glassmorphism**.
- Customer-facing: it must look like a finished commercial product suitable for demos, screenshots and compliance reviews.

## Evidence on Hand

Real event data comes from the guard at runtime. No customer names, logos, metrics or testimonials exist; none may be invented.

## Product Principles

1. Action first: what needs a decision or a fix leads; history follows.
2. Every claim is traceable to an event: detector, file/line, machine, time.
3. Calm by default, loud only for real risk: severity and verdict carry colour; chrome does not.
4. Evidence-grade: what a screenshot shows must stand up in an audit.

## Accessibility & Inclusion

Status must never rely on colour alone (always paired with a word or icon). Keyboard navigable, visible focus. Readable at laptop sizes and on a projector for demos.
