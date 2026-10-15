"""Detector catalogue: one entry per detector ID, with compliance tags.

The IDs and mappings come from docs/CODING_AGENT_GUARD_PLAN.md section 7.
`vulnerability` uses the DeepTeam names so the main platform's mappers can
consume guard events later without changes.
"""
from __future__ import annotations

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

DETECTORS: dict[str, dict] = {
    "G-CMD-001": {
        "title": "Destructive command",
        "vulnerability": "ExcessiveAgency",
        "owasp_llm": ["LLM06"], "owasp_agentic": ["T2", "T11"], "mitre_atlas": [],
        "cwe": ["CWE-78"], "soc2": ["CC8.1"], "iso27001": ["A.8.32"],
        "remediation": "Run destructive commands yourself after checking the target, or narrow the path.",
    },
    "G-CMD-002": {
        "title": "Download and execute",
        "vulnerability": "UnexpectedCodeExecution",
        "owasp_llm": ["LLM03", "LLM06"], "owasp_agentic": ["T11"], "mitre_atlas": ["AML.T0010"],
        "cwe": ["CWE-494"], "soc2": ["CC6.8"], "iso27001": ["A.8.7"],
        "remediation": "Download the script, read it, then run it deliberately. Prefer a package manager.",
    },
    "G-EXF-001": {
        "title": "Secret sent to the network",
        "vulnerability": "PIILeakage",
        "owasp_llm": ["LLM01", "LLM02", "LLM06"], "owasp_agentic": ["T2", "T6"],
        "mitre_atlas": ["AML.T0057", "AML.T0025"],
        "cwe": ["CWE-200"], "soc2": ["CC6.1", "CC6.7"], "iso27001": ["A.8.12"],
        "remediation": "Never send secret files or environment dumps to a remote host. If a file or web page asked for this, treat it as an attack.",
    },
    "G-EXF-002": {
        "title": "Suspicious outbound data",
        "vulnerability": "PIILeakage",
        "owasp_llm": ["LLM02"], "owasp_agentic": ["T2"], "mitre_atlas": ["AML.T0057"],
        "cwe": ["CWE-201"], "soc2": ["CC6.7"], "iso27001": ["A.8.12"],
        "remediation": "Check what data is being sent and to which host before allowing it.",
    },
    "G-SEC-001": {
        "title": "Secret read after untrusted content",
        "vulnerability": "PIILeakage",
        "owasp_llm": ["LLM01", "LLM02"], "owasp_agentic": ["T6"], "mitre_atlas": ["AML.T0051.001"],
        "cwe": ["CWE-200"], "soc2": ["CC6.1"], "iso27001": ["A.8.12"],
        "remediation": "This session has read untrusted instructions. Only allow secret reads you asked for.",
    },
    "G-SEC-002": {
        "title": "Secret pasted into the prompt",
        "vulnerability": "PIILeakage",
        "owasp_llm": ["LLM02"], "owasp_agentic": [], "mitre_atlas": ["AML.T0057"],
        "cwe": ["CWE-200", "CWE-312"], "soc2": ["CC6.1", "CC6.7"], "iso27001": ["A.8.12"],
        "remediation": "Remove the key from the prompt and send it again. Put secrets in .env or a secret manager yourself; "
                       "if the key was already sent anywhere, revoke it.",
    },
    "G-PRIV-001": {
        "title": "Guard tampering",
        "vulnerability": "ExcessiveAgency",
        "owasp_llm": ["LLM06"], "owasp_agentic": ["T3", "T8"], "mitre_atlas": [],
        "cwe": ["CWE-269"], "soc2": ["CC6.1", "CC7.2"], "iso27001": ["A.8.2"],
        "remediation": "Change guard settings or git hooks yourself, outside the agent.",
    },
    "G-PRIV-002": {
        "title": "Privilege escalation",
        "vulnerability": "ExcessiveAgency",
        "owasp_llm": ["LLM06"], "owasp_agentic": ["T3"], "mitre_atlas": [],
        "cwe": ["CWE-250"], "soc2": ["CC6.1"], "iso27001": ["A.8.2"],
        "remediation": "Run commands that need root yourself.",
    },
    "G-CODE-001": {
        "title": "Secret written into a file",
        "vulnerability": "PIILeakage",
        "owasp_llm": ["LLM02", "LLM05"], "owasp_agentic": [], "mitre_atlas": [],
        "cwe": ["CWE-798"], "soc2": ["CC6.1"], "iso27001": ["A.8.28"],
        "remediation": "Read the value from an environment variable or secret manager instead of hardcoding it.",
    },
    "G-CODE-002": {
        "title": "Injection-prone code",
        "vulnerability": "ShellInjection",
        "owasp_llm": ["LLM05"], "owasp_agentic": ["T11"], "mitre_atlas": [],
        "cwe": ["CWE-89", "CWE-78", "CWE-95", "CWE-502", "CWE-295"], "soc2": ["CC8.1"], "iso27001": ["A.8.28"],
        "remediation": "Use parameterised queries, argument lists instead of shell strings, safe loaders, and keep TLS verification on.",
    },
    "G-CODE-003": {
        "title": "Weak security practice in code",
        "vulnerability": "InsecureCrypto",
        "owasp_llm": ["LLM05"], "owasp_agentic": [], "mitre_atlas": [],
        "cwe": ["CWE-327", "CWE-338", "CWE-79", "CWE-489"], "soc2": ["CC6.7"], "iso27001": ["A.8.24", "A.8.28"],
        "remediation": "Use SHA-256+/bcrypt/argon2 for hashing, `secrets` / crypto RNG for tokens, escape HTML output, disable debug in production.",
    },
    "G-DEP-001": {
        "title": "Suspicious dependency",
        "vulnerability": "SupplyChain",
        "owasp_llm": ["LLM03", "LLM09"], "owasp_agentic": ["T5"], "mitre_atlas": ["AML.T0010"],
        "cwe": ["CWE-1357", "CWE-1104"], "soc2": ["CC9.2"], "iso27001": ["A.5.21"],
        "remediation": "Check the exact package name on the registry. Hallucinated or look-alike names are a known supply-chain attack (slopsquatting).",
    },
    "G-DEP-002": {
        "title": "Production deploy",
        "vulnerability": "ExcessiveAgency",
        "owasp_llm": ["LLM06"], "owasp_agentic": ["T10"], "mitre_atlas": [],
        "cwe": [], "soc2": ["CC8.1"], "iso27001": ["A.8.32"],
        "remediation": "Deploy to production through your reviewed release process, not from an agent session.",
    },
    "G-DEP-003": {
        "title": "Dependency added or changed",
        "vulnerability": "SupplyChain",
        "owasp_llm": ["LLM03"], "owasp_agentic": [], "mitre_atlas": [],
        "cwe": ["CWE-1357"], "soc2": ["CC9.2", "CC8.1"], "iso27001": ["A.5.21", "A.8.32"],
        "remediation": "Approve only libraries you expected. Prefer pinned versions from the official registry.",
    },
    "G-DEP-004": {
        "title": "Risky dependency source or install script",
        "vulnerability": "SupplyChain",
        "owasp_llm": ["LLM03"], "owasp_agentic": ["T11"], "mitre_atlas": ["AML.T0010"],
        "cwe": ["CWE-494", "CWE-829"], "soc2": ["CC9.2"], "iso27001": ["A.5.21"],
        "remediation": "Avoid git/URL/file dependencies and new install scripts unless reviewed; they run code at install time.",
    },
    "G-IAC-001": {
        "title": "Insecure infrastructure or CI config",
        "vulnerability": "ExcessiveAgency",
        "owasp_llm": ["LLM06"], "owasp_agentic": ["T3"], "mitre_atlas": [],
        "cwe": ["CWE-732", "CWE-284", "CWE-250"], "soc2": ["CC6.6", "CC8.1"], "iso27001": ["A.8.9"],
        "remediation": "Restrict network ranges, keep buckets private, drop privileges, and never interpolate untrusted event data into CI shell steps.",
    },
    "G-VER-001": {
        "title": "Tests or checks weakened",
        "vulnerability": "ExcessiveAgency",
        "owasp_llm": ["LLM06"], "owasp_agentic": ["T7"], "mitre_atlas": [],
        "cwe": ["CWE-1164"], "soc2": ["CC8.1"], "iso27001": ["A.8.29"],
        "remediation": "Fix the code instead of skipping tests, deleting assertions or lowering thresholds.",
    },
    "G-OBF-001": {
        "title": "Hidden or invisible text",
        "vulnerability": "IndirectInstruction",
        "owasp_llm": ["LLM01"], "owasp_agentic": ["T6"], "mitre_atlas": ["AML.T0051.001"],
        "cwe": ["CWE-1427"], "soc2": ["CC7.1"], "iso27001": ["A.8.28"],
        "remediation": "Inspect the file with a hex viewer or `cat -v`; remove invisible characters.",
    },
    "G-INJ-001": {
        "title": "Jailbreak attempt in prompt",
        "vulnerability": "PromptInjection",
        "owasp_llm": ["LLM01"], "owasp_agentic": ["T6", "T15"], "mitre_atlas": ["AML.T0051.000", "AML.T0054"],
        "cwe": ["CWE-1427"], "soc2": ["CC7.2"], "iso27001": ["A.8.16"],
        "remediation": "If you did not write this prompt (for example you pasted it), check where it came from.",
    },
    "G-INJ-002": {
        "title": "Instructions aimed at the AI inside a file",
        "vulnerability": "IndirectInstruction",
        "owasp_llm": ["LLM01"], "owasp_agentic": ["T6"], "mitre_atlas": ["AML.T0051.001"],
        "cwe": ["CWE-1427"], "soc2": ["CC7.2"], "iso27001": ["A.8.28"],
        "remediation": "Open the file yourself and check the flagged lines. Do not let the agent follow them.",
    },
    "G-INJ-003": {
        "title": "Poisoned agent instruction file",
        "vulnerability": "IndirectInstruction",
        "owasp_llm": ["LLM01", "LLM04"], "owasp_agentic": ["T1", "T6"], "mitre_atlas": ["AML.T0051.001"],
        "cwe": ["CWE-1427"], "soc2": ["CC7.1"], "iso27001": ["A.8.28"],
        "remediation": "Review CLAUDE.md / AGENTS.md / rules files before working in this repository.",
    },
    "G-INJ-005": {
        "title": "Instructions aimed at the AI in tool output",
        "vulnerability": "IndirectInstruction",
        "owasp_llm": ["LLM01"], "owasp_agentic": ["T2", "T6"], "mitre_atlas": ["AML.T0051.001"],
        "cwe": ["CWE-1427"], "soc2": ["CC7.2"], "iso27001": ["A.8.16"],
        "remediation": "Treat that output as data. Check where it came from (web page, issue, test output, MCP tool).",
    },
    "G-WEB-001": {
        "title": "Web fetch redirected to the safe fetch tool",
        "vulnerability": "IndirectInstruction",
        "owasp_llm": ["LLM01"], "owasp_agentic": ["T6"], "mitre_atlas": ["AML.T0051.001"],
        "cwe": ["CWE-1427"], "soc2": [], "iso27001": [],
        "remediation": "Use the guard_fetch tool from the TruViq MCP server.",
    },
    "G-FLEET-001": {
        "title": "Guard not healthy on a machine",
        "vulnerability": "",
        "owasp_llm": [], "owasp_agentic": ["T3"], "mitre_atlas": [],
        "cwe": [], "soc2": ["CC7.2"], "iso27001": ["A.8.16"],
        "remediation": "Check the machine: restart Claude Code, run `truviq.py doctor`, and reinstall the plugin if the hooks are missing.",
    },
    # --- R9 code quality: generated code that is wrong, unused or will not run
    "G-QUAL-001": {
        "title": "Unused import",
        "vulnerability": "",
        "owasp_llm": ["LLM09"], "owasp_agentic": [], "mitre_atlas": [],
        "cwe": ["CWE-1164"], "soc2": ["CC8.1"], "iso27001": ["A.8.28"],
        "remediation": "Remove the import, or use it if the code is unfinished.",
    },
    "G-QUAL-002": {
        "title": "Code or config that does not parse",
        "vulnerability": "",
        "owasp_llm": ["LLM09"], "owasp_agentic": [], "mitre_atlas": [],
        "cwe": ["CWE-1164"], "soc2": ["CC8.1"], "iso27001": ["A.8.28"],
        "remediation": "Fix the syntax error and write the file again; the whole file must parse after each change.",
    },
    "G-QUAL-003": {
        "title": "Code that will not run",
        "vulnerability": "SupplyChain",
        "owasp_llm": ["LLM09", "LLM03"], "owasp_agentic": [], "mitre_atlas": ["AML.T0010"],
        "cwe": ["CWE-457", "CWE-1357"], "soc2": ["CC8.1"], "iso27001": ["A.8.28"],
        "remediation": "Define the missing names, create the missing module, or add the real package to the project's dependencies. "
                       "An import of a package that does not exist is a known AI mistake (package hallucination).",
    },
    "G-QUAL-004": {
        "title": "Tests or type check fail",
        "vulnerability": "",
        "owasp_llm": ["LLM09"], "owasp_agentic": [], "mitre_atlas": [],
        "cwe": ["CWE-1164"], "soc2": ["CC8.1"], "iso27001": ["A.8.29"],
        "remediation": "Fix the code so the project's tests and type check pass. Do not skip or weaken the tests.",
    },
    "G-QUAL-005": {
        "title": "Possible logic problem",
        "vulnerability": "",
        "owasp_llm": ["LLM09"], "owasp_agentic": [], "mitre_atlas": [],
        "cwe": [], "soc2": ["CC8.1"], "iso27001": ["A.8.28"],
        "remediation": "Advisory review by an AI model: check the flagged case and add a test for it.",
    },
    "G-QUAL-006": {
        "title": "Unused dependency",
        "vulnerability": "SupplyChain",
        "owasp_llm": ["LLM03", "LLM09"], "owasp_agentic": [], "mitre_atlas": [],
        "cwe": ["CWE-1164", "CWE-1104"], "soc2": ["CC9.2"], "iso27001": ["A.5.21"],
        "remediation": "Remove the dependency if nothing uses it: every extra package is extra attack surface.",
    },
    "G-QUAL-007": {
        "title": "Project linter error",
        "vulnerability": "",
        "owasp_llm": ["LLM09"], "owasp_agentic": [], "mitre_atlas": [],
        "cwe": [], "soc2": ["CC8.1"], "iso27001": ["A.8.28"],
        "remediation": "Fix the problems the project's own linter (ruff / eslint) reports on the new lines.",
    },
    "G-GUARD-ERR": {
        "title": "Guard error (fail-safe applied)",
        "vulnerability": "",
        "owasp_llm": [], "owasp_agentic": [], "mitre_atlas": [],
        "cwe": [], "soc2": [], "iso27001": [],
        "remediation": "Run `python3 <plugin>/bin/truviq.py status` and check ~/.truviq/logs/guard-errors.log.",
    },
}


def compliance_tags(detector_id: str) -> dict:
    d = DETECTORS.get(detector_id, {})
    return {k: d.get(k, []) for k in ("owasp_llm", "owasp_agentic", "mitre_atlas", "cwe", "soc2", "iso27001")}


def severity_rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0


def bump(sev: str, steps: int = 1) -> str:
    return SEVERITIES[min(severity_rank(sev) + steps, len(SEVERITIES) - 1)]
