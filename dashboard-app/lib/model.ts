import type { ActionGroup, Category, EventRow, Severity, Verdict } from "./types";

export const SEVERITY_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0, "": 0 };

export const RANGES = [
  { id: "1h", label: "1 hour", ms: 3_600_000 },
  { id: "24h", label: "24 hours", ms: 86_400_000 },
  { id: "7d", label: "7 days", ms: 604_800_000 },
  { id: "all", label: "All time", ms: Number.POSITIVE_INFINITY },
] as const;
export type RangeId = (typeof RANGES)[number]["id"];

export const CATEGORIES: { id: Category; label: string }[] = [
  { id: "inj", label: "Prompt injection" },
  { id: "code", label: "Generated code" },
  { id: "deps", label: "Dependencies" },
  { id: "cmd", label: "Commands & data" },
];

/** A pending ASK with no recorded "Yes" after this long is treated as not approved. */
export const ASK_TIMEOUT_MS = 15 * 60_000;

export function ts(r: EventRow): number {
  return Date.parse(r.event_ts || r.created_at || "") || 0;
}

export function category(detector = ""): Category {
  if (/^G-(CODE|IAC|VER|QUAL)/.test(detector)) return "code";
  if (/^G-DEP/.test(detector)) return "deps";
  if (/^G-(INJ|OBF)/.test(detector)) return "inj";
  return "cmd";
}

function toVerdict(v?: string): Verdict {
  return v === "DENY" || v === "ASK" ? v : "APPROVE";
}

/** Group finding rows into one entry per guarded action and attach ASK outcomes. */
export function groupActions(rows: EventRow[]): ActionGroup[] {
  const outcomes = new Map<string, EventRow>();
  const groups = new Map<string, ActionGroup>();
  for (const r of rows) {
    if (r.kind === "outcome") {
      if (r.tool_use_id) outcomes.set(r.tool_use_id, r);
      continue;
    }
    const key = [r.machine, r.session_id, r.tool_use_id || `${r.event_ts}|${r.hook_event}|${r.tool}`].join("|");
    let g = groups.get(key);
    if (!g) {
      g = { key, verdict: toVerdict(r.verdict), time: ts(r), top: r, rows: [], categories: new Set(), outcome: null, deps: [] };
      groups.set(key, g);
    }
    g.rows.push(r);
    g.time = Math.max(g.time, ts(r));
  }
  for (const g of groups.values()) {
    g.rows.sort((a, b) => (SEVERITY_RANK[b.severity || ""] ?? 0) - (SEVERITY_RANK[a.severity || ""] ?? 0));
    g.top = g.rows[0];
    g.categories = new Set(g.rows.map((r) => category(r.detector)));
    g.outcome = g.top.tool_use_id ? outcomes.get(g.top.tool_use_id) ?? null : null;
    g.deps = g.rows.find((r) => Array.isArray(r.deps) && r.deps.length)?.deps ?? [];
  }
  return [...groups.values()].sort((a, b) => b.time - a.time);
}

export type AskState = "approved" | "waiting" | "not-approved";

export function askState(g: ActionGroup, now = Date.now()): AskState | null {
  if (g.verdict !== "ASK") return null;
  if (g.outcome) return "approved";
  return now - g.time > ASK_TIMEOUT_MS ? "not-approved" : "waiting";
}

export function topSeverity(g: ActionGroup): Severity {
  return (g.top.severity || "") as Severity;
}

/** Triage order: asked-and-waiting first, then other asks, blocked, allowed with notes. */
export function triageRank(g: ActionGroup, now = Date.now()): number {
  if (g.verdict === "ASK") return askState(g, now) === "waiting" ? 0 : 1;
  return g.verdict === "DENY" ? 2 : 3;
}

/** Sort for the table: triage lane, then severity, then newest. */
export function byTriage(a: ActionGroup, b: ActionGroup, now = Date.now()): number {
  return (
    triageRank(a, now) - triageRank(b, now) ||
    (SEVERITY_RANK[b.top.severity || ""] ?? 0) - (SEVERITY_RANK[a.top.severity || ""] ?? 0) ||
    b.time - a.time
  );
}

export function controls(g: ActionGroup): string[] {
  const tags = new Set<string>();
  for (const r of g.rows) {
    const c = r.compliance || {};
    (c.owasp_llm || []).forEach((t) => tags.add(`OWASP ${t}`));
    (c.mitre_atlas || []).forEach((t) => tags.add(t));
    (c.cwe || []).forEach((t) => tags.add(t));
    (c.soc2 || []).forEach((t) => tags.add(`SOC 2 ${t}`));
    (c.iso27001 || []).forEach((t) => tags.add(`ISO 27001 ${t}`));
  }
  return [...tags];
}

const HOOK_NAMES: Record<string, string> = { UserPromptSubmit: "Prompt", SessionStart: "Session start", Stop: "End of turn", Outcome: "Decision" };

const SOURCE_NAMES: Record<string, string> = {
  Bash: "Shell command",
  Read: "File read",
  Write: "File write",
  Edit: "File edit",
  MultiEdit: "File edit",
  NotebookEdit: "Notebook edit",
  WebFetch: "Web page",
  WebSearch: "Web search",
  Grep: "Code search",
  Glob: "File search",
};

/** What triggered the action, in words: "Shell command", "Prompt", "File write". */
export function sourceName(r: EventRow): string {
  if (r.tool) return SOURCE_NAMES[r.tool] ?? (r.tool.startsWith("mcp__") ? `Tool ${r.tool.split("__").slice(1).join(" / ")}` : r.tool);
  return HOOK_NAMES[r.hook_event || ""] || r.hook_event || "";
}

/** For the Where column: a literal file path (shown as code) or the project the action ran in. */
export function place(r: EventRow): { path: string | null; project: string } {
  const path = r.file_path ? (r.line ? `${r.file_path}:${r.line}` : r.file_path) : null;
  return { path, project: r.project || "" };
}

const rtf = typeof Intl !== "undefined" ? new Intl.RelativeTimeFormat("en", { numeric: "auto" }) : null;
export function ago(t: number, now = Date.now()): string {
  if (!t) return "unknown";
  const s = Math.round((t - now) / 1000);
  const abs = Math.abs(s);
  if (!rtf) return new Date(t).toLocaleString();
  if (abs < 45) return "just now";
  if (abs < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(s / 3600), "hour");
  return rtf.format(Math.round(s / 86400), "day");
}

export function exactTime(t: number): string {
  return t ? new Date(t).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" }) : "";
}

export function hoursLabel(h: number): string {
  if (h < 1) return "under 1 h ago";
  if (h < 48) return `${Math.round(h)} h ago`;
  return `${Math.round(h / 24)} days ago`;
}
