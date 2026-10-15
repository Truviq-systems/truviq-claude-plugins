export type Verdict = "DENY" | "ASK" | "APPROVE";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "";
export type Category = "code" | "deps" | "inj" | "cmd";

/** One row of guard_events (one finding, or one ASK outcome). Mirrors sink.rows_from_record. */
export interface EventRow {
  id?: number;
  created_at?: string;
  event_ts?: string;
  machine?: string;
  os_user?: string;
  plugin_version?: string;
  session_id?: string;
  project?: string;
  hook_event?: string;
  tool?: string;
  tool_use_id?: string;
  kind?: "finding" | "outcome";
  decision?: string;
  verdict?: string;
  enforced?: boolean;
  tainted?: boolean;
  detector?: string;
  severity?: Severity;
  title?: string;
  summary?: string;
  evidence?: string;
  file_path?: string;
  line?: number | null;
  compliance?: Record<string, string[]>;
  deps?: string[];
  card?: string;
}

export interface EventsPayload {
  source: "supabase" | "local";
  rows: EventRow[];
  error?: string;
  note?: string | null;
  generated_at?: string;
}

export interface FleetMachine {
  machine: string;
  os_user?: string;
  device_id?: string;
  last_seen?: string;
  age_hours: number;
  plugin_version?: string;
  claude_version?: string | null;
  mode?: string;
  hooks_ok?: boolean;
  org_policy_version?: number | null;
  problems: { kind: string; detail: string }[];
}

export interface FleetPayload {
  source: "supabase" | "local";
  machines: FleetMachine[];
  problems: { machine: string; kind: string; detail: string }[];
  error?: string;
  note?: string;
}

export interface RedTeamArm {
  cases: number;
  attempted: number;
  blocked: number;
  leaked: number;
  not_reached: number;
}

export interface RedTeamRun {
  run_id: string;
  ts: string;
  model?: string;
  machine?: string;
  plugin_version?: string;
  summary: {
    monitor?: RedTeamArm;
    enforce?: RedTeamArm;
    verdict?: "PASS" | "FAIL" | "INCONCLUSIVE" | string;
    block_rate_when_attempted?: number | null;
  };
}

export interface RedTeamPayload {
  source: "supabase" | "local";
  runs: RedTeamRun[];
  error?: string;
}

/** One guarded action: every finding raised for a single tool call, prompt or session event. */
export interface ActionGroup {
  key: string;
  verdict: Verdict;
  time: number;
  top: EventRow;
  rows: EventRow[];
  categories: Set<Category>;
  outcome: EventRow | null;
  deps: string[];
}
