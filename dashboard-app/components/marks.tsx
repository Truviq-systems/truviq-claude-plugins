import { CircleCheck, CircleHelp, OctagonX } from "lucide-react";
import type { Severity, Verdict } from "@/lib/types";

const VERDICT_WORD: Record<Verdict, string> = { DENY: "DENY", ASK: "ASK", APPROVE: "APPROVE" };
const VERDICT_ICON = { DENY: OctagonX, ASK: CircleHelp, APPROVE: CircleCheck } as const;

/** The triage tag: a notched label carrying a shape mark and the verdict word. Never colour alone. */
export function TriageTag({ verdict }: { verdict: Verdict }) {
  const Icon = VERDICT_ICON[verdict];
  return (
    <span className={`tag tag-${verdict}`}>
      <Icon size={13} strokeWidth={2.5} aria-hidden />
      {VERDICT_WORD[verdict]}
    </span>
  );
}

const SEV_WORD: Record<string, string> = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", INFO: "Info", "": "Info" };

export function SeverityMark({ severity }: { severity?: Severity }) {
  const s = severity || "";
  return (
    <span className={`sev sev-${s}`}>
      <i aria-hidden />
      {SEV_WORD[s] ?? s}
    </span>
  );
}

/** "New since you looked": a worded mark that stays until the action is opened or everything is marked seen. */
export function NewMark() {
  return (
    <span className="new-mark" title="New since you looked">
      New
    </span>
  );
}
