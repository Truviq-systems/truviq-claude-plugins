"use client";

import { CheckCheck, ShieldCheck } from "lucide-react";
import { RANGES, type RangeId } from "@/lib/model";

interface Props {
  source: "supabase" | "local" | null;
  offline: boolean;
  range: RangeId;
  onRange: (r: RangeId) => void;
  updatedAt: number | null;
  newCount: number;
  onMarkSeen: () => void;
}

export function TopBar({ source, offline, range, onRange, updatedAt, newCount, onMarkSeen }: Props) {
  const sourceText = offline
    ? "Dashboard server not reachable"
    : source === "supabase"
      ? "All machines · live"
      : source === "local"
        ? "This machine only"
        : "Connecting…";
  return (
    <header className="topbar">
      <div className="topbar-inner">
        <div className="brand">
          <ShieldCheck size={20} strokeWidth={2.25} aria-hidden />
          TruViq Guard <span>Security console</span>
        </div>
        <span className={`source${offline ? " offline" : ""}`} role="status">
          <span className="source-dot" aria-hidden />
          {sourceText}
        </span>
        <div className="spacer" />
        <div className="range" role="group" aria-label="Time range">
          {RANGES.map((r) => (
            <button key={r.id} type="button" aria-pressed={range === r.id} onClick={() => onRange(r.id)}>
              {r.id === "all" ? "All" : r.id}
            </button>
          ))}
        </div>
        <span className="updated num">{updatedAt ? `Updated ${new Date(updatedAt).toLocaleTimeString()}` : ""}</span>
        <button type="button" className="bar-btn" onClick={onMarkSeen} disabled={newCount === 0}>
          <CheckCheck size={15} aria-hidden />
          {newCount ? `Mark ${newCount} as seen` : "All caught up"}
        </button>
      </div>
    </header>
  );
}
