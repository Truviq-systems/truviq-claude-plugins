"use client";

import type { ActionGroup, Verdict } from "@/lib/types";
import { ago, askState, byTriage } from "@/lib/model";
import { NewMark, TriageTag } from "./marks";

interface Props {
  groups: ActionGroup[];
  active: Verdict | "ALL";
  onLane: (v: Verdict | "ALL") => void;
  onOpen: (key: string) => void;
  isNew: (key: string, time: number) => boolean;
}

const LANES: { verdict: Verdict; name: string; empty: string }[] = [
  { verdict: "ASK", name: "Asked a person", empty: "No action needed a person's decision in this period." },
  { verdict: "DENY", name: "Blocked", empty: "Nothing was blocked in this period." },
  { verdict: "APPROVE", name: "Allowed with notes", empty: "No warnings in this period." },
];

export function TriageStrip({ groups, active, onLane, onOpen, isNew }: Props) {
  return (
    <section className="panel area-triage" aria-label="Triage">
      <div className="triage">
        {LANES.map((lane) => {
          const items = groups.filter((g) => g.verdict === lane.verdict).sort((a, b) => byTriage(a, b));
          const pressed = active === lane.verdict;
          let lead = "";
          let sub = "";
          if (lane.verdict === "ASK") {
            const approved = items.filter((g) => askState(g) === "approved").length;
            const waiting = items.filter((g) => askState(g) === "waiting").length;
            const refused = items.length - approved - waiting;
            lead = waiting ? `${waiting} waiting` : "None waiting";
            sub = `${approved} approved · ${refused} not approved`;
          } else if (lane.verdict === "DENY") {
            sub = `${items.filter((g) => g.top.severity === "CRITICAL").length} critical`;
          } else {
            const n = new Set(items.map((g) => g.top.machine)).size;
            sub = `on ${n} machine${n === 1 ? "" : "s"}`;
          }
          return (
            <div className="lane" key={lane.verdict}>
              <button
                type="button"
                className="lane-head"
                aria-pressed={pressed}
                onClick={() => onLane(pressed ? "ALL" : lane.verdict)}
                title={pressed ? "Show all verdicts" : `Show only “${lane.name.toLowerCase()}” in the table`}
              >
                <span className="lane-tag">
                  <TriageTag verdict={lane.verdict} />
                </span>
                <span className="lane-count num">{items.length}</span>
                <span className="lane-name">{lane.name}</span>
                <span className="lane-sub num">
                  {lead ? <b className={lead === "None waiting" ? "" : "lane-lead"}>{lead}</b> : null}
                  {lead ? " · " : ""}
                  {sub}
                </span>
              </button>
              {items.length === 0 ? (
                <p className="lane-empty">{lane.empty}</p>
              ) : (
                <>
                  <ul className="lane-list">
                    {items.slice(0, 3).map((g) => (
                      <li key={g.key}>
                        <button type="button" className="lane-item" onClick={() => onOpen(g.key)}>
                          <span className="lane-title">
                            {isNew(g.key, g.time) ? <NewMark /> : null}
                            {g.top.title || g.top.detector}
                          </span>
                          <span className="lane-meta">
                            {g.top.machine || "unknown machine"} · {ago(g.time)}
                          </span>
                        </button>
                      </li>
                    ))}
                  </ul>
                  {items.length > 3 ? (
                    <div className="lane-foot">
                      <button type="button" className="link-btn" onClick={() => onLane(lane.verdict)}>
                        Show all {items.length} in the table
                      </button>
                    </div>
                  ) : null}
                </>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
