"use client";

import { Fragment, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, ChevronRight, CircleCheck, CircleX, Hourglass } from "lucide-react";
import type { ActionGroup } from "@/lib/types";
import { SEVERITY_RANK, ago, askState, byTriage, controls, exactTime, place, sourceName, triageRank } from "@/lib/model";
import { NewMark, SeverityMark, TriageTag } from "./marks";

type SortKey = "triage" | "time" | "severity";

const LANE_DIVIDERS = ["Asked a person · waiting for a decision", "Asked a person · decided", "Blocked", "Allowed with notes"];

interface Props {
  groups: ActionGroup[];
  openKey: string | null;
  onToggle: (key: string) => void;
  isNew: (key: string, time: number) => boolean;
  loading: boolean;
  emptyTitle: string;
  emptyText: string;
}

function AskOutcome({ g }: { g: ActionGroup }) {
  const s = askState(g);
  if (!s) return null;
  if (s === "approved")
    return (
      <span className="ask-state ask-approved">
        <CircleCheck size={14} aria-hidden /> Approved by a person
      </span>
    );
  if (s === "not-approved")
    return (
      <span className="ask-state ask-not-approved">
        <CircleX size={14} aria-hidden /> Not approved
      </span>
    );
  return (
    <span className="ask-state ask-waiting">
      <Hourglass size={14} aria-hidden /> Waiting for a decision
    </span>
  );
}

function depClass(line: string): string {
  const c = line.trimStart()[0];
  return c === "+" ? "dep dep-add" : c === "~" ? "dep dep-chg" : c === "-" ? "dep dep-rm" : "dep dep-warn";
}

function Detail({ g }: { g: ActionGroup }) {
  const r = g.top;
  const tags = controls(g);
  return (
    <div className="detail-grid">
      <div>
        <ul className="findings">
          {g.rows.map((f, i) => (
            <li className="finding" key={`${f.detector}-${i}`}>
              <div className="finding-head">
                <SeverityMark severity={f.severity} />
                <span className="code">{f.detector}</span>
                <span className="finding-title">{f.title}</span>
              </div>
              <p>{f.summary}</p>
              {f.evidence && !/^G-(CODE-001|SEC-002)$/.test(f.detector || "") ? <pre className="evidence">{f.evidence}</pre> : null}
            </li>
          ))}
        </ul>
        {g.deps.length ? (
          <>
            <h3 className="sub-h">Dependencies changed</h3>
            <div className="deps">
              {g.deps.slice(0, 30).map((d, i) => (
                <span className={depClass(d)} key={i}>
                  {d}
                </span>
              ))}
            </div>
          </>
        ) : null}
        {r.card ? (
          <details className="chat">
            <summary>
              <ChevronRight size={14} aria-hidden />
              Card shown in Claude Code
            </summary>
            <pre>{r.card}</pre>
          </details>
        ) : null}
      </div>
      <div>
        <dl className="facts">
          <dt>Verdict</dt>
          <dd>
            <TriageTag verdict={g.verdict} /> <AskOutcome g={g} />
          </dd>
          <dt>Machine</dt>
          <dd>{r.machine || "unknown"}</dd>
          <dt>User</dt>
          <dd>{r.os_user || "unknown"}</dd>
          <dt>Project</dt>
          <dd>{r.project || "—"}</dd>
          <dt>Where</dt>
          <dd>{place(r).path ?? sourceName(r) ?? "—"}</dd>
          <dt>Hook</dt>
          <dd>
            {r.hook_event}
            {r.tool ? ` / ${r.tool}` : ""}
          </dd>
          <dt>When</dt>
          <dd className="num">{exactTime(g.time)}</dd>
          <dt>Mode</dt>
          <dd>{r.enforced === false ? "Monitor (not enforced)" : "Enforced"}</dd>
          {r.tainted ? (
            <>
              <dt>Session</dt>
              <dd>Had read untrusted content</dd>
            </>
          ) : null}
          <dt>Plugin</dt>
          <dd className="num">{r.plugin_version || "—"}</dd>
        </dl>
        {tags.length ? (
          <>
            <h3 className="sub-h">Controls</h3>
            <div className="controls">
              {tags.slice(0, 16).map((t) => (
                <span className="control" key={t}>
                  {t}
                </span>
              ))}
            </div>
          </>
        ) : null}
      </div>
    </div>
  );
}

export function EventTable({ groups, openKey, onToggle, isNew, loading, emptyTitle, emptyText }: Props) {
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" }>({ key: "triage", dir: "desc" });

  const rows = useMemo(() => {
    const out = [...groups];
    const sign = sort.dir === "desc" ? -1 : 1;
    const now = Date.now();
    out.sort((a, b) => {
      if (sort.key === "triage") return sort.dir === "desc" ? byTriage(a, b, now) : byTriage(b, a, now);
      if (sort.key === "severity") {
        const d = (SEVERITY_RANK[a.top.severity || ""] ?? 0) - (SEVERITY_RANK[b.top.severity || ""] ?? 0);
        if (d) return sign * d;
      }
      return sign * (a.time - b.time);
    });
    return out.slice(0, 300);
  }, [groups, sort]);

  const header = (key: SortKey, label: string) => {
    const active = sort.key === key;
    const Arrow = sort.dir === "desc" ? ArrowDown : ArrowUp;
    return (
      <th aria-sort={active ? (sort.dir === "desc" ? "descending" : "ascending") : "none"}>
        <button type="button" onClick={() => setSort({ key, dir: active && sort.dir === "desc" ? "asc" : "desc" })}>
          {label}
          {active ? <Arrow size={13} aria-hidden /> : null}
        </button>
      </th>
    );
  };

  if (!loading && rows.length === 0) {
    return (
      <div className="empty">
        <h3>{emptyTitle}</h3>
        <p>{emptyText}</p>
      </div>
    );
  }

  return (
    <div className="table-wrap">
      <table className="events">
        <caption className="sr-only">Guarded actions in triage order. Select a row for the evidence.</caption>
        <thead>
          <tr>
            {header("triage", "Verdict")}
            {header("severity", "Severity")}
            <th>
              <span>What happened</span>
            </th>
            <th>
              <span>Machine</span>
            </th>
            <th>
              <span>Where</span>
            </th>
            {header("time", "When")}
          </tr>
        </thead>
        <tbody>
          {loading && rows.length === 0
            ? Array.from({ length: 6 }, (_, i) => (
                <tr className="skeleton-row" key={i}>
                  <td colSpan={6}>
                    <span className="skeleton" style={{ width: `${60 + ((i * 7) % 30)}%` }} />
                  </td>
                </tr>
              ))
            : rows.map((g, i) => {
                const open = openKey === g.key;
                const fresh = isNew(g.key, g.time);
                const r = g.top;
                const where = place(r);
                const rank = triageRank(g);
                const divider = sort.key === "triage" && (i === 0 || triageRank(rows[i - 1]) !== rank);
                return (
                  <Fragment key={g.key}>
                    {divider ? (
                      <tr className="lane-divider">
                        <th colSpan={6} scope="rowgroup">
                          {LANE_DIVIDERS[rank]}
                        </th>
                      </tr>
                    ) : null}
                    <tr
                      className={`row${open ? " open" : ""}${fresh ? " fresh" : ""}`}
                      onClick={() => onToggle(g.key)}
                      id={`row-${encodeURIComponent(g.key)}`}
                    >
                      <td className="cell-tag">
                        <div className="wrap">
                          <button
                            type="button"
                            className="expand"
                            aria-expanded={open}
                            aria-label={open ? "Hide evidence" : "Show evidence"}
                            onClick={(e) => {
                              e.stopPropagation();
                              onToggle(g.key);
                            }}
                          >
                            <ChevronRight size={16} aria-hidden />
                          </button>
                          <TriageTag verdict={g.verdict} />
                          {fresh ? <NewMark /> : null}
                        </div>
                      </td>
                      <td className="cell-sev">
                        <SeverityMark severity={r.severity} />
                      </td>
                      <td className="cell-what">
                        <div className="what-title">{r.title || r.detector}</div>
                        <div className="what-sum">{r.summary}</div>
                        {g.rows.length > 1 ? <div className="what-more">+{g.rows.length - 1} more finding{g.rows.length > 2 ? "s" : ""}</div> : null}
                        <AskOutcome g={g} />
                      </td>
                      <td className="mach">
                        {r.machine || "unknown"}
                        <span className="muted">{r.os_user || ""}</span>
                      </td>
                      <td className="cell-where">
                        {where.path ? <div className="where-path">{where.path}</div> : <div className="where-project">{where.project || "—"}</div>}
                        <div className="where-source">
                          {sourceName(r)}
                          {where.path && where.project ? ` · ${where.project}` : ""}
                        </div>
                      </td>
                      <td className="when" title={exactTime(g.time)}>
                        {ago(g.time)}
                      </td>
                    </tr>
                    {open ? (
                      <tr className="detail">
                        <td colSpan={6}>
                          <Detail g={g} />
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
        </tbody>
      </table>
    </div>
  );
}
