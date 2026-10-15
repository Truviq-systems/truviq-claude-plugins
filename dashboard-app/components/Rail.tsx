"use client";

import { CircleCheck, CircleHelp, OctagonX, TriangleAlert } from "lucide-react";
import type { ActionGroup, FleetPayload, RedTeamPayload } from "@/lib/types";
import { ago, hoursLabel } from "@/lib/model";

const RESULT_ICON = { PASS: CircleCheck, FAIL: OctagonX } as const;

/** Red-team result: shape mark plus word, like every other state on the board. */
function Result({ verdict, plain = false }: { verdict?: string; plain?: boolean }) {
  const v = verdict || "INCONCLUSIVE";
  const Icon = RESULT_ICON[v as keyof typeof RESULT_ICON] ?? CircleHelp;
  return (
    <span className={plain ? `result-plain result-${v}` : `result result-${v}`}>
      <Icon size={13} strokeWidth={2.5} aria-hidden />
      {v}
    </span>
  );
}

export function FleetPanel({ fleet }: { fleet: FleetPayload | null }) {
  const machines = fleet?.machines ?? [];
  const bad = machines.filter((m) => m.problems.length).length;
  return (
    <section className="panel area-fleet" aria-labelledby="fleet-h">
      <div className="panel-head">
        <h2 id="fleet-h">Fleet health</h2>
        <span className="meta num">
          {machines.length} machine{machines.length === 1 ? "" : "s"}
          {bad ? ` · ${bad} need${bad === 1 ? "s" : ""} attention` : ""}
        </span>
      </div>
      <div className="panel-body">
        {!fleet ? (
          <p className="muted small">Loading…</p>
        ) : machines.length === 0 ? (
          <p className="muted small">{fleet.error || "No heartbeats yet. Each machine reports once an hour after a Claude Code session starts."}</p>
        ) : (
          <ul className="mlist">
            {[...machines]
              .sort((a, b) => b.problems.length - a.problems.length || a.machine.localeCompare(b.machine))
              .map((m) => (
                <li className="machine" key={`${m.device_id || ""}-${m.machine}`}>
                  {m.problems.length ? (
                    <TriangleAlert size={16} className="bad" aria-label="Needs attention" />
                  ) : (
                    <CircleCheck size={16} className="ok" aria-label="Healthy" />
                  )}
                  <span className="machine-name">
                    {m.machine} <span>{m.os_user ? `· ${m.os_user}` : ""}</span>
                  </span>
                  <span className="machine-meta num">
                    v{m.plugin_version || "?"} · {m.mode || "?"} · {hoursLabel(m.age_hours)}
                  </span>
                  {m.problems.map((p) => (
                    <span className="problem" key={p.kind}>
                      {p.detail}
                    </span>
                  ))}
                </li>
              ))}
          </ul>
        )}
        {fleet?.note ? <p className="muted small panel-note">{fleet.note}</p> : null}
      </div>
    </section>
  );
}

export function RedTeamPanel({ redteam }: { redteam: RedTeamPayload | null }) {
  const runs = redteam?.runs ?? [];
  const latest = runs[0];
  const s = latest?.summary;
  return (
    <section className="panel area-rt" aria-labelledby="rt-h">
      <div className="panel-head">
        <h2 id="rt-h">Nightly red team</h2>
        {latest ? <span className="meta">{ago(Date.parse(latest.ts))}</span> : null}
      </div>
      <div className="panel-body">
        {!redteam ? (
          <p className="muted small">Loading…</p>
        ) : !latest ? (
          <p className="muted small">{redteam.error || "No runs yet. An admin runs it with python3 redteam/nightly.py from the marketplace repository."}</p>
        ) : (
          <>
            <div className="rt-latest">
              <div>
                <Result verdict={s?.verdict} />
                <span className="muted small"> &nbsp;{latest.model ? `model ${latest.model}` : ""}</span>
              </div>
              <div className="rt-line">
                <span>Guard off: attacks the agent attempted</span>
                <b>
                  {s?.monitor?.attempted ?? "?"} of {s?.monitor?.cases ?? "?"}
                </b>
              </div>
              <div className="rt-line">
                <span>Guard on: attempts blocked</span>
                <b>
                  {s?.enforce?.blocked ?? "?"} of {s?.enforce?.attempted ?? "?"}
                </b>
              </div>
              <div className="rt-line">
                <span>Guard on: leaked</span>
                <b className={s?.enforce?.leaked ? "bad" : "ok"}>{s?.enforce?.leaked ?? "?"}</b>
              </div>
            </div>
            {runs.length > 1 ? (
              <ul className="rt-history">
                {runs.slice(1, 6).map((r) => (
                  <li key={r.run_id}>
                    <span>{new Date(Date.parse(r.ts)).toLocaleDateString(undefined, { day: "numeric", month: "short" })}</span>
                    <Result verdict={r.summary.verdict} plain />
                  </li>
                ))}
              </ul>
            ) : null}
          </>
        )}
      </div>
    </section>
  );
}

export function DetectorPanel({ groups, onPick }: { groups: ActionGroup[]; onPick: (detector: string) => void }) {
  const counts = new Map<string, { title: string; n: number }>();
  for (const g of groups)
    for (const r of g.rows) {
      const k = r.detector || "?";
      const cur = counts.get(k) || { title: r.title || "", n: 0 };
      cur.n += 1;
      counts.set(k, cur);
    }
  const top = [...counts].sort((a, b) => b[1].n - a[1].n).slice(0, 7);
  return (
    <section className="panel area-det" aria-labelledby="det-h">
      <div className="panel-head">
        <h2 id="det-h">Most frequent detectors</h2>
      </div>
      <div className="panel-body">
        {top.length === 0 ? (
          <p className="muted small">Nothing detected in this period.</p>
        ) : (
          <table className="dtable">
            <tbody>
              {top.map(([det, v]) => (
                <tr key={det}>
                  <td>
                    <button type="button" onClick={() => onPick(det)} title={`Show ${det} in the table`}>
                      <span className="code">{det}</span>
                      {v.title}
                    </button>
                  </td>
                  <td className="num">{v.n}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
