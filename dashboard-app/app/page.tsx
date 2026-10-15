"use client";

import { useEffect, useMemo, useState } from "react";
import { CircleAlert, Info } from "lucide-react";
import type { Category, Verdict } from "@/lib/types";
import { RANGES, groupActions, type RangeId } from "@/lib/model";
import { useGuardData, useSeen } from "@/lib/useGuardData";
import { TopBar } from "@/components/TopBar";
import { TriageStrip } from "@/components/TriageStrip";
import { FilterBar } from "@/components/FilterBar";
import { EventTable } from "@/components/EventTable";
import { DetectorPanel, FleetPanel, RedTeamPanel } from "@/components/Rail";

const VERDICT_NAME: Record<Verdict, string> = { ASK: "asked a person", DENY: "blocked", APPROVE: "allowed with notes" };

export default function Dashboard() {
  const { events, fleet, redteam, status, updatedAt } = useGuardData();
  const { isNew, markOpened, markAllSeen } = useSeen();
  const [range, setRange] = useState<RangeId>("24h");
  const [verdict, setVerdict] = useState<Verdict | "ALL">("ALL");
  const [category, setCategory] = useState<Category | "ALL">("ALL");
  const [machine, setMachine] = useState("ALL");
  const [query, setQuery] = useState("");
  const [openKey, setOpenKey] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(t);
  }, []);

  const all = useMemo(() => groupActions(events?.rows ?? []), [events]);
  const inRange = useMemo(() => {
    const ms = RANGES.find((r) => r.id === range)?.ms ?? Infinity;
    return all.filter((g) => now - g.time <= ms);
  }, [all, range, now]);

  const machines = useMemo(() => [...new Set(inRange.map((g) => g.top.machine || "unknown"))].sort(), [inRange]);
  const scoped = useMemo(() => inRange.filter((g) => machine === "ALL" || (g.top.machine || "unknown") === machine), [inRange, machine]);

  const counts = useMemo(() => {
    const c: Record<Category, number> = { inj: 0, code: 0, deps: 0, cmd: 0 };
    for (const g of scoped) for (const k of g.categories) c[k] += 1;
    return c;
  }, [scoped]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return scoped.filter((g) => {
      if (verdict !== "ALL" && g.verdict !== verdict) return false;
      if (category !== "ALL" && !g.categories.has(category)) return false;
      if (!q) return true;
      const hay = g.rows
        .map((r) => [r.detector, r.title, r.summary, r.file_path, r.project, r.machine, r.os_user, r.tool, r.evidence].join(" "))
        .join(" ")
        .concat(" ", g.deps.join(" "))
        .toLowerCase();
      return hay.includes(q);
    });
  }, [scoped, verdict, category, query]);

  const newCount = useMemo(() => all.filter((g) => isNew(g.key, g.time)).length, [all, isNew]);
  const filtered = verdict !== "ALL" || category !== "ALL" || machine !== "ALL" || query.trim() !== "";

  const toggle = (key: string) => {
    setOpenKey((k) => (k === key ? null : key));
    markOpened(key);
  };
  const openFromLane = (key: string) => {
    setVerdict("ALL");
    setCategory("ALL");
    setQuery("");
    setOpenKey(key);
    markOpened(key);
    requestAnimationFrame(() => document.getElementById(`row-${encodeURIComponent(key)}`)?.scrollIntoView({ behavior: "smooth", block: "center" }));
  };
  const clear = () => {
    setVerdict("ALL");
    setCategory("ALL");
    setMachine("ALL");
    setQuery("");
  };

  const offline = status === "offline";
  const rangeLabel = RANGES.find((r) => r.id === range)?.label.toLowerCase() ?? "";
  const message = offline
    ? { error: true, text: "The dashboard server is not answering. Start it with `truviq dashboard` and this page reconnects on its own." }
    : events?.error
      ? { error: true, text: events.error }
      : null;

  return (
    <>
      <TopBar
        source={events?.source ?? null}
        offline={offline}
        range={range}
        onRange={setRange}
        updatedAt={updatedAt}
        newCount={newCount}
        onMarkSeen={markAllSeen}
      />
      {message ? (
        <div className="banner-wrap">
          <div className={`banner${message.error ? " error" : ""}`} role="status">
            {message.error ? <CircleAlert size={16} aria-hidden /> : <Info size={16} aria-hidden />}
            <span>{message.text}</span>
          </div>
        </div>
      ) : null}
      {/* One grid: triage and table on the left, fleet and red team in the rail. Below 1180px the rail
          dissolves so fleet health and the red team sit between the triage strip and the table. */}
      <main className="page">
        <h1 className="sr-only">TruViq Guard security console</h1>
        <TriageStrip groups={scoped} active={verdict} onLane={setVerdict} onOpen={openFromLane} isNew={isNew} />

        <section className="panel area-events" aria-labelledby="events-h">
          <div className="panel-head">
            <h2 id="events-h">Guarded actions</h2>
            <span className="meta num">Last {rangeLabel}</span>
          </div>
          <FilterBar
            query={query}
            onQuery={setQuery}
            category={category}
            onCategory={setCategory}
            counts={counts}
            machine={machine}
            machines={machines}
            onMachine={setMachine}
          />
          <div className="resultline num">
            <span>
              Showing {Math.min(visible.length, 300)} of {scoped.length}
              {verdict !== "ALL" ? ` · only ${VERDICT_NAME[verdict]}` : ""}
            </span>
            {filtered ? (
              <button type="button" className="link-btn" onClick={clear}>
                Clear filters
              </button>
            ) : null}
          </div>
          <EventTable
            groups={visible}
            openKey={openKey}
            onToggle={toggle}
            isNew={isNew}
            loading={!events && !offline}
            emptyTitle={filtered ? "No actions match these filters" : `No guarded actions in the last ${rangeLabel}`}
            emptyText={
              filtered
                ? "Clear the filters or widen the time range."
                : "When Claude Code blocks, asks about or warns on an action on any machine, it appears here within seconds."
            }
          />
        </section>

        <aside className="rail" aria-label="Fleet and assurance">
          <FleetPanel fleet={fleet} />
          <RedTeamPanel redteam={redteam} />
          <DetectorPanel
            groups={scoped}
            onPick={(det) => {
              setQuery(det);
              setVerdict("ALL");
              setCategory("ALL");
            }}
          />
        </aside>
      </main>
      <footer className="footer">
        <span>Read-only view. Secret values are redacted before anything is stored.</span>
        <span>Decisions are made in Claude Code; this page records them.</span>
      </footer>
    </>
  );
}
