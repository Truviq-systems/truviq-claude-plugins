"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { EventsPayload, FleetPayload, RedTeamPayload } from "./types";

type Status = "loading" | "ok" | "offline";

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(path, { cache: "no-store", headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`${path} answered ${res.status}`);
  return (await res.json()) as T;
}

/** Polls the plugin's read-only API: events every 5 s, fleet and red team every 30 s. */
export function useGuardData() {
  const [events, setEvents] = useState<EventsPayload | null>(null);
  const [fleet, setFleet] = useState<FleetPayload | null>(null);
  const [redteam, setRedteam] = useState<RedTeamPayload | null>(null);
  const [status, setStatus] = useState<Status>("loading");
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const alive = useRef(true);

  const loadEvents = useCallback(async () => {
    try {
      const d = await getJson<EventsPayload>("/api/events");
      if (!alive.current) return;
      setEvents({ ...d, rows: Array.isArray(d.rows) ? d.rows : [] });
      setStatus("ok");
      setUpdatedAt(Date.now());
    } catch {
      if (alive.current) setStatus("offline");
    }
  }, []);

  const loadSide = useCallback(async () => {
    const [f, r] = await Promise.allSettled([getJson<FleetPayload>("/api/fleet"), getJson<RedTeamPayload>("/api/redteam")]);
    if (!alive.current) return;
    if (f.status === "fulfilled") setFleet(f.value);
    if (r.status === "fulfilled") setRedteam(r.value);
  }, []);

  useEffect(() => {
    alive.current = true;
    loadEvents();
    loadSide();
    const a = setInterval(loadEvents, 5000);
    const b = setInterval(loadSide, 30000);
    return () => {
      alive.current = false;
      clearInterval(a);
      clearInterval(b);
    };
  }, [loadEvents, loadSide]);

  return { events, fleet, redteam, status, updatedAt, refresh: loadEvents };
}

const SEEN_KEY = "truviq.dashboard.seen.v1";

/** "New since you looked": persists the moment you last caught up, plus actions opened individually. */
export function useSeen() {
  const [since, setSince] = useState<number>(() => Date.now());
  const [opened, setOpened] = useState<Set<string>>(new Set());

  useEffect(() => {
    try {
      const raw = localStorage.getItem(SEEN_KEY);
      if (raw) {
        const d = JSON.parse(raw) as { since?: number; opened?: string[] };
        if (typeof d.since === "number") setSince(d.since);
        if (Array.isArray(d.opened)) setOpened(new Set(d.opened.slice(-2000)));
      } else {
        // First visit: nothing has been looked at yet, so everything in view is new until marked seen.
        setSince(0);
        localStorage.setItem(SEEN_KEY, JSON.stringify({ since: 0, opened: [] }));
      }
    } catch {
      /* storage unavailable: everything simply starts as seen */
    }
  }, []);

  const persist = (s: number, o: Set<string>) => {
    try {
      localStorage.setItem(SEEN_KEY, JSON.stringify({ since: s, opened: [...o].slice(-2000) }));
    } catch {
      /* ignore */
    }
  };

  const isNew = useCallback((key: string, time: number) => time > since && !opened.has(key), [since, opened]);
  const markOpened = useCallback(
    (key: string) => {
      setOpened((prev) => {
        if (prev.has(key)) return prev;
        const next = new Set(prev).add(key);
        persist(since, next);
        return next;
      });
    },
    [since],
  );
  const markAllSeen = useCallback(() => {
    const now = Date.now();
    setSince(now);
    setOpened(new Set());
    persist(now, new Set());
  }, []);

  return { isNew, markOpened, markAllSeen };
}
