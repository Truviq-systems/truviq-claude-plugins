"use client";

import { Search } from "lucide-react";
import { CATEGORIES } from "@/lib/model";
import type { Category } from "@/lib/types";

interface Props {
  query: string;
  onQuery: (q: string) => void;
  category: Category | "ALL";
  onCategory: (c: Category | "ALL") => void;
  counts: Record<Category, number>;
  machine: string;
  machines: string[];
  onMachine: (m: string) => void;
}

export function FilterBar({ query, onQuery, category, onCategory, counts, machine, machines, onMachine }: Props) {
  return (
    <div className="filters">
      <label className="search">
        <span className="sr-only">Search events</span>
        <Search size={16} aria-hidden />
        <input
          type="search"
          value={query}
          onChange={(e) => onQuery(e.target.value)}
          placeholder="Search file, package, detector, machine…"
        />
      </label>
      <label>
        <span className="sr-only">Machine</span>
        <select className="select" value={machine} onChange={(e) => onMachine(e.target.value)}>
          <option value="ALL">All machines</option>
          {machines.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
      </label>
      <div className="chips" role="group" aria-label="Category">
        {CATEGORIES.map((c) => {
          const pressed = category === c.id;
          return (
            <button key={c.id} type="button" className="chip" aria-pressed={pressed} onClick={() => onCategory(pressed ? "ALL" : c.id)}>
              {c.label} <span className="num">{counts[c.id]}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
