/*
 * Adapted from "Lattice Loader" by React Bits (https://reactbits.dev), MIT + Commons Clause
 * License Condition v1.0, Copyright (c) 2026 David Haz. The full notice is in
 * THIRD_PARTY_NOTICES.md. Changes: TypeScript; one pattern (the 3 x 3 orbit); colours and sizes
 * from the design tokens (lattice-loader.css); the stopwatch counts from a given moment (when the
 * incident was submitted), not from when the page opened; no live region of its own (the page
 * already announces changes politely), only text for screen readers.
 */
import { useLayoutEffect, useRef } from "react";

/** The orbit: a wave travelling round the edge of a 3 x 3 lattice, the centre left dark. */
const ORBIT = [0, 1, 2, 7, null, 3, 6, 5, 4];
const LOOP = 8;
const SCALE = 1.2;
const STEP_MS = 90;
const MARKS = { done: [2, 3, 5, 7], error: [0, 2, 4, 6, 8] };

const tenths = (ms: number) => Math.max(0, Math.floor(ms / 100));
const shown = (ds: number) => (ds < 600 ? `${(ds / 10).toFixed(1)}s` : `${Math.floor(ds / 600)}m ${((ds % 600) / 10).toFixed(1)}s`);

interface Props {
  status: "working" | "done" | "error";
  label: string;
  /** When the work began (ms since 1970): the stopwatch counts from here. */
  startedAt?: number;
  showTimer?: boolean;
}

/** A small lattice whose cells brighten in a wave while the work runs, beside a stopwatch. */
export function LatticeLoader({ status, label, startedAt, showTimer = true }: Props) {
  const timer = useRef<HTMLSpanElement>(null);
  const delay = STEP_MS * SCALE;
  const cycle = Math.round(LOOP * delay);
  const mark = status === "error" ? "error" : "done";

  useLayoutEffect(() => {
    if (!showTimer || status !== "working") {
      return;
    }
    const from = startedAt ?? Date.now();
    const paint = () => {
      if (timer.current) {
        timer.current.textContent = shown(tenths(Date.now() - from));
      }
    };
    paint();
    const id = window.setInterval(paint, 100);
    return () => window.clearInterval(id);
  }, [status, startedAt, showTimer]);

  return (
    <span className="lattice-loader" data-status={status} style={{ ["--ll-cycle" as string]: `${cycle}ms` }}>
      <span className="lattice-loader__grid" aria-hidden="true">
        <span className="lattice-loader__layer lattice-loader__run">
          {ORBIT.map((unit, i) => (
            <span
              key={i}
              className="lattice-loader__cell"
              data-hole={unit === null ? "" : undefined}
              style={unit === null ? undefined : { animationDelay: `${Math.round(unit * delay)}ms` }}
            />
          ))}
        </span>
        <span className="lattice-loader__layer lattice-loader__mark">
          {ORBIT.map((_, i) => (
            <span key={i} className="lattice-loader__cell" data-on={MARKS[mark].includes(i) ? "" : undefined} />
          ))}
        </span>
      </span>
      <span className="lattice-loader__label">{label}</span>
      {showTimer && status === "working" && <span ref={timer} className="lattice-loader__timer mono" aria-hidden="true" />}
    </span>
  );
}
