import { useEffect, useRef, useState } from "react";

/** How long a number takes to count to its new value. */
const COUNT_MS = 600;

/**
 * True when motion should not play: the visitor asked for reduced motion, or the browser cannot
 * say (as in tests), in which case the final state is simply shown.
 */
export function prefersStill(): boolean {
  return typeof window.matchMedia !== "function" || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * A number that counts up from 0 when it first appears, and from its previous value when it
 * changes, easing out; when motion is off it is simply the number.
 */
export function CountUp({ value }: { value: number }) {
  const [shown, setShown] = useState(() => (prefersStill() ? value : 0));
  const from = useRef(prefersStill() ? value : 0);

  useEffect(() => {
    const start = from.current;
    from.current = value;
    if (start === value || prefersStill()) {
      setShown(value);
      return;
    }
    const began = performance.now();
    let frame = requestAnimationFrame(function step(now) {
      const t = Math.min((now - began) / COUNT_MS, 1);
      const eased = 1 - (1 - t) ** 3;
      setShown(Math.round(start + (value - start) * eased));
      if (t < 1) {
        frame = requestAnimationFrame(step);
      }
    });
    return () => cancelAnimationFrame(frame);
  }, [value]);

  return <>{shown}</>;
}

/** Grey shapes where content is about to appear; screen readers hear "Loading...". */
export function Skeleton({ kind }: { kind: "page" | "cards" }) {
  return (
    <div className={`skeleton skeleton-${kind}`} aria-busy="true">
      <span className="sr-only">Loading...</span>
      {kind === "page" && <span className="skeleton-bar skeleton-title" aria-hidden="true" />}
      <div className={kind === "cards" ? "skeleton-grid" : "skeleton-stack"} aria-hidden="true">
        {[1, 2, 3, 4].map((n) => (
          <span key={n} className="skeleton-bar skeleton-block" />
        ))}
      </div>
    </div>
  );
}
