/*
 * Adapted from "Branched Menu" by React Bits (https://reactbits.dev), MIT + Commons Clause
 * License Condition v1.0, Copyright (c) 2026 David Haz. The full notice is in
 * THIRD_PARTY_NOTICES.md. Changes: TypeScript; Lucide icons instead of Hugeicons; colours and
 * sizes from the design tokens (branched-menu.css); the active entry is controlled by the page;
 * every section starts open; aria-current="page" for the page you are on.
 */
import { useLayoutEffect, useRef, useState, type ReactNode } from "react";

interface BranchedMenuChild {
  value: string;
  label: string;
  icon?: ReactNode;
  /** A short note after the label, such as "2 waiting". */
  note?: string;
}

export interface BranchedMenuSection {
  label: string;
  children: BranchedMenuChild[];
}

interface Props {
  sections: BranchedMenuSection[];
  /** The child value that is current (the page or tab you are on). */
  active: string;
  onSelect: (value: string) => void;
  label: string;
}

// The geometry of the lines, in px. Kept here (not in CSS) because the SVG paths are drawn from it.
const ROW = 36;
const PAD = 6;
const TRUNK = 14;
const INDENT = 40;
const RADIUS = 10;
const MARK = 16;

const rowY = (k: number) => PAD + k * ROW + ROW / 2;
const r = Math.min(RADIUS, ROW / 2 - 2);
const endX = INDENT - 8;
const branch = (k: number) => `M ${TRUNK} ${rowY(k) - r} A ${r} ${r} 0 0 0 ${TRUNK + r} ${rowY(k)} H ${endX}`;
const reach = (k: number) => `M ${TRUNK} 0 V ${rowY(k) - r} A ${r} ${r} 0 0 0 ${TRUNK + r} ${rowY(k)} H ${endX}`;
const length = (k: number) => rowY(k) - r + (Math.PI * r) / 2 + (endX - TRUNK - r);

/**
 * A menu of sections, each branching from one trunk; a line traces from the trunk to the current
 * entry, and a marker on the rail follows its section. Sections fold when their heading is clicked.
 */
export function BranchedMenu({ sections, active, onSelect, label }: Props) {
  const [folded, setFolded] = useState<Set<string>>(() => new Set());
  const navRef = useRef<HTMLElement>(null);
  const heads = useRef<(HTMLButtonElement | null)[]>([]);
  const markerRef = useRef<HTMLSpanElement>(null);

  const activeSection = sections.findIndex((section) => section.children.some((child) => child.value === active));
  const markerShown = activeSection >= 0 && !folded.has(sections[activeSection].label);

  useLayoutEffect(() => {
    const place = (glide: boolean) => {
      const marker = markerRef.current;
      const head = heads.current[activeSection];
      if (!marker) {
        return;
      }
      const on = markerShown && head;
      if (!glide) {
        marker.style.transition = "none";
      }
      if (on) {
        marker.style.top = `${head.offsetTop + (head.offsetHeight - MARK) / 2}px`;
      }
      marker.toggleAttribute("data-on", Boolean(on));
      if (!glide) {
        void marker.offsetHeight;
        marker.style.transition = "";
      }
    };
    place(true);
    if (typeof ResizeObserver === "undefined" || !navRef.current) {
      return;
    }
    let first = true;
    const observer = new ResizeObserver(() => {
      if (first) {
        first = false;
        return;
      }
      place(false);
    });
    observer.observe(navRef.current);
    return () => observer.disconnect();
  }, [activeSection, markerShown, sections]);

  const toggle = (section: string) =>
    setFolded((previous) => {
      const next = new Set(previous);
      if (next.has(section)) {
        next.delete(section);
      } else {
        next.add(section);
      }
      return next;
    });

  return (
    <nav ref={navRef} className="branched-menu" aria-label={label}>
      <span ref={markerRef} className="branched-menu__marker" aria-hidden="true" />
      {sections.map((section, i) => {
        const isOpen = !folded.has(section.label);
        const bodyHeight = PAD * 2 + section.children.length * ROW;
        return (
          <div key={section.label} className="branched-menu__section" data-open={isOpen ? "" : undefined}>
            <button
              ref={(element) => {
                heads.current[i] = element;
              }}
              type="button"
              className="branched-menu__head"
              aria-expanded={isOpen}
              onClick={() => toggle(section.label)}
            >
              {section.label}
            </button>
            <div className="branched-menu__body">
              <div className="branched-menu__fold">
                <div className="branched-menu__tree" style={{ height: bodyHeight }}>
                  <svg className="branched-menu__lines" width={INDENT} height={bodyHeight} aria-hidden="true">
                    <path className="branched-menu__base" d={`M ${TRUNK} 0 V ${rowY(section.children.length - 1) - r}`} />
                    {section.children.map((child, k) => (
                      <path key={child.value} className="branched-menu__base" d={branch(k)} />
                    ))}
                    {section.children.map((child, k) => (
                      <path
                        key={child.value}
                        className="branched-menu__reach"
                        d={reach(k)}
                        style={{ strokeDasharray: length(k), strokeDashoffset: child.value === active ? 0 : length(k) }}
                      />
                    ))}
                  </svg>
                  {section.children.map((child) => (
                    <button
                      key={child.value}
                      type="button"
                      className="branched-menu__item"
                      aria-current={child.value === active ? "page" : undefined}
                      tabIndex={isOpen ? 0 : -1}
                      onClick={() => onSelect(child.value)}
                    >
                      {child.icon && (
                        <span className="branched-menu__icon" aria-hidden="true">
                          {child.icon}
                        </span>
                      )}
                      <span className="branched-menu__label">{child.label}</span>
                      {child.note && <span className="tab-note">{child.note}</span>}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        );
      })}
    </nav>
  );
}
