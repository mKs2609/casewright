import type { Meaning } from "../meaning";
import type { Signal } from "../types";

export function StatusChip({ meaning }: { meaning: Meaning }) {
  const { Icon, word, tone } = meaning;
  return (
    <span className={`chip tone-${tone}`}>
      <Icon aria-hidden="true" size={14} />
      {word}
    </span>
  );
}

/** A reference like E3. Always a button: clicking it goes to that step. */
export function EvidenceChip({ label, onCite }: { label: string; onCite: (label: string) => void }) {
  return (
    <button type="button" className="evidence-chip" aria-label={`Go to evidence ${label}`} onClick={() => onCite(label)}>
      {label}
    </button>
  );
}

export function SignalChip({ signal }: { signal: Signal }) {
  const strength = signal.weight >= 30 ? "strong" : signal.weight > 0 ? "some" : "none";
  return (
    <span className={`signal-chip signal-${strength}`}>
      {signal.label} <span className="weight">+{signal.weight}</span>
    </span>
  );
}
