import { useState } from "react";

import { api } from "../api";
import { ACTION_WORDS, actionStatusMeaning, when } from "../meaning";
import type { Action, Evidence, User } from "../types";
import { EvidenceChip, SignalChip, StatusChip } from "./Chips";

const canDecide = (user: User) => user.role === "ANALYST" || user.role === "ADMIN";

interface ApprovalProps {
  action: Action;
  step: Evidence | undefined;
  user: User;
  onCite: (label: string) => void;
  onDecided: () => void;
}

/** A human decision: the evidence comes first, above the buttons. */
function ApprovalCard({ action, step, user, onCite, onDecided }: ApprovalProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const words = ACTION_WORDS[action.action];

  async function decide(decision: "approve" | "reject") {
    setBusy(true);
    setError(null);
    try {
      await api.decide(action.id, decision);
      onDecided();
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not save your decision. Try again.");
      setBusy(false);
    }
  }

  return (
    <li className="card approval" aria-label={`Decision needed: ${words?.name ?? action.action}`}>
      <div className="step-head">
        <strong>{words?.name ?? action.action}</strong>
        <span className="mono target">{action.target}</span>
      </div>
      <div className="approval-evidence">
        <EvidenceChip label={action.evidence} onCite={onCite} />
        <span>{step?.summary}</span>
        {step && step.signals.length > 0 && (
          <div className="chip-row">
            {step.signals.map((signal) => (
              <SignalChip key={signal.id + (signal.indicator ?? "")} signal={signal} />
            ))}
          </div>
        )}
      </div>
      {action.expiresAt && <p className="small muted">Must be decided by {when(action.expiresAt)}</p>}
      {canDecide(user) ? (
        <div className="button-row">
          <button type="button" className="button button-danger" disabled={busy} onClick={() => decide("approve")}>
            {words?.approve ?? "Approve"}
          </button>
          <button type="button" className="button" disabled={busy} onClick={() => decide("reject")}>
            Reject
          </button>
        </div>
      ) : (
        <p className="small muted">Only analysts and admins can decide this.</p>
      )}
      {error && (
        <p role="alert" className="error-text">
          {error}
        </p>
      )}
    </li>
  );
}

function DoneRow({ action, onCite }: { action: Action; onCite: (label: string) => void }) {
  return (
    <li className="action-row">
      <span>
        {ACTION_WORDS[action.action]?.name ?? action.action} <span className="mono target">{action.target}</span>{" "}
        <EvidenceChip label={action.evidence} onCite={onCite} />
      </span>
      <span className="chip-row">
        <StatusChip meaning={actionStatusMeaning(action.status)} />
        {action.decidedBy && <span className="small muted">by {action.decidedBy}</span>}
      </span>
    </li>
  );
}

interface Props {
  actions: Action[];
  evidence: Evidence[];
  user: User;
  onCite: (label: string) => void;
  onDecided: () => void;
}

export function Actions({ actions, evidence, user, onCite, onDecided }: Props) {
  if (actions.length === 0) {
    return null;
  }
  const waiting = actions.filter((action) => action.status === "pending");
  const others = actions.filter((action) => action.status !== "pending");
  return (
    <section aria-label="Actions">
      {waiting.length > 0 && (
        <>
          <h3 className="label">Waiting for your decision</h3>
          <ul className="stack">
            {waiting.map((action) => (
              <ApprovalCard
                key={action.id}
                action={action}
                step={evidence.find((step) => step.label === action.evidence)}
                user={user}
                onCite={onCite}
                onDecided={onDecided}
              />
            ))}
          </ul>
        </>
      )}
      {others.length > 0 && (
        <>
          <h3 className="label">Actions</h3>
          <p className="small muted">Enforcement is simulated: nothing real is blocked.</p>
          <ul className="stack">
            {others.map((action) => (
              <DoneRow key={action.id} action={action} onCite={onCite} />
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
