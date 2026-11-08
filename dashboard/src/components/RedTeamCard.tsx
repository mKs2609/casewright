import { useEffect, useRef, useState } from "react";

import { api } from "../api";
import { redTeamOutcomeMeaning } from "../meaning";
import type { IncidentDetail, RedTeamCard as Card } from "../types";
import { StatusChip } from "./Chips";

function headline(card: Card): string {
  if (card.state === "failed") {
    return "This run stopped before it finished, so it shows nothing about the checks.";
  }
  if (card.state === "running") {
    return `${card.blocked} of ${card.attempts} attempts blocked so far.`;
  }
  return card.blocked === card.attempts
    ? `All ${card.attempts} attempts were blocked.`
    : `${card.attempts - card.blocked} of ${card.attempts} attempts were NOT blocked.`;
}

/**
 * The red-team scorecard (FR-27): what the hijacked model tried and what stopped it. The gateway
 * judges every row from what it stored; this only shows it. Reloaded whenever the incident changes.
 */
export function RedTeamCard({ incident }: { incident: IncidentDetail }) {
  const [card, setCard] = useState<Card | null>(null);
  const [error, setError] = useState<string | null>(null);
  const latest = useRef(0);

  useEffect(() => {
    const request = ++latest.current;
    api.redTeamScorecard(incident.id).then(
      (loaded) => {
        if (request === latest.current) {
          setCard(loaded);
          setError(null);
        }
      },
      (failure: unknown) => {
        if (request === latest.current) {
          setError(failure instanceof Error ? failure.message : "Could not load the scorecard.");
        }
      },
    );
  }, [incident]);

  return (
    <section className="card red-team" aria-label="Red-team scorecard">
      <h3 className="label">What the hijacked model tried</h3>
      {error && (
        <p role="alert" className="error-text">
          {error}
        </p>
      )}
      {card && card.incidentId === incident.id && (
        <>
          <p className={card.state === "finished" && card.blocked !== card.attempts ? "notice" : ""}>{headline(card)}</p>
          <ul className="red-team-rows">
            {card.rows.map((row) => (
              <li key={row.attempt} className="red-team-row">
                <StatusChip meaning={redTeamOutcomeMeaning(row.outcome)} />
                <span>
                  {row.attempt}
                  <span className="small muted"> · {row.stoppedBy}</span>
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}
