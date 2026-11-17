import { Crosshair, Play } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";

import { api } from "../api";
import type { DemoScenario, IncidentDetail, User } from "../types";

/** Not a scenario name (those are lowercase words), so it can never clash with one. */
const RED_TEAM = "Red team";

interface Props {
  user: User;
  onStarted: (incident: IncidentDetail) => void;
}

const RED_TEAM_WORDS =
  "A scripted, hijacked model follows the trick email's hidden note. Every attempt it makes is shown, with what stopped it.";

/**
 * The Scenarios page (FR-26): each demo as a card with what it is and its button. Each names a
 * made-up incident the gateway keeps; the browser sends only the name. When the gateway has demos
 * switched off, the page says so. A viewer sees the buttons disabled, but the gateway's role
 * check is what stops them.
 */
export function Scenarios({ user, onStarted }: Props) {
  const [scenarios, setScenarios] = useState<DemoScenario[] | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.demoScenarios().then(setScenarios, () => setScenarios([]));
  }, []);

  if (scenarios === null) {
    return <p className="muted loading">Loading...</p>;
  }
  if (scenarios.length === 0) {
    return (
      <div className="page">
        <h1 className="page-title">Scenarios</h1>
        <p className="muted">Demo scenarios are switched off on this site.</p>
      </div>
    );
  }
  const allowed = user.role === "ANALYST" || user.role === "ADMIN";

  const run = async (name: string) => {
    setRunning(name);
    setError(null);
    try {
      onStarted(await (name === RED_TEAM ? api.startRedTeam() : api.runScenario(name)));
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not start the scenario. Try again.");
    } finally {
      setRunning(null);
    }
  };

  const card = (key: string, words: string, button: ReactNode) => (
    <li key={key} className="card scenario">
      <p>{words}</p>
      {button}
    </li>
  );

  return (
    <div className="page">
      <h1 className="page-title">Scenarios</h1>
      <p className="muted">
        {allowed ? "Made-up incidents about fictional employees, investigated for real." : "Only analysts and admins can run scenarios."}
      </p>
      {error && (
        <p role="alert" className="error-text">
          {error}
        </p>
      )}
      <section aria-label="Demo scenarios">
        <ul className="scenario-grid">
          {scenarios.map((scenario, index) =>
            card(
              scenario.name,
              scenario.description,
              <button
                type="button"
                className={index === 0 ? "button button-primary" : "button"}
                disabled={!allowed || running !== null}
                // Read out as the button's description, as well as shown on the card.
                title={scenario.description}
                onClick={() => void run(scenario.name)}
              >
                {index === 0 && <Play aria-hidden="true" size={16} />}
                {running === scenario.name ? "Starting..." : scenario.title}
              </button>,
            ),
          )}
          {card(
            RED_TEAM,
            RED_TEAM_WORDS,
            <button
              type="button"
              className="button"
              disabled={!allowed || running !== null}
              title={RED_TEAM_WORDS}
              onClick={() => void run(RED_TEAM)}
            >
              <Crosshair aria-hidden="true" size={16} />
              {running === RED_TEAM ? "Starting..." : "Red-team the agent"}
            </button>,
          )}
        </ul>
      </section>
    </div>
  );
}
