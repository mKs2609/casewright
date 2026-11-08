import { Crosshair, Play } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "../api";
import type { DemoScenario, IncidentDetail, User } from "../types";

/** Not a scenario name (those are lowercase words), so it can never clash with one. */
const RED_TEAM = "Red team";

interface Props {
  user: User;
  onStarted: (incident: IncidentDetail) => void;
}

/**
 * The demo buttons (FR-26). Each names a made-up incident the gateway keeps; the browser sends
 * only the name. Hidden when the gateway has demos switched off. A viewer sees them disabled,
 * but the gateway's role check is what stops them.
 */
export function Scenarios({ user, onStarted }: Props) {
  const [scenarios, setScenarios] = useState<DemoScenario[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.demoScenarios().then(setScenarios, () => setScenarios([]));
  }, []);

  if (scenarios.length === 0) {
    return null;
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

  return (
    <section className="demo-bar" aria-label="Demo scenarios">
      <h2 className="label">Try a scenario</h2>
      <div className="button-row">
        {scenarios.map((scenario, index) => (
          <button
            key={scenario.name}
            type="button"
            className={index === 0 ? "button button-primary" : "button"}
            disabled={!allowed || running !== null}
            // Shown on hover, and read out as the button's description.
            title={scenario.description}
            onClick={() => void run(scenario.name)}
          >
            {index === 0 && <Play aria-hidden="true" size={16} />}
            {running === scenario.name ? "Starting..." : scenario.title}
          </button>
        ))}
        <button
          type="button"
          className="button"
          disabled={!allowed || running !== null}
          title="A scripted, hijacked model follows the trick email's hidden note. Every attempt it makes is shown, with what stopped it."
          onClick={() => void run(RED_TEAM)}
        >
          <Crosshair aria-hidden="true" size={16} />
          {running === RED_TEAM ? "Starting..." : "Red-team the agent"}
        </button>
      </div>
      <p className="small muted">
        {allowed ? "Made-up incidents about fictional employees, investigated for real." : "Only analysts and admins can run scenarios."}
      </p>
      {error && (
        <p role="alert" className="error-text">
          {error}
        </p>
      )}
    </section>
  );
}
