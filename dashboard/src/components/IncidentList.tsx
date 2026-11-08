import { CircleHelp, RefreshCw } from "lucide-react";

import type { LiveState } from "../live";
import { KIND_ICONS, KIND_WORDS, liveMeaning, RED_TEAM, SIMULATED, statusMeaning, verdictMeaning, when } from "../meaning";
import type { IncidentSummary } from "../types";
import { StatusChip } from "./Chips";

interface Props {
  incidents: IncidentSummary[] | null;
  selected: number | null;
  error: string | null;
  onSelect: (id: number) => void;
  onRefresh: () => void;
  live: LiveState;
}

export function IncidentList({ incidents, selected, error, onSelect, onRefresh, live }: Props) {
  return (
    <section className="panel incidents" aria-label="Incidents">
      <div className="panel-title">
        <h2 className="label">Incidents</h2>
        <span role="status" className="live-state">
          <StatusChip meaning={liveMeaning(live)} />
        </span>
        <button type="button" className="button" onClick={onRefresh}>
          <RefreshCw aria-hidden="true" size={16} />
          Refresh
        </button>
      </div>
      {error && (
        <p role="alert" className="error-text">
          {error}
        </p>
      )}
      {incidents?.length === 0 && <p className="muted">No incidents yet.</p>}
      <ul className="incident-list">
        {incidents?.map((incident) => {
          const KindIcon = KIND_ICONS[incident.kind] ?? CircleHelp;
          return (
            <li key={incident.id}>
              <button
                type="button"
                className="incident-item"
                aria-current={incident.id === selected ? "true" : undefined}
                onClick={() => onSelect(incident.id)}
              >
                <span className="incident-line">
                  <KindIcon aria-hidden="true" size={16} />
                  <span className="sr-only">{KIND_WORDS[incident.kind] ?? incident.kind}</span>
                  <span className="mono">#{incident.id}</span>
                  <span className="subject">{incident.subjectName}</span>
                  {incident.riskScore !== null && <span className="mono risk-number">{incident.riskScore}</span>}
                </span>
                <span className="incident-line">
                  {incident.verdict ? <StatusChip meaning={verdictMeaning(incident.verdict)} /> : null}
                  <StatusChip meaning={statusMeaning(incident.status)} />
                  {incident.source === "demo" && <StatusChip meaning={SIMULATED} />}
                  {incident.source === "red_team" && <StatusChip meaning={RED_TEAM} />}
                </span>
                <span className="small muted">{when(incident.createdAt)}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
