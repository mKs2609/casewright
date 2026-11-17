import { ArrowLeft, FileText, Fingerprint, UserRoundCheck, type LucideIcon } from "lucide-react";
import { useEffect, useRef, useState, type KeyboardEvent } from "react";

import type { IncidentDetail, User } from "../types";
import { Actions } from "./Actions";
import { EvidenceTimeline, IncidentHeader } from "./Investigation";
import { RedTeamCard } from "./RedTeamCard";
import { Reports } from "./Reports";

export type Tab = "evidence" | "reports" | "actions";

interface Props {
  incident: IncidentDetail;
  user: User;
  highlighted: string | null;
  onCite: (label: string) => void;
  onDecided: () => void;
  onBack: () => void;
  tab: Tab;
  onTab: (tab: Tab) => void;
}

/**
 * One incident on its own page: what it is and its risk at the top, then three tabs (the WAI-ARIA
 * tabs pattern: arrow keys move between them, only the open one is shown).
 */
export function IncidentPage({ incident, user, highlighted, onCite, onDecided, onBack, tab, onTab }: Props) {
  const waiting = incident.actions.filter((action) => action.status === "pending").length;
  const tabs: { id: Tab; word: string; Icon: LucideIcon; note?: string }[] = [
    { id: "evidence", word: "Evidence", Icon: Fingerprint, note: String(incident.evidence.length) },
    { id: "reports", word: "Reports", Icon: FileText },
    { id: "actions", word: "Actions", Icon: UserRoundCheck, note: waiting > 0 ? `${waiting} waiting` : undefined },
  ];
  const buttons = useRef<Record<Tab, HTMLButtonElement | null>>({ evidence: null, reports: null, actions: null });

  function onKey(event: KeyboardEvent) {
    const at = tabs.findIndex((t) => t.id === tab);
    const next =
      event.key === "ArrowRight" ? (at + 1) % tabs.length
      : event.key === "ArrowLeft" ? (at + tabs.length - 1) % tabs.length
      : event.key === "Home" ? 0
      : event.key === "End" ? tabs.length - 1
      : null;
    if (next !== null) {
      event.preventDefault();
      onTab(tabs[next].id);
      buttons.current[tabs[next].id]?.focus();
    }
  }

  return (
    <section className="page incident-page" aria-label="Investigation">
      <button type="button" className="button back" onClick={onBack}>
        <ArrowLeft aria-hidden="true" size={16} />
        All incidents
      </button>
      <IncidentHeader incident={incident} />
      {waiting > 0 && tab !== "actions" && (
        <p className="notice waiting-note">
          {waiting === 1 ? "1 action is" : `${waiting} actions are`} waiting for a decision.{" "}
          <button type="button" className="text-button" onClick={() => onTab("actions")}>
            Open Actions
          </button>
        </p>
      )}
      <div role="tablist" aria-label="Incident" className="tabs" onKeyDown={onKey}>
        {tabs.map(({ id, word, Icon, note }) => (
          <button
            key={id}
            ref={(element) => {
              buttons.current[id] = element;
            }}
            type="button"
            role="tab"
            id={`tab-${id}`}
            aria-selected={tab === id}
            aria-controls={`panel-${id}`}
            tabIndex={tab === id ? 0 : -1}
            className="tab"
            onClick={() => onTab(id)}
          >
            <Icon aria-hidden="true" size={16} />
            {word}
            {note && <span className="tab-note">{note}</span>}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} className="tab-panel">
        {tab === "evidence" && (
          <>
            {incident.source === "red_team" && <RedTeamCard incident={incident} />}
            <EvidenceTimeline incident={incident} highlighted={highlighted} />
          </>
        )}
        {tab === "reports" && <Reports verdict={incident.verdict} onCite={onCite} />}
        {tab === "actions" &&
          (incident.actions.length > 0 ? (
            <Actions actions={incident.actions} evidence={incident.evidence} user={user} onCite={onCite} onDecided={onDecided} />
          ) : (
            <p className="muted">No actions were proposed for this incident.</p>
          ))}
      </div>
    </section>
  );
}

/** After an evidence chip is clicked, the Evidence tab opens; then that step gets the focus and scrolls into view. */
export function useFocusEvidence(tab: Tab, highlighted: string | null) {
  const [pending, setPending] = useState<string | null>(null);
  useEffect(() => {
    if (tab === "evidence" && pending) {
      const target = document.getElementById(`evidence-${pending}`);
      target?.focus({ preventScroll: true });
      target?.scrollIntoView?.({ block: "center" });
      setPending(null);
    }
  }, [tab, pending, highlighted]);
  return setPending;
}
