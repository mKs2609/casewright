import { FileWarning, Inbox, OctagonX, ShieldCheck, UserRoundCheck, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

import { isAttack, isWaiting, ofKind, shown, type Filters, type KindChoice, type Show } from "../filters";
import { CountUp, Skeleton } from "../motion";
import type { AuditCheck, IncidentSummary } from "../types";
import { IncidentList } from "./IncidentList";
import type { Tab } from "./IncidentPage";

interface Props {
  incidents: IncidentSummary[] | null;
  audit: AuditCheck | null;
  error: string | null;
  filters: Filters;
  onFilter: (filters: Filters) => void;
  /** Opens an incident, on the given tab (the Evidence tab unless said otherwise). */
  onOpen: (id: number, tab?: Tab) => void;
}

function FigureContent({ Icon, value, words }: { Icon: LucideIcon; value: number | string; words: string }) {
  return (
    <>
      <span className="label">
        <Icon aria-hidden="true" size={14} />
        {words}
      </span>
      <span className="figure-value">{typeof value === "number" ? <CountUp value={value} /> : value}</span>
    </>
  );
}

/** A figure that is also a filter: pressed while its incidents are the ones shown below. */
function FilterFigure({ pressed, onClick, children }: { pressed: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <li>
      <button type="button" className="figure card figure-button" aria-pressed={pressed} onClick={onClick}>
        {children}
      </button>
    </li>
  );
}

const TYPE_CHOICES: { choice: KindChoice; words: string }[] = [
  { choice: "all", words: "All" },
  { choice: "email", words: "Email" },
  { choice: "sign-ins", words: "Sign-ins" },
  { choice: "calls", words: "Phone calls" },
];

const SHOW_WORDS: Record<Exclude<Show, "all">, string> = { attacks: "attacks", waiting: "waiting for a decision" };

/**
 * The first page after logging in: a few figures at a glance, which also filter the incidents below
 * (attacks, or those waiting for a decision), a row of types, then the incidents.
 */
export function Overview({ incidents, audit, error, filters, onFilter, onOpen }: Props) {
  const ofType = incidents?.filter(ofKind(filters.kind)) ?? null;
  const count = (keep: (incident: IncidentSummary) => boolean) => (ofType ? ofType.filter(keep).length : "–");
  const visible = ofType?.filter(shown(filters.show)) ?? null;
  const filtered = filters.show !== "all" || filters.kind !== "all";

  const showOnly = (show: Show) => onFilter({ ...filters, show: filters.show === show ? "all" : show });
  // With exactly one incident waiting, its decision is one click away: open it on its Actions tab.
  const openWaiting = () => {
    const waiting = ofType?.filter(isWaiting) ?? [];
    if (waiting.length === 1 && filters.show !== "waiting") {
      onOpen(waiting[0].id, "actions");
    } else {
      showOnly("waiting");
    }
  };

  return (
    <div className="page">
      <h1 className="page-title">Overview</h1>
      <ul className="figures" aria-label="At a glance">
        <FilterFigure pressed={filters.show === "all"} onClick={() => onFilter({ ...filters, show: "all" })}>
          <FigureContent Icon={Inbox} value={count(() => true)} words="Incidents" />
        </FilterFigure>
        <FilterFigure pressed={filters.show === "attacks"} onClick={() => showOnly("attacks")}>
          <FigureContent Icon={OctagonX} value={count(isAttack)} words="Attacks found" />
        </FilterFigure>
        <FilterFigure pressed={filters.show === "waiting"} onClick={openWaiting}>
          <FigureContent Icon={UserRoundCheck} value={count(isWaiting)} words="Waiting for a decision" />
        </FilterFigure>
        <li className="figure card">
          {audit && !audit.valid ? (
            <FigureContent Icon={FileWarning} value="Tampered" words="Audit log" />
          ) : (
            <FigureContent Icon={ShieldCheck} value={audit ? audit.entries : "–"} words="Audit log entries" />
          )}
        </li>
      </ul>

      <div className="filter-row">
        <div className="filter-group" role="group" aria-label="Type">
          {TYPE_CHOICES.map(({ choice, words }) => (
            <button
              key={choice}
              type="button"
              className="filter"
              aria-pressed={filters.kind === choice}
              onClick={() => onFilter({ ...filters, kind: choice })}
            >
              {words}
              {incidents && <span className="filter-count">{incidents.filter(ofKind(choice)).length}</span>}
            </button>
          ))}
        </div>
        {filtered && visible && incidents && (
          <p className="small muted filter-summary">
            Showing {visible.length} of {incidents.length}
            {filters.show !== "all" && <> ({SHOW_WORDS[filters.show]})</>}.{" "}
            <button type="button" className="text-button" onClick={() => onFilter({ show: "all", kind: "all" })}>
              Show all
            </button>
          </p>
        )}
      </div>

      {incidents === null && !error ? (
        <Skeleton kind="cards" />
      ) : (
        <IncidentList
          incidents={visible}
          selected={null}
          error={error}
          empty={filtered ? "No incidents match these filters." : "No incidents yet."}
          // Waiting incidents open where the decision is made.
          onSelect={(id) => onOpen(id, filters.show === "waiting" ? "actions" : undefined)}
        />
      )}
    </div>
  );
}
