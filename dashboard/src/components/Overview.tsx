import { FileWarning, Inbox, OctagonX, ShieldCheck, UserRoundCheck, type LucideIcon } from "lucide-react";

import type { AuditCheck, IncidentSummary } from "../types";
import { IncidentList } from "./IncidentList";

interface Props {
  incidents: IncidentSummary[] | null;
  audit: AuditCheck | null;
  error: string | null;
  onOpen: (id: number) => void;
}

function Figure({ Icon, value, words }: { Icon: LucideIcon; value: string; words: string }) {
  return (
    <div className="figure card">
      <dt className="label">
        <Icon aria-hidden="true" size={14} />
        {words}
      </dt>
      <dd className="figure-value">{value}</dd>
    </div>
  );
}

/** The first page after logging in: a few figures at a glance, then every incident. */
export function Overview({ incidents, audit, error, onOpen }: Props) {
  const count = (keep: (incident: IncidentSummary) => boolean) => (incidents ? String(incidents.filter(keep).length) : "–");
  return (
    <div className="page">
      <h1 className="page-title">Overview</h1>
      <dl className="figures" aria-label="At a glance">
        <Figure Icon={Inbox} value={count(() => true)} words="Incidents" />
        <Figure Icon={OctagonX} value={count((i) => i.verdict === "malicious")} words="Attacks found" />
        <Figure Icon={UserRoundCheck} value={count((i) => i.status === "awaiting_approval")} words="Waiting for a decision" />
        {audit && !audit.valid ? (
          <Figure Icon={FileWarning} value="Tampered" words="Audit log" />
        ) : (
          <Figure Icon={ShieldCheck} value={audit ? String(audit.entries) : "–"} words="Audit log entries" />
        )}
      </dl>
      <IncidentList incidents={incidents} selected={null} error={error} onSelect={onOpen} />
    </div>
  );
}
