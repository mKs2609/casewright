import {
  CircleHelp,
  FileText,
  Fingerprint,
  FlaskConical,
  LayoutDashboard,
  LogOut,
  Radar,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  UserRoundCheck,
} from "lucide-react";
import { useState } from "react";

import type { LiveState } from "../live";
import { liveMeaning } from "../meaning";
import type { AuditCheck, User } from "../types";
import { BranchedMenu, type BranchedMenuSection } from "./BranchedMenu";
import { StatusChip } from "./Chips";
import type { Tab } from "./IncidentPage";

export type Page = "overview" | "scenarios";

const ADDRESSES: Record<Page, string> = { overview: "#/", scenarios: "#/scenarios" };

/** The open incident, for its branch of the menu: its number and how many decisions wait. */
export interface OpenIncident {
  id: number;
  waiting: number;
  tab: Tab;
}

function AuditBadge({ check }: { check: AuditCheck | null }) {
  if (!check) {
    return (
      <span className="chip tone-muted">
        <CircleHelp aria-hidden="true" size={14} />
        Audit log not checked
      </span>
    );
  }
  if (!check.valid) {
    return (
      <span className="chip tone-malicious">
        <ShieldAlert aria-hidden="true" size={14} />
        Audit log tampered at entry {check.brokenAt}
      </span>
    );
  }
  return (
    <span className="chip tone-benign">
      <ShieldCheck aria-hidden="true" size={14} />
      Audit log intact
    </span>
  );
}

interface Props {
  current: Page | null;
  incident: OpenIncident | null;
  onTab: (tab: Tab) => void;
  user: User;
  audit: AuditCheck | null;
  live: LiveState;
  onGo: (address: string) => void;
  /** Reloads everything; resolves when it is done. */
  onRefresh: () => Promise<void>;
  onLogout: () => void;
}

/**
 * The dashboard's menu: a branched menu of the pages and, when an incident is open, its tabs; then
 * who is logged in. Pages are addresses (#/, #/scenarios), changed by buttons: no links are built.
 */
export function Sidebar({ current, incident, onTab, user, audit, live, onGo, onRefresh, onLogout }: Props) {
  const sections: BranchedMenuSection[] = [
    {
      label: "Dashboard",
      children: [
        { value: "overview", label: "Overview", icon: <LayoutDashboard size={16} /> },
        { value: "scenarios", label: "Scenarios", icon: <FlaskConical size={16} /> },
      ],
    },
  ];
  if (incident) {
    sections.push({
      label: `Incident #${incident.id}`,
      children: [
        { value: "tab:evidence", label: "Evidence", icon: <Fingerprint size={16} /> },
        { value: "tab:reports", label: "Reports", icon: <FileText size={16} /> },
        {
          value: "tab:actions",
          label: "Actions",
          icon: <UserRoundCheck size={16} />,
          note: incident.waiting > 0 ? `${incident.waiting} waiting` : undefined,
        },
      ],
    });
  }
  // Refresh says what it did: the icon turns while it works, then the time it finished. With the
  // live feed on there is often nothing new, and without this it would look as if nothing happened.
  const [refreshing, setRefreshing] = useState(false);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const refresh = () => {
    setRefreshing(true);
    onRefresh().finally(() => {
      setRefreshing(false);
      setUpdatedAt(new Date());
    });
  };
  const active = incident ? `tab:${incident.tab}` : (current ?? "");
  const select = (value: string) => {
    if (value.startsWith("tab:")) {
      onTab(value.slice(4) as Tab);
    } else {
      onGo(ADDRESSES[value as Page]);
    }
  };

  return (
    <aside className="sidebar">
      <span className="brand">
        <span className="logo-tile">
          <Radar aria-hidden="true" size={18} />
        </span>
        <strong className="product">Casewright</strong>
      </span>
      <BranchedMenu label="Pages" sections={sections} active={active} onSelect={select} />
      <div className="sidebar-foot">
        {/* The system's state: whether updates arrive by themselves (Refresh works either way), and
            whether the audit log verifies. */}
        <div className="sidebar-group">
          <div className="sidebar-status">
            <span role="status">
              <StatusChip meaning={liveMeaning(live)} />
            </span>
            <AuditBadge check={audit} />
          </div>
          <button type="button" className="button" onClick={refresh} aria-busy={refreshing}>
            <RefreshCw aria-hidden="true" size={16} className={refreshing ? "spin" : undefined} />
            Refresh
          </button>
          {updatedAt && <span className="small muted">Updated {updatedAt.toLocaleTimeString()}</span>}
        </div>
        {/* Who is logged in. */}
        <div className="sidebar-group sidebar-account">
          <span className="user">
            <span className="user-name">{user.username}</span> <span className="role">{user.role.toLowerCase()}</span>
          </span>
          <button type="button" className="button" onClick={onLogout}>
            <LogOut aria-hidden="true" size={16} />
            Log out
          </button>
        </div>
      </div>
    </aside>
  );
}
