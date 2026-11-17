import { CircleHelp, FlaskConical, LayoutDashboard, LogOut, Radar, RefreshCw, ShieldAlert, ShieldCheck, type LucideIcon } from "lucide-react";

import type { LiveState } from "../live";
import { liveMeaning } from "../meaning";
import type { AuditCheck, User } from "../types";
import { StatusChip } from "./Chips";

export type Page = "overview" | "scenarios";

const PAGES: { page: Page; word: string; Icon: LucideIcon; address: string }[] = [
  { page: "overview", word: "Overview", Icon: LayoutDashboard, address: "#/" },
  { page: "scenarios", word: "Scenarios", Icon: FlaskConical, address: "#/scenarios" },
];

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
  user: User;
  audit: AuditCheck | null;
  live: LiveState;
  onGo: (address: string) => void;
  onRefresh: () => void;
  onLogout: () => void;
}

/**
 * The dashboard's menu: one entry per page, and who is logged in. Pages are addresses
 * (#/, #/scenarios), changed by buttons: the product code builds no links.
 */
export function Sidebar({ current, user, audit, live, onGo, onRefresh, onLogout }: Props) {
  return (
    <aside className="sidebar">
      <span className="brand">
        <span className="logo-tile">
          <Radar aria-hidden="true" size={18} />
        </span>
        <strong className="product">Casewright</strong>
      </span>
      <nav aria-label="Pages" className="nav">
        {PAGES.map(({ page, word, Icon, address }) => (
          <button
            key={page}
            type="button"
            className="nav-item"
            aria-current={current === page ? "page" : undefined}
            onClick={() => onGo(address)}
          >
            <Icon aria-hidden="true" size={18} />
            {word}
          </button>
        ))}
      </nav>
      <div className="sidebar-foot">
        {/* Whether updates arrive by themselves, on every page; Refresh works either way. */}
        <span role="status">
          <StatusChip meaning={liveMeaning(live)} />
        </span>
        <button type="button" className="button" onClick={onRefresh}>
          <RefreshCw aria-hidden="true" size={16} />
          Refresh
        </button>
        <AuditBadge check={audit} />
        <span className="user">
          {user.username} <span className="role">{user.role.toLowerCase()}</span>
        </span>
        <button type="button" className="button" onClick={onLogout}>
          <LogOut aria-hidden="true" size={16} />
          Log out
        </button>
      </div>
    </aside>
  );
}
