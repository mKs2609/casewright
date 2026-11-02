import { CircleHelp, LogOut, ShieldAlert, ShieldCheck } from "lucide-react";

import type { AuditCheck, User } from "../types";

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

export function AppBar({ user, audit, onLogout }: { user: User; audit: AuditCheck | null; onLogout: () => void }) {
  return (
    <header className="app-bar">
      <strong className="product">Casewright</strong>
      <AuditBadge check={audit} />
      <span className="spacer" />
      <span className="muted">
        {user.username} <span className="role">{user.role.toLowerCase()}</span>
      </span>
      <button type="button" className="button" onClick={onLogout}>
        <LogOut aria-hidden="true" size={16} />
        Log out
      </button>
    </header>
  );
}
