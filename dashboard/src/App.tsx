import { useCallback, useEffect, useRef, useState } from "react";

import { api, setSessionLostHandler } from "./api";
import { Actions } from "./components/Actions";
import { AppBar } from "./components/AppBar";
import { IncidentList } from "./components/IncidentList";
import { Investigation } from "./components/Investigation";
import { Login } from "./components/Login";
import { Reports } from "./components/Reports";
import type { AuditCheck, IncidentDetail, IncidentSummary, User } from "./types";

const message = (failure: unknown) => (failure instanceof Error ? failure.message : "Something went wrong. Try again.");

/** The selected incident lives in the address (#/incidents/57), so a reload keeps your place. */
function selectedFromAddress(): number | null {
  const match = /^#\/incidents\/(\d{1,15})$/.exec(window.location.hash);
  return match ? Number(match[1]) : null;
}

function Dashboard({ user, onLogout }: { user: User; onLogout: () => void }) {
  const [incidents, setIncidents] = useState<IncidentSummary[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [selected, setSelected] = useState<number | null>(selectedFromAddress);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [audit, setAudit] = useState<AuditCheck | null>(null);
  const [highlighted, setHighlighted] = useState<string | null>(null);
  const latestRequest = useRef(0);

  const loadList = useCallback(async () => {
    try {
      setIncidents(await api.incidents());
      setListError(null);
    } catch (failure) {
      setListError(message(failure));
    }
    api.auditCheck().then(setAudit, () => setAudit(null));
  }, []);

  const loadDetail = useCallback(async (id: number | null) => {
    // Only the newest request counts, so a slow answer can't replace the incident you moved on to.
    const request = ++latestRequest.current;
    if (id === null) {
      setDetail(null);
      setDetailError(null);
      return;
    }
    try {
      const incident = await api.incident(id);
      if (request === latestRequest.current) {
        setDetail(incident);
        setDetailError(null);
      }
    } catch (failure) {
      if (request === latestRequest.current) {
        setDetail(null);
        setDetailError(message(failure));
      }
    }
  }, []);

  useEffect(() => {
    void loadList();
  }, [loadList]);

  useEffect(() => {
    setHighlighted(null);
    void loadDetail(selected);
  }, [selected, loadDetail]);

  useEffect(() => {
    const follow = () => setSelected(selectedFromAddress());
    window.addEventListener("hashchange", follow);
    return () => window.removeEventListener("hashchange", follow);
  }, []);

  const refresh = useCallback(() => {
    void loadList();
    void loadDetail(selected);
  }, [loadList, loadDetail, selected]);

  const cite = useCallback((label: string) => {
    setHighlighted(label);
    const target = document.getElementById(`evidence-${label}`);
    target?.focus({ preventScroll: true });
    target?.scrollIntoView?.({ block: "center" });
  }, []);

  return (
    <div className="app">
      <AppBar user={user} audit={audit} onLogout={onLogout} />
      <div className="columns">
        <IncidentList
          incidents={incidents}
          selected={selected}
          error={listError}
          onSelect={(id) => {
            window.location.hash = `#/incidents/${id}`;
            setSelected(id);
          }}
          onRefresh={refresh}
        />
        {detail && detail.id === selected ? (
          <>
            <Investigation incident={detail} highlighted={highlighted} />
            <section className="panel reports" aria-label="Reports and actions">
              <Actions
                actions={detail.actions}
                evidence={detail.evidence}
                user={user}
                onCite={cite}
                onDecided={refresh}
              />
              <Reports verdict={detail.verdict} onCite={cite} />
            </section>
          </>
        ) : (
          <section className="panel empty" aria-label="Investigation">
            {detailError ? (
              <p role="alert" className="error-text">
                {detailError}
              </p>
            ) : (
              <p className="muted">{selected === null ? "Choose an incident to see its investigation." : "Loading..."}</p>
            )}
          </section>
        )}
      </div>
    </div>
  );
}

export function App() {
  // undefined: still finding out whether there is a session.
  const [user, setUser] = useState<User | null | undefined>(undefined);

  useEffect(() => {
    setSessionLostHandler(() => setUser(null));
    api.me().then(setUser, () => setUser(null));
  }, []);

  if (user === undefined) {
    return <p className="muted loading">Loading...</p>;
  }
  if (user === null) {
    return <Login onLogin={setUser} />;
  }
  return (
    <Dashboard
      user={user}
      onLogout={() => {
        // Show the login screen whatever happens: the cookies are cleared if the request gets through.
        api.logout().finally(() => {
          window.location.hash = "";
          setUser(null);
        });
      }}
    />
  );
}
