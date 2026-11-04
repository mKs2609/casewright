import { useCallback, useEffect, useRef, useState } from "react";

import { api, setSessionLostHandler } from "./api";
import { followIncidents, type LiveState } from "./live";
import { Actions } from "./components/Actions";
import { AppBar } from "./components/AppBar";
import { IncidentList } from "./components/IncidentList";
import { Investigation } from "./components/Investigation";
import { Login } from "./components/Login";
import { Reports } from "./components/Reports";
import type { AuditCheck, IncidentDetail, IncidentSummary, User } from "./types";

const message = (failure: unknown) => (failure instanceof Error ? failure.message : "Something went wrong. Try again.");

/** Time between live reloads, so a burst of changes becomes a few reloads instead of dozens. */
const RELOAD_GAP_MS = 300;

/** Runs work one at a time. Calls that arrive while it runs become one more run afterwards. */
function coalesced(work: () => Promise<void>): () => void {
  let running = false;
  let again = false;
  const run = async () => {
    running = true;
    do {
      again = false;
      await work();
      await new Promise((resolve) => setTimeout(resolve, RELOAD_GAP_MS));
    } while (again);
    running = false;
  };
  return () => {
    if (running) {
      again = true;
    } else {
      void run();
    }
  };
}

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
  const [live, setLive] = useState<LiveState>("connecting");
  const latestRequest = useRef(0);
  // What the live feed compares changes with; it outlives any one render, so it reads this instead of "selected".
  const selectedNow = useRef(selected);
  useEffect(() => {
    selectedNow.current = selected;
  }, [selected]);

  const loadIncidents = useCallback(async () => {
    try {
      setIncidents(await api.incidents());
      setListError(null);
    } catch (failure) {
      setListError(message(failure));
    }
  }, []);

  // Walks the whole audit chain on the server, so not on every live change: on load, Refresh and decisions.
  const loadList = useCallback(async () => {
    await loadIncidents();
    api.auditCheck().then(setAudit, () => setAudit(null));
  }, [loadIncidents]);

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

  // Live updates: the feed only says which incident changed, and that is fetched like any other request.
  useEffect(() => {
    const reloadList = coalesced(loadIncidents);
    const reloadDetail = coalesced(() => loadDetail(selectedNow.current));
    return followIncidents({
      onState: setLive,
      // Every (re)connection starts here: reload, in case something changed while there was no feed.
      onReady: () => {
        reloadList();
        reloadDetail();
      },
      onChanged: (id) => {
        reloadList();
        if (id === selectedNow.current) {
          reloadDetail();
        }
      },
    });
  }, [loadIncidents, loadDetail]);

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
          live={live}
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
