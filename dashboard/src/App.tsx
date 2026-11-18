import { useCallback, useEffect, useRef, useState } from "react";

import { api, setSessionLostHandler } from "./api";
import { followIncidents, type LiveState } from "./live";
import { IncidentPage, useFocusEvidence, type Tab } from "./components/IncidentPage";
import { Login } from "./components/Login";
import { Skeleton } from "./motion";
import { Overview } from "./components/Overview";
import { Scenarios } from "./components/Scenarios";
import { Sidebar, type Page } from "./components/Sidebar";
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

/**
 * The page lives in the address, so a reload keeps your place: #/ (Overview), #/scenarios, or
 * #/incidents/57. Anything else is the Overview.
 */
type Route = { page: Page } | { page: "incident"; id: number };

function routeFromAddress(): Route {
  const hash = window.location.hash;
  if (hash === "#/scenarios") {
    return { page: "scenarios" };
  }
  const match = /^#\/incidents\/(\d{1,15})$/.exec(hash);
  return match ? { page: "incident", id: Number(match[1]) } : { page: "overview" };
}

const selectedIn = (route: Route) => (route.page === "incident" ? route.id : null);

function Dashboard({ user, onLogout }: { user: User; onLogout: () => void }) {
  const [incidents, setIncidents] = useState<IncidentSummary[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [route, setRoute] = useState<Route>(routeFromAddress);
  const selected = selectedIn(route);
  const [tab, setTab] = useState<Tab>("evidence");
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
    setTab("evidence");
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
    const follow = () => setRoute(routeFromAddress());
    window.addEventListener("hashchange", follow);
    return () => window.removeEventListener("hashchange", follow);
  }, []);

  const go = useCallback((address: string) => {
    window.location.hash = address;
    setRoute(routeFromAddress());
    window.scrollTo?.(0, 0);
  }, []);

  const refresh = useCallback(() => {
    void loadList();
    void loadDetail(selected);
  }, [loadList, loadDetail, selected]);

  const focusEvidence = useFocusEvidence(tab, highlighted);
  // An evidence chip (in a report or a decision) opens the Evidence tab at that step.
  const cite = useCallback(
    (label: string) => {
      setHighlighted(label);
      setTab("evidence");
      focusEvidence(label);
    },
    [focusEvidence],
  );

  return (
    <div className="shell">
      <Sidebar
        current={route.page === "incident" ? null : route.page}
        incident={
          route.page === "incident" && detail && detail.id === selected
            ? { id: detail.id, waiting: detail.actions.filter((action) => action.status === "pending").length, tab }
            : null
        }
        onTab={setTab}
        user={user}
        audit={audit}
        live={live}
        onGo={go}
        onRefresh={refresh}
        onLogout={onLogout}
      />
      <main className="main">
        {route.page === "overview" && (
          <Overview
            incidents={incidents}
            audit={audit}
            error={listError}
            onOpen={(id) => go(`#/incidents/${id}`)}
          />
        )}
        {route.page === "scenarios" && (
          <Scenarios
            user={user}
            onStarted={(started) => {
              // Open the new incident at once; the live feed fills in its steps.
              go(`#/incidents/${started.id}`);
              void loadIncidents();
            }}
          />
        )}
        {route.page === "incident" &&
          (detail && detail.id === selected ? (
            <IncidentPage
              incident={detail}
              user={user}
              highlighted={highlighted}
              onCite={cite}
              onDecided={refresh}
              onBack={() => go("#/")}
              tab={tab}
              onTab={setTab}
            />
          ) : (
            <div className="page">
              {detailError ? (
                <p role="alert" className="error-text">
                  {detailError}
                </p>
              ) : (
                <Skeleton kind="page" />
              )}
            </div>
          ))}
      </main>
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
