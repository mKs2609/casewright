import type { Action, AuditCheck, DemoScenario, IncidentDetail, IncidentSummary, User } from "./types";

/** A refusal from the server, with its own message (which never repeats what was sent). */
export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

let onSessionLost: () => void = () => {};

const SCENARIO_NAME = /^[a-z_]{1,40}$/;

/** Called when the session has ended and cannot be renewed, so the app can show the login screen. */
export function setSessionLostHandler(handler: () => void): void {
  onSessionLost = handler;
}

let refreshing: Promise<boolean> | null = null;

/**
 * Renews the session, one refresh at a time. A refresh token works once, and the gateway treats a
 * second use as theft and ends the session (ADR-26), so two requests that find the access token
 * expired must share one refresh. Web Locks stretches that across browser tabs.
 */
function refreshOnce(): Promise<boolean> {
  refreshing ??= (async () => {
    const renew = async () => (await fetch("/api/auth/refresh", { method: "POST" })).ok;
    return navigator.locks ? navigator.locks.request("session-refresh", renew) : renew();
  })()
    .catch(() => false)
    .finally(() => {
      refreshing = null;
    });
  return refreshing;
}

type Method = "GET" | "POST";

async function send(path: string, body?: unknown, signal?: AbortSignal, method?: Method): Promise<Response> {
  try {
    return await fetch(`/api${path}`, {
      method: method ?? (body === undefined && !path.startsWith("/auth/") ? "GET" : "POST"),
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
  } catch (failure) {
    if (signal?.aborted) {
      throw failure;
    }
    throw new ApiError(0, "Could not reach the server. Check that the gateway is running, then try again.");
  }
}

/** Sends a request, renewing the session once if it has expired. Any refusal becomes an ApiError. */
async function authorised(path: string, body?: unknown, signal?: AbortSignal, method?: Method): Promise<Response> {
  let response = await send(path, body, signal, method);
  if (response.status === 401 && !path.startsWith("/auth/")) {
    if (await refreshOnce()) {
      response = await send(path, body, signal, method);
    }
    if (response.status === 401) {
      onSessionLost();
    }
  }
  if (!response.ok) {
    throw new ApiError(response.status, await errorMessage(response));
  }
  return response;
}

async function request<T>(path: string, body?: unknown, method?: Method): Promise<T> {
  const response = await authorised(path, body, undefined, method);
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
}

async function errorMessage(response: Response): Promise<string> {
  try {
    const { error } = (await response.json()) as { error?: unknown };
    if (typeof error === "string") {
      return error;
    }
  } catch {
    // Not our JSON: the development server answers this way when the gateway is down.
  }
  return "Something went wrong on the server. Try again.";
}

export const api = {
  me: () => request<User>("/me"),
  login: (username: string, password: string) => request<User>("/auth/login", { username, password }),
  logout: () => request<void>("/auth/logout"),
  incidents: () => request<IncidentSummary[]>("/incidents"),
  incident: (id: number) => request<IncidentDetail>(`/incidents/${id}`),
  decide: (id: number, decision: "approve" | "reject") => request<Action>(`/actions/${id}/decision`, { decision }),
  auditCheck: () => request<AuditCheck>("/audit/verify"),
  /** The demo buttons. Names that are not plain lowercase words are dropped: they become part of a URL. */
  demoScenarios: async () =>
    (await request<DemoScenario[]>("/demo/scenarios")).filter((scenario) => SCENARIO_NAME.test(scenario.name)),
  /** Fires a demo scenario. Only its name is sent; the gateway submits its own copy. */
  runScenario: (name: string) => {
    if (!SCENARIO_NAME.test(name)) {
      return Promise.reject(new ApiError(0, "That is not a demo scenario."));
    }
    return request<IncidentDetail>(`/demo/${name}`, undefined, "POST");
  },
  /** The live feed (ADR-49): an open response that the gateway keeps adding to. */
  openFeed: async (signal: AbortSignal) => {
    const response = await authorised("/incidents/events", undefined, signal);
    if (!response.body) {
      throw new ApiError(0, "Live updates are not available in this browser.");
    }
    return response.body;
  },
};
