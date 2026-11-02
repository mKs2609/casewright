import type { Action, AuditCheck, IncidentDetail, IncidentSummary, User } from "./types";

/** A refusal from the server, with its own message (which never repeats what was sent). */
export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

let onSessionLost: () => void = () => {};

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

async function send(path: string, body?: unknown): Promise<Response> {
  try {
    return await fetch(`/api${path}`, {
      method: body === undefined && !path.startsWith("/auth/") ? "GET" : "POST",
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "Could not reach the server. Check that the gateway is running, then try again.");
  }
}

async function request<T>(path: string, body?: unknown): Promise<T> {
  let response = await send(path, body);
  if (response.status === 401 && !path.startsWith("/auth/")) {
    if (await refreshOnce()) {
      response = await send(path, body);
    }
    if (response.status === 401) {
      onSessionLost();
    }
  }
  if (!response.ok) {
    throw new ApiError(response.status, await errorMessage(response));
  }
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
};
