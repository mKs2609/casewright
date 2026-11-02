import { describe, expect, it, vi } from "vitest";

import { api, ApiError, setSessionLostHandler } from "../api";
import { analyst, fakeGateway } from "./fixtures";

const calls = (fetchMock: ReturnType<typeof fakeGateway>, url: string) =>
  fetchMock.mock.calls.filter(([called]) => called === url).length;

describe("renewing the session", () => {
  it("refreshes after a 401 and repeats the request", async () => {
    let expired = true;
    const fetchMock = fakeGateway({
      "GET /api/me": () => (expired ? { status: 401, body: { error: "Authentication required" } } : { status: 200, body: analyst }),
      "POST /api/auth/refresh": () => {
        expired = false;
        return { status: 204 };
      },
    });

    await expect(api.me()).resolves.toEqual(analyst);
    expect(calls(fetchMock, "/api/auth/refresh")).toBe(1);
    expect(calls(fetchMock, "/api/me")).toBe(2);
  });

  it("shares one refresh between requests that expire together, because a second use ends the session", async () => {
    let expired = true;
    const fetchMock = fakeGateway({
      "GET /api/me": () => (expired ? { status: 401 } : { status: 200, body: analyst }),
      "GET /api/incidents": () => (expired ? { status: 401 } : { status: 200, body: [] }),
      "GET /api/audit/verify": () => (expired ? { status: 401 } : { status: 200, body: { valid: true } }),
      "POST /api/auth/refresh": () => {
        expired = false;
        return { status: 204 };
      },
    });

    await Promise.all([api.me(), api.incidents(), api.auditCheck()]);

    expect(calls(fetchMock, "/api/auth/refresh")).toBe(1);
  });

  it("uses a browser-wide lock when there is one, so two tabs cannot refresh at once", async () => {
    const request = vi.fn((_name: string, work: () => Promise<boolean>) => work());
    vi.stubGlobal("navigator", { locks: { request } });
    fakeGateway({ "GET /api/me": { status: 401 }, "POST /api/auth/refresh": { status: 401 } });
    setSessionLostHandler(() => {});

    await expect(api.me()).rejects.toBeInstanceOf(ApiError);

    expect(request).toHaveBeenCalledTimes(1);
    expect(request.mock.calls[0][0]).toBe("session-refresh");
  });

  it("reports the session as lost when the refresh is refused", async () => {
    const lost = vi.fn();
    setSessionLostHandler(lost);
    fakeGateway({ "GET /api/me": { status: 401 }, "POST /api/auth/refresh": { status: 401 } });

    await expect(api.me()).rejects.toMatchObject({ status: 401 });

    expect(lost).toHaveBeenCalledTimes(1);
  });

  it("never tries to refresh after a failed login: a wrong password is not an expired session", async () => {
    const lost = vi.fn();
    setSessionLostHandler(lost);
    const fetchMock = fakeGateway({
      "POST /api/auth/login": { status: 401, body: { error: "Invalid username or password" } },
    });

    await expect(api.login("test.analyst", "wrong")).rejects.toThrow("Invalid username or password");

    expect(calls(fetchMock, "/api/auth/refresh")).toBe(0);
    expect(lost).not.toHaveBeenCalled();
  });

  it("does not refresh on 403: the session is fine, the answer is no", async () => {
    const fetchMock = fakeGateway({
      "POST /api/actions/9/decision": { status: 403, body: { error: "You cannot decide an action on your own account" } },
    });

    await expect(api.decide(9, "approve")).rejects.toThrow("You cannot decide an action on your own account");

    expect(calls(fetchMock, "/api/auth/refresh")).toBe(0);
  });
});

describe("requests", () => {
  it("sends a decision as exactly what the gateway accepts", async () => {
    const fetchMock = fakeGateway({ "POST /api/actions/9/decision": { status: 200, body: {} } });

    await api.decide(9, "reject");

    expect(fetchMock.mock.calls[0][1]?.body).toBe('{"decision":"reject"}');
  });

  it("has a plain message when the server cannot be reached", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("failed")));

    await expect(api.incidents()).rejects.toThrow("Could not reach the server");
  });

  it("has a plain message when the answer is not the gateway's JSON", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html>Bad gateway</html>", { status: 502 })));

    await expect(api.incidents()).rejects.toThrow("Something went wrong on the server");
  });
});
