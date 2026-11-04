import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { setSessionLostHandler } from "../api";
import { App } from "../App";
import { followIncidents, readEvents, timing, type LiveState } from "../live";
import type { Evidence } from "../types";
import { analyst, fakeGateway, incident, liveFeed, loggedInAs, summary } from "./fixtures";

const original = { ...timing };

beforeEach(() => {
  // The real delays are seconds long; the order of events is what is being tested.
  Object.assign(timing, { afterEnd: 5, firstRetry: 5, maxRetry: 40, minimumLife: 0 });
});

afterEach(() => {
  Object.assign(timing, original);
});

function streamOf(...chunks: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      chunks.forEach((chunk) => controller.enqueue(encoder.encode(chunk)));
      controller.close();
    },
  });
}

async function eventsIn(...chunks: string[]) {
  const seen: string[] = [];
  await readEvents(streamOf(...chunks), new AbortController().signal, (event, data) => seen.push(`${event} ${data}`));
  return seen;
}

describe("reading the feed", () => {
  it("understands messages split anywhere, either line ending, and skips keep-alive comments", async () => {
    expect(await eventsIn("event: rea", "dy\ndata:\n\n: keep-alive\n\nevent:incident\r\ndata:57\r\n\r\n")).toEqual([
      "ready ",
      "incident 57",
    ]);
  });

  it("gives up on a line longer than any this feed sends", async () => {
    await expect(eventsIn("data: " + "x".repeat(2000))).rejects.toThrow("unexpected");
  });
});

describe("following the feed", () => {
  function follow() {
    const changed: number[] = [];
    const states: LiveState[] = [];
    const ready = vi.fn();
    const stop = followIncidents({ onReady: ready, onChanged: (id) => changed.push(id), onState: (s) => states.push(s) });
    return { changed, states, ready, stop };
  }

  it("passes on incident numbers and nothing else", async () => {
    const feed = liveFeed();
    fakeGateway({ "GET /api/incidents/events": feed.route });
    const { changed, ready, stop } = follow();
    await waitFor(() => expect(feed.connections).toBe(1));

    feed.send("event: ready\ndata:\n\n");
    feed.send("event: incident\ndata: 57\n\n");
    feed.send("event: incident\ndata: 57<img src=x onerror=alert(1)>\n\n");
    feed.send("event: incident\ndata: javascript:alert(1)\n\n");
    feed.send("event: something-else\ndata: 58\n\n");
    feed.send("event: incident\ndata: 59\n\n");

    await waitFor(() => expect(changed).toEqual([57, 59]));
    expect(ready).toHaveBeenCalledTimes(1);
    stop();
  });

  it("reconnects when the gateway ends the feed, and says ready again", async () => {
    const feed = liveFeed();
    fakeGateway({ "GET /api/incidents/events": feed.route });
    const { ready, states, stop } = follow();
    await waitFor(() => expect(feed.connections).toBe(1));
    feed.send("event: ready\ndata:\n\n");
    await waitFor(() => expect(ready).toHaveBeenCalledTimes(1));

    feed.end(); // the login behind it expired

    await waitFor(() => expect(feed.connections).toBe(2));
    feed.send("event: ready\ndata:\n\n");
    await waitFor(() => expect(ready).toHaveBeenCalledTimes(2));
    expect(states).toEqual(["connecting", "live", "paused", "connecting", "live"]);
    stop();
  });

  it("renews the session first when the feed says the login has expired", async () => {
    let expired = true;
    const feed = liveFeed();
    const fetchMock = fakeGateway({
      "GET /api/incidents/events": () => (expired ? { status: 401 } : feed.route()),
      "POST /api/auth/refresh": () => {
        expired = false;
        return { status: 204 };
      },
    });
    const { stop } = follow();

    await waitFor(() => expect(feed.connections).toBe(1));
    expect(fetchMock.mock.calls.filter(([url]) => url === "/api/auth/refresh")).toHaveLength(1);
    stop();
  });

  it("stops for good when the session cannot be renewed", async () => {
    setSessionLostHandler(() => {});
    const fetchMock = fakeGateway({
      "GET /api/incidents/events": { status: 401 },
      "POST /api/auth/refresh": { status: 401 },
    });
    const { states } = follow();

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2)); // the feed, then the refused refresh
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(states).toEqual(["connecting"]);
  });

  it("waits longer after each failure, and longest when there are too many tabs", async () => {
    // Long enough that the doubling stands out from the timer's own jitter.
    Object.assign(timing, { firstRetry: 30, maxRetry: 300 });
    const answers = [{ status: 500 }, { status: 500 }, { status: 429, body: { error: "Too many dashboard tabs" } }];
    const times: number[] = [];
    const feed = liveFeed();
    fakeGateway({
      "GET /api/incidents/events": () => {
        times.push(Date.now());
        return answers.shift() ?? feed.route();
      },
    });
    const { states, stop } = follow();

    await waitFor(() => expect(times).toHaveLength(4), { timeout: 2000 });
    const gaps = times.slice(1).map((t, i) => t - times[i]);
    expect(gaps[1]).toBeGreaterThan(gaps[0]);
    expect(gaps[2]).toBeGreaterThanOrEqual(timing.maxRetry - 5);
    expect(states).toContain("paused");
    stop();
  });

  it("a feed that keeps ending at once is retried more and more slowly, not in a tight loop", async () => {
    timing.minimumLife = 1000;
    const times: number[] = [];
    fakeGateway({
      "GET /api/incidents/events": () => {
        times.push(Date.now());
        return new Response(streamOf("event: ready\ndata:\n\n"), { status: 200 });
      },
    });
    const { stop } = follow();

    await waitFor(() => expect(times.length).toBeGreaterThanOrEqual(4), { timeout: 2000 }).finally(stop);
    const gaps = times.slice(1).map((t, i) => t - times[i]);
    expect(gaps[2]).toBeGreaterThanOrEqual(timing.firstRetry * 4 - 2);
    expect(gaps[2]).toBeGreaterThan(gaps[0]);
  });

  it("stopping closes the feed and does not reconnect", async () => {
    const feed = liveFeed();
    fakeGateway({ "GET /api/incidents/events": feed.route });
    const { stop } = follow();
    await waitFor(() => expect(feed.connections).toBe(1));

    stop();
    await new Promise((resolve) => setTimeout(resolve, 60));

    expect(feed.connections).toBe(1);
  });
});

describe("the dashboard with live updates", () => {
  const newStep: Evidence = {
    label: "E3",
    tool: "baseline_check",
    args: { identity: "sara.khan" },
    status: "ok",
    summary: "Called outside working hours",
    result: {},
    signals: [],
    reason: null,
    createdAt: "2026-11-01T10:00:05Z",
  };

  function setUp() {
    const feed = liveFeed();
    let detail = incident;
    const fetchMock = fakeGateway({
      ...loggedInAs(analyst),
      "GET /api/incidents/events": feed.route,
      "GET /api/incidents/57": () => ({ status: 200, body: detail }),
    });
    const addStep = () => {
      detail = { ...incident, evidence: [...incident.evidence, newStep] };
    };
    const calls = (url: string) => fetchMock.mock.calls.filter(([called]) => called === url).length;
    return { feed, addStep, calls };
  }

  async function openIncident() {
    window.location.hash = "#/incidents/57";
    render(<App />);
    await screen.findByRole("region", { name: "Reports and actions" });
  }

  it("shows a new step on the open incident as soon as the gateway says it changed", async () => {
    const { feed, addStep, calls } = setUp();
    await openIncident();
    feed.send("event: ready\ndata:\n\n");
    // Let the reload that "ready" starts finish first, so only the change can bring the new step.
    await waitFor(() => expect(calls("/api/incidents/57")).toBe(2));
    await new Promise((resolve) => setTimeout(resolve, 400));
    expect(screen.queryByText("Called outside working hours")).not.toBeInTheDocument();

    addStep();
    feed.send("event: incident\ndata: 57\n\n");

    expect(await screen.findByText("Called outside working hours")).toBeInTheDocument();
  });

  it("a change to another incident reloads the list, not the incident on screen, and never the audit check", async () => {
    const { feed, calls } = setUp();
    await openIncident();
    feed.send("event: ready\ndata:\n\n");
    await waitFor(() => expect(calls("/api/incidents")).toBe(2));
    await new Promise((resolve) => setTimeout(resolve, 400));
    const before = { detail: calls("/api/incidents/57"), audit: calls("/api/audit/verify") };

    feed.send("event: incident\ndata: 58\n\n");

    await waitFor(() => expect(calls("/api/incidents")).toBe(3));
    expect(calls("/api/incidents/57")).toBe(before.detail);
    expect(calls("/api/audit/verify")).toBe(before.audit);
  });

  it("a burst of changes becomes a few reloads, not one each", async () => {
    const { feed, calls } = setUp();
    await openIncident();
    feed.send("event: ready\ndata:\n\n");
    await new Promise((resolve) => setTimeout(resolve, 400));
    const before = calls("/api/incidents/57");

    for (let i = 0; i < 10; i++) {
      feed.send("event: incident\ndata: 57\n\n");
    }
    await new Promise((resolve) => setTimeout(resolve, 800));

    expect(calls("/api/incidents/57") - before).toBeGreaterThan(0);
    expect(calls("/api/incidents/57") - before).toBeLessThanOrEqual(2);
  });

  it("says whether updates are live, in words as well as colour", async () => {
    const { feed } = setUp();
    await openIncident();
    expect(screen.getByRole("status")).toHaveTextContent("Connecting");

    feed.send("event: ready\ndata:\n\n");
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Live"));

    feed.end();
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent(/Live updates paused|Connecting/));
  });

  it("keeps working with Refresh when there is no feed", async () => {
    fakeGateway({
      ...loggedInAs(analyst),
      "GET /api/incidents/events": { status: 503, body: { error: "Live updates are busy. Use Refresh for now." } },
    });
    await openIncident();

    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Live updates paused"));
    expect(screen.getAllByText(summary.subjectName).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Refresh" })).toBeEnabled();
  });
});
