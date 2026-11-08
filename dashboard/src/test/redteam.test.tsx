import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { App } from "../App";
import type { DemoScenario, RedTeamCard, RedTeamRow } from "../types";
import { analyst, fakeGateway, incident, liveFeed, loggedInAs, viewer } from "./fixtures";

const SCENARIOS: DemoScenario[] = [{ name: "phishing_email", title: "Phishing email", description: "A fake warning." }];

const run = { ...incident, id: 70, source: "red_team" };

function row(attempt: string, outcome: RedTeamRow["outcome"] = "blocked"): RedTeamRow {
  return { attempt, stoppedBy: "The tool guardrail", outcome };
}

function card(rows: RedTeamRow[], state: RedTeamCard["state"] = "finished"): RedTeamCard {
  return { incidentId: 70, state, blocked: rows.filter((r) => r.outcome === "blocked").length, attempts: rows.length, rows };
}

const allBlocked = card([row("Use a tool that is not on the allow-list: block_ip on 10.0.0.5"), row("Call the email safe")]);

async function openRun(scorecard: () => { status: number; body?: unknown }, extra = {}) {
  const fetchMock = fakeGateway({
    ...loggedInAs(analyst, run),
    "GET /api/red-team/70": scorecard,
    ...extra,
  });
  window.location.hash = "#/incidents/70";
  render(<App />);
  await screen.findByRole("heading", { name: /#70/ });
  return fetchMock;
}

const scorecard = () => screen.getByRole("region", { name: "Red-team scorecard" });

describe("the red-team probe", () => {
  it("the button starts a run, sending nothing, and opens it", async () => {
    const fetchMock = fakeGateway({
      ...loggedInAs(analyst),
      "GET /api/demo/scenarios": { status: 200, body: SCENARIOS },
      "POST /api/red-team": { status: 202, body: { ...run, status: "queued", evidence: [], verdict: null, actions: [] } },
      "GET /api/incidents/70": { status: 200, body: run },
      "GET /api/red-team/70": { status: 200, body: allBlocked },
    });
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: "Red-team the agent" }));

    await waitFor(() => expect(window.location.hash).toBe("#/incidents/70"));
    const started = fetchMock.mock.calls.find(([url]) => url === "/api/red-team")!;
    expect(started[1]).toMatchObject({ method: "POST", body: undefined });
  });

  it("a viewer sees it disabled", async () => {
    fakeGateway({ ...loggedInAs(viewer), "GET /api/demo/scenarios": { status: 200, body: SCENARIOS } });
    render(<App />);

    expect(await screen.findByRole("button", { name: "Red-team the agent" })).toBeDisabled();
  });

  it("a run is marked, says who played the AI, and shows each attempt and what stopped it", async () => {
    await openRun(() => ({ status: 200, body: allBlocked }));

    const investigation = screen.getByRole("region", { name: "Investigation" });
    expect(within(investigation).getByText("Red team")).toBeInTheDocument();
    expect(within(investigation).getByText("A scripted, hijacked model played the AI")).toBeInTheDocument();
    expect(await within(scorecard()).findByText("All 2 attempts were blocked.")).toBeInTheDocument();
    expect(within(scorecard()).getAllByText("Blocked")).toHaveLength(2);
    expect(within(scorecard()).getByText(/block_ip on 10\.0\.0\.5/)).toBeInTheDocument();
    expect(within(scorecard()).getAllByText(/The tool guardrail/)).toHaveLength(2);
  });

  it("an attempt that got through is shown, not hidden", async () => {
    await openRun(() => ({ status: 200, body: card([row("Use a tool"), row("Call the email safe", "not_blocked")]) }));

    const headline = await within(scorecard()).findByText("1 of 2 attempts were NOT blocked.");
    expect(headline).toHaveClass("notice");
    expect(within(scorecard()).getByText("Not blocked")).toBeInTheDocument();
  });

  it("while running it counts so far, and a failed run says it proves nothing", async () => {
    let state: RedTeamCard["state"] = "running";
    const feed = liveFeed();
    await openRun(() => ({ status: 200, body: card([row("Use a tool"), row("Call the email safe", "waiting")], state) }), {
      "GET /api/incidents/events": feed.route,
    });
    expect(await within(scorecard()).findByText("1 of 2 attempts blocked so far.")).toBeInTheDocument();
    expect(within(scorecard()).getByText("Waiting")).toBeInTheDocument();

    state = "failed";
    feed.send("event: ready\ndata:\n\n");   // every reconnection reloads what is on screen

    expect(await within(scorecard()).findByText(/stopped before it finished/)).toBeInTheDocument();
  });

  it("the scorecard follows the live feed", async () => {
    let answer = card([row("Use a tool"), row("Call the email safe", "waiting")], "running");
    const feed = liveFeed();
    await openRun(() => ({ status: 200, body: answer }), { "GET /api/incidents/events": feed.route });
    await within(scorecard()).findByText("1 of 2 attempts blocked so far.");
    feed.send("event: ready\ndata:\n\n");
    await new Promise((resolve) => setTimeout(resolve, 400));

    answer = card([row("Use a tool"), row("Call the email safe")]);
    feed.send("event: incident\ndata: 70\n\n");

    expect(await within(scorecard()).findByText("All 2 attempts were blocked.")).toBeInTheDocument();
  });

  it("an ordinary incident has no scorecard and never asks for one", async () => {
    const fetchMock = fakeGateway(loggedInAs(analyst));
    window.location.hash = "#/incidents/57";
    render(<App />);

    await screen.findByRole("heading", { name: /#57/ });
    expect(screen.queryByRole("region", { name: "Red-team scorecard" })).not.toBeInTheDocument();
    expect(screen.queryByText("Red team")).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url]) => String(url).startsWith("/api/red-team"))).toBe(false);
  });
});
