import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { App } from "../App";
import type { DemoScenario } from "../types";
import { analyst, fakeGateway, incident, loggedInAs, summary, viewer } from "./fixtures";

const SCENARIOS: DemoScenario[] = [
  { name: "credential_stuffing", title: "Attempt breach", description: "Password guessing, then a way in." },
  { name: "phishing_email", title: "Phishing email", description: "A fake security warning." },
  { name: "normal_login", title: "Normal sign-in", description: "Should come out safe." },
];

const started = { ...incident, id: 61, status: "queued", source: "demo", evidence: [], verdict: null, actions: [] };

const demoBar = () => screen.getByRole("region", { name: "Demo scenarios" });

describe("demo scenarios", () => {
  it("shows the buttons with Attempt breach first and as the main one", async () => {
    fakeGateway({ ...loggedInAs(analyst), "GET /api/demo/scenarios": { status: 200, body: SCENARIOS } });
    render(<App />);

    await screen.findByRole("button", { name: "Attempt breach" });
    const buttons = within(demoBar()).getAllByRole("button");
    expect(buttons.map((b) => b.textContent)).toEqual(["Attempt breach", "Phishing email", "Normal sign-in"]);
    expect(buttons[0]).toHaveClass("button-primary");
    expect(buttons[1]).not.toHaveClass("button-primary");
    expect(buttons[0]).toHaveAccessibleDescription("Password guessing, then a way in.");
  });

  it("sends only the scenario's name, then opens the new incident", async () => {
    const fetchMock = fakeGateway({
      ...loggedInAs(analyst),
      "GET /api/demo/scenarios": { status: 200, body: SCENARIOS },
      "POST /api/demo/credential_stuffing": { status: 202, body: started },
      "GET /api/incidents/61": { status: 200, body: started },
    });
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: "Attempt breach" }));

    await waitFor(() => expect(window.location.hash).toBe("#/incidents/61"));
    const fired = fetchMock.mock.calls.find(([url]) => url === "/api/demo/credential_stuffing")!;
    expect(fired[1]).toMatchObject({ method: "POST", body: undefined });
    expect(await screen.findByRole("heading", { name: /#61/ })).toBeInTheDocument();
  });

  it("a viewer sees the buttons disabled, and why", async () => {
    const fetchMock = fakeGateway({ ...loggedInAs(viewer), "GET /api/demo/scenarios": { status: 200, body: SCENARIOS } });
    render(<App />);

    const breach = await screen.findByRole("button", { name: "Attempt breach" });
    expect(breach).toBeDisabled();
    expect(within(demoBar()).getByText("Only analysts and admins can run scenarios.")).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url]) => String(url).startsWith("/api/demo/") && url !== "/api/demo/scenarios")).toBe(false);
  });

  it("shows the gateway's refusal and lets you try again", async () => {
    fakeGateway({
      ...loggedInAs(analyst),
      "GET /api/demo/scenarios": { status: 200, body: SCENARIOS },
      "POST /api/demo/phishing_email": { status: 429, body: { error: "Too many requests. Try again later." } },
    });
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: "Phishing email" }));

    expect(await within(demoBar()).findByRole("alert")).toHaveTextContent("Too many requests. Try again later.");
    expect(within(demoBar()).getByRole("button", { name: "Phishing email" })).toBeEnabled();
  });

  it("never puts a name that is not a plain word into a request", async () => {
    const odd = [
      { name: "../auth/logout", title: "Sneaky", description: "x" },
      { name: "phishing_email?x=1", title: "Also sneaky", description: "x" },
      SCENARIOS[1],
    ];
    fakeGateway({ ...loggedInAs(analyst), "GET /api/demo/scenarios": { status: 200, body: odd } });
    render(<App />);

    await screen.findByRole("button", { name: "Phishing email" });
    expect(within(demoBar()).getAllByRole("button")).toHaveLength(1);
    expect(screen.queryByText("Sneaky")).not.toBeInTheDocument();
  });

  it("is not there at all when the gateway has demos switched off", async () => {
    fakeGateway({ ...loggedInAs(analyst), "GET /api/demo/scenarios": { status: 404, body: { error: "Not Found" } } });
    render(<App />);

    await screen.findAllByText("Sara Khan");
    await waitFor(() => expect(screen.queryByRole("region", { name: "Demo scenarios" })).not.toBeInTheDocument());
  });

  it("marks a simulated incident in the list and on the incident itself", async () => {
    const demo = { ...incident, source: "demo" };
    fakeGateway({
      ...loggedInAs(analyst, demo),
      "GET /api/incidents": { status: 200, body: [{ ...summary, source: "demo" }] },
    });
    window.location.hash = "#/incidents/57";
    render(<App />);

    await screen.findByRole("heading", { name: /#57/ });
    expect(within(screen.getByRole("region", { name: "Investigation" })).getByText("Simulated")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Incidents" })).getByText("Simulated")).toBeInTheDocument();
  });

  it("does not mark an ordinary incident", async () => {
    fakeGateway(loggedInAs(analyst));
    window.location.hash = "#/incidents/57";
    render(<App />);

    await screen.findByRole("heading", { name: /#57/ });
    expect(screen.queryByText("Simulated")).not.toBeInTheDocument();
  });
});
