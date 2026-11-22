import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { App } from "../App";
import { NO_FILTERS, addressFor, filtersFrom } from "../filters";
import type { IncidentSummary } from "../types";
import { analyst, fakeGateway, loggedInAs, summary } from "./fixtures";

// 57: a phone call, an attack, waiting for a decision (and its page has one pending action).
// 58: an email attack. 59: a harmless email. 60: a sign-in attack.
const incidents: IncidentSummary[] = [
  summary,
  { ...summary, id: 58, kind: "email", subjectName: "Priya Sharma", status: "needs_review" },
  { ...summary, id: 59, kind: "email", subjectName: "Arjun Mehta", verdict: "benign", status: "closed", riskScore: 0 },
  { ...summary, id: 60, kind: "login", subjectName: "Priya Sharma", status: "needs_review" },
];

function openOverview(list: IncidentSummary[], address = "#/") {
  fakeGateway({ ...loggedInAs(analyst), "GET /api/incidents": { status: 200, body: list } });
  window.location.hash = address;
  render(<App />);
}

/** The incident numbers shown in the list, in order. */
const shown = () =>
  within(screen.getByRole("region", { name: "Incidents" }))
    .queryAllByRole("button")
    .map((card) => /#(\d+)/.exec(card.textContent ?? "")?.[1]);

const figure = (name: RegExp) => within(screen.getByLabelText("At a glance")).getByRole("button", { name });
const type = (name: RegExp) => within(screen.getByRole("group", { name: "Type" })).getByRole("button", { name });

describe("the overview's filters", () => {
  it("a figure shows only its incidents, the address remembers it, and a second click shows all again", async () => {
    openOverview(incidents);
    const user = userEvent.setup();
    await waitFor(() => expect(shown()).toEqual(["57", "58", "59", "60"]));
    expect(figure(/Incidents/)).toHaveAttribute("aria-pressed", "true");

    await user.click(figure(/Attacks found/));
    expect(shown()).toEqual(["57", "58", "60"]);
    expect(window.location.hash).toBe("#/?show=attacks");
    expect(figure(/Attacks found/)).toHaveAttribute("aria-pressed", "true");
    expect(figure(/Incidents/)).toHaveAttribute("aria-pressed", "false");

    await user.click(figure(/Attacks found/));
    expect(shown()).toEqual(["57", "58", "59", "60"]);
    expect(window.location.hash).toBe("#/");
  });

  it("the type row combines with the figures, counts within the type, and Show all clears both", async () => {
    openOverview(incidents);
    const user = userEvent.setup();
    await waitFor(() => expect(shown()).toHaveLength(4));

    await user.click(figure(/Attacks found/));
    await user.click(type(/^Email/));

    expect(shown()).toEqual(["58"]);
    expect(window.location.hash).toBe("#/?show=attacks&kind=email");
    expect(figure(/Incidents/)).toHaveTextContent("2");
    expect(screen.getByText(/Showing 1 of 4/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Show all" }));
    expect(shown()).toEqual(["57", "58", "59", "60"]);
    expect(window.location.hash).toBe("#/");
  });

  it("with one incident waiting, its figure opens that incident on the Actions tab", async () => {
    openOverview(incidents);
    const user = userEvent.setup();
    await waitFor(() => expect(shown()).toHaveLength(4));

    await user.click(figure(/Waiting for a decision/));

    expect(await screen.findByRole("heading", { name: /#57/ })).toBeInTheDocument();
    expect(window.location.hash).toBe("#/incidents/57");
    expect(screen.getByRole("tab", { name: /^Actions/ })).toHaveAttribute("aria-selected", "true");
  });

  it("with several waiting, its figure lists them, and each opens on the Actions tab", async () => {
    openOverview([...incidents, { ...summary, id: 61, kind: "email", status: "awaiting_approval" }]);
    const user = userEvent.setup();
    await waitFor(() => expect(shown()).toHaveLength(5));

    await user.click(figure(/Waiting for a decision/));
    expect(shown()).toEqual(["57", "61"]);
    expect(window.location.hash).toBe("#/?show=waiting");

    await user.click(within(screen.getByRole("region", { name: "Incidents" })).getAllByRole("button")[0]);
    expect(await screen.findByRole("heading", { name: /#57/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /^Actions/ })).toHaveAttribute("aria-selected", "true");
  });

  it("an incident opened from the list still opens on Evidence when not filtered by waiting", async () => {
    openOverview(incidents, "#/?show=attacks");
    const user = userEvent.setup();
    await waitFor(() => expect(shown()).toEqual(["57", "58", "60"]));

    await user.click(within(screen.getByRole("region", { name: "Incidents" })).getAllByRole("button")[0]);
    expect(await screen.findByRole("heading", { name: /#57/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /^Evidence/ })).toHaveAttribute("aria-selected", "true");
  });

  it("All incidents goes back to the list as it was filtered", async () => {
    openOverview(incidents, "#/?show=attacks&kind=calls");
    const user = userEvent.setup();
    await waitFor(() => expect(shown()).toEqual(["57"]));

    await user.click(within(screen.getByRole("region", { name: "Incidents" })).getAllByRole("button")[0]);
    await user.click(await screen.findByRole("button", { name: "All incidents" }));

    expect(window.location.hash).toBe("#/?show=attacks&kind=calls");
    await waitFor(() => expect(shown()).toEqual(["57"]));
  });

  it("says so when nothing matches", async () => {
    openOverview(incidents, "#/?show=waiting&kind=sign-ins");
    expect(await screen.findByText("No incidents match these filters.")).toBeInTheDocument();
  });
});

describe("the filters in the address", () => {
  it("are read strictly: anything but the exact words means all", () => {
    expect(filtersFrom("show=attacks&kind=email")).toEqual({ show: "attacks", kind: "email" });
    expect(filtersFrom("show=everything&kind=spam")).toEqual(NO_FILTERS);
    // Words that exist on every JavaScript object are not types.
    expect(filtersFrom("kind=toString")).toEqual(NO_FILTERS);
    expect(filtersFrom("kind=__proto__&show=constructor")).toEqual(NO_FILTERS);
  });

  it("are written only when something is filtered, and read back the same", () => {
    expect(addressFor(NO_FILTERS)).toBe("#/");
    const filters = { show: "waiting", kind: "sign-ins" } as const;
    expect(filtersFrom(addressFor(filters).slice("#/?".length))).toEqual(filters);
  });

  it("an address the Overview does not know still opens the Overview, unfiltered", async () => {
    openOverview(incidents, "#/?show=<script>");
    await waitFor(() => expect(shown()).toEqual(["57", "58", "59", "60"]));
    expect(figure(/Incidents/)).toHaveAttribute("aria-pressed", "true");
  });
});

describe("Refresh", () => {
  it("says when it last updated, so a click never looks like nothing happened", async () => {
    openOverview(incidents);
    const user = userEvent.setup();
    await waitFor(() => expect(shown()).toHaveLength(4));
    expect(screen.queryByText(/^Updated /)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Refresh" }));

    expect(await screen.findByText(/^Updated /)).toBeInTheDocument();
  });
});
