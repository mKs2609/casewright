import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { App } from "../App";
import { analyst, fakeGateway, incident, loggedInAs, summary } from "./fixtures";

const pages = () => screen.getByRole("navigation", { name: "Pages" });

describe("the sidebar", () => {
  it("opens each page and marks the one you are on", async () => {
    fakeGateway({ ...loggedInAs(analyst), "GET /api/demo/scenarios": { status: 200, body: [] } });
    const user = userEvent.setup();
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(within(pages()).getByRole("button", { name: "Overview" })).toHaveAttribute("aria-current", "page");

    await user.click(within(pages()).getByRole("button", { name: "Scenarios" }));

    expect(window.location.hash).toBe("#/scenarios");
    expect(await screen.findByRole("heading", { name: "Scenarios" })).toBeInTheDocument();
    expect(within(pages()).getByRole("button", { name: "Scenarios" })).toHaveAttribute("aria-current", "page");
    expect(within(pages()).getByRole("button", { name: "Overview" })).not.toHaveAttribute("aria-current");
  });
});

describe("the overview", () => {
  it("counts the incidents, the attacks, what is waiting, and the audit log", async () => {
    fakeGateway({
      ...loggedInAs(analyst),
      "GET /api/incidents": {
        status: 200,
        body: [summary, { ...summary, id: 58, verdict: "benign", status: "closed" }, { ...summary, id: 59, status: "needs_review" }],
      },
    });
    render(<App />);

    const glance = await screen.findByLabelText("At a glance");
    const value = (words: string) => within(glance).getByText(words).closest(".figure")!.querySelector("dd")!.textContent;
    await waitFor(() => expect(value("Incidents")).toBe("3"));
    expect(value("Attacks found")).toBe("2");
    expect(value("Waiting for a decision")).toBe("1");
    expect(value("Audit log entries")).toBe("24");
  });
});

describe("the incident page", () => {
  async function openIncident() {
    window.location.hash = "#/incidents/57";
    render(<App />);
    await screen.findByRole("heading", { name: /#57/ });
  }

  it("opens on the Evidence tab, and the arrow keys move between tabs", async () => {
    fakeGateway(loggedInAs(analyst));
    const user = userEvent.setup();
    await openIncident();

    const evidence = screen.getByRole("tab", { name: /^Evidence/ });
    expect(evidence).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel")).toHaveAttribute("aria-labelledby", evidence.id);

    evidence.focus();
    await user.keyboard("{ArrowRight}");
    const reports = screen.getByRole("tab", { name: /^Reports/ });
    expect(reports).toHaveAttribute("aria-selected", "true");
    expect(reports).toHaveFocus();
    expect(screen.getByRole("article", { name: "Report for everyone" })).toBeInTheDocument();

    await user.keyboard("{End}");
    expect(screen.getByRole("tab", { name: /^Actions/ })).toHaveFocus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: /^Evidence/ })).toHaveFocus();
  });

  it("says how many decisions are waiting, and opens them", async () => {
    fakeGateway(loggedInAs(analyst));
    const user = userEvent.setup();
    await openIncident();

    expect(screen.getByRole("tab", { name: /^Actions/ })).toHaveTextContent("1 waiting");
    expect(screen.getByText(/1 action is waiting for a decision/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Open Actions" }));

    expect(screen.getByRole("tab", { name: /^Actions/ })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("listitem", { name: /Decision needed/ })).toBeInTheDocument();
  });

  it("an incident with no proposed actions says so on the Actions tab", async () => {
    fakeGateway(loggedInAs(analyst, { ...incident, actions: [] }));
    const user = userEvent.setup();
    await openIncident();

    await user.click(screen.getByRole("tab", { name: /^Actions/ }));

    expect(screen.getByText("No actions were proposed for this incident.")).toBeInTheDocument();
  });

  it("All incidents goes back to the overview", async () => {
    fakeGateway(loggedInAs(analyst));
    const user = userEvent.setup();
    await openIncident();

    await user.click(screen.getByRole("button", { name: "All incidents" }));

    expect(window.location.hash).toBe("#/");
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
  });
});
