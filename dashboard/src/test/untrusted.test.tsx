import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { App } from "../App";
import type { IncidentDetail } from "../types";
import { analyst, fakeGateway, incident, loggedInAs, pendingBlock, summary } from "./fixtures";

// Everything an attacker can influence, carrying markup that would run if it were treated as HTML.
const IMG = `<img src=x onerror="window.__hacked=1">`;
const SCRIPT = `<script>window.__hacked=1</script>`;
const LINK = `<a href="javascript:window.__hacked=1">click</a>`;
const URL_TEXT = "https://paypa1-secure-login.example/reset";
const HOSTILE = `${IMG}${SCRIPT}${LINK}${URL_TEXT}`;

const hostileIncident: IncidentDetail = {
  ...incident,
  subjectName: HOSTILE,
  createdBy: HOSTILE,
  payload: { kind: "email", body: HOSTILE, subject: HOSTILE },
  evidence: [
    {
      ...incident.evidence[0],
      args: { value: HOSTILE },
      summary: HOSTILE,
      result: { quoted: HOSTILE },
      signals: [{ id: "X", label: HOSTILE, plain: HOSTILE, weight: 40 }],
    },
    { ...incident.evidence[1], args: { value: HOSTILE }, reason: HOSTILE },
    incident.evidence[2],
  ],
  verdict: {
    ...incident.verdict!,
    counterfactual: HOSTILE,
    socReport: {
      headline: HOSTILE,
      findings: [{ evidence: "E1", signal: "X", text: HOSTILE, weight: 40 }],
      techniques: [HOSTILE],
      nextSteps: [HOSTILE],
      aiSummary: `${HOSTILE} [E1] ${HOSTILE}`,
    },
    plainReport: {
      headline: HOSTILE,
      whatHappened: HOSTILE,
      reasons: [{ evidence: "E1", signal: "X", text: HOSTILE }],
      whatToDo: [HOSTILE],
    },
  },
  actions: [
    { ...pendingBlock, target: HOSTILE, evidence: "E1" },
    { ...pendingBlock, id: 10, status: "executed", target: HOSTILE, decidedBy: HOSTILE, evidence: "E1" },
  ],
};

describe("text from an incident is only ever text", () => {
  it("no markup from anywhere in an incident becomes an element, and nothing runs", async () => {
    fakeGateway({
      ...loggedInAs(analyst, hostileIncident),
      "GET /api/incidents": { status: 200, body: [{ ...summary, subjectName: HOSTILE }] },
    });
    window.location.hash = "#/incidents/57";
    render(<App />);
    await screen.findByRole("region", { name: "Reports and actions" });

    expect(document.querySelectorAll("img, script, iframe, object, embed")).toHaveLength(0);
    expect(document.querySelectorAll("[onerror], [onclick]")).toHaveLength(0);
    expect((window as unknown as { __hacked?: number }).__hacked).toBeUndefined();
    // And the words are really on the screen, not dropped.
    expect(document.body.textContent).toContain(IMG);
    expect(document.body.textContent).toContain(SCRIPT);
  });

  it("no link is ever made from incident data, even one that looks harmless", async () => {
    fakeGateway(loggedInAs(analyst, hostileIncident));
    window.location.hash = "#/incidents/57";
    render(<App />);
    await screen.findByRole("region", { name: "Reports and actions" });

    expect(document.querySelectorAll("a")).toHaveLength(0);
    expect(document.body.textContent).toContain(URL_TEXT);
  });

  it("a bracketed note in the AI line cannot make a chip that goes anywhere else", async () => {
    const line = `Look [E1] and [javascript:alert(1)] and [E1, <img src=x>].`;
    fakeGateway(
      loggedInAs(analyst, { ...incident, verdict: { ...incident.verdict!, socReport: { ...incident.verdict!.socReport!, aiSummary: line } } }),
    );
    const user = userEvent.setup();
    window.location.hash = "#/incidents/57";
    render(<App />);

    await screen.findByRole("article", { name: "Report for the security team" });
    const paragraph = screen.getByText(/javascript:alert/).parentElement!;
    expect(paragraph.querySelectorAll("button")).toHaveLength(1);
    expect(paragraph.querySelector("img")).toBeNull();
    await user.click(paragraph.querySelector("button")!);
    expect(document.getElementById("evidence-E1")).toHaveClass("highlighted");
  });
});
