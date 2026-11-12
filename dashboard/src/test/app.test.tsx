import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { App } from "../App";
import type { IncidentDetail } from "../types";
import { analyst, fakeGateway, incident, loggedInAs, pendingBlock, summary, viewer } from "./fixtures";

// A development machine: no demo button. The login page asks once, when it opens.
const noSession = {
  "GET /api/me": { status: 401 },
  "POST /api/auth/refresh": { status: 401 },
  "GET /api/auth/options": { status: 200, body: { signupOpen: true, demoLogin: false } },
};
const publicDemo = {
  ...noSession,
  "GET /api/auth/options": { status: 200, body: { signupOpen: false, demoLogin: true } },
};

async function openIncident() {
  window.location.hash = "#/incidents/57";
  render(<App />);
  await screen.findByRole("region", { name: "Reports and actions" });
}

describe("logging in", () => {
  it("shows the login screen when there is no session", async () => {
    fakeGateway(noSession);
    render(<App />);

    expect(await screen.findByLabelText("Password")).toHaveAttribute("type", "password");
  });

  it("logs in and shows the incidents", async () => {
    fakeGateway({
      ...noSession,
      "POST /api/auth/login": { status: 200, body: analyst },
      "GET /api/incidents": { status: 200, body: [summary] },
      "GET /api/audit/verify": { status: 200, body: { valid: true, entries: 1, headSeq: 1, brokenAt: null } },
    });
    const user = userEvent.setup();
    render(<App />);

    await user.type(await screen.findByLabelText("Username"), "test.analyst");
    await user.type(screen.getByLabelText("Password"), "a-test-password");
    await user.click(screen.getByRole("button", { name: "Log in" }));

    expect(await screen.findByText("Sara Khan")).toBeInTheDocument();
    expect(screen.getByText("Choose an incident to see its investigation.")).toBeInTheDocument();
  });

  it("shows the server's refusal and clears the password", async () => {
    fakeGateway({ ...noSession, "POST /api/auth/login": { status: 401, body: { error: "Invalid username or password" } } });
    const user = userEvent.setup();
    render(<App />);

    await user.type(await screen.findByLabelText("Username"), "test.analyst");
    await user.type(screen.getByLabelText("Password"), "wrong");
    await user.click(screen.getByRole("button", { name: "Log in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid username or password");
    expect(screen.getByLabelText("Password")).toHaveValue("");
    expect(screen.getByRole("button", { name: "Log in" })).toBeEnabled();
  });

  it("offers no demo button on a development machine", async () => {
    fakeGateway(noSession);
    render(<App />);

    await screen.findByLabelText("Password");
    expect(screen.queryByRole("button", { name: "Try the demo" })).not.toBeInTheDocument();
  });

  it("on the public demo, Try the demo logs in without sending any password", async () => {
    const demo = { username: "demo", role: "ANALYST" as const };
    const fetchMock = fakeGateway({
      ...publicDemo,
      "POST /api/auth/demo-login": { status: 200, body: demo },
      "GET /api/incidents": { status: 200, body: [summary] },
      "GET /api/audit/verify": { status: 200, body: { valid: true, entries: 1, headSeq: 1, brokenAt: null } },
    });
    const user = userEvent.setup();
    render(<App />);

    expect(await screen.findByText(/approving an action changes nothing real/)).toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "Try the demo" }));

    expect(await screen.findByText("Sara Khan")).toBeInTheDocument();
    const [, init] = fetchMock.mock.calls.find(([url]) => url === "/api/auth/demo-login")!;
    expect(init?.method).toBe("POST");
    expect(init?.body).toBeUndefined();
  });

  it("shows the server's refusal of the demo login, such as today's limit", async () => {
    fakeGateway({
      ...publicDemo,
      "POST /api/auth/demo-login": { status: 429, body: { error: "Too many requests. Try again later." } },
    });
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: "Try the demo" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Too many requests. Try again later.");
    expect(screen.getByRole("button", { name: "Try the demo" })).toBeEnabled();
  });

  it("still shows the ordinary login form when the server cannot say what it offers", async () => {
    fakeGateway({ ...noSession, "GET /api/auth/options": { status: 500 } });
    render(<App />);

    expect(await screen.findByLabelText("Password")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Try the demo" })).not.toBeInTheDocument();
  });

  it("goes back to the login screen when the session can no longer be renewed", async () => {
    let live = true;
    fakeGateway({
      ...loggedInAs(analyst),
      "GET /api/incidents": () => (live ? { status: 200, body: [summary] } : { status: 401 }),
      "POST /api/auth/refresh": { status: 401 },
    });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Sara Khan");

    live = false;
    await user.click(screen.getByRole("button", { name: "Refresh" }));

    expect(await screen.findByLabelText("Password")).toBeInTheDocument();
  });

  it("logs out", async () => {
    const fetchMock = fakeGateway({ ...loggedInAs(analyst), "POST /api/auth/logout": { status: 204 } });
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: "Log out" }));

    expect(await screen.findByLabelText("Password")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/auth/logout", expect.objectContaining({ method: "POST" }));
  });
});

describe("the incident", () => {
  it("every status has a word as well as a colour", async () => {
    fakeGateway(loggedInAs(analyst));
    await openIncident();

    const list = screen.getByRole("region", { name: "Incidents" });
    expect(within(list).getByText("Attack")).toBeInTheDocument();
    expect(within(list).getByText("Waiting for approval")).toBeInTheDocument();
    expect(within(list).getByText("75")).toBeInTheDocument();
  });

  it("an incident with no verdict yet shows no verdict and no score", async () => {
    fakeGateway({
      ...loggedInAs(analyst),
      "GET /api/incidents": { status: 200, body: [{ ...summary, verdict: null, riskScore: null, status: "investigating" }] },
    });
    render(<App />);

    const list = await screen.findByRole("region", { name: "Incidents" });
    expect(await within(list).findByText("Investigating")).toBeInTheDocument();
    expect(within(list).queryByText("Attack")).not.toBeInTheDocument();
    expect(within(list).queryByText("75")).not.toBeInTheDocument();
  });

  it("opening an incident puts it in the address, so a reload keeps your place", async () => {
    fakeGateway(loggedInAs(analyst));
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: /Sara Khan/ }));

    expect(window.location.hash).toBe("#/incidents/57");
    expect(await screen.findByRole("meter", { name: "Risk score" })).toHaveAttribute("aria-valuenow", "75");
  });

  it("ignores an address that is not an incident number", async () => {
    window.location.hash = "#/incidents/1;alert(1)";
    fakeGateway(loggedInAs(analyst));
    render(<App />);

    expect(await screen.findByText("Choose an incident to see its investigation.")).toBeInTheDocument();
  });

  it("a slow answer for the old incident cannot replace the one you moved on to", async () => {
    const other: IncidentDetail = { ...incident, id: 58, subjectName: "Omar Haddad", actions: [] };
    let releaseOld: (response: Response) => void = () => {};
    const routes: Record<string, () => Promise<Response>> = {
      "/api/me": async () => Response.json(analyst),
      "/api/incidents": async () => Response.json([summary, { ...summary, id: 58, subjectName: "Omar Haddad" }]),
      "/api/audit/verify": async () => Response.json({ valid: true }),
      "/api/incidents/57": () => new Promise((resolve) => (releaseOld = resolve)),
      "/api/incidents/58": async () => Response.json(other),
    };
    fakeFetch(routes);
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByRole("button", { name: /Sara Khan/ }));
    await user.click(screen.getByRole("button", { name: /Omar Haddad/ }));
    await screen.findByRole("heading", { name: /about Omar Haddad/ });
    releaseOld(Response.json(incident));
    await new Promise((resolve) => setTimeout(resolve));

    expect(screen.getByRole("heading", { name: /about Omar Haddad/ })).toBeInTheDocument();
  });

  it("shows a refused tool call as blocked, with its reason", async () => {
    fakeGateway(loggedInAs(analyst));
    await openIncident();

    const blocked = document.getElementById("evidence-R1")!;
    expect(within(blocked).getByText("Blocked")).toBeInTheDocument();
    expect(within(blocked).getByText("This address does not appear in the incident")).toBeInTheDocument();
  });

  it("an investigation that failed says so", async () => {
    fakeGateway(loggedInAs(analyst, { ...incident, status: "error", verdict: null, actions: [] }));
    await openIncident();

    expect(screen.getByText(/stopped before finishing/)).toBeInTheDocument();
    expect(screen.getByText("The reports appear once the investigation has finished.")).toBeInTheDocument();
  });

  it("an incident from before reports existed still opens", async () => {
    fakeGateway(loggedInAs(analyst, { ...incident, verdict: { ...incident.verdict!, socReport: null, plainReport: null } }));
    await openIncident();

    expect(screen.getByText("This incident was investigated before reports existed.")).toBeInTheDocument();
  });

  it("a verdict that disagreed with the evidence is called out", async () => {
    fakeGateway(loggedInAs(analyst, { ...incident, verdict: { ...incident.verdict!, disagreement: true } }));
    await openIncident();

    expect(screen.getByText(/did not match the evidence/)).toBeInTheDocument();
  });

  it("a broken audit chain is loud, with where it broke", async () => {
    fakeGateway({
      ...loggedInAs(analyst),
      "GET /api/audit/verify": { status: 200, body: { valid: false, entries: 24, headSeq: 24, brokenAt: 7 } },
    });
    render(<App />);

    expect(await screen.findByText("Audit log tampered at entry 7")).toBeInTheDocument();
  });
});

describe("evidence chips", () => {
  it("clicking one goes to that step and marks it", async () => {
    fakeGateway(loggedInAs(analyst));
    const user = userEvent.setup();
    await openIncident();

    const plain = screen.getByRole("article", { name: "Report for everyone" });
    await user.click(within(plain).getByRole("button", { name: "Go to evidence E2" }));

    const step = document.getElementById("evidence-E2")!;
    await waitFor(() => expect(step).toHaveClass("highlighted"));
    expect(step).toHaveFocus();
    expect(document.getElementById("evidence-E1")).not.toHaveClass("highlighted");
  });

  it("the AI line's citations become chips and its words stay text", async () => {
    fakeGateway(loggedInAs(analyst));
    await openIncident();

    const soc = screen.getByRole("article", { name: "Report for the security team" });
    const line = within(soc).getByText(/A caller asked for a one-time code/).parentElement!;
    expect(within(line).getAllByRole("button").map((chip) => chip.textContent)).toEqual(["E1", "E2", "E1"]);
  });
});

describe("both reports", () => {
  it("show the same verdict from one evidence chain", async () => {
    fakeGateway(loggedInAs(analyst));
    await openIncident();

    const plain = screen.getByRole("article", { name: "Report for everyone" });
    const soc = screen.getByRole("article", { name: "Report for the security team" });
    expect(within(plain).getByText("This phone call is a scam.")).toBeInTheDocument();
    expect(within(plain).getByText("Attack")).toBeInTheDocument();
    expect(within(soc).getByText(/Malicious: vishing/)).toBeInTheDocument();
    expect(within(soc).getByText("T1566.004")).toBeInTheDocument();
  });
});

describe("approval", () => {
  const card = () => screen.getByRole("listitem", { name: /Decision needed/ });

  it("shows the evidence above the buttons", async () => {
    fakeGateway(loggedInAs(analyst));
    await openIncident();

    const evidence = within(card()).getByText("The number is on a list of scam callers");
    const approve = within(card()).getByRole("button", { name: "Approve block" });
    expect(evidence.compareDocumentPosition(approve) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(card()).getByText("+15555550142")).toBeInTheDocument();
    expect(within(card()).getByText(/Must be decided by/)).toBeInTheDocument();
  });

  it("approving sends the decision and shows the new state", async () => {
    let decided = false;
    const after: IncidentDetail = {
      ...incident,
      status: "needs_review",
      actions: [{ ...pendingBlock, status: "executed", decidedBy: analyst.username, expiresAt: null }],
    };
    const fetchMock = fakeGateway({
      ...loggedInAs(analyst),
      "GET /api/incidents/57": () => ({ status: 200, body: decided ? after : incident }),
      "POST /api/actions/9/decision": () => {
        decided = true;
        return { status: 200, body: after.actions[0] };
      },
    });
    const user = userEvent.setup();
    await openIncident();

    await user.click(within(card()).getByRole("button", { name: "Approve block" }));

    expect(await screen.findByText(`by ${analyst.username}`)).toBeInTheDocument();
    expect(screen.queryByRole("listitem", { name: /Decision needed/ })).not.toBeInTheDocument();
    const decision = fetchMock.mock.calls.find(([url]) => url === "/api/actions/9/decision")!;
    expect(decision[1]?.body).toBe('{"decision":"approve"}');
  });

  it("rejecting sends a rejection", async () => {
    const fetchMock = fakeGateway({ ...loggedInAs(analyst), "POST /api/actions/9/decision": { status: 200, body: pendingBlock } });
    const user = userEvent.setup();
    await openIncident();

    await user.click(within(card()).getByRole("button", { name: "Reject" }));

    await waitFor(() => {
      const decision = fetchMock.mock.calls.find(([url]) => url === "/api/actions/9/decision");
      expect(decision?.[1]?.body).toBe('{"decision":"reject"}');
    });
  });

  it("a viewer gets no buttons", async () => {
    fakeGateway(loggedInAs(viewer));
    await openIncident();

    expect(within(card()).queryByRole("button", { name: "Approve block" })).not.toBeInTheDocument();
    expect(within(card()).queryByRole("button", { name: "Reject" })).not.toBeInTheDocument();
    expect(within(card()).getByText("Only analysts and admins can decide this.")).toBeInTheDocument();
  });

  it("the server has the last word: a refusal is shown and the buttons come back", async () => {
    fakeGateway({
      ...loggedInAs(analyst),
      "POST /api/actions/9/decision": { status: 403, body: { error: "You cannot decide an action on your own account" } },
    });
    const user = userEvent.setup();
    await openIncident();

    await user.click(within(card()).getByRole("button", { name: "Approve block" }));

    expect(await within(card()).findByRole("alert")).toHaveTextContent("You cannot decide an action on your own account");
    expect(within(card()).getByRole("button", { name: "Approve block" })).toBeEnabled();
  });

  it("says that enforcement is simulated", async () => {
    fakeGateway(loggedInAs(analyst));
    await openIncident();

    expect(screen.getByText(/nothing real is blocked/)).toBeInTheDocument();
  });
});

function fakeFetch(routes: Record<string, () => Promise<Response>>) {
  vi.stubGlobal("fetch", (url: string) => routes[url]());
}
