import { vi } from "vitest";

import type { Action, IncidentDetail, IncidentSummary, User } from "../types";

// Reserved example names only, as everywhere in this project's test data.

export const analyst: User = { username: "test.analyst", role: "ANALYST" };
export const viewer: User = { username: "test.viewer", role: "VIEWER" };

export const summary: IncidentSummary = {
  id: 57,
  kind: "call_transcript",
  subjectIdentity: "sara.khan",
  subjectName: "Sara Khan",
  status: "awaiting_approval",
  source: "api",
  createdBy: "test.analyst",
  createdAt: "2026-11-01T10:00:00Z",
  verdict: "malicious",
  riskScore: 75,
};

export const pendingBlock: Action = {
  id: 9,
  incidentId: 57,
  action: "block_phone_number",
  target: "+15555550142",
  risk: "high",
  status: "pending",
  evidence: "E2",
  decidedBy: null,
  decidedAt: null,
  expiresAt: "2026-11-02T10:00:00Z",
  createdAt: "2026-11-01T10:00:00Z",
};

export const incident: IncidentDetail = {
  id: 57,
  kind: "call_transcript",
  subjectIdentity: "sara.khan",
  subjectName: "Sara Khan",
  status: "awaiting_approval",
  source: "api",
  createdBy: "test.analyst",
  createdAt: "2026-11-01T10:00:00Z",
  payload: { kind: "call_transcript", callerNumber: "+15555550142", transcript: "Read me the code." },
  evidence: [
    {
      label: "E1",
      tool: "pattern_match",
      args: { target: "all" },
      status: "ok",
      summary: "Asked for a one-time code",
      result: { matched: ["otp-request"] },
      signals: [{ id: "OTP-REQUEST", label: "Asks for a one-time code", plain: "The caller asked for a code.", weight: 40 }],
      reason: null,
      createdAt: "2026-11-01T10:00:01Z",
    },
    {
      label: "R1",
      tool: "reputation_lookup",
      args: { value: "10.0.0.5" },
      status: "rejected",
      summary: null,
      result: null,
      signals: [],
      reason: "This address does not appear in the incident",
      createdAt: "2026-11-01T10:00:02Z",
    },
    {
      label: "E2",
      tool: "reputation_lookup",
      args: { value: "+15555550142" },
      status: "ok",
      summary: "The number is on a list of scam callers",
      result: { listed: true },
      signals: [{ id: "REP-MALICIOUS", label: "Number is known-malicious", plain: "This number is on lists of known scammers.", weight: 45 }],
      reason: null,
      createdAt: "2026-11-01T10:00:03Z",
    },
  ],
  verdict: {
    verdict: "malicious",
    attackType: "vishing",
    riskScore: 75,
    agentVerdict: "malicious",
    agentRiskScore: 75,
    disagreement: false,
    engine: "llm",
    citedEvidence: ["E1", "E2"],
    counterfactual: "If the number were not listed, this would be suspicious.",
    socReport: {
      headline: "Malicious: vishing (voice phishing), risk 75/100",
      findings: [{ evidence: "E2", signal: "REP-MALICIOUS", text: "Number is known-malicious", weight: 45 }],
      techniques: ["T1566.004"],
      nextSteps: ["Block the caller number if the evidence supports it."],
      aiSummary: "A caller asked for a one-time code [E1] from a listed number [E2, E1].",
    },
    plainReport: {
      headline: "This phone call is a scam.",
      whatHappened: "We checked a phone call that was reported as suspicious.",
      reasons: [{ evidence: "E2", signal: "REP-MALICIOUS", text: "This number is on lists of known scammers." }],
      whatToDo: ["Hang up on calls like this. Real staff never ask for codes."],
    },
    createdAt: "2026-11-01T10:00:04Z",
  },
  actions: [
    { ...pendingBlock, id: 8, action: "monitor", target: "sara.khan", risk: "low", status: "executed", evidence: "E1", expiresAt: null },
    pendingBlock,
  ],
};

type Answer = { status: number; body?: unknown } | (() => { status: number; body?: unknown });

/** A stand-in for the gateway: "METHOD /path" -> answer. Unlisted calls fail the test loudly. */
export function fakeGateway(routes: Record<string, Answer>) {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    const key = `${init?.method ?? "GET"} ${url}`;
    const route = routes[key];
    if (!route) {
      throw new Error(`Unexpected request: ${key}`);
    }
    const { status, body } = typeof route === "function" ? route() : route;
    return new Response(body === undefined ? null : JSON.stringify(body), { status });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

export const loggedInAs = (user: User, detail: IncidentDetail = incident) => ({
  "GET /api/me": { status: 200, body: user },
  "GET /api/incidents": { status: 200, body: [summary] },
  [`GET /api/incidents/${detail.id}`]: { status: 200, body: detail },
  "GET /api/audit/verify": { status: 200, body: { valid: true, entries: 24, headSeq: 24, brokenAt: null } },
});
