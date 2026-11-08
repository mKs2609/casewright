// What the gateway's API sends back. Every string that came from an incident is untrusted:
// it is only ever shown as plain text.

export type Role = "VIEWER" | "ANALYST" | "ADMIN";

export interface User {
  username: string;
  role: Role;
}

export interface IncidentSummary {
  id: number;
  kind: string;
  subjectIdentity: string;
  subjectName: string;
  status: string;
  source: string;
  createdBy: string;
  createdAt: string;
  verdict: string | null;
  riskScore: number | null;
}

export interface Signal {
  id: string;
  label: string;
  plain: string;
  weight: number;
  mitre?: string | null;
  indicator?: string | null;
}

export interface Evidence {
  label: string;
  tool: string;
  args: Record<string, string>;
  status: "ok" | "rejected";
  summary: string | null;
  result: unknown;
  signals: Signal[];
  reason: string | null;
  createdAt: string;
}

export interface SocFinding {
  evidence: string;
  signal: string;
  text: string;
  weight: number;
  mitre?: string | null;
}

export interface SocReport {
  headline: string;
  findings: SocFinding[];
  techniques: string[];
  nextSteps: string[];
  aiSummary?: string | null;
}

export interface PlainReport {
  headline: string;
  whatHappened: string;
  reasons: { evidence: string; signal: string; text: string }[];
  whatToDo: string[];
}

export interface Verdict {
  verdict: string;
  attackType: string;
  riskScore: number;
  agentVerdict: string;
  agentRiskScore: number;
  disagreement: boolean;
  engine: string;
  citedEvidence: string[];
  counterfactual: string | null;
  socReport: SocReport | null;
  plainReport: PlainReport | null;
  createdAt: string;
}

export interface Action {
  id: number;
  incidentId: number;
  action: string;
  target: string;
  risk: string;
  status: string;
  evidence: string;
  decidedBy: string | null;
  decidedAt: string | null;
  expiresAt: string | null;
  createdAt: string;
}

export interface IncidentDetail extends Omit<IncidentSummary, "verdict" | "riskScore"> {
  payload: unknown;
  evidence: Evidence[];
  verdict: Verdict | null;
  actions: Action[];
}

/** A demo button. The incident behind it stays on the gateway. */
export interface DemoScenario {
  name: string;
  title: string;
  description: string;
}

/** One attempt of the red-team run's hijacked model, judged by the gateway from what it stored. */
export interface RedTeamRow {
  attempt: string;
  stoppedBy: string;
  outcome: "blocked" | "not_blocked" | "waiting";
}

export interface RedTeamCard {
  incidentId: number;
  state: "running" | "finished" | "failed";
  blocked: number;
  attempts: number;
  rows: RedTeamRow[];
}

export interface AuditCheck {
  valid: boolean;
  entries: number;
  headSeq: number | null;
  brokenAt: number | null;
}
