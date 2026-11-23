import { Gauge, ShieldX } from "lucide-react";
import { useEffect, useRef } from "react";

import { KIND_WORDS, RED_TEAM, riskBand, SIMULATED, statusMeaning, verdictMeaning, when } from "../meaning";
import type { Evidence, IncidentDetail } from "../types";
import { CountUp } from "../motion";
import { SignalChips, StatusChip } from "./Chips";
import { LatticeLoader } from "./LatticeLoader";

function RiskMeter({ score }: { score: number }) {
  return (
    <div className="risk-meter">
      <div className="risk-figure">
        <span className={`risk-score tone-text-${riskBand(score)}`}>
          <CountUp value={score} />
        </span>
        <span className="label">
          <Gauge aria-hidden="true" size={14} />
          Risk / 100
        </span>
      </div>
      <div className="risk-scale">
        <span className="label" aria-hidden="true">
          0 safe · 30 suspicious · 65 attack · 100
        </span>
        <div
          className="meter-track"
          role="meter"
          aria-label="Risk score"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={score}
        >
          <div className={`meter-fill fill-${riskBand(score)}`} style={{ width: `${score}%` }} />
        </div>
      </div>
    </div>
  );
}

/** A refused tool call: what the guardrails stopped, and why. */
function GuardrailCard({ step, highlighted, arrived }: { step: Evidence; highlighted: boolean; arrived: boolean }) {
  return (
    <li
      id={`evidence-${step.label}`}
      tabIndex={-1}
      className={`card guardrail ${highlighted ? "highlighted" : ""} ${arrived ? "step-new" : ""}`}
    >
      <div className="step-head">
        <ShieldX aria-hidden="true" size={16} />
        <strong>Blocked</strong>
        <span className="mono muted">{step.label}</span>
        <span className="mono step-tool">{step.tool.replaceAll("_", " ")}</span>
      </div>
      <Arguments args={step.args} />
      <p>{step.reason}</p>
    </li>
  );
}

function Arguments({ args }: { args: Record<string, string> }) {
  return (
    <dl className="arguments">
      {Object.entries(args).map(([name, value]) => (
        <div key={name}>
          <dt className="muted">{name}</dt>
          <dd className="mono">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function StepCard({ step, highlighted, arrived }: { step: Evidence; highlighted: boolean; arrived: boolean }) {
  return (
    <li
      id={`evidence-${step.label}`}
      tabIndex={-1}
      className={`card step ${highlighted ? "highlighted" : ""} ${arrived ? "step-new" : ""}`}
    >
      <div className="step-head">
        <span className="evidence-tag mono">{step.label}</span>
        <span className="mono step-tool">{step.tool.replaceAll("_", " ")}</span>
      </div>
      <Arguments args={step.args} />
      <p>{step.summary}</p>
      <SignalChips signals={step.signals} />
      <details>
        <summary>Raw evidence</summary>
        <pre>{JSON.stringify(step.result, null, 2)}</pre>
      </details>
    </li>
  );
}

/** The top of an incident's page: what it is, its state, and its risk. Always shown above the tabs. */
export function IncidentHeader({ incident }: { incident: IncidentDetail }) {
  const { verdict, status } = incident;
  const unfinished = status === "queued" || status === "investigating";
  return (
    <div className="incident-header">
      <h2 className="incident-title">
        {KIND_WORDS[incident.kind] ?? incident.kind} about {incident.subjectName}{" "}
        <span className="mono muted">#{incident.id}</span>
      </h2>
      <p className="small muted">
        <span className="mono">{incident.subjectIdentity}</span> · submitted by {incident.createdBy} · {when(incident.createdAt)}
      </p>
      <div className="chip-row">
        {verdict && <StatusChip meaning={verdictMeaning(verdict.verdict)} />}
        <StatusChip meaning={statusMeaning(status)} />
        {verdict && (
          <span className="chip tone-muted">
            {incident.source === "red_team"
              ? "A scripted, hijacked model played the AI"
              : verdict.engine === "llm"
                ? "Led by the AI model"
                : "Fixed plan"}
          </span>
        )}
        {incident.source === "demo" && <StatusChip meaning={SIMULATED} />}
        {incident.source === "red_team" && <StatusChip meaning={RED_TEAM} />}
      </div>
      {verdict && <RiskMeter score={verdict.riskScore} />}
      {verdict?.disagreement && (
        <p className="notice">The agent's verdict did not match the evidence, so a person must review this.</p>
      )}
      {unfinished && (
        <>
          <p className="notice">This investigation is still running. New steps appear as they happen.</p>
          <p className="investigating">
            <LatticeLoader
              status="working"
              label={status === "queued" ? "Queued" : "Investigating"}
              startedAt={Date.parse(incident.createdAt)}
            />
          </p>
        </>
      )}
      {status === "error" && <p className="notice">This investigation stopped before finishing. Any evidence so far is below.</p>}
    </div>
  );
}

/** The Evidence tab: what was reported, and every step the investigation took. */
export function EvidenceTimeline({ incident, highlighted }: { incident: IncidentDetail; highlighted: string | null }) {
  const { evidence } = incident;
  // The steps already shown. Ones found later (live) are marked new, so only they slide in.
  const seen = useRef<{ incident: number; labels: Set<string> } | null>(null);
  if (seen.current === null || seen.current.incident !== incident.id) {
    seen.current = { incident: incident.id, labels: new Set(evidence.map((step) => step.label)) };
  }
  const shown = seen.current.labels;
  useEffect(() => {
    evidence.forEach((step) => shown.add(step.label));
  });
  return (
    <div className="panel">
      <details className="payload">
        <summary>What was reported</summary>
        <pre>{JSON.stringify(incident.payload, null, 2)}</pre>
      </details>

      {evidence.length === 0 && <p className="muted">No evidence yet.</p>}
      <ol className="timeline" aria-live="polite">
        {evidence.map((step) =>
          step.status === "ok" ? (
            <StepCard key={step.label} step={step} highlighted={highlighted === step.label} arrived={!shown.has(step.label)} />
          ) : (
            <GuardrailCard
              key={step.label}
              step={step}
              highlighted={highlighted === step.label}
              arrived={!shown.has(step.label)}
            />
          ),
        )}
      </ol>
    </div>
  );
}
