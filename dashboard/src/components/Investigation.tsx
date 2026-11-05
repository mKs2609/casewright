import { ShieldX } from "lucide-react";

import { KIND_WORDS, riskBand, SIMULATED, statusMeaning, verdictMeaning, when } from "../meaning";
import type { Evidence, IncidentDetail } from "../types";
import { SignalChip, StatusChip } from "./Chips";

function RiskMeter({ score }: { score: number }) {
  return (
    <div className="risk-meter">
      <span className={`risk-score tone-text-${riskBand(score)}`}>{score}</span>
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
  );
}

/** A refused tool call: what the guardrails stopped, and why. */
function GuardrailCard({ step, highlighted }: { step: Evidence; highlighted: boolean }) {
  return (
    <li id={`evidence-${step.label}`} tabIndex={-1} className={`card guardrail ${highlighted ? "highlighted" : ""}`}>
      <div className="step-head">
        <ShieldX aria-hidden="true" size={16} />
        <strong>Blocked</strong>
        <span className="mono muted">{step.label}</span>
        <span className="mono">{step.tool}</span>
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

function StepCard({ step, highlighted }: { step: Evidence; highlighted: boolean }) {
  return (
    <li id={`evidence-${step.label}`} tabIndex={-1} className={`card step ${highlighted ? "highlighted" : ""}`}>
      <div className="step-head">
        <span className="evidence-tag mono">{step.label}</span>
        <span className="mono">{step.tool}</span>
      </div>
      <Arguments args={step.args} />
      <p>{step.summary}</p>
      {step.signals.length > 0 && (
        <div className="chip-row">
          {step.signals.map((signal) => (
            <SignalChip key={signal.id + (signal.indicator ?? "")} signal={signal} />
          ))}
        </div>
      )}
      <details>
        <summary>Raw evidence</summary>
        <pre>{JSON.stringify(step.result, null, 2)}</pre>
      </details>
    </li>
  );
}

interface Props {
  incident: IncidentDetail;
  highlighted: string | null;
}

export function Investigation({ incident, highlighted }: Props) {
  const { verdict, evidence, status } = incident;
  const unfinished = status === "queued" || status === "investigating";
  return (
    <section className="panel investigation" aria-label="Investigation">
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
          <span className="chip tone-muted">{verdict.engine === "llm" ? "Led by the AI model" : "Fixed plan"}</span>
        )}
        {incident.source === "demo" && <StatusChip meaning={SIMULATED} />}
      </div>
      {verdict && <RiskMeter score={verdict.riskScore} />}
      {verdict?.disagreement && (
        <p className="notice">The agent's verdict did not match the evidence, so a person must review this.</p>
      )}
      {unfinished && <p className="notice">This investigation is still running. New steps appear as they happen.</p>}
      {status === "error" && <p className="notice">This investigation stopped before finishing. Any evidence so far is below.</p>}

      <details className="payload">
        <summary>What was reported</summary>
        <pre>{JSON.stringify(incident.payload, null, 2)}</pre>
      </details>

      <h3 className="label">Evidence</h3>
      {evidence.length === 0 && <p className="muted">No evidence yet.</p>}
      <ol className="timeline" aria-live="polite">
        {evidence.map((step) =>
          step.status === "ok" ? (
            <StepCard key={step.label} step={step} highlighted={highlighted === step.label} />
          ) : (
            <GuardrailCard key={step.label} step={step} highlighted={highlighted === step.label} />
          ),
        )}
      </ol>
    </section>
  );
}
