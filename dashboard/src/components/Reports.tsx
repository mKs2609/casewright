import type { PlainReport as Plain, SocReport as Soc, Verdict } from "../types";
import { verdictMeaning } from "../meaning";
import { EvidenceChip, StatusChip } from "./Chips";

type Cite = (label: string) => void;

function PlainReport({ report, verdict, onCite }: { report: Plain; verdict: Verdict; onCite: Cite }) {
  return (
    <article className="card report report-plain" aria-label="Report for everyone">
      <h3 className="label">For everyone</h3>
      <StatusChip meaning={verdictMeaning(verdict.verdict)} />
      <h4 className="plain-headline">{report.headline}</h4>
      <p>{report.whatHappened}</p>
      {report.reasons.length > 0 && (
        <>
          <h5>Why we think so</h5>
          <ul>
            {report.reasons.map((reason) => (
              <li key={reason.signal}>
                {reason.text} <EvidenceChip label={reason.evidence} onCite={onCite} />
              </li>
            ))}
          </ul>
        </>
      )}
      <h5>What to do</h5>
      <ul>
        {report.whatToDo.map((step) => (
          <li key={step}>{step}</li>
        ))}
      </ul>
    </article>
  );
}

/** The one model-written line. Its citations, like [E2, E1], become chips; everything else is plain text. */
function AiSummary({ text, onCite }: { text: string; onCite: Cite }) {
  const parts = text.split(/\[(E\d+(?:,\s*E\d+)*)\]/);
  return (
    <p>
      <span className="muted">AI summary: </span>
      {parts.map((part, index) =>
        index % 2 === 1 ? (
          part.split(/,\s*/).map((label) => <EvidenceChip key={`${index}-${label}`} label={label} onCite={onCite} />)
        ) : (
          <span key={index}>{part}</span>
        ),
      )}
    </p>
  );
}

function SocReport({ report, verdict, onCite }: { report: Soc; verdict: Verdict; onCite: Cite }) {
  return (
    <article className="card report" aria-label="Report for the security team">
      <h3 className="label">For the security team</h3>
      <p>
        <strong>{report.headline}</strong>
      </p>
      {report.aiSummary && <AiSummary text={report.aiSummary} onCite={onCite} />}
      {report.techniques.length > 0 && (
        <div className="chip-row">
          {report.techniques.map((technique) => (
            <span key={technique} className="technique mono">
              {technique}
            </span>
          ))}
        </div>
      )}
      {report.findings.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Evidence</th>
                <th scope="col">Finding</th>
                <th scope="col">Weight</th>
              </tr>
            </thead>
            <tbody>
              {report.findings.map((finding) => (
                <tr key={finding.signal}>
                  <td>
                    <EvidenceChip label={finding.evidence} onCite={onCite} />
                  </td>
                  <td>{finding.text}</td>
                  <td className="mono">{finding.weight}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {verdict.counterfactual && (
        <>
          <h5>What would change this</h5>
          <p>{verdict.counterfactual}</p>
        </>
      )}
      <h5>Next steps</h5>
      <ul>
        {report.nextSteps.map((step) => (
          <li key={step}>{step}</li>
        ))}
      </ul>
    </article>
  );
}

export function Reports({ verdict, onCite }: { verdict: Verdict | null; onCite: Cite }) {
  if (!verdict) {
    return <p className="muted">The reports appear once the investigation has finished.</p>;
  }
  if (!verdict.plainReport || !verdict.socReport) {
    return <p className="muted">This incident was investigated before reports existed.</p>;
  }
  return (
    <>
      <PlainReport report={verdict.plainReport} verdict={verdict} onCite={onCite} />
      <SocReport report={verdict.socReport} verdict={verdict} onCite={onCite} />
    </>
  );
}
