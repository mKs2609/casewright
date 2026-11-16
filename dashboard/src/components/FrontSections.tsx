import { Fingerprint, Gauge, Globe, Link2, ScanSearch, UserRoundCheck, Users, Workflow, type LucideIcon } from "lucide-react";
import { useEffect, useRef, type ReactNode } from "react";

/**
 * Marks an element "is-visible" once it scrolls into view, which lets CSS fade it in (once).
 * Where the browser cannot watch (or in tests), it is simply visible from the start.
 */
function Reveal({ children, className = "" }: { children: ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const element = ref.current;
    if (!element) {
      return;
    }
    if (typeof IntersectionObserver === "undefined") {
      element.classList.add("is-visible");
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          element.classList.add("is-visible");
          observer.disconnect();
        }
      },
      { threshold: 0.15 },
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  return (
    <div ref={ref} className={`reveal ${className}`}>
      {children}
    </div>
  );
}

/** An evidence reference on the front page: it looks like the dashboard's, but goes nowhere. */
const Ref = ({ label }: { label: string }) => <span className="ref-chip">{label}</span>;

/**
 * The four tools, in the order the fixed plan runs them, with an example finding from a made-up
 * phishing email (reserved example names only: .example domains, 203.0.113.0/24).
 */
const TOOLS: { label: string; tool: string; Icon: LucideIcon; does: string; finding: string }[] = [
  {
    label: "E1",
    tool: "Pattern match",
    Icon: ScanSearch,
    does: "Reads the message for pressure, threats and requests for passwords or codes.",
    finding: "Asks to confirm credentials",
  },
  {
    label: "E2",
    tool: "Reputation lookup",
    Icon: Globe,
    does: "Checks every link, address and phone number against lists of known attackers.",
    finding: "paypa1-secure-login.example is on attacker lists",
  },
  {
    label: "E3",
    tool: "Baseline check",
    Icon: Fingerprint,
    does: "Compares the activity with what is normal for that person.",
    finding: "Sign-in from 203.0.113.42, a country never seen before",
  },
  {
    label: "E4",
    tool: "Correlation",
    Icon: Link2,
    does: "Looks for the same sender or address in other recent incidents.",
    finding: "The same sender reached two more people this week",
  },
];

function SectionHead({ index, Icon, kicker, title }: { index: string; Icon: LucideIcon; kicker: string; title: ReactNode }) {
  return (
    <Reveal className="section-head">
      <p className="label">
        <Icon aria-hidden="true" size={14} />
        <span className="section-index">{index}</span>
        {kicker}
      </p>
      <h2 className="section-title">{title}</h2>
    </Reveal>
  );
}

/** The front page's sections, below the login: what Casewright does, shown with made-up examples. */
export function FrontSections() {
  return (
    <div className="front-sections">
      <section id="how-it-works" className="front-section" aria-labelledby="how-title">
        <SectionHead
          index="01"
          Icon={Workflow}
          kicker="How it investigates"
          title={
            <span id="how-title">
              Four tools. <em>Every step on the record.</em>
            </span>
          }
        />
        <ol className="tool-steps">
          {TOOLS.map(({ label, tool, Icon, does, finding }, position) => (
            <li key={label}>
              <Reveal className={`tool-step step-${position + 1}`}>
                <span className="tool-icon">
                  <Icon aria-hidden="true" size={18} />
                </span>
                <div className="tool-text">
                  <p className="tool-name">
                    <Ref label={label} /> {tool}
                  </p>
                  <p className="muted">{does}</p>
                  <p className="tool-finding">{finding}</p>
                </div>
              </Reveal>
            </li>
          ))}
        </ol>
        <Reveal>
          <p className="section-note">
            Every tool is read-only and may only look up what is in the incident. Anything else is refused, and the
            refusal is shown as a blocked step.
          </p>
        </Reveal>
      </section>

      <section className="front-section" aria-labelledby="reports-title">
        <SectionHead
          index="02"
          Icon={Users}
          kicker="Two reports, one evidence chain"
          title={
            <span id="reports-title">
              One verdict, explained <em>twice.</em>
            </span>
          }
        />
        <div className="report-pair">
          <Reveal className="card example">
            <p className="label">
              <Users aria-hidden="true" size={14} />
              For everyone
            </p>
            <p className="plain-headline">This email is a scam.</p>
            <ul className="example-list">
              <li>
                This website is on lists of known attackers. <Ref label="E2" />
              </li>
              <li>
                The address is made to look like paypal.com, but it isn't. <Ref label="E2" />
              </li>
              <li>
                It asks you to confirm your password or account details. <Ref label="E1" />
              </li>
            </ul>
          </Reveal>
          <Reveal className="card example">
            <p className="label">
              <Gauge aria-hidden="true" size={14} />
              For the security team
            </p>
            <p className="example-verdict">Malicious: phishing · risk 90</p>
            <dl className="example-findings">
              <div>
                <dt>
                  <Ref label="E2" />
                </dt>
                <dd className="mono">paypa1-secure-login.example is known-malicious</dd>
              </div>
              <div>
                <dt>
                  <Ref label="E2" />
                </dt>
                <dd className="mono">imitates paypal.com</dd>
              </div>
              <div>
                <dt>
                  <Ref label="E1" />
                </dt>
                <dd className="mono">asks to confirm credentials</dd>
              </div>
            </dl>
          </Reveal>
        </div>

        <Reveal className="card example approval decide">
          <p className="label">
            <UserRoundCheck aria-hidden="true" size={14} />A person decides
          </p>
          <p>
            <strong>Block this domain</strong> <span className="mono">paypa1-secure-login.example</span> <Ref label="E2" />
          </p>
          <p className="muted">
            Risky actions are only ever proposed. Nothing happens until an analyst approves it, and every decision is
            written to a tamper-evident log.
          </p>
          <div className="button-row example-buttons">
            <span className="button button-danger" aria-hidden="true">
              Approve block
            </span>
            <span className="button" aria-hidden="true">
              Reject
            </span>
            <span className="small muted">Example: in the dashboard these are real buttons</span>
          </div>
        </Reveal>
      </section>

      <p className="front-footer small muted">Every example on this page is made up.</p>
    </div>
  );
}
