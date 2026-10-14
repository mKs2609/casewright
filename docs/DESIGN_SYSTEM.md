# Design System

**Status:** Draft v1 · **Last updated:** 2026-10-02
Applies to the React dashboard. Tokens live in `dashboard/src/styles/tokens.css` as CSS variables; components never hardcode a colour, size or duration.

---

## 1. Principles

1. **Calm by default, loud only when it matters.** A quiet screen means nothing is wrong. Red is reserved for real danger and blocked actions.
2. **Evidence first.** Every claim on screen can be traced to an evidence item in one click.
3. **Two audiences, one truth.** The expert view and the plain view sit side by side and never disagree.
4. **Show the work.** The investigation appears step by step, so a viewer understands *how* the verdict was reached.
5. **Never colour alone.** Every status uses colour **plus** an icon **plus** a word.
6. **Untrusted text is just text.** Anything that came from an incident is rendered as plain text, never as HTML.

## 2. Colour tokens

Dark theme only for v1 (a SOC dashboard is used in low light and on projectors).
Contrast ratios below were measured against the three surface colours (WCAG 2.1; body text needs ≥ 4.5, large text and UI parts ≥ 3).

### Surfaces and text
| Token | Hex | Use | Contrast on bg / surface / surface-2 |
|---|---|---|---|
| `--color-bg` | `#0b0f14` | Page background | – |
| `--color-surface` | `#121821` | Cards, panels | – |
| `--color-surface-2` | `#18202b` | Raised elements, buttons | – |
| `--color-border` | `#243040` | Decorative dividers only | 1.4 (decorative, not relied on) |
| `--color-border-control` | `#5b728f` | Borders of inputs and buttons | 3.9 / 3.6 / 3.3 |
| `--color-text` | `#dbe4ee` | Body text | 15.0 / 13.9 / 12.8 |
| `--color-text-muted` | `#8494a7` | Secondary text, timestamps | 6.2 / 5.7 / 5.3 |
| `--color-accent` | `#4cc2ff` | Links, focus ring, evidence chips, "investigating" | 9.6 / 8.9 / 8.2 |
| `--color-on-accent` | `#04121c` | Text on accent backgrounds | 9.4 on accent |

### Meaning (verdicts and states)
| Token | Hex | Meaning | Icon | Word | Contrast on bg / surface / surface-2 |
|---|---|---|---|---|---|
| `--color-benign` | `#3fcf8e` | Safe, approved, intact | ✓ check | "Safe" | 9.6 / 8.9 / 8.2 |
| `--color-suspicious` | `#f5b942` | Unusual, waiting for a human | ! triangle | "Suspicious" | 10.9 / 10.1 / 9.3 |
| `--color-malicious` | `#ff5d5d` | Attack, blocked, tampered | ✕ octagon | "Attack" | 6.4 / 5.9 / 5.4 |
| `--color-info` | `#c6a8ff` | MITRE technique tags | – | – | 9.6 / 8.9 / 8.2 |
| `--color-danger-fill` | `#c93a3a` | Background of destructive buttons (with white text) | – | – | white text: 5.1 |

> Do **not** put white text on `--color-malicious` (`#ff5d5d`): it measures 3.0 and fails. Use `--color-danger-fill` for filled red buttons.

### Risk scale
| Score | Band | Colour |
|---|---|---|
| 0–29 | Benign | `--color-benign` |
| 30–64 | Suspicious | `--color-suspicious` |
| 65–100 | Malicious | `--color-malicious` |

The number is always shown next to the bar; the bar colour is a reinforcement, not the message.

## 3. Typography

| Token | Value | Use |
|---|---|---|
| `--font-sans` | `system-ui, "Segoe UI", Roboto, sans-serif` | Everything |
| `--font-mono` | `ui-monospace, "Cascadia Code", Consolas, monospace` | IPs, domains, IDs, JSON, scores |

| Style | Size / line-height / weight | Use |
|---|---|---|
| Display | 26 / 32 / 700, mono | Risk number |
| H1 | 20 / 28 / 600 | Plain-report headline |
| H2 | 18 / 26 / 600 | Incident title |
| H3 | 16 / 24 / 600 | Card titles |
| Body | 14 / 21 / 400 | Default |
| Body-large | 15 / 24 / 400 | Plain-language report text |
| Small | 12 / 18 / 400 | Metadata, timestamps |
| Label | 12 / 16 / 500, uppercase, +0.06em | Section labels only |

Minimum size is 12px. Numbers that are compared (scores, counts) use tabular figures.

## 4. Spacing, shape, elevation

| Token | Value |
|---|---|
| `--space-1 … --space-6` | 4, 8, 12, 16, 24, 32 px |
| `--radius-sm` / `--radius-md` / `--radius-lg` / `--radius-pill` | 4 / 8 / 12 / 999 px |
| Elevation | Flat. Depth is shown with surface colour steps and borders, not shadows. |

Layout: three columns on desktop (incidents 290px · investigation 1.25fr · reports 1fr), collapsing to a single column under 1150px. No horizontal scrolling at any width; long values (domains, hashes) wrap.

## 5. Motion

| Token | Value | Use |
|---|---|---|
| `--motion-fast` | 150 ms | Hover, focus |
| `--motion-base` | 450 ms, `cubic-bezier(.2,.8,.2,1)` | A step entering the timeline |
| `--motion-slow` | 600 ms | Risk bar growing |

- Motion explains change: a step slides in, the risk bar grows. Nothing loops forever except the single "investigating" pulse.
- Respect `prefers-reduced-motion`: replace movement with an instant change.

## 6. Components

| Component | Purpose | Rules |
|---|---|---|
| **App bar** | Product name, engine badge, audit-chain badge, live-connection badge, user menu | Badges always show icon + text. |
| **Scenario buttons** | Fire simulated incidents | One primary "Attempt breach"; others secondary. Disabled for `VIEWER`. |
| **Incident list item** | One incident in the feed | Verdict icon + colour dot, kind icon, `#id`, subject, status text, risk number. Selected state uses accent border. |
| **Risk meter** | Running risk score | Big number + bar. Updates on every step. `role="meter"` with `aria-valuenow`. |
| **Step card** | One tool call | Evidence chip (`E3`), tool name, arguments, one-line summary, signal chips, expandable raw evidence. |
| **Guardrail card** | A blocked call/action | Red border, shield icon, the word "Blocked", the reason. |
| **Thought line** | Agent narration | Muted italic, no card. |
| **Evidence chip** | Reference like `E3` | Always a button; clicking scrolls to and highlights that step. |
| **Signal chip** | A finding and its weight | Mono text; three strength levels (muted / amber / red) plus the numeric weight. |
| **Report panel (plain)** | For everyone | Headline with icon and word, "what happened", "why we think so", "what to do". Body-large text. |
| **Report panel (SOC)** | For experts | Verdict line, technique tags, analysis with evidence chips, findings table, indicator table, counterfactual, actions. |
| **Approval card** | Human decision | Amber border. Shows evidence summary **above** the buttons. Approve = danger-fill button, Reject = ghost button, optional reason field, expiry time. |
| **Status chip** | Any state | Icon + word; colour from the meaning tokens. |
| **Toast** | Transient feedback | `role="status"`, auto-dismiss after 3.5 s, never the only place an error appears. |
| **Empty state** | Nothing selected | One sentence telling the user what to do next. |

### States every interactive component must define
Default · hover · focus-visible (2px accent outline, 1px offset) · active · disabled (45% opacity, `not-allowed`) · loading.

## 7. Icons

One outline icon set (Lucide), 16–20px, `currentColor`. Decorative icons are `aria-hidden`; icon-only buttons have an `aria-label`. Emoji are not used in the product UI.

## 8. Voice and content

### Plain-language report (for employees)
- Short sentences. Aim for a reading grade of 8 or below.
- No acronyms, no product names, no technique IDs. Say "one-time code", not "OTP" or "MFA".
- Say what happened, then what to do. Lead with the action if there is one.
- Reassure: reporting is good, clicking by mistake is fixable. Never blame.
- Never ask the reader to do something risky (reply, click, call a number from the message).

| Instead of | Write |
|---|---|
| "Credential-harvesting phish via look-alike domain" | "This email pretends to be from a service you trust so you'll type in your password." |
| "Anomalous geo-velocity detected" | "Your account was used in two far-apart places within minutes." |

### SOC report (for analysts)
- Precise and compact. Every factual claim carries an evidence chip.
- Use standard terms (IOC, TTP, technique IDs) without explaining them.
- State uncertainty and the counterfactual plainly.

### Interface text
- Buttons say what happens: "Approve block", not "OK".
- Errors say what went wrong and what to do, in the interface's voice, without blaming.
- Sentence case everywhere.

## 9. Accessibility checklist

- [ ] All text meets the contrast values in section 2.
- [ ] Every status has icon + word, not just colour.
- [ ] Everything works by keyboard; focus is always visible; focus order follows reading order.
- [ ] Live updates are announced politely (`aria-live="polite"` on the timeline; not every step interrupts).
- [ ] `prefers-reduced-motion` is respected.
- [ ] Touch/click targets are at least 32×32px.
- [ ] Page works at 200% zoom without horizontal scrolling.

## 10. Security rules for the UI

- Render untrusted strings with React's default text escaping. `dangerouslySetInnerHTML` is banned.
- No inline scripts or inline event-handler attributes (the CSP forbids them).
- No secrets in the bundle; the browser only ever holds HttpOnly cookies it cannot read.
- Links built from incident data are never clickable.
