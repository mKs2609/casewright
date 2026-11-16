# Design System

**Status:** v2 "signal" · **Last updated:** 2026-11-16
Applies to the React dashboard. Tokens live in `dashboard/src/styles/tokens.css` as CSS variables; components never hardcode a colour, size or duration, and every token is used (`src/test/rules.test.ts` checks all three). Decision: [ADR-57](DECISIONS.md).

A near-black, monochrome control room on a faint blueprint grid, with white type and **one soft indigo signal colour** (from the Dovetail and zkPass references). Headlines are a whisper-weight serif; labels are widely tracked capitals with a small indigo icon; panels are sharp and separated by hairlines. The login is one centred stack over a slowly turning dotted globe, with an icon tile set into the headline like a word.

---

## 1. Principles

1. **Calm by default, loud only when it matters.** A quiet screen means nothing is wrong. Red is reserved for real danger and blocked actions.
2. **Evidence first.** Every claim on screen can be traced to an evidence item in one click.
3. **Two audiences, one truth.** The expert view and the plain view sit side by side and never disagree.
4. **Show the work.** The investigation appears step by step, so a viewer understands *how* the verdict was reached.
5. **Never colour alone.** Every status uses colour **plus** an icon **plus** a word.
6. **Untrusted text is just text.** Anything that came from an incident is rendered as plain text, never as HTML.
7. **One signal.** Indigo marks only focus, evidence references, label icons, the timeline, the open incident and one accent word. The main action is white. Everything else is monochrome, except the meaning colours.
8. **Nothing blends.** Text always sits on a solid panel or, on the login, on a dark pool that keeps the globe's dots away from it.

## 2. Colour tokens

Dark theme only. Contrast ratios were measured (WCAG 2.1): body text needs at least 4.5, large text and the borders of controls at least 3.

### Surfaces and text
| Token | Hex | Use | Contrast on bg / surface / surface-2 |
|---|---|---|---|
| `--color-void` | `#000000` | App bar, inputs, code | – |
| `--color-bg` | `#060606` | Page background | – |
| `--color-surface` | `#121212` | Panels, cards | – |
| `--color-surface-2` | `#1c1c1c` | Buttons, meter track | – |
| `--color-border` | `#252525` | Hairline dividers (decorative) | not relied on |
| `--color-border-control` | `#6e6e6e` | Borders of inputs and buttons | 3.9 / 3.7 / 3.3 |
| `--color-text-strong` | `#ffffff` | Headlines, names | 20 or more |
| `--color-text` | `#e5e5e5` | Body text | 16.1 / 14.9 / 13.5 |
| `--color-text-muted` | `#8f8f8f` | Secondary text, timestamps | 6.3 / 5.8 / 5.3 |
| `--color-label` | `#868686` | Bracketed labels | 5.6 / 5.1 / 4.7 |
| `--color-accent` | `#6798ff` | The signal (black on it: 7.5; never white text on it: 2.8) | 7.2 / 6.7 / 6.1 |
| `--color-grid` | white at 3.5% | The blueprint grid behind the page (decoration) | – |

The main button is white with black text (21:1). The signal's glow (`--glow-accent`) is the only shadow in the system: on the logo tile, the headline tile, the open incident, the timeline's markers and a hovered main button.

### Meaning (verdicts and states)
| Token | Hex | Meaning | Icon | Word | Contrast on bg / surface / surface-2 |
|---|---|---|---|---|---|
| `--color-benign` | `#4fd69c` | Safe, approved, intact | ✓ check | "Safe" | 11.0 / 10.2 / 9.3 |
| `--color-suspicious` | `#f0b54a` | Unusual, waiting for a human | ! triangle | "Suspicious" | 11.0 / 10.2 / 9.3 |
| `--color-malicious` | `#ff6e6e` | Attack, blocked, tampered | ✕ octagon | "Attack" | 7.4 / 6.9 / 6.3 |
| `--color-info` | `#b8a5ff` | MITRE technique tags | – | – | 9.5 / 8.8 / 8.0 |
| `--color-danger-fill` | `#c93a3a` | Destructive buttons (white text: 5.1) | – | – | – |

Chips take their colour from `currentcolor`: the text in the meaning colour, a hairline at 40% and a wash at 7% of it (`color-mix`), so one rule serves every tone.

### Risk scale
| Score | Band | Colour |
|---|---|---|
| 0–29 | Benign | `--color-benign` |
| 30–64 | Suspicious | `--color-suspicious` |
| 65–100 | Malicious | `--color-malicious` |

The number is always shown next to the bar; the bar colour is a reinforcement, not the message.

## 3. Typography

Free fonts under the SIL Open Font License, **bundled into the app** from the Fontsource packages and served by our own server (the page policy allows fonts from nowhere else).

| Token | Font | Use |
|---|---|---|
| `--font-display` | Source Serif 4, weight 300 (and its italic) | Wordmark, login headline, incident title, plain-report headline, risk number |
| `--font-sans` | Inter Tight (variable) | Body, controls, labels, chips |
| `--font-mono` | IBM Plex Mono 400/500 | IDs, values, evidence references, signals |

| Style | Size / line / weight | Use |
|---|---|---|
| Hero | 72 / 70 / 300 serif, −0.025em | Login headline (44 on phones); an icon tile set in it, and one italic indigo accent word |
| Display | 56 / 52 / 300 serif | Risk number |
| Title | 32 / 36 / 300 serif | Incident title |
| Headline | 26 / 30 / 300 serif | Wordmark, plain-report headline |
| Body | 14 / 22 / 400 | Default |
| Body-large | 15 / 24 / 400 | Plain-language report |
| Small | 12 / 18 / 400 | Metadata, timestamps |
| Label | 12 / 16 / 500, upper case, +0.2em, with a 14px indigo icon | Section labels, roles, table headers |
| Tag | 12 / 18 / 500, upper case, +0.06em | Chips, tool names |

Minimum size is 12px. Numbers that are compared use tabular figures. Label icons are `aria-hidden`, so headings read as their words.

## 4. Spacing, shape, elevation

| Token | Value |
|---|---|
| `--space-1 … --space-7` | 4, 8, 12, 16, 24, 32, 48 px |
| Panels and cards | Sharp (no radius); a 1px `--color-border` hairline |
| `--radius-tag` / `--radius-button` / `--radius-tile` / `--radius-pill` | 2 (evidence and signal tags) / 4 (buttons, inputs, logo tile) / 10 (the headline tile) / pill (status chips) |
| `--neon-bar` | 3px indigo bar along the top of every page |
| `--grid-size` | 56px blueprint grid |
| Elevation | Flat: surface steps and hairlines. The only glow belongs to the signal. |

Layout: three columns on desktop (incidents 300px · investigation 1.25fr · reports 1fr, at most 1600px wide), one column under 1150px. The login is centred. No horizontal scrolling at any width; long values wrap.

## 5. Motion

| Token | Value | Use |
|---|---|---|
| `--motion-fast` | 150 ms | Hover, focus |
| `--motion-slow` | 600 ms, `--ease-out` | Risk bar growing; a front-page block rising into view |
| `--motion-stagger` | 120 ms | The delay between the four tool steps rising in |
| `--motion-pulse` | 1800 ms | The arrow on "See how it works" nudging down |

- The dotted globe behind the login turns slowly and leans with the pointer. It draws one still frame when the visitor asks for reduced motion, and stops while the tab is hidden.
- On the front page, blocks rise into view once as they are scrolled to, and a thin line along the top grows with the scroll (a CSS scroll-driven animation; browsers without it show the line full).
- Respect `prefers-reduced-motion`: transitions and animations are switched off, every block is simply there, and the progress line is hidden.

## 6. Components

| Component | Purpose | Rules |
|---|---|---|
| **App bar** | Indigo logo tile (radar), serif wordmark, audit-chain badge, user badge (pill), log out | Black, sticky, under the indigo bar. Badges always show icon + text. |
| **Live badge** | Beside "Incidents": Live, Connecting, or Live updates paused | Icon + word, read out politely (`role="status"`). Refresh stays available. |
| **Scenario buttons** | Fire simulated incidents, in a strip under the app bar | One white "Attempt breach"; others charcoal; the description on hover and to screen readers. Disabled for `VIEWER`, with a note why. Hidden when the gateway has demos off. |
| **Red-team button and scorecard** | "Red-team the agent"; on a run, a card listing each attempt, what is meant to stop it, and the outcome | Outcomes are icon + word: Blocked, Not blocked, Waiting. The card sits on an indigo hairline and wash. |
| **Simulated badge** | On demo incidents | Muted chip, icon + "Simulated". |
| **Incident list item** | One incident in the feed | Kind icon, mono `#id`, subject, risk number, chips, time. The open one: indigo hairline, wash and glow. |
| **Risk meter** | Running risk score | Panel with the serif number, "Risk / 100" (gauge icon), the scale and a 4px bar with a glow of its band colour. `role="meter"`. |
| **Evidence timeline** | The investigation's steps | One indigo rail with a glowing diamond per step (red, without glow, for a blocked step). |
| **Step card** | One tool call | Mono header "E1 PATTERN MATCH"; arguments as a two-column list; summary; signal tags; expandable raw evidence. |
| **Guardrail card** | A blocked call/action | Red hairline and wash, shield icon, the word "Blocked", the reason. |
| **Evidence chip** | Reference like `E3` | Always a button (indigo hairline, 2px radius); clicking scrolls to and highlights that step. |
| **Signal tag** | A finding and its weight | Mono text; three strengths (muted / amber / red) plus the numeric weight. |
| **Report panel (plain)** | For everyone | Serif headline, status chip, "what happened", "why we think so", "what to do". |
| **Report panel (SOC)** | For experts | Verdict line, technique tags, AI summary with evidence chips, findings table, counterfactual, next steps. |
| **Approval card** | Human decision | Amber hairline and wash. Evidence summary **above** the buttons. Approve = danger-fill, Reject = charcoal. Expiry time. |
| **Login** | The front door | Indigo bar, logo tile; centred "Agentic security analyst", "Every alert, [shield tile] *investigated.*", and the form, on a dark pool; the dotted globe (canvas, `aria-hidden`) behind. On the public demo, "Try the demo" with its note that nothing is real. |
| **Front page sections** | Below the login: 01 how it investigates, 02 two reports and a person decides | A serif section title with one indigo accent phrase; the four tools on the evidence rail; example reports with evidence references that look like the dashboard's but are not buttons (`.ref-chip`); an example decision whose buttons are dimmed pictures, labelled as an example. Every example uses reserved example names. |
| **Status chip** | Any state | Pill, upper case; icon + word in the meaning colour on its own wash. |
| **Empty state** | Nothing selected | One sentence telling the user what to do next. |

### States every interactive component must define
Default · hover · focus-visible (2px indigo outline, 2px offset) · active · disabled (45% opacity, `not-allowed`) · loading.

## 7. Icons

One outline icon set (Lucide), 14–20px, `currentColor`. Decorative icons are `aria-hidden`; icon-only buttons have an `aria-label`. Emoji are not used in the product UI.

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
- Sentence case in the text; labels and chips are upper-cased by CSS only, so screen readers and tests read the real words.
- The login says as little as possible: what it is, and the way in.

## 9. Accessibility checklist

- [ ] All text meets the contrast values in section 2.
- [ ] Every status has icon + word, not just colour.
- [ ] Everything works by keyboard; focus is always visible; focus order follows reading order.
- [ ] Live updates are announced politely (`aria-live="polite"` on the timeline; not every step interrupts). The globe is hidden from screen readers.
- [ ] `prefers-reduced-motion` is respected (section 5).
- [ ] Touch/click targets are at least 32×32px.
- [ ] Page works at 200% zoom and at phone width (390px) without horizontal scrolling.

## 10. Security rules for the UI

- Render untrusted strings with React's default text escaping. `dangerouslySetInnerHTML` is banned.
- No inline scripts or inline event-handler attributes (the page policy forbids them).
- Fonts, like scripts and styles, come only from our own server (`font-src 'self'`).
- No secrets in the bundle; the browser only ever holds HttpOnly cookies it cannot read.
- Links built from incident data are never clickable.
