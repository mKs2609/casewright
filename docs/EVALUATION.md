# Evaluation

How often Casewright gets it right, measured on labelled incidents (PRD section 8). The method is in ADR-53 in [`DECISIONS.md`](DECISIONS.md).

**This file is generated** by `scripts\evaluate.py` and checked by `agent/tests/test_evaluation.py`: if the numbers below stop matching what the agent does, CI fails.

## What is measured

- **Attacks caught** (detection rate, or recall): of the attacks, how many were sent to a person (`needs_review`) rather than closed as harmless.
- **False alarms** (false-positive rate): of the harmless incidents, how many were sent to a person anyway.
- Each rate comes with a **95% range** (Wilson score interval). With 20 or 30 examples, one example moves a rate by 3 to 5 points, so the range shows how sure the number is.
- The rule engine is measured (no AI model), so every run gives the same answer.

## Results

| Measure | Result, and 95% range | PRD target |
|---|---|---|
| **Held-out set** (the honest number): attacks caught | 12 of 20 (60%), range 39% to 78% | **not met** (at least 90%) |
| **Held-out set** (the honest number): false alarms | 1 of 20 (5%), range 1% to 24% | met (at most 10%) |
| Development set, after the fixes: attacks caught | 27 of 30 (90%), range 74% to 97% | met (at least 90%) |
| Development set, after the fixes: false alarms | 4 of 30 (13%), range 5% to 30% | **not met** (at most 10%) |
| Development set, first run: attacks caught | 22 of 30 (73%), range 56% to 86% | **not met** (at least 90%) |
| Development set, first run: false alarms | 6 of 30 (20%), range 10% to 37% | **not met** (at most 10%) |

**In plain words:** on incidents it was not tuned on, the rule engine raised 1 false alarm(s) in 20 harmless incidents, but let 8 of 20 attacks through. The ones it misses use no tell-tale words: a calm request with no link, no threat and nothing the threat list knows. The development set's after-fix numbers are flattering, because the fixes were made by looking at it; the held-out set was written after the fixes and run once, so it is the number to quote.

## The sets

- **Development set**: 60 incidents (`agent/tests/evaluation_set.py`), 30 attacks and 30 harmless. Written first, run, and used to find gaps.
- **Held-out set**: 40 incidents (`agent/tests/evaluation_heldout.py`), 20 attacks and 20 harmless. Written after the fixes, with different scams and situations, and run once.
- Every attack follows a pattern from a public source (below). The wording is our own and every name, address and number is a reserved example one. None is one of the six demo scenarios.
- Both sets include hard cases on purpose, both ways: attacks with no obvious keyword, and harmless messages that contain one (a real bank alert that mentions an OTP, a security-training email that quotes phishing phrases, a company VPN in another country).
- Both sets are frozen. A new example is added, never an old one changed.

### By kind of incident

Held-out set:

| Kind | Attacks caught | False alarms |
|---|---|---|
| Emails | 4 of 8 | 0 of 8 |
| Sign-in batches | 5 of 6 | 1 of 6 |
| Phone calls | 3 of 6 | 0 of 6 |

Development set, after the fixes (first run in brackets):

| Kind | Attacks caught | False alarms |
|---|---|---|
| Emails | 11 of 12 (9) | 2 of 12 (3) |
| Sign-in batches | 9 of 10 (8) | 2 of 10 (2) |
| Phone calls | 7 of 8 (5) | 0 of 8 (1) |

## What the held-out set got wrong

| Example | Truth | Casewright said | Risk | Findings | About it |
|---|---|---|---|---|---|
| `held-email-benefits-enrolment` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | HR-themed credential harvest: benefits enrolment 'closes Friday', log in with company credentials. |
| `held-email-payroll-diversion` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | Hard: payroll diversion. A colleague's 'personal address' asks payroll to change the salary account. No link, no threat. |
| `held-email-macro-invoice` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | Hard: an 'overdue invoice' attachment that asks to enable macros (how malware gets in). No link. |
| `held-email-injection-summarise` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | Hard: an indirect prompt injection with no classic phrase; it asks the AI to describe the email as a newsletter and leave out the link. |
| `held-login-stolen-session-us` | malicious | benign | 25 | `BASELINE-GEO` | Hard: a stolen session replayed from the US with the person's own browser name, in working hours. |
| `held-login-cached-old-password` | benign | suspicious | 46 | `BASELINE-DEVICE`, `SUCCESS-AFTER-FAILURES` | Hard: after a password change, a phone keeps trying the old one, then the person types the new one. |
| `held-call-hr-bank-details` | malicious | benign | 5 | `BASELINE-UNKNOWN-CALLER` | Hard: a fake HR caller 'updating payroll records' asks for the bank account number. |
| `held-call-insurance-refund` | malicious | benign | 24 | `BASELINE-UNKNOWN-CALLER`, `SIG-PAYMENT` | Insurance-refund scam: money is waiting, pay a processing charge by UPI first. |
| `held-call-investment-advisor` | malicious | benign | 5 | `BASELINE-UNKNOWN-CALLER` | Hard: an 'investment advisor' promises guaranteed returns and wants a transfer to a wallet. Calm, polite. |

## What the development set still gets wrong

Left as they are on purpose: a fix would only fit these examples, or would weaken a check that catches real attacks (for example, lowering the weight of "success after many failures" would hide the account takeover in `held-login-local-takeover`).

| Example | Truth | Casewright said | Risk | Findings | About it |
|---|---|---|---|---|---|
| `email-parcel-customs-fee` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | Courier scam: a parcel is held, pay a small fee on a link (which asks for card details). |
| `email-otp-awareness` | benign | suspicious | 35 | `SIG-OTP-REQ` | Hard: IT warns staff never to share an OTP, so the text names the thing attackers ask for. |
| `email-phishing-training` | benign | suspicious | 49 | `SIG-CRED-REQ`, `SIG-PAYMENT`, `SIG-URGENCY` | Hard: a security-training announcement that quotes the phrases phishing emails use. |
| `login-stolen-creds-same-city` | malicious | benign | 10 | `BASELINE-DEVICE` | Hard: a password stolen by malware, used from the person's own city in working hours; only the device is new. |
| `login-forgot-password-after-leave` | benign | suspicious | 40 | `SUCCESS-AFTER-FAILURES` | Hard: back from leave, six wrong guesses at a half-remembered password, then a success. |
| `login-company-vpn-exit` | benign | suspicious | 55 | `BASELINE-GEO`, `IMPOSSIBLE-TRAVEL` | Hard: switching on the company VPN, whose exit is in Singapore, 25 minutes after signing in at home. |
| `call-electricity-cutoff` | malicious | benign | 19 | `BASELINE-UNKNOWN-CALLER`, `SIG-URGENCY` | Hard: 'your power will be cut tonight', pay a small amount through an app the caller sends. |

## What the first run changed

The first run missed 8 attacks and raised 6 false alarms. Each change below is a general rule, written from what the attack does rather than the example's words.

| Gap | Change | First seen in |
|---|---|---|
| Asks for card or bank details | New finding `SIG-FINANCIAL-DETAILS`. | `email-tax-refund` |
| Threatens arrest or legal action | New finding `SIG-THREAT`. | `call-digital-arrest` |
| Asks to keep it secret | New finding `SIG-SECRECY`. | `call-cloned-ceo-voice` |
| Password spraying over many addresses | New finding `PASSWORD-SPRAY`: failures on 10+ accounts from 3+ addresses, at least 80% failing, when no single address is already credential stuffing. | `login-distributed-spray` |
| Police, customs and tax officials | `SIG-IMPERSONATION` also recognises them, and "I am ...". | `call-digital-arrest` |
| Deadlines in days; power cuts | `SIG-URGENCY` also recognises "within 3 days", "will be disconnected", "do it fast". | `email-tax-refund` |
| "Sign in with your password" | `SIG-CRED-REQ` also recognises requests to enter or sign in with a password. | `email-document-share` |
| "We will never ask for your OTP" | A request finding no longer fires on a mention that directly follows "never ask for". Deliberately narrow: a "never" anywhere else does not switch it off (tested in `test_patterns.py`). | `email-bank-statement` |

Missed on the first run: `email-document-share`, `email-tax-refund`, `email-parcel-customs-fee`, `login-distributed-spray`, `login-stolen-creds-same-city`, `call-digital-arrest`, `call-electricity-cutoff`, `call-cloned-ceo-voice`.

False alarms on the first run: `email-otp-awareness`, `email-bank-statement`, `email-phishing-training`, `login-forgot-password-after-leave`, `login-company-vpn-exit`, `call-real-fraud-alert`.

## With the local AI model

Model `qwen3:8b`, run on 2026-11-09. The model's answers vary from run to run, so CI does not repeat this; it is a recorded measurement. The rules still set the minimum: the model can make a verdict more severe, never less (ADR-43).

| Set | Attacks caught | False alarms | Investigations the model finished |
|---|---|---|---|
| Held-out | 20 of 20 (100%), range 84% to 100% | 13 of 20 (65%), range 43% to 82% | 37 of 40 |
| Development | 30 of 30 (100%), range 89% to 100% | 16 of 30 (53%), range 36% to 70% | 55 of 60 |

**In plain words:** where the model led (92 of 100 investigations; the rest fell back to the rule engine after a model failure or time limit), it called 57 "suspicious". Of the 39 harmless incidents whose evidence scored below 30 (benign by the rules), it flagged 24: it treats any finding, even an unknown caller, as a warning sign. Because the model can raise a verdict but never lower it, it can add catches and false alarms but never turn a catch into a miss. With the model on, the system is safe but noisy: too many false alarms teach people to ignore them. Calibrating the model's verdicts is future work, and would need its own held-out measurement.

## Limitations

- **Small sets.** 50 attacks and 50 harmless incidents in all. The 95% ranges above are wide; a few more misses or catches would move the numbers noticeably.
- **The same author** wrote the examples and the detectors. Writing the held-out set after the fixes reduces this, but an independent author, or real reported incidents, would be a stronger test.
- **Synthetic text.** The examples follow published attack patterns, but they are not real messages: real attacks are messier, longer and in many languages (all of these are in English).
- **A small threat list.** The built-in list knows a handful of example addresses (ADR-40), so most attacks here are judged on their words and behaviour alone. A real threat-intelligence feed would catch more.
- **One incident at a time.** Each example is investigated on its own; links to other recent incidents (ADR-42), which would help with campaigns, are not part of this measurement.
- **Only the decision is measured**: flagged or closed. Whether the attack type and the reports are right is checked by other tests, on the demo scenarios.

## Sources

The patterns the attacks follow:

- `T1566.002`: [MITRE ATT&CK T1566.002, Phishing: spearphishing link](https://attack.mitre.org/techniques/T1566/002/)
- `T1566.004`: [MITRE ATT&CK T1566.004, Phishing: spearphishing voice](https://attack.mitre.org/techniques/T1566/004/)
- `T1110.001`: [MITRE ATT&CK T1110.001, Brute force: password guessing](https://attack.mitre.org/techniques/T1110/001/)
- `T1110.003`: [MITRE ATT&CK T1110.003, Brute force: password spraying](https://attack.mitre.org/techniques/T1110/003/)
- `T1110.004`: [MITRE ATT&CK T1110.004, Brute force: credential stuffing](https://attack.mitre.org/techniques/T1110/004/)
- `T1078`: [MITRE ATT&CK T1078, Valid accounts](https://attack.mitre.org/techniques/T1078/)
- `T1111`: [MITRE ATT&CK T1111, Multi-factor authentication interception](https://attack.mitre.org/techniques/T1111/)
- `T1219`: [MITRE ATT&CK T1219, Remote access tools](https://attack.mitre.org/techniques/T1219/)
- `T1656`: [MITRE ATT&CK T1656, Impersonation](https://attack.mitre.org/techniques/T1656/)
- `T1657`: [MITRE ATT&CK T1657, Financial theft](https://attack.mitre.org/techniques/T1657/)
- `AML.T0051`: [MITRE ATLAS AML.T0051, LLM prompt injection](https://atlas.mitre.org/techniques/AML.T0051)
- `OWASP-LLM01`: [OWASP Top 10 for LLM Applications, LLM01 Prompt injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- `IC3`: [FBI Internet Crime Complaint Center (IC3) public service announcements: business email compromise, payroll and vendor fraud, tech-support and government-impersonation scams, AI voice cloning](https://www.ic3.gov/)
- `FTC`: [US Federal Trade Commission consumer advice: gift-card, job, refund and tech-support scams](https://consumer.ftc.gov/)
- `RBI`: [Reserve Bank of India, "BE(A)WARE" booklet on the methods of financial fraudsters: KYC updates, OTP requests, UPI collect requests](https://www.rbi.org.in/)
- `I4C`: [Indian Cyber Crime Coordination Centre (I4C) advisories: "digital arrest", courier, electricity-bill and fake-job scams](https://cybercrime.gov.in/)
- `CISA-PHISHING`: [CISA, NSA, FBI and MS-ISAC, "Phishing Guidance: Stopping the Attack Cycle at Phase One" (2023)](https://www.cisa.gov/)
- `CISA-AA23-320A`: [CISA advisory AA23-320A: help-desk impersonation and MFA prompts](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)
- `APWG`: [Anti-Phishing Working Group, Phishing Activity Trends Reports](https://apwg.org/trendsreports/)

## Run it yourself

```
agent\.venv\Scripts\python.exe scripts\evaluate.py
```

Prints every example's result and rewrites this file. With `--model`, it also runs both sets with the local AI model (Ollama must be running) and records the result for the section above.
