# Evaluation

How often Casewright gets it right, measured on labelled incidents (PRD section 8). The method is in ADR-53 and ADR-63 in [`DECISIONS.md`](DECISIONS.md).

**This file is generated** by `scripts\evaluate.py` and checked by `agent/tests/test_evaluation.py`: if the numbers below stop matching what the agent does, CI fails.

## What is measured

- **Attacks caught** (detection rate, or recall): of the attacks, how many were sent to a person (`needs_review`) rather than closed as harmless.
- **False alarms** (false-positive rate): of the harmless incidents, how many were sent to a person anyway.
- Each rate comes with a **95% range** (Wilson score interval). With 12 to 30 examples, one example moves a rate by 3 to 8 points, so the range shows how sure the number is.
- The rule engine is measured (no AI model), so every run gives the same answer.
- A set only gives an honest number until someone changes the detectors after reading its mistakes. So each round of fixes is measured on sets written before the fixes and run once afterwards (ADR-53, ADR-63).

## Results

| Measure | Result, and 95% range | PRD target |
|---|---|---|
| **Fourth held-out set** (fresh: the honest number): attacks caught | 6 of 20 (30%), range 15% to 52% | **not met** (at least 90%) |
| **Fourth held-out set** (fresh: the honest number): false alarms | 3 of 20 (15%), range 5% to 36% | **not met** (at most 10%) |
| Third held-out set, its one honest run (step 23): attacks caught | 8 of 20 (40%), range 22% to 61% | **not met** (at least 90%) |
| Third held-out set, its one honest run (step 23): false alarms | 2 of 20 (10%), range 3% to 30% | met (at most 10%) |
| Third held-out set now: attacks caught | 15 of 20 (75%), range 53% to 89% | **not met** (at least 90%) |
| Third held-out set now: false alarms | 2 of 20 (10%), range 3% to 30% | met (at most 10%) |
| Second held-out and independent sets, their one honest run (step 22): attacks caught | 13 of 32 (41%), range 26% to 58% | **not met** (at least 90%) |
| Second held-out and independent sets, their one honest run (step 22): false alarms | 6 of 32 (19%), range 9% to 35% | **not met** (at most 10%) |
| Second held-out set now: attacks caught | 11 of 20 (55%), range 34% to 74% | **not met** (at least 90%) |
| Second held-out set now: false alarms | 4 of 20 (20%), range 8% to 42% | **not met** (at most 10%) |
| Independent set now: attacks caught | 11 of 12 (92%), range 65% to 99% | met (at least 90%) |
| Independent set now: false alarms | 2 of 12 (17%), range 5% to 45% | **not met** (at most 10%) |
| First held-out set, its one honest run (before step 22): attacks caught | 12 of 20 (60%), range 39% to 78% | **not met** (at least 90%) |
| First held-out set, its one honest run (before step 22): false alarms | 1 of 20 (5%), range 1% to 24% | met (at most 10%) |
| First held-out set now: attacks caught | 19 of 20 (95%), range 76% to 99% | met (at least 90%) |
| First held-out set now: false alarms | 1 of 20 (5%), range 1% to 24% | met (at most 10%) |
| Development set now: attacks caught | 29 of 30 (97%), range 83% to 99% | met (at least 90%) |
| Development set now: false alarms | 4 of 30 (13%), range 5% to 30% | **not met** (at most 10%) |
| Development set, first run: attacks caught | 22 of 30 (73%), range 56% to 86% | **not met** (at least 90%) |
| Development set, first run: false alarms | 6 of 30 (20%), range 10% to 37% | **not met** (at most 10%) |

**In plain words:** on 20 attacks and 20 harmless incidents it was never tuned on, the rule engine caught 6 attacks and raised 3 false alarms. Step 24 recognises what a caller asks for by the shape of the request (an instruction, a request verb, something valuable) instead of fixed phrases. On the fresh set's calls it caught 2 of 10 scams (before: 0) with 2 false alarms (before: 2). The shapes still rely on lists of verbs and valuable things, and real callers used words outside them ("put your PIN", "clear it today", "tell me those numbers") or asked with a question ("what's your current password?"). Recognising a request in any wording is still the open problem.

### Did step 24 help on incidents it was not made from?

| Fourth held-out set (run once) | Before step 24 | After step 24 |
|---|---|---|
| All attacks caught | 4 of 20 | 6 of 20 |
| All false alarms | 3 of 20 | 3 of 20 |
| Phone calls: scams caught | 0 of 10 | 2 of 10 |
| Phone calls: false alarms | 2 of 10 | 2 of 10 |

A little, with no new false alarms, and far less than on the sets it was designed from. On those seen sets it caught 8 more attacks (phone calls: 27 of 35 before, 35 of 35 after) and raised 0 more false alarms. The gap between the two is why the fresh number is the one quoted.

Why the fresh scam calls still got past (read after the one run; nothing was changed because of them):

- `held4-call-fastag-blacklist`: "put your debit card details there": "put" is not one of the request verbs.
- `held4-call-whatsapp-code`: "tell me those numbers": "numbers" on its own is not one of the valuable things.
- `held4-call-crypto-recovery`: "our charge ... has to be cleared before we start": a demand, but not worded as an instruction.
- `held4-call-money-mule-job`: "what's the account number?": a request asked as a question, left out on purpose because no seen call asked that way.
- `held4-call-refund-qr`: "put your PIN": "put" again.
- `held4-call-traffic-fine`: "clear it today" (the fine): "clear" is not one of the money verbs.
- `held4-call-it-current-password`: "what's your current password?": a question, as above.
- `held4-call-sim-5g-upgrade`: "send an SMS ... with the word UPGRADE and the 20 digits": cutting the clause at "and" separated the verb from the digits.

And why its two harmless calls were flagged:

- `held4-call-school-fees`: the step-23 keyword rule `SIG-SEND-MONEY` reads "please pay the fee on the school portal" as a request; it was flagged before step 24 too.
- `held4-call-mother-asks-advice`: the caller repeats someone else's request for an OTP while asking for advice; flagged before step 24 too.

### Did step 23 help on incidents it was not made from?

Step 23 changed how a phone call's evidence adds up (a stranger asking for something is enough for a person to look) and was measured on the third held-out set, run once (2026-11-27):

| Third held-out set (run once) | Before step 23 | After step 23 |
|---|---|---|
| All attacks caught | 3 of 20 | 8 of 20 |
| All false alarms | 2 of 20 | 2 of 20 |
| Phone calls: scams caught | 0 of 10 | 3 of 10 |

Yes, with no new false alarms. On the sets it was made from it caught 9 more attacks (phone calls: 16 of 25 before, 24 of 25 after) and raised 0 more false alarms.

### Did the step-22 fixes help on incidents they were not made from?

Step 22 added keyword rules and was measured on the second held-out and independent sets, run once (2026-11-26):

| Fresh set (run once) | Detectors before step 22 | After step 22 |
|---|---|---|
| Second held-out set: attacks caught | 6 of 20 | 6 of 20 |
| Second held-out set: false alarms | 3 of 20 | 4 of 20 |
| Independent set: attacks caught | 7 of 12 | 7 of 12 |
| Independent set: false alarms | 1 of 12 | 2 of 12 |

No: they caught 8 more attacks on the sets they were made from, but 0 more on the fresh sets, and added 2 false alarms. They are kept, because each describes a documented attack, but they were not proven on new data. The new false alarms, still not fixed (a fix made after reading them would need yet another fresh set to be measured on):

- `held2-email-vendor-bank-change-done-right`: `SIG-PAYMENT-CHANGE` reads the subject "Change of bank details" as a request, though the email says to confirm by phone first.
- `ind-email-alumni-evening`: `SIG-ADVANCE-FEE` fires on "There is no registration fee": the no/not/never guard was added to the bank-change finding but not to this one.

## The sets

- **Development set**: 60 incidents, 30 attacks and 30 harmless (`agent/tests/evaluation_set.py`). Written first and used to find gaps (step 18b).
- **First held-out set**: 40 incidents, 20 attacks and 20 harmless (`agent/tests/evaluation_heldout.py`). Written after the step-18b fixes and run once. Its mistakes were then read and fixed in step 22, so it is now a development set too.
- **Second held-out set**: 40 incidents, 20 attacks and 20 harmless (`agent/tests/evaluation_heldout2.py`). Written before the step-22 fixes, committed and pushed before any of them, and run once after them. Read for step 23, so now seen.
- **Independent set**: 24 incidents, 12 attacks and 12 harmless, emails and calls (`agent/tests/evaluation_independent.py`). The incidents were chosen by the project owner, who did not write the detectors, and worded with ChatGPT; nobody working on the detectors saw them until the step-22 fixes were frozen. Copied in with only the rupee sign, reserved phone numbers and source labels added, then run once. Read for step 23, so now seen.
- **Third held-out set**: 40 incidents, 20 attacks and 20 harmless (`agent/tests/evaluation_heldout3.py`), half of them phone calls. Written before the step-23 change and run once after it. Read for step 24, so now seen.
- **Fourth held-out set**: 40 incidents, 20 attacks and 20 harmless (`agent/tests/evaluation_heldout4.py`), half of them phone calls. Written before the step-24 change, committed and pushed before any of it, and run once after it was frozen. Its author had a rough idea of the change in mind, so it also has scams that do not fit that idea and harmless calls that do.
- Every attack follows a pattern from a public source (below). Every name, address and number is a reserved example one. None is one of the six demo scenarios.
- Every set includes hard cases on purpose, both ways: attacks with no obvious keyword, and harmless messages that contain one (a real bank email with a one-time code, an angry customer threatening legal action, a company VPN in another country).
- All sets are frozen. A new example is added, never an old one changed.

### By kind of incident

Fourth held-out set:

| Kind | Attacks caught | False alarms |
|---|---|---|
| Emails | 1 of 6 | 1 of 6 |
| Sign-in batches | 3 of 4 | 0 of 4 |
| Phone calls | 2 of 10 | 2 of 10 |

Third held-out set now:

| Kind | Attacks caught | False alarms |
|---|---|---|
| Emails | 2 of 6 | 1 of 6 |
| Sign-in batches | 3 of 4 | 1 of 4 |
| Phone calls | 10 of 10 | 0 of 10 |

Second held-out set now:

| Kind | Attacks caught | False alarms |
|---|---|---|
| Emails | 2 of 8 | 3 of 8 |
| Sign-in batches | 3 of 6 | 1 of 6 |
| Phone calls | 6 of 6 | 0 of 6 |

Independent set now (no sign-ins):

| Kind | Attacks caught | False alarms |
|---|---|---|
| Emails | 6 of 7 | 2 of 5 |
| Phone calls | 5 of 5 | 0 of 7 |

First held-out set now:

| Kind | Attacks caught | False alarms |
|---|---|---|
| Emails | 8 of 8 | 0 of 8 |
| Sign-in batches | 5 of 6 | 1 of 6 |
| Phone calls | 6 of 6 | 0 of 6 |

Development set now (first run in brackets):

| Kind | Attacks caught | False alarms |
|---|---|---|
| Emails | 12 of 12 (9) | 2 of 12 (3) |
| Sign-in batches | 9 of 10 (8) | 2 of 10 (2) |
| Phone calls | 8 of 8 (5) | 0 of 8 (1) |

## What the fourth held-out set got wrong

| Example | Truth | Casewright said | Risk | Findings | About it |
|---|---|---|---|---|---|
| `held4-email-meeting-invite-lure` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | A fake meeting invitation whose 'join' page asks for the work account. |
| `held4-email-domain-expiry` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | A fake domain-renewal notice: the company's website will 'go offline' unless a card is entered on a look-alike registrar page. |
| `held4-email-copyright-strike` | malicious | benign | 28 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN`, `SIG-URGENCY` | A fake copyright complaint against the company's social media page; the 'appeal' asks for the page's login. |
| `held4-email-new-payroll-portal` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | Hard: 'we have moved to a new payroll portal': set up an account and add bank details there. |
| `held4-email-note-for-summary-bots` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | Hard: a 'shipping update' with a line telling automated summaries to mark it low priority and leave the link out. |
| `held4-email-security-quiz` | benign | suspicious | 51 | `SIG-CRED-REQ`, `SIG-OTP-REQ` | Hard: IT's security quiz, which mentions passwords, PINs and codes. |
| `held4-login-failures-then-abroad-usual-device` | malicious | benign | 25 | `BASELINE-GEO` | Four wrong passwords and then a success from Vietnam, on the person's usual kind of laptop. |
| `held4-call-fastag-blacklist` | malicious | benign | 5 | `BASELINE-UNKNOWN-CALLER` | A 'toll tag' call: the tag will be blacklisted tonight; the fix is a link sent by SMS where the card is entered. |
| `held4-call-whatsapp-code` | malicious | benign | 5 | `BASELINE-UNKNOWN-CALLER` | Hard: a 'gas agency' caller asks for the number that 'comes on WhatsApp', which is the code to move the WhatsApp account to the attacker's phone. |
| `held4-call-crypto-recovery` | malicious | benign | 5 | `BASELINE-UNKNOWN-CALLER` | A 'recovery agency' promises to get back money lost in an earlier investment scam, for a charge up front. |
| `held4-call-money-mule-job` | malicious | benign | 5 | `BASELINE-UNKNOWN-CALLER` | Hard: a 'payments job': receive money into your own account and pass it on, keeping a commission. The ask is for the account, phrased as a question. |
| `held4-call-refund-qr` | malicious | benign | 5 | `BASELINE-UNKNOWN-CALLER` | Hard: a 'refund' that needs a QR code scanned and the UPI PIN entered, which pays the caller instead. |
| `held4-call-traffic-fine` | malicious | benign | 19 | `BASELINE-UNKNOWN-CALLER`, `SIG-IMPERSONATION` | A 'traffic police' call about an unpaid fine and a court date tomorrow; payment through a link on WhatsApp. |
| `held4-call-it-current-password` | malicious | benign | 5 | `BASELINE-UNKNOWN-CALLER` | Hard: an 'IT' caller from an unknown number asks, as a question, for the current password to 'move the mailbox'. |
| `held4-call-sim-5g-upgrade` | malicious | benign | 5 | `BASELINE-UNKNOWN-CALLER` | A free '5G upgrade': send the long number printed on a new SIM by SMS, which moves the person's number to the attacker's SIM. |
| `held4-call-school-fees` | benign | suspicious | 50 | `BASELINE-STRANGER-ASKS`, `BASELINE-UNKNOWN-CALLER`, `SIG-SEND-MONEY` | Hard: the school office reminds a parent that term fees are due, paid on the school's portal. |
| `held4-call-mother-asks-advice` | benign | suspicious | 63 | `BASELINE-STRANGER-ASKS`, `BASELINE-UNKNOWN-CALLER`, `SIG-IMPERSONATION`, `SIG-OTP-REQ` | Hard: the person's mother, from a number not in the list, asks whether she should give an OTP to a stranger who called her. |

## What step 24 changed

Made by looking only at the five seen sets (the development set, the first, second and third held-out sets and the independent set). Agent only: the risk formula is unchanged, so the gateway, which recomputes every score, needed no change (ADR-43, ADR-65).

| Gap | Change | First seen in |
|---|---|---|
| Requests worded in ways no keyword rule knows | New: a request is recognised by its shape (`agent/app/request_shape.py`). A clause counts when it starts as an instruction to the listener ("Please ...", "Just ...", "you need to ...", "can you ...") and pairs a request verb with something valuable: money (an amount, the money itself, or "it" sent to someone else's account), a code, private details (a PIN, card numbers, Aadhaar, date of birth), approving a prompt, or installing an app. Warnings and promises ("don't pay any fee", "I'll send it") never start as an instruction, so they do not count; nor does paying cash or at a counter. It feeds only `BASELINE-STRANGER-ASKS` (a stranger's call), so emails and the risk formula are unchanged. | `held3-call-card-back-numbers` |
| Advice that always talked about codes | The finding, the employee's "what to do" and the analyst's next steps now name what the caller asked for: money, a code, private details, an approval or an app. | `held3-call-ceo-boarding` |

## What step 23 changed

Made by looking only at the four sets seen at the time. Agent only (ADR-43, ADR-64).

| Gap | Change | First seen in |
|---|---|---|
| A request to send or move money | New finding `SIG-SEND-MONEY` (weight 25): pay, send, transfer, deposit, move or return money, an amount, a fee or a balance; "send it back to this number"; "the payment goes there". Not when the money comes to you ("we'll pay", "I will transfer"), nor after "never", "not" or "don't". A bare number is not an amount ("send the report by 5"). | `held2-call-wrong-transfer` |
| A stranger asking for something | New finding `BASELINE-STRANGER-ASKS` (weight 30), from the baseline check: the caller's number is unknown to the person and the caller's own lines ask for money, a code, a password, card or bank details, a payment change, a fee, remote-access software or an app from a link. Either alone stays low; together they cross the line. Only which kinds of request are recorded, never the caller's words. | `held-call-hr-bank-details` |

## What step 22 changed

Each change is a general rule, written from what the attack does rather than the example's words, and made by looking only at the development and first held-out sets.

| Gap | Change | First seen in |
|---|---|---|
| "Log in with your company credentials" | `SIG-CRED-REQ` also recognises signing in with your credentials or login details. | `held-email-benefits-enrolment` |
| "I just need your bank account number" | `SIG-FINANCIAL-DETAILS` also recognises "need your ...". | `held-call-hr-bank-details` |
| Payment to a crypto wallet | `SIG-PAYMENT` also recognises a wallet address. | `held-call-investment-advisor` |
| Changing where salary or payments go | New finding `SIG-PAYMENT-CHANGE` (weight 30). Not when "no", "not" or "never" comes directly before ("there is no change to our bank details"). | `held-email-payroll-diversion` |
| Pay a fee to receive money or a parcel | New finding `SIG-ADVANCE-FEE` (weight 20): processing, customs, clearance, release, activation, registration or handling fees and charges. | `held-call-insurance-refund` |
| Guaranteed or unrealistic returns | New finding `SIG-TOO-GOOD` (weight 30). | `held-call-investment-advisor` |
| Enable macros or content in a document | New finding `SIG-ENABLE-CONTENT` (weight 30). | `held-email-macro-invoice` |
| Install an app from a link the sender gives | New finding `SIG-APP-LINK` (weight 25). | `call-electricity-cutoff` |
| Text that speaks to an AI reading the message | `SIG-AI-INJECTION` also recognises an AI addressed as the reader ("AI assistant reading this inbox", "when you summarise this"). | `held-email-injection-summarise` |

## What the seen sets still get wrong

Left as they are on purpose: a fix would only fit these examples, or would weaken a check that catches real attacks (for example, lowering the weight of "success after many failures" would hide the account takeover in `held-login-local-takeover`).

Third held-out set:

| Example | Truth | Casewright said | Risk | Findings | About it |
|---|---|---|---|---|---|
| `held3-email-mailbox-quota` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | A 'mailbox full' notice: new mail is being held until the person signs in on a look-alike page. |
| `held3-email-tax-refund` | malicious | benign | 28 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN`, `SIG-URGENCY` | A fake tax-refund notice that asks for bank details 'to credit the refund'. |
| `held3-email-callback-renewal` | malicious | benign | 28 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN`, `SIG-URGENCY` | Hard: callback phishing. A fake renewal receipt with no link at all, only a number to call to 'cancel'; the call is where the theft happens. |
| `held3-email-invoice-for-reviewers` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | Hard: an invoice with a line addressed to automated reviewers, saying the sender is trusted and the invoice should go straight to payment. |
| `held3-email-ai-bot-test-notes` | benign | suspicious | 40 | `SIG-AI-INJECTION` | Hard: an internal update about testing the company's chatbot, which quotes attack phrases it was tested with. |
| `held3-login-night-new-device-home-city` | malicious | benign | 19 | `BASELINE-DEVICE`, `BASELINE-HOURS` | Hard: a success from the person's home city, but late at night on a kind of device they have never used. |
| `held3-login-london-trip` | benign | suspicious | 40 | `BASELINE-GEO`, `REP-SUSPICIOUS` | Hard: a work trip to London on the usual laptop; signs in from Mumbai, then from London eleven hours later. |

Second held-out set:

| Example | Truth | Casewright said | Risk | Findings | About it |
|---|---|---|---|---|---|
| `held2-email-voicemail-lure` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | A 'new voicemail' notice whose player asks for the work account to listen. |
| `held2-email-esign-salary` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | A fake e-signature request about a 'revised salary structure', on a document site that wants the work password. |
| `held2-email-form16-request` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | Hard: the 'CFO', from a personal address, asks for every employee's tax forms (data theft, not money). No link. |
| `held2-email-cv-screening-injection` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | Hard: a job application whose CV text addresses automated screening tools, telling them to rank it first and not to flag it. |
| `held2-email-gst-notice-archive` | malicious | benign | 28 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN`, `SIG-URGENCY` | A fake tax-penalty notice: download a password-protected archive and open the file inside (how malware gets past email scanners). |
| `held2-email-thread-hijack` | malicious | benign | 15 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN` | Hard: a hijacked email thread. A near-copy of a partner's domain replies 'as discussed' with a document link and its password. |
| `held2-email-vendor-bank-change-done-right` | benign | suspicious | 50 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN`, `SIG-IMPERSONATION`, `SIG-PAYMENT-CHANGE` | Hard: a real vendor announces a new bank account and asks the customer to confirm it by phone with their usual contact before changing anything. |
| `held2-email-angry-customer` | benign | suspicious | 46 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN`, `SIG-THREAT`, `SIG-URGENCY` | Hard: an angry real customer threatens legal action over a late delivery. Unknown sender, threat words, asks for nothing sensitive. |
| `held2-email-bank-otp-delivery` | benign | suspicious | 45 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN`, `SIG-OTP-REQ` | Hard: a real bank emails a one-time code the person just asked for, with the usual warning. |
| `held2-login-script-working-hours` | malicious | benign | 10 | `BASELINE-DEVICE` | Hard: a stolen password used by a script from the person's own city, in working hours, on the first try. |
| `held2-login-botnet-guessing` | malicious | benign | 19 | `BASELINE-DEVICE`, `BASELINE-GEO` | Password guessing on one account from nine addresses in four countries within ten minutes. |
| `held2-login-usual-country-odd-hour` | malicious | benign | 19 | `BASELINE-DEVICE`, `BASELINE-HOURS` | Hard: a success in a country the person often works from (the UAE), but at night and on a Linux browser they have never used. |
| `held2-login-locked-then-reset` | benign | suspicious | 40 | `SUCCESS-AFTER-FAILURES` | Hard: five wrong passwords lock the account; half an hour later, after a helpdesk reset, a success. |

Independent set:

| Example | Truth | Casewright said | Risk | Findings | About it |
|---|---|---|---|---|---|
| `ind-email-electricity-bill` | malicious | benign | 28 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN`, `SIG-URGENCY` | Fake electricity bill notice with an urgent payment link |
| `ind-email-bank-statement` | benign | suspicious | 45 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN`, `SIG-OTP-REQ` | Bank sending a routine monthly statement notification without requesting credentials |
| `ind-email-alumni-evening` | benign | suspicious | 32 | `BASELINE-NEW-SENDER`, `REP-UNKNOWN`, `SIG-ADVANCE-FEE` | University alumni office inviting him to an optional networking event |

First held-out set:

| Example | Truth | Casewright said | Risk | Findings | About it |
|---|---|---|---|---|---|
| `held-login-stolen-session-us` | malicious | benign | 25 | `BASELINE-GEO` | Hard: a stolen session replayed from the US with the person's own browser name, in working hours. |
| `held-login-cached-old-password` | benign | suspicious | 46 | `BASELINE-DEVICE`, `SUCCESS-AFTER-FAILURES` | Hard: after a password change, a phone keeps trying the old one, then the person types the new one. |

Development set:

| Example | Truth | Casewright said | Risk | Findings | About it |
|---|---|---|---|---|---|
| `email-otp-awareness` | benign | suspicious | 35 | `SIG-OTP-REQ` | Hard: IT warns staff never to share an OTP, so the text names the thing attackers ask for. |
| `email-phishing-training` | benign | suspicious | 49 | `SIG-CRED-REQ`, `SIG-PAYMENT`, `SIG-URGENCY` | Hard: a security-training announcement that quotes the phrases phishing emails use. |
| `login-stolen-creds-same-city` | malicious | benign | 10 | `BASELINE-DEVICE` | Hard: a password stolen by malware, used from the person's own city in working hours; only the device is new. |
| `login-forgot-password-after-leave` | benign | suspicious | 40 | `SUCCESS-AFTER-FAILURES` | Hard: back from leave, six wrong guesses at a half-remembered password, then a success. |
| `login-company-vpn-exit` | benign | suspicious | 55 | `BASELINE-GEO`, `IMPOSSIBLE-TRAVEL` | Hard: switching on the company VPN, whose exit is in Singapore, 25 minutes after signing in at home. |

## What the first run changed (step 18b)

The development set's first run missed 8 attacks and raised 6 false alarms. Each change below is a general rule, written from what the attack does rather than the example's words.

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

This recorded run covers the development and first held-out sets only, and predates steps 22 to 24; the later sets have not been run with the model.

## Limitations

- **Small sets.** 122 attacks and 122 harmless incidents in all, and only 20 of each in the fresh set. The 95% ranges above are wide; a few more misses or catches would move the numbers noticeably.
- **The same author** wrote the detectors, the development set and all four held-out sets. Writing each held-out set before the fixes it measures reduces this; the independent set removes it for 24 incidents, but its wording was written by an AI model, which tends to state warning signs more plainly than real attackers do.
- **Synthetic text.** The examples follow published attack patterns, but they are not real messages: real attacks are messier, longer and in many languages (all of these are in English). Public collections of real phishing exist, but none fits all three kinds of incident, and their messages cannot be published with the project; measuring on one is future work.
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

Prints every example's result and rewrites this file. With `--model`, it also runs the development and first held-out sets with the local AI model (Ollama must be running) and records the result for the section above.
