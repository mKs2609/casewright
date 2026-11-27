"""The fifth held-out set (step 24, ADR-63): 10 phone calls, 5 scams and 5 harmless, written by the
project owner.

Why it matters: every earlier set except the independent one was written by the same author as
the detectors, and the fourth by an author who had the step-24 design in mind. These calls were
written by the project owner, who did not write the detectors, after the step-24 change was frozen,
without looking at the code or the design notes. They were committed and pushed before being run,
and are run once.

Copied in as written, typing included. Only what the project's rules require was changed:
- phone numbers: real-looking ones became reserved example numbers (+1 555 555 01xx), each call its
  own, none on the built-in threat list or known to the person (the two the owner gave in that
  range are kept);
- the person: every incident is about one of the three example people with a baseline, chosen by
  the name that speaks in the call (Priya, Arjun, Sara); the two calls where "Rakesh" speaks are
  given to arjun.mehta, and his lines are left as written;
- the labels: the last call had no SCAM / NOT SCAM line; it was in the harmless group;
- each scam names a public source for its pattern (the sets' rule).
The real bank name in two scams is the one impersonated, as real scam calls do; it is not labelled
as malicious.
"""

from tests.evaluation_set import Example, call

SCAMS = [
    Example("held5-call-lottery-otp", "call_transcript", "priya.sharma", "malicious", ("RBI", "T1111"),
            "Written by the project owner. Asks for an OTP to send lottery winnings the person never entered for.",
            call("+15555550130",
                 "Caller: Hello ma'am, we need a otp for bank\n"
                 "Priya: why do u need it\n"
                 "caller: we want to transfer some money you won on lottery\n"
                 "priya: i never applied for lottery")),
    Example("held5-call-yono-mpin", "call_transcript", "arjun.mehta", "malicious", ("RBI", "T1111"),
            "Written by the project owner. Asks for the banking app's MPIN, promising double the money.",
            call("+15555550131",
                 "caller: hey can we get you mpin for yono sbi\n"
                 "Rakesh:  for what purpose\n"
                 "caller: we want to give you 2x money value\n"
                 "rakesh: i can give you but i feel that it is suspicious")),
    Example("held5-call-kyc-block", "call_transcript", "arjun.mehta", "malicious", ("RBI", "T1656"),
            "Written by the project owner. A fake bank KYC call: the account will be blocked unless account "
            "details and the OTP are shared.",
            call("+15555550132",
                 "Caller: Hello sir im calling from SBI customer care.\n"
                 "Arjun: Yes, tell me\n"
                 "Caller: Your bank account will be blocked today because your kyc is not updated.\n"
                 "Arjun: But I updated it last month.\n"
                 "Caller: Yes sir, but it is showing pending. Just share your account details and OTP.\n"
                 "Arjun: Can't I update it by visiting the bank?")),
    Example("held5-call-iphone-delivery-fee", "call_transcript", "sara.khan", "malicious", ("FTC", "T1657"),
            "Written by the project owner. A prize the person never entered for, released for a delivery charge.",
            call("+15555550133",
                 "Caller: Hello maam congratulationsyou have won an iPhone in our lucky draw.\n"
                 "Sara: Really? But I didn't participate in any lucky draw.\n"
                 "Caller: Ma'am, your number was selected automatically.\n"
                 "Sara: Okay, so how do I get it?\n"
                 "Caller: Just pay 1500 rupees for delivery charges.\n"
                 "Sara: Why should I pay when I won it for free?")),
    Example("held5-call-electricity-link", "call_transcript", "priya.sharma", "malicious", ("I4C", "T1566.004"),
            "Written by the project owner. A fake electricity disconnection that pushes a payment link.",
            call("+15555550134",
                 "Caller: Hello ma'am, I'm calling from your electricity department.\n"
                 "Priya: Yes, what happened\n"
                 "Caller: Your electricity bill is pending and your connection will be disconnected tonight.\n"
                 "Priya: But I paid the bill yesterday in your app only\n"
                 "Caller: It is not updated in our system. Please click the payment link i am sending you.\n"
                 "Priya: Can't I check it on the official app of yours")),
]

HARMLESS = [
    Example("held5-call-debit-card-dispatch", "call_transcript", "priya.sharma", "benign", (),
            "Written by the project owner. The bank says a new debit card is on its way; nothing is asked.",
            call("+15555550135",
                 "Caller: Hello mam I'm calling from your bank regarding your new debit card.\n"
                 "Priya: okay what do you want\n"
                 "Caller: Your card has been dispatched and should reach you in 2-3 days.\n"
                 "Priya: Okay, will I get a message when it arrives?\n"
                 "Caller: Yes ma'am, you'll receive an SMS with the delivery details.\n"
                 "Priya: Alright, thank you.")),
    Example("held5-call-hospital-appointment", "call_transcript", "priya.sharma", "benign", (),
            "Written by the project owner. A hospital confirms an appointment and asks the person to bring reports.",
            call("+15555550136",
                 "Caller: Hello sir I'm calling from the hospital to confirm your appointment.\n"
                 "Priya: Yes, I booked it for Monday.\n"
                 "Caller: Correct ma'am, your appointment is confirmed for 10:30 AM.\n"
                 "Priya: Should I bring any documents?\n"
                 "Caller: Please bring your previous reports and appointment receipt.\n"
                 "Priya: Okay, thank you ")),
    Example("held5-call-courier-arrived", "call_transcript", "sara.khan", "benign", (),
            "Written by the project owner. A courier says the parcel reached the local centre.",
            call("+15555550145",
                 "Caller: Hi sir, I'm calling from the courier service.\n"
                 "Sara: Yes, is there a problem with my delivery\n"
                 "Caller: No sir, your parcel has arrived at the local delivery centre.\n"
                 "Sara: Oh, when will I receive it?\n"
                 "Caller:  by tomorrow afternoon.\n"
                 "Sara: Okay, I'll be available then at that time")),
    Example("held5-call-college-timetable", "call_transcript", "arjun.mehta", "benign", (),
            "Written by the project owner. The college office says the exam timetable is on the portal.",
            call("+15555550137",
                 "Caller: Hello sir, I'm calling from your college administration office.\n"
                 "Arjun: Yes sir, tell me.\n"
                 "Caller: Your semester exam timetable has been uploaded to the college portal.\n"
                 "Arjun: Okay, do we need to submit anything?\n"
                 "Caller: No, just download the timetable and check your exam dates.\n"
                 "Arjun: Alright then ill check it'")),
    Example("held5-call-bank-statement-app", "call_transcript", "arjun.mehta", "benign", (),
            "Written by the project owner. The bank says a statement is ready in its official app.",
            call("+15555550138",
                 "Caller: Hello sir, your bank statement is ready.\n"
                 "Rakesh: Okay, how can I check it?\n"
                 "Caller: You can download it from your official banking app.\n"
                 "Rakesh: Alright, thank you.")),
]

HELD_OUT_5 = SCAMS + HARMLESS
