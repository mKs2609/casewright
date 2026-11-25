"""The independent set (step 22, ADR-63): 24 labelled incidents, 12 attacks and 12 harmless, written by
someone who did not write the detectors.

They were written before the step-22 detector changes were finished and kept unseen until those
changes were frozen, then copied in here. The only edits: the rupee sign (lost in the source PDF) is
written "Rs", each call gets an unused reserved example number (the source gives none), and each
attack is labelled with the public source its pattern matches. The wording is the author's own.
Run once, together with the second held-out set; frozen like the other sets.
"""

from tests.evaluation_set import Example, call, email

# ================================================================== emails: 7 attacks, 5 harmless

EMAILS = [
    Example("ind-email-electricity-bill", "email", "priya.sharma", "malicious", ("I4C", "T1566.002"),
            "Fake electricity bill notice with an urgent payment link",
            email("billing@northgrid-power.example", "Action required: electricity bill marked overdue",
                  "Hello Priya,\n\nOur records show that your latest electricity bill of Rs 2,480 is still unpaid. To "
                  "avoid a service interruption tomorrow, please settle the balance using the payment page below:\n\n"
                  "http://northgrid-payments.example/settle\n\nIf you have already paid, ignore this notice. Otherwise, "
                  "complete payment within 30 minutes and reply with the transaction reference.\n\nNorthGrid Billing Desk")),
    Example("ind-email-holiday-calendar", "email", "sara.khan", "benign", (),
            "HR sharing the published holiday calendar",
            email("people-ops@brightpath.example", "Updated office holiday calendar",
                  "Hi Sara,\n\nThe People Operations team has uploaded the revised holiday calendar for the coming year "
                  "to the usual employee portal.\n\nYou can find it by opening the portal from your saved company "
                  "bookmark and selecting Resources → Policies → Holiday Calendar. No action is required; this is just "
                  "for planning.\n\nRegards,\n\nRitika\n\nPeople Operations")),
    Example("ind-email-parcel-fee", "email", "arjun.mehta", "malicious", ("I4C", "T1566.002"),
            "Fake parcel delivery fee with a link to a lookalike tracking page",
            email("delivery-alert@quickship-update.example", "Delivery attempt failed — small fee pending",
                  "Hello Arjun,\n\nOur courier could not complete delivery of parcel QX-481920 because the address "
                  "confirmation fee of Rs 35 remains unpaid.\n\nPlease confirm your address and pay the fee here: "
                  "http://quickship-redelivery.example/confirm\n\nYour parcel will be returned to the sender if this is "
                  "not completed today.\n\nQuickShip Dispatch")),
    Example("ind-email-bank-statement", "email", "arjun.mehta", "benign", (),
            "Bank sending a routine monthly statement notification without requesting credentials",
            email("alerts@harborbank.example", "Your monthly account statement is ready",
                  "Dear Arjun,\n\nYour monthly account statement for October is now available in Harbor Bank's mobile "
                  "app.\n\nFor your safety, we will never ask you to share your password, PIN, or one-time passcode by "
                  "email or phone. Open the app directly to view the statement.\n\nRegards,\n\nHarbor Bank Notifications")),
    Example("ind-email-storage-quota", "email", "sara.khan", "malicious", ("APWG", "T1566.002"),
            "Fake cloud-storage quota warning designed to steal a work password",
            email("workspace-storage@cloudquota-check.example", "Mailbox and drive access will be paused",
                  "Hi Sara,\n\nYour team storage has reached 98% capacity. Files may stop syncing unless you verify your "
                  "account today.\n\nContinue here: http://workspace-capacity.example/verify\n\nThe verification page "
                  "will ask you to sign in again. Please complete it within one hour to prevent temporary access "
                  "restrictions.\n\nCloud Workspace Support")),
    Example("ind-email-payroll-correction", "email", "priya.sharma", "malicious", ("IC3", "CISA-PHISHING"),
            "Fake payroll correction asking employee to open an attachment and enter bank details",
            email("payroll-review@brightpath-hr.example", "Salary correction required before payroll closes",
                  "Hi Priya,\n\nPayroll has flagged a mismatch in your salary account details. To prevent this month's "
                  "salary from being delayed, open the attached file named Salary_Update_Form.html and confirm your bank "
                  "account, card number, and online banking password.\n\nPlease complete this before 6 p.m. today. Do "
                  "not contact the payroll desk because this is being handled as a confidential correction.\n\n"
                  "Payroll Processing")),
    Example("ind-email-meeting-notes", "email", "priya.sharma", "benign", (),
            "Project lead sending meeting notes and an agenda",
            email("devika.rao@brightpath.example", "Notes and agenda for Friday's project review",
                  "Hi Priya,\n\nThanks for joining today's planning discussion. I've attached the meeting notes and added "
                  "three items to Friday's agenda: open design questions, the testing timeline, and ownership of the "
                  "next release tasks.\n\nPlease add comments in the shared project document using the company "
                  "workspace you normally access. There is no urgent action before Friday.\n\nBest,\n\nDevika")),
    Example("ind-email-gift-cards", "email", "sara.khan", "malicious", ("IC3", "FTC", "T1656"),
            "Fake executive gift-card request framed as a confidential urgent task",
            email("director.office@brightpath-leadership.example", "Quick confidential favour before the meeting",
                  "Sara,\n\nI'm tied up in back-to-back meetings and need you to help with something discreet. Purchase "
                  "six gift cards worth Rs 2,000 each and send me clear photos of the codes by email.\n\nI'll reimburse "
                  "you later. Please don't call because I'm presenting, and keep this between us until the team "
                  "announcement.\n\nThanks,\n\nOffice of the Director")),
    Example("ind-email-alumni-evening", "email", "arjun.mehta", "benign", (),
            "University alumni office inviting him to an optional networking event",
            email("alumni@westbridge-college.example", "Invitation: alumni networking evening",
                  "Hello Arjun,\n\nWe're hosting an alumni networking evening on Saturday, 12 December, from 5 p.m. to "
                  "7 p.m. at the campus auditorium.\n\nAttendance is optional. If you'd like to join, please register "
                  "through the alumni page you normally use, or reply to this email with a simple yes. There is no "
                  "registration fee.\n\nWarm regards,\n\nWestbridge Alumni Office")),
    Example("ind-email-tax-refund", "email", "arjun.mehta", "malicious", ("I4C", "T1566.002"),
            "Fake tax refund notice directing recipient to a fraudulent refund form",
            email("refund-desk@tax-services-india.example", "Tax refund pending — confirm details",
                  "Dear Arjun,\n\nA refund of Rs 12,640 has been approved but could not be deposited because your profile "
                  "is incomplete.\n\nSubmit your PAN, bank account, debit card details, and OTP at "
                  "http://income-refund-check.example/claim within 24 hours.\n\nFailure to verify will cause the refund "
                  "to expire.\n\nRefund Processing Desk")),
    Example("ind-email-printer-visit", "email", "sara.khan", "benign", (),
            "Known vendor notifying the recipient of a routine service visit",
            email("service@evergreen-office.example", "Reminder: printer maintenance visit on Wednesday",
                  "Hello Sara,\n\nThis is a reminder that our technician is scheduled to visit your office on Wednesday "
                  "between 11 a.m. and noon for the printer maintenance covered by your service plan.\n\nThe technician "
                  "will show an appointment reference at reception. No payment or account information is needed during "
                  "the visit.\n\nRegards,\n\nEvergreen Office Services")),
    Example("ind-email-document-share", "email", "priya.sharma", "malicious", ("APWG", "T1566.002"),
            "Fake shared-document notification with a link to a credential-harvesting page",
            email("document-share@files-notice.example", "Priya Sharma shared a confidential document with you",
                  "Priya,\n\nA document titled 'Annual Compensation Review' has been shared with you. Access will be "
                  "removed shortly.\n\nView document: http://files-access-review.example/open\n\nIf prompted, sign in "
                  "with your company email and password to confirm your identity. The document owner has requested "
                  "that you do not forward this notice.\n\nFile Sharing Service")),
]

# ================================================================== calls: 5 attacks, 7 harmless

CALLS = [
    Example("ind-call-dental-clinic", "call_transcript", "arjun.mehta", "benign", (),
            "Dental clinic confirming an upcoming appointment",
            call("+15555550120",
                 "Caller: Hello, may I speak with Arjun Mehta?\n"
                 "Arjun: Speaking.\n"
                 "Caller: This is Neha from Green Park Dental Clinic. I'm confirming your appointment for Thursday at "
                 "4:30 p.m. with Dr. Rao.\n"
                 "Arjun: Yes, that's correct.\n"
                 "Caller: Great. Please arrive about ten minutes early. You don't need to make any payment over the "
                 "phone.\n"
                 "Arjun: All right, thank you.\n"
                 "Caller: Thank you. Have a good day.")),
    Example("ind-call-it-otp", "call_transcript", "priya.sharma", "malicious", ("CISA-AA23-320A", "T1566.004", "T1111"),
            "Caller impersonating IT support and asking for an OTP",
            call("+15555550121",
                 "Caller: Good afternoon. I'm calling from the company's IT help desk. We detected an unusual sign-in "
                 "attempt on your work account.\n"
                 "Priya: I haven't signed in anywhere unusual.\n"
                 "Caller: That's why we're securing it. A verification code has just been sent to your phone. Read it "
                 "out so I can block the other session.\n"
                 "Priya: Can you give me a ticket number?\n"
                 "Caller: The system is busy. We need the code immediately or your mailbox may be locked.\n"
                 "Priya: I won't share a code. I'll contact IT using the number in the company directory.\n"
                 "Caller: Please do it quickly.")),
    Example("ind-call-meeting-room", "call_transcript", "sara.khan", "benign", (),
            "Colleague checking whether a meeting room is available",
            call("+15555550122",
                 "Caller: Hi Sara, it's Kabir from the design team. Are you free for a quick question?\n"
                 "Sara: Sure.\n"
                 "Caller: I booked Cedar Room for our 2 p.m. review, but the calendar still shows it as tentative. "
                 "Could you check whether the room is free?\n"
                 "Sara: I'll look at the shared room calendar.\n"
                 "Caller: Thanks. No need to send me any login details; I just want to avoid a double booking.\n"
                 "Sara: It looks free. I'll confirm the booking there.\n"
                 "Caller: Perfect, thanks.")),
    Example("ind-call-safe-account", "call_transcript", "sara.khan", "malicious", ("FTC", "T1566.004", "T1656", "T1657"),
            "Fake bank fraud team pressuring recipient to move money to a so-called safe account",
            call("+15555550123",
                 "Caller: Am I speaking with Sara Khan? This is the Harbor Bank fraud department.\n"
                 "Sara: Yes. What's happened?\n"
                 "Caller: A suspicious transfer is waiting to clear. We can protect your balance if you move the money "
                 "to our temporary safe account.\n"
                 "Sara: What account is that?\n"
                 "Caller: I'll text you the details. Keep this call private so the investigation isn't compromised.\n"
                 "Sara: I will hang up and call the number printed on my bank card.\n"
                 "Caller: If you disconnect, we may not be able to stop the transfer.")),
    Example("ind-call-courier-window", "call_transcript", "priya.sharma", "benign", (),
            "Courier confirming a delivery window without asking for sensitive information",
            call("+15555550124",
                 "Caller: Hello Priya, I'm Manoj from City Parcel Services. We have a package addressed to you.\n"
                 "Priya: When will it arrive?\n"
                 "Caller: Between 5 and 7 this evening. Would someone be available to receive it?\n"
                 "Priya: Yes, someone will be home.\n"
                 "Caller: Thank you. The tracking reference ends in 6721. You can check the status in the courier app "
                 "if you wish.\n"
                 "Priya: Okay.\n"
                 "Caller: Have a nice day.")),
    Example("ind-call-isp-maintenance", "call_transcript", "arjun.mehta", "benign", (),
            "Internet provider confirming a scheduled maintenance window",
            call("+15555550125",
                 "Caller: Hello, this is Asha from MetroNet customer care. I'm calling about planned maintenance in your "
                 "area.\n"
                 "Arjun: Will my connection be affected?\n"
                 "Caller: There may be a short interruption between 1 and 2 a.m. on Sunday.\n"
                 "Arjun: Do I need to do anything?\n"
                 "Caller: No. Your router should reconnect automatically. You can also check the notice in your "
                 "provider app.\n"
                 "Arjun: Thanks for letting me know.\n"
                 "Caller: You're welcome.")),
    Example("ind-call-police-deposit", "call_transcript", "arjun.mehta", "malicious", ("I4C", "T1566.004", "T1656"),
            "Impersonator claiming to be police and threatening arrest unless a fee is paid",
            call("+15555550126",
                 "Caller: Mr. Arjun Mehta? I'm calling from the cyber investigation unit. Your identity has been linked "
                 "to an illegal transaction.\n"
                 "Arjun: What transaction?\n"
                 "Caller: We can close the matter today if you pay a verification deposit of Rs 8,900. Do not tell "
                 "anyone or the case will become public.\n"
                 "Arjun: Can I verify this through an official office number?\n"
                 "Caller: No. This is a confidential operation. Stay on the line while I send the payment details.\n"
                 "Arjun: I will verify independently and end this call.\n"
                 "Caller: You may face immediate action.")),
    Example("ind-call-restaurant", "call_transcript", "sara.khan", "benign", (),
            "Restaurant confirming a table reservation",
            call("+15555550127",
                 "Caller: Hello, may I speak with Sara Khan?\n"
                 "Sara: This is Sara.\n"
                 "Caller: I'm calling from Olive Street Kitchen to confirm your table for two tomorrow at 7:30 p.m.\n"
                 "Sara: Yes, that's right.\n"
                 "Caller: Wonderful. We'll hold the table for fifteen minutes. You can make any changes by calling the "
                 "restaurant's published number.\n"
                 "Sara: Great, thank you.\n"
                 "Caller: We look forward to seeing you.")),
    Example("ind-call-sim-otp", "call_transcript", "priya.sharma", "malicious", ("T1566.004", "T1111"),
            "Fake telecom support call claiming the SIM will be blocked unless details are confirmed",
            call("+15555550128",
                 "Caller: Hello Priya, I'm from your mobile network's security department. Your SIM has been flagged "
                 "for duplicate registration.\n"
                 "Priya: I haven't requested a replacement SIM.\n"
                 "Caller: We can stop it, but first tell me the six-digit code that just arrived by SMS.\n"
                 "Priya: Why do you need my code?\n"
                 "Caller: It confirms ownership. If you don't share it, the other person may take control of your "
                 "number.\n"
                 "Priya: I won't share an OTP. I'll contact my operator through its official app.\n"
                 "Caller: You're risking a permanent block.")),
    Example("ind-call-coworker-slides", "call_transcript", "priya.sharma", "benign", (),
            "Known coworker asking her to review a shared presentation",
            call("+15555550129",
                 "Caller: Hi Priya, it's Nikhil from the sales team.\n"
                 "Priya: Hi Nikhil.\n"
                 "Caller: I've added the latest figures to the quarterly presentation. Could you review slides six "
                 "through eight before tomorrow's meeting?\n"
                 "Priya: Sure. Where did you save it?\n"
                 "Caller: In the usual team drive under Quarterly Review. Open it from your company workspace, not from "
                 "a new link.\n"
                 "Priya: I'll take a look.\n"
                 "Caller: Thanks, appreciate it.")),
    Example("ind-call-job-fee", "call_transcript", "sara.khan", "malicious", ("I4C", "FTC", "T1657"),
            "Caller posing as a recruiter and requesting an upfront fee to secure a job",
            call("+15555550143",
                 "Caller: Hello Sara, I'm calling about your application for a remote analyst role.\n"
                 "Sara: Which company is this for?\n"
                 "Caller: A partner firm. Your profile is selected, but you must pay a refundable onboarding and "
                 "laptop-registration fee of Rs 1,499 today.\n"
                 "Sara: Can you send the job description from a company email address?\n"
                 "Caller: The offer expires in twenty minutes, so payment has to come first.\n"
                 "Sara: I won't pay to apply for a job. I'll verify the company independently.\n"
                 "Caller: Then we will move to the next candidate.")),
    Example("ind-call-pharmacy", "call_transcript", "arjun.mehta", "benign", (),
            "Pharmacy checking whether a routine prescription refill is ready",
            call("+15555550144",
                 "Caller: Hello, is this Arjun? This is Meera calling from Lakeside Pharmacy.\n"
                 "Arjun: Yes.\n"
                 "Caller: Your routine refill is ready for collection. Our counter is open until 9 p.m. today.\n"
                 "Arjun: Do I need to bring anything?\n"
                 "Caller: Please bring your usual prescription or the collection slip. You can also call the published "
                 "store number if you need to check the opening hours.\n"
                 "Arjun: I'll come by this evening.\n"
                 "Caller: Thank you.")),
]

INDEPENDENT: list[Example] = EMAILS + CALLS
