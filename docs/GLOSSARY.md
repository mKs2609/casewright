# Glossary

Plain-language meanings of the terms used in this project.

## Security terms

| Term | Meaning |
|---|---|
| **SOC** | Security Operations Centre. The team that watches for and responds to attacks. |
| **Incident** | One suspicious event that needs investigating. |
| **Indicator / IOC** | A concrete clue such as an IP address, domain, email address or phone number. IOC = indicator of compromise. |
| **Verdict** | The conclusion: benign (safe), suspicious, or malicious. |
| **Phishing** | A fake message that tricks someone into giving up a password or clicking a bad link. |
| **Vishing** | Phishing by phone call. |
| **Credential stuffing** | Trying many stolen username/password pairs against many accounts. |
| **Brute force** | Guessing one account's password over and over. |
| **Account takeover** | An attacker successfully logging in as someone else. |
| **Impossible travel** | The same account used in two places too far apart for the time between them. |
| **Look-alike domain** | A web address made to resemble a real one, such as `paypa1.com`. |
| **Baseline** | A record of someone's normal behaviour, used to spot unusual activity. |
| **MITRE ATT&CK** | A public catalogue of attacker techniques, each with an ID like `T1566`. |
| **MITRE ATLAS** | The same idea for attacks on AI systems, with IDs like `AML.T0051`. |
| **Prompt injection** | Text written by an attacker that tries to give instructions to an AI. |
| **Human-in-the-loop** | A person must approve before the system acts. |
| **Audit log** | A permanent record of who did what and when. |
| **Hash chain** | A log where each entry includes a fingerprint of the previous one, so edits are detectable. |
| **HMAC** | A fingerprint that can only be produced with a secret key. |
| **Append-only** | Entries can be added but never changed or removed. |
| **Advisory lock** | A lock in PostgreSQL that means whatever the application decides, here "one audit entry at a time". |
| **Chain head** | The newest entry of a hash chain and its hash. |
| **STRIDE** | A checklist of threat types: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege. |
| **Threat model** | A structured list of what could go wrong and how we prevent it. |
| **Least privilege** | Giving each part only the access it needs. |
| **Defence in depth** | Several independent protections, so one failing is not fatal. |

## Web and authentication terms

| Term | Meaning |
|---|---|
| **Gateway** | The service that receives all requests from the browser. |
| **Discriminator** | A field (here `kind`) whose value decides which shape the rest of a JSON body must have. |
| **JSONB** | PostgreSQL's binary JSON column type: it checks the JSON is valid and can be queried. |
| **202 Accepted** | "Received, will be processed later": used when work, such as an investigation, has only been queued. |
| **Service-to-service authentication** | One program proving its identity to another; here the gateway sends a shared secret token to the agent. |
| **Bearer token** | A secret sent in the `Authorization: Bearer ...` header; whoever holds ("bears") it is let in. |
| **Constant-time comparison** | Comparing secrets in a way that takes the same time however much matches, so timing reveals nothing. |
| **Stateless service** | A service that remembers nothing between requests; everything it needs comes with each request. |
| **NDJSON** | Newline-delimited JSON: one JSON object per line, so a long answer can be read and acted on line by line. |
| **Stub** | A stand-in that gives a fixed, simple answer until the real thing is built. |
| **Defence in depth** | Several independent protections, so one failing doesn't expose everything. |
| **Endpoint** | One URL the server responds to, such as `/api/health`. |
| **Hashing (passwords)** | Storing a one-way fingerprint of a password, never the password itself. |
| **Argon2** | A modern password-hashing algorithm that is deliberately slow and memory-hungry. |
| **JWT** | JSON Web Token. A signed piece of data that proves who you are. |
| **Access token** | A short-lived token sent with each request. |
| **Refresh token** | A longer-lived token used only to get a new access token. |
| **Rotation** | Replacing a refresh token with a new one each time it is used. |
| **Cookie flags** | `HttpOnly` (JavaScript can't read it), `Secure` (HTTPS only), `SameSite` (not sent from other sites). |
| **CSRF** | Cross-site request forgery. Another website tricking your browser into sending a request. |
| **XSS** | Cross-site scripting. Attacker-supplied text running as code in your page. |
| **CSP** | Content Security Policy. A header telling the browser which scripts may run. |
| **Rate limiting** | Capping how many requests one client can make in a period. |
| **Exponential backoff** | Making each retry wait longer than the last. |
| **Token bucket** | A rate-limiting method: a bucket holds up to N tokens, each request takes one, and tokens flow back at a steady rate. Short bursts are fine; a sustained flood runs it dry. |
| **429 Too Many Requests** | The HTTP status for "slow down". Usually sent with a `Retry-After` header saying how many seconds to wait. |
| **Virtual environment (Python)** | A private folder of libraries for one project (`agent/.venv`), so nothing is installed system-wide. |
| **Transitive dependency** | A library your libraries need. Pinned too, so every install is identical. |
| **Asynchronous / background work** | Work handed to another thread so the current request can answer straight away. |
| **Indicator (IOC)** | A checkable fact in an incident: an IP address, domain, email address or phone number. "Indicator of compromise" when it points to an attack. |
| **Threat intelligence** | Information about known attackers: bad addresses, phishing sites, scam numbers, with a score and tags. |
| **Look-alike domain (typosquatting)** | A domain made to resemble a real brand's, like `paypa1` for `paypal`. |
| **Evidence chain** | The numbered record of every tool call in an investigation (E1, E2, … accepted; R1, R2, … refused), which verdicts and reports cite. |
| **Signal** | One finding from a tool, with a technical label, a plain-language sentence and a weight. |
| **Guardrail** | A rule enforced in code that refuses an action, whatever the AI asks for. |
| **Reserved example names** | Domains like `.example`, IP ranges like `203.0.113.0/24` and 555-01xx numbers, set aside for documentation so examples never point at real people or sites. |
| **Unicode normalisation** | Rewriting text into one standard form, e.g. full-width letters into plain ones, so look-alike spellings compare equal. |
| **Zero-width character** | An invisible character (such as U+200B) that can be hidden inside a word to break a filter: "ign​ore". |
| **Homoglyph** | A letter that looks like another, such as Cyrillic "і" and Latin "i". |
| **Campaign** | One attacker targeting several people at once, often reusing the same domain, address or number. |
| **Correlation window** | How far back earlier incidents are compared with a new one (7 days here). |
| **Noisy-OR** | Combining findings by asking how likely it is that all of them are false alarms: risk = 100 × (1 − product of (1 − weight/100)). Findings compound, and the total never passes 100. |
| **Risk band** | The verdict a score falls into: 0–29 benign, 30–64 suspicious, 65–100 malicious. |
| **Score floor** | The rule that a verdict is never lower than its evidence's band, enforced by the gateway. |
| **Counterfactual** | "What would change the verdict": the strongest finding and the risk without it. |
| **SOC report / plain report** | The two reports of every investigation: one for the security team (technical, every finding with its evidence ID), one for the employee (what happened, why, what to do; no jargon). |
| **Reading grade (Flesch-Kincaid)** | A formula from sentence length and syllables per word that estimates the school year needed to read a text easily. The plain report must be grade 8 or below. |
| **Masking** | Replacing real values (names, addresses, numbers) with plain words before showing text to someone, or something, that should not see them. |
| **Golden file** | A file of test cases with known answers, shared by two implementations so they stay identical. |
| **Encryption at rest** | Data is stored encrypted, so a stolen disk, backup or database dump is unreadable without the key. |
| **AES-256-GCM** | A standard encryption method. AES-256 hides the data; GCM adds a tag that detects any change to it (authenticated encryption). |
| **Nonce** | A "number used once": a random value mixed into each encryption so the same data never encrypts to the same bytes. Must never repeat with the same key. |
| **Associated data** | Extra context (here, the employee's identity) that is checked during decryption but not hidden. Decryption fails if it doesn't match. |
| **Account lockout** | Disabling an account after too many wrong passwords. We use backoff instead, so an attacker cannot lock a real user out. |
| **Object-level authorisation** | Checking that *this* user may access *this specific* record. |
| **WebSocket** | A connection that stays open so the server can push updates. |
| **TLS / HTTPS** | Encryption for data in transit. HTTPS is ordinary HTTP sent inside a TLS connection. |
| **TLS handshake** | The first moments of a TLS connection: the two sides agree a version and cipher, the server proves its identity with its certificate, and they agree the keys for the session. |
| **Certificate** | A public document that says "this public key belongs to `localhost`" (or to a website), signed by someone who vouches for it. |
| **Private key** | The secret half of the key pair. Whoever holds it can pose as the server, so it never leaves the server. |
| **Certificate authority (CA)** | An organisation, or a certificate, that browsers trust to vouch for other certificates. |
| **Self-signed certificate** | A certificate that vouches for itself. Fine for development once you trust it deliberately; browsers warn about it otherwise. |
| **Keystore (PKCS12, `.p12`)** | A password-protected file holding a certificate together with its private key. |
| **SAN (Subject Alternative Name)** | The list of names a certificate is valid for, such as `localhost` and `127.0.0.1`. Browsers check the address against it. |
| **HSTS** | A header telling the browser "only ever use HTTPS for this host". It applies to the host name, not the port. |

## AI terms

| Term | Meaning |
|---|---|
| **LLM** | Large language model, such as Claude, Qwen or Llama. |
| **Local model** | An LLM that runs on your own computer instead of a company's servers: free, and the data never leaves the machine. |
| **Ollama** | A free program that downloads open models and serves them on your own machine (here at `127.0.0.1:11434`). |
| **Parameters (of a model)** | The numbers a model learned during training; "8B" means 8 billion. More usually means more capable, and needs more memory. |
| **Token** | The chunk of text a model reads and writes: often part of a word. Limits and costs are counted in tokens. |
| **Context window** | How many tokens a model can consider at once: the prompt, the conversation and its reply together. |
| **Thinking mode** | A model writing out its reasoning before answering. More careful on hard problems, much slower. |
| **Temperature** | How much randomness a model uses when choosing words; 0 makes it as repeatable as possible. |
| **Fallback** | The plan that runs when the first one fails: here, the rule engine when the AI model cannot finish. |
| **Agent** | An LLM that works in a loop, choosing tools to call until it finishes a task. |
| **Tool / function calling** | The LLM asking our code to run a specific function with specific arguments. |
| **Allow-list** | A fixed list of what is permitted; everything else is refused. |
| **Guardrail** | A check in code that blocks something the AI should not do. |
| **Evidence chain** | The ordered list of everything the agent checked and found. |
| **Signal** | One finding, with a weight saying how suspicious it is. |
| **Noisy-OR** | A way to combine several independent signals into one score that never passes 100. |
| **Counterfactual** | A statement of what would have changed the result. |
| **Schema validation** | Checking that data has exactly the expected shape before using it. |
| **Red team** | Deliberately attacking your own system to find weaknesses. |
| **Hijacked model** | A model that has been talked into following an attacker's instructions (e.g. by prompt injection). The defences must hold even then. |
| **Fence (in a prompt)** | Tags around untrusted text, so the model can tell data from instructions; the text inside is escaped so it cannot close the fence. |

## Project and tooling terms

| Term | Meaning |
|---|---|
| **Spring Boot** | A Java framework for building web services. |
| **Maven / `mvnw`** | The Java build tool, and the wrapper script that downloads it for you. |
| **`pom.xml`** | The file listing a Java project's libraries and settings. |
| **Controller** | The class that handles requests for a set of URLs. |
| **DTO** | Data transfer object. A small class describing the shape of a request or response. |
| **Migration** | A versioned SQL script that changes the database schema. |
| **Flyway** | The tool that runs migrations in order. |
| **FastAPI** | A Python framework for building web services. |
| **CI** | Continuous integration. Automated checks that run on every push. |
| **ADR** | Architecture decision record. A short note on why a choice was made. |
| **PRD** | Product requirements document. What we are building and why. |
