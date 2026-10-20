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
| **LLM** | Large language model, such as Claude. |
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
