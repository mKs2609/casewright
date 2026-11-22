# Development

How to run Casewright on your own machine, and how to try each part. The fastest way to see it working needs no setup at all: the **Open in GitHub Codespaces** button in the [README](../README.md#try-it-yourself) starts the whole system in containers ([Deployment](DEPLOYMENT.md)).

On a Windows machine you need **Java 25**, **Python 3.14**, **Node 24** and **PostgreSQL 16**; the setup scripts in `scripts/` are PowerShell. Start the gateway first, then the agent, then the dashboard. Every command below is run from the repository root unless it says otherwise; [`AGENTS.md`](../AGENTS.md) has the full list in one table.

## Running the gateway

Requirements: Java 25 or newer and PostgreSQL 16. Maven comes bundled as `mvnw`.

One-time database setup (creates the database, a limited database user, and your local `.env` file; it asks for your PostgreSQL `postgres` password):

```bash
powershell -ExecutionPolicy Bypass -File scripts\setup-db.ps1
```

Generate the application's secrets, then the development certificate the gateway uses for HTTPS (both are safe to re-run, and nothing they create is committed):

```bash
powershell -ExecutionPolicy Bypass -File scripts\setup-secrets.ps1
```

```bash
powershell -ExecutionPolicy Bypass -File scripts\setup-https.ps1
```

Optionally, trust that certificate for your Windows account so browsers stop warning about it (Windows asks you to confirm; `-Untrust` removes it again):

```bash
powershell -ExecutionPolicy Bypass -File scripts\setup-https.ps1 -Trust
```

Then start the gateway:

```bash
cd gateway
./mvnw spring-boot:run
```

Then open https://localhost:8443/api/health. The gateway only speaks HTTPS. You should see `{"status":"UP","database":"UP", ...}`.

If you already have a `.env` from before the audit log, run `setup-secrets.ps1` again to add its key. Keep that key: changing it makes every existing audit entry fail verification. The gateway also writes `gateway/logs/gateway.log`, which is a record of the audit chain's latest position outside the database.

Settings such as how long approvals stay open (`actions.approval-lifetime`, 24 hours) and which domains can never be blocked (`actions.protected-domains`) are in `gateway/src/main/resources/application.properties`.

Run the tests (they start their own throwaway PostgreSQL, so they need no setup). GitHub also runs them on every pull request:

```bash
cd gateway
./mvnw test
```

## Running the agent

The agent is a separate Python service (3.14) that the gateway calls to investigate each incident. It listens on this machine only and accepts calls only from the gateway, which proves itself with `AGENT_SERVICE_TOKEN` from `.env` (created by `setup-secrets.ps1`).

One-time setup, from the `agent` folder:

```bash
python -m venv .venv
```

```bash
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.txt
```

Start it (keep it running alongside the gateway):

```bash
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --no-server-header
```

Run its tests:

```bash
.\.venv\Scripts\python.exe -m pytest
```

Optional: let a free local AI model choose the investigation steps. Install [Ollama](https://ollama.com/download) (use "Download manually"), download the model once, then add `LLM_PROVIDER=ollama` to `.env` and restart the agent. Without it, the agent uses its fixed plan.

```bash
ollama pull qwen3:8b
```

Measure its accuracy on the labelled incidents (from the repository root; rewrites `docs/EVALUATION.md`, and with `--model` also runs them with the local AI model):

```bash
agent\.venv\Scripts\python.exe scripts\evaluate.py
```

## Running the dashboard

The dashboard needs Node 24 and the development certificate from `setup-https.ps1`. It talks only to the gateway, so start that first. One-time setup, from the `dashboard` folder:

```bash
npm ci
```

Start it, then open https://localhost:5173. The login comes first; below it, **See how it works** scrolls to a short explanation. After logging in:

- **Overview** shows the key figures (incidents, attacks found, decisions waiting, audit log entries) and every incident. The figures are also filters: **Attacks found** shows only attacks, **Waiting for a decision** opens what waits on its Actions tab, and the row under them picks a type (Email, Sign-ins, Phone calls). The filters stay in the address, so a reload keeps them. Click an incident to open it.
- **Scenarios** lets analysts and admins fire a made-up attack, starting with **Attempt breach**; these incidents are marked Simulated. **Red-team the agent** starts a run in which a scripted, hijacked model plays the AI, with a scorecard of every attempt and what stopped it.
- **Each incident** has its own page: the risk at the top, then **Evidence** (every step the investigation took), **Reports** (for the security team and for everyone) and **Actions** (decisions waiting for you). Clicking a reference like `E2` in a report jumps to that step.

Investigations update on screen as they run: new evidence slides in, a small lattice and a stopwatch show the work is still going, and the figures count to their new values. With an incident open, the sidebar's menu branches to its Evidence, Reports and Actions. The sidebar shows whether live updates are on; Refresh always works, and says when it last updated. Every animation stops if your system asks for reduced motion.

```bash
npm run dev
```

`npm run dev` relaxes the page's security policy for hot reloading. To run the built app under the strict policy:

```bash
npm run build
```

```bash
npm run preview
```

Run its tests (they need neither the gateway nor the certificate):

```bash
npm test
```

Incidents can also be submitted through the API, for example with `scripts\try-incident.ps1` ([below](#the-approval-api)).

## The approval API

A high-risk action (blocking an address, domain or number, quarantining an email, locking an account or forcing a password reset) starts as `pending`, and its incident shows `awaiting_approval`. Analysts and admins decide it on the incident's **Actions** tab in the dashboard, or through the API:

| Request | What it does |
|---|---|
| `GET /api/actions` | What is waiting (or `?status=executed`, `rejected`, `expired`) |
| `GET /api/incidents/{id}` | The incident with its evidence, verdict, reports and actions |
| `POST /api/actions/{id}/decision` | Body `{"decision": "approve"}` or `{"decision": "reject"}` |
| `GET /api/audit` | Recent audit entries |
| `GET /api/audit/verify` | Checks the chain, and says where it broke if it did |

Internal addresses and your own domains can never be blocked, whatever an incident says. So a hidden "block 10.0.0.5" note in an email goes nowhere.

To try the whole path, with the gateway and agent running (above):

```bash
powershell -ExecutionPolicy Bypass -File scripts\try-incident.ps1 -Username <you> -Decide approve
```

Your account needs the `ANALYST` or `ADMIN` role, which `scripts\set-role.ps1` can grant.
