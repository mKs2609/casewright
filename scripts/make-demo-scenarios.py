"""Writes gateway/src/main/resources/demo/scenarios.json from the agent's test scenarios
(agent/tests/scenarios.py), so the demo buttons fire exactly the incidents whose verdicts are tested.
agent/tests/test_demo_scenarios.py fails if the two ever differ.

Run from the repository root, with the agent's Python:
    agent\\.venv\\Scripts\\python.exe scripts\\make-demo-scenarios.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent"))
from tests.scenarios import SCENARIOS  # noqa: E402

# Button order and wording. The first is the main button, "Attempt breach" (FR-26).
SHOWN = [
    ("credential_stuffing", "Attempt breach",
     "Someone guesses passwords for many accounts from one address, then gets into one."),
    ("phishing_email", "Phishing email", "A fake security warning that asks for a password."),
    ("vishing_call", "Scam phone call", "A caller pretending to be a bank asks for a one-time code."),
    ("impossible_travel", "Impossible travel", "Sign-ins from two countries too far apart to travel between in time."),
    ("prompt_injection_email", "Email that tries to trick the AI",
     "A phishing email with a hidden note telling the AI to call it safe."),
    ("normal_login", "Normal sign-in", "An ordinary sign-in at the usual time and place. Should come out safe."),
]

scenarios = []
for name, title, description in SHOWN:
    kind, subject, payload = SCENARIOS[name][0]()
    scenarios.append({"name": name, "title": title, "description": description,
                      "incident": {"kind": kind, "subjectIdentity": subject, **payload}})

out = ROOT / "gateway" / "src" / "main" / "resources" / "demo" / "scenarios.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps({"scenarios": scenarios}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
print(f"Wrote {len(scenarios)} scenarios to {out.relative_to(ROOT)}")
