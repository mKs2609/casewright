"""Runs the evaluation sets (step 18b, ADR-53) and rewrites docs/EVALUATION.md.

    agent\\.venv\\Scripts\\python.exe scripts\\evaluate.py           the rule engine (what CI checks)
    agent\\.venv\\Scripts\\python.exe scripts\\evaluate.py --model   also with the local AI model

Without --model the AI is switched off whatever .env says, so the result is the same every time.
With --model, Ollama must be running (LLM_MODEL and OLLAMA_URL come from .env, as for the agent);
the result is recorded in testdata/evaluation-model-run.json. It takes a while: every incident
is a full investigation by the model.
"""
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent"))
WITH_MODEL = "--model" in sys.argv[1:]
# Off for the rule-engine runs whatever .env says; switched on only to build the model (model_run).
os.environ["LLM_PROVIDER"] = "off"

from app import config, reasoning  # noqa: E402
from tests.evaluation import detection, false_alarms, report, run, run_all  # noqa: E402
from tests.evaluation_heldout import HELD_OUT  # noqa: E402
from tests.evaluation_set import DEVELOPMENT  # noqa: E402

REPORT = ROOT / "docs" / "EVALUATION.md"
MODEL_RUN = ROOT / "testdata" / "evaluation-model-run.json"


def show(title: str, outcomes: list) -> None:
    print(f"\n{title}")
    for o in outcomes:
        print(f"  {'ok   ' if o.correct else 'WRONG'} {o.example.label:9} -> {o.verdict:10} risk {o.risk:3}  {o.example.name}")
    d, f = detection(outcomes), false_alarms(outcomes)
    print(f"  Attacks caught: {d.shown()}    False alarms: {f.shown()}", flush=True)


def model_run() -> dict:
    # Read the model settings (and their checks: a loopback address only) with the provider on, then
    # switch it off again: the model is passed to each run directly.
    os.environ["LLM_PROVIDER"] = "ollama"
    config.llm_settings.cache_clear()
    model, settings = reasoning.configured_model(), config.llm_settings()
    os.environ["LLM_PROVIDER"] = "off"
    config.llm_settings.cache_clear()
    print(f"\nWith the AI model {settings.model} at {settings.url} (one full investigation per incident) ...")
    budget_examples = DEVELOPMENT + HELD_OUT
    results = {}
    for i, example in enumerate(budget_examples):
        outcome = run(example, 2000 + i, model)
        results[example.name] = {"flagged": outcome.flagged, "verdict": outcome.verdict, "risk": outcome.risk,
                                 "engine": outcome.engine}
        print(f"  {i + 1:3}/{len(budget_examples)} {'ok   ' if outcome.correct else 'WRONG'} [{outcome.engine:5}] "
              f"{example.name}", flush=True)
    finished = sum(r["engine"] == "llm" for r in results.values())
    if finished == 0:
        raise SystemExit("The model finished no investigation (is Ollama running?). Nothing was recorded.")
    return {"model": settings.model, "date": datetime.now(UTC).date().isoformat(), "results": results}


print("Running the rule engine on both sets ...", flush=True)
development, held_out = run_all(DEVELOPMENT), run_all(HELD_OUT)
show("Development set (rule engine)", development)
show("Held-out set (rule engine)", held_out)

if WITH_MODEL:
    recorded = model_run()
    MODEL_RUN.write_text(json.dumps(recorded, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"\nRecorded in {MODEL_RUN.relative_to(ROOT)}")
recorded = json.loads(MODEL_RUN.read_text(encoding="utf-8")) if MODEL_RUN.exists() else None

REPORT.write_text(report(development, held_out, recorded), encoding="utf-8", newline="\n")
print(f"Wrote {REPORT.relative_to(ROOT)}")
