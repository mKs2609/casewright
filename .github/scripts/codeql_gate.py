"""The CodeQL gate (ADR-52): fails if CodeQL reported anything not in .github/codeql-reviewed.json.

Usage: python3 .github/scripts/codeql_gate.py <folder with .sarif files> [reviewed list]
Prints every finding, marked "reviewed" or "NEW", and exits 1 if any is new.
"""
import json
import sys
from pathlib import Path

results_dir = Path(sys.argv[1])
reviewed_file = Path(sys.argv[2] if len(sys.argv) > 2 else ".github/codeql-reviewed.json")
reviewed = {(entry["rule"], entry["file"]) for entry in json.loads(reviewed_file.read_text(encoding="utf-8"))["reviewed"]}

sarif_files = sorted(results_dir.glob("*.sarif"))
if not sarif_files:
    sys.exit(f"No CodeQL results found in {results_dir}: the analysis did not run")

new = 0
for sarif in sarif_files:
    for run in json.loads(sarif.read_text(encoding="utf-8"))["runs"]:
        for result in run.get("results", []):
            location = result["locations"][0]["physicalLocation"]
            rule, file = result["ruleId"], location["artifactLocation"]["uri"]
            line = location.get("region", {}).get("startLine", "?")
            known = (rule, file) in reviewed
            new += 0 if known else 1
            print(f"{'reviewed' if known else 'NEW     '}  {rule}: {file}:{line}")

print(f"New CodeQL findings: {new}")
sys.exit(1 if new else 0)
