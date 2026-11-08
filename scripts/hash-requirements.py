"""Adds the SHA-256 fingerprint of every published file to each pinned package in
agent/requirements*.txt, taken from PyPI. With hashes present, pip installs a package only if its
file matches one of them, so a tampered or swapped download stops the install.

Run after changing a version (it rewrites the files in place, keeping comments and order):
    agent\\.venv\\Scripts\\python.exe scripts\\hash-requirements.py
"""
import json
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = [ROOT / "agent" / "requirements.txt", ROOT / "agent" / "requirements-dev.txt"]
PINNED = re.compile(r"^([A-Za-z0-9_.\-]+(?:\[[A-Za-z0-9_,\-]+\])?)==([A-Za-z0-9_.\-+!]+)\s*(;[^#]*?)?\s*(#.*)?$")


def hashes(name: str, version: str) -> list[str]:
    bare = re.sub(r"\[.*\]", "", name)
    request = urllib.request.Request(f"https://pypi.org/pypi/{bare}/{version}/json", headers={"User-Agent": "hash-requirements"})
    with urllib.request.urlopen(request, timeout=60) as response:
        files = json.load(response)["urls"]
    found = sorted({f["digests"]["sha256"] for f in files})
    if not found:
        raise SystemExit(f"PyPI lists no files for {bare}=={version}")
    return found


for path in FILES:
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("--hash=") or stripped == "\\":
            continue   # the old hashes of a line being rewritten
        match = PINNED.match(stripped.rstrip("\\").strip())
        if not match:
            out.append(line)
            continue
        name, version, marker, comment = match.groups()
        if comment:
            out.append(comment)
        found = hashes(name, version)
        out.append(f"{name}=={version}" + (f" {marker.strip()}" if marker else "") + " \\")
        out.extend(f"    --hash=sha256:{h}" + (" \\" if i < len(found) - 1 else "") for i, h in enumerate(found))
    path.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    print(f"{path.relative_to(ROOT)}: hashed")
