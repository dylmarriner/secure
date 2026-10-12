#!/usr/bin/env python3
"""Fail if docs/security-remediation-plan.md cites, on a checked `- [x]` item, a snake_case
identifier (test name, function, field) that does not exist anywhere in the Rust sources.

This exists because Phase R1 was once checked off with descriptions of code and tests that had
never landed. It cannot prove a claim is *true*; it does make an invented test name fail CI.
Identifiers need at least two underscores (three words) to count, which skips ordinary prose.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLAN = ROOT / "docs" / "security-remediation-plan.md"
IDENT = re.compile(r"`([a-z][a-z0-9]*(?:_[a-z0-9]+){2,})`")

sources = "\n".join(
    p.read_text(encoding="utf-8", errors="replace")
    for base in ("crates", "apps")
    for p in (ROOT / base).rglob("*.rs")
    if "target" not in p.parts
)

missing = []
in_checked_item = False
for number, line in enumerate(PLAN.read_text(encoding="utf-8").splitlines(), 1):
    stripped = line.lstrip()
    if stripped.startswith("- [x]"):
        in_checked_item = True
    elif stripped.startswith("- [ ]") or stripped.startswith("#") or not stripped:
        in_checked_item = False
    if not in_checked_item:
        continue
    for ident in IDENT.findall(line):
        if not re.search(rf"\b{re.escape(ident)}\b", sources):
            missing.append((number, ident))

for number, ident in missing:
    print(f"{PLAN.relative_to(ROOT)}:{number}: checked item cites `{ident}`, which is not in any .rs file")
if missing:
    sys.exit(1)
print("every identifier cited by a checked remediation item exists in the sources")
