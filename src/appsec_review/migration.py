from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any


DISPOSITIONS = {"port", "merge", "replace", "retire", "defer"}
DESTINATION = re.compile(r"job_[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){0,2}$")


def validate_ledger(path: Path) -> dict[str, Any]:
    ledger = json.loads(Path(path).read_text(encoding="utf-8"))
    if ledger.get("schema") != "appsec-review/migration-ledger/1":
        raise ValueError("invalid migration ledger schema")
    summary = {}
    for category, value in ledger.get("categories", {}).items():
        sources = value.get("sources", [])
        if len(sources) != value.get("expected_count") or len(sources) != len(set(sources)):
            raise ValueError(f"{category} source accounting is incomplete or duplicated")
        explicit: set[str] = set()
        fallback = None
        for rule in value.get("rules", []):
            if rule.get("disposition") not in DISPOSITIONS:
                raise ValueError(f"invalid disposition in {category}")
            for destination in rule.get("destination", []):
                if not DESTINATION.fullmatch(destination):
                    raise ValueError(f"invalid destination: {destination}")
            if rule.get("sources") == ["*"]:
                if fallback is not None:
                    raise ValueError(f"duplicate fallback in {category}")
                fallback = rule
            else:
                names = set(rule.get("sources", []))
                if explicit & names or not names <= set(sources):
                    raise ValueError(f"duplicate or unknown source rule in {category}")
                explicit |= names
        if fallback is None and explicit != set(sources):
            raise ValueError(f"unmapped sources in {category}")
        verified = {
            source for rule in value.get("rules", [])
            if str(rule.get("verification", "")).endswith("_verified")
            for source in rule.get("sources", []) if source != "*"
        }
        summary[category] = {"count": len(sources), "wave1_verified": len(verified),
                             "deferred": len(sources) - len(verified)}
    if set(summary) != {"graph_jobs", "templates"}:
        raise ValueError("ledger must account for graph jobs and templates")
    return summary
