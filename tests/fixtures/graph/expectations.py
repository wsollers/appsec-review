"""Semantic expectations for a graph-export fixture (``expected-facts.json``).

Shared by the offline check over the recording and the live tier over a pinned-image export, so both
hold the export pack to the same floor.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SCHEMA = "appsec-review/graph-export-expected-facts/1"
SYNTHETIC = Path(__file__).parent / "codeql_export" / "synthetic"


def load_expectations(fixture: Path = SYNTHETIC) -> dict[str, Any]:
    document = json.loads((fixture / "expected-facts.json").read_text(encoding="utf-8"))
    if document.get("schema") != SCHEMA:
        raise ValueError(f"expected-facts schema must be {SCHEMA}")
    return document


def unmet(exports: Mapping[str, Mapping[str, Any]], document: Mapping[str, Any]) -> list[str]:
    """Return one message per expectation that no row of its export satisfies."""
    failures = []
    for expectation in document["expectations"]:
        query_id, where = expectation["query_id"], expectation["where"]
        export = exports.get(query_id)
        if export is None:
            failures.append(f"{expectation['case']}: export {query_id} is missing")
            continue
        columns = list(export["columns"])
        unknown = sorted(set(where) - set(columns))
        if unknown:
            failures.append(f"{expectation['case']}: {query_id} has no columns {unknown}")
            continue
        index = {name: columns.index(name) for name in where}
        if not any(all(row[index[name]] == value for name, value in where.items()) for row in export["rows"]):
            failures.append(f"{expectation['case']}: no {query_id} row has {json.dumps(where, sort_keys=True)}")
    return failures
