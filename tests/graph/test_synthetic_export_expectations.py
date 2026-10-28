"""The synthetic graph-export recording satisfies its semantic expectations, and they cover every case."""
from __future__ import annotations

import copy
import json

from appsec_review.codeql.runtime import load_graph_exports
from appsec_review.graph import contract
from tests.fixtures.graph.expectations import SYNTHETIC, load_expectations, unmet


def _recording():
    return load_graph_exports(SYNTHETIC / "exports", bytes_limit=contract.GraphSettings().max_export_bytes)


def test_recording_meets_every_expectation() -> None:
    assert unmet(_recording(), load_expectations()) == []


def test_every_provenance_case_has_an_expectation() -> None:
    cases = json.loads((SYNTHETIC / "provenance.json").read_text(encoding="utf-8"))["cases"]
    assert {item["case"] for item in load_expectations()["expectations"]} == set(cases)


def test_a_missing_row_or_column_is_reported() -> None:
    exports = copy.deepcopy(_recording())
    exports["path_flows"]["rows"] = [row for row in exports["path_flows"]["rows"] if row[1] != 55]
    document = load_expectations()
    document["expectations"].append({"case": "bad", "query_id": "ranges", "where": {"no_such_column": 1}})
    document["expectations"].append({"case": "absent", "query_id": "no_such_export", "where": {}})
    failures = unmet(exports, document)
    assert len(failures) == 3
    assert failures[0].startswith("two_paths_to_one_sink: no path_flows row")
    assert "no columns ['no_such_column']" in failures[1]
    assert "export no_such_export is missing" in failures[2]
