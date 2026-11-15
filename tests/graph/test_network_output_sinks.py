"""T-5017: network-output sinks classify, and a dataflow path is eligible exactly when its sink site is.

The fixture ``tests/fixtures/graph/run_rows/smoke-cpp-2026-11-14-0005-paths.json`` holds the classification
fields of the 44 ``dataflow_path`` facts and their 18 ``sink_site`` facts (plus every unclassified sink) that
smoke-cpp run ``2026-11-14-0005`` published with catalog revision 1, where the 10 paths ending in ``send``
were ineligible with ``unclassified_sink``. The run itself is never read at test time.
"""
from __future__ import annotations

import json
from pathlib import Path

from appsec_review.graph import contract as c
from appsec_review.graph.catalog import load_catalog

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "graph" / "run_rows" / "smoke-cpp-2026-11-14-0005-paths.json"
ROWS = json.loads(FIXTURE.read_text(encoding="utf-8"))
CPP = load_catalog().language("cpp")


def _reclassified(sink: dict) -> c.SinkClass:
    row = {"api": sink["api"], "declared_in": sink["declared_in"] or "", "argument_index": sink["argument_index"],
           "model": sink["model"]}
    return CPP.classify_sink(row)


def test_the_run_published_ten_paths_ineligible_only_because_their_sink_was_unclassified() -> None:
    ineligible = [path for path in ROWS["paths"] if path["ineligibility_reasons"]]
    assert len(ROWS["paths"]) == 44 and len(ineligible) == 10
    assert {tuple(path["ineligibility_reasons"]) for path in ineligible} == {("unclassified_sink",)}
    assert {ROWS["sink_sites"][path["sink_site"]]["api"] for path in ineligible} == {"send"}
    # The paths sink class was already the sink sites class: classification happens once, at the sink site.
    for path in ROWS["paths"]:
        assert path["sink_class"] == ROWS["sink_sites"][path["sink_site"]]["sink_class"]


def test_send_and_write_sinks_classify_as_network_output_through_the_api_tier() -> None:
    unclassified = {identity: sink for identity, sink in ROWS["sink_sites"].items() if sink["sink_class"] == "unclassified"}
    assert {sink["api"] for sink in unclassified.values()} == {"send", "write"}
    assert {sink["model"] for sink in unclassified.values()} == {"RemoteFlowSinkFunction"}
    for sink in unclassified.values():
        result = _reclassified(sink)
        assert result.klass == c.SinkClass.NETWORK_OUTPUT.value and result.tier == 1
        assert result.rule_id == "cpp.sink.api." + sink["api"] and result.cwe_family == "CWE-200"


def test_every_classified_sink_keeps_its_class_under_the_new_catalog() -> None:
    for sink in ROWS["sink_sites"].values():
        if sink["sink_class"] != "unclassified":
            result = _reclassified(sink)
            assert (result.klass, result.rule_id) == (sink["sink_class"], sink["catalog_rule"]), sink["api"]


def test_every_path_whose_sink_site_is_classified_is_direct_eligible() -> None:
    for path in ROWS["paths"]:
        sink = ROWS["sink_sites"][path["sink_site"]]
        sink_class = _reclassified(sink).klass
        payload = {"family": c.Family.DATAFLOW_PATH.value, "exact": path["exact"],
                   "coverage_status": path["coverage_status"],
                   "cross_check": {"state": path["cross_check_state"], "producers": []},
                   "result": {"source": {"source_class": path["source_class"]},
                              "sink": {"sink_site": path["sink_site"], "sink_class": sink_class}}}
        assert sink_class != c.SinkClass.UNCLASSIFIED.value
        assert c.admissibility(payload) == {"rule": c.ADMISSIBILITY_RULE, "direct_eligible": True,
                                            "ineligibility_reasons": []}, path["name"]


def test_the_catalog_schema_and_contract_carry_the_output_sink_classes() -> None:
    schema = json.loads((Path(__file__).resolve().parents[2] / "rules" / "codeql-graph-export"
                         / "catalog.schema.json").read_text(encoding="utf-8"))
    enum = set(schema["$defs"]["sink_class"]["enum"])
    assert {"network_output", "file_write"} <= enum
    assert enum == {value.value for value in c.SinkClass} - {"unclassified"}
    assert load_catalog().revision >= 2
    assert _reclassified({"api": "fwrite", "declared_in": "stdio.h", "argument_index": 0, "model": "api"}).klass == "file_write"
