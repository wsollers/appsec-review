from __future__ import annotations

import pytest

from appsec_review.jobs.job_security_tagging import job
from appsec_review.jobs.job_security_tagging.producers import Row, collect_observation_facts
from appsec_review.jobs.job_security_tagging.taxonomy import TaxonomyError
from appsec_review.retrieval import EntityKind, LogicalIdentity

from .helpers import CannedIndexes, SNAPSHOT, fact, scope, shard, taxonomy, unit_context


def handler(name):
    return next(unit.handler for unit in job.build_job().units if unit.unit_id == name)


def test_real_source_handler_publishes_declared_and_graph_facts(tmp_path, monkeypatch):
    graph = fact()
    source_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {"path": "src/app.py"}).value
    source = Row(source_id, "source_file", "src/app.py", "app.py", {"language": "Python"}, graph.location)
    indexes = CannedIndexes(groups=[(shard("source"), [source]), (shard(), [graph])])
    monkeypatch.setattr(job, "_indexes", lambda unit: indexes)
    monkeypatch.setattr(job, "_scope", lambda unit: scope())
    loaded = handler("taxonomy.load_taxonomy")(unit_context(tmp_path, "taxonomy.load_taxonomy"))
    unit = unit_context(tmp_path, "collection.source_facts", {"taxonomy.load_taxonomy": loaded})
    result = handler(unit.unit_id)(unit)
    artifact = job._read(unit, result["artifact"])
    assert result["terminal_status"] == "SUCCEEDED" and not result["gaps"]
    assert result["item_count"] == 2
    assert {(record["tag"], record["basis"]) for record in artifact["assignments"]} == {
        ("lang:python", "declared"), ("func:data:sql-query", "invoked")}
    assert artifact["collector"] == "source-facts"
    assert artifact["assignments"][0]["vocabulary_sha256"] == loaded["identities"]["vocabulary_sha256"]
    assert job.TOPOLOGY["collection"] == ("source_facts", "observation_facts", "coverage_gaps")
    assert all("not implemented; func tags" not in gap for gap in job.STANDING_GAPS)


def test_missing_graph_and_assignment_cap_flow_through_real_handler(tmp_path, monkeypatch):
    monkeypatch.setattr(job, "_indexes", lambda unit: CannedIndexes(missing=True))
    monkeypatch.setattr(job, "_scope", lambda unit: scope())
    loaded = handler("taxonomy.load_taxonomy")(unit_context(tmp_path, "taxonomy.load_taxonomy"))
    unit = unit_context(tmp_path, "collection.source_facts", {"taxonomy.load_taxonomy": loaded})
    result = handler(unit.unit_id)(unit)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS" and result["item_count"] == 0
    assert "missing_graph" in result["gaps"][0]
    monkeypatch.setattr(job, "_indexes", lambda unit: CannedIndexes([fact(), fact(start=1)]))
    unit.job.config.settings["max_assignments"] = 1
    with pytest.raises(ValueError, match="assignment bound 1"):
        handler(unit.unit_id)(unit)


def test_handler_refuses_taxonomy_identity_change(tmp_path):
    loaded = handler("taxonomy.load_taxonomy")(unit_context(tmp_path, "taxonomy.load_taxonomy"))
    loaded["identities"]["capability_rules_sha256"] = "0" * 64
    unit = unit_context(tmp_path, "collection.source_facts", {"taxonomy.load_taxonomy": loaded})
    with pytest.raises(ValueError, match="identity changed"):
        handler(unit.unit_id)(unit)


def test_taxonomy_uses_explicit_scoped_pins_not_central_configuration(tmp_path):
    from .helpers import ROOT, settings
    configured = settings()
    configured["taxonomy"]["capability_rules_sha256"] = "0" * 64
    with pytest.raises(TaxonomyError, match="hash mismatch"):
        job._taxonomy(ROOT, configured)


def test_packages_and_observations_keep_their_declared_and_reported_bases():
    vocabulary, rules, _ = taxonomy()
    package = Row("package-observation", "tool_observation", "pkg", "inventory",
                  {"tool_id": "tool-syft", "package": "pyjwt", "category": "software_inventory"}, None)
    finding = Row("finding-observation", "tool_observation", "rule", "finding",
                  {"producer": "codeql", "rule": {"properties": {"tags": ["external/cwe/cwe-089"]}}}, None)
    indexes = CannedIndexes(groups=[(shard("observations"), [package, finding])])
    records, gaps = collect_observation_facts(indexes, scope(), vocabulary, rules, 10)
    assert not gaps
    assert {(item["tag"], item["basis"]) for item in records} == {
        ("func:authn:jwt", "declared"), ("cwe:89", "reported")}
    assert all(item["basis"] != "invoked" for item in records)
