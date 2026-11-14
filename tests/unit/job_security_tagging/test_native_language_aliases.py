from __future__ import annotations

import pytest

from appsec_review.jobs.job_security_tagging.crosswalk import evaluate
from appsec_review.jobs.job_security_tagging.producers import collect_graph_facts

from .helpers import CannedIndexes, fact, scope, taxonomy


@pytest.mark.parametrize("language,native", [
    ("c", True), ("cpp", True), ("c++", True), ("c/c++", True), ("rust", True),
    (" C/C++ ", True),
    ("java", False), ("java-kotlin", False), ("kotlin", False),
    ("csharp", False), ("c#", False), ("javascript-typescript", False),
    ("typescript", False), ("python", False), ("go", False), ("swift", False),
    ("unknown", False),
], ids=["c", "cpp", "c++", "c-c++", "rust", "normalized-c-c++", "java", "java-kotlin", "kotlin",
        "csharp", "c#", "javascript-typescript", "typescript", "python", "go", "swift", "unknown"])
def test_native_memory_matches_graph_catalog_aliases_without_changing_provenance(language, native):
    vocabulary, rules, _ = taxonomy()
    rows = [fact("memory_read", language=language), fact("memory_write", language=language)]
    indexes = CannedIndexes(rows)
    records, gaps = collect_graph_facts(indexes, scope(), vocabulary, rules, 10, enable_swift=True)
    if native:
        assert not gaps and len(records) == 2
        assert {record["tag"] for record in records} == {"func:exec:unmanaged-memory"}
        assert all(record["basis"] == "invoked" and record["family"] == "code_facts" for record in records)
        assert {record["evidence"][0]["ref"] for record in records} == {row.identity for row in rows}
        assert all(record["evidence"][0]["graph_scope"]["language"] == language for record in records)
    else:
        assert not records and len(gaps) == 2
        assert all("unmapped_class" in gap for gap in gaps)
        assert not indexes.source_reads


def test_observed_operations_cannot_promote_existing_crosswalk_labels_into_evidence():
    vocabulary, rules, crosswalk = taxonomy()
    accepted_scope = scope()
    rows = [fact("xml_external_entity"), fact("template_injection")]
    observed, gaps = collect_graph_facts(CannedIndexes(rows), accepted_scope, vocabulary, rules, 10)
    assert not gaps and all(record["namespace"] == "func" and record["basis"] == "invoked"
                            for record in observed)
    derived = evaluate(crosswalk, vocabulary, observed,
                       scope_subject=lambda kind, key, group: [accepted_scope.component_subject(key)])
    assert {record["tag"] for record in derived} == {"cwe:611", "capec:221", "cwe:1336", "asvs5:v1"}
    observed_ids = {record["assignment_id"] for record in observed}
    for record in derived:
        assert record["basis"] == "derived" and record["evidence"] == []
        assert record["derived_from"] and set(record["derived_from"]) <= observed_ids
    assert {record["evidence"][0]["ref"] for record in observed} == {row.identity for row in rows}
