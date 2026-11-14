"""Read-only, operator-supplied run acceptance. This file must be selected explicitly.

Prerequisites: authorize this check, set APPSEC_T146_TAGS_ACCEPTANCE_RUN to a completed run with
accepted security tags and graph facts, and APPSEC_T146_TAGS_EXPECTED_REFS to a JSON list of
independently selected graph entry/sink identities whose behavior must appear. Those expected
references prevent a vacuous 'job succeeded' result. No target execution or model calls occur.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from appsec_review.graph.contract import validate_payload
from appsec_review.indexing.store import accepted_handoff
from appsec_review.retrieval import EntityKind, LogicalIdentity, RetrievalCore
from appsec_review.storage.shared import verify_reference


pytestmark = pytest.mark.time_budget(120, reason="bounded read-only inspection of operator-supplied accepted run")
RUN_ENVIRONMENT = "APPSEC_T146_TAGS_ACCEPTANCE_RUN"


def test_accepted_behavior_tags_are_source_resolving_scoped_operations_not_findings():
    selected = os.environ.get(RUN_ENVIRONMENT)
    expected_json = os.environ.get("APPSEC_T146_TAGS_EXPECTED_REFS")
    assert selected and expected_json, (
        "manual prerequisite: APPSEC_T146_TAGS_ACCEPTANCE_RUN and APPSEC_T146_TAGS_EXPECTED_REFS")
    root = Path(selected).resolve(strict=True)
    expected = json.loads(expected_json)
    assert isinstance(expected, list) and expected and all(isinstance(item, str) for item in expected)
    accepted = accepted_handoff(root, "job_security_tagging")
    assert accepted is not None, "manual prerequisite: accepted job_security_tagging publication"
    output = accepted.handoff["outputs"]["publication.publish_handoff"]
    document = json.loads(verify_reference(root, output["artifact"]).read_bytes())
    assignments = json.loads(verify_reference(root, document["assignments"]).read_bytes())["assignments"]
    manifest = document["index_manifest"]
    core = RetrievalCore(root.parent, root.name, manifest_path=verify_reference(root, manifest),
                         manifest_sha256=manifest["sha256"])
    graph_tags = [record for record in assignments if record["basis"] == "invoked"
                  and any(evidence.get("index") == "graph" for evidence in record["evidence"])]
    assert graph_tags, "acceptance requires observed behavior, not a successful empty publication"
    cited = set()
    for record in graph_tags:
        assert record["family"] == "code_facts" and not record["derived_from"]
        assert record["tag"].startswith(("func:", "surface:entry:"))
        assert record["subject"]["kind"] == "source_span"
        for evidence in record["evidence"]:
            assert evidence["index"] == "graph"
            original = core.find(identity=evidence["ref"], limit=2)["results"]
            assert original, "the original accepted graph fact must still resolve"
            fact = original[0]
            validate_payload(fact["payload"])
            assert fact["payload"]["admissibility"]["direct_eligible"]
            assert fact["payload"]["producer"] == evidence["graph_producer"]
            assert fact["payload"]["scope"] == evidence["graph_scope"]
            assert fact["payload"]["upstream"] == evidence["graph_upstream"]
            assert fact["location"]["file_sha256"] == evidence["file_sha256"]
            shard = next(item for item in core.manifest["indexes"]
                         if item["name"] == "graph" and item["shard_id"] == evidence["shard_id"])
            assert shard["sha256"] == evidence["index_sha256"]
            assert shard["producer"] == evidence["index_producer"]
            read = core.read_excerpt(identity=evidence["ref"], context_lines=0)
            assert read["results"] and not read["results"][0]["excerpt_truncated"]
            location = evidence["location"]
            site = LogicalIdentity.derive(EntityKind.SOURCE_SPAN, document["target_snapshot"], {
                "path": location["path"], "sha256": location["file_sha256"],
                "start_byte": location["start_byte"], "end_byte": location["end_byte"]}).value
            assert site == record["subject"]["logical_id"]
            if fact["payload"]["family"] == "entry_point" and fact["payload"]["result"]["source_class"] == "remote":
                assert record["tag"] == "surface:entry:remote-input"
            cited.add(evidence["ref"])
    assert set(expected) <= cited, "independently selected operation sites were omitted"
    assert document["security_findings"] == []
    assert document["assignment_count"] == len(assignments)
    assert sum(document["basis_counts"].values()) == len(assignments)
    assert sum(document["family_counts"].values()) == len(assignments)
    assert document["gaps"], "bounded operation coverage must not be presented as complete review coverage"
