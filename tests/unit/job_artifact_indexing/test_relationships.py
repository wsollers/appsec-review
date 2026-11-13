"""job_artifact_indexing: the ``index.relationships`` unit and its per-artifact relation builder.

``_artifact_relations`` is a pure function of the receipt context and one artifact, so producer
attribution (receipt rows, captured invocations, argv fallback, heuristic mappings, the ambiguous
fan-out) and link provenance (deduplicated LINKS_INTO relations with bounded observation lists) are
asserted on the records directly. The batching cases through ``_relationships`` come from the
pre-walk throughput suite and assert the written shards. Replaces the relation claims of the graph
tests ``test_repeated_link_observations...`` and ``test_captured_invocation_parent_attributes...``.
"""
from __future__ import annotations

import json
from pathlib import Path
import random
import sqlite3

import pytest

from appsec_review.jobs.job_artifact_indexing import job as job_module
from appsec_review.jobs.job_artifact_indexing.job import _MAX_LINK_OBSERVATIONS, _artifact_relations, _ReceiptContext, _relationships
from appsec_review.retrieval import IndexBuilder, RelationKind
from tests.unit.job_artifact_indexing.support import SNAPSHOT, UNIT, loaded_output, unit_context, validated_receipt


def _unit(run_root: Path, receipt: dict):
    return unit_context(run_root, "index.relationships", {"load.accepted_builds": loaded_output([receipt])})


def _limits(monkeypatch, *, artifacts: int | None = None, rows: int | None = None) -> None:
    if artifacts is not None:
        monkeypatch.setattr(job_module, "MAX_ARTIFACTS_PER_SHARD", artifacts)
    if rows is not None:
        monkeypatch.setattr(job_module, "MAX_ROWS_PER_SHARD", rows)


def _coverage_areas(run_root: Path, identity: dict) -> list[str]:
    with sqlite3.connect(run_root / str(identity["relative_path"])) as database:
        return [row[0] for row in database.execute("SELECT area FROM coverage ORDER BY area")]


def _relations(context: _ReceiptContext, artifact: dict, kind: RelationKind) -> list[tuple]:
    rows = _artifact_relations(context, artifact)
    return sorted((relation.source_id, relation.target_id, relation.exact, relation.confidence, relation.ambiguity)
                  for relation in rows.relations if relation.kind is kind)


# --- producer attribution (pure) ---------------------------------------------------------------------

def test_receipt_rows_and_captured_parents_attribute_an_object_to_its_compile_action() -> None:
    receipt = validated_receipt(1)
    context = _ReceiptContext.build(receipt, SNAPSHOT)
    obj = receipt["validated_artifacts"][0]
    compile_action = context.action_identity("compile").value
    rows = _artifact_relations(context, obj)
    assert rows.artifact is obj and rows.entities == [] and rows.gaps == [] and rows.size == 2
    assert _relations(context, obj, RelationKind.GENERATED_FROM) == sorted([
        (obj["canonical_identity"], compile_action, False, 0.9, "producer supplied bounded build attribution"),
        (obj["canonical_identity"], compile_action, True, 1.0, None)])
    receipt_row = next(relation for relation in rows.relations if not relation.exact)
    assert receipt_row.payload == {"mapping": "fixture"}


def test_captured_invocation_parent_attributes_outputs_and_unproduced_artifacts_stay_ambiguous() -> None:
    receipt = validated_receipt(1)
    obj, executable = receipt["validated_artifacts"]
    receipt["relationships"] = []
    receipt["tool_invocations"] = [{
        "tool": "cc", "tool_kind": "compiler", "parent_command_id": "compile",
        "origin": "execution-capture:command-001:event-7", "argv_sha256": "c" * 64, "mapping_confidence": 1.0,
        "inputs": [], "outputs": [{"workspace_path": obj["workspace_path"], "sha256": obj["sha256"]}]}]
    context = _ReceiptContext.build(receipt, SNAPSHOT)
    assert _relations(context, obj, RelationKind.GENERATED_FROM) == [
        (obj["canonical_identity"], context.action_identity("compile").value, True, 1.0, None)]
    assert _artifact_relations(context, obj).gaps == []
    ambiguity = "receipt did not attribute the artifact to a unique producing action"
    assert _relations(context, executable, RelationKind.GENERATED_FROM) == sorted([
        (executable["canonical_identity"], context.action_identity(command).value, False, 0.25, ambiguity)
        for command in ("compile", "link")])
    assert _artifact_relations(context, executable).gaps == ["build/app: producing action mapping is ambiguous"]


def test_an_unknown_parent_falls_back_to_a_unique_argv_match_and_heuristic_mappings_stay_inexact() -> None:
    receipt = validated_receipt(1)
    receipt["relationships"] = []
    obj, executable = receipt["validated_artifacts"]
    receipt["tool_invocations"] = [
        {"tool": "cc", "tool_kind": "compiler", "parent_command_id": "unknown", "argv_sha256": "1" * 64,
         "mapping_confidence": 0.7, "inputs": [], "outputs": [{"workspace_path": obj["workspace_path"], "sha256": obj["sha256"]}]},
        {"tool": "ld", "tool_kind": "linker", "parent_command_id": "unknown", "argv_sha256": "9" * 64,
         "mapping_confidence": 1.0, "inputs": [],
         "outputs": [{"workspace_path": executable["workspace_path"], "sha256": executable["sha256"]}]}]
    context = _ReceiptContext.build(receipt, SNAPSHOT)
    assert _relations(context, obj, RelationKind.GENERATED_FROM) == [
        (obj["canonical_identity"], context.action_identity("compile").value, False, 0.7,
         "tool invocation output mapping was heuristic")]
    # no parent and no argv match: the executable fans out to every command
    assert len(_relations(context, executable, RelationKind.GENERATED_FROM)) == 2
    assert _artifact_relations(context, executable).gaps == ["build/app: producing action mapping is ambiguous"]


def test_a_receipt_without_commands_yields_no_relations_and_an_unavailable_gap() -> None:
    receipt = validated_receipt(1)
    receipt["commands"] = []
    context = _ReceiptContext.build(receipt, SNAPSHOT)
    rows = _artifact_relations(context, receipt["validated_artifacts"][0])
    assert rows.relations == [] and rows.gaps == ["build/obj/unit-00000.o: producing action receipt unavailable"]


def test_relationship_rows_naming_unknown_commands_are_ignored() -> None:
    receipt = validated_receipt(1)
    receipt["relationships"] = [{"artifact_sha256": receipt["validated_artifacts"][0]["sha256"], "command_id": "ghost",
                                 "confidence": 0.9}]
    receipt["tool_invocations"] = []
    context = _ReceiptContext.build(receipt, SNAPSHOT)
    rows = _artifact_relations(context, receipt["validated_artifacts"][0])
    assert all(relation.confidence == 0.25 for relation in rows.relations) and len(rows.relations) == 2


# --- link provenance (pure) -----------------------------------------------------------------------------

def _linked(observation_count: int, *, family: str = "native") -> tuple[dict, dict, dict, tuple[str, ...]]:
    receipt = validated_receipt(1)
    receipt["family"] = family
    receipt["relationships"] = []
    source, output = receipt["validated_artifacts"]
    base_tools = ("cc", "collect2", "rust-lld") if family == "rust" else ("cc", "collect2", "ld")
    tools = (*base_tools[:observation_count], *(f"ld-{index}" for index in range(3, observation_count)))
    receipt["tool_invocations"] = [{
        "tool": tool, "tool_kind": "linker-driver" if index == 0 else "linker",
        "origin": f"execution-capture:command-001:event-{index}", "mapping_confidence": 1.0,
        "outputs": [{"workspace_path": output["workspace_path"], "sha256": output["sha256"]}],
        "inputs": [{"workspace_path": source["workspace_path"], "sha256": source["sha256"], "mapping_confidence": 1.0}],
    } for index, tool in enumerate(tools)]
    return receipt, source, output, tools


@pytest.mark.parametrize("family, observation_count", sorted((("rust", 3), ("native", 3), ("native", 501))),
                         ids=["native-3", "native-501", "rust-3"])
def test_repeated_link_observations_produce_one_relation_with_bounded_provenance(family: str, observation_count: int) -> None:
    receipt, source, output, tools = _linked(observation_count, family=family)
    context = _ReceiptContext.build(receipt, SNAPSHOT)
    rows = _artifact_relations(context, output)
    links = [relation for relation in rows.relations if relation.kind is RelationKind.LINKS_INTO]
    (link,) = links
    assert (link.source_id, link.target_id, link.exact, link.confidence, link.ambiguity) == (
        source["canonical_identity"], output["canonical_identity"], True, 1.0, None)
    payload = link.payload
    assert payload["build_unit_id"] == UNIT and payload["observation_count"] == observation_count
    observations = payload["observations"]
    assert [item["tool"] for item in observations] == list(tools[:_MAX_LINK_OBSERVATIONS])
    assert [item["invocation_index"] for item in observations] == list(range(min(observation_count, 500)))
    assert observations[0] == {"invocation_index": 0, "input_index": 0, "origin": "execution-capture:command-001:event-0",
                               "tool": "cc", "confidence": 1.0}
    relation_gap = f"build/app: link provenance exceeds 500 observations for {link.relation_id}"
    assert (relation_gap in rows.gaps) == (observation_count > 500)
    assert "build/app: producing action mapping is ambiguous" in rows.gaps, "no invocation named a producing action"
    assert _MAX_LINK_OBSERVATIONS == 500


def test_link_inputs_resolve_by_hash_when_the_path_is_unknown_and_heuristic_links_stay_distinct() -> None:
    receipt, source, output, _ = _linked(1)
    receipt["tool_invocations"][0]["inputs"] = [{"workspace_path": "elsewhere/renamed.o", "sha256": source["sha256"],
                                                 "mapping_confidence": 0.6}]
    receipt["tool_invocations"].append({"tool": "ld", "tool_kind": "linker", "mapping_confidence": 1.0, "origin": "o",
                                        "outputs": [{"workspace_path": output["workspace_path"], "sha256": output["sha256"]}],
                                        "inputs": [{"workspace_path": "not/an/artifact.o", "sha256": "0" * 64},
                                                   {"workspace_path": source["workspace_path"], "mapping_confidence": 1.0}]})
    context = _ReceiptContext.build(receipt, SNAPSHOT)
    links = sorted((relation for relation in _artifact_relations(context, output).relations
                    if relation.kind is RelationKind.LINKS_INTO), key=lambda relation: relation.confidence)
    assert [(link.source_id, link.exact, link.confidence, link.ambiguity) for link in links] == [
        (source["canonical_identity"], False, 0.6, "link input mapping was heuristic"),
        (source["canonical_identity"], True, 1.0, None)]
    # an exact and a heuristic observation of the same edge are distinct relations, each with its own provenance
    assert [link.payload["observation_count"] for link in links] == [1, 1]
    assert links[0].payload["observations"] == [{"invocation_index": 0, "input_index": 0, "tool": "cc", "confidence": 0.6,
                                                 "origin": "execution-capture:command-001:event-0"}]
    assert links[1].payload["observations"][0]["input_index"] == 1, "the unknown input before it is skipped, not counted"


def test_non_linker_invocations_never_produce_link_relations() -> None:
    receipt, source, output, _ = _linked(1)
    receipt["tool_invocations"][0]["tool_kind"] = "compiler"
    context = _ReceiptContext.build(receipt, SNAPSHOT)
    assert [relation for relation in _artifact_relations(context, output).relations if relation.kind is RelationKind.LINKS_INTO] == []


# --- batching through the unit (from the pre-walk throughput suite) ------------------------------------

@pytest.mark.parametrize("count", [50, 500])
def test_one_build_unit_under_the_limits_is_one_shard(tmp_path: Path, count: int) -> None:
    receipt = validated_receipt(count)
    result = _relationships(_unit(tmp_path, receipt))
    assert [item["shard_id"] for item in result["indexes"]] == [f"relations-{UNIT}-0000"]
    producer = result["indexes"][0]["producer"]
    assert producer == {"job": "job_artifact_indexing", "unit": "index.relationships",
                        "family": "relationships", "build_unit_id": UNIT, "batch": 0, "batch_count": 1}
    assert len(_coverage_areas(tmp_path, result["indexes"][0])) == count + 1
    assert result["gaps"] == [] and result["terminal_status"] == "SUCCEEDED"


def test_artifact_limit_packs_sorted_artifacts_into_stable_batches(tmp_path: Path, monkeypatch) -> None:
    _limits(monkeypatch, artifacts=20)
    receipt = validated_receipt(50)
    result = _relationships(_unit(tmp_path, receipt))
    shard_ids = [item["shard_id"] for item in result["indexes"]]
    assert shard_ids == [f"relations-{UNIT}-{index:04d}" for index in range(3)]
    assert [(item["producer"]["batch"], item["producer"]["batch_count"]) for item in result["indexes"]] == [
        (0, 3), (1, 3), (2, 3)]
    areas = [_coverage_areas(tmp_path, item) for item in result["indexes"]]
    assert [len(batch) for batch in areas] == [20, 20, 11]
    expected = sorted(str(item["workspace_path"]) for item in receipt["validated_artifacts"])
    assert [area for batch in areas for area in batch] == expected


def test_a_single_artifact_over_the_row_limit_gets_its_own_shard(tmp_path: Path, monkeypatch) -> None:
    _limits(monkeypatch, rows=10)
    result = _relationships(_unit(tmp_path, validated_receipt(15)))
    areas = [_coverage_areas(tmp_path, item) for item in result["indexes"]]
    # build/app has 15 LINKS_INTO rows plus its producer; each object has two producer rows
    # (receipt attribution and tool invocation), so five objects fill a 10-row batch.
    assert areas[0] == ["build/app"]
    assert [len(batch) for batch in areas] == [1, 5, 5, 5]
    with sqlite3.connect(tmp_path / result["indexes"][0]["relative_path"]) as database:
        assert database.execute("SELECT count(*) FROM relations WHERE kind='LINKS_INTO'").fetchone()[0] == 15


def test_per_artifact_work_does_not_rescan_receipt_rows(tmp_path: Path, monkeypatch) -> None:
    passes = {}
    for label, count, artifacts in (("small", 50, None), ("large", 500, None), ("batched", 50, 20)):
        if artifacts is not None:
            _limits(monkeypatch, artifacts=artifacts)
        receipt = validated_receipt(count)
        _relationships(_unit(tmp_path / label, receipt))
        passes[label] = (receipt["tool_invocations"].passes, receipt["relationships"].passes)
    assert passes["small"] == passes["large"] == passes["batched"]
    assert max(passes["small"]) <= 3


def test_input_order_does_not_change_shard_identity_or_bytes(tmp_path: Path, monkeypatch) -> None:
    _limits(monkeypatch, artifacts=20)
    first = _relationships(_unit(tmp_path / "first", validated_receipt(50)))
    shuffled = validated_receipt(50)
    random.Random(3).shuffle(shuffled["validated_artifacts"])
    second = _relationships(_unit(tmp_path / "second", shuffled))
    assert [(item["shard_id"], item["fingerprint"], item["sha256"]) for item in first["indexes"]] == [
        (item["shard_id"], item["fingerprint"], item["sha256"]) for item in second["indexes"]]


def test_resume_reuses_completed_batches_and_rebuilds_only_missing_ones(tmp_path: Path, monkeypatch) -> None:
    _limits(monkeypatch, artifacts=20)
    receipt = validated_receipt(50)
    unit = _unit(tmp_path, receipt)
    first = _relationships(unit)
    missing = tmp_path / first["indexes"][1]["relative_path"]
    missing.unlink()
    built: list[str] = []
    original = IndexBuilder.build

    def tracked(self):
        built.append(self.shard_id)
        return original(self)

    monkeypatch.setattr(IndexBuilder, "build", tracked)
    second = _relationships(unit)
    assert built == [f"relations-{UNIT}-0001"]
    assert second["reused_count"] == second["shard_count"] - 1 == 2
    assert [item["sha256"] for item in second["indexes"]] == [item["sha256"] for item in first["indexes"]]


def test_written_relation_rows_and_gaps_match_the_pure_builder(tmp_path: Path) -> None:
    receipt, source, output, _ = _linked(3)
    result = _relationships(_unit(tmp_path, receipt))
    (index,) = result["indexes"]
    assert result["gaps"] == list(index["gaps"]) == ["build/app: producing action mapping is ambiguous",
                                                     "build/obj/unit-00000.o: producing action mapping is ambiguous"]
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    with sqlite3.connect(tmp_path / index["relative_path"]) as database:
        rows = database.execute("SELECT payload_json FROM relations WHERE kind='LINKS_INTO' AND target_id=?",
                                (output["canonical_identity"],)).fetchall()
        declared = json.loads(database.execute("SELECT value FROM metadata WHERE key='relation_kind_counts'").fetchone()[0])
        coverage = database.execute("SELECT area, status FROM coverage ORDER BY area").fetchall()
    assert len(rows) == declared["LINKS_INTO"] == 1 and declared["GENERATED_FROM"] == 4
    assert json.loads(rows[0][0])["observation_count"] == 3
    assert coverage == [("build/app", "partial"), ("build/obj/unit-00000.o", "partial")]


def test_receipts_without_artifacts_are_skipped_and_the_unit_is_not_applicable(tmp_path: Path) -> None:
    result = _relationships(unit_context(tmp_path, "index.relationships", {
        "load.accepted_builds": loaded_output([{**validated_receipt(0), "validated_artifacts": []}])}))
    assert result == {"indexes": [], "shard_count": 0, "reused_count": 0, "gaps": [], "terminal_status": "NOT_APPLICABLE"}
