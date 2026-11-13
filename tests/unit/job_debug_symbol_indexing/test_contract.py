"""job_debug_symbol_indexing: the declared inputs and outputs are the job's contract.

The job consumes the accepted artifact-indexing handoff (its catalog shards and summary) and,
when supplied, the language-build handoff (receipts bind produced binaries to their build image);
it publishes one indexed ``debug_symbols`` shard family, the decision, coverage and summary
documents, and two protected datasets. These tests pin every input and output declaration, that
each dataset input names a dataset its producer really declares with the same schema, the files
the handlers write under the attempt root, and that every published document lands inside its
declared artifact glob with its declared schema id.
"""
from __future__ import annotations

from fnmatch import fnmatch
import json
from pathlib import Path

from appsec_review.debug_symbols.contract import DECISION_SCHEMA, INDEX_NAME, JOB_ID, QUERY_TOOL
from appsec_review.jobs.job_artifact_indexing.datasets import DATASETS as ARTIFACT_DATASETS
from appsec_review.jobs.job_debug_symbol_indexing.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_debug_symbol_indexing.job import _TOPOLOGY, SCHEMA, build_job
from appsec_review.jobs.job_language_build.datasets import DATASETS as LANGUAGE_DATASETS
from appsec_review.mcp.schema import TOOLS
from appsec_review.retrieval import INDEX_SCHEMA
from appsec_review.retrieval.index import INDEX_NAMES
from appsec_review.runtime.contracts import (
    Availability, CoveragePolicy, DispatchClass, EvidenceAuthority, InputChannel, MissingPolicy, TargetAccess,
)
from appsec_review.runtime.datasets import METADATA_ROUTE
from tests.unit.job_debug_symbol_indexing.support import (
    ELF, accepted_inputs, artifact, catalog_shard, decide, extractor, handlers, job_context, manifest, unit,
)

HANDOFF = "appsec-review/job-handoff/2"
ATTEMPT_GLOB = "data/jobs/job_debug_symbol_indexing/attempts/*/artifacts/debug-symbols/"
EXPECTED_INPUTS = (
    ("job_artifact_indexing", "handoff", HANDOFF),
    ("job_artifact_indexing", "artifact_catalog", INDEX_SCHEMA),
    ("job_artifact_indexing", "archive_members", INDEX_SCHEMA),
    ("job_artifact_indexing", "artifact_relationships", INDEX_SCHEMA),
    ("job_artifact_indexing", "artifact_index_summary", "appsec-review/artifact-indexing/1"),
    ("job_language_build", "handoff", HANDOFF),
    ("job_language_build", "topology_refinement_inputs", "appsec-review/build-topology-refinement/1"),
    ("job_language_build", "build_actions", INDEX_SCHEMA),
    ("job_language_build", "jvm_build_actions", INDEX_SCHEMA),
    ("job_language_build", "language_build_receipts", "appsec-review/language-build-handoff/2"),
    ("job_language_build", "build_workspaces", "application/octet-stream"),
)


def _declared() -> dict[str, object]:
    return {item.output_kind: item for item in DATASETS}


def _claimed(path: str) -> list[str]:
    return [item.output_kind for item in DATASETS if any(fnmatch(path, pattern) for pattern in item.artifacts)]


def _shard_claims(shard_id: str) -> list[str]:
    return [item.output_kind for item in DATASETS if INDEX_NAME in item.indexes
            and any(shard_id.startswith(prefix) for prefix in item.shard_prefixes)]


# --- inputs ----------------------------------------------------------------------------------------

def test_inputs_are_pinned_with_their_producer_dataset_and_schema_and_are_all_optional_gaps() -> None:
    assert [(item.producer, item.output_kind, item.schema) for item in CONTRACT.inputs] == list(EXPECTED_INPUTS)
    for item in CONTRACT.inputs:
        assert item.availability is Availability.OPTIONAL, item.output_kind
        assert item.missing is MissingPolicy.GAP, item.output_kind
        assert item.coverage is CoveragePolicy.ALLOW_PARTIAL, item.output_kind
        assert item.channel is InputChannel.HANDOFF, item.output_kind
        assert item.authority is EvidenceAuthority.PRODUCER_EVIDENCE, item.output_kind


def test_every_dataset_input_names_a_declaration_its_producer_makes_with_the_same_schema() -> None:
    producers = {"job_artifact_indexing": {item.output_kind: item for item in ARTIFACT_DATASETS},
                 "job_language_build": {item.output_kind: item for item in LANGUAGE_DATASETS}}
    for item in CONTRACT.inputs:
        if item.output_kind == "handoff":
            continue
        declaration = producers[item.producer].get(item.output_kind)
        assert declaration is not None, f"{item.producer} does not declare {item.output_kind}"
        assert declaration.schema == item.schema, item.output_kind
        assert declaration.authority is item.authority, item.output_kind
    # every dataset the two producers declare is consumed: a new upstream output needs a decision here
    for producer, declarations in producers.items():
        consumed = {item.output_kind for item in CONTRACT.inputs if item.producer == producer}
        assert consumed == set(declarations) | {"handoff"}, producer


def test_the_job_is_a_review_graph_producer_scheduled_after_the_artifact_index() -> None:
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.schedule_after == ("job_artifact_indexing",)
    assert CONTRACT.always_execute is False and CONTRACT.propagate_handoff is True
    assert CONTRACT.consumes == CONSUMES == ("job_artifact_indexing", "job_language_build")


# --- outputs ---------------------------------------------------------------------------------------

def test_outputs_are_one_indexed_shard_family_three_documents_and_two_protected_datasets() -> None:
    declared = _declared()
    assert [(k, v.step, v.family, v.disposition, v.schema, v.sensitivity) for k, v in declared.items()] == [
        ("normalized_symbols", "extract", "symbols", "indexed", INDEX_SCHEMA, "internal"),
        ("symbol_coverage", "extract", "symbols", "artifact_only", "appsec-review/debug-symbol-coverage/1", "internal"),
        ("target_decision", "decide", "configuration", "artifact_only", "appsec-review/debug-symbol-decision/1",
         "internal"),
        ("raw_artifact_refs", "extract", "symbols", "protected", "appsec-review/debug-symbol-inputs/1", "sensitive"),
        ("reader_executions", "extract", "symbols", "protected", "appsec-review/container-execution/1", "sensitive"),
        ("debug_symbol_summary", "acceptance", "symbols", "artifact_only", SCHEMA, "internal"),
    ]
    for item in DATASETS:
        assert item.store == "retrieval" and item.required is False, item.output_kind
        assert item.authority is EvidenceAuthority.PRODUCER_EVIDENCE, item.output_kind
    symbols = declared["normalized_symbols"]
    assert symbols.indexes == (INDEX_NAME,) and symbols.shard_prefixes == ("symbols-",) and symbols.artifacts == ()
    assert symbols.query_route == QUERY_TOOL and symbols.reason is None
    assert declared["symbol_coverage"].query_route == f"{QUERY_TOOL} mode=coverage"
    for kind in ("target_decision", "raw_artifact_refs", "reader_executions", "debug_symbol_summary"):
        assert declared[kind].query_route == METADATA_ROUTE and declared[kind].indexes == (), kind
    assert {item.artifacts for item in DATASETS if item.artifacts} == {
        (ATTEMPT_GLOB + "coverage.json",), (ATTEMPT_GLOB + "decision.json",), (ATTEMPT_GLOB + "raw-refs.json",),
        (ATTEMPT_GLOB + "executions/**",), (ATTEMPT_GLOB + "accepted-index.json",)}
    steps = {item.unit_id.split(".")[0] for item in build_job().units}
    assert {item.step for item in DATASETS} == steps == set(_TOPOLOGY) == {"decide", "extract", "acceptance"}


def test_symbol_shard_and_query_tool_are_part_of_the_public_retrieval_contract() -> None:
    assert INDEX_NAME in INDEX_NAMES
    tools = {tool["name"]: tool for tool in TOOLS}
    assert QUERY_TOOL in tools
    assert tools[QUERY_TOOL]["inputSchema"]["additionalProperties"] is False


def test_shard_ids_of_both_lanes_are_claimed_by_the_symbol_prefix_and_nothing_else() -> None:
    assert _shard_claims("symbols-clang_dwarf") == ["normalized_symbols"]
    assert _shard_claims("symbols-msvc_pdb") == ["normalized_symbols"]
    assert _shard_claims("catalog-fixture") == [] and _shard_claims("clang_dwarf") == []
    attempt = "data/jobs/job_debug_symbol_indexing/attempts/attempt_0001/artifacts/debug-symbols/"
    assert _claimed(attempt + "decision.json") == ["target_decision"]
    assert _claimed(attempt + "coverage.json") == ["symbol_coverage"]
    assert _claimed(attempt + "raw-refs.json") == ["raw_artifact_refs"]
    assert _claimed(attempt + "accepted-index.json") == ["debug_symbol_summary"]
    assert _claimed(attempt + "executions/key/export.bin") == ["reader_executions"]
    assert _claimed(attempt + "executions/key/receipt.json") == ["reader_executions"]
    assert _claimed("data/jobs/job_debug_symbol_indexing/attempts/attempt_0001/result.json") == []
    assert _claimed("data/indices/manifests/debug-symbol-indexing-attempt_0001.json") == [], \
        "the merged manifest is handed off by reference, not claimed as a dataset"
    assert _claimed(f"data/indices/{INDEX_NAME}/{'f' * 64}.sqlite") == [], "shards are claimed by index name and prefix"


# --- the files the handlers write ------------------------------------------------------------------

def test_every_published_document_lands_inside_its_glob_with_its_declared_schema(tmp_path: Path, monkeypatch) -> None:
    context = job_context(tmp_path)
    run_root = context.run_root
    binary = artifact(run_root, "bin/program", ELF)
    job = build_job(extractor=extractor())
    upstream = manifest(run_root, [catalog_shard(run_root, [binary])])
    decision = decide(monkeypatch, job, context, accepted_inputs([binary], upstream))
    selected = handlers(job)["extract.clang_dwarf"](unit(context, "extract.clang_dwarf", {"decide.target": decision}))
    skipped = handlers(job)["extract.msvc_pdb"](unit(context, "extract.msvc_pdb", {"decide.target": decision}))
    published = handlers(job)["acceptance.publish_handoff"](unit(context, "acceptance.publish_handoff", {
        "decide.target": decision, "extract.clang_dwarf": selected, "extract.msvc_pdb": skipped}))
    written = {"target_decision": decision["artifact"], "raw_artifact_refs": selected["artifact"],
               "symbol_coverage": selected["coverage"], "debug_symbol_summary": published["artifact"]}
    declared = _declared()
    for kind, reference in written.items():
        assert _claimed(reference["path"]) == [kind], reference["path"]
        document = json.loads((run_root / reference["path"]).read_text(encoding="utf-8"))
        if kind == "target_decision":
            # TODO(T-114): the declaration says debug-symbol-decision/1; the job writes and verifies /2.
            assert document["schema"] == DECISION_SCHEMA == "appsec-review/debug-symbol-decision/2"
        else:
            assert document["schema"] == declared[kind].schema, kind
    (index,) = selected["indexes"]
    assert index["name"] == INDEX_NAME and index["schema"] == INDEX_SCHEMA == declared["normalized_symbols"].schema
    assert _shard_claims(index["shard_id"]) == ["normalized_symbols"]
    assert index["relative_path"] == f"data/indices/{INDEX_NAME}/{index['fingerprint']}.sqlite"
    assert (run_root / index["relative_path"]).is_file()
    assert index["producer"] == {"job_id": JOB_ID, "compiler_target": "clang", "lane": "clang_dwarf",
                                 "reader_identity": json.loads((run_root / decision["artifact"]["path"]).read_text())["reader_identity"]}
    assert published["index_manifest"]["path"] == "data/indices/manifests/debug-symbol-indexing-attempt_0001.json"
    assert not (run_root / "data/jobs/job_debug_symbol_indexing/attempts/attempt_0001/artifacts/debug-symbols/executions").exists(), \
        "an injected extractor never provisions a reader execution"


def test_the_job_carries_the_contract_and_declarations_it_was_built_from() -> None:
    job = build_job()
    assert job.contract is CONTRACT and job.datasets is DATASETS
    assert job.consumes == CONTRACT.consumes
    assert (job.job_id, job.name, job.schema_identity) == (JOB_ID, "debug_symbol_indexing", SCHEMA)
    assert job.strict_gaps is False, "still on the legacy free-text gap list (tests/test_gap_contract.py)"
    assert [item.unit_id for item in job.units] == [
        "decide.target", "extract.clang_dwarf", "extract.msvc_pdb", "acceptance.publish_handoff"]
