"""job_language_build: the declared inputs and outputs are the job's contract.

Every file the job reads comes from an upstream handoff named in ``CONTRACT.inputs`` or from the
run-owned configuration; every file it writes is claimed by a ``DATASETS`` declaration. These
tests pin both, the files the handlers touch under the run root, and that the one document the
job hands downstream, its build index shard and its per-family workspaces land inside their own
declared artifact globs with the declared schema ids.
"""
from __future__ import annotations

from fnmatch import fnmatch
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_language_build.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_language_build.job import (
    EXECUTOR_IDENTITY, RECEIPT_SCHEMA, SCHEMA, _artifact, _safe_artifact, build_job,
)
from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, MissingPolicy, TargetAccess,
)

FAMILIES = ("native", "go", "dotnet", "node", "python", "rust", "php", "java", "wasm")


def _declared() -> dict[str, object]:
    return {item.output_kind: item for item in DATASETS}


# --- inputs ----------------------------------------------------------------------------------------

def test_inputs_name_every_upstream_job_and_the_project_build_handoff_is_the_one_hard_requirement() -> None:
    by_job: dict[str, set[str]] = {}
    for requirement in CONTRACT.inputs:
        by_job.setdefault(requirement.producer, set()).add(requirement.output_kind)
    assert by_job == {
        "job_build_environment_analysis": {"handoff", "build_environment"},
        "job_project_build": {"handoff", "topology_refinement_inputs", "project_build_dispatch",
                              "probe_workspaces", "image_build_streams"},
        "job_review_intake": {"handoff", "model_preflight", "binary_evidence", "review_intake"},
        "job_target_analysis_plan": {"handoff", "planning_feedback_cache", "analysis_plan",
                                     "analysis_plan_documents"},
        "job_target_catalog": {"handoff", "target_artifact_inputs", "source_files", "declaration_symbols",
                               "components", "target_documents", "build_units", "catalog_documents"},
    }
    required = [(item.producer, item.output_kind) for item in CONTRACT.inputs
                if item.availability is Availability.REQUIRED or item.missing is MissingPolicy.REJECT]
    assert required == [("job_project_build", "handoff")]
    handoffs = {item.producer: item.schema for item in CONTRACT.inputs if item.output_kind == "handoff"}
    assert set(handoffs.values()) == {"appsec-review/job-handoff/2"}
    assert CONTRACT.consumes == tuple(sorted(by_job)) == CONSUMES
    assert CONTRACT.schedule_after == ("job_project_build",)
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH and CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False and CONTRACT.propagate_handoff is True


def test_input_schemas_and_authority_are_pinned_per_dataset() -> None:
    schemas = {(item.producer, item.output_kind): item.schema for item in CONTRACT.inputs}
    assert schemas[("job_project_build", "project_build_dispatch")] == "appsec-review/project-build-dispatch/3"
    assert schemas[("job_project_build", "topology_refinement_inputs")] == "appsec-review/build-topology-refinement/1"
    assert schemas[("job_project_build", "probe_workspaces")] == "application/octet-stream"
    assert schemas[("job_project_build", "image_build_streams")] == "text/plain"
    assert schemas[("job_build_environment_analysis", "build_environment")] == "appsec-review/build-environment-analysis/1"
    assert schemas[("job_target_analysis_plan", "analysis_plan_documents")] == "appsec-review/target-analysis-plan/1"
    assert schemas[("job_target_catalog", "catalog_documents")] == "appsec-review/target-catalog/1"
    assert {schemas[("job_target_catalog", kind)] for kind in
            ("source_files", "declaration_symbols", "components", "target_documents", "build_units")} == {
        "appsec-review/retrieval-index/2"}
    authority = {item.producer: {item.authority for item in CONTRACT.inputs if item.producer == item_producer}
                 for item_producer in {item.producer for item in CONTRACT.inputs}
                 for item in CONTRACT.inputs if item.producer == item_producer}
    assert authority["job_build_environment_analysis"] == {EvidenceAuthority.OPERATIONAL}
    for producer in ("job_project_build", "job_review_intake", "job_target_analysis_plan", "job_target_catalog"):
        assert authority[producer] == {EvidenceAuthority.PRODUCER_EVIDENCE}, producer


# --- outputs ---------------------------------------------------------------------------------------

def test_outputs_are_declared_per_step_with_their_schema_and_disposition() -> None:
    declared = _declared()
    assert set(declared) == {"topology_refinement_inputs", "build_actions", "jvm_build_actions",
                             "language_build_receipts", "build_workspaces"}
    assert [(k, v.step, v.disposition, v.schema) for k, v in declared.items()] == [
        ("topology_refinement_inputs", "execute", "protected", "appsec-review/build-topology-refinement/1"),
        ("build_actions", "acceptance", "indexed", "appsec-review/retrieval-index/2"),
        ("jvm_build_actions", "execute", "indexed", "appsec-review/retrieval-index/2"),
        ("language_build_receipts", "acceptance", "artifact_only", SCHEMA),
        ("build_workspaces", "execute", "protected", "application/octet-stream"),
    ]
    assert declared["language_build_receipts"].sensitivity == "sensitive"
    assert declared["build_workspaces"].sensitivity == "sensitive"
    assert declared["topology_refinement_inputs"].sensitivity == "sensitive"
    assert declared["build_actions"].indexes == ("build",) and declared["build_actions"].shard_prefixes == ("language-build",)
    assert declared["jvm_build_actions"].indexes == ("build",) and declared["jvm_build_actions"].shard_prefixes == ("jvm-",)
    assert declared["build_actions"].query_route == (
        "find/trace index=build; query_precomputed query_set=build_provenance")
    steps = {unit.unit_id.split(".")[0] for unit in build_job().units}
    assert {item.step for item in DATASETS} <= steps
    assert all(item.family == "build" for item in DATASETS)
    assert all(item.artifacts or item.indexes for item in DATASETS), "every output claims files or an index"
    assert SCHEMA == "appsec-review/language-build-handoff/2"
    assert RECEIPT_SCHEMA == "appsec-review/language-build-receipt/1"
    assert EXECUTOR_IDENTITY.startswith("appsec-review/generic-language-build-executor/4+")


def test_build_workspaces_claim_one_tree_per_family_lane() -> None:
    patterns = _declared()["build_workspaces"].artifacts
    for family in (*FAMILIES, "jvm"):
        path = f"data/build/{family}/units/build-unit-{'a' * 20}/attempts/attempt_0001/workspace/src/main.c"
        assert any(fnmatch(path, pattern) for pattern in patterns), family
    assert not any(fnmatch("data/build/probes/units/x/attempts/attempt_0001/workspace/a.o", pattern)
                   for pattern in patterns), "probe workspaces belong to job_project_build"
    assert any(fnmatch("data/build/topology/refinements/abc.json", pattern)
               for pattern in _declared()["topology_refinement_inputs"].artifacts)


def test_the_published_receipt_set_lands_inside_its_declared_artifact_glob(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    attempt_root = run_root / "data" / "jobs" / "job_language_build" / "attempts" / "attempt_0001"
    unit = SimpleNamespace(job=SimpleNamespace(run_root=run_root, attempt_root=attempt_root))
    document = {"schema": SCHEMA, "receipts": [], "gaps": []}
    identity = _artifact(unit, "accepted-language-builds.json", document)
    assert identity["path"] == ("data/jobs/job_language_build/attempts/attempt_0001/artifacts/language-build/"
                                "accepted-language-builds.json")
    receipts = _declared()["language_build_receipts"]
    assert any(fnmatch(identity["path"], pattern) for pattern in receipts.artifacts), receipts.artifacts
    elsewhere = "data/jobs/job_project_build/attempts/attempt_0001/artifacts/language-build/x.json"
    assert not any(fnmatch(elsewhere, pattern) for pattern in receipts.artifacts)
    written = json.loads((run_root / identity["path"]).read_text(encoding="utf-8"))
    assert written["schema"] == receipts.schema == SCHEMA
    assert identity["sha256"] and identity["size_bytes"] == (run_root / identity["path"]).stat().st_size
    # the consumer-side reader resolves the same identity and refuses a changed document
    assert _safe_artifact(run_root, identity) == document
    (run_root / identity["path"]).write_text(json.dumps({**document, "gaps": ["x"]}), encoding="utf-8")
    with pytest.raises(ValueError, match="artifact identity changed"):
        _safe_artifact(run_root, identity)
    with pytest.raises(ValueError, match="artifact path is invalid"):
        _safe_artifact(run_root, {**identity, "path": "../outside.json"})


def test_the_build_index_shard_carries_the_declared_prefix() -> None:
    declared = _declared()["build_actions"]
    shard = "language-build-attempt_0001-" + "f" * 64 + ".sqlite"
    assert any(shard.startswith(prefix) for prefix in declared.shard_prefixes)
    assert not any(shard.startswith(prefix) for prefix in _declared()["jvm_build_actions"].shard_prefixes)


def test_the_job_carries_the_contract_and_declarations_it_was_built_from() -> None:
    job = build_job()
    assert job.contract is CONTRACT and job.datasets is DATASETS
    assert job.consumes == CONTRACT.consumes
    assert (job.job_id, job.name, job.schema_identity) == ("job_language_build", "language_build", SCHEMA)
