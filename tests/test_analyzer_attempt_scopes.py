"""A new analyzer attempt must execute its scopes without replacing earlier evidence."""
from copy import copy
from dataclasses import is_dataclass, replace

import pytest


def _next_attempt(unit, job_id):
    context = copy(unit.job)
    context.attempt_id = "attempt_0002"
    context.attempt_root = context.run_root / "data/jobs" / job_id / "attempts" / context.attempt_id
    step, task = unit.unit_id.split(".")
    root = context.attempt_root / "steps" / step / "tasks" / task
    root.mkdir(parents=True)
    if is_dataclass(unit):
        return replace(unit, job=context, unit_root=root)
    result = copy(unit)
    result.job, result.unit_root = context, root
    return result


@pytest.mark.parametrize("analyzer", ["clang", "clangd", "joern"])
def test_new_attempt_recomputes_unchanged_scope_and_preserves_original_bytes(tmp_path, analyzer):
    if analyzer == "clang":
        from appsec_review.jobs.job_clang_static_analysis import job as module
        from tests.unit.job_clang_static_analysis.support import FakeExecutor, _scope, _unit

        scope, unit = _scope(tmp_path), _unit(tmp_path)
        executor = FakeExecutor(unit.job.run_root)
        execute = module._analyze_scope
        scope_root = unit.job.run_root / "data/clang-static" / scope.scope_id
        calls_per_attempt = 2
    elif analyzer == "clangd":
        from appsec_review.jobs.job_cpp_symbol_index import job as module
        from tests.unit.job_cpp_symbol_index.test_handlers import (
            FakeClangdExecutor, _make_scope_and_unit, _symbol_document,
        )

        _, _, scope, unit = _make_scope_and_unit(tmp_path)
        executor = FakeClangdExecutor(unit.job.run_root, yaml_text=_symbol_document("1111111111111111"))
        execute = module._index_scope
        scope_root = unit.job.run_root / "data/code-index/clangd" / scope.scope_id
        calls_per_attempt = 1
    else:
        from appsec_review.jobs.job_cpg_analysis import job as module
        from tests.seeded_clang_support import CpgExecutor
        from tests.unit.job_cpg_analysis.test_handlers import _make_scope_and_unit

        _, scope, unit = _make_scope_and_unit(tmp_path)
        executor = CpgExecutor(unit.job.run_root)
        execute = module._generate
        scope_root = unit.job.run_root / "data/code-index/joern" / scope.scope_id
        calls_per_attempt = 1
    first = execute(unit, scope, lambda _: executor)
    assert len(executor.calls) == calls_per_attempt
    assert (scope_root / "attempts/attempt_0001/checkpoint.json").is_file()
    original = {path: path.read_bytes() for path in scope_root.rglob("*") if path.is_file()}
    index = unit.job.run_root / first["index_identity"]["relative_path"]
    original[index] = index.read_bytes()

    second_unit = _next_attempt(unit, module.JOB_ID)
    second = execute(second_unit, scope, lambda _: executor)
    assert len(executor.calls) == calls_per_attempt * 2
    assert not second.get("checkpoint_reused", False)
    assert (scope_root / "attempts/attempt_0002/checkpoint.json").is_file()
    assert {path: path.read_bytes() for path in original} == original
    assert second["index_identity"]["relative_path"] != first["index_identity"]["relative_path"]

    same_attempt = execute(second_unit, scope, lambda _: executor)
    assert same_attempt["checkpoint_reused"] is True
    assert len(executor.calls) == calls_per_attempt * 2


def test_whole_job_shard_and_derived_isolation_across_attempts(tmp_path):
    from types import SimpleNamespace
    from appsec_review.indexing.derive import Derived, fact, publish_derived
    from appsec_review.jobs.job_document_issue_analysis import datasets as doc_ds, job as doc_job
    from appsec_review.owasp_workbench.indexes import publish_shard
    from appsec_review.runtime.datasets import dataset_contract
    from appsec_review.storage import atomic_json
    from appsec_review.storage.shared import SharedArtifacts

    s1 = publish_shard(
        tmp_path, family="control-result", shard_id="comp-a",
        records=[{"id": "r1"}], fingerprint_inputs={"k": "v"}, attempt_id="attempt_0001",
    )
    s2 = publish_shard(
        tmp_path, family="control-result", shard_id="comp-a",
        records=[{"id": "r1"}], fingerprint_inputs={"k": "v"}, attempt_id="attempt_0002",
    )
    assert s1["path"] != s2["path"]
    assert "/attempt_0001/" in s1["path"]
    assert "/attempt_0002/" in s2["path"]

    calls = 0

    def _build():
        nonlocal calls
        calls += 1
        derived = Derived()
        derived.entities.append(
            fact("snap-1", "document_context", "1", {"k": "v"}, name="doc", text="doc",
                 result={"count": calls}, basis="unit", upstream=())
        )
        derived.coverage.append(("documents", "complete", None))
        return derived

    run_root = tmp_path / "run-doc"
    dc = dataset_contract(
        "job_document_issue_analysis",
        ("analysis",),
        doc_ds.DATASETS,
        job_contract=doc_ds.CONTRACT.document(),
    )
    for idx_num, attempt_id in enumerate(("attempt_0001", "attempt_0002"), start=1):
        attempt_rel = f"data/jobs/job_document_issue_analysis/attempts/{attempt_id}"
        attempt_root = run_root / attempt_rel
        atomic_json(
            attempt_root / "claim.json",
            {
                "run_id": run_root.name,
                "job_id": "job_document_issue_analysis",
                "attempt_id": attempt_id,
                "attempt_path": attempt_rel,
                "orchestration": {"system": "direct"},
                "recovery_boundary": "whole_job",
                "dataset_contract": dc,
            },
        )
        ctx = SimpleNamespace(
            run_id=run_root.name,
            run_root=run_root,
            attempt_root=attempt_root,
            attempt_id=attempt_id,
            orchestration={"system": "direct"},
            config=SimpleNamespace(job_id="job_document_issue_analysis"),
            component_identities={"implementation": "impl/1", "schema": "schema/1", "validation": "val/1"},
        )
        out = publish_derived(
            run_root, index="precomputed", shard_id="document-issues",
            job_id="job_document_issue_analysis", unit_id="analysis.publish",
            rule="doc_nav", rule_version="1", snapshot="snap-1",
            inputs={"seed": "same"}, build=_build, shared=SharedArtifacts.for_job(ctx),
        )
        assert out["reused"] is False
        assert calls == idx_num
