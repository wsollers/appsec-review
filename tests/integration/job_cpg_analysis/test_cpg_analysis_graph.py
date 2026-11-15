"""Graph-level integration tests for job_cpg_analysis."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.jobs.cpp_index_scopes import CheckpointIntegrityError, accepted_cpp_scopes
from appsec_review.jobs.job_cpg_analysis import JOERN_DISABLED, JOERN_GAP, build_job as build_cpg
from appsec_review.jobs.job_cpp_symbol_index import build_job as build_symbols
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.storage import file_sha256
from tests.test_cpp_index_jobs import (
    LIMIT,
    IndexExecutor,
    RLimitJoern,
    _accepted_cpp,
    _outputs,
    _rows,
    _run,
)

pytestmark = pytest.mark.integration


def test_cpg_job_retains_the_cpg_but_claims_no_coverage(tmp_path: Path) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path)
    run_root = config.runtime.runs_dir / run_id
    outcome = _run(
        config,
        target,
        run_id,
        fingerprint,
        build_cpg(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, [])),
    )
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    generated = _outputs(outcome, "job_cpg_analysis")["generate.scopes"]
    (scope,) = generated["scopes"]
    assert scope["observation_count"] == 0 and scope["gaps"] == [JOERN_GAP]
    assert (run_root / scope["cpg"]["path"]).read_bytes() == b"fixture-cpg"
    identity = scope["index_identity"]
    assert _rows(run_root, identity, "SELECT status, gap FROM coverage") == [("unavailable", JOERN_GAP)]
    ((payload,),) = _rows(run_root, identity, "SELECT payload_json FROM entities")
    assert json.loads(payload)["status"] == "BLOCKED" and json.loads(payload)["cpg"] == scope["cpg"]


def test_cpg_job_is_disabled_by_default_and_runs_no_joern(tmp_path: Path) -> None:
    assert "enabled = false\n# Joern is memory-heavy" in (
        Path(__file__).resolve().parents[3] / "appsec-review.toml"
    ).read_text(encoding="utf-8")
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path, joern=False)
    calls: list[str] = []
    outcome = _run(
        config,
        target,
        run_id,
        fingerprint,
        build_cpg(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, calls)),
    )
    generated = _outputs(outcome, "job_cpg_analysis")["generate.scopes"]
    assert calls == [] and generated["scopes"] == [] and generated["disabled"]
    assert generated["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert all(
        JOERN_DISABLED in gap for gap in generated["gaps"] if gap.split(": ", 1)[0] in generated["disabled"]
    )
    published = _outputs(outcome, "job_cpg_analysis")["acceptance.publish_handoff"]
    assert published["counts"]["cpgs_generated"] == 0 and published["counts"]["disabled_scopes"] == len(
        generated["disabled"]
    )


def test_failed_c2cpg_is_a_named_gap_without_a_cpg(tmp_path: Path) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path)
    outcome = _run(
        config,
        target,
        run_id,
        fingerprint,
        build_cpg(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, [], joern_exit=3)),
    )
    (scope,) = _outputs(outcome, "job_cpg_analysis")["generate.scopes"]["scopes"]
    assert scope["cpg"] is None and scope["gaps"] == ["Joern c2cpg exited with status 3", JOERN_GAP]


@pytest.mark.parametrize("order", ["cpg-first", "symbols-first"])
def test_jobs_are_independent_and_never_drop_each_others_shards(tmp_path: Path, order: str) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path)
    run_root = config.runtime.runs_dir / run_id
    jobs = [
        build_cpg(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, [])),
        build_symbols(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, [])),
    ]
    if order == "symbols-first":
        jobs.reverse()
    for job in jobs:
        _run(config, target, run_id, fingerprint, job)
    path, sha = resolve_accepted_manifest(run_root)
    document, _ = load_verified_manifest(run_root, path, sha)
    producers = {item["producer"]["job"] for item in document["indexes"]}
    assert {"job_cpp_compiled_analysis", "job_cpp_symbol_index", "job_cpg_analysis"} <= producers


def test_scope_loading_rejects_sources_changed_after_acceptance(tmp_path: Path) -> None:
    config, _target, run_id, _fingerprint = _accepted_cpp(tmp_path)
    run_root = config.runtime.runs_dir / run_id
    _accepted, (scope,), unavailable = accepted_cpp_scopes(run_root)
    assert unavailable == {} and scope.files
    (scope.case_root / scope.files[0]["scratch_path"]).write_text("int main() { return 1; }\n", encoding="utf-8")
    with pytest.raises(ValueError, match="materialized source changed after acceptance"):
        accepted_cpp_scopes(run_root)


def test_cpg_limit_stops_c2cpg_while_writing_and_discards_the_partial_cpg(tmp_path: Path) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path, max_cpg_bytes=LIMIT)
    run_root = config.runtime.runs_dir / run_id
    joern = RLimitJoern(run_root, [], attempt=64 * LIMIT)
    outcome = _run(config, target, run_id, fingerprint, build_cpg(executor_factory=lambda unit: joern))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    (scope,) = _outputs(outcome, "job_cpg_analysis")["generate.scopes"]["scopes"]
    assert joern.limits == [LIMIT + 1]
    assert scope["execution"]["file_size_limit_reached"] is False and scope["execution"]["exit_code"] == 1
    assert scope["resource_limit"] == {
        "mechanism": "RLIMIT_FSIZE",
        "max_cpg_bytes": LIMIT,
        "enforced_bytes": LIMIT + 1,
        "disposition": "LIMIT_REACHED",
        "observed_bytes": LIMIT + 1,
    }
    assert scope["cpg"] is None
    assert not list((run_root / "data" / "code-index" / "joern").rglob("cpg.bin"))
    assert scope["gaps"][0] == (
        f"Joern c2cpg reached the {LIMIT}-byte CPG limit while writing; the partial CPG was discarded"
    )
    coverage = _rows(run_root, scope["index_identity"], "SELECT status, gap FROM coverage")
    assert coverage[0][0] == "unavailable" and "CPG limit" in coverage[0][1]
    manifest = json.loads((run_root / scope["cpg_manifest"]["path"]).read_text(encoding="utf-8"))
    assert manifest["resource_limit"]["disposition"] == "LIMIT_REACHED" and manifest["cpg"] is None
    receipt = json.loads((run_root / scope["execution"]["receipt"]["path"]).read_text(encoding="utf-8"))
    assert receipt["limits"]["file_size_bytes"] == LIMIT + 1


@pytest.mark.parametrize("size", [LIMIT, LIMIT - 1])
def test_cpg_immediately_below_the_limit_is_retained_complete(tmp_path: Path, size: int) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path, max_cpg_bytes=LIMIT)
    run_root = config.runtime.runs_dir / run_id
    joern = RLimitJoern(run_root, [], attempt=size)
    outcome = _run(config, target, run_id, fingerprint, build_cpg(executor_factory=lambda unit: joern))
    (scope,) = _outputs(outcome, "job_cpg_analysis")["generate.scopes"]["scopes"]
    assert scope["resource_limit"]["disposition"] == "WITHIN_LIMIT"
    path = run_root / scope["cpg"]["path"]
    assert path.stat().st_size == size == scope["cpg"]["size_bytes"]
    assert file_sha256(path) == scope["cpg"]["sha256"] and path.read_bytes() == b"c" * size
    assert scope["gaps"] == [JOERN_GAP]


def _checkpointed(tmp_path: Path, max_cpg_bytes: int | None = None):
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path, max_cpg_bytes=max_cpg_bytes)
    run_root = config.runtime.runs_dir / run_id
    calls: list[str] = []
    job = lambda: build_cpg(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, calls))
    first = _run(config, target, run_id, fingerprint, job())
    (scope,) = _outputs(first, "job_cpg_analysis")["generate.scopes"]["scopes"]
    reused = _run(config, target, run_id, fingerprint, job(), force_from="job_cpg_analysis")
    (again,) = _outputs(reused, "job_cpg_analysis")["generate.scopes"]["scopes"]
    assert again["checkpoint_reused"] is True and calls == ["tool-joern"]
    return config, target, run_id, fingerprint, run_root, scope, job, calls


REFERENCED = {
    "cpg": lambda scope: scope["cpg"]["path"],
    "cpg-manifest": lambda scope: scope["cpg_manifest"]["path"],
    "execution-receipt": lambda scope: scope["execution"]["receipt"]["path"],
    "scope-compile-database": lambda scope: scope["execution"]["compile_database"]["path"],
    "index-shard": lambda scope: scope["index_identity"]["relative_path"],
}


@pytest.mark.parametrize("change", ["delete", "mutate"])
@pytest.mark.parametrize("name", sorted(REFERENCED))
def test_cpg_checkpoint_reuse_revalidates_every_referenced_artifact(
    tmp_path: Path, name: str, change: str
) -> None:
    config, target, run_id, fingerprint, run_root, scope, job, calls = _checkpointed(tmp_path)
    pointer = run_root / "data" / "jobs" / "job_cpg_analysis" / "latest.json"
    accepted = pointer.read_bytes()
    path = run_root / REFERENCED[name](scope)
    if change == "delete":
        path.unlink()
    else:
        path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(RuntimeError, match="generate.scopes"):
        _run(config, target, run_id, fingerprint, job(), force_from="job_cpg_analysis")
    (traceback,) = (run_root / "data" / "jobs" / "job_cpg_analysis").rglob(
        "generate/tasks/scopes/traceback.txt"
    )
    text = traceback.read_text(encoding="utf-8")
    assert "CheckpointIntegrityError" in text and scope["scope_id"] in text, text[-1500:]
    assert calls == ["tool-joern"]
    assert pointer.read_bytes() == accepted


def test_cpg_checkpoint_rejects_a_changed_accepted_compile_database(tmp_path: Path) -> None:
    from appsec_review.jobs.cpp_index_scopes import scope_checkpoint

    config, target, run_id, fingerprint, run_root, scope, job, calls = _checkpointed(tmp_path)
    checkpoint = run_root / "data" / "code-index" / "joern" / scope["scope_id"] / "checkpoint.json"
    document = json.loads(checkpoint.read_text(encoding="utf-8"))
    _accepted, (index_scope,), _ = accepted_cpp_scopes(run_root)
    assert scope_checkpoint(checkpoint, document["identity"], run_root, index_scope) is not None
    for mutate in (
        lambda result: result["accepted_compile_database"].update(sha256="0" * 64),
        lambda result: result.update(scope_id="cpp-scope-other"),
        lambda result: result["execution"].pop("receipt"),
    ):
        altered = json.loads(json.dumps(document))
        mutate(altered["result"])
        checkpoint.write_text(json.dumps(altered), encoding="utf-8")
        with pytest.raises(CheckpointIntegrityError):
            scope_checkpoint(
                checkpoint, document["identity"], run_root, index_scope, required=("execution.receipt",)
            )
    checkpoint.write_text("{not json", encoding="utf-8")
    with pytest.raises(CheckpointIntegrityError):
        scope_checkpoint(checkpoint, document["identity"], run_root, index_scope)
    checkpoint.write_text(json.dumps(document), encoding="utf-8")
    assert scope_checkpoint(checkpoint, "other-identity", run_root, index_scope) is None
    accepted = run_root / index_scope.compile_database["path"]
    accepted.write_bytes(accepted.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="accepted compile database changed"):
        accepted_cpp_scopes(run_root)


def test_cpg_checkpoint_identity_binds_the_configured_limit(tmp_path: Path) -> None:
    identities = []
    for name, limit in (("default", None), ("bounded", LIMIT)):
        (tmp_path / name).mkdir()
        _, _, _, _, run_root, scope, _, _ = _checkpointed(tmp_path / name, limit)
        checkpoint = run_root / "data" / "code-index" / "joern" / scope["scope_id"] / "checkpoint.json"
        identities.append((scope["scope_id"], json.loads(checkpoint.read_text(encoding="utf-8"))["identity"]))
    assert identities[0][0] == identities[1][0] and identities[0][1] != identities[1][1]
