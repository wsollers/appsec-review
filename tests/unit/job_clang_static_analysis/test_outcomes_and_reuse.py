"""Clang per-file coverage and evidence-bound scope reuse."""
from dataclasses import replace
import json
import sqlite3

import pytest

from appsec_review import seeding
from appsec_review.jobs.cpp_index_scopes import CheckpointIntegrityError
from appsec_review.jobs.job_clang_static_analysis import job, seeded
from appsec_review.storage import canonical_json
from tests import seeded_clang_support as sc
from .test_seeded_clang_static import _run, _unit


def _coverage(staged, result):
    with sqlite3.connect(staged.run_root / result["index_identity"]["relative_path"]) as db:
        return db.execute("select status from coverage").fetchone()[0]


@pytest.mark.parametrize("kind", ["missing", "omitted", "duplicate", "malformed"])
def test_missing_or_invalid_unit_evidence_is_incomplete_and_never_checkpointed(tmp_path, kind):
    staged = sc.stage(tmp_path)

    class Executor(sc.StaticExecutor):
        def execute(self, request):
            result = super().execute(request)
            path = request.scratch_root / f"{request.argv[1]}.json"
            document = json.loads(path.read_text())
            if kind == "missing":
                del document["units"]
            elif kind == "omitted":
                document["units"] = document["units"][:1]
            elif kind == "duplicate":
                document["units"] = [document["units"][0]] * 2
            else:
                document["units"][0]["exit_code"] = False
            path.write_text(json.dumps(document))
            return result

    result, _ = _run(staged, Executor(staged.run_root))
    assert result["observation_count"] > 0
    counts = result["seeded"]["status_counts"]
    assert counts.get("unresolved", 0) >= 1
    assert any("outcome" in gap for gap in result["gaps"])
    assert not (staged.run_root / "data/clang-static/cpp-scope-seeded/checkpoint.json").exists()
    if kind == "missing":
        assert counts == {"unresolved": 2} and _coverage(staged, result) == "unavailable"
    if kind in {"omitted", "malformed"}:
        assert counts == {"resolved": 1, "unresolved": 1}


def test_all_failed_units_are_unavailable_not_partial(tmp_path):
    staged = sc.stage(tmp_path)
    failures = tuple((engine, stem) for engine in ("tidy", "analyze") for stem in ("net", "util"))
    result, _ = _run(staged, sc.StaticExecutor(staged.run_root, fail=failures))
    assert result["observation_count"] == 0
    assert _coverage(staged, result) == "unavailable"
    assert result["seeded"]["status_counts"] == {"unresolved": 2}


def test_one_failed_unit_preserves_positive_evidence_and_unaffected_seed(tmp_path):
    staged = sc.stage(tmp_path)
    result, _ = _run(staged, sc.StaticExecutor(staged.run_root, fail=(("tidy", "net"),)))
    assert result["observation_count"] > 0 and _coverage(staged, result) == "partial"
    assert result["seeded"]["status_counts"] == {"resolved": 1, "unresolved": 1}


def test_retry_of_missing_outcomes_preserves_original_evidence_bytes(tmp_path):
    staged = sc.stage(tmp_path)
    first, _ = _run(staged, sc.StaticExecutor(staged.run_root, report_units=False))
    paths = [staged.run_root / item["path"] for item in first["evidence_artifacts"]]
    original = {path: path.read_bytes() for path in paths}
    second, _ = _run(staged, sc.StaticExecutor(staged.run_root))
    assert second["seeded"]["status_counts"] == {"resolved": 2}
    assert second["ledger"]["path"] != first["ledger"]["path"]
    assert all(path.read_bytes() == value for path, value in original.items())


@pytest.mark.parametrize("change", ["population", "provenance"])
def test_seed_metadata_changes_invalidate_clang_scope_reuse(tmp_path, change):
    staged = sc.stage(tmp_path)
    scope, unit = sc.index_scope(staged), _unit(staged)
    settings = seeded.settings_of(unit)
    plan = seeded.plan_for(unit, [scope], settings)
    original = plan.for_scope(sc.CASE)
    run = seeded.Run(settings, plan, original, seeded.Neighborhood())
    executor = sc.StaticExecutor(staged.run_root)
    first = job._analyze_scope(unit, scope, lambda _u: executor, run)
    original_ledger = (staged.run_root / first["ledger"]["path"]).read_bytes()
    if change == "population":
        revised = replace(original, total=original.total + 5, dropped=5)
        new_plan = replace(plan, scopes={sc.CASE: revised}, not_in_database=3, unlocated=2)
    else:
        seed = original.seeds[0]
        revised = replace(original, seeds=(
            replace(seed, sources=(replace(seed.sources[0], observation_id="different-evidence"),)),
            *original.seeds[1:]))
        new_plan = replace(plan, scopes={sc.CASE: revised})
    second = job._analyze_scope(unit, scope, lambda _u: executor,
                                seeded.Run(settings, new_plan, revised, run.hood))
    assert not second.get("checkpoint_reused") and len(executor.calls) == 4
    assert second["index_identity"]["sha256"] != first["index_identity"]["sha256"]
    assert (staged.run_root / first["ledger"]["path"]).read_bytes() == original_ledger
    if change == "population":
        assert second["seeded"]["status_counts"]["over_limit"] == 5
        assert any("seed_unlocated: 2" in gap for gap in second["gaps"])


def test_reordering_identical_seed_evidence_keeps_reuse(tmp_path):
    staged = sc.stage(tmp_path)
    scope, unit = sc.index_scope(staged), _unit(staged)
    settings = seeded.settings_of(unit)
    plan = seeded.plan_for(unit, [scope], settings)
    original = plan.for_scope(sc.CASE)
    run = seeded.Run(settings, plan, original, seeded.Neighborhood())
    executor = sc.StaticExecutor(staged.run_root)
    first = job._analyze_scope(unit, scope, lambda _u: executor, run)
    reordered = replace(original, seeds=tuple(reversed(original.seeds)))
    result = job._analyze_scope(unit, scope, lambda _u: executor, replace(run, scope_seeds=reordered))
    assert result["checkpoint_reused"]
    assert canonical_json(result["index_identity"]) == canonical_json(first["index_identity"])
    assert len(executor.calls) == 2


@pytest.mark.parametrize("damage", ["native", "wrapper", "stdout"])
def test_matching_checkpoint_refuses_missing_native_or_raw_evidence(tmp_path, damage):
    from appsec_review.storage import atomic_json
    from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner, reference
    from appsec_review.jobs.job_clang_static_analysis.datasets import DATASETS
    from appsec_review.runtime.datasets import dataset_contract
    from .support import _scope, _unit as basic_unit, FakeExecutor

    scope, unit = _scope(tmp_path), basic_unit(tmp_path)
    run_root = unit.job.run_root
    attempt = run_root / "data/jobs" / job.JOB_ID / "attempts/attempt_0001"
    actor = {"run_id": run_root.name, "job_id": job.JOB_ID, "attempt_id": "attempt_0001",
             "orchestration": {"system": "fixture"}}
    atomic_json(attempt / "claim.json", {
        **actor, "attempt_path": attempt.relative_to(run_root).as_posix(),
        "dataset_contract": dataset_contract(job.JOB_ID, ("load", "analyze", "acceptance"), DATASETS)})
    owner = SharedArtifacts(run_root, attempt, {**actor, "claim": reference(run_root, attempt / "claim.json")})
    executor = FakeExecutor(run_root)
    with publication_scope_for_owner(owner):
        result = job._analyze_scope(unit, scope, lambda _u: executor)
        assert job._analyze_scope(unit, scope, lambda _u: executor)["checkpoint_reused"]
        if damage == "native":
            with sqlite3.connect(run_root / result["index_identity"]["relative_path"]) as db:
                payload = json.loads(db.execute("select payload_json from entities where kind='tool_observation'").fetchone()[0])
            path = run_root / payload["common"]["evidence_refs"][0]["artifact"]["path"]
        else:
            scratch = (run_root / result["executions"]["clang-tidy"]["compile_database"]["path"]).parent
            path = scratch / ("tidy.json" if damage == "wrapper" else "raw/stdout.bin")
        path.unlink()
        with pytest.raises(CheckpointIntegrityError):
            job._analyze_scope(unit, scope, lambda _u: executor)
    assert len(executor.calls) == 2


def test_unsupported_only_scope_survives_summary_without_unavailable_coverage(monkeypatch, tmp_path):
    from .support import _scope
    staged = sc.stage(tmp_path / "staged")
    scope = _scope(tmp_path / "unsupported")
    scope = replace(scope, compile_commands=({"target_path": "native/boot.S", "arguments": ["cc", "boot.S"]},))
    unit = staged.unit("load.accepted_cpp", {}, job_id=job.JOB_ID)
    unit.job.config.settings.update(sc.STATIC_SETTINGS)
    accepted = {"handoff": {"source_fingerprint": sc.SNAPSHOT},
                "handoff_sha256": "a" * 64, "manifest": {
                    "path": staged.manifest_path.relative_to(staged.run_root).as_posix(),
                    "sha256": staged.manifest_sha}}
    monkeypatch.setattr(job, "accepted_cpp_scopes", lambda _root: (accepted, [scope], {}))
    handlers = {item.unit_id: item.handler for item in job.build_job(
        executor_factory=lambda _u: pytest.fail("unsupported scope launched")).units}
    outputs = {"load.accepted_cpp": handlers["load.accepted_cpp"](unit)}
    unit.output = lambda key: outputs[key]
    outputs["analyze.scopes"] = handlers["analyze.scopes"](unit)
    result = handlers["acceptance.publish_handoff"](unit)
    summary = json.loads((staged.run_root / result["artifact"]["path"]).read_text())
    assert summary["counts"]["not_applicable_scopes"] == 1
    assert summary["not_applicable_scopes"][0]["scope_id"] == scope.scope_id
    assert summary["not_applicable_scopes"][0]["terminal_status"] == "SKIPPED_NA"
    assert result["terminal_status"] == "NOT_APPLICABLE"
    manifest = json.loads((staged.run_root / result["index_manifest"]["path"]).read_text())
    clang = [index for index in manifest["indexes"] if index["producer"].get("job") == job.JOB_ID]
    assert any(index["producer"].get("terminal_status") == "SKIPPED_NA" for index in clang)
    for index in clang:
        with sqlite3.connect(staged.run_root / index["relative_path"]) as db:
            assert db.execute("select * from coverage").fetchall() == []
