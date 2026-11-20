from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from types import MappingProxyType, SimpleNamespace

from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.cpp_index_scopes import IndexScope
from appsec_review.jobs.engineering_contracts import CLANG_STATIC_HANDOFF_SCHEMA
from appsec_review.jobs.job_clang_static_analysis import JOB_ID, TOOL_ID, build_job
from appsec_review.jobs.job_clang_static_analysis.job import (
    ENGINES, OUTPUT_SCHEMA, _analyze_scope, _read_output,
)
from appsec_review.runtime import UnitContext
from appsec_review.storage import file_sha256


from .support import DIGEST, SETTINGS, FakeExecutor, _scope, _unit


def test_positive_scope_runs_both_engines_and_publishes_observations(tmp_path: Path) -> None:
    scope, unit = _scope(tmp_path), _unit(tmp_path)
    executor = FakeExecutor(unit.job.run_root)
    result = _analyze_scope(unit, scope, lambda _unit: executor)
    assert executor.calls == list(ENGINES)
    assert result["terminal_status"] == "SUCCEEDED"
    assert result["observation_count"] == 2
    assert result["gaps"] == []
    shard = unit.job.run_root / result["index_identity"]["relative_path"]
    assert shard.is_file() and file_sha256(shard) == result["index_identity"]["sha256"]
    with sqlite3.connect(shard) as database:
        entities = {row[0] for row in database.execute("SELECT identity FROM entities")}
        relations = database.execute("SELECT source_id, target_id FROM relations").fetchall()
    assert relations
    assert all(source in entities and target in entities for source, target in relations)


def test_adapter_version_invalidates_a_pre_fix_scope_checkpoint(
        monkeypatch, tmp_path: Path) -> None:
    import appsec_review.jobs.job_clang_static_analysis.job as module

    current_adapter = module.ADAPTER
    scope, unit = _scope(tmp_path), _unit(tmp_path)
    executor = FakeExecutor(unit.job.run_root)

    monkeypatch.setattr(module, "ADAPTER", "clang-static-adapter/8")
    first = module._analyze_scope(unit, scope, lambda _unit: executor)
    assert first.get("checkpoint_reused", False) is False

    monkeypatch.setattr(module, "ADAPTER", current_adapter)
    second = module._analyze_scope(unit, scope, lambda _unit: executor)

    assert second.get("checkpoint_reused", False) is False
    assert executor.calls == list(ENGINES) * 2


def test_no_applicable_target_is_not_clean_coverage(monkeypatch, tmp_path: Path) -> None:
    import appsec_review.jobs.job_clang_static_analysis.job as module
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda _root: ({}, [], {}))
    job = build_job(executor_factory=lambda _unit: None)
    handler = next(unit.handler for unit in job.units if unit.unit_id == "analyze.scopes")
    context = _unit(tmp_path)
    context = UnitContext(context.job, context.unit_id, context.step_id, context.task_id,
                          context.unit_root, MappingProxyType({"load.accepted_cpp": {"scopes": []}}))
    result = handler(context)
    assert result["terminal_status"] == "NOT_APPLICABLE"
    assert result["scope_count"] == 0


def test_missing_compile_context_is_an_explicit_gap(monkeypatch, tmp_path: Path) -> None:
    import appsec_review.jobs.job_clang_static_analysis.job as module
    monkeypatch.setattr(module, "accepted_cpp_scopes",
                        lambda _root: ({}, [], {"case-a": "accepted C++ project has no compile commands"}))
    job = build_job(executor_factory=lambda _unit: None)
    handler = next(unit.handler for unit in job.units if unit.unit_id == "analyze.scopes")
    context = _unit(tmp_path)
    context = UnitContext(context.job, context.unit_id, context.step_id, context.task_id,
                          context.unit_root, MappingProxyType({"load.accepted_cpp": {"scopes": []}}))
    result = handler(context)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["gaps"] == ["case-a: accepted C++ project has no compile commands"]


def test_one_analyzer_failure_is_a_scope_gap_without_erasing_other_results(tmp_path: Path) -> None:
    scope, unit = _scope(tmp_path), _unit(tmp_path)
    executor = FakeExecutor(unit.job.run_root, fail="clang-static-analyzer")
    result = _analyze_scope(unit, scope, lambda _unit: executor)
    assert result["observation_count"] == 1
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert "clang-static-analyzer exited with status 7" in result["gaps"]


def test_malformed_and_unbounded_outputs_are_gaps(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    records, gaps = _read_output(malformed, engine="clang-tidy", max_bytes=1024,
                                 max_diagnostics=20)
    assert records == [] and gaps == ["clang-tidy result was malformed JSON"]

    unbounded = tmp_path / "unbounded.json"
    unbounded.write_text(json.dumps({"schema": OUTPUT_SCHEMA, "engine": "clang-tidy",
                                     "truncated": False, "diagnostics": [{}] * 21}), encoding="utf-8")
    records, gaps = _read_output(unbounded, engine="clang-tidy", max_bytes=65536,
                                 max_diagnostics=20)
    assert records == [] and "exceeded the 20-diagnostic bound" in gaps[0]


def test_handoff_schema_and_summary_artifact_are_immutable(monkeypatch, tmp_path: Path) -> None:
    import appsec_review.jobs.job_clang_static_analysis.job as module
    manifest = tmp_path / "run" / "manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text("{}", encoding="utf-8")
    identity = {"path": "manifest.json", "sha256": file_sha256(manifest),
                "size_bytes": manifest.stat().st_size}
    monkeypatch.setattr(module, "publish_scope_indexes", lambda *_args, **_kwargs: identity)
    job = build_job(executor_factory=lambda _unit: None)
    handler = next(unit.handler for unit in job.units if unit.unit_id == "acceptance.publish_handoff")
    context = _unit(tmp_path)
    outputs = {
        "load.accepted_cpp": {"upstream": {"handoff_sha256": "a" * 64}, "unavailable": {}},
        "analyze.scopes": {"scopes": [], "gaps": [], "terminal_status": "NOT_APPLICABLE"},
    }
    context = UnitContext(context.job, "acceptance.publish_handoff", "acceptance", "publish_handoff",
                          context.unit_root, MappingProxyType(outputs))
    result = handler(context)
    assert job.schema_identity == CLANG_STATIC_HANDOFF_SCHEMA
    assert result["schema"] == CLANG_STATIC_HANDOFF_SCHEMA
    summary = context.job.run_root / result["artifact"]["path"]
    assert file_sha256(summary) == result["artifact"]["sha256"]
    assert json.loads(summary.read_text(encoding="utf-8"))["schema"] == CLANG_STATIC_HANDOFF_SCHEMA


def test_analyzer_checkers_must_be_names_not_patterns() -> None:
    import pytest

    from appsec_review.jobs.job_clang_static_analysis.job import _validated_settings

    good = _validated_settings({**SETTINGS, "clang_analyzer_checkers": ["core", "alpha.security", "unix.Malloc"]})
    assert good["clang_analyzer_checkers"] == ("core", "alpha.security", "unix.Malloc")
    with pytest.raises(ValueError, match=r"not patterns: alpha\.security\.\*"):
        _validated_settings({**SETTINGS, "clang_analyzer_checkers": ["core", "alpha.security.*"]})


def test_read_output_and_read_units_reject_all_contract_violations(tmp_path: Path) -> None:
    from appsec_review.jobs.job_clang_static_analysis.job import _read_units

    missing = tmp_path / "missing.json"
    assert _read_output(missing, engine="clang-tidy", max_bytes=1024, max_diagnostics=5) == (
        [], ["clang-tidy produced no result document"]
    )
    assert _read_units(missing, max_bytes=1024) is None

    oversize = tmp_path / "oversize.json"
    oversize.write_text("x" * 200, encoding="utf-8")
    assert _read_output(oversize, engine="clang-tidy", max_bytes=50, max_diagnostics=5) == (
        [], ["clang-tidy result exceeded the 50-byte output bound"]
    )
    assert _read_units(oversize, max_bytes=50) is None

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{broken", encoding="utf-8")
    assert _read_units(bad_json, max_bytes=1024) is None

    bad_env = tmp_path / "bad_env.json"
    bad_env.write_text(json.dumps({"schema": "wrong", "engine": "clang-tidy", "diagnostics": []}), encoding="utf-8")
    assert _read_output(bad_env, engine="clang-tidy", max_bytes=1024, max_diagnostics=5) == (
        [], ["clang-tidy result envelope was malformed"]
    )

    bad_diag_list = tmp_path / "bad_list.json"
    bad_diag_list.write_text(
        json.dumps({"schema": OUTPUT_SCHEMA, "engine": "clang-tidy", "diagnostics": "nope"}),
        encoding="utf-8",
    )
    assert _read_output(bad_diag_list, engine="clang-tidy", max_bytes=1024, max_diagnostics=5) == (
        [], ["clang-tidy diagnostics were malformed"]
    )

    valid_diag = {
        "rule_id": "bugprone-branch-clone",
        "message": "identical branches",
        "path": "/target/source/main.cpp",
        "line": 1,
        "column": 5,
    }
    truncated = tmp_path / "truncated.json"
    truncated.write_text(
        json.dumps({"schema": OUTPUT_SCHEMA, "engine": "clang-tidy", "truncated": True, "diagnostics": [valid_diag]}),
        encoding="utf-8",
    )
    recs, gaps = _read_output(truncated, engine="clang-tidy", max_bytes=4096, max_diagnostics=5)
    assert len(recs) == 1 and gaps == ["clang-tidy output was truncated by its bounded wrapper"]

    for name, bad_item, expected in (
        ("non_mapping", "bad", "clang-tidy diagnostic 0 was malformed"),
        ("bool_line", {**valid_diag, "line": True}, "clang-tidy diagnostic 0 was malformed"),
        ("zero_line", {**valid_diag, "line": 0}, "clang-tidy diagnostic 0 exceeded field bounds"),
        ("bad_trace", {**valid_diag, "notes": "not-a-list"}, "clang-tidy diagnostic 0 had an unbounded trace"),
    ):
        doc = tmp_path / f"{name}.json"
        doc.write_text(
            json.dumps({"schema": OUTPUT_SCHEMA, "engine": "clang-tidy", "diagnostics": [bad_item]}),
            encoding="utf-8",
        )
        assert _read_output(doc, engine="clang-tidy", max_bytes=4096, max_diagnostics=5) == ([], [expected])


def test_analyze_scope_execution_bounds_exception_and_unmapped_paths(monkeypatch, tmp_path: Path) -> None:
    import appsec_review.jobs.job_clang_static_analysis.job as module

    # 1. Executor exception -> tool/image unavailable gap
    scope_exc, unit_exc = _scope(tmp_path / "exc"), _unit(tmp_path / "exc")

    class RaisingExecutor:
        def execute(self, _request):
            raise RuntimeError("docker unavailable")

    res_exc = _analyze_scope(unit_exc, scope_exc, lambda _u: RaisingExecutor())
    assert res_exc["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("tool/image unavailable: RuntimeError: docker unavailable" in g for g in res_exc["gaps"])

    # 2. Timeout, OOM, truncation, missing output file, and unmapped diagnostic path
    def make_exec_result(run_root: Path, scratch: Path, *, timed_out=False, oom_killed=False,
                         limit_reached=False, write_output: dict | None = None):
        raw = scratch / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        (raw / "stdout.bin").write_bytes(b"")
        (raw / "stderr.bin").write_bytes(b"")
        receipt = scratch / "execution.json"
        receipt.write_text("{}", encoding="utf-8")
        if write_output is not None:
            action = "tidy" if scratch.name == "tidy" else "analyze"
            (scratch / f"{action}.json").write_text(json.dumps(write_output), encoding="utf-8")
        rel = lambda p: p.relative_to(run_root).as_posix()
        return ExecutionResult(
            "appsec-review/container-execution/1", TOOL_ID,
            "appsec-review/tool-clang-static-analysis:1.0.0", DIGEST, DIGEST, "argv", (), {},
            "start", "end", 0, timed_out, oom_killed, False, False,
            rel(raw / "stdout.bin"), rel(raw / "stderr.bin"), rel(receipt),
            65537, limit_reached,
        )

    # Timeout on tidy, OOM on analyzer
    scope_to, unit_to = _scope(tmp_path / "to"), _unit(tmp_path / "to")

    class TimeoutOomExecutor:
        def execute(self, request):
            if request.argv[1] == "tidy":
                return make_exec_result(unit_to.job.run_root, request.scratch_root, timed_out=True)
            return make_exec_result(unit_to.job.run_root, request.scratch_root, oom_killed=True)

    res_to = _analyze_scope(unit_to, scope_to, lambda _u: TimeoutOomExecutor())
    assert "clang-tidy timed out" in res_to["gaps"]
    assert "clang-static-analyzer was OOM-killed" in res_to["gaps"]

    # File-size limit on tidy, missing output file on analyzer
    scope_lim, unit_lim = _scope(tmp_path / "lim"), _unit(tmp_path / "lim")

    class LimitMissingExecutor:
        def execute(self, request):
            if request.argv[1] == "tidy":
                return make_exec_result(unit_lim.job.run_root, request.scratch_root, limit_reached=True)
            return make_exec_result(unit_lim.job.run_root, request.scratch_root, write_output=None)

    res_lim = _analyze_scope(unit_lim, scope_lim, lambda _u: LimitMissingExecutor())
    assert "clang-tidy output was truncated or exceeded its execution bound" in res_lim["gaps"]
    assert "clang-static-analyzer produced no result document" in res_lim["gaps"]

    # Unmapped diagnostic path + multiple diagnostics in same accepted file
    scope_unm, unit_unm = _scope(tmp_path / "unm"), _unit(tmp_path / "unm")

    class UnmappedAndDuplicateFileExecutor:
        def execute(self, request):
            engine = "clang-tidy" if request.argv[1] == "tidy" else "clang-static-analyzer"
            return make_exec_result(
                unit_unm.job.run_root,
                request.scratch_root,
                write_output={
                    "schema": OUTPUT_SCHEMA,
                    "engine": engine,
                    "truncated": False,
                    "diagnostics": [
                        {
                            "rule_id": "core.NullDereference",
                            "message": "d1",
                            "path": "/target/source/main.cpp",
                            "line": 1,
                            "column": 10,
                        },
                        {
                            "rule_id": "core.DivideZero",
                            "message": "d2",
                            "path": "/target/source/untracked.cpp",
                            "line": 1,
                            "column": 5,
                        },
                    ],
                },
            )

    res_unm = _analyze_scope(unit_unm, scope_unm, lambda _u: UnmappedAndDuplicateFileExecutor())
    assert res_unm["observation_count"] == 2
    assert any("diagnostic path did not resolve to accepted source: /target/source/untracked.cpp" in g
               for g in res_unm["gaps"])
    assert module._source_of("relative/only.cpp") == "relative/only.cpp"


def test_build_job_load_and_analyze_units_unseeded_and_seeded(monkeypatch, tmp_path: Path) -> None:
    import pytest
    import appsec_review.jobs.job_clang_static_analysis.job as module
    from tests import seeded_clang_support as sc

    scope = _scope(tmp_path / "ok")
    asm_scope = IndexScope(
        scope_id="cpp-scope-asm", case_id="case-asm", project_id="cpp:asm", root="asm",
        case_snapshot="b" * 64, case_root=scope.case_root, files=scope.files,
        compile_commands=({"target_path": "asm/start.S", "arguments": ["clang-18", "/scratch/source/start.S"]},),
        compile_database=scope.compile_database, _by_relative=scope._by_relative,
    )
    base = _unit(tmp_path / "ok")
    accepted_payload = {
        "handoff": {"source_fingerprint": base.job.source_fingerprint},
        "handoff_sha256": "d" * 64,
        "manifest": {"path": "manifest.json"},
    }
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda _root: (accepted_payload, [scope, asm_scope], {}))

    executor = FakeExecutor(base.job.run_root)
    job = build_job(executor_factory=lambda _u: executor)
    load_fn = next(u.handler for u in job.units if u.unit_id == "load.accepted_cpp")
    analyze_fn = next(u.handler for u in job.units if u.unit_id == "analyze.scopes")

    loaded = load_fn(base)
    assert loaded["upstream"]["handoff_sha256"] == "d" * 64
    assert len(loaded["scopes"]) == 2

    # Snapshot mismatch in load.accepted_cpp
    bad_accepted = {**accepted_payload, "handoff": {"source_fingerprint": "0" * 64}}
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda _root: (bad_accepted, [scope], {}))
    with pytest.raises(ValueError, match="target snapshot differs"):
        load_fn(base)

    # Scope set mismatch between load and analyze
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda _root: (accepted_payload, [scope], {}))
    analyze_ctx = UnitContext(base.job, "analyze.scopes", "analyze", "scopes", base.unit_root,
                              MappingProxyType({"load.accepted_cpp": loaded}))
    with pytest.raises(ValueError, match="scopes changed between load and analysis"):
        analyze_fn(analyze_ctx)

    # Unseeded analyze.scopes succeeds with runnable + skipped scope
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda _root: (accepted_payload, [scope, asm_scope], {}))
    analyzed = analyze_fn(analyze_ctx)
    assert analyzed["terminal_status"] == "SUCCEEDED"
    assert analyzed["scope_count"] == 1
    assert analyzed["not_applicable_scopes"][0]["terminal_status"] == "SKIPPED_NA"

    # Seeded analyze.scopes exercises run_for(scope) through build_job
    staged = sc.stage(tmp_path / "seeded_job")
    seeded_scope = sc.index_scope(staged)
    seeded_unit = staged.unit(
        "analyze.scopes",
        {"load.accepted_cpp": {"scopes": [seeded_scope.as_dict()]}},
        seeded=sc.SEEDED,
        job_id=JOB_ID,
    )
    seeded_unit.job.config.settings.update(sc.STATIC_SETTINGS)
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda _root: ({}, [seeded_scope], {}))
    seeded_exec = sc.StaticExecutor(staged.run_root)
    seeded_job = build_job(executor_factory=lambda _u: seeded_exec)
    seeded_analyze = next(u.handler for u in seeded_job.units if u.unit_id == "analyze.scopes")
    seeded_res = seeded_analyze(seeded_unit)
    assert seeded_res["scope_count"] == 1
    assert len(seeded_exec.calls) == 2


def _observation_payloads(run_root: Path, result: dict) -> list[dict]:
    shard = run_root / result["index_identity"]["relative_path"]
    with sqlite3.connect(shard) as database:
        rows = database.execute("SELECT payload_json FROM entities WHERE kind = 'tool_observation'").fetchall()
    return [json.loads(row[0]) for row in rows]


def test_clang_observations_carry_native_severity_and_a_common_record(tmp_path: Path) -> None:
    """Clang ``warning`` must order review as medium, not unknown, through the shared normalizer."""
    from appsec_review.retrieval.observations import normalize_reported_severity

    scope, unit = _scope(tmp_path), _unit(tmp_path)
    result = _analyze_scope(unit, scope, lambda _unit: FakeExecutor(unit.job.run_root))
    payloads = _observation_payloads(unit.job.run_root, result)
    assert len(payloads) == 2 and result["collapsed_identical_records"] == 0
    for payload in payloads:
        assert payload["native_severity"] == "warning" == payload["reported_severity"]
        assert payload["common"]["reported_severity"]["value"] == "medium"
        assert payload["common"]["reported_severity"]["basis"] == "native-label"
        assert payload["common"]["scanner"] == TOOL_ID
        assert payload["common"]["observation_class"] == "source_sast"
        assert normalize_reported_severity(payload)["value"] == "medium"
        # Direct handler calls have no retention owner: the record says so instead of citing nothing.
        assert payload["common"]["evidence_refs"] == [] and len(payload["common"]["gap_ids"]) == 1


def test_legacy_clang_payload_reported_severity_is_normalized() -> None:
    from appsec_review.retrieval.observations import normalize_reported_severity

    legacy = {"tool_id": TOOL_ID, "category": "source_sast", "native_rule_id": "r", "reported_severity": "error"}
    assert normalize_reported_severity(legacy)["value"] == "high"
    assert normalize_reported_severity({**legacy, "reported_severity": "warning"})["value"] == "medium"


def test_clang_common_record_cites_the_retained_wrapper_output_inside_an_attempt(tmp_path: Path) -> None:
    from appsec_review.storage import atomic_json
    from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner, reference

    scope, unit = _scope(tmp_path), _unit(tmp_path)
    run_root = unit.job.run_root
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / "attempt_0001"
    actor = {"run_id": run_root.name, "job_id": JOB_ID, "attempt_id": "attempt_0001", "orchestration": {"system": "fixture"}}
    from appsec_review.jobs.job_clang_static_analysis.datasets import DATASETS
    from appsec_review.runtime.datasets import dataset_contract
    atomic_json(attempt_root / "claim.json", {
        **actor, "attempt_path": attempt_root.relative_to(run_root).as_posix(),
        "dataset_contract": dataset_contract(JOB_ID, ("load", "analyze", "acceptance"), DATASETS)})
    owner = SharedArtifacts(run_root, attempt_root, {**actor, "claim": reference(run_root, attempt_root / "claim.json")})
    with publication_scope_for_owner(owner):
        result = _analyze_scope(unit, scope, lambda _unit: FakeExecutor(run_root))
    assert result["terminal_status"] == "SUCCEEDED"
    payloads = _observation_payloads(run_root, result)
    assert len(payloads) == 2
    for payload in payloads:
        refs = payload["common"]["evidence_refs"]
        assert len(refs) == 1 and refs[0]["selector"] == {"kind": "json_pointer", "value": "/diagnostics/0"}
        assert refs[0]["parser_identity"] == "clang-static-adapter/9"
        assert payload["common"]["gap_ids"] == []
        assert payload["common"]["reported_severity"]["value"] == "medium"


def test_identical_clang_diagnostics_collapse_to_one_counted_observation(tmp_path: Path) -> None:
    scope, unit = _scope(tmp_path), _unit(tmp_path)
    result = _analyze_scope(unit, scope, lambda _unit: FakeExecutor(unit.job.run_root, duplicate="clang-tidy"))
    assert result["terminal_status"] == "SUCCEEDED"
    assert result["collapsed_identical_records"] == 1
    assert result["observation_count"] == 2 == len(_observation_payloads(unit.job.run_root, result))


def test_repeated_clang_diagnostics_inside_an_attempt_collapse_to_one_observation_citing_the_first_report(
        tmp_path: Path) -> None:
    """Run 2026-11-17-0002: inside a publication attempt each repeat of one diagnostic cited its own native-output
    selector, so one evidence identity reached the shard builder with two payloads ("conflicting entities")."""
    from appsec_review.storage import atomic_json
    from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner, reference
    from appsec_review.jobs.job_clang_static_analysis.datasets import DATASETS
    from appsec_review.runtime.datasets import dataset_contract

    scope, unit = _scope(tmp_path), _unit(tmp_path)
    run_root = unit.job.run_root
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / "attempt_0001"
    actor = {"run_id": run_root.name, "job_id": JOB_ID, "attempt_id": "attempt_0001", "orchestration": {"system": "fixture"}}
    atomic_json(attempt_root / "claim.json", {
        **actor, "attempt_path": attempt_root.relative_to(run_root).as_posix(),
        "dataset_contract": dataset_contract(JOB_ID, ("load", "analyze", "acceptance"), DATASETS)})
    owner = SharedArtifacts(run_root, attempt_root, {**actor, "claim": reference(run_root, attempt_root / "claim.json")})
    with publication_scope_for_owner(owner):
        result = _analyze_scope(unit, scope, lambda _unit: FakeExecutor(run_root, duplicate="clang-tidy"))
    assert result["terminal_status"] == "SUCCEEDED"
    assert result["collapsed_identical_records"] == 1
    payloads = _observation_payloads(run_root, result)
    assert result["observation_count"] == 2 == len(payloads)
    tidy = [payload for payload in payloads if payload["scanner"] == "clang-tidy"]
    assert len(tidy) == 1
    [ref] = tidy[0]["common"]["evidence_refs"]
    assert ref["selector"] == {"kind": "json_pointer", "value": "/diagnostics/0"}
