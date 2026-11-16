"""Direct unit-handler tests for src/appsec_review/jobs/job_poc_generation/job.py (zero JobRunner/Docker)."""
from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import shutil
from types import MappingProxyType, SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_poc_generation import job as poc_job
from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds, MissingBuild
from appsec_review.jobs.job_poc_generation.candidates import parse_candidates
from appsec_review.jobs.job_poc_generation.inputs import VerifiedInputs
from appsec_review.jobs.job_poc_generation.statuses import (
    ARTIFACT_GENERATED,
    COMPILE_FAILED,
    COMPILE_VERIFIED,
    INSUFFICIENT_EVIDENCE,
    NOT_APPLICABLE,
    POLICY_DENIED,
)
from appsec_review.jobs.job_poc_generation.writer import WriterOutcome
from appsec_review.observability import EventLog
from appsec_review.review.models import IntegrityError
from appsec_review.runtime.job import JobContext
from appsec_review.storage import atomic_json, canonical_json
from tests.fixtures.poc_generation import relay
from tests.poc_support import FIXTURES, ROOT, FakeExecutor, ast_document, builds, manifest_of, relay_unit


def _fast_workspace(destination: Path) -> tuple[Path, dict[str, str]]:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(FIXTURES / "relay_source", destination)
    for rel in ("build/CMakeFiles/relay.dir/src/packet.cpp.o", "build/CMakeFiles/relay.dir/src/main.cpp.o"):
        path = destination / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELF placeholder " + rel.encode())
    return destination, manifest_of(destination)


def _job_context(tmp_path: Path, *, config=None, upstream: dict[str, str] | None = None) -> JobContext:
    cfg = config or load_config(ROOT / "appsec-review.toml").job(poc_job.JOB_ID)
    run_root = tmp_path / "run"
    attempt_root = run_root / "data" / "jobs" / poc_job.JOB_ID / "attempts" / "att-1"
    metadata_root = run_root / "metadata"
    attempt_root.mkdir(parents=True, exist_ok=True)
    metadata_root.mkdir(parents=True, exist_ok=True)
    return JobContext(
        run_id="run-1",
        attempt_id="att-1",
        trigger="unit-test",
        repository_root=ROOT,
        run_root=run_root,
        attempt_root=attempt_root,
        metadata_root=metadata_root,
        orchestration={},
        config=cfg,
        events=EventLog(attempt_root / "events.jsonl"),
        evidence_target_snapshot="snap-1",
        source_fingerprint="fp-1",
        input_manifest_sha256="scope-1",
        upstream_handoffs=MappingProxyType(
            upstream
            if upstream is not None
            else {
                "job_inference_security_review": "a" * 64,
                "job_language_build": "b" * 64,
            }
        ),
    )


def _basis_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "entry": ["asr:entry_point:" + "1" * 64],
        "path": ["asr:call_site:" + "2" * 64],
        "trigger": [relay.TRIGGER],
        "input_format": "4-byte header",
        "preconditions": ["local"],
        "expected_observation": "stack-buffer-overflow",
        "unknowns": [],
    }
    base.update(overrides)
    return base


def _candidate_dict(idx: int, *, verdict: str = "red_correct", basis: dict[str, Any] | None = None) -> dict[str, Any]:
    bval = _basis_dict() if basis is None else basis
    hex_id = f"{idx:064x}"
    return {
        "claim_id": f"claim-{hex_id}",
        "package_id": f"finding_lead-{hex_id}",
        "state": "confirmed",
        "judge_verdict": verdict,
        "poc_basis": {"sha256": hashlib.sha256(canonical_json(bval)).hexdigest(), "brief": bval},
        "finding_package": {"finding_package_id": f"finding-{hex_id}", "sha256": "4" * 64},
        "evidence_refs": [f"evrel-{hex_id}"],
    }


def _verified_inputs(
    run_root: Path,
    candidate_dicts: list[dict[str, Any]],
    packages_by_idx: dict[int, dict[str, Any]],
) -> VerifiedInputs:
    cands = parse_candidates(candidate_dicts)
    findings: dict[str, dict[str, Any]] = {}
    package_records: dict[str, dict[str, str]] = {}
    for idx, cd in enumerate(candidate_dicts, start=1):
        fid = cd["finding_package"]["finding_package_id"]
        pid = cd["package_id"]
        findings[fid] = {
            "finding_package_id": fid,
            "sha256": "4" * 64,
            "path": f"jobs/rev/findings/{fid}.json",
            "title": f"Finding {idx}",
            "label": f"F{idx}",
            "lane": "lead",
            "state": "confirmed",
            "missing_predicates": [],
        }
        if idx in packages_by_idx:
            rel = f"data/jobs/job_inference_security_review/attempts/att-rev/packages/{pid}.json"
            full = run_root / rel
            atomic_json(full, packages_by_idx[idx])
            package_records[pid] = {
                "path": rel,
                "sha256": hashlib.sha256(full.read_bytes()).hexdigest(),
                "lane": "lead",
            }
    return VerifiedInputs(
        run_id="run-1",
        review_job_handoff={"path": "jobs/rev/latest.json", "sha256": "a" * 64},
        review_handoff={"path": "jobs/rev/review.json", "sha256": "c" * 64},
        review_status="SUCCEEDED",
        manifest_sha256="5" * 64,
        manifest_path="idx/manifest.json",
        candidates=cands,
        findings=findings,
        package_records=package_records,
        bindings=(),
    )


def _view_with_resolved_labels() -> SimpleNamespace:
    return SimpleNamespace(
        document={
            "labels": [
                {"label": "L1", "ref": "asr:entry_point:" + "1" * 64, "summary": "entry"},
                {"label": "C1", "ref": "asr:call_site:" + "2" * 64, "summary": "main -> relay::parse_header (L16)"},
            ]
        }
    )


def test_validate_and_terminal_guards(tmp_path: Path) -> None:
    ctx = _job_context(tmp_path)
    poc_job._validate(ctx, None)

    bad_steps = SimpleNamespace(steps=("load",), step=ctx.config.step, settings=ctx.config.settings)
    with pytest.raises(ValueError, match="topology does not match"):
        poc_job._validate(SimpleNamespace(config=bad_steps), None)

    bad_task = SimpleNamespace(
        steps=ctx.config.steps,
        step=lambda _s: SimpleNamespace(tasks=("wrong_task",)),
        settings=ctx.config.settings,
    )
    with pytest.raises(ValueError, match="task configuration mismatch"):
        poc_job._validate(SimpleNamespace(config=bad_task), None)

    with pytest.raises(ValueError, match="unknown PoC status"):
        poc_job._terminal("not_a_valid_status", "bad")


def test_full_job_handler_happy_path_via_injected_fakes(tmp_path: Path) -> None:
    workspace, manifest = _fast_workspace(tmp_path / "ws")
    unit = relay_unit(workspace, manifest)
    fake_exec = FakeExecutor(ast=ast_document("good"))
    ctx = _job_context(tmp_path)

    cd = _candidate_dict(1)
    pkg = {
        "package_id": cd["package_id"],
        "neighborhood": {"function": {"name": relay.SINK, "path": "src/packet.cpp", "start_line": 8, "end_line": 20}},
    }
    ver = _verified_inputs(ctx.run_root, [cd], {1: pkg})
    fake_builds = AcceptedBuilds(unit.workspace.parent, loader=lambda _r: {"receipts": [], "language_build_handoff_sha256": "b" * 64})
    fake_builds.locate = lambda _p: SimpleNamespace(unit=unit, reason="", code="found")  # type: ignore[method-assign]

    ans_result = dict(relay.answer()["result"], claim=cd["claim_id"])
    writer_out = WriterOutcome("answered", ans_result, "ok", ())

    job = poc_job.build_job(
        infer=lambda *_a, **_kw: None,
        executor_factory=lambda _u, _p: fake_exec,
        builds_factory=lambda _r: fake_builds,
        core_factory=lambda _r, _m: SimpleNamespace(),
        view_factory=lambda *_a, **_kw: _view_with_resolved_labels(),
        repository_root=ROOT,
    )

    accepted_ptr = SimpleNamespace(path="jobs/rev/latest.json", sha256="a" * 64)
    with (
        patch("appsec_review.jobs.job_poc_generation.inputs.verify_inputs", return_value=ver),
        patch("appsec_review.jobs.job_poc_generation.job.accepted_handoff", return_value=accepted_ptr),
        patch("appsec_review.jobs.job_poc_generation.job.run_writer", return_value=writer_out),
    ):
        result = job.handler(ctx)

    pub = result["outputs"]["publish.publish_handoff"]
    assert pub["terminal_status"] == "SUCCEEDED"
    assert pub["counts"]["by_status"][COMPILE_VERIFIED] == 1


def test_unit_branches_for_plan_write_validate_compile_and_publish_errors(tmp_path: Path) -> None:
    workspace, manifest = _fast_workspace(tmp_path / "ws")
    unit = relay_unit(workspace, manifest)

    base_cfg = load_config(ROOT / "appsec-review.toml").job(poc_job.JOB_ID)
    wide_settings = dict(base_cfg.settings)
    wide_settings["max_candidates"] = 13  # 14th candidate triggers omitted/max_candidates gap!
    wide_cfg = replace(base_cfg, settings=wide_settings)
    ctx = _job_context(tmp_path / "wide", config=wide_cfg)

    cands = [
        _candidate_dict(1, verdict="blue_correct"),          # NOT_APPLICABLE (unaccepted verdict)
        _candidate_dict(2, basis=_basis_dict(entry=[])),     # INSUFFICIENT_EVIDENCE (unusable basis)
        _candidate_dict(3),                                  # INSUFFICIENT_EVIDENCE (missing package)
        _candidate_dict(4),                                  # INSUFFICIENT_EVIDENCE (no sink)
        _candidate_dict(5),                                  # NOT_APPLICABLE (unlocated sink path)
        _candidate_dict(6),                                  # INSUFFICIENT_EVIDENCE (unresolved basis refs)
        _candidate_dict(7),                                  # declined writer -> INSUFFICIENT_EVIDENCE
        _candidate_dict(8),                                  # failed writer -> INSUFFICIENT_EVIDENCE
        _candidate_dict(9),                                  # pre-parse text violation -> POLICY_DENIED
        _candidate_dict(10),                                 # AST violation -> POLICY_DENIED
        _candidate_dict(11),                                 # compiler_exit_code=1 -> COMPILE_FAILED
        _candidate_dict(12),                                 # AST None -> ARTIFACT_GENERATED
        _candidate_dict(13),                                 # compile RuntimeError -> ARTIFACT_GENERATED
        _candidate_dict(14),                                 # omitted due to max_candidates=13
    ]
    good_pkg = {
        "neighborhood": {"function": {"name": relay.SINK, "path": "src/packet.cpp", "start_line": 8, "end_line": 20}},
    }
    pkgs = {
        4: {"neighborhood": {}},
        5: {"neighborhood": {"function": {"name": relay.SINK, "path": "unbuilt/file.cpp"}}},
        6: good_pkg,
        7: good_pkg,
        8: good_pkg,
        9: good_pkg,
        10: good_pkg,
        11: good_pkg,
        12: good_pkg,
        13: good_pkg,
    }
    ver = _verified_inputs(ctx.run_root, cands, pkgs)
    binding_file = ctx.run_root / "idx" / "bound.json"
    atomic_json(binding_file, {"ok": True})
    ver = replace(
        ver,
        bindings=({"path": "idx/bound.json", "sha256": hashlib.sha256(binding_file.read_bytes()).hexdigest()},),
    )

    def _locate(path: str) -> Any:
        if path == "unbuilt/file.cpp":
            return SimpleNamespace(unit=None, reason="not compiled", code="not_in_compile_commands")
        return SimpleNamespace(unit=unit, reason="", code="found")

    fake_builds = AcceptedBuilds(unit.workspace.parent, loader=lambda _r: {"receipts": [], "language_build_handoff_sha256": "b" * 64})
    fake_builds.locate = _locate  # type: ignore[method-assign]

    claim_7 = cands[6]["claim_id"]
    claim_8 = cands[7]["claim_id"]
    claim_9 = cands[8]["claim_id"]
    claim_10 = cands[9]["claim_id"]
    claim_11 = cands[10]["claim_id"]
    claim_12 = cands[11]["claim_id"]
    claim_13 = cands[12]["claim_id"]

    def _view_factory(package: Any, *_a: Any, **_kw: Any) -> Any:
        if package.get("_empty_view"):
            return SimpleNamespace(document={})
        return _view_with_resolved_labels()

    pkg6_path = ctx.run_root / ver.package_records[cands[5]["package_id"]]["path"]
    pkg6_doc = dict(good_pkg, _empty_view=True)
    atomic_json(pkg6_path, pkg6_doc)
    ver.package_records[cands[5]["package_id"]]["sha256"] = hashlib.sha256(pkg6_path.read_bytes()).hexdigest()  # type: ignore[index]

    def _ast_for_source(src_text: str) -> dict[str, Any] | None:
        if claim_10 in src_text:
            return ast_document("system_call")
        if claim_11 in src_text:
            doc = dict(ast_document("good"))
            doc["compiler_exit_code"] = 1
            return doc
        if claim_12 in src_text:
            return None
        return ast_document("good")

    class _SelectiveExec(FakeExecutor):
        def execute(self, argv: Any, *, workspace: Path, working_directory: str, environment: Any) -> Any:
            if argv[0] != "python3":
                src_file = workspace / ".appsec-poc" / "poc.cpp"
                if src_file.is_file() and claim_13 in src_file.read_text(encoding="utf-8"):
                    raise RuntimeError("docker daemon crashed during compile")
            return super().execute(argv, workspace=workspace, working_directory=working_directory, environment=environment)

    fake_exec = _SelectiveExec(ast=_ast_for_source)

    def _fake_writer(brief_obj: Any, *, claim_id: str, **_kw: Any) -> WriterOutcome:
        if claim_id == claim_7:
            return WriterOutcome(
                "declined",
                {"claim": claim_id, "decline": {"status": INSUFFICIENT_EVIDENCE, "why": "missing layout"}},
                "declined",
                (),
            )
        if claim_id == claim_8:
            return WriterOutcome("failed", None, "provider_timeout", ())
        if claim_id == claim_9:
            bad_res = dict(relay.answer(test="void poc_parse_header_overlong_name() {\n#define X 1\n}")["result"], claim=claim_id)
            return WriterOutcome("answered", bad_res, "ok", ())
        ok_res = dict(relay.answer()["result"], claim=claim_id)
        return WriterOutcome("answered", ok_res, "ok", ())

    job = poc_job.build_job(
        infer=lambda *_a, **_kw: None,
        executor_factory=lambda _u, _p: fake_exec,
        builds_factory=lambda _r: fake_builds,
        core_factory=lambda _r, _m: SimpleNamespace(),
        view_factory=_view_factory,
        repository_root=ROOT,
    )

    accepted_ptr = SimpleNamespace(path="jobs/rev/latest.json", sha256="a" * 64)
    with (
        patch("appsec_review.jobs.job_poc_generation.inputs.verify_inputs", return_value=ver),
        patch("appsec_review.jobs.job_poc_generation.job.accepted_handoff", return_value=accepted_ptr),
        patch("appsec_review.jobs.job_poc_generation.job.run_writer", side_effect=_fake_writer),
    ):
        result = job.handler(ctx)

    pub = result["outputs"]["publish.publish_handoff"]
    assert pub["terminal_status"] == "COMPLETED_WITH_GAPS"
    by_status = pub["counts"]["by_status"]
    assert by_status[NOT_APPLICABLE] == 2
    assert by_status[INSUFFICIENT_EVIDENCE] == 6
    assert by_status[POLICY_DENIED] == 2
    assert by_status[COMPILE_FAILED] == 1
    assert by_status[ARTIFACT_GENERATED] == 2
    assert pub["counts"]["omitted"] == 1

    # No-pending fast path in write + MissingBuild gap in load + stale review handoff in publish
    empty_ctx = _job_context(tmp_path / "empty")
    ver_empty = _verified_inputs(empty_ctx.run_root, [_candidate_dict(1, verdict="blue_correct")], {})

    def _missing_builds(_r: Path) -> Any:
        if not getattr(_missing_builds, "called", False):
            _missing_builds.called = True  # type: ignore[attr-defined]
            raise MissingBuild("no language build handoff")
        return fake_builds

    missing_job = poc_job.build_job(
        builds_factory=_missing_builds,
        core_factory=lambda _r, _m: SimpleNamespace(),
        view_factory=lambda *_a, **_kw: _view_with_resolved_labels(),
        repository_root=ROOT,
    )
    with (
        patch("appsec_review.jobs.job_poc_generation.inputs.verify_inputs", return_value=ver_empty),
        patch("appsec_review.jobs.job_poc_generation.job.accepted_handoff", return_value=accepted_ptr),
    ):
        res_empty = missing_job.handler(empty_ctx)
    pub_empty = res_empty["outputs"]["publish.publish_handoff"]
    assert pub_empty["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("accepted_build_unavailable" in g for g in pub_empty["gaps"])

    # Stale accepted_handoff during publish records FAILED unit via UnitExecutor
    stale_ctx = _job_context(tmp_path / "stale")
    ver_stale = _verified_inputs(stale_ctx.run_root, [], {})
    with (
        patch("appsec_review.jobs.job_poc_generation.inputs.verify_inputs", return_value=ver_stale),
        patch("appsec_review.jobs.job_poc_generation.job.accepted_handoff", return_value=None),
    ):
        res_stale = job.handler(stale_ctx)
    assert res_stale["status"] == "FAILED"
    assert "publish.publish_handoff" in res_stale["failed_units"]

    # RuntimeError during executor resolution in validate and compile steps
    unavail_ctx = _job_context(tmp_path / "unavail")
    ver_unavail = _verified_inputs(unavail_ctx.run_root, [_candidate_dict(1)], {1: good_pkg})
    unavail_exec = FakeExecutor(unavailable="docker daemon unreachable")
    unavail_job = poc_job.build_job(
        infer=lambda *_a, **_kw: None,
        executor_factory=lambda _u, _p: unavail_exec,
        builds_factory=lambda _r: fake_builds,
        core_factory=lambda _r, _m: SimpleNamespace(),
        view_factory=lambda *_a, **_kw: _view_with_resolved_labels(),
        repository_root=ROOT,
    )
    ans_1 = dict(relay.answer()["result"], claim=ver_unavail.candidates[0].claim_id)
    with (
        patch("appsec_review.jobs.job_poc_generation.inputs.verify_inputs", return_value=ver_unavail),
        patch("appsec_review.jobs.job_poc_generation.job.accepted_handoff", return_value=accepted_ptr),
        patch("appsec_review.jobs.job_poc_generation.job.run_writer", return_value=WriterOutcome("answered", ans_1, "ok", ())),
    ):
        res_unavail = unavail_job.handler(unavail_ctx)
    pub_unavail = res_unavail["outputs"]["publish.publish_handoff"]
    assert pub_unavail["counts"]["by_status"][ARTIFACT_GENERATED] == 1

    # Also exercise RuntimeError during compile step after validate passes
    comp_err_ctx = _job_context(tmp_path / "comp_err")
    ver_comp = _verified_inputs(comp_err_ctx.run_root, [_candidate_dict(1)], {1: good_pkg})
    step_calls = {"count": 0}

    def _exec_fails_on_compile(_u: Any, _p: Any) -> Any:
        step_calls["count"] += 1
        if step_calls["count"] >= 2:
            return FakeExecutor(unavailable="docker lost before compile")
        return FakeExecutor(ast=ast_document("good"))

    comp_err_job = poc_job.build_job(
        infer=lambda *_a, **_kw: None,
        executor_factory=_exec_fails_on_compile,
        builds_factory=lambda _r: fake_builds,
        core_factory=lambda _r, _m: SimpleNamespace(),
        view_factory=lambda *_a, **_kw: _view_with_resolved_labels(),
        repository_root=ROOT,
    )
    with (
        patch("appsec_review.jobs.job_poc_generation.inputs.verify_inputs", return_value=ver_comp),
        patch("appsec_review.jobs.job_poc_generation.job.accepted_handoff", return_value=accepted_ptr),
        patch("appsec_review.jobs.job_poc_generation.job.run_writer", return_value=WriterOutcome("answered", ans_1, "ok", ())),
    ):
        res_comp = comp_err_job.handler(comp_err_ctx)
    pub_comp = res_comp["outputs"]["publish.publish_handoff"]
    assert pub_comp["counts"]["by_status"][ARTIFACT_GENERATED] == 1


    # Upstream handoff mismatch in load records FAILED unit via UnitExecutor
    bad_up_ctx = _job_context(
        tmp_path / "bad_up",
        upstream={"job_inference_security_review": "f" * 64, "job_language_build": "b" * 64},
    )
    with patch("appsec_review.jobs.job_poc_generation.inputs.verify_inputs", return_value=ver_stale):
        res_bad_up = job.handler(bad_up_ctx)
    assert res_bad_up["status"] == "FAILED"
    assert "load.verify_inputs" in res_bad_up["failed_units"]
