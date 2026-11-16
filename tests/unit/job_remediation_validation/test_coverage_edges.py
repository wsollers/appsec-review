from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from appsec_review.config.loader import JobConfig, StepConfig, TaskConfig
from appsec_review.config.remediation import RemediationValidationSettings
from appsec_review.indexing.store import AcceptedHandoff
from appsec_review.inference import ModelResult
from appsec_review.jobs import accepted_review
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.jobs.completion_contracts import (
    REMEDIATION_PLANNING_JOB,
    REMEDIATION_VALIDATION_JOB,
    RemediationValidationStatus as Status,
)
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds, CompileCommand, Located
from appsec_review.jobs.job_remediation_planning import build_job as build_planning_job
from appsec_review.jobs.job_remediation_planning import job as planning_job
from appsec_review.jobs.job_remediation_validation import (
    build_job,
    inputs as validation_inputs,
    job as validation_job,
    workspace as validation_workspace,
)
from appsec_review.jobs.job_remediation_validation.workspace import WorkspaceLimit, cleanup, manifest, materialize
from appsec_review.observability import EventLog
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import JobContext
from appsec_review.storage import atomic_json
from tests import remediation_support as support
from tests.poc_support import relay_unit


def _write(root: Path, rel: str, doc: object) -> dict[str, str]:
    path = root / "data" / "seed" / rel
    atomic_json(path, doc)
    return artifact_ref(root, path)


def _job_ctx(
    root: Path,
    job_id: str,
    name: str,
    topology: dict[str, tuple[str, ...]],
    settings: dict,
    attempt_name: str = "att-1",
    steps: dict | None = None,
) -> JobContext:
    step_map = steps if steps is not None else {
        step: StepConfig(step, 1, {}, {tasks[0]: TaskConfig(tasks[0], 1, {})})
        for step, tasks in topology.items()
    }
    cfg = JobConfig(job_id, name, 1, None, settings, step_map)
    attempt = root / "data" / "jobs" / job_id / "attempts" / attempt_name
    attempt.mkdir(parents=True, exist_ok=True)
    return JobContext(
        run_id=root.name,
        attempt_id=attempt_name,
        trigger="test",
        repository_root=support.ROOT,
        run_root=root,
        attempt_root=attempt,
        metadata_root=attempt,
        orchestration={},
        config=cfg,
        events=EventLog(attempt / "events.jsonl"),
    )


def _plan_ctx(root: Path, settings: dict, attempt_name: str = "att-plan") -> JobContext:
    return _job_ctx(root, planning_job.JOB_ID, "remediation_planning", planning_job.TOPOLOGY, settings, attempt_name)


def _val_ctx(root: Path, settings: dict, attempt_name: str = "att-val", steps: dict | None = None) -> JobContext:
    return _job_ctx(
        root,
        REMEDIATION_VALIDATION_JOB,
        "remediation_validation",
        validation_job.TOPOLOGY,
        settings,
        attempt_name,
        steps=steps,
    )


def _seed_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    candidate_count: int = 1,
    extra_files: dict[str, str] | None = None,
    plan_infer=None,
    plan_settings: dict | None = None,
    builds_fn=None,
    primary_path: str = "native/src/parse.c",
    extra_entity_path: str | None = None,
) -> SimpleNamespace:
    root = tmp_path / "run-val"
    ws = root / "data" / "workspace"
    src_file = ws / primary_path
    src_file.parent.mkdir(parents=True, exist_ok=True)
    src_text = "void p(char *s) {\n  char b[8];\n  strcpy(b, s);\n}\n"
    src_file.write_text(src_text, encoding="utf-8")
    ws_manifest = {primary_path: hashlib.sha256(src_file.read_bytes()).hexdigest()}
    file_hashes = dict(ws_manifest)
    for rel, content in (extra_files or {}).items():
        fpath = ws / rel
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")
        sha = hashlib.sha256(fpath.read_bytes()).hexdigest()
        ws_manifest[rel] = sha
        file_hashes[rel] = sha

    builds = builds_fn(root, ws, ws_manifest) if builds_fn else support.builds_for(root, ws, ws_manifest)

    relations_by_claim: dict[str, list[dict]] = {}
    packages: list[dict] = []
    confirmed_ids: list[str] = []
    entity_files: dict[str, tuple[str, str]] = {}
    for idx in range(candidate_count):
        cid = f"claim-{idx + 1}"
        fid = f"finding-{idx + 1}"
        rel_id = f"evrel-{idx + 1}"
        ent_id = f"entity-{idx + 1}"
        confirmed_ids.append(fid)
        rels = [{"relation_id": rel_id, "entity_id": ent_id}]
        entity_files[ent_id] = (primary_path, file_hashes[primary_path])
        d_ev = [rel_id]
        if extra_entity_path is not None and idx == 0:
            rel2 = f"evrel-extra-{idx + 1}"
            ent2 = f"entity-extra-{idx + 1}"
            rels.append({"relation_id": rel2, "entity_id": ent2})
            entity_files[ent2] = (extra_entity_path, file_hashes[extra_entity_path])
            d_ev.append(rel2)
        relations_by_claim[cid] = rels
        packages.append(
            {
                "claim_id": cid,
                "finding_package_id": fid,
                "sha256": f"{idx + 1}" * 64,
                "adjudication_id": f"adj-{idx + 1}",
                "state": "confirmed",
                "title": f"Buffer copy {idx + 1}",
                "direct_evidence": d_ev,
            }
        )

    projection_ref = _write(root, "projection.json", {"relations": relations_by_claim})
    scope_manifest_ref = _write(root, "scope-manifest.json", {"run_id": root.name})
    scope_ref = _write(
        root,
        "scope.json",
        {"manifest_path": scope_manifest_ref["path"], "manifest_sha256": scope_manifest_ref["sha256"]},
    )
    job_handoff_ref = _write(
        root,
        "job-handoff.json",
        {"outputs": {"scope.accept_manifest": {"artifact": scope_ref}}},
    )
    review_handoff_ref = _write(root, "review-handoff.json", {"run_id": root.name})
    binding_ref = _write(root, "bound-item.json", {"ok": True})

    review_doc = {
        "run_id": root.name,
        "partition": {"confirmed": confirmed_ids, "supported": []},
        "packages": packages,
        "inputs": {
            "projection": projection_ref,
            "job_handoff": job_handoff_ref,
            "review_handoff": review_handoff_ref,
        },
        "bindings": [binding_ref],
    }

    monkeypatch.setattr(
        accepted_review,
        "load_accepted_review",
        lambda *_args, **_kwargs: SimpleNamespace(document=copy.deepcopy(review_doc)),
    )

    class FakeCore:
        def find(self, *, identity: str, limit: int = 1) -> dict:
            path, sha = entity_files[identity]
            return {"results": [{"entity_id": identity, "location": {"path": path, "file_sha256": sha}}]}

    core = FakeCore()
    p_job = build_planning_job(
        infer=plan_infer or support.Writer(),
        builds_factory=lambda _r: builds,
        core_factory=lambda _r, _rev: core,
        repository_root=support.ROOT,
    )
    p_res = p_job.execute(_plan_ctx(root, plan_settings or support.planning_settings()))
    assert not p_res["failed_units"], p_res
    pub_out = p_res["outputs"]["acceptance.publish_handoff"]
    handoff_doc = {
        "job_id": REMEDIATION_PLANNING_JOB,
        "outputs": {"acceptance.publish_handoff": pub_out},
    }
    handoff_ref = _write(root, "planning-handoff.json", handoff_doc)
    accepted_box = [AcceptedHandoff(REMEDIATION_PLANNING_JOB, handoff_doc, handoff_ref["sha256"], handoff_ref["path"])]
    monkeypatch.setattr(validation_inputs, "accepted_handoff", lambda _r, _j: accepted_box[0])

    return SimpleNamespace(
        root=root,
        workspace=ws,
        src_file=src_file,
        manifest=ws_manifest,
        file_hashes=file_hashes,
        builds=builds,
        review_doc=review_doc,
        entity_files=entity_files,
        core=core,
        handoff_doc=handoff_doc,
        handoff_ref=handoff_ref,
        accepted_box=accepted_box,
        pub_out=pub_out,
    )


def test_workspace_materialize_manifest_and_cleanup_edges(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_root = tmp_path / "run-ws"
    ws = run_root / "data" / "ws"
    f1 = ws / "sub" / "a.c"
    f1.parent.mkdir(parents=True)
    f1.write_bytes(b"int x = 1;\n")
    sha1 = hashlib.sha256(f1.read_bytes()).hexdigest()
    cmd = CompileCommand(("/usr/bin/clang", "-c", "sub/a.c"), "sub/a.c", "c", ".", "exact")
    unit = relay_unit(ws, {"sub/a.c": sha1}, compile_command=cmd, objects=())
    b = support.bounds()

    # Outside run_root refused
    outside_unit = replace(unit, workspace=tmp_path / "outside")
    with pytest.raises(IntegrityError, match="not run-owned"):
        materialize(outside_unit, run_root / "dest", b, run_root=run_root)

    # max_workspace_files exceeded
    with pytest.raises(WorkspaceLimit, match="workspace_file_bound_reached"):
        materialize(unit, run_root / "dest-f", replace(b, max_workspace_files=0), run_root=run_root)

    # Existing destination refused
    existing = run_root / "existing"
    existing.mkdir(parents=True)
    with pytest.raises(IntegrityError, match="already exists"):
        materialize(unit, existing, b, run_root=run_root)

    # max_workspace_bytes exceeded
    with pytest.raises(WorkspaceLimit, match="workspace_byte_bound_reached"):
        materialize(unit, run_root / "dest-b", replace(b, max_workspace_bytes=2), run_root=run_root)

    # Tampered workspace bytes refused
    bad_unit = replace(unit, workspace_manifest={"sub/a.c": "0" * 64})
    with pytest.raises(IntegrityError, match="accepted workspace bytes changed"):
        materialize(bad_unit, run_root / "dest-bad", b, run_root=run_root)

    # Clean materialize + manifest + empty manifest
    dest = run_root / "attempts" / "0" / "scratch"
    materialize(unit, dest / "baseline", b, run_root=run_root)
    assert manifest(dest / "baseline", b) == {"sub/a.c": sha1}
    empty_unit = replace(unit, workspace_manifest={})
    materialize(empty_unit, dest / "empty", b, run_root=run_root)
    assert manifest(dest / "empty", b) == {}

    # manifest file/byte bounds & symlink check
    with pytest.raises(WorkspaceLimit, match="scratch_workspace_bound_reached"):
        manifest(dest / "baseline", replace(b, max_workspace_files=0))
    with pytest.raises(WorkspaceLimit, match="scratch_workspace_bound_reached"):
        manifest(dest / "baseline", replace(b, max_workspace_bytes=2))

    sym = dest / "baseline" / "link.c"
    sym.symlink_to(f1)
    with pytest.raises(IntegrityError, match="unexpected symlink"):
        manifest(dest / "baseline", b)
    sym.unlink()

    # cleanup path guards, missing dir, OSError handling, and clean removal
    with pytest.raises(IntegrityError, match="not a named attempt-owned remediation scratch directory"):
        cleanup(tmp_path / "scratch", run_root)
    with pytest.raises(IntegrityError, match="not a named attempt-owned remediation scratch directory"):
        cleanup(run_root / "not-scratch", run_root)

    missing_scratch = run_root / "attempts" / "99" / "scratch"
    rec_missing = cleanup(missing_scratch, run_root)
    assert rec_missing == {"workspace": "attempts/99/scratch", "created": False, "removed": True, "error": None}

    monkeypatch.setattr(shutil, "rmtree", lambda _p: (_ for _ in ()).throw(OSError("busy")))
    rec_err = cleanup(dest, run_root)
    assert rec_err["created"] is True and rec_err["removed"] is False and "OSError:busy" in rec_err["error"]
    monkeypatch.undo()

    rec_ok = cleanup(dest, run_root)
    assert rec_ok == {"workspace": "attempts/0/scratch", "created": True, "removed": True, "error": None}
    assert not dest.exists()


def test_inputs_load_planning_validation_and_mismatch_edges(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _seed_env(tmp_path, monkeypatch, candidate_count=2, plan_settings=support.planning_settings(max_candidates=1))
    schemas = SchemaSet(support.ROOT / planning_job.SCHEMA_ROOT)
    review = planning_job.load_review(env.root, support.ROOT, support.bounds())

    # Clean load_planning with 1 proposal_generated + 1 capped (plan is None)
    ref, summary = validation_inputs.load_planning(env.root, review, schemas)
    assert ref == env.handoff_ref and len(summary["items"]) == 2

    # ValueError from accepted_handoff -> IntegrityError
    monkeypatch.setattr(validation_inputs, "accepted_handoff", lambda *_a: (_ for _ in ()).throw(ValueError("bad pin")))
    with pytest.raises(IntegrityError, match="cannot be verified"):
        validation_inputs.load_planning(env.root, review, schemas)

    # None from accepted_handoff -> IntegrityError
    monkeypatch.setattr(validation_inputs, "accepted_handoff", lambda *_a: None)
    with pytest.raises(IntegrityError, match="is required"):
        validation_inputs.load_planning(env.root, review, schemas)

    # Wrong job_id
    bad_job = AcceptedHandoff(REMEDIATION_PLANNING_JOB, {**env.handoff_doc, "job_id": "other"}, "a" * 64, "p")
    monkeypatch.setattr(validation_inputs, "accepted_handoff", lambda *_a: bad_job)
    with pytest.raises(IntegrityError, match="belongs to another job"):
        validation_inputs.load_planning(env.root, review, schemas)

    # Bad output schema
    bad_out = AcceptedHandoff(
        REMEDIATION_PLANNING_JOB,
        {"job_id": REMEDIATION_PLANNING_JOB, "outputs": {"acceptance.publish_handoff": {"schema": "wrong"}}},
        "a" * 64,
        "p",
    )
    monkeypatch.setattr(validation_inputs, "accepted_handoff", lambda *_a: bad_out)
    with pytest.raises(IntegrityError, match="publication schema is unsupported"):
        validation_inputs.load_planning(env.root, review, schemas)

    # Schema mismatch in summary
    bad_sum_ref = _write(env.root, "bad-sum.json", {"schema": "wrong"})
    bad_sum_acc = AcceptedHandoff(
        REMEDIATION_PLANNING_JOB,
        {
            "job_id": REMEDIATION_PLANNING_JOB,
            "outputs": {"acceptance.publish_handoff": {**env.pub_out, "artifact": bad_sum_ref}},
        },
        "a" * 64,
        "p",
    )
    monkeypatch.setattr(validation_inputs, "accepted_handoff", lambda *_a: bad_sum_acc)
    with pytest.raises(IntegrityError, match="summary schema mismatch"):
        validation_inputs.load_planning(env.root, review, schemas)

    # Cross-review mixing / item_count mismatch
    mismatch_acc = AcceptedHandoff(
        REMEDIATION_PLANNING_JOB,
        {
            "job_id": REMEDIATION_PLANNING_JOB,
            "outputs": {"acceptance.publish_handoff": {**env.pub_out, "item_count": 99}},
        },
        "a" * 64,
        "p",
    )
    monkeypatch.setattr(validation_inputs, "accepted_handoff", lambda *_a: mismatch_acc)
    with pytest.raises(IntegrityError, match="cross-review mixing"):
        validation_inputs.load_planning(env.root, review, schemas)

    # proposal_generated with plan=None (bypass schema check via stub SchemaSet)
    no_plan_sum = copy.deepcopy(summary)
    no_plan_sum["items"][0]["plan"] = None
    no_plan_ref = _write(env.root, "no-plan-sum.json", no_plan_sum)
    no_plan_acc = AcceptedHandoff(
        REMEDIATION_PLANNING_JOB,
        {
            "job_id": REMEDIATION_PLANNING_JOB,
            "outputs": {"acceptance.publish_handoff": {**env.pub_out, "artifact": no_plan_ref}},
        },
        "a" * 64,
        "p",
    )
    monkeypatch.setattr(validation_inputs, "accepted_handoff", lambda *_a: no_plan_acc)
    stub_schemas = SimpleNamespace(errors=lambda *_: [], validate=lambda *_: None)
    with pytest.raises(IntegrityError, match="proposal has no plan"):
        validation_inputs.load_planning(env.root, review, stub_schemas)

    # Outcome status disagrees with plan status
    disagree_sum = copy.deepcopy(summary)
    disagree_sum["items"][0]["reason"] = "changed reason"
    disagree_ref = _write(env.root, "disagree-sum.json", disagree_sum)
    disagree_acc = AcceptedHandoff(
        REMEDIATION_PLANNING_JOB,
        {
            "job_id": REMEDIATION_PLANNING_JOB,
            "outputs": {"acceptance.publish_handoff": {**env.pub_out, "artifact": disagree_ref}},
        },
        "a" * 64,
        "p",
    )
    monkeypatch.setattr(validation_inputs, "accepted_handoff", lambda *_a: disagree_acc)
    with pytest.raises(IntegrityError, match="outcome disagrees with its plan"):
        validation_inputs.load_planning(env.root, review, stub_schemas)


def test_semantic_answer_and_job_happy_empty_and_capped_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = RemediationValidationSettings.from_mapping(support.validation_settings())

    with pytest.raises(ValueError, match="supported, contradicted or unresolved"):
        validation_job.semantic_answer(
            {"decision": "maybe", "reason": "r", "evidence_ids": ["e1"], "residual_concerns": []},
            cfg,
            {"e1"},
        )
    with pytest.raises(ValueError, match="cites evidence outside"):
        validation_job.semantic_answer(
            {"decision": "supported", "reason": "r", "evidence_ids": ["e2"], "residual_concerns": []},
            cfg,
            {"e1"},
        )
    ok_sem = validation_job.semantic_answer(
        {"decision": "supported", "reason": "ok", "evidence_ids": ["e1"], "residual_concerns": ["none"]},
        cfg,
        {"e1"},
    )
    assert ok_sem["decision"] == "supported"

    # Topology check in _validate
    env = _seed_env(tmp_path, monkeypatch, candidate_count=1)
    with pytest.raises(ValueError, match="topology does not match"):
        validation_job._validate(_val_ctx(env.root, support.validation_settings(), steps={}), None)

    # Clean BUILD_CHECKED -> SUCCEEDED (with repository_root=None)
    exec_ok = support.Executor(codes=(0, 0))
    job_ok = build_job(
        infer=support.Writer(semantic="supported"),
        executor_factory=lambda _u, _p: exec_ok,
        builds_factory=lambda _r: env.builds,
        repository_root=None,
    )
    ctx_ok = _val_ctx(env.root, support.validation_settings(), "att-ok")
    for validator in job_ok.input_validators:
        validator(ctx_ok, None)
    res_ok = job_ok.execute(ctx_ok)
    assert not res_ok["failed_units"], res_ok
    pub_ok = res_ok["outputs"]["acceptance.publish_handoff"]
    assert pub_ok["terminal_status"] == "SUCCEEDED"
    assert pub_ok["gaps"] == []
    val_summary = read_bound_json(env.root, pub_ok["artifact"])
    assert val_summary["items"][0]["status"] == Status.BUILD_CHECKED.value

    # Empty confirmed findings -> SKIPPED_NA
    env_empty = _seed_env(tmp_path / "empty", monkeypatch, candidate_count=0)
    job_empty = build_job(
        infer=support.Writer(),
        executor_factory=lambda _u, _p: support.Executor(),
        builds_factory=lambda _r: env_empty.builds,
    )
    res_empty = job_empty.execute(_val_ctx(env_empty.root, support.validation_settings(), "att-empty"))
    assert res_empty["outputs"]["acceptance.publish_handoff"]["terminal_status"] == "SKIPPED_NA"

    # Capped validation candidate + no_patch_proposal + manual_design_required (patch=None)
    def manual_writer(request, *, timeout_seconds):
        rel = request.task_input["task"]["accepted_evidence"][0]["relation_id"]
        return ModelResult(
            {"action": "final", "result": support.answer([rel], None, status="manual_design_required")},
            input_tokens=5,
            output_tokens=5,
        )

    env_multi = _seed_env(
        tmp_path / "multi",
        monkeypatch,
        candidate_count=3,
        plan_infer=manual_writer,
        plan_settings=support.planning_settings(max_candidates=1),
    )
    job_multi = build_job(
        infer=support.Writer(),
        executor_factory=lambda _u, _p: support.Executor(),
        builds_factory=lambda _r: env_multi.builds,
    )
    res_multi = job_multi.execute(_val_ctx(env_multi.root, support.validation_settings(max_candidates=2), "att-multi"))
    pub_multi = res_multi["outputs"]["acceptance.publish_handoff"]
    assert pub_multi["terminal_status"] == "COMPLETED_WITH_GAPS"
    items_multi = read_bound_json(env_multi.root, pub_multi["artifact"])["items"]
    assert items_multi[0]["reason"] == "proposal_requires_manual_design"
    assert items_multi[1]["reason"].startswith("no_patch_proposal:")
    assert items_multi[2]["reason"] == "validation_candidate_bound_reached"


def test_validate_patch_semantic_adapter_and_integrity_branches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 1. Semantic decisions: None (invalid output), contradicted, unresolved, and adapters=[] (static_checked)
    env = _seed_env(tmp_path / "sem", monkeypatch, candidate_count=1)
    for idx, (writer, adapters, expected_status, expected_reason) in enumerate(
        [
            (support.Writer(invalid=True), ["native_syntax"], Status.INCONCLUSIVE.value, "independent_semantic_review_unavailable"),
            (support.Writer(semantic="contradicted"), ["native_syntax"], Status.REJECTED.value, "analyst_assessed_contradicted"),
            (support.Writer(semantic="unresolved"), ["native_syntax"], Status.INCONCLUSIVE.value, "analyst_assessed_unresolved"),
            (support.Writer(semantic="supported"), [], Status.STATIC_CHECKED.value, "selected_static_checks_only"),
        ]
    ):
        job = build_job(
            infer=writer,
            executor_factory=lambda _u, _p: support.Executor(),
            builds_factory=lambda _r: env.builds,
        )
        res = job.execute(_val_ctx(env.root, support.validation_settings(adapters=adapters), f"att-sem-{idx}"))
        summary = read_bound_json(env.root, res["outputs"]["acceptance.publish_handoff"]["artifact"])
        assert summary["items"][0]["status"] == expected_status
        assert summary["items"][0]["reason"] == expected_reason

    # 2. Compiler outcomes: baseline_failed, patched_failed, unavailable, unsafe, and mutate -> IntegrityError
    for idx, (executor, expected_status, expected_reason) in enumerate(
        [
            (support.Executor(codes=(1, 0)), Status.INCONCLUSIVE.value, "baseline_build_failed"),
            (support.Executor(codes=(0, 1)), Status.REJECTED.value, "patched_build_failed"),
            (support.Executor(unavailable=True), Status.STATIC_CHECKED.value, "build_unavailable_static_checks_only"),
        ]
    ):
        job = build_job(
            infer=support.Writer(semantic="supported"),
            executor_factory=lambda _u, _p, ex=executor: ex,
            builds_factory=lambda _r: env.builds,
        )
        res = job.execute(_val_ctx(env.root, support.validation_settings(), f"att-comp-{idx}"))
        summary = read_bound_json(env.root, res["outputs"]["acceptance.publish_handoff"]["artifact"])
        assert summary["items"][0]["status"] == expected_status
        assert summary["items"][0]["reason"] == expected_reason

    # Unsafe replay command -> accepted_build_replay_unsafe
    def _unsafe_builds_fn(r, ws, man):
        b = AcceptedBuilds(r, loader=lambda _r: {"receipts": []})
        cmd = CompileCommand(("/bin/sh", "-c", "native/src/parse.c"), "native/src/parse.c", "c", ".", "exact")
        b.locate = lambda _n: Located(relay_unit(ws, man, compile_command=cmd, objects=()), "")
        return b

    env_unsafe = _seed_env(tmp_path / "unsafe-cmd", monkeypatch, candidate_count=1, builds_fn=_unsafe_builds_fn)
    res_unsafe_cmd = build_job(
        infer=support.Writer(semantic="supported"),
        executor_factory=lambda _u, _p: support.Executor(),
        builds_factory=lambda _r: env_unsafe.builds,
    ).execute(_val_ctx(env_unsafe.root, support.validation_settings(), "att-unsafe-cmd"))
    sum_unsafe = read_bound_json(env_unsafe.root, res_unsafe_cmd["outputs"]["acceptance.publish_handoff"]["artifact"])
    assert sum_unsafe["items"][0]["reason"] == "accepted_build_replay_unsafe"

    # Uncommissioned BuildProfile (image_user="root") -> accepted_build_profile_uncommissioned
    def _root_builds_fn(r, ws, man):
        base_b = support.builds_for(r, ws, man)
        u = base_b.locate("native/src/parse.c").unit
        b = AcceptedBuilds(r, loader=lambda _r: {"receipts": []})
        b.locate = lambda _n: Located(replace(u, image_user="root"), "")
        return b

    env_root = _seed_env(tmp_path / "root-prof", monkeypatch, candidate_count=1, builds_fn=_root_builds_fn)
    res_root = build_job(
        infer=support.Writer(semantic="supported"),
        executor_factory=lambda _u, _p: support.Executor(),
        builds_factory=lambda _r: env_root.builds,
    ).execute(_val_ctx(env_root.root, support.validation_settings(), "att-root-prof"))
    sum_root = read_bound_json(env_root.root, res_root["outputs"]["acceptance.publish_handoff"]["artifact"])
    assert sum_root["items"][0]["reason"] == "accepted_build_profile_uncommissioned"

    # Non-exact command basis -> patch_scope_not_covered_by_native_adapter
    def _inexact_builds_fn(r, ws, man):
        base_b = support.builds_for(r, ws, man)
        u = base_b.locate("native/src/parse.c").unit
        b = AcceptedBuilds(r, loader=lambda _r: {"receipts": []})
        b.locate = lambda _n: Located(replace(u, command=replace(u.command, basis="inferred")), "")
        return b

    env_inexact = _seed_env(tmp_path / "inexact", monkeypatch, candidate_count=1, builds_fn=_inexact_builds_fn)
    res_inexact = build_job(
        infer=support.Writer(semantic="supported"),
        executor_factory=lambda _u, _p: support.Executor(),
        builds_factory=lambda _r: env_inexact.builds,
    ).execute(_val_ctx(env_inexact.root, support.validation_settings(), "att-inexact"))
    sum_inexact = read_bound_json(env_inexact.root, res_inexact["outputs"]["acceptance.publish_handoff"]["artifact"])
    assert sum_inexact["items"][0]["reason"] == "patch_scope_not_covered_by_native_adapter"

    # Two distinct build units -> multi_build_proposal_requires_manual_validation
    def _multi_builds_fn(r, ws, man):
        b = AcceptedBuilds(r, loader=lambda _r: {"receipts": []})

        def _loc(name):
            cmd = CompileCommand(("/usr/bin/clang", "-c", f"/workspace/{name}"), name, "c", ".", "exact")
            u = relay_unit(ws, man, compile_command=cmd, objects=())
            return Located(replace(u, build_unit_id=f"bu-{name}"), "")

        b.locate = _loc
        return b

    env_multibu = _seed_env(
        tmp_path / "multibu",
        monkeypatch,
        candidate_count=1,
        extra_files={"native/src/other.c": "int y = 0;\n"},
        extra_entity_path="native/src/other.c",
        builds_fn=_multi_builds_fn,
    )
    res_nobuild = build_job(
        infer=support.Writer(semantic="supported"),
        executor_factory=lambda _u, _p: support.Executor(),
        builds_factory=lambda _r: env_multibu.builds,
    ).execute(_val_ctx(env_multibu.root, support.validation_settings(), "att-nobuild"))
    sum_nobuild = read_bound_json(env_multibu.root, res_nobuild["outputs"]["acceptance.publish_handoff"]["artifact"])
    assert sum_nobuild["items"][0]["reason"] == "multi_build_proposal_requires_manual_validation"

    # Re-pin env before WorkspaceLimit / mutate / PatchError checks
    monkeypatch.setattr(
        accepted_review,
        "load_accepted_review",
        lambda *_a, **_k: SimpleNamespace(document=copy.deepcopy(env.review_doc)),
    )
    monkeypatch.setattr(validation_inputs, "accepted_handoff", lambda _r, _j: env.accepted_box[0])

    # WorkspaceLimit caught -> manual_validation_required
    res_wslim = build_job(
        infer=support.Writer(semantic="supported"),
        executor_factory=lambda _u, _p: support.Executor(),
        builds_factory=lambda _r: env.builds,
    ).execute(_val_ctx(env.root, support.validation_settings(max_workspace_bytes=4), "att-wslim"))
    sum_wslim = read_bound_json(env.root, res_wslim["outputs"]["acceptance.publish_handoff"]["artifact"])
    assert sum_wslim["items"][0]["status"] == Status.MANUAL_VALIDATION_REQUIRED.value
    assert sum_wslim["items"][0]["reason"] == "workspace_byte_bound_reached"

    # Mutating compiler -> IntegrityError
    res_mut = build_job(
        infer=support.Writer(semantic="supported"),
        executor_factory=lambda _u, _p: support.Executor(mutate=True),
        builds_factory=lambda _r: env.builds,
    ).execute(_val_ctx(env.root, support.validation_settings(), "att-mut"))
    assert "assess.validate" in res_mut["failed_units"]

    # PatchError during apply_exact + merge-conflict static failure + unsafe build file change
    def conflict_writer(request, *, timeout_seconds):
        task = request.task_input["task"]
        rel = task["accepted_evidence"][0]["relation_id"]
        f0 = task["source_files"][0]
        old = "strcpy(b, s);"
        off = f0["text"].encode().index(old.encode())
        p = support.patch(f0["path"], f0["sha256"], old=old, new="<<<<<<< HEAD\n", start=off)
        return ModelResult({"action": "final", "result": support.answer([rel], p)}, input_tokens=5, output_tokens=5)

    env_conf = _seed_env(tmp_path / "conf", monkeypatch, candidate_count=1, plan_infer=conflict_writer)
    res_conf = build_job(
        infer=support.Writer(semantic="supported"),
        executor_factory=lambda _u, _p: support.Executor(),
        builds_factory=lambda _r: env_conf.builds,
    ).execute(_val_ctx(env_conf.root, support.validation_settings(), "att-conf"))
    sum_conf = read_bound_json(env_conf.root, res_conf["outputs"]["acceptance.publish_handoff"]["artifact"])
    assert sum_conf["items"][0]["status"] == Status.REJECTED.value
    assert sum_conf["items"][0]["reason"] == "static_patch_policy_failed"

    # PatchError caught when apply_exact raises PatchError
    monkeypatch.setattr(
        accepted_review,
        "load_accepted_review",
        lambda *_a, **_k: SimpleNamespace(document=copy.deepcopy(env.review_doc)),
    )
    monkeypatch.setattr(validation_inputs, "accepted_handoff", lambda _r, _j: env.accepted_box[0])
    orig_apply = validation_job.apply_exact
    monkeypatch.setattr(
        validation_job,
        "apply_exact",
        lambda *_a, **_k: (_ for _ in ()).throw(validation_job.PatchError("offset mismatch")),
    )
    res_pe = build_job(
        infer=support.Writer(semantic="supported"),
        executor_factory=lambda _u, _p: support.Executor(),
        builds_factory=lambda _r: env.builds,
    ).execute(_val_ctx(env.root, support.validation_settings(), "att-pe"))
    sum_pe = read_bound_json(env.root, res_pe["outputs"]["acceptance.publish_handoff"]["artifact"])
    assert sum_pe["items"][0]["status"] == Status.REJECTED.value
    assert sum_pe["items"][0]["reason"].startswith("patch_rejected:")

    # Undeclared edits during apply_exact -> IntegrityError
    monkeypatch.setattr(
        validation_job,
        "apply_exact",
        lambda p, dest, man, b: (orig_apply(p, dest, man, b), (dest / "extra.txt").write_text("x")),
    )
    res_undecl = build_job(
        infer=support.Writer(semantic="supported"),
        executor_factory=lambda _u, _p: support.Executor(),
        builds_factory=lambda _r: env.builds,
    ).execute(_val_ctx(env.root, support.validation_settings(), "att-undecl"))
    assert "assess.validate" in res_undecl["failed_units"]
    monkeypatch.setattr(validation_job, "apply_exact", orig_apply)

    # Unsafe build configuration change (CMakeLists.txt) -> unsafe_build_configuration_mutation
    def _cmake_builds_fn(r, ws, man):
        b = AcceptedBuilds(r, loader=lambda _r: {"receipts": []})
        cmd = CompileCommand(("/usr/bin/clang", "-c", "/workspace/CMakeLists.txt"), "CMakeLists.txt", "c", ".", "exact")
        b.locate = lambda _n: Located(relay_unit(ws, man, compile_command=cmd, objects=()), "")
        return b

    env_cmake = _seed_env(
        tmp_path / "cmake",
        monkeypatch,
        candidate_count=1,
        primary_path="CMakeLists.txt",
        builds_fn=_cmake_builds_fn,
    )
    res_cmake = build_job(
        infer=support.Writer(semantic="supported"),
        executor_factory=lambda _u, _p: support.Executor(),
        builds_factory=lambda _r: env_cmake.builds,
    ).execute(_val_ctx(env_cmake.root, support.validation_settings(), "att-cmake"))
    sum_cmake = read_bound_json(env_cmake.root, res_cmake["outputs"]["acceptance.publish_handoff"]["artifact"])
    assert sum_cmake["items"][0]["reason"] == "unsafe_build_configuration_mutation"

    # Cleanup failure -> IntegrityError
    monkeypatch.setattr(
        validation_job,
        "cleanup",
        lambda _s, _r: {"workspace": "scratch", "created": True, "removed": False, "error": "OSError:busy"},
    )
    res_clean_err = build_job(
        infer=support.Writer(semantic="supported"),
        executor_factory=lambda _u, _p: support.Executor(),
        builds_factory=lambda _r: env_cmake.builds,
    ).execute(_val_ctx(env_cmake.root, support.validation_settings(), "att-clean-err"))
    assert "assess.validate" in res_clean_err["failed_units"]
    monkeypatch.setattr(validation_job, "cleanup", cleanup)

    # Publish drift detection (planning_handoff changed between load and publish, and outcomes mismatch)
    v_job = build_job(
        infer=support.Writer(semantic="supported"),
        executor_factory=lambda _u, _p: support.Executor(),
        builds_factory=lambda _r: env_cmake.builds,
    )
    u_by_id = {u.unit_id: u for u in v_job.units}
    ctx_drift = _val_ctx(env_cmake.root, support.validation_settings(), "att-drift")
    from appsec_review.runtime import UnitContext

    u_load_dir = ctx_drift.attempt_root / "steps" / "load" / "verify_inputs"
    u_load_dir.mkdir(parents=True)
    out_load = u_by_id["load.verify_inputs"].handler(
        UnitContext(ctx_drift, "load.verify_inputs", "load", "verify_inputs", u_load_dir, {})
    )
    u_val_dir = ctx_drift.attempt_root / "steps" / "assess" / "validate"
    u_val_dir.mkdir(parents=True)
    out_val = u_by_id["assess.validate"].handler(
        UnitContext(ctx_drift, "assess.validate", "assess", "validate", u_val_dir, {"load.verify_inputs": out_load})
    )

    bad_outcomes = _write(env_cmake.root, "bad-outcomes.json", {"items": []})
    u_pub_dir = ctx_drift.attempt_root / "steps" / "acceptance" / "publish_handoff"
    u_pub_dir.mkdir(parents=True)
    with pytest.raises(IntegrityError, match="do not exactly account"):
        u_by_id["acceptance.publish_handoff"].handler(
            UnitContext(
                ctx_drift,
                "acceptance.publish_handoff",
                "acceptance",
                "publish_handoff",
                u_pub_dir,
                {"load.verify_inputs": out_load, "assess.validate": {**out_val, "artifact": bad_outcomes}},
            )
        )

    env_cmake.accepted_box[0] = AcceptedHandoff(
        REMEDIATION_PLANNING_JOB,
        env_cmake.handoff_doc,
        "f" * 64,
        env_cmake.handoff_ref["path"],
    )
    with pytest.raises(IntegrityError, match="inputs changed during validation"):
        u_by_id["acceptance.publish_handoff"].handler(
            UnitContext(
                ctx_drift,
                "acceptance.publish_handoff",
                "acceptance",
                "publish_handoff",
                u_pub_dir,
                {"load.verify_inputs": out_load, "assess.validate": out_val},
            )
        )
