"""Code-level unit tests for job_cpg_analysis.job handlers, checkpoints, exports, and publication."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest

from appsec_review import seeding
from appsec_review.config import load_config
from appsec_review.config.seeding import SeededSettings
from appsec_review.indexing.inventory import Claim, FileClaims, runtime_claims, scan_run_tree
from appsec_review.jobs.cpp_index_scopes import CheckpointIntegrityError, IndexScope, SCOPE_SCHEMA
from appsec_review.jobs.cpp_seeded import Selection
from appsec_review.jobs.job_cpg_analysis import JOERN_DISABLED, JOERN_GAP, build_job, seeded
from appsec_review.jobs.job_cpg_analysis.datasets import DATASETS
import appsec_review.jobs.job_cpg_analysis.job as job_mod
from appsec_review.jobs.job_cpg_analysis.job import (
    JOB_ID,
    SCHEMA,
    TOOL_ID,
    _enabled,
    _export,
    _generate,
    _reuse,
)
from appsec_review.observability import EventLog
from appsec_review.retrieval import write_manifest
from appsec_review.storage import atomic_json, canonical_json, file_sha256, run_artifact


REPO_ROOT = Path(__file__).resolve().parents[3]
RECORDED_EXPORT = REPO_ROOT / "tests" / "fixtures" / "seeded_clang" / "recorded" / "cpg" / "export"
SNAPSHOT = "a" * 64


def _make_scope_and_unit(
    base: Path,
    *,
    unit_id: str = "generate.scopes",
    settings_override: dict[str, Any] | None = None,
    outputs: dict[str, Any] | None = None,
) -> tuple[Path, IndexScope, Any]:
    run_root = base / "run"
    target_root = base / "target"
    src_rel = "native/a.cpp"
    content = "int main() { return 0; }\n"
    tfile = target_root / src_rel
    tfile.parent.mkdir(parents=True, exist_ok=True)
    tfile.write_text(content, encoding="utf-8")
    sha = file_sha256(tfile)

    case_id = "case-native"
    case_root = run_root / "data" / "cpp" / "projects" / case_id
    sfile = case_root / "source" / "a.cpp"
    sfile.parent.mkdir(parents=True, exist_ok=True)
    sfile.write_text(content, encoding="utf-8")
    entry = {"target_path": src_rel, "scratch_path": "source/a.cpp", "sha256": sha}

    cdb_rows = [{"target_path": src_rel, "arguments": ["clang++", "-c", "/scratch/source/a.cpp"]}]
    cdb_path = case_root / "compile_commands.json"
    cdb_path.write_text(json.dumps(cdb_rows), encoding="utf-8")
    cdb_art = run_artifact(run_root, cdb_path)

    scope_id = "cpp-scope-" + hashlib.sha256(
        canonical_json(
            {
                "schema": SCOPE_SCHEMA,
                "case_id": case_id,
                "case_snapshot": SNAPSHOT,
                "compile_database": cdb_art["sha256"],
            }
        )
    ).hexdigest()[:24]
    scope = IndexScope(
        scope_id=scope_id,
        case_id=case_id,
        project_id="cpp:native",
        root="native",
        case_snapshot=SNAPSHOT,
        case_root=case_root,
        files=(entry,),
        compile_commands=tuple(cdb_rows),
        compile_database=cdb_art,
        _by_relative={"a.cpp": entry},
    )

    upstream_manifest = run_root / "data" / "indices" / "manifests" / "upstream.json"
    write_manifest(
        upstream_manifest,
        run_id="2026-11-15-0002",
        target_snapshot=SNAPSHOT,
        target_root=target_root,
        indexes=[],
    )

    config = load_config(REPO_ROOT / "appsec-review.toml")
    merged = dict(config.job(JOB_ID).settings)
    merged["enabled"] = True
    merged["max_cpg_bytes"] = 4096
    if settings_override:
        merged.update(settings_override)
    job_cfg = SimpleNamespace(
        steps=config.job(JOB_ID).steps,
        step=config.job(JOB_ID).step,
        settings=MappingProxyType(merged),
    )

    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / "attempt_0001"
    step_name, task_name = unit_id.split(".", 1)
    unit_root = attempt_root / "steps" / step_name / "tasks" / task_name
    unit_root.mkdir(parents=True, exist_ok=True)
    events = EventLog(run_root / "metadata" / "events.jsonl")
    store = dict(outputs or {})
    job_ctx = SimpleNamespace(
        job_id=JOB_ID,
        run_id="2026-11-15-0002",
        attempt_id="attempt_0001",
        attempt_root=attempt_root,
        run_root=run_root,
        target_root=target_root,
        repository_root=REPO_ROOT,
        source_fingerprint=SNAPSHOT,
        input_manifest_path=upstream_manifest,
        input_manifest_sha256=file_sha256(upstream_manifest),
        config=job_cfg,
        events=events,
        review_policy=config.review_policy,
    )
    unit = SimpleNamespace(
        unit_id=unit_id,
        unit_root=unit_root,
        job=job_ctx,
        output=lambda key: store[key],
    )
    return run_root, scope, unit


def _fake_execution(
    run_root: Path,
    scratch: Path,
    *,
    cpg_bytes: bytes | None = b"valid-cpg",
    cpg_symlink_to: Path | None = None,
    exit_code: int = 0,
    timed_out: bool = False,
    oom_killed: bool = False,
    limit_reached: bool = False,
    limit_bytes: int | None = 4097,
) -> dict[str, Any]:
    scratch.mkdir(parents=True, exist_ok=True)
    cdb = scratch / "compile_commands.json"
    cdb.write_text("[]", encoding="utf-8")
    rec = scratch / "execution.json"
    rec.write_text('{"tool_id":"tool-joern"}', encoding="utf-8")
    cpg_path = scratch / "cpg.bin"
    if cpg_symlink_to is not None:
        cpg_path.symlink_to(cpg_symlink_to)
    elif cpg_bytes is not None:
        cpg_path.write_bytes(cpg_bytes)
    return {
        "receipt": run_artifact(run_root, rec),
        "compile_database": run_artifact(run_root, cdb),
        "image_id": "appsec-review/tool-joern:4.0.630",
        "image_digest": "sha256:" + "c" * 64,
        "argv_identity": "argv-sha",
        "exit_code": exit_code,
        "timed_out": timed_out,
        "oom_killed": oom_killed,
        "file_size_limit_bytes": limit_bytes,
        "file_size_limit_reached": limit_reached,
    }


def test_enabled_flag_rejects_non_boolean(tmp_path: Path) -> None:
    _, _, unit = _make_scope_and_unit(tmp_path, settings_override={"enabled": "yes"})
    with pytest.raises(ValueError, match="jobs.job_cpg_analysis.settings.enabled must be a boolean"):
        _enabled(unit)


@pytest.mark.parametrize(
    ("case", "kwargs", "expected_gap", "expected_disposition"),
    [
        ("limit_flag", {"cpg_bytes": b"part", "limit_reached": True}, "reached the 4096-byte CPG limit", "LIMIT_REACHED"),
        ("oversized", {"cpg_bytes": b"x" * 4097, "limit_reached": False}, "reached the 4096-byte CPG limit", "LIMIT_REACHED"),
        ("timed_out", {"cpg_bytes": None, "timed_out": True}, "Joern c2cpg timed out before a CPG was produced", "NOT_PRODUCED"),
        ("oom_killed", {"cpg_bytes": None, "oom_killed": True}, "Joern c2cpg was OOM-killed before a CPG was produced", "NOT_PRODUCED"),
        ("nonzero_exit", {"cpg_bytes": None, "exit_code": 7}, "Joern c2cpg exited with status 7", "NOT_PRODUCED"),
        ("empty_cpg", {"cpg_bytes": b""}, "Joern c2cpg produced no CPG", "NOT_PRODUCED"),
        ("missing_cpg", {"cpg_bytes": None}, "Joern c2cpg produced no CPG", "NOT_PRODUCED"),
    ],
)
def test_generate_handles_all_c2cpg_failure_and_limit_dispositions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    kwargs: dict[str, Any],
    expected_gap: str,
    expected_disposition: str,
) -> None:
    run_root, scope, unit = _make_scope_and_unit(tmp_path / case)
    monkeypatch.setattr(
        job_mod,
        "execute_scope_tool",
        lambda _u, _s, _t, _argv, scratch, _ef, **_kw: _fake_execution(run_root, scratch, **kwargs),
    )
    # Pass executor_factory=None on one case to exercise tool_identity(repository_root, TOOL_ID)
    ef = None if case == "missing_cpg" else (lambda _u: object())
    result = _generate(unit, scope, ef)
    assert result["cpg"] is None
    assert result["resource_limit"]["disposition"] == expected_disposition
    assert any(expected_gap in g for g in result["gaps"])
    assert JOERN_GAP in result["gaps"]
    assert not (run_root / "data" / "code-index" / "joern" / scope.scope_id / "run" / "cpg.bin").exists()


def test_generate_unlinks_symlinked_cpg_and_reuses_checkpoint_plus_detects_manifest_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 1. Symlinked cpg.bin is rejected as non-regular and unlinked, and failed whole-program checkpoint reuses cleanly (cpg is None).
    run_root, scope, unit = _make_scope_and_unit(tmp_path / "sym")
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"secret")
    calls = 0

    def _symlink_exec(_u, _s, _t, _argv, scratch, _ef, **_kw):
        nonlocal calls
        calls += 1
        return _fake_execution(run_root, scratch, cpg_bytes=None, cpg_symlink_to=outside)

    monkeypatch.setattr(job_mod, "execute_scope_tool", _symlink_exec)
    first = _generate(unit, scope, lambda _u: object())
    assert first["cpg"] is None
    assert calls == 1
    reused_none = _generate(unit, scope, lambda _u: object())
    assert reused_none["checkpoint_reused"] is True and calls == 1

    # 2. Successful whole-program CPG reuses cleanly, then rejects manifest mismatch and escaped CPG path.
    run_root2, scope2, unit2 = _make_scope_and_unit(tmp_path / "ok")
    monkeypatch.setattr(
        job_mod,
        "execute_scope_tool",
        lambda _u, _s, _t, _argv, scratch, _ef, **_kw: _fake_execution(run_root2, scratch, cpg_bytes=b"cpg-bytes"),
    )
    produced = _generate(unit2, scope2, lambda _u: object())
    assert produced["cpg"] is not None
    reused_ok = _generate(unit2, scope2, lambda _u: object())
    assert reused_ok["checkpoint_reused"] is True

    root2 = run_root2 / "data" / "code-index" / "joern" / scope2.scope_id
    ckpt_doc = json.loads((root2 / "checkpoint.json").read_text(encoding="utf-8"))
    identity = ckpt_doc["identity"]

    # Tamper cpg-manifest.json execution field without changing its sha256 in checkpoint -> caught by _reuse!
    manifest_path = run_root2 / produced["cpg_manifest"]["path"]
    orig_manifest_bytes = manifest_path.read_bytes()
    bad_manifest = json.loads(orig_manifest_bytes.decode("utf-8"))
    bad_manifest["execution"] = "not-a-dict"
    manifest_path.write_text(json.dumps(bad_manifest), encoding="utf-8")
    # Update checkpoint's cpg_manifest artifact record so scope_checkpoint passes hash check and reaches _reuse's bound check
    tampered_ckpt = json.loads(json.dumps(ckpt_doc))
    tampered_ckpt["result"]["cpg_manifest"] = run_artifact(run_root2, manifest_path)
    (root2 / "checkpoint.json").write_text(json.dumps(tampered_ckpt), encoding="utf-8")
    with pytest.raises(CheckpointIntegrityError, match="CPG manifest does not match its checkpoint"):
        _reuse(unit2, root2, identity, scope2)

    # Escape CPG path outside `<root>/run/` while keeping valid artifact hash + matching manifest
    escaped_cpg = root2 / "outside-run.bin"
    escaped_cpg.write_bytes(b"escaped")
    escaped_art = run_artifact(run_root2, escaped_cpg)
    escaped_manifest = json.loads(orig_manifest_bytes.decode("utf-8"))
    escaped_manifest["cpg"] = escaped_art
    manifest_path.write_text(json.dumps(escaped_manifest), encoding="utf-8")
    escaped_ckpt = json.loads(json.dumps(ckpt_doc))
    escaped_ckpt["result"]["cpg"] = escaped_art
    escaped_ckpt["result"]["cpg_manifest"] = run_artifact(run_root2, manifest_path)
    (root2 / "checkpoint.json").write_text(json.dumps(escaped_ckpt), encoding="utf-8")
    with pytest.raises(CheckpointIntegrityError, match="checkpointed CPG left its scope root"):
        _reuse(unit2, root2, identity, scope2)


@pytest.mark.parametrize(
    ("mode", "expected_gap"),
    [
        ("limit", f"Joern export reached the {seeded.MAX_EXPORT_FILE_BYTES}-byte per-file limit"),
        ("timeout", "Joern export timed out; no seeded CPG fact is published"),
        ("oom", "Joern export was OOM-killed; no seeded CPG fact is published"),
        ("exit", "Joern export exited with status 9"),
        ("no_dir", "Joern export produced no output directory"),
        ("symlink_dir", "Joern export produced no output directory"),
        ("empty_methods", "cpg_export_no_methods"),
    ],
)
def test_export_covers_all_failure_and_empty_method_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, expected_gap: str
) -> None:
    run_root, scope, unit = _make_scope_and_unit(tmp_path / mode)
    root = run_root / "data" / "code-index" / "joern" / scope.scope_id
    cpg_path = tmp_path / mode / "cpg.bin"
    cpg_path.write_bytes(b"cpg")

    def _fake_export_exec(_u, _s, _t, _argv, scratch, _ef, **_kw):
        (scratch / "cpg.bin").parent.mkdir(parents=True, exist_ok=True)
        (scratch / "cpg.bin").write_bytes(b"staged")
        if mode == "symlink_dir":
            real_dir = tmp_path / mode / "real-export"
            real_dir.mkdir(parents=True, exist_ok=True)
            (scratch / "export").symlink_to(real_dir)
        elif mode == "empty_methods":
            (scratch / "export").mkdir(parents=True, exist_ok=True)
        return _fake_execution(
            run_root,
            scratch,
            cpg_bytes=None,
            limit_reached=(mode == "limit"),
            timed_out=(mode == "timeout"),
            oom_killed=(mode == "oom"),
            exit_code=(9 if mode == "exit" else 0),
        )

    monkeypatch.setattr(job_mod, "execute_scope_tool", _fake_export_exec)
    record, artifacts, gaps = _export(unit, scope, root, cpg_path, lambda _u: object())
    assert record is None
    assert len(artifacts) == 2
    assert any(expected_gap in g for g in gaps)
    assert not (root / "export-run" / "cpg.bin").exists()


def test_seeded_empty_selection_skips_container_and_records_selection_gaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_root, scope, unit = _make_scope_and_unit(tmp_path)
    seeded_settings = SeededSettings(mode="seeded", depth=1, seed_limit=10)
    seed_item = seeding.Seed("missing.cpp", 5, 5)
    scope_seeds = seeding.ScopeSeeds(scope_id=scope.case_id, seeds=(seed_item,), total=1)
    plan = seeding.SeedPlan(scopes={scope.case_id: scope_seeds})
    empty_selection = Selection(
        rows=(),
        container_rows=(),
        by_seed={},
        reasons={("missing.cpp", 5, 5): "no_compile_unit"},
        gaps=("seed_selection_empty: no compile unit matched missing.cpp",),
    )
    monkeypatch.setattr(job_mod.cpp_seeded, "select", lambda *_a, **_kw: empty_selection)
    called = False

    def _never(*_a, **_kw):
        nonlocal called
        called = True

    monkeypatch.setattr(job_mod, "execute_scope_tool", _never)
    res = _generate(unit, scope, lambda _u: object(), seeded.Run(seeded_settings, plan, scope_seeds))
    assert called is False
    assert res["execution"] is None
    assert res["cpg"] is None
    assert any("seed_selection_empty" in g for g in res["gaps"])


def test_build_job_load_generate_and_publish_units_plus_dataset_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 1. load rejects mismatched source_fingerprint
    run_root, scope, load_unit = _make_scope_and_unit(tmp_path / "mismatch", unit_id="load.accepted_cpp")
    job = build_job(executor_factory=lambda _u: object())
    by_id = {u.unit_id: u.handler for u in job.units}

    monkeypatch.setattr(
        job_mod,
        "accepted_cpp_scopes",
        lambda _r: ({"handoff": {"source_fingerprint": "b" * 64}, "handoff_sha256": "1" * 64, "manifest": None}, [scope], {}),
    )
    with pytest.raises(ValueError, match=r"CPG target snapshot differs from the accepted C\+\+ build"):
        by_id["load.accepted_cpp"](load_unit)

    # 2. Full whole-program enabled pipeline (load -> generate -> publish) + scan_run_tree dataset audit
    run_root2, scope2, load_u2 = _make_scope_and_unit(
        tmp_path / "whole",
        unit_id="load.accepted_cpp",
        settings_override={"enabled": True, "seeded": {"mode": "whole_program"}},
    )
    accepted_payload = {
        "handoff": {"source_fingerprint": SNAPSHOT},
        "handoff_sha256": "2" * 64,
        "manifest": {"path": load_u2.job.input_manifest_path.relative_to(run_root2).as_posix(), "sha256": load_u2.job.input_manifest_sha256},
    }
    unavailable_map = {"case-broken": "compile failed"}
    monkeypatch.setattr(job_mod, "accepted_cpp_scopes", lambda _r: (accepted_payload, [scope2], dict(unavailable_map)))
    monkeypatch.setattr(
        job_mod,
        "execute_scope_tool",
        lambda _u, _s, _t, _argv, scratch, _ef, **_kw: _fake_execution(run_root2, scratch, cpg_bytes=b"whole-cpg"),
    )

    loaded_out = dict(by_id["load.accepted_cpp"](load_u2))
    assert len(loaded_out["scopes"]) == 1 and loaded_out["unavailable"] == unavailable_map

    # Scope drift between load and generate is rejected
    _, _, drift_unit = _make_scope_and_unit(
        tmp_path / "whole",
        unit_id="generate.scopes",
        outputs={"load.accepted_cpp": {"scopes": [{"scope_id": "cpp-scope-different"}]}},
    )
    with pytest.raises(ValueError, match="accepted C\\+\\+ scopes changed between load and generate"):
        by_id["generate.scopes"](drift_unit)

    # Seeded mode enabled inside generate() exercises plan_for / run_for non-None branch!
    _, _, gen_seeded = _make_scope_and_unit(
        tmp_path / "whole",
        unit_id="generate.scopes",
        settings_override={"enabled": True, "seeded": {"mode": "seeded", "depth": 1}},
        outputs={"load.accepted_cpp": loaded_out},
    )
    seeded_plan = seeding.SeedPlan(
        scopes={scope2.case_id: seeding.ScopeSeeds(scope_id=scope2.case_id, seeds=())},
    )
    monkeypatch.setattr(job_mod.cpp_seeded, "plan_for", lambda *_a, **_kw: seeded_plan)
    seeded_gen_out = dict(by_id["generate.scopes"](gen_seeded))
    assert seeded_gen_out["terminal_status"] == "COMPLETED_WITH_GAPS"

    # Whole-program generate -> publish -> scan_run_tree ownership check
    _, _, gen_whole = _make_scope_and_unit(
        tmp_path / "whole2",
        unit_id="generate.scopes",
        settings_override={"enabled": True, "seeded": {"mode": "whole_program"}},
    )
    run_root3 = gen_whole.job.run_root
    scope3 = IndexScope(
        scope_id=scope2.scope_id,
        case_id=scope2.case_id,
        project_id=scope2.project_id,
        root=scope2.root,
        case_snapshot=scope2.case_snapshot,
        case_root=run_root3 / "data" / "cpp" / "projects" / scope2.case_id,
        files=scope2.files,
        compile_commands=scope2.compile_commands,
        compile_database=gen_whole.job.input_manifest_path,  # replaced below
        _by_relative=scope2._by_relative,
    )
    run_root3, scope3, load_u3 = _make_scope_and_unit(
        tmp_path / "whole3",
        unit_id="load.accepted_cpp",
        settings_override={"enabled": True, "seeded": {"mode": "whole_program"}},
    )
    accepted3 = {
        "handoff": {"source_fingerprint": SNAPSHOT},
        "handoff_sha256": "3" * 64,
        "manifest": {"path": load_u3.job.input_manifest_path.relative_to(run_root3).as_posix(), "sha256": load_u3.job.input_manifest_sha256},
    }
    monkeypatch.setattr(job_mod, "accepted_cpp_scopes", lambda _r: (accepted3, [scope3], dict(unavailable_map)))
    monkeypatch.setattr(
        job_mod,
        "execute_scope_tool",
        lambda _u, _s, _t, _argv, scratch, _ef, **_kw: _fake_execution(run_root3, scratch, cpg_bytes=b"whole-cpg-3"),
    )
    loaded3 = dict(by_id["load.accepted_cpp"](load_u3))
    gen_u3 = SimpleNamespace(
        unit_id="generate.scopes",
        unit_root=load_u3.job.attempt_root / "steps" / "generate" / "tasks" / "scopes",
        job=load_u3.job,
        output=lambda k: {"load.accepted_cpp": loaded3}[k],
    )
    gen_u3.unit_root.mkdir(parents=True, exist_ok=True)
    generated3 = dict(by_id["generate.scopes"](gen_u3))
    assert generated3["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("case-broken: compile failed" in g for g in generated3["gaps"])

    pub_u3 = SimpleNamespace(
        unit_id="acceptance.publish_handoff",
        unit_root=load_u3.job.attempt_root / "steps" / "acceptance" / "tasks" / "publish_handoff",
        job=load_u3.job,
        output=lambda k: {"load.accepted_cpp": loaded3, "generate.scopes": generated3}[k],
    )
    pub_u3.unit_root.mkdir(parents=True, exist_ok=True)
    published3 = dict(by_id["acceptance.publish_handoff"](pub_u3))
    assert published3["schema"] == SCHEMA
    assert published3["counts"] == {"scopes": 1, "disabled_scopes": 0, "cpgs_generated": 1, "observations": 0}

    # Verify dataset ownership across the job's attempt and data/code-index/joern tree
    config = load_config(REPO_ROOT / "appsec-review.toml")
    steps = list(config.job(JOB_ID).steps)
    claims = runtime_claims({JOB_ID: steps}) + [
        Claim(JOB_ID, item.step, item.output_kind, item) for item in DATASETS
    ]
    tree = scan_run_tree(run_root3, FileClaims(claims), max_files=100_000)
    unowned_job_files = [
        rel
        for rel in tree.unaccounted
        if rel.startswith((f"data/jobs/{JOB_ID}/", "data/code-index/joern/"))
    ]
    assert unowned_job_files == []
    assert tree.claim_errors == []

    # 3. Empty scopes + empty unavailable produces NOT_APPLICABLE for both disabled and enabled modes!
    monkeypatch.setattr(job_mod, "accepted_cpp_scopes", lambda _r: (accepted3, [], {}))
    _, _, empty_dis = _make_scope_and_unit(
        tmp_path / "empty_dis",
        unit_id="generate.scopes",
        settings_override={"enabled": False},
        outputs={"load.accepted_cpp": {"scopes": [], "unavailable": {}}},
    )
    out_dis = by_id["generate.scopes"](empty_dis)
    assert out_dis["terminal_status"] == "NOT_APPLICABLE" and out_dis["gaps"] == []

    _, _, empty_en = _make_scope_and_unit(
        tmp_path / "empty_en",
        unit_id="generate.scopes",
        settings_override={"enabled": True},
        outputs={"load.accepted_cpp": {"scopes": [], "unavailable": {}}},
    )
    out_en = by_id["generate.scopes"](empty_en)
    assert out_en["terminal_status"] == "NOT_APPLICABLE" and out_en["scopes"] == []
