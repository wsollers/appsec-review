"""Direct per-unit handler tests for job_inference_security_review (job.py + audit.py)."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
from types import MappingProxyType, SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_inference_security_review import audit as job_audit
from appsec_review.jobs.job_inference_security_review.audit import AuditInputs
from appsec_review.jobs.job_inference_security_review.datasets import DATASETS
from appsec_review.jobs.job_inference_security_review.job import JOB_ID, TOPOLOGY, _read, build_job
from appsec_review.observability import EventLog
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.review.decision_audit.publication import AuditUnavailable
from appsec_review.review.models import IntegrityError
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.job import JobContext
from appsec_review.runtime.units import UnitContext
from appsec_review.storage import atomic_json, bounded_file_lock, file_sha256
from appsec_review.storage.shared import publication_scope
from appsec_review.storage.validation import validation_scope
from tests.fixtures.inference_review.acceptance import ROOT
from tests.fixtures.inference_review.fake_infer import ScriptedInfer
from tests.review.test_attack_chain_job import ChainInfer
from tests.review.test_team_handler import (
    NARRATIVES,
    build_accepted_index_set,
    job_tables,
    write_config,
)

EARLY_UNITS = (
    "scope.accept_manifest",
    "scope.assemble_scope",
    "triage.lead_severity",
    "packages.plan_hunt_campaign",
    "packages.assemble_lead_packages",
    "packages.assemble_hunt_packages",
    "lead_review.teams",
    "hunt_review.teams",
    "merge.claims",
    "adjudicate.apply_policy",
    "scoring.score_claims",
)

LATE_UNITS = (
    "attack_chains.compose_candidates",
    "attack_chains.refute_edges",
    "attack_chains.verify_weakest_links",
    "completeness.audit",
    "publication.publish_claim_ledger",
    "publication.publish_handoff",
)


@pytest.fixture(autouse=True)
def _no_fsync_in_unit_handlers(monkeypatch) -> None:
    # Storage durability is tested in storage unit/integration suites; unit handler tests check semantics.
    monkeypatch.setattr(os, "fsync", lambda _fd: None)


def _fast_infer(base_infer, *, zero_claims: bool = False):
    """Fast deterministic model stub that exercises every unit contract in <2s."""
    proposed_once: list[str] = []

    def _call(request, *, timeout_seconds):
        payload = request.task_input.get("input") or {}
        if request.role in {"red_team_analyst", "hypothesis_hunter"} and isinstance(payload.get("package"), dict):
            pkg = payload["package"]
            if zero_claims or pkg.get("kind") == "hunt" or proposed_once:
                return base_infer._red(request, [])
            proposed_once.append(request.cell_id)
            return base_infer(request, timeout_seconds=timeout_seconds)
        if request.role == "blue_team_refuter":
            return ScriptedInfer._final({"stance": "unresolved", "why": NARRATIVES["blue-guard"]})
        if request.role == "independent_verifier":
            return ScriptedInfer._final(
                {"disposition": "insufficient_evidence", "per_predicate": {}, "why": NARRATIVES["verifier"]}
            )
        return base_infer(request, timeout_seconds=timeout_seconds)

    return ChainInfer(inner=_call)


def _fast_settings(base_settings, *, triage_enabled: bool = False, budget_packages: int = 1):
    return replace(
        base_settings,
        teams=replace(base_settings.teams, review_teams=1, red_per_team=1, blue_per_team=1, verifier_per_team=1),
        lanes=replace(
            base_settings.lanes,
            lead_admission=("critical", "high", "unknown"),
            lead_admission_kev=False,
            hunt_max_units=1,
        ),
        rounds=replace(base_settings.rounds, max_rounds=1, stable_rounds_required=1, max_attack_chains=1),
        budgets=replace(base_settings.budgets, budget_team_packages=budget_packages),
        triage=replace(base_settings.triage, enabled=triage_enabled),
        result_cache=replace(base_settings.result_cache, enabled=False),
    )


def _make_job_ctx(run_root: Path, config_path: Path, run_id: str, job, *, typed_settings=None, attempt_id: str = "attempt-u1") -> JobContext:
    manifest_doc = json.loads((run_root / "data" / "configuration" / "manifest.json").read_text(encoding="utf-8"))
    resolved_doc = json.loads((run_root / "data" / "configuration" / "resolved.json").read_text(encoding="utf-8"))
    with validation_scope(run_root):
        in_manifest_path, in_manifest_sha = resolve_accepted_manifest(run_root)
    target_snapshot = json.loads(in_manifest_path.read_text(encoding="utf-8"))["target_snapshot"]

    cfg = load_config(config_path).job(JOB_ID)
    cfg = replace(
        cfg,
        settings=resolved_doc["jobs"][JOB_ID]["settings"],
        typed_settings=typed_settings if typed_settings is not None else cfg.typed_settings,
    )
    upstream = {
        p.parent.name: json.loads(p.read_bytes())["handoff_sha256"]
        for p in sorted((run_root / "data" / "jobs").glob("*/latest.json"))
        if p.parent.name != JOB_ID
    }
    attempt_rel = f"data/jobs/{JOB_ID}/attempts/{attempt_id}"
    attempt_root = run_root / attempt_rel
    attempt_root.mkdir(parents=True, exist_ok=True)
    (attempt_root / "claim.json").write_text(
        json.dumps(
            {
                "schema": "appsec-review/attempt-claim/1",
                "run_id": run_id,
                "job_id": JOB_ID,
                "attempt_id": attempt_id,
                "attempt_path": attempt_rel,
                "orchestration": {},
                "repository_root": str(ROOT),
                "source_fingerprint": "none",
                "evidence_target_snapshot": target_snapshot,
                "input_manifest_path": in_manifest_path.relative_to(run_root).as_posix(),
                "input_manifest_sha256": in_manifest_sha,
                "resolved_config_sha256": manifest_doc["resolved_sha256"],
                "upstream_handoffs": upstream,
                "dataset_contract": dataset_contract(JOB_ID, tuple(TOPOLOGY), DATASETS),
            }
        ),
        encoding="utf-8",
    )
    return JobContext(
        run_id=run_id,
        attempt_id=attempt_id,
        trigger="cli",
        repository_root=ROOT,
        run_root=run_root,
        attempt_root=attempt_root,
        metadata_root=attempt_root / "meta",
        orchestration={},
        config=cfg,
        events=EventLog(attempt_root / "events.jsonl"),
        evidence_target_snapshot=target_snapshot,
        upstream_handoffs=MappingProxyType(upstream),
        contract=job.contract,
        source_fingerprint="none",
        input_manifest_path=in_manifest_path,
        input_manifest_sha256=in_manifest_sha,
    )


def _run_unit(job, job_ctx: JobContext, unit_id: str, outputs: dict) -> dict:
    unit = next(item for item in job.units if item.unit_id == unit_id)
    step_id, task_id = unit_id.split(".", 1)
    unit_root = job_ctx.attempt_root / "steps" / step_id / "tasks" / task_id
    unit_root.mkdir(parents=True, exist_ok=True)
    u_ctx = UnitContext(
        job=job_ctx,
        unit_id=unit_id,
        step_id=step_id,
        task_id=task_id,
        unit_root=unit_root,
        outputs=outputs,
    )
    with publication_scope(job_ctx):
        return dict(unit.handler(u_ctx))


@pytest.fixture(scope="session")
def _index_template(tmp_path_factory):
    basetemp = Path(tmp_path_factory.getbasetemp())
    session_root = basetemp.parent if basetemp.name.startswith("popen-gw") else basetemp
    # Reuse team-handler-template if already materialized on this xdist session, else build minimal index set.
    shared_ready = session_root / "team-handler-template" / "ready.json"
    if shared_ready.is_file():
        meta = json.loads(shared_ready.read_text(encoding="utf-8"))
        return SimpleNamespace(
            base=session_root / "team-handler-template",
            run_id=meta["run_id"],
            ids=dict(meta["ids"]),
        )
    base = session_root / "isr-unit-index-template"
    ready = base / "ready.json"
    with pytest.MonkeyPatch.context() as mp:
        mp.delenv("APPSEC_REVIEW_CONFIG_OVERLAY", raising=False)
        mp.setattr(os, "fsync", lambda _fd: None)
        with bounded_file_lock(session_root / "isr-unit-index-template.lock", 60.0):
            if not ready.is_file():
                shutil.rmtree(base, ignore_errors=True)
                base.mkdir(parents=True, exist_ok=True)
                config = write_config(
                    base,
                    base / "runs",
                    overrides={"backoff_seconds": [0]},
                    extra=job_tables("job_third_party_data_sync"),
                )
                built = build_accepted_index_set(base, config=config, publish_v1_packages=False)
                ready.write_text(json.dumps({"run_id": built.run_id, "ids": dict(built.ids)}), encoding="utf-8")
    meta = json.loads(ready.read_text(encoding="utf-8"))
    return SimpleNamespace(base=base, run_id=meta["run_id"], ids=dict(meta["ids"]))


@pytest.fixture(scope="session")
def _packages_template(tmp_path_factory, _index_template):
    basetemp = Path(tmp_path_factory.getbasetemp())
    session_root = basetemp.parent if basetemp.name.startswith("popen-gw") else basetemp
    base = session_root / "isr-unit-packages-template"
    ready = base / "packages-outputs.json"
    with pytest.MonkeyPatch.context() as mp:
        mp.delenv("APPSEC_REVIEW_CONFIG_OVERLAY", raising=False)
        mp.setattr(os, "fsync", lambda _fd: None)
        with bounded_file_lock(session_root / "isr-unit-packages-template.lock", 60.0):
            if not ready.is_file():
                shutil.rmtree(base, ignore_errors=True)
                base.mkdir(parents=True, exist_ok=True)
                run_root = base / "runs" / _index_template.run_id
                shutil.copytree(_index_template.base / "runs" / _index_template.run_id, run_root)
                config_path = write_config(
                    base,
                    base / "runs",
                    overrides={"backoff_seconds": [0]},
                    extra=job_tables("job_third_party_data_sync"),
                )
                base_s = load_config(config_path).job(JOB_ID).typed_settings
                settings = _fast_settings(base_s, triage_enabled=False, budget_packages=1)
                settings = replace(
                    settings,
                    lanes=replace(settings.lanes, lead_admission=("critical", "high", "unknown"), lead_admission_kev=False, hunt_max_units=0),
                    packages=replace(settings.packages, slice_strategies=("lexical_identifiers",)),
                )
                infer = _fast_infer(ScriptedInfer({"ids": _index_template.ids}), zero_claims=True)
                job = build_job(infer=infer, repository_root=ROOT)
                job_ctx = _make_job_ctx(run_root, config_path, _index_template.run_id, job, typed_settings=settings)
                outputs: dict[str, dict] = {}
                for uid in EARLY_UNITS[:6]:
                    outputs[uid] = _run_unit(job, job_ctx, uid, outputs)
                ready.write_text(
                    json.dumps({"run_id": _index_template.run_id, "ids": _index_template.ids, "outputs": outputs}),
                    encoding="utf-8",
                )
    meta = json.loads(ready.read_text(encoding="utf-8"))
    return SimpleNamespace(base=base, run_id=meta["run_id"], ids=dict(meta["ids"]), outputs=meta["outputs"])


@pytest.fixture(scope="session")
def _early_units_template(tmp_path_factory, _packages_template):
    basetemp = Path(tmp_path_factory.getbasetemp())
    session_root = basetemp.parent if basetemp.name.startswith("popen-gw") else basetemp
    base = session_root / "isr-unit-early-template"
    ready = base / "early-outputs.json"
    with pytest.MonkeyPatch.context() as mp:
        mp.delenv("APPSEC_REVIEW_CONFIG_OVERLAY", raising=False)
        mp.setattr(os, "fsync", lambda _fd: None)
        with bounded_file_lock(session_root / "isr-unit-early-template.lock", 60.0):
            if not ready.is_file():
                shutil.rmtree(base, ignore_errors=True)
                base.mkdir(parents=True, exist_ok=True)
                run_root = base / "runs" / _packages_template.run_id
                shutil.copytree(_packages_template.base / "runs" / _packages_template.run_id, run_root)
                config_path = write_config(
                    base,
                    base / "runs",
                    overrides={"backoff_seconds": [0]},
                    extra=job_tables("job_third_party_data_sync"),
                )
                base_s = load_config(config_path).job(JOB_ID).typed_settings
                settings = _fast_settings(base_s, triage_enabled=False, budget_packages=1)
                settings = replace(
                    settings,
                    lanes=replace(settings.lanes, lead_admission=("critical", "high", "unknown"), lead_admission_kev=False, hunt_max_units=0),
                    packages=replace(settings.packages, slice_strategies=("lexical_identifiers",)),
                )
                infer = _fast_infer(ScriptedInfer({"ids": _packages_template.ids}), zero_claims=True)
                job = build_job(infer=infer, repository_root=ROOT)
                job_ctx = _make_job_ctx(
                    run_root, config_path, _packages_template.run_id, job, typed_settings=settings
                )
                outputs: dict[str, dict] = dict(_packages_template.outputs)
                for uid in EARLY_UNITS[6:]:
                    outputs[uid] = _run_unit(job, job_ctx, uid, outputs)
                ready.write_text(
                    json.dumps({"run_id": _packages_template.run_id, "ids": _packages_template.ids, "outputs": outputs}),
                    encoding="utf-8",
                )
    meta = json.loads(ready.read_text(encoding="utf-8"))
    return SimpleNamespace(base=base, run_id=meta["run_id"], ids=dict(meta["ids"]), outputs=meta["outputs"])


def _clone_workspace(template_base: Path, run_id: str, tmp_path: Path):
    work = tmp_path / "work"
    run_root = work / "runs" / run_id
    shutil.copytree(template_base / "runs" / run_id, run_root)
    config_path = write_config(
        work,
        work / "runs",
        overrides={"backoff_seconds": [0]},
        extra=job_tables("job_third_party_data_sync"),
    )
    return config_path, run_root


def test_scope_and_package_units_execute_directly_and_reject_manifest_drift(_index_template, tmp_path) -> None:
    assert tuple(f"{step}.{task}" for step, tasks in TOPOLOGY.items() for task in tasks) == EARLY_UNITS + LATE_UNITS
    config_path, run_root = _clone_workspace(_index_template.base, _index_template.run_id, tmp_path)
    base_settings = load_config(config_path).job(JOB_ID).typed_settings
    fast_settings = _fast_settings(base_settings, triage_enabled=False, budget_packages=1)
    job = build_job(infer=_fast_infer(ScriptedInfer({"ids": _index_template.ids})), repository_root=ROOT)
    job_ctx = _make_job_ctx(run_root, config_path, _index_template.run_id, job, typed_settings=fast_settings)

    outputs: dict[str, dict] = {}
    for uid in EARLY_UNITS[:6]:
        outputs[uid] = _run_unit(job, job_ctx, uid, outputs)
        assert outputs[uid]["terminal_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}

    drifted = {
        **outputs,
        "scope.accept_manifest": {**outputs["scope.accept_manifest"], "manifest_sha256": "f" * 64},
    }
    with pytest.raises(IntegrityError, match="accepted manifest changed during the review attempt"):
        _run_unit(job, job_ctx, "scope.assemble_scope", drifted)


def test_lane_units_execute_directly(_packages_template, tmp_path) -> None:
    config_path, run_root = _clone_workspace(_packages_template.base, _packages_template.run_id, tmp_path)
    base_settings = load_config(config_path).job(JOB_ID).typed_settings
    fast_settings = replace(
        _fast_settings(base_settings, triage_enabled=False, budget_packages=1),
        lanes=replace(base_settings.lanes, lead_admission=("critical", "high", "unknown"), lead_admission_kev=False, hunt_max_units=0),
        decision_audit=replace(base_settings.decision_audit, enabled=False),
    )
    infer = _fast_infer(ScriptedInfer({"ids": _packages_template.ids}), zero_claims=True)
    job = build_job(infer=infer, repository_root=ROOT)
    job_ctx = _make_job_ctx(
        run_root, config_path, _packages_template.run_id, job, typed_settings=fast_settings, attempt_id="attempt-u2a"
    )

    outputs: dict[str, dict] = dict(_packages_template.outputs)
    for uid in EARLY_UNITS[6:8]:
        outputs[uid] = _run_unit(job, job_ctx, uid, outputs)
        assert outputs[uid]["terminal_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}


def test_merge_adjudicate_and_score_units_and_tamper_guards(_early_units_template, tmp_path) -> None:
    config_path, run_root = _clone_workspace(_early_units_template.base, _early_units_template.run_id, tmp_path)
    base_settings = load_config(config_path).job(JOB_ID).typed_settings
    fast_settings = _fast_settings(base_settings, triage_enabled=False, budget_packages=1)
    infer = _fast_infer(ScriptedInfer({"ids": _early_units_template.ids}), zero_claims=True)
    job = build_job(infer=infer, repository_root=ROOT)
    job_ctx = _make_job_ctx(
        run_root, config_path, _early_units_template.run_id, job, typed_settings=fast_settings, attempt_id="attempt-u2b"
    )

    outputs: dict[str, dict] = {k: v for k, v in _early_units_template.outputs.items() if k in EARLY_UNITS[:7]}
    for uid in EARLY_UNITS[7:]:
        outputs[uid] = _run_unit(job, job_ctx, uid, outputs)
        assert outputs[uid]["terminal_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}

    # Shard tamper guard in merge.claims
    bad_shard = {
        **outputs,
        "lead_review.teams": {
            **outputs["lead_review.teams"],
            "ledger_shard": {**outputs["lead_review.teams"]["ledger_shard"], "sha256": "0" * 64},
        },
    }
    with pytest.raises(IntegrityError, match="ledger shard changed after its unit sealed it"):
        _run_unit(job, job_ctx, "merge.claims", bad_shard)

    # Merge ledger head tamper guard in adjudicate.apply_policy
    merge_doc_path = job_ctx.run_root / outputs["merge.claims"]["artifact"]["path"]
    tampered_merge = job_ctx.attempt_root / "tampered-merge.json"
    atomic_json(tampered_merge, {**json.loads(merge_doc_path.read_text(encoding="utf-8")), "ledger_head_sha256": "0" * 64})
    bad_merge = {
        **outputs,
        "merge.claims": {
            **outputs["merge.claims"],
            "artifact": {
                "path": tampered_merge.relative_to(job_ctx.run_root).as_posix(),
                "sha256": file_sha256(tampered_merge),
                "size_bytes": tampered_merge.stat().st_size,
            },
        },
    }
    with pytest.raises(IntegrityError, match="lane ledger changed between merge and adjudication"):
        _run_unit(job, job_ctx, "adjudicate.apply_policy", bad_merge)


def test_triage_enabled_and_lane_exception_records_lane_failure(_index_template, tmp_path, monkeypatch) -> None:
    config_path, run_root = _clone_workspace(_index_template.base, _index_template.run_id, tmp_path)
    base_settings = load_config(config_path).job(JOB_ID).typed_settings
    fast_settings = _fast_settings(base_settings, triage_enabled=True)
    job = build_job(infer=_fast_infer(ScriptedInfer({"ids": _index_template.ids})), repository_root=ROOT)
    job_ctx = _make_job_ctx(run_root, config_path, _index_template.run_id, job, typed_settings=fast_settings)

    outputs: dict[str, dict] = {}
    for uid in (
        "scope.accept_manifest",
        "scope.assemble_scope",
        "triage.lead_severity",
        "packages.plan_hunt_campaign",
        "packages.assemble_lead_packages",
    ):
        outputs[uid] = _run_unit(job, job_ctx, uid, outputs)

    assert _read(job_ctx.run_root, outputs["triage.lead_severity"]["artifact"])["enabled"] is True
    pkg_count = len(_read(job_ctx.run_root, outputs["packages.assemble_lead_packages"]["artifact"])["packages"])
    assert pkg_count >= 1

    monkeypatch.setattr(
        "appsec_review.jobs.job_inference_security_review.job.run_lane",
        lambda *_a, **_kw: (_ for _ in ()).throw(OSError("simulated disk hiccup")),
    )
    lead_out = _run_unit(job, job_ctx, "lead_review.teams", outputs)
    assert lead_out["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert lead_out["gaps"] == [f"lead: {pkg_count} gaps"]
    assert _read(job_ctx.run_root, lead_out["artifact"])["counts"]["gaps"] == pkg_count


def test_late_synthesis_and_publication_units_execute_directly(_early_units_template, tmp_path, monkeypatch) -> None:
    config_path, run_root = _clone_workspace(_early_units_template.base, _early_units_template.run_id, tmp_path)
    base_settings = load_config(config_path).job(JOB_ID).typed_settings
    fast_settings = _fast_settings(base_settings, triage_enabled=False, budget_packages=1)
    job = build_job(infer=_fast_infer(ScriptedInfer({"ids": _early_units_template.ids})), repository_root=ROOT)
    job_ctx = _make_job_ctx(run_root, config_path, _early_units_template.run_id, job, typed_settings=fast_settings)

    outputs: dict[str, dict] = dict(_early_units_template.outputs)
    for uid in LATE_UNITS:
        outputs[uid] = _run_unit(job, job_ctx, uid, outputs)

    handoff_out = outputs["publication.publish_handoff"]
    assert handoff_out["terminal_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    handoff_doc = _read(job_ctx.run_root, handoff_out["artifact"])
    assert handoff_doc["schema"] == "appsec-review/inference-review-handoff/3"

    # Completeness tamper guard in publish_claim_ledger
    comp_doc_path = job_ctx.run_root / outputs["completeness.audit"]["artifact"]["path"]
    tampered_comp = job_ctx.attempt_root / "tampered-completeness.json"
    atomic_json(tampered_comp, {**json.loads(comp_doc_path.read_text(encoding="utf-8")), "ledger_head_sha256": "0" * 64})
    bad_comp = {
        **outputs,
        "completeness.audit": {
            **outputs["completeness.audit"],
            "artifact": {
                "path": tampered_comp.relative_to(job_ctx.run_root).as_posix(),
                "sha256": file_sha256(tampered_comp),
                "size_bytes": tampered_comp.stat().st_size,
            },
        },
    }
    with pytest.raises(IntegrityError, match="ledger changed between"):
        _run_unit(job, job_ctx, "publication.publish_claim_ledger", bad_comp)

    # Duplicate chain cell identity guard in completeness.audit
    compose_doc_path = job_ctx.run_root / outputs["attack_chains.compose_candidates"]["artifact"]["path"]
    refute_doc_path = job_ctx.run_root / outputs["attack_chains.refute_edges"]["artifact"]["path"]
    tampered_compose = job_ctx.attempt_root / "tampered-compose.json"
    tampered_refute = job_ctx.attempt_root / "tampered-refute.json"
    atomic_json(tampered_compose, {**json.loads(compose_doc_path.read_text(encoding="utf-8")), "expected_cells": {"cell-dup": "hunt"}})
    atomic_json(tampered_refute, {**json.loads(refute_doc_path.read_text(encoding="utf-8")), "expected_cells": {"cell-dup": "hunt"}})
    dup_chain_outputs = {
        **outputs,
        "attack_chains.compose_candidates": {
            **outputs["attack_chains.compose_candidates"],
            "artifact": {
                "path": tampered_compose.relative_to(job_ctx.run_root).as_posix(),
                "sha256": file_sha256(tampered_compose),
                "size_bytes": tampered_compose.stat().st_size,
            },
        },
        "attack_chains.refute_edges": {
            **outputs["attack_chains.refute_edges"],
            "artifact": {
                "path": tampered_refute.relative_to(job_ctx.run_root).as_posix(),
                "sha256": file_sha256(tampered_refute),
                "size_bytes": tampered_refute.stat().st_size,
            },
        },
    }
    with pytest.raises(IntegrityError, match="duplicate"):
        _run_unit(job, job_ctx, "completeness.audit", dup_chain_outputs)


def test_audit_publish_rejects_disagreeing_lane_warrants_and_obligations(_early_units_template, tmp_path, monkeypatch) -> None:
    config_path, run_root = _clone_workspace(_early_units_template.base, _early_units_template.run_id, tmp_path)
    base_settings = load_config(config_path).job(JOB_ID).typed_settings
    fast_settings = _fast_settings(base_settings, triage_enabled=False, budget_packages=1)
    job = build_job(infer=_fast_infer(ScriptedInfer({"ids": _early_units_template.ids})), repository_root=ROOT)
    job_ctx = _make_job_ctx(run_root, config_path, _early_units_template.run_id, job, typed_settings=fast_settings)

    outputs: dict[str, dict] = dict(_early_units_template.outputs)
    for uid in LATE_UNITS[:-1]:
        outputs[uid] = _run_unit(job, job_ctx, uid, outputs)

    captured: list[tuple] = []

    def _capture_audit(*, run_root, attempt_root, origin, scope, collection, inputs, settings):
        captured.append((run_root, attempt_root, origin, scope, collection, inputs, settings))
        raise AuditUnavailable("input_unavailable: skip encryption")

    monkeypatch.setattr(job_audit, "publish_decision_audit", _capture_audit)
    outputs["publication.publish_handoff"] = _run_unit(job, job_ctx, "publication.publish_handoff", outputs)
    assert outputs["publication.publish_handoff"]["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("decision_audit_input_unavailable" in str(g) for g in outputs["publication.publish_handoff"]["gaps"])

    run_root_cap, attempt_root, origin, scope, collection, audit_inputs, audit_settings = captured[0]

    lead_lane_path = run_root_cap / audit_inputs.lanes[0]["path"]
    lead_lane_doc = json.loads(lead_lane_path.read_text(encoding="utf-8"))
    tampered_lane = attempt_root / "units" / "lead_review" / "teams" / "lane-tampered-w.json"
    atomic_json(tampered_lane, {**lead_lane_doc, "warrants": {"path": "x", "sha256": "0" * 64}})
    bad_inputs: AuditInputs = replace(
        audit_inputs,
        lanes=(
            {"path": tampered_lane.relative_to(run_root_cap).as_posix(), "sha256": file_sha256(tampered_lane)},
            audit_inputs.lanes[1],
        ),
    )
    with pytest.raises(IntegrityError, match="disagree on predicate warrant production"):
        job_audit._publish(
            run_root=run_root_cap,
            attempt_root=attempt_root,
            origin=origin,
            scope=scope,
            collection=collection,
            inputs=bad_inputs,
            settings=audit_settings,
        )

    tampered_ob = attempt_root / "units" / "lead_review" / "teams" / "lane-tampered-ob.json"
    atomic_json(tampered_ob, {**lead_lane_doc, "evidence_obligations": None})
    bad_ob_inputs: AuditInputs = replace(
        audit_inputs,
        lanes=(
            {"path": tampered_ob.relative_to(run_root_cap).as_posix(), "sha256": file_sha256(tampered_ob)},
            audit_inputs.lanes[1],
        ),
    )
    with pytest.raises(IntegrityError, match="disagree on evidence obligation production"):
        job_audit._publish(
            run_root=run_root_cap,
            attempt_root=attempt_root,
            origin=origin,
            scope=scope,
            collection=collection,
            inputs=bad_ob_inputs,
            settings=audit_settings,
        )
