from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.jobs.completion_contracts import (
    ATTACK_CHAIN_MANIFEST_SCHEMA,
    REMEDIATION_PLANNING_HANDOFF_SCHEMA,
    REMEDIATION_PLANNING_SCHEMA,
    REMEDIATION_PLAN_SCHEMA,
    REMEDIATION_VALIDATION_HANDOFF_SCHEMA,
    REMEDIATION_VALIDATION_SCHEMA,
    REMEDIATION_VALIDATION_SUMMARY_SCHEMA,
    nonexecution_assurance,
)
from appsec_review.jobs.engineering_contracts import POC_GENERATION_HANDOFF_SCHEMA, POC_GENERATION_SCHEMA
from appsec_review.jobs.job_dossier_publication import JOB_ID, DossierPublicationSettings, build_job, inputs
from appsec_review.jobs.job_dossier_publication import job as dossier_job
from appsec_review.observability import EventLog
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import JobContext
from appsec_review.storage import atomic_bytes, atomic_json
from appsec_review.storage import canonical_json
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_remediation_planning.contracts import PlanAnswer, verify_plan
from appsec_review.reporting.dossiers import DossierLimits, build_dossier
from appsec_review.reporting.dossier_render import render_dossier, render_dossier_markdown
from tests import remediation_support
from tests.dossier_fixture import ROOT, seed, settings


def _write(root: Path, name: str, value: object) -> dict[str, str]:
    path = root / "data" / "seed" / name
    atomic_json(path, value)
    return artifact_ref(root, path)


def _acceptance(root: Path, document: dict, name: str) -> SimpleNamespace:
    path = root / "data" / "seed" / name
    atomic_json(path, document)
    ref = artifact_ref(root, path)
    return SimpleNamespace(path=ref["path"], sha256=ref["sha256"], handoff=document)


def _seed_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    root = tmp_path / "run-d"
    source = seed(root)
    finding = source["finding"]
    reference = _write(root, "finding.json", finding)
    finding.update(reference)
    binding = {key: finding[key] for key in ("claim_id", "finding_package_id", "sha256")}
    source["poc"]["finding"] = binding
    projection_ref = _write(
        root,
        "projection.json",
        {"claims": [source["claim"]], "relations": {finding["claim_id"]: source["relations"]}},
    )
    manifest = _write(root, "manifest.json", {"run_id": root.name, "indexes": []})
    scope = _write(root, "scope.json", {"manifest_path": manifest["path"], "manifest_sha256": manifest["sha256"]})
    review_ref = _write(root, "review.json", {"run_id": root.name})
    review_job = _acceptance(
        root,
        {"job_id": inputs.REVIEW_JOB, "outputs": {"scope.accept_manifest": {"artifact": scope}}},
        "review-job.json",
    )
    accepted: dict[str, SimpleNamespace] = {inputs.REVIEW_JOB: review_job}

    def producer(job_name: str, schema: str, handoff_schema: str, items: list, *, review=review_ref, gaps=None, extra=None):
        key = "candidates" if job_name == "job_poc_generation" else "items"
        doc = {"schema": schema, "run_id": root.name, "upstream": {"review_handoff": review, **(extra or {})}, key: items, "gaps": gaps or []}
        ref = _write(root, job_name + ".json", doc)
        unit = inputs.PRODUCERS[job_name][0]
        accepted[job_name] = _acceptance(
            root,
            {"job_id": job_name, "outputs": {unit: {"schema": handoff_schema, "artifact": ref, "item_count": len(items), "gaps": gaps or []}}},
            job_name + "-handoff.json",
        )
        return doc

    producer("job_poc_generation", POC_GENERATION_SCHEMA, POC_GENERATION_HANDOFF_SCHEMA, [source["poc"]])
    verified = {
        "run_id": root.name,
        "packages": [finding],
        "inputs": {
            "projection": projection_ref,
            "review_handoff": review_ref,
            "job_handoff": {"path": review_job.path, "sha256": review_job.sha256},
        },
        "review": {"ledger_head_sha256": "a" * 64, "configuration_sha256": "b" * 64},
    }
    monkeypatch.setattr(inputs, "accepted_handoff", lambda _root, j: accepted.get(j))
    return SimpleNamespace(root=root, source=source, verified=verified, accepted=accepted, producer=producer, binding=binding)


def _ctx(root: Path, name: str = "att-1", **overrides) -> JobContext:
    cfg = SimpleNamespace(
        settings=settings(**{"render_pdf": False, **overrides}).identity(),
        steps=dossier_job.TOPOLOGY,
        step=lambda key: SimpleNamespace(tasks=dossier_job.TOPOLOGY[key]),
    )
    attempt = root / "data" / "jobs" / JOB_ID / "attempts" / name
    attempt.mkdir(parents=True, exist_ok=True)
    return JobContext(
        run_id=root.name,
        attempt_id=name,
        trigger="test",
        repository_root=ROOT,
        run_root=root,
        attempt_root=attempt,
        metadata_root=attempt,
        orchestration={},
        config=cfg,
        events=EventLog(attempt / "events.jsonl"),
    )


def _accepted_exact_remediation(env, *, planning_status="proposal_generated", validation_status=None,
                                static_status="passed", semantic_status="analyst_supported", proposal=None):
    proposal = proposal or remediation_support.patch(
        "src/example.c", "a" * 64, old="return n;", new="if (n > 8) return 0;\nreturn n;")
    answer = remediation_support.answer(
        env.source["finding"]["direct_evidence"], proposal if planning_status == "proposal_generated" else None,
        status=planning_status)
    parsed = PlanAnswer.from_mapping(answer, remediation_support.bounds(),
                                    evidence_ids=set(env.source["finding"]["direct_evidence"]))
    patch_ref = None if parsed.patch is None else _write(env.root, "exact-patch.json", parsed.patch.document)
    context_ref = _write(env.root, "context.json", {
        "finding": env.binding, "adjudication_id": env.source["finding"]["adjudication_id"]})
    receipt_ref = _write(env.root, "writer.json", {
        "role": "remediation_writer", "status": "answered",
        "cell_id": f"remediation-writer:{env.binding['claim_id']}",
        "guidance_bundle_sha256": "b" * 64, "result_sha256": hashlib.sha256(canonical_json(answer)).hexdigest()})
    plan = {
        "schema": REMEDIATION_PLAN_SCHEMA, "run_id": env.root.name,
        "upstream": {"review_handoff": env.verified["inputs"]["review_handoff"], "poc_handoff": None},
        "finding": env.binding, "adjudication_id": env.source["finding"]["adjudication_id"],
        **answer, "patch": patch_ref, "assurance": nonexecution_assurance(),
        "provenance": {"settings_sha256": "c" * 64, "source_context": context_ref,
                       "writer_receipt": receipt_ref, "guidance_bundle_sha256": "b" * 64}, "gaps": [],
    }
    plan_ref = _write(env.root, "plan.json", plan)
    schemas = SchemaSet(ROOT / "docs" / "schemas" / "remediation")
    assert verify_plan(env.root, plan_ref, review_handoff=env.verified["inputs"]["review_handoff"],
                       finding=env.binding, schemas=schemas) == plan
    env.producer("job_remediation_planning", REMEDIATION_PLANNING_SCHEMA, REMEDIATION_PLANNING_HANDOFF_SCHEMA,
                 [{"finding": env.binding, "status": planning_status, "reason": plan["reason"],
                   "plan": plan_ref, "gap_ids": []}])
    if validation_status:
        from appsec_review.jobs.job_remediation_validation.job import _initial_checks
        checks = _initial_checks()
        for dimension, status in (("patch_applicability", "passed"), ("static_checks", static_status),
                                  ("semantic_review", semantic_status)):
            checks[dimension] = {"status": status, "reason": "retained check result", "artifact": None}
        if validation_status == "build_checked":
            checks["build"] = {"status": "passed", "reason": "retained build check", "artifact": None}
        planning = env.accepted["job_remediation_planning"]
        planning_ref = {"path": planning.path, "sha256": planning.sha256}
        validation = {
            "schema": REMEDIATION_VALIDATION_SCHEMA, "run_id": env.root.name,
            "upstream": {**plan["upstream"], "planning_handoff": planning_ref},
            "finding": env.binding, "adjudication_id": plan["adjudication_id"],
            "plan": plan_ref, "patch": patch_ref, "status": validation_status,
            "reason": "retained validation outcome", "checks": checks,
            "assurance": nonexecution_assurance(), "settings_sha256": "d" * 64,
            "cleanup": None, "gaps": [],
        }
        schemas.validate("validation", validation)
        validation_ref = _write(env.root, "validation.json", validation)
        env.producer("job_remediation_validation", REMEDIATION_VALIDATION_SUMMARY_SCHEMA,
                     REMEDIATION_VALIDATION_HANDOFF_SCHEMA,
                     [{"finding": env.binding, "status": validation_status, "reason": validation["reason"],
                       "validation": validation_ref, "gap_ids": []}], extra={"planning_handoff": planning_ref})
    return patch_ref


@pytest.mark.parametrize("plan,status,static,semantic,tier", [
    ("proposal_generated", None, "passed", "analyst_supported", "proposal_only"),
    ("manual_design_required", None, "passed", "analyst_supported", "manual_design_required"),
    ("insufficient_evidence", None, "passed", "analyst_supported", "insufficient_evidence"),
    ("proposal_generated", "rejected", "failed", "not_performed", "rejected"),
    ("proposal_generated", "rejected", "passed", "analyst_contradicted", "rejected"),
    ("proposal_generated", "inconclusive", "passed", "analyst_unresolved", "inconclusive"),
    ("proposal_generated", "manual_validation_required", "passed", "analyst_supported", "manual_validation_required"),
    ("proposal_generated", "static_checked", "passed", "analyst_supported", "static_checked"),
    ("proposal_generated", "build_checked", "passed", "analyst_supported", "build_checked"),
], ids=["proposal", "manual-design", "insufficient", "static-rejected", "semantic-rejected",
        "inconclusive", "manual-validation", "static", "build"])
def test_accepted_remediation_projection_retains_exact_edits_and_outcomes(
        tmp_path, monkeypatch, plan, status, static, semantic, tier):
    env = _seed_env(tmp_path, monkeypatch)
    patch_ref = _accepted_exact_remediation(
        env, planning_status=plan, validation_status=status, static_status=static, semantic_status=semantic)
    loaded = inputs.load_inputs(env.root, env.verified, settings())
    remedies = dossier_job._remediation(env.root, loaded, env.binding["finding_package_id"], settings())
    model = build_dossier(kind="confirmed_finding", **{**env.source, "remediation": remedies})
    assert model["remediation_guide"]["validation_tier"] == tier
    if patch_ref:
        projected = next(row["patch"] for row in model["remediation"] if row["stage"] == "Planning")
        assert projected["artifact"] == patch_ref
        assert projected["files"] == read_bound_json(env.root, patch_ref)["files"]
    assert model["remediation_guide"]["proposed_diff"] is None
    result = render_dossier(env.root, env.root / "rendered", model,
                            settings=settings(render_pdf=False), repository_root=ROOT)
    assert result["status"] == "latex_only"
    for suffix in ("md", "html"):
        rendered = (env.root / "rendered" / f"dossier.{suffix}").read_text()
        assert tier in rendered
        assert "Validated Remediation Patch" not in rendered
        if patch_ref:
            assert patch_ref["sha256"] in rendered
            assert "return n;" in rendered
        if status:
            assert semantic in rendered and static in rendered


def test_exact_patch_projection_bounds_and_rechecks_original_bytes(tmp_path, monkeypatch):
    env = _seed_env(tmp_path, monkeypatch)
    patch_ref = _accepted_exact_remediation(env)
    loaded = inputs.load_inputs(env.root, env.verified, settings())
    remedies = dossier_job._remediation(env.root, loaded, env.binding["finding_package_id"], settings())
    model = build_dossier(kind="confirmed_finding", **{**env.source, "remediation": remedies},
                          limits=DossierLimits(code_chars=8))
    assert any("patch" in cut["field"] for cut in model["truncations"])
    assert "Bounded" in render_dossier_markdown(model)
    atomic_bytes(env.root / patch_ref["path"], b"{}")
    with pytest.raises((IntegrityError, ValueError), match="hash|sha256|changed"):
        dossier_job._remediation(env.root, loaded, env.binding["finding_package_id"], settings())


def test_exact_edits_keep_byte_order_new_file_absence_and_protected_text(tmp_path, monkeypatch):
    env = _seed_env(tmp_path, monkeypatch)
    proposal = {"schema": "appsec-review/remediation-exact-patch/1", "files": [
        {"path": "src/example.c", "before_sha256": "a" * 64, "absence_proof": False,
         "edits": [{"start": 2, "end": 3, "old": "a", "new": "b"},
                   {"start": 10, "end": 11, "old": "c", "new": "d"}]},
        {"path": "src/new.c", "before_sha256": None, "absence_proof": True,
         "edits": [{"start": 0, "end": 0, "old": "", "new": 'password = "private-patch-value";\n'}]},
    ]}
    patch_ref = _accepted_exact_remediation(env, proposal=proposal)
    loaded = inputs.load_inputs(env.root, env.verified, settings())
    remedies = dossier_job._remediation(env.root, loaded, env.binding["finding_package_id"], settings())
    model = build_dossier(kind="confirmed_finding", **{**env.source, "remediation": remedies})
    patch_view = model["remediation"][0]["patch"]
    assert patch_view["artifact"] == patch_ref
    files = {row["path"]: row for row in patch_view["files"]}
    assert [edit["start"] for edit in files["src/example.c"]["edits"]] == [2, 10]
    assert files["src/new.c"]["before_sha256"] is None
    assert files["src/new.c"]["absence_proof"] is True
    assert files["src/new.c"]["edits"][0]["old"] == ""
    assert "private-patch-value" not in canonical_json(model).decode()
    assert read_bound_json(env.root, patch_ref) == proposal


def test_absent_remediation_has_no_invented_design_or_patch(tmp_path):
    source = seed(tmp_path / "run")
    model = build_dossier(kind="confirmed_finding", **{**source, "remediation": []})
    guide = model["remediation_guide"]
    assert guide["validation_tier"] == "not_available"
    assert guide["proposed_diff"] is None and guide["concrete_fix_steps"] == []
    assert guide["corrected_invariant"] == "Not recorded in upstream remediation plan."
    assert "No remediation is claimed" in render_dossier_markdown(model)


def test_remediation_row_cap_does_not_hide_rejected_outcome(tmp_path, monkeypatch):
    env = _seed_env(tmp_path, monkeypatch)
    _accepted_exact_remediation(env, validation_status="rejected", static_status="failed")
    loaded = inputs.load_inputs(env.root, env.verified, settings())
    remedies = dossier_job._remediation(env.root, loaded, env.binding["finding_package_id"], settings())
    model = build_dossier(kind="confirmed_finding", **{**env.source, "remediation": remedies},
                          limits=DossierLimits(evidence_rows=1))
    assert model["remediation_guide"]["validation_tier"] == "rejected"
    assert any(cut["field"] == "remediation" and cut["omitted"] == 1 for cut in model["truncations"])


def test_exact_patch_input_refuses_unclosed_shape_and_artifact_bound(tmp_path):
    root = tmp_path / "run"
    patch_ref = _write(root, "bad-patch.json", {
        **remediation_support.patch("src/example.c", "a" * 64), "raw_prompt": "DO_NOT_COPY"})
    with pytest.raises(IntegrityError, match="schema mismatch"):
        inputs.exact_patch(root, patch_ref, settings().max_artifact_bytes)
    with pytest.raises(IntegrityError, match="exceeds max_artifact_bytes"):
        inputs.exact_patch(root, patch_ref, 8)


def test_settings_and_validate_topology_edges(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must define exactly"):
        DossierPublicationSettings.from_mapping({})
    for bad_tag in ("", "bad tag", "-leading", 123):
        with pytest.raises(ValueError, match="image_tag"):
            settings(image_tag=bad_tag)
    s = settings()
    assert len(s.settings_sha256()) == 64

    ctx = _ctx(tmp_path / "r")
    dossier_job._validate(ctx, None)

    bad_steps = SimpleNamespace(settings=s.identity(), steps={"load": ("verify_inputs",)}, step=lambda k: SimpleNamespace(tasks=("verify_inputs",)))
    with pytest.raises(ValueError, match="topology does not match"):
        dossier_job._validate(SimpleNamespace(config=bad_steps), None)

    bad_tasks = SimpleNamespace(
        settings=s.identity(),
        steps=dossier_job.TOPOLOGY,
        step=lambda k: SimpleNamespace(tasks=("wrong",) if k == "dossiers" else dossier_job.TOPOLOGY[k]),
    )
    with pytest.raises(ValueError, match="task configuration mismatch"):
        dossier_job._validate(SimpleNamespace(config=bad_tasks), None)

    with patch("appsec_review.jobs.accepted_review.load_accepted_review", return_value="ok_rev") as mock_rev:
        assert dossier_job._accepted_review(tmp_path, SimpleNamespace(), max_packages=10) == "ok_rev"
        mock_rev.assert_called_once()
    with patch("appsec_review.jobs.bound_artifacts.source_context_core", return_value="ok_core") as mock_core:
        assert dossier_job._core(tmp_path, {"path": "m", "sha256": "0" * 64}) == "ok_core"
        mock_core.assert_called_once()


def test_inputs_error_branches_and_validation_chain_audit_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _seed_env(tmp_path, monkeypatch)
    cfg = settings()

    # bound_json max_artifact_bytes guard
    with pytest.raises(IntegrityError, match="exceeds max_artifact_bytes"):
        inputs.bound_json(env.root, env.verified["inputs"]["projection"], maximum=2)

    # finding_binding legacy finding_package fallback
    fb = inputs.finding_binding({"claim_id": "c1", "finding_package": {"finding_package_id": "f1", "sha256": "1" * 64}})
    assert fb.finding_package_id == "f1"

    # foreign run_id and max_packages guard
    bad_run = dict(env.verified, run_id="other-run")
    with pytest.raises(IntegrityError, match="another run"):
        inputs.load_inputs(env.root, bad_run, cfg)
    dup_verified = dict(env.verified, packages=[env.verified["packages"][0], env.verified["packages"][0]])
    with pytest.raises(IntegrityError, match="exceeds max_packages|invalid"):
        inputs.load_inputs(env.root, dup_verified, cfg)

    # accepted_handoff raising ValueError in accepted_producer and verify_snapshot
    loaded = inputs.load_inputs(env.root, env.verified, cfg)
    monkeypatch.setattr(inputs, "accepted_handoff", lambda *_a: (_ for _ in ()).throw(ValueError("bad pointer")))
    with pytest.raises(IntegrityError, match="cannot be verified"):
        inputs.accepted_producer(env.root, "job_poc_generation", env.verified["inputs"]["review_handoff"], {}, cfg)
    with pytest.raises(IntegrityError, match="acceptance changed"):
        inputs.verify_snapshot(env.root, loaded, cfg)
    monkeypatch.setattr(inputs, "accepted_handoff", lambda _r, j: env.accepted.get(j))

    # unsupported accepted dossier producer schema
    orig_poc = env.accepted["job_poc_generation"]
    env.accepted["job_poc_generation"] = SimpleNamespace(path=orig_poc.path, sha256=orig_poc.sha256, handoff={"job_id": "wrong", "outputs": {}})
    with pytest.raises(IntegrityError, match="unsupported accepted dossier producer"):
        inputs.load_inputs(env.root, env.verified, cfg)
    env.accepted["job_poc_generation"] = orig_poc

    # unsupported PoC status & empty status
    bad_poc = copy.deepcopy(env.source["poc"])
    bad_poc["status"] = "bogus_status"
    env.producer("job_poc_generation", POC_GENERATION_SCHEMA, POC_GENERATION_HANDOFF_SCHEMA, [bad_poc])
    with pytest.raises(IntegrityError, match="unsupported accepted PoC status"):
        inputs.load_inputs(env.root, env.verified, cfg)
    env.producer("job_poc_generation", POC_GENERATION_SCHEMA, POC_GENERATION_HANDOFF_SCHEMA, [env.source["poc"]])

    # remediation validation without planning, then mismatched planning_handoff, then valid planning + validation
    val_art = _write(
        env.root,
        "val.json",
        {
            "schema": REMEDIATION_VALIDATION_SCHEMA,
            "run_id": env.root.name,
            "finding": env.binding,
            "status": "static_checked",
            "upstream": {"review_handoff": env.verified["inputs"]["review_handoff"]},
            "assurance": nonexecution_assurance(),
        },
    )
    val_item = {"finding": env.binding, "status": "static_checked", "reason": "ok", "validation": val_art, "gap_ids": []}
    env.producer("job_remediation_validation", REMEDIATION_VALIDATION_SUMMARY_SCHEMA, REMEDIATION_VALIDATION_HANDOFF_SCHEMA, [val_item])
    with pytest.raises(IntegrityError, match="no accepted planning producer"):
        inputs.load_inputs(env.root, env.verified, cfg)

    plan_item_no_ref = {"finding": env.binding, "status": "insufficient_evidence", "reason": "none", "plan": None, "gap_ids": []}
    env.producer("job_remediation_planning", REMEDIATION_PLANNING_SCHEMA, REMEDIATION_PLANNING_HANDOFF_SCHEMA, [plan_item_no_ref])
    with pytest.raises(IntegrityError, match="another planning handoff"):
        inputs.load_inputs(env.root, env.verified, cfg)

    # remediation artifact disagreeing with summary & empty status & non-confirmed finding
    bad_val_art = _write(
        env.root,
        "bad-val.json",
        {
            "schema": "wrong/schema",
            "run_id": env.root.name,
            "finding": env.binding,
            "status": "static_checked",
            "upstream": {"review_handoff": env.verified["inputs"]["review_handoff"]},
            "assurance": nonexecution_assurance(),
        },
    )
    env.producer(
        "job_remediation_validation",
        REMEDIATION_VALIDATION_SUMMARY_SCHEMA,
        REMEDIATION_VALIDATION_HANDOFF_SCHEMA,
        [{"finding": env.binding, "status": "static_checked", "validation": bad_val_art, "gap_ids": []}],
        extra={"planning_handoff": {"path": env.accepted["job_remediation_planning"].path, "sha256": env.accepted["job_remediation_planning"].sha256}},
    )
    with pytest.raises(IntegrityError, match="disagrees with its accepted summary"):
        inputs.load_inputs(env.root, env.verified, cfg)

    env.producer(
        "job_remediation_validation",
        REMEDIATION_VALIDATION_SUMMARY_SCHEMA,
        REMEDIATION_VALIDATION_HANDOFF_SCHEMA,
        [{"finding": env.binding, "status": "", "validation": None, "gap_ids": []}],
        extra={"planning_handoff": {"path": env.accepted["job_remediation_planning"].path, "sha256": env.accepted["job_remediation_planning"].sha256}},
    )
    with pytest.raises(IntegrityError, match="no terminal status"):
        inputs.load_inputs(env.root, env.verified, cfg)

    # Valid planning + validation + valid/invalid attack_chain_manifest + decision_audit branches
    env.producer(
        "job_remediation_validation",
        REMEDIATION_VALIDATION_SUMMARY_SCHEMA,
        REMEDIATION_VALIDATION_HANDOFF_SCHEMA,
        [val_item],
        extra={"planning_handoff": {"path": env.accepted["job_remediation_planning"].path, "sha256": env.accepted["job_remediation_planning"].sha256}},
    )
    bad_chain_ref = _write(env.root, "bad-chains.json", {"schema": "wrong", "run_id": env.root.name})
    env.verified["inputs"]["review_handoff"] = _write(env.root, "rev-bad-chain.json", {"run_id": env.root.name, "attack_chain_manifest": bad_chain_ref})
    for j in list(env.accepted):
        if j != inputs.REVIEW_JOB:
            del env.accepted[j]
    with pytest.raises(IntegrityError, match="attack-chain manifest"):
        inputs.load_inputs(env.root, env.verified, cfg)

    good_chain_ref = _write(
        env.root,
        "good-chains.json",
        {
            "schema": ATTACK_CHAIN_MANIFEST_SCHEMA,
            "run_id": env.root.name,
            "items": [
                {"chain_id": "ch-other", "status": "qualified_supported", "component_claim_ids": ["other"], "artifact": None},
                {"chain_id": "ch-match", "status": "qualified_supported", "component_claim_ids": [env.binding["claim_id"]], "artifact": None},
            ],
        },
    )
    rev_good = _write(env.root, "rev-good-chain.json", {"run_id": env.root.name, "attack_chain_manifest": good_chain_ref})
    env.verified["inputs"]["review_handoff"] = rev_good
    env.producer("job_remediation_planning", REMEDIATION_PLANNING_SCHEMA, REMEDIATION_PLANNING_HANDOFF_SCHEMA, [plan_item_no_ref], review=rev_good)
    env.producer(
        "job_remediation_validation",
        REMEDIATION_VALIDATION_SUMMARY_SCHEMA,
        REMEDIATION_VALIDATION_HANDOFF_SCHEMA,
        [val_item_rebound := {**val_item, "validation": _write(env.root, "val-rebound.json", {"schema": REMEDIATION_VALIDATION_SCHEMA, "run_id": env.root.name, "finding": env.binding, "status": "static_checked", "upstream": {"review_handoff": rev_good}, "assurance": nonexecution_assurance()})}],
        review=rev_good,
        extra={"planning_handoff": {"path": env.accepted["job_remediation_planning"].path, "sha256": env.accepted["job_remediation_planning"].sha256}},
    )

    avail_audit = SimpleNamespace(available=True, reads=("r1",), unavailable_reason=None, reference=SimpleNamespace(to_dict=lambda: {"manifest_sha256": "9" * 64}))
    doc_avail = inputs.load_inputs(env.root, env.verified, cfg, decision_audit=avail_audit)
    assert doc_avail["decision_audit"] == {"manifest_sha256": "9" * 64}

    unavail_audit = SimpleNamespace(available=False, reads=("r1",), unavailable_reason="audit_missing", reference=None)
    doc_unavail = inputs.load_inputs(env.root, env.verified, cfg, decision_audit=unavail_audit)
    assert doc_unavail["decision_audit_unavailable_reason"] == "audit_missing"

    silent_audit = SimpleNamespace(available=False, reads=(), unavailable_reason=None, reference=None)
    doc_silent = inputs.load_inputs(env.root, env.verified, cfg, decision_audit=silent_audit)
    assert "decision_audit" not in doc_silent and "decision_audit_unavailable_reason" not in doc_silent

    # Exercise _remediation and _chains edge branches (ref is None, non-matching items)
    rem_rows = dossier_job._remediation(env.root, doc_silent, "non-matching-id", cfg)
    assert rem_rows == []
    rem_rows_match = dossier_job._remediation(env.root, doc_silent, env.binding["finding_package_id"], cfg)
    assert len(rem_rows_match) == 2
    chain_rows = dossier_job._chains(env.root, doc_silent, env.source["finding"], cfg)
    assert len(chain_rows) == 1 and chain_rows[0]["chain_id"] == "ch-match"

    # Non-confirmed finding rejected when remediation producer references it
    sup_finding = dict(env.source["finding"], state="supported")
    sup_claim = dict(env.source["claim"], state="supported")
    env.verified["packages"] = [sup_finding]
    env.verified["inputs"]["projection"] = _write(env.root, "sup-proj.json", {"claims": [sup_claim], "relations": {sup_claim["claim_id"]: env.source["relations"]}})
    with pytest.raises(IntegrityError, match="confirmed finding"):
        inputs.load_inputs(env.root, env.verified, cfg)


def test_job_create_publish_and_verify_publication_edges(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _seed_env(tmp_path, monkeypatch)
    cfg = settings(render_pdf=False)

    # _excerpts wrong returned identity raises IntegrityError
    class _BadCore:
        def read_excerpt(self, *, identity: str, context_lines: int) -> dict:
            return {"results": [{"identity": "wrong-id"}], "truncated": False}

    with pytest.raises(IntegrityError, match="returned another identity"):
        dossier_job._excerpts(_BadCore(), env.source["relations"], env.source["finding"], cfg)

    # PoC source non-UTF8 and oversize source_cap in create, plus decision_audit re-verification in create
    bad_utf8 = env.root / "data" / "seed" / "bad_utf8.cpp"
    atomic_bytes(bad_utf8, b"\xff\xfe\xfd")
    poc_bad_utf8 = copy.deepcopy(env.source["poc"])
    poc_bad_utf8["files"]["source"] = artifact_ref(env.root, bad_utf8)
    env.producer("job_poc_generation", POC_GENERATION_SCHEMA, POC_GENERATION_HANDOFF_SCHEMA, [poc_bad_utf8])

    unavail_audit = SimpleNamespace(
        available=False,
        reads=("r1",),
        unavailable_reason="audit_gap",
        reference=None,
        manifest=None,
        basis=lambda _cid: None,
    )

    class _GoodCore:
        def read_excerpt(self, *, identity: str, context_lines: int) -> dict:
            return {"results": env.source["excerpts"], "truncated": False}

    j = build_job(
        repository_root=ROOT,
        review_loader=lambda *_a, **_kw: SimpleNamespace(document=env.verified, decision_audit=unavail_audit),
        core_factory=lambda *_a: _GoodCore(),
    )
    with patch("appsec_review.review.decision_audit.reader.load_decision_audit", return_value=unavail_audit):
        res = j.execute(_ctx(env.root, "utf8-att"))
    assert res["status"] == "COMPLETED_WITH_GAPS"
    pub = res["outputs"]["acceptance.publish_handoff"]
    assert pub["terminal_status"] == "COMPLETED_WITH_GAPS"
    summary = read_bound_json(env.root, pub["artifact"])
    assert any("poc_source_unavailable" in g for g in summary["gaps"])

    # Decision audit changed between load and create -> FAILED in dossiers.create
    changed_audit = SimpleNamespace(
        available=False,
        reads=("r1",),
        unavailable_reason="different",
        reference=None,
        manifest=None,
        basis=lambda _cid: None,
    )
    with patch("appsec_review.review.decision_audit.reader.load_decision_audit", return_value=changed_audit):
        res_changed = j.execute(_ctx(env.root, "audit-changed"))
    assert res_changed["failed_units"] == ["dossiers.create"]

    # Oversize PoC source file triggers poc_source_cap
    big_src = env.root / "data" / "seed" / "big.cpp"
    atomic_bytes(big_src, b"a" * 200_000)
    poc_big = copy.deepcopy(env.source["poc"])
    poc_big["files"]["source"] = artifact_ref(env.root, big_src)
    env.producer("job_poc_generation", POC_GENERATION_SCHEMA, POC_GENERATION_HANDOFF_SCHEMA, [poc_big])
    j_plain = build_job(
        repository_root=ROOT,
        review_loader=lambda *_a, **_kw: SimpleNamespace(document=env.verified),
        core_factory=lambda *_a: _GoodCore(),
    )
    res_big = j_plain.execute(_ctx(env.root, "big-att", max_artifact_bytes=100_000))
    sum_big = read_bound_json(env.root, res_big["outputs"]["acceptance.publish_handoff"]["artifact"])
    assert any("poc_source_cap" in g for g in sum_big["gaps"])

    # verify_publication error branches
    with pytest.raises(IntegrityError, match="schema or run binding"):
        dossier_job.verify_publication(env.root, {**summary, "schema": "wrong"})

    dup_items = copy.deepcopy(summary)
    dup_items["items"].append(dup_items["items"][0])
    dup_items["counts"]["admitted"] += 1
    dup_items["counts"]["items"] += 1
    with pytest.raises(IntegrityError, match="duplicate or unknown"):
        dossier_job.verify_publication(env.root, dup_items)

    bad_kind_counts = copy.deepcopy(summary)
    bad_kind_counts["counts"]["by_kind"]["poc"] += 5
    with pytest.raises(IntegrityError, match="kind accounting"):
        dossier_job.verify_publication(env.root, bad_kind_counts)

    bad_status_counts = copy.deepcopy(summary)
    bad_status_counts["counts"]["by_status"]["rendered"] += 5
    with pytest.raises(IntegrityError, match="rendering accounting"):
        dossier_job.verify_publication(env.root, bad_status_counts)

    bad_item_status = copy.deepcopy(summary)
    bad_item_status["items"][0]["status"] = "bogus"
    bad_item_status["counts"]["by_status"]["latex_only"] -= 1
    with pytest.raises(IntegrityError, match="rendering accounting|unknown dossier render status"):
        dossier_job.verify_publication(env.root, bad_item_status)

    bad_model = copy.deepcopy(summary)
    bad_model["items"][0]["dossier_id"] = "dossier-" + "0" * 64
    with pytest.raises(IntegrityError, match="receipt/model disagrees"):
        dossier_job.verify_publication(env.root, bad_model)
