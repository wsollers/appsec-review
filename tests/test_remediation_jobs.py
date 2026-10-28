"""Semantic jobs over a real scripted accepted review, never a hand-written confirmed intake."""
from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from appsec_review.config.loader import JobConfig, StepConfig, TaskConfig
from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.jobs.job_remediation_planning import build_job as planning_job
from appsec_review.jobs.job_remediation_planning.inputs import binding, confirmed_findings, load_review
from appsec_review.jobs.job_remediation_validation import build_job as validation_job
from appsec_review.jobs.job_remediation_validation.inputs import load_planning
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.observability import EventLog
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import JobContext
from appsec_review.storage import file_sha256
from tests import remediation_support as support
from tests.final_report_support import job_tables, run_job
from tests.fixtures.inference_review.acceptance import JOB, write_config, write_overlay, write_scenario
from tests.fixtures.inference_review.builder import FILES, build_accepted_index_set


def summary(root, job):
    pointer = json.loads((root / "data" / "jobs" / job / "latest.json").read_text())
    handoff = json.loads((root / pointer["handoff_path"]).read_text())
    published = handoff["outputs"]["acceptance.publish_handoff"]
    return published, read_bound_json(root, published["artifact"])


@pytest.fixture(scope="module")
def chain(tmp_path_factory):
    base = tmp_path_factory.mktemp("rm")
    fixture = build_accepted_index_set(base / "data")
    native_ids = support.add_native_graph_facts(fixture)
    config = write_config(base, fixture.runs_dir,
                          extra=support.toml_tables() + job_tables("job_third_party_data_sync"))
    logs = base / "logs"
    logs.mkdir()
    env = {"APPSEC_REVIEW_CONFIG_OVERLAY": str(write_overlay(base, 1)), "APPSEC_C7_CONFIG": str(config),
           "APPSEC_C7_SCENARIO": str(write_scenario(logs, fixture.ids, calls=str(logs / "calls.jsonl"),
                                                     captures=str(logs / "captures")))}
    from appsec_review.jobs.job_inference_security_review import build_job as inference_review_job
    real_review = inference_review_job(infer=support.native_review_infer({**fixture.ids, **native_ids}),
                                     repository_root=support.ROOT)
    outcome = run_job(config, real_review, fixture.run_id, env=env)
    assert outcome["status"]["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}, outcome
    workspace = fixture.run_root / "data" / "remediation-fixture" / "accepted-workspace"
    workspace.mkdir(parents=True)
    source = workspace / "native" / "src" / "parse.c"
    source.parent.mkdir(parents=True)
    source.write_text(FILES["native/src/parse.c"][1], encoding="utf-8")
    manifest = {"native/src/parse.c": file_sha256(source)}
    builds = lambda _root: support.builds_for(fixture.run_root, workspace, manifest)
    writer, executor = support.Writer(retrieve=True), support.Executor()
    job = planning_job(infer=writer, builds_factory=builds, repository_root=support.ROOT)
    pointer = json.loads((fixture.run_root / "data" / "jobs" / JOB / "latest.json").read_text())
    outcome = run_job(config, job, fixture.run_id, {JOB: pointer["handoff_sha256"]}, env)
    assert outcome["status"]["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}, outcome
    return SimpleNamespace(base=base, fixture=fixture, root=fixture.run_root, config=config, env=env,
                           builds=builds, writer=writer, executor=executor, workspace=workspace, manifest=manifest,
                           native_ids=native_ids)


def direct(chain, job, settings, attempt):
    tasks = {"load": "verify_inputs", "assess": "propose" if job.job_id == support.PLAN else "validate",
             "acceptance": "publish_handoff"}
    steps = {step: StepConfig(step, 1, {}, {task: TaskConfig(task, 1, {})}) for step, task in tasks.items()}
    config = JobConfig(job.job_id, job.name, 1, None, settings, steps)
    root = chain.root / "data" / "jobs" / job.job_id / "attempts" / attempt
    context = JobContext(chain.root.name, attempt, "test", support.ROOT, chain.root, root,
                         chain.root / "metadata", {}, config, EventLog(root / "events.jsonl"))
    return job.execute(context), root


def direct_summary(result):
    return result["outputs"]["acceptance.publish_handoff"]["artifact"]


def test_native_fixture_basis_resolves_in_actual_packaged_view(tmp_path):
    from appsec_review.retrieval import RetrievalCore
    from appsec_review.review.package_view import ViewLimits, build_view
    from appsec_review.review.packages import assemble_packages
    from appsec_review.review.scope import accept_manifest
    from appsec_review.review.references import load_cwe_reference
    from appsec_review.review.scoring.evidence_source import AcceptedEvidenceSource

    fixture = build_accepted_index_set(tmp_path)
    ids = support.add_native_graph_facts(fixture)
    scope = accept_manifest(fixture.run_root)
    assembly = assemble_packages(scope)
    [package] = [item.document() for item in assembly.packages
                 if item.kind == "finding_lead" and item.lead_ids == (fixture.ids["sast_critical"],)]
    core = RetrievalCore(fixture.runs_dir, fixture.run_id)
    view = build_view(package, core, ViewLimits())
    assert view.document["neighborhood"]["function"]["name"] == "p"
    assert {ids["fix_entry"], ids["fix_call"], ids["fix_function"]} <= set(view.labels.values())
    tags = AcceptedEvidenceSource(core, scope).tags({fixture.ids["native/src/parse.c"]}, set(), set())
    assert any(tag.assignment_id == ids["fix_surface"] and tag.basis == "declared" for tag in tags)
    catalog = load_cwe_reference(fixture.run_root)
    assert catalog.source == "mitre_catalog", catalog.gap
    assert catalog.lookup("CWE-120").consequences


def test_real_review_produces_exact_confirmed_only_proposals_and_regression_specs(chain):
    published, document = summary(chain.root, support.PLAN)
    review = load_review(chain.root, support.ROOT, support.bounds())
    assert [row["finding"] for row in document["items"]] == [binding(row) for row in confirmed_findings(review)]
    assert published["item_count"] == len(document["items"])
    assert review["partition"]["supported"]
    assert not {row["finding"]["finding_package_id"] for row in document["items"]} & set(review["partition"]["supported"])
    proposals = [row for row in document["items"] if row["status"] == "proposal_generated"]
    assert proposals, [(row["status"], row["reason"]) for row in document["items"]]
    for row in proposals:
        plan = read_bound_json(chain.root, row["plan"])
        patch = read_bound_json(chain.root, plan["patch"])
        assert patch["files"][0]["before_sha256"] == chain.manifest["native/src/parse.c"]
        assert patch["files"][0]["edits"][0]["new"].startswith("if (strlen")
        assert plan["regression_spec"] == support.REGRESSION
        assert plan["assurance"] == {"execution": "not_performed_by_policy", "runtime_verified": False, "result_id": None}
        assert plan["adjudication_id"]
    assert any(request.transcript for request in chain.writer.requests)
    assert chain.writer.requests[0].role == "remediation_writer"


def test_native_review_really_emits_confirmed_poc_candidacy_without_injected_candidates(chain):
    review = load_review(chain.root, support.ROOT, support.bounds())
    handoff = read_bound_json(chain.root, review["inputs"]["review_handoff"])
    candidates = handoff["poc_candidates"]
    assert candidates, [(package["title"], package["state"], package["judge_verdict"],
                         [(score["native"], score["missing_factors"]) for score in package["scores"]])
                        for package in review["packages"]]
    assert len({candidate["claim_id"] for candidate in candidates}) == len(candidates)
    for candidate in candidates:
        assert candidate["state"] == "confirmed"
        assert candidate["finding_package"]["finding_package_id"] in review["partition"]["confirmed"]
        assert candidate["judge_verdict"] == "red_correct"
        basis = candidate["poc_basis"]["brief"]
        assert basis["entry"] == [chain.native_ids["fix_entry"]]
        assert basis["path"] == [chain.native_ids["fix_call"]]
        assert basis["trigger"][0]["field"] == "s"


def test_real_runner_publishes_build_checked_without_changing_original_state_or_shipment(chain):
    review = load_review(chain.root, support.ROOT, support.bounds())
    before = {item["path"]: (chain.root / item["path"]).read_bytes() for item in review["bindings"]}
    executor, reviewer = support.Executor(), support.Writer()
    job = validation_job(infer=reviewer, builds_factory=chain.builds,
                         executor_factory=lambda _unit, _profile: executor, repository_root=support.ROOT)
    plan_pointer = json.loads((chain.root / "data" / "jobs" / support.PLAN / "latest.json").read_text())
    result = run_job(chain.config, job, chain.root.name, {support.PLAN: plan_pointer["handoff_sha256"]}, chain.env)
    assert result["status"]["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}, result
    published, document = summary(chain.root, support.VALIDATE)
    checked = [row for row in document["items"] if row["status"] == "build_checked"]
    assert checked, [(row["status"], row["reason"]) for row in document["items"]]
    assert published["item_count"] == len(review["partition"]["confirmed"])
    for row in checked:
        record = read_bound_json(chain.root, row["validation"])
        assert record["checks"]["semantic_review"]["status"] == "analyst_supported"
        assert record["checks"]["build"]["status"] == "passed"
        assert record["checks"]["runtime_regression"]["status"] == "not_performed_by_policy"
        assert record["checks"]["regression_compile"]["status"] == "not_performed"
        assert read_bound_json(chain.root, record["cleanup"])["removed"] is True
        assert not any(key in record for key in ("ship_block", "remediation_priority", "state"))
    for request in reviewer.requests:
        assert request.cell_id.startswith("remediation-reviewer:")
        assert "reason" not in request.task_input["task"]
        assert "compatibility_effects" not in request.task_input["task"]
        assert request.transcript == ()
    for call in executor.calls:
        argv = call["argv"]
        assert argv[0] == "/usr/bin/clang" and "-fsyntax-only" in argv and "-o" not in argv
        assert "scratch" in call["workspace"].parts
    events = [json.loads(line) for line in (chain.root / "data" / "jobs" / support.VALIDATE / "attempts" /
                                           "attempt_0001" / "logs" / "events.jsonl").read_text().splitlines()]
    published_event = next(event for event in events if event["event"] == "REMEDIATION_VALIDATION_PUBLISHED")
    assert published_event["item_count"] == len(document["items"])
    assert sum(published_event["outcome_counts"].values()) == len(document["items"])
    assert published_event["outcome_counts"]["build_checked"] == len(checked)
    assert published_event["output_bytes"] > 0
    adapter_events = [event for event in events if event["event"] == "REMEDIATION_VALIDATION_ADAPTER_COMPLETED"]
    assert len(adapter_events) == len(checked)
    assert all(event["baseline_attempted"] and event["patched_attempted"] and event["timeout_count"] == 0
               and event["failure_count"] == 0 and event["duration_ms"] >= 0 for event in adapter_events)
    telemetry = json.dumps([event for event in events if event["event"].startswith("REMEDIATION_")])
    assert "strcpy" not in telemetry and "violated_invariant" not in telemetry and "source_files" not in telemetry
    assert {item: (chain.root / item).read_bytes() for item in before} == before
    assert file_sha256(chain.workspace / "native" / "src" / "parse.c") == chain.manifest["native/src/parse.c"]


@pytest.mark.parametrize("codes,adapters,unavailable,expected,check", [
    ((1, 0), ["native_syntax"], False, "inconclusive", "baseline_failed"),
    ((0, 1), ["native_syntax"], False, "rejected", "patched_failed"),
    ((0, 0), [], False, "static_checked", "not_performed"),
    ((0, 0), ["native_syntax"], True, "static_checked", "unavailable"),
])
def test_comparison_outcomes_are_truthfully_assurance_labelled(chain, codes, adapters, unavailable, expected, check):
    executor = support.Executor(codes, unavailable=unavailable)
    job = validation_job(infer=support.Writer(), builds_factory=chain.builds,
                         executor_factory=lambda _unit, _profile: executor, repository_root=support.ROOT)
    attempt = f"scenario-{expected}-{check}"
    result, root = direct(chain, job, support.validation_settings(adapters=adapters), attempt)
    assert not result["failed_units"], result
    document = read_bound_json(chain.root, direct_summary(result))
    rows = [row for row in document["items"] if row["validation"] is not None
            and read_bound_json(chain.root, row["validation"])["patch"] is not None]
    assert rows
    first = read_bound_json(chain.root, rows[0]["validation"])
    assert first["status"] == expected
    assert first["checks"]["build"]["status"] == check
    assert read_bound_json(chain.root, first["cleanup"])["removed"]
    assert not list(root.rglob("scratch"))


def test_invalid_writer_and_candidate_caps_are_accounted_without_placeholders(chain):
    writer = support.Writer(invalid=True)
    job = planning_job(infer=writer, builds_factory=chain.builds, repository_root=support.ROOT)
    result, _root = direct(chain, job, support.planning_settings(max_candidates=1), "invalid-writer")
    assert not result["failed_units"], result
    summary_doc = read_bound_json(chain.root, direct_summary(result))
    assert len(summary_doc["items"]) == len(summary(chain.root, support.PLAN)[1]["items"])
    assert summary_doc["items"][0]["status"] == "insufficient_evidence"
    assert summary_doc["items"][0]["plan"] is None
    assert all(row["status"] == "capped" and row["plan"] is None for row in summary_doc["items"][1:])
    assert len(writer.requests) == 1
    assert summary_doc["gaps"]


def test_retry_retains_every_byte_reachable_from_previous_accepted_plans(chain):
    _published, previous = summary(chain.root, support.PLAN)
    refs = []
    for item in previous["items"]:
        if item["plan"]:
            refs.append(item["plan"])
            plan = read_bound_json(chain.root, item["plan"])
            refs.extend(plan["provenance"][key] for key in ("source_context", "writer_receipt"))
            if plan["patch"]:
                refs.append(plan["patch"])
    before = {ref["path"]: (chain.root / ref["path"]).read_bytes() for ref in refs}
    job = planning_job(infer=support.Writer(), builds_factory=chain.builds, repository_root=support.ROOT)
    result, root = direct(chain, job, support.planning_settings(), "retry-immutable")
    assert not result["failed_units"], result
    assert {name: (chain.root / name).read_bytes() for name in before} == before
    new = read_bound_json(chain.root, direct_summary(result))
    assert all(root in (chain.root / row["plan"]["path"]).parents for row in new["items"] if row["plan"])


def test_manifest_tamper_and_cross_review_mixing_fail_closed(chain):
    review = load_review(chain.root, support.ROOT, support.bounds())
    schemas = SchemaSet(support.ROOT / "docs" / "schemas" / "remediation")
    _ref, _summary = load_planning(chain.root, review, schemas)
    wrong = deepcopy(review)
    wrong["inputs"]["review_handoff"]["sha256"] = "0" * 64
    with pytest.raises(IntegrityError, match="cross-review"):
        load_planning(chain.root, wrong, schemas)
    row = next(item for item in _summary["items"] if item["plan"])
    path = chain.root / row["plan"]["path"]
    before = path.read_bytes()
    try:
        path.write_bytes(before + b" ")
        with pytest.raises((IntegrityError, ValueError), match="(changed|integrity)"):
            load_planning(chain.root, review, schemas)
    finally:
        path.write_bytes(before)


def test_generated_or_undeclared_executor_edits_fail_and_cleanup_is_retained(chain):
    executor = support.Executor(mutate=True)
    job = validation_job(infer=support.Writer(), builds_factory=chain.builds,
                         executor_factory=lambda _unit, _profile: executor, repository_root=support.ROOT)
    result, root = direct(chain, job, support.validation_settings(), "undeclared-executor-edit")
    assert result["failed_units"] == ["assess.validate"]
    receipts = list(root.rglob("cleanup.json"))
    assert receipts and all(json.loads(path.read_text())["removed"] for path in receipts)
    assert not list(root.rglob("scratch"))


def test_missing_native_source_produces_manual_design_not_fake_patch_or_build(chain):
    # No accepted native workspace is offered; indexed evidence still allows an honest design outcome.
    from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds
    builds = lambda root: AcceptedBuilds(root, loader=lambda _root: {"receipts": []})
    job = planning_job(infer=support.Writer(), builds_factory=builds, repository_root=support.ROOT)
    result, _root = direct(chain, job, support.planning_settings(), "no-native-source")
    assert not result["failed_units"], result
    document = read_bound_json(chain.root, direct_summary(result))
    assert all(row["status"] == "manual_design_required" for row in document["items"])
    assert all(read_bound_json(chain.root, row["plan"])["patch"] is None for row in document["items"])
