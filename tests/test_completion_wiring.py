from __future__ import annotations

from itertools import product
from pathlib import Path
from types import MappingProxyType

import pytest

from appsec_review.cli import POST_INDEX_JOB_IDS, main, parser
from appsec_review.config import load_config
from appsec_review.config.loader import profile_override_keys
from appsec_review.orchestration.topology import WAVE1_REQUIRED, upstream_closure, wave1_dependencies
from appsec_review.runtime.launch import TARGET_INDEPENDENT_JOBS, TARGET_JOBS, launch_inputs
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.runner import JobRunner


ROOT = Path(__file__).resolve().parents[1]
REVIEW = "job_inference_security_review"
GATE = "job_final_publication_gate"
REPORT = "job_final_report_publication"
OPTIONAL = ("job_poc_generation", "job_remediation_planning", "job_remediation_validation",
            "job_dossier_publication")
BASE = WAVE1_REQUIRED | {
    "job_review_data_indexing", "job_review_package_assembly", "job_document_issue_analysis",
    REVIEW, GATE, REPORT,
}


@pytest.mark.parametrize("enabled", list(product((False, True), repeat=len(OPTIONAL))))
def test_every_completion_configuration_has_no_gate_cycle_and_one_terminal(enabled) -> None:
    selected = {name for name, active in zip(OPTIONAL, enabled, strict=True) if active}
    if "job_remediation_validation" in selected and "job_remediation_planning" not in selected:
        with pytest.raises(ValueError, match="requires enabled job_remediation_planning"):
            wave1_dependencies(BASE | selected)
        return
    dependencies = wave1_dependencies(BASE | selected)
    assert dependencies is not None
    visited = set()
    for job_id, upstream in dependencies.items():
        assert set(upstream) <= visited
        visited.add(job_id)
    assert set(dependencies) - {parent for parents in dependencies.values() for parent in parents} == {REPORT}
    assert dependencies[REPORT] == (GATE,)
    gate_upstreams = set(upstream_closure(GATE, dependencies, set(dependencies)))
    assert selected <= gate_upstreams
    for job_id in selected:
        assert GATE not in upstream_closure(job_id, dependencies, set(dependencies))
    if "job_remediation_planning" in selected:
        assert REVIEW in upstream_closure("job_remediation_planning", dependencies, set(dependencies))


def test_direct_completion_order_agrees_with_publication_dependencies() -> None:
    assert POST_INDEX_JOB_IDS.index(REVIEW) < POST_INDEX_JOB_IDS.index("job_poc_generation")
    assert POST_INDEX_JOB_IDS.index("job_poc_generation") < POST_INDEX_JOB_IDS.index("job_remediation_planning")
    assert POST_INDEX_JOB_IDS.index("job_remediation_validation") < POST_INDEX_JOB_IDS.index("job_dossier_publication")
    assert POST_INDEX_JOB_IDS.index("job_dossier_publication") < POST_INDEX_JOB_IDS.index(GATE)
    assert POST_INDEX_JOB_IDS[-1] == REPORT


def test_indexing_excludes_every_downstream_consumer_but_retains_file_ownership() -> None:
    from appsec_review.jobs.job_review_data_indexing.job import DOWNSTREAM_JOBS, registry_providers

    job_ids, declarations, _consumes = registry_providers()
    registered = set(job_ids)
    dependencies = wave1_dependencies(registered)
    assert dependencies is not None
    consumers = {job_id for job_id in dependencies
                 if "job_review_data_indexing" in upstream_closure(job_id, dependencies, registered)}
    assert DOWNSTREAM_JOBS == consumers
    assert consumers <= declarations.keys()


@pytest.mark.parametrize("job_id", OPTIONAL[1:])
def test_new_completion_jobs_never_receive_the_live_target(job_id) -> None:
    assert job_id in TARGET_INDEPENDENT_JOBS
    assert job_id not in TARGET_JOBS
    from appsec_review.runtime import Job

    job = Job(job_id=job_id, name=job_id.removeprefix("job_"), handler=lambda context: {})
    inputs = launch_inputs(job, target=ROOT / "target-that-must-not-be-read", upstream_handoffs={"upstream": "a" * 64})
    assert inputs.target_root is None
    assert inputs.source_fingerprint == "none"
    assert inputs.upstream_handoffs == {"upstream": "a" * 64}


def test_job_context_preserves_an_immutable_explicit_upstream_admission(tmp_path: Path) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    runner = JobRunner(config)
    job = builtin_registry().build(GATE)
    runner.runs = type("Runs", (), {"resolve": lambda self, run_id: tmp_path / "runs" / run_id})()
    (tmp_path / "runs" / "test-context" / "attempt").mkdir(parents=True)
    claim = {"run_id": "test-context", "attempt_id": "attempt_0001", "trigger": "manual",
             "attempt_path": "attempt",
             "upstream_handoffs": {"job_poc_generation": "a" * 64}}
    context = runner._context(job, claim)
    assert context.upstream_handoffs == {"job_poc_generation": "a" * 64}
    assert isinstance(context.upstream_handoffs, MappingProxyType)
    claim["upstream_handoffs"]["job_poc_generation"] = "b" * 64
    assert context.upstream_handoffs["job_poc_generation"] == "a" * 64
    with pytest.raises(TypeError):
        context.upstream_handoffs["new"] = "c" * 64


@pytest.mark.parametrize("arguments", [
    ["run", "job_poc_generation", "--admit-manual-poc"],
    ["run", GATE, "--admit-manual-poc"],
    ["run", GATE, "--run-id", "fixture", "--admit-manual-poc"],
])
def test_manual_poc_admission_is_only_valid_for_an_explicit_run_gate(arguments) -> None:
    with pytest.raises(SystemExit) as exc:
        main(arguments)
    assert exc.value.code == 2


def test_manual_poc_admission_flag_is_explicit_and_opt_in() -> None:
    normal = parser().parse_args(["run", GATE])
    assert normal.admit_manual_poc is False
    explicit = parser().parse_args(["run", GATE, "--run-id", "fixture",
                                    "--upstream-from-run", "--admit-manual-poc"])
    assert explicit.admit_manual_poc is True


@pytest.mark.parametrize("job_id,field", [
    ("job_remediation_planning", "writer"), ("job_remediation_validation", "reviewer"),
])
def test_remediation_model_profiles_allow_only_bounded_model_settings(job_id, field) -> None:
    override = {"jobs": {job_id: {"settings": {field: {
        "provider": "claude-cli", "model": "claude-haiku-5-5", "max_queries": 4,
    }}}}}
    keys = profile_override_keys(override)
    assert f"jobs.{job_id}.settings.{field}.model" in keys
    override["jobs"][job_id]["settings"][field]["enabled"] = False
    with pytest.raises(ValueError, match="enabled"):
        profile_override_keys(override)


def test_default_completion_jobs_are_enabled_typed_and_registered_without_execution(monkeypatch) -> None:
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("configuration and job construction must not execute a process")

    monkeypatch.setattr(subprocess, "run", forbidden)
    config = load_config(ROOT / "appsec-review.toml")
    registry = builtin_registry()
    for job_id in OPTIONAL:
        assert config.job(job_id).settings["enabled"] is True
        job = registry.build(job_id)
        configured_units = tuple(f"{step_id}.{task_id}" for step_id, step in config.job(job_id).steps.items()
                                 for task_id in step.tasks)
        assert tuple(unit.unit_id for unit in job.units) == configured_units
    assert config.job("job_remediation_planning").typed_settings.writer.max_queries == 4
    assert config.job("job_remediation_validation").typed_settings.adapters == ("native_syntax",)
    assert config.job("job_dossier_publication").typed_settings.render_pdf is True
    review_units = tuple(unit.unit_id for unit in registry.build(REVIEW).units)
    assert review_units.index("scoring.score_claims") < review_units.index("attack_chains.compose_candidates")
    assert review_units.index("attack_chains.verify_weakest_links") < review_units.index("completeness.audit")


def test_configuration_rejects_enabled_validation_without_planning(tmp_path: Path) -> None:
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8").replace(
        "[jobs.job_remediation_planning.settings]\nenabled = true",
        "[jobs.job_remediation_planning.settings]\nenabled = false", 1)
    path = tmp_path / "appsec-review.toml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="requires enabled job_remediation_planning"):
        load_config(path)
