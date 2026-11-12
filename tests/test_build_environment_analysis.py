from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import (
    BuildEnvironmentSettings, PlanningFeedbackSettings, load_config, parse_bounded_settings,
)
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_build_environment_analysis.job import (
    JOB_ID, analyze_environment, build_job, environment_contract, load_environment, redact, validate_environment,
)
from appsec_review.jobs.job_review_intake import build_job as intake_job
from appsec_review.jobs.job_target_catalog import build_job as catalog_job
from appsec_review.runtime import GraphRunner

ROOT = Path(__file__).parents[1]


def _static(files, **limits):
    payloads = {path: text.encode() for path, text in files.items()}
    catalog = {"source_fingerprint": "synthetic-source", "catalog_handoff_sha256": "c" * 64,
               "files": [{"path": path, "sha256": hashlib.sha256(data).hexdigest(),
                          "size_bytes": len(data)} for path, data in payloads.items()]}
    return analyze_environment(catalog, lambda item, bound: payloads[item["path"]][:bound + 1],
                               replace(BuildEnvironmentSettings(), **limits))


def test_static_literals_are_advisory_redacted_and_source_resolving():
    value = _static({"setup.sh": "SDK_ROOT=tools/sdk\nAPI_TOKEN=do-not-retain\nURL=https://u:p@host/a\n"})
    assert value["availability"] == "AVAILABLE"
    assert value["declarations"][0]["value"] == "tools/sdk"
    assert value["declarations"][0]["reason"] == "static_literal_advisory_only"
    assert [item["status"] for item in value["declarations"]] == ["declared", "redacted", "redacted"]
    assert all(item["sha256"] == hashlib.sha256(
        b"SDK_ROOT=tools/sdk\nAPI_TOKEN=do-not-retain\nURL=https://u:p@host/a\n").hexdigest()
               for item in value["declarations"])
    assert "do-not-retain" not in json.dumps(value)
    assert "u:p@" not in json.dumps(value)


@pytest.mark.parametrize("text", [
    "if test -f flag; then\nCC=clang\nfi\n", "source other.sh\nCC=clang\n",
    "SDK=$(dirname \"$0\")\nCC=clang\n", "call other.cmd\nCC=clang\n",
    "cd child\nCC=clang\n", "CC=clang;make\n", "CC=clang args\n",
    "pushd child\nCC=clang\n", "function setup {\nCC=clang\n}\n", "setup() {\nCC=clang\n}\n",
])
def test_uncertain_script_context_never_becomes_a_known_value(text):
    value = _static({"setup.sh": text})
    assert value["declarations"]
    assert all(item["value"] is None and item["status"] == "unknown" for item in value["declarations"])


def test_literal_sourced_inventory_is_bounded_and_context_tainted():
    value = _static({"setup.sh": "source child.sh\n", "child.sh": "CC=clang\n",
                     "unselected.sh": "UNRELATED=1\n"})
    assert value["bounds"]["inspected_scripts"] == 2
    assert value["declarations"][0]["path"] == "child.sh"
    assert value["declarations"][0]["status"] == "unknown"
    assert all(item["name"] != "UNRELATED" for item in value["declarations"])


@pytest.mark.parametrize("child", ["env-child.sh", "z-env.sh"])
def test_sourced_context_taints_an_already_selected_script_in_either_discovery_order(child):
    value = _static({"setup.sh": "source " + child + "\n", child: "CC=clang\n"})
    assert value["bounds"]["inspected_scripts"] == 2
    declarations = [item for item in value["declarations"] if item["path"] == child]
    assert len(declarations) == 1 and declarations[0]["status"] == "unknown"
    assert declarations[0]["value"] is None and value["coverage"] == "partial"


@pytest.mark.parametrize("limit,files,expected", [
    ({"max_scripts": 1}, {"env-a.sh": "A=1", "env-b.sh": "B=2"}, "script_count_exhausted"),
    ({"max_script_bytes": 1}, {"setup.sh": "A=1"}, "script_byte_bound"),
    ({"max_assignments": 1}, {"setup.sh": "A=1\nB=2\n"}, "assignment_count_exhausted"),
    ({"max_depth": 1}, {"setup.sh": "source a.sh", "a.sh": "source b.sh",
                       "b.sh": "B=2"}, "source_depth_or_script_bound"),
])
def test_static_exhaustion_publishes_partial_coverage(limit, files, expected):
    value = _static(files, **limit)
    assert value["coverage"] == "partial"
    assert any(expected in gap for gap in value["gaps"])


def test_powershell_and_empty_inventory_have_distinct_honest_coverage():
    unsupported = _static({"setup.ps1": "$env:CC='cl'"})
    assert unsupported["availability"] == "UNAVAILABLE" and unsupported["coverage"] == "partial"
    assert _static({})["coverage"] == "not_applicable"
    assert "inspected scope" not in unsupported["gaps"]


def test_internal_deadline_is_a_named_gap_not_an_unexpected_failure():
    catalog = {"source_fingerprint": "s", "catalog_handoff_sha256": "c" * 64, "files": []}
    # A finite empty scope is not a timeout; a pending script is.
    catalog["files"] = [{"path": "setup.sh", "sha256": "a" * 64, "size_bytes": 1}]
    times = iter((0, 31))
    result = analyze_environment(catalog, lambda *_: pytest.fail("deadline must prevent the read"),
                                 BuildEnvironmentSettings(), clock=lambda: next(times))
    assert result["availability"] == "UNAVAILABLE"
    assert result["gaps"] == ["internal_environment_deadline"]


def test_source_corruption_and_unexpected_reader_bugs_propagate():
    catalog = {"source_fingerprint": "s", "catalog_handoff_sha256": "c" * 64,
               "files": [{"path": "setup.sh", "sha256": "a" * 64, "size_bytes": 3}]}
    with pytest.raises(ValueError, match="source bytes changed"):
        analyze_environment(catalog, lambda *_: b"A=1", BuildEnvironmentSettings())
    def broken(*_):
        raise RuntimeError("synthetic unexpected bug")
    with pytest.raises(RuntimeError, match="synthetic unexpected bug"):
        analyze_environment(catalog, broken, BuildEnvironmentSettings())


@pytest.mark.parametrize("kind,key,value", [
    ("environment", "max_scripts", 65), ("environment", "max_script_bytes", 262145),
    ("environment", "max_assignments", 4097), ("environment", "max_depth", 5),
    ("environment", "enabled", "true"), ("feedback", "max_calls", 5),
    ("feedback", "max_evidence_rounds", 4), ("feedback", "max_documents", 9),
    ("feedback", "max_request_bytes", 131073), ("feedback", "max_response_bytes", 65537),
    ("feedback", "units_per_scope", 0), ("feedback", "max_scopes", True),
])
def test_typed_bounds_reject_loosening_and_nonintegers(kind, key, value):
    with pytest.raises(ValueError):
        parse_bounded_settings({key: value}, BuildEnvironmentSettings if kind == "environment"
                               else PlanningFeedbackSettings)


def _published(tmp_path, *, reusable=False, mode="strict"):
    config_path = tmp_path / "appsec-review.toml"
    target = tmp_path / "target"
    target.mkdir()
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if reusable:
        policy = '[review_policy]\nmode = "strict"\napproved_first_party_projects = []'
        assert text.count(policy) == 1 and text.count("[review_policy.releases]\n") == 1
        text = text.replace(policy,
            f'[review_policy]\nmode = "{mode}"\nproject_id = "synthetic-environment"\n'
            'approved_first_party_projects = ["synthetic-environment"]\n'
            f'target_root = {json.dumps(str(target))}\ncustody = "application_private_v1"')
    config_path.write_bytes(text.encode("utf-8"))
    config = load_config(config_path)
    (target / "setup.sh").write_bytes(b"SDK_ROOT=tools/sdk\n")
    fingerprint = source_fingerprint(target)
    result = GraphRunner(config, [intake_job(), catalog_job(), build_job()]).run(
        target_root=target, source_fingerprint=fingerprint)
    run_root = config.runtime.runs_dir / result["run_id"]
    pointer = json.loads((run_root / "data/jobs" / JOB_ID / "latest.json").read_bytes())
    contract = environment_contract(config, {"workflow": "wave1_review"},
                                    {JOB_ID: pointer["handoff_sha256"]})
    return config, run_root, fingerprint, contract


def test_real_static_producer_publication_and_strict_current_reader(tmp_path):
    config, root, fingerprint, contract = _published(tmp_path)
    value = load_environment(root, fingerprint, contract)
    assert config.job(JOB_ID).settings["enabled"] is True
    assert value["availability"] == "AVAILABLE"
    assert value["evidence"]["declarations"][0]["name"] == "SDK_ROOT"
    assert value["expected_producer"] == JOB_ID
    assert value["artifact"]["sha256"] == hashlib.sha256(
        (root / value["artifact"]["path"]).read_bytes()).hexdigest()


@pytest.mark.parametrize("consumer_id", ["job_language_build", "job_evidence_collection"])
def test_plan_consumer_admits_and_records_bound_environment(tmp_path, consumer_id):
    from appsec_review.jobs.job_evidence_collection.datasets import CONTRACT as evidence_contract
    from appsec_review.jobs.job_language_build.datasets import CONTRACT as language_contract
    from appsec_review.jobs.job_project_build.datasets import DATASETS as project_datasets
    from appsec_review.runtime import Job, JobRunner, Unit
    from appsec_review.runtime.contracts import EvidenceAuthority

    config, root, source, environment = _published(tmp_path)
    runner = JobRunner(config)
    target = tmp_path / "target"
    # This input fixture supplies the required project handoff; no build behavior is under test.
    runner.run(Job("job_project_build", config.job("job_project_build").name, lambda _: {},
                   units=(Unit("acceptance.publish_handoff", lambda _: {}),),
                   datasets=project_datasets),
               run_id=root.name, target_root=target, source_fingerprint=source)
    contract = language_contract if consumer_id == "job_language_build" else evidence_contract
    inputs = [item for item in contract.inputs if item.producer == JOB_ID]
    assert {item.output_kind for item in inputs} == {"handoff", "build_environment"}
    assert all(item.authority is EvidenceAuthority.OPERATIONAL for item in inputs)

    def read_environment(unit):
        return {"environment": load_environment(unit.job.run_root, source, environment)}

    unit_id = "iterations.dispatch" if consumer_id == "job_language_build" else "source_sast.semgrep_scan"
    consumer = Job(consumer_id, config.job(consumer_id).name, lambda _: {},
                   units=(Unit(unit_id, read_environment),), contract=contract,
                   input_identity=lambda _: "environment-reader-fixture-no-external-feeds")
    result = runner.run(consumer, run_id=root.name, target_root=target, source_fingerprint=source)
    attempt = Path(result["attempt_root"])
    claim = json.loads((attempt / "claim.json").read_bytes())
    assert claim["upstream_handoffs"][JOB_ID] == environment["reference"]
    step, task = unit_id.split(".")
    unit_path = attempt / "steps" / step / "tasks" / task
    status = json.loads((unit_path / "status.json").read_bytes())
    assert any(item["producer"] == JOB_ID and item["read"]
               and item["authority"] == "operational"
               and item["handoff_sha256"] == environment["reference"]
               for item in status["input_consumption"]["reads"])
    output = json.loads((unit_path / "result.json").read_bytes())
    assert output["environment"]["reference"] == environment["reference"]
    assert output["environment"]["evidence"]["declarations"][0]["name"] == "SDK_ROOT"


def test_real_environment_publication_uses_registered_build_dataset_contract(tmp_path):
    from appsec_review.jobs.job_build_environment_analysis.datasets import CONSUMES, DATASETS
    from appsec_review.runtime.datasets import FAMILIES, METADATA_ROUTE, read_dataset_contract

    producer = build_job()
    assert producer.datasets == DATASETS and producer.consumes == CONSUMES == ("job_target_catalog",)
    declaration, = producer.datasets
    assert declaration.family == "build" and declaration.family in FAMILIES
    assert "build_environment" not in FAMILIES
    assert declaration.output_kind == "build_environment"
    assert declaration.step == "environment_analysis"
    assert declaration.schema == producer.schema_identity == "appsec-review/build-environment-analysis/1"
    assert declaration.sensitivity == "sensitive" and declaration.disposition == "artifact_only"
    assert declaration.query_route == METADATA_ROUTE
    assert declaration.reason == "advisory source declarations; never recipe-enforced target proof"
    assert declaration.artifacts == (
        "data/jobs/job_build_environment_analysis/attempts/*/steps/"
        "environment_analysis/tasks/publish_handoff/build-environment.json",)
    with pytest.raises(ValueError, match="unknown dataset family: build_environment"):
        replace(declaration, family="build_environment")

    _, root, source, contract = _published(tmp_path)
    environment = load_environment(root, source, contract)
    pointer = json.loads((root / "data/jobs" / JOB_ID / "latest.json").read_bytes())
    handoff_bytes = (root / pointer["handoff_path"]).read_bytes()
    assert hashlib.sha256(handoff_bytes).hexdigest() == contract["reference"]
    handoff = json.loads(handoff_bytes)
    claim = json.loads((root / handoff["resolving_paths"]["attempt"] / "claim.json").read_bytes())
    steps, published = read_dataset_contract(claim["dataset_contract"], JOB_ID)
    assert steps == ("environment_analysis",) and published == DATASETS
    assert handoff["dataset_contract_sha256"] == claim["dataset_contract"]["sha256"]
    artifact = handoff["outputs"]["environment_analysis.publish_handoff"]["artifact"]
    assert artifact == environment["artifact"] and Path(artifact["path"]).match(declaration.artifacts[0])
    assert artifact in handoff["artifacts"]
    raw = (root / artifact["path"]).read_bytes()
    assert len(raw) == artifact["size_bytes"] and hashlib.sha256(raw).hexdigest() == artifact["sha256"]
    assert environment["availability"] == "AVAILABLE"
    assert environment["evidence"]["declarations"][0]["reason"] == "static_literal_advisory_only"


def test_optional_prior_stale_is_unavailable_but_expected_current_blocks(tmp_path):
    config, root, source, contract = _published(tmp_path)
    optional = environment_contract(config, {"environment_mode": "OPTIONAL_PRIOR"},
                                    {JOB_ID: contract["reference"]})
    assert optional["mode"] == "OPTIONAL_PRIOR" and optional["expected_producer"] is None
    assert optional["workflow"] == "standalone" and optional["reference"] == contract["reference"]
    current = load_environment(root, source, optional)
    assert current["availability"] == "AVAILABLE" and current["evidence"]["declarations"]
    value = load_environment(root, "other-source", optional)
    assert value["availability"] == "UNAVAILABLE"
    assert value["evidence"] is None and value["artifact"] is None
    assert value["reason"] == "STALE optional prior source"
    with pytest.raises(ValueError, match="wrong source"):
        load_environment(root, "other-source", contract)
    (root / current["artifact"]["path"]).write_bytes(b"{}")
    with pytest.raises(ValueError, match="identity mismatch"):
        load_environment(root, "other-source", optional)


@pytest.mark.parametrize("workflow", ["wave1_review", "project_build_review"])
def test_scheduled_environment_cannot_be_downgraded_to_optional_prior(workflow):
    config = load_config(ROOT / "appsec-review.toml")
    with pytest.raises(ValueError, match="scheduled environment producer cannot be optional"):
        environment_contract(config, {"workflow": workflow, "environment_mode": "OPTIONAL_PRIOR"},
                             {JOB_ID: "a" * 64})


@pytest.mark.parametrize("stale", [False, True])
@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
@pytest.mark.parametrize("reference_source", ["upstream", "host"])
def test_optional_prior_host_identity_survives_direct_launch_and_reuse(
        tmp_path, stale, mode, reference_source):
    from appsec_review.jobs.job_target_analysis_plan import build_job as planner_job, load_accepted_plan
    from appsec_review.runtime import JobRunner
    from appsec_review.runtime.resume import ResumePlanner
    config, root, source, environment = _published(tmp_path, reusable=True, mode=mode)
    prior = load_environment(root, source, environment)
    target = tmp_path / "target"
    if stale:
        (target / "README.md").write_bytes(b"synthetic new source after accepted optional environment\n")
        source = source_fingerprint(target)
        GraphRunner(config, [intake_job(), catalog_job()]).run(
            target_root=target, source_fingerprint=source, run_id=root.name)
    upstream = {name: json.loads((root / "data/jobs" / name / "latest.json").read_bytes())["handoff_sha256"]
                for name in ("job_review_intake", "job_target_catalog", JOB_ID)}
    orchestration = {"workflow": "standalone", "environment_mode": "OPTIONAL_PRIOR"}
    if reference_source == "host":
        upstream.pop(JOB_ID)
        orchestration["environment_reference"] = environment["reference"]
    job = planner_job(infer=lambda *_args, **_kwargs: pytest.fail("environment-only fixture cannot call a model"))
    runner = JobRunner(config)
    result = runner.run(job, run_id=root.name, target_root=target, source_fingerprint=source,
                        upstream_handoffs=upstream, orchestration=orchestration)
    plan = load_accepted_plan(root)
    stored = plan["build_environment"]
    assert stored["mode"] == "OPTIONAL_PRIOR" and stored["expected_producer"] is None
    assert stored["reference"] == environment["reference"]
    assert stored["availability"] == ("UNAVAILABLE" if stale else "AVAILABLE")
    assert (stored["evidence"] is None) is stale
    assert (stored["artifact"] is None) is stale
    original = json.loads((Path(result["attempt_root"]) / "claim.json").read_bytes())
    launch = environment_contract(config, orchestration, upstream)
    assert json.loads(original["orchestration"]["build_environment_contract"]) == launch
    required = {key: value for key, value in upstream.items() if key != JOB_ID}
    assert original["upstream_handoffs"] == result["handoff"]["upstream_handoff_sha256"] == required
    assert environment["reference"] not in json.dumps(json.loads(
        (root / original["input_manifest_path"]).read_bytes()))
    resumed = ResumePlanner(config, root, [job], source, target_root=target,
                            orchestration=orchestration)
    assert resumed.accepted(job, upstream) == ((), result["handoff_sha256"])
    claim = runner.begin_or_reuse_attempt(job, run_id=root.name, target_root=target,
        source_fingerprint=source, upstream_handoffs=upstream, orchestration=orchestration)
    assert claim["reused"] is True and claim["attempt_id"] == original["attempt_id"]
    assert claim["upstream_handoffs"] == required
    assert json.loads(claim["orchestration"]["build_environment_contract"]) == launch
    assert load_accepted_plan(root) == plan
    if stale and reference_source == "upstream":
        with pytest.raises(ValueError, match="current catalog|wrong source"):
            ResumePlanner(config, root, [job], source, target_root=target).accepted(job, upstream)
    else:
        reasons, _ = ResumePlanner(config, root, [job], source,
                                   target_root=target).accepted(job, upstream)
        assert "planning environment availability identity changed" in reasons
    assert not (root / "data/jobs/job_target_analysis_plan/attempts/attempt_0002").exists()
    artifact = root / prior["artifact"]["path"]
    artifact.write_bytes(artifact.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="identity mismatch"):
        runner.begin_or_reuse_attempt(job, run_id=root.name, target_root=target,
            source_fingerprint=source, upstream_handoffs=upstream, orchestration=orchestration)
    assert not (root / "data/jobs/job_target_analysis_plan/attempts/attempt_0002").exists()


@pytest.mark.parametrize("stale", [False, True])
@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
def test_unscheduled_optional_host_reference_survives_actual_graph_plan_and_run(tmp_path, stale, mode):
    from appsec_review.jobs.job_target_analysis_plan import build_job as planner_job, load_accepted_plan
    config, root, source, environment = _published(tmp_path, reusable=True, mode=mode)
    target = tmp_path / "target"
    if stale:
        (target / "README.md").write_bytes(b"synthetic new graph source\n")
        source = source_fingerprint(target)
    orchestration = {"workflow": "standalone", "environment_mode": "OPTIONAL_PRIOR",
                     "environment_reference": environment["reference"]}
    job = planner_job(infer=lambda *_args, **_kwargs: pytest.fail("environment-only fixture cannot call a model"))
    graph = GraphRunner(config, [intake_job(), catalog_job(), job])
    first = graph.run(target_root=target, source_fingerprint=source, run_id=root.name,
                      orchestration=orchestration)
    stored = load_accepted_plan(root)["build_environment"]
    assert stored["reference"] == environment["reference"] and stored["mode"] == "OPTIONAL_PRIOR"
    assert stored["availability"] == ("UNAVAILABLE" if stale else "AVAILABLE")
    assert (stored["evidence"] is None) is stale
    # A stale optional prior is a named planner gap, never a silent success.
    plan_gaps = load_accepted_plan(root)["coverage_gaps"]
    assert ("build environment: STALE optional prior source" in plan_gaps) is stale
    if stale:
        assert first["jobs"]["job_target_analysis_plan"]["status"]["status"] == "COMPLETED_WITH_GAPS"
    planned = graph.plan(root.name, source, target_root=target, orchestration=orchestration)
    assert [decision.action for decision in planned] == ["REUSE", "REUSE", "REUSE"]
    again = graph.run(target_root=target, source_fingerprint=source, run_id=root.name,
                      orchestration=orchestration)
    assert [decision["action"] for decision in again["decisions"]] == ["REUSE", "REUSE", "REUSE"]
    assert again["jobs"]["job_target_analysis_plan"]["handoff_sha256"] == (
        first["jobs"]["job_target_analysis_plan"]["handoff_sha256"])
    without_prior = graph.plan(root.name, source, target_root=target)
    assert without_prior[-1].action == "RUN"
    assert "planning environment availability identity changed" in without_prior[-1].reasons
    with pytest.raises(ValueError, match="^environment reference is not the accepted producer$"):
        graph.plan(root.name, source, target_root=target, orchestration={"workflow": "wave1_review"})


@pytest.mark.parametrize("orchestration,upstream", [
    ({"environment_mode": "OPTIONAL_PRIOR"}, {}),
    ({"environment_reference": "a" * 64}, {}),
    ({"environment_mode": "OPTIONAL_PRIOR", "environment_reference": "not-a-hash"}, {}),
    ({"environment_mode": "OPTIONAL_PRIOR", "environment_reference": "a" * 64}, {JOB_ID: "b" * 64}),
    ({"environment_mode": "NOT_RUN", "environment_reference": "a" * 64}, {}),
])
def test_explicit_optional_host_references_reject_missing_conflicting_or_contradictory_identity(
        orchestration, upstream):
    config = load_config(ROOT / "appsec-review.toml")
    with pytest.raises(ValueError):
        environment_contract(config, orchestration, upstream)


@pytest.mark.parametrize("mode,availability", [("NOT_RUN", "ABSENT"), ("DISABLED", "DISABLED")])
def test_explicit_absent_or_disabled_needs_no_producer(tmp_path, mode, availability):
    config = load_config(ROOT / "appsec-review.toml")
    orchestration = {}
    if mode == "DISABLED":
        jobs = dict(config.jobs)
        jobs[JOB_ID] = replace(jobs[JOB_ID], settings={**jobs[JOB_ID].settings, "enabled": False})
        config = replace(config, jobs=jobs)
    upstream = {JOB_ID: "a" * 64} if mode == "DISABLED" else {}
    contract = environment_contract(config, orchestration, upstream)
    assert contract["mode"] == mode and contract["reason"]
    assert contract["expected_producer"] is None
    assert load_environment(tmp_path, "s", contract)["availability"] == availability


def test_expected_current_missing_and_changed_bytes_block(tmp_path):
    config = load_config(ROOT / "appsec-review.toml")
    contract = environment_contract(config, {"workflow": "wave1_review"}, {})
    with pytest.raises(ValueError, match="no accepted handoff"):
        load_environment(tmp_path, "s", contract)
    _, root, source, contract = _published(tmp_path)
    value = load_environment(root, source, contract)
    (root / value["artifact"]["path"]).write_bytes(b"{}")
    with pytest.raises(ValueError, match="identity mismatch"):
        load_environment(root, source, contract)


def test_redaction_precedes_model_context():
    assert redact("TOKEN=abc\nURL=https://name:password@host/x\n") == (
        "[REDACTED assignment]\nURL=https://[REDACTED]@host/x\n")


@pytest.mark.parametrize("mutation", ["unknown_field", "unknown_bound", "loosen_bound", "bad_path",
                                   "unavailable_facts", "false_complete", "false_not_applicable"])
def test_environment_reader_rejects_schema_and_coverage_corruption(mutation):
    value = _static({"setup.sh": "SDK=tools/sdk\n"})
    if mutation == "unknown_field":
        value["extra"] = True
    elif mutation == "unknown_bound":
        value["bounds"]["extra"] = True
    elif mutation == "loosen_bound":
        value["bounds"]["max_scripts"] = 65
    elif mutation == "bad_path":
        value["declarations"][0]["path"] = "dir\\setup.sh"
    elif mutation == "unavailable_facts":
        value["availability"] = "UNAVAILABLE"
    elif mutation == "false_complete":
        value["gaps"] = ["unsupported"]
    else:
        value["coverage"] = "not_applicable"
    with pytest.raises(ValueError):
        validate_environment(value)


def test_redaction_preserves_unmodified_raw_line_endings_and_withholds_container_secrets():
    text = "FROM pinned-base\r\nENV SDK=tools/sdk\r\n"
    assert redact(text) == text
    assert redact("ENV API_TOKEN=value\r\n") == "[REDACTED assignment]\r\n"


@pytest.mark.parametrize("prefix", ['@set "', 'set "'])
@pytest.mark.parametrize("ending", ["\n", "\r\n"])
def test_quoted_batch_assignments_preserve_safe_bytes_but_never_publish_sensitive_values(prefix, ending):
    safe = prefix + 'SDK_ROOT=tools/sdk"' + ending
    sensitive = prefix + 'API_TOKEN=SYNTHETIC_BOUNDARY_SENTINEL"' + ending
    assert redact(safe) == safe
    assert redact(sensitive) == "[REDACTED assignment]" + ending
    value = _static({"setup.cmd": safe + sensitive})
    first, second = value["declarations"]
    assert first["name"] == "SDK_ROOT" and first["value"] == "tools/sdk"
    assert first["status"] == "declared"
    assert second["status"] == "redacted" and second["value"] is None
    assert second["sha256"] == hashlib.sha256((safe + sensitive).encode()).hexdigest()
    assert "SYNTHETIC_BOUNDARY_SENTINEL" not in json.dumps(value)


def test_environment_publication_matches_the_checked_in_offline_schema():
    from jsonschema import Draft202012Validator
    schema = json.loads((ROOT / "docs/schemas/build-environment-analysis.schema.json").read_bytes())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for files in ({}, {"setup.ps1": "unsupported"}, {"setup.sh": "SDK=tools/sdk\n"},
                  {"setup.sh": "source missing.sh\nSDK=tools/sdk\n"}):
        validator.validate(_static(files))


@pytest.mark.parametrize("handoff", [False, True])
def test_environment_handoff_bound_does_not_relax_the_environment_artifact_bound(tmp_path, handoff):
    from appsec_review.jobs.job_build_environment_analysis.job import _read
    data = b'{"padding":"' + b"x" * 16777216 + b'"}'
    path = tmp_path / "bounded-environment.json"
    path.write_bytes(data)
    identity = {"path": path.name, "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}
    if handoff:
        assert len(_read(tmp_path, identity, byte_limit=33554432)["padding"]) == 16777216
        with pytest.raises(ValueError, match="identity mismatch"):
            _read(tmp_path, {**identity, "sha256": "f" * 64}, byte_limit=33554432)
    else:
        with pytest.raises(ValueError, match="exceeds its bound"):
            _read(tmp_path, identity)
    with pytest.raises(ValueError, match="unsupported.*byte limit"):
        _read(tmp_path, identity, byte_limit=33554433)
