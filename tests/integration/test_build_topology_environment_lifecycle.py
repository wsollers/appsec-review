"""I3: real static producer/publication and E1 launch lifecycle. AUTHORED - NOT RUN.

R4/R5/R6/R7/R11 and E1/E2: absence, stale optional evidence and failed expected
production remain different identities in both actual workflow definitions.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json

import pytest

from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_build_environment_analysis.job import (
    JOB_ID, build_job as environment_job, environment_contract, load_environment,
)
from appsec_review.jobs.job_review_intake import build_job as intake_job
from appsec_review.jobs.job_target_analysis_plan import build_job as planner_job, load_accepted_plan
from appsec_review.jobs.job_target_catalog import build_job as catalog_job
from appsec_review.runtime import GraphRunner
from tests.integration.test_build_topology_catalog_planner_publication import (
    ROOT, isolated_config, offline_reporting, run_pipeline,
)


def published_environment(tmp_path):
    config = isolated_config(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    (target / "setup.sh").write_bytes(
        b"SDK_ROOT=tools/sdk\nAPI_TOKEN=synthetic-secret-never-publish\n")
    source = source_fingerprint(target)
    result = GraphRunner(config, [intake_job(), catalog_job(), environment_job()]).run(
        target_root=target, source_fingerprint=source)
    root = config.runtime.runs_dir / result["run_id"]
    pointer = json.loads((root / "data/jobs" / JOB_ID / "latest.json").read_bytes())
    contract = environment_contract(config, {"workflow": "wave1_review"},
                                    {JOB_ID: pointer["handoff_sha256"]})
    return config, target, root, source, contract


def test_static_producer_accepted_reader_and_planner_share_exact_redacted_evidence(tmp_path):
    _config, _target, _runner, _result, root, plan = run_pipeline(
        tmp_path, {"setup.sh": "SDK_ROOT=tools/sdk\nTOKEN=synthetic-private\n"}, environment=True)
    stored = plan["build_environment"]
    assert stored["availability"] == "AVAILABLE"
    assert stored["mode"] == "EXPECTED_CURRENT" and stored["expected_producer"] == JOB_ID
    declarations = stored["evidence"]["declarations"]
    assert any(d["name"] == "SDK_ROOT" and d["value"] == "tools/sdk"
               and d["reason"] == "static_literal_advisory_only" for d in declarations)
    assert any(d["status"] == "redacted" and d["value"] is None for d in declarations)
    assert "synthetic-private" not in json.dumps(stored)
    artifact = root / stored["artifact"]["path"]
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == stored["artifact"]["sha256"]
    assert plan["build_topology"]["evidence_bundle"]["environment"] == stored
    assert load_accepted_plan(root)["build_environment"] == stored


@pytest.mark.parametrize("child", ["env-child.sh", "z-env.sh"])
def test_sourced_context_stays_unknown_through_real_producer_and_planner_in_both_orders(tmp_path, child):
    _config, _target, _runner, _result, root, plan = run_pipeline(
        tmp_path, {"setup.sh": "source " + child + "\n", child: "CC=clang\n"}, environment=True)
    evidence = plan["build_environment"]["evidence"]
    declarations = [item for item in evidence["declarations"] if item["path"] == child]
    assert len(declarations) == 1
    assert declarations[0]["status"] == "unknown" and declarations[0]["value"] is None
    assert evidence["coverage"] == "partial" and evidence["gaps"]
    assert evidence["bounds"]["inspected_scripts"] == 2
    assert load_accepted_plan(root)["build_environment"]["evidence"] == evidence


def test_unsupported_environment_is_accepted_partial_evidence_not_a_missing_producer(tmp_path):
    _config, _target, _runner, _result, root, plan = run_pipeline(
        tmp_path, {"setup.ps1": "$env:CC='cl'\n"}, environment=True)
    environment = plan["build_environment"]
    assert environment["mode"] == "EXPECTED_CURRENT" and environment["reference"]
    assert environment["availability"] == "UNAVAILABLE"
    assert environment["evidence"]["coverage"] == "partial"
    assert "PowerShell environment scripts are not supported" in environment["evidence"]["gaps"]
    assert environment["evidence"]["declarations"] == []
    assert load_accepted_plan(root)["build_environment"] == environment


def test_optional_wrong_snapshot_is_unavailable_but_expected_current_still_blocks(tmp_path):
    config, _target, root, source, current = published_environment(tmp_path)
    optional = environment_contract(
        config, {"environment_mode": "OPTIONAL_PRIOR"}, {JOB_ID: current["reference"]})
    evidence = load_environment(root, source, optional)
    assert evidence["availability"] == "AVAILABLE"
    stale = load_environment(root, "independent-new-source", optional)
    assert stale["availability"] == "UNAVAILABLE"
    assert stale["artifact"] is None and stale["evidence"] is None
    assert "STALE" in stale["reason"]
    with pytest.raises(ValueError, match="wrong source"):
        load_environment(root, "independent-new-source", current)
    artifact = root / evidence["artifact"]["path"]
    artifact.write_bytes(artifact.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="identity mismatch"):
        load_environment(root, "independent-new-source", optional)


def test_standalone_absence_and_configuration_disable_do_not_require_a_fake_publication(tmp_path):
    config = isolated_config(tmp_path)
    absent = environment_contract(config, {}, {})
    assert absent["mode"] == "NOT_RUN" and absent["expected_producer"] is None
    assert load_environment(tmp_path, "source", absent)["availability"] == "ABSENT"
    jobs = dict(config.jobs)
    jobs[JOB_ID] = replace(jobs[JOB_ID], settings={**jobs[JOB_ID].settings, "enabled": False})
    disabled = environment_contract(replace(config, jobs=jobs), {"workflow": "wave1_review"}, {})
    assert disabled["mode"] == "DISABLED"
    assert load_environment(tmp_path, "source", disabled)["availability"] == "DISABLED"
    expected = environment_contract(config, {"workflow": "wave1_review"}, {})
    with pytest.raises(ValueError, match="no accepted handoff"):
        load_environment(tmp_path, "source", expected)


def test_expected_producer_bug_blocks_planner_instead_of_becoming_absence(tmp_path):
    config = isolated_config(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    (target / "setup.sh").write_bytes(b"CC=clang\n")
    environment = environment_job()
    planned_calls = []
    units = list(environment.units)
    failing = next(i for i, unit in enumerate(units)
                   if unit.unit_id == "environment_analysis.analyze_scripts")

    def fail(_context):
        raise RuntimeError("independent unexpected environment failure")

    units[failing] = replace(units[failing], handler=fail)
    # Keep the actual job executor wired to the changed units, not the old closure.
    from appsec_review.runtime import UnitExecutor
    broken = replace(environment, units=tuple(units), handler=UnitExecutor(tuple(units)).execute)

    def forbidden_model(*args, **kwargs):
        planned_calls.append((args, kwargs))
        raise AssertionError("an expected failed producer cannot authorize planner inference")

    initial = GraphRunner(config, [intake_job(), catalog_job()]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    with pytest.raises(RuntimeError, match="independent unexpected environment failure"):
        GraphRunner(config, [
            intake_job(), catalog_job(), broken, planner_job(infer=forbidden_model),
        ]).run(target_root=target, source_fingerprint=source_fingerprint(target), run_id=initial["run_id"])
    root = config.runtime.runs_dir / initial["run_id"]
    status = root / "data/jobs" / JOB_ID / "attempts/attempt_0001/status.json"
    assert json.loads(status.read_bytes())["status"] == "FAILED"
    assert planned_calls == []
    assert not (root / "data/jobs/job_target_analysis_plan/latest.json").exists()


@pytest.mark.parametrize("workflow", ["wave1_review", "project_build_review"])
@pytest.mark.parametrize("enabled", [False, True])
def test_actual_workflow_edges_keep_expected_environment_a_required_dependency(tmp_path, workflow, enabled):
    from appsec_review.orchestration.dagster import build_definitions

    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    original = "[jobs.job_build_environment_analysis.settings]\nenabled = true"
    assert text.count(original) == 1
    config_path = tmp_path / "workflow.toml"
    config_path.write_text(text.replace(original, original.rsplit("true", 1)[0] + str(enabled).lower()),
                           encoding="utf-8")
    definitions = build_definitions(config_path)
    definitions.get_repository_def().load_all_definitions()
    graph = definitions.get_job_def(workflow).graph
    prefix = "project_build_review__" if workflow == "project_build_review" else ""
    upstream = graph.dependency_structure.input_to_upstream_outputs_for_node(
        prefix + "target_analysis_plan__begin")
    names = {output.node_name.removeprefix(prefix)
             for outputs in upstream.values() for output in outputs}
    if enabled:
        assert "build_environment_analysis__finalize" in names
        environment = graph.dependency_structure.input_to_upstream_outputs_for_node(
            prefix + "build_environment_analysis__begin")
        assert {output.node_name.removeprefix(prefix)
                for outputs in environment.values() for output in outputs} == {"target_catalog__finalize"}
    else:
        assert names
        assert "build_environment_analysis__finalize" not in names
        assert prefix + "build_environment_analysis__begin" not in {node.name for node in graph.node_defs}
