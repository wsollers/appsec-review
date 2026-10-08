from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import json
import threading

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import LockUnavailable, atomic_json
from appsec_review.retrieval import RunIndexBackend, SearchRequest
from tests.resume_conformance import assert_reuse_without_execution


ROOT = Path(__file__).parents[1]


def _fixture(tmp_path: Path):
    config = tmp_path / "appsec-review.toml"
    config.write_bytes((ROOT / "appsec-review.toml").read_bytes())
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    (target / "package.json").write_text('{"dependencies":{"fixture":"1.0.0"}}', encoding="utf-8")
    return load_config(config), target


def _counted(job, calls: dict[str, int]):
    handler = job.handler
    def wrapped(context):
        calls[job.job_id] = calls.get(job.job_id, 0) + 1
        return handler(context)
    return replace(job, handler=wrapped)


def test_every_wave1_job_is_reused_without_handler_execution(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    calls: dict[str, int] = {}
    jobs = [_counted(build_intake(), calls), _counted(build_catalog(), calls)]
    graph = GraphRunner(config, jobs)
    assert_reuse_without_execution(graph, target, calls)
    assert calls == {"job_review_intake": 1, "job_target_catalog": 1}


@pytest.mark.parametrize("field", ["implementation_identity", "schema_identity", "validation_identity"])
def test_identity_change_invalidates_exact_downstream_closure(tmp_path: Path, field: str) -> None:
    config, target = _fixture(tmp_path)
    jobs = [build_intake(), build_catalog()]
    graph = GraphRunner(config, jobs)
    fingerprint = source_fingerprint(target)
    first = graph.run(target_root=target, source_fingerprint=fingerprint)

    changed_catalog = replace(jobs[1], **{field: f"changed-{field}"})
    downstream_plan = GraphRunner(config, [jobs[0], changed_catalog]).plan(first["run_id"], fingerprint)
    assert [item.action for item in downstream_plan] == ["REUSE", "RUN"]
    reason_label = {"implementation_identity": "implementation", "schema_identity": "schema",
                    "validation_identity": "validator"}[field]
    assert any(reason_label in reason for reason in downstream_plan[1].reasons)

    changed_intake = replace(jobs[0], **{field: f"changed-upstream-{field}"})
    upstream_plan = GraphRunner(config, [changed_intake, jobs[1]]).plan(first["run_id"], fingerprint)
    assert [item.action for item in upstream_plan] == ["RUN", "INVALIDATE"]


def test_target_change_invalidates_entire_closure(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    graph = GraphRunner(config, [build_intake(), build_catalog()])
    first = graph.run(target_root=target, source_fingerprint=source_fingerprint(target))
    (target / "src/main.py").write_text("def main():\n    return 2\n", encoding="utf-8")
    plan = graph.plan(first["run_id"], source_fingerprint(target))
    assert [item.action for item in plan] == ["RUN", "INVALIDATE"]
    assert "target fingerprint identity changed" in plan[0].reasons


def test_catalog_indices_are_queried_without_target_scan(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    outcome = GraphRunner(config, [build_intake(), build_catalog()]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    page = RunIndexBackend(config.runtime.runs_dir).search(
        SearchRequest(outcome["run_id"], "path", "main.py", limit=5))
    assert [hit.path for hit in page.hits] == ["src/main.py"]
    assert page.hits[0].source_id


def test_graph_publishes_bidirectional_orchestration_receipt(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    outcome = GraphRunner(config, [build_intake(), build_catalog()]).run(
        target_root=target, source_fingerprint=source_fingerprint(target),
        orchestration={"system": "fixture", "run_id": "orchestrator-1"})
    receipt = json.loads(Path(outcome["orchestration_receipt"]).read_text(encoding="utf-8"))
    assert receipt["application_run_id"] == outcome["run_id"]
    assert receipt["orchestrator"] == {"system": "fixture", "run_id": "orchestrator-1"}
    assert [item["action"] for item in receipt["decisions"]] == ["RUN", "INVALIDATE"]


def test_failure_resume_preserves_attempt_and_starts_at_failed_job(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    runner = JobRunner(config)
    run_id, _ = runner.runs.create(__import__("datetime").datetime(2026, 10, 8, tzinfo=__import__("datetime").timezone.utc))
    fingerprint = source_fingerprint(target)
    failing = GraphRunner(config, [build_intake(), build_catalog(fail_task="retrieval_indexes.build_path_index")])
    with pytest.raises(RuntimeError, match="partial failure"):
        failing.run(target_root=target, source_fingerprint=fingerprint, run_id=run_id)

    failed = config.runtime.runs_dir / run_id / "data/jobs/job_target_catalog/attempts/attempt_0001/status.json"
    assert json.loads(failed.read_text(encoding="utf-8"))["status"] == "FAILED"
    resumed = GraphRunner(config, [build_intake(), build_catalog()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert [item["action"] for item in resumed["decisions"]] == ["REUSE", "RUN"]
    assert "no accepted handoff" in resumed["decisions"][1]["reasons"]
    assert failed.is_file()
    assert resumed["jobs"]["job_target_catalog"]["status"]["attempt_id"] == "attempt_0002"


@pytest.mark.parametrize("damage", ["corrupt", "missing"])
def test_corrupt_or_missing_artifact_and_force_from_invalidate_downstream(tmp_path: Path, damage: str) -> None:
    config, target = _fixture(tmp_path)
    jobs = [build_intake(), build_catalog()]
    graph = GraphRunner(config, jobs)
    first = graph.run(target_root=target, source_fingerprint=source_fingerprint(target))
    run_root = config.runtime.runs_dir / first["run_id"]
    handoff = json.loads((run_root / "data/jobs/job_review_intake/attempts/attempt_0001/handoff.json").read_text())
    artifact = run_root / handoff["artifacts"][1]["path"]
    if damage == "corrupt":
        artifact.write_text("corrupt", encoding="utf-8")
    else:
        artifact.unlink()
    plan = graph.plan(first["run_id"], source_fingerprint(target))
    assert plan[0].action == "RUN"
    assert any(f"artifact {damage if damage == 'missing' else 'changed'}" in reason for reason in plan[0].reasons)
    assert plan[1].action == "INVALIDATE"

    forced = graph.plan(first["run_id"], source_fingerprint(target), force_from="job_target_catalog")
    assert forced[0].action == "RUN"  # corruption remains truthful before the forced boundary
    assert forced[1].action == "RUN"
    assert forced[1].reasons == ("forced rerun from named job",)


def test_resolved_configuration_change_invalidates_entire_closure(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    graph = GraphRunner(config, [build_intake(), build_catalog()])
    fingerprint = source_fingerprint(target)
    first = graph.run(target_root=target, source_fingerprint=fingerprint)
    config.source_path.write_text(config.source_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    changed = load_config(config.source_path)
    plan = GraphRunner(changed, [build_intake(), build_catalog()]).plan(first["run_id"], fingerprint)
    assert [item.action for item in plan] == ["RUN", "INVALIDATE"]
    assert "resolved configuration identity changed" in plan[0].reasons


def test_interrupted_running_attempt_is_not_accepted_and_is_retried(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    runner = JobRunner(config)
    run_id, run_root = runner.runs.create(__import__("datetime").datetime(
        2026, 10, 8, tzinfo=__import__("datetime").timezone.utc))
    runner._bind_configuration(run_root)
    interrupted = run_root / "data/jobs/job_review_intake/attempts/attempt_0001/status.json"
    atomic_json(interrupted, {"status": "RUNNING", "attempt_id": "attempt_0001"})
    outcome = GraphRunner(config, [build_intake(), build_catalog()]).run(
        target_root=target, source_fingerprint=source_fingerprint(target), run_id=run_id)
    assert outcome["decisions"][0]["action"] == "RUN"
    assert outcome["jobs"]["job_review_intake"]["status"]["attempt_id"] == "attempt_0002"
    assert json.loads(interrupted.read_text(encoding="utf-8"))["status"] == "RUNNING"


def test_concurrent_resume_attempts_cannot_claim_same_run(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    runner = JobRunner(config)
    run_id, _ = runner.runs.create(__import__("datetime").datetime(
        2026, 10, 8, tzinfo=__import__("datetime").timezone.utc))
    entered = threading.Event()
    release = threading.Event()
    original = build_intake()
    def blocked(context):
        entered.set()
        assert release.wait(10)
        return original.handler(context)
    jobs = [replace(original, handler=blocked), build_catalog()]
    first_error: list[BaseException] = []
    def first() -> None:
        try:
            GraphRunner(config, jobs).run(target_root=target, source_fingerprint=source_fingerprint(target),
                                          run_id=run_id)
        except BaseException as exc:  # pragma: no cover - asserted below
            first_error.append(exc)
    thread = threading.Thread(target=first)
    thread.start()
    assert entered.wait(10)
    with pytest.raises(LockUnavailable, match="already held"):
        GraphRunner(config, jobs).run(target_root=target, source_fingerprint=source_fingerprint(target),
                                      run_id=run_id)
    release.set()
    thread.join(15)
    assert not first_error
