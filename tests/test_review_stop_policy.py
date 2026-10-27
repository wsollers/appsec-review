"""Offline first-error policy regressions; no real Docker, provider, or HTTP calls."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import importlib
import json
import multiprocessing
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from appsec_review.runtime import execution_safety as safety


ROOT = Path(__file__).parents[1]


def _policy():
    return safety.policy(str(uuid4()), {
        "source_commit": "a" * 40, "target_commit": "b" * 40,
        "configuration": {"base_sha256": "c" * 64, "profile": "copilot-prod",
                          "profile_sha256": "d" * 64, "overlay_sha256": None}})


@contextmanager
def _running(root, envelope=None):
    envelope = envelope or _policy()
    with safety.AdmissionGuardian(envelope, root, resolved_config_sha256="e" * 64) as guardian:
        with safety.safety_scope(envelope):
            yield guardian


def _child_admission(envelope, ready, proceed, results):
    try:
        with safety.safety_scope(envelope):
            with safety.operation("child.first"):
                results.put("admitted")
            ready.set()
            if not proceed.wait(5):
                raise RuntimeError("parent did not release fixture")
            with safety.operation("child.after_stop"):
                results.put("incorrectly admitted")
    except safety.ReviewStopped:
        results.put("stopped")


def _configuration(tmp_path):
    return SimpleNamespace(
        source_sha256="c" * 64, resolved_sha256="e" * 64,
        resolved_json=json.dumps({"configuration_profile": {
            "name": "copilot-prod", "sha256": "d" * 64}}),
        runtime=SimpleNamespace(metadata_dir=tmp_path),
        dagster=SimpleNamespace(max_concurrent=1, pool_limits={}))


def _dagster_run(envelope):
    return SimpleNamespace(
        run_id=envelope["dagster_run_id"],
        run_config={"execution": {"config": {"safety": envelope}}},
        tags={"dagster/max_retries": "0", "appsec/safety_identity": safety.identity(envelope)})


def test_policy_identity_and_legacy_default(tmp_path):
    from appsec_review.orchestration.dagster.fail_fast import _envelope
    value = _policy()
    assert safety.validate(value) == value
    assert not safety.active()
    with safety.operation("legacy"):
        safety.fail("legacy result remains the caller's responsibility")
    run = _dagster_run(value)
    assert _envelope(run, _configuration(tmp_path)) == value
    for changed in ("run_id", "tags", "configuration"):
        candidate = _dagster_run(value)
        config = _configuration(tmp_path)
        if changed == "run_id":
            candidate.run_id = str(uuid4())
        elif changed == "tags":
            candidate.tags["dagster/max_retries"] = "1"
        else:
            config.source_sha256 = "f" * 64
        with pytest.raises(ValueError):
            _envelope(candidate, config)
    assert _envelope(SimpleNamespace(run_config={}), _configuration(tmp_path)) is None
    with _running(tmp_path, value):
        safety.bind_run("application-one")
        with pytest.raises(safety.ReviewStopped):
            safety.bind_run("application-two")


def test_cross_process_admission_and_first_error(tmp_path):
    context = multiprocessing.get_context("spawn")
    ready, proceed, results = context.Event(), context.Event(), context.Queue()
    with _running(tmp_path) as guardian:
        child = context.Process(target=_child_admission,
                                args=(guardian.policy, ready, proceed, results))
        child.start()
        try:
            assert ready.wait(8)
            assert results.get(timeout=2) == "admitted"
            with pytest.raises(safety.ReviewStopped):
                safety.fail("original failure", action="first")
            safety.latch("secondary failure", action="second")
            proceed.set()
            assert results.get(timeout=5) == "stopped"
            child.join(5)
            assert child.exitcode == 0
            assert guardian.state["first_error"]["reason"] == "original failure"
            assert not guardian.state["active"]
        finally:
            proceed.set()
            if child.is_alive():
                child.terminate()
                child.join(5)
            results.close()
            results.join_thread()


@pytest.mark.parametrize("failure", ["controller", "journal", "lost_response", "identity"])
def test_lost_controller_or_journal_fails_closed(tmp_path, monkeypatch, failure):
    envelope = _policy()
    if failure == "controller":
        with pytest.raises(safety.ReviewStopped, match="unavailable"):
            with safety.safety_scope(envelope):
                pytest.fail("unavailable controller admitted work")
        return
    with _running(tmp_path, envelope) as guardian:
        if failure == "journal":
            persist = guardian._persist
            def unavailable(_event):
                raise OSError("fixture disk unavailable")
            monkeypatch.setattr(guardian, "_persist", unavailable)
            with pytest.raises(safety.ReviewStopped):
                with safety.operation("cannot_journal"):
                    pytest.fail("unjournaled work was admitted")
            monkeypatch.setattr(guardian, "_persist", persist)
        elif failure == "lost_response":
            send = safety._send
            def lose_grant(connection, value):
                if "permit" in value and value.get("ok") is True:
                    raise BrokenPipeError("fixture lost grant response")
                return send(connection, value)
            monkeypatch.setattr(safety, "_send", lose_grant)
            with pytest.raises(safety.ReviewStopped):
                with safety.operation("uncertain"):
                    pytest.fail("lost grant was treated as successful")
            assert guardian.state["active"]
        else:
            changed = json.loads(json.dumps(envelope))
            changed["submission"]["target_commit"] = "f" * 40
            with pytest.raises(safety.ReviewStopped):
                safety.SafetyClient(changed).request("check")
        with pytest.raises(safety.ReviewStopped):
            safety.check_running()
        assert guardian.stopped.is_set()
    with pytest.raises(FileExistsError):
        with safety.AdmissionGuardian(envelope, tmp_path, resolved_config_sha256="e" * 64):
            pytest.fail("controller restarted from an uncertain journal")


def test_dagster_first_error_disables_retries_and_cancels_once(tmp_path):
    from dagster import DagsterInstance, job, op
    from appsec_review.orchestration.dagster.fail_fast import SafetyExecutor, execution_definition
    envelope, config = _policy(), _configuration(tmp_path)
    @op
    def noop():
        return 1
    @job
    def fixture_job():
        noop()
    definition = execution_definition(config)
    with DagsterInstance.ephemeral() as instance:
        for enabled in (False, True):
            created = definition.executor_creation_fn(SimpleNamespace(
                executor_config={"safety": envelope} if enabled else {},
                job=fixture_job, instance=instance))
            assert created.retries.value == ("disabled" if enabled else "enabled")
    cancelled = []
    event = SimpleNamespace(is_step_failure=True, is_resource_init_failure=False,
                            is_engine_event=False, event_type_value="STEP_FAILURE", step_key="failed")
    class Delegate:
        def execute(self, context, plan):
            yield event
            with pytest.raises(safety.ReviewStopped):
                safety.SafetyClient(envelope).request("admit", action="queued")
            yield event
    context = SimpleNamespace(
        dagster_run=_dagster_run(envelope), run_id=envelope["dagster_run_id"],
        instance=SimpleNamespace(run_launcher=SimpleNamespace(
            terminate=lambda run_id: cancelled.append(run_id) or True)))
    with pytest.raises(RuntimeError, match="review stopped"):
        list(SafetyExecutor(Delegate(), config).execute(context, object()))
    assert cancelled == [envelope["dagster_run_id"]]
    journal = json.loads((tmp_path / "dagster-safety" / f"{envelope['dagster_run_id']}.json").read_text())
    assert journal["cancellation"] == "REQUEST_ACCEPTED"
    assert journal["first_error"]["action"] == "failed"


@pytest.mark.parametrize("executor_kind", ["scanner", "build", "codeql"])
def test_executor_failure_retains_evidence_and_cancels_siblings(tmp_path, executor_kind):
    from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
    from appsec_review.container_runtime.executor import CommandOutcome, ContainerExecutor, ExecutionRequest
    from appsec_review.codeql.runtime import CodeQLExecutor, CodeQLImage
    from tests.test_container_runtime import DIGEST, catalog
    calls = []
    def runner(argv, timeout):
        argv = tuple(argv)
        calls.append(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, DIGEST.encode(), b"", False
        if argv[:3] == ("docker", "container", "inspect"):
            return 1, b"", f"No such container: {argv[3]}".encode(), False
        if argv[:2] == ("docker", "inspect"):
            return 0, b'[{"Destination":"/","Source":"/"}]', b"", False
        if argv[:2] == ("docker", "run") and (
                "/bin/fixture" in argv or "/opt/appsec/codeql_runner.py" in argv):
            return 2, b"partial", b"failure", False
        return 0, b"", b"", False
    target, scratch = tmp_path / "target", tmp_path / "scratch"
    target.mkdir()
    scratch.mkdir()
    with _running(tmp_path / "metadata") as guardian:
        with pytest.raises(safety.ReviewStopped):
            with safety.operation("fixture.executor"):
                if executor_kind == "scanner":
                    wrapped = lambda argv, timeout: CommandOutcome(*runner(argv, timeout))
                    ContainerExecutor(catalog(tmp_path), tmp_path, runner=wrapped).execute(
                        ExecutionRequest("tool-fixture", ("/bin/fixture",), target, scratch))
                elif executor_kind == "build":
                    executor = BuildContainerExecutor(
                        BuildProfile("fixture", "fixture:1", DIGEST, "10001:10001"),
                        runner=runner, timeout_seconds=5, output_bytes=1024)
                    executor.execute(("/bin/fixture",), workspace=target, working_directory=".",
                                     environment={})
                else:
                    image = CodeQLImage("appsec-review/codeql-derived-image/2", "a" * 64, DIGEST,
                        DIGEST, "build:local", DIGEST, "codeql:local", "10001:10001",
                        "b" * 64, "c" * 64, False, "manifest.json")
                    settings = SimpleNamespace(inventory_timeout_seconds=5, database_timeout_seconds=5,
                        query_timeout_seconds=5, output_bytes=1024, threads=2, ram_mb=1024)
                    CodeQLExecutor(image=image, run_root=tmp_path, settings=settings, runner=runner).execute(
                        "database", ("--language", "csharp", "--database", "database"),
                        scratch_root=scratch)
        with pytest.raises(safety.ReviewStopped):
            with safety.operation("sibling"):
                pytest.fail("sibling started")
        assert guardian.state["first_error"]
        assert any(path.is_file() and path.read_bytes() == b"partial"
                   for path in tmp_path.rglob("*stdout*"))
        assert any(call[:3] == ("docker", "rm", "--force") for call in calls)
        assert guardian.state["active"]


@pytest.mark.parametrize("consumer", ["cell", "http", "dependency", "target_plan", "build_repair"])
def test_retry_consumer_stops_after_first_attempt(tmp_path, monkeypatch, consumer):
    with _running(tmp_path / "metadata") as guardian:
        with pytest.raises(safety.ReviewStopped):
            if consumer == "cell":
                from tests.review.test_cells import ScriptedInfer, run
                infer = ScriptedInfer(RuntimeError("first provider error"), RuntimeError("must not retry"))
                try:
                    run(tmp_path, infer, max_attempts=3)
                finally:
                    assert len(infer.requests) == 1
            elif consumer == "http":
                from appsec_review.jobs.job_dependency_intelligence.scorecard import HttpResponse, ScorecardClient
                calls = []
                def transport(*args, **kwargs):
                    calls.append(1)
                    return HttpResponse(503, b"unavailable", {})
                client = ScorecardClient(base_url="https://fixture.invalid", allowed_hosts=("fixture.invalid",),
                    max_requests=10, max_response_bytes=1024, timeout_seconds=1, retries=3,
                    transport=transport, sleeper=lambda _: pytest.fail("retry slept"))
                try:
                    client.fetch({"host": "github.com", "owner": "example", "name": "example"})
                finally:
                    assert len(calls) == 1
            elif consumer == "target_plan":
                from tests.test_target_analysis_plan import test_model_failure_uses_bounded_retries_and_safe_fallback
                test_model_failure_uses_bounded_retries_and_safe_fallback(tmp_path)
            elif consumer == "dependency":
                from appsec_review.jobs.job_dependency_intelligence.inference import resolve_with_inference
                dependency = {"dependency_id": "dependency-a", "name": "mystery", "repository": None,
                    "observations": [{"evidence_id": "native:1"}],
                    "native_candidate": {"candidate_id": "native-dependency-a", "native_name": "mystery",
                        "observations": [{"command_id": "cmd-1", "kind": "link_flag", "value": "-lmystery"}]}}
                calls = []
                def infer(*args, **kwargs):
                    calls.append(1)
                    raise RuntimeError("fixture dependency inference failure")
                model = {"enabled": True, "provider": "fake", "model": "fake", "reasoning": "low",
                    "max_input_tokens": 10000, "max_output_tokens": 1000, "timeout_seconds": 7, "retries": 3}
                try:
                    resolve_with_inference(dependency, repository_root=ROOT, run_root=tmp_path,
                        model=model, supported_hosts=("github.com",), infer=infer, max_candidate_bytes=10000)
                finally:
                    assert len(calls) == 1
            else:
                from tests.test_project_build import test_failed_default_build_repairs_image_and_reuses_winning_definition
                test_failed_default_build_repairs_image_and_reuses_winning_definition(tmp_path)
        assert guardian.state["first_error"]["action"] != "fixture"


@pytest.mark.parametrize("disposition", ["not_found", "finding", "authority", "budget", "missing_history"])
def test_expected_dispositions_do_not_trip_latch(tmp_path, disposition):
    with _running(tmp_path / "metadata") as guardian:
        if disposition == "not_found":
            from appsec_review.jobs.job_dependency_intelligence.scorecard import HttpResponse, ScorecardClient, ScorecardError
            client = ScorecardClient(base_url="https://fixture.invalid", allowed_hosts=("fixture.invalid",),
                max_requests=1, max_response_bytes=1024, timeout_seconds=1, retries=3,
                transport=lambda *args, **kwargs: HttpResponse(404, b"{}", {}))
            with pytest.raises(ScorecardError) as error:
                client.fetch({"host": "github.com", "owner": "example", "name": "example"})
            assert error.value.kind == "not_found"
        elif disposition == "missing_history":
            from tests.test_source_history_analysis import test_missing_history_is_an_explicit_skip_not_a_clean_result
            test_missing_history_is_an_explicit_skip_not_a_clean_result(tmp_path)
        else:
            from tests.review.test_cells import ScriptedInfer, capability, final, retrieve, run
            infer = ScriptedInfer(final())
            cap = None
            if disposition == "authority":
                denied = retrieve({"tool": "not_granted", "parameters": {}})
                infer = ScriptedInfer(denied, denied)
            elif disposition == "budget":
                cap = capability(max_turns=1)
                infer = ScriptedInfer(retrieve({"tool": "search", "parameters": {"query": "x"}}))
            run(tmp_path, infer, cap=cap)
        safety.check_running()
        assert guardian.state["first_error"] is None


@pytest.mark.parametrize("surface", ["clang", "replay_missing", "replay_malformed", "replay_failure",
                                     "artifact", "ci", "evidence", "symbols", "codeql_export"])
def test_malformed_outputs_stop_before_gap_conversion(tmp_path, surface):
    with _running(tmp_path / "metadata") as guardian:
        with pytest.raises(safety.ReviewStopped):
            if surface == "clang":
                from appsec_review.jobs.job_clang_static_analysis.job import _read_output
                path = tmp_path / "result.json"
                path.write_text("{", encoding="utf-8")
                _read_output(path, engine="clang-tidy", max_bytes=1024, max_diagnostics=10)
            elif surface.startswith("replay"):
                from appsec_review.jobs.job_cpp_compiled_analysis.job import replay_failures
                path = tmp_path / "analysis/ast/receipt.json"
                path.parent.mkdir(parents=True)
                if surface == "replay_malformed":
                    path.write_text("{", encoding="utf-8")
                elif surface == "replay_failure":
                    path.write_text('[{"index":0,"exit_code":2,"stderr":"compiler failed"}]', encoding="utf-8")
                replay_failures(tmp_path, "ast", [{"target_path": "source.c"}])
            else:
                module_name, name = {
                    "artifact": ("tests.test_artifact_security_analysis",
                        "test_job_isolates_scanner_failure_retains_raw_output_and_indexes_siblings"),
                    "ci": ("tests.test_ci_configuration_analysis",
                        "test_failed_linter_is_a_gap_and_sibling_results_survive"),
                    "evidence": ("tests.test_evidence_collection_job",
                        "test_job_has_explicit_dispositions_and_reuses_only_successful_tool_checkpoints"),
                    "symbols": ("tests.test_cpp_index_jobs",
                        "test_failed_clangd_run_is_scoped_unavailable_coverage"),
                    "codeql_export": ("tests.test_codeql_export_step",
                        "test_timeout_or_nonzero_exit_is_a_scope_gap_that_spares_siblings"),
                }[surface]
                getattr(importlib.import_module(module_name), name)(tmp_path)
        assert guardian.state["first_error"] is not None


@pytest.mark.parametrize("confirmed", [False, True])
def test_cleanup_requires_confirmed_descendant_and_container_death(tmp_path, monkeypatch, confirmed):
    from appsec_review.runtime import resources
    quarantined, stopped = [], []
    monkeypatch.setattr(resources, "quarantine_resources", quarantined.append)
    monkeypatch.setattr(resources, "container_stopped", stopped.append)
    def runner(argv, timeout):
        if tuple(argv[:3]) == ("docker", "container", "inspect"):
            return (1, b"", b"No such container: owned", False) if confirmed else (0, b"false", b"", False)
        return 0, b"", b"", False
    with _running(tmp_path):
        if confirmed:
            with resources.tracked_container("owned", runner, label="Fixture"):
                pass
        else:
            with pytest.raises(RuntimeError, match="unconfirmed"):
                with resources.tracked_container("owned", runner, label="Fixture"):
                    pass
        assert stopped == (["owned"] if confirmed else [])
        assert bool(quarantined) is not confirmed
    with _running(tmp_path / "process") as guardian:
        with safety.operation("bounded.process"):
            code, out, err, timed_out = safety.run_process(
                [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(20)"], 1)
        assert code is None and timed_out and b"started" in out
        events = [json.loads(line) for line in guardian.events.read_text().splitlines()]
        pid = next(event["process"]["pid"] for event in events if event["event"] == "PROCESS")
        assert not Path(f"/proc/{pid}").exists()


def test_success_and_failed_receipts_keep_correct_timings(tmp_path):
    with _running(tmp_path) as guardian:
        with safety.operation("success"):
            time.sleep(0.002)
        with pytest.raises(safety.ReviewStopped):
            with safety.operation("failure"):
                raise RuntimeError("fixture failure")
        events = [json.loads(line) for line in guardian.events.read_text().splitlines()]
        finishes = {row["action"]: row for row in events if row["event"] == "FINISH"}
        assert finishes["success"]["succeeded"] is True
        assert finishes["failure"]["succeeded"] is False
        assert all(type(row["duration_ms"]) is int and row["duration_ms"] >= 0
                   for row in finishes.values())
        assert len(guardian.state["active"]) == 1


def test_scope_and_profiles_keep_models_budgets_and_disabled_lanes(tmp_path, monkeypatch):
    from appsec_review.config import load_config
    from appsec_review.orchestration.dagster.fail_fast import _envelope
    before = load_config(ROOT / "appsec-review.toml", profile="copilot-prod")
    with _running(tmp_path):
        after = load_config(ROOT / "appsec-review.toml", profile="copilot-prod")
        assert before.resolved_json == after.resolved_json
        assert before.resolved_sha256 == after.resolved_sha256
    value = json.loads(before.resolved_json)
    assert value["configuration_profile"]["name"] == "copilot-prod"
    monkeypatch.setenv("APPSEC_NATIVE_ENGINE_CONTRACT", "/not-commissioned")
    with pytest.raises(ValueError, match="native"):
        _envelope(_dagster_run(_policy()), _configuration(tmp_path))


def test_queued_thread_and_inference_work_never_starts_after_stop(tmp_path):
    from appsec_review.storage.shared import PublicationThreadPoolExecutor
    from appsec_review.inference.copilot_sdk import _run
    entered, release = threading.Event(), threading.Event()
    calls = []
    with _running(tmp_path) as guardian:
        def first():
            entered.set()
            assert release.wait(5)
        with PublicationThreadPoolExecutor(max_workers=1) as pool:
            one = pool.submit(first)
            assert entered.wait(5)
            two = pool.submit(lambda: calls.append("queued"))
            safety.latch("stop before queued work")
            release.set()
            for future in (one, two):
                with pytest.raises(safety.ReviewStopped):
                    future.result(timeout=5)
        async def inference():
            calls.append("inference")
        with pytest.raises(safety.ReviewStopped):
            with safety.operation("inference"):
                _run(inference(), 5)
        assert calls == []
        assert guardian.stopped.is_set()
    started, cancelled = threading.Event(), threading.Event()
    with _running(tmp_path / "sdk") as guardian:
        async def in_flight():
            started.set()
            try:
                await asyncio.sleep(10)
            finally:
                cancelled.set()
        def stop_model():
            assert started.wait(5)
            guardian.client.request("failure", reason="fixture sibling failed", action="fixture")
        stopper = threading.Thread(target=stop_model)
        stopper.start()
        try:
            with pytest.raises(safety.ReviewStopped):
                with safety.operation("copilot"):
                    _run(in_flight(), 5)
        finally:
            stopper.join(5)
        assert not stopper.is_alive()
        assert cancelled.is_set()
