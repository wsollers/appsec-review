"""Offline tests for CodeQL execution telemetry: per-query sources, job emits and run-metrics views."""
from __future__ import annotations

from dataclasses import asdict
import functools
import json
import os
from pathlib import Path
import shutil
import stat
from types import SimpleNamespace
from typing import Any

import pytest

from appsec_review.codeql import execution_metrics as metrics
from appsec_review.jobs.job_codeql_analysis import job as codeql_job
from appsec_review.observability import PipelineLog, aggregate_run_metrics
from appsec_review.storage import atomic_json, file_sha256
from tests.test_codeql_export_step import (
    NATIVE, RUNNER, FakeExecutor, _database, _scope, _unit,
)


@pytest.fixture(autouse=True)
def _cold_compile_cache(monkeypatch: pytest.MonkeyPatch):
    codeql_job._PRECOMPILED.clear()

    # Staged export packs are read-only; Windows refuses to unlink them without this retry.
    def writable_retry(function, path, _exc):
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        function(path)

    monkeypatch.setattr(shutil, "rmtree", functools.partial(shutil.rmtree, onexc=writable_retry))
    yield
    codeql_job._PRECOMPILED.clear()


def _identity(root: Path, path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _sarif(*rules: str, results: tuple[dict[str, Any], ...] = ()) -> dict[str, Any]:
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [{"id": rule} for rule in rules]},
                 "extensions": [{"name": "pack", "rules": [{"id": "ext/rule"}]}]},
        "results": list(results)}]}


# --- per-query sources ---------------------------------------------------------------------------

def test_analyze_metrics_report_query_runtimes_and_rule_counts_side_by_side(tmp_path: Path) -> None:
    timings = tmp_path / metrics.QUERY_TIMINGS_NAME
    timings.write_text(json.dumps({"schema": metrics.QUERY_TIMINGS_SCHEMA, "expected_query_count": 3,
        "truncated": False, "queries": [
            {"ordinal": 1, "query": "codeql/py/Security/A", "eval_ms": 1200, "cached": False},
            {"ordinal": 2, "query": "codeql/py/Security/B", "eval_ms": 0, "cached": True}]}),
        encoding="utf-8")
    sarif = _sarif("py/a", "py/b", results=({"ruleId": "py/a"}, {"ruleIndex": 0}, {"rule": {"index": 1}}))
    document = metrics.analyze_query_metrics(timings, sarif)

    assert document["schema"] == metrics.QUERY_METRICS_SCHEMA and document["action"] == "analyze"
    assert [(row["query"], row["status"], row["duration_ms"]) for row in document["queries"]] == [
        ("codeql/py/Security/A", "SUCCEEDED", 1200), ("codeql/py/Security/B", "REUSED", 0)]
    assert document["rules"] == [{"rule_id": "ext/rule", "result_count": 0},
                                 {"rule_id": "py/a", "result_count": 2},
                                 {"rule_id": "py/b", "result_count": 1}]
    assert document["gaps"] == ["1 of 3 queries reported no evaluation time"]


def test_absent_or_empty_per_query_sources_are_named_gaps_never_zero(tmp_path: Path) -> None:
    missing = metrics.analyze_query_metrics(tmp_path / "absent.json", None)
    assert missing["queries"] == [] and missing["expected_query_count"] is None
    assert missing["gaps"] == [
        "per-query evaluation timing unavailable: runner wrote no query-timings.json",
        "per-rule result counts unavailable: no accepted SARIF"]
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"schema": metrics.QUERY_TIMINGS_SCHEMA, "expected_query_count": None,
                                 "queries": [], "truncated": False}), encoding="utf-8")
    assert "CodeQL analyze progress reported no per-query evaluation lines" in \
        metrics.analyze_query_metrics(empty, _sarif())["gaps"]
    assert metrics.export_query_metrics({})["gaps"] == [
        "per-query export metrics unavailable: no accepted export manifest"]
    assert metrics.compile_query_metrics(None)["gaps"] == [
        "per-query compile timing unavailable: no runner compile summary"]


def test_export_metrics_come_from_the_manifest_and_name_rows_without_evaluate_time() -> None:
    manifest = json.loads((NATIVE / "export-manifest.json").read_text(encoding="utf-8"))
    timing = {"evaluate_ms", "decode_ms", "compile_s"}
    manifest = {**manifest, "exports": [{key: value for key, value in entry.items() if key not in timing}
                                        for entry in manifest["exports"]]}
    document = metrics.export_query_metrics(manifest)
    assert document["observed_query_count"] == len(manifest["exports"]) > 0
    assert all(row["duration_ms"] is None for row in document["queries"])
    assert all(row["result_count"] is not None for row in document["queries"])
    assert len(document["gaps"]) == len(manifest["exports"])
    timed = {**manifest, "exports": [{**manifest["exports"][0], "evaluate_ms": 40, "decode_ms": 2,
                                      "compile_s": 1.5, "truncated": True}]}
    row = metrics.export_query_metrics(timed)["queries"][0]
    assert (row["duration_ms"], row["compile_ms"], row["truncated"]) == (42, 1500, True)


def test_compile_metrics_parse_the_runner_summary_and_name_cache_hits(tmp_path: Path) -> None:
    stdout = tmp_path / "stdout.bin"
    stdout.write_text("noise\n" + json.dumps({"schema": metrics.COMPILE_SCHEMA, "language": "cpp",
        "query_count": 3, "compile_ms": 5000, "compile_s": {"A.ql": 2.5, "B.ql": 0.25}}) + "\n",
        encoding="utf-8")
    document = metrics.compile_query_metrics(stdout)
    assert [(row["query"], row["duration_ms"]) for row in document["queries"]] == [("A.ql", 2500), ("B.ql", 250)]
    assert document["gaps"] == ["1 of 3 export queries reported no compile time (compile-cache hit or unreported)"]


# --- runner ----------------------------------------------------------------------------------------

@pytest.mark.parametrize(("token", "expected"), [
    ("1.5s", 1500), ("1m3s", 63000), ("2h0m1s", 7201000), ("250ms", 250), ("", None), ("x", None)])
def test_runner_duration_tokens(token: str, expected: int | None) -> None:
    assert RUNNER._duration_ms(token) == expected


class _Process:
    def __init__(self, lines: list[str], code: int) -> None:
        self.stderr, self.returncode = iter(lines), code

    def wait(self) -> int:
        return self.returncode


@pytest.mark.parametrize("code", [0, 2])
def test_runner_records_bounded_analyze_timings_even_when_analysis_fails(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    lines = ["Compiling query plan\n",
             "[1/3 eval 1m2.5s] Evaluation done; writing results to codeql/cpp-queries/Sec/A.bqrs.\n",
             "[2/3] Found in cache: codeql/cpp-queries/Sec/B.bqrs.\n"]
    monkeypatch.setattr(RUNNER.subprocess, "Popen", lambda *args, **kwargs: _Process(lines, code))
    monkeypatch.setattr(RUNNER, "QUERY_TIMINGS_LIMIT", 1)
    timings = tmp_path / RUNNER.QUERY_TIMINGS_NAME
    if code:
        with pytest.raises(RuntimeError, match="exited 2"):
            RUNNER._run_analyze(["codeql"], cwd=tmp_path, environment={}, timings=timings)
    else:
        RUNNER._run_analyze(["codeql"], cwd=tmp_path, environment={}, timings=timings)
    document = json.loads(timings.read_text(encoding="utf-8"))
    assert document == {"schema": metrics.QUERY_TIMINGS_SCHEMA, "expected_query_count": 3, "truncated": True,
                        "queries": [{"ordinal": 1, "query": "codeql/cpp-queries/Sec/A", "eval_ms": 62500,
                                     "cached": False}]}
    assert RUNNER.QUERY_TIMINGS_SCHEMA == metrics.QUERY_TIMINGS_SCHEMA
    assert RUNNER.QUERY_TIMINGS_NAME == metrics.QUERY_TIMINGS_NAME


# --- job emits -------------------------------------------------------------------------------------

def _replay(run_root: Path, records: list[tuple[str, dict[str, Any]]]) -> None:
    log = PipelineLog(run_root)
    for event, details in records:
        log.write(event, run_id="run", details=json.loads(json.dumps(details, default=str)))


REQUIRED = {"action", "tool_id", "language", "source_languages", "scope_id", "build_mode"}


class _AnalyzeExecutor:
    """Stands in for CodeQLExecutor on the analyze action."""

    outcome: tuple[int, bool] = (0, False)

    def __init__(self, *, image, run_root, settings) -> None:
        self.run_root = run_root

    def execute(self, action: str, argv, *, scratch_root: Path):
        assert action == "query"
        code, timed_out = self.outcome
        if not code and not timed_out:
            atomic_json(scratch_root / "sarif" / "results.sarif",
                        _sarif("cpp/a", results=({"ruleId": "cpp/a"}, {"ruleId": "cpp/a"})))
            (scratch_root / metrics.QUERY_TIMINGS_NAME).write_text(json.dumps({
                "schema": metrics.QUERY_TIMINGS_SCHEMA, "expected_query_count": 1, "truncated": False,
                "queries": [{"ordinal": 1, "query": "codeql/cpp/A", "eval_ms": 900, "cached": False}]}),
                encoding="utf-8")
        atomic_json(scratch_root / "executions" / action / "receipt.json", {
            "schema": "appsec-review/codeql-execution/2", "action": action, "duration_ms": 1234,
            "timed_out": timed_out, "started_at": "2025-01-01T00:00:00+00:00",
            "completed_at": "2025-01-01T00:00:01.234000+00:00"})
        return SimpleNamespace(exit_code=None if timed_out else code, timed_out=timed_out, duration_ms=1234,
                               stdout_truncated=False, stderr_truncated=False)


def _profiles(unit) -> tuple[dict[str, Any], ...]:
    return tuple(dict(item) for item in codeql_job._query_profiles(
        codeql_job._settings(unit).languages["cpp"]))


@pytest.mark.parametrize(("outcome", "status"), [((0, False), "SUCCEEDED"), ((None, True), "TIMED_OUT"),
                                                  ((3, False), "FAILED")])
def test_analyze_emits_pack_language_status_runtime_and_per_query_metrics(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome, status: str) -> None:
    cpp = _scope("cpp", "native", "a")
    database = _database(tmp_path, cpp)
    unit = _unit(tmp_path, [database])
    monkeypatch.setattr(_AnalyzeExecutor, "outcome", outcome)
    monkeypatch.setattr(codeql_job, "CodeQLExecutor", _AnalyzeExecutor)
    profile = _profiles(unit)[0]
    value = codeql_job._query_one(unit, database, profile)

    completed = [details for event, details in unit.job.events.records if event == "TOOL_INVOCATION_COMPLETED"]
    started = [details for event, details in unit.job.events.records if event == "TOOL_INVOCATION_STARTED"]
    assert len(completed) == len(started) == 1
    details = completed[0]
    assert REQUIRED <= set(details) and details["action"] == "analyze"
    assert details["source_languages"] == ["C++"] and details["build_mode"] == "manual"
    assert (details["query_pack"], details["query_pack_version"], details["query_suite"]) == (
        profile["query_pack"], profile["query_pack_version"], profile["query_suite"])
    assert details["duration_ms"] == 1234 and details["timed_out"] is (status == "TIMED_OUT")
    assert "query_metrics" in details and value["terminal_status"] == ("SUCCEEDED" if status == "SUCCEEDED" else "FAILED")

    _replay(unit.job.run_root, unit.job.events.records)
    codeql = aggregate_run_metrics(unit.job.run_root)["codeql"]
    pack = codeql["by_query_pack"][profile["query_pack"]]
    assert pack["statuses"][status] == 1 and pack["runtime_ms"]["total"] == 1234
    assert codeql["by_language"]["cpp"]["source_languages"] == ["C++"]
    assert codeql["by_query_pack_language"][profile["query_pack"]]["cpp"]["by_action"]["analyze"]["count"] == 1
    if status == "SUCCEEDED":
        rows = {(row["key_kind"], row["query"]): row for row in codeql["by_query"]}
        assert rows[("query_path", "codeql/cpp/A")]["runtime_ms"]["total"] == 900
        assert rows[("rule_id", "cpp/a")]["result_count"] == 2
        assert codeql["executions"][0]["per_query"]["status"] == "complete"
    else:
        assert codeql["by_query"] == []
        assert any("runner wrote no query-timings.json" in gap for gap in codeql["gaps"])


def test_skips_and_isolated_failures_are_counted_not_dropped(tmp_path: Path, monkeypatch) -> None:
    cpp = _scope("cpp", "native", "a")
    failed = _database(tmp_path, cpp, status="FAILED")
    unit = _unit(tmp_path, [failed])
    profile = _profiles(unit)[0]
    codeql_job._query_one(unit, failed, profile)
    assert codeql_job._export_one(unit, failed)["export_status"] == "SKIPPED"

    def explode(*_args, **_kwargs):
        raise TimeoutError("boom")

    monkeypatch.setattr(codeql_job, "_database_one", explode)
    assert codeql_job._database_isolated(unit, cpp, {})["terminal_status"] == "FAILED"
    monkeypatch.setattr(codeql_job, "_export_one", explode)
    assert codeql_job._export_isolated(unit, _database(tmp_path, cpp))["export_status"] == "FAILED"

    events = [(event, details["action"]) for event, details in unit.job.events.records]
    assert events == [("CODEQL_ACTION_SKIPPED", "analyze"), ("CODEQL_ACTION_SKIPPED", "export"),
                      ("CODEQL_ACTION_FAILED", "database"), ("CODEQL_ACTION_FAILED", "export")]
    for _event, details in unit.job.events.records:
        assert REQUIRED <= set(details) and details["reason"]
    _replay(unit.job.run_root, unit.job.events.records)
    codeql = aggregate_run_metrics(unit.job.run_root)["codeql"]
    assert codeql["by_language"]["cpp"]["statuses"] == {
        "FAILED": 2, "REUSED": 0, "SKIPPED": 2, "SUCCEEDED": 0, "TIMED_OUT": 0}
    assert codeql["by_language"]["cpp"]["runtime_ms"]["unmeasured_count"] == 2
    assert codeql["by_query_pack"]["(database creation)"]["statuses"]["FAILED"] == 1
    assert sum(1 for gap in codeql["gaps"] if "runtime unmeasured" in gap) == 2


def test_export_and_compile_emit_identity_per_query_metrics_and_reuse(tmp_path: Path) -> None:
    cpp = _scope("cpp", "native", "a")
    databases = [_database(tmp_path, cpp)]
    unit = _unit(tmp_path, databases)
    codeql_job._export_scopes(unit, executor_factory=FakeExecutor().factory)
    completed = {details["action"]: details for event, details in unit.job.events.records
                 if event == "TOOL_INVOCATION_COMPLETED"}
    assert set(completed) == {"compile", "export"}
    for action, details in completed.items():
        assert REQUIRED <= set(details) and details["export_pack"] and details["query_suite"]
        assert details["timed_out"] is False and details["duration_ms"] in {5, 7}
    assert "query_metrics" in completed["export"] and "query_metrics" in completed["compile"]

    rerun = _unit(tmp_path, databases)
    codeql_job._export_scopes(rerun, executor_factory=lambda *args: pytest.fail("reuse must not execute"))
    records = unit.job.events.records + rerun.job.events.records
    _replay(unit.job.run_root, records)
    codeql = aggregate_run_metrics(unit.job.run_root)["codeql"]
    pack = completed["export"]["export_pack"]
    view = codeql["by_query_pack_language"][pack]["cpp"]
    assert view["by_action"]["export"]["statuses"]["SUCCEEDED"] == 1
    assert view["by_action"]["export"]["statuses"]["REUSED"] == 1
    assert view["by_action"]["export"]["runtime_ms"] == {
        "measured_count": 1, "unmeasured_count": 0, "total": 5, "min": 5, "max": 5, "p50": 5, "p95": 5}
    assert view["by_action"]["compile"]["count"] == 1
    export_rows = [row for row in codeql["by_query"] if row["action"] == "export"]
    assert export_rows and all(row["result_count"] is not None for row in export_rows)
    # The native recording is a live export, so its manifest carries per-query evaluate_ms.
    assert all(row["runtime_ms"]["unmeasured_count"] == 0 for row in export_rows)
    assert any("no runner compile summary" in gap for gap in codeql["gaps"])
    reused = [row for row in codeql["executions"] if row["status"] == "REUSED"]
    assert reused[0]["per_query"]["status"] == "not_applicable"


# --- aggregator views ------------------------------------------------------------------------------

def test_views_aggregate_packs_languages_and_their_product_without_enumerating_languages(tmp_path: Path) -> None:
    log = PipelineLog(tmp_path)

    def execution(index: int, *, language: str, pack: str | None, action: str, duration: int,
                  disposition: str = "SUCCEEDED", reused: bool = False, timed_out: bool = False,
                  source: tuple[str, ...] = ()) -> None:
        receipt = tmp_path / "data" / "receipts" / f"{index}.json"
        atomic_json(receipt, {"duration_ms": duration, "timed_out": timed_out})
        details = {"tool_id": "codeql", "tool_invocation_id": f"inv-{index}", "action": action,
                   "scope_id": f"scope-{language}", "language": language, "source_languages": list(source),
                   "query_pack": pack, "query_pack_version": "1.0.0" if pack else None,
                   "query_suite": "suite.qls" if pack else None}
        log.write("TOOL_INVOCATION_STARTED", run_id="run", details=details)
        log.write("TOOL_INVOCATION_COMPLETED", run_id="run", details={
            **details, "disposition": disposition, "duration_ms": duration, "result_count": 1,
            "gap_count": 0 if disposition == "SUCCEEDED" else 1, "checkpoint_reused": reused,
            "timed_out": timed_out, "truncated": False, "metrics_receipt": _identity(tmp_path, receipt),
            **({"query_metrics_gap": "checkpoint reused; no query was evaluated in this run"} if reused else {})})

    execution(1, language="java", pack=None, action="database", duration=100, source=("Java", "Kotlin"))
    execution(2, language="java", pack="codeql/java-queries", action="analyze", duration=300, source=("Java", "Kotlin"))
    execution(3, language="java", pack="sei/cert-java", action="analyze", duration=0, reused=True,
              source=("Java", "Kotlin"))
    execution(4, language="javascript", pack="codeql/javascript-queries", action="analyze", duration=900,
              disposition="FAILED", timed_out=True, source=("JavaScript", "TypeScript"))
    execution(5, language="zz-new-language", pack="codeql/java-queries", action="analyze", duration=500,
              disposition="FAILED")
    log.write("CODEQL_ACTION_SKIPPED", run_id="run", details={
        "tool_id": "codeql", "action": "analyze", "language": "javascript", "scope_id": "scope-javascript",
        "query_pack": "codeql/javascript-queries", "reason": "database failed"})
    log.write("CODEQL_ACTION_FAILED", run_id="run", details={
        "action": "normalize", "language": "java", "scope_id": "scope-java", "reason": "ignored"})

    report = aggregate_run_metrics(tmp_path)
    assert report["schema"] == "appsec-review/run-metrics/5"
    codeql = report["codeql"]
    assert codeql["totals"]["count"] == 6
    assert codeql["totals"]["statuses"] == {"FAILED": 1, "REUSED": 1, "SKIPPED": 1, "SUCCEEDED": 2, "TIMED_OUT": 1}
    java_pack = codeql["by_query_pack"]["codeql/java-queries"]
    assert java_pack["languages"] == ["java", "zz-new-language"] and java_pack["query_pack_versions"] == ["1.0.0"]
    assert java_pack["runtime_ms"] == {"measured_count": 2, "unmeasured_count": 0, "total": 800, "min": 300,
                                       "max": 500, "p50": 300, "p95": 500}
    assert codeql["by_query_pack"]["(database creation)"]["by_action"]["database"]["count"] == 1
    java = codeql["by_language"]["java"]
    assert java["statuses"]["REUSED"] == 1 and java["runtime_ms"]["total"] == 400
    assert java["source_languages"] == ["Java", "Kotlin"]
    javascript = codeql["by_query_pack_language"]["codeql/javascript-queries"]["javascript"]
    assert javascript["statuses"]["TIMED_OUT"] == 1 and javascript["statuses"]["SKIPPED"] == 1
    assert javascript["runtime_ms"]["total"] == 900
    assert codeql["by_query_pack_language"]["codeql/java-queries"]["zz-new-language"]["statuses"]["FAILED"] == 1
    assert codeql["by_source_language"]["Kotlin"]["count"] == 3
    assert any("per-query metrics were not recorded" in gap for gap in codeql["gaps"])
