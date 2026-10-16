"""Seeded mode of the job_codeql_analysis graph export (docs/architecture/seeded-codeql-neighborhoods.md 3, 4, 6)."""
from __future__ import annotations

import copy
import csv
from dataclasses import asdict, replace
import hashlib
import io
import json
from pathlib import Path
import tomllib
from types import SimpleNamespace
from typing import Any

import pytest

from appsec_review.codeql.runtime import EXPORT_MANIFEST_NAME, EXPORT_MANIFEST_SCHEMA, graph_export_arguments
from appsec_review.config import CodeQLExportSettings, parse_codeql_settings
from appsec_review.config.codeql import SEED_DEPTH_CEILING
from appsec_review.graph.contract import EXPORT_SCHEMA
from appsec_review import seeding
from appsec_review.jobs.job_codeql_analysis.job import (
    FrameworkIntegrityError,
    _export_identity,
    _export_one,
    _export_profile,
    _export_scopes,
    _validate_config,
    _verify_export_manifest,
)
from appsec_review.jobs.job_codeql_analysis.planning import SCOPE_SCHEMA, CodeQLScope
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation, write_manifest,
)
from appsec_review.retrieval.index import INDEX_SCHEMA
from appsec_review.storage import atomic_json, file_sha256
from tests.test_codeql_export_step import Events, ROOT, _database, _settings


JOB = "job_codeql_analysis"
SNAPSHOT = "f" * 64


def _scope(root: str, files: tuple[str, ...], unit: str = "a") -> CodeQLScope:
    entries = tuple({"path": path, "sha256": "a" * 64, "size_bytes": 12} for path in files)
    return CodeQLScope(SCOPE_SCHEMA, f"codeql-unit-{unit * 24}", "cpp", ("C++",), "manual", root, entries,
                       f"build-unit-{unit * 20}", unit * 64, "e" * 64, True)


def _observation(path: str | None, start: int | None = 1, end: int | None = None, *, tool: str = "tool-cppcheck",
                 rule: str = "r1", severity: str = "HIGH", category: str = "source_sast") -> dict[str, Any]:
    return {"path": path, "start": start, "end": end if end is not None else start, "tool": tool, "rule": rule,
            "severity": severity, "category": category}


def _shard(tmp_path: Path, shard_id: str, job: str, observations: list[dict[str, Any]]) -> IndexIdentity:
    run_root = tmp_path / "run"
    fingerprint = hashlib.sha256(shard_id.encode()).hexdigest()
    path = run_root / "data" / "indices" / "observations" / shard_id / f"{fingerprint}.sqlite"
    if path.exists():   # the same shard rebuilt in one test: reuse the immutable file
        return IndexIdentity("observations", INDEX_SCHEMA, file_sha256(path), fingerprint,
                             path.relative_to(run_root).as_posix(), {"job": job, "producer": shard_id}, (), shard_id)
    builder = IndexBuilder(path, name="observations", fingerprint=fingerprint, target_snapshot=SNAPSHOT,
                           shard_id=shard_id)
    for ordinal, item in enumerate(observations):
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT,
                                          {"shard": shard_id, "ordinal": ordinal})
        location = None
        if item["path"] is not None and item["start"] is not None:
            location = SourceLocation(SNAPSHOT, item["path"], "a" * 64, 0, 10, item["start"], item["end"], 1, 1,
                                      {"tool": item["tool"]}, "producer-line-location", 1.0)
        builder.add_entity(EntityRecord(
            identity, f"{shard_id}-{ordinal}", item["rule"], item["rule"],
            {"tool_id": item["tool"], "native_rule_id": item["rule"], "native_severity": item["severity"],
             "category": item["category"]}, location))
    sha = builder.build()
    return IndexIdentity("observations", INDEX_SCHEMA, sha, fingerprint,
                         path.relative_to(run_root).as_posix(), {"job": job, "producer": shard_id}, (), shard_id)


def _manifest(tmp_path: Path, name: str, *shards: IndexIdentity) -> dict[str, str]:
    run_root = tmp_path / "run"
    path = run_root / "data" / "indices" / "manifests" / f"{name}.json"
    write_manifest(path, run_id="run", target_snapshot=SNAPSHOT, target_root=tmp_path, indexes=shards)
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path)}


def _extract(tmp_path: Path, observations: list[dict[str, Any]], scopes: list[CodeQLScope], *,
             limit: int = 200) -> seeding.SeedPlan:
    manifest = _manifest(tmp_path, "upstream", _shard(tmp_path, "evidence", "job_evidence_collection", observations))
    return seeding.extract_seeds(tmp_path / "run", [manifest], scopes, seed_limit=limit)


# ---------------------------------------------------------------------------------------------- extraction


def test_seeds_map_to_database_relative_paths_dedupe_and_keep_bounded_sorted_sources(tmp_path: Path) -> None:
    rooted = _scope("native", ("native/src/a.cpp", "native/b.cpp"), "a")
    plain = _scope(".", ("tools/c.cpp",), "b")
    observations = [
        _observation("native/src/a.cpp", 10, 12, rule="zeta", tool="tool-b"),
        _observation("native/src/a.cpp", 10, 12, rule="alpha", tool="tool-a", severity="LOW"),
        _observation("native/b.cpp", 3),
        _observation("tools/c.cpp", 7, 9),
        _observation("not/in/a/db.py", 1),
    ] + [_observation("native/src/a.cpp", 10, 12, rule=f"extra{number:02d}", tool="tool-c") for number in range(20)]
    plan = _extract(tmp_path, observations, [rooted, plain])

    first = plan.for_scope(rooted.scope_id)
    assert [seed.key for seed in first.seeds] == [("b.cpp", 3, 3), ("src/a.cpp", 10, 12)]
    assert first.total == 2 and first.dropped == 0
    merged = first.seeds[1]
    assert len(merged.sources) == seeding.MAX_SOURCES_PER_SEED
    assert [source.key() for source in merged.sources] == sorted(source.key() for source in merged.sources)
    assert merged.sources[0].scanner == "tool-a" and merged.sources[0].severity == "low"
    assert all(source.observation_id.startswith("asr:tool_observation:") for source in merged.sources)
    assert [seed.key for seed in plan.for_scope(plain.scope_id).seeds] == [("tools/c.cpp", 7, 9)]
    assert plan.not_in_database == 1 and plan.unlocated == 0
    assert plan.shared_gaps() == ["seed_file_not_in_database: 1 finding locations lie in no CodeQL database "
                                  "scope and cannot seed a neighborhood"]


def test_seed_limit_keeps_the_highest_severity_then_path_and_line_and_names_the_drop(tmp_path: Path) -> None:
    scope = _scope(".", ("a.cpp", "b.cpp"))
    observations = [
        _observation("b.cpp", 1, severity="LOW"),
        _observation("a.cpp", 50, severity="MEDIUM"),
        _observation("b.cpp", 5, severity="CRITICAL"),
        _observation("a.cpp", 9, severity="MEDIUM"),
        _observation("a.cpp", 2, severity="INFO"),
        _observation("a.cpp", 3, severity="mystery"),
    ]
    plan = _extract(tmp_path, observations, [scope], limit=3)
    selected = plan.for_scope(scope.scope_id)
    # critical, then the two medium ones by path and line; output order is path, start, end.
    assert [seed.key for seed in selected.seeds] == [("a.cpp", 9, 9), ("a.cpp", 50, 50), ("b.cpp", 5, 5)]
    assert (selected.total, selected.dropped) == (6, 3)
    section = seeding.seeded_section(depth=3, seed_limit=3, scope_seeds=selected, plan=plan)
    assert "seed_limit_exceeded: 3 of 6 seeds dropped" in section["gaps"]
    assert section["status_counts"]["over_limit"] == 3
    # Re-extraction is deterministic.
    assert _extract(tmp_path, observations, [scope], limit=3).for_scope(scope.scope_id) == selected


def test_codeql_results_are_not_seeds_and_unlocated_source_findings_are_counted(tmp_path: Path) -> None:
    scope = _scope(".", ("a.cpp",))
    run = tmp_path / "run"
    own = _shard(tmp_path, "codeql-cpp", JOB, [_observation("a.cpp", 4, tool="codeql")])
    evidence = _shard(tmp_path, "evidence", "job_evidence_collection", [
        _observation("a.cpp", 8, tool="codeql"),                      # produced by CodeQL under another job
        _observation("a.cpp", 20),
        _observation(None, None),                                      # source finding without a line
        _observation(None, None, category="dependency", tool="tool-trivy"),  # not a source finding: no seed, no noise
    ])
    manifest = _manifest(tmp_path, "upstream", own, evidence)
    plan = seeding.extract_seeds(run, [manifest], [scope], seed_limit=10)
    assert [seed.key for seed in plan.for_scope(scope.scope_id).seeds] == [("a.cpp", 20, 20)]
    assert plan.unlocated == 1 and plan.not_in_database == 0   # the source finding without a line
    assert any("seed_unlocated: 1" in gap for gap in plan.shared_gaps())


def test_a_path_in_two_nested_scopes_seeds_both_and_a_changed_shard_is_refused(tmp_path: Path) -> None:
    outer = _scope(".", ("sub/a.cpp",), "a")
    inner = _scope("sub", ("sub/a.cpp",), "b")
    manifest = _manifest(tmp_path, "upstream",
                         _shard(tmp_path, "evidence", "job_evidence_collection", [_observation("sub/a.cpp", 2)]))
    plan = seeding.extract_seeds(tmp_path / "run", [manifest], [outer, inner], seed_limit=5)
    assert plan.for_scope(outer.scope_id).rows == (("sub/a.cpp", 2, 2),)
    assert plan.for_scope(inner.scope_id).rows == (("a.cpp", 2, 2),)
    shard = next((tmp_path / "run" / "data" / "indices" / "observations" / "evidence").glob("*.sqlite"))
    shard.chmod(0o644)
    shard.write_bytes(shard.read_bytes() + b"x")
    with pytest.raises(seeding.SeedIntegrityError, match="shard identity"):
        seeding.extract_seeds(tmp_path / "run", [manifest], [outer], seed_limit=5)
    with pytest.raises(seeding.SeedIntegrityError, match="manifest identity"):
        seeding.extract_seeds(tmp_path / "run", [{**manifest, "sha256": "0" * 64}], [outer], seed_limit=5)


# ---------------------------------------------------------------------------------------------- settings


def _raw() -> dict[str, Any]:
    raw = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    return raw["jobs"][JOB]["settings"]


def test_central_toml_defaults_to_seeded_mode_and_validates_the_depth_bounds() -> None:
    export = parse_codeql_settings(_raw()).export_queries
    assert (export.mode, export.seed_depth, export.max_seed_depth, export.seed_limit) == ("seeded", 3, 8, 200)
    assert SEED_DEPTH_CEILING == 8
    assert CodeQLExportSettings(mode="whole_program", seed_depth=0).seed_depth == 0
    assert CodeQLExportSettings(seed_depth=8, max_seed_depth=8).seed_depth == 8
    for bad in ({"mode": "Seeded"}, {"seed_depth": 9}, {"max_seed_depth": 9}, {"seed_depth": -1},
                {"seed_limit": 0}, {"seed_limit": False}, {"seed_depth": 4, "max_seed_depth": 2}):
        with pytest.raises(ValueError):
            CodeQLExportSettings(**bad)
    raw = copy.deepcopy(_raw())
    raw["export_queries"]["seed_depth"] = 9
    with pytest.raises(ValueError, match="seed_depth"):
        parse_codeql_settings(raw)


def test_job_config_validation_rejects_invalid_export_scope_settings() -> None:
    from appsec_review.config import load_config

    config = load_config(ROOT / "appsec-review.toml").job(JOB)
    _validate_config(SimpleNamespace(config=config), None)
    export = config.typed_settings.export_queries
    object.__setattr__(export, "seed_depth", 12)   # corrupt after construction: the job re-validates
    try:
        with pytest.raises(ValueError, match="seed_depth"):
            _validate_config(SimpleNamespace(config=config), None)
    finally:
        object.__setattr__(export, "seed_depth", 3)


# ---------------------------------------------------------------------------------------------- identity & staging


def test_export_identity_binds_mode_depth_limit_and_the_sorted_seed_set(tmp_path: Path) -> None:
    settings = _settings("seeded")
    database = _database(tmp_path, _scope(".", ("a.cpp",)))
    profile = _export_profile(settings, "cpp")
    assert profile is not None

    def identity(value=settings, seeds=(("a.cpp", 1, 2),)) -> str:
        return _export_identity(database, profile, value, runner_sha256="9" * 64, seeds=seeds)

    base = identity()
    assert identity(seeds=(("a.cpp", 1, 2),)) == base
    assert identity(seeds=[("b.cpp", 1, 1), ("a.cpp", 1, 2)]) == identity(seeds=[("a.cpp", 1, 2), ("b.cpp", 1, 1)])
    assert identity(seeds=(("a.cpp", 1, 3),)) != base
    assert identity(seeds=(("a.cpp", 1, 2), ("a.cpp", 5, 5))) != base
    export = settings.export_queries
    assert identity(replace(settings, export_queries=replace(export, seed_depth=2))) != base
    assert identity(replace(settings, export_queries=replace(export, seed_limit=7))) != base
    whole = replace(settings, export_queries=replace(export, mode="whole_program"))
    assert identity(whole) != base
    # Whole-program identity depends on the mode only, never on depth, limit or seeds.
    assert identity(whole, seeds=()) == identity(
        replace(whole, export_queries=replace(whole.export_queries, seed_depth=1, seed_limit=2)), seeds=(("x", 1, 1),))


def test_staging_writes_headerless_csv_with_proper_quoting(tmp_path: Path) -> None:
    from appsec_review.jobs.job_codeql_analysis.job import _stage_export

    scope = _scope(".", ("a.cpp",))
    database = _database(tmp_path, scope)
    profile = _export_profile(_settings(), "cpp")
    assert profile is not None
    root = tmp_path / "run" / "data" / "codeql" / "scopes" / scope.scope_id
    unit = SimpleNamespace(job=SimpleNamespace(repository_root=ROOT), unit_id="export.scopes")
    rows = [("src/b, odd.cpp", 5, 6), ('q"uote.cpp', 1, 1), ("a.cpp", 10, 12)]
    _stage_export(unit, root, root / "export", profile, mode="seeded", depth=4, seed_rows=rows)
    assert (root / "export" / "scope.csv").read_text(encoding="utf-8") == "seeded,4\n"
    text = (root / "export" / "seeds.csv").read_text(encoding="utf-8")
    assert text.splitlines()[0] == "a.cpp,10,12"
    assert list(csv.reader(io.StringIO(text))) == [["a.cpp", "10", "12"], ['q"uote.cpp', "1", "1"],
                                                  ["src/b, odd.cpp", "5", "6"]]
    assert database["terminal_status"] == "SUCCEEDED"


# ---------------------------------------------------------------------------------------------- the job


def _rows(name: str, *rows: list[Any]) -> list[Any]:
    return sorted(rows, key=lambda row: tuple(str(value) for value in row))


SEED_FUNCTION_COLUMNS = ["seed_path", "seed_start_line", "seed_end_line", "function_name", "function_path",
                         "function_start_line", "function_start_column"]
NEIGHBORHOOD_COLUMNS = ["function_name", "function_path", "function_start_line", "function_start_column", "depth"]


class SeededExecutor:
    """Plays the runner: reads the staged CSV files, writes a bounded export with the two report queries."""

    def __init__(self, resolved: dict[tuple[str, int, int], list[str]], neighborhood: list[list[Any]],
                 *, manifest_scope: dict[str, Any] | None = None, reports: bool = True) -> None:
        self.resolved, self.neighborhood = resolved, neighborhood
        self.manifest_scope, self.reports = manifest_scope, reports
        self.calls: list[tuple[str, ...]] = []
        self.staged: dict[str, str] = {}

    def factory(self, image, run_root, settings):
        return self

    def execute(self, action: str, argv, *, scratch_root: Path):
        if action == "compile":
            atomic_json(scratch_root / "executions" / action / "receipt.json",
                        {"schema": "appsec-review/codeql-execution/2", "action": action})
            return SimpleNamespace(exit_code=0, timed_out=False, duration_ms=1, stdout_truncated=False,
                                   stderr_truncated=False)
        self.calls.append(tuple(argv))
        values = dict(zip(argv[::2], argv[1::2]))
        self.staged = {name: (scratch_root / values[flag]).read_text(encoding="utf-8")
                       for name, flag in (("scope", "--scope-file"), ("seeds", "--seeds-file"))}
        scope_rows = list(csv.reader(io.StringIO(self.staged["scope"])))
        seed_rows = list(csv.reader(io.StringIO(self.staged["seeds"])))
        output = scratch_root / values["--output-dir"]
        output.mkdir(parents=True)
        documents = {"call_sites": (["caller_name"], [])}
        if self.reports:
            documents["seed_functions"] = (SEED_FUNCTION_COLUMNS, _rows("seed", *[
                [path, start, end, name, path, start, 1] for (path, start, end), names in self.resolved.items()
                for name in names]))
            documents["neighborhood"] = (NEIGHBORHOOD_COLUMNS, _rows("n", *self.neighborhood))
        exports = []
        for query_id, (columns, rows) in sorted(documents.items()):
            document = {"bqrs_sha256": "d" * 64, "columns": columns, "query_id": query_id, "row_count": len(rows),
                        "rows": rows, "schema": EXPORT_SCHEMA, "truncated": False}
            path = output / f"{query_id}.json"
            path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            exports.append({"bqrs_sha256": "d" * 64, "bytes": path.stat().st_size, "decode_ms": 0,
                            "exported_rows": len(rows), "path": path.name, "query_file": f"{query_id}.ql",
                            "query_id": query_id, "row_count": len(rows), "sha256": file_sha256(path),
                            "truncated": False})
        profile = _export_profile(_settings(), "cpp")
        scope = self.manifest_scope or {"mode": scope_rows[0][0], "depth": int(scope_rows[0][1]),
                                        "seed_count": len(seed_rows)}
        manifest = {"export_schema": EXPORT_SCHEMA, "exports": exports, "language": "cpp", "max_bytes": 268435456,
                    "pack": {key: profile[key] for key in ("columns_sha256", "file_count", "query_id", "query_pack",
                                                           "query_pack_version", "tree_sha256")},
                    "row_limit": 200000, "schema": EXPORT_MANIFEST_SCHEMA, "scope": scope}
        atomic_json(output / EXPORT_MANIFEST_NAME, manifest)
        atomic_json(scratch_root / "executions" / action / "receipt.json",
                    {"schema": "appsec-review/codeql-execution/2", "action": action})
        return SimpleNamespace(exit_code=0, timed_out=False, duration_ms=3, stdout_truncated=False,
                               stderr_truncated=False)


def _unit(tmp_path: Path, databases: list[dict[str, Any]], manifests: list[dict[str, str]], settings=None):
    run_root = tmp_path / "run"
    job = SimpleNamespace(run_root=run_root, repository_root=ROOT, source_fingerprint=SNAPSHOT, events=Events(),
                          attempt_root=run_root / "data" / "jobs" / JOB / "attempts" / "attempt_0001",
                          config=SimpleNamespace(typed_settings=settings or _settings("seeded")))
    outputs = {"database.scopes": {"databases": databases},
               "plan.inventory": {"upstream_manifests": manifests}}
    return SimpleNamespace(job=job, unit_id="export.scopes", output=lambda name: outputs[name])


def _fixture(tmp_path: Path, observations: list[dict[str, Any]]):
    scope = _scope("native", ("native/a.cpp", "native/b.cpp"))
    manifest = _manifest(tmp_path, "upstream", _shard(tmp_path, "evidence", "job_evidence_collection", observations))
    return scope, _database(tmp_path, scope), manifest


def test_seeded_export_stages_the_seeds_and_publishes_the_ledger_from_the_report_queries(tmp_path: Path) -> None:
    scope, database, manifest = _fixture(tmp_path, [
        _observation("native/a.cpp", 10, 12, rule="oob", severity="HIGH"),
        _observation("native/b.cpp", 40, severity="LOW"),
        _observation("native/b.cpp", 1, severity="MEDIUM"),
        _observation("docs/readme.md", 1),
    ])
    executor = SeededExecutor(
        resolved={("a.cpp", 10, 12): ["ns::f", "ns::f2"], ("b.cpp", 40, 40): ["g"]},
        neighborhood=[["ns::f", "a.cpp", 8, 1, 0], ["ns::f2", "a.cpp", 20, 1, 0], ["g", "b.cpp", 38, 1, 0],
                      ["h", "b.cpp", 70, 1, 1], ["i", "c.cpp", 3, 1, 1], ["j", "c.cpp", 9, 1, 2]])
    unit = _unit(tmp_path, [database], [manifest])
    output = _export_scopes(unit, executor_factory=executor.factory)

    assert executor.staged["scope"] == "seeded,3\n"
    assert executor.staged["seeds"] == "a.cpp,10,12\nb.cpp,1,1\nb.cpp,40,40\n"
    assert executor.calls[0][executor.calls[0].index("--scope-file") + 1] == "export/scope.csv"
    assert tuple(executor.calls[0]) == graph_export_arguments(
        database="export/database", pack="export/pack", columns="export/columns.json",
        asset_lock="export/assets.lock.json", language="cpp", output_dir="exports", scope_file="export/scope.csv",
        seeds_file="export/seeds.csv", row_limit=200000, max_bytes=268435456, threads=2, ram_mb=4096)

    record = output["exports"][0]
    assert record["export_status"] == "SUCCEEDED"
    seeded = record["seeded"]
    assert {key: seeded[key] for key in ("mode", "depth", "seed_limit", "seed_count", "resolved_seed_count",
                                         "neighborhood_function_count", "depth_histogram")} == {
        "mode": "seeded", "depth": 3, "seed_limit": 200, "seed_count": 3, "resolved_seed_count": 2,
        "neighborhood_function_count": 6, "depth_histogram": {"0": 3, "1": 2, "2": 1}}
    ledger = {(item["path"], item["start_line"], item["end_line"]): item for item in seeded["seeds"]}
    assert list(ledger) == [("a.cpp", 10, 12), ("b.cpp", 1, 1), ("b.cpp", 40, 40)]
    assert ledger[("a.cpp", 10, 12)]["status"] == "resolved"
    assert ledger[("a.cpp", 10, 12)]["functions"] == ["ns::f", "ns::f2"]
    assert ledger[("a.cpp", 10, 12)]["sources"][0] | {"observation_id": "x"} == {
        "scanner": "tool-cppcheck", "rule": "oob", "severity": "high", "observation_id": "x"}
    assert ledger[("b.cpp", 1, 1)]["status"] == "unresolved" and ledger[("b.cpp", 1, 1)]["functions"] == []
    assert seeded["status_counts"] == {"resolved": 2, "unresolved": 1, "file_not_in_database": 1}
    assert any(gap.startswith("seed_unresolved: 1 of 3") for gap in seeded["gaps"])
    assert set(seeded["gaps"]) <= set(record["gaps"]) and output["terminal_status"] == "COMPLETED_WITH_GAPS"

    # The seeds are part of the identity: a changed seed set re-runs, an unchanged one is reused.
    again = _export_scopes(_unit(tmp_path, [database], [manifest]), executor_factory=_never)
    assert again["exports"][0]["export_reused"] is True and again["exports"][0]["seeded"] == seeded
    other = _manifest(tmp_path, "upstream2", _shard(tmp_path, "evidence2", "job_evidence_collection",
                                                    [_observation("native/a.cpp", 11)]))
    rerun = _export_scopes(_unit(tmp_path, [database], [other]), executor_factory=executor.factory)
    assert rerun["exports"][0]["export_reused"] is False and len(executor.calls) == 2
    assert rerun["exports"][0]["export_identity"] != record["export_identity"]


def _never(image, run_root, settings):
    raise AssertionError("this scope must not run CodeQL")


def test_a_scope_without_seeds_is_skipped_with_a_named_partial_gap_and_never_runs_codeql(tmp_path: Path) -> None:
    scope, database, manifest = _fixture(tmp_path, [_observation("docs/readme.md", 1),
                                                    _observation("native/a.cpp", 4, tool="codeql")])
    output = _export_scopes(_unit(tmp_path, [database], [manifest]), executor_factory=_never)
    record = output["exports"][0]
    assert record["export_status"] == "SKIPPED" and record["reason"] == seeding.NO_SEEDS_GAP
    assert record["gaps"][0] == "seeded export skipped: no finding locations map into this database"
    assert record["seeded"]["seed_count"] == 0 and record["seeded"]["seeds"] == []
    assert record["seeded"]["mode"] == "seeded" and record["seeded"]["depth"] == 3
    assert output["terminal_status"] == "COMPLETED_WITH_GAPS" and output["export_count"] == 0
    assert output["dispositions"][0]["terminal_status"] == "SKIPPED"
    scope_root = tmp_path / "run" / "data" / "codeql" / "scopes" / scope.scope_id
    assert not (scope_root / "export-checkpoint.json").exists() and not (scope_root / "exports").exists()


def test_no_observation_manifests_at_all_is_the_same_named_gap(tmp_path: Path) -> None:
    scope, database, _manifest_ref = _fixture(tmp_path, [])
    output = _export_scopes(_unit(tmp_path, [database], []), executor_factory=_never)
    assert output["exports"][0]["export_status"] == "SKIPPED"
    assert seeding.NO_SEEDS_GAP in output["gaps"]


def test_whole_program_mode_needs_no_seeds_and_records_an_empty_seeded_section(tmp_path: Path) -> None:
    scope, database, manifest = _fixture(tmp_path, [])
    settings = _settings("whole_program")
    executor = SeededExecutor({}, [], reports=False)
    unit = _unit(tmp_path, [database], [], settings)
    unit.output = lambda name: {"database.scopes": {"databases": [database]}}[name]   # no plan needed
    output = _export_scopes(unit, executor_factory=executor.factory)
    record = output["exports"][0]
    assert executor.staged == {"scope": "whole_program,0\n", "seeds": ""}
    assert record["export_status"] == "SUCCEEDED"
    assert record["seeded"] == seeding.whole_program_section()
    assert record["seeded"]["mode"] == "whole_program" and record["seeded"]["depth"] is None
    assert record["seeded"]["seeds"] == []


def test_seeded_export_without_its_report_queries_or_with_a_wrong_manifest_scope_is_a_failed_export(
        tmp_path: Path) -> None:
    scope, database, manifest = _fixture(tmp_path, [_observation("native/a.cpp", 10)])
    missing = SeededExecutor({}, [], reports=False)
    value = _export_one(_unit(tmp_path, [database], [manifest]), database, executor_factory=missing.factory)
    assert value["export_status"] == "FAILED"
    assert value["gaps"] == ["CodeQL graph export produced an invalid bounded export (GraphExportIntegrityError)"]
    assert not (tmp_path / "run" / "data" / "codeql" / "scopes" / scope.scope_id / "export-checkpoint.json").exists()

    for wrong in ({"mode": "whole_program", "depth": 3, "seed_count": 1},
                  {"mode": "seeded", "depth": 2, "seed_count": 1},
                  {"mode": "seeded", "depth": 3, "seed_count": 5}):
        executor = SeededExecutor({}, [], manifest_scope=wrong)
        value = _export_one(_unit(tmp_path, [database], [manifest]), database, executor_factory=executor.factory)
        assert value["export_status"] == "FAILED", wrong


def test_manifest_scope_is_verified_only_when_present(tmp_path: Path) -> None:
    scope = _scope(".", ("a.cpp",))
    profile = _export_profile(_settings("seeded"), "cpp")
    assert profile is not None
    base = {"language": "cpp", "row_limit": 200000, "max_bytes": 268435456,
            "pack": {key: profile[key] for key in ("tree_sha256", "query_pack", "query_pack_version",
                                                   "columns_sha256")}}
    root = tmp_path / "exports"
    root.mkdir()

    def verify(extra: dict[str, Any], settings=None, seed_count: int = 2):
        atomic_json(root / EXPORT_MANIFEST_NAME, {**base, **extra})
        return _verify_export_manifest(root, scope, profile, settings or _settings("seeded"), seed_count=seed_count)

    verify({})
    verify({"scope": {"mode": "seeded", "depth": 3, "seed_count": 2}})
    for scope_value in ({"mode": "seeded", "depth": 3, "seed_count": 1}, {"mode": "seeded", "depth": 4, "seed_count": 2},
                        {"mode": "whole_program", "depth": 0, "seed_count": 0}, "seeded"):
        with pytest.raises(Exception, match="scope differs"):
            verify({"scope": scope_value})
    verify({"scope": {"mode": "whole_program", "depth": 0, "seed_count": 0}}, _settings("whole_program"), 0)
    with pytest.raises(Exception, match="scope differs"):
        verify({"scope": {"mode": "whole_program", "depth": 0, "seed_count": 1}}, _settings("whole_program"), 0)


def test_ledger_statuses_and_depth_histogram_from_fake_report_rows() -> None:
    selected = seeding.ScopeSeeds("s", (
        seeding.Seed("a.cpp", 1, 2, (seeding.SeedSource("t", "r", "high", "asr:tool_observation:1"),)),
        seeding.Seed("b.cpp", 3, 3)), total=5, dropped=3)
    plan = seeding.SeedPlan({"s": selected}, not_in_database=2, unlocated=1)
    functions = {"columns": SEED_FUNCTION_COLUMNS, "rows": [
        ["a.cpp", 1, 2, f"f{number}", "a.cpp", 1, 1] for number in range(12)]}
    neighborhood = {"columns": NEIGHBORHOOD_COLUMNS, "rows": [
        ["f0", "a.cpp", 1, 1, 0], ["f0", "a.cpp", 1, 1, 0], ["g", "a.cpp", 9, 1, 1], ["h", "z.cpp", 4, 2, 10]]}
    section = seeding.seeded_section(depth=3, seed_limit=2, scope_seeds=selected, plan=plan,
                                     seed_functions=functions, neighborhood=neighborhood)
    assert section["neighborhood_function_count"] == 3
    assert section["depth_histogram"] == {"0": 1, "1": 1, "10": 1}
    assert [item["status"] for item in section["seeds"]] == ["resolved", "unresolved"]
    assert len(section["seeds"][0]["functions"]) == seeding.MAX_FUNCTIONS_PER_SEED
    assert section["status_counts"] == {"resolved": 1, "unresolved": 1, "file_not_in_database": 2, "over_limit": 3}
    assert section["gaps"][0] == "seed_limit_exceeded: 3 of 5 seeds dropped"
    assert any(gap.startswith("seed_file_not_in_database: 2") for gap in section["gaps"])
    empty = seeding.seeded_section(depth=0, seed_limit=2, scope_seeds=selected, plan=seeding.SeedPlan(),
                                   seed_functions={"columns": SEED_FUNCTION_COLUMNS, "rows": []},
                                   neighborhood={"columns": NEIGHBORHOOD_COLUMNS, "rows": []})
    assert empty["resolved_seed_count"] == 0 and "seeded neighborhood is empty" in " ".join(empty["gaps"])
    assert json.dumps(section)   # JSON-serialisable, no sets or dataclasses
    assert asdict(selected.seeds[0])["path"] == "a.cpp"
