"""Bounded W4 semantics over hand-authored exports, not evidence that CodeQL ran.

Exercise the shared live/offline matcher, real normalizer, shard publisher and retrieval
consumer. Seed reports and syscall events remain recorded substitutions; native compilation,
Kotlin export semantics and preinstalled CodeQL/cache commissioning are separate gaps.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import os
from pathlib import Path
import time

import pytest

from appsec_review import seeding
from appsec_review.acceptance.lanes import LaneWorkspace
from appsec_review.graph import contract as c
from appsec_review.graph.catalog import load_catalog
from appsec_review.graph.normalize import CoverageRow, normalize_scope
from appsec_review.jobs.build_bookkeeping import BookkeepingExclusions
from appsec_review.jobs.job_code_graph_index.scopes import apply_seeded_coverage, database_card, publish_scope
from appsec_review.jobs.job_codeql_analysis.planning import build_codeql_plan
from appsec_review.jobs.job_language_build.native_components import compile_entries
from appsec_review.retrieval import EntityKind, IndexIdentity, LogicalIdentity, RetrievalCore, write_manifest
from appsec_review.storage import file_sha256
from tests.fixtures.graph.expectations import SCHEMA, unmet
from tests.graph.test_normalize import _exports as _cpp_exports, _normalize as _normalize_cpp
from tests.graph.test_python_export import SCOPE, SOURCE, SOURCE_BYTES, TARGET_PATH, _exports
from tests.test_build_output_mapping import Capture, _exec
from tests.test_codeql_seeded_export import NEIGHBORHOOD_COLUMNS, SEED_FUNCTION_COLUMNS, _extract, _observation


ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = "f" * 64


@contextmanager
def _timed_lane(name: str, *, cap_seconds: int = 30):
    workspace = LaneWorkspace.create(Path(os.environ.get("APPSEC_ACCEPTANCE_ROOT", ROOT)), name)
    started = time.monotonic()
    with workspace.span(f"acceptance.{name.replace('-', '_')}"):
        yield workspace
        elapsed = time.monotonic() - started
        assert elapsed < cap_seconds, f"{name}: {elapsed:.3f}s exceeds {cap_seconds}s; {workspace.root}"
        workspace.emit("ACCEPTANCE_CASE_COMPLETED", duration_ms=elapsed * 1000, outcome="passed",
                       deadline_seconds=cap_seconds)
    records, torn = workspace.pipeline.read()
    assert records and not torn
    assert all(row["run_id"] == workspace.invocation_id and row["trigger"] == "acceptance" for row in records)
    completed = [row for row in records if row["event_type"] == "OPERATION_COMPLETED"]
    assert completed and all(row["details"]["terminal_status"] == "SUCCEEDED" for row in completed)
    assert all(row["details"]["duration_ms"] >= 0 for row in completed)
    assert all(row["details"]["resources"]["cpu_user_seconds"] >= 0 for row in completed)


def test_timed_lane_inherits_outer_root_without_relocating_source_assets(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("APPSEC_ACCEPTANCE_ROOT", str(tmp_path))
    with _timed_lane("graph-outer-root") as workspace:
        assert workspace.repository == tmp_path.resolve() and workspace.repository != ROOT
        assert workspace.root.is_relative_to(tmp_path.resolve())
        assert (ROOT / "rules" / "codeql-graph-export" / "columns.json").is_file()


def _floor():
    return {
        "schema": SCHEMA,
        "expectations": [
            {"case": "guarded", "query_id": "guards",
             "where": {"sink_start_line": 32, "guard_state": "dominating", "polarity": "true_branch"}},
            {"case": "unguarded", "query_id": "guards",
             "where": {"sink_start_line": 33, "guard_state": "none"}},
        ],
        "forbidden": [
            {"case": "safe_control_loses_guard", "query_id": "guards",
             "where": {"sink_start_line": 32, "guard_state": "none"}},
            {"case": "near_miss_gains_guard", "query_id": "guards",
             "where": {"sink_start_line": 33, "guard_state": "dominating"}},
        ],
    }


@pytest.mark.parametrize("mutation", [
    "required-missing", "forbidden-present", "split-columns", "missing-export", "truncated-negative",
])
def test_matcher_requires_and_forbids_facts_on_the_same_row(mutation: str) -> None:
    with _timed_lane("graph-matcher") as workspace:
        exports, document = _exports(), _floor()
        assert unmet(exports, document) == []
        guards = exports["guards"]
        line = guards["columns"].index("sink_start_line")
        state = guards["columns"].index("guard_state")
        polarity = guards["columns"].index("polarity")
        if mutation == "required-missing":
            guards["rows"] = [row for row in guards["rows"] if row[line] != 32]
            guards["row_count"] = len(guards["rows"])
            expected = "guarded: no guards row"
        elif mutation == "forbidden-present":
            row = next(row for row in guards["rows"] if row[line] == 33)
            row[state] = "dominating"
            expected = "near_miss_gains_guard: forbidden guards row"
        elif mutation == "split-columns":
            next(row for row in guards["rows"] if row[line] == 32)[polarity] = "false_branch"
            next(row for row in guards["rows"] if row[line] == 33)[polarity] = "true_branch"
            assert any(row[polarity] == "true_branch" for row in guards["rows"])
            expected = "guarded: no guards row"
        elif mutation == "missing-export":
            del exports["guards"]
            expected = "near_miss_gains_guard: export guards is missing"
        else:
            guards["truncated"] = True
            expected = "near_miss_gains_guard: guards is truncated; absence is unproven"
        failures = unmet(exports, document)
        assert failures and any(message.startswith(expected) for message in failures), failures
        workspace.emit("ACCEPTANCE_SEMANTIC_NEGATIVE", mutation=mutation, failures=failures)


@pytest.mark.parametrize("empty", ["subjects", "selector", "forbidden-selector", "rows"])
def test_matcher_cannot_pass_vacuous_subjects(empty: str) -> None:
    with _timed_lane("graph-nonempty"):
        exports, document = _exports(), _floor()
        if empty == "subjects":
            document["expectations"] = []
            expected = "at least one required expectation"
        elif empty in {"selector", "forbidden-selector"}:
            group = "expectations" if empty == "selector" else "forbidden"
            document[group][0]["where"] = {}
            expected = "requires a nonempty where selector"
        else:
            exports["guards"]["rows"] = []
            exports["guards"]["row_count"] = 0
            expected = "no guards row"
        assert any(expected in message for message in unmet(exports, document))


def test_safe_allowlist_and_unguarded_command_remain_distinct_in_graph_consumer() -> None:
    with _timed_lane("graph-consumer") as workspace:
        exports = _exports()
        assert unmet(exports, _floor()) == []
        target = workspace.require_owned_path(workspace.root / "fixture" / "target")
        source = target / "src" / "app.py"
        source.parent.mkdir(parents=True)
        source.write_bytes(SOURCE_BYTES)
        assert file_sha256(source) == SOURCE.sha256
        normalized = normalize_scope(
            exports, scope=SCOPE, target_snapshot=SNAPSHOT, sources={TARGET_PATH: SOURCE},
            catalog=load_catalog(), settings=c.GraphSettings(), tool_version="2.27.0",
            export_pack_sha256="e" * 64)
        sinks = {fact.location.start_line: fact for fact in normalized.facts
                 if fact.family is c.Family.SINK_SITE and fact.location.start_line in {32, 33}}
        assert set(sinks) == {32, 33}
        assert all(fact.payload["exact"] and fact.payload["result"]["sink_class"] == "command_execution"
                   for fact in sinks.values())
        run_id = "2026-10-28-0001"
        run_root = workspace.runs_dir / run_id
        indexes = publish_scope(
            run_root, scope=SCOPE, snapshot=SNAPSHOT, identity="a" * 64, facts=normalized.facts,
            symbols=normalized.symbols, relations=normalized.relations, coverage=normalized.coverage,
            catalog_release="recorded-fixture", unit_id="acceptance")
        manifest = run_root / "data" / "indices" / "manifests" / "graph.json"
        write_manifest(manifest, run_id=run_id, target_snapshot=SNAPSHOT, target_root=target,
                       indexes=[IndexIdentity(**item) for item in indexes])
        core = RetrievalCore(workspace.runs_dir, run_id, manifest_path=manifest,
                             manifest_sha256=file_sha256(manifest), graph_settings=c.GraphSettings())
        responses = {
            line: core.query_code_graph(mode="guards", subject=fact.identity.value)
            for line, fact in sinks.items()
        }
        assert all(response["results"] for response in responses.values())
        guarded, = responses[32]["results"]
        unguarded = {row["payload"]["result"]["guard_state"]: row for row in responses[33]["results"]}
        assert guarded["payload"]["result"]["guard_state"] == "dominating"
        assert guarded["payload"]["result"]["polarity"] == "true_branch"
        assert guarded["payload"]["result"]["constrains_sink_operand"] is True
        assert set(unguarded) == {"none", "non_dominating"}
        assert unguarded["none"]["payload"]["result"]["condition"] is None
        assert all(guarded["identity"] != row["identity"] for row in unguarded.values())
        for line, response in responses.items():
            for row in response["results"]:
                assert row["identity"]
                assert row["payload"]["result"]["sink"]["sink_site"] == sinks[line].identity.value
                assert row["location"]["path"] == TARGET_PATH
                assert row["location"]["file_sha256"] == file_sha256(source)
        unknown = LogicalIdentity.derive(EntityKind.SINK_SITE, SNAPSHOT, {"outside": True}).value
        missing = core.query_code_graph(mode="guards", subject=unknown)
        assert missing["results"] == [] and any("absence is a gap" in gap for gap in missing["coverage_gaps"])
        workspace.emit("ACCEPTANCE_GRAPH_CONSUMED", fact_count=len(normalized.facts),
                       subject_count=len(sinks), shard_count=len(indexes), manifest_sha256=file_sha256(manifest),
                       substitution="hand-authored Python graph exports; explicit pinned test manifest")


def test_python_seed_ledger_keeps_in_scope_and_names_out_of_scope() -> None:
    with _timed_lane("graph-python-seeds") as workspace:
        plan = build_codeql_plan(
            source_fingerprint=SNAPSHOT, files=SCOPE["files"], receipts=[], supported_extractors={"python"},
            source_image_id="sha256:" + "1" * 64)
        scope, = plan.scopes
        assert scope.language == "python" and scope.mode == "none"
        seed_plan = _extract(workspace.root / "fixture", [
            _observation(TARGET_PATH, 32), _observation("excluded/other.py", 32),
        ], [scope])
        selected = seed_plan.for_scope(scope.scope_id)
        assert scope.root == "src" and selected.rows == (("app.py", 32, 32),)
        assert seed_plan.not_in_database == 1 and seed_plan.unlocated == 0
        section = seeding.seeded_section(
            depth=0, seed_limit=200, scope_seeds=selected, plan=seed_plan,
            seed_functions={"columns": SEED_FUNCTION_COLUMNS,
                            "rows": [["app.py", 32, 32, "ping", "app.py", 30, 1]]},
            neighborhood={"columns": NEIGHBORHOOD_COLUMNS, "rows": [["ping", "app.py", 30, 1, 0]]})
        assert section["status_counts"] == {"resolved": 1, "file_not_in_database": 1}
        assert section["resolved_seed_count"] == section["neighborhood_function_count"] == 1
        assert section["seeds"][0]["functions"] == ["ping"]
        assert any(gap.startswith("seed_file_not_in_database: 1") for gap in section["gaps"])
        scope_document = {**asdict(scope), "seeded": section, "export_status": "SUCCEEDED"}
        coverage = apply_seeded_coverage(scope_document, [
            CoverageRow(scope.scope_id, c.Family.CALL_SITE, c.Coverage.COMPLETE, facts=1),
        ])
        assert coverage[0].status is c.Coverage.PARTIAL
        card = database_card(scope_document, snapshot=SNAPSHOT, coverage=coverage)
        assert card.payload["coverage"] == "partial"
        assert any("absence outside it is not evidence" in gap for gap in card.payload["gaps"])
        workspace.emit("ACCEPTANCE_SEED_SCOPE_CHECKED", language="python", selected=1, outside=1,
                       substitution="recorded seed-function/neighborhood report rows", seeded=section)


@pytest.mark.parametrize("language", ["C", "CXX"])
def test_compiler_id_contamination_is_excluded_but_real_targets_remain(language: str) -> None:
    with _timed_lane("graph-compiler-id") as workspace:
        suffix = "c" if language == "C" else "cpp"
        probe = f"build/CMakeFiles/3.28.3/CompilerId{language}/CMake{language}CompilerId.{suffix}"
        real = f"src/CompilerId{language}.{suffix}"
        capture = Capture([
            _exec(1, "/usr/bin/cc", ["cc", "-c", f"/workspace/{probe}"]),
            _exec(2, "/usr/bin/cc", ["cc", "-c", real, "-o", "build/CMakeFiles/app.dir/main.o"]),
        ])
        exclusions = BookkeepingExclusions()
        entries, gaps = compile_entries([(1, capture)], initial_directory="/workspace", exclusions=exclusions)
        assert gaps == [] and [entry["file"] for entry in entries] == [f"/workspace/{real}"]
        assert exclusions.document()["counts"] == {"cmake-compiler-identification": 1}
        assert exclusions.document()["examples"] == {"cmake-compiler-identification": [f"/workspace/{probe}"]}
        baseline = _normalize_cpp()
        exports = _cpp_exports()
        calls = exports["call_sites"]
        contaminated = list(calls["rows"][0])
        contaminated[calls["columns"].index("call_path")] = probe
        calls["rows"].append(contaminated)
        calls["row_count"] = len(calls["rows"])
        result = _normalize_cpp(exports)
        assert result.facts and {fact.identity.value for fact in result.facts} == {
            fact.identity.value for fact in baseline.facts}
        assert result.coverage_for("call_site").status is c.Coverage.PARTIAL
        assert any(gap.startswith("unmapped_location: call at " + probe)
                   for gap in result.coverage_for("call_site").gaps)
        workspace.emit("ACCEPTANCE_COMPILER_ID_EXCLUDED", probe=probe, real_source=real,
                       exclusions=exclusions.document(), substitution="recorded successful compiler exec events")
