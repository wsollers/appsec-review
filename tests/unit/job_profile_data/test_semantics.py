"""Profile report bytes -> immutable publication -> bounded, context-only consumers."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_profile_data import ProfileBounds, build_job, parse_profile
from appsec_review.jobs.job_profile_data.datasets import DATASETS
from appsec_review.retrieval import write_manifest
from appsec_review.retrieval.core import RetrievalCore, RetrievalLimits
from appsec_review.retrieval.model import canonical_json
from appsec_review.review.scope import accept_manifest
from appsec_review.review.units import _engineering_context
from appsec_review.runtime import UnitContext
from appsec_review.storage import file_sha256


def _publish(
    tmp_path: Path, reports: list[tuple[str, bytes, str]], *,
    bounds: ProfileBounds = ProfileBounds(), attempt: str = "attempt_0001",
) -> SimpleNamespace:
    """Supply accepted-receipt inputs; all profile handlers and storage remain real."""
    root = tmp_path / "runs" / "2026-11-19-0001"
    artifacts = []
    for name, data, origin in reports:
        path = root / "data" / "build" / "u" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(data)
        assert path.read_bytes() == data
        artifacts.append({
            "path": path.relative_to(root).as_posix(), "sha256": file_sha256(path),
            "workspace_path": name, "kind": "execution-profile", "artifact_origin": origin,
        })
    upstream = root / "data" / "indices" / "manifests" / "upstream.json"
    if not upstream.exists():
        write_manifest(upstream, run_id=root.name, target_snapshot="profile-snapshot",
                       target_root=root, indexes=())
    context = SimpleNamespace(
        run_root=root, run_id=root.name, source_fingerprint="profile-snapshot",
        target_root=root, repository_root=root, attempt_id=attempt,
        attempt_root=root / "data" / "jobs" / "job_profile_data" / "attempts" / attempt,
        config=SimpleNamespace(settings={"bounds": asdict(bounds)}),
    )
    outputs = {"load.accepted_inputs": {
        "receipts": [{"build_unit_id": "u", "family": "native", "artifacts": artifacts}],
        "upstream_manifest": {"path": upstream.relative_to(root).as_posix(),
                              "sha256": file_sha256(upstream)},
        "upstream_handoffs": {}, "gaps": [],
    }}
    for unit in build_job().units[1:]:
        step, task = unit.unit_id.split(".")
        outputs[unit.unit_id] = unit.handler(UnitContext(
            context, unit.unit_id, step, task, context.attempt_root / step / task, outputs))
    publication = outputs["acceptance.publish_handoff"]
    manifest = root / publication["index_manifest"]["path"]
    core = RetrievalCore(root.parent, root.name, manifest_path=manifest,
                         manifest_sha256=publication["index_manifest"]["sha256"])
    document = json.loads((root / publication["artifact"]["path"]).read_text(encoding="utf-8"))
    return SimpleNamespace(root=root, outputs=outputs, publication=publication,
                           document=document, manifest=manifest, core=core)


def _callgrind(source: str, symbol: str = "hot") -> bytes:
    return f"events: Ir\nfl={source}\nfn={symbol}\n7 9\n".encode()


def test_identical_reports_keep_distinct_origins_and_reuse_independent_of_order(tmp_path: Path) -> None:
    reports = [("a.folded", b"hot 9\n", "accepted-input"),
               ("b.folded", b"hot 9\n", "build-output")]
    first = _publish(tmp_path, reports)
    rows = first.core.query_engineering_signals(signal_family="profile")["results"]
    assert len(rows) == len({row["identity"] for row in rows}) == 2
    by_report = {row["payload"]["report_path"]: row["payload"] for row in rows}
    for rank, (name, data, origin) in enumerate(reports, 1):
        relative = f"data/build/u/{name}"
        payload = by_report[relative]
        assert payload["report_sha256"] == file_sha256(first.root / relative)
        assert payload["artifact_origin"] == origin
        assert payload["count"] == 9
        assert (payload["hotness_rank"], payload["hotness_population"]) == (rank, 2)
    second = _publish(tmp_path, list(reversed(reports)), attempt="attempt_0002")
    assert second.outputs["index.profile_data"]["indexes"] == first.outputs["index.profile_data"]["indexes"]
    assert second.document["build_units"] == first.document["build_units"]
    assert first.publication["terminal_status"] == "SUCCEEDED"


def test_callgrind_keeps_callsite_callee_and_self_costs_distinct(tmp_path: Path) -> None:
    report = b"""events: Ir Dr
fl=(1) caller.c
fn=(1) caller
10 1 0
cfl=(2) callee.c
cfn=(2) callee
calls=1 7
100 9 2
fl=(2)
fn=(2)
7 9 2
"""
    result = _publish(tmp_path, [("callgrind.out", report, "accepted-input")])
    rows = result.core.query_engineering_signals(signal_family="profile", path="callee.c")["results"]
    assert len(rows) == 4
    by_kind = {(row["payload"]["cost_kind"], row["payload"]["event"]): row["payload"] for row in rows}
    for event, count in (("Ir", 9), ("Dr", 2)):
        call = by_kind[("call_inclusive", event)]
        own = by_kind[("self", event)]
        assert (call["symbol"], call["source"], call["line"], call["count"]) == ("callee", "callee.c", 7, count)
        assert (call["callsite_symbol"], call["callsite_source"], call["callsite_line"]) == ("caller", "caller.c", 100)
        assert (own["symbol"], own["source"], own["line"], own["count"]) == ("callee", "callee.c", 7, count)
        assert own["callsite_line"] is None
    assert all("location" not in row for row in rows)


def test_callgrind_implicit_callee_file_and_unresolved_calls_do_not_reuse_stale_context() -> None:
    document = parse_profile(b"""events: Ir
fl=src/a.c
fn=caller
1 1
cfn=callee
calls=2 7
3 5
cfn=(99)
calls=1 8
4 9
fn=next
calls=1 1
6 2
7 0
""", "callgrind")
    calls = [row for row in document.rows if row.cost_kind == "call_inclusive"]
    assert len(calls) == 1
    assert (calls[0].symbol, calls[0].source, calls[0].line, calls[0].callsite_line) == ("callee", "src/a.c", 7, 3)
    assert any("ambiguous_symbol" in gap for gap in document.gaps)
    assert any(row.symbol == "next" and row.count == 0 and row.cost_kind == "self" for row in document.rows)


def test_callgrind_relative_call_positions_are_separate_from_caller_positions() -> None:
    document = parse_profile(b"""positions: line
events: Ir
fl=caller.c
fn=caller
10 1
cfl=callee.c
cfn=callee
calls=1 7
+90 9
calls=1 +2
+1 3
calls=1 *
* 2
""", "callgrind")
    assert {(row.line, row.callsite_line, row.count) for row in document.rows
            if row.cost_kind == "call_inclusive"} == {(7, 100, 9), (9, 101, 5)}
    assert document.gaps == ()


@pytest.mark.parametrize("positions", ["instr", "instr line"])
def test_callgrind_unsupported_positions_are_a_named_gap_not_source_lines(tmp_path: Path, positions: str) -> None:
    report = f"positions: {positions}\nevents: Ir\nfl=src/a.c\nfn=f\n100 9\n".encode()
    result = _publish(tmp_path, [("callgrind.out", report, "accepted-input")])
    assert result.publication["item_count"] == 0
    assert any("unsupported Callgrind positions" in gap for gap in result.document["gaps"])
    assert result.publication["terminal_status"] == "COMPLETED_WITH_GAPS"


@pytest.mark.parametrize("event", ["cycles", "cycles:u", "sched:sched_switch"])
def test_perf_periods_do_not_split_or_weight_sample_event_identity(event: str) -> None:
    document = parse_profile(
        (f"w 1 1.0: 100 {event}:\n    7fff hot (app)\n\n"
         f"w 1 2.0: 200 {event}:\n    7fff hot (app)\n\n"
         f"w 1 3.0: {event}:\n    7fff hot (app)\n").encode(), "perf-script")
    assert [(row.symbol, row.event, row.module, row.count) for row in document.rows] == [("hot", event, "app", 3)]
    assert document.gaps == ()


@pytest.mark.parametrize("malformed", ["broken:-7:1", "broken:7:no", "unrecognized header line"],
                         ids=["negative-count", "invalid-head-count", "unrecognized"])
def test_partial_llvm_headers_publish_valid_rows_with_explicit_gaps(tmp_path: Path, malformed: str) -> None:
    result = _publish(tmp_path, [("samples.llvm-sample",
                                f"hot:9:1\n 1: 9\n{malformed}\n# comment\ncold:0:0\n".encode(),
                                "accepted-input")])
    assert result.publication["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("malformed_llvm_header" in gap for gap in result.document["gaps"])
    response = result.core.query_engineering_signals(signal_family="profile")
    assert {(row["payload"]["symbol"], row["payload"]["count"]) for row in response["results"]} == {("hot", 9), ("cold", 0)}
    assert any("malformed_llvm_header" in gap for gap in response["coverage_gaps"])


@pytest.mark.parametrize("character", ["é", "😀"])
def test_utf8_character_across_detector_prefix_is_not_malformed(tmp_path: Path, character: str) -> None:
    data = b"#" + b"x" * 32765 + b"\n" + b"y" * 32768 + character.encode() + b" 1\n"
    assert len(data[:65535].decode("utf-8")) == 65535
    result = _publish(tmp_path, [("valid.folded", data, "accepted-input")])
    assert result.publication["terminal_status"] == "SUCCEEDED"
    row = result.document["build_units"][0]["rows"][0]
    assert row["symbol"] == "y" * 32768 + character
    assert row["count"] == 1
    assert row["report_sha256"] == file_sha256(result.root / row["report_path"])


def test_invalid_utf8_after_detector_prefix_remains_a_named_gap(tmp_path: Path) -> None:
    data = b"# comment\n" * 6600 + b"bad\xff 1\n"
    result = _publish(tmp_path, [("bad.folded", data, "accepted-input")])
    assert result.publication["item_count"] == 0
    assert result.publication["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("not UTF-8" in gap for gap in result.document["gaps"])


def test_declared_route_retrieves_real_profile_publication(tmp_path: Path) -> None:
    result = _publish(tmp_path, [("hot.folded", b"hot 9\n", "accepted-input")])
    route = next(dataset.query_route for dataset in DATASETS if dataset.output_kind == "profile_data")
    method, parameter = route.split()
    key, value = parameter.split("=")
    response = getattr(result.core, method)(**{key: value})
    assert len(response["results"]) == 1
    assert response["results"][0]["payload"]["count"] == 9
    assert response["coverage_gaps"] == []


def test_profile_path_filter_paginates_matching_rows_without_source_assurance(tmp_path: Path) -> None:
    data = b"".join(_callgrind(f"src/{name}.c", name) for name in ("other", "a", "b", "a", "last"))
    result = _publish(tmp_path, [("callgrind.out", data, "accepted-input")])
    all_rows = result.core.query_engineering_signals(signal_family="profile")["results"]
    expected = [row for row in all_rows if row["payload"]["source"] == "src/a.c"]
    assert len(expected) == 1
    response = result.core.query_engineering_signals(signal_family="profile", path="src/a.c", limit=1)
    assert response["results"] == expected
    row = response["results"][0]
    assert "location" not in row
    assert row["artifact_reference"]["identity"] == row["identity"]
    assert row["payload"]["count"] == 18
    assert row["payload"]["semantics"] == "context_only"
    assert row["payload"]["is_finding"] is False
    assert row["payload"]["defect_probability"] is None
    assert result.core.query_engineering_signals(path="src/a.c", subject=row["identity"])["results"] == expected
    assert result.core.query_engineering_signals(signal_family="profile", path="src/missing.c")["results"] == []
    last = all_rows[-1]
    assert result.core.query_engineering_signals(
        signal_family="profile", path=last["payload"]["source"], limit=1)["results"] == [last]
    assert result.core.query_engineering_signals(
        signal_family="profile", subject=last["identity"], limit=1)["results"] == [last]


@pytest.mark.parametrize("has_rows", [False, True])
def test_profile_query_retains_coverage_when_no_rows_match_path(tmp_path: Path, has_rows: bool) -> None:
    reports = [("cpu.pprof", b"opaque", "accepted-input")]
    if has_rows:
        reports.append(("hot.folded", b"hot 9\ncold 1\n", "build-output"))
    result = _publish(tmp_path, reports, bounds=ProfileBounds(max_rows_per_artifact=1))
    response = result.core.query_engineering_signals(signal_family="profile", path="src/missing.c")
    assert response["results"] == []
    assert any("unsupported_profile_format" in gap for gap in response["coverage_gaps"])
    if has_rows:
        assert any("row_truncation" in gap for gap in response["coverage_gaps"])
    assert result.document["build_units"][0]["coverage_state"] == ("partial" if has_rows else "unavailable")


def test_review_profile_context_is_file_scoped_except_unlocated_rows(tmp_path: Path) -> None:
    result = _publish(tmp_path, [
        ("callgrind.out", _callgrind("src/a.c", "a") + _callgrind("src/b.c", "b"), "accepted-input"),
        ("unlocated.folded", b"build_wide 4\n", "build-output"),
        ("opaque.pprof", b"opaque", "accepted-input"),
    ])
    scope = accept_manifest(result.root, manifest_path=result.manifest,
                            manifest_sha256=result.publication["index_manifest"]["sha256"])
    by_path, by_build, _dependencies = _engineering_context(scope)
    rows = result.core.query_engineering_signals(signal_family="profile")["results"]
    by_symbol = {row["payload"]["symbol"]: row for row in rows}
    assert {entry.id for entry in by_path["src/a.c"]} == {by_symbol["a"]["identity"]}
    assert {entry.id for entry in by_path["src/b.c"]} == {by_symbol["b"]["identity"]}
    assert {entry.id for entry in by_build["u"]} == {by_symbol["build_wide"]["identity"]}
    assert all(entry.shard_sha256 == scope.shards[0]["sha256"]
               for entries in (*by_path.values(), *by_build.values()) for entry in entries)
    assert any("unsupported_profile_format" in gap.reason for gap in scope.gaps if gap.producer == "profile_data")


def test_local_shard_reuse_binds_normalized_rows_and_coverage(tmp_path: Path) -> None:
    reports = [("hot.folded", b"hot 9\ncold 1\n", "accepted-input")]
    first = _publish(tmp_path, reports, bounds=ProfileBounds(max_rows_per_artifact=1))
    old_shard = first.outputs["index.profile_data"]["indexes"][0]
    old_path = first.root / old_shard["relative_path"]
    second = _publish(tmp_path, reports, attempt="attempt_0002")
    new_shard = second.outputs["index.profile_data"]["indexes"][0]
    assert new_shard["fingerprint"] != old_shard["fingerprint"]
    assert file_sha256(old_path) == old_shard["sha256"]
    assert len(first.core.query_engineering_signals(signal_family="profile")["results"]) == 1
    assert len(second.core.query_engineering_signals(signal_family="profile")["results"]) == 2
    assert second.publication["terminal_status"] == "SUCCEEDED"


def test_artifact_byte_bound_equality_and_overflow_have_truthful_query_coverage(tmp_path: Path) -> None:
    data = b"hot 9\n"
    accepted = _publish(tmp_path, [("hot.folded", data, "accepted-input")],
                        bounds=ProfileBounds(max_artifact_bytes=len(data)))
    assert accepted.publication["item_count"] == 1
    bounded = _publish(tmp_path, [("hot.folded", data, "accepted-input")],
                       bounds=ProfileBounds(max_artifact_bytes=len(data) - 1), attempt="attempt_0002")
    response = bounded.core.query_engineering_signals(signal_family="profile")
    assert response["results"] == []
    assert any("artifact_byte_bound" in gap for gap in response["coverage_gaps"])


def test_profile_pagination_and_response_byte_bound_do_not_drop_rows(tmp_path: Path) -> None:
    data = b"".join(_callgrind("src/a.c", f"hot{i}") for i in range(5))
    result = _publish(tmp_path, [("callgrind.out", data, "accepted-input")])
    result.core.limits = RetrievalLimits(max_response_bytes=2800)
    expected = {row["symbol"] for row in result.document["build_units"][0]["rows"]}
    seen = []
    cursor = None
    byte_truncated = False
    for _ in range(6):
        response = result.core.query_engineering_signals(signal_family="profile", path="src/a.c", limit=3, cursor=cursor)
        assert len(canonical_json(response)) <= result.core.limits.max_response_bytes
        byte_truncated |= response["truncated"]
        seen.extend(row["payload"]["symbol"] for row in response["results"])
        cursor = response["pagination"]["next_cursor"]
        if cursor is None:
            break
    assert set(seen) == expected
    assert len(seen) == len(expected)
    assert byte_truncated
