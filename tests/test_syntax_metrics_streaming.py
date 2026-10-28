"""Bounded-memory, pre-filter, and admission-lease behavior of review prioritization syntax metrics."""
import json
from pathlib import Path
from types import SimpleNamespace
import tracemalloc
import tomllib

import pytest

from appsec_review.config.assurance import ReviewPolicy
from appsec_review.jobs.job_review_prioritization import job as priority
from appsec_review.jobs.job_review_prioritization.streaming import FilesDocumentWriter, ShardRowIndex
from appsec_review.jobs.job_review_prioritization.syntax import Node
from appsec_review.runtime.resources import ResourceBudget
from appsec_review.storage import canonical_json, file_sha256

RESERVATION = {"cpu": 1, "memory_mb": 64, "io_slots": 0, "admission_timeout_seconds": 5}
SETTINGS = {
    "max_functions": 1000, "max_files": 1000, "max_file_bytes": 4096,
    "cyclomatic_thresholds": [10, 20, 50], "count_error_propagation": True,
    "max_signals_per_file": 100, "max_import_records": 100,
    "custom_parsing_min_operations": 1, "custom_parsing_min_density": 0.1,
    "state_mutation_min_operations": 1, "syntax_metrics_reservation": RESERVATION,
}
PAYLOAD = b"const value = 1;\n"


class Events:
    def __init__(self) -> None:
        self.rows: list[tuple[str, dict]] = []

    def write(self, name: str, **fields) -> None:
        self.rows.append((name, fields))

    def named(self, name: str) -> list[dict]:
        return [fields for event, fields in self.rows if event == name]


def _row(path: str, digest: str, padding: int = 0, ordinal: int = 0) -> dict:
    return {"path": path, "file_sha256": digest, "ordinal": ordinal, "padding": "x" * padding,
            "location": {"producer_location": {"grammar": "javascript"}}}


def _write_shard(path: Path, rows: list[dict]) -> dict:
    lines = sorted(json.dumps(row, sort_keys=True).encode() + b"\n" for row in rows)
    path.write_bytes(b"".join(lines))
    return {"path": path.name, "sha256": file_sha256(path)}


def _fixture(tmp_path: Path, monkeypatch, files: dict, rows: list[dict], *, settings=None, budget=None):
    events = Events()
    shard = _write_shard(tmp_path / "shard.jsonl", rows)
    documents = {"files": files, "tree": {"dispositions": [{"artifact": shard}]}}
    loaded = {"files_artifact": "files", "inputs": {"tree_sitter_artifact": "tree"}}
    monkeypatch.setattr(priority, "read_json", lambda root, identity: documents[identity])
    root = Node("program", None, True, False, 0, len(PAYLOAD), 1, 1, 1, len(PAYLOAD))
    monkeypatch.setattr(priority, "build_tree", lambda rows: (root, 0))
    monkeypatch.setattr(priority, "_settings", lambda _: settings or SETTINGS)
    policy = ReviewPolicy(resources=budget) if budget else ReviewPolicy()
    unit = SimpleNamespace(job=SimpleNamespace(run_root=tmp_path, target_root=tmp_path,
                                               metadata_root=tmp_path / "metadata", review_policy=policy,
                                               events=events),
                           unit_id="extract.syntax_metrics", unit_root=tmp_path / "unit", output=lambda _: loaded)
    handler = next(item for item in priority.build_job().units
                   if item.unit_id == "extract.syntax_metrics").handler
    return handler, unit, events


def _source(tmp_path: Path, path: str, **extra) -> dict:
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(PAYLOAD)
    return {"sha256": file_sha256(target), "size_bytes": len(PAYLOAD), "language": "JavaScript",
            "scope_role": "target_source", "component_id": "fixture", **extra}


def _facts(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "unit" / "artifacts" / "syntax-facts.json").read_text(encoding="utf-8"))


def test_streamed_document_is_byte_identical_to_canonical_json(tmp_path):
    files = {"b/é.c": {"n": 2, "list": [1, "ü"]}, "a.c": {"n": 1}, "a/b.c": {"nested": {"z": 1, "a": None}}}
    fields = {"schema": "s/1", "by_language": {"C": {"file_count": 3}}, "identities": {"x": "y"}}
    writer = FilesDocumentWriter(tmp_path / "out.json")
    for key in sorted(files):
        writer.add(key, files[key])
    writer.finish(fields)
    assert (tmp_path / "out.json").read_bytes() ==     canonical_json({**fields, "files": files})
    assert sorted(item.name for item in tmp_path.iterdir()) == ["out.json"]
    with pytest.raises(ValueError, match="ascending"):
        unordered = FilesDocumentWriter(tmp_path / "bad.json")
        unordered.add("b", {})
        try:
            unordered.add("a", {})
        finally:
            unordered.abort()


def test_index_holds_only_wanted_rows_and_rejects_a_changed_shard(tmp_path):
    rows = [_row("keep.js", "1", ordinal=index) for index in range(3)] + [_row("other.js", "2", 64)]
    shard = _write_shard(tmp_path / "shard.jsonl", rows)
    with ShardRowIndex(tmp_path, [shard], {"keep.js", "absent.js"}, tmp_path / "scratch") as index:
        assert index.has_rows("keep.js") and not index.has_rows("other.js") and not index.has_rows("absent.js")
        assert sorted(row["ordinal"] for row in index.rows("keep.js")) == [0, 1, 2]
        assert index.rows("other.js") == []
    assert not (tmp_path / "scratch" / "shard-rows.sqlite").exists()
    with pytest.raises(ValueError, match="identity changed"):
        ShardRowIndex(tmp_path, [{**shard, "sha256": "0" * 64}], {"keep.js"}, tmp_path / "scratch")
    with pytest.raises(ValueError, match="outside the run"):
        ShardRowIndex(tmp_path, [{"path": "../escape.jsonl", "sha256": shard["sha256"]}], {"keep.js"},
                      tmp_path / "scratch")


def test_non_source_out_of_scope_and_oversized_files_are_named_skips_never_loaded(tmp_path, monkeypatch):
    scored = _source(tmp_path, "src/app.js")
    files = {
        "src/app.js": scored,
        "assets/logo.png": {**scored, "language": None},
        "sdk/platform.js": {**scored, "scope_role": "supplied_platform"},
        "src/huge.js": {**scored, "size_bytes": SETTINGS["max_file_bytes"] + 1},
    }
    rows = [_row(path, value["sha256"]) for path, value in files.items()]
    handler, unit, events = _fixture(tmp_path, monkeypatch, files, rows)
    wanted: list[set[str]] = []
    loaded_bytes: list[str] = []
    real_index, real_bytes = priority.ShardRowIndex, priority._target_bytes

    def index(run_root, shards, paths, scratch):
        wanted.append(set(paths))
        return real_index(run_root, shards, paths, scratch)

    def target_bytes(unit, path, *args, **kwargs):
        loaded_bytes.append(path)
        return real_bytes(unit, path, *args, **kwargs)

    monkeypatch.setattr(priority, "ShardRowIndex", index)
    monkeypatch.setattr(priority, "_target_bytes", target_bytes)
    result = handler(unit)
    assert wanted == [{"src/app.js"}] and loaded_bytes == ["src/app.js"]
    assert result["file_count"] == 1 and list(_facts(tmp_path)["files"]) == ["src/app.js"]
    assert result["skipped"] == {"file_byte_bound": 1, "not_source": 1, "out_of_delivery_scope": 1}
    assert "src/huge.js: file_byte_bound_reached" in result["gaps"]
    assert result["terminal_status"] == "PARTIAL"
    assert events.named("REVIEW_PRIORITIZATION_SYNTAX_EXTRACTED")[0]["skipped"] == result["skipped"]


def test_step_holds_a_configured_admission_lease_for_its_whole_extent(tmp_path, monkeypatch):
    files = {"src/app.js": _source(tmp_path, "src/app.js")}
    handler, unit, events = _fixture(tmp_path, monkeypatch, files, [_row("src/app.js", files["src/app.js"]["sha256"])])
    ledger = tmp_path / "metadata" / "resource-admission" / "leases.json"
    seen: list[dict] = []
    real_extract = priority.ShardRowIndex

    def index(*args):
        seen.append(json.loads(ledger.read_text(encoding="utf-8"))["leases"])
        return real_extract(*args)

    monkeypatch.setattr(priority, "ShardRowIndex", index)
    handler(unit)
    (lease,) = seen[0].values()
    assert lease["action"] == "review_prioritization.syntax_metrics"
    assert lease["reservation"] == {"cpu": 1, "memory_mb": 64, "io_slots": 0}
    admitted, released = events.named("RESOURCE_ADMITTED"), events.named("RESOURCE_RELEASED")
    assert len(admitted) == len(released) == 1
    assert admitted[0]["span_id"] == released[0]["span_id"]
    assert admitted[0]["operation_id"] == "review_prioritization.syntax_metrics"
    started = events.named("OPERATION_STARTED")
    assert started and started[0]["resource_lease_id"] == admitted[0]["span_id"]
    assert json.loads(ledger.read_text(encoding="utf-8"))["leases"] == {}


def test_a_failed_step_releases_its_lease_and_leaves_no_partial_artifact(tmp_path, monkeypatch):
    files = {"src/app.js": _source(tmp_path, "src/app.js")}
    rows = [_row("src/app.js", "0" * 64)]
    handler, unit, events = _fixture(tmp_path, monkeypatch, files, rows)
    with pytest.raises(ValueError, match="catalog hash"):
        handler(unit)
    ledger = tmp_path / "metadata" / "resource-admission" / "leases.json"
    assert json.loads(ledger.read_text(encoding="utf-8"))["leases"] == {}
    assert len(events.named("RESOURCE_RELEASED")) == 1
    assert not any((tmp_path / "unit" / "artifacts").iterdir())


def test_a_reservation_beyond_the_budget_is_refused_before_any_work(tmp_path, monkeypatch):
    settings = {**SETTINGS, "syntax_metrics_reservation": {**RESERVATION, "memory_mb": 4096}}
    files = {"src/app.js": _source(tmp_path, "src/app.js")}
    handler, unit, events = _fixture(tmp_path, monkeypatch, files, [], settings=settings,
                                     budget=ResourceBudget(cpu=2, memory_mb=1024, io_slots=1))
    with pytest.raises(ValueError, match="exceeds the configured aggregate resource budget"):
        handler(unit)
    assert not events.named("RESOURCE_ADMITTED") and not (tmp_path / "unit").exists()


def test_reservation_settings_are_validated():
    with (Path(__file__).resolve().parents[1] / "appsec-review.toml").open("rb") as stream:
        settings = tomllib.load(stream)["jobs"][priority.JOB_ID]["settings"]
    context = SimpleNamespace(config=SimpleNamespace(settings=settings))
    assert priority._settings(context)["syntax_metrics_reservation"]["io_slots"] == 0
    for broken in ({**RESERVATION, "memory_mb": 0}, {**RESERVATION, "cpu": True},
                   {key: value for key, value in RESERVATION.items() if key != "io_slots"},
                   {**RESERVATION, "extra": 1}):
        bad = SimpleNamespace(config=SimpleNamespace(settings={**settings, "syntax_metrics_reservation": broken}))
        with pytest.raises(ValueError, match="syntax_metrics_reservation"):
            priority._settings(bad)


def _peak(tmp_path: Path, monkeypatch, count: int, rows_per_file: int, padding: int) -> tuple[int, int]:
    root = tmp_path / str(count)
    root.mkdir()
    files, rows = {}, []
    for number in range(count):
        path = f"src/f{number:04}.js"
        files[path] = _source(root, path)
        rows.extend(_row(path, files[path]["sha256"], padding, ordinal) for ordinal in range(rows_per_file))
    handler, unit, _events = _fixture(root, monkeypatch, files, rows)
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        baseline = tracemalloc.get_traced_memory()[0]
        result = handler(unit)
        peak = tracemalloc.get_traced_memory()[1] - baseline
    finally:
        tracemalloc.stop()
    assert result["file_count"] == count
    return peak, (root / "shard.jsonl").stat().st_size


def test_peak_memory_follows_the_largest_file_not_the_tree(tmp_path, monkeypatch):
    small, _ = _peak(tmp_path, monkeypatch, 4, 40, 2048)
    large, shard_bytes = _peak(tmp_path, monkeypatch, 160, 40, 2048)
    # 160 files x 40 rows x 2 KiB is ~13 MiB of rows; holding them all would add far more than this.
    assert shard_bytes > 12 * 1024 * 1024
    assert large - small < 2 * 1024 * 1024, (small, large)
