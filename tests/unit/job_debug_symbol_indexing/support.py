"""Canned fixtures for the job_debug_symbol_indexing unit tier.

Everything here is code-level: a real ``JobContext``/``UnitContext`` over a run root the test
owns, accepted inputs handed to the handlers as the dictionaries ``_accepted_inputs`` returns
(the upstream readers are faked at the module boundary), binaries as bytes under
``data/shared/objects``, a catalog manifest written with the real retrieval writer, and the
symbol reader faked by an injected extractor. No runner, no graph run, no engine.
"""
from __future__ import annotations

from collections.abc import Callable
import json
from pathlib import Path
import sqlite3
from typing import Any

from appsec_review.config import JobConfig, StepConfig, TaskConfig
from appsec_review.config.debug_symbols import parse_debug_symbol_settings
from appsec_review.debug_symbols.contract import AddressRange, Extraction, RecordKind, SymbolRecord
from appsec_review.jobs.job_artifact_indexing.job import canonical_target_artifact_identity
from appsec_review.jobs.job_debug_symbol_indexing import job as job_module
from appsec_review.jobs.job_debug_symbol_indexing.job import _TOPOLOGY, build_job
from appsec_review.observability import EventLog
from appsec_review.retrieval import (
    INDEX_SCHEMA, EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, write_manifest,
)
from appsec_review.retrieval.model import SourceLocation
from appsec_review.runtime import Job, JobContext, UnitContext
from appsec_review.storage import file_sha256
from appsec_review.storage.shared import put_bytes

JOB_ID = "job_debug_symbol_indexing"
SNAPSHOT = "a" * 64
RUN_ID = "2026-11-13-0001"
ATTEMPT = "attempt_0001"
HANDOFF_SHA = "1" * 64
ELF = b"\x7fELFfixture"
MZ = b"MZfixture"
MSF = b"Microsoft C/C++ MSF 7.00\r\nfixture"


def ref(root: Path, path: Path) -> dict[str, Any]:
    """The run-relative hash-bound reference the job reads and writes."""
    return {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def job_context(tmp_path: Path, *, target: str = "clang", settings: dict[str, Any] | None = None,
                snapshot: str = SNAPSHOT, run_id: str = RUN_ID, attempt_id: str = ATTEMPT,
                repository_root: Path | None = None) -> JobContext:
    """A real job context over ``tmp_path/<run_id>`` with the job's topology and parsed settings."""
    run_root = tmp_path / run_id
    run_root.mkdir(parents=True, exist_ok=True)
    parsed = parse_debug_symbol_settings({"compiler_target": target, **(settings or {})})
    config = JobConfig(JOB_ID, "debug_symbol_indexing", 1, None, parsed, {
        step: StepConfig(step, 1, {}, {task: TaskConfig(task, 1, {}) for task in tasks})
        for step, tasks in _TOPOLOGY.items()})
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / attempt_id
    attempt_root.mkdir(parents=True, exist_ok=True)
    return JobContext(run_id, attempt_id, "test", repository_root or tmp_path, run_root, attempt_root,
                      run_root / "metadata", {}, config, EventLog(attempt_root / "events.jsonl"),
                      source_fingerprint=snapshot)


def unit(context: JobContext, unit_id: str, outputs: dict[str, Any] | None = None) -> UnitContext:
    """The unit context ``UnitExecutor`` would build for ``unit_id`` (same unit root layout)."""
    step, task = unit_id.split(".")
    return UnitContext(context, unit_id, step, task,
                       context.attempt_root / "steps" / step / "tasks" / task, dict(outputs or {}))


def handlers(job: Job) -> dict[str, Callable[[UnitContext], Any]]:
    return {item.unit_id: item.handler for item in job.units}


def artifact(run_root: Path, name: str, content: bytes, kind: str = "executable", *,
             snapshot: str = SNAPSHOT, build_image: dict[str, str] | None = None) -> dict[str, Any]:
    """One entry of ``_accepted_inputs()["artifacts"]`` whose reference resolves to real bytes."""
    stored = put_bytes(run_root, content)
    reference = {**stored, "workspace_path": name, "kind": kind, "artifact_origin": "target-intake"}
    identity = canonical_target_artifact_identity(snapshot, reference).value
    return {"artifact_identity": identity, "kind": kind,
            "reference": {**reference, "canonical_identity": identity}, "build_image": build_image}


def source_shard(run_root: Path, content: bytes, *, path: str = "src/main.cc", snapshot: str = SNAPSHOT,
                 store_object: bool = True, text: str | None = None) -> IndexIdentity:
    """An accepted ``source`` shard with one source file (its bytes stored under the run root)."""
    digest = put_bytes(run_root, content)["sha256"]
    if not store_object:
        (run_root / "data" / "shared" / "objects" / digest).unlink()
    shard_path = run_root / "data" / "indices" / "source" / f"{digest}.sqlite"
    shard_id = f"catalog-source-{digest[:12]}"
    builder = IndexBuilder(shard_path, name="source", fingerprint="b" * 64, target_snapshot=snapshot,
                           shard_id=shard_id)
    identity = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, {"path": path, "sha256": digest})
    location = SourceLocation(snapshot, path, digest, 0, len(content), 1, max(1, content.count(b"\n") + 1),
                              1, 1, {}, "inventory-exact", 1.0)
    builder.add_entity(EntityRecord(identity, path, Path(path).name,
                                    content.decode() if text is None else text,
                                    {"path": path, "sha256": digest}, location))
    builder.add_coverage("fixture", "complete")
    return IndexIdentity("source", INDEX_SCHEMA, builder.build(), "b" * 64,
                         shard_path.relative_to(run_root).as_posix(), {}, (), shard_id)


def catalog_shard(run_root: Path, artifacts: list[dict[str, Any]], *, snapshot: str = SNAPSHOT,
                  shard_id: str = "catalog-fixture", name: str = "artifacts") -> IndexIdentity:
    """An accepted ``artifacts`` catalog shard whose entity payloads are the artifact references."""
    shard_path = run_root / "data" / "indices" / name / f"{shard_id}.sqlite"
    builder = IndexBuilder(shard_path, name=name, fingerprint="c" * 64, target_snapshot=snapshot,
                           shard_id=shard_id)
    for item in artifacts:
        reference = item["reference"]
        builder.add_entity(EntityRecord(LogicalIdentity.parse(item["artifact_identity"]), reference["sha256"],
                                        reference["workspace_path"], "", reference))
    builder.add_coverage("fixture", "complete")
    return IndexIdentity(name, INDEX_SCHEMA, builder.build(), "c" * 64,
                         shard_path.relative_to(run_root).as_posix(), {}, (), shard_id)


def manifest(run_root: Path, indexes: list[IndexIdentity] = (), *, snapshot: str = SNAPSHOT,
             run_id: str = RUN_ID, name: str = "artifacts.json") -> dict[str, Any]:
    """The accepted upstream index manifest, written by the real writer; returns its reference."""
    path = run_root / "data" / "indices" / "manifests" / name
    write_manifest(path, run_id=run_id, target_snapshot=snapshot, target_root=run_root.parent, indexes=indexes)
    return ref(run_root, path)


def accepted_inputs(artifacts: list[dict[str, Any]], upstream_manifest: dict[str, Any], *,
                    gaps: list[str] | None = None, language_sha: str | None = None) -> dict[str, Any]:
    """What ``_accepted_inputs`` hands ``_decision``."""
    return {"artifacts": list(artifacts), "gaps": sorted(set(gaps or ())),
            "upstream_manifest": dict(upstream_manifest), "artifact_handoff_sha256": HANDOFF_SHA,
            "language_build_handoff_sha256": language_sha}


def decide(monkeypatch, job: Job, context: JobContext, inputs: dict[str, Any]) -> dict[str, Any]:
    """Run the real ``decide.target`` handler with the upstream loader faked at the module boundary."""
    monkeypatch.setattr(job_module, "_accepted_inputs", lambda _unit, _settings: inputs)
    return handlers(job)["decide.target"](unit(context, "decide.target"))


def extracted(records: tuple[SymbolRecord, ...] | None = None, gaps: tuple[str, ...] = (),
              producer: str = "fixture-reader/1") -> Extraction:
    return Extraction(RECORDS if records is None else records, gaps, producer)


RECORDS = (
    SymbolRecord("cu:1", RecordKind.COMPILATION_UNIT, "private-unit"),
    SymbolRecord("fn:1", RecordKind.SYMBOL, "private-function", (AddressRange(4096, 4128),), None, "cu:1",
                 {"signature": "int private-function()", "source_identity": "forged"}),
    SymbolRecord("type:1", RecordKind.TYPE_LAYOUT, "private-type",
                 data={"size_bytes": 8, "members": [{"offset": 0}]}),
)


def extractor(calls: list | None = None, *, result: Extraction | None = None,
              gaps: tuple[str, ...] = ()) -> Callable[..., Extraction]:
    """A fake ``extract_symbols`` recording its calls and returning three canned records."""
    def extract(binary, debug_file, *, target, settings):
        if calls is not None:
            calls.append((binary, debug_file, target, settings))
        return extracted(gaps=gaps) if result is None else result
    return extract


def events(context: JobContext) -> list[dict[str, Any]]:
    path = context.events.path
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.is_file() else []


def shard(context: JobContext, output: dict[str, Any]) -> sqlite3.Connection:
    """Open the symbol shard an ``extract.*`` output points at."""
    (index,) = output["indexes"]
    return sqlite3.connect(context.run_root / index["relative_path"])


def payloads(context: JobContext, output: dict[str, Any]) -> list[dict[str, Any]]:
    with shard(context, output) as database:
        rows = database.execute("SELECT payload_json FROM entities ORDER BY identity").fetchall()
    return [json.loads(row[0]) for row in rows]


def extract_output(records: list[dict[str, Any]] | None = None, *, lane: str = "clang_dwarf",
                   fingerprint: str = "d" * 64, gaps: list[str] | None = None,
                   skipped: bool = False) -> dict[str, Any]:
    """A canned ``extract.<lane>`` output, as ``_publish`` consumes it."""
    if skipped:
        return {"status": "SKIPPED", "terminal_status": "SKIPPED_NA", "reason": "unselected_compiler_target",
                "input_fingerprint": "e" * 64, "indexes": [], "gaps": []}
    return {"status": "COMPLETED", "indexes": list(records or []), "artifact": None, "coverage": None,
            "input_fingerprint": fingerprint, "record_count": 0, "artifact_count": 0,
            "gaps": list(gaps or []), "duration_ms": 5,
            "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}


__all__ = ["build_job", "job_module"]
