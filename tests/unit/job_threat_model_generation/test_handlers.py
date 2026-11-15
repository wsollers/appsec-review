"""Code-level unit handler and fail-closed validation tests for job_threat_model_generation."""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import shutil
from types import MappingProxyType
from typing import Any, Mapping, Sequence

import pytest

from appsec_review.config import JobConfig, load_config
from appsec_review.interchange import GAP_SCHEMA, GapCode
from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.jobs.job_threat_model_generation import JOB_ID, build_job
from appsec_review.jobs.job_threat_model_generation.datasets import ARTIFACT_DIRECTORY, CONTRACT, PRODUCER_DATASETS
from appsec_review.jobs.job_threat_model_generation import job as tm_job
from appsec_review.jobs.job_threat_model_generation.job import (
    ASSEMBLY, DEPLOYMENT_GAP, INTERACTIONS, LOAD, PUBLISH, RENDER, RESOLVE, STRUCTURE, THREATS,
    ThreatModelGenerationFailed,
)
from appsec_review.observability import EventLog
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation, write_manifest,
)
from appsec_review.runtime import JobContext
from appsec_review.runtime.consume import UpstreamIntegrityError
from appsec_review.runtime.datasets import dataset_contract, shard_owner
from appsec_review.runtime.repair import WORKER_PROTOCOL
from appsec_review.runtime.units import UnitContext
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.threat_model.contract import (
    AUTHORITY, DFD_SCHEMA, EVIDENCE_SCHEMA, RESULT_SCHEMA, THREAT_MODEL_SCHEMA, Limits, canonical,
)
from appsec_review.threat_model.documents import Documents
from appsec_review.threat_model.index_view import DECLARED_INPUTS, IndexEvidenceView
from appsec_review.threat_model.reference import load_reference
from appsec_review.threat_model.render import render_markdown, render_mermaid
from appsec_review.threat_model.validate import validate_documents
from tests.handoff_fixture import write_fixture_handoff

ROOT = Path(__file__).resolve().parents[3]
RUN_ID = "2026-11-15-0036"
ATTEMPT_ID = "attempt_0001"
SNAPSHOT = "target-sha256:" + "7" * 64
CATALOG = "job_target_catalog"
SYNTAX = "job_tree_sitter_ast"
BUILD_UNIT = "native-cmake-0001"
SETTINGS = "[jobs.job_threat_model_generation.settings]\nenabled = false\n"

SERVER_C = b"int main(void) { int s = listen(0, 1); int c = accept(s, 0, 0); recv(c, 0, 0, 0); fopen(\"cfg\", \"r\"); }\n"
CLIENT_C = b"int main(void) { connect(0, 0, 0); recv(0, 0, 0, 0); }\n"
POINTS = [
    {"name": "echo-server", "kind": "executable", "evidence": "CMakeLists.txt:4", "sources": ["server.c"],
     "include_dirs": []},
    {"name": "echo-client", "kind": "executable", "evidence": "CMakeLists.txt:5", "sources": ["client.c"],
     "include_dirs": []},
]


@pytest.fixture(autouse=True)
def _no_disk_flush(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "fsync", lambda descriptor: None)


def _job_config(*, max_render_nodes: int | None = None) -> JobConfig:
    base = load_config(ROOT / "appsec-review.toml").jobs[JOB_ID]
    settings = dict(base.settings)
    settings["enabled"] = True
    if max_render_nodes is not None:
        settings["max_render_nodes"] = max_render_nodes
    return replace(base, settings=settings)


def _entity(kind: EntityKind, key: str, payload: Mapping[str, Any] | None = None, *, name: str | None = None,
            text: str = "", location: SourceLocation | None = None) -> EntityRecord:
    return EntityRecord(LogicalIdentity.derive(kind, SNAPSHOT, {"unit": key}), key, name or key, text,
                        payload or {}, location)


def _build_unit(points: Sequence[Mapping[str, Any]] = POINTS) -> EntityRecord:
    return _entity(EntityKind.BUILD_ACTION, BUILD_UNIT, {
        "build_unit_id": BUILD_UNIT, "root": ".", "family": "native", "build_system": "cmake",
        "build_points": list(points),
    }, name="cmake")


def _syntax_calls() -> list[EntityRecord]:
    sources = (("server.c", SERVER_C, ("listen", "accept", "recv", "fopen")),
               ("client.c", CLIENT_C, ("connect", "recv")))
    nodes: list[EntityRecord] = []
    for filename, data, callees in sources:
        digest = hashlib.sha256(data).hexdigest()
        for index, callee in enumerate(callees, start=1):
            start = data.index(callee.encode("ascii"))
            location = SourceLocation(SNAPSHOT, filename, digest, start, start + len(callee), 1, 1, start + 1,
                                      start + len(callee) + 1, {}, "unit", 1.0)
            nodes.append(_entity(EntityKind.AST_NODE, f"{filename}:{index}:{callee}", {
                "schema": "appsec-review/tree-sitter-normalizer/1",
                "grammar_native_type": "call_expression",
                "language": "c",
                "syntax_only": True,
                "build_unit_id": BUILD_UNIT,
                "syntax": {
                    "category": "call_expression",
                    "written_name": callee,
                    "enclosing_definition": None,
                    "syntactic_qualifiers": [],
                    "resolution": "unresolved",
                },
            }, name="call_expression", text=f"call_expression {callee}", location=location))
    return nodes


class SyntheticAttempt:
    """Minimal synthetic run directory + JobContext with zero JobRunner involvement."""

    def __init__(self, tmp_path: Path, *, repo_root: Path = ROOT, snapshot: str | None = SNAPSHOT,
                 max_render_nodes: int | None = None) -> None:
        self.repo_root = repo_root
        self.run_root = tmp_path / "runs" / RUN_ID
        self.attempt_root = self.run_root / "data" / "jobs" / JOB_ID / "attempts" / ATTEMPT_ID
        self.attempt_root.mkdir(parents=True, exist_ok=True)
        self.pins: dict[str, str] = {}
        self._shard_seq = 0
        self._snapshot = snapshot
        self._job_config = _job_config(max_render_nodes=max_render_nodes)

    def shard(self, producer: str, index: str, shard_id: str, entities: Sequence[EntityRecord] = ()) -> IndexIdentity:
        self._shard_seq += 1
        fingerprint = hashlib.sha256(f"{producer}/{index}/{shard_id}/{self._shard_seq}".encode()).hexdigest()
        path = self.run_root / "data" / "indices" / index / f"{producer}-{shard_id}-{fingerprint[:8]}.sqlite"
        builder = IndexBuilder(path, name=index, fingerprint=fingerprint, target_snapshot=SNAPSHOT, shard_id=shard_id)
        for item in entities:
            builder.add_entity(item)
        builder.add_coverage("unit", "complete")
        unit = f"{shard_owner(PRODUCER_DATASETS[producer], index, shard_id).step}.shard{self._shard_seq}"
        return IndexIdentity(index, "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                             path.relative_to(self.run_root).as_posix(), {"job": producer, "unit": unit}, (), shard_id)

    def accept(self, producer: str, shards: Sequence[IndexIdentity], attempt_id: str = "attempt_0001") -> str:
        datasets = PRODUCER_DATASETS[producer]
        manifest = self.run_root / "data" / "indices" / "manifests" / f"{producer}-{attempt_id}.json"
        write_manifest(manifest, run_id=RUN_ID, target_snapshot=SNAPSHOT,
                       target_root=self.run_root.parent / "target", indexes=shards)
        attempt = self.run_root / "data" / "jobs" / producer / "attempts" / attempt_id
        atomic_json(attempt / "claim.json", {
            "worker_protocol": WORKER_PROTOCOL,
            "dataset_contract": dataset_contract(producer, sorted({item.step for item in datasets}), datasets),
        })
        outputs = {item.producer["unit"]: {
            "index_identity": asdict(item),
            "index_manifest": artifact_ref(self.run_root, manifest),
        } for item in shards}
        handoff = attempt / "handoff.json"
        write_fixture_handoff(self.run_root, handoff, {
            "job_id": producer,
            "source_fingerprint": SNAPSHOT,
            "outputs": outputs,
            "artifacts": [artifact_ref(self.run_root, self.run_root / item.relative_path) for item in shards],
        })
        digest = file_sha256(handoff)
        atomic_json(self.run_root / "data" / "jobs" / producer / "latest.json", {
            "handoff_path": handoff.relative_to(self.run_root).as_posix(),
            "handoff_sha256": digest,
        })
        self.pins[producer] = digest
        return digest

    def accept_catalog(self, points: Sequence[Mapping[str, Any]] = POINTS) -> str:
        return self.accept(CATALOG, [
            self.shard(CATALOG, index, "default", [_build_unit(points)] if index == "build" else ())
            for index in ("analysis", "build", "components", "documents", "source")
        ])

    def accept_syntax(self, nodes: Sequence[EntityRecord] | None = None) -> IndexIdentity:
        shard = self.shard(SYNTAX, "analysis", "ts-c", _syntax_calls() if nodes is None else nodes)
        self.accept(SYNTAX, [shard])
        return shard

    def job_context(self) -> JobContext:
        return JobContext(
            run_id=RUN_ID,
            attempt_id=ATTEMPT_ID,
            trigger="unit",
            repository_root=self.repo_root,
            run_root=self.run_root,
            attempt_root=self.attempt_root,
            metadata_root=self.run_root / "metadata",
            orchestration={"driver": "unit"},
            config=self._job_config,
            events=EventLog(self.attempt_root / "logs" / "events.jsonl"),
            evidence_target_snapshot=self._snapshot,
            upstream_handoffs=MappingProxyType(dict(self.pins)),
            contract=CONTRACT,
        )

    def unit_context(self, unit_id: str, outputs: Mapping[str, Mapping[str, Any]] | None = None) -> UnitContext:
        step_id, task_id = unit_id.split(".")
        unit_root = self.attempt_root / "steps" / step_id / "tasks" / task_id
        unit_root.mkdir(parents=True, exist_ok=True)
        return UnitContext(
            job=self.job_context(),
            unit_id=unit_id,
            step_id=step_id,
            task_id=task_id,
            unit_root=unit_root,
            outputs=MappingProxyType(dict(outputs or {})),
        )


def _handlers():
    job = build_job()
    return job, {unit.unit_id: unit.handler for unit in job.units}


def test_execute_all_units_publishes_validated_documents_and_resolving_views(tmp_path: Path) -> None:
    attempt = SyntheticAttempt(tmp_path)
    attempt.accept_catalog()
    attempt.accept_syntax()
    before_indices = {
        p.relative_to(attempt.run_root).as_posix(): file_sha256(p)
        for p in sorted((attempt.run_root / "data" / "indices").rglob("*")) if p.is_file()
    }

    job = build_job()
    execution = job.handler(attempt.job_context())
    outputs = execution["outputs"]
    assert set(outputs) == {LOAD, STRUCTURE, INTERACTIONS, ASSEMBLY, THREATS, RESOLVE, RENDER, PUBLISH}
    assert outputs[PUBLISH]["terminal_status"] == "SUCCEEDED" and outputs[PUBLISH]["gaps"] == []
    assert outputs[RENDER]["terminal_status"] == "SUCCEEDED" and outputs[RENDER]["gaps"] == []
    assert outputs[LOAD]["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert [gap["reason"] for gap in outputs[LOAD]["gaps"] if gap["scope_id"] == "job_deployment_inventory"] == [
        DEPLOYMENT_GAP
    ]

    all_unit_gaps = [gap for uid, out in outputs.items() for gap in out["gaps"]]
    assert all(gap["schema"] == GAP_SCHEMA for gap in all_unit_gaps)
    assert len({gap["gap_id"] for gap in all_unit_gaps}) == len(all_unit_gaps) == outputs[PUBLISH]["joined_gap_count"]

    base = attempt.attempt_root / ARTIFACT_DIRECTORY
    dfd = json.loads((base / "dfd.json").read_bytes())
    model = json.loads((base / "threat-model.json").read_bytes())
    evidence = json.loads((base / "evidence.json").read_bytes())
    result = json.loads((base / "result.json").read_bytes())
    assert [doc["schema"] for doc in (dfd, model, evidence, result)] == [
        DFD_SCHEMA, THREAT_MODEL_SCHEMA, EVIDENCE_SCHEMA, RESULT_SCHEMA,
    ]
    validate_documents(dfd, model, evidence, result)
    assert (dfd["origin"]["producer"], dfd["origin"]["authority"], dfd["origin"]["target_supplied"]) == (
        JOB_ID, AUTHORITY, False,
    )
    assert dfd["origin"]["reference_data"] == dict(load_reference(ROOT).sha256s)

    ledger = {(row["producer"], row["output_kind"]): row["state"] for row in result["input_ledger"]}
    assert set(ledger) == set(DECLARED_INPUTS) | {("job_deployment_inventory", "deployment_inventory")}
    assert ledger[(CATALOG, "build_units")] == "read"
    assert ledger[(SYNTAX, "tree_sitter_ast")] == "read"
    from appsec_review.runtime import job_is_enabled
    cfg = load_config(ROOT / "appsec-review.toml")
    expected_cpp = "absent" if job_is_enabled(cfg, "job_cpp_compiled_analysis") else "disabled"
    assert ledger[("job_cpp_compiled_analysis", "cpp_build_graph")] == expected_cpp
    assert ledger[("job_language_build", "build_actions")] == "absent"
    assert ledger[("job_deployment_inventory", "deployment_inventory")] == "not_registered"

    view = IndexEvidenceView(attempt.run_root, attempt.pins)
    from appsec_review.threat_model.codec import evidence_ref_from_plain
    refs = [evidence_ref_from_plain(item) for item in evidence["references"]]
    assert refs and all(view.resolves(item) for item in refs)

    mmd_text = (base / "views" / "dfd.mmd").read_text(encoding="utf-8")
    md_text = (base / "views" / "threat-model.md").read_text(encoding="utf-8")
    assert mmd_text == render_mermaid(dfd, Limits())[0]["dfd.mmd"]
    assert md_text == render_markdown(dfd, model, result)

    after_indices = {
        p.relative_to(attempt.run_root).as_posix(): file_sha256(p)
        for p in sorted((attempt.run_root / "data" / "indices").rglob("*")) if p.is_file()
    }
    assert after_indices == before_indices


def test_render_truncation_and_redacted_build_points_report_structured_gaps(tmp_path: Path) -> None:
    attempt = SyntheticAttempt(tmp_path, max_render_nodes=2)
    redacted_points = [
        {**POINTS[0], "name": "<redacted>", "sources": ["server.c", "<redacted>"]},
        {**POINTS[1], "name": "<redacted>"},
    ]
    attempt.accept_catalog(redacted_points)
    attempt.accept_syntax()

    job = build_job()
    outputs = job.handler(attempt.job_context())["outputs"]
    assert outputs[RENDER]["terminal_status"] == "COMPLETED_WITH_GAPS"
    [render_gap] = outputs[RENDER]["gaps"]
    assert (render_gap["code"], render_gap["scope_id"], render_gap["unit_id"]) == (
        GapCode.TRUNCATED.value, "publication.max_render_nodes", RENDER,
    )
    [redacted_gap] = [gap for gap in outputs[STRUCTURE]["gaps"] if gap["scope_id"] == "structure.redacted"]
    assert redacted_gap["code"] == GapCode.PROVENANCE_UNAVAILABLE.value

    base = attempt.attempt_root / ARTIFACT_DIRECTORY
    dfd = json.loads((base / "dfd.json").read_bytes())
    result = json.loads((base / "result.json").read_bytes())
    md_text = (base / "views" / "threat-model.md").read_text(encoding="utf-8")
    assert "<redacted>" not in json.dumps(dfd)
    assert "publication.max_render_nodes" in md_text
    assert render_gap["gap_id"] in {item["gap_id"] for item in result["gaps"]}
    assert len(outputs[RENDER]["views"]) >= 3


def test_load_and_reference_guards_fail_closed(tmp_path: Path) -> None:
    _, handlers = _handlers()

    no_snapshot = SyntheticAttempt(tmp_path / "no_snapshot", snapshot=None)
    with pytest.raises(ThreatModelGenerationFailed, match="no evidence target snapshot"):
        handlers[LOAD](no_snapshot.unit_context(LOAD))

    bad_repo = tmp_path / "bad_repo"
    (bad_repo / "data" / "reference" / "threat-model").mkdir(parents=True)
    invalid_ref = SyntheticAttempt(tmp_path / "invalid_ref", repo_root=bad_repo)
    with pytest.raises(ThreatModelGenerationFailed, match="threat-model reference data is invalid"):
        handlers[LOAD](invalid_ref.unit_context(LOAD))

    mutable_repo = tmp_path / "mutable_repo"
    shutil.copytree(ROOT / "data" / "reference" / "threat-model",
                    mutable_repo / "data" / "reference" / "threat-model")
    changed_ref = SyntheticAttempt(tmp_path / "changed_ref", repo_root=mutable_repo)
    changed_ref.accept_catalog()
    load_out = handlers[LOAD](changed_ref.unit_context(LOAD))
    with (mutable_repo / "data" / "reference" / "threat-model" / "threat-crosswalk.json").open("ab") as fh:
        fh.write(b"\n")
    with pytest.raises(ThreatModelGenerationFailed, match="reference data changed during the attempt"):
        handlers[INTERACTIONS](changed_ref.unit_context(INTERACTIONS, {LOAD: load_out}))


def test_working_file_custody_digest_json_and_record_guards_fail_closed(tmp_path: Path) -> None:
    _, handlers = _handlers()
    attempt = SyntheticAttempt(tmp_path)
    attempt.accept_catalog()
    attempt.accept_syntax()

    load_out = handlers[LOAD](attempt.unit_context(LOAD))
    structure_out = handlers[STRUCTURE](attempt.unit_context(STRUCTURE, {LOAD: load_out}))
    interactions_out = handlers[INTERACTIONS](attempt.unit_context(INTERACTIONS, {LOAD: load_out}))

    outside = attempt.run_root / "outside.json"
    outside.write_bytes(b"{}")
    foreign_out = {**structure_out, "artifact": {
        "path": outside.relative_to(attempt.run_root).as_posix(),
        "sha256": file_sha256(outside),
        "size_bytes": 2,
    }}
    with pytest.raises(ThreatModelGenerationFailed, match="not owned by this attempt"):
        handlers[ASSEMBLY](attempt.unit_context(ASSEMBLY, {
            LOAD: load_out, STRUCTURE: foreign_out, INTERACTIONS: interactions_out,
        }))

    work_path = attempt.run_root / structure_out["artifact"]["path"]
    original_bytes = work_path.read_bytes()
    work_path.write_bytes(original_bytes + b" ")
    with pytest.raises(ThreatModelGenerationFailed, match="changed after it was written"):
        handlers[ASSEMBLY](attempt.unit_context(ASSEMBLY, {
            LOAD: load_out, STRUCTURE: structure_out, INTERACTIONS: interactions_out,
        }))

    bad_json_bytes = b"{not-json"
    work_path.write_bytes(bad_json_bytes)
    bad_json_out = {**structure_out, "artifact": {
        "path": structure_out["artifact"]["path"],
        "sha256": hashlib.sha256(bad_json_bytes).hexdigest(),
        "size_bytes": len(bad_json_bytes),
    }}
    with pytest.raises(ThreatModelGenerationFailed, match="not valid JSON"):
        handlers[ASSEMBLY](attempt.unit_context(ASSEMBLY, {
            LOAD: load_out, STRUCTURE: bad_json_out, INTERACTIONS: interactions_out,
        }))

    bad_schema_bytes = b'{"unexpected": 1}'
    work_path.write_bytes(bad_schema_bytes)
    bad_schema_out = {**structure_out, "artifact": {
        "path": structure_out["artifact"]["path"],
        "sha256": hashlib.sha256(bad_schema_bytes).hexdigest(),
        "size_bytes": len(bad_schema_bytes),
    }}
    with pytest.raises(ThreatModelGenerationFailed, match="working record of facts.structure is invalid"):
        handlers[ASSEMBLY](attempt.unit_context(ASSEMBLY, {
            LOAD: load_out, STRUCTURE: bad_schema_out, INTERACTIONS: interactions_out,
        }))

    work_path.write_bytes(original_bytes)


def test_publish_and_upstream_integrity_guards_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, handlers = _handlers()
    attempt = SyntheticAttempt(tmp_path / "publish_guards")
    attempt.accept_catalog()
    shard = attempt.accept_syntax()

    outputs: dict[str, Mapping[str, Any]] = {}
    for unit_id in (LOAD, STRUCTURE, INTERACTIONS, ASSEMBLY, THREATS, RESOLVE, RENDER):
        outputs[unit_id] = handlers[unit_id](attempt.unit_context(unit_id, outputs))

    mmd_identity = dict(outputs[RENDER]["views"]["dfd.mmd"])
    mmd_path = attempt.run_root / mmd_identity["path"]
    original_mmd = mmd_path.read_bytes()
    tampered_mmd = original_mmd + b"\n%% drift\n"
    mmd_path.write_bytes(tampered_mmd)
    drifted_render = {
        **outputs[RENDER],
        "views": {
            **outputs[RENDER]["views"],
            "dfd.mmd": {
                "path": mmd_identity["path"],
                "sha256": hashlib.sha256(tampered_mmd).hexdigest(),
                "size_bytes": len(tampered_mmd),
            },
        },
    }
    with pytest.raises(ThreatModelGenerationFailed, match="generated views differ from a fresh render"):
        handlers[PUBLISH](attempt.unit_context(PUBLISH, {**outputs, RENDER: drifted_render}))
    mmd_path.write_bytes(original_mmd)

    real_documents = tm_job._documents
    calls = 0

    def impure_documents(unit: UnitContext, gaps: Sequence[Mapping[str, Any]],
                         artifacts: Mapping[str, Mapping[str, Any]] | None = None) -> Documents:
        nonlocal calls
        calls += 1
        built = real_documents(unit, gaps, artifacts)
        if calls == 2:
            return replace(built, dfd={**built.dfd, "elements": []})
        return built

    with monkeypatch.context() as mp:
        mp.setattr(tm_job, "_documents", impure_documents)
        mp.setattr(tm_job, "validate_documents", lambda *_args: None)
        with pytest.raises(ThreatModelGenerationFailed, match="not a pure function of the working records"):
            handlers[PUBLISH](attempt.unit_context(PUBLISH, outputs))

    with monkeypatch.context() as mp:
        mp.setattr(tm_job, "validate_documents", lambda *_args: (_ for _ in ()).throw(ValueError("broken doc")))
        with pytest.raises(ThreatModelGenerationFailed, match="broken doc"):
            handlers[PUBLISH](attempt.unit_context(PUBLISH, outputs))

    mismatched_pin = SyntheticAttempt(tmp_path / "mismatched_pin")
    mismatched_pin.accept_catalog()
    mismatched_pin.accept_syntax()
    mismatched_pin.pins[SYNTAX] = "0" * 64
    with pytest.raises(UpstreamIntegrityError, match="not the one this attempt admitted"):
        handlers[INTERACTIONS](mismatched_pin.unit_context(INTERACTIONS, {LOAD: outputs[LOAD]}))

    shard_path = attempt.run_root / shard.relative_path
    shard_path.write_bytes(shard_path.read_bytes() + b"\0")
    with pytest.raises(ValueError, match="integrity"):
        handlers[INTERACTIONS](attempt.unit_context(INTERACTIONS, {LOAD: outputs[LOAD]}))
