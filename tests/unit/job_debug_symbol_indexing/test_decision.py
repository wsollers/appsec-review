"""``decide.target`` freezes the compiler route, the accepted inputs and the reader identity into
an immutable decision; ``_read_decision`` is what every later unit trusts, so each way the
decision can drift from the unit's own inputs is refused by name."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.config.debug_symbols import parse_debug_symbol_settings
from appsec_review.debug_symbols.contract import DECISION_SCHEMA
from appsec_review.jobs.job_debug_symbol_indexing import job as job_module
from appsec_review.jobs.job_debug_symbol_indexing.job import (
    FrameworkIntegrityError, _decision, _digest, _read_decision, _reader_identity,
)
from tests.unit.job_debug_symbol_indexing.support import (
    ELF, HANDOFF_SHA, SNAPSHOT, accepted_inputs, artifact, build_job, decide, events, extractor, job_context,
    manifest, unit,
)


@pytest.fixture
def decided(tmp_path: Path, monkeypatch):
    context = job_context(tmp_path, target="msvc")
    run_root = context.run_root
    inputs = accepted_inputs([artifact(run_root, "bin/program", b"MZfixture"),
                              artifact(run_root, "symbols/program.pdb", b"Microsoft C/C++ MSF 7.00\r\nx",
                                       "debug-information")],
                             manifest(run_root), gaps=["catalog gap"], language_sha="f" * 64)
    job = build_job(extractor=extractor())
    return context, job, inputs, decide(monkeypatch, job, context, inputs)


@pytest.mark.parametrize("target,lane", [("clang", "clang_dwarf"), ("msvc", "msvc_pdb")])
def test_decision_routes_the_lane_and_freezes_inputs_settings_and_reader_identity(tmp_path: Path, monkeypatch,
                                                                                  target, lane) -> None:
    context = job_context(tmp_path, target=target, settings={"max_artifacts": 7})
    inputs = accepted_inputs([artifact(context.run_root, "bin/program", ELF)], manifest(context.run_root))
    reader = extractor()
    job = build_job(extractor=reader)
    result = decide(monkeypatch, job, context, inputs)
    assert result["terminal_status"] == "SUCCEEDED"
    assert (result["compiler_target"], result["selected_lane"]) == (target, lane)
    assert result["artifact"]["path"] == f"data/jobs/job_debug_symbol_indexing/attempts/attempt_0001/artifacts/debug-symbols/decision.json"
    document = json.loads((context.run_root / result["artifact"]["path"]).read_text(encoding="utf-8"))
    body = {key: value for key, value in document.items() if key != "input_fingerprint"}
    assert document["input_fingerprint"] == result["input_fingerprint"] == _digest(body)
    assert body == {"schema": DECISION_SCHEMA, "compiler_target": target, "selected_lane": lane,
                    "source_fingerprint": SNAPSHOT, "reader_identity": _reader_identity(reader),
                    "settings": parse_debug_symbol_settings({"compiler_target": target, "max_artifacts": 7}),
                    "execution": None, **inputs}
    assert body["artifact_handoff_sha256"] == HANDOFF_SHA and body["settings"]["max_artifacts"] == 7
    (event,) = events(context)
    assert event["event"] == "DEBUG_SYMBOL_TARGET_SELECTED"
    assert {key: event[key] for key in ("unit_id", "compiler_target", "lane", "record_count", "artifact_count", "gap_count")} == {
        "unit_id": "decide.target", "compiler_target": target, "lane": lane, "record_count": 0,
        "artifact_count": 1, "gap_count": 0}
    assert isinstance(event["duration_ms"], int)


def test_decision_fingerprint_changes_with_inputs_settings_target_and_reader(tmp_path: Path, monkeypatch) -> None:
    fingerprints = set()
    for index, (target, settings, reader) in enumerate([
            ("clang", {}, extractor()), ("msvc", {}, extractor()), ("clang", {"max_artifacts": 2}, extractor()),
            ("clang", {}, lambda *a, **k: None)]):
        context = job_context(tmp_path / str(index), target=target, settings=settings)
        inputs = accepted_inputs([artifact(context.run_root, "bin/program", ELF)], manifest(context.run_root))
        fingerprints.add(decide(monkeypatch, build_job(extractor=reader), context, inputs)["input_fingerprint"])
    assert len(fingerprints) == 4
    context = job_context(tmp_path / "same", target="clang")
    inputs = accepted_inputs([artifact(context.run_root, "bin/program", ELF)], manifest(context.run_root))
    first = decide(monkeypatch, build_job(extractor=extractor()), context, inputs)["input_fingerprint"]
    repeated = decide(monkeypatch, build_job(extractor=extractor()), context, inputs)["input_fingerprint"]
    assert first == repeated, "identical inputs, settings, target and reader source reproduce the fingerprint"
    assert first not in fingerprints, "the fingerprint binds the upstream manifest bytes of this run"
    inputs["gaps"] = ["new gap"]
    assert decide(monkeypatch, build_job(extractor=extractor()), context, inputs)["input_fingerprint"] != first


def test_production_decision_freezes_the_execution_plan(tmp_path: Path, monkeypatch) -> None:
    context = job_context(tmp_path)
    inputs = accepted_inputs([artifact(context.run_root, "bin/program", ELF)], manifest(context.run_root))
    monkeypatch.setattr(job_module, "_accepted_inputs", lambda _unit, _settings: inputs)
    plan = {"schema": "appsec-review/debug-symbol-execution-plan/2", "fallback": {"image_id": "sha256:" + "f" * 64}}
    seen = []
    monkeypatch.setattr(job_module, "execution_plan", lambda repository, run_root: seen.append((repository, run_root)) or plan)
    result = _decision(unit(context, "decide.target"), _reader_identity(None), production=True)
    assert seen == [(context.repository_root, context.run_root)]
    document = json.loads((context.run_root / result["artifact"]["path"]).read_text(encoding="utf-8"))
    assert document["execution"] == plan and document["reader_identity"] == _reader_identity(None)
    extraction = unit(context, "extract.clang_dwarf", {"decide.target": result})
    assert _read_decision(extraction, _reader_identity(None))["execution"] == plan
    monkeypatch.setattr(job_module, "execution_plan", lambda repository, run_root: {**plan, "fallback": {}})
    with pytest.raises(FrameworkIntegrityError, match="execution plan differs"):
        _read_decision(extraction, _reader_identity(None))


def test_read_decision_returns_the_frozen_document_for_the_matching_unit(decided) -> None:
    context, job, inputs, result = decided
    reader_identity = json.loads((context.run_root / result["artifact"]["path"]).read_text())["reader_identity"]
    decision = _read_decision(unit(context, "extract.msvc_pdb", {"decide.target": result}), reader_identity)
    assert decision["selected_lane"] == "msvc_pdb" and decision["artifacts"] == inputs["artifacts"]
    assert decision["gaps"] == ["catalog gap"] and decision["upstream_manifest"] == inputs["upstream_manifest"]
    assert decision["language_build_handoff_sha256"] == "f" * 64


def test_read_decision_refuses_a_rewritten_or_tampered_document(decided) -> None:
    context, job, inputs, result = decided
    reader_identity = json.loads((context.run_root / result["artifact"]["path"]).read_text())["reader_identity"]
    path = context.run_root / result["artifact"]["path"]
    original = path.read_bytes()
    path.write_text("{}")
    with pytest.raises(FrameworkIntegrityError, match="decision integrity verification failed"):
        _read_decision(unit(context, "extract.msvc_pdb", {"decide.target": result}), reader_identity)
    document = json.loads(original)
    document["gaps"] = []
    path.write_text(json.dumps(document))
    with pytest.raises(FrameworkIntegrityError, match="decision integrity"):
        _read_decision(unit(context, "extract.msvc_pdb", {"decide.target": result}), reader_identity)
    path.write_bytes(original)
    forged = {**result, "artifact": {**result["artifact"], "path": result["artifact"]["path"]},
              "input_fingerprint": "0" * 64}
    with pytest.raises(ValueError, match="does not match immutable inputs"):
        _read_decision(unit(context, "extract.msvc_pdb", {"decide.target": forged}), reader_identity)


def test_read_decision_refuses_a_unit_whose_settings_snapshot_or_reader_differ(decided, tmp_path: Path) -> None:
    context, job, inputs, result = decided
    reader_identity = json.loads((context.run_root / result["artifact"]["path"]).read_text())["reader_identity"]
    changed_settings = job_context(tmp_path, target="msvc", settings={"max_artifacts": 3})
    with pytest.raises(ValueError, match="does not match immutable inputs"):
        _read_decision(unit(changed_settings, "extract.msvc_pdb", {"decide.target": result}), reader_identity)
    changed_target = job_context(tmp_path, target="clang")
    with pytest.raises(ValueError, match="does not match immutable inputs"):
        _read_decision(unit(changed_target, "extract.msvc_pdb", {"decide.target": result}), reader_identity)
    other_snapshot = job_context(tmp_path, target="msvc", snapshot="b" * 64)
    with pytest.raises(ValueError, match="does not match immutable inputs"):
        _read_decision(unit(other_snapshot, "extract.msvc_pdb", {"decide.target": result}), reader_identity)
    with pytest.raises(ValueError, match="does not match immutable inputs"):
        _read_decision(unit(context, "extract.msvc_pdb", {"decide.target": result}), _reader_identity(None))


def test_decision_is_checked_before_any_reader_runs(decided) -> None:
    context, job, inputs, result = decided
    calls = []
    job = build_job(extractor=extractor(calls))
    (context.run_root / result["artifact"]["path"]).write_text("{}")
    handler = {item.unit_id: item.handler for item in job.units}["extract.msvc_pdb"]
    with pytest.raises(FrameworkIntegrityError, match="decision"):
        handler(unit(context, "extract.msvc_pdb", {"decide.target": result}))
    assert calls == []
