"""``load_accepted_debug_symbols`` is the consumer-side reader: it trusts nothing the accepted
handoff does not bind by hash. The handoff lookup is faked at the ``consume`` boundary; the
summary, decision, reader evidence and manifest it points at are the real published files."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_debug_symbol_indexing.job import load_accepted_debug_symbols
from appsec_review.runtime import consume
from appsec_review.storage import atomic_json
from tests.unit.job_debug_symbol_indexing.support import (
    ELF, accepted_inputs, artifact, build_job, catalog_shard, decide, extractor, handlers, job_context, manifest, ref,
    unit,
)


@pytest.fixture
def published(tmp_path: Path, monkeypatch):
    """A real decision, extraction and publication, bound into a faked accepted handoff."""
    context = job_context(tmp_path)
    run_root = context.run_root
    binary = artifact(run_root, "bin/program", ELF)
    job = build_job(extractor=extractor())
    upstream = manifest(run_root, [catalog_shard(run_root, [binary])])
    decision = decide(monkeypatch, job, context, accepted_inputs([binary], upstream))
    selected = handlers(job)["extract.clang_dwarf"](unit(context, "extract.clang_dwarf", {"decide.target": decision}))
    skipped = handlers(job)["extract.msvc_pdb"](unit(context, "extract.msvc_pdb", {"decide.target": decision}))
    output = handlers(job)["acceptance.publish_handoff"](unit(context, "acceptance.publish_handoff", {
        "decide.target": decision, "extract.clang_dwarf": selected, "extract.msvc_pdb": skipped}))
    state = SimpleNamespace(context=context, output=dict(output), decision=decision, selected=selected, calls=[],
                            artifacts=[output["artifact"], output["index_manifest"]])

    def accepted_upstream(run_root, job_id):
        state.calls.append((Path(run_root), job_id))
        handoff = {"status": "ACCEPTED", "job_id": job_id, "outputs": {"acceptance.publish_handoff": state.output},
                   "artifacts": list(state.artifacts)}
        return SimpleNamespace(handoff=handoff, sha256="5" * 64)

    monkeypatch.setattr(consume, "accepted_upstream", accepted_upstream)
    return state


def test_loader_returns_the_summary_bound_to_its_handoff(published) -> None:
    accepted = load_accepted_debug_symbols(published.context.run_root)
    assert published.calls == [(published.context.run_root, "job_debug_symbol_indexing")]
    summary = json.loads((published.context.run_root / published.output["artifact"]["path"]).read_text())
    assert accepted == {**summary, "handoff_sha256": "5" * 64}
    assert accepted["compiler_target"] == "clang" and accepted["record_count"] == 3


def test_summary_must_be_listed_among_the_handoff_artifacts(published) -> None:
    published.artifacts = [published.output["index_manifest"]]
    with pytest.raises(ValueError, match="not bound to accepted handoff"):
        load_accepted_debug_symbols(published.context.run_root)


def test_summary_schema_and_bytes_are_verified(published) -> None:
    path = published.context.run_root / published.output["artifact"]["path"]
    document = json.loads(path.read_text())
    atomic_json(path, {**document, "schema": "appsec-review/debug-symbol-indexing/0"})
    published.output["artifact"] = ref(published.context.run_root, path)
    published.artifacts = [published.output["artifact"], published.output["index_manifest"]]
    with pytest.raises(ValueError, match="unsupported accepted debug-symbol schema"):
        load_accepted_debug_symbols(published.context.run_root)
    path.write_text("{}")
    with pytest.raises(ValueError, match="summary integrity"):
        load_accepted_debug_symbols(published.context.run_root)


def test_tampered_decision_is_refused(published) -> None:
    (published.context.run_root / published.decision["artifact"]["path"]).write_text("{}")
    with pytest.raises(ValueError, match="decision"):
        load_accepted_debug_symbols(published.context.run_root)


@pytest.mark.parametrize("field,value", [("compiler_target", "msvc"), ("selected_lane", "msvc_pdb"),
                                         ("source_fingerprint", "b" * 64)])
def test_summary_and_decision_must_agree_on_target_lane_and_snapshot(published, field, value) -> None:
    path = published.context.run_root / published.output["artifact"]["path"]
    document = json.loads(path.read_text())
    atomic_json(path, {**document, field: value})
    published.output["artifact"] = ref(published.context.run_root, path)
    published.artifacts = [published.output["artifact"], published.output["index_manifest"]]
    with pytest.raises(ValueError, match="decision binding differs"):
        load_accepted_debug_symbols(published.context.run_root)


def test_manifest_binding_and_bytes_are_verified(published) -> None:
    run_root = published.context.run_root
    published.output["index_manifest"] = {**published.output["index_manifest"], "sha256": "0" * 64}
    with pytest.raises(ValueError, match="manifest binding differs"):
        load_accepted_debug_symbols(run_root)
    published.output = dict(published.output, index_manifest=json.loads(
        (run_root / published.output["artifact"]["path"]).read_text())["index_manifest"])
    (run_root / published.output["index_manifest"]["path"]).write_text("{}")
    with pytest.raises(ValueError, match="manifest integrity"):
        load_accepted_debug_symbols(run_root)


def test_reader_evidence_and_its_execution_receipts_are_verified(published) -> None:
    run_root = published.context.run_root
    evidence_path = run_root / published.selected["artifact"]["path"]
    evidence = json.loads(evidence_path.read_text())
    receipt = run_root / "data/jobs/job_debug_symbol_indexing/attempts/attempt_0001/artifacts/debug-symbols/executions/k/receipt.json"
    atomic_json(receipt, {"outcome": "succeeded"})
    evidence["artifacts"][0]["reader_executions"] = [{"execution": ref(run_root, receipt), "outcome": "succeeded"}]
    atomic_json(evidence_path, evidence)
    summary_path = run_root / published.output["artifact"]["path"]
    summary = json.loads(summary_path.read_text())
    atomic_json(summary_path, {**summary, "reader_evidence": ref(run_root, evidence_path)})
    published.output["artifact"] = ref(run_root, summary_path)
    published.artifacts = [published.output["artifact"], published.output["index_manifest"]]
    assert load_accepted_debug_symbols(run_root)["reader_evidence"] == ref(run_root, evidence_path)
    receipt.write_text("{}")
    with pytest.raises(ValueError, match="debug-symbol execution integrity"):
        load_accepted_debug_symbols(run_root)
    evidence_path.write_text("{}")
    with pytest.raises(ValueError, match="reader evidence integrity"):
        load_accepted_debug_symbols(run_root)


def test_unavailable_accepted_handoff_is_a_refusal(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="accepted"):
        load_accepted_debug_symbols(tmp_path)
