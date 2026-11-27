"""Focused unit regressions for seq=30 parent re-execution and repair planning."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest

from appsec_review.jobs.job_third_party_data_sync.publication import publish_snapshot, verify_current
from appsec_review.runtime import repair as repair_mod
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, feed_provenance as feeds, file_sha256, shared
from appsec_review.storage.validation import validation_scope
from tests.test_shared_layout_provenance import provenance_scope, receipts


def _feed_owner(repository: Path, run: str, number: int = 1, job: str = "job_third_party_data_sync"):
    root = repository / "runs" / run
    attempt = root / "data/jobs" / job / "attempts" / f"attempt_{number:04d}"
    resolved = {"jobs": {"job_third_party_data_sync": {"steps": {
        step: {"settings": {"feed_root": f"data/feeds/{feed}"}}
        for feed, step in feeds.STEPS.items()}}}}
    config = root / "data/configuration/resolved.json"
    atomic_json(config, resolved)
    claim = {
        "run_id": run, "job_id": job, "attempt_id": attempt.name,
        "attempt_path": attempt.relative_to(root).as_posix(),
        "orchestration": {"system": "dagster", "run_id": f"{run}-{number}"},
        "repository_root": str(repository), "resolved_config_sha256": file_sha256(config),
        "dataset_contract": dataset_contract(job, ("work",), ()),
    }
    atomic_json(attempt / "claim.json", claim)
    return shared.SharedArtifacts.for_job(SimpleNamespace(
        run_root=root, attempt_root=attempt, run_id=run, attempt_id=attempt.name,
        orchestration=claim["orchestration"], config=SimpleNamespace(job_id=job),
    ))


def test_verify_feed_receipt_memoizes_within_validation_scope_and_rechecks_new_scope(tmp_path, monkeypatch):
    producer = _feed_owner(tmp_path, "seq30-feed")
    source = tmp_path / "source.json"
    source.write_bytes(b'{"public": true, "items": [1, 2, 3]}\n')
    with provenance_scope(producer):
        publish_snapshot(tmp_path / "data/feeds/mitre", feed_id="mitre", schema="fixture",
                         files={"reference.json": source}, manifest_fields={"version": "1"})
    consumer_a = _feed_owner(tmp_path, "seq30-feed", number=2, job="job_dependency_intelligence")
    consumer_b = _feed_owner(tmp_path, "seq30-feed", number=3, job="job_dossier_publication")
    with provenance_scope(consumer_a):
        ref_a = verify_current(tmp_path / "data/feeds/mitre", "mitre")["provenance"]
    with provenance_scope(consumer_b):
        ref_b = verify_current(tmp_path / "data/feeds/mitre", "mitre")["provenance"]

    receipt_a = json.loads(shared.verify_reference(producer.run_root, ref_a).read_bytes())
    receipt_b = json.loads(shared.verify_reference(producer.run_root, ref_b).read_bytes())
    claim_a = json.loads(shared.verify_reference(producer.run_root, consumer_a.actor["claim"]).read_bytes())
    claim_b = json.loads(shared.verify_reference(producer.run_root, consumer_b.actor["claim"]).read_bytes())

    calls = []
    original = feeds._verify_snapshot

    def counted(root, manifest, feed):
        calls.append((str(root), manifest["path"], feed))
        return original(root, manifest, feed)

    monkeypatch.setattr(feeds, "_verify_snapshot", counted)
    with validation_scope(producer.run_root):
        feeds.verify_feed_receipt(producer.run_root, receipt_a, claim_a)
        feeds.verify_feed_receipt(producer.run_root, receipt_b, claim_b)
    assert len(calls) == 1

    # A fresh validation_scope must perform a fresh full verification.
    with validation_scope(producer.run_root):
        feeds.verify_feed_receipt(producer.run_root, receipt_a, claim_a)
    assert len(calls) == 2


def test_verify_feed_receipt_fails_closed_when_feed_file_mutates_inside_validation_scope(tmp_path):
    producer = _feed_owner(tmp_path, "seq30-tamper")
    source = tmp_path / "source.json"
    source.write_bytes(b'{"public": true, "items": [1, 2, 3]}\n')
    with provenance_scope(producer):
        pointer = publish_snapshot(tmp_path / "data/feeds/mitre", feed_id="mitre", schema="fixture",
                                   files={"reference.json": source}, manifest_fields={"version": "1"})
    original_receipt = receipts(producer, "feed-snapshot")[0]
    claim = json.loads(shared.verify_reference(producer.run_root, producer.actor["claim"]).read_bytes())
    blob = tmp_path / "data/feeds/mitre/snapshots" / pointer["snapshot_id"] / "reference.json"

    with validation_scope(producer.run_root):
        feeds.verify_feed_receipt(producer.run_root, original_receipt, claim)
        blob.chmod(0o600)
        blob.write_bytes(b'{"public": false, "items": [9, 9, 9]}\n')
        with pytest.raises(ValueError, match="integrity|size|mismatch"):
            feeds.verify_feed_receipt(producer.run_root, original_receipt, claim)


def test_published_input_indexes_shared_inputs_once_per_upstream_handoff(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir()
    producer = "job_inference_security_review"
    consumer = "job_dossier_publication"
    origin_job = "job_evidence_collection"

    consumer_claim_rel = f"data/jobs/{consumer}/attempts/attempt_0001/claim.json"
    consumer_claim_doc = {
        "job_id": consumer, "attempt_id": "attempt_0001",
        "resolved_config_sha256": "c" * 64,
        "deployment_identity": {"image_id": None, "scripts_sha256": "s" * 64, "python": "3.12"},
        "component_identities": {"implementation": "i", "schema": "sc", "validation": "v"},
        "dataset_contract": {"job_contract": {
            "inputs": [{"producer": producer, "output_kind": "handoff", "channel": "handoff"}]
        }},
        "upstream_handoffs": {producer: "h" * 64},
    }
    atomic_json(root / consumer_claim_rel, consumer_claim_doc)
    consumer_claim_ref = shared.reference(root, root / consumer_claim_rel)

    shared_items = []
    origin_refs = []
    consumer_receipts = []
    for idx in range(25):
        obj = {"path": f"data/shared/objects/{idx:064x}", "sha256": f"{idx:064x}", "size_bytes": 16}
        origin_ref = {
            "path": f"data/jobs/{origin_job}/attempts/attempt_0001/shared/blob/{idx:064x}.json",
            "sha256": f"{(idx + 100):064x}", "size_bytes": 32,
        }
        origin_refs.append(origin_ref)
        up_rel = f"data/jobs/{producer}/attempts/attempt_0001/shared/shared-input/{idx:064x}.json"
        atomic_json(root / up_rel, {"object": obj, "producer_receipt": origin_ref})
        shared_items.append(shared.reference(root, root / up_rel))
        consumer_receipts.append({
            "namespace": "shared-input",
            "actor": {"job_id": consumer, "claim": consumer_claim_ref},
            "object": obj,
            "producer_receipt": shared_items[-1],
        })

    handoff_rel = f"data/jobs/{producer}/attempts/attempt_0001/handoff.json"
    handoff_doc = {
        "resolved_config_sha256": "c" * 64,
        "completion_status": "SUCCEEDED",
        "resolving_paths": {"attempt": f"data/jobs/{producer}/attempts/attempt_0001"},
        "artifacts": shared_items,
    }
    atomic_json(root / handoff_rel, handoff_doc)
    handoff_digest = file_sha256(root / handoff_rel)
    consumer_claim_doc["upstream_handoffs"][producer] = handoff_digest
    atomic_json(root / consumer_claim_rel, consumer_claim_doc)
    consumer_claim_ref = shared.reference(root, root / consumer_claim_rel)
    for rec in consumer_receipts:
        rec["actor"]["claim"] = consumer_claim_ref

    status_path = root / f"data/jobs/{producer}/attempts/attempt_0001/status.json"
    atomic_json(status_path, {"status": "SUCCEEDED"})
    atomic_json(root / f"data/jobs/{producer}/attempts/attempt_0001/published.json", {
        "schema": repair_mod.PUBLICATION_PROTOCOL,
        "handoff_sha256": handoff_digest,
        "status_sha256": file_sha256(status_path),
    })

    monkeypatch.setattr("appsec_review.runtime.release.validate_claim_release", lambda *_a: {"sha256": "r" * 64})
    monkeypatch.setattr(
        "appsec_review.runtime.release.identities_from_release",
        lambda *_a: {"implementation": "i", "schema": "sc", "validation": "v"},
    )
    monkeypatch.setattr(
        "appsec_review.retrieval.core._accepted_handoff",
        lambda _r, _p, _d: (handoff_doc, root / handoff_rel),
    )

    def fake_verify_receipt(_r, ref):
        if "/shared/shared-input/" in ref["path"]:
            return json.loads((root / ref["path"]).read_text(encoding="utf-8"))
        return {"producer_receipt": None, "actor": {"job_id": origin_job}}

    monkeypatch.setattr("appsec_review.storage.shared.verify_receipt", fake_verify_receipt)
    monkeypatch.setattr(repair_mod.ComputationAdmission, "_configuration_matches", lambda *_a: True)

    reads = []
    orig_read = repair_mod.read_document

    def counted_read(path):
        reads.append(Path(path).as_posix())
        return orig_read(path)

    monkeypatch.setattr(repair_mod, "read_document", counted_read)

    admission = repair_mod.ComputationAdmission(
        release={"sha256": "r" * 64}, declarations={}, configuration_sha256="c" * 64,
        deployment=consumer_claim_doc["deployment_identity"], job_id=consumer, schema_identity="sc",
    )
    with validation_scope(root):
        for idx, rec in enumerate(consumer_receipts):
            assert admission._published_input(
                root, rec, origin_refs[idx], {"actor": {"job_id": origin_job}}
            ) is True
        # An unpinned origin receipt with matching object must still be rejected.
        forged_origin = {**origin_refs[0], "sha256": "f" * 64}
        assert admission._published_input(
            root, consumer_receipts[0], forged_origin, {"actor": {"job_id": origin_job}}
        ) is False

    shared_reads = [p for p in reads if "/shared/shared-input/" in p]
    # 25 index-build reads + 25 single-bucket verify reads + 1 forged check = 51 (vs 25*25 + 25 = 650 O(N^2)).
    assert len(shared_reads) == 51


def test_ops_review_start_uses_600s_timeout_for_parent_reexecution():
    repo_root = Path(__file__).resolve().parents[2]
    bin_dir = repo_root / "deploy/dagster/bin"
    spec = importlib.util.spec_from_file_location("_seq30_ops", bin_dir / "ops.py")
    assert spec is not None and spec.loader is not None
    old_path = list(sys.path)
    sys.path.insert(0, str(bin_dir))
    try:
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_seq30_ops"] = mod
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop("_seq30_ops", None)
        sys.path[:] = old_path
    source = (bin_dir / "ops.py").read_text(encoding="utf-8")
    assert "preview = docker(*reexecute_run.container_command(code.id, request), timeout=600)" in source
    assert "launched = docker(*command, timeout=180 if reexecution is None else 600)" in source
