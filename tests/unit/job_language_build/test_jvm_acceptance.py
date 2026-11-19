"""JVM provenance publication follows the final transaction outcome, not the precommit index."""
from __future__ import annotations

from copy import deepcopy
import json
import sqlite3

import pytest

from appsec_review.interchange import GapCode, producer_gap
from appsec_review.jobs.build_iterations import IterationOutcome, read_reference
from appsec_review.config.build_selection import AXES
from appsec_review.jobs.build_workspace import ProductSpec
from appsec_review.jobs.job_language_build import jvm
from appsec_review.retrieval.core import _flatten_manifest
from appsec_review.retrieval.index import IndexIdentity, load_verified_manifest, write_manifest
from appsec_review.storage import canonical_json, file_sha256
from appsec_review.storage.shared import immutable_bytes
from tests.unit.job_build_iteration.test_diagnostic_tail import _controller
from tests.unit.job_build_iteration.test_workspace_resume import _invoke
from tests.unit.job_language_build import support
from tests.unit.job_language_build.test_audit_correctness import _jvm_receipt


@pytest.mark.parametrize("mode", ["rejected", "qualified", "typed-qualification", "tampered-rejection"])
def test_accepted_jvm_index_agrees_with_final_receipt_and_keeps_unrelated_shards(tmp_path, mode):
    controller, action = _controller(tmp_path, "java", 8)
    root = controller.run_root
    unit = support.unit_context(
        tmp_path / "publication", "acceptance.publish_handoff", run_root=root,
        run_id=root.name, target_root=controller.target,
        source_fingerprint=controller.graph["source_fingerprint"],
        attempt_root=root / "data/jobs/job_language_build/attempts/attempt_0001")
    artifact = immutable_bytes(root, "artifacts/synthetic/App.class", b"\xca\xfe\xba\xbecompiled-fixture")
    original = _jvm_receipt()
    original.update(build_unit_id=action["build_unit_id"], root=".")
    original["artifacts"][0].update(
        artifact, workspace_path="build/App.class", build_unit_id=action["build_unit_id"])
    original["retrieval_index"] = jvm._index(unit, original)
    original_index = original["retrieval_index"]["identity"]
    original_digest = file_sha256(root / original_index["relative_path"])
    sibling = deepcopy(original)
    sibling["build_unit_id"] = "build-unit-" + "2" * 20
    sibling["artifacts"][0]["build_unit_id"] = sibling["build_unit_id"]
    sibling_index = jvm._index(unit, sibling)["identity"]
    prior = root / "data/indices/jvm-prior.json"
    write_manifest(prior, run_id=root.name, target_snapshot=unit.job.source_fingerprint,
                   target_root=controller.target,
                   indexes=[IndexIdentity(**value) for value in (original_index, sibling_index)])
    unit.job.input_manifest_path, unit.job.input_manifest_sha256 = prior, file_sha256(prior)

    if "rejection" in mode or mode == "rejected":
        def missing_products(_request, _run_id):
            missing = ProductSpec(
                "target/build/missing.jar", "package_metadata", "missing", "java:missing",
                controller.graph["nodes"][0]["variant"], "package", dict.fromkeys(AXES))
            return IterationOutcome(original, (missing,), True)

        result = controller.run(missing_products, invoke=_invoke)
        assert result["states"] == {action["build_unit_id"]: "FAILED"}
        final, = result["receipts"]
        assert final["artifacts"] == []
        assert canonical_json(final["retrieval_index"]) == canonical_json(original["retrieval_index"])
        failure_pointer = root / "data/build/iterations/failures" / f"{action['build_unit_id']}.json"
        failure = read_reference(root, json.loads(failure_pointer.read_bytes())["failure"])
        historical = read_reference(root, failure["receipt"])
        assert historical["terminal_status"] == "SUCCEEDED" and historical["artifacts"]
    else:
        final = {**original, "terminal_status": "COMPLETED_WITH_GAPS",
                 "gaps": ["late compiler provenance qualification"]}
        if mode == "typed-qualification":
            final["gaps"] = [producer_gap(
                GapCode.PROVENANCE_UNAVAILABLE, unit_id="execute.java",
                scope_id=action["build_unit_id"], reason="late compiler provenance qualification")]
    final_before = deepcopy(final)
    outputs = {"iterations.dispatch": {"graph": None, "gaps": final["gaps"]},
               "load.native": {"accepted": support.accepted()}}
    outputs.update({f"execute.{family}": {"receipts": [final] if family == "java" else [],
                                         "gaps": final["gaps"] if family == "java" else []}
                    for family in support.FAMILIES})
    unit.output = lambda key: outputs[key]
    publish = support.units()["acceptance.publish_handoff"].handler
    if mode == "tampered-rejection":
        path = root / original_index["relative_path"]
        path.chmod(0o600)
        path.write_bytes(b"corrupt")
        with pytest.raises(ValueError, match="integrity"):
            publish(unit)
        return

    published = publish(unit)
    document = json.loads((root / published["artifact"]["path"]).read_bytes())
    accepted_receipt, = document["receipts"]
    updated = accepted_receipt["retrieval_index"]["identity"]
    assert updated["sha256"] != original_index["sha256"]
    assert final == final_before
    assert accepted_receipt["gaps"] == final["gaps"]
    manifest = published["index_manifest"]
    load_verified_manifest(root, root / manifest["path"], manifest["sha256"])
    indexes, _ = _flatten_manifest(root, root / manifest["path"], manifest["sha256"])
    assert indexes[("build", original_index["shard_id"])]["sha256"] == updated["sha256"]
    assert indexes[("build", sibling_index["shard_id"])]["sha256"] == sibling_index["sha256"]
    with sqlite3.connect(root / updated["relative_path"]) as database:
        payloads = [json.loads(row[0]) for row in database.execute("SELECT payload_json FROM entities")]
        coverage = database.execute("SELECT status, gap FROM coverage").fetchall()
    assert any(value.get("command_id") == "old-command" for value in payloads)
    assert any(value.get("workspace_path") == "build/App.class" for value in payloads) == (mode != "rejected")
    assert coverage[0][0] == "partial" and coverage[0][1]
    assert file_sha256(root / original_index["relative_path"]) == original_digest
