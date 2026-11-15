from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

import pytest

from appsec_review.retrieval import IndexIdentity, write_manifest
from appsec_review.review.models import GapClass, IntegrityError
from appsec_review.review.scope import accept_manifest
from appsec_review.storage import atomic_json, file_sha256
from tests.fixtures.inference_review.builder import build_accepted_index_set, shard_path


@pytest.fixture(scope="module")
def readonly_fixture(tmp_path_factory):
    return build_accepted_index_set(tmp_path_factory.mktemp("scope"), publish_v1_packages=False)


def test_accept_manifest_builds_a_deterministic_evidence_map(readonly_fixture) -> None:
    from dataclasses import replace
    import random

    scope = accept_manifest(readonly_fixture.run_root)
    evidence = scope.evidence_map()

    assert evidence == accept_manifest(readonly_fixture.run_root).evidence_map()
    rng = random.Random(7)
    scrambled = replace(
        scope,
        producers=tuple(rng.sample(list(scope.producers), len(scope.producers))),
        components=tuple(reversed(scope.components)),
        build_units=tuple(reversed(scope.build_units)),
        source_files=tuple(reversed(scope.source_files)),
        gaps=tuple(reversed(scope.gaps)),
    )
    assert scrambled.evidence_map() == evidence
    assert [item["component_id"] for item in evidence["components"]] == ["component:0001", "component:0002"]
    assert all(item["trust_boundary_id"] is None for item in evidence["components"])
    assert {item["build_unit_id"]: item["languages"] for item in evidence["build_units"]} == {
        "native-main": ["C"], "py-svc": ["Python"]}
    assert evidence["languages"] == {"C": 2, "Python": 2, "YAML": 1}
    assert evidence["reference_freshness"] == {"dependency_advisories": "stale", "reference_intelligence": "partial"}
    assert {"artifact_scanner", "post_build_hardening", "control_evidence"} <= set(evidence["missing"])
    assert {"source_sast", "codeql", "ci_configuration", "scanner_correlation"} <= set(evidence["available"])
    assert scope.component_for("native/src/io.c").component_id == "component:0002"
    assert scope.build_unit_for("svc/api/util.py").build_unit_id == "py-svc"
    assert scope.component_for(".github/workflows/ci.yml") is None


def test_unavailable_producers_are_coverage_gaps_never_clean(readonly_fixture) -> None:
    scope = accept_manifest(readonly_fixture.run_root)
    artifact = scope.producer("artifact_scanner")
    assert artifact.state == "missing" and not artifact.shards
    [gap] = artifact.gaps
    assert gap.state == "missing" and "not clean" in gap.reason
    assert gap.gap_id.startswith("gap-") and len(gap.gap_id) == 68
    record = gap.to_gap()
    assert record.gap_class is GapClass.COVERAGE_GAP and record.gap_id == gap.gap_id
    stale = scope.producer("dependency_advisories")
    assert stale.state == "stale" and [item.state for item in stale.gaps] == ["stale"]
    assert [gap.gap_id for gap in scope.gaps] == sorted(gap.gap_id for gap in scope.gaps)


def test_changed_shard_byte_blocks_acceptance(tmp_path: Path) -> None:
    fixture = build_accepted_index_set(tmp_path, publish_v1_packages=False)
    path = shard_path(fixture, "observations", "semgrep")
    data = bytearray(path.read_bytes())
    data[-1] ^= 0x01
    path.write_bytes(bytes(data))
    with pytest.raises(IntegrityError, match="integrity mismatch"):
        accept_manifest(fixture.run_root)


def test_swapped_manifest_blocks_acceptance(tmp_path: Path) -> None:
    fixture = build_accepted_index_set(tmp_path, publish_v1_packages=False)
    manifest_path = fixture.run_root / "data" / "indices" / "manifests" / "fixture.json"
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    # A well-formed manifest that silently drops the semgrep shard replaces the accepted one.
    kept = [IndexIdentity(**{**item, "gaps": tuple(item["gaps"])}) for item in document["indexes"]
            if item["shard_id"] != "semgrep"]
    write_manifest(manifest_path, run_id=fixture.run_id, target_snapshot=fixture.snapshot,
                   target_root=fixture.target, indexes=kept)
    with pytest.raises(IntegrityError, match="accepted index set failed verification: target evidence integrity mismatch"):
        accept_manifest(fixture.run_root)


def test_pointer_to_a_manifest_outside_the_handoff_is_rejected(tmp_path: Path) -> None:
    fixture = build_accepted_index_set(tmp_path, publish_v1_packages=False)
    source = fixture.run_root / "data" / "indices" / "manifests" / "fixture.json"
    other = source.with_name("other.json")
    other.write_bytes(source.read_bytes())
    pointer_path = fixture.run_root / "data" / "indices" / "accepted.json"
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    atomic_json(pointer_path, {**pointer, "manifest_path": other.relative_to(fixture.run_root).as_posix(),
                               "manifest_sha256": file_sha256(other)})
    with pytest.raises(IntegrityError, match="not bound to its producer handoff"):
        accept_manifest(fixture.run_root)


def test_missing_pointer_and_post_acceptance_change_are_integrity_failures(tmp_path: Path) -> None:
    fixture = build_accepted_index_set(tmp_path, publish_v1_packages=False)
    scope = accept_manifest(fixture.run_root)
    scope.verify()
    path = shard_path(fixture, "priority", "review-prioritization")
    path.write_bytes(path.read_bytes() + b"\0")
    with pytest.raises(IntegrityError, match="changed during assembly"):
        scope.verify()
    (fixture.run_root / "data" / "indices" / "accepted.json").unlink()
    with pytest.raises(IntegrityError, match="unavailable"):
        accept_manifest(fixture.run_root)


def test_shard_identity_order_does_not_change_scope(tmp_path: Path, readonly_fixture) -> None:
    first = accept_manifest(readonly_fixture.run_root)
    second = accept_manifest(build_accepted_index_set(tmp_path / "b", seed=2, publish_v1_packages=False).run_root)
    assert [asdict(item) for item in first.components] == [asdict(item) for item in second.components]
    assert [shard["sha256"] for shard in first.shards] == [shard["sha256"] for shard in second.shards]
