"""job_artifact_indexing: canonical identities, artifact families, member paths, shard ids,
batching and the shard fingerprint, all pure functions of the receipt data they are given."""
from __future__ import annotations

import json

import pytest

from appsec_review.jobs.job_artifact_indexing import (
    artifact_family, artifact_index_fingerprint, canonical_archive_member_identity, canonical_artifact_identity,
)
from appsec_review.jobs.job_artifact_indexing import job as job_module
from appsec_review.jobs.job_artifact_indexing.job import (
    MAX_ARTIFACTS_PER_SHARD, MAX_ROWS_PER_SHARD, SHARD_LAYOUT, ArtifactIndexIntegrityError, _ArtifactRows,
    _artifact_fields, _batch_shard_id, _manifest_entries, _member_path, _pack, _ReceiptContext, _shard_layout,
    canonical_target_artifact_identity,
)
from appsec_review.retrieval import EntityKind, LogicalIdentity
from tests.unit.job_artifact_indexing.support import SNAPSHOT, validated_artifact, validated_receipt

FAMILIES = sorted({
    "object": EntityKind.OBJECT_FILE, "static-library": EntityKind.LIBRARY, "shared-library": EntityKind.LIBRARY,
    "library": EntityKind.LIBRARY, "executable": EntityKind.EXECUTABLE, "native-output": EntityKind.EXECUTABLE,
    "wheel": EntityKind.PACKAGE, "source-distribution": EntityKind.PACKAGE, "jar": EntityKind.PACKAGE,
    "war": EntityKind.PACKAGE, "ear": EntityKind.PACKAGE, "package-archive": EntityKind.PACKAGE,
    "package": EntityKind.PACKAGE, "bytecode": EntityKind.BYTECODE_MODULE, "python-bytecode": EntityKind.BYTECODE_MODULE,
    "jvm-class": EntityKind.BYTECODE_MODULE, "dex": EntityKind.BYTECODE_MODULE, "llvm-bitcode": EntityKind.BYTECODE_MODULE,
    "managed-assembly": EntityKind.MANAGED_ASSEMBLY, "wasm-module": EntityKind.WASM_MODULE,
    "wasm-component": EntityKind.WASM_MODULE, "generated-code": EntityKind.BUILD_ARTIFACT,
    "unknown": EntityKind.BUILD_ARTIFACT, "": EntityKind.BUILD_ARTIFACT,
}.items())


@pytest.mark.parametrize("kind, family", FAMILIES, ids=[kind or "empty" for kind, _ in FAMILIES])
def test_artifact_family_maps_every_known_format_and_defaults_to_build_artifact(kind: str, family: EntityKind) -> None:
    assert artifact_family(kind) is family
    assert artifact_family(kind.upper()) is family, "format comparison is case-insensitive"


def test_canonical_artifact_identity_is_stable_under_key_order_and_binds_unit_path_hash_and_format() -> None:
    artifact = {"workspace_path": "dist/module.wasm", "sha256": "1" * 64, "size_bytes": 8, "kind": "wasm-module"}
    first = canonical_artifact_identity("snapshot", "unit", artifact)
    assert first == canonical_artifact_identity("snapshot", "unit", dict(reversed(list(artifact.items()))))
    assert first.kind is EntityKind.WASM_MODULE
    assert first == LogicalIdentity.derive(EntityKind.WASM_MODULE, "snapshot", {
        "build_unit_id": "unit", "workspace_path": "dist/module.wasm", "sha256": "1" * 64, "format": "wasm-module"})
    assert first != canonical_artifact_identity("snapshot", "other-unit", artifact)
    assert first != canonical_artifact_identity("other-snapshot", "unit", artifact)
    assert first != canonical_artifact_identity("snapshot", "unit", {**artifact, "kind": "wasm-component"})
    assert first == canonical_artifact_identity("snapshot", "unit", {**artifact, "size_bytes": 9}), \
        "size is validated but is not part of the identity"
    assert canonical_artifact_identity("snapshot", "unit", {**artifact, "workspace_path": "./dist//module.wasm"}) == first


WEAK_ARTIFACTS = {
    "no-hash": ({"workspace_path": "a", "kind": "object", "size_bytes": 1}, "canonical path, hash, and format"),
    "short-hash": ({"workspace_path": "a", "kind": "object", "size_bytes": 1, "sha256": "ab"}, "canonical path, hash"),
    "upper-hash": ({"workspace_path": "a", "kind": "object", "size_bytes": 1, "sha256": "A" * 64}, "canonical path, hash"),
    "no-kind": ({"workspace_path": "a", "size_bytes": 1, "sha256": "a" * 64}, "canonical path, hash, and format"),
    "no-size": ({"workspace_path": "a", "kind": "object", "sha256": "a" * 64}, "size is invalid"),
    "bool-size": ({"workspace_path": "a", "kind": "object", "sha256": "a" * 64, "size_bytes": True}, "size is invalid"),
    "negative-size": ({"workspace_path": "a", "kind": "object", "sha256": "a" * 64, "size_bytes": -1}, "size is invalid"),
    "float-size": ({"workspace_path": "a", "kind": "object", "sha256": "a" * 64, "size_bytes": 1.0}, "size is invalid"),
}


@pytest.mark.parametrize("artifact, message", [WEAK_ARTIFACTS[key] for key in sorted(WEAK_ARTIFACTS)],
                         ids=sorted(WEAK_ARTIFACTS))
def test_artifact_fields_reject_a_missing_or_weak_identity(artifact: dict, message: str) -> None:
    with pytest.raises(ArtifactIndexIntegrityError, match=message):
        _artifact_fields(artifact)
    with pytest.raises(ArtifactIndexIntegrityError, match=message):
        canonical_artifact_identity(SNAPSHOT, "unit", artifact)


def test_artifact_fields_normalize_the_path_and_keep_hash_and_format() -> None:
    assert _artifact_fields({"workspace_path": "./build//a.o", "sha256": "b" * 64, "size_bytes": 0, "kind": "object"}) == (
        "build/a.o", "b" * 64, "object")


def test_target_artifact_identity_is_a_distinct_origin_from_a_produced_artifact_of_the_same_bytes() -> None:
    artifact = {"workspace_path": "prebuilt/module.wasm", "sha256": "2" * 64, "size_bytes": 8, "kind": "wasm-module"}
    target = canonical_target_artifact_identity(SNAPSHOT, artifact)
    assert target.kind is EntityKind.WASM_MODULE
    assert target == LogicalIdentity.derive(EntityKind.WASM_MODULE, SNAPSHOT, {
        "origin": "target-intake", "target_path": "prebuilt/module.wasm", "sha256": "2" * 64, "format": "wasm-module"})
    assert target != canonical_artifact_identity(SNAPSHOT, "unit", artifact)
    with pytest.raises(ArtifactIndexIntegrityError, match="size is invalid"):
        canonical_target_artifact_identity(SNAPSHOT, {**artifact, "size_bytes": None})


# --- archive members -----------------------------------------------------------------------------

def test_archive_member_identity_binds_parent_path_size_and_optional_hash() -> None:
    parent = canonical_artifact_identity(SNAPSHOT, "unit", validated_artifact("dist/sample.whl", "wheel", "PK"))
    member = canonical_archive_member_identity(SNAPSHOT, parent, {"member": "pkg/mod.py", "size_bytes": 9})
    assert member.kind is EntityKind.ARCHIVE_MEMBER
    assert member == canonical_archive_member_identity(SNAPSHOT, parent.value, {"member": "pkg\\mod.py", "size_bytes": 9}), \
        "a string parent and a backslash path resolve to the same member"
    assert member == LogicalIdentity.derive(EntityKind.ARCHIVE_MEMBER, SNAPSHOT, {
        "parent": parent.value, "path": "pkg/mod.py", "size_bytes": 9, "sha256": None})
    hashed = canonical_archive_member_identity(SNAPSHOT, parent, {"member": "pkg/mod.py", "size_bytes": 9, "sha256": "3" * 64})
    assert hashed != member
    assert canonical_archive_member_identity(SNAPSHOT, parent, {"member": "pkg/mod.py", "size_bytes": 10}) != member


WEAK_MEMBERS = {
    "dotdot": ({"member": "pkg/../secret", "size_bytes": 9}, "non-canonical"),
    "dot": ({"member": "./pkg/mod.py", "size_bytes": 9}, "non-canonical"),
    "double-slash": ({"member": "pkg//mod.py", "size_bytes": 9}, "non-canonical"),
    "absolute": ({"member": "/etc/passwd", "size_bytes": 9}, "must be relative"),
    "drive": ({"member": "C:/windows/system32", "size_bytes": 9}, "must be relative"),
    "empty": ({"member": "", "size_bytes": 9}, "path is invalid"),
    "nul": ({"member": "pkg/mod\x00.py", "size_bytes": 9}, "path is invalid"),
    "no-size": ({"member": "pkg/mod.py"}, "size is invalid"),
    "negative-size": ({"member": "pkg/mod.py", "size_bytes": -1}, "size is invalid"),
    "bad-hash": ({"member": "pkg/mod.py", "size_bytes": 1, "sha256": "zz"}, "hash is invalid"),
}


@pytest.mark.parametrize("member, message", [WEAK_MEMBERS[key] for key in sorted(WEAK_MEMBERS)], ids=sorted(WEAK_MEMBERS))
def test_archive_member_identity_rejects_non_canonical_paths_and_weak_fields(member: dict, message: str) -> None:
    parent = canonical_artifact_identity(SNAPSHOT, "unit", validated_artifact("dist/sample.whl", "wheel", "PK"))
    with pytest.raises(ArtifactIndexIntegrityError, match=message):
        canonical_archive_member_identity(SNAPSHOT, parent, member)


def test_member_path_canonicalizes_separators() -> None:
    assert _member_path("pkg\\sub\\mod.py") == "pkg/sub/mod.py"
    assert _member_path("pkg/mod.py") == "pkg/mod.py"


# --- shard ids, layout and packing -----------------------------------------------------------------

@pytest.mark.parametrize("unit", sorted(["unit/escape", "unit with space", "u" * 120]), ids=["long", "slash", "space"])
def test_batch_shard_ids_are_bounded_and_portable(unit: str) -> None:
    with pytest.raises(ArtifactIndexIntegrityError, match="shard id is invalid"):
        _batch_shard_id("relations", unit, 0)


def test_batch_shard_id_is_prefix_unit_and_a_zero_padded_batch() -> None:
    assert _batch_shard_id("members", "build-unit-1", 12) == "members-build-unit-1-0012"
    assert _batch_shard_id("relations", "build-unit-" + "a" * 20, 0) == "relations-build-unit-" + "a" * 20 + "-0000"
    assert _batch_shard_id("relations", "u" * 113, 1) == "relations-" + "u" * 113 + "-0001", "128 characters fit"
    with pytest.raises(ArtifactIndexIntegrityError, match="shard id is invalid"):
        _batch_shard_id("relations", "u" * 114, 1)


def test_shard_layout_names_the_bounds_that_are_bound_into_batched_fingerprints() -> None:
    assert _shard_layout() == {"layout": SHARD_LAYOUT, "max_artifacts_per_shard": MAX_ARTIFACTS_PER_SHARD,
                               "max_rows_per_shard": MAX_ROWS_PER_SHARD}
    assert (SHARD_LAYOUT, MAX_ARTIFACTS_PER_SHARD, MAX_ROWS_PER_SHARD) == ("build-unit-batch/1", 5_000, 100_000)


def _rows(*sizes: int) -> list[_ArtifactRows]:
    return [_ArtifactRows({"workspace_path": f"a{index}"}, [], ["r"] * size, []) for index, size in enumerate(sizes)]


def test_pack_is_greedy_by_artifact_count_and_row_count_and_isolates_an_oversized_artifact(monkeypatch) -> None:
    monkeypatch.setattr(job_module, "MAX_ARTIFACTS_PER_SHARD", 3)
    monkeypatch.setattr(job_module, "MAX_ROWS_PER_SHARD", 10)
    batches = [[item.artifact["workspace_path"] for item in batch] for batch in _pack(_rows(2, 2, 2, 2, 5, 5, 1, 30, 1))]
    assert batches == [["a0", "a1", "a2"], ["a3", "a4"], ["a5", "a6"], ["a7"], ["a8"]]
    assert list(_pack([])) == []
    assert [[item.artifact["workspace_path"] for item in batch] for batch in _pack(_rows(30))] == [["a0"]]
    assert _rows(4)[0].size == 4


# --- fingerprints ----------------------------------------------------------------------------------

def test_fingerprints_bind_relevant_inputs_but_not_scanner_or_mcp_identity() -> None:
    receipt = {"build_unit_id": "unit", "fingerprint": "1" * 64, "recipe_identity": "2" * 64, "probe_identity": "3" * 64,
               "upstream_handoff_sha256": "4" * 64, "image": {"image_id": "sha256:" + "5" * 64},
               "workspace_manifest": {"sha256": "6" * 64}, "commands": [],
               "executor_identity": "executor/1", "capture_identity": "capture/1", "family": "native"}
    artifact = {"workspace_path": "a.o", "sha256": "7" * 64, "size_bytes": 1, "kind": "object"}
    arguments = dict(name="artifacts", target_snapshot="snapshot", receipt=receipt, artifacts=[artifact],
                     upstream_manifests=["6" * 64], extractor_identity="extractor/1", parser_identity="parser/1",
                     normalizer_identity="normalizer/1", mapping_identity="mapping/1")
    first = artifact_index_fingerprint(**arguments)
    assert first == artifact_index_fingerprint(**arguments)
    assert "scanner" not in json.dumps(arguments) and "mcp" not in json.dumps(arguments)
    for change in ({"extractor_identity": "extractor/2"}, {"parser_identity": "parser/2"},
                   {"normalizer_identity": "normalizer/2"}, {"mapping_identity": "mapping/2"},
                   {"target_snapshot": "other"}, {"upstream_manifests": ["9" * 64]},
                   {"artifacts": [{**artifact, "size_bytes": 2}]}, {"artifacts": [{**artifact, "kind": "executable"}]},
                   {"receipt": {**receipt, "recipe_identity": "9" * 64}}, {"receipt": {**receipt, "image": {}}},
                   {"receipt": {**receipt, "commands": [{"command_id": "c", "argv_sha256": "8" * 64}]}},
                   {"receipt": {**receipt, "executor_identity": "executor/2"}}):
        assert artifact_index_fingerprint(**{**arguments, **change}) != first, change
    assert artifact_index_fingerprint(**{**arguments, "receipt": {**receipt, "workspace_manifest": {"sha256": "0" * 64}}}) == first, \
        "the workspace manifest reaches the fingerprint through upstream_manifests, not the receipt"
    reordered = [{**artifact, "workspace_path": "b.o"}, artifact]
    assert artifact_index_fingerprint(**{**arguments, "artifacts": reordered}) == artifact_index_fingerprint(
        **{**arguments, "artifacts": list(reversed(reordered))})


def test_receipt_context_and_layout_binding_in_fingerprints(monkeypatch) -> None:
    receipt = validated_receipt(5)
    artifacts = receipt["validated_artifacts"]
    arguments = dict(name="artifacts", target_snapshot=SNAPSHOT, receipt=receipt, artifacts=artifacts,
                     upstream_manifests=_manifest_entries(receipt, artifacts), extractor_identity="none",
                     parser_identity="parser/1", normalizer_identity="normalizer/1", mapping_identity="mapping/1")
    context = _ReceiptContext.build(receipt, SNAPSHOT)
    plain = artifact_index_fingerprint(**arguments)
    assert artifact_index_fingerprint(**arguments, receipt_context=context) == plain
    layout = artifact_index_fingerprint(**arguments, shard_layout=_shard_layout())
    assert layout != plain
    assert artifact_index_fingerprint(**arguments, receipt_context=context, shard_layout=_shard_layout()) == layout
    monkeypatch.setattr(job_module, "MAX_ROWS_PER_SHARD", 99)
    assert artifact_index_fingerprint(**arguments, shard_layout=_shard_layout()) != layout
    with pytest.raises(ArtifactIndexIntegrityError, match="another receipt"):
        artifact_index_fingerprint(**arguments, receipt_context=_ReceiptContext.build(validated_receipt(5), SNAPSHOT))


def test_manifest_entries_are_sorted_hashes_of_unit_path_and_digest() -> None:
    receipt = validated_receipt(2)
    artifacts = receipt["validated_artifacts"]
    entries = _manifest_entries(receipt, artifacts)
    assert len(entries) == 3 and entries == tuple(sorted(entries)) and all(len(item) == 64 for item in entries)
    assert _manifest_entries(receipt, reversed(artifacts)) == entries
    assert _manifest_entries({**receipt, "build_unit_id": "other"}, artifacts) != entries
    assert _manifest_entries(receipt, artifacts[:1]) == entries[:1] or len(_manifest_entries(receipt, artifacts[:1])) == 1


def test_receipt_context_indexes_actions_invocations_rows_and_artifacts_once() -> None:
    receipt = validated_receipt(3, link_inputs=2)
    context = _ReceiptContext.build(receipt, SNAPSHOT)
    assert set(context.actions) == {"compile", "link"}
    assert context.actions_by_argv == {"1" * 64: ["compile"], "2" * 64: ["link"]}
    app = receipt["validated_artifacts"][-1]
    (index, invocation), = context.invocations_by_output[(app["workspace_path"], app["sha256"])]
    assert index == 3 and invocation["tool"] == "ld"
    first = receipt["validated_artifacts"][0]
    assert [row["command_id"] for row in context.relationship_rows_by_sha[first["sha256"]]] == ["compile"]
    assert context.artifacts_by_path[first["workspace_path"]] is first
    assert context.artifacts_by_hash[first["sha256"]] is first
    # invocations are walked once for the output index and once for the receipt-wide fingerprint parts
    assert (receipt["tool_invocations"].passes, receipt["relationships"].passes) == (2, 1)
    action = context.action_identity("compile")
    assert action.kind is EntityKind.BUILD_ACTION and context.action_identity("compile") is action
    assert action == LogicalIdentity.derive(EntityKind.BUILD_ACTION, SNAPSHOT, {"build_unit_id": receipt["build_unit_id"],
                                                                                 "command_id": "compile"})
