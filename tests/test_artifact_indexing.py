from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_artifact_indexing import (
    artifact_index_fingerprint,
    build_job,
    canonical_archive_member_identity,
    canonical_artifact_identity,
    load_accepted_artifact_index,
)
from appsec_review.jobs.job_artifact_indexing.job import _finish_shard
from appsec_review.retrieval import (
    INDEX_SCHEMA,
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RetrievalCore,
    index_fingerprint,
    write_manifest,
)
from appsec_review.runtime import GraphRunner
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import atomic_json, file_sha256


ROOT = Path(__file__).parents[1]
RUN_ID = "2026-10-08-0001"


def _identity(run_root: Path, path: Path) -> dict[str, object]:
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _seed(tmp_path: Path):
    config_path = tmp_path / "appsec-review.toml"
    config_text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if "[jobs.job_artifact_indexing]" not in config_text:
        config_text += """

[jobs.job_artifact_indexing]
name = "artifact_indexing"
workers = 8
[jobs.job_artifact_indexing.settings]
catalog_parser_identity = "appsec-review/produced-artifact-catalog/1"
member_extractor_identity = "appsec-review/accepted-archive-member-manifest/1"
member_parser_identity = "appsec-review/archive-member-normalizer/1"
relationship_parser_identity = "appsec-review/produced-artifact-relations/1"
normalizer_identity = "appsec-review/artifact-normalizer/1"
mapping_identity = "appsec-review/receipt-workspace-mapping/1"
[jobs.job_artifact_indexing.steps.load]
workers = 1
[jobs.job_artifact_indexing.steps.load.tasks.accepted_builds]
[jobs.job_artifact_indexing.steps.index]
workers = 8
[jobs.job_artifact_indexing.steps.index.tasks.catalogs]
[jobs.job_artifact_indexing.steps.index.tasks.members]
[jobs.job_artifact_indexing.steps.index.tasks.relationships]
[jobs.job_artifact_indexing.steps.acceptance]
workers = 1
[jobs.job_artifact_indexing.steps.acceptance.tasks.publish_handoff]
"""
    config_path.write_text(config_text, encoding="utf-8")
    config = load_config(config_path)
    target = tmp_path / "target"
    target.mkdir()
    (target / "README.md").write_text("fixture\n", encoding="utf-8")
    snapshot = source_fingerprint(target)
    run_root = config.runtime.runs_dir / RUN_ID
    run_root.mkdir(parents=True)

    specifications = [
        ("build-unit-00000000000000000001", "native", [
            ("build/main.o", "object", b"object-one"),
            ("build/app", "executable", b"\x7fELFapp"),
        ]),
        ("build-unit-00000000000000000002", "dotnet", [
            ("bin/Sample.dll", "managed-assembly", b"MZmanaged"),
        ]),
        ("build-unit-00000000000000000003", "wasm", [
            ("dist/module.wasm", "wasm-module", b"\x00asm\x01\x00\x00\x00"),
        ]),
        ("build-unit-00000000000000000004", "python", [
            ("dist/sample.whl", "wheel", b"PKfixture-wheel"),
        ]),
    ]
    receipts = []
    action_entities = []
    for ordinal, (unit_id, family, artifacts_spec) in enumerate(specifications, 1):
        workspace = run_root / "data" / "build" / family / unit_id / "workspace"
        workspace.mkdir(parents=True)
        artifacts = []
        files = {}
        for relative, kind, content in artifacts_spec:
            path = workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            files[relative] = file_sha256(path)
            artifacts.append({**_identity(run_root, path), "workspace_path": relative,
                              "kind": kind, "build_unit_id": unit_id,
                              "mapping": "exact-workspace-path", "mapping_confidence": 1.0})
        manifest_path = workspace.parent / "workspace-manifest.json"
        atomic_json(manifest_path, {"schema": "appsec-review/build-workspace-manifest/1",
                                    "build_unit_id": unit_id, "files": files})
        command_id = f"command-{ordinal}"
        action = LogicalIdentity.derive(EntityKind.BUILD_ACTION, snapshot,
                                         {"build_unit_id": unit_id, "command_id": command_id})
        action_entities.append(EntityRecord(action, command_id, f"{family} build", family,
                                            {"argv_sha256": str(ordinal) * 64}))
        receipt = {
            "schema": "appsec-review/language-build-receipt/1",
            "fingerprint": str(ordinal) * 64,
            "source_fingerprint": snapshot,
            "upstream_handoff_sha256": "a" * 64,
            "build_unit_id": unit_id,
            "family": family,
            "recipe_identity": str(ordinal + 4) * 64,
            "probe_identity": str(ordinal + 5) * 64,
            "image": {"image_id": f"sha256:{str(ordinal + 6) * 64}",
                      "dependency_hashes": {"lock": str(ordinal + 7) * 64}},
            "workspace": workspace.relative_to(run_root).as_posix(),
            "workspace_manifest": _identity(run_root, manifest_path),
            "commands": [{"command_id": command_id, "argv_sha256": str(ordinal) * 64,
                          "image_id": f"sha256:{str(ordinal + 6) * 64}", "role": "build",
                          "tool_kind": "build-driver"}],
            "tool_invocations": [],
            "artifacts": artifacts,
            "gaps": [],
            "terminal_status": "SUCCEEDED",
            "executor_identity": f"fixture-{family}-executor/1",
            "capture_identity": f"fixture-{family}-capture/1",
        }
        if family == "python":
            receipt["package_members"] = [
                {"package_path": "dist/sample.whl", "member": "sample/__init__.py", "size_bytes": 12},
                {"package_path": "dist/sample.whl", "member": "sample-1.0.dist-info/METADATA", "size_bytes": 24},
            ]
        receipts.append(receipt)

    fingerprint = index_fingerprint(
        name="build", target_snapshot=snapshot, producer_artifacts=[{"fixture": True}],
        tool_identity={"fixture": "build-actions"}, parser_identity="fixture/1",
        normalizer_identity="fixture/1", mapping_identity="fixture/1",
    )
    build_path = run_root / "data" / "indices" / "build" / f"{fingerprint}.sqlite"
    builder = IndexBuilder(build_path, name="build", fingerprint=fingerprint,
                           target_snapshot=snapshot, shard_id="fixture-actions")
    for entity in action_entities:
        builder.add_entity(entity)
    builder.add_coverage("fixture-actions", "complete")
    build_identity = IndexIdentity("build", INDEX_SCHEMA, builder.build(), fingerprint,
                                   build_path.relative_to(run_root).as_posix(), {"fixture": True},
                                   (), "fixture-actions")
    manifest_path = run_root / "data" / "indices" / "manifests" / "language-build.json"
    write_manifest(manifest_path, run_id=RUN_ID, target_snapshot=snapshot,
                   target_root=target, indexes=[build_identity])
    manifest_identity = _identity(run_root, manifest_path)

    attempt = run_root / "data" / "jobs" / "job_language_build" / "attempts" / "attempt_0001"
    accepted_path = attempt / "artifacts" / "language-build" / "accepted-language-builds.json"
    accepted_path.parent.mkdir(parents=True)
    atomic_json(accepted_path, {"schema": "appsec-review/language-build-handoff/1",
                                "source_fingerprint": snapshot,
                                "upstream_project_build_handoff_sha256": "a" * 64,
                                "receipts": receipts, "gaps": []})
    accepted_identity = _identity(run_root, accepted_path)
    handoff_path = attempt / "handoff.json"
    atomic_json(handoff_path, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
        "job_id": "job_language_build", "attempt_id": "attempt_0001",
        "outputs": {"acceptance.publish_handoff": {"artifact": accepted_identity,
                                                     "index_manifest": manifest_identity}},
        "artifacts": [accepted_identity, manifest_identity]})
    latest = run_root / "data" / "jobs" / "job_language_build" / "latest.json"
    atomic_json(latest, {"handoff_path": handoff_path.relative_to(run_root).as_posix(),
                         "handoff_sha256": file_sha256(handoff_path)})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff_path.relative_to(run_root).as_posix(),
        "handoff_sha256": file_sha256(handoff_path),
        "manifest_path": manifest_identity["path"], "manifest_sha256": manifest_identity["sha256"],
    })
    return config, target, snapshot, run_root, receipts, accepted_path, handoff_path, latest


def _publish_changed_language_receipts(run_root: Path, receipts: list[dict], accepted_path: Path,
                                       handoff_path: Path, latest: Path) -> None:
    document = json.loads(accepted_path.read_text(encoding="utf-8"))
    document["receipts"] = receipts
    atomic_json(accepted_path, document)
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    identity = _identity(run_root, accepted_path)
    handoff["outputs"]["acceptance.publish_handoff"]["artifact"] = identity
    handoff["artifacts"] = [identity, handoff["outputs"]["acceptance.publish_handoff"]["index_manifest"]]
    atomic_json(handoff_path, handoff)
    atomic_json(latest, {"handoff_path": handoff_path.relative_to(run_root).as_posix(),
                         "handoff_sha256": file_sha256(handoff_path)})


def test_canonical_artifact_and_archive_member_identities_are_stable_and_strict() -> None:
    artifact = {"workspace_path": "dist/module.wasm", "sha256": "1" * 64,
                "size_bytes": 8, "kind": "wasm-module"}
    first = canonical_artifact_identity("snapshot", "unit", artifact)
    second = canonical_artifact_identity("snapshot", "unit", dict(reversed(list(artifact.items()))))
    assert first == second and first.kind == EntityKind.WASM_MODULE
    member = canonical_archive_member_identity("snapshot", first,
                                                {"member": "pkg/mod.py", "size_bytes": 9})
    assert member.kind == EntityKind.ARCHIVE_MEMBER
    with pytest.raises(ValueError, match="non-canonical"):
        canonical_archive_member_identity("snapshot", first,
                                          {"member": "pkg/../secret", "size_bytes": 9})


def test_fingerprints_bind_relevant_inputs_but_not_scanner_or_mcp_identity() -> None:
    receipt = {"build_unit_id": "unit", "fingerprint": "1" * 64,
               "recipe_identity": "2" * 64, "probe_identity": "3" * 64,
               "upstream_handoff_sha256": "4" * 64, "image": {"image_id": "sha256:" + "5" * 64},
               "workspace_manifest": {"sha256": "6" * 64}, "commands": [],
               "executor_identity": "executor/1", "capture_identity": "capture/1", "family": "native"}
    artifact = {"workspace_path": "a.o", "sha256": "7" * 64, "size_bytes": 1, "kind": "object"}
    arguments = dict(name="artifacts", target_snapshot="snapshot", receipt=receipt,
        artifacts=[artifact], upstream_manifests=["6" * 64], extractor_identity="extractor/1",
        parser_identity="parser/1", normalizer_identity="normalizer/1", mapping_identity="mapping/1")
    first = artifact_index_fingerprint(**arguments)
    assert first == artifact_index_fingerprint(**arguments)
    assert first != artifact_index_fingerprint(**{**arguments, "extractor_identity": "extractor/2"})
    assert "scanner" not in json.dumps(arguments) and "mcp" not in json.dumps(arguments)


def test_mixed_language_partition_resume_selective_invalidation_and_retrieval(tmp_path: Path) -> None:
    config, target, snapshot, run_root, receipts, accepted_path, handoff_path, latest = _seed(tmp_path)
    job = build_job()
    runner = JobRunner(config)
    claim = runner.begin_attempt(job, run_id=RUN_ID, target_root=target, source_fingerprint=snapshot,
                                 upstream_handoffs={"job_language_build": file_sha256(handoff_path)})
    runner.execute_or_reuse_unit(job, claim, "load.accepted_builds")
    catalogs = runner.execute_or_reuse_unit(job, claim, "index.catalogs")
    assert catalogs["shard_count"] == 5
    restarted_catalogs = runner.execute_or_reuse_unit(job, claim, "index.catalogs")
    assert [item["fingerprint"] for item in restarted_catalogs["indexes"]] == [
        item["fingerprint"] for item in catalogs["indexes"]]
    runner.execute_or_reuse_unit(job, claim, "index.members")
    runner.execute_or_reuse_unit(job, claim, "index.relationships")
    runner.execute_or_reuse_unit(job, claim, "acceptance.publish_handoff")
    runner.finalize_attempt(job, claim)

    accepted = load_accepted_artifact_index(run_root)
    assert accepted["artifact_count"] == 5 and accepted["artifact_shard_count"] == 11
    core = RetrievalCore(config.runtime.runs_dir, RUN_ID)
    expected_kinds = {"object_file", "executable", "managed_assembly", "wasm_module", "package",
                      "archive_member"}
    mixed = [item for kind in expected_kinds for item in
             core.find(kind=kind, indexes=("artifacts",), limit=100)["results"]]
    assert {item["kind"] for item in mixed} >= expected_kinds
    package = next(item for item in mixed if item["kind"] == "package")
    trace = core.trace(identity=package["identity"], relations=("CONTAINS",), depth=1)
    assert len(trace["results"]) == 2
    coverage = core.coverage(indexes=("artifacts",))
    assert coverage["results"] and any("ambiguous" in gap for gap in coverage["coverage_gaps"])

    resumed = GraphRunner(config, [job]).run(target_root=target, source_fingerprint=snapshot,
                                              run_id=RUN_ID, force_from="job_artifact_indexing")
    result_path = Path(resumed["jobs"]["job_artifact_indexing"]["attempt_root"]) / "result.json"
    outputs = json.loads(result_path.read_text(encoding="utf-8"))["outputs"]
    assert outputs["index.catalogs"]["reused_count"] == outputs["index.catalogs"]["shard_count"]
    assert outputs["index.members"]["reused_count"] == outputs["index.members"]["shard_count"]
    assert outputs["index.relationships"]["reused_count"] == outputs["index.relationships"]["shard_count"]

    before = {item["shard_id"]: item["fingerprint"] for item in RetrievalCore(
              config.runtime.runs_dir, RUN_ID).manifest["indexes"] if item["name"] == "artifacts"}
    changed = receipts[0]["artifacts"][0]
    old_relation_shard = next(key for key in before if key.startswith("relations-") and
                              before[key] == artifact_index_fingerprint(
                                  name="artifacts", target_snapshot=snapshot, receipt=receipts[0],
                                  artifacts=[changed],
                                  upstream_manifests=[__import__("hashlib").sha256(json.dumps({
                                      "schema": "appsec-review/build-workspace-manifest/1",
                                      "build_unit_id": receipts[0]["build_unit_id"],
                                      "workspace_path": changed["workspace_path"],
                                      "sha256": changed["sha256"],
                                  }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()],
                                  extractor_identity="none",
                                  parser_identity=config.job("job_artifact_indexing").settings[
                                      "relationship_parser_identity"],
                                  normalizer_identity=config.job("job_artifact_indexing").settings[
                                      "normalizer_identity"],
                                  mapping_identity=config.job("job_artifact_indexing").settings[
                                      "mapping_identity"]))
    changed_path = run_root / changed["path"]
    changed_path.write_bytes(b"object-two")
    changed["sha256"] = file_sha256(changed_path)
    changed["size_bytes"] = changed_path.stat().st_size
    workspace_manifest = run_root / receipts[0]["workspace_manifest"]["path"]
    manifest_doc = json.loads(workspace_manifest.read_text(encoding="utf-8"))
    manifest_doc["files"][changed["workspace_path"]] = changed["sha256"]
    atomic_json(workspace_manifest, manifest_doc)
    receipts[0]["workspace_manifest"] = _identity(run_root, workspace_manifest)
    _publish_changed_language_receipts(run_root, receipts, accepted_path, handoff_path, latest)
    GraphRunner(config, [job]).run(target_root=target, source_fingerprint=snapshot,
                                    run_id=RUN_ID, force_from="job_artifact_indexing")
    after = {item["shard_id"]: item["fingerprint"] for item in RetrievalCore(
             config.runtime.runs_dir, RUN_ID).manifest["indexes"] if item["name"] == "artifacts"}
    changed_shards = {key for key in before if before[key] != after.get(key)}
    assert changed_shards == {
        "catalog-build-unit-00000000000000000001-object_file",
        old_relation_shard,
    }


def test_tamper_corruption_and_concurrent_reuse_stop_or_reuse_safely(tmp_path: Path) -> None:
    config, target, snapshot, run_root, *_ = _seed(tmp_path)
    job = build_job()
    GraphRunner(config, [job]).run(target_root=target, source_fingerprint=snapshot, run_id=RUN_ID)
    accepted = load_accepted_artifact_index(run_root)
    assert accepted["artifact_shard_count"]

    concurrent_path = run_root / "data" / "indices" / "artifacts" / "concurrent.sqlite"
    builders = [IndexBuilder(concurrent_path, name="artifacts", fingerprint="f" * 64,
                             target_snapshot=snapshot, shard_id="concurrent") for _ in range(2)]
    for builder in builders:
        builder.add_coverage("concurrency", "complete")
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda builder: _finish_shard(builder, concurrent_path), builders))
    assert {reused for _sha, reused in outcomes} == {False, True}
    assert len({sha for sha, _reused in outcomes}) == 1

    core = RetrievalCore(config.runtime.runs_dir, RUN_ID)
    shard = next(item for item in core.manifest["indexes"] if item["name"] == "artifacts")
    path = run_root / shard["relative_path"]
    path.write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="integrity|corrupt"):
        RetrievalCore(config.runtime.runs_dir, RUN_ID)
