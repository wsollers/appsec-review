from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import (
    INDEX_SCHEMA, ArtifactQueryRequest, EntityKind, EntityRecord, IndexBuilder, IndexIdentity,
    LogicalIdentity, RelationKind, RelationRecord, RetrievalCore, index_fingerprint, write_manifest,
)
from appsec_review.storage import atomic_json, file_sha256


RUN_ID = "2026-10-08-0042"


def _artifact_fixture(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    runs = tmp_path / "runs"
    run_root = runs / RUN_ID
    attempt = run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001"
    attempt.mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir()
    snapshot = "target-sha256:" + "1" * 64
    ids = {
        "action": LogicalIdentity.derive(EntityKind.BUILD_ACTION, snapshot, {"command": "link-1"}).value,
        "wasm": LogicalIdentity.derive(EntityKind.WASM_MODULE, snapshot, {"sha256": "a" * 64}).value,
        "package": LogicalIdentity.derive(EntityKind.PACKAGE, snapshot, {"sha256": "b" * 64}).value,
        "member": LogicalIdentity.derive(EntityKind.ARCHIVE_MEMBER, snapshot, {"member": "lib/A.class"}).value,
        "observation": LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"scanner": "syft"}).value,
        "finding": LogicalIdentity.derive(EntityKind.FINDING_PACKAGE, snapshot, {"cve": "CVE-2099-0001"}).value,
    }
    indexes: list[IndexIdentity] = []

    def build(name: str, shard: str, entities: list[EntityRecord], relations: list[RelationRecord],
              status: str = "complete", gap: str | None = None) -> None:
        fingerprint = index_fingerprint(
            name=name, target_snapshot=snapshot, producer_artifacts=[{"sha256": shard}],
            tool_identity={"fixture": shard}, parser_identity="fixture/1",
            normalizer_identity="fixture/1", mapping_identity="fixture/1",
        )
        path = run_root / "data" / "indices" / name / shard / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name=name, fingerprint=fingerprint,
                               target_snapshot=snapshot, shard_id=shard)
        for entity in entities:
            builder.add_entity(entity)
        for relation in relations:
            builder.add_relation(relation)
        builder.add_coverage(shard, status, gap)
        sha = builder.build()
        indexes.append(IndexIdentity(name, INDEX_SCHEMA, sha, fingerprint,
            path.relative_to(run_root).as_posix(), {"fixture": shard}, (gap,) if gap else (), shard))

    build("build", "actions", [EntityRecord(
        LogicalIdentity.parse(ids["action"]), "link-1", "link package", "build action", {"command_id": "link-1"})], [])
    build("artifacts", "catalog-rust-wasm", [EntityRecord(
        LogicalIdentity.parse(ids["wasm"]), "a" * 64, "service.wasm", "wasm-module service.wasm", {
            "sha256": "a" * 64, "format": "wasm-module", "kind": "wasm-module",
            "artifact_family": "wasm_module", "language": "rust", "producer_family": "rust",
            "runtime": "wasi", "platform": "linux", "architecture": "wasm32",
            "build_unit_id": "unit-rust", "project": "payments", "component": "gateway",
            "package": "gateway-wasm", "purl": "pkg:cargo/gateway@1.0.0",
            "workspace_path": "target/service.wasm", "path": "data/protected/service.wasm",
            "argv": ["secret-command"], "stdout": "raw stdout", "stderr": "raw stderr",
            "raw_artifacts": [{"path": "protected/stdout.bin"}], "environment": {"TOKEN": "secret"},
        })], [])
    build("artifacts", "catalog-java-package", [EntityRecord(
        LogicalIdentity.parse(ids["package"]), "b" * 64, "service.jar", "jar service.jar", {
            "sha256": "b" * 64, "kind": "jar", "artifact_family": "package",
            "producer_family": "java", "runtime": "jvm", "platform": "linux",
            "architecture": "any", "build_unit_id": "unit-java", "project_id": "payments",
            "component_id": "worker", "package_id": "service", "package_purl": "pkg:maven/x/service@1",
            "workspace_path": "build/service.jar",
        })], [])
    build("artifacts", "members-bbbbbbbbbbbbbbbbbbbbbbbb", [EntityRecord(
        LogicalIdentity.parse(ids["member"]), "lib/A.class", "A.class", "lib/A.class", {
            "member_path": "lib/A.class", "parent_artifact": ids["package"], "size_bytes": 42,
        })], [RelationRecord(RelationKind.CONTAINS, ids["package"], ids["member"], True, 1.0)])
    build("artifacts", "relations-aaaaaaaaaaaaaaaaaaaaaaaa", [], [
        RelationRecord(RelationKind.GENERATED_FROM, ids["wasm"], ids["action"], True, 1.0),
        RelationRecord(RelationKind.LINKS_INTO, ids["wasm"], ids["package"], False, 0.7,
                       "link map matched two generated outputs", {"argv": ["hidden-link-command"]}),
    ])
    build("observations", "artifact-security", [EntityRecord(
        LogicalIdentity.parse(ids["observation"]), "syft-1", "inventory", "artifact inventory", {
            "artifact": {"sha256": "a" * 64, "build_unit_id": "unit-rust"},
            "classification": {"format": "wasm-module", "platform": "linux"},
            "scanner_identity": "syft@1", "tool_identity": {"tool": "syft", "id": "syft@1"},
        })], [RelationRecord(RelationKind.OBSERVED_AT, ids["observation"], ids["wasm"], True, 1.0)])
    build("evidence", "artifact-cves", [EntityRecord(
        LogicalIdentity.parse(ids["finding"]), "CVE-2099-0001", "CVE-2099-0001", "CVE evidence", {
            "artifact": {"sha256": "a" * 64}, "scanner_identity": "osv@1", "cve": "CVE-2099-0001",
        })], [RelationRecord(RelationKind.SUPPORTS, ids["finding"], ids["observation"], True, 1.0)])
    build("observations", "scanner-unavailable", [], [], "unavailable", "grype scanner unavailable")

    manifest_path = run_root / "data" / "indices" / "manifests" / "fixture.json"
    write_manifest(manifest_path, run_id=RUN_ID, target_snapshot=snapshot,
                   target_root=target, indexes=indexes)
    manifest = {"path": manifest_path.relative_to(run_root).as_posix(),
                "sha256": file_sha256(manifest_path), "size_bytes": manifest_path.stat().st_size}
    handoff_path = attempt / "handoff.json"
    atomic_json(handoff_path, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
        "job_id": "fixture", "attempt_id": "attempt_0001", "artifacts": [manifest], "outputs": {}})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff_path.relative_to(run_root).as_posix(),
        "handoff_sha256": file_sha256(handoff_path), "manifest_path": manifest["path"],
        "manifest_sha256": manifest["sha256"],
    })
    return runs, ids


@pytest.mark.parametrize(("filters", "expected"), [
    ({"sha256": "a" * 64}, "wasm"), ({"kind": "wasm_module"}, "wasm"),
    ({"format": "wasm-module"}, "wasm"), ({"language": "rust"}, "wasm"),
    ({"runtime": "wasi"}, "wasm"), ({"platform": "linux", "architecture": "wasm32"}, "wasm"),
    ({"build_unit": "unit-rust"}, "wasm"), ({"project": "payments", "component": "gateway"}, "wasm"),
    ({"package": "gateway-wasm"}, "wasm"), ({"purl": "pkg:cargo/gateway@1.0.0"}, "wasm"),
    ({"scanner": "syft@1"}, "observation"), ({"tool": "syft"}, "observation"),
    ({"coverage_status": "unavailable", "shard": "scanner-unavailable"}, None),
])
def test_all_exact_artifact_filters(tmp_path: Path, filters: dict[str, str], expected: str | None) -> None:
    runs, ids = _artifact_fixture(tmp_path)
    response = RetrievalCore(runs, RUN_ID).query_artifacts(**filters)
    identities = [item["identity"] for item in response["results"]]
    if expected is None:
        assert identities == []
    else:
        assert ids[expected] in identities
    assert response["run_id"] == RUN_ID
    assert all(set(item) >= {"name", "schema", "sha256", "fingerprint", "shard_id"}
               for item in response["indexes"])
    if expected is None:
        assert any("grype scanner unavailable" in gap for gap in response["coverage_gaps"])


def test_artifact_identity_action_relations_mixed_languages_and_safe_payload(tmp_path: Path) -> None:
    runs, ids = _artifact_fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    exact = core.query_artifacts(ArtifactQueryRequest(artifact_identity=ids["wasm"]))
    assert exact["results"][0]["index_identity"]["shard_id"] == "catalog-rust-wasm"
    serialized = json.dumps(exact)
    assert all(secret not in serialized for secret in (
        "secret-command", "raw stdout", "raw stderr", "protected/stdout.bin", "data/protected/service.wasm"))
    produced = core.query_artifacts(producing_build_action=ids["action"])
    assert [item["identity"] for item in produced["results"]] == [ids["wasm"]]
    java = core.query_artifacts(language="java")
    assert java["results"][0]["identity"] == ids["package"]
    trace = core.trace(identity=ids["wasm"], depth=3)
    assert {item["kind"] for item in trace["results"]} >= {"GENERATED_FROM", "LINKS_INTO", "OBSERVED_AT", "SUPPORTS"}
    assert any(not item["exact"] and item["ambiguity"] for item in trace["results"])
    assert "hidden-link-command" not in json.dumps(trace)
    bounded = core.trace(identity=ids["wasm"], depth=3, limit=1)
    assert bounded["truncated"] and "trace result bound reached" in bounded["coverage_gaps"]


def test_artifact_pagination_cursor_tamper_concurrency_and_late_corruption(tmp_path: Path) -> None:
    runs, _ = _artifact_fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    first = core.query_artifacts(limit=1)
    assert first["pagination"]["next_cursor"]
    second = core.query_artifacts(limit=1, cursor=first["pagination"]["next_cursor"])
    assert first["results"] != second["results"]
    with pytest.raises(ValueError, match="tampered"):
        core.query_artifacts(limit=1, cursor=first["pagination"]["next_cursor"] + "x")
    with ThreadPoolExecutor(max_workers=4) as pool:
        pages = list(pool.map(lambda _: core.query_artifacts(language="rust"), range(12)))
    assert all(page["results"][0]["payload"]["producer_family"] == "rust" for page in pages)
    shard = core.run_root / next(item["relative_path"] for item in core.manifest["indexes"]
                                  if item["shard_id"] == "catalog-rust-wasm")
    with shard.open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(ValueError, match="integrity"):
        core.query_artifacts(language="rust")


def test_artifact_run_isolation_missing_coverage_and_mcp_stdio_parity(tmp_path: Path) -> None:
    runs, ids = _artifact_fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    adapter = RetrievalMcpAdapter(core)
    direct = core.query_artifacts(artifact_identity=ids["wasm"])
    via_adapter = adapter.call("query_artifacts", {"artifact_identity": ids["wasm"]})
    assert {key: value for key, value in direct.items() if key != "duration_ms"} == {
        key: value for key, value in via_adapter.items() if key != "duration_ms"}
    missing = core.query_artifacts(shard="does-not-exist")
    assert missing["results"] == [] and "artifact shard is unavailable" in missing["coverage_gaps"][0]
    process = subprocess.Popen(
        [sys.executable, "-m", "appsec_review.mcp.stdio", "--runs-dir", str(runs), "--run-id", RUN_ID],
        cwd=Path(__file__).parents[1], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
    )
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "query_artifacts", "arguments": {"sha256": "a" * 64}}}
    stdout, stderr = process.communicate(json.dumps(request) + "\n", timeout=20)
    assert process.returncode == 0, stderr
    response = json.loads(stdout)
    assert ids["wasm"] in {
        item["identity"] for item in response["result"]["structuredContent"]["results"]}
    pointer_path = runs / RUN_ID / "data" / "indices" / "accepted.json"
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    atomic_json(pointer_path, {**pointer, "run_id": "2026-10-08-9999"})
    with pytest.raises(ValueError, match="run isolation"):
        RetrievalCore(runs, RUN_ID)
