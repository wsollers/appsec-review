from __future__ import annotations

from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tarfile
import zipfile

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_artifact_security_analysis import (
    build_job, load_accepted_artifact_security_analysis)
from appsec_review.jobs.job_artifact_security_analysis.formats import (
    ArchiveLimits, classify, inspect_archive, parse_wasm)
from appsec_review.jobs.job_artifact_security_analysis.scanners import ADAPTERS
from appsec_review.retrieval import IndexBuilder, IndexIdentity, RetrievalCore, write_manifest
from appsec_review.retrieval.index import INDEX_SCHEMA
from appsec_review.runtime import GraphRunner, plan_jobs
from appsec_review.storage import RunStore, atomic_json, file_sha256


ROOT = Path(__file__).parents[1]


def test_magic_classification_does_not_trust_extension(tmp_path: Path) -> None:
    elf = tmp_path / "looks-like.jar"
    elf.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 64)
    assert classify(elf, {"kind": "jar"})["format"] == "elf"
    wasm = tmp_path / "module.txt"
    wasm.write_bytes(b"\0asm\x01\0\0\0")
    assert classify(wasm, {"kind": "generated-output"})["format"] == "wasm"
    sdist = tmp_path / "package.data"
    sdist.write_bytes(b"\x1f\x8b" + b"\0" * 20)
    assert classify(sdist, {"kind": "source-distribution", "producer": {"family": "python"}})["family"] == "python"


def test_archive_inspection_rejects_traversal_links_and_bombs(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as value:
        value.writestr("../escape", b"bad")
        link = zipfile.ZipInfo("link")
        link.external_attr = 0o120777 << 16
        value.writestr(link, b"target")
        value.writestr("large.txt", b"A" * 4096, compress_type=zipfile.ZIP_DEFLATED)
    result = inspect_archive(archive, ArchiveLimits(member_bytes=1024, ratio=2))
    assert result["safe"] is False
    assert any("rejected" in gap for gap in result["gaps"])
    assert any("byte limit" in gap or "ratio" in gap for gap in result["gaps"])


def test_archive_inspection_rejects_tar_symlink(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.tar"
    with tarfile.open(archive, "w") as value:
        info = tarfile.TarInfo("link")
        info.type, info.linkname = tarfile.SYMTYPE, "../../escape"
        value.addfile(info)
    result = inspect_archive(archive)
    assert result["safe"] is False and "rejected" in result["gaps"][0]


def test_wasm_parser_rejects_truncated_section() -> None:
    with pytest.raises(ValueError, match="truncated"):
        parse_wasm(b"\0asm\x01\0\0\0\x01\x05\0")


def test_wasm_parser_reports_capabilities_exports_and_limits() -> None:
    data = (b"\0asm\x01\0\0\0" + b"\x02\x0b\x01\x03env\x03foo\x00\x00" +
            b"\x05\x04\x01\x01\x01\x02" + b"\x07\x07\x01\x03run\x00\x00")
    parsed = parse_wasm(data)
    assert parsed["capabilities"] == ["env", "env::foo"]
    assert parsed["exports"] == [{"name": "run", "kind": 0, "index": 0}]
    assert parsed["memories"] == [{"minimum": 1, "shared": 0, "memory64": 0, "maximum": 2}]


def test_scanner_adapters_mount_artifacts_as_data() -> None:
    for capability, adapter in ADAPTERS.items():
        argv = adapter.argv(f"/opt/{capability}", "outputs/sample.bin")
        assert argv[0] == f"/opt/{capability}"
        assert any("/target/sample.bin" in item for item in argv)
        assert argv[0] != next(item for item in argv if "/target/sample.bin" in item)
    parsed = ADAPTERS["spotbugs"].parse(
        b'<BugCollection><BugInstance type="X" category="SECURITY" priority="1"/></BugCollection>')
    assert parsed["finding_count"] == 1


def _fixture(tmp_path: Path, payload: bytes = b"\0asm\x01\0\0\0"):
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"), encoding="utf-8")
    config = load_config(config_path)
    run_id, run_root = RunStore(config.runtime.runs_dir).create(datetime.now(timezone.utc))
    target = tmp_path / "target"
    target.mkdir()
    produced = run_root / "data" / "build" / "wasm" / "module.wasm"
    produced.parent.mkdir(parents=True)
    produced.write_bytes(payload)
    artifact = {"path": produced.relative_to(run_root).as_posix(), "workspace_path": "build/module.wasm",
        "sha256": file_sha256(produced), "size_bytes": produced.stat().st_size, "kind": "wasm-module",
        "build_unit_id": "build-unit-fixture", "mapping": "exact-workspace-path", "mapping_confidence": 1.0}
    fingerprint = "a" * 64
    index_path = run_root / "data" / "indices" / "artifacts" / "fixture.sqlite"
    builder = IndexBuilder(index_path, name="artifacts", fingerprint="b" * 64,
                           target_snapshot=fingerprint, shard_id="language-build")
    index_sha = builder.build()
    index_identity = IndexIdentity("artifacts", INDEX_SCHEMA, index_sha, "b" * 64,
        index_path.relative_to(run_root).as_posix(), {"job": "job_language_build"}, (), "language-build")
    manifest_path = run_root / "data" / "indices" / "manifests" / "language-build.json"
    write_manifest(manifest_path, run_id=run_id, target_snapshot=fingerprint, target_root=target,
                   indexes=[index_identity])
    manifest = {"path": manifest_path.relative_to(run_root).as_posix(),
                "sha256": file_sha256(manifest_path), "size_bytes": manifest_path.stat().st_size}
    accepted_path = run_root / "data" / "upstream" / "accepted-language-builds.json"
    accepted_path.parent.mkdir(parents=True)
    atomic_json(accepted_path, {"schema": "appsec-review/language-build-handoff/1",
        "source_fingerprint": fingerprint, "upstream_project_build_handoff_sha256": "c" * 64,
        "receipts": [{"build_unit_id": "build-unit-fixture", "family": "wasm", "fingerprint": "d" * 64,
                      "executor_identity": "fixture", "capture_identity": "fixture", "artifacts": [artifact]}],
        "gaps": []})
    accepted = {"path": accepted_path.relative_to(run_root).as_posix(), "sha256": file_sha256(accepted_path),
                "size_bytes": accepted_path.stat().st_size}
    handoff_path = run_root / "data" / "jobs" / "job_language_build" / "attempts" / "attempt_0001" / "handoff.json"
    handoff_path.parent.mkdir(parents=True)
    atomic_json(handoff_path, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
        "job_id": "job_language_build", "attempt_id": "attempt_0001", "artifacts": [accepted, manifest],
        "outputs": {"acceptance.publish_handoff": {"artifact": accepted, "index_manifest": manifest}}})
    pointer = handoff_path.parents[2] / "latest.json"
    atomic_json(pointer, {"handoff_path": handoff_path.relative_to(run_root).as_posix(),
                          "handoff_sha256": file_sha256(handoff_path)})
    indexing_summary_path = run_root / "data" / "upstream" / "accepted-artifact-index.json"
    atomic_json(indexing_summary_path, {"schema": "appsec-review/artifact-indexing/1",
        "source_fingerprint": fingerprint, "language_build_handoff_sha256": file_sha256(handoff_path),
        "artifact_shard_count": 1, "reused_shard_count": 0, "artifact_count": 1, "gaps": [],
        "index_manifest": manifest})
    indexing_summary = {"path": indexing_summary_path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(indexing_summary_path), "size_bytes": indexing_summary_path.stat().st_size}
    indexing_handoff_path = (run_root / "data" / "jobs" / "job_artifact_indexing" / "attempts" /
                             "attempt_0001" / "handoff.json")
    indexing_handoff_path.parent.mkdir(parents=True)
    atomic_json(indexing_handoff_path, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
        "job_id": "job_artifact_indexing", "attempt_id": "attempt_0001",
        "artifacts": [indexing_summary, manifest],
        "outputs": {"acceptance.publish_handoff": {"artifact": indexing_summary, "index_manifest": manifest}}})
    atomic_json(indexing_handoff_path.parents[2] / "latest.json", {
        "handoff_path": indexing_handoff_path.relative_to(run_root).as_posix(),
        "handoff_sha256": file_sha256(indexing_handoff_path)})
    return config, run_id, run_root, target, fingerprint, produced


def test_job_isolates_scanner_failure_retains_raw_output_and_indexes_siblings(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = _fixture(tmp_path)
    calls: list[str] = []
    def scanner(capability, path, artifact, timeout, limit):
        calls.append(capability)
        if capability == "grype":
            raise RuntimeError("fixture scanner failure")
        return {"stdout": b'{"packages":[]}', "stderr": b"", "exit_code": 0,
                "observation": {"packages": []},
                "tool_identity": {"scanner": capability, "image": "sha256:" + "e" * 64, "rules": "fixture"}}
    outcome = GraphRunner(config, [build_job(scanner_runner=scanner)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_artifact_security_analysis(run_root)
    assert accepted["artifact_count"] == 1
    assert accepted["observation_count"] >= 5
    assert accepted["capabilities"]["grype"]["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert accepted["capabilities"]["syft"]["observation_count"] == 1
    assert set(calls) == {"blint", "syft", "grype", "osv"}
    raw = list((run_root / "data" / "jobs" / "job_artifact_security_analysis" / "attempts").rglob("stdout.bin"))
    assert raw and all(path.is_file() for path in raw)
    manifest = run_root / accepted["index_manifest"]["path"]
    assert file_sha256(manifest) == accepted["index_manifest"]["sha256"]
    results = RetrievalCore(config.runtime.runs_dir, run_id).find(
        kind="tool_observation", indexes=("observations",), limit=100)
    observation = next(item for item in results["results"] if item["kind"] == "tool_observation")
    payload = observation["payload"]
    assert "raw_artifacts" not in payload and payload["evidence_identities"]
    for identity in payload["evidence_identities"]:
        raw_path = run_root / identity["relative_path"]
        assert raw_path.is_file() and file_sha256(raw_path) == identity["sha256"]


def test_changed_accepted_artifact_is_an_integrity_failure(tmp_path: Path) -> None:
    config, run_id, _run_root, target, fingerprint, produced = _fixture(tmp_path)
    produced.write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="partial failure"):
        GraphRunner(config, [build_job()]).run(target_root=target,
            source_fingerprint=fingerprint, run_id=run_id)


def test_resume_reuses_verified_artifact_capability_shards(tmp_path: Path) -> None:
    config, run_id, _run_root, target, fingerprint, _ = _fixture(tmp_path)
    first_calls: list[str] = []
    def scanner(capability, path, artifact, timeout, limit):
        first_calls.append(capability)
        return {"stdout": b"{}", "stderr": b"", "exit_code": 0, "observation": {},
                "tool_identity": {"scanner": capability, "image": "fixture", "rules": "fixture"}}
    job = build_job(scanner_runner=scanner)
    GraphRunner(config, [job]).run(target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert first_calls
    first_calls.clear()
    GraphRunner(config, [job]).run(target_root=target, source_fingerprint=fingerprint, run_id=run_id,
                                   force_from="job_artifact_security_analysis")
    assert first_calls == []


def test_dagster_graph_exposes_independent_capability_units() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    graph = plan_jobs((build_job(),), config)
    assert graph.node("job_artifact_security_analysis.analyze.native").dependencies == (
        "job_artifact_security_analysis.load.accepted_artifacts",)
    assert "job_artifact_security_analysis.analyze.wasm" in graph.node(
        "job_artifact_security_analysis.index.observations").dependencies
