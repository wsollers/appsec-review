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
from appsec_review.jobs.job_artifact_security_analysis.scanners import ADAPTERS, _execution_token
from appsec_review.retrieval import IndexBuilder, IndexIdentity, RetrievalCore, write_manifest
from appsec_review.retrieval.index import INDEX_SCHEMA
from appsec_review.runtime import GraphRunner, plan_jobs
from appsec_review.storage import RunStore, atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff


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
    blint = ADAPTERS["blint"].argv("/opt/blint", "sample.bin")
    assert blint == ("/opt/blint", "--no-banner", "--no-error", "--quiet", "--src",
                     "/target/sample.bin", "--reports", "/scratch")
    # blint 3.4.0 writes findings.json/<name>-metadata.json; the runner assembles this document.
    assert ADAPTERS["blint"].output_file == "/scratch/blint-report.json"
    assert "--lockfile" in ADAPTERS["osv"].argv("/opt/osv", "Cargo.lock")
    assert "--recursive" not in ADAPTERS["osv"].argv("/opt/osv", "Cargo.lock")


def test_scanner_execution_tokens_distinguish_equal_content_artifacts() -> None:
    shared = {"sha256": "a" * 64}
    first = _execution_token("syft", {**shared, "canonical_identity": "asr:managed_assembly:first"})
    second = _execution_token("syft", {**shared, "canonical_identity": "asr:managed_assembly:second"})
    assert first != second


def test_spotbugs_failed_or_malformed_output_is_a_retained_gap(tmp_path: Path) -> None:
    for exit_code in (1, 0):
        case = tmp_path / str(exit_code)
        case.mkdir()
        config, run_id, run_root, target, fingerprint, _ = _fixture(
            case, payload=b"\xca\xfe\xba\xbe" + b"\0" * 32)

        def scanner(capability, path, artifact, timeout, limit):
            result = {"stdout": b"", "stderr": b"scanner failed" if exit_code else b"",
                      "exit_code": exit_code if capability == "spotbugs" else 0,
                      "observation": {} if capability != "spotbugs" else None,
                      "tool_identity": {"scanner": capability, "image": "fixture", "rules": "fixture"}}
            if capability == "spotbugs":
                result["payload"] = b""
            return result

        outcome = GraphRunner(config, [build_job(scanner_runner=scanner)]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
        assert outcome["status"] == "COMPLETED_WITH_GAPS"
        accepted = load_accepted_artifact_security_analysis(run_root)
        assert accepted["capabilities"]["spotbugs"]["terminal_status"] == "COMPLETED_WITH_GAPS"
        assert any(("scanner exited 1" if exit_code else "output could not be parsed") in gap
                   for gap in accepted["capabilities"]["spotbugs"]["gaps"])
        raw = list((run_root / "data" / "jobs" / "job_artifact_security_analysis" / "attempts").glob(
            "*/artifacts/asa/*/spotbugs/parser-input.bin"))
        assert raw and raw[0].read_bytes() == b""


def _fixture(tmp_path: Path, payload: bytes = b"\0asm\x01\0\0\0", *, disable_grype: bool = False,
             duplicate_artifact: bool = False, no_artifacts: bool = False,
             name: str = "module.wasm", kind: str = "wasm-module", declared_releases: bool = True):
    config_path = tmp_path / "appsec-review.toml"
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if declared_releases:
        components = ("platform", "validation", *(adapter.tool_id for adapter in ADAPTERS.values()))
        text = text.replace("[review_policy.releases]", "[review_policy.releases]\n" +
                            "\n".join(f'"{key}" = "fixture/1"' for key in components))
    if not disable_grype:
        text = text.replace("disable_grype = true", "disable_grype = false")
    config_path.write_text(text, encoding="utf-8")
    config = load_config(config_path)
    run_id, run_root = RunStore(config.runtime.runs_dir).create(datetime.now(timezone.utc))
    target = tmp_path / "target"
    target.mkdir()
    produced = run_root / "data" / "build" / "wasm" / name
    produced.parent.mkdir(parents=True)
    produced.write_bytes(payload)
    artifact = {"path": produced.relative_to(run_root).as_posix(), "workspace_path": f"build/{name}",
        "sha256": file_sha256(produced), "size_bytes": produced.stat().st_size, "kind": kind,
        "build_unit_id": "build-unit-fixture", "mapping": "exact-workspace-path", "mapping_confidence": 1.0}
    artifacts = [] if no_artifacts else [artifact]
    if duplicate_artifact:
        duplicate = run_root / "data" / "build" / "wasm" / "module-copy.wasm"
        duplicate.write_bytes(payload)
        artifacts.append({**artifact, "path": duplicate.relative_to(run_root).as_posix(),
                          "workspace_path": "build/module-copy.wasm"})
    fingerprint = "a" * 64
    index_path = run_root / "data" / "indices" / "artifacts" / "fixture.sqlite"
    builder = IndexBuilder(index_path, name="artifacts", fingerprint="b" * 64,
                           target_snapshot=fingerprint, shard_id="language-build")
    index_sha = builder.build()
    index_identity = IndexIdentity("artifacts", INDEX_SCHEMA, index_sha, "b" * 64,
        index_path.relative_to(run_root).as_posix(), {"job": "job_language_build"}, (), "language-build")
    manifest_path = run_root / "data" / "indices" / "manifests" / "language-build.json"
    write_manifest(manifest_path, run_id=run_id, target_snapshot=fingerprint, target_root=target,
                   indexes=[] if no_artifacts else [index_identity])
    manifest = {"path": manifest_path.relative_to(run_root).as_posix(),
                "sha256": file_sha256(manifest_path), "size_bytes": manifest_path.stat().st_size}
    accepted_path = run_root / "data" / "upstream" / "accepted-language-builds.json"
    accepted_path.parent.mkdir(parents=True)
    atomic_json(accepted_path, {"schema": "appsec-review/language-build-handoff/1",
        "source_fingerprint": fingerprint, "upstream_project_build_handoff_sha256": "c" * 64,
        "receipts": [{"build_unit_id": "build-unit-fixture", "family": "wasm", "fingerprint": "d" * 64,
                      "executor_identity": "fixture", "capture_identity": "fixture", "artifacts": artifacts}],
        "gaps": ["no produced artifacts"] if no_artifacts else []})
    accepted = {"path": accepted_path.relative_to(run_root).as_posix(), "sha256": file_sha256(accepted_path),
                "size_bytes": accepted_path.stat().st_size}
    handoff_path = run_root / "data" / "jobs" / "job_language_build" / "attempts" / "attempt_0001" / "handoff.json"
    handoff_path.parent.mkdir(parents=True)
    write_fixture_handoff(run_root, handoff_path, {"status": "ACCEPTED",
        "job_id": "job_language_build", "attempt_id": "attempt_0001", "artifacts": [accepted, manifest],
        "outputs": {"acceptance.publish_handoff": {"artifact": accepted, "index_manifest": manifest}}})
    pointer = handoff_path.parents[2] / "latest.json"
    atomic_json(pointer, {"handoff_path": handoff_path.relative_to(run_root).as_posix(),
                          "handoff_sha256": file_sha256(handoff_path)})
    indexing_summary_path = run_root / "data" / "upstream" / "accepted-artifact-index.json"
    atomic_json(indexing_summary_path, {"schema": "appsec-review/artifact-indexing/1",
        "source_fingerprint": fingerprint, "language_build_handoff_sha256": file_sha256(handoff_path),
        "artifact_shard_count": 0 if no_artifacts else 1, "reused_shard_count": 0,
        "artifact_count": len(artifacts), "gaps": ["no produced artifacts"] if no_artifacts else [],
        "index_manifest": manifest})
    indexing_summary = {"path": indexing_summary_path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(indexing_summary_path), "size_bytes": indexing_summary_path.stat().st_size}
    indexing_handoff_path = (run_root / "data" / "jobs" / "job_artifact_indexing" / "attempts" /
                             "attempt_0001" / "handoff.json")
    indexing_handoff_path.parent.mkdir(parents=True)
    write_fixture_handoff(run_root, indexing_handoff_path, {"status": "ACCEPTED",
        "job_id": "job_artifact_indexing", "attempt_id": "attempt_0001",
        "artifacts": [indexing_summary, manifest],
        "outputs": {"acceptance.publish_handoff": {"artifact": indexing_summary, "index_manifest": manifest}}})
    atomic_json(indexing_handoff_path.parents[2] / "latest.json", {
        "handoff_path": indexing_handoff_path.relative_to(run_root).as_posix(),
        "handoff_sha256": file_sha256(indexing_handoff_path)})
    return config, run_id, run_root, target, fingerprint, produced


def test_no_artifacts_is_a_named_gap_with_verified_empty_index(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = _fixture(tmp_path, no_artifacts=True)
    outcome = GraphRunner(config, [build_job()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_artifact_security_analysis(run_root)
    assert accepted["artifact_count"] == accepted["observation_count"] == 0
    assert "no target or produced artifacts were available for artifact security analysis" in accepted["gaps"]


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
    assert accepted["observation_count"] >= 4
    assert accepted["capabilities"]["grype"]["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert accepted["capabilities"]["syft"]["observation_count"] == 1
    # blint parses ELF/PE/Mach-O/APK only and osv-scanner lockfiles only: the WebAssembly fixture
    # is SKIPPED_NA for both, never launched.
    assert set(calls) == {"syft", "grype"}
    assert accepted["capabilities"]["osv"]["not_applicable_inputs"]["count"] == 1
    blint = accepted["capabilities"]["blint"]
    assert blint["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert blint["gaps"] == ["build/module.wasm: delivery status is unknown (delivery_fact_unavailable)"]
    assert blint["not_applicable_inputs"]["count"] == 1
    assert blint["not_applicable_inputs"]["items"][0]["reason_code"] == "INPUT_FORMAT_UNSUPPORTED"
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


def test_no_package_scan_exposes_native_reference_closure_without_a_finding(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = _fixture(
        tmp_path, payload=b"version = 3\n", name="Cargo.lock", kind="lockfile")
    def scanner(capability, path, artifact, timeout, limit):
        execution = (run_root / "data" / "jobs" / "job_artifact_security_analysis" / "attempts" /
                     "attempt_0001" / "steps" / "analyze" / "tasks" / "osv" / "containers" /
                     "fixture" / "execution.json")
        atomic_json(execution, {"exit_code": 128, "tool": "osv"})
        return {"stdout": b"No package sources found", "stderr": b"", "exit_code": 128,
                "payload": b'{"results":[]}', "execution_receipt": {
                    "path": execution.relative_to(run_root).as_posix(), "sha256": file_sha256(execution),
                    "size_bytes": execution.stat().st_size}}
    GraphRunner(config, [build_job(scanner_runner=scanner)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    handoff_path = run_root / json.loads((
        run_root / "data" / "jobs" / "job_artifact_security_analysis" / "latest.json").read_bytes())["handoff_path"]
    handoff = json.loads(handoff_path.read_bytes())
    output = json.loads((handoff_path.parent / "steps" / "analyze" / "tasks" / "osv" /
                         "result.json").read_bytes())
    assert not output["observations"] and output["not_applicable_inputs"]["count"] == 1
    scan, = output["not_applicable_scan_artifacts"]
    assert scan["result_artifact"] and scan["native_output"]["retention_receipt"]
    assert scan["execution_receipt"]["path"] == scan["native_output"]["execution_reference"]["path"]
    assert (run_root / scan["native_output"]["artifact"]["path"]).read_bytes() == b'{"results":[]}'
    assert scan["native_output"]["artifact"] in handoff["artifacts"]


def test_finding_record_bound_is_reported_in_publication_coverage(tmp_path: Path, monkeypatch) -> None:
    from appsec_review.jobs.job_artifact_security_analysis import findings
    monkeypatch.setattr(findings, "FINDING_BOUND", 1)
    config, run_id, run_root, target, fingerprint, _ = _fixture(tmp_path)
    def scanner(capability, path, artifact, timeout, limit):
        payload = ({"matches": [{"vulnerability": {"id": "CVE-A"}}, {"vulnerability": {"id": "CVE-B"}}]}
                   if capability == "grype" else {"artifacts": []})
        return {"stdout": b"", "stderr": b"", "exit_code": 0, "payload": json.dumps(payload).encode()}
    GraphRunner(config, [build_job(scanner_runner=scanner)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    accepted = load_accepted_artifact_security_analysis(run_root)
    assert accepted["finding_count"] == 1
    assert any("2 findings; only the first 1 are recorded" in gap for gap in accepted["gaps"])


@pytest.mark.parametrize("declared_releases", (False, True))
def test_resume_reuses_verified_artifact_capability_shards(tmp_path: Path, declared_releases: bool) -> None:
    config, run_id, _run_root, target, fingerprint, _ = _fixture(
        tmp_path, declared_releases=declared_releases)
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
    assert bool(first_calls) is not declared_releases


def test_equal_content_artifacts_have_distinct_observation_checkpoints(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = _fixture(
        tmp_path, duplicate_artifact=True)

    def scanner(capability, path, artifact, timeout, limit):
        return {"stdout": b"{}", "stderr": b"", "exit_code": 0, "observation": {},
                "tool_identity": {"scanner": capability, "image": "fixture", "rules": "fixture"}}

    outcome = GraphRunner(config, [build_job(scanner_runner=scanner)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_artifact_security_analysis(run_root)
    assert accepted["artifact_count"] == 2
    assert accepted["capabilities"]["syft"]["observation_count"] == 2
    shards = list((run_root / "data" / "artifact-security" / "shards" / "syft").glob(
        "*/result.json"))
    assert len(shards) == 2


def test_dagster_graph_exposes_independent_capability_units() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    graph = plan_jobs((build_job(),), config)
    assert graph.node("job_artifact_security_analysis.analyze.native").dependencies == (
        "job_artifact_security_analysis.load.accepted_artifacts",)
    assert "job_artifact_security_analysis.analyze.wasm" in graph.node(
        "job_artifact_security_analysis.index.observations").dependencies


def test_configured_disabled_grype_never_calls_runner_and_publishes_gap(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = _fixture(tmp_path, disable_grype=True)
    calls: list[str] = []
    def scanner(capability, path, artifact, timeout, limit):
        calls.append(capability)
        return {"stdout": b"{}", "stderr": b"", "exit_code": 0, "observation": {},
                "tool_identity": {"scanner": capability, "image": "fixture", "rules": "fixture"}}
    GraphRunner(config, [build_job(scanner_runner=scanner)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    accepted = load_accepted_artifact_security_analysis(run_root)
    assert "grype" not in calls
    assert accepted["capabilities"]["grype"]["terminal_status"] == "NOT_APPLICABLE"
    assert "configured disabled" in accepted["capabilities"]["grype"]["gaps"][0]


def test_runtime_dependency_rows_reach_packages_and_only_their_binaries_reach_blint(
        tmp_path: Path, monkeypatch) -> None:
    from types import SimpleNamespace

    from appsec_review.jobs.job_artifact_security_analysis import job as security

    payload = tmp_path / "node_modules" / "express" / "package.json"
    payload.parent.mkdir(parents=True)
    payload.write_text('{"name":"express","version":"4.19.2"}')
    addon = tmp_path / "node_modules" / "sharp" / "build" / "Release" / "sharp.node"
    addon.parent.mkdir(parents=True)
    addon.write_bytes(b"\x7fELF-native-addon")
    evidence = {"kind": "npm-installed-record", "entry": "node_modules/express"}
    artifact = {"path": "node_modules/express/package.json", "workspace_path": "node_modules/express/package.json",
                "kind": "package-metadata", "sha256": file_sha256(payload), "artifact_id": "runtime-dep",
                "scope_role": "runtime_dependency", "delivery_evidence": evidence}
    binary = {"path": "node_modules/sharp/build/Release/sharp.node",
              "workspace_path": "node_modules/sharp/build/Release/sharp.node", "kind": "native-addon",
              "sha256": file_sha256(addon), "artifact_id": "runtime-addon", "scope_role": "runtime_dependency",
              "delivery_evidence": {**evidence, "entry": "node_modules/sharp"}}
    dev_binary = {**binary, "artifact_id": "dev-addon", "scope_role": "build_dependency"}
    scanned: list[tuple[str, str]] = []

    def fake_scan(unit, row, capability, runner):
        scanned.append((capability, row["artifact_id"]))
        return {"artifact": row, "gaps": [], "terminal_status": "SUCCEEDED"}

    original_scan = security._scan_one
    monkeypatch.setattr(security, "classify", lambda path, row, **kwargs: (
        {"family": "native", "format": "elf"} if row["kind"] == "native-addon" else
        {"family": "node", "format": "json"}))
    monkeypatch.setattr(security, "_scan_one", fake_scan)
    unit = SimpleNamespace(job=SimpleNamespace(run_root=tmp_path),
                           output=lambda _: {"artifacts": [artifact, binary, dev_binary]})
    units = {item.unit_id: item for item in security.build_job(scanner_runner=lambda *args: None).units}
    packages = units["analyze.packages"].handler(unit)
    native = units["analyze.native"].handler(unit)
    blint = units["analyze.blint"].handler(unit)
    assert scanned == [("packages", "runtime-dep"), ("blint", "runtime-addon")]
    assert packages["observation_count"] == 1 and packages["gaps"] == []
    assert native["observation_count"] == 0 and native["gaps"] == []
    assert {row["artifact_id"] for row in native["scope_dispositions"] if row["selected"]} == set()
    refused = native["scope_dispositions"][0]
    assert refused["selected"] is False and refused["analysis_lane"] == "supply_chain"
    assert refused["reason"] == "accepted-runtime-dependency-review"
    assert refused["delivery_status"] == "not_established"
    assert blint["observation_count"] == 1 and blint["gaps"] == []
    assert {row["artifact_id"]: row["selected"] for row in blint["scope_dispositions"]} == {
        "runtime-dep": False, "runtime-addon": True, "dev-addon": False}
    with pytest.raises(security.FrameworkIntegrityError, match="scope excludes native"):
        original_scan(unit, artifact, "native", None)
    with pytest.raises(security.FrameworkIntegrityError, match="scope excludes blint"):
        original_scan(unit, dev_binary, "blint", None)
