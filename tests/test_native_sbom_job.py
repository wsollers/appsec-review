from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_dependency_intelligence import build_job, load_accepted_dependency_intelligence
from appsec_review.jobs.job_dependency_intelligence.integration import (
    NativeSbomInfrastructureError, accepted_framework, convert_syft,
)
from appsec_review.jobs.job_dependency_intelligence.native_sbom_contracts import NativeInputIntegrityError
from appsec_review.jobs.job_evidence_collection.adapters import _syft_parser
from appsec_review.jobs.job_evidence_collection.evidence import build_envelope
from appsec_review.observability import aggregate_run_metrics
from appsec_review.retrieval import EntityKind, IndexBuilder, IndexIdentity, RetrievalCore, write_manifest
from appsec_review.runtime import UnitContext
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from appsec_review.storage.shared import reference
from tests.handoff_fixture import write_fixture_handoff


ROOT = Path(__file__).parents[1]
SNAPSHOT = "f" * 64
RUN_ID = "2026-10-28-0001"
CREATED = "2026-10-28T00:00:00Z"


def _write(root: Path, name: str, document: dict) -> dict:
    path = root / "data" / "native-sbom-fixtures" / name
    atomic_json(path, document)
    return reference(root, path)


def _framework(root: Path, job: str, outputs: dict, artifacts: list[dict]) -> dict:
    path = root / "data" / "native-sbom-fixtures" / (job + ".json")
    write_fixture_handoff(root, path, {
        "status": "ACCEPTED", "job_id": job,
        "run_id": RUN_ID, "attempt_id": "attempt_0001", "source_fingerprint": SNAPSHOT,
        "started_at": CREATED, "outputs": outputs, "artifacts": artifacts,
    })
    identity = reference(root, path)
    atomic_json(root / "data" / "jobs" / job / "latest.json",
                {"handoff_path": identity["path"], "handoff_sha256": identity["sha256"]})
    return identity


def _manifest(root: Path, target: Path, name: str, *, observation: dict | None = None) -> tuple[dict, list[dict]]:
    from dataclasses import asdict
    from appsec_review.retrieval import EntityRecord, LogicalIdentity
    path = root / "data" / "indices" / f"{name}.sqlite"
    builder = IndexBuilder(path, name="observations" if name == "observations" else "artifacts",
                           fingerprint="a" * 64, target_snapshot=SNAPSHOT, shard_id=name)
    if observation:
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"name": name})
        builder.add_entity(EntityRecord(identity, "syft-1", "package", "zlib", observation))
    digest = builder.build()
    index = IndexIdentity(builder.name, "appsec-review/retrieval-index/2", digest, "a" * 64,
                          path.relative_to(root).as_posix(), {"producer": "tool-syft"}, (), name)
    manifest_path = root / "data" / "indices" / f"{name}-manifest.json"
    write_manifest(manifest_path, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=target,
                   indexes=(index,))
    return reference(root, manifest_path), [reference(root, path), reference(root, manifest_path)]


def seed(tmp_path: Path, *, files: dict[str, bytes] | None = None, source_syft: bool = True,
         catalog_gaps: list[str] | None = None):
    config = load_config(ROOT / "appsec-review.toml")
    config = replace(config, runtime=replace(config.runtime, runs_dir=tmp_path / "runs",
                                            metadata_dir=tmp_path / "metadata"))
    root = config.runtime.runs_dir / RUN_ID
    root.mkdir(parents=True)
    JobRunner(config)._bind_configuration(root)
    target = tmp_path / "target"
    target.mkdir()
    files = files if files is not None else {
        "third_party/zlib/zlib.h": b'#define ZLIB_VERSION "1.3.1"\r\n',
        "third_party/zlib/README": b"Package: zlib\nVersion: 1.3.1\n",
    }
    catalog_files = []
    for relative, payload in files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        catalog_files.append({"path": relative, "sha256": file_sha256(path), "size_bytes": len(payload)})
    partition = _write(root, "partition.json", {
        "schema": "appsec-review/repository-partition/1", "source_fingerprint": SNAPSHOT,
        "files": catalog_files, "gaps": catalog_gaps or [], "configured_exclusions": [],
    })
    dependencies = _write(root, "dependencies.json", {
        "schema": "appsec-review/dependency-catalog/1", "dependencies": [],
    })
    catalog = _write(root, "catalog.json", {
        "schema": "appsec-review/target-catalog/1", "source_fingerprint": SNAPSHOT,
        "artifacts": {"repository_discovery.partition_repository": partition,
                      "component_discovery.catalog_dependencies": dependencies},
    })
    _framework(root, "job_target_catalog",
               {"publish_catalog.publish_handoff": {"artifact": catalog}},
               [partition, dependencies, catalog])
    language = _write(root, "language.json", {
        "schema": "appsec-review/language-build-handoff/1", "source_fingerprint": SNAPSHOT,
        "receipts": [], "gaps": [],
    })
    _framework(root, "job_language_build",
               {"acceptance.publish_handoff": {"artifact": language}}, [language])
    artifact_manifest, artifact_members = _manifest(root, target, "artifact")
    artifact = _write(root, "artifact-index.json", {
        "schema": "appsec-review/artifact-indexing/1", "source_fingerprint": SNAPSHOT,
        "target_artifacts": [], "gaps": [], "index_manifest": artifact_manifest,
    })
    _framework(root, "job_artifact_indexing", {
        "acceptance.publish_handoff": {"artifact": artifact, "index_manifest": artifact_manifest},
    }, [artifact, *artifact_members])
    evidence_manifest, evidence_members = _manifest(root, target, "observations", observation={
        "package": "zlib", "version": "1.3.1", "purl": "pkg:generic/zlib@1.3.1",
    } if files else None)
    syft = _write(root, "syft.json", {
        "artifacts": [], "artifactRelationships": [], "descriptor": {"name": "syft", "version": "1.52.0"},
        "source": {"id": "test", "name": "fixture", "version": "", "type": "directory",
                   "metadata": {"path": "/target"}},
        "schema": {"version": "16.1.10", "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.10.json"},
    })
    envelope = _write(root, "syft-evidence.json", {
        "schema": "appsec-review/static-tool-evidence/1", "target_fingerprint": SNAPSHOT,
        "source_inventory": syft, "raw_artifacts": [syft], "exclusions_and_gaps": [],
    })
    outputs = {"evidence_publication.publish_handoff": {"index_manifest": evidence_manifest}}
    if source_syft:
        outputs["software_inventory.syft_scan"] = {"artifact": envelope, "terminal_status": "SUCCEEDED"}
    _framework(root, "job_evidence_collection", outputs,
               [*evidence_members, syft, envelope])
    return config, root, target


def converter(source: dict, *, unit: UnitContext) -> dict:
    document = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "fixture", "documentNamespace": "https://example.invalid/fixture",
        "creationInfo": {"creators": ["Tool: syft-1.52.0"], "created": CREATED},
        "packages": [],
    }
    path = unit.unit_root / "baseline.spdx.json"
    atomic_json(path, document)
    return {"document": document, "artifact": reference(unit.job.run_root, path),
            "source_artifact": source, "tool_identity": {"tool_id": "tool-syft", "image_id": "sha256:" + "a" * 64}}


def execute(config, root: Path, target: Path, *, convert=converter):
    job = build_job(syft_converter=convert)
    return JobRunner(config).run(job, run_id=RUN_ID, target_root=target, source_fingerprint=SNAPSHOT)


def test_accepts_buildless_catalog_and_bound_source_inventory(tmp_path: Path) -> None:
    config, root, target = seed(tmp_path)
    runner, job = JobRunner(config), build_job()
    claim = runner.begin_attempt(job, run_id=RUN_ID, target_root=target, source_fingerprint=SNAPSHOT)
    loaded = runner.execute_or_reuse_unit(job, claim, "inputs.load_accepted")
    assert len(loaded["native_files"]) == 2
    assert loaded["native_invocations"] == [] and loaded["receipts"] == []
    assert loaded["source_syft"]["path"].endswith("syft.json")
    assert loaded["native_created"] == CREATED
    assert loaded["packages"][0]["version"] == "1.3.1"


def test_catalog_membership_is_required_for_native_inputs(tmp_path: Path) -> None:
    config, root, target = seed(tmp_path)
    framework, _ = accepted_framework(root, "job_target_catalog", 1_000_000)
    framework["artifacts"] = [ref for ref in framework["artifacts"] if not ref["path"].endswith("partition.json")]
    _framework(root, "job_target_catalog", framework["outputs"], framework["artifacts"])
    runner, job = JobRunner(config), build_job()
    claim = runner.begin_attempt(job, run_id=RUN_ID, target_root=target, source_fingerprint=SNAPSHOT)
    with pytest.raises(NativeInputIntegrityError, match="not bound"):
        runner.execute_or_reuse_unit(job, claim, "inputs.load_accepted")


def test_buildless_native_spdx_is_accepted_and_evidence_is_indexed(tmp_path: Path) -> None:
    config, root, target = seed(tmp_path)
    result = execute(config, root, target)
    assert result["handoff"]["status"] == "ACCEPTED"
    accepted = load_accepted_dependency_intelligence(root)
    sbom = accepted["sbom"]
    assert sbom["format"] == "spdx-json" and sbom["spec_version"] == "2.3"
    provenance = json.loads((root / sbom["provenance"]["path"]).read_bytes())
    assert provenance["input_fingerprint"] == sbom["input_fingerprint"]
    spdx = json.loads((root / sbom["artifact"]["path"]).read_bytes())
    native = next(item for item in spdx["packages"] if item["name"].casefold() == "zlib")
    assert native["versionInfo"] == "1.3.1"
    shard = root / accepted["index_identity"]["relative_path"]
    with sqlite3.connect(shard) as database:
        observed = database.execute("SELECT payload_json FROM entities WHERE kind='tool_observation'").fetchall()
        relations = database.execute("SELECT COUNT(*) FROM relations WHERE kind='DERIVED_FROM'").fetchone()[0]
    assert observed and relations >= len(observed)
    assert any(json.loads(row[0])["selector"].get("start_line") == 1 for row in observed)
    assert accepted["security_findings"] == []
    metrics = aggregate_run_metrics(root)["native_sbom"]
    assert metrics["current_inventory"]["counters"]["candidates_total"] >= 1
    assert metrics["fresh_work"] == 1
    core = RetrievalCore(config.runtime.runs_dir, RUN_ID,
                         manifest_path=root / accepted["index_manifest"]["path"],
                         manifest_sha256=accepted["index_manifest"]["sha256"])
    observations = core.find(kind="tool_observation", limit=100)["results"]
    located = next(item for item in observations if item.get("location"))
    assert core.read_excerpt(identity=located["identity"])["results"][0]["excerpt"]
    relationships = core.resolve_evidence(identity=located["identity"])["results"][0]["relationships"]
    assert {item["kind"] for item in relationships} >= {"OBSERVED_AT", "DERIVED_FROM"}


@pytest.mark.parametrize("publication", ["artifact", "baseline", "provenance", "metrics", "native_discovery"])
def test_advertised_native_artifact_tampering_is_rejected(tmp_path: Path, publication: str) -> None:
    config, root, target = seed(tmp_path)
    execute(config, root, target)
    accepted = load_accepted_dependency_intelligence(root)
    ref = accepted[publication] if publication == "native_discovery" else accepted["sbom"][publication]
    (root / ref["path"]).write_bytes(b"changed")
    with pytest.raises(ValueError):
        load_accepted_dependency_intelligence(root)


def test_native_only_publication_names_missing_baseline(tmp_path: Path) -> None:
    config, root, target = seed(tmp_path, source_syft=False)
    execute(config, root, target, convert=lambda *_args, **_kwargs: pytest.fail("no source conversion"))
    accepted = load_accepted_dependency_intelligence(root)
    assert accepted["sbom"]["status"] == "COMPLETED_WITH_GAPS"
    assert accepted["sbom"]["baseline"] is None
    assert any(item["kind"] == "input_missing" for item in accepted["sbom"]["gaps"])


def test_source_catalog_gaps_survive_native_discovery(tmp_path: Path) -> None:
    config, root, target = seed(tmp_path, catalog_gaps=["source catalog file limit reached"])
    execute(config, root, target)
    accepted = load_accepted_dependency_intelligence(root)
    discovery = json.loads((root / accepted["native_discovery"]["path"]).read_bytes())
    assert discovery["coverage"]["inherited_catalog_gaps"] == ["source catalog file limit reached"]
    assert accepted["sbom"]["status"] == "COMPLETED_WITH_GAPS"
    assert any(item["kind"] == "upstream_partial" for item in discovery["gaps"])


def test_oversized_discovery_cannot_be_accepted_then_unreadable(tmp_path: Path) -> None:
    config, root, target = seed(tmp_path)
    job = config.jobs["job_dependency_intelligence"]
    config = replace(config, jobs={**config.jobs, job.job_id: replace(
        job, settings={**job.settings, "sbom_output_bytes": 512})})
    with pytest.raises(RuntimeError, match="native discovery exceeds.*publication byte bound"):
        execute(config, root, target)
    assert not (root / "data" / "jobs" / "job_dependency_intelligence" / "latest.json").is_file()


def test_conversion_receipts_outside_task_directory_are_accepted_and_verified(tmp_path: Path) -> None:
    config, root, target = seed(tmp_path)
    def traced(source, *, unit):
        baseline = converter(source, unit=unit)
        execution = _write(root, "conversion-execution.json", {"exit_code": 0})
        atomic_json(unit.unit_root / "conversion.json", {"execution": execution})
        return baseline
    execute(config, root, target, convert=traced)
    accepted = load_accepted_dependency_intelligence(root)
    receipt = accepted["sbom"]["conversion"]["execution"]
    assert json.loads((root / receipt["path"]).read_bytes())["exit_code"] == 0
    (root / receipt["path"]).write_bytes(b"{}")
    with pytest.raises(ValueError, match="integrity mismatch"):
        load_accepted_dependency_intelligence(root)


def test_conversion_failure_keeps_native_inventory_and_records_metrics(tmp_path: Path) -> None:
    config, root, target = seed(tmp_path)
    def fail(_source, *, unit):
        raise RuntimeError("converter timeout")
    execute(config, root, target, convert=fail)
    accepted = load_accepted_dependency_intelligence(root)
    assert accepted["sbom"]["artifact"]
    assert any(item["kind"] == "sbom_conversion_failed" for item in accepted["sbom"]["gaps"])
    receipt = json.loads((root / accepted["sbom"]["metrics"]["path"]).read_bytes())
    assert receipt["conversion_status"] == "FAILED"
    assert receipt["status"] == "COMPLETED_WITH_GAPS"


def test_source_size_change_aborts_native_discovery(tmp_path: Path) -> None:
    config, root, target = seed(tmp_path)
    (target / "third_party" / "zlib" / "zlib.h").write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="native source|native.*changed"):
        execute(config, root, target)
    assert not (root / "data" / "jobs" / "job_dependency_intelligence" / "latest.json").is_file()


def test_source_syft_tampering_is_admission_failure_not_native_only_success(tmp_path: Path) -> None:
    config, root, target = seed(tmp_path)
    (root / "data" / "native-sbom-fixtures" / "syft.json").write_bytes(b"{}")
    with pytest.raises(RuntimeError, match="integrity mismatch"):
        execute(config, root, target)
    assert not (root / "data" / "jobs" / "job_dependency_intelligence" / "latest.json").is_file()


def test_converter_byte_tampering_is_not_downgraded_to_coverage_gap(tmp_path: Path) -> None:
    config, root, target = seed(tmp_path)
    def tamper(source, *, unit):
        baseline = converter(source, unit=unit)
        (unit.job.run_root / baseline["artifact"]["path"]).write_bytes(b"{}")
        return baseline
    with pytest.raises(RuntimeError, match="converter artifact identity changed"):
        execute(config, root, target, convert=tamper)
    assert not (root / "data" / "jobs" / "job_dependency_intelligence" / "latest.json").is_file()


def test_conversion_runtime_failure_is_not_native_only_success(tmp_path: Path) -> None:
    config, root, target = seed(tmp_path)
    def fail(_source, *, unit):
        raise NativeSbomInfrastructureError("Docker unavailable")
    with pytest.raises(RuntimeError, match="Docker unavailable"):
        execute(config, root, target, convert=fail)
    assert not (root / "data" / "jobs" / "job_dependency_intelligence" / "latest.json").is_file()


def test_source_changed_after_admission_is_not_conversion_coverage_gap(tmp_path: Path) -> None:
    config, root, target = seed(tmp_path)
    def tamper(source, *, unit):
        (root / source["path"]).write_bytes(b"{}")
        return convert_syft(source, unit=unit)
    with pytest.raises(RuntimeError, match="source Syft inventory integrity changed"):
        execute(config, root, target, convert=tamper)
    assert not (root / "data" / "jobs" / "job_dependency_intelligence" / "latest.json").is_file()


@pytest.mark.parametrize("family", ["native", "python"])
@pytest.mark.parametrize("directory", ["/workspace", "/target"])
def test_workspace_and_embedded_native_evidence_resolves_normalized_selectors(
        tmp_path: Path, family: str, directory: str) -> None:
    config, root, target = seed(tmp_path)
    workspace = root / "build"
    header = workspace / "vendor" / "zlib" / "zlib.h"
    header.parent.mkdir(parents=True)
    header.write_bytes(b'#define ZLIB_VERSION "1.2.13"\n')
    readme = header.parent / "README"
    readme.write_bytes(b"Package: zlib\nVersion: 1.2.13\n")
    protected = _write(root, "commands.json", {
        "schema": "appsec-review/protected-compile-commands/1",
        "rows": [{"directory": directory,
                  "argv": ["cc", "-c", "-Ivendor/zlib", "-I/target/third_party/zlib", "main.c"]}],
    })
    manifest = _write(root, "workspace.json", {
        "files": {"vendor/zlib/zlib.h": file_sha256(header), "vendor/zlib/README": file_sha256(readme)},
    })
    language = _write(root, "language-native.json", {
        "schema": "appsec-review/language-build-handoff/1", "source_fingerprint": SNAPSHOT,
        "receipts": [{
            "family": family, "build_unit_id": "native-fixture", "workspace": "build",
            "protected_compile_commands": protected, "workspace_manifest": manifest,
            "artifacts": [{"path": "build/lib/libz.so.1", "workspace_path": "lib/libz.so.1",
                           "loader_dependencies": ["libz.so.1"], "loader_soname": "libz.so.1"}],
        }], "gaps": [],
    })
    _framework(root, "job_language_build",
               {"acceptance.publish_handoff": {"artifact": language}}, [language, protected, manifest])
    execute(config, root, target)
    accepted = load_accepted_dependency_intelligence(root)
    discovery = json.loads((root / accepted["native_discovery"]["path"]).read_bytes())
    workspace_evidence = [item for item in discovery["evidence"] if item["domain"] == "workspace"]
    assert workspace_evidence
    for item in workspace_evidence:
        assert item["backing"]["sha256"] == item["sha256"]
        assert (root / item["backing"]["path"]).read_bytes() == (workspace / item["path"]).read_bytes()
    run_evidence = [item for item in discovery["evidence"] if item["domain"] == "run"]
    assert run_evidence
    for item in run_evidence:
        value = json.loads((root / item["upstream"]["path"]).read_bytes())
        for token in item["selector"]["json_pointer"].split("/")[1:]:
            token = token.replace("~1", "/").replace("~0", "~")
            value = value[int(token)] if isinstance(value, list) else value[token]
        assert value == ("-I" + item["value"] if item["kind"] == "path_hint" else item["value"])
    spdx = json.loads((root / accepted["sbom"]["artifact"]["path"]).read_bytes())
    assert {item.get("versionInfo") for item in spdx["packages"] if item["name"] == "zlib"} >= {
        "1.3.1", "1.2.13",
    }


def test_schema_failure_retains_failed_metrics_without_accepted_spdx(tmp_path: Path, monkeypatch) -> None:
    from appsec_review.jobs.job_dependency_intelligence.native_sbom_contracts import SpdxValidationError
    config, root, target = seed(tmp_path)
    def fail(**_kwargs):
        raise SpdxValidationError("invalid SPDX fixture")
    monkeypatch.setattr("appsec_review.jobs.job_dependency_intelligence.sbom.build_spdx", fail)
    execute(config, root, target)
    accepted = load_accepted_dependency_intelligence(root)
    assert accepted["sbom"]["status"] == "FAILED"
    assert accepted["sbom"]["artifact"] is None
    metrics = aggregate_run_metrics(root)["native_sbom"]
    assert metrics["attempt_outcomes"]["FAILED"] == 1
    assert metrics["current_inventory"]["availability"] == "not_available"
    assert metrics["current_inventory"]["counters"]["output_packages"] is None


def test_complete_zero_native_spdx_is_not_missing_coverage(tmp_path: Path) -> None:
    config, root, target = seed(tmp_path, files={})
    execute(config, root, target)
    accepted = load_accepted_dependency_intelligence(root)
    assert accepted["sbom"]["status"] == "SUCCEEDED"
    metrics = aggregate_run_metrics(root)["native_sbom"]["current_inventory"]
    assert metrics["counters"]["candidates_total"] == 0
    assert metrics["counters"]["output_packages"] == 0
    assert metrics["status"] == "SUCCEEDED"


def test_publication_task_reuse_does_not_repeat_discovery_or_conversion(tmp_path: Path, monkeypatch) -> None:
    config, root, target = seed(tmp_path)
    calls = []
    def convert(source, *, unit):
        calls.append(source["sha256"])
        return converter(source, unit=unit)
    runner, job = JobRunner(config), build_job(syft_converter=convert)
    claim = runner.begin_attempt(job, run_id=RUN_ID, target_root=target, source_fingerprint=SNAPSHOT)
    for unit in job.units:
        runner.execute_or_reuse_unit(job, claim, unit.unit_id)
    first = runner.finalize_attempt(job, claim)
    accepted = load_accepted_dependency_intelligence(root)
    monkeypatch.setattr("appsec_review.jobs.job_dependency_intelligence.job.read_native_file",
                        lambda *_args, **_kwargs: pytest.fail("reused discovery must not read"))
    runner.execute_or_reuse_unit(job, claim, "resolution.detect_dependencies")
    repeated = runner.execute_or_reuse_unit(job, claim, "publication.publish_sbom")
    assert calls and len(calls) == 1
    assert repeated["artifact"] == accepted["sbom"]["artifact"]
    assert first["handoff"]["status"] == "ACCEPTED"


def test_structured_syft_identity_survives_parser_and_envelope(tmp_path: Path) -> None:
    payload = canonical_json({"artifacts": [{
        "id": "native-zlib", "name": "zlib", "version": "1.3.1",
        "purl": "pkg:generic/zlib@1.3.1", "metadata": {"repository": "https://github.com/madler/zlib"},
        "locations": [{"path": "vendor/zlib/zlib.h"}],
    }]})
    records = _syft_parser(payload)
    envelope = build_envelope(tool={"id": "tool-syft"}, target_fingerprint=SNAPSHOT,
        applicability={}, coverage_scope={}, gaps=[], raw_artifacts=[], parser_identity="test",
        observations=records, cataloged_paths=["vendor/zlib/zlib.h"],
        terminal_status="SUCCEEDED", run_root=tmp_path)
    row = envelope["records"][0]
    assert row["version"] == "1.3.1"
    assert row["purl"] == "pkg:generic/zlib@1.3.1"
    assert row["repository_url"] == "https://github.com/madler/zlib"
    assert row["raw_selector"] == "/artifacts/0"
