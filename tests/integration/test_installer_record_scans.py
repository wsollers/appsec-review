"""Integration: one pinned syft, grype and osv-scanner launch per npm installer record.

The npm installer record (``node_modules/.package-lock.json``) is staged read-only as
``/target/package-lock.json`` and scanned once per capability; its verified package anchors are
not launched individually (``INSTALLER_RECORD_COVERED``). These tests launch the real pinned
scanner images on the Node dependency fixture from
``tests/test_node_dependency_output_filtering.py``. They need Docker, the cataloged
``tool-syft``, ``tool-grype`` and ``tool-osv-scanner`` images, and verified grype and osv feed
snapshots (with npm data) under ``data/feeds``; otherwise they skip with the missing
precondition named. Implicit collection excludes this directory; run it explicitly:

    python -m pytest -p no:cacheprovider tests/integration/test_installer_record_scans.py \
        --basetemp=test/tmp/installer-record-scans
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import tomllib
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import load_catalog
from appsec_review.jobs.delivery_scope import scope_fields
from appsec_review.jobs.job_artifact_security_analysis import (
    build_job, load_accepted_artifact_security_analysis)
from appsec_review.jobs.job_artifact_security_analysis import job as security
from appsec_review.jobs.job_artifact_security_analysis.findings import FINDING_NORMALIZER
from appsec_review.jobs.job_artifact_security_analysis.scanners import ADAPTERS, ContainerScannerRunner
from appsec_review.jobs.job_language_build import node
from appsec_review.jobs.job_third_party_data_sync.publication import verify_current
from appsec_review.osv_offline import snapshot_ecosystems
from appsec_review.retrieval import (
    EntityKind, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, write_manifest)
from appsec_review.retrieval.index import INDEX_SCHEMA, load_verified_manifest
from appsec_review.runtime import GraphRunner
from appsec_review.storage import RunStore, atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff
from tests.test_node_dependency_output_filtering import _shipped_dispositions, _workspace


ROOT = Path(__file__).resolve().parents[2]
SCANNED = ("syft", "grype", "osv")
BUILD_UNIT = "build-unit-node"
RECORD = "node_modules/.package-lock.json"
RECORD_METADATA = {"format": ".package-lock.json", "manager": "npm", "role": "installed-dependency-record"}
PACKAGE_ROLE = "installed-dependency-package"
PRESENTATION = "appsec-review/npm-installed-record-as-package-lock/1"
COVERED = "INSTALLER_RECORD_COVERED"
SOURCE_FINGERPRINT = "a" * 64
# osv-scanner 1.x reports the parsed package count on stderr for each --lockfile input.
OSV_SCANNED = re.compile(
    r"Scanned /target/package-lock\.json file (?:as a \S+ )?and found (\d+) packages?")


def _unavailable() -> list[str]:
    if shutil.which("docker") is None:
        return ["the docker CLI"]
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=60, check=True)
    except (OSError, subprocess.SubprocessError):
        return ["the Docker daemon"]
    catalog = load_catalog(ROOT)
    missing = []
    for capability in SCANNED:
        tag = catalog.tool(ADAPTERS[capability].tool_id).tag
        inspected = subprocess.run(["docker", "image", "inspect", tag], capture_output=True, timeout=60)
        if inspected.returncode != 0:
            missing.append(tag)
    for feed in ("grype", "osv"):
        try:
            current = verify_current(ROOT / "data" / "feeds" / feed, feed)
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            missing.append(f"verified {feed} feed snapshot ({type(exc).__name__})")
            continue
        if feed == "osv" and "npm" not in snapshot_ecosystems(Path(str(current["directory"]))):
            missing.append("npm data in the verified osv feed snapshot")
    return missing


@pytest.fixture(scope="module")
def scanners_available() -> None:
    missing = _unavailable()
    if missing:
        pytest.skip("installer-record scan preconditions are unavailable: " + ", ".join(missing))


def _osv_memory() -> str:
    document = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    return str(document["jobs"]["job_artifact_security_analysis"]["settings"]["osv_memory"])


def _role(row: Mapping[str, Any], field: str) -> str | None:
    metadata = row.get(field)
    return metadata.get("role") if isinstance(metadata, Mapping) else None


def _catalog(run_root: Path) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    """Catalog the fixture workspace under the run root; return (rows, record row, anchor rows)."""
    workspace, _ = _workspace(run_root / "data" / "build" / "node")
    rows, _ = node.catalog(run_root, workspace, {}, 10_000, BUILD_UNIT, dispositions=_shipped_dispositions())
    [record] = [row for row in rows if _role(row, "dependency_metadata") == "installed-dependency-record"]
    assert record["workspace_path"] == RECORD and record["dependency_metadata"] == RECORD_METADATA
    anchors = [row for row in rows if _role(row, "package_metadata") == PACKAGE_ROLE]
    assert len(anchors) == 38
    return rows, record, anchors


def _pairs(anchors: Sequence[Mapping[str, Any]], *, dev: bool | None = None) -> set[tuple[str, str]]:
    return {(row["package_metadata"]["name"], row["package_metadata"]["version"]) for row in anchors
            if dev is None or row["package_metadata"]["dev"] is dev}


def _artifact(row: Mapping[str, Any], identity: str) -> dict[str, Any]:
    return {**row, **scope_fields(row), "artifact_id": f"artifact-{identity}",
            "canonical_identity": f"fixture:{BUILD_UNIT}:{identity}:{row['workspace_path']}"}


def _runner(run_root: Path, name: str) -> ContainerScannerRunner:
    return ContainerScannerRunner(ROOT, run_root, run_root / "data" / "scratch" / name,
                                  osv_memory=_osv_memory())


def _launch(runner: ContainerScannerRunner, capability: str, run_root: Path,
            artifact: Mapping[str, Any]) -> Mapping[str, Any]:
    result = runner(capability, run_root / artifact["path"], artifact, 600, 64 * 1024 * 1024)
    assert result.get("precondition_gap") is None, result.get("precondition_gap")
    assert not result["timed_out"], f"{capability} timed out"
    assert result["exit_code"] in ADAPTERS[capability].accepted_exit_codes, (
        capability, result["exit_code"], bytes(result["stderr"])[-2000:])
    return result


def _document(result: Mapping[str, Any]) -> Mapping[str, Any]:
    return json.loads(bytes(result["payload"]))


def test_finding_normalizer_carries_installer_record_attribution() -> None:
    # Attribution fields are added to grype/osv finding payloads (design D5/D7).
    assert FINDING_NORMALIZER == "appsec-review/artifact-security-findings/3"


def test_syft_reports_every_verified_package_from_the_staged_record(
        tmp_path: Path, scanners_available) -> None:
    run_root = tmp_path / "run"
    _, record, anchors = _catalog(run_root)

    result = _launch(_runner(run_root, "syft"), "syft", run_root, _artifact(record, "record"))

    reported = {(item.get("name"), item.get("version")) for item in _document(result).get("artifacts", ())}
    # Dev entries are included through SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES (design D3/D4).
    assert len(_pairs(anchors, dev=True)) == 30
    assert _pairs(anchors) <= reported, sorted(_pairs(anchors) - reported)


def test_syft_on_the_unstaged_record_reports_nothing(tmp_path: Path, scanners_available) -> None:
    """Root-cause pin: the record's own name and location give syft no lock parser input.

    If a future syft parses ``node_modules/.package-lock.json`` directly, this fails and the
    staging (design D3) can be revisited.
    """
    run_root = tmp_path / "run"
    _, record, _ = _catalog(run_root)
    unstaged = {key: value for key, value in record.items() if key != "dependency_metadata"}

    result = _launch(_runner(run_root, "syft-unstaged"), "syft", run_root, _artifact(unstaged, "unstaged"))

    reported = _document(result).get("artifacts")
    assert not reported, [(item.get("name"), item.get("version")) for item in reported]


def test_grype_completes_on_the_staged_record_without_matching_dev_entries(
        tmp_path: Path, scanners_available) -> None:
    run_root = tmp_path / "run"
    _, record, anchors = _catalog(run_root)

    result = _launch(_runner(run_root, "grype"), "grype", run_root, _artifact(record, "record"))

    document = _document(result)
    assert isinstance(document.get("matches"), list)
    matched = {(match.get("artifact", {}).get("name"), match.get("artifact", {}).get("version"))
               for match in document["matches"]}
    # The pinned grype excludes npm dev entries from a file: source (design D4).
    assert not matched & _pairs(anchors, dev=True), sorted(matched & _pairs(anchors, dev=True))


def test_osv_parses_the_staged_record_as_an_npm_lockfile(tmp_path: Path, scanners_available) -> None:
    run_root = tmp_path / "run"
    _, record, _ = _catalog(run_root)

    result = _launch(_runner(run_root, "osv"), "osv", run_root, _artifact(record, "record"))

    output = (bytes(result["stdout"]) + b"\n" + bytes(result["stderr"])).decode("utf-8", "replace")
    match = OSV_SCANNED.search(output)
    assert match is not None, output[-2000:]
    # 38 verified entries plus the version-mismatched entry; the link entry may be dropped.
    assert 38 <= int(match.group(1)) <= 40, match.group(0)
    assert isinstance(_document(result).get("results", []), list)


def _seed_run(tmp_path: Path) -> tuple[Any, str, Path, Path, dict[str, Any], list[dict[str, Any]]]:
    """A run whose accepted language build holds the installer record and its 38 anchors only."""
    config_path = tmp_path / "appsec-review.toml"
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    components = ("platform", "validation", *(adapter.tool_id for adapter in ADAPTERS.values()))
    text = text.replace("[review_policy.releases]", "[review_policy.releases]\n" +
                        "\n".join(f'"{key}" = "fixture/1"' for key in components))
    text = text.replace("disable_grype = true", "disable_grype = false")
    config_path.write_text(text, encoding="utf-8")
    config = load_config(config_path)
    run_id, run_root = RunStore(config.runtime.runs_dir).create(datetime.now(timezone.utc))
    target = tmp_path / "target"
    target.mkdir()
    _, record, anchors = _catalog(run_root)
    rows = [record, *anchors]

    index_path = run_root / "data" / "indices" / "artifacts" / "fixture.sqlite"
    index_sha = IndexBuilder(index_path, name="artifacts", fingerprint="b" * 64,
                             target_snapshot=SOURCE_FINGERPRINT, shard_id="language-build").build()
    index_identity = IndexIdentity("artifacts", INDEX_SCHEMA, index_sha, "b" * 64,
        index_path.relative_to(run_root).as_posix(), {"job": "job_language_build"}, (), "language-build")
    manifest_path = run_root / "data" / "indices" / "manifests" / "language-build.json"
    write_manifest(manifest_path, run_id=run_id, target_snapshot=SOURCE_FINGERPRINT, target_root=target,
                   indexes=[index_identity])
    manifest = {"path": manifest_path.relative_to(run_root).as_posix(),
                "sha256": file_sha256(manifest_path), "size_bytes": manifest_path.stat().st_size}
    accepted_path = run_root / "data" / "upstream" / "accepted-language-builds.json"
    accepted_path.parent.mkdir(parents=True)
    atomic_json(accepted_path, {"schema": "appsec-review/language-build-handoff/1",
        "source_fingerprint": SOURCE_FINGERPRINT, "upstream_project_build_handoff_sha256": "c" * 64,
        "receipts": [{"build_unit_id": BUILD_UNIT, "family": "node", "fingerprint": "d" * 64,
                      "executor_identity": "fixture", "capture_identity": "fixture", "artifacts": rows}],
        "gaps": []})
    accepted = {"path": accepted_path.relative_to(run_root).as_posix(), "sha256": file_sha256(accepted_path),
                "size_bytes": accepted_path.stat().st_size}
    handoff_path = run_root / "data" / "jobs" / "job_language_build" / "attempts" / "attempt_0001" / "handoff.json"
    handoff_path.parent.mkdir(parents=True)
    write_fixture_handoff(run_root, handoff_path, {"status": "ACCEPTED",
        "job_id": "job_language_build", "attempt_id": "attempt_0001", "artifacts": [accepted, manifest],
        "outputs": {"acceptance.publish_handoff": {"artifact": accepted, "index_manifest": manifest}}})
    atomic_json(handoff_path.parents[2] / "latest.json", {
        "handoff_path": handoff_path.relative_to(run_root).as_posix(),
        "handoff_sha256": file_sha256(handoff_path)})
    summary_path = run_root / "data" / "upstream" / "accepted-artifact-index.json"
    atomic_json(summary_path, {"schema": "appsec-review/artifact-indexing/1",
        "source_fingerprint": SOURCE_FINGERPRINT, "language_build_handoff_sha256": file_sha256(handoff_path),
        "artifact_shard_count": 1, "reused_shard_count": 0, "artifact_count": len(rows), "gaps": [],
        "index_manifest": manifest})
    summary = {"path": summary_path.relative_to(run_root).as_posix(),
               "sha256": file_sha256(summary_path), "size_bytes": summary_path.stat().st_size}
    indexing_path = (run_root / "data" / "jobs" / "job_artifact_indexing" / "attempts" /
                     "attempt_0001" / "handoff.json")
    indexing_path.parent.mkdir(parents=True)
    write_fixture_handoff(run_root, indexing_path, {"status": "ACCEPTED",
        "job_id": "job_artifact_indexing", "attempt_id": "attempt_0001", "artifacts": [summary, manifest],
        "outputs": {"acceptance.publish_handoff": {"artifact": summary, "index_manifest": manifest}}})
    atomic_json(indexing_path.parents[2] / "latest.json", {
        "handoff_path": indexing_path.relative_to(run_root).as_posix(),
        "handoff_sha256": file_sha256(indexing_path)})
    return config, run_id, run_root, target, record, anchors


def _observations(run_root: Path, analysis: Mapping[str, Any]) -> list[tuple[Mapping[str, Any], set[str]]]:
    """(payload, OBSERVED_AT targets) for every tool observation in the artifact-security shard."""
    raw = analysis["index_manifest"]
    manifest, _ = load_verified_manifest(run_root, run_root / raw["path"], raw["sha256"])
    [shard] = [item for item in manifest["indexes"]
               if item["name"] == "observations" and item.get("shard_id") == "artifact-security"]
    path = run_root / shard["relative_path"]
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True)) as database:
        payloads = {identity: json.loads(payload) for identity, payload in database.execute(
            "SELECT identity, payload_json FROM entities WHERE kind = ?", (EntityKind.TOOL_OBSERVATION.value,))}
        targets: dict[str, set[str]] = {}
        for source, target in database.execute(
                "SELECT source_id, target_id FROM relations WHERE kind = ?", (RelationKind.OBSERVED_AT.value,)):
            targets.setdefault(source, set()).add(target)
    return [(payload, targets.get(identity, set())) for identity, payload in payloads.items()]


def _entity(canonical_identity: str) -> str:
    return LogicalIdentity.parse(canonical_identity).value


def test_review_scans_the_installer_record_once_and_covers_its_anchors(
        tmp_path: Path, scanners_available) -> None:
    config, run_id, run_root, target, record_row, anchor_rows = _seed_run(tmp_path)
    runner = ContainerScannerRunner(ROOT, run_root, run_root / "data" / "scratch" / "installer-record-job",
                                    osv_memory=_osv_memory())

    outcome = GraphRunner(config, [build_job(scanner_runner=runner)]).run(
        target_root=target, source_fingerprint=SOURCE_FINGERPRINT, run_id=run_id)

    assert outcome["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}, outcome
    analysis = load_accepted_artifact_security_analysis(run_root)
    artifacts = security._accepted_artifacts(run_root)["artifacts"]
    [record] = [row for row in artifacts if row.get("dependency_metadata") == RECORD_METADATA]
    anchors = {row["artifact_id"]: row for row in artifacts if _role(row, "package_metadata") == PACKAGE_ROLE}
    assert len(anchors) == 38 and record["sha256"] == record_row["sha256"]
    dev_anchors = sum(1 for row in anchor_rows if row["package_metadata"]["dev"])
    assert dev_anchors == 30

    expected_entry = {"artifact_id": record["artifact_id"], "workspace_path": RECORD,
                      "sha256": record["sha256"], "presentation": PRESENTATION,
                      "anchors_covered": 38, "dev_anchors": dev_anchors, "scan_outcome": "completed"}
    for capability in ("syft", "grype"):
        summary = analysis["capabilities"][capability]
        assert summary["observation_count"] == 1, (capability, summary["observation_count"])
        reason = (f"{capability} covers this package through one scan of installer record {RECORD} "
                  f"(sha256 {record['sha256'][:12]})")
        covered = {item["artifact_id"]: item for item in summary["scope_dispositions"]
                   if item.get("input_reason_code") == COVERED}
        assert set(covered) == set(anchors), capability
        for artifact_id, item in covered.items():
            assert item["input_disposition"] == "SKIPPED_NA" and "format" in item
            assert item["input_reason"] == reason
            assert item["input_covered_by"] == record["artifact_id"]
            assert item["input_evidence_ref"] == f"{RECORD}#{anchors[artifact_id]['delivery_evidence']['entry']}"
        assert summary["not_applicable_inputs"]["by_reason"].get(reason) == 38, capability
        entries = summary["installer_records"]
        assert entries == [{**expected_entry, **({"anchors_reported": 38} if capability == "syft" else {})}], (
            capability, entries)
    osv = analysis["capabilities"]["osv"]
    assert osv["observation_count"] == 1
    # osv skips no anchor (they stay format-skipped for it) but still counts the record's dev anchors.
    assert osv["installer_records"] == [{**expected_entry, "anchors_covered": 0}], osv["installer_records"]
    assert not [item for item in osv["scope_dispositions"] if item.get("input_reason_code") == COVERED]

    grype_dev_gap = (f"{record['artifact_id']}: grype: {dev_anchors} dev-only packages recorded by {RECORD} "
                     "are not vulnerability-matched by the pinned grype (npm dev entries excluded); "
                     "osv-scanner scans the same record")
    assert grype_dev_gap in analysis["capabilities"]["grype"]["gaps"]
    all_gaps = [gap for capability in SCANNED for gap in analysis["capabilities"][capability]["gaps"]]
    assert not [gap for gap in all_gaps if "did not complete" in gap or "were not reported" in gap], all_gaps

    observations = _observations(run_root, analysis)
    record_entity = _entity(record["canonical_identity"])
    anchor_entities = {_entity(row["canonical_identity"]): artifact_id for artifact_id, row in anchors.items()}
    summaries = [(payload, targets) for payload, targets in observations
                 if payload.get("record_kind") == "scan_summary" and payload.get("capability") in SCANNED]
    for capability in SCANNED:
        at_record = [payload for payload, targets in summaries
                     if payload["capability"] == capability and record_entity in targets]
        assert len(at_record) == 1, (capability, len(at_record))
        assert at_record[0]["scan_outcome"] == "completed", at_record[0].get("gaps")
    assert not [payload["capability"] for payload, targets in summaries if targets & set(anchor_entities)]
    for payload, targets in observations:
        if payload.get("record_kind") != "finding" or payload.get("capability") not in {"grype", "osv"}:
            continue
        attribution = payload.get("installed_package_attribution")
        assert attribution in {"verified-anchor", "unverified-record-entry"}, payload.get("subject")
        # Attribution matches the finding's (package_name, package_version) to the record's anchors.
        matched = {artifact_id for artifact_id, row in anchors.items()
                   if (row["package_metadata"]["name"], row["package_metadata"]["version"]) ==
                   (payload.get("package_name"), payload.get("package_version"))}
        if attribution == "unverified-record-entry":
            assert not matched and "installed_packages" not in payload, payload.get("subject")
            assert targets == {record_entity}, payload.get("subject")
            continue
        described = [item["artifact_id"] for item in payload["installed_packages"]]
        # The fixture records 38 packages, below the 64-descriptor bound, so nothing is truncated.
        assert set(described) == matched and len(described) == len(matched), payload.get("subject")
        assert "installed_packages_truncated" not in payload
        assert targets == {record_entity} | {_entity(anchors[item]["canonical_identity"]) for item in matched}
