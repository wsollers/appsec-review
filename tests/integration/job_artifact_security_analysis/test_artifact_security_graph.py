"""GraphRunner and JobRunner integration tests for job_artifact_security_analysis.

Moved from root ``tests/test_artifact_security_analysis.py`` during the T-113 unit-tier walk
because these scenarios execute the multi-unit review graph and accepted handoff lifecycle.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.job_artifact_security_analysis import (
    build_job,
    load_accepted_artifact_security_analysis,
)
from appsec_review.jobs.job_artifact_security_analysis import findings as findings_module
from appsec_review.jobs.job_artifact_security_analysis import job as security
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import JobRunner
from appsec_review.storage import atomic_json, file_sha256
from tests.artifact_input_support import recorded_graph
from tests.unit.job_artifact_security_analysis.support import (
    INSTALLED,
    RECORD,
    _fixture,
    _installed_rows,
)


def test_spotbugs_failed_or_malformed_output_is_a_retained_gap(tmp_path: Path) -> None:
    for exit_code in (1, 0):
        case = tmp_path / str(exit_code)
        case.mkdir()
        config, run_id, run_root, target, fingerprint, _ = _fixture(
            case, payload=b"\xca\xfe\xba\xbe" + b"\0" * 32
        )

        def scanner(capability, path, artifact, timeout, limit):
            result = {
                "stdout": b"",
                "stderr": b"scanner failed" if exit_code else b"",
                "exit_code": exit_code if capability == "spotbugs" else 0,
                "observation": {} if capability != "spotbugs" else None,
                "tool_identity": {"scanner": capability, "image": "fixture", "rules": "fixture"},
            }
            if capability == "spotbugs":
                result["payload"] = b""
            return result

        outcome = recorded_graph(config, [build_job(scanner_runner=scanner)], run_id).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id
        )
        assert outcome["status"] == "COMPLETED_WITH_GAPS"
        accepted = load_accepted_artifact_security_analysis(run_root)
        assert accepted["capabilities"]["spotbugs"]["terminal_status"] == "COMPLETED_WITH_GAPS"
        assert any(
            ("scanner exited 1" if exit_code else "output could not be parsed") in gap
            for gap in accepted["capabilities"]["spotbugs"]["gaps"]
        )
        raw = list(
            (run_root / "data" / "jobs" / "job_artifact_security_analysis" / "attempts").glob(
                "*/artifacts/asa/*/spotbugs/parser-input.bin"
            )
        )
        assert raw and raw[0].read_bytes() == b""


def test_no_artifacts_is_a_named_gap_with_verified_empty_index(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = _fixture(tmp_path, no_artifacts=True)
    outcome = recorded_graph(config, [build_job()], run_id).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id
    )
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_artifact_security_analysis(run_root)
    assert accepted["artifact_count"] == accepted["observation_count"] == 0
    assert "no target or produced artifacts were available for artifact security analysis" in accepted["gaps"]


def test_producer_gap_records_from_upstream_handoffs_are_read_as_text(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = _fixture(
        tmp_path, no_artifacts=True, gap_records=True
    )
    outcome = recorded_graph(config, [build_job()], run_id).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id
    )
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_artifact_security_analysis(run_root)
    assert all(isinstance(gap, str) for gap in accepted["gaps"])
    assert "no produced artifacts" in accepted["gaps"]
    assert "no target or produced artifacts were available for artifact security analysis" in accepted["gaps"]


def test_job_isolates_scanner_failure_retains_raw_output_and_indexes_siblings(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = _fixture(tmp_path)
    calls: list[str] = []

    def scanner(capability, path, artifact, timeout, limit):
        calls.append(capability)
        if capability == "grype":
            raise RuntimeError("fixture scanner failure")
        return {
            "stdout": b'{"packages":[]}',
            "stderr": b"",
            "exit_code": 0,
            "observation": {"packages": []},
            "tool_identity": {
                "scanner": capability,
                "image": "sha256:" + "e" * 64,
                "rules": "fixture",
            },
        }

    outcome = recorded_graph(config, [build_job(scanner_runner=scanner)], run_id).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id
    )
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_artifact_security_analysis(run_root)
    assert accepted["artifact_count"] == 1
    assert accepted["observation_count"] >= 4
    assert accepted["capabilities"]["grype"]["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert accepted["capabilities"]["syft"]["observation_count"] == 1
    assert set(calls) == {"syft", "grype"}
    assert accepted["capabilities"]["osv"]["not_applicable_inputs"]["count"] == 1
    blint = accepted["capabilities"]["blint"]
    assert blint["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert blint["gaps"] == ["build/module.wasm: delivery status is unknown (delivery_fact_unavailable)"]
    assert blint["not_applicable_inputs"]["count"] == 1
    assert blint["not_applicable_inputs"]["items"][0]["reason_code"] == "INPUT_FORMAT_UNSUPPORTED"
    raw = list(
        (run_root / "data" / "jobs" / "job_artifact_security_analysis" / "attempts").rglob("stdout.bin")
    )
    assert raw and all(path.is_file() for path in raw)
    manifest = run_root / accepted["index_manifest"]["path"]
    assert file_sha256(manifest) == accepted["index_manifest"]["sha256"]
    results = RetrievalCore(config.runtime.runs_dir, run_id).find(
        kind="tool_observation", indexes=("observations",), limit=100
    )
    observation = next(item for item in results["results"] if item["kind"] == "tool_observation")
    payload = observation["payload"]
    assert "raw_artifacts" not in payload and payload["evidence_identities"]
    for identity in payload["evidence_identities"]:
        raw_path = run_root / identity["relative_path"]
        assert raw_path.is_file() and file_sha256(raw_path) == identity["sha256"]


@pytest.mark.parametrize("tamper", (False, True), ids=("unchanged-control", "accepted-bytes-changed"))
def test_changed_accepted_artifact_is_an_integrity_failure(tmp_path: Path, tamper: bool) -> None:
    config, run_id, run_root, target, fingerprint, produced = _fixture(tmp_path, seed_accepted=True)
    producers = ("job_language_build", "job_artifact_indexing")
    supplied, history = {}, {}
    for producer in producers:
        directory = run_root / "data/jobs" / producer
        assert (directory / "latest.json").is_file()
        accepted = accepted_handoff(run_root, producer)
        assert accepted is not None and accepted.handoff["status"] == "ACCEPTED"
        supplied[producer] = accepted.sha256
        history[producer] = {
            path.relative_to(directory).as_posix(): path.read_bytes()
            for path in directory.rglob("*")
            if path.is_file()
        }
    indexed = json.loads(history["job_artifact_indexing"]["attempts/attempt_0001/handoff.json"])
    assert indexed["upstream_handoff_sha256"] == {"job_language_build": supplied["job_language_build"]}
    language = json.loads(history["job_language_build"]["attempts/attempt_0001/handoff.json"])
    relative = produced.relative_to(run_root).as_posix()
    bound = next(ref for ref in language["artifacts"] if ref["path"] == relative)
    assert bound["sha256"] == file_sha256(produced)

    def forbidden_scanner(*args):
        pytest.fail("admission and load must not invoke a scanner")

    runner, job = JobRunner(config), build_job(scanner_runner=forbidden_scanner)
    if tamper:
        produced.write_bytes(b"\xff" * produced.stat().st_size)
        assert produced.stat().st_size == bound["size_bytes"]
        assert file_sha256(produced) != bound["sha256"]
        with pytest.raises(ValueError, match="^target evidence integrity mismatch$"):
            runner.begin_attempt(
                job,
                run_id=run_id,
                target_root=target,
                source_fingerprint=fingerprint,
                upstream_handoffs=supplied,
            )
        assert not (run_root / "data/jobs" / job.job_id / "attempts").exists()
    else:
        claim = runner.begin_attempt(
            job,
            run_id=run_id,
            target_root=target,
            source_fingerprint=fingerprint,
            upstream_handoffs=supplied,
        )
        assert claim["upstream_handoffs"] == supplied
        loaded = runner.execute_or_reuse_unit(job, claim, "load.accepted_artifacts")
        assert loaded["artifact_count"] == 1
        assert loaded["artifacts"][0]["verified_path"] == relative
    for producer in producers:
        directory = run_root / "data/jobs" / producer
        assert {
            path.relative_to(directory).as_posix(): path.read_bytes()
            for path in directory.rglob("*")
            if path.is_file()
        } == history[producer]
    assert not (run_root / "data/jobs" / job.job_id / "latest.json").exists()


def test_no_package_scan_exposes_native_reference_closure_without_a_finding(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = _fixture(
        tmp_path, payload=b"version = 3\n", name="Cargo.lock", kind="lockfile"
    )

    def scanner(capability, path, artifact, timeout, limit):
        execution = (
            run_root
            / "data"
            / "jobs"
            / "job_artifact_security_analysis"
            / "attempts"
            / "attempt_0001"
            / "steps"
            / "analyze"
            / "tasks"
            / "osv"
            / "containers"
            / "fixture"
            / "execution.json"
        )
        atomic_json(execution, {"exit_code": 128, "tool": "osv"})
        return {
            "stdout": b"No package sources found",
            "stderr": b"",
            "exit_code": 128,
            "payload": b'{"results":[]}',
            "execution_receipt": {
                "path": execution.relative_to(run_root).as_posix(),
                "sha256": file_sha256(execution),
                "size_bytes": execution.stat().st_size,
            },
        }

    recorded_graph(config, [build_job(scanner_runner=scanner)], run_id).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id
    )
    handoff_path = (
        run_root
        / json.loads(
            (run_root / "data" / "jobs" / "job_artifact_security_analysis" / "latest.json").read_bytes()
        )["handoff_path"]
    )
    handoff = json.loads(handoff_path.read_bytes())
    output = json.loads(
        (handoff_path.parent / "steps" / "analyze" / "tasks" / "osv" / "result.json").read_bytes()
    )
    assert not output["observations"] and output["not_applicable_inputs"]["count"] == 1
    (scan,) = output["not_applicable_scan_artifacts"]
    assert scan["result_artifact"] and scan["native_output"]["retention_receipt"]
    assert scan["execution_receipt"]["path"] == scan["native_output"]["execution_reference"]["path"]
    assert (run_root / scan["native_output"]["artifact"]["path"]).read_bytes() == b'{"results":[]}'
    assert scan["native_output"]["artifact"] in handoff["artifacts"]


def test_finding_record_bound_is_reported_in_publication_coverage(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(findings_module, "FINDING_BOUND", 1)
    config, run_id, run_root, target, fingerprint, _ = _fixture(tmp_path)

    def scanner(capability, path, artifact, timeout, limit):
        payload = (
            {"matches": [{"vulnerability": {"id": "CVE-A"}}, {"vulnerability": {"id": "CVE-B"}}]}
            if capability == "grype"
            else {"artifacts": []}
        )
        return {"stdout": b"", "stderr": b"", "exit_code": 0, "payload": json.dumps(payload).encode()}

    recorded_graph(config, [build_job(scanner_runner=scanner)], run_id).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id
    )
    accepted = load_accepted_artifact_security_analysis(run_root)
    assert accepted["finding_count"] == 1
    assert any("2 findings; only the first 1 are recorded" in gap for gap in accepted["gaps"])


@pytest.mark.parametrize("declared_releases", (False, True))
def test_resume_reuses_verified_artifact_capability_shards(tmp_path: Path, declared_releases: bool) -> None:
    config, run_id, _run_root, target, fingerprint, _ = _fixture(
        tmp_path, declared_releases=declared_releases
    )
    first_calls: list[str] = []

    def scanner(capability, path, artifact, timeout, limit):
        first_calls.append(capability)
        return {
            "stdout": b"{}",
            "stderr": b"",
            "exit_code": 0,
            "observation": {},
            "tool_identity": {"scanner": capability, "image": "fixture", "rules": "fixture"},
        }

    job = build_job(scanner_runner=scanner)
    recorded_graph(config, [job], run_id).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id
    )
    assert first_calls
    first_calls.clear()
    recorded_graph(config, [job], run_id).run(
        target_root=target,
        source_fingerprint=fingerprint,
        run_id=run_id,
        force_from="job_artifact_security_analysis",
    )
    assert bool(first_calls) is not declared_releases


def test_equal_content_artifacts_have_distinct_observation_checkpoints(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = _fixture(tmp_path, duplicate_artifact=True)

    def scanner(capability, path, artifact, timeout, limit):
        return {
            "stdout": b"{}",
            "stderr": b"",
            "exit_code": 0,
            "observation": {},
            "tool_identity": {"scanner": capability, "image": "fixture", "rules": "fixture"},
        }

    outcome = recorded_graph(config, [build_job(scanner_runner=scanner)], run_id).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id
    )
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_artifact_security_analysis(run_root)
    assert accepted["artifact_count"] == 2
    assert accepted["capabilities"]["syft"]["observation_count"] == 2
    shards = list((run_root / "data" / "artifact-security" / "shards" / "syft").glob("*/result.json"))
    assert len(shards) == 2


def test_configured_disabled_grype_never_calls_runner_and_publishes_gap(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = _fixture(tmp_path, disable_grype=True)
    calls: list[str] = []

    def scanner(capability, path, artifact, timeout, limit):
        calls.append(capability)
        return {
            "stdout": b"{}",
            "stderr": b"",
            "exit_code": 0,
            "observation": {},
            "tool_identity": {"scanner": capability, "image": "fixture", "rules": "fixture"},
        }

    recorded_graph(config, [build_job(scanner_runner=scanner)], run_id).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id
    )
    accepted = load_accepted_artifact_security_analysis(run_root)
    assert "grype" not in calls
    assert accepted["capabilities"]["grype"]["terminal_status"] == "NOT_APPLICABLE"
    assert "configured disabled" in accepted["capabilities"]["grype"]["gaps"][0]


def test_scan_fingerprint_adds_scanner_input_only_for_record_scans(tmp_path: Path, monkeypatch) -> None:
    materials: list[tuple[str, dict]] = []
    current: list[str] = []
    original_json, original_scan = security.canonical_json, security._scan_one

    def capture(value):
        if isinstance(value, dict) and value.get("schema") == security.OBSERVATION_SCHEMA and "parser" in value:
            materials.append((current[-1], value))
        return original_json(value)

    def scan(unit, artifact, capability, runner):
        current.append(capability)
        return original_scan(unit, artifact, capability, runner)

    def rows_with_addon(root: Path) -> list[dict]:
        rows = _installed_rows(root)
        addon = root / "data/build/node/node_modules/a/build/Release/addon.node"
        addon.parent.mkdir(parents=True)
        addon.write_bytes(b"\x7fELF-native-addon")
        return [
            *rows,
            {
                **{
                    key: rows[1][key]
                    for key in (
                        "build_unit_id",
                        "mapping",
                        "mapping_confidence",
                        "scope_role",
                        "delivery_evidence",
                    )
                },
                "path": addon.relative_to(root).as_posix(),
                "kind": "native-addon",
                "workspace_path": "node_modules/a/build/Release/addon.node",
                "sha256": file_sha256(addon),
                "size_bytes": addon.stat().st_size,
            },
        ]

    monkeypatch.setattr(security, "canonical_json", capture)
    monkeypatch.setattr(security, "_scan_one", scan)
    config, run_id, run_root, target, fingerprint, _ = _fixture(tmp_path, artifacts_factory=rows_with_addon)

    def scanner(capability, path, artifact, timeout, limit):
        return {
            "stdout": b"{}",
            "stderr": b"",
            "exit_code": 0,
            "observation": {},
            "tool_identity": {"scanner": capability, "image": "fixture", "rules": "fixture"},
        }

    recorded_graph(config, [build_job(scanner_runner=scanner)], run_id).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id
    )
    rows = {row["workspace_path"]: row for row in security._accepted_artifacts(run_root)["artifacts"]}
    record_sha = rows[RECORD]["sha256"]
    addon_sha = rows["node_modules/a/build/Release/addon.node"]["sha256"]
    by_scan = {(name, material["artifact_sha256"]): material for name, material in materials}
    record_scans = {name: material for (name, sha), material in by_scan.items() if sha == record_sha}
    assert record_scans["syft"]["scanner_input"]["environment"] == {
        "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"
    }
    assert record_scans["grype"]["scanner_input"]["environment"] == {}
    assert record_scans["osv"]["scanner_input"]["name"] == "package-lock.json"
    assert "inventory" in record_scans
    assert {("syft", addon_sha), ("grype", addon_sha)} <= set(by_scan)
    assert all(
        "scanner_input" not in material
        for (name, sha), material in by_scan.items()
        if sha != record_sha or name not in {"syft", "grype", "osv"}
    )


def test_installer_record_findings_are_attributed_to_verified_anchors(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = _fixture(tmp_path, artifacts_factory=_installed_rows)
    calls: list[tuple[str, str]] = []

    def scanner(capability, path, artifact, timeout, limit):
        calls.append((capability, artifact["workspace_path"]))
        observation: dict = {}
        if artifact["workspace_path"] == RECORD and capability == "grype":
            observation = {
                "matches": [
                    {
                        "vulnerability": {"id": check, "severity": "High"},
                        "artifact": {"name": name, "version": "1.0.0"},
                    }
                    for check, name in (("GHSA-aaaa", "a"), ("GHSA-mmmm", "mismatch"))
                ]
            }
        elif artifact["workspace_path"] == RECORD and capability == "osv":
            observation = {
                "results": [
                    {
                        "packages": [
                            {
                                "package": {"name": name, "version": "1.0.0", "ecosystem": "npm"},
                                "vulnerabilities": [{"id": check}],
                            }
                            for check, name in (("GHSA-aaaa", "a"), ("GHSA-mmmm", "mismatch"))
                        ]
                    }
                ]
            }
        elif artifact["workspace_path"] == RECORD and capability == "syft":
            observation = {
                "artifacts": [{"name": name, "version": version} for _, name, version, _ in INSTALLED]
            }
        return {
            "stdout": b"{}",
            "stderr": b"",
            "exit_code": 0,
            "observation": observation,
            "tool_identity": {"scanner": capability, "image": "fixture", "rules": "fixture"},
        }

    recorded_graph(config, [build_job(scanner_runner=scanner)], run_id).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id
    )
    assert sorted(calls) == [("grype", RECORD), ("osv", RECORD), ("syft", RECORD)]
    rows = {row["workspace_path"]: row for row in security._accepted_artifacts(run_root)["artifacts"]}
    record = rows[RECORD]
    anchors = sorted(
        (rows[f"{path}/package.json"] for path, *_rest in INSTALLED if path.endswith("/a")),
        key=lambda row: row["canonical_identity"],
    )

    accepted = load_accepted_artifact_security_analysis(run_root)
    capabilities = accepted["capabilities"]
    expected = {
        "artifact_id": record["artifact_id"],
        "workspace_path": RECORD,
        "sha256": record["sha256"],
        "presentation": "appsec-review/npm-installed-record-as-package-lock/1",
        "dev_anchors": 1,
    }
    assert [{key: entry[key] for key in expected} for entry in capabilities["grype"]["installer_records"]] == [
        expected
    ]
    assert capabilities["syft"]["installer_records"][0]["anchors_reported"] == 3
    assert [
        capabilities[name]["installer_records"][0]["anchors_covered"] for name in ("syft", "grype", "osv")
    ] == [3, 3, 0]
    assert capabilities["inventory"]["installer_records"] == []
    assert not any("were not reported" in gap for gap in capabilities["syft"]["gaps"])
    assert any("1 dev-only packages" in gap for gap in capabilities["grype"]["gaps"])

    [index_path] = (run_root / "data" / "indices" / "observations").glob("artifact-security-*.sqlite")
    with sqlite3.connect(index_path) as connection:
        entities = {
            identity: (text, json.loads(payload))
            for identity, text, payload in connection.execute(
                "SELECT identity, text, payload_json FROM entities"
            )
        }
        relations = connection.execute(
            "SELECT source_id, target_id, kind, confidence FROM relations"
        ).fetchall()
    findings = {
        (payload["capability"], payload["rule_id"]): (identity, payload)
        for identity, (_, payload) in entities.items()
        if payload.get("record_kind") == "finding"
    }
    assert set(findings) == {
        (name, check) for name in ("grype", "osv") for check in ("GHSA-aaaa", "GHSA-mmmm")
    }
    observed: dict[str, set[str]] = {}
    for source, target_id, kind, confidence in relations:
        if kind == "OBSERVED_AT":
            assert confidence == 1.0
            observed.setdefault(source, set()).add(target_id)
    for name in ("grype", "osv"):
        identity, payload = findings[(name, "GHSA-aaaa")]
        assert payload["installed_package_attribution"] == "verified-anchor"
        assert payload["installed_packages"] == [
            {
                "canonical_identity": anchor["canonical_identity"],
                "artifact_id": anchor["artifact_id"],
                "workspace_path": anchor["workspace_path"],
                "install_path": anchor["package_metadata"]["install_path"],
                "evidence_ref": f"{RECORD}#{anchor['package_metadata']['install_path']}",
                "dev": False,
                "dev_optional": False,
                "scope_role": "runtime_dependency",
            }
            for anchor in anchors
        ]
        assert "installed_packages_truncated" not in payload
        assert observed[identity] == {
            record["canonical_identity"],
            *(anchor["canonical_identity"] for anchor in anchors),
        }
        identity, payload = findings[(name, "GHSA-mmmm")]
        assert payload["installed_package_attribution"] == "unverified-record-entry"
        assert "installed_packages" not in payload
        assert observed[identity] == {record["canonical_identity"]}
    for anchor in anchors:
        assert anchor["canonical_identity"] in entities
    summaries = [
        identity for identity, (_, payload) in entities.items() if payload.get("record_kind") == "summary"
    ]
    assert all(len(observed[identity]) == 1 for identity in summaries)
