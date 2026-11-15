"""Unit tests for scanners.py: bounded JSON/XML parsers, adapters, and ContainerScannerRunner."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review import blint_report
from appsec_review.container_runtime import ContainerExecutor
from appsec_review.jobs.job_artifact_security_analysis import scanners as scanners_module
from appsec_review.jobs.job_artifact_security_analysis.scanners import (
    ADAPTERS,
    INSTALLER_RECORD_PRESENTATION,
    ContainerScannerRunner,
    ScannerAdapter,
    _bounded,
    _execution_token,
    native_result_count,
    parse_json,
    parse_spotbugs,
    scanner_input,
)

from .support import RECORD_METADATA, ROOT, _installed_rows


def test_bounded_parse_json_native_result_count_and_parse_spotbugs() -> None:
    assert _bounded({"a": 1}) == {"a": 1}

    class CustomObj:
        def __str__(self) -> str:
            return "X" * 5000

    truncations: set[str] = set()
    deep: dict = {"leaf": 1}
    for _ in range(9):
        deep = {"n": deep}
    bounded = _bounded(
        {
            "deep": deep,
            "k" * 140: "v" * 70_000,
            "arr": list(range(20_005)),
            "big_map": {f"m{i}": i for i in range(2_005)},
            "scalars": [None, True, 3, 1.5, CustomObj()],
        },
        truncations=truncations,
    )
    assert truncations == {"depth", "object_members", "object_key", "array_items", "string"}
    assert len(bounded["scalars"][-1]) == 4096

    with pytest.raises(ValueError, match="exceeds parser byte bound"):
        parse_json(bytes(64 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="output is empty"):
        parse_json(b"   \n")

    parsed_list = parse_json(b"[1, 2, 3]")
    assert parsed_list["records"] == [1, 2, 3]
    assert parsed_list["_native_result_count"] == 3
    assert parsed_list["_parser_truncated"] is False

    assert native_result_count(42) == 0
    assert native_result_count({"matches": [1, 2]}) == 2
    assert native_result_count({"other": 1}) == 0
    assert (
        native_result_count(
            {
                "results": [
                    "bad",
                    {"packages": ["bad", {"vulnerabilities": [1, 2]}, {"vulnerabilities": "bad"}]},
                ]
            }
        )
        == 2
    )

    with pytest.raises(ValueError, match="SpotBugs XML exceeds parser byte bound"):
        parse_spotbugs(bytes(64 * 1024 * 1024 + 1))
    sb = parse_spotbugs(
        b'<BugCollection xmlns="https://spotbugs.github.io/">'
        b'<BugInstance type="SQL" category="SECURITY" priority="1">'
        b'<SourceLine classname="pkg.A" sourcepath="pkg/A.java" start="3" end="5"/>'
        b"</BugInstance>"
        b'<BugInstance type="XSS" category="SECURITY" priority="2"/>'
        b"</BugCollection>"
    )
    assert sb["finding_count"] == 2 and sb["_parser_truncated"] is False
    assert sb["findings"][0]["class"] == "pkg.A" and sb["findings"][1]["class"] is None

    sb_many = parse_spotbugs(b"<BugCollection>" + (b"<BugInstance/>" * 20_001) + b"</BugCollection>")
    assert sb_many["finding_count"] == 20_000
    assert sb_many["finding_count_reported"] == 20_001
    assert sb_many["_parser_truncated"] is True
    assert sb_many["_parser_bounds"] == ["array_items"]


def test_scanner_adapters_scanner_input_and_execution_token() -> None:
    for capability, adapter in ADAPTERS.items():
        assert adapter.identity == "undeclared"
        argv = adapter.argv(f"/opt/{capability}", "outputs/sample.bin")
        assert argv[0] == f"/opt/{capability}"
        assert any("/target/sample.bin" in item for item in argv)
        assert argv[0] != next(item for item in argv if "/target/sample.bin" in item)
    assert ADAPTERS["blint"].argv("/opt/blint", "sample.bin") == (
        "/opt/blint",
        "--no-banner",
        "--no-error",
        "--quiet",
        "--src",
        "/target/sample.bin",
        "--reports",
        "/scratch",
    )
    assert "--lockfile" in ADAPTERS["osv"].argv("/opt/osv", "Cargo.lock")
    assert ADAPTERS["syft"].parse(b'{"artifacts":[{"name":"x"}]}')["_native_result_count"] == 1
    assert ADAPTERS["spotbugs"].parse(b"<BugCollection/>")["finding_count"] == 0
    with pytest.raises(ValueError, match="unknown scanner capability"):
        ScannerAdapter("other", "tool-other", frozenset({0}), "/scratch/out").argv("/bin/x", "a")

    record = {"dependency_metadata": dict(RECORD_METADATA)}
    assert scanner_input(record, "syft") == {
        "name": "package-lock.json",
        "presentation": INSTALLER_RECORD_PRESENTATION,
        "environment": {"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"},
    }
    assert scanner_input(record, "grype")["environment"] == {} == scanner_input(record)["environment"]
    assert scanner_input({"dependency_metadata": {**RECORD_METADATA, "extra": 1}}) is None
    assert scanner_input({"package_metadata": {"role": "installed-dependency-package"}}) is None

    shared = {"sha256": "a" * 64}
    assert _execution_token("syft", {**shared, "canonical_identity": "asr:a:1"}) != _execution_token(
        "syft", {**shared, "canonical_identity": "asr:a:2"}
    )
    with pytest.raises(ValueError, match="canonical identity is required"):
        _execution_token("syft", shared)


def test_container_scanner_runner_identity_caching_and_feed_validation(
    tmp_path: Path, monkeypatch
) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    runner = ContainerScannerRunner(ROOT, run_root, run_root / "scratch", osv_memory="2g")

    monkeypatch.setattr(runner.executor, "resolve_image", lambda tool: "sha256:" + "1" * 64)
    blint_id = runner.identity("blint", {})
    assert blint_id["image"] == "sha256:" + "1" * 64
    # Cached hit
    assert runner.identity("blint", {}) is blint_id

    # Image resolution failure records unavailable
    runner_missing = ContainerScannerRunner(ROOT, run_root, run_root / "scratch2")
    monkeypatch.setattr(
        runner_missing.executor,
        "resolve_image",
        lambda tool: (_ for _ in ()).throw(RuntimeError("no local image")),
    )
    unavailable = runner_missing.identity("syft", {})
    assert "pinned scanner image unavailable" in unavailable["unavailable"]
    with pytest.raises(RuntimeError, match="pinned scanner image unavailable"):
        runner_missing("syft", run_root, {"canonical_identity": "id"}, 10, 1024)

    # Grype valid + version mismatch
    grype_tool = runner.catalog.tool("tool-grype")
    monkeypatch.setattr(scanners_module.grype_feed, "consumer_settings", lambda repo, run: "settings")
    monkeypatch.setattr(
        scanners_module.grype_feed,
        "verify",
        lambda settings, expected_image_id: {
            "tool": {"tool_version": grype_tool.version},
            "snapshot_id": "snap-1",
            "manifest_sha256": "2" * 64,
            "directory": str(tmp_path / "grype-db"),
        },
    )
    grype_id = runner.identity("grype", {})
    assert grype_id["rules"] == {"feed": "grype", "snapshot_id": "snap-1", "manifest_sha256": "2" * 64}

    runner_mismatch = ContainerScannerRunner(ROOT, run_root, run_root / "scratch3")
    monkeypatch.setattr(runner_mismatch.executor, "resolve_image", lambda tool: "sha256:" + "1" * 64)
    monkeypatch.setattr(
        scanners_module.grype_feed,
        "verify",
        lambda settings, expected_image_id: {
            "tool": {"tool_version": "0.0.0-wrong"},
            "snapshot_id": "snap-1",
            "manifest_sha256": "2" * 64,
            "directory": str(tmp_path),
        },
    )
    assert "verified immutable grype database unavailable" in runner_mismatch.identity("grype", {})["unavailable"]

    # OSV valid
    osv_dir = tmp_path / "osv-db"
    osv_dir.mkdir()
    monkeypatch.setattr(
        scanners_module,
        "verify_current",
        lambda path, feed: {"snapshot_id": "osv-1", "manifest_sha256": "3" * 64, "directory": str(osv_dir)},
    )
    monkeypatch.setattr(scanners_module, "snapshot_ecosystems", lambda d: {"npm": osv_dir})
    osv_id = runner.identity("osv", {})
    assert osv_id["rules"]["feed"] == "osv"


@pytest.mark.parametrize("capability", ("syft", "grype", "osv"))
def test_runner_stages_installer_record_as_read_only_package_lock(
    tmp_path: Path, monkeypatch, capability: str
) -> None:
    run_root = tmp_path / "run"
    [record, *_anchors] = _installed_rows(run_root)
    path = run_root / record["path"]
    before = path.read_bytes()
    requests = []

    class Captured(Exception):
        pass

    def execute(self, request):
        requests.append(request)
        raise Captured

    monkeypatch.setattr(ContainerExecutor, "execute", execute)
    runner = ContainerScannerRunner(ROOT, run_root, run_root / "scratch", osv_memory="3g")
    monkeypatch.setattr(runner, "identity", lambda *args: {"scanner": "fixture"})
    database = tmp_path / "database"
    (database / "npm").mkdir(parents=True)
    runner._feeds["grype"] = {"directory": str(database)}
    runner._osv_ecosystems = {"npm": database / "npm"}
    with pytest.raises(Captured):
        runner(capability, path, {**record, "canonical_identity": "fixture:record"}, 30, 4096)

    [request] = requests
    staged = [mount for mount in request.extra_mounts if mount.target.startswith("/target/")]
    assert [(mount.source, mount.target, mount.read_only) for mount in staged] == [
        (path, "/target/package-lock.json", True)
    ]
    assert "/target/package-lock.json" in " ".join(request.argv)
    assert request.target_root.parent == run_root / "scratch" / "installer-records"
    assert "node_modules" not in request.target_root.parts
    assert path.read_bytes() == before
    if capability == "osv":
        assert request.memory == "3g"
        assert request.expected_nonzero(128, b"No package sources found", b"") is True


def test_runner_executes_target_intake_missing_osv_ecosystem_blint_and_stdout_fallback(
    tmp_path: Path, monkeypatch
) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    artifact_file = run_root / "data/shared/objects/ab/hash"
    artifact_file.parent.mkdir(parents=True)
    artifact_file.write_bytes(b"version = 3\n")
    runner = ContainerScannerRunner(ROOT, run_root, run_root / "scratch")
    monkeypatch.setattr(runner, "identity", lambda *args: {"scanner": "fixture"})

    # OSV missing ecosystem returns precondition_gap without container execution
    runner._osv_ecosystems = {}
    precond = runner(
        "osv",
        artifact_file,
        {
            "canonical_identity": "asr:target:cargo",
            "sha256": "a" * 64,
            "artifact_origin": "target-intake",
            "target_relative_path": "sub/Cargo.lock",
        },
        30,
        4096,
    )
    assert precond["exit_code"] is None and precond["execution_receipt"] is None
    assert "Cargo" in precond["precondition_gap"] or "crates.io" in precond["precondition_gap"]

    # Blint assembly + target-intake staging + stdout fallback when output file absent
    def fake_execute(self, request):
        stdout_rel = f"stdout-{request.tool_id}.bin"
        stderr_rel = f"stderr-{request.tool_id}.bin"
        receipt_rel = f"receipt-{request.tool_id}.json"
        (run_root / stdout_rel).write_bytes(b'{"fallback":true}')
        (run_root / stderr_rel).write_bytes(b"")
        (run_root / receipt_rel).write_text("{}", encoding="utf-8")
        if request.tool_id == "tool-blint":
            (request.scratch_root / "findings.json").write_text('{"findings":[]}', encoding="utf-8")
        return SimpleNamespace(
            exit_code=0,
            timed_out=False,
            stdout_path=stdout_rel,
            stderr_path=stderr_rel,
            stdout_truncated=True,
            stderr_truncated=False,
            receipt_path=receipt_rel,
        )

    monkeypatch.setattr(ContainerExecutor, "execute", fake_execute)
    monkeypatch.setattr(
        blint_report,
        "write",
        lambda scratch, out: out.write_text(json.dumps({"analyzed": True, "findings": []}), encoding="utf-8"),
    )
    blint_out = runner(
        "blint",
        artifact_file,
        {
            "canonical_identity": "asr:target:bin",
            "sha256": "b" * 64,
            "artifact_origin": "target-intake",
            "target_relative_path": "bin/app",
        },
        30,
        4096,
    )
    assert blint_out["payload_truncated"] is False
    assert "findings.json" in blint_out["native_reports"]
    assert blint_out["execution_receipt"]["path"] == "receipt-tool-blint.json"

    syft_out = runner(
        "syft",
        artifact_file,
        {"canonical_identity": "asr:produced:pkg", "sha256": "c" * 64},
        30,
        4096,
    )
    assert syft_out["payload"] == b'{"fallback":true}'
    assert syft_out["payload_truncated"] is True
