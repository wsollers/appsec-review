"""osv-scanner runs once per target project, mounts only needed databases, and isolates failures.

Offline osv-scanner loads every mounted ecosystem database whole (npm alone is 368 MB of JSON), so
one launch for the whole target was OOM-killed on a live run and lost all OSV coverage. Every
executor here is injected; nothing needs Docker.
"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.config.evidence_collection import (
    EvidenceCollectionSettings, parse_evidence_collection_settings,
)
from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, load_catalog
from appsec_review.container_runtime.executor import CommandOutcome
from appsec_review.container_runtime.catalog import ContainerCatalog
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_artifact_security_analysis.scanners import ContainerScannerRunner
from appsec_review.jobs.job_evidence_collection import build_job as build_evidence
from appsec_review.jobs.job_evidence_collection.adapters import Applicability, ScanCatalog, adapter_registry
from appsec_review.jobs.job_evidence_collection.job import _plan_invocations, osv_project_groups
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_analysis_plan
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.osv_offline import offline_database_mounts
from appsec_review.runtime import GraphRunner

from tests import test_evidence_collection_job as evidence_tests
from tests.test_tool_adapter_outputs import _osv_snapshot


ROOT = Path(__file__).parents[1]
OSV = "tool-osv-scanner"
SCAN_UNIT = "vulnerability_matching.osv_scanner_scan"


def _lockfiles(argv: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(argv[index + 1] for index, value in enumerate(argv) if value == "--lockfile")


def test_lockfiles_group_by_deepest_project_root_else_their_directory() -> None:
    projects = ({"root": "."}, {"root": "web"}, {"root": "web/admin"}, {"root": "svc"}, {"root": "svc"})
    groups = osv_project_groups(
        ("web/package-lock.json", "web/admin/yarn.lock", "web/admin/deep/pnpm-lock.yaml",
         "svc/Cargo.lock", "requirements.txt", "webapp/poetry.lock"), projects)
    assert groups == {
        ".": ("requirements.txt", "webapp/poetry.lock"),  # "webapp" is not under "web"
        "svc": ("svc/Cargo.lock",),
        "web": ("web/package-lock.json",),
        "web/admin": ("web/admin/deep/pnpm-lock.yaml", "web/admin/yarn.lock"),
    }
    # Without a root project, a lockfile outside every project groups by its own directory.
    assert osv_project_groups(("tools/requirements.txt", "Cargo.lock"), ({"root": "web"},)) == {
        ".": ("Cargo.lock",), "tools": ("tools/requirements.txt",)}


def test_invocations_chunk_large_projects_and_mount_only_needed_databases(tmp_path: Path) -> None:
    archives = {}
    for name in ("npm", "PyPI", "crates.io"):
        archives[name] = tmp_path / f"{name}.zip"
        archives[name].write_bytes(b"zip")
    mounts = offline_database_mounts(archives)
    files = ("api/requirements.txt", *(f"web/pkg{index}/package-lock.json" for index in range(5)))
    selection = Applicability(True, "x", files, "dependency_lockfiles")
    catalog = ScanCatalog("fp", "h", (), ({"root": "api"}, {"root": "web"}))
    invocations = _plan_invocations(adapter_registry()[OSV], catalog, selection, mounts, 2)
    assert [(item.project_root, len(item.selection.files)) for item in invocations] == [
        ("api", 1), ("web", 2), ("web", 2), ("web", 1)]
    assert {mount.target for mount in invocations[0].mounts} == {"/database/osv-scanner/PyPI/all.zip"}
    assert all({mount.target for mount in item.mounts} == {"/database/osv-scanner/npm/all.zip"}
               for item in invocations[1:])
    assert invocations[0].subject == " for project api (1 lockfile(s))"
    assert invocations[2].subject == " for project web (chunk 2/3, 2 lockfile(s))"
    assert sorted(path for item in invocations for path in item.selection.files) == sorted(files)
    # Other tools keep one launch over the whole selection.
    semgrep = _plan_invocations(adapter_registry()["tool-semgrep"], catalog, selection, mounts, 2)
    assert len(semgrep) == 1 and semgrep[0].selection is selection and semgrep[0].project_root is None


class ProjectExecutor(evidence_tests.FakeExecutor):
    """Report one advisory per lockfile; OOM-kill launches that scan a project in ``oom``."""

    def __init__(self, repository: Path, run_root: Path, calls: list[str], history: list, oom: set[str]):
        super().__init__(repository, run_root, calls)
        self.history = history
        self.oom = oom

    def execute(self, request):
        result = super().execute(request)
        if request.tool_id != OSV:
            return result
        self.history.append(request)
        lockfiles = _lockfiles(request.argv)
        if any(path.removeprefix("/target/").split("/")[0] in self.oom for path in lockfiles):
            return replace(result, exit_code=137, oom_killed=True)
        document = {"results": [{"source": {"path": path, "type": "lockfile"}, "packages": [{
            "package": {"name": f"pkg-{path.split('/')[-2]}"},
            "vulnerabilities": [{"id": f"GHSA-{path.split('/')[-2]}", "summary": "fixture"}]}]}
            for path in lockfiles]}
        (request.scratch_root / "output.json").write_text(json.dumps(document), encoding="utf-8")
        return result


def _run(tmp_path: Path, oom: set[str]):
    config, target = evidence_tests.fixture(tmp_path)
    (target / "package-lock.json").unlink()
    for relative, text in {"web/package.json": "{}", "web/package-lock.json": "{}",
                           "api/pyproject.toml": "[project]\nname='api'\n",
                           "api/requirements.txt": "requests==2.19.0\n"}.items():
        (target / relative).parent.mkdir(parents=True, exist_ok=True)
        (target / relative).write_text(text, encoding="utf-8")
    _osv_snapshot(tmp_path, ("PyPI", "npm"))
    calls: list[str] = []
    history: list = []
    factory = lambda unit: ProjectExecutor(unit.job.repository_root, unit.job.run_root, calls, history, oom)
    outcome = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan(),
                                   build_evidence(executor_factory=factory)]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    run_root = config.runtime.runs_dir / outcome["run_id"]
    scan = outcome["jobs"]["job_evidence_collection"]["result"]["outputs"][SCAN_UNIT]
    telemetry = [json.loads(line) for line in (run_root / "data" / "logs" / "pipeline.jsonl").read_text(
        encoding="utf-8").splitlines()]
    events = [item["details"] for item in telemetry if item["event_type"].startswith("TOOL_INVOCATION")
              and item["details"].get("tool_id") == OSV]
    return run_root, scan, history, events


def test_one_project_oom_is_a_named_gap_and_other_projects_keep_their_evidence(tmp_path: Path) -> None:
    run_root, scan, history, events = _run(tmp_path, {"web"})
    retries = int(load_config(tmp_path / "appsec-review.toml").job("job_evidence_collection")
                  .settings["tool_retries"])
    # api once, web once plus its retries; each with only its own lockfiles and database.
    assert sorted(_lockfiles(item.argv) for item in history) == sorted(
        [("/target/api/requirements.txt",)] + [("/target/web/package-lock.json",)] * (retries + 1))
    assert all(item.memory == "3g" for item in history)
    for item in history:
        databases = {mount.target for mount in item.extra_mounts if mount.target.startswith("/database/")}
        assert databases == ({"/database/osv-scanner/npm/all.zip"} if "web" in item.argv[-1]
                             else {"/database/osv-scanner/PyPI/all.zip"})
    assert scan["terminal_status"] == "PARTIAL"
    assert "tool-osv-scanner was OOM-killed for project web (1 lockfile(s))" in scan["gaps"]
    assert {item["project_root"]: item["terminal_status"] for item in scan["invocations"]} == {
        "api": "SUCCEEDED", "web": "FAILED"}
    evidence = json.loads((run_root / scan["artifact"]["path"]).read_text(encoding="utf-8"))
    assert evidence["terminal_status"] == "PARTIAL"
    assert [record.get("advisory") for record in evidence["records"]] == ["GHSA-api"]
    merged = json.loads((run_root / scan["scanner_output"]).read_text(encoding="utf-8"))
    assert [item["source"]["path"] for item in merged["results"]] == ["/target/api/requirements.txt"]
    assert [item["project_root"] for item in merged["invocations"]] == ["api"]
    assert {(item["project_root"], item["lockfile_count"]) for item in events} == {("api", 1), ("web", 1)}
    completed = [item for item in events if "disposition" in item]
    assert {item["project_root"]: item["disposition"] for item in completed if item["project_root"] == "api"} == {
        "api": "SUCCEEDED"}
    receipt_paths = {item["path"] for item in json.loads(
        (run_root / scan["checkpoint"]["path"]).read_text(encoding="utf-8"))["artifacts"]}
    assert scan["scanner_output"] in receipt_paths


def test_every_project_failing_is_failed_with_a_retry_marker(tmp_path: Path) -> None:
    run_root, scan, history, _ = _run(tmp_path, {"web", "api"})
    assert scan["terminal_status"] == "FAILED" and scan["scanner_output"] is None
    assert {gap for gap in scan["gaps"] if "OOM-killed" in gap} == {
        "tool-osv-scanner was OOM-killed for project api (1 lockfile(s))",
        "tool-osv-scanner was OOM-killed for project web (1 lockfile(s))"}
    marker = json.loads((run_root / "data" / "task-checkpoints" / "job_evidence_collection" / OSV /
                         "retry-required.json").read_text(encoding="utf-8"))
    assert marker["retry_required"] is True and marker["checkpoint_identity"] == scan["checkpoint_identity"]


def _executor(tmp_path: Path, commands: list) -> tuple[ContainerExecutor, ContainerCatalog]:
    catalog = load_catalog(ROOT)

    def runner(argv, timeout):
        commands.append(list(argv))
        if argv[:3] == ("docker", "image", "inspect"):
            return CommandOutcome(0, b"sha256:" + b"b" * 64 + b"\n", b"")
        return CommandOutcome(0, b"{}", b"")

    tool = replace(catalog.tool(OSV), expected_image_id=None)
    pinned = ContainerCatalog(catalog.source, catalog.runtime_policy, catalog.policy, {OSV: tool})
    return ContainerExecutor(pinned, tmp_path, runner=runner), pinned


def test_memory_override_reaches_the_docker_command_and_the_receipt(tmp_path: Path) -> None:
    commands: list = []
    executor, catalog = _executor(tmp_path, commands)
    target = tmp_path / "target"
    target.mkdir()
    tool = catalog.tool(OSV)
    request = ExecutionRequest(OSV, (tool.executable, "--version"), target, tmp_path / "scratch", memory="3g")
    result = executor.execute(request)
    run = next(command for command in commands if command[:2] == ["docker", "run"])
    assert run[run.index("--memory") + 1] == "3g"
    receipt = json.loads((tmp_path / result.receipt_path).read_text(encoding="utf-8"))
    assert receipt["limits"]["memory"] == "3g" and receipt["limits"]["memory_source"] == "request"
    # Without an override the catalog policy value applies and is recorded as such.
    default = executor.execute(replace(request, memory=None, scratch_root=tmp_path / "scratch2"))
    receipt = json.loads((tmp_path / default.receipt_path).read_text(encoding="utf-8"))
    assert receipt["limits"]["memory"] == tool.memory and receipt["limits"]["memory_source"] == "catalog"
    for invalid in ("3G", "3", "0g", "3g --privileged", "1.5g"):
        with pytest.raises(ValueError, match="memory override"):
            executor.execute(replace(request, memory=invalid))


def test_artifact_osv_mounts_only_the_lockfile_ecosystem_with_the_configured_memory(tmp_path: Path) -> None:
    requests: list = []
    runner = object.__new__(ContainerScannerRunner)
    runner.scratch_root = tmp_path / "scratch"
    runner.run_root = tmp_path
    runner.catalog = load_catalog(ROOT)
    runner.osv_memory = "3g"
    runner._identities = {"osv": {"scanner": OSV, "adapter": "fixture"}}
    runner._osv_ecosystems = {"PyPI": tmp_path / "PyPI.zip", "npm": tmp_path / "npm.zip"}

    class Recording:
        def execute(self, request):
            requests.append(request)
            raw = request.scratch_root / "raw"
            raw.mkdir(parents=True, exist_ok=True)
            for name in ("stdout.bin", "stderr.bin"):
                (raw / name).write_bytes(b"")
            (request.scratch_root / "execution.json").write_text("{}", encoding="utf-8")
            rel = lambda path: path.relative_to(tmp_path).as_posix()
            return SimpleNamespace(stdout_path=rel(raw / "stdout.bin"), stderr_path=rel(raw / "stderr.bin"),
                                   receipt_path=rel(request.scratch_root / "execution.json"),
                                   exit_code=0, timed_out=False, stdout_truncated=False,
                                   stderr_truncated=False)

    runner.executor = Recording()
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("requests==2.19.0\n", encoding="utf-8")
    runner("osv", lockfile, {"canonical_identity": "asr:x:1", "sha256": "a" * 64}, 60, 1024)
    (request,) = requests
    assert request.memory == "3g"
    assert [mount.target for mount in request.extra_mounts] == ["/database/osv-scanner/PyPI/all.zip"]


def test_evidence_collection_settings_are_typed_and_validated() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    typed = config.job("job_evidence_collection").typed_settings
    assert typed == EvidenceCollectionSettings(tool_retries=1, osv_memory="3g",
                                               osv_max_lockfiles_per_invocation=50)
    assert parse_evidence_collection_settings({}) == EvidenceCollectionSettings()
    for settings, message in (({"osv_memory": "3gb"}, "osv_memory"), ({"osv_memory": 3}, "osv_memory"),
                              ({"osv_memory": "256m"}, "between 512m and 64g"),
                              ({"osv_memory": "65g"}, "between 512m and 64g"),
                              ({"osv_max_lockfiles_per_invocation": 0}, "osv_max_lockfiles"),
                              ({"osv_max_lockfiles_per_invocation": True}, "osv_max_lockfiles"),
                              ({"tool_retries": 4}, "tool_retries"),
                              ({"osv_mem": "3g"}, "unknown settings")):
        with pytest.raises(ValueError, match=message):
            parse_evidence_collection_settings(settings)
