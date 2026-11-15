"""Shared code-level test fixtures and fake container executor for job_evidence_collection."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import shutil
from types import SimpleNamespace
from typing import Any, Mapping
import zipfile

from appsec_review.config import load_config
from appsec_review.config.assurance import ComponentReleases, ReviewPolicy
from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner
from appsec_review.config.evidence_collection import EvidenceCollectionSettings
from appsec_review.container_runtime import load_catalog
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.job_evidence_collection.adapters import ADAPTERS, ScanCatalog, adapter_registry
from appsec_review.jobs.job_evidence_collection.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_evidence_collection.job import TOPOLOGY
from appsec_review.jobs.job_third_party_data_sync.publication import publish_snapshot
from appsec_review.retrieval import IndexIdentity, write_manifest
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, file_sha256
from tests.container_fixture import copy_containers
from tests.handoff_fixture import write_fixture_handoff
from tests.release_support import declare_releases


ROOT = Path(__file__).resolve().parents[3]
DIGEST = "sha256:" + "a" * 64
SOURCE_FP = "f" * 64
_BASE_CONFIG = load_config(ROOT / "appsec-review.toml")
_BASE_RESOLVED_BYTES = _BASE_CONFIG.resolved_json
_BASE_RESOLVED_SHA256 = _BASE_CONFIG.resolved_sha256


class FakeExecutor:
    """Deterministic fake ContainerExecutor that never invokes Docker."""

    def __init__(self, repository: Path, run_root: Path, calls: list[str]):
        self.catalog = load_catalog(repository)
        self.run_root = run_root
        self.calls = calls

    def resolve_image(self, tool: Any) -> str:
        return DIGEST

    def execute(self, request: Any) -> ExecutionResult:
        self.calls.append(request.tool_id)
        for mount in request.extra_mounts:
            if mount.source.is_file():
                assert mount.source.stat().st_mode & 0o004, f"{mount.source} is unreadable by the tool user"
        request.scratch_root.mkdir(parents=True, exist_ok=True)
        stdout = request.scratch_root / "raw" / "stdout.bin"
        stderr = request.scratch_root / "raw" / "stderr.bin"
        stdout.parent.mkdir(parents=True, exist_ok=True)
        payload = b"{}"
        stdout.write_bytes(payload)
        stderr.write_bytes(b"")
        output_names = {
            "tool-gitleaks": "output.json",
            "tool-semgrep": "output.json",
            "tool-opengrep": "output.json",
            "tool-gosec": "output.json",
            "tool-mobsfscan": "output.json",
            "tool-syft": "output.json",
            "tool-osv-scanner": "output.json",
            "tool-grype": "output.json",
            "tool-trivy": "output.json",
            "tool-blint": "blint-report.json",
        }
        if request.tool_id in output_names:
            if request.tool_id == "tool-blint":
                (request.scratch_root / "reviews.json").write_text('[{"exe_name": "app"}]', encoding="utf-8")
                (request.scratch_root / "findings.json").write_text('{"findings": []}', encoding="utf-8")
            (request.scratch_root / output_names[request.tool_id]).write_bytes(payload)
        if request.tool_id == "tool-semgrep" or request.tool_id == "tool-opengrep":
            scanned = [arg for arg in request.argv if arg.startswith("/target/")]
            (request.scratch_root / "output.json").write_text(
                json.dumps({"results": [], "errors": [], "paths": {"scanned": scanned}}),
                encoding="utf-8",
            )
        if request.tool_id == "tool-spotbugs":
            (request.scratch_root / "output.xml").write_text("<BugCollection/>", encoding="utf-8")
        if request.tool_id == "tool-cppcheck":
            (request.scratch_root / "output.xml").write_text("<results><errors/></results>", encoding="utf-8")
        if request.tool_id == "tool-pmd":
            (request.scratch_root / "output.json").write_text('{"files":[]}', encoding="utf-8")
        receipt = request.scratch_root / "execution.json"
        receipt.write_text("{}", encoding="utf-8")
        rel = lambda path: path.relative_to(self.run_root).as_posix()
        return ExecutionResult(
            "appsec-review/container-execution/1",
            request.tool_id,
            "fixture:1",
            DIGEST,
            DIGEST,
            "argv",
            (),
            {},
            "start",
            "end",
            0,
            False,
            False,
            False,
            False,
            rel(stdout),
            rel(stderr),
            rel(receipt),
        )


def fixture(tmp_path: Path):
    """Build a hermetic repository/config/target fixture without copying host feed archives."""
    shutil.copy2(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    config_path = tmp_path / "appsec-review.toml"
    releases = [
        "platform",
        "validation",
        *adapter_registry(),
        *(f"rules_{tool}" for tool in adapter_registry()),
    ]
    text = config_path.read_text(encoding="utf-8")
    config_path.write_text(declare_releases(text, **{key: "fixture-1" for key in releases}), encoding="utf-8")
    copy_containers(ROOT, tmp_path)
    shutil.copytree(ROOT / "rules", tmp_path / "rules")
    target = tmp_path / "target"
    (target / ".github" / "workflows").mkdir(parents=True)
    (target / "main.py").write_text("print('fixture')\n", encoding="utf-8")
    (target / "main.go").write_text("package main\nfunc main(){}\n", encoding="utf-8")
    (target / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    (target / "app.php").write_text("<?php echo 'fixture';\n", encoding="utf-8")
    (target / "run.sh").write_text("#!/bin/sh\necho fixture\n", encoding="utf-8")
    (target / "MainActivity.java").write_text("class MainActivity {}\n", encoding="utf-8")
    (target / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
    (target / "main.tf").write_text('resource "x" "y" {}\n', encoding="utf-8")
    (target / ".github" / "workflows" / "ci.yml").write_text("on: push\njobs: {}\n", encoding="utf-8")
    (target / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{}}', encoding="utf-8")
    return load_config(config_path), target


def write_osv_feed(repository_root: Path, ecosystems: tuple[str, ...] = ("npm",)) -> Path:
    """Publish a tiny synthetic OSV snapshot under ``repository_root/data/feeds/osv``."""
    staging = repository_root / ".osv-staging"
    staging.mkdir(parents=True, exist_ok=True)
    files: dict[str, Path] = {}
    for ecosystem in ecosystems:
        archive = staging / f"{ecosystem}.zip"
        with zipfile.ZipFile(archive, "w"):
            pass
        files[f"sources/{ecosystem}.zip"] = archive
    publish_snapshot(
        repository_root / "data" / "feeds" / "osv",
        feed_id="osv",
        schema="appsec-review/osv-snapshot/1",
        files=files,
        manifest_fields={"source": "unit-fixture"},
    )
    shutil.rmtree(staging, ignore_errors=True)
    return repository_root / "data" / "feeds" / "osv"


def make_unit_context(
    tmp_path: Path,
    *,
    unit_id: str = "source_sast.shellcheck_scan",
    repository_root: Path = ROOT,
    target_files: Mapping[str, bytes | str] | None = None,
    settings_override: Mapping[str, Any] | None = None,
    task_settings: Mapping[str, Any] | None = None,
    declared_releases: bool = True,
    strict_platform_verification: bool = False,
    disable_grype: bool = False,
    enable_swift: bool = False,
    source_fingerprint: str = SOURCE_FP,
    outputs: Mapping[str, Any] | None = None,
) -> tuple[SimpleNamespace, ScanCatalog, list[tuple[str, dict[str, Any]]]]:
    """Construct a fast, engine-free UnitContext + ScanCatalog for direct code-level calls."""
    run_root = tmp_path / "runs" / "run_0001"
    attempt_root = run_root / "data" / "jobs" / "job_evidence_collection" / "attempts" / "attempt_0001"
    step_id, task_id = unit_id.split(".", 1)
    unit_root = attempt_root / "steps" / step_id / "tasks" / task_id
    unit_root.mkdir(parents=True, exist_ok=True)

    target_root = tmp_path / "target"
    target_root.mkdir(parents=True, exist_ok=True)
    files_spec = {"run.sh": "#!/bin/sh\necho hi\n"} if target_files is None else dict(target_files)
    catalog_files: list[dict[str, Any]] = []
    lang_by_suffix = {
        ".py": "Python",
        ".go": "Go",
        ".cpp": "C++",
        ".c": "C",
        ".h": "C",
        ".java": "Java",
        ".kt": "Kotlin",
        ".swift": "Swift",
        ".scala": "Scala",
        ".php": "PHP",
        ".sh": "Shell",
        ".tf": "HCL",
    }
    for rel, raw in sorted(files_spec.items()):
        data = raw.encode("utf-8") if isinstance(raw, str) else raw
        dest = target_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        catalog_files.append({
            "path": rel,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
            "language": lang_by_suffix.get(Path(rel).suffix.lower()),
        })

    settings = {
        "enabled": True,
        "tool_retries": 1,
        "osv_memory": "3g",
        "osv_max_lockfiles_per_invocation": 50,
        **(dict(settings_override) if settings_override else {}),
    }
    typed_settings = EvidenceCollectionSettings(
        tool_retries=int(settings["tool_retries"]),
        osv_memory=str(settings["osv_memory"]),
        osv_max_lockfiles_per_invocation=int(settings["osv_max_lockfiles_per_invocation"]),
    )
    releases = (
        {
            "platform": "fixture-1",
            "validation": "fixture-1",
            **{tool: "fixture-1" for tool in ADAPTERS},
            **{f"rules_{tool}": "fixture-1" for tool in ADAPTERS},
        }
        if declared_releases
        else {}
    )
    policy = ReviewPolicy(
        releases=ComponentReleases(values=releases),
    )

    events: list[tuple[str, dict[str, Any]]] = []
    task_cfg = SimpleNamespace(settings=dict(task_settings or {}))
    steps_map = {
        s: SimpleNamespace(
            tasks={t: (task_cfg if (s, t) == (step_id, task_id) else SimpleNamespace(settings={})) for t in tasks},
            task=lambda t, s_name=s, t_list=tasks: (
                task_cfg if (s_name, t) == (step_id, task_id) else SimpleNamespace(settings={})
            ),
        )
        for s, tasks in TOPOLOGY.items()
    }
    job_cfg = SimpleNamespace(
        job_id="job_evidence_collection",
        settings=settings,
        typed_settings=typed_settings,
        steps=steps_map,
        step=steps_map.__getitem__,
    )
    out_map = dict(outputs or {})
    config_dir = run_root / "data" / "configuration"
    config_dir.mkdir(parents=True, exist_ok=True)
    resolved_path = config_dir / "resolved.json"
    if not resolved_path.is_file():
        resolved_path.write_bytes(_BASE_RESOLVED_BYTES)
        atomic_json(config_dir / "manifest.json", {"resolved_sha256": _BASE_RESOLVED_SHA256})
    claim_path = attempt_root / "claim.json"
    atomic_json(
        claim_path,
        {
            "run_id": run_root.name,
            "job_id": "job_evidence_collection",
            "attempt_id": "attempt_0001",
            "attempt_path": attempt_root.relative_to(run_root).as_posix(),
            "repository_root": str(repository_root),
            "resolved_config_sha256": _BASE_RESOLVED_SHA256,
            "orchestration": {"system": "cli"},
            "dataset_contract": dataset_contract(
                "job_evidence_collection",
                sorted({d.step for d in DATASETS}),
                DATASETS,
                job_contract=CONTRACT.document(),
            ),
        },
    )

    unit = SimpleNamespace(
        unit_id=unit_id,
        step_id=step_id,
        task_id=task_id,
        unit_root=unit_root,
        output=out_map.__getitem__,
        job=SimpleNamespace(
            run_id=run_root.name,
            attempt_id="attempt_0001",
            run_root=run_root,
            attempt_root=attempt_root,
            repository_root=repository_root,
            target_root=target_root,
            source_fingerprint=source_fingerprint,
            orchestration={"system": "cli"},
            config=job_cfg,
            tools=SimpleNamespace(disable_grype=disable_grype, enable_swift=enable_swift),
            review_policy=policy,
            events=SimpleNamespace(write=lambda event_type, **details: events.append((event_type, details))),
            input_manifest_path=None,
            input_manifest_sha256=None,
        ),
    )
    catalog = ScanCatalog(
        source_fingerprint=source_fingerprint,
        handoff_sha256="c" * 64,
        files=tuple(catalog_files),
        projects=({"root": ".", "ecosystem": "generic"},),
        artifacts=(),
        target_root=target_root,
        compile_commands=(),
    )
    return unit, catalog, events


@contextmanager
def attempt_scope(unit: Any):
    """Activate SharedArtifacts provenance owner for direct unit-handler calls."""
    with publication_scope_for_owner(SharedArtifacts.for_job(unit.job)):
        yield


def seed_accepted_catalog_and_plan(
    run_root: Path,
    target_root: Path,
    *,
    files: list[dict[str, Any]],
    projects: list[dict[str, Any]] | None = None,
    build_targets: list[dict[str, Any]] | None = None,
    compile_commands: list[dict[str, Any]] | None = None,
    scanner_selections: list[dict[str, Any]] | None = None,
    source_fingerprint: str = SOURCE_FP,
    plan_fingerprint: str | None = None,
    include_intake: bool = True,
) -> dict[str, str]:
    """Write accepted handoffs for intake, target catalog, and target analysis plan."""
    shas: dict[str, str] = {}

    def _art(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(path, dict(payload))
        return {
            "path": path.relative_to(run_root).as_posix(),
            "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size,
        }

    if include_intake:
        intake_attempt = run_root / "data/jobs/job_review_intake/attempts/attempt_0001"
        intake_doc = _art(
            intake_attempt / "steps/publish_intake/tasks/publish_handoff/review-intake.json",
            {
                "schema": "appsec-review/review-intake/1",
                "source_fingerprint": source_fingerprint,
                "target": {"path": str(target_root)},
            },
        )
        intake_handoff = write_fixture_handoff(
            run_root,
            intake_attempt / "handoff.json",
            {
                "job_id": "job_review_intake",
                "schema_identity": "appsec-review/review-intake/1",
                "source_fingerprint": source_fingerprint,
                "outputs": {"publish_intake.publish_handoff": {"artifact": intake_doc}},
            },
        )
        shas["job_review_intake"] = file_sha256(intake_handoff)
        atomic_json(
            intake_attempt.parent.parent / "latest.json",
            {
                "schema": "appsec-review/latest-handoff/1",
                "attempt_id": "attempt_0001",
                "handoff_path": intake_handoff.relative_to(run_root).as_posix(),
                "handoff_sha256": shas["job_review_intake"],
            },
        )

    cat_attempt = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001"
    part_ref = _art(
        cat_attempt / "artifacts/partition.json",
        {
            "files": files,
            "target_artifacts": [{"path": "bin/app.bin"}],
            "gaps": [
                {"path": "vendor/skip", "reason": "excluded_directory"},
                {"path": "broken/link", "reason": "symlink_outside_target"},
            ],
        },
    )
    proj_ref = _art(cat_attempt / "artifacts/projects.json", {"projects": projects or []})
    build_ref = _art(cat_attempt / "artifacts/builds.json", {"targets": build_targets or []})
    cc_ref = _art(cat_attempt / "artifacts/compile_commands.json", {"files": compile_commands or []})
    cat_doc = _art(
        cat_attempt / "steps/publish_catalog/tasks/publish_handoff/target-catalog.json",
        {
            "schema": "appsec-review/target-catalog/1",
            "source_fingerprint": source_fingerprint,
            "artifacts": {
                "repository_discovery.partition_repository": part_ref,
                "repository_discovery.discover_projects": proj_ref,
                "build_discovery.catalog_build_targets": build_ref,
                "build_discovery.discover_compile_commands": cc_ref,
            },
        },
    )
    from appsec_review.retrieval import EntityKind, EntityRecord, LogicalIdentity
    from appsec_review.retrieval.index import IndexBuilder

    cat_manifest = run_root / "data/indices/manifests/catalog-attempt_0001.json"
    shard_fp = "f" * 64
    shard_file = run_root / f"data/indices/source/source_files/{shard_fp}.sqlite"
    builder = IndexBuilder(
        shard_file,
        name="source",
        fingerprint=shard_fp,
        target_snapshot=source_fingerprint,
        shard_id="source_files",
    )
    for item in files:
        fid = LogicalIdentity.derive(
            EntityKind.SOURCE_FILE,
            source_fingerprint,
            {"path": item["path"], "sha256": item["sha256"]},
        )
        builder.add_entity(EntityRecord(fid, item["sha256"], item["path"], item["path"], dict(item)))
    builder.add_coverage("catalog", "complete", None)
    shard_sha = builder.build()
    write_manifest(
        cat_manifest,
        run_id=run_root.name,
        target_snapshot=source_fingerprint,
        target_root=target_root,
        indexes=[
            IndexIdentity(
                "source",
                "appsec-review/retrieval-index/2",
                shard_sha,
                shard_fp,
                shard_file.relative_to(run_root).as_posix(),
                {"job": "job_target_catalog", "producer": "catalog"},
                (),
                "source_files",
            )
        ],
    )
    cat_handoff = write_fixture_handoff(
        run_root,
        cat_attempt / "handoff.json",
        {
            "job_id": "job_target_catalog",
            "schema_identity": "appsec-review/target-catalog/1",
            "source_fingerprint": source_fingerprint,
            "outputs": {
                "publish_catalog.publish_handoff": {
                    "artifact": cat_doc,
                    "index_manifest": {
                        "path": cat_manifest.relative_to(run_root).as_posix(),
                        "sha256": file_sha256(cat_manifest),
                    },
                }
            },
        },
    )
    shas["job_target_catalog"] = file_sha256(cat_handoff)
    atomic_json(
        cat_attempt.parent.parent / "latest.json",
        {
            "schema": "appsec-review/latest-handoff/1",
            "attempt_id": "attempt_0001",
            "handoff_path": cat_handoff.relative_to(run_root).as_posix(),
            "handoff_sha256": shas["job_target_catalog"],
        },
    )

    if scanner_selections is not None:
        from appsec_review.jobs.build_topology import _identity_graph1
        from appsec_review.jobs.job_target_analysis_plan.planning import PLAN_SCHEMA

        plan_fp = plan_fingerprint or source_fingerprint
        exec_graph: dict[str, Any] = {
            "schema": "appsec-review/build-topology/1",
            "source_fingerprint": plan_fp,
            "nodes": [],
            "edges": [],
            "external_requirements": [],
            "coverage_gaps": [],
        }
        exec_graph["topology_id"] = _identity_graph1(exec_graph)
        plan_attempt = run_root / "data/jobs/job_target_analysis_plan/attempts/attempt_0001"
        plan_payload = {
            "schema": PLAN_SCHEMA,
            "source_fingerprint": plan_fp,
            "catalog_handoff_sha256": shas["job_target_catalog"],
            "components": [],
            "scanner_selections": scanner_selections,
            "build_actions": [],
            "build_topology": {"executable_graph": exec_graph},
            "coverage_gaps": [],
        }
        plan_ref = _art(plan_attempt / "artifacts/analysis-plan/plan.json", plan_payload)
        plan_handoff = write_fixture_handoff(
            run_root,
            plan_attempt / "handoff.json",
            {
                "job_id": "job_target_analysis_plan",
                "schema_identity": "appsec-review/target-analysis-plan/1",
                "source_fingerprint": plan_fp,
                "upstream_handoff_sha256": {"job_target_catalog": shas["job_target_catalog"]},
                "outputs": {
                    "plan_acceptance.publish_handoff": {
                        "schema": "appsec-review/target-analysis-plan-handoff/1",
                        "artifact": plan_ref,
                    }
                },
            },
        )
        shas["job_target_analysis_plan"] = file_sha256(plan_handoff)
        atomic_json(
            plan_attempt.parent.parent / "latest.json",
            {
                "schema": "appsec-review/latest-handoff/1",
                "attempt_id": "attempt_0001",
                "handoff_path": plan_handoff.relative_to(run_root).as_posix(),
                "handoff_sha256": shas["job_target_analysis_plan"],
            },
        )

    return shas
