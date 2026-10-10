from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any

from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, Mount, load_catalog
from appsec_review.jobs.job_evidence_collection.adapters import (
    Applicability,
    ScanCatalog,
    SEI_CERT_MOUNT,
    ToolAdapter,
    adapter_registry,
)
from appsec_review.jobs.job_evidence_collection.evidence import NORMALIZER_IDENTITY, build_envelope
from appsec_review.jobs.job_target_analysis_plan import load_accepted_plan
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import FileLock, atomic_json, canonical_json, file_sha256, tool_input_json
from appsec_review.jobs.job_third_party_data_sync.publication import verify_current
from appsec_review.rulepacks.sei_cert.pack import LOCK_NAME as SEI_CERT_LOCK, tree_digest


CAPABILITIES: Mapping[str, tuple[str, ...]] = {
    "secrets": ("tool-gitleaks",),
    "source_sast": ("tool-semgrep", "tool-opengrep", "tool-gosec", "tool-mobsfscan", "tool-shellcheck",
                    "tool-phpcs", "tool-phpstan", "tool-psalm", "tool-spotbugs",
                    "tool-cppcheck", "tool-pmd"),
    "software_inventory": ("tool-syft",),
    "vulnerability_matching": ("tool-osv-scanner", "tool-grype"),
    "configuration": ("tool-hadolint", "tool-checkov", "tool-trivy", "tool-zizmor"),
    "binary_hardening": ("tool-blint",),
}
TOPOLOGY: Mapping[str, tuple[str, ...]] = {
    capability: tuple(
        f"{tool.removeprefix('tool-').replace('-', '_')}_{phase}"
        for tool in tools for phase in ("scan", "normalize", "index")
    )
    for capability, tools in CAPABILITIES.items()
}
TOPOLOGY = {**TOPOLOGY, "evidence_publication": ("assemble_manifest", "publish_handoff")}


ExecutorFactory = Callable[[UnitContext], ContainerExecutor]


def _rel(run_root: Path, path: Path) -> str:
    return path.resolve().relative_to(run_root.resolve()).as_posix()


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": _rel(run_root, path), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _read_artifact(run_root: Path, identity: Mapping[str, Any]) -> Mapping[str, Any]:
    path = (run_root / str(identity["path"])).resolve()
    if run_root.resolve() not in path.parents or not path.is_file():
        raise ValueError("upstream artifact is missing or outside the run")
    if file_sha256(path) != identity["sha256"]:
        raise ValueError("upstream artifact hash changed")
    return json.loads(path.read_text(encoding="utf-8"))


def load_target_catalog(run_root: Path) -> ScanCatalog:
    latest_path = run_root / "data" / "jobs" / "job_target_catalog" / "latest.json"
    if not latest_path.is_file():
        raise ValueError("accepted job_target_catalog handoff is required")
    latest = json.loads(latest_path.read_text(encoding="utf-8"))
    handoff_path = (run_root / latest["handoff_path"]).resolve()
    if run_root.resolve() not in handoff_path.parents or file_sha256(handoff_path) != latest["handoff_sha256"]:
        raise ValueError("target catalog handoff identity mismatch")
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    if handoff.get("status") != "ACCEPTED" or handoff.get("schema") != "appsec-review/job-handoff/1":
        raise ValueError("target catalog handoff is not accepted")
    published = handoff.get("outputs", {}).get("publish_catalog.publish_handoff", {})
    catalog_doc = _read_artifact(run_root, published["artifact"])
    if catalog_doc.get("schema") != "appsec-review/target-catalog/1":
        raise ValueError("target catalog schema mismatch")
    partition = _read_artifact(run_root, catalog_doc["artifacts"]["repository_discovery.partition_repository"])
    projects = _read_artifact(run_root, catalog_doc["artifacts"]["repository_discovery.discover_projects"])
    builds = _read_artifact(run_root, catalog_doc["artifacts"]["build_discovery.catalog_build_targets"])
    compile_commands = _read_artifact(
        run_root, catalog_doc["artifacts"]["build_discovery.discover_compile_commands"])
    artifacts = tuple(item for item in builds.get("targets", []) if item.get("artifact_kind") == "built")
    target_root = None
    intake_latest = run_root / "data" / "jobs" / "job_review_intake" / "latest.json"
    if intake_latest.is_file():
        intake_pointer = json.loads(intake_latest.read_text(encoding="utf-8"))
        intake_handoff = _read_artifact(run_root, {
            "path": intake_pointer["handoff_path"], "sha256": intake_pointer["handoff_sha256"]})
        intake_artifact = intake_handoff.get("outputs", {}).get("publish_intake.publish_handoff", {}).get("artifact")
        if isinstance(intake_artifact, Mapping):
            intake = _read_artifact(run_root, intake_artifact)
            target_root = Path(str(intake.get("target", {}).get("path", ""))).resolve()
    return ScanCatalog(
        source_fingerprint=str(catalog_doc["source_fingerprint"]),
        handoff_sha256=str(latest["handoff_sha256"]), files=tuple(partition.get("files", [])),
        projects=tuple(projects.get("projects", [])), artifacts=artifacts, target_root=target_root,
        compile_commands=tuple(compile_commands.get("files", [])),
    )


def plan_applicability(run_root: Path) -> list[dict[str, Any]]:
    catalog = load_target_catalog(run_root)
    try:
        accepted = load_accepted_plan(run_root)
    except ValueError:
        accepted = None
    selections = {item["scanner_id"]: item for item in accepted.get("scanner_selections", [])} if accepted else {}
    values = []
    for tool_id, adapter in adapter_registry().items():
        applicability = adapter.applicability(catalog)
        if accepted is not None and tool_id not in selections:
            applicability = Applicability(False, "not selected by accepted target analysis plan", (),
                                          applicability.coverage_kind)
        elif accepted is not None:
            planned = tuple(item["path"] for item in selections[tool_id]["scope"])
            applicability = Applicability(bool(planned), selections[tool_id]["reason"], planned,
                                          applicability.coverage_kind, applicability.gaps,
                                          applicability.families)
        values.append({"tool_id": tool_id, "capability": adapter.capability, **applicability.as_dict()})
    return values


SEI_CERT_TOOLS = frozenset({"tool-semgrep", "tool-opengrep"})


def _sei_cert_pack(repository: Path) -> tuple[Path, dict[str, str]] | None:
    """Verify the SEI CERT rule files against pack.lock.json and return the rules root and identity."""
    pack = repository / "rules" / "sei-cert"
    try:
        lock = json.loads((pack / SEI_CERT_LOCK).read_text(encoding="utf-8"))
        manifest = json.loads((pack / "pack.json").read_text(encoding="utf-8"))
        rules_root = pack / "rules"
        actual = {path.relative_to(pack).as_posix(): file_sha256(path)
                  for path in sorted(rules_root.rglob("*")) if path.is_file()}
        locked = {relative: digest for relative, digest in lock["files"].items() if relative.startswith("rules/")}
        if (lock.get("schema") != "appsec-review/sei-cert-rule-pack-lock/1" or not actual
                or any(path.is_symlink() for path in rules_root.rglob("*")) or actual != locked
                or sorted(actual) != sorted(manifest.get("rule_files", []))
                or tree_digest(actual) != lock.get("rule_files_sha256")):
            return None
    except (OSError, KeyError, ValueError, json.JSONDecodeError):
        return None
    return rules_root, {"id": str(lock.get("pack")), "version": str(lock.get("version")),
                        "rule_files_sha256": str(lock["rule_files_sha256"]),
                        "tree_sha256": str(lock.get("tree_sha256"))}


def _rule_pack_identity(unit: UnitContext, adapter: ToolAdapter) -> dict[str, Any]:
    """Rule-pack identities recorded with a tool's evidence, so results bind to exact rules."""
    packs: dict[str, Any] = {}
    repository = unit.job.repository_root
    if adapter.tool_id in SEI_CERT_TOOLS:
        verified = _sei_cert_pack(repository)
        packs["appsec-review/sei-cert"] = verified[1] if verified else {"verified": False}
    if adapter.tool_id == "tool-semgrep":
        try:
            lock = json.loads((repository / "rules" / "semgrep" / "rules.lock.json").read_text(encoding="utf-8"))
            packs["semgrep-security-baseline"] = {"sha256": lock["files"]["security.yml"]["sha256"]}
        except (OSError, KeyError, json.JSONDecodeError):
            packs["semgrep-security-baseline"] = {"verified": False}
    return {"rule_packs": packs} if packs else {}


def _prerequisites(unit: UnitContext, adapter: ToolAdapter, selection: Applicability) -> tuple[Applicability, tuple[Mount, ...], dict[str, str], str | None]:
    if not selection.applicable:
        return selection, (), {}, None
    mounts: list[Mount] = []
    environment: dict[str, str] = {}
    repository = unit.job.repository_root
    if adapter.tool_id == "tool-semgrep":
        rules = repository / "rules" / "semgrep"
        try:
            lock = json.loads((rules / "rules.lock.json").read_text(encoding="utf-8"))
            expected = lock["files"]["security.yml"]["sha256"]
            verified = lock.get("schema") == "appsec-review/rule-bundle-lock/1" and file_sha256(
                rules / "security.yml") == expected
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            verified = False
        if not verified:
            return selection, (), {}, "hash-pinned Semgrep rule bundle is unavailable"
        mounts.append(Mount(rules, "/rules", True))
    if adapter.tool_id in SEI_CERT_TOOLS:
        verified_pack = _sei_cert_pack(repository)
        if verified_pack is None:
            return selection, (), {}, "hash-pinned SEI CERT rule pack is unavailable or does not match pack.lock.json"
        mounts.append(Mount(verified_pack[0], SEI_CERT_MOUNT, True))
    if adapter.tool_id == "tool-pmd":
        rules = repository / "rules" / "pmd"
        ruleset = rules / "java-security.xml"
        try:
            lock = json.loads((rules / "rules.lock.json").read_text(encoding="utf-8"))
            verified = (lock.get("schema") == "appsec-review/rules-lock/1" and
                        lock.get("ruleset") == "rules/pmd/java-security.xml" and
                        file_sha256(ruleset) == lock["sha256"])
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            verified = False
        if not verified:
            return selection, (), {}, "hash-pinned PMD security rules are unavailable"
        mounts.append(Mount(rules, "/rules", True))
        file_list = unit.unit_root / "inputs" / "pmd-files.txt"
        file_list.parent.mkdir(parents=True, exist_ok=True)
        file_list.write_text("".join(f"/target/{path}\n" for path in selection.files), encoding="utf-8")
        mounts.append(Mount(file_list, "/scratch/pmd-files.txt", True))
    if adapter.tool_id == "tool-cppcheck" and selection.families.get("compile_database"):
        if unit.job.target_root is None:
            return selection, (), {}, "target root is unavailable for the compile database"
        source = unit.job.target_root / selection.families["compile_database"][0]
        try:
            original = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return selection, (), {}, "accepted compile database could not be read"
        cataloged = set(selection.files)
        sanitized = []
        for entry in original:
            if not isinstance(entry, Mapping) or not entry.get("file"):
                continue
            raw_file = Path(str(entry["file"]))
            directory = Path(str(entry.get("directory", unit.job.target_root)))
            resolved = raw_file if raw_file.is_absolute() else directory / raw_file
            try:
                relative = resolved.resolve().relative_to(unit.job.target_root.resolve()).as_posix()
            except ValueError:
                continue
            if relative not in cataloged:
                continue
            sanitized.append({"directory": "/target", "file": f"/target/{relative}",
                              "arguments": ["c++", f"/target/{relative}"]})
        if not sanitized:
            return selection, (), {}, "compile database contained no cataloged C/C++ translation units"
        compile_database = unit.unit_root / "inputs" / "compile_commands.json"
        compile_database.parent.mkdir(parents=True, exist_ok=True)
        tool_input_json(compile_database, sanitized)
        mounts.append(Mount(compile_database, "/scratch/compile_commands.json", True))
    if adapter.tool_id == "tool-osv-scanner":
        try:
            identity = verify_current(unit.job.repository_root / "data" / "feeds" / "osv", "osv")
            source = Path(identity["directory"]) / "sources" / "PyPI.zip"
            database = unit.unit_root / "inputs" / "osv-db" / "osv-scanner" / "PyPI"
            database.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, database / "all.zip")
            mounts.append(Mount(unit.unit_root / "inputs" / "osv-db", "/database", True))
            environment["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = "/database"
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            return selection, (), {}, f"verified immutable OSV database snapshot is unavailable ({type(exc).__name__})"
    if adapter.tool_id == "tool-grype":
        try:
            identity = verify_current(unit.job.repository_root / "data" / "feeds" / "grype", "grype")
            mounts.append(Mount(Path(identity["directory"]), "/database", True))
            environment["GRYPE_DB_CACHE_DIR"] = "/database"
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            return selection, (), {}, f"verified immutable Grype database snapshot is unavailable ({type(exc).__name__})"
        syft = unit.output("software_inventory.syft_scan")
        if syft.get("terminal_status") not in {"SUCCEEDED", "PARTIAL"} or not syft.get("scanner_output"):
            return selection, (), {}, "a successful Syft SBOM is required"
        mounts.append(Mount(unit.job.run_root / syft["scanner_output"], "/inputs/syft.json", True))
    return selection, tuple(mounts), environment, None


def _scope_identity(catalog: ScanCatalog, selection: Applicability) -> str:
    hashes = {str(item["path"]): item.get("sha256") for item in catalog.files}
    value = [{"path": path, "sha256": hashes.get(path)} for path in selection.files]
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _extra_identity(mounts: tuple[Mount, ...]) -> dict[str, str]:
    identity: dict[str, str] = {}
    for mount in mounts:
        source = mount.source.resolve()
        if source.is_file():
            identity[mount.target] = file_sha256(source)
        elif source.is_dir():
            digest = hashlib.sha256()
            for path in sorted((item for item in source.rglob("*") if item.is_file()),
                               key=lambda item: item.relative_to(source).as_posix()):
                digest.update(path.relative_to(source).as_posix().encode())
                digest.update(file_sha256(path).encode())
            identity[mount.target] = digest.hexdigest()
    return identity


def _checkpoint_identity(unit: UnitContext, adapter: ToolAdapter, catalog: ScanCatalog,
                         selection: Applicability, image_id: str, mounts: tuple[Mount, ...]) -> str:
    value = {
        "tool_id": adapter.tool_id, "target_fingerprint": catalog.source_fingerprint,
        "catalog_handoff": catalog.handoff_sha256, "scope": _scope_identity(catalog, selection),
        "image_id": image_id, "adapter": adapter.adapter_identity, "parser": adapter.parser_identity,
        "normalizer": NORMALIZER_IDENTITY, "validator": "static-tool-evidence/2",
        "inputs": _extra_identity(mounts),
        "job_settings": dict(unit.job.config.settings),
        "task_settings": dict(unit.job.config.step(unit.step_id).task(unit.task_id).settings),
    }
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _valid_checkpoint(run_root: Path, path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        for item in value.get("artifacts", []):
            artifact = (run_root / item["path"]).resolve()
            if run_root.resolve() not in artifact.parents or file_sha256(artifact) != item["sha256"]:
                return None
        return value
    except (OSError, KeyError, ValueError, json.JSONDecodeError):
        return None


def _separate_parser_diagnostics(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Keep scanner diagnostics out of observations while preserving them as coverage gaps."""
    observations: list[dict[str, Any]] = []
    gaps: list[str] = []
    for record in records:
        gap = record.get("coverage_gap")
        if gap:
            gaps.append(str(gap))
        if not record.get("gap_only"):
            observations.append(record)
    return observations, list(dict.fromkeys(gaps))


def _write_evidence(unit: UnitContext, adapter: ToolAdapter, catalog: ScanCatalog,
                    selection: Applicability, *, tool_identity: Mapping[str, Any],
                    raw_artifacts: tuple[Path, ...], observations: list[dict[str, Any]],
                    terminal_status: str, gaps: tuple[str, ...]) -> tuple[dict[str, Any], Path]:
    destination = unit.unit_root / "evidence.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    envelope = build_envelope(
        tool={**tool_identity, **_rule_pack_identity(unit, adapter)}, target_fingerprint=catalog.source_fingerprint,
        applicability=selection.as_dict(), coverage_scope={
            "kind": selection.coverage_kind, "paths": list(selection.files),
            "path_count": len(selection.files),
        }, gaps=(*selection.gaps, *adapter.limitations, *gaps), raw_artifacts=raw_artifacts,
        parser_identity=adapter.parser_identity, observations=observations,
        cataloged_paths=catalog.paths, terminal_status=terminal_status, run_root=unit.job.run_root,
        source_hashes={str(item["path"]): str(item["sha256"]) for item in catalog.files if item.get("sha256")},
    )
    atomic_json(destination, envelope)
    return envelope, destination


def _execute_tool(unit: UnitContext, adapter: ToolAdapter, catalog: ScanCatalog,
                  executor_factory: ExecutorFactory, fail_tool: str | None,
                  planned: Applicability | None = None) -> Mapping[str, Any]:
    if adapter.tool_id == "tool-grype" and unit.job.tools.disable_grype:
        selection = planned if planned is not None else adapter.applicability(catalog)
        gap = "Grype coverage was configured disabled by tools.disable_grype"
        envelope, path = _write_evidence(
            unit, adapter, catalog, selection,
            tool_identity={"id": adapter.tool_id, "disposition": "configured_disabled"},
            raw_artifacts=(), observations=[], terminal_status="NOT_APPLICABLE", gaps=(gap,),
        )
        unit.job.events.write("TOOL_CONFIGURED_DISABLED", unit_id=unit.unit_id,
                              tool_id=adapter.tool_id, disposition="CONFIGURED_DISABLED",
                              gap_count=1, gaps=[gap], checkpoint_reused=False)
        return {"tool_id": adapter.tool_id, "capability": adapter.capability,
                "terminal_status": "NOT_APPLICABLE", "coverage_disposition": "CONFIGURED_DISABLED",
                "checkpoint_reused": False, "artifact": _artifact(unit.job.run_root, path),
                "scanner_output": None, "execution": None, "record_count": 0,
                "gaps": envelope["exclusions_and_gaps"], "retry_count": 0}
    selection, mounts, environment, blocked = _prerequisites(
        unit, adapter, planned if planned is not None else adapter.applicability(catalog))
    if not selection.applicable:
        envelope, path = _write_evidence(
            unit, adapter, catalog, selection,
            tool_identity={"id": adapter.tool_id, "disposition": "not_executed"},
            raw_artifacts=(), observations=[], terminal_status="NOT_APPLICABLE", gaps=(selection.reason,),
        )
        return {"tool_id": adapter.tool_id, "capability": adapter.capability,
                "terminal_status": "NOT_APPLICABLE", "checkpoint_reused": False,
                "artifact": _artifact(unit.job.run_root, path), "record_count": 0,
                "gaps": envelope["exclusions_and_gaps"]}
    if blocked is not None:
        envelope, path = _write_evidence(
            unit, adapter, catalog, selection,
            tool_identity={"id": adapter.tool_id, "disposition": "blocked"},
            raw_artifacts=(), observations=[], terminal_status="BLOCKED", gaps=(blocked,),
        )
        return {"tool_id": adapter.tool_id, "capability": adapter.capability,
                "terminal_status": "BLOCKED", "checkpoint_reused": False,
                "artifact": _artifact(unit.job.run_root, path), "record_count": 0,
                "gaps": envelope["exclusions_and_gaps"]}

    executor = executor_factory(unit)
    tool = executor.catalog.tool(adapter.tool_id)
    try:
        image_id = executor.resolve_image(tool)
    except RuntimeError as exc:
        invocation_id = hashlib.sha256(
            f"{unit.job.run_id}:{unit.job.attempt_id}:{unit.unit_id}:resolve".encode()).hexdigest()
        unit.job.events.write("TOOL_INVOCATION_STARTED", unit_id=unit.unit_id,
                              tool_invocation_id=invocation_id, tool_id=adapter.tool_id,
                              tool_identity={"name": tool.name, "version": tool.version}, retry_count=0)
        unit.job.events.write("TOOL_INVOCATION_COMPLETED", unit_id=unit.unit_id,
                              tool_invocation_id=invocation_id, tool_id=adapter.tool_id,
                              tool_identity={"name": tool.name, "version": tool.version},
                              disposition="FAILED", retry_count=0, error_class=type(exc).__name__,
                              result_count=0, gap_count=1, gaps=[str(exc)],
                              checkpoint_reused=False, truncated=False, duration_ms=0)
        envelope, evidence_path = _write_evidence(
            unit, adapter, catalog, selection,
            tool_identity={"id": adapter.tool_id, "name": tool.name, "version": tool.version,
                           "image_tag": tool.tag, "disposition": "unavailable"},
            raw_artifacts=(), observations=[], terminal_status="FAILED", gaps=(str(exc),))
        return {"tool_id": adapter.tool_id, "capability": adapter.capability,
                "terminal_status": "FAILED", "checkpoint_reused": False,
                "artifact": _artifact(unit.job.run_root, evidence_path), "scanner_output": None,
                "execution": None, "record_count": 0, "gaps": envelope["exclusions_and_gaps"],
                "retry_count": 0}
    identity = _checkpoint_identity(unit, adapter, catalog, selection, image_id, mounts)
    checkpoint_root = unit.job.run_root / "data" / "task-checkpoints" / "job_evidence_collection" / adapter.tool_id / identity[:24]
    checkpoint_path = checkpoint_root / "checkpoint.json"
    retry_marker = checkpoint_root.parent / "retry-required.json"
    with FileLock(checkpoint_root.parent / (identity[:24] + ".lock")):
        retry_required = False
        if retry_marker.is_file():
            marker = json.loads(retry_marker.read_text(encoding="utf-8"))
            retry_required = bool(marker.get("retry_required")) and marker.get("checkpoint_identity") == identity
        checkpoint = None if retry_required else _valid_checkpoint(unit.job.run_root, checkpoint_path)
        if checkpoint is not None:
            prior = checkpoint["output"]
            unit.job.events.write(
                "TOOL_CHECKPOINT_REUSED", unit_id=unit.unit_id, tool_id=adapter.tool_id,
                tool_identity={"name": tool.name, "version": tool.version, "image_id": image_id},
                checkpoint_identity=identity, disposition=prior.get("terminal_status"),
                result_count=prior.get("record_count", 0), gap_count=len(prior.get("gaps", ())),
                gaps=list(prior.get("gaps", ()))[:50], retry_count=prior.get("retry_count", 0),
                checkpoint_reused=True, truncated=False, duration_ms=0,
            )
            return {**checkpoint["output"], "checkpoint_reused": True,
                    "checkpoint": _artifact(unit.job.run_root, checkpoint_path)}
        configured_retries = int(unit.job.config.settings.get("tool_retries", 1))
        if not 0 <= configured_retries <= 3:
            raise ValueError("tool_retries must be between zero and three")
        raw_paths: tuple[Path, ...] = ()
        result = None
        output = None
        observations: list[dict[str, Any]] = []
        gaps: list[str] = []
        error_class = None
        for attempt in range(configured_retries + 1):
            scratch = unit.unit_root / "scratch" / f"attempt_{attempt + 1:02d}"
            invocation_id = hashlib.sha256(
                f"{unit.job.run_id}:{unit.job.attempt_id}:{unit.unit_id}:{attempt + 1}".encode()).hexdigest()
            invoked = time.monotonic()
            unit.job.events.write("TOOL_INVOCATION_STARTED", unit_id=unit.unit_id,
                                  tool_invocation_id=invocation_id, tool_id=adapter.tool_id,
                                  tool_identity={"name": tool.name, "version": tool.version,
                                                 "image_id": image_id},
                                  input_identities=_extra_identity(mounts), retry_count=attempt)
            if adapter.tool_id == "tool-trivy":
                staged = scratch / "inputs"
                for relative in selection.files:
                    source = (unit.job.target_root or Path()) / relative
                    destination = staged / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)
            try:
                if fail_tool == adapter.tool_id:
                    raise RuntimeError(f"injected bounded failure: {adapter.tool_id}")
                result = executor.execute(ExecutionRequest(
                    tool_id=adapter.tool_id, argv=adapter.argv(tool.executable, selection),
                    target_root=unit.job.target_root or Path(), scratch_root=scratch,
                    extra_mounts=mounts, environment=environment,
                ))
                attempt_paths = (unit.job.run_root / result.stdout_path,
                                 unit.job.run_root / result.stderr_path,
                                 unit.job.run_root / result.receipt_path)
                raw_paths = (*raw_paths, *attempt_paths)
                if result.stdout_truncated:
                    gaps.append("stdout was truncated at the configured byte bound")
                if result.stderr_truncated:
                    gaps.append("stderr was truncated at the configured byte bound")
                if result.timed_out:
                    raise RuntimeError(f"{adapter.tool_id} timed out")
                if result.oom_killed:
                    raise RuntimeError(f"{adapter.tool_id} was OOM-killed")
                if result.exit_code not in adapter.accepted_exit_codes:
                    raise RuntimeError(f"{adapter.tool_id} exited with {result.exit_code}")
                output = scratch / adapter.output_file.removeprefix("/scratch/") if adapter.output_file else attempt_paths[0]
                if not output.is_file():
                    raise RuntimeError(f"{adapter.tool_id} did not produce its expected output")
                if output.stat().st_size > tool.output_bytes:
                    raise RuntimeError(f"{adapter.tool_id} output artifact exceeded its byte bound")
                if output not in raw_paths:
                    raw_paths = (*raw_paths, output)
                try:
                    parsed = adapter.parse(output.read_bytes())
                    observations, parser_gaps = _separate_parser_diagnostics(parsed)
                    gaps.extend(parser_gaps)
                except (ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
                    raise RuntimeError(f"{adapter.tool_id} parser incompatibility ({type(exc).__name__})") from exc
                error_class = None
                effective_gaps = list(dict.fromkeys((*selection.gaps, *adapter.limitations, *gaps)))
                unit.job.events.write("TOOL_INVOCATION_COMPLETED", unit_id=unit.unit_id,
                                      tool_invocation_id=invocation_id, tool_id=adapter.tool_id,
                                      tool_identity={"name": tool.name, "version": tool.version,
                                                     "image_id": image_id},
                                      disposition="SUCCEEDED", retry_count=attempt,
                                      result_count=len(observations), gap_count=len(effective_gaps),
                                      gaps=effective_gaps[:50], checkpoint_reused=False,
                                      truncated=result.stdout_truncated or result.stderr_truncated,
                                      duration_ms=max(0, int((time.monotonic() - invoked) * 1000)))
                break
            except (RuntimeError, subprocess.SubprocessError) as exc:
                error_class = type(exc).__name__
                gaps.append(str(exc))
                unit.job.events.write("TOOL_INVOCATION_COMPLETED", unit_id=unit.unit_id,
                                      tool_invocation_id=invocation_id, tool_id=adapter.tool_id,
                                      tool_identity={"name": tool.name, "version": tool.version,
                                                     "image_id": image_id},
                                      disposition="FAILED", retry_count=attempt, error_class=error_class,
                                      result_count=0, gap_count=len(gaps), gaps=gaps[-50:],
                                      checkpoint_reused=False, truncated=False,
                                      duration_ms=max(0, int((time.monotonic() - invoked) * 1000)))
                if attempt < configured_retries:
                    continue
        terminal = "FAILED" if error_class is not None else ("PARTIAL" if gaps else "SUCCEEDED")
        envelope, evidence_path = _write_evidence(
            unit, adapter, catalog, selection,
            tool_identity={"id": adapter.tool_id, "name": tool.name, "version": tool.version,
                           "image_tag": tool.tag, "image_id": image_id,
                           "attempt_count": configured_retries + 1 if error_class else attempt + 1,
                           "error_class": error_class},
            raw_artifacts=raw_paths, observations=observations, terminal_status=terminal, gaps=tuple(gaps),
        )
        output_value = {
            "tool_id": adapter.tool_id, "capability": adapter.capability,
            "terminal_status": terminal, "checkpoint_reused": False,
            "artifact": _artifact(unit.job.run_root, evidence_path),
            "scanner_output": _rel(unit.job.run_root, output) if output is not None else None,
            "execution": (_artifact(unit.job.run_root, unit.job.run_root / result.receipt_path)
                          if result is not None else None),
            "record_count": envelope["record_count"], "gaps": envelope["exclusions_and_gaps"],
            "checkpoint_identity": identity, "retry_count": attempt if error_class is None else configured_retries,
        }
        if terminal in {"SUCCEEDED", "PARTIAL"}:
            checkpoint_root.mkdir(parents=True, exist_ok=True)
            checkpoint_artifacts = [output_value["artifact"]]
            if output_value["execution"] is not None:
                checkpoint_artifacts.append(output_value["execution"])
            if output is not None:
                checkpoint_artifacts.append(_artifact(unit.job.run_root, output))
            atomic_json(checkpoint_path, {
                "schema": "appsec-review/tool-task-checkpoint/1", "identity": identity,
                "output": output_value, "artifacts": checkpoint_artifacts,
            })
            if retry_required:
                atomic_json(retry_marker, {"schema": "appsec-review/injected-tool-failure/1",
                                          "tool_id": adapter.tool_id, "checkpoint_identity": identity,
                                          "retry_required": False, "failed_attempt": marker.get("failed_attempt"),
                                          "resolved_attempt": unit.job.attempt_id})
            return {**output_value, "checkpoint": _artifact(unit.job.run_root, checkpoint_path)}
        atomic_json(retry_marker, {"schema": "appsec-review/tool-retry-required/1",
                                  "tool_id": adapter.tool_id, "checkpoint_identity": identity,
                                  "retry_required": True, "failed_attempt": unit.job.attempt_id})
        return output_value


def _normalize_tool(unit: UnitContext, scan_unit: str) -> Mapping[str, Any]:
    output = dict(unit.output(scan_unit))
    evidence = _read_artifact(unit.job.run_root, output["artifact"])
    if evidence.get("schema") != "appsec-review/static-tool-evidence/1":
        raise ValueError("scanner evidence envelope schema mismatch")
    if evidence.get("terminal_status") != output.get("terminal_status"):
        raise ValueError("scanner disposition changed before normalization")
    return {**output, "normalizer_identity": NORMALIZER_IDENTITY,
            "normalized_artifact": output["artifact"],
            "normalization_reused": bool(output.get("checkpoint_reused"))}


def _build_producer_shard(unit: UnitContext, normalize_unit: str) -> Mapping[str, Any]:
    output = dict(unit.output(normalize_unit))
    evidence = _read_artifact(unit.job.run_root, output["normalized_artifact"])
    producer = str(output["tool_id"])
    shard_id = producer.removeprefix("tool-").replace("-", "_")
    fingerprint = index_fingerprint(
        name="observations", target_snapshot=unit.job.source_fingerprint,
        producer_artifacts=[{"sha256": output["normalized_artifact"]["sha256"]}],
        tool_identity={"tool_id": producer}, parser_identity="static-adapters/1",
        normalizer_identity=NORMALIZER_IDENTITY, mapping_identity="native-location/1",
    )
    index_path = (unit.job.run_root / "data" / "indices" / "observations" / shard_id /
                  f"{fingerprint}.sqlite")
    checkpoint = (unit.job.run_root / "data" / "task-checkpoints" / "job_evidence_collection" /
                  "index" / shard_id / f"{fingerprint}.json")
    if checkpoint.is_file():
        value = json.loads(checkpoint.read_text(encoding="utf-8"))
        identity = IndexIdentity(**{**value["index_identity"],
                                    "gaps": tuple(value["index_identity"].get("gaps", ()))})
        candidate = unit.job.run_root / identity.relative_path
        if candidate.is_file() and file_sha256(candidate) == identity.sha256:
            reused = {**value, "checkpoint_reused": output.get("checkpoint_reused", False),
                      "index_reused": True}
            unit.job.events.write(
                "PRODUCER_SHARD_COMPLETED", unit_id=unit.unit_id, producer=producer,
                shard_identity=reused["index_identity"], disposition=reused["terminal_status"],
                result_count=reused.get("record_count", 0), gap_count=len(reused.get("gaps", ())),
                gaps=list(reused.get("gaps", ()))[:50],
                checkpoint_reused=bool(reused.get("checkpoint_reused")), index_reused=True,
            )
            return reused
    builder = IndexBuilder(index_path, name="observations", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard_id)
    artifact_id = LogicalIdentity.derive(EntityKind.EVIDENCE_ARTIFACT, unit.job.source_fingerprint,
                                         {"path": output["artifact"]["path"],
                                          "sha256": output["artifact"]["sha256"]})
    builder.add_entity(EntityRecord(artifact_id, output["artifact"]["sha256"],
                                    producer + " evidence", producer,
                                    {"artifact": output["artifact"], "tool_id": producer}))
    for record in evidence.get("records", []):
        observation_id = LogicalIdentity.derive(
            EntityKind.TOOL_OBSERVATION, unit.job.source_fingerprint,
            {"tool_id": producer, "evidence_id": record["evidence_id"]})
        location_value = record.get("location")
        location = None
        source_id = None
        if location_value:
            target_path = (unit.job.target_root or Path()) / location_value["path"]
            if target_path.is_file():
                source_sha = file_sha256(target_path)
                data = target_path.read_bytes()
                line_offsets = [0, *(match.end() for match in re.finditer(b"\n", data))]
                start_line, end_line = int(location_value["start_line"]), int(location_value["end_line"])
                start_byte = line_offsets[min(start_line - 1, len(line_offsets) - 1)]
                end_byte = line_offsets[min(end_line, len(line_offsets) - 1)] if end_line < len(line_offsets) else len(data)
                location = SourceLocation(
                    target_snapshot=unit.job.source_fingerprint, path=location_value["path"],
                    file_sha256=source_sha, start_byte=start_byte, end_byte=end_byte,
                    start_line=start_line, end_line=end_line, start_column=1, end_column=1,
                    producer_location={"tool": producer, **location_value},
                    mapping_method="producer-line-location", confidence=1.0)
                source_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, unit.job.source_fingerprint,
                                                   {"path": location_value["path"], "sha256": source_sha})
        builder.add_entity(EntityRecord(
            observation_id, record["evidence_id"], str(record.get("native_rule_id", "observation")),
            " ".join(str(record.get(key) or "") for key in (
                "native_rule_id", "message", "category", "component", "package", "advisory", "language")),
            {"tool_id": producer, **record}, location))
        builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, observation_id.value,
                                            artifact_id.value, True, 1.0))
        if source_id is not None:
            builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT, observation_id.value,
                                                source_id.value, True, 1.0))
    status = "complete" if output["terminal_status"] == "SUCCEEDED" else "partial"
    builder.add_coverage(producer, status, None if status == "complete" else "; ".join(output.get("gaps", [])[:10]))
    sha256 = builder.build()
    identity = IndexIdentity("observations", "appsec-review/retrieval-index/2", sha256, fingerprint,
                             index_path.relative_to(unit.job.run_root).as_posix(),
                             {"job": "job_evidence_collection", "producer": producer},
                             tuple(dict.fromkeys(output.get("gaps", ()))), shard_id)
    value = {"artifact": _artifact(unit.job.run_root, index_path),
             "index_identity": __import__("dataclasses").asdict(identity), "index_reused": False,
             "tool_id": producer, "terminal_status": output["terminal_status"],
             "checkpoint_reused": output.get("checkpoint_reused", False),
             "record_count": output.get("record_count", 0), "gaps": output.get("gaps", [])}
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(checkpoint, value)
    unit.job.events.write(
        "PRODUCER_SHARD_COMPLETED", unit_id=unit.unit_id, producer=producer,
        shard_identity=value["index_identity"], disposition=value["terminal_status"],
        result_count=value.get("record_count", 0), gap_count=len(value.get("gaps", ())),
        gaps=list(value.get("gaps", ()))[:50],
        checkpoint_reused=bool(value.get("checkpoint_reused")), index_reused=False,
    )
    return value


def _assemble_manifest(unit: UnitContext, index_units: tuple[str, ...]) -> Mapping[str, Any]:
    manifest_path, manifest_sha = resolve_accepted_manifest(unit.job.run_root)
    upstream, _ = load_verified_manifest(unit.job.run_root, manifest_path, manifest_sha)
    if any(item["name"] == "observations" for item in upstream["indexes"]):
        base_candidates = upstream.get("upstream_manifests", [])
        if not base_candidates:
            raise ValueError("observation manifest has no stable upstream index set")
        base = base_candidates[0]
        manifest_path = (unit.job.run_root / base["path"]).resolve()
        manifest_sha = base["sha256"]
        upstream, _ = load_verified_manifest(unit.job.run_root, manifest_path, manifest_sha)
    gaps: list[str] = []
    dispositions: list[dict[str, Any]] = []
    shards: list[IndexIdentity] = []
    for unit_id in index_units:
        output = unit.output(unit_id)
        dispositions.append({"tool_id": output["tool_id"], "terminal_status": output["terminal_status"],
                             "checkpoint_reused": output["checkpoint_reused"], "record_count": output["record_count"],
                             "index_reused": output.get("index_reused", False),
                             "shard_id": output["index_identity"]["shard_id"],
                             "gaps": output.get("gaps", [])})
        gaps.extend(str(item) for item in output.get("gaps", []))
        shards.append(IndexIdentity(**{**output["index_identity"],
                                       "gaps": tuple(output["index_identity"].get("gaps", ())) }))
    existing = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))}) for item in upstream["indexes"]]
    combined = existing + shards
    combined_manifest = unit.job.run_root / "data" / "indices" / "manifests" / f"evidence-{unit.job.attempt_id}.json"
    write_manifest(combined_manifest, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                   target_root=unit.job.target_root or Path(), indexes=combined,
                   upstream_manifests=({"path": manifest_path.relative_to(unit.job.run_root).as_posix(),
                                        "sha256": manifest_sha},))
    load_verified_manifest(unit.job.run_root, combined_manifest, file_sha256(combined_manifest))
    return {"index_manifest": _artifact(unit.job.run_root, combined_manifest),
            "shards": [__import__("dataclasses").asdict(item) for item in shards],
            "item_count": sum(item["record_count"] for item in dispositions),
            "dispositions": dispositions, "gaps": list(dict.fromkeys(gaps))}


def build_job(*, executor_factory: ExecutorFactory | None = None, fail_tool: str | None = None) -> Job:
    adapters = adapter_registry()
    if set(adapters) != {tool for tools in CAPABILITIES.values() for tool in tools}:
        raise ValueError("enabled static tool disposition is incomplete")

    def validate(context, result) -> None:
        if context.target_root is None:
            raise ValueError("evidence collection requires the graph-provided target root")
        if tuple(context.config.steps) != tuple(TOPOLOGY):
            raise ValueError("evidence collection topology does not match configuration")
        for step, tasks in TOPOLOGY.items():
            if tuple(context.config.step(step).tasks) != tasks:
                raise ValueError(f"evidence collection task order mismatch: {step}")
        catalog = load_catalog(context.repository_root)
        static_tools = {tool_id for tool_id, tool in catalog.tools.items()
                        if tool.metadata.get("static_adapter", True) is not False}
        if static_tools != set(adapters):
            missing = sorted(static_tools - set(adapters))
            extra = sorted(set(adapters) - static_tools)
            raise ValueError(f"enabled tool/adapter mismatch: missing={missing}, extra={extra}")
        target_catalog = load_target_catalog(context.run_root)
        if context.source_fingerprint != target_catalog.source_fingerprint:
            raise ValueError("graph target fingerprint does not match the accepted target catalog")
        accepted_plan = load_accepted_plan(context.run_root)
        if accepted_plan.get("source_fingerprint") != context.source_fingerprint:
            raise ValueError("graph target fingerprint does not match the accepted analysis plan")

    def factory(unit: UnitContext) -> ContainerExecutor:
        if executor_factory is not None:
            return executor_factory(unit)
        return ContainerExecutor(load_catalog(unit.job.repository_root), unit.job.run_root)

    units: list[Unit] = []
    index_units: list[str] = []
    for capability, tool_ids in CAPABILITIES.items():
        for tool_id in tool_ids:
            adapter = adapters[tool_id]
            stem = tool_id.removeprefix("tool-").replace("-", "_")
            scan_id = f"{capability}.{stem}_scan"
            normalize_id = f"{capability}.{stem}_normalize"
            index_id = f"{capability}.{stem}_index"
            dependencies = ("software_inventory.syft_scan",) if tool_id == "tool-grype" else ()
            def handler(unit: UnitContext, selected: ToolAdapter = adapter) -> Mapping[str, Any]:
                catalog = load_target_catalog(unit.job.run_root)
                plan = load_accepted_plan(unit.job.run_root)
                by_tool = {item["scanner_id"]: item for item in plan["scanner_selections"]}
                natural = selected.applicability(catalog)
                decision = by_tool.get(selected.tool_id)
                planned = (Applicability(False, "not selected by accepted target analysis plan", (),
                                         natural.coverage_kind) if decision is None else
                           Applicability(True, str(decision["reason"]),
                                         tuple(item["path"] for item in decision["scope"]),
                                         natural.coverage_kind, natural.gaps, natural.families))
                return _execute_tool(unit, selected, catalog, factory, fail_tool, planned)
            units.append(Unit(scan_id, handler, dependencies))
            units.append(Unit(normalize_id,
                              lambda unit, scan=scan_id: _normalize_tool(unit, scan), (scan_id,)))
            units.append(Unit(index_id,
                              lambda unit, normalized=normalize_id: _build_producer_shard(unit, normalized),
                              (normalize_id,)))
            index_units.append(index_id)

    index_dependencies = tuple(index_units)
    units.append(Unit("evidence_publication.assemble_manifest",
                      lambda unit: _assemble_manifest(unit, index_dependencies), index_dependencies))

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        index = unit.output("evidence_publication.assemble_manifest")
        document = {
            "schema": "appsec-review/evidence-collection-handoff/1",
            "target_fingerprint": unit.job.source_fingerprint,
            "shards": index["shards"], "dispositions": index["dispositions"],
            "gaps": index["gaps"], "security_findings": [],
        }
        path = unit.unit_root / "handoff.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(path, document)
        return {"schema": document["schema"], "artifact": _artifact(unit.job.run_root, path),
                "index_manifest": index["index_manifest"],
                "item_count": index["item_count"], "gaps": document["gaps"],
                "dispositions": document["dispositions"]}

    units.append(Unit("evidence_publication.publish_handoff", publish,
                      ("evidence_publication.assemble_manifest",)))
    source_files = (Path(__file__), Path(__file__).with_name("adapters.py"), Path(__file__).with_name("evidence.py"))
    implementation = hashlib.sha256(b"".join(path.read_bytes() for path in source_files) + str(fail_tool).encode()).hexdigest()

    def runtime_identity() -> str:
        root = Path(os.environ.get("APPSEC_REVIEW_CONFIG", "appsec-review.toml")).resolve().parent
        catalog = load_catalog(root)
        static_tools = {tool_id: tool for tool_id, tool in catalog.tools.items()
                        if tool.metadata.get("static_adapter", True) is not False}
        paths = [root / "containers" / "catalog.toml", root / "containers" / "runtime-policy.toml",
                 root / "rules" / "semgrep" / "security.yml", root / "rules" / "semgrep" / "rules.lock.json",
                 root / "rules" / "sei-cert" / "pack.lock.json",
                 root / "data" / "feeds" / "osv" / "current.json",
                 root / "data" / "feeds" / "grype" / "current.json",
                 *(tool.manifest_path for tool in static_tools.values())]
        digest = hashlib.sha256()
        for path in paths:
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(path.read_bytes() if path.is_file() else b"MISSING")
        if executor_factory is None:
            for tool_id in sorted(static_tools):
                tool = static_tools[tool_id]
                inspected = subprocess.run(
                    ["docker", "image", "inspect", tool.tag, "--format", "{{.Id}}"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
                )
                digest.update(tool_id.encode())
                digest.update(tool.tag.encode())
                digest.update(inspected.stdout.strip().encode() if inspected.returncode == 0 else b"UNAVAILABLE")
        else:
            digest.update(b"injected-executor")
        return digest.hexdigest()

    return Job("job_evidence_collection", "evidence_collection", UnitExecutor(tuple(units)).execute,
               input_validators=(validate,), schema_identity="appsec-review/evidence-collection-job/1",
               implementation_identity=implementation,
               validation_identity=hashlib.sha256(Path(__file__).read_bytes() + b"validation").hexdigest(),
               runtime_identity=runtime_identity, units=tuple(units))
