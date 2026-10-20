from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import time
from typing import Any

from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, Mount, load_catalog
from appsec_review.jobs.job_evidence_collection.adapters import (
    Applicability,
    ScanCatalog,
    GITLEAKS_RULES_MOUNT,
    SEI_CERT_MOUNT,
    ToolAdapter,
    adapter_registry,
    checkov_unreported_inputs,
    semgrep_rule_languages,
    semgrep_unscanned_inputs,
)
from appsec_review.jobs.job_evidence_collection.evidence import NORMALIZER_IDENTITY, build_envelope
from appsec_review.jobs.job_target_analysis_plan import load_accepted_plan
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_context_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import FileLock, atomic_json, canonical_json, file_sha256, tool_input_json
from appsec_review.jobs.job_third_party_data_sync.publication import verify_current
from appsec_review.rulepacks.sei_cert.pack import PackError, PackIdentity, verify_pack
from appsec_review.jobs.job_evidence_collection.datasets import CONSUMES, DATASETS
from appsec_review.applicability import ReasonCode
from appsec_review.config.evidence_collection import (
    EvidenceCollectionSettings, parse_evidence_collection_settings,
)
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.osv_offline import (
    DATABASE_ROOT as OSV_DATABASE_ROOT, ENVIRONMENT as OSV_DB_ENVIRONMENT, database_mount_target,
    no_packages_declared, offline_database_mounts, snapshot_ecosystems,
)
from appsec_review.tool_inputs import (
    TOOL_INPUT_SUPPORT, InputDecision, bounded_diagnostic, not_applicable_summary,
    osv_ecosystem, osv_missing_ecosystem_gap, osv_missing_ecosystems, partition_paths,
)
from appsec_review.swift_policy import (
    SWIFT_KNOWN_GAP, filter_swift_files, is_swift_path, reject_swift_derived,
    swift_inventory_count,
)


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


def _apply_swift_policy(selection: Applicability, *, enabled: bool) -> Applicability:
    if enabled:
        return selection
    files = tuple(path for path in selection.files if not is_swift_path(path))
    if files == selection.files:
        return selection
    gaps = tuple(dict.fromkeys((*selection.gaps, SWIFT_KNOWN_GAP)))
    reason = (f"{selection.reason}; Swift inputs excluded by tools.enable_swift=false" if files else
              "only Swift inputs matched and Swift execution is disabled by tools.enable_swift=false")
    return Applicability(bool(files), reason, files, selection.coverage_kind, gaps, selection.families)


_HEAD_BYTES = 256


def _bounded_head(target_root: Path | None) -> Callable[[str], bytes | None]:
    """Read a bounded prefix of one cataloged file for declared-dialect checks (e.g. shebangs)."""
    def read(relative: str) -> bytes | None:
        pure = PurePosixPath(relative)
        if target_root is None or pure.is_absolute() or ".." in pure.parts:
            return None
        candidate = target_root / pure
        try:
            if candidate.is_symlink() or not candidate.is_file():
                return None
            with candidate.open("rb") as stream:
                return stream.read(_HEAD_BYTES)
        except OSError:
            return None
    return read


def _filter_supported_inputs(selection: Applicability, adapter: ToolAdapter,
                             target_root: Path | None) -> tuple[Applicability, tuple[InputDecision, ...]]:
    """Drop planned inputs outside the tool's declared support before launch (SKIPPED_NA)."""
    if not selection.files or adapter.tool_id not in TOOL_INPUT_SUPPORT:
        return selection, ()
    partition = partition_paths(adapter.tool_id, selection.files, read_head=_bounded_head(target_root))
    if not partition.not_applicable:
        return selection, ()
    files = partition.supported
    count = len(partition.not_applicable)
    if files:
        reason = f"{selection.reason}; {count} planned input(s) outside declared tool support were not launched"
        return (Applicability(True, reason, files, selection.coverage_kind, selection.gaps, selection.families),
                partition.not_applicable)
    reason = f"all {count} planned input(s) are outside {adapter.tool_id} declared input support"
    # Policy gaps (the Swift execution policy) stay named; scope limitations of a tool that does
    # not run are not gaps.
    policy_gaps = tuple(gap for gap in selection.gaps if gap == SWIFT_KNOWN_GAP)
    return (Applicability(False, reason, (), selection.coverage_kind, policy_gaps, selection.families),
            partition.not_applicable)


def _container_relative(path: str) -> str:
    value = str(path)
    for prefix in ("/target/", "/scratch/inputs/"):
        if value.startswith(prefix):
            return value[len(prefix):]
    return value


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


def _sei_cert_pack(repository: Path) -> PackIdentity | None:
    """Strictly verify the complete SEI CERT pack against pack.lock.json.

    Every regular file in ``rules/sei-cert`` (rules, mappings, source index, fixtures, manifest,
    documents) must match the lock, so the complete-pack identity reported with evidence is the
    identity that was actually verified. Any mismatch, unexpected file, symlink, or malformed lock
    leaves the pack unverified.
    """
    try:
        return verify_pack(repository / "rules" / "sei-cert")
    except (PackError, OSError):
        return None


def _banned_function_drift(repository: Path) -> str | None:
    """Why the generated banned-function rules no longer match [banned_functions] (None when they do)."""

    from appsec_review.rulepacks.banned_functions import check

    try:
        problems = check(repository)
    except (OSError, ValueError, KeyError):
        return "banned-function rules cannot be checked against the configured [banned_functions] table"
    return problems[0] if problems else None


def _semgrep_rule_files(*, repository_root: Path, tool_id: str) -> list[Path]:
    """The rule files mounted for a Semgrep-family tool (mirrors _prerequisites and the argv)."""
    files: list[Path] = []
    if tool_id == "tool-semgrep":
        files += [repository_root / "rules" / "semgrep" / name
                  for name in ("security.yml", "review-signals.yml", "banned-functions.yml")]
    elif tool_id == "tool-opengrep":
        files += [repository_root / "rules" / "semgrep" / name
                  for name in ("review-signals.yml", "banned-functions.yml")]
    pack = _sei_cert_pack(repository_root)
    if pack is not None:
        files += sorted(path for path in pack.rules_root.rglob("*") if path.suffix in {".yml", ".yaml"})
    return files


def _rule_pack_identity(unit: UnitContext, adapter: ToolAdapter) -> dict[str, Any]:
    """Rule-pack identities recorded with a tool's evidence, so results bind to exact rules."""
    packs: dict[str, Any] = {}
    repository = unit.job.repository_root
    if adapter.tool_id in SEI_CERT_TOOLS:
        verified = _sei_cert_pack(repository)
        packs["appsec-review/sei-cert"] = verified.as_record() if verified else {"verified": False}
    if adapter.tool_id == "tool-gitleaks":
        try:
            lock = json.loads((repository / "rules" / "gitleaks" / "rules.lock.json").read_text(encoding="utf-8"))
            packs["gitleaks-generic-secrets"] = {"sha256": lock["files"]["generic-secrets.toml"]["sha256"]}
        except (OSError, KeyError, json.JSONDecodeError):
            packs["gitleaks-generic-secrets"] = {"verified": False}
    if adapter.tool_id == "tool-opengrep":
        try:
            lock = json.loads((repository / "rules" / "semgrep" / "rules.lock.json").read_text(encoding="utf-8"))
            packs["semgrep-review-signals"] = {"sha256": lock["files"]["review-signals.yml"]["sha256"]}
            packs["semgrep-banned-functions"] = {"sha256": lock["files"]["banned-functions.yml"]["sha256"]}
        except (OSError, KeyError, json.JSONDecodeError):
            packs["semgrep-review-signals"] = {"verified": False}
    if adapter.tool_id == "tool-semgrep":
        try:
            lock = json.loads((repository / "rules" / "semgrep" / "rules.lock.json").read_text(encoding="utf-8"))
            packs["semgrep-security-baseline"] = {"sha256": lock["files"]["security.yml"]["sha256"]}
            packs["semgrep-review-signals"] = {"sha256": lock["files"]["review-signals.yml"]["sha256"]}
            packs["semgrep-banned-functions"] = {"sha256": lock["files"]["banned-functions.yml"]["sha256"]}
        except (OSError, KeyError, json.JSONDecodeError):
            packs["semgrep-security-baseline"] = {"verified": False}
    return {"rule_packs": packs} if packs else {}


def _prerequisites(unit: UnitContext, adapter: ToolAdapter, selection: Applicability) -> tuple[Applicability, tuple[Mount, ...], dict[str, str], str | None]:
    if not selection.applicable:
        return selection, (), {}, None
    mounts: list[Mount] = []
    environment: dict[str, str] = {}
    repository = unit.job.repository_root
    if adapter.tool_id in ("tool-semgrep", "tool-opengrep"):
        rules = repository / "rules" / "semgrep"
        names = (("security.yml", "review-signals.yml", "banned-functions.yml") if adapter.tool_id == "tool-semgrep"
                 else ("review-signals.yml", "banned-functions.yml"))
        try:
            lock = json.loads((rules / "rules.lock.json").read_text(encoding="utf-8"))
            verified = lock.get("schema") == "appsec-review/rule-bundle-lock/1" and all(
                file_sha256(rules / name) == lock["files"][name]["sha256"] for name in names)
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            verified = False
        if not verified:
            return selection, (), {}, "hash-pinned Semgrep rule bundle is unavailable"
        stale = _banned_function_drift(repository)
        if stale:
            return selection, (), {}, stale
        mounts.append(Mount(rules, "/rules", True))
    if adapter.tool_id == "tool-gitleaks":
        rules = repository / "rules" / "gitleaks"
        try:
            lock = json.loads((rules / "rules.lock.json").read_text(encoding="utf-8"))
            verified = lock.get("schema") == "appsec-review/rule-bundle-lock/1" and \
                file_sha256(rules / "generic-secrets.toml") == lock["files"]["generic-secrets.toml"]["sha256"]
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            verified = False
        if not verified:
            return selection, (), {}, "hash-pinned gitleaks rule bundle is unavailable"
        mounts.append(Mount(rules, GITLEAKS_RULES_MOUNT, True))
    if adapter.tool_id in SEI_CERT_TOOLS:
        verified_pack = _sei_cert_pack(repository)
        if verified_pack is None:
            return selection, (), {}, "hash-pinned SEI CERT rule pack is unavailable or does not match pack.lock.json"
        mounts.append(Mount(verified_pack.rules_root, SEI_CERT_MOUNT, True))
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
        mounts.append(Mount(file_list, "/inputs/pmd-files.txt", True))
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
        mounts.append(Mount(compile_database, "/inputs/compile_commands.json", True))
    if adapter.tool_id == "tool-osv-scanner":
        try:
            identity = verify_current(unit.job.repository_root / "data" / "feeds" / "osv", "osv")
            ecosystems = snapshot_ecosystems(Path(identity["directory"]))
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            return selection, (), {}, f"verified immutable OSV database snapshot is unavailable ({type(exc).__name__})"
        selection, missing_gap = _osv_split_by_snapshot(selection, ecosystems)
        if not selection.files:
            return selection, (), {}, missing_gap
        # Offline mode loads every mounted database whole; never mount one no lockfile needs.
        mounts.extend(offline_database_mounts(ecosystems, {osv_ecosystem(path) for path in selection.files}))
        environment[OSV_DB_ENVIRONMENT] = OSV_DATABASE_ROOT
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


def _osv_split_by_snapshot(selection: Applicability,
                           ecosystems: Mapping[str, Any]) -> tuple[Applicability, str | None]:
    """Keep lockfiles whose OSV ecosystem the snapshot holds; name the rest as a coverage gap.

    osv-scanner 1.9.2 aborts the whole offline run (exit 127) when any scanned lockfile needs an
    ecosystem with no local database, so uncovered inputs are withheld and recorded, never hidden.
    """
    missing: dict[str, list[str]] = {}
    kept: list[str] = []
    for path in selection.files:
        ecosystem = osv_ecosystem(path)
        if ecosystem is not None and ecosystem not in ecosystems:
            missing.setdefault(ecosystem, []).append(path)
        else:
            kept.append(path)
    if not missing:
        return selection, None
    count = sum(len(paths) for paths in missing.values())
    sample = ", ".join(sorted(path for paths in missing.values() for path in paths)[:10])
    gap = osv_missing_ecosystem_gap(missing, f"{count} lockfile(s): {sample}")
    if not kept:
        # Supported inputs exist but none can be matched: the caller records this as BLOCKED.
        return (Applicability(True, gap, (), selection.coverage_kind, selection.gaps,
                              selection.families), gap)
    reason = f"{selection.reason}; {count} lockfile(s) need an ecosystem absent from the OSV snapshot"
    return (Applicability(True, reason, tuple(kept), selection.coverage_kind,
                          (*selection.gaps, gap), selection.families), gap)


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
        # Bind the complete verified rule-pack identity, not only the mounted rule files, so a
        # changed mapping, source index, fixture, or manifest never reuses an older checkpoint.
        **_rule_pack_identity(unit, adapter),
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
    records: list[dict[str, Any]], tool_id: str = "",
) -> tuple[list[dict[str, Any]], list[str], list[InputDecision]]:
    """Keep scanner diagnostics out of observations while preserving them as coverage gaps.

    A tool's own recognized "unsupported input" report (``not_applicable_input``) is SKIPPED_NA for
    that input, counted separately, and never a gap or an observation.
    """
    observations: list[dict[str, Any]] = []
    gaps: list[str] = []
    skipped: dict[str, InputDecision] = {}
    for record in records:
        if record.get("not_applicable_input"):
            path = _container_relative(str(record["not_applicable_input"]))
            skipped.setdefault(path, InputDecision(
                path, tool_id, ReasonCode.TOOL_REPORTED_UNSUPPORTED_INPUT,
                str(record.get("not_applicable_reason") or "tool reported an unsupported input")))
            continue
        gap = record.get("coverage_gap")
        if gap:
            gaps.append(str(gap))
        if not record.get("gap_only"):
            observations.append(record)
    return observations, list(dict.fromkeys(gaps)), list(skipped.values())


def _write_evidence(unit: UnitContext, adapter: ToolAdapter, catalog: ScanCatalog,
                    selection: Applicability, *, tool_identity: Mapping[str, Any],
                    raw_artifacts: tuple[Path, ...], observations: list[dict[str, Any]],
                    terminal_status: str, gaps: tuple[str, ...],
                    not_applicable: tuple[InputDecision, ...] = (),
                    include_limitations: bool = True) -> tuple[dict[str, Any], Path]:
    destination = unit.unit_root / "evidence.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    envelope = build_envelope(
        tool={**tool_identity, **_rule_pack_identity(unit, adapter)}, target_fingerprint=catalog.source_fingerprint,
        applicability=selection.as_dict(), coverage_scope={
            "kind": selection.coverage_kind, "paths": list(selection.files),
            "path_count": len(selection.files),
        }, gaps=(*selection.gaps, *(adapter.limitations if include_limitations else ()), *gaps),
        raw_artifacts=raw_artifacts,
        parser_identity=adapter.parser_identity, observations=observations,
        cataloged_paths=catalog.paths, terminal_status=terminal_status, run_root=unit.job.run_root,
        source_hashes={str(item["path"]): str(item["sha256"]) for item in catalog.files if item.get("sha256")},
    )
    envelope["not_applicable_inputs"] = not_applicable_summary(not_applicable)
    atomic_json(destination, envelope)
    return envelope, destination


def _settings(unit: UnitContext) -> EvidenceCollectionSettings:
    typed = unit.job.config.typed_settings
    if isinstance(typed, EvidenceCollectionSettings):
        return typed
    return parse_evidence_collection_settings(unit.job.config.settings)


@dataclass(frozen=True, slots=True)
class _Invocation:
    """One container launch: a tool's whole selection, or one bounded chunk of one OSV project."""

    selection: Applicability
    mounts: tuple[Mount, ...]
    project_root: str | None = None
    # Names the launch in gaps, e.g. "project web (2 lockfile(s))"; empty for whole-selection runs.
    subject: str = ""


@dataclass(slots=True)
class _InvocationOutcome:
    raw_paths: tuple[Path, ...] = ()
    output: Path | None = None
    result: ExecutionResult | None = None
    observations: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    not_applicable: list[InputDecision] = field(default_factory=list)
    error_class: str | None = None
    attempt: int = 0


def osv_project_groups(paths: Iterable[str],
                       projects: Iterable[Mapping[str, Any]]) -> dict[str, tuple[str, ...]]:
    """Assign each lockfile to its deepest containing cataloged project root.

    A lockfile under no project root groups by its parent directory. Roots are target-relative
    POSIX paths; ``.`` is the target root and contains every path.
    """
    roots = {PurePosixPath(str(item["root"])).as_posix() for item in projects if item.get("root") is not None}
    groups: dict[str, list[str]] = {}
    for path in sorted(set(paths)):
        pure = PurePosixPath(path)
        containing = [root for root in roots
                      if root == "." or pure.parts[:len(PurePosixPath(root).parts)] == PurePosixPath(root).parts]
        root = (max(containing, key=lambda item: 0 if item == "." else len(PurePosixPath(item).parts))
                if containing else pure.parent.as_posix())
        groups.setdefault(root, []).append(path)
    return {root: tuple(groups[root]) for root in sorted(groups)}


def _plan_invocations(adapter: ToolAdapter, catalog: ScanCatalog, selection: Applicability,
                      mounts: tuple[Mount, ...], max_lockfiles: int) -> list[_Invocation]:
    """One launch for most tools; for osv-scanner one per project, in chunks of ``max_lockfiles``.

    osv-scanner's offline mode loads each mounted ecosystem database whole, so each launch mounts
    only the databases its own lockfiles need, and one project's failure loses only that project.
    """
    if adapter.tool_id != "tool-osv-scanner":
        return [_Invocation(selection, mounts)]
    database_targets = {mount.target for mount in mounts
                        if mount.target.startswith(f"{OSV_DATABASE_ROOT}/osv-scanner/")}
    shared = tuple(mount for mount in mounts if mount.target not in database_targets)
    invocations: list[_Invocation] = []
    for root, paths in osv_project_groups(selection.files, catalog.projects).items():
        chunks = [paths[index:index + max_lockfiles] for index in range(0, len(paths), max_lockfiles)]
        name = "at the target root" if root == "." else root
        for number, chunk in enumerate(chunks, start=1):
            needed = {database_mount_target(str(osv_ecosystem(path))) for path in chunk}
            part = f"chunk {number}/{len(chunks)}, " if len(chunks) > 1 else ""
            invocations.append(_Invocation(
                Applicability(True, selection.reason, chunk, selection.coverage_kind, selection.gaps,
                              selection.families),
                (*shared, *(mount for mount in mounts if mount.target in needed & database_targets)),
                root, f" for project {name} ({part}{len(chunk)} lockfile(s))"))
    return invocations


def _run_invocation(unit: UnitContext, adapter: ToolAdapter, catalog: ScanCatalog,
                    invocation: _Invocation, index: int, *, executor: ContainerExecutor, tool: Any,
                    image_id: str, fail_tool: str | None, retries: int, swift_present: bool,
                    environment: Mapping[str, str], memory: str | None,
                    input_identities: Mapping[str, str]) -> _InvocationOutcome:
    """Launch one invocation with bounded retries; failures become gaps naming the invocation."""
    selection, mounts, subject = invocation.selection, invocation.mounts, invocation.subject
    outcome = _InvocationOutcome()
    project_fields: dict[str, Any] = ({} if invocation.project_root is None else
                                      {"project_root": invocation.project_root,
                                       "lockfile_count": len(selection.files)})
    tool_identity = {"name": tool.name, "version": tool.version, "image_id": image_id}
    for attempt in range(retries + 1):
        outcome.attempt = attempt
        outcome.observations = []
        if invocation.project_root is None:
            scratch = unit.unit_root / "scratch" / f"attempt_{attempt + 1:02d}"
            invocation_key = f"{attempt + 1}"
        else:
            scratch = unit.unit_root / "scratch" / f"invocation_{index + 1:03d}" / f"attempt_{attempt + 1:02d}"
            invocation_key = f"invocation-{index + 1}:{attempt + 1}"
        invocation_id = hashlib.sha256(
            f"{unit.job.run_id}:{unit.job.attempt_id}:{unit.unit_id}:{invocation_key}".encode()).hexdigest()
        invoked = time.monotonic()
        unit.job.events.write("TOOL_INVOCATION_STARTED", unit_id=unit.unit_id,
                              tool_invocation_id=invocation_id, tool_id=adapter.tool_id,
                              tool_identity=tool_identity, input_identities=dict(input_identities),
                              retry_count=attempt, **project_fields)
        if adapter.tool_id == "tool-trivy":
            staged = scratch / "inputs"
            for relative in selection.files:
                source = (unit.job.target_root or Path()) / relative
                destination = staged / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
        execution_target = unit.job.target_root or Path()
        if swift_present and not unit.job.tools.enable_swift and adapter.tool_id not in {
                "tool-spotbugs", "tool-blint", "tool-grype"}:
            stage_id = hashlib.sha256(canonical_json({
                "tool": adapter.tool_id, "files": list(selection.files),
                "catalog": catalog.handoff_sha256,
            })).hexdigest()[:16]
            staged_target = unit.job.run_root / ".scratch" / "swift-policy-targets" / stage_id
            staged_target.mkdir(parents=True, exist_ok=True)
            hashes = {str(item["path"]): str(item.get("sha256", "")) for item in catalog.files}
            for relative in selection.files:
                if relative not in hashes:
                    continue
                source = (execution_target / relative).resolve()
                if (execution_target.resolve() not in source.parents or source.is_symlink()
                        or not source.is_file() or file_sha256(source) != hashes[relative]):
                    raise ValueError(f"accepted scanner input changed or escapes the target: {relative}")
                destination = staged_target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists():
                    if destination.is_symlink() or file_sha256(destination) != hashes[relative]:
                        raise ValueError(f"staged scanner input identity changed: {relative}")
                else:
                    shutil.copyfile(source, destination)
            execution_target = staged_target
        gaps: list[str] = []
        try:
            if fail_tool == adapter.tool_id:
                raise RuntimeError(f"injected bounded failure: {adapter.tool_id}{subject}")
            result = executor.execute(ExecutionRequest(
                tool_id=adapter.tool_id, argv=adapter.argv(tool.executable, selection),
                target_root=execution_target, scratch_root=scratch,
                extra_mounts=mounts, environment=environment, memory=memory,
            ))
            outcome.result = result
            attempt_paths = (unit.job.run_root / result.stdout_path,
                             unit.job.run_root / result.stderr_path,
                             unit.job.run_root / result.receipt_path)
            outcome.raw_paths = (*outcome.raw_paths, *attempt_paths)
            if result.stdout_truncated:
                gaps.append(f"stdout was truncated at the configured byte bound{subject}")
            if result.stderr_truncated:
                gaps.append(f"stderr was truncated at the configured byte bound{subject}")
            if result.timed_out:
                raise RuntimeError(f"{adapter.tool_id} timed out{subject}")
            if result.oom_killed:
                raise RuntimeError(f"{adapter.tool_id} was OOM-killed{subject}")
            if (adapter.tool_id == "tool-osv-scanner" and attempt_paths[1].is_file() and
                    no_packages_declared(result.exit_code, attempt_paths[1].read_bytes(), selection.files)):
                # Every lockfile was scanned and declares no packages: nothing can match an advisory.
                outcome.not_applicable = [InputDecision(
                    path, adapter.tool_id, ReasonCode.TOOL_REPORTED_UNSUPPORTED_INPUT,
                    "osv-scanner scanned the lockfile and found 0 packages") for path in selection.files]
                outcome.error_class = None
                unit.job.events.write("TOOL_INVOCATION_COMPLETED", unit_id=unit.unit_id,
                                      tool_invocation_id=invocation_id, tool_id=adapter.tool_id,
                                      tool_identity=tool_identity, disposition="SUCCEEDED", retry_count=attempt,
                                      result_count=0, gap_count=len(gaps), gaps=gaps[:50],
                                      checkpoint_reused=False, truncated=False,
                                      duration_ms=max(0, int((time.monotonic() - invoked) * 1000)),
                                      **project_fields)
                outcome.gaps.extend(gaps)
                return outcome
            if result.exit_code not in adapter.accepted_exit_codes:
                stderr = attempt_paths[1].read_bytes() if attempt_paths[1].is_file() else b""
                missing = (osv_missing_ecosystems(stderr)
                           if adapter.tool_id == "tool-osv-scanner" else ())
                if missing:
                    raise RuntimeError(osv_missing_ecosystem_gap(
                        missing, f"the lockfiles{subject}" if subject else "the selected lockfiles"))
                detail = bounded_diagnostic(stderr)
                raise RuntimeError(f"{adapter.tool_id} exited with {result.exit_code}{subject}" +
                                   (f": {detail}" if detail else ""))
            if adapter.collector is not None:
                try:
                    adapter.collector(scratch)
                except (OSError, ValueError, UnicodeError) as exc:
                    raise RuntimeError(f"{adapter.tool_id} report could not be assembled{subject} "
                                       f"({type(exc).__name__}: {exc})") from exc
            if adapter.stderr_gaps is not None and attempt_paths[1].is_file():
                gaps.extend(adapter.stderr_gaps(attempt_paths[1].read_bytes()))
            output = scratch / adapter.output_file.removeprefix("/scratch/") if adapter.output_file else attempt_paths[0]
            if not output.is_file():
                raise RuntimeError(f"{adapter.tool_id} did not produce its expected output{subject}")
            if output.stat().st_size > tool.output_bytes:
                raise RuntimeError(f"{adapter.tool_id} output artifact exceeded its byte bound{subject}")
            if output not in outcome.raw_paths:
                outcome.raw_paths = (*outcome.raw_paths, output)
            try:
                parsed = adapter.parse(output.read_bytes())
                observations, parser_gaps, reported_not_applicable = _separate_parser_diagnostics(
                    parsed, adapter.tool_id)
                reject_swift_derived(
                    observations, enabled=unit.job.tools.enable_swift,
                    context=f"{adapter.tool_id} observations")
                gaps.extend(parser_gaps)
                if adapter.tool_id == "tool-checkov":
                    known = {item.path for item in reported_not_applicable}
                    reported_not_applicable.extend(
                        InputDecision(path, adapter.tool_id, ReasonCode.TOOL_REPORTED_UNSUPPORTED_INPUT,
                                      "Checkov accepted the input and reported no check, skip, or parse error")
                        for path in checkov_unreported_inputs(output.read_bytes(), selection.files)
                        if path not in known)
                if adapter.tool_id in SEI_CERT_TOOLS:
                    dropped_gaps, dropped_na = semgrep_unscanned_inputs(
                        output.read_bytes(), selection.files,
                        semgrep_rule_languages(_semgrep_rule_files(repository_root=unit.job.repository_root,
                                                                   tool_id=adapter.tool_id)),
                        _container_relative)
                    gaps.extend(dropped_gaps)
                    known = {item.path for item in reported_not_applicable}
                    reported_not_applicable.extend(
                        InputDecision(path, adapter.tool_id, ReasonCode.TOOL_REPORTED_UNSUPPORTED_INPUT, reason)
                        for path, reason in dropped_na if path not in known)
            except (ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"{adapter.tool_id} parser incompatibility{subject} "
                                   f"({type(exc).__name__})") from exc
            outcome.output = output
            outcome.observations = observations
            outcome.not_applicable = reported_not_applicable
            outcome.gaps.extend(gaps)
            outcome.error_class = None
            effective_gaps = list(dict.fromkeys((*selection.gaps, *adapter.limitations, *outcome.gaps)))
            unit.job.events.write("TOOL_INVOCATION_COMPLETED", unit_id=unit.unit_id,
                                  tool_invocation_id=invocation_id, tool_id=adapter.tool_id,
                                  tool_identity=tool_identity, disposition="SUCCEEDED", retry_count=attempt,
                                  result_count=len(observations), gap_count=len(effective_gaps),
                                  gaps=effective_gaps[:50], checkpoint_reused=False,
                                  truncated=result.stdout_truncated or result.stderr_truncated,
                                  duration_ms=max(0, int((time.monotonic() - invoked) * 1000)),
                                  **project_fields)
            return outcome
        except (RuntimeError, subprocess.SubprocessError) as exc:
            outcome.error_class = type(exc).__name__
            outcome.observations = []
            outcome.gaps.extend((*gaps, str(exc)))
            unit.job.events.write("TOOL_INVOCATION_COMPLETED", unit_id=unit.unit_id,
                                  tool_invocation_id=invocation_id, tool_id=adapter.tool_id,
                                  tool_identity=tool_identity, disposition="FAILED", retry_count=attempt,
                                  error_class=outcome.error_class, result_count=0,
                                  gap_count=len(outcome.gaps), gaps=outcome.gaps[-50:],
                                  checkpoint_reused=False, truncated=False,
                                  duration_ms=max(0, int((time.monotonic() - invoked) * 1000)),
                                  **project_fields)
    return outcome


def _merge_osv_outputs(unit: UnitContext, invocations: list[_Invocation],
                       outcomes: list[_InvocationOutcome]) -> Path:
    """One osv-scanner-shaped document holding every successful project's ``results``.

    Each per-project output stays a raw artifact under its own byte bound; this merged view is
    the task's ``scanner_output`` and records which bounded output each result came from.
    """
    results: list[Any] = []
    sources: list[dict[str, Any]] = []
    for invocation, outcome in zip(invocations, outcomes):
        if outcome.output is None:
            continue
        document = json.loads(outcome.output.read_bytes())
        results.extend(document.get("results", []) if isinstance(document, Mapping) else [])
        sources.append({"project_root": invocation.project_root,
                        "lockfiles": list(invocation.selection.files),
                        "output": _artifact(unit.job.run_root, outcome.output)})
    destination = unit.unit_root / "osv-scanner-merged.json"
    atomic_json(destination, {"schema": "appsec-review/osv-scanner-merged-output/1",
                              "results": results, "invocations": sources})
    return destination


def _execute_tool(unit: UnitContext, adapter: ToolAdapter, catalog: ScanCatalog,
                  executor_factory: ExecutorFactory, fail_tool: str | None,
                  planned: Applicability | None = None, *, swift_present: bool = False) -> Mapping[str, Any]:
    selection = _apply_swift_policy(
        planned if planned is not None else adapter.applicability(catalog),
        enabled=unit.job.tools.enable_swift)
    if swift_present and not unit.job.tools.enable_swift and SWIFT_KNOWN_GAP not in selection.gaps:
        selection = Applicability(
            selection.applicable, selection.reason, selection.files, selection.coverage_kind,
            (*selection.gaps, SWIFT_KNOWN_GAP), selection.families)
    selection, not_applicable = _filter_supported_inputs(selection, adapter, unit.job.target_root)
    if adapter.tool_id == "tool-grype" and unit.job.tools.disable_grype:
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
    selection, mounts, environment, blocked = _prerequisites(unit, adapter, selection)
    if not selection.applicable:
        # Every planned input was outside the tool's declared support: SKIPPED_NA, not a gap.
        unsupported_only = bool(not_applicable)
        envelope, path = _write_evidence(
            unit, adapter, catalog, selection,
            tool_identity={"id": adapter.tool_id, "disposition": "not_executed"},
            raw_artifacts=(), observations=[], terminal_status="NOT_APPLICABLE",
            gaps=() if unsupported_only else (selection.reason,), not_applicable=not_applicable,
            include_limitations=not unsupported_only,
        )
        return {"tool_id": adapter.tool_id, "capability": adapter.capability,
                "terminal_status": "NOT_APPLICABLE",
                **({"coverage_disposition": "SKIPPED_NA", "reason": selection.reason}
                   if unsupported_only else {}),
                "checkpoint_reused": False,
                "artifact": _artifact(unit.job.run_root, path), "record_count": 0,
                "gaps": envelope["exclusions_and_gaps"],
                "not_applicable_inputs": envelope["not_applicable_inputs"]}
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
        settings = _settings(unit)
        configured_retries = settings.tool_retries
        invocations = _plan_invocations(adapter, catalog, selection, mounts,
                                        settings.osv_max_lockfiles_per_invocation)
        input_identities = _extra_identity(mounts)
        memory = settings.osv_memory if adapter.tool_id == "tool-osv-scanner" else None
        outcomes = [
            _run_invocation(unit, adapter, catalog, invocation, index, executor=executor, tool=tool,
                            image_id=image_id, fail_tool=fail_tool, retries=configured_retries,
                            swift_present=swift_present, environment=environment, memory=memory,
                            input_identities={target: value for target, value in input_identities.items()
                                              if target in {mount.target for mount in invocation.mounts}})
            for index, invocation in enumerate(invocations)]
        raw_paths = tuple(path for outcome in outcomes for path in outcome.raw_paths)
        observations = [record for outcome in outcomes for record in outcome.observations]
        gaps = [gap for outcome in outcomes for gap in outcome.gaps]
        reported_not_applicable = [item for outcome in outcomes for item in outcome.not_applicable]
        failed = [outcome for outcome in outcomes if outcome.error_class is not None]
        # One failed project is a named gap beside the others' evidence; FAILED only when none ran.
        error_class = failed[-1].error_class if len(failed) == len(outcomes) else None
        terminal = "FAILED" if error_class is not None else ("PARTIAL" if failed or gaps else "SUCCEEDED")
        results = [outcome.result for outcome in outcomes if outcome.result is not None]
        result = results[-1] if results else None
        outputs = [outcome.output for outcome in outcomes if outcome.output is not None]
        partitioned = any(invocation.project_root is not None for invocation in invocations)
        if partitioned and outputs:
            output = _merge_osv_outputs(unit, invocations, outcomes)
        else:
            output = outputs[-1] if outputs else None
        tool_identity: dict[str, Any] = {
            "id": adapter.tool_id, "name": tool.name, "version": tool.version,
            "image_tag": tool.tag, "image_id": image_id,
            "attempt_count": sum(outcome.attempt + 1 for outcome in outcomes),
            "error_class": error_class}
        if partitioned:
            tool_identity.update({"invocation_count": len(outcomes), "failed_invocation_count": len(failed),
                                  "memory": memory})
        envelope, evidence_path = _write_evidence(
            unit, adapter, catalog, selection, tool_identity=tool_identity,
            raw_artifacts=raw_paths, observations=observations, terminal_status=terminal, gaps=tuple(gaps),
            not_applicable=(*not_applicable, *reported_not_applicable),
        )
        output_value = {
            "tool_id": adapter.tool_id, "capability": adapter.capability,
            "terminal_status": terminal, "checkpoint_reused": False,
            "artifact": _artifact(unit.job.run_root, evidence_path),
            "scanner_output": _rel(unit.job.run_root, output) if output is not None else None,
            "execution": (_artifact(unit.job.run_root, unit.job.run_root / result.receipt_path)
                          if result is not None else None),
            "record_count": envelope["record_count"], "gaps": envelope["exclusions_and_gaps"],
            "not_applicable_inputs": envelope["not_applicable_inputs"],
            "checkpoint_identity": identity,
            "retry_count": max(outcome.attempt for outcome in outcomes),
        }
        if partitioned:
            output_value["invocations"] = [
                {"project_root": invocation.project_root, "lockfile_count": len(invocation.selection.files),
                 "terminal_status": "FAILED" if outcome.error_class else "SUCCEEDED",
                 "retry_count": outcome.attempt,
                 "scanner_output": (_rel(unit.job.run_root, outcome.output)
                                    if outcome.output is not None else None),
                 "execution": (_artifact(unit.job.run_root, unit.job.run_root / outcome.result.receipt_path)
                               if outcome.result is not None else None)}
                for invocation, outcome in zip(invocations, outcomes)]
        if terminal in {"SUCCEEDED", "PARTIAL"}:
            checkpoint_root.mkdir(parents=True, exist_ok=True)
            checkpoint_artifacts = [output_value["artifact"]]
            for item in results:
                checkpoint_artifacts.append(_artifact(unit.job.run_root, unit.job.run_root / item.receipt_path))
            for path in (*outputs, *((output,) if output is not None and output not in outputs else ())):
                checkpoint_artifacts.append(_artifact(unit.job.run_root, path))
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
                      "index_reused": True,
                      "not_applicable_inputs": output.get("not_applicable_inputs") or not_applicable_summary(())}
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
             "record_count": output.get("record_count", 0), "gaps": output.get("gaps", []),
             "not_applicable_inputs": output.get("not_applicable_inputs") or not_applicable_summary(())}
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


SOURCE_ANALYZERS = CAPABILITIES["source_sast"]


def unsupported_source_coverage(catalog: ScanCatalog) -> dict[str, Any]:
    """Cataloged source files that no declared source analyzer supports (unsupported-language coverage)."""
    paths = sorted(str(item["path"]) for item in catalog.files
                   if item.get("language") is not None and not any(
                       TOOL_INPUT_SUPPORT[tool].supports_path(str(item["path"])) for tool in SOURCE_ANALYZERS))
    languages: dict[str, int] = {}
    selected = set(paths)
    for item in catalog.files:
        if str(item["path"]) in selected:
            key = str(item.get("language"))
            languages[key] = languages.get(key, 0) + 1
    gap = (f"unsupported-language coverage: {len(paths)} cataloged source file(s) have no declared source "
           f"analyzer ({', '.join(f'{key}={value}' for key, value in sorted(languages.items()))})") if paths else None
    return {"kind": "unsupported-language", "count": len(paths), "languages": dict(sorted(languages.items())),
            "paths": paths[:200], "truncated": len(paths) > 200, "gap": gap}


def _assemble_manifest(unit: UnitContext, index_units: tuple[str, ...]) -> Mapping[str, Any]:
    manifest_path, manifest_sha = resolve_context_manifest(unit.job)
    upstream, _ = load_verified_manifest(unit.job.run_root, manifest_path, manifest_sha)
    gaps: list[str] = []
    dispositions: list[dict[str, Any]] = []
    shards: list[IndexIdentity] = []
    not_applicable: list[Mapping[str, Any]] = []
    for unit_id in index_units:
        output = unit.output(unit_id)
        skipped = output.get("not_applicable_inputs") or not_applicable_summary(())
        dispositions.append({"tool_id": output["tool_id"], "terminal_status": output["terminal_status"],
                             "checkpoint_reused": output["checkpoint_reused"], "record_count": output["record_count"],
                             "index_reused": output.get("index_reused", False),
                             "shard_id": output["index_identity"]["shard_id"],
                             "gaps": output.get("gaps", []),
                             "not_applicable_input_count": int(skipped.get("count", 0))})
        not_applicable.extend(skipped.get("items", ()))
        gaps.extend(str(item) for item in output.get("gaps", []))
        shards.append(IndexIdentity(**{**output["index_identity"],
                                       "gaps": tuple(output["index_identity"].get("gaps", ()))}))
    unsupported = unsupported_source_coverage(load_target_catalog(unit.job.run_root))
    if unsupported["count"]:
        # No declared source analyzer supports these files: a named coverage gap, never clean.
        gaps.append(unsupported["gap"])
    existing = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))})
                for item in upstream["indexes"]
                if item.get("producer", {}).get("job") != "job_evidence_collection"]
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
            "dispositions": dispositions, "gaps": list(dict.fromkeys(gaps)),
            "not_applicable_inputs": not_applicable_summary(not_applicable),
            "unsupported_coverage": unsupported}


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
                swift_present = bool(swift_inventory_count(catalog.files))
                if not unit.job.tools.enable_swift:
                    catalog = ScanCatalog(
                        catalog.source_fingerprint, catalog.handoff_sha256,
                        filter_swift_files(catalog.files, enabled=False), catalog.projects,
                        catalog.artifacts, catalog.target_root, catalog.compile_commands)
                plan = load_accepted_plan(unit.job.run_root)
                by_tool = {item["scanner_id"]: item for item in plan["scanner_selections"]}
                natural = selected.applicability(catalog)
                decision = by_tool.get(selected.tool_id)
                planned = (Applicability(False, "not selected by accepted target analysis plan", (),
                                         natural.coverage_kind) if decision is None else
                           Applicability(True, str(decision["reason"]),
                                         tuple(item["path"] for item in decision["scope"]),
                                         natural.coverage_kind, natural.gaps, natural.families))
                return _execute_tool(
                    unit, selected, catalog, factory, fail_tool, planned,
                    swift_present=swift_present)
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
            "not_applicable_inputs": index.get("not_applicable_inputs"),
            "unsupported_coverage": index.get("unsupported_coverage"),
        }
        path = unit.unit_root / "handoff.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(path, document)
        return {"schema": document["schema"], "artifact": _artifact(unit.job.run_root, path),
                "index_manifest": index["index_manifest"],
                "item_count": index["item_count"], "gaps": document["gaps"],
                "dispositions": document["dispositions"],
                "not_applicable_inputs": document["not_applicable_inputs"],
                "unsupported_coverage": document["unsupported_coverage"]}

    units.append(Unit("evidence_publication.publish_handoff", publish,
                      ("evidence_publication.assemble_manifest",)))
    source_files = (Path(__file__), Path(__file__).with_name("adapters.py"), Path(__file__).with_name("evidence.py"))
    implementation = hashlib.sha256(b"".join(path.read_bytes() for path in source_files) + str(fail_tool).encode()).hexdigest()

    def runtime_identity(repository_root: Path) -> str:
        root = Path(repository_root).resolve()
        catalog = load_catalog(root)
        static_tools = {tool_id: tool for tool_id, tool in catalog.tools.items()
                        if tool.metadata.get("static_adapter", True) is not False}
        paths = [root / "containers" / "catalog.toml", root / "containers" / "runtime-policy.toml",
                 root / "rules" / "semgrep" / "security.yml", root / "rules" / "semgrep" / "review-signals.yml",
                 root / "rules" / "semgrep" / "rules.lock.json",
                 root / "rules" / "sei-cert" / "pack.lock.json",
                 root / "data" / "feeds" / "osv" / "current.json",
                 root / "data" / "feeds" / "grype" / "current.json",
                 *(tool.manifest_path for tool in static_tools.values())]
        digest = hashlib.sha256()
        for path in paths:
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(path.read_bytes() if path.is_file() else b"MISSING")
        # The lock bytes alone do not show whether the pack still matches them; bind the result of
        # strict verification so any pack change forces the job to re-run rather than be reused.
        sei_cert = _sei_cert_pack(root)
        digest.update(canonical_json(sei_cert.as_record() if sei_cert else {"verified": False}))
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
               runtime_identity=runtime_identity, units=tuple(units),
               datasets=DATASETS, consumes=CONSUMES)
