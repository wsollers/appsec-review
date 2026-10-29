"""AddressSanitizer and UndefinedBehaviorSanitizer rebuild of accepted native build units.

After ``job_language_build`` is accepted, each successful native build unit is replayed in a
separate run-owned workspace with sanitizer flags injected through the environment
(``CFLAGS``/``CXXFLAGS``/``LDFLAGS``). The job runs only build tools (the accepted recipe's
configure and build commands) inside the same build container policy as the normal build; it never
loads or executes a produced binary. Instrumentation is proven by reading the produced ELF for
sanitizer runtime references, and every unit that is not provably instrumented is a named gap.
The instrumented tree is catalogued in a hash-bound handoff and consumed by no existing job; a
later, separately authorized execution stage is the only thing that may run it
(docs/operations/sanitizer-build.md).
"""

from __future__ import annotations

from appsec_review.storage.shared import PublicationThreadPoolExecutor as ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import time
from typing import Any, Callable, Mapping, Sequence

from appsec_review.config.build_outputs import BuildOutputPolicy
from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
from appsec_review.jobs.build_bookkeeping import BookkeepingExclusions, bookkeeping_reason
from appsec_review.jobs.build_output_scope import BuildOutputDispositions
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.engineering_contracts import SANITIZER_BUILD_HANDOFF_SCHEMA
from appsec_review.jobs.job_codeql_analysis.planning import replay_commands
from appsec_review.jobs.job_language_build import elf as elf_reader
from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.jobs.job_language_build.job import _build_output_policy, _copy_source, _kind, _snapshot
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256, protected_json
from .datasets import CONSUMES, DATASETS
from .evidence import (
    CATALOGED_KINDS, LINKED_KINDS, any_referenced, referenced, runtime_evidence,
)
from .settings import SanitizerBuildSettings, argument_conflicts, instrumented_environment


JOB_ID = "job_sanitizer_build"
UNIT_SCHEMA = "appsec-review/sanitizer-build-unit/1"
REPLAY_SCHEMA = "appsec-review/sanitizer-build-replay/1"
PROTECTED_COMMAND_SCHEMA = "appsec-review/protected-build-command/2"
IMPLEMENTATION = "appsec-review/sanitizer-build/1"
OUTPUT_ROOT = ("data", "sanitizer")
_GAP_LIMIT = 20
_MISSING_RUNTIME = re.compile(
    rb"(?:cannot find|No such file or directory|library not found for)[^\n]{0,160}?"
    rb"(lib(?:clang_rt\.)?(?:asan|ubsan)[A-Za-z0-9_.+-]*|-l(?:asan|ubsan))")


class FrameworkIntegrityError(ValueError):
    """A changed accepted identity or run-owned artifact; publication must stop."""


def _settings(unit: UnitContext) -> SanitizerBuildSettings:
    return SanitizerBuildSettings.from_mapping(unit.job.config.settings)


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    if run_root.resolve() not in resolved.parents or resolved.is_symlink():
        raise FrameworkIntegrityError("sanitizer-build artifact escaped the run")
    return {"path": resolved.relative_to(run_root.resolve()).as_posix(),
            "sha256": file_sha256(resolved), "size_bytes": resolved.stat().st_size}


def _protected_command(run_root: Path, command: Mapping[str, Any], image: Mapping[str, Any]
                       ) -> tuple[dict[str, Any] | None, str | None]:
    """One accepted command's exact argv, working directory and environment, hash-verified."""
    identity = command.get("protected_argv")
    if not isinstance(identity, Mapping):
        return None, "accepted build command lacks its protected argv"
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        return None, "accepted protected build command is unavailable"
    if file_sha256(path) != identity.get("sha256"):
        raise FrameworkIntegrityError("accepted protected build command identity changed")
    document = json.loads(path.read_text(encoding="utf-8"))
    argv, environment = document.get("argv"), document.get("environment")
    if (document.get("schema") != PROTECTED_COMMAND_SCHEMA or not isinstance(argv, list) or not argv or
            any(not isinstance(item, str) for item in argv) or not isinstance(environment, Mapping)):
        return None, "accepted protected build command is invalid"
    if argv[0].startswith("<redacted"):
        return None, "accepted build command was redacted by the secret scan and cannot be replayed"
    argv_sha = hashlib.sha256(canonical_json(argv)).hexdigest()
    if (argv_sha != command.get("argv_sha256") or
            document.get("working_directory") != command.get("working_directory") or
            command.get("image_id") != image.get("image_id")):
        raise FrameworkIntegrityError("accepted build command identity mismatch")
    return {"argv": argv, "argv_sha256": argv_sha, "working_directory": str(document["working_directory"]),
            "environment": {str(key): str(value) for key, value in environment.items()}}, None


def _replay(run_root: Path, receipt: Mapping[str, Any]) -> tuple[list[dict[str, Any]] | None, str | None]:
    image = receipt.get("image")
    if not isinstance(receipt.get("recipe"), Mapping) or not isinstance(image, Mapping):
        return None, "accepted build recipe or image is unavailable"
    accepted = replay_commands(receipt)
    if accepted is None:
        return None, "accepted build command set is incomplete"
    commands = []
    for ordinal, (command, role) in enumerate(accepted, 1):
        replayed, error = _protected_command(run_root, command, image)
        if replayed is None:
            return None, error
        commands.append({"ordinal": ordinal, "role": role, **replayed})
    return commands, None


def _stream(path: Path, data: bytes, total: int | None, truncated: bool, run_root: Path) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {**_artifact(run_root, path), "total_bytes": total if total is not None else len(data),
            "truncated": truncated}


def _baseline(run_root: Path, receipt: Mapping[str, Any], relative: str, kind: str) -> dict[str, Any] | None:
    """The normal build's file at the same workspace path, read as a control (never executed)."""
    for item in receipt.get("artifacts", ()):
        if not isinstance(item, Mapping) or item.get("workspace_path") != relative or item.get("kind") != kind:
            continue
        path = (run_root / str(item.get("path", ""))).resolve()
        if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
            return {"path": item.get("path"), "evidence_status": "unavailable", "runtime_referenced": None}
        if file_sha256(path) != item.get("sha256"):
            return {"path": item.get("path"), "evidence_status": "changed", "runtime_referenced": None}
        evidence = runtime_evidence(path, kind)
        return {"path": item["path"], "sha256": item["sha256"], "evidence_status": evidence["evidence_status"],
                "runtime_referenced": any_referenced(evidence) if evidence["evidence_status"] == "resolved" else None}
    return None


def _compact(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Object files keep the booleans; the symbol listings stay with the linked outputs."""
    return {**evidence, "sanitizers": {name: {"runtime_referenced": item["runtime_referenced"],
                                              "symbol_count": item["symbol_count"]}
                                       for name, item in evidence["sanitizers"].items()}}


def _dispositions(receipt: Mapping[str, Any], policy: BuildOutputPolicy | None,
                  exclusions: BookkeepingExclusions) -> BuildOutputDispositions:
    """Replay the accepted language build's tree decisions onto the identical rebuild layout.

    Dependency trees are not part of the target's instrumentation verdict, so their files are
    pruned here without keeping linked outputs; per-file decisions stay ordinary content.
    """
    dispositions = BuildOutputDispositions(policy, family="native", bookkeeping=exclusions)
    accepted = receipt.get("build_output_dispositions")
    for root in accepted.get("roots", ()) if isinstance(accepted, Mapping) else ():
        if not isinstance(root, Mapping) or root.get("disposition") == "per_file":
            continue
        dispositions.classify_tree(
            str(root["root"]), disposition=str(root["disposition"]), basis=str(root["basis"]),
            confidence=str(root["confidence"]), name=str(root["name"]), reason=str(root["reason"]),
            evidence_ref=root.get("evidence_ref"), pattern=root.get("pattern"), scope=root.get("scope"),
            scope_role=root.get("scope_role"))
    return dispositions


def _catalog(run_root: Path, workspace: Path, before: Mapping[str, str], receipt: Mapping[str, Any],
             settings: SanitizerBuildSettings, build_unit_id: str, policy: BuildOutputPolicy | None = None
             ) -> tuple[list[dict[str, Any]], BuildOutputDispositions, list[str]]:
    outputs: list[dict[str, Any]] = []
    gaps: list[str] = []
    dispositions = _dispositions(receipt, policy, BookkeepingExclusions())
    for relative, decision in dispositions.walk(workspace):
        if decision.kept:
            continue
        path = workspace / relative
        kind = _kind(path, "native", relative=relative, before=before)
        if kind not in CATALOGED_KINDS:
            continue
        digest = file_sha256(path)
        if before.get(relative) == digest:
            continue  # an accepted input that the rebuild did not produce
        reason = bookkeeping_reason(relative)
        if reason is not None:
            dispositions.record_bookkeeping(reason, relative)
            continue
        evidence = runtime_evidence(path, kind)
        outputs.append({
            "path": path.relative_to(run_root).as_posix(), "workspace_path": relative, "sha256": digest,
            "size_bytes": path.stat().st_size, "kind": kind, "build_unit_id": build_unit_id,
            "evidence": evidence if kind in LINKED_KINDS else _compact(evidence),
            "baseline": _baseline(run_root, receipt, relative, kind),
        })
        if len(outputs) >= settings.artifact_count_limit:
            gaps.append("instrumented output catalog truncated at the configured count bound")
            break
    return outputs, dispositions, gaps


def _judge(outputs: list[dict[str, Any]], settings: SanitizerBuildSettings) -> list[str]:
    """Set each output's boolean ``instrumented`` fact and name every reason a unit is not proven."""
    gaps: list[str] = []
    required = settings.required_evidence
    for output in outputs:
        evidence = output["evidence"]
        status = evidence["evidence_status"]
        output["instrumented"] = status == "resolved" and referenced(evidence, required)
        if output["kind"] not in LINKED_KINDS or output["instrumented"]:
            continue
        where = output["workspace_path"]
        if status == "unparsed":
            gaps.append(f"{where}: ELF was not parseable, so instrumentation could not be proven")
        elif status == "no_symbol_tables":
            gaps.append(f"{where}: no symbol tables (stripped), so instrumentation could not be proven")
        else:
            missing = [name for name in required if not evidence["sanitizers"][name]["runtime_referenced"]]
            gaps.append(f"{where}: no {', '.join(missing)} sanitizer runtime reference in "
                        f"{', '.join(evidence['symbol_tables']) or 'the file'}; the build did not take the flags")
    linked = [item for item in outputs if item["kind"] in LINKED_KINDS]
    if not outputs:
        gaps.append("the instrumented build produced no native objects, executables or shared libraries")
    elif not linked and not any(item["instrumented"] for item in outputs):
        gaps.append("the instrumented build produced no linked output and no object references the sanitizer runtime")
    return gaps


def _bounded(gaps: Sequence[str]) -> list[str]:
    unique = list(dict.fromkeys(gaps))
    if len(unique) <= _GAP_LIMIT:
        return unique
    return [*unique[:_GAP_LIMIT], f"{len(unique) - _GAP_LIMIT} further gaps omitted"]


def _runtime_reason(stderr: bytes) -> str | None:
    match = _MISSING_RUNTIME.search(stderr)
    return (f"the build image lacks the sanitizer runtime {match.group(1).decode('ascii', 'replace')}"
            if match else None)


def _build_unit(unit: UnitContext, receipt: Mapping[str, Any], settings: SanitizerBuildSettings,
                executor_factory: Callable[[UnitContext, BuildProfile], Any] | None) -> dict[str, Any]:
    run_root = unit.job.run_root
    build_unit_id = str(receipt["build_unit_id"])
    recipe = receipt.get("recipe") if isinstance(receipt.get("recipe"), Mapping) else {}
    image = receipt.get("image") if isinstance(receipt.get("image"), Mapping) else {}
    root = run_root.joinpath(*OUTPUT_ROOT, build_unit_id)
    result: dict[str, Any] = {
        "schema": UNIT_SCHEMA, "build_unit_id": build_unit_id, "family": receipt.get("family"),
        "root": receipt.get("root"), "build_system": receipt.get("build_system"),
        "recipe_identity": receipt.get("recipe_identity"), "receipt_fingerprint": receipt.get("fingerprint"),
        "image": {key: image.get(key) for key in ("image_tag", "image_id")},
        "network_required": recipe.get("network_required"), "flags": list(settings.flags),
        "workspace": None, "commands": [], "outputs": [], "excluded_bookkeeping": None,
        "build_output_dispositions": None,
        "instrumented": False, "gaps": [], "terminal_status": "COMPLETED_WITH_GAPS",
    }

    def gap(reason: str, status: str = "COMPLETED_WITH_GAPS") -> dict[str, Any]:
        result["gaps"] = _bounded([*result["gaps"], reason])
        result["terminal_status"] = status
        return result

    unit.job.events.write("SANITIZER_BUILD_STARTED", unit_id=unit.unit_id, build_unit_id=build_unit_id,
                          build_system=receipt.get("build_system"), flags=list(settings.flags))
    if receipt.get("terminal_status") != "SUCCEEDED":
        return gap("the accepted native build did not succeed, so there is no recipe to instrument")
    if receipt.get("build_system") not in settings.build_systems:
        return gap(f"build system {receipt.get('build_system')!r} is not enabled for sanitizer rebuilds "
                   f"(configured: {', '.join(settings.build_systems)})")
    commands, error = _replay(run_root, receipt)
    if commands is None:
        return gap(f"not replayable: {error}")
    conflicts = argument_conflicts([item["argv"] for item in commands])
    environments = []
    for command in commands:
        environment, environment_conflicts = instrumented_environment(settings, command["environment"])
        environments.append(environment)
        conflicts.extend(environment_conflicts)
    if conflicts:
        return gap("sanitizer flags cannot be injected through the environment: " +
                   "; ".join(dict.fromkeys(conflicts)))

    if root.exists():
        try:
            shutil.rmtree(root)
        except OSError as exc:
            return gap(f"a previous sanitizer workspace could not be removed ({type(exc).__name__})")
    workspace = root / "workspace"
    try:
        _copy_source(unit, receipt, workspace)
    except (ValueError, OSError) as exc:
        return gap(f"the accepted source could not be copied into a fresh workspace: {exc}")
    result["workspace"] = workspace.relative_to(run_root).as_posix()
    replay = root / "protected-commands" / "replay.json"
    protected_json(replay, {
        "schema": REPLAY_SCHEMA, "build_unit_id": build_unit_id, "flags": list(settings.flags),
        "commands": [{"ordinal": item["ordinal"], "role": item["role"], "argv": item["argv"],
                      "working_directory": item["working_directory"], "environment": environment}
                     for item, environment in zip(commands, environments, strict=True)],
        "access": "run-owned-protected"})
    result["replay"] = _artifact(run_root, replay)

    try:
        before = _snapshot(workspace, settings.artifact_count_limit * 10)
    except ValueError as exc:
        return gap(f"the accepted source exceeds the workspace file bound: {exc}")
    try:
        profile = BuildProfile(str(receipt.get("family")), str(image["image_tag"]), str(image["image_id"]),
                               str(image["user"]))
        executor = executor_factory(unit, profile) if executor_factory else BuildContainerExecutor(
            profile, timeout_seconds=settings.command_timeout_seconds, output_bytes=settings.output_bytes)
        executor.resolve()
    except (KeyError, RuntimeError, ValueError, TimeoutError) as exc:
        return gap(f"the accepted build image is unavailable or changed ({type(exc).__name__}: {exc})", "FAILED")

    started = time.monotonic()
    for command, environment in zip(commands, environments, strict=True):
        began = time.monotonic()
        try:
            outcome = executor.execute(tuple(command["argv"]), workspace=workspace,
                                       working_directory=command["working_directory"], environment=environment)
        except (RuntimeError, TimeoutError, OSError) as exc:
            return gap(f"instrumented build command {command['ordinal']} could not run ({type(exc).__name__})",
                       "FAILED")
        failed = outcome.timed_out or outcome.exit_code != 0
        ordinal = command["ordinal"]
        result["commands"].append({
            "ordinal": ordinal, "role": command["role"], "tool": Path(command["argv"][0]).name,
            "argv_sha256": command["argv_sha256"], "working_directory": command["working_directory"],
            "exit_code": outcome.exit_code, "timed_out": outcome.timed_out,
            "duration_ms": int((time.monotonic() - began) * 1000),
            "stdout": _stream(root / "logs" / f"{ordinal:03d}.stdout", outcome.stdout, outcome.stdout_bytes,
                              outcome.stdout_truncated, run_root),
            "stderr": _stream(root / "logs" / f"{ordinal:03d}.stderr", outcome.stderr, outcome.stderr_bytes,
                              outcome.stderr_truncated, run_root)})
        if failed:
            reason = _runtime_reason(outcome.stderr + outcome.stderr_tail)
            gap(f"instrumented build command {ordinal} "
                f"{'timed out' if outcome.timed_out else f'exited {outcome.exit_code}'}" +
                (f"; {reason}" if reason else ""), "FAILED")
            break
    if source_fingerprint(unit.job.target_root or Path()) != unit.job.source_fingerprint:
        raise FrameworkIntegrityError("target changed during the sanitizer build")
    if result["terminal_status"] != "FAILED":
        outputs, dispositions, catalog_gaps = _catalog(run_root, workspace, before, receipt, settings,
                                                       build_unit_id, _build_output_policy(unit))
        verdict_gaps = _judge(outputs, settings)
        result.update(outputs=outputs, excluded_bookkeeping=dispositions.bookkeeping.document(),
                      build_output_dispositions=dispositions.document(),
                      outputs_sha256=hashlib.sha256(canonical_json(
                          [[item["workspace_path"], item["sha256"]] for item in outputs])).hexdigest())
        result["gaps"] = _bounded([*catalog_gaps, *verdict_gaps])
        result["instrumented"] = bool(outputs) and not result["gaps"]
        result["terminal_status"] = "SUCCEEDED" if result["instrumented"] else "COMPLETED_WITH_GAPS"
    try:
        files = _snapshot(workspace, settings.artifact_count_limit * 10)
    except ValueError as exc:
        # Without a complete manifest the tree is not hash-bound, so the unit cannot be called instrumented.
        files = None
        result["instrumented"] = False
        gap(f"the instrumented workspace exceeds the file bound, so it has no manifest: {exc}",
            "FAILED" if result["terminal_status"] == "FAILED" else "COMPLETED_WITH_GAPS")
    if files is not None:
        manifest = root / "workspace-manifest.json"
        atomic_json(manifest, {"schema": "appsec-review/build-workspace-manifest/1",
                               "build_unit_id": build_unit_id, "files": files})
        result["workspace_manifest"] = _artifact(run_root, manifest)
    result["duration_ms"] = int((time.monotonic() - started) * 1000)
    result["completed_at"] = datetime.now(timezone.utc).isoformat()
    unit.job.events.write("SANITIZER_BUILD_COMPLETED", unit_id=unit.unit_id, build_unit_id=build_unit_id,
                          disposition=result["terminal_status"], instrumented=result["instrumented"],
                          result_count=len(result["outputs"]), gap_count=len(result["gaps"]),
                          duration_ms=result["duration_ms"])
    return result


def _validate(context: Any, _result: Any) -> None:
    if tuple(context.config.steps) != ("load", "build", "acceptance"):
        raise ValueError("sanitizer-build topology does not match central configuration")
    for step, task in (("load", "accepted_native"), ("build", "units"), ("acceptance", "publish_handoff")):
        if tuple(context.config.step(step).tasks) != (task,):
            raise ValueError(f"sanitizer-build task configuration mismatch: {step}")
    SanitizerBuildSettings.from_mapping(context.config.settings)


def build_job(*, executor_factory: Callable[[UnitContext, BuildProfile], Any] | None = None) -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        accepted = load_accepted_language_build(unit.job.run_root)
        if accepted.get("source_fingerprint") != unit.job.source_fingerprint:
            raise FrameworkIntegrityError("sanitizer-build target snapshot differs from the accepted language build")
        receipts = [item for item in accepted.get("receipts", ()) if isinstance(item, Mapping)]
        ids = [str(item.get("build_unit_id")) for item in receipts]
        if len(ids) != len(set(ids)):
            raise FrameworkIntegrityError("accepted language build contains duplicate build units")
        native = sorted((item for item in receipts if item.get("family") == "native"),
                        key=lambda item: str(item["build_unit_id"]))
        row = lambda item: {"build_unit_id": item["build_unit_id"], "family": item.get("family"),
                            "root": item.get("root"), "build_system": item.get("build_system"),
                            "receipt_fingerprint": item.get("fingerprint")}
        return {"upstream": {"language_build_handoff_sha256": accepted["language_build_handoff_sha256"]},
                "planned": [row(item) for item in native[:settings.max_units]],
                "omitted": [row(item) for item in native[settings.max_units:]],
                "not_applicable": [{**row(item), "reason": f"family {item.get('family')!r} has no native "
                                    "sanitizer rebuild", "disposition": "SKIPPED_NA"}
                                   for item in receipts if item.get("family") != "native"]}

    def build(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        loaded = unit.output("load.accepted_native")
        accepted = load_accepted_language_build(unit.job.run_root)
        if accepted["language_build_handoff_sha256"] != loaded["upstream"]["language_build_handoff_sha256"]:
            raise FrameworkIntegrityError("accepted language build changed between load and build")
        receipts = {str(item["build_unit_id"]): item for item in accepted["receipts"]}
        planned = [receipts[item["build_unit_id"]] for item in loaded["planned"]]
        with ThreadPoolExecutor(max_workers=max(1, settings.workers)) as pool:
            units = list(pool.map(lambda receipt: _build_unit(unit, receipt, settings, executor_factory), planned))
        gaps = [f"{item['build_unit_id']}: {gap}" for item in units for gap in item["gaps"]]
        gaps.extend(f"{item['build_unit_id']}: unit bound of {settings.max_units} reached; "
                    "this native build unit was not rebuilt" for item in loaded["omitted"])
        incomplete = [item for item in units if not item["instrumented"]]
        status = ("NOT_APPLICABLE" if not units and not loaded["omitted"] else
                  "SUCCEEDED" if not incomplete and not loaded["omitted"] else "COMPLETED_WITH_GAPS")
        return {"units": units, "gaps": gaps, "terminal_status": status}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        loaded, built = unit.output("load.accepted_native"), unit.output("build.units")
        outputs = [output for item in built["units"] for output in item["outputs"] if output["instrumented"]]
        counts = {"planned_units": len(loaded["planned"]), "omitted_units": len(loaded["omitted"]),
                  "instrumented_units": sum(1 for item in built["units"] if item["instrumented"]),
                  "not_applicable_units": len(loaded["not_applicable"]),
                  "instrumented_outputs": len(outputs), "gap_count": len(built["gaps"])}
        summary = unit.unit_root / "sanitizer-build-summary.json"
        atomic_json(summary, {
            "schema": SANITIZER_BUILD_HANDOFF_SCHEMA, "upstream": loaded["upstream"],
            "execution_policy": "build tools only; no produced binary was loaded or executed",
            "flags": list(settings.flags), "settings": settings.identity(),
            "build_outputs_policy": _build_output_policy(unit).identity, "counts": counts,
            "units": built["units"], "not_applicable_units": loaded["not_applicable"],
            "omitted_units": loaded["omitted"], "gaps": built["gaps"]})
        return {"schema": SANITIZER_BUILD_HANDOFF_SCHEMA, "artifact": _artifact(unit.job.run_root, summary),
                "item_count": counts["instrumented_outputs"], "counts": counts, "gaps": built["gaps"],
                "terminal_status": built["terminal_status"]}

    units = (
        Unit("load.accepted_native", load),
        Unit("build.units", build, ("load.accepted_native",)),
        Unit("acceptance.publish_handoff", publish, ("load.accepted_native", "build.units")),
    )
    package = Path(__file__).parent
    implementation = None
    return Job(JOB_ID, "sanitizer_build", UnitExecutor(units).execute,
               input_validators=(_validate,), schema_identity=SANITIZER_BUILD_HANDOFF_SCHEMA,
               implementation_identity=implementation, validation_identity=implementation,
               units=units, datasets=DATASETS, consumes=CONSUMES)
