from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from appsec_review.config import RustBuildSettings
from appsec_review.container_runtime import VerifiedCapture
from appsec_review.storage import canonical_json, file_sha256


CAPTURE_IDENTITY = "appsec-review/rust-cargo-build-capture/2"
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_TARGET = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_FORBIDDEN = {"run", "test", "bench", "install", "fix", "miri"}
_TARGET_FLAGS = {"--example", "--examples", "--test", "--tests", "--bench", "--benches", "--all-targets"}
_VALUE_FLAGS = {"--manifest-path", "--target", "--profile", "--features", "--package", "-p", "--jobs", "-j"}
_RUST_ARTIFACTS = {
    ".rlib": "rust-library", ".rmeta": "rust-metadata", ".a": "static-library",
    ".so": "shared-library", ".dylib": "shared-library", ".o": "object",
    ".dwo": "debug-information", ".dwp": "debug-information", ".pdb": "debug-information",
}
_C_DRIVER = re.compile(r"(?:[a-z0-9_]+-)*(?:cc|c\+\+|gcc|g\+\+|clang|clang\+\+)(?:-[0-9.]+)?")
_LINKERS = {"ld", "ld.bfd", "ld.gold", "ld.lld", "lld", "rust-lld", "collect2", "mold"}
_ARCHIVERS = {"ar", "llvm-ar"}
_COMPILE_ONLY = {"-c", "-E", "-S"}
_LINK_KINDS = ("linker-driver", "linker", "archiver")
_INVOCATION_LIMIT = 16384
_EVENT_ORDINAL_LIMIT = 8
_REDACTED = "<redacted"


def validate_dispatch(dispatch: Mapping[str, Any], settings: RustBuildSettings) -> tuple[str, ...]:
    recipe = dispatch.get("recipe")
    if not isinstance(recipe, Mapping) or dispatch.get("build_system") != "cargo":
        return ("Rust execution requires an accepted Cargo recipe",)
    errors: list[str] = []
    commands = [*recipe.get("configure_commands", ()), *recipe.get("build_commands", ())]
    cargo_builds = 0
    for argv in commands:
        if not isinstance(argv, list) or len(argv) < 2 or argv[0] != "cargo":
            errors.append("Rust recipes may execute Cargo commands only")
            continue
        subcommand = str(argv[1]).lower()
        if subcommand in _FORBIDDEN or subcommand not in {"build", "rustc", "check", "metadata"}:
            errors.append(f"Cargo subcommand is unsupported: {subcommand}")
        if subcommand in {"build", "rustc"}:
            cargo_builds += 1
        values = [str(value) for value in argv[2:]]
        if any(value in _TARGET_FLAGS for value in values):
            errors.append("Cargo examples, tests, benchmarks, and all-target builds are forbidden")
        for index, value in enumerate(values):
            if value in {"--target", "--profile", "--features", "--package", "-p"}:
                if index + 1 >= len(values):
                    errors.append(f"Cargo option is missing its value: {value}")
                    continue
                selected = values[index + 1]
                if value == "--target" and not _TARGET.fullmatch(selected):
                    errors.append("Cargo target selection is invalid")
                if value in {"--profile", "--package", "-p"} and not _NAME.fullmatch(selected):
                    errors.append(f"Cargo selection is invalid: {value}")
                if value == "--features" and any(not _NAME.fullmatch(feature)
                        for feature in selected.split(",") if feature):
                    errors.append("Cargo feature selection is invalid")
        if settings.target and "--target" in values:
            index = values.index("--target")
            if index + 1 < len(values) and values[index + 1] != settings.target:
                errors.append("Cargo target differs from central Rust configuration")
        if "--profile" in values:
            index = values.index("--profile")
            if index + 1 < len(values) and values[index + 1] != settings.profile:
                errors.append("Cargo profile differs from central Rust configuration")
    if cargo_builds < 1:
        errors.append("Rust recipe must contain a Cargo build or rustc command")
    dependencies = {PurePosixPath(str(value)).name for value in recipe.get("dependency_files", ())}
    if settings.locked and "Cargo.lock" not in dependencies:
        errors.append("locked Rust builds require Cargo.lock in accepted dependency inputs")
    return tuple(dict.fromkeys(errors))


def _has_option(argv: Sequence[str], option: str) -> bool:
    return option in argv or any(str(value).startswith(option + "=") for value in argv)


def build_argv(argv: Sequence[str], settings: RustBuildSettings) -> tuple[str, ...]:
    values = [str(value) for value in argv]
    if len(values) < 2 or values[0] != "cargo":
        raise ValueError("Rust build command is not Cargo")
    if settings.offline and "--offline" not in values:
        values.append("--offline")
    if settings.locked and "--locked" not in values:
        values.append("--locked")
    if settings.target and not _has_option(values, "--target"):
        values.extend(("--target", settings.target))
    if settings.profile != "dev" and not _has_option(values, "--profile") and "--release" not in values:
        values.extend(("--profile", settings.profile))
    if settings.features and not _has_option(values, "--features"):
        values.extend(("--features", ",".join(settings.features)))
    if values[1] in {"build", "rustc", "check"}:
        if "-vv" not in values and "--verbose" not in values:
            values.append("-vv")
        if not _has_option(values, "--message-format"):
            values.append("--message-format=json-render-diagnostics")
    return tuple(values)


def metadata_argv(recipe: Mapping[str, Any], settings: RustBuildSettings) -> tuple[str, ...]:
    values = ["cargo", "metadata", "--format-version", "1", "--manifest-path", "Cargo.toml"]
    if settings.offline:
        values.append("--offline")
    if settings.locked:
        values.append("--locked")
    if settings.features:
        values.extend(("--features", ",".join(settings.features)))
    return tuple(values)


def parse_metadata(data: bytes, *, max_packages: int = 20000) -> dict[str, Any]:
    value = json.loads(data.decode("utf-8"))
    if not isinstance(value, Mapping) or value.get("version") != 1:
        raise ValueError("Cargo metadata schema is unsupported")
    raw_packages = value.get("packages", [])
    if not isinstance(raw_packages, list) or len(raw_packages) > max_packages:
        raise ValueError("Cargo package count exceeds its bound")
    packages = []
    for package in raw_packages:
        if not isinstance(package, Mapping) or not isinstance(package.get("id"), str):
            raise ValueError("Cargo package metadata is invalid")
        targets = []
        for target in package.get("targets", ()):
            if not isinstance(target, Mapping):
                continue
            targets.append({"name": str(target.get("name", "")),
                            "kind": sorted(str(item) for item in target.get("kind", ())),
                            "crate_types": sorted(str(item) for item in target.get("crate_types", ())),
                            "src_path_sha256": hashlib.sha256(str(target.get("src_path", "")).encode()).hexdigest()})
        packages.append({"id": package["id"], "name": str(package.get("name", "")),
                         "version": str(package.get("version", "")),
                         "manifest_path_sha256": hashlib.sha256(str(package.get("manifest_path", "")).encode()).hexdigest(),
                         "targets": targets, "features": sorted(str(key) for key in
                         package.get("features", {}) if isinstance(package.get("features"), Mapping))})
    resolve = value.get("resolve")
    relationships = []
    if isinstance(resolve, Mapping):
        for node in resolve.get("nodes", ()):
            if not isinstance(node, Mapping) or not isinstance(node.get("id"), str):
                continue
            for dependency in node.get("dependencies", ()):
                if isinstance(dependency, str):
                    relationships.append({"from": node["id"], "to": dependency, "kind": "cargo-resolve"})
    proc_macro_targets = [
        {"package_id": package["id"], "package_name": package["name"], "target": target["name"]}
        for package in packages
        for target in package["targets"]
        if "proc-macro" in target["kind"] or "proc-macro" in target["crate_types"]
    ]
    return {"schema": "appsec-review/rust-cargo-metadata/1", "workspace_root_sha256":
            hashlib.sha256(str(value.get("workspace_root", "")).encode()).hexdigest(),
            "target_directory_sha256": hashlib.sha256(str(value.get("target_directory", "")).encode()).hexdigest(),
            "workspace_members": sorted(str(item) for item in value.get("workspace_members", ())),
            "packages": packages, "relationships": relationships,
            "proc_macro_targets": proc_macro_targets}


def _mapped(workspace: Path, directory: str, value: str) -> dict[str, Any] | None:
    normalized = value.replace("\\", "/")
    if normalized.startswith("/workspace/"):
        logical = PurePosixPath(normalized[len("/workspace/"):])
    elif normalized.startswith("/"):
        return None
    else:
        # Cargo starts workspace-member tools in the accepted source directory.
        logical = PurePosixPath(directory) / normalized
    if ".." in logical.parts:
        return None
    root = workspace.resolve()
    candidate = (root / Path(*logical.parts)).resolve()
    if root != candidate and root not in candidate.parents:
        return None
    result: dict[str, Any] = {"workspace_path": candidate.relative_to(root).as_posix()}
    if candidate.is_file() and not candidate.is_symlink():
        result.update(sha256=file_sha256(candidate), size_bytes=candidate.stat().st_size,
                      mapping="exact-workspace-path", mapping_confidence=1.0)
    else:
        result.update(mapping="declared-path-unresolved", mapping_confidence=0.5)
    return result


def tool_kind(name: str, argv: Sequence[str]) -> str | None:
    """Classify one observed executable; unknown tools are not Rust build provenance."""
    if name == "rustc":
        return "compiler"
    if name.startswith(("build-script-", "build_script_")):
        return "code-generator"
    if name in _ARCHIVERS or name.endswith("-ar"):
        return "archiver"
    if name in _LINKERS:
        return "linker"
    if _C_DRIVER.fullmatch(name):
        return "compiler-driver" if _COMPILE_ONLY & set(argv[1:]) else "linker-driver"
    return None


def _row(name: str, kind: str, argv: Sequence[str], workspace: Path, directory: str,
         origin: str) -> dict[str, Any]:
    values = [str(value) for value in argv]
    outputs: list[str] = []
    inputs: list[str] = []
    for index, value in enumerate(values[:-1]):
        if value in {"-o", "--out-dir"}:
            outputs.append(values[index + 1])
    if kind == "archiver":
        outputs.extend(value for value in values[1:] if Path(value).suffix.lower() in {".a", ".rlib"})
        outputs = outputs[:1]
    for value in values[1:]:
        if Path(value).suffix.lower() in {".rs", ".rlib", ".rmeta", ".o", ".a", ".so"} and value not in outputs:
            inputs.append(value)
    return {"tool": name, "tool_kind": kind, "argv": values,
            "argv_sha256": hashlib.sha256(canonical_json(values)).hexdigest(),
            "inputs": [item for item in (_mapped(workspace, directory, value) for value in inputs) if item],
            "outputs": [item for item in (_mapped(workspace, directory, value) for value in outputs) if item],
            "origin": origin, "mapping_confidence": 1.0}


def _invocation_key(name: str, argv: Sequence[str]) -> str:
    # A PATH launcher, a toolchain proxy, and the resolved binary differ only in argv[0].
    return hashlib.sha256(canonical_json([name, *[str(value) for value in argv[1:]]])).hexdigest()


def capture_invocations(captures: Sequence[tuple[int, VerifiedCapture]], workspace: Path,
                        directory: str) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Derive Rust tool provenance from hash-verified standardized capture records.

    Only a successful process-exec syscall event establishes that a tool ran, including tools
    started by absolute path. A PATH tool-call record is reconciled onto an invocation the
    collector observed and contributes exit and stream identities. A tool-call record with no
    such event never becomes an invocation: it is counted and reported as a gap.
    """
    rows: dict[str, dict[str, Any]] = {}
    facts = {"process_exec_events": 0, "failed_exec_events": 0, "redacted_exec_events": 0,
             "tool_call_records": 0, "redacted_tool_calls": 0, "unreconciled_tool_calls": 0,
             "connect_events": 0, "envp_events": 0, "envp_redacted_names": []}
    redacted_names: set[str] = set()
    truncated = False
    for ordinal, capture in captures:
        label = f"execution-capture:command-{ordinal:03d}"
        record_sha = str(capture.identity["sha256"])
        for event in capture.events():
            if event.get("kind") == "connect":
                facts["connect_events"] += 1
            if event.get("kind") != "process_exec":
                continue
            facts["process_exec_events"] += 1
            argv = [str(value) for value in event.get("argv", ())]
            executable = str(event.get("executable", ""))
            if executable.startswith(_REDACTED) or (argv and argv[0].startswith(_REDACTED)):
                facts["redacted_exec_events"] += 1
                continue
            if event.get("result", 0) != 0:
                facts["failed_exec_events"] += 1
                continue
            if event.get("envp_captured"):
                facts["envp_events"] += 1
                redacted_names.update(str(name) for name in event.get("envp_redacted_names", ()))
            name = PurePosixPath(executable or (argv[0] if argv else "")).name
            kind = tool_kind(name, argv)
            if kind is None:
                continue
            key = _invocation_key(name, argv)
            row = rows.get(key)
            if row is None:
                if len(rows) >= _INVOCATION_LIMIT:
                    truncated = True
                    continue
                row = rows[key] = _row(name, kind, argv, workspace, directory,
                                       f"{label}:event-{event.get('ordinal')}")
                row["evidence"] = {"capture_record_sha256": record_sha, "tool_call": None,
                                   "process_exec": {"count": 0, "event_ordinals": [], "executable": executable}}
            observed = row["evidence"]["process_exec"]
            observed["count"] += 1
            if len(observed["event_ordinals"]) < _EVENT_ORDINAL_LIMIT:
                observed["event_ordinals"].append(event.get("ordinal"))
        for call in capture.tool_calls:
            document = call["record"]
            facts["tool_call_records"] += 1
            argv = [str(value) for value in document.get("argv", ())]
            if argv and argv[0].startswith(_REDACTED):
                facts["redacted_tool_calls"] += 1
                continue
            name = str(document.get("tool", ""))
            kind = tool_kind(name, argv)
            if kind is None:
                continue
            row = rows.get(_invocation_key(name, argv))
            if row is None:
                facts["unreconciled_tool_calls"] += 1
                continue
            if row["evidence"]["tool_call"] is None:
                row["evidence"]["tool_call"] = {
                    "uri": call["uri"], "sha256": call["sha256"], "exit_code": document.get("exit_code"),
                    "stdout_sha256": document.get("stdout", {}).get("sha256"),
                    "stderr_sha256": document.get("stderr", {}).get("sha256")}
    for row in rows.values():
        row["mapping"] = ("syscall-process-exec+tool-call" if row["evidence"]["tool_call"] else
                          "syscall-process-exec")
    facts["envp_redacted_names"] = sorted(redacted_names)[:256]
    gaps: list[str] = []
    if facts["redacted_exec_events"]:
        gaps.append(f"{facts['redacted_exec_events']} process-exec events were redacted by the secret "
                    "scan; their tool provenance is unavailable")
    if facts["unreconciled_tool_calls"]:
        gaps.append(f"{facts['unreconciled_tool_calls']} tool-call records had no matching successful "
                    "process-exec event and are not claimed as tool execution")
    if truncated:
        gaps.append("Rust tool invocation catalog truncated at its row bound")
    return list(rows.values()), facts, gaps


def link_rows(rows: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [row for row in rows if row.get("tool_kind") in _LINK_KINDS]


def artifact_kind(path: Path, relative: str, before: Mapping[str, str]) -> str | None:
    suffix = path.suffix.lower()
    if suffix in _RUST_ARTIFACTS:
        return _RUST_ARTIFACTS[suffix]
    normalized = relative.replace("\\", "/")
    if suffix == ".rs" and ("/target/" in "/" + normalized or "/out/" in "/" + normalized):
        return "generated-source"
    if suffix == ".d":
        return "dependency-metadata"
    if path.name in {"Cargo.toml", "Cargo.lock", ".rustc_info.json"} and before.get(relative) != file_sha256(path):
        return "cargo-metadata"
    try:
        magic = path.read_bytes()[:4]
    except OSError:
        return None
    return "executable" if magic == b"\x7fELF" else None
