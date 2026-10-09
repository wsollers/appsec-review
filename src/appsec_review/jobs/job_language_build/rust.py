from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
from typing import Any

from appsec_review.config import RustBuildSettings
from appsec_review.storage import canonical_json, file_sha256


CAPTURE_IDENTITY = "appsec-review/rust-cargo-build-capture/1"
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


def install_capture_wrappers(workspace: Path, settings: RustBuildSettings) -> tuple[dict[str, str], Path]:
    root = workspace / ".appsec-review" / "rust-capture"
    invocations = root / "invocations"
    invocations.mkdir(parents=True, exist_ok=True)
    # The orchestration process creates this run-owned directory, but compiler wrappers execute
    # as the pinned image's distinct non-root uid. Permit that uid to create opaque invocation
    # records without granting directory listing or read access to other users.
    root.chmod(0o755)
    invocations.chmod(0o733)

    def wrapper(name: str, real: str, *, rustc: bool = False) -> Path:
        path = root / f"{name}-wrapper.sh"
        shift = "" if not rustc else "# RUSTC_WRAPPER receives the real compiler as argv[1].\n"
        script = (
            "#!/bin/sh\nset -eu\n" + shift +
            f"out=/workspace/.appsec-review/rust-capture/invocations/{name}.$$\n"
            ": > \"$out\"\nfor value in \"$@\"; do printf '%s\\0' \"$value\" >> \"$out\"; done\n"
            + ("exec \"$@\"\n" if rustc else f"exec {real} \"$@\"\n"))
        # Bytes preserve the POSIX LF shebang even when tests prepare a Docker bind on Windows.
        path.write_bytes(script.encode("utf-8"))
        path.chmod(0o755)
        return path

    rustc = wrapper("rustc", "rustc", rustc=True)
    environment = {"RUSTC_WRAPPER": "/workspace/" + rustc.relative_to(workspace).as_posix()}
    if settings.capture_linker:
        linker = wrapper("linker", "cc")
        archiver = wrapper("archiver", "ar")
        environment.update({
            "RUSTFLAGS": f"-C linker=/workspace/{linker.relative_to(workspace).as_posix()}",
            "AR": "/workspace/" + archiver.relative_to(workspace).as_posix(),
        })
    return environment, invocations


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


def _mapped(workspace: Path, value: str) -> dict[str, Any] | None:
    normalized = value.replace("\\", "/")
    if normalized.startswith("/workspace/"):
        normalized = normalized[len("/workspace/"):]
    elif normalized.startswith("/"):
        return None
    candidate = (workspace / Path(*PurePosixPath(normalized).parts)).resolve()
    if workspace.resolve() != candidate and workspace.resolve() not in candidate.parents:
        return None
    result: dict[str, Any] = {"workspace_path": candidate.relative_to(workspace).as_posix()}
    if candidate.is_file() and not candidate.is_symlink():
        result.update(sha256=file_sha256(candidate), size_bytes=candidate.stat().st_size,
                      mapping="exact-workspace-path", mapping_confidence=1.0)
    else:
        result.update(mapping="declared-path-unresolved", mapping_confidence=0.5)
    return result


def _row(argv: Sequence[str], kind: str, workspace: Path, origin: str) -> dict[str, Any]:
    values = [str(value) for value in argv]
    outputs: list[str] = []
    inputs: list[str] = []
    for index, value in enumerate(values[:-1]):
        if value in {"-o", "--out-dir"}:
            outputs.append(values[index + 1])
    if kind == "archiver":
        outputs.extend(value for value in values[1:] if Path(value).suffix.lower() in {".a", ".rlib"})
    for value in values[1:]:
        if Path(value).suffix.lower() in {".rs", ".rlib", ".rmeta", ".o", ".a", ".so"} and value not in outputs:
            inputs.append(value)
    mapped_inputs = [item for item in (_mapped(workspace, value) for value in inputs) if item]
    mapped_outputs = [item for item in (_mapped(workspace, value) for value in outputs) if item]
    tool = Path(values[0]).name if values else kind
    if kind == "rustc" and len(values) > 1 and tool.endswith("wrapper.sh"):
        tool = Path(values[1]).name
    return {"tool": tool, "tool_kind": {"rustc": "compiler", "linker": "linker-driver",
            "archiver": "archiver", "build-script": "code-generator"}.get(kind, kind),
            "argv": values, "argv_sha256": hashlib.sha256(canonical_json(values)).hexdigest(),
            "inputs": mapped_inputs, "outputs": mapped_outputs, "origin": origin,
            "mapping": "framework-wrapper" if origin.startswith("wrapper:") else "cargo-verbose-trace",
            "mapping_confidence": 1.0 if origin.startswith("wrapper:") else 0.8}


def parse_invocations(stderr: bytes, workspace: Path, invocation_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(invocation_root.glob("*")) if invocation_root.is_dir() else ():
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
            continue
        kind = path.name.split(".", 1)[0]
        argv = [value.decode("utf-8", "surrogateescape") for value in path.read_bytes().split(b"\0") if value]
        if argv:
            rows.append(_row(argv, kind, workspace, f"wrapper:{path.name}"))
    for line_number, line in enumerate(stderr.decode("utf-8", "replace").splitlines(), 1):
        text = line.strip()
        match = re.search(r"Running `(.+)`$", text)
        if match is None:
            continue
        try:
            argv = shlex.split(match.group(1))
        except ValueError:
            continue
        if not argv:
            continue
        tool = Path(argv[0]).name
        if tool.startswith("build-script-") or any("/build/" in value.replace("\\", "/") and
                                                   "build-script-" in value for value in argv[:1]):
            rows.append(_row(argv, "build-script", workspace, f"cargo-stderr:{line_number}"))
    deduped: dict[str, dict[str, Any]] = {}
    for row in rows[:16384]:
        deduped.setdefault(str(row["argv_sha256"]), row)
    return list(deduped.values())


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
