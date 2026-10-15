from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from appsec_review.config import RustBuildSettings
from appsec_review.jobs.artifact_kinds import binary_role
from appsec_review.storage import canonical_json, file_sha256

from .capture import CapturedBuildDescriptor, ToolIdentity, image_owned, normalized_path


CAPTURE_IDENTITY = "appsec-review/rust-cargo-build-capture/4"
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
_BUILD_SCRIPT_NAMES = ("build-script-", "build_script_")
# Cargo runs a package's build script from `<target-dir>/.../build/<package>-<hash>/`.
_BUILD_SCRIPT_PATH = re.compile(r"/workspace/(?:[^/]+/)+build/[^/]+/build[-_]script[-_][^/]+")


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
        if subcommand in _FORBIDDEN or subcommand not in {"build", "rustc", "check", "metadata", "fetch"}:
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
    """The kind a tool name stands for; a name alone never establishes that the tool ran."""
    if name == "rustc":
        return "compiler"
    if name.startswith(_BUILD_SCRIPT_NAMES):
        return "code-generator"
    if name in _ARCHIVERS or name.endswith("-ar"):
        return "archiver"
    if name in _LINKERS:
        return "linker"
    if _C_DRIVER.fullmatch(name):
        return "compiler-driver" if _COMPILE_ONLY & set(argv[1:]) else "linker-driver"
    return None


_RUSTC_EMIT_SUFFIXES = {"dep-info": ".d", "metadata": ".rmeta", "obj": ".o", "llvm-ir": ".ll",
                        "llvm-bc": ".bc", "asm": ".s", "mir": ".mir"}


def _rustc_options(values: Sequence[str]) -> dict[str, list[str]]:
    """The rustc options that decide output names, in both spaced and attached spellings."""
    options: dict[str, list[str]] = {"--crate-name": [], "--crate-type": [], "--emit": [],
                                     "--out-dir": [], "-o": [], "--target": [], "-C": []}
    index = 1
    while index < len(values):
        value = values[index]
        if value in {"-C", "--codegen"} and index + 1 < len(values):
            options["-C"].append(values[index + 1])
            index += 2
            continue
        if value.startswith("-C") and len(value) > 2:
            options["-C"].append(value[2:])
        elif value.startswith("--codegen="):
            options["-C"].append(value.split("=", 1)[1])
        elif value in options and index + 1 < len(values):
            options[value].append(values[index + 1])
            index += 2
            continue
        elif value.startswith("--") and "=" in value and value.split("=", 1)[0] in options:
            key, selected = value.split("=", 1)
            options[key].append(selected)
        index += 1
    return options


def rustc_outputs(argv: Sequence[str]) -> list[str]:
    """Files a rustc compilation writes, derived from its argv the way rustc names them.

    ``--crate-name``, ``--crate-type``, ``--emit`` and ``-C extra-filename`` decide the file
    names and ``--out-dir`` (or ``-o``) the location, so a captured compile names its rlib,
    rmeta, shared or static library, executable and dependency-info outputs. Nothing is read
    from the workspace here; an invocation without a crate name names no outputs.
    """
    values = [str(value) for value in argv]
    options = _rustc_options(values)
    if not options["--crate-name"]:
        return []
    name = options["--crate-name"][-1].replace("-", "_")
    extra = ""
    for codegen in options["-C"]:
        if codegen.startswith("extra-filename="):
            extra = codegen.split("=", 1)[1]
    crate_types = [item.strip() for value in options["--crate-type"] for item in value.split(",")
                   if item.strip()] or (["bin"] if "--test" not in values else ["bin"])
    emits: dict[str, str | None] = {}
    for value in options["--emit"] or ["link"]:
        for item in value.split(","):
            kind, _, explicit = item.strip().partition("=")
            if kind:
                emits[kind] = explicit or None
    target = (options["--target"][-1] if options["--target"] else "").lower()
    windows, apple, wasm = "windows" in target, "apple" in target or "darwin" in target, \
        target.startswith("wasm")
    explicit_output = options["-o"][-1] if options["-o"] else None
    out_dir = options["--out-dir"][-1] if options["--out-dir"] else None
    if explicit_output is None and out_dir is None:
        return []

    def placed(file_name: str) -> str:
        return f"{out_dir.rstrip('/')}/{file_name}" if out_dir is not None else file_name

    outputs: list[str] = []
    if "link" in emits:
        if emits["link"]:
            outputs.append(str(emits["link"]))
        elif explicit_output is not None:
            outputs.append(explicit_output)
        else:
            stem = f"{name}{extra}"
            for crate_type in crate_types:
                if crate_type in {"lib", "rlib"}:
                    outputs.append(placed(f"lib{stem}.rlib"))
                elif crate_type == "staticlib":
                    outputs.append(placed(f"{stem}.lib" if windows and "msvc" in target else f"lib{stem}.a"))
                elif crate_type in {"dylib", "cdylib", "proc-macro"}:
                    if windows:
                        outputs.append(placed(f"{stem}.dll"))
                    elif wasm and crate_type == "cdylib":
                        outputs.append(placed(f"{stem}.wasm"))
                    else:
                        outputs.append(placed(f"lib{stem}.{'dylib' if apple else 'so'}"))
                elif crate_type == "bin":
                    outputs.append(placed(f"{stem}.exe" if windows else f"{stem}.wasm" if wasm else stem))
    for kind, suffix in _RUSTC_EMIT_SUFFIXES.items():
        if kind not in emits:
            continue
        if emits[kind]:
            outputs.append(str(emits[kind]))
        elif kind == "metadata":
            outputs.append(placed(f"lib{name}{extra}{suffix}"))
        elif explicit_output is not None and out_dir is None:
            outputs.append(str(PurePosixPath(explicit_output).with_suffix(suffix)))
        else:
            outputs.append(placed(f"{name}{extra}{suffix}"))
    return list(dict.fromkeys(outputs))


def _cargo_uplifts(workspace: Path, directory: str, argv: Sequence[str],
                   outputs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Cargo's hard-linked copies of a rustc output, outside ``deps/`` and without the hash.

    Cargo links ``<profile>/deps/<file><extra>`` to ``<profile>/<file>``. The copy is the same
    bytes rustc wrote, so it is named as this invocation's output only when it exists with the
    identical digest; anything else stays unattributed.
    """
    options = _rustc_options([str(value) for value in argv])
    extra = next((value.split("=", 1)[1] for value in reversed(options["-C"])
                  if value.startswith("extra-filename=")), "")
    if not extra:
        return []
    uplifts = []
    for output in outputs:
        relative, digest = PurePosixPath(str(output.get("workspace_path", ""))), output.get("sha256")
        if not digest or relative.parent.name != "deps" or extra not in relative.name:
            continue
        candidate = _mapped(workspace, directory,
                            "/workspace/" + (relative.parent.parent / relative.name.replace(extra, "", 1)).as_posix())
        if candidate is not None and candidate.get("sha256") == digest:
            uplifts.append({**candidate, "mapping": "cargo-uplift-identical-digest"})
    return uplifts


def _row(name: str, kind: str, argv: Sequence[str], workspace: Path, directory: str,
         origin: str) -> dict[str, Any]:
    values = [str(value) for value in argv]
    outputs: list[str] = []
    inputs: list[str] = []
    if name == "rustc":
        outputs.extend(rustc_outputs(values))
    for index, value in enumerate(values[:-1]):
        if value in {"-o", "--out-dir"} and not (name == "rustc" and outputs):
            outputs.append(values[index + 1])
    if kind == "archiver":
        outputs.extend(value for value in values[1:] if Path(value).suffix.lower() in {".a", ".rlib"})
        outputs = outputs[:1]
    for value in values[1:]:
        if Path(value).suffix.lower() in {".rs", ".rlib", ".rmeta", ".o", ".a", ".so"} and value not in outputs:
            inputs.append(value)
    mapped_outputs = [item for item in (_mapped(workspace, directory, value) for value in outputs) if item]
    if name == "rustc":
        mapped_outputs.extend(_cargo_uplifts(workspace, directory, values, mapped_outputs))
    return {"tool": name, "tool_kind": kind, "argv": values,
            "argv_sha256": hashlib.sha256(canonical_json(values)).hexdigest(),
            "inputs": [item for item in (_mapped(workspace, directory, value) for value in inputs) if item],
            "outputs": mapped_outputs,
            "origin": origin, "mapping_confidence": 1.0}


def tool_identity(executable: str, argv: Sequence[str]) -> tuple[str, str] | None:
    """Classify the kernel-resolved executable of one successful process-exec event.

    `argv[0]` is caller-chosen and is never consulted. The compiler, C driver, linker, and
    archiver count only at an image-owned path: a file below a mount the build can write,
    including a capture wrapper launcher, is not evidence that a toolchain tool ran. A Cargo
    build script is the one exception, because Cargo compiles it into the workspace target
    directory. Its row records that target-built code ran as a build step and nothing else.
    """
    name = PurePosixPath(executable).name
    if name.startswith(_BUILD_SCRIPT_NAMES):
        scripted = normalized_path(executable) and _BUILD_SCRIPT_PATH.fullmatch(executable)
        return (name, "code-generator") if scripted else None
    if not image_owned(executable):
        return None
    kind = tool_kind(name, argv)
    return (name, kind) if kind is not None else None


def _classify_tool(executable: str, argv: Sequence[str]) -> ToolIdentity | None:
    identity = tool_identity(executable, argv)
    return ToolIdentity(*identity) if identity is not None else None


def _classify_record(tool: str, argv: Sequence[str]) -> ToolIdentity | None:
    """The kind a PATH tool-call record names; it selects records to reconcile, nothing more."""
    kind = tool_kind(tool, argv)
    return ToolIdentity(tool, kind) if kind is not None else None


def _compiles(row: Mapping[str, Any]) -> bool:
    # Cargo also starts rustc to report its version and target configuration; only an
    # invocation that names a crate and an output location is a compilation.
    argv = row.get("argv", ())
    return row.get("tool") == "rustc" and "--crate-name" in argv and bool({"--out-dir", "-o"} & set(argv))


CAPTURE_DESCRIPTOR = CapturedBuildDescriptor(
    family="rust",
    capture_identity=CAPTURE_IDENTITY,
    provenance_schema="appsec-review/rust-capture-provenance/1",
    catalog_label="Rust",
    classify_tool=_classify_tool,
    build_invocation=_row,
    link_kinds=frozenset(_LINK_KINDS),
    missing_tool_gap="Rust compiler execution was not observed in the standardized capture",
    classify_record=_classify_record,
    required_execution=_compiles,
)


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
    role, _format = binary_role(path)
    return role if role in {"executable", "shared-library", "object", "static-library"} else None
