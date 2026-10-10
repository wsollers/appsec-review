from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
from typing import Any

from appsec_review.storage import canonical_json, file_sha256


CAPTURE_IDENTITY = "appsec-review/node-build-capture/2"
LOCKFILES = {"package-lock.json": "npm", "pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn"}
TOOL_KINDS = {
    "tsc": "typescript-compiler", "babel": "transpiler", "babeljs": "transpiler",
    "swc": "transpiler", "esbuild": "bundler", "webpack": "bundler",
    "rollup": "bundler", "vite": "bundler", "parcel": "bundler",
    "node-gyp": "native-addon-builder", "prebuild": "package-builder",
    "prebuildify": "package-builder", "npm": "package-manager",
    "pnpm": "package-manager", "yarn": "package-manager", "node": "runtime-driver",
    "protoc": "code-generator", "graphql-codegen": "code-generator",
    "openapi-generator": "code-generator", "prisma": "code-generator",
    "cc": "compiler-driver", "gcc": "compiler-driver", "clang": "compiler-driver",
    "c++": "compiler-driver", "g++": "compiler-driver", "clang++": "compiler-driver",
    "as": "assembler", "ld": "linker", "ld.lld": "linker", "ar": "archiver",
    "llvm-ar": "archiver", "ranlib": "post-link", "strip": "post-link",
    "objcopy": "post-link",
}
_SOURCE_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
_GENERATED_SUFFIXES = _SOURCE_SUFFIXES | {".d.ts", ".d.mts", ".d.cts"}
_CONFIG_NAMES = {
    "package.json", "tsconfig.json", "babel.config.js", "babel.config.cjs", "babel.config.mjs",
    ".babelrc", ".swcrc", "webpack.config.js", "webpack.config.cjs", "webpack.config.mjs",
    "rollup.config.js", "rollup.config.mjs", "vite.config.js", "vite.config.ts",
}
_CONTROL = {"&&", "||", ";", "|", "&"}
_TEST_TOOLS = {"jest", "mocha", "vitest", "ava", "tap", "cypress", "playwright", "karma"}
_SECRET = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)", re.I)


def dependency_identity(dispatch: Mapping[str, Any]) -> tuple[str | None, dict[str, Any], list[str]]:
    hashes = dispatch.get("image", {}).get("dependency_hashes", {})
    if not isinstance(hashes, Mapping):
        raise ValueError("accepted Node dependency identities are unavailable")
    by_name = {PurePosixPath(str(path)).name: (str(path), str(digest))
               for path, digest in hashes.items()}
    locks = [(name, *by_name[name]) for name in sorted(LOCKFILES) if name in by_name]
    package = by_name.get("package.json")
    if package is None:
        return None, {}, ["Node build package.json identity is unavailable"]
    if len(locks) > 1:
        return None, {}, ["Node build declares multiple package-manager lockfiles"]
    commands = [*dispatch.get("recipe", {}).get("configure_commands", ()),
                *dispatch.get("recipe", {}).get("build_commands", ())]
    invoked = {Path(str(argv[0])).name for argv in commands if isinstance(argv, list) and argv}
    managers = invoked & set(LOCKFILES.values())
    if len(managers) > 1:
        return None, {}, ["accepted Node commands use multiple package managers"]
    lock_name, lock_path, lock_sha = locks[0] if locks else (None, None, None)
    manager = LOCKFILES[str(lock_name)] if lock_name else next(iter(managers), "npm")
    identity = {
        "manager": manager,
        "package_manifest": {"path": package[0], "sha256": package[1]},
        "lockfile": ({"path": lock_path, "sha256": lock_sha} if lock_name else None),
        "sha256": hashlib.sha256(canonical_json({
            "manager": manager, "package": package,
            "lock": ((lock_path, lock_sha) if lock_name else None),
        })).hexdigest(),
    }
    if managers and managers != {manager}:
        return None, identity, [f"accepted Node commands use {', '.join(sorted(managers))}, "
                                f"but the dependency inputs bind the build to {manager}"]
    return manager, identity, []


def environment_facts(environment: Mapping[str, str]) -> dict[str, str]:
    return {key: "set" for key in sorted(environment) if not _SECRET.search(key)}


def artifact_kind(path: Path) -> str | None:
    name, suffix = path.name.lower(), path.suffix.lower()
    if name.endswith((".d.ts", ".d.mts", ".d.cts")):
        return "generated-declaration"
    if suffix == ".map":
        return "source-map"
    if suffix == ".node":
        return "native-addon"
    if suffix in {".tgz", ".zip"}:
        return "package"
    if suffix in _GENERATED_SUFFIXES:
        return "generated-code"
    if suffix in {".wasm", ".css", ".html"}:
        return "bundle-asset"
    if suffix in {".o", ".obj", ".a", ".lib", ".so", ".dll", ".dylib"}:
        return "native-intermediate" if suffix in {".o", ".obj"} else "native-library"
    if name in {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
        return "package-metadata"
    return None


def catalog(run_root: Path, workspace: Path, before: Mapping[str, str], limit: int,
            build_unit_id: str) -> tuple[list[dict[str, Any]], list[str]]:
    artifacts: list[dict[str, Any]] = []
    gaps: list[str] = []
    for path in sorted(workspace.rglob("*")):
        try:
            if path.is_symlink() or not path.is_file():
                continue
        except OSError:
            continue
        relative = path.relative_to(workspace).as_posix()
        digest = file_sha256(path)
        if before.get(relative) == digest:
            continue
        kind = artifact_kind(path)
        if kind is None:
            continue
        value: dict[str, Any] = {
            "path": path.relative_to(run_root).as_posix(), "workspace_path": relative,
            "sha256": digest, "size_bytes": path.stat().st_size, "kind": kind,
            "build_unit_id": build_unit_id, "mapping": "exact-workspace-path",
            "mapping_confidence": 1.0,
        }
        if kind == "source-map":
            try:
                if path.stat().st_size > 16 * 1024 * 1024:
                    raise ValueError("source map exceeds 16 MiB bound")
                document = json.loads(path.read_text(encoding="utf-8"))
                sources = document.get("sources", ()) if isinstance(document, Mapping) else ()
                if not isinstance(sources, list) or len(sources) > 4096:
                    raise ValueError("source list is invalid or exceeds its row bound")
                source_root = str(document.get("sourceRoot", ""))
                source_identities = []
                for item in sources:
                    if not isinstance(item, str):
                        continue
                    logical = PurePosixPath(source_root) / PurePosixPath(item)
                    candidate = (path.parent / Path(*logical.parts)).resolve()
                    row: dict[str, Any] = {"declared_path": item}
                    if (workspace.resolve() in candidate.parents and
                            candidate.is_file() and not candidate.is_symlink()):
                        row.update(workspace_path=candidate.relative_to(workspace).as_posix(),
                                   sha256=file_sha256(candidate), size_bytes=candidate.stat().st_size,
                                   mapping="source-map", mapping_confidence=1.0)
                    else:
                        row.update(mapping="declared-path-unresolved", mapping_confidence=0.5)
                    source_identities.append(row)
                value["source_map"] = {
                    "sources": [str(item) for item in sources if isinstance(item, str)],
                    "source_identities": source_identities,
                    "source_root": source_root,
                    "file": str(document.get("file", "")),
                }
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                gaps.append(f"{relative}: source-map provenance unavailable: {type(exc).__name__}")
        artifacts.append(value)
        if len(artifacts) >= limit:
            gaps.append("Node artifact catalog truncated at configured count bound")
            break
    return artifacts, gaps


def _package_document(workspace: Path, source_dir: str) -> tuple[Path, Mapping[str, Any]] | None:
    path = workspace / Path(*PurePosixPath(source_dir).parts) / "package.json"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    return (path, value) if isinstance(value, Mapping) else None


def _script_name(argv: Sequence[str], manager: str) -> str | None:
    values = list(argv[1:])
    if manager == "npm":
        marker = "run" if "run" in values else "run-script" if "run-script" in values else None
        if marker is None:
            return None
        index = values.index(marker) + 1
        return values[index] if index < len(values) and not values[index].startswith("-") else None
    if "run" in values:
        index = values.index("run") + 1
        return values[index] if index < len(values) and not values[index].startswith("-") else None
    skip = False
    for index, value in enumerate(values):
        if skip:
            skip = False
            continue
        if value in {"--cwd", "--dir", "--prefix"}:
            skip = True
            continue
        if not value.startswith("-"):
            return value
    return None


def validate_lifecycle_scripts(workspace: Path, source_dir: str,
                               commands: Sequence[Sequence[str]]) -> list[str]:
    package = _package_document(workspace, source_dir)
    if package is None:
        return ["package.json is unavailable for lifecycle-script validation"]
    scripts = package[1].get("scripts", {})
    if not isinstance(scripts, Mapping):
        return ["package.json scripts must be an object"]
    gaps: list[str] = []
    for argv in commands:
        if not argv:
            continue
        manager = Path(str(argv[0])).name
        if manager not in {"npm", "pnpm", "yarn"}:
            continue
        requested = _script_name(argv, manager)
        if requested is None:
            continue
        for name in (f"pre{requested}", requested, f"post{requested}"):
            script = scripts.get(name)
            if not isinstance(script, str):
                continue
            try:
                tokens = shlex.split(script)
            except ValueError:
                gaps.append(f"package lifecycle script {name} is not safely parseable")
                continue
            lowered = {Path(value).name.lower() for value in tokens if value not in _CONTROL}
            if lowered & _TEST_TOOLS:
                gaps.append(f"package lifecycle script {name} requests a test runner")
            for index, value in enumerate(tokens):
                if Path(value).name in {"node", "tsx", "ts-node"} and "--check" not in tokens[index + 1:]:
                    gaps.append(f"package lifecycle script {name} may execute a target application")
                    break
    return list(dict.fromkeys(gaps))


def invocation_rows(workspace: Path, source_dir: str, argv: Sequence[str], *, success: bool,
                    before: Mapping[str, str], after: Mapping[str, str],
                    diagnostic_streams: Sequence[bytes] = ()) -> tuple[list[dict[str, Any]], list[str]]:
    tool = Path(str(argv[0])).name
    rows: list[dict[str, Any]] = [{
        "tool": tool, "tool_kind": TOOL_KINDS.get(tool, "build-driver"), "argv": list(argv),
        "directory": source_dir, "inputs": [], "outputs": [], "origin": "accepted-recipe",
        "mapping": "direct-invocation", "mapping_confidence": 1.0,
    }]
    gaps: list[str] = []
    changed = sorted(path for path, digest in after.items() if before.get(path) != digest)
    rows[0]["outputs"] = [{"workspace_path": path, "sha256": after[path],
                           "mapping": "command-delta", "mapping_confidence": 0.75}
                          for path in changed[:4096]]
    root = workspace / Path(*PurePosixPath(source_dir).parts)
    rows[0]["inputs"] = [{"workspace_path": path.relative_to(workspace).as_posix(),
                           "sha256": file_sha256(path), "size_bytes": path.stat().st_size,
                           "mapping": "configuration-input", "mapping_confidence": 0.75}
                          for path in sorted(root.rglob("*")) if path.is_file() and not path.is_symlink()
                          and (path.name in _CONFIG_NAMES or path.suffix.lower() in _SOURCE_SUFFIXES)][:4096]
    for stream in diagnostic_streams:
        for line in stream.decode("utf-8", "replace").splitlines()[:20000]:
            try:
                trace = shlex.split(line.strip())
            except ValueError:
                continue
            if not trace:
                continue
            trace_tool = Path(trace[0]).name
            if trace_tool not in TOOL_KINDS or trace_tool in {"npm", "pnpm", "yarn", "node"}:
                continue
            outputs = [trace[index + 1] for index, value in enumerate(trace[:-1]) if value == "-o"]
            inputs = [value for value in trace[1:] if value not in outputs and
                      Path(value).suffix.lower() in (_SOURCE_SUFFIXES | {".o", ".obj", ".a", ".lib"})]
            rows.append({"tool": trace_tool, "tool_kind": TOOL_KINDS[trace_tool], "argv": trace,
                         "directory": source_dir,
                         "inputs": [{"workspace_path": value, "mapping": "diagnostic-path",
                                     "mapping_confidence": 0.75} for value in inputs],
                         "outputs": [{"workspace_path": value, "mapping": "diagnostic-path",
                                      "mapping_confidence": 0.75} for value in outputs],
                         "origin": "retained-build-diagnostics", "mapping": "diagnostic-trace",
                         "mapping_confidence": 0.9})
    if not success or tool not in {"npm", "pnpm", "yarn"}:
        return rows, gaps
    package = _package_document(workspace, source_dir)
    script_name = _script_name(argv, tool)
    scripts = package[1].get("scripts", {}) if package else {}
    script = scripts.get(script_name) if isinstance(scripts, Mapping) and script_name else None
    if not isinstance(script, str):
        gaps.append("successful package-manager command did not resolve to a bounded package script")
        return rows, gaps
    try:
        tokens = shlex.split(script)
    except ValueError:
        gaps.append(f"package script {script_name} could not be parsed for nested tool provenance")
        return rows, gaps
    if not tokens or any(value in _CONTROL for value in tokens):
        gaps.append(f"package script {script_name} uses shell composition; nested invocation provenance is ambiguous")
        return rows, gaps
    nested_tool = Path(tokens[0]).name
    rows.append({
        "tool": nested_tool, "tool_kind": TOOL_KINDS.get(nested_tool, "package-script-tool"),
        "argv": tokens, "directory": source_dir, "inputs": rows[0]["inputs"],
        "outputs": rows[0]["outputs"], "origin": f"package.json#scripts.{script_name}",
        "mapping": "successful-package-script", "mapping_confidence": 0.9,
    })
    return rows, gaps
