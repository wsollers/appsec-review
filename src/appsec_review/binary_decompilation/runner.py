"""Pre-run decompilation of one third-party binary into the content-addressed publication store.

This runs before a review is submitted. It is not a review job: it owns no run directory, and its
publications live under ``<data_dir>/binary-decompilation/<binary-sha256>/<identity-prefix>/`` so
that any later review can reference them by hash.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import time
from types import MappingProxyType
from typing import Any
import uuid

from appsec_review.config.binary_decompilation import BinaryDecompilationSettings, BinaryRequest
from appsec_review.container_runtime import ContainerCatalog, ContainerExecutor, ExecutionRequest, load_catalog
from appsec_review.container_runtime.executor import Runner
from appsec_review.storage import atomic_json, file_sha256

from .publication import SCHEMA, PublicationError, publish_export, verify_publication


STORE_DIRECTORY = "binary-decompilation"
# The directory carries a prefix of the identity; the manifest carries all of it. Two full hashes
# in one path exceed the legacy Windows path limit below an ordinary checkout.
IDENTITY_DIRECTORY_CHARS = 16
POINTER_SCHEMA = "appsec-review/binary-decompilation-pointer/1"
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")


class DecompilationError(RuntimeError):
    """The container did not produce a complete export. ``evidence`` keeps its logs and receipt."""

    def __init__(self, message: str, *, status: str, evidence: Path | None = None):
        super().__init__(message)
        self.status = status
        self.evidence = evidence


def store_root(data_dir: Path) -> Path:
    return data_dir.resolve() / STORE_DIRECTORY


def verified_binary(request: BinaryRequest, settings: BinaryDecompilationSettings) -> tuple[Path, int]:
    """Return the resolved binary and its size once it matches the configured hash and bounds."""
    if request.path.is_symlink():
        raise ValueError(f"binary {request.binary_id} is a symbolic link")
    path = request.path.resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"binary {request.binary_id} is not a regular file")
    size = path.stat().st_size
    if not 0 < size <= settings.max_binary_bytes:
        raise ValueError(f"binary {request.binary_id} is empty or exceeds max_binary_bytes")
    if file_sha256(path) != request.sha256:
        raise ValueError(f"binary {request.binary_id} does not match its configured SHA-256")
    return path, size


def decompilation_identity(*, binary_sha256: str, image_id: str, tool_version: str,
                           settings: BinaryDecompilationSettings, request: BinaryRequest) -> str:
    """Hash of everything that can change the publication for one binary."""
    document = {
        "schema": SCHEMA,
        "binary_sha256": binary_sha256,
        "image_id": image_id,
        "tool_version": tool_version,
        "settings": settings.semantic_view(),
        "loader_overrides": {"processor": request.processor, "compiler_spec": request.compiler_spec,
                             "loader": request.loader},
    }
    if request.debug_symbols_sha256 is not None:
        # Absent for binaries without debug symbols so their existing identities are unchanged.
        document["debug_symbols_sha256"] = request.debug_symbols_sha256
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def export_argv(executable: str, input_name: str, settings: BinaryDecompilationSettings,
                request: BinaryRequest, debug_symbols_name: str | None = None) -> tuple[str, ...]:
    argv = [
        executable, "--input", f"/target/{input_name}", "--output", "/scratch/export",
        "--work", "/scratch/ghidra-work", "--max-heap", settings.max_heap,
        "--max-cpu", str(settings.cpus),
        "--analysis-timeout", str(settings.analysis_timeout_seconds),
        "--decompile-timeout", str(settings.decompile_timeout_seconds),
        "--max-functions", str(settings.max_functions),
        "--max-function-bytes", str(settings.max_function_bytes),
        "--max-pcode-ops", str(settings.max_pcode_ops),
        "--max-strings", str(settings.max_strings),
        "--min-string-length", str(settings.min_string_length),
    ]
    for option, value in (("--processor", request.processor), ("--cspec", request.compiler_spec),
                          ("--loader", request.loader)):
        if value is not None:
            argv += [option, value]
    if debug_symbols_name is not None:
        argv += ["--debug-symbols", f"/target/{debug_symbols_name}"]
    return tuple(argv)


def verified_debug_symbols(request: BinaryRequest, settings: BinaryDecompilationSettings) -> Path | None:
    """Return the resolved debug-symbol file once it matches its configured hash and bounds."""
    if request.debug_symbols_path is None:
        return None
    if request.debug_symbols_path.is_symlink():
        raise ValueError(f"binary {request.binary_id} debug symbols are a symbolic link")
    path = request.debug_symbols_path.resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"binary {request.binary_id} debug symbols are not a regular file")
    if not 0 < path.stat().st_size <= settings.max_binary_bytes:
        raise ValueError(f"binary {request.binary_id} debug symbols are empty or exceed max_binary_bytes")
    if file_sha256(path) != request.debug_symbols_sha256:
        raise ValueError(f"binary {request.binary_id} debug symbols do not match debug_symbols_sha256")
    return path


def _staged_name(path: Path, fallback: str) -> str:
    return _UNSAFE_NAME.sub("_", path.name)[:128].lstrip(".-") or fallback


def request_record(request: BinaryRequest) -> dict[str, Any]:
    """The request fields a publication manifest records (and a review later checks)."""
    record: dict[str, Any] = {"id": request.binary_id, "authorization": request.authorization,
                              "processor": request.processor, "compiler_spec": request.compiler_spec,
                              "loader": request.loader}
    if request.debug_symbols_sha256 is not None:
        record["debug_symbols_sha256"] = request.debug_symbols_sha256
    return record


def _elevated_catalog(repository_root: Path, settings: BinaryDecompilationSettings) -> ContainerCatalog:
    """The catalog with this one tool's capacity raised; isolation settings are untouched."""
    catalog = load_catalog(repository_root)
    tool = replace(catalog.tool(settings.tool_id), memory=settings.memory, cpus=str(settings.cpus),
                   pids_limit=settings.pids_limit, timeout_seconds=settings.timeout_seconds)
    return ContainerCatalog(catalog.source, catalog.runtime_policy, catalog.policy,
                            MappingProxyType({tool.tool_id: tool}))


def _replace_directory(source: Path, destination: Path) -> None:
    """Rename a directory, tolerating the brief handles Windows scanners hold on new files."""
    for attempt in range(10):
        try:
            os.replace(source, destination)
            return
        except PermissionError:
            if attempt == 9:
                raise
            time.sleep(0.2 * (attempt + 1))


def publication_path(store: Path, binary_sha256: str, identity: str) -> Path:
    return store / binary_sha256 / identity[:IDENTITY_DIRECTORY_CHARS]


def _verified(path: Path, binary_sha256: str, identity: str) -> dict[str, Any]:
    """Verify a stored publication and that it is the one this binary and identity name."""
    manifest = verify_publication(path)
    if manifest["identity"] != identity or manifest["binary"]["sha256"] != binary_sha256:
        raise PublicationError(f"publication at {path} belongs to another binary or identity")
    return manifest


def _point_current(path: Path, manifest: Mapping[str, Any]) -> None:
    """Record which publication a later review resolves for this binary."""
    atomic_json(path.parent / "current.json", {
        "schema": POINTER_SCHEMA, "binary_sha256": manifest["binary"]["sha256"],
        "identity": manifest["identity"], "publication": path.name,
        "manifest_sha256": file_sha256(path / "manifest.json")})


def resolve_current(data_dir: Path, binary_sha256: str) -> dict[str, Any]:
    """Resolve and verify the current publication for one binary hash, without Docker.

    This is the lookup a review performs at submission: the mutable pointer names a publication,
    and the returned identity and manifest hash are what the run freezes.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", binary_sha256):
        raise PublicationError("binary reference is not a SHA-256")
    directory = store_root(data_dir) / binary_sha256
    pointer_path = directory / "current.json"
    if not pointer_path.is_file():
        raise PublicationError(f"binary {binary_sha256} has no current decompilation publication")
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicationError("decompilation pointer is not JSON") from exc
    identity = pointer.get("identity") if isinstance(pointer, dict) else None
    if (not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{64}", identity) or
            pointer.get("schema") != POINTER_SCHEMA or pointer.get("binary_sha256") != binary_sha256 or
            pointer.get("publication") != identity[:IDENTITY_DIRECTORY_CHARS]):
        raise PublicationError("decompilation pointer is malformed")
    path = directory / identity[:IDENTITY_DIRECTORY_CHARS]
    summary = _summary(_verified(path, binary_sha256, identity), path, reused=True)
    if summary["manifest_sha256"] != pointer.get("manifest_sha256"):
        raise PublicationError("publication manifest differs from the one the pointer recorded")
    return summary


def _summary(manifest: Mapping[str, Any], path: Path, *, reused: bool) -> dict[str, Any]:
    return {"binary_id": manifest["request"]["id"], "binary_sha256": manifest["binary"]["sha256"],
            "identity": manifest["identity"], "path": str(path), "reused": reused,
            "manifest_sha256": file_sha256(path / "manifest.json"),
            "coverage": manifest["coverage"], "gaps": manifest["gaps"]}


def expected_publication(*, repository_root: Path, data_dir: Path, settings: BinaryDecompilationSettings,
                         request: BinaryRequest, runner: Runner | None = None) -> tuple[Path, str]:
    """Where the publication for this binary, image, and configuration lives, and its identity."""
    catalog = _elevated_catalog(repository_root, settings)
    tool = catalog.tool(settings.tool_id)
    image_id = ContainerExecutor(catalog, store_root(data_dir), runner=runner).resolve_image(tool)
    identity = decompilation_identity(binary_sha256=request.sha256, image_id=image_id,
                                      tool_version=tool.version, settings=settings, request=request)
    return publication_path(store_root(data_dir), request.sha256, identity), identity


def verify_binary(*, repository_root: Path, data_dir: Path, settings: BinaryDecompilationSettings,
                  request: BinaryRequest, runner: Runner | None = None) -> dict[str, Any]:
    """Verify the existing publication for one configured binary without running Ghidra."""
    final, identity = expected_publication(repository_root=repository_root, data_dir=data_dir,
                                           settings=settings, request=request, runner=runner)
    if not (final / "manifest.json").is_file():
        raise PublicationError(f"binary {request.binary_id} has no publication for the current "
                               "image and configuration")
    return _summary(_verified(final, request.sha256, identity), final, reused=True)


def decompile_binary(*, repository_root: Path, data_dir: Path, settings: BinaryDecompilationSettings,
                     request: BinaryRequest, runner: Runner | None = None,
                     force: bool = False) -> dict[str, Any]:
    """Decompile one configured binary, or reuse its verified publication."""
    binary_path, binary_bytes = verified_binary(request, settings)
    symbols_path = verified_debug_symbols(request, settings)
    store = store_root(data_dir)
    catalog = _elevated_catalog(repository_root, settings)
    tool = catalog.tool(settings.tool_id)
    staging = store / ".staging" / uuid.uuid4().hex[:16]
    executor = ContainerExecutor(catalog, staging, runner=runner)
    image_id = executor.resolve_image(tool)
    identity = decompilation_identity(binary_sha256=request.sha256, image_id=image_id,
                                      tool_version=tool.version, settings=settings, request=request)
    final = publication_path(store, request.sha256, identity)
    if final.exists() and not force:
        # A publication that fails verification is never silently replaced.
        manifest = _verified(final, request.sha256, identity)
        _point_current(final, manifest)
        return _summary(manifest, final, reused=True)

    input_name = _staged_name(binary_path, "binary")
    symbols_name = None
    if symbols_path is not None:
        symbols_name = _staged_name(symbols_path, "symbols.pdb")
        if symbols_name == input_name:
            symbols_name = f"symbols-{symbols_name}"[:128]
    input_root = staging / "input"
    scratch = staging / "scratch"
    input_root.mkdir(parents=True)
    try:
        shutil.copyfile(binary_path, input_root / input_name)
        if file_sha256(input_root / input_name) != request.sha256:
            raise ValueError(f"binary {request.binary_id} changed while it was staged")
        if symbols_path is not None and symbols_name is not None:
            shutil.copyfile(symbols_path, input_root / symbols_name)
            if file_sha256(input_root / symbols_name) != request.debug_symbols_sha256:
                raise ValueError(f"binary {request.binary_id} debug symbols changed while they were staged")
        result = executor.execute(ExecutionRequest(
            tool.tool_id, export_argv(tool.executable, input_name, settings, request, symbols_name),
            input_root, scratch, working_directory="/scratch",
            file_size_limit_bytes=settings.output_file_bytes))
        shutil.rmtree(scratch / "ghidra-work", ignore_errors=True)
        shutil.rmtree(input_root, ignore_errors=True)
        export_root = scratch / "export"
        if result.terminal_status != "COMPLETED" or result.exit_code != 0:
            status = result.terminal_status if result.terminal_status != "COMPLETED" else "FAILED"
            raise DecompilationError(
                f"Ghidra export for {request.binary_id} ended {status} (exit {result.exit_code})",
                status=status)
        receipt = scratch / "execution.json"
        publication = staging / "publication"
        try:
            manifest = publish_export(
                export_root, publication, identity=identity,
                binary={"sha256": request.sha256, "bytes": binary_bytes, "name": input_name},
                request=request_record(request),
                tool={"id": tool.tool_id, "version": tool.version, "image_tag": tool.tag,
                      "image_id": image_id},
                settings=settings.semantic_view(),
                execution={"receipt": "execution/execution.json", "receipt_sha256": file_sha256(receipt),
                           "terminal_status": result.terminal_status, "exit_code": result.exit_code,
                           "limits": dict(result.limits)})
        except PublicationError as exc:
            raise DecompilationError(f"Ghidra export for {request.binary_id} is unusable: {exc}",
                                     status="INVALID_EXPORT") from exc
        execution_root = publication / "execution"
        execution_root.mkdir()
        shutil.copyfile(receipt, execution_root / "execution.json")
        for name in ("stdout.bin", "stderr.bin"):
            shutil.copyfile(scratch / "raw" / name, execution_root / name)
        final.parent.mkdir(parents=True, exist_ok=True)
        if final.exists():
            shutil.rmtree(final)
        _replace_directory(publication, final)
    except DecompilationError as exc:
        # Keep the receipt and logs of a failed attempt; they are the evidence for the gap.
        failed = store / ".failed" / f"{identity[:16]}-{staging.name}"
        failed.parent.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(input_root, ignore_errors=True)
        shutil.rmtree(scratch / "ghidra-work", ignore_errors=True)
        _replace_directory(staging, failed)
        exc.evidence = failed
        raise
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    shutil.rmtree(staging, ignore_errors=True)
    _point_current(final, manifest)
    return _summary(manifest, final, reused=False)
