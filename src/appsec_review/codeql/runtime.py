from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import time
from typing import Any, Protocol
from uuid import uuid4

from appsec_review.container_runtime.build_executor import Runner, _run, resolve_host_bind_path
from appsec_review.container_runtime.identity import application_runtime_user
from appsec_review.storage import atomic_json, bounded_file_lock, canonical_json, file_sha256


IMAGE_SCHEMA = "appsec-review/codeql-derived-image/2"
EXECUTION_SCHEMA = "appsec-review/codeql-execution/2"
EXPORT_MANIFEST_SCHEMA = "appsec-review/codeql-graph-export-manifest/1"
EXPORT_MANIFEST_NAME = "export-manifest.json"
COMPILE_CACHE_MOUNT = "/codeql-cache"
ACTIONS = frozenset({"inventory", "database", "query", "export", "compile"})


class RuntimeSettings(Protocol):
    source_image_tag: str
    source_image_id: str
    database_timeout_seconds: int
    query_timeout_seconds: int
    inventory_timeout_seconds: int
    output_bytes: int
    threads: int
    ram_mb: int


def action_timeout(settings: RuntimeSettings, action: str) -> int:
    """Per-action timeout; ``export`` uses the typed ``export_timeout_seconds`` setting when the
    configuration provides it and the contract default (GraphSettings) otherwise."""
    if action == "export":
        value = getattr(settings, "export_timeout_seconds", None)
        if value is None:
            from appsec_review.graph.contract import GraphSettings
            value = GraphSettings().export_timeout_seconds
        return int(value)
    if action == "compile":
        return int(getattr(settings, "compile_timeout_seconds", None) or action_timeout(settings, "export"))
    return {"inventory": settings.inventory_timeout_seconds,
            "database": settings.database_timeout_seconds,
            "query": settings.query_timeout_seconds}[action]


def compile_cache_volume(image: "CodeQLImage") -> str:
    """Docker volume holding the content-addressed query compile cache for one CodeQL payload."""
    return "appsec-codeql-compile-" + hashlib.sha256(image.source_image_id.encode()).hexdigest()[:16]


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class CodeQLImage:
    schema: str
    identity: str
    source_image_id: str
    build_image_id: str
    build_image_tag: str
    image_id: str
    image_tag: str
    runtime_user: str
    dockerfile_sha256: str
    runner_sha256: str
    reused: bool
    manifest_path: str


@dataclass(frozen=True, slots=True)
class CodeQLExecution:
    schema: str
    action: str
    image_id: str
    image_tag: str
    argv_identity: str
    exit_code: int | None
    timed_out: bool
    started_at: str
    completed_at: str
    duration_ms: int
    stdout_path: str
    stderr_path: str
    stdout_sha256: str
    stderr_sha256: str
    stdout_total_bytes: int
    stderr_total_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_tail_bytes: int
    stderr_tail_bytes: int
    limits: Mapping[str, Any]


def load_asset_lock(repository_root: Path) -> Mapping[str, Any]:
    path = repository_root / "containers" / "tools" / "codeql" / "assets.lock.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != "appsec-review/codeql-assets-lock/2":
        raise ValueError("CodeQL asset lock schema is unsupported")
    return {**document, "path": path.as_posix(), "sha256": file_sha256(path)}


class CodeQLImageResolver:
    """Layer the pinned CodeQL payload onto an accepted build/source environment, offline."""

    def __init__(self, *, repository_root: Path, metadata_root: Path, settings: RuntimeSettings,
                 timeout_seconds: int = 1800, output_bytes: int = 8 * 1024 * 1024,
                 runner: Runner | None = None) -> None:
        self.repository_root = repository_root
        self.metadata_root = metadata_root
        self.settings = settings
        self.timeout_seconds = timeout_seconds
        self.output_bytes = output_bytes
        self.runner = runner or _run

    def _inspect(self, reference: str) -> str | None:
        code, stdout, _stderr, timed_out = self.runner(
            ("docker", "image", "inspect", reference, "--format", "{{.Id}}"), 60)
        value = stdout.decode("utf-8", "replace").strip()
        return value if not timed_out and code == 0 and re.fullmatch(r"sha256:[0-9a-f]{64}", value) else None

    def resolve(self, *, build_image_tag: str, build_image_id: str,
                runtime_user: str) -> tuple[CodeQLImage, bytes, bytes]:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", build_image_id):
            raise ValueError("accepted CodeQL environment image id is invalid")
        if not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", runtime_user):
            raise ValueError("accepted CodeQL runtime user must be numeric and non-root")
        source_at_tag = self._inspect(self.settings.source_image_tag)
        if source_at_tag != self.settings.source_image_id:
            if self._inspect(self.settings.source_image_id) is None:
                raise RuntimeError("licensed CodeQL source image is unavailable")
            raise ValueError("licensed CodeQL source image tag changed identity")
        build_at_tag = self._inspect(build_image_tag)
        if build_at_tag != build_image_id:
            if self._inspect(build_image_id) is None:
                raise RuntimeError("accepted CodeQL environment image is unavailable")
            raise ValueError("accepted CodeQL environment image tag changed identity")
        tool_root = self.repository_root / "containers" / "tools" / "codeql"
        dockerfile = tool_root / ("Dockerfile.source" if build_image_id == self.settings.source_image_id
                                  else "Dockerfile")
        runner_path = tool_root / "codeql_runner.py"
        identity = hashlib.sha256(canonical_json({
            "schema": IMAGE_SCHEMA, "source_image_id": self.settings.source_image_id,
            "build_image_id": build_image_id, "runtime_user": runtime_user,
            "dockerfile_sha256": file_sha256(dockerfile), "runner_sha256": file_sha256(runner_path),
        })).hexdigest()
        root = self.metadata_root / "codeql-images" / identity
        manifest_path = root / "manifest.json"
        image_tag = f"appsec-review-codeql:{identity[:24]}"
        root.mkdir(parents=True, exist_ok=True)
        with bounded_file_lock(root / "build.lock", self.timeout_seconds):
            image_id = self._inspect(image_tag)
            if manifest_path.is_file() and image_id is not None:
                value = json.loads(manifest_path.read_text(encoding="utf-8"))
                if (value.get("schema") == IMAGE_SCHEMA and value.get("identity") == identity and
                        value.get("image_id") == image_id):
                    return CodeQLImage(**{**value, "reused": True}), b"", b""
            context = root / "context"
            if context.exists():
                shutil.rmtree(context)
            context.mkdir(parents=True)
            shutil.copyfile(dockerfile, context / "Dockerfile")
            shutil.copyfile(runner_path, context / "codeql_runner.py")
            source_tag = f"appsec-review-codeql-source:{self.settings.source_image_id[7:31]}"
            base_tag = f"appsec-review-codeql-base:{build_image_id[7:31]}"
            for image, tag in ((self.settings.source_image_id, source_tag), (build_image_id, base_tag)):
                code, _stdout, stderr, timed_out = self.runner(("docker", "image", "tag", image, tag), 60)
                if timed_out or code != 0:
                    raise RuntimeError("could not bind an immutable CodeQL image input: " +
                                       stderr[:4096].decode("utf-8", "replace"))
            command_values = [
                "docker", "buildx", "build", "--load", "--pull=false", "--network", "none",
                "--tag", image_tag, "--build-arg", f"CODEQL_SOURCE_IMAGE={source_tag}",
            ]
            if build_image_id != self.settings.source_image_id:
                command_values.extend(("--build-arg", f"BUILD_IMAGE={base_tag}"))
            command_values.extend(("--build-arg", f"RUNTIME_USER={runtime_user}",
                "--file", str((context / "Dockerfile").resolve()), str(context.resolve())))
            command = tuple(command_values)
            # Docker Desktop's layer commits are not reliably concurrent. Keep the
            # immutable identity lock above, and serialize only the daemon mutation.
            with bounded_file_lock(self.metadata_root / "codeql-images" / "docker-build.lock",
                                   self.timeout_seconds):
                code, stdout, stderr, timed_out = self.runner(command, self.timeout_seconds)
            if timed_out or code != 0:
                detail = stderr[:self.output_bytes].decode("utf-8", "replace")
                raise RuntimeError("CodeQL derived image build timed out" if timed_out else
                                   f"CodeQL derived image build exited {code}: {detail}")
            image_id = self._inspect(image_tag)
            if image_id is None:
                raise RuntimeError("CodeQL derived image is unavailable after build")
            value = asdict(CodeQLImage(
                IMAGE_SCHEMA, identity, self.settings.source_image_id, build_image_id,
                build_image_tag, image_id, image_tag, runtime_user, file_sha256(dockerfile),
                file_sha256(runner_path), False,
                manifest_path.relative_to(self.metadata_root).as_posix(),
            ))
            atomic_json(manifest_path, value)
            return CodeQLImage(**value), stdout[:self.output_bytes], stderr[:self.output_bytes]


def _bounded_stream(path: Path, value: bytes, limit: int) -> tuple[str, int, bool, int]:
    truncated = len(value) > limit
    if not truncated:
        captured, tail_bytes = value, 0
    else:
        head = limit // 2
        tail_bytes = limit - head
        captured = value[:head] + value[-tail_bytes:]
    path.write_bytes(captured)
    return file_sha256(path), len(value), truncated, tail_bytes


class CodeQLExecutor:
    def __init__(self, *, image: CodeQLImage, run_root: Path, settings: RuntimeSettings,
                 runner: Runner | None = None) -> None:
        self.image = image
        self.run_root = run_root.resolve()
        self.settings = settings
        self.runner = runner or _run

    def execute(self, action: str, argv: Sequence[str], *, scratch_root: Path) -> CodeQLExecution:
        if action not in ACTIONS or any(
                not isinstance(value, str) or "\0" in value for value in argv):
            raise ValueError("CodeQL execution request is invalid")
        scratch = scratch_root.resolve()
        if scratch != self.run_root and self.run_root not in scratch.parents:
            raise ValueError("CodeQL scratch must be run-owned")
        scratch.mkdir(parents=True, exist_ok=True)
        runtime_user = application_runtime_user(self.image.runtime_user)
        container_uid = int(runtime_user.split(":", 1)[0])
        # Query and graph export may run concurrently for one scope. Export owns only its staged
        # ``export`` tree plus the scope root used to create ``exports``; traversing sibling query
        # scratch here races query cleanup and can turn a valid producer run into a host EIO.
        access_root = scratch / "export" if action in {"export", "compile"} else scratch
        access_paths = ((scratch, access_root, *access_root.rglob("*"))
                        if access_root != scratch else (scratch, *scratch.rglob("*")))
        for path in access_paths:
            if path.is_symlink():
                continue
            mode = path.stat().st_mode
            try:
                path.chmod(mode | (0o007 if path.is_dir() else 0o006))
            except PermissionError:
                # Outputs from an earlier CodeQL action share the application UID and remain
                # accessible to the next action; unrelated ownership is an integrity error.
                if path.stat().st_uid != container_uid:
                    raise
        # Every container below runs by image id, so the id must exist; the human tag may legitimately
        # move when another process rebuilds the same identity on the shared daemon.
        inspected = self.runner(("docker", "image", "inspect", self.image.image_id,
                                 "--format", "{{.Id}}"), 60)
        if inspected[3] or inspected[0] != 0 or inspected[1].decode().strip() != self.image.image_id:
            reason = ("timed out" if inspected[3] else
                      inspected[2][:512].decode("utf-8", "replace").strip() or
                      f"resolved {inspected[1].decode('utf-8', 'replace').strip()}")
            raise ValueError(f"CodeQL derived image {self.image.image_id} ({self.image.image_tag}) "
                             f"is unavailable: {reason}")
        effective = resolve_host_bind_path(scratch, self.runner)
        timeout = action_timeout(self.settings, action)
        # Export reads a staged database and pack without network access.
        network = "none" if action in {"export", "compile"} else "bridge"
        threads, ram_mb = ((int(getattr(self.settings, "compile_threads", self.settings.threads)),
                            int(getattr(self.settings, "compile_ram_mb", self.settings.ram_mb)))
                           if action == "compile" else (self.settings.threads, self.settings.ram_mb))
        database_name = None
        volume_name = None
        if action in {"database", "query"}:
            # CodeQL's pool writes require local Linux filesystem semantics. Keep only the
            # mutable database in a disposable Docker volume; the runner exports its bytes
            # back into the run-owned bind mount for normal hashing and receipts.
            try:
                database_name = argv[argv.index("--database") + 1]
            except (ValueError, IndexError) as exc:
                raise ValueError("CodeQL database path is required") from exc
            if not re.fullmatch(r"[a-z][a-z0-9-]*", database_name):
                raise ValueError("CodeQL database path is invalid")
            volume_name = f"appsec-codeql-{uuid4().hex}"
        mounts = ["--mount", f"type=bind,src={effective},dst=/scratch"]
        if volume_name is not None:
            mounts.extend(("--mount", f"type=volume,src={volume_name},dst=/scratch/{database_name}"))
            if action == "query":
                mounts.extend(("--mount", f"type=bind,src={effective},dst=/source,readonly"))
        # CodeQL's compilation cache is content addressed, so a volume shared by every query,
        # export and compile execution only ever turns a recompile into a hit. It is keyed by the
        # pinned CodeQL payload image, not the derived image, so every project environment (and
        # every edit of the runner script) reuses one warm cache. It is an optimization: a failure
        # to provision it must not fail the analysis. Ownership is re-asserted recursively: entries
        # written under another uid (``build.py query-packs --warm`` or a different host user) are
        # otherwise unreadable to this execution's CodeQL, which then recompiles from cold.
        cache_volume = None
        if action in {"query", "export", "compile"}:
            cache_volume = compile_cache_volume(self.image)
            created = self.runner(("docker", "volume", "create",
                "--label", "appsec-review=codeql-compile-cache", cache_volume), 60)
            initialized = self.runner(("docker", "run", "--rm", "--network", "none",
                "--read-only", "--user", "0:0", "--security-opt", "no-new-privileges",
                "--mount", f"type=volume,src={cache_volume},dst={COMPILE_CACHE_MOUNT}",
                "--entrypoint", "chown", self.image.image_id, "-R", runtime_user,
                COMPILE_CACHE_MOUNT), 60) if not created[3] and created[0] == 0 else created
            if initialized[3] or initialized[0] != 0:
                cache_volume = None
            else:
                mounts.extend(("--mount", f"type=volume,src={cache_volume},dst={COMPILE_CACHE_MOUNT}"))
        container_name = f"appsec-review-codeql-{uuid4().hex}"
        command = [
            "docker", "run", "--rm", "--name", container_name, "--network", network, "--read-only",
            "--user", runtime_user, "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--cpus", str(threads),
            "--memory", f"{ram_mb + 1024}m", "--pids-limit", "2048",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=2g", *mounts, "--workdir", "/scratch",
            "--env", "HOME=/tmp/codeql-home", "--env", "LANG=C.UTF-8", "--env", "LC_ALL=C.UTF-8",
            "--env", "TZ=UTC", "--entrypoint", "python3", self.image.image_id,
            "/opt/appsec/codeql_runner.py", action,
            *(("--staged-database",) if volume_name is not None else ()), *argv,
        ]
        started, monotonic = _stamp(), time.monotonic()
        volume_created = False
        try:
            if volume_name is not None:
                created = self.runner(("docker", "volume", "create",
                    "--label", "appsec-review=codeql-scratch", volume_name), 60)
                if created[3] or created[0] != 0:
                    raise RuntimeError("CodeQL temporary database volume could not be created")
                volume_created = True
                initialized = self.runner(("docker", "run", "--rm", "--network", "none",
                    "--read-only", "--user", "0:0", "--security-opt", "no-new-privileges",
                    "--mount", f"type=volume,src={volume_name},dst=/scratch/{database_name}",
                    "--entrypoint", "chown", self.image.image_id, runtime_user,
                    f"/scratch/{database_name}"), 60)
                if initialized[3] or initialized[0] != 0:
                    raise RuntimeError("CodeQL temporary database volume could not be initialized")
            code, stdout, stderr, timed_out = self.runner(command, timeout)
            if timed_out:
                # Killing the docker client leaves the container running and holding the volume.
                self.runner(("docker", "rm", "--force", container_name), 60)
        finally:
            if volume_created:
                removed = self.runner(("docker", "volume", "rm", volume_name), 60)
                if removed[3] or removed[0] != 0:
                    raise RuntimeError("CodeQL temporary database volume could not be removed")
        if action == "database" and not timed_out and code == 0:
            exported = scratch / "database-export"
            database = scratch / str(database_name)
            if (not exported.is_dir() or exported.is_symlink() or
                    database.is_symlink() or database.is_file() or
                    database.is_dir() and any(database.iterdir())):
                raise RuntimeError("CodeQL temporary database export is incomplete")
            if database.is_dir():
                database.rmdir()
            exported.rename(database)
        duration_ms, completed = max(0, int((time.monotonic() - monotonic) * 1000)), _stamp()
        log_root = scratch / "executions" / action
        log_root.mkdir(parents=True, exist_ok=True)
        stdout_path, stderr_path = log_root / "stdout.bin", log_root / "stderr.bin"
        stdout_sha, stdout_total, stdout_truncated, stdout_tail = _bounded_stream(
            stdout_path, stdout, self.settings.output_bytes)
        stderr_sha, stderr_total, stderr_truncated, stderr_tail = _bounded_stream(
            stderr_path, stderr, self.settings.output_bytes)
        result = CodeQLExecution(
            EXECUTION_SCHEMA, action, self.image.image_id, self.image.image_tag,
            hashlib.sha256(canonical_json(list(argv))).hexdigest(), code, timed_out,
            started, completed, duration_ms, stdout_path.relative_to(self.run_root).as_posix(),
            stderr_path.relative_to(self.run_root).as_posix(), stdout_sha, stderr_sha,
            stdout_total, stderr_total, stdout_truncated, stderr_truncated, stdout_tail, stderr_tail,
            {"network": network, "root_filesystem": "read-only", "user": runtime_user,
             "cap_drop": ["ALL"], "no_new_privileges": True, "threads": threads,
             "ram_mb": ram_mb, "timeout_seconds": timeout,
             "output_bytes": self.settings.output_bytes, "capture_mode": "head-tail",
             "database_storage": "disposable-docker-volume" if volume_name else "run-bind",
             "compile_cache": "persistent-docker-volume" if cache_volume else "none"},
        )
        atomic_json(log_root / "receipt.json", asdict(result))
        return result


def tree_manifest(root: Path, *, file_limit: int, bytes_limit: int) -> Mapping[str, Any]:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("CodeQL database directory is unavailable")
    files: dict[str, str] = {}
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("CodeQL database contains an unsupported symlink")
        if not path.is_file():
            continue
        if len(files) >= file_limit:
            raise ValueError("CodeQL database file count exceeds configured bound")
        total += path.stat().st_size
        if total > bytes_limit:
            raise ValueError("CodeQL database size exceeds configured bound")
        files[path.relative_to(root).as_posix()] = file_sha256(path)
    if not files:
        raise ValueError("CodeQL database is empty")
    return {"schema": "appsec-review/codeql-database-manifest/1", "files": files,
            "file_count": len(files), "size_bytes": total,
            "tree_sha256": hashlib.sha256(canonical_json(files)).hexdigest()}


def load_sarif(path: Path, *, bytes_limit: int, result_limit: int) -> Mapping[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > bytes_limit:
        raise ValueError("CodeQL SARIF is missing, linked, or exceeds its configured bound")
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("version") != "2.1.0" or not isinstance(document.get("runs"), list):
        raise ValueError("CodeQL SARIF contract is unsupported")
    count = 0
    for run in document["runs"]:
        if not isinstance(run, Mapping) or not isinstance(run.get("results", []), list):
            raise ValueError("CodeQL SARIF run is invalid")
        count += len(run.get("results", []))
    if count > result_limit:
        raise ValueError("CodeQL SARIF result count exceeds its configured bound")
    return document


class GraphExportIntegrityError(ValueError):
    """A raw graph export directory differs from its manifest or the export contract."""


def graph_export_arguments(*, database: str, pack: str, columns: str, asset_lock: str, language: str,
                           output_dir: str, scope_file: str, seeds_file: str, row_limit: int,
                           max_bytes: int, threads: int, ram_mb: int) -> tuple[str, ...]:
    """Runner argv for the ``export`` action; every path is relative to the execution scratch.

    ``scope_file`` (``<mode>,<depth>``) and ``seeds_file`` (``<path>,<start_line>,<end_line>`` rows)
    are staged CSV files the runner binds to the pack's external predicates
    (docs/architecture/seeded-codeql-neighborhoods.md section 5).
    """
    for value in (database, pack, columns, asset_lock, output_dir, scope_file, seeds_file):
        logical = PurePosixPath(value)
        if not logical.parts or logical.is_absolute() or ".." in logical.parts:
            raise ValueError("CodeQL export path must be scratch-relative")
    for value in (row_limit, max_bytes, threads, ram_mb):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("CodeQL export bounds must be positive integers")
    return ("--database", database, "--pack", pack, "--columns", columns, "--asset-lock", asset_lock,
            "--language", language, "--output-dir", output_dir, "--scope-file", scope_file,
            "--seeds-file", seeds_file, "--row-limit", str(row_limit),
            "--max-bytes", str(max_bytes), "--threads", str(threads), "--ram", str(ram_mb))


def graph_compile_arguments(*, pack: str, columns: str, asset_lock: str, language: str,
                            threads: int, ram_mb: int) -> tuple[str, ...]:
    """Runner argv for the ``compile`` action, which warms the persistent query compile cache."""
    for value in (pack, columns, asset_lock):
        logical = PurePosixPath(value)
        if not logical.parts or logical.is_absolute() or ".." in logical.parts:
            raise ValueError("CodeQL compile path must be scratch-relative")
    for value in (threads, ram_mb):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("CodeQL compile bounds must be positive integers")
    return ("--pack", pack, "--columns", columns, "--asset-lock", asset_lock, "--language", language,
            "--threads", str(threads), "--ram", str(ram_mb))


def load_graph_exports(root: Path, *, bytes_limit: int) -> dict[str, Mapping[str, Any]]:
    """Verify a raw graph export directory against its manifest; return the exports by query id.

    Every file must be listed with its byte size and SHA-256, no other file may exist, the total
    must stay within ``bytes_limit``, and every object must satisfy the shared export contract
    and agree with its manifest row.
    """
    from appsec_review.graph.contract import EXPORT_SCHEMA, GraphContractError, validate_export

    manifest_path = root / EXPORT_MANIFEST_NAME
    if (not root.is_dir() or root.is_symlink() or not manifest_path.is_file() or
            manifest_path.is_symlink()):
        raise GraphExportIntegrityError("graph export directory or manifest is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, Mapping):
        raise GraphExportIntegrityError("graph export manifest is unsupported")
    exports = manifest.get("exports")
    if (manifest.get("schema") != EXPORT_MANIFEST_SCHEMA or manifest.get("export_schema") != EXPORT_SCHEMA
            or not isinstance(exports, list) or not exports):
        raise GraphExportIntegrityError("graph export manifest is unsupported")
    query_ids = [item.get("query_id") for item in exports if isinstance(item, Mapping)]
    if (len(query_ids) != len(exports) or not all(isinstance(value, str) and value for value in query_ids)
            or query_ids != sorted(set(query_ids))):
        raise GraphExportIntegrityError("graph export manifest rows are invalid")
    expected = {EXPORT_MANIFEST_NAME, *(f"{query_id}.json" for query_id in query_ids)}
    if {path.name for path in root.iterdir()} != expected:
        raise GraphExportIntegrityError("graph export directory holds unlisted or missing files")
    documents: dict[str, Mapping[str, Any]] = {}
    total = 0
    for item in exports:
        path = root / f"{item['query_id']}.json"
        if item.get("path") != path.name or not path.is_file() or path.is_symlink():
            raise GraphExportIntegrityError(f"graph export {item['query_id']} file is invalid")
        size = path.stat().st_size
        total += size
        if size != item.get("bytes") or total > bytes_limit:
            raise GraphExportIntegrityError(f"graph export {item['query_id']} size differs or exceeds its bound")
        if file_sha256(path) != item.get("sha256"):
            raise GraphExportIntegrityError(f"graph export {item['query_id']} hash differs from its manifest")
        document = json.loads(path.read_text(encoding="utf-8"))
        try:
            validate_export(document)
        except GraphContractError as error:
            raise GraphExportIntegrityError(f"graph export {item['query_id']}: {error}") from error
        if (document["query_id"] != item["query_id"] or document["row_count"] != item.get("row_count") or
                document["truncated"] != item.get("truncated") or
                len(document["rows"]) != item.get("exported_rows") or
                document["bqrs_sha256"] != item.get("bqrs_sha256")):
            raise GraphExportIntegrityError(f"graph export {item['query_id']} differs from its manifest row")
        documents[item["query_id"]] = document
    return documents
