from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import time
from typing import Any, Protocol
from uuid import uuid4

from appsec_review.application_paths import application_asset
from appsec_review.container_runtime.build_executor import Runner, _run, resolve_host_bind_path
from appsec_review.container_runtime.identity import application_runtime_user
from appsec_review.config.assurance import ComponentReleases
from appsec_review.config.codeql import CodeQLPreinstalledRuntime
from appsec_review.config.native_dagster import native_execution_requested
from appsec_review.storage import atomic_json, bounded_file_lock, canonical_json, file_sha256
from appsec_review.runtime import execution_safety as safety


IMAGE_SCHEMA = "appsec-review/codeql-derived-image/3"
PREINSTALLED_IMAGE_SCHEMA = "appsec-review/codeql-preinstalled-image/1"
EXECUTION_SCHEMA = "appsec-review/codeql-execution/2"
EXPORT_MANIFEST_SCHEMA = "appsec-review/codeql-graph-export-manifest/1"
EXPORT_MANIFEST_NAME = "export-manifest.json"
COMPILE_CACHE_MOUNT = "/codeql-cache"
ACTIONS = frozenset({"inventory", "database", "query", "export", "compile"})
RUNNER_ASSET = "containers/tools/codeql/codeql_runner.py"
RUNNER_CONTAINER_PATH = "/opt/appsec/codeql_runner.py"


class RuntimeSettings(Protocol):
    source_image_tag: str
    source_image_id: str
    database_timeout_seconds: int
    query_timeout_seconds: int
    inventory_timeout_seconds: int
    output_bytes: int
    threads: int
    ram_mb: int
    preinstalled_runtimes: tuple[CodeQLPreinstalledRuntime, ...]


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


def compile_cache_volume(image: "CodeQLImage", run_root: Path) -> str:
    """Run-private compilation cache, keyed by declarations rather than supplied payloads."""
    identity = {"run_root": str(run_root.resolve()), "codeql": image.component_release_id,
                "runner": image.runner_release_id, "user": application_runtime_user(image.runtime_user)}
    return "appsec-codeql-compile-" + hashlib.sha256(canonical_json(identity)).hexdigest()[:24]


def action_resources(settings: RuntimeSettings, action: str) -> tuple[int, int]:
    if action == "compile":
        return (int(getattr(settings, "compile_threads", settings.threads)),
                int(getattr(settings, "compile_ram_mb", settings.ram_mb)))
    return settings.threads, settings.ram_mb


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
    component_release_id: str | None
    runner_release_id: str | None
    reused: bool
    manifest_path: str
    preparation_receipt: Mapping[str, Any] | None = None
    preinstalled: bool = False
    image_build_performed: bool | None = None
    runner_source: str = "image"


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
    return {**document, "path": path.as_posix()}


class CodeQLImageResolver:
    """Select an explicitly declared installed runtime or prepare its bounded offline layer."""

    def __init__(self, *, repository_root: Path, metadata_root: Path, settings: RuntimeSettings,
                 timeout_seconds: int = 1800, output_bytes: int = 8 * 1024 * 1024,
                 runner: Runner | None = None, releases: ComponentReleases | None = None) -> None:
        self.repository_root = repository_root
        self.metadata_root = metadata_root
        self.settings = settings
        self.timeout_seconds = timeout_seconds
        self.output_bytes = output_bytes
        self.runner = runner or _run
        self.releases = releases or ComponentReleases()

    def _inspect(self, reference: str) -> str | None:
        code, stdout, _stderr, timed_out = self.runner(
            ("docker", "image", "inspect", reference, "--format", "{{.Id}}"), 60)
        value = stdout.decode("utf-8", "replace").strip()
        return value if not timed_out and code == 0 and re.fullmatch(r"sha256:[0-9a-f]{64}", value) else None

    def declared_identity(self, *, build_image_id: str, runtime_user: str) -> str:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", build_image_id):
            raise ValueError("accepted CodeQL environment image id is invalid")
        if not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", runtime_user):
            raise ValueError("accepted CodeQL runtime user must be numeric and non-root")
        preinstalled = self._preinstalled(build_image_id=build_image_id, runtime_user=runtime_user)
        identity = {
            "schema": IMAGE_SCHEMA, "source_image_id": self.settings.source_image_id,
            "build_image_id": build_image_id, "runtime_user": runtime_user,
            "component_release_id": self.releases.values.get("codeql"),
            "runner_release_id": self.releases.values.get("codeql_runner"),
        }
        if preinstalled is not None:
            identity.update(schema=PREINSTALLED_IMAGE_SCHEMA, preinstalled=asdict(preinstalled),
                            runtime_user=preinstalled.runtime_user)
        return hashlib.sha256(canonical_json(identity)).hexdigest()

    def _preinstalled(self, *, build_image_id: str, runtime_user: str) -> CodeQLPreinstalledRuntime | None:
        declarations = getattr(self.settings, "preinstalled_runtimes", ())
        if not declarations:
            return None
        effective_user = application_runtime_user(runtime_user)
        matches = [item for item in declarations
                   if item.build_image_id == build_image_id and item.runtime_user == effective_user]
        if len(matches) != 1:
            raise ValueError("CodeQL preinstalled runtime requires one exact environment/user declaration")
        selected = matches[0]
        if selected.runner_source == "application" and native_execution_requested():
            raise ValueError("application-supplied CodeQL runner is unsupported with native execution")
        if (selected.source_image_id != self.settings.source_image_id
                or selected.codeql_release_id != self.releases.values.get("codeql")
                or selected.runner_release_id != self.releases.values.get("codeql_runner")):
            raise ValueError("CodeQL preinstalled runtime source or release declaration conflicts with frozen policy")
        return selected

    def resolve(self, *, build_image_tag: str, build_image_id: str,
                runtime_user: str) -> tuple[CodeQLImage, bytes, bytes]:
        from appsec_review.container_runtime.image_builder import (
            bounded_image_preparation, builder_namespace, verify_builder_receipt,
        )
        identity = self.declared_identity(build_image_id=build_image_id, runtime_user=runtime_user)
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
        preinstalled = self._preinstalled(build_image_id=build_image_id, runtime_user=runtime_user)
        if preinstalled is not None:
            if self._inspect(preinstalled.runtime_image_id) != preinstalled.runtime_image_id:
                raise ValueError("CodeQL preinstalled runtime image is missing or differs from its immutable ID")
            manifest_path = self.metadata_root / "codeql-preinstalled-images" / f"{identity}.json"
            image = CodeQLImage(
                PREINSTALLED_IMAGE_SCHEMA, identity, self.settings.source_image_id, build_image_id,
                build_image_tag, preinstalled.runtime_image_id, preinstalled.runtime_image_id,
                preinstalled.runtime_user, preinstalled.codeql_release_id, preinstalled.runner_release_id,
                False, manifest_path.relative_to(self.metadata_root).as_posix(),
                preinstalled=True, image_build_performed=False, runner_source=preinstalled.runner_source)
            atomic_json(manifest_path, asdict(image))
            return image, b"", b""
        tool_root = self.repository_root / "containers" / "tools" / "codeql"
        dockerfile = tool_root / ("Dockerfile.source" if build_image_id == self.settings.source_image_id
                                  else "Dockerfile")
        runner_path = tool_root / "codeql_runner.py"
        namespace = builder_namespace()
        image_root = self.metadata_root / "codeql-images"
        root = image_root / namespace / identity if namespace is not None else image_root / identity
        manifest_path = root / "manifest.json"
        image_tag = f"appsec-review-codeql:{namespace[:12] + identity[:12] if namespace else identity[:24]}"
        root.mkdir(parents=True, exist_ok=True)
        with bounded_file_lock(root / "build.lock", self.timeout_seconds):
            image_id = self._inspect(image_tag)
            reusable, _reason = self.releases.require("codeql", "codeql_runner")
            if reusable and manifest_path.is_file() and image_id is not None:
                value = json.loads(manifest_path.read_text(encoding="utf-8"))
                if (value.get("schema") == IMAGE_SCHEMA and value.get("identity") == identity and
                        value.get("image_id") == image_id):
                    if namespace is not None:
                        verify_builder_receipt(value["preparation_receipt"], identity=identity, tag=image_tag,
                                               image_id=image_id)
                    return CodeQLImage(**{**value, "reused": True, "image_build_performed": False}), b"", b""
            from appsec_review.runtime.resources import require_bounded_image_builder
            require_bounded_image_builder()
            with bounded_image_preparation(identity=identity, tag=image_tag,
                                           timeout_seconds=self.timeout_seconds) as builder:
                context = builder.context if builder is not None else root / "context"
                if builder is None and context.exists():
                    shutil.rmtree(context)
                context.mkdir(parents=True, exist_ok=builder is not None)
                shutil.copyfile(dockerfile, context / "Dockerfile")
                shutil.copyfile(runner_path, context / "codeql_runner.py")
                prefix = namespace[:12] if namespace else ""
                source_tag = f"appsec-review-codeql-source:{prefix}{self.settings.source_image_id[7:31]}"
                base_tag = f"appsec-review-codeql-base:{prefix}{build_image_id[7:31]}"
                arguments = {"CODEQL_SOURCE_IMAGE": source_tag, "RUNTIME_USER": runtime_user}
                if build_image_id != self.settings.source_image_id:
                    arguments["BUILD_IMAGE"] = base_tag
                images = {source_tag: self.settings.source_image_id, base_tag: build_image_id}
                if builder is not None:
                    code, stdout, stderr, timed_out = builder.build(
                        network="none", build_args=arguments, image_inputs=images)
                else:
                    for tag, image in images.items():
                        code, _stdout, stderr, timed_out = self.runner(("docker", "image", "tag", image, tag), 60)
                        if timed_out or code != 0:
                            raise RuntimeError("could not bind an immutable CodeQL image input: " +
                                               stderr[:4096].decode("utf-8", "replace"))
                    command_values = [
                        "docker", "buildx", "build", "--load", "--pull=false", "--network", "none",
                        "--tag", image_tag,
                    ]
                    for name, value in arguments.items():
                        command_values.extend(("--build-arg", f"{name}={value}"))
                    command_values.extend(("--file", str((context / "Dockerfile").resolve()), str(context.resolve())))
                    with bounded_file_lock(self.metadata_root / "codeql-images" / "docker-build.lock",
                                           self.timeout_seconds):
                        code, stdout, stderr, timed_out = self.runner(tuple(command_values), self.timeout_seconds)
            if timed_out or code != 0:
                detail = stderr[:self.output_bytes].decode("utf-8", "replace")
                raise RuntimeError("CodeQL derived image build timed out" if timed_out else
                                   f"CodeQL derived image build exited {code}: {detail}")
            image_id = self._inspect(image_tag)
            if image_id is None:
                raise RuntimeError("CodeQL derived image is unavailable after build")
            if builder is not None and image_id != builder.output_image_id:
                raise ValueError("bounded builder output image differs from local image binding")
            value = asdict(CodeQLImage(
                IMAGE_SCHEMA, identity, self.settings.source_image_id, build_image_id,
                build_image_tag, image_id, image_tag, runtime_user, self.releases.values.get("codeql"),
                self.releases.values.get("codeql_runner"), False,
                manifest_path.relative_to(self.metadata_root).as_posix(),
                builder.receipt() if builder is not None else None,
                image_build_performed=True,
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

    def _native_directory(self, relative: str) -> Path:
        from appsec_review.container_runtime.buildkit_worker import private_path
        from appsec_review.storage.shared import safe_path

        path = safe_path(self.run_root, relative)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        private_path(path)
        return path

    @contextmanager
    def _container(self, name: str):
        from appsec_review.runtime.resources import tracked_container
        with tracked_container(name, self.runner, label="CodeQL"):
            yield

    def _initialize_volume(self, volume: str, mount: str, runtime_user: str) -> None:
        name = f"appsec-review-codeql-init-{uuid4().hex}"
        command = ("docker", "run", "--rm", "--name", name, "--network", "none",
                   "--read-only", "--user", "0:0", "--cap-drop", "ALL",
                   "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE",
                   "--security-opt", "no-new-privileges", "--cpus", "1", "--memory", "128m",
                   "--pids-limit", "64", "--mount", f"type=volume,src={volume},dst={mount}",
                   "--entrypoint", "chown", self.image.image_id, runtime_user, mount)
        with self._container(name):
            result = self.runner(command, 60)
        if result[3] or result[0] != 0:
            raise RuntimeError(f"CodeQL volume initialization failed: {volume}")

    def _compile_cache(self, runtime_user: str) -> str | None:
        if not self.image.component_release_id or not self.image.runner_release_id:
            return None
        volume = compile_cache_volume(self.image, self.run_root)
        if native_execution_requested():
            return str(self._native_directory(f"data/codeql/native-compile-cache/{volume}"))
        root = self.run_root / "data" / "codeql" / "cache-initialization"
        marker = root / f"{volume}.json"
        with bounded_file_lock(root / f"{volume}.lock", 60):
            created = self.runner(("docker", "volume", "create",
                                   "--label", "appsec-review=codeql-compile-cache", volume), 60)
            if created[3] or created[0] != 0:
                raise RuntimeError("CodeQL compile-cache volume could not be created")
            inspected = self.runner(("docker", "volume", "inspect", volume,
                                     "--format", "{{.CreatedAt}}"), 60)
            if inspected[3] or inspected[0] != 0 or not inspected[1].strip():
                raise RuntimeError("CodeQL compile-cache volume identity is unavailable")
            identity = {"schema": "appsec-review/codeql-cache-initialization/1",
                        "volume": volume, "created_at": inspected[1].decode().strip(),
                        "runtime_user": runtime_user}
            if marker.exists() and json.loads(marker.read_text(encoding="utf-8")) == identity:
                return volume
            self._initialize_volume(volume, COMPILE_CACHE_MOUNT, runtime_user)
            atomic_json(marker, identity)
        return volume

    def execute(self, action: str, argv: Sequence[str], *, scratch_root: Path) -> CodeQLExecution:
        if action not in ACTIONS or any(
                not isinstance(value, str) or "\0" in value for value in argv):
            raise ValueError("CodeQL execution request is invalid")
        scratch = scratch_root.resolve()
        if scratch != self.run_root and self.run_root not in scratch.parents:
            raise ValueError("CodeQL scratch must be run-owned")
        from appsec_review.runtime.resources import reserve_execution
        threads, ram_mb = action_resources(self.settings, action)
        with reserve_execution(cpu=str(threads), memory=f"{ram_mb + 1024}m",
                               action=f"codeql.{action}", timeout_seconds=action_timeout(self.settings, action)):
            try:
                return self._execute(action, argv, scratch=scratch)
            finally:
                _close_write_window(scratch)

    def _execute(self, action: str, argv: Sequence[str], *, scratch: Path) -> CodeQLExecution:
        scratch.mkdir(parents=True, exist_ok=True)
        native = native_execution_requested()
        runtime_user = application_runtime_user(self.image.runtime_user)
        if self.image.preinstalled and runtime_user != self.image.runtime_user:
            raise ValueError("CodeQL preinstalled runtime user changed before execution")
        if self.image.preinstalled:
            if self.image.component_release_id is None or self.image.runner_release_id is None:
                raise ValueError("CodeQL preinstalled runtime is missing declared releases")
            declaration = CodeQLPreinstalledRuntime(
                self.image.source_image_id, self.image.build_image_id, self.image.image_id,
                self.image.runtime_user, self.image.component_release_id, self.image.runner_release_id,
                self.image.runner_source)
            if declaration not in getattr(self.settings, "preinstalled_runtimes", ()):
                raise ValueError("CodeQL preinstalled runtime declaration changed before execution")
        runner_mount = None
        if self.image.runner_source == "application":
            if not self.image.preinstalled or native:
                raise ValueError("application-supplied CodeQL runner requires ordinary preinstalled execution")
            runner_path = application_asset(RUNNER_ASSET)
            if (runner_path.is_symlink() or not runner_path.is_file()
                    or not runner_path.resolve().is_relative_to(runner_path.parents[3].resolve())):
                raise ValueError("application-supplied CodeQL runner must remain in the trusted application root")
            runner_mount = resolve_host_bind_path(runner_path, self.runner)
        elif self.image.runner_source != "image":
            raise ValueError("CodeQL runtime runner source is invalid")
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
                permissions = (0o700 if path.is_dir() else 0o600) if native else (
                    0o007 if path.is_dir() else 0o006)
                path.chmod(((mode & ~0o022) if native else mode) | permissions)
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
            raise ValueError(f"CodeQL runtime image {self.image.image_id} ({self.image.image_tag}) "
                             f"is unavailable: {reason}")
        effective = resolve_host_bind_path(scratch, self.runner)
        timeout = action_timeout(self.settings, action)
        # Export reads a staged database and pack without network access.
        network = "none" if action in {"export", "compile"} else "bridge"
        threads, ram_mb = action_resources(self.settings, action)
        database_name = None
        volume_name = None
        native_database = None
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
            if native:
                native_database = self._native_directory(
                    (scratch.relative_to(self.run_root) / f".native-codeql-{uuid4().hex}").as_posix())
            else:
                volume_name = f"appsec-codeql-{uuid4().hex}"
        mounts = ["--mount", f"type=bind,src={effective},dst=/scratch"]
        if runner_mount is not None:
            mounts.extend(("--mount", f"type=bind,src={runner_mount},dst={RUNNER_CONTAINER_PATH},readonly"))
        staged_database = volume_name is not None or native_database is not None
        if staged_database:
            database_mount = (f"type=bind,src={native_database}" if native_database is not None
                              else f"type=volume,src={volume_name}")
            mounts.extend(("--mount", f"{database_mount},dst=/scratch/{database_name}"))
            if action == "query":
                mounts.extend(("--mount", f"type=bind,src={effective},dst=/source,readonly"))
        cache_volume = None
        if action in {"query", "export", "compile"}:
            cache_volume = self._compile_cache(runtime_user)
            if cache_volume is not None:
                mounts.extend(("--mount", f"type={'bind' if native else 'volume'},"
                               f"src={cache_volume},dst={COMPILE_CACHE_MOUNT}"))
        container_name = f"appsec-review-codeql-{uuid4().hex}"
        command = [
            "docker", "run", "--rm", "--name", container_name, "--network", network, "--read-only",
            "--user", runtime_user, "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--cpus", str(threads),
            "--memory", f"{ram_mb + 1024}m", "--pids-limit", "2048",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=2g", *mounts, "--workdir", "/scratch",
            "--env", "HOME=/tmp/codeql-home", "--env", "LANG=C.UTF-8", "--env", "LC_ALL=C.UTF-8",
            "--env", "TZ=UTC", "--entrypoint", "python3", self.image.image_id,
            RUNNER_CONTAINER_PATH, action,
            *(("--staged-database",) if staged_database else ()), *argv,
        ]
        started, monotonic = _stamp(), time.monotonic()
        from appsec_review.runtime.resources import quarantine_resources
        volume_created = False
        container_removed = False
        try:
            if volume_name is not None:
                created = self.runner(("docker", "volume", "create",
                    "--label", "appsec-review=codeql-scratch", volume_name), 60)
                if created[3] or created[0] != 0:
                    raise RuntimeError("CodeQL temporary database volume could not be created")
                volume_created = True
                self._initialize_volume(volume_name, f"/scratch/{database_name}", runtime_user)
            with self._container(container_name):
                code, stdout, stderr, timed_out = self.runner(command, timeout)
                if safety.active():
                    retained = scratch / "executions" / action
                    retained.mkdir(parents=True, exist_ok=True)
                    _bounded_stream(retained / "stdout.bin", stdout, self.settings.output_bytes)
                    _bounded_stream(retained / "stderr.bin", stderr, self.settings.output_bytes)
                    atomic_json(retained / "partial-receipt.json", {
                        "schema": EXECUTION_SCHEMA, "action": action, "image_id": self.image.image_id,
                        "started_at": started, "completed_at": _stamp(),
                        "duration_ms": max(0, int((time.monotonic() - monotonic) * 1000)),
                        "exit_code": code, "timed_out": timed_out, "cleanup": "PENDING",
                        "container": container_name, "volume": volume_name})
                    if timed_out or code != 0:
                        safety.latch(f"CodeQL {action} failed; evidence: {retained}", action=f"codeql.{action}")
            container_removed = True
        finally:
            if native_database is not None and container_removed:
                shutil.rmtree(native_database)
            if volume_created:
                if safety.active() and not container_removed:
                    quarantine_resources("codeql_container_removal_unconfirmed")
                    raise safety.ReviewStopped("CodeQL volume retained until container removal is confirmed")
                with safety.cleanup_scope():
                    removed = self.runner(("docker", "volume", "rm", volume_name), 60)
                if removed[3] or removed[0] != 0:
                    quarantine_resources("codeql_volume_cleanup_failed")
                    raise RuntimeError("CodeQL temporary database volume could not be removed")
        safety.check_running()
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
             "runner_source": self.image.runner_source, "runner_release_id": self.image.runner_release_id,
             "output_bytes": self.settings.output_bytes, "capture_mode": "head-tail",
             "database_storage": ("disposable-native-bind" if native_database is not None else
                                  "disposable-docker-volume" if volume_name else "run-bind"),
             "compile_cache": ("run-private-native-bind" if native and cache_volume else
                               "persistent-docker-volume" if cache_volume else "none"),
             "compile_cache_reason": ("run_private_declared_release" if cache_volume else
                                      "missing_release" if action in {"query", "export", "compile"}
                                      else "not_applicable")},
        )
        atomic_json(log_root / "receipt.json", asdict(result))
        return result


def _close_write_window(root: Path) -> None:
    """Remove the world-write bit from ``root`` and everything under it, tolerating concurrent cleanup."""

    def clear(path: str) -> None:
        try:
            info = os.lstat(path)
            if not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o002:
                os.chmod(path, info.st_mode & ~0o002)
        except OSError:
            pass  # gone, or not ours to change; the permission audit reports what remains

    clear(str(root))
    for current, directories, files in os.walk(root, onerror=lambda _error: None):
        for name in (*directories, *files):
            clear(os.path.join(current, name))


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
