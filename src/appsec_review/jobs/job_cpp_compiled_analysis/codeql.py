from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any

from appsec_review.config import CodeQLSettings
from appsec_review.container_runtime.build_executor import Runner, _run, resolve_host_bind_path
from appsec_review.storage import FileLock, atomic_json, canonical_json, file_sha256


IMAGE_SCHEMA = "appsec-review/codeql-derived-image/1"
EXECUTION_SCHEMA = "appsec-review/codeql-execution/1"


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
    stdout_path: str
    stderr_path: str
    stdout_sha256: str
    stderr_sha256: str
    stdout_truncated: bool
    stderr_truncated: bool
    limits: Mapping[str, Any]


def validate_assets(repository_root: Path, settings: CodeQLSettings) -> Mapping[str, Any]:
    path = repository_root / "containers" / "tools" / "codeql-cpp" / "assets.lock.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "source_image": {"tag": settings.source_image_tag, "image_id": settings.source_image_id},
        "codeql": {
            "version": settings.version.split("+", 1)[0],
            "commit": settings.version.split("+", 1)[1] if "+" in settings.version else "",
            "cli_sha256": settings.cli_sha256,
            "cpp_extractor_sha256": settings.extractor_sha256,
            "license_sha256": settings.license_sha256,
        },
        "query_pack": {
            "name": settings.query_pack, "version": settings.query_pack_version,
            "suite": settings.query_suite, "suite_sha256": settings.query_suite_sha256,
            "qlpack_sha256": settings.query_pack_sha256,
            "lock_sha256": settings.query_lock_sha256,
        },
    }
    if document.get("schema") != "appsec-review/codeql-assets-lock/1" or any(
            document.get(key) != value for key, value in expected.items()):
        raise ValueError("CodeQL configuration differs from the reviewed asset lock")
    return {**document, "path": path.as_posix(), "sha256": file_sha256(path)}


def database_identity(settings: CodeQLSettings, *, target_snapshot: str, case_snapshot: str,
                      replay: Mapping[str, Any], image_identity: str) -> str:
    return hashlib.sha256(canonical_json({
        "schema": "appsec-review/codeql-database-checkpoint/1",
        "target_snapshot": target_snapshot, "case_snapshot": case_snapshot,
        "recipe_identity": replay["recipe_identity"], "build_image_id": replay["build_image_id"],
        "dependency_hashes": replay["dependency_hashes"],
        "protected_commands": replay["protected_commands"],
        "codeql_image_identity": image_identity, "codeql_version": settings.version,
        "cli_sha256": settings.cli_sha256, "extractor_sha256": settings.extractor_sha256,
        "database_limits": {"file_limit": settings.database_file_limit,
                            "bytes_limit": settings.database_bytes_limit,
                            "threads": settings.threads, "ram_mb": settings.ram_mb},
    })).hexdigest()


def query_identity(settings: CodeQLSettings, *, database_tree_sha256: str,
                   image_id: str) -> str:
    return hashlib.sha256(canonical_json({
        "schema": "appsec-review/codeql-query-checkpoint/1",
        "database_tree_sha256": database_tree_sha256,
        "query_pack": settings.query_pack, "query_pack_version": settings.query_pack_version,
        "query_suite": settings.query_suite, "query_suite_sha256": settings.query_suite_sha256,
        "query_pack_sha256": settings.query_pack_sha256,
        "query_lock_sha256": settings.query_lock_sha256, "codeql_image_id": image_id,
        "query_limits": {"result_limit": settings.result_limit,
                         "sarif_bytes_limit": settings.sarif_bytes_limit,
                         "max_paths": settings.max_paths, "threads": settings.threads,
                         "ram_mb": settings.ram_mb},
    })).hexdigest()


class CodeQLImageResolver:
    """Layer the pinned CodeQL payload onto an accepted project build image, offline."""

    def __init__(self, *, repository_root: Path, metadata_root: Path, settings: CodeQLSettings,
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

    def _validate_source_payload(self) -> None:
        pack_root = f"/opt/codeql/qlpacks/codeql/cpp-queries/{self.settings.query_pack_version}"
        expected = {
            "/opt/codeql/codeql": self.settings.cli_sha256,
            "/opt/codeql/cpp/tools/linux64/extractor": self.settings.extractor_sha256,
            "/opt/codeql/LICENSE.md": self.settings.license_sha256,
            f"{pack_root}/qlpack.yml": self.settings.query_pack_sha256,
            f"{pack_root}/codeql-pack.lock.yml": self.settings.query_lock_sha256,
            f"{pack_root}/{self.settings.query_suite}": self.settings.query_suite_sha256,
        }
        command = (
            "docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--entrypoint", "sha256sum",
            self.settings.source_image_id, *expected,
        )
        code, stdout, _stderr, timed_out = self.runner(command, 120)
        if timed_out or code != 0:
            raise ValueError("licensed CodeQL payload validation failed")
        actual = {}
        for line in stdout.decode("utf-8", "replace").splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                actual[parts[1].lstrip("* ")] = parts[0]
        if actual != expected:
            raise ValueError("licensed CodeQL payload identities differ from the asset lock")

    def resolve(self, *, build_image_tag: str, build_image_id: str,
                runtime_user: str) -> tuple[CodeQLImage, bytes, bytes]:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", build_image_id):
            raise ValueError("accepted CodeQL build image id is invalid")
        if not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", runtime_user):
            raise ValueError("accepted CodeQL runtime user must be numeric and non-root")
        if self._inspect(self.settings.source_image_tag) != self.settings.source_image_id:
            raise ValueError("licensed CodeQL source image is absent or changed")
        self._validate_source_payload()
        if self._inspect(build_image_tag) != build_image_id:
            raise ValueError("accepted project build image is absent or changed")
        tool_root = self.repository_root / "containers" / "tools" / "codeql-cpp"
        dockerfile = tool_root / "Dockerfile"
        runner_path = tool_root / "codeql_runner.py"
        identity = hashlib.sha256(canonical_json({
            "schema": IMAGE_SCHEMA, "source_image_id": self.settings.source_image_id,
            "build_image_id": build_image_id, "runtime_user": runtime_user,
            "dockerfile_sha256": file_sha256(dockerfile), "runner_sha256": file_sha256(runner_path),
        })).hexdigest()
        root = self.metadata_root / "codeql-images" / identity
        manifest_path = root / "manifest.json"
        image_tag = f"appsec-review-codeql-cpp:{identity[:24]}"
        root.mkdir(parents=True, exist_ok=True)
        with FileLock(root / "build.lock"):
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
            command = (
                "docker", "buildx", "build", "--load", "--pull=false", "--network", "none",
                "--tag", image_tag, "--build-arg", f"CODEQL_SOURCE_IMAGE={source_tag}",
                "--build-arg", f"BUILD_IMAGE={base_tag}", "--build-arg", f"RUNTIME_USER={runtime_user}",
                "--file", str((context / "Dockerfile").resolve()), str(context.resolve()),
            )
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


class CodeQLExecutor:
    def __init__(self, *, image: CodeQLImage, run_root: Path, settings: CodeQLSettings,
                 runner: Runner | None = None) -> None:
        self.image = image
        self.run_root = run_root.resolve()
        self.settings = settings
        self.runner = runner or _run

    def execute(self, action: str, argv: Sequence[str], *, scratch_root: Path) -> CodeQLExecution:
        if action not in {"database", "query"} or any(not isinstance(value, str) or "\0" in value for value in argv):
            raise ValueError("CodeQL execution request is invalid")
        scratch = scratch_root.resolve()
        if scratch != self.run_root and self.run_root not in scratch.parents:
            raise ValueError("CodeQL scratch must be run-owned")
        scratch.mkdir(parents=True, exist_ok=True)
        scratch.chmod(0o777)
        inspected = self.runner(("docker", "image", "inspect", self.image.image_tag,
                                 "--format", "{{.Id}}"), 60)
        if inspected[3] or inspected[0] != 0 or inspected[1].decode().strip() != self.image.image_id:
            raise ValueError("CodeQL derived image identity changed")
        effective = resolve_host_bind_path(scratch, self.runner)
        timeout = (self.settings.database_timeout_seconds if action == "database" else
                   self.settings.query_timeout_seconds)
        command = [
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--user", self.image.runtime_user, "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--cpus", str(self.settings.threads),
            "--memory", f"{self.settings.ram_mb + 1024}m", "--pids-limit", "2048",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=2g", "--mount",
            f"type=bind,src={effective},dst=/scratch", "--workdir", "/scratch",
            "--env", "HOME=/tmp/codeql-home", "--env", "LANG=C.UTF-8", "--env", "LC_ALL=C.UTF-8",
            "--env", "TZ=UTC", "--entrypoint", "python3", self.image.image_id,
            "/opt/appsec/codeql_runner.py", action, *argv,
        ]
        started = _stamp()
        code, stdout, stderr, timed_out = self.runner(command, timeout)
        completed = _stamp()
        log_root = scratch / "executions" / action
        log_root.mkdir(parents=True, exist_ok=True)
        stdout_path, stderr_path = log_root / "stdout.bin", log_root / "stderr.bin"
        stdout_path.write_bytes(stdout[:self.settings.output_bytes])
        stderr_path.write_bytes(stderr[:self.settings.output_bytes])
        result = CodeQLExecution(
            EXECUTION_SCHEMA, action, self.image.image_id, self.image.image_tag,
            hashlib.sha256(canonical_json(list(argv))).hexdigest(), code, timed_out,
            started, completed, stdout_path.relative_to(self.run_root).as_posix(),
            stderr_path.relative_to(self.run_root).as_posix(), file_sha256(stdout_path),
            file_sha256(stderr_path), len(stdout) > self.settings.output_bytes,
            len(stderr) > self.settings.output_bytes,
            {"network": "none", "root_filesystem": "read-only", "user": self.image.runtime_user,
             "cap_drop": ["ALL"], "no_new_privileges": True, "threads": self.settings.threads,
             "ram_mb": self.settings.ram_mb, "timeout_seconds": timeout,
             "output_bytes": self.settings.output_bytes},
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
        size = path.stat().st_size
        total += size
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
