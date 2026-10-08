from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import time
from typing import Any

from appsec_review.storage import FileLock, LockUnavailable, atomic_json, canonical_json, file_sha256

from .build_executor import BuildProfile, Runner, _run


SCHEMA = "appsec-review/project-build-image/1"
GENERATOR_IDENTITY = "appsec-review/project-dockerfile/4"


class ProjectImageBuildError(RuntimeError):
    """A bounded, artifact-safe record of a failed project image build."""

    def __init__(self, message: str, *, stdout: bytes = b"", stderr: bytes = b"") -> None:
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr


@dataclass(frozen=True, slots=True)
class ProjectImage:
    schema: str
    recipe_identity: str
    family: str
    base_image_id: str
    image_tag: str
    image_id: str
    dockerfile_sha256: str | None
    customized: bool
    reused: bool
    dependency_hashes: Mapping[str, str]
    manifest_path: str | None = None


def _safe_dependency(target_root: Path, relative: str) -> Path:
    logical = PurePosixPath(relative)
    if not logical.parts or logical.is_absolute() or ".." in logical.parts:
        raise ValueError("dependency file path is not normalized")
    target = target_root.resolve(strict=True)
    path = (target / Path(*logical.parts)).resolve(strict=True)
    if target not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError("dependency file is unavailable or outside the target")
    return path


def dependency_hashes(target_root: Path, recipe: Mapping[str, Any]) -> dict[str, str]:
    return {str(relative): file_sha256(_safe_dependency(target_root, str(relative)))
            for relative in sorted(recipe.get("dependency_files", ())) }


def project_recipe_identity(recipe: Mapping[str, Any], profile: BuildProfile,
                            hashes: Mapping[str, str]) -> str:
    operational_recipe = {key: value for key, value in recipe.items() if key != "reason"}
    return hashlib.sha256(canonical_json({
        "schema": SCHEMA, "generator": GENERATOR_IDENTITY, "recipe": operational_recipe,
        "base_image_id": profile.image_id, "dependency_hashes": hashes,
    })).hexdigest()


def _restore_command(recipe: Mapping[str, Any]) -> tuple[str, ...] | None:
    system = str(recipe.get("build_system", ""))
    files = {PurePosixPath(str(value)).name for value in recipe.get("dependency_files", ())}
    if system == "cargo":
        return ("cargo", "fetch", "--locked") if "Cargo.lock" in files else ("cargo", "fetch")
    if system == "go":
        return ("go", "mod", "download")
    if system == "maven":
        return ("mvn", "-B", "dependency:go-offline", "-DskipTests")
    if system == "gradle":
        return ("gradle", "--no-daemon", "dependencies")
    if system == "dotnet":
        return ("dotnet", "restore")
    if system == "node":
        return ("npm", "ci", "--ignore-scripts") if "package-lock.json" in files else ("npm", "install", "--ignore-scripts")
    if system == "composer":
        return ("composer", "install", "--no-interaction", "--no-scripts", "--prefer-dist")
    requirements = sorted(name for name in files if name.startswith("requirements") and name.endswith(".txt"))
    if system == "python" and requirements:
        return ("python", "-m", "pip", "install", "--target", "/opt/project-deps", "-r", requirements[0])
    return None


def project_dependency_environment(recipe: Mapping[str, Any]) -> dict[str, str]:
    """Expose immutable dependency caches to later network-disabled build containers."""
    system = str(recipe.get("build_system", ""))
    source = f"/opt/project/{recipe['source_dir']}"
    environments = {
        "cargo": {"CARGO_HOME": "/opt/project-deps/cargo"},
        "go": {"GOMODCACHE": "/opt/project-deps/go"},
        "maven": {"MAVEN_OPTS": "-Dmaven.repo.local=/opt/project-deps/maven"},
        "gradle": {"GRADLE_USER_HOME": "/opt/project-deps/gradle"},
        "dotnet": {"NUGET_PACKAGES": "/opt/project-deps/nuget"},
        "node": {"NPM_CONFIG_CACHE": "/opt/project-deps/npm-cache",
                 "NODE_PATH": f"{source}/node_modules",
                 "PATH": f"{source}/node_modules/.bin:$PATH"},
        "composer": {"COMPOSER_HOME": "/opt/project-deps/composer-home",
                     "COMPOSER_VENDOR_DIR": "/opt/project-deps/composer-vendor"},
        "python": {"PYTHONPATH": "/opt/project-deps"},
    }
    return environments.get(system, {})


def _json_instruction(name: str, argv: Sequence[str]) -> str:
    return name + " " + json.dumps(list(argv), ensure_ascii=True, separators=(",", ":"))


@contextmanager
def _bounded_lock(path: Path, timeout_seconds: int):
    lock = FileLock(path)
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            lock.__enter__()
            break
        except LockUnavailable:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)
    try:
        yield
    finally:
        lock.__exit__(None, None, None)


class ProjectImageResolver:
    """Generate or reuse a dependency-bearing image derived from a pinned language baseline."""

    def __init__(self, *, metadata_root: Path, target_root: Path, timeout_seconds: int = 1800,
                 output_bytes: int = 8 * 1024 * 1024, runner: Runner | None = None) -> None:
        self.metadata_root = metadata_root
        self.target_root = target_root
        self.timeout_seconds = timeout_seconds
        self.output_bytes = output_bytes
        self.runner = runner or _run

    def _inspect(self, reference: str) -> str | None:
        code, stdout, _stderr, timed_out = self.runner(
            ("docker", "image", "inspect", reference, "--format", "{{.Id}}"), 60)
        value = stdout.decode("utf-8", "replace").strip()
        return value if not timed_out and code == 0 and value.startswith("sha256:") else None

    def resolve(self, recipe: Mapping[str, Any], profile: BuildProfile) -> tuple[ProjectImage, bytes, bytes]:
        hashes = dependency_hashes(self.target_root, recipe)
        identity = project_recipe_identity(recipe, profile, hashes)
        customized = bool(recipe.get("system_packages")) or bool(recipe.get("network_required"))
        if not customized:
            if self._inspect(profile.tag) != profile.image_id:
                raise ValueError(f"base build image identity changed: {profile.name}")
            return ProjectImage(SCHEMA, identity, profile.name, profile.image_id, profile.tag,
                                profile.image_id, None, False, True, hashes), b"", b""
        cache_root = self.metadata_root / "project-images" / identity
        manifest_path = cache_root / "manifest.json"
        tag = f"appsec-review-project-{profile.name}:{identity[:24]}"
        cache_root.mkdir(parents=True, exist_ok=True)
        with FileLock(cache_root / "build.lock"):
            if manifest_path.is_file():
                value = json.loads(manifest_path.read_text(encoding="utf-8"))
                image_id = self._inspect(tag)
                if (value.get("schema") == SCHEMA and value.get("recipe_identity") == identity and
                        image_id == value.get("image_id")):
                    return ProjectImage(**{**value, "reused": True}), b"", b""
            context = cache_root / "context"
            if context.exists():
                shutil.rmtree(context)
            inputs = context / "inputs"
            inputs.mkdir(parents=True)
            copies: list[tuple[str, str]] = []
            for ordinal, relative in enumerate(sorted(hashes)):
                source = _safe_dependency(self.target_root, relative)
                staged = inputs / f"{ordinal:04d}"
                shutil.copyfile(source, staged)
                copies.append((staged.relative_to(context).as_posix(), f"/opt/project/{relative}"))
            uid, gid = profile.user.split(":", 1)
            # The tag is verified against the configured immutable image ID before use.
            # BuildKit treats a bare `sha256:<image-id>` in FROM as a registry name.
            lines = [f"FROM {profile.tag}", "USER 0:0",
                     _json_instruction("RUN", ("mkdir", "-p", "/opt/project", "/opt/project-home", "/opt/project-deps"))]
            packages = tuple(str(value) for value in recipe.get("system_packages", ()))
            if packages:
                lines.extend((_json_instruction("RUN", ("apt-get", "update")),
                              _json_instruction("RUN", ("apt-get", "install", "-y", "--no-install-recommends", *packages)),
                              _json_instruction("RUN", ("rm", "-rf", "/var/lib/apt/lists"))))
            for source, destination in copies:
                lines.append("COPY --chown=" + profile.user + " " +
                             json.dumps([source, destination], separators=(",", ":")))
            lines.extend((_json_instruction("RUN", ("chown", "-R", f"{uid}:{gid}",
                                                       "/opt/project", "/opt/project-home", "/opt/project-deps")),
                          f"USER {profile.user}", "ENV HOME=/opt/project-home"))
            for key, value in sorted(project_dependency_environment(recipe).items()):
                lines.append(f"ENV {key}={value}")
            lines.append(f"WORKDIR /opt/project/{recipe['source_dir']}")
            restore = _restore_command({**recipe, "build_system": recipe.get("build_system")})
            if bool(recipe.get("network_required")):
                if restore is None:
                    raise ValueError("network-required recipe has no supported deterministic dependency restore")
                lines.append(_json_instruction("RUN", restore))
            dockerfile = ("\n".join(lines) + "\n").encode("utf-8")
            dockerfile_path = context / "Dockerfile"
            dockerfile_path.write_bytes(dockerfile)
            # `docker buildx build` reads and uploads its context in the CLI process. Unlike a
            # sibling `docker run --mount`, this path must therefore remain in the code
            # container's namespace rather than being translated into the daemon host's
            # namespace.
            build_context = context.resolve()
            network = "default" if recipe.get("network_required") or packages else "none"
            # Docker Desktop may expose only the legacy builder inside the code location.
            # Its layer commits are not reliably concurrent, so serialize only this narrow
            # daemon mutation while the surrounding family DAG remains parallel.
            with _bounded_lock(self.metadata_root / "project-images" / "docker-build.lock",
                               self.timeout_seconds):
                code, stdout, stderr, timed_out = self.runner((
                    "docker", "buildx", "build", "--load", "--pull=false", "--network", network, "--tag", tag,
                    "--file", str(build_context / "Dockerfile"), str(build_context)), self.timeout_seconds)
            if timed_out or code != 0:
                raise ProjectImageBuildError(
                    "project build image creation timed out" if timed_out else
                    f"project build image creation exited {code}",
                    stdout=stdout[:self.output_bytes], stderr=stderr[:self.output_bytes])
            image_id = self._inspect(tag)
            if image_id is None:
                raise RuntimeError("project build image was not resolvable after creation")
            value = asdict(ProjectImage(SCHEMA, identity, profile.name, profile.image_id, tag,
                                        image_id, hashlib.sha256(dockerfile).hexdigest(), True,
                                        False, hashes,
                                        manifest_path.relative_to(self.metadata_root).as_posix()))
            atomic_json(manifest_path, value)
            return ProjectImage(**value), stdout[:self.output_bytes], stderr[:self.output_bytes]
