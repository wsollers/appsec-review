from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
from typing import Any

from appsec_review.storage import FileLock, atomic_json, bounded_file_lock, canonical_json, file_sha256

from .build_executor import BuildProfile, Runner, _run


SCHEMA = "appsec-review/project-build-image/1"
GENERATOR_IDENTITY = "appsec-review/project-dockerfile/5"


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
    dockerfile_path: str | None = None
    cache_disposition: str = "MISS"
    cache_rejection_reason: str | None = None
    saved_build_count: int = 0


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
        "platform": str(recipe.get("platform", "linux")),
        "architecture": str(recipe.get("architecture", "native")),
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
        locks = files & {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
        if len(locks) != 1:
            raise ValueError("Node dependency restore requires exactly one supported lockfile")
        if "package-lock.json" in locks:
            return ("npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund")
        if "pnpm-lock.yaml" in locks:
            return ("pnpm", "install", "--frozen-lockfile", "--ignore-scripts")
        return ("yarn", "install", "--frozen-lockfile", "--ignore-scripts", "--non-interactive")
    if system == "composer":
        files = {PurePosixPath(str(value)).name for value in recipe.get("dependency_files", ())}
        if "composer.lock" not in files:
            raise ValueError("Composer dependency restore requires composer.lock")
        return ("composer", "install", "--no-interaction", "--no-scripts", "--no-plugins",
                "--prefer-dist", "--no-progress")
    requirements = sorted(name for name in files if name.startswith("requirements") and name.endswith(".txt"))
    if system == "python" and requirements:
        return ("python", "-m", "pip", "install", "--require-hashes", "--target",
                "/opt/project-deps", "-r", requirements[0])
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
                 "PNPM_STORE_DIR": "/opt/project-deps/pnpm-store",
                 "YARN_CACHE_FOLDER": "/opt/project-deps/yarn-cache",
                 "NODE_PATH": f"{source}/node_modules",
                 "PATH": f"{source}/node_modules/.bin:$PATH"},
        "composer": {"COMPOSER_HOME": "/opt/project-deps/composer-home",
                     "COMPOSER_VENDOR_DIR": "/opt/project-deps/composer-vendor"},
        "python": {"PYTHONPATH": "/opt/project-deps"},
    }
    return environments.get(system, {})


def _json_instruction(name: str, argv: Sequence[str]) -> str:
    return name + " " + json.dumps(list(argv), ensure_ascii=True, separators=(",", ":"))


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

    def definition(self, recipe: Mapping[str, Any], profile: BuildProfile) -> tuple[str, bytes]:
        """Return the exact identity and Dockerfile used for this recipe without mutating Docker."""
        hashes = dependency_hashes(self.target_root, recipe)
        identity = project_recipe_identity(recipe, profile, hashes)
        uid, gid = profile.user.split(":", 1)
        lines = [f"FROM {profile.tag}", "USER 0:0",
                 _json_instruction("RUN", ("mkdir", "-p", "/opt/project", "/opt/project-home",
                                             "/opt/project-deps"))]
        packages = tuple(str(value) for value in recipe.get("system_packages", ()))
        if packages:
            lines.extend((_json_instruction("RUN", ("apt-get", "update")),
                          _json_instruction("RUN", ("apt-get", "install", "-y",
                                                    "--no-install-recommends", *packages)),
                          _json_instruction("RUN", ("rm", "-rf", "/var/lib/apt/lists"))))
        for ordinal, relative in enumerate(sorted(hashes)):
            lines.append("COPY --chown=" + profile.user + " " + json.dumps(
                [f"inputs/{ordinal:04d}", f"/opt/project/{relative}"], separators=(",", ":")))
        lines.extend((_json_instruction("RUN", ("chown", "-R", f"{uid}:{gid}",
                                                   "/opt/project", "/opt/project-home",
                                                   "/opt/project-deps")),
                      f"USER {profile.user}", "ENV HOME=/opt/project-home"))
        for key, value in sorted(project_dependency_environment(recipe).items()):
            lines.append(f"ENV {key}={value}")
        lines.append(f"WORKDIR /opt/project/{recipe['source_dir']}")
        restore = _restore_command({**recipe, "build_system": recipe.get("build_system")})
        if bool(recipe.get("network_required")):
            if restore is None:
                raise ValueError("network-required recipe has no supported deterministic dependency restore")
            lines.append(_json_instruction("RUN", restore))
        return identity, ("\n".join(lines) + "\n").encode("utf-8")

    def resolve(self, recipe: Mapping[str, Any], profile: BuildProfile) -> tuple[ProjectImage, bytes, bytes]:
        hashes = dependency_hashes(self.target_root, recipe)
        identity, dockerfile = self.definition(recipe, profile)
        customized = bool(recipe.get("system_packages")) or bool(recipe.get("network_required"))
        if self._inspect(profile.tag) != profile.image_id:
            raise ValueError(f"base build image identity changed: {profile.name}")
        if not customized:
            return ProjectImage(SCHEMA, identity, profile.name, profile.image_id, profile.tag,
                                profile.image_id, None, False, True, hashes,
                                cache_disposition="HIT", saved_build_count=1), b"", b""
        cache_root = self.metadata_root / "project-images" / identity
        manifest_path = cache_root / "manifest.json"
        tag = f"appsec-review-project-{profile.name}:{identity[:24]}"
        cache_root.mkdir(parents=True, exist_ok=True)
        with FileLock(cache_root / "build.lock"):
            rejection_reason = None
            if manifest_path.is_file():
                try:
                    value = json.loads(manifest_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    value = {}
                image_id = self._inspect(tag)
                retained_definition = cache_root / "context" / "Dockerfile"
                if (value.get("schema") == SCHEMA and value.get("recipe_identity") == identity and
                        image_id == value.get("image_id") and retained_definition.is_file() and
                        not retained_definition.is_symlink() and
                        file_sha256(retained_definition) == value.get("dockerfile_sha256")):
                    return ProjectImage(**{**value, "reused": True,
                                           "cache_disposition": "HIT",
                                           "cache_rejection_reason": None,
                                           "saved_build_count": 1}), b"", b""
                rejection_reason = ("image_missing_or_changed" if image_id != value.get("image_id") else
                                    "dockerfile_missing_or_changed" if not retained_definition.is_file() or
                                    retained_definition.is_symlink() or
                                    file_sha256(retained_definition) != value.get("dockerfile_sha256") else
                                    "manifest_identity_mismatch")
            context = cache_root / "context"
            if context.exists():
                shutil.rmtree(context)
            inputs = context / "inputs"
            inputs.mkdir(parents=True)
            for ordinal, relative in enumerate(sorted(hashes)):
                source = _safe_dependency(self.target_root, relative)
                staged = inputs / f"{ordinal:04d}"
                shutil.copyfile(source, staged)
            packages = tuple(str(value) for value in recipe.get("system_packages", ()))
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
            with bounded_file_lock(self.metadata_root / "project-images" / "docker-build.lock",
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
                                        manifest_path.relative_to(self.metadata_root).as_posix(),
                                        dockerfile_path.relative_to(self.metadata_root).as_posix(),
                                        "REJECTED" if rejection_reason else "MISS", rejection_reason, 0))
            atomic_json(manifest_path, value)
            return ProjectImage(**value), stdout[:self.output_bytes], stderr[:self.output_bytes]
