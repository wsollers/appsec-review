from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
from typing import Any

from appsec_review.storage import FileLock, atomic_json, bounded_file_lock, canonical_json, file_sha256
from appsec_review.config.assurance import ComponentReleases

from .build_executor import BuildProfile, Runner, _run


SCHEMA = "appsec-review/project-build-image/2"
GENERATOR_IDENTITY = "appsec-review/project-dockerfile/8"


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
    component_releases: Mapping[str, str | None] = field(default_factory=dict)
    preparation_receipt: Mapping[str, Any] | None = None


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
                            hashes: Mapping[str, str], *, releases: ComponentReleases | None = None) -> str:
    operational_recipe = {key: value for key, value in recipe.items() if key != "reason"}
    releases = releases or ComponentReleases()
    value = {
        "schema": SCHEMA, "generator": GENERATOR_IDENTITY, "recipe": operational_recipe,
        "base_image_id": profile.image_id, "dependency_hashes": hashes,
        "platform": str(recipe.get("platform", "linux")),
        "architecture": str(recipe.get("architecture", "native")),
        "component_releases": {key: releases.values.get(key)
                               for key in ("platform", "build_toolchain")},
    }
    if node_workspace_layout(recipe):
        # Only images that carry the workspace layout step change identity; every other
        # recipe keeps its cached image.
        value["node_layout"] = NODE_WORKSPACE_LAYOUT_IDENTITY
    return hashlib.sha256(canonical_json(value)).hexdigest()


def node_dependency_root(recipe: Mapping[str, Any]) -> str:
    source = PurePosixPath(str(recipe.get("source_dir", ".")))
    locks = sorted(PurePosixPath(str(value)) for value in recipe.get("dependency_files", ())
                   if PurePosixPath(str(value)).name in {
                       "package-lock.json", "pnpm-lock.yaml", "yarn.lock"})
    if not locks:
        return source.as_posix()
    parent = locks[0].parent
    return parent.as_posix()


# The build executor mounts the run-owned build workspace here (see BuildContainerExecutor).
BUILD_WORKSPACE_MOUNT = "/workspace"
NODE_WORKSPACE_LAYOUT_IDENTITY = "appsec-review/node-workspace-layout/1"
# Runs in the image after the dependency restore. It gives the built unit its own node_modules
# directory (pnpm and non-hoisted npm/Yarn installs keep member dependencies there), and
# re-points workspace links, links from node_modules into the project tree rather than into
# another package, at the build workspace: the image holds only member manifests, while the
# build workspace holds their sources and build outputs.
_NODE_WORKSPACE_LAYOUT_SCRIPT = (
    'const fs=require("fs"),path=require("path");'
    'const [project,workspace,source]=process.argv.slice(1);'
    'fs.mkdirSync(path.join(project,source,"node_modules"),{recursive:true});'
    'const relink=(link)=>{let real;try{real=fs.realpathSync(link);}catch(error){return;}'
    'const rel=path.relative(project,real);'
    'if(!rel||rel.startsWith("..")||path.isAbsolute(rel)||rel.split(path.sep).includes("node_modules"))return;'
    'fs.unlinkSync(link);fs.symlinkSync(path.join(workspace,rel),link);};'
    'const modules=(dir)=>{for(const entry of fs.readdirSync(dir,{withFileTypes:true})){'
    'const item=path.join(dir,entry.name);'
    'if(entry.isDirectory()&&entry.name.startsWith("@"))modules(item);'
    'else if(entry.isSymbolicLink())relink(item);}};'
    'const visit=(dir,depth)=>{if(depth>8)return;'
    'for(const entry of fs.readdirSync(dir,{withFileTypes:true})){'
    'if(!entry.isDirectory())continue;const item=path.join(dir,entry.name);'
    'if(entry.name==="node_modules")modules(item);else visit(item,depth+1);}};'
    'visit(project,0);'
)


def node_workspace_layout(recipe: Mapping[str, Any]) -> bool:
    """Whether a Node image restores a workspace tree (or an ancestor root) for this unit."""
    if str(recipe.get("build_system", "")) != "node" or not bool(recipe.get("network_required")):
        return False
    manifests = [value for value in recipe.get("dependency_files", ())
                 if PurePosixPath(str(value)).name == "package.json"]
    source = PurePosixPath(str(recipe.get("source_dir", "."))).as_posix()
    return len(manifests) > 1 or node_dependency_root(recipe) != source


def node_workspace_layout_command(recipe: Mapping[str, Any]) -> tuple[str, ...]:
    source = PurePosixPath(str(recipe.get("source_dir", "."))).as_posix()
    return ("node", "-e", _NODE_WORKSPACE_LAYOUT_SCRIPT, "/opt/project", BUILD_WORKSPACE_MOUNT, source)


# Package managers a repair may select because the family build image already pins them
# (containers/buildenv/typescript installs Node.js 22.23.3 with its bundled npm, pnpm 9.15.9 and
# Yarn 1.22.22). Other families pin exactly one manager, so there is nothing to select.
PINNED_PACKAGE_MANAGERS: dict[str, dict[str, str]] = {
    "node": {"npm": "bundled with Node.js 22.23.3", "pnpm": "9.15.9", "yarn": "1.22.22"},
}
_NODE_LOCKS = {"package-lock.json": "npm", "pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn"}
_REPAIR_ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_REPAIR_ENV_VALUE = re.compile(r"^[A-Za-z0-9._=,:+/ -]{1,512}$")


def _image_repairs(recipe: Mapping[str, Any]) -> Mapping[str, Any]:
    value = recipe.get("image_repairs")
    return value if isinstance(value, Mapping) else {}


def _node_lockless_manager(recipe: Mapping[str, Any]) -> str:
    selected = _image_repairs(recipe).get("package_manager")
    if selected is not None:
        return str(selected)
    commands = [*recipe.get("configure_commands", ()), *recipe.get("build_commands", ())]
    managers = {PurePosixPath(str(argv[0])).name for argv in commands
                if isinstance(argv, list) and argv} & {"npm", "pnpm", "yarn"}
    if len(managers) > 1:
        raise ValueError("Node dependency restore accepts one package manager")
    return next(iter(managers), "npm")


def restore_manager(build_system: str, recipe: Mapping[str, Any], manifest: str) -> str | None:
    """The family package manager that restores ``manifest`` into the image, or ``None``.

    Only manifests whose dependencies land where the later build reads them qualify: the shared
    pip target, Cargo home, Go module cache, Maven repository, Gradle cache, and NuGet folder for
    any accepted manifest; the single Node and Composer dependency roots for those families.
    """
    path = PurePosixPath(manifest)
    name = path.name
    accepted = {str(value) for value in recipe.get("dependency_files", ())}
    if build_system == "python":
        return "pip" if re.fullmatch(r"requirements[A-Za-z0-9_.-]*\.txt", name) else None
    if build_system == "node":
        if name not in {"package.json", *_NODE_LOCKS} or (
                path.parent.as_posix() != node_dependency_root(recipe)):
            return None
        locks = [lock for lock in _NODE_LOCKS if (path.parent / lock).as_posix() in accepted]
        if len(locks) > 1:
            return None
        return _NODE_LOCKS[locks[0]] if locks else _node_lockless_manager(recipe)
    if build_system == "cargo":
        return "cargo" if name == "Cargo.toml" else None
    if build_system == "go":
        return "go" if name in {"go.mod", "go.work"} else None
    if build_system == "maven":
        return "mvn" if name == "pom.xml" else None
    if build_system == "gradle":
        return "gradle" if name in {"build.gradle", "build.gradle.kts", "settings.gradle",
                                    "settings.gradle.kts"} else None
    if build_system == "dotnet":
        return "dotnet" if path.suffix in {".csproj", ".fsproj", ".vbproj", ".sln"} else None
    if build_system == "composer":
        return ("composer" if name == "composer.json" and
                path.parent.as_posix() == PurePosixPath(str(recipe.get("source_dir", "."))).as_posix()
                else None)
    return None


def repair_restore_commands(recipe: Mapping[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    """Render each typed repair restore as ``(working directory, argv)``; no free-form text."""
    restores = _image_repairs(recipe).get("dependency_restores", ())
    if not isinstance(restores, (list, tuple)) or len(restores) > 8:
        raise ValueError("image repair dependency restores are invalid")
    build_system = str(recipe.get("build_system", ""))
    accepted = {str(value) for value in recipe.get("dependency_files", ())}
    result = []
    for item in restores:
        manifest = str(item.get("manifest", "")) if isinstance(item, Mapping) else ""
        path = PurePosixPath(manifest)
        if (manifest not in accepted or not path.parts or path.is_absolute() or ".." in path.parts):
            raise ValueError(f"image repair restore manifest is not accepted: {manifest[:512]}")
        manager = restore_manager(build_system, recipe, manifest)
        if manager is None or manager != item.get("manager"):
            raise ValueError(f"image repair restore manager is invalid for {manifest[:512]}")
        directory = "/opt/project" if path.parent.as_posix() == "." else f"/opt/project/{path.parent}"
        name = path.name
        if manager == "pip":
            argv: tuple[str, ...] = ("python", "-m", "pip", "install", "--target", "/opt/project-deps",
                                     "-r", name)
        elif build_system == "node":
            locked = any((path.parent / lock).as_posix() in accepted for lock in _NODE_LOCKS)
            argv = {("npm", True): ("npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"),
                    ("npm", False): ("npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"),
                    ("pnpm", True): ("pnpm", "install", "--frozen-lockfile", "--ignore-scripts"),
                    ("pnpm", False): ("pnpm", "install", "--no-frozen-lockfile", "--ignore-scripts"),
                    ("yarn", True): ("yarn", "install", "--frozen-lockfile", "--ignore-scripts",
                                     "--non-interactive"),
                    ("yarn", False): ("yarn", "install", "--ignore-scripts", "--non-interactive"),
                    }[(manager, locked)]
        elif manager == "cargo":
            locked = (path.parent / "Cargo.lock").as_posix() in accepted
            argv = ("cargo", "fetch", "--locked") if locked else ("cargo", "fetch")
        elif manager == "go":
            argv = ("go", "mod", "download")
        elif manager == "mvn":
            argv = ("mvn", "-B", "-DskipTests", "-f", name, "dependency:go-offline")
        elif manager == "gradle":
            argv = ("gradle", "--no-daemon", "dependencies")
        elif manager == "dotnet":
            argv = ("dotnet", "restore", name)
        else:
            argv = ("composer", "install", "--no-interaction", "--no-scripts", "--no-plugins",
                    "--prefer-dist", "--no-progress")
        result.append((directory, argv))
    return result


def repair_environment(recipe: Mapping[str, Any]) -> dict[str, str]:
    """The validated repair environment the image carries (set before any restore runs)."""
    value = _image_repairs(recipe).get("environment", {})
    if not isinstance(value, Mapping) or len(value) > 16:
        raise ValueError("image repair environment is invalid")
    for key, item in value.items():
        if not isinstance(key, str) or not _REPAIR_ENV_KEY.fullmatch(key) or not isinstance(
                item, str) or not _REPAIR_ENV_VALUE.fullmatch(item):
            raise ValueError("image repair environment is invalid")
    return {str(key): str(item) for key, item in sorted(value.items())}


def _cargo_placeholder_dirs(recipe: Mapping[str, Any]) -> list[str]:
    directories = set()
    if str(recipe.get("build_system", "")) != "cargo":
        return []
    if bool(recipe.get("network_required")):
        directories.add(PurePosixPath(str(recipe["source_dir"])).as_posix())
    for directory, argv in repair_restore_commands(recipe):
        if argv[0] == "cargo":
            relative = directory[len("/opt/project"):].lstrip("/")
            directories.add(relative or ".")
    return sorted(directories)


def _restore_command(recipe: Mapping[str, Any]) -> tuple[str, ...] | None:
    system = str(recipe.get("build_system", ""))
    files = {PurePosixPath(str(value)).name for value in recipe.get("dependency_files", ())}
    if system == "cargo":
        return ("cargo", "fetch", "--locked") if "Cargo.lock" in files else ("cargo", "fetch")
    if system == "go":
        return ("go", "mod", "download")
    if system == "maven":
        # Execute the clean lifecycle while the image is writable so Maven also resolves the
        # (occasionally very old) clean-plugin dependencies needed by the later immutable build.
        return ("mvn", "-B", "-DskipTests", "clean", "dependency:go-offline")
    if system == "gradle":
        return ("gradle", "--no-daemon", "dependencies")
    if system == "dotnet":
        return ("dotnet", "restore")
    if system == "node":
        locks = files & {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
        if len(locks) > 1:
            raise ValueError("Node dependency restore accepts at most one supported lockfile")
        if not locks:
            manager = _node_lockless_manager(recipe)
            if manager == "pnpm":
                return ("pnpm", "install", "--no-frozen-lockfile", "--ignore-scripts")
            if manager == "yarn":
                return ("yarn", "install", "--ignore-scripts", "--non-interactive")
            return ("npm", "install", "--ignore-scripts", "--no-audit", "--no-fund")
        dependency_root = node_dependency_root(recipe)
        source_dir = str(recipe.get("source_dir", "."))
        prefix = "/opt/project" if dependency_root == "." else f"/opt/project/{dependency_root}"
        if "package-lock.json" in locks:
            leading = ("npm",) if dependency_root == source_dir else ("npm", "--prefix", prefix)
            return (*leading, "ci", "--ignore-scripts", "--no-audit", "--no-fund")
        if "pnpm-lock.yaml" in locks:
            leading = ("pnpm",) if dependency_root == source_dir else ("pnpm", "--dir", prefix)
            return (*leading, "install", "--frozen-lockfile", "--ignore-scripts")
        leading = ("yarn",) if dependency_root == source_dir else ("yarn", "--cwd", prefix)
        return (*leading, "install", "--frozen-lockfile", "--ignore-scripts", "--non-interactive")
    if system == "composer":
        return ("composer", "install", "--no-interaction", "--no-scripts", "--no-plugins",
                "--prefer-dist", "--no-progress")
    source = PurePosixPath(str(recipe.get("source_dir", ".")))
    requirements = sorted(
        (PurePosixPath(str(value)) for value in recipe.get("dependency_files", ())
         if PurePosixPath(str(value)).name.startswith("requirements") and
         PurePosixPath(str(value)).name.endswith(".txt")), key=lambda value: value.as_posix())
    if system == "python" and requirements:
        # Every accepted requirements file (for example requirements-build.txt pinning the
        # build backend) is restored; the image WORKDIR is the source directory.
        arguments: list[str] = []
        for value in requirements:
            if source.as_posix() == ".":
                path = value.as_posix()
            elif source in value.parents:
                path = value.relative_to(source).as_posix()
            else:
                path = "/opt/project/" + value.as_posix()
            arguments.extend(("-r", path))
        return ("python", "-m", "pip", "install", "--target", "/opt/project-deps", *arguments)
    return None


def project_dependency_environment(recipe: Mapping[str, Any]) -> dict[str, str]:
    """Expose dependency caches to later build containers."""
    system = str(recipe.get("build_system", ""))
    node_root = node_dependency_root(recipe) if system == "node" else str(recipe["source_dir"])
    node_source = "/opt/project" if node_root == "." else f"/opt/project/{node_root}"
    environments = {
        "cargo": {"CARGO_HOME": "/opt/project-deps/cargo"},
        "go": {"GOMODCACHE": "/opt/project-deps/go"},
        "maven": {"MAVEN_OPTS": "-Dmaven.repo.local=/opt/project-deps/maven"},
        "gradle": {"GRADLE_USER_HOME": "/opt/project-deps/gradle"},
        "dotnet": {"NUGET_PACKAGES": "/opt/project-deps/nuget"},
        "node": {"NPM_CONFIG_CACHE": "/opt/project-deps/npm-cache",
                 "PNPM_STORE_DIR": "/opt/project-deps/pnpm-store",
                 "YARN_CACHE_FOLDER": "/opt/project-deps/yarn-cache",
                 "NODE_PATH": f"{node_source}/node_modules",
                 "PATH": f"{node_source}/node_modules/.bin:$PATH"},
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
                 output_bytes: int = 8 * 1024 * 1024, runner: Runner | None = None,
                 releases: ComponentReleases | None = None, run_root: Path | None = None) -> None:
        self.metadata_root = metadata_root
        self.target_root = target_root
        self.timeout_seconds = timeout_seconds
        self.output_bytes = output_bytes
        self.runner = runner or _run
        self.releases = releases or ComponentReleases()
        self.cache_namespace = hashlib.sha256(str((run_root or target_root).resolve()).encode()).hexdigest()[:24]

    def _inspect(self, reference: str) -> str | None:
        code, stdout, _stderr, timed_out = self.runner(
            ("docker", "image", "inspect", reference, "--format", "{{.Id}}"), 60)
        value = stdout.decode("utf-8", "replace").strip()
        return value if not timed_out and code == 0 and value.startswith("sha256:") else None

    def definition(self, recipe: Mapping[str, Any], profile: BuildProfile) -> tuple[str, bytes]:
        """Return identity and baseline Dockerfile; bounded builds bind FROM to a private immutable alias."""
        hashes = dependency_hashes(self.target_root, recipe)
        return self._definition(recipe, profile, hashes)

    def _definition(self, recipe: Mapping[str, Any], profile: BuildProfile,
                    hashes: Mapping[str, str]) -> tuple[str, bytes]:
        identity = project_recipe_identity(recipe, profile, hashes, releases=self.releases)
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
        for directory in _cargo_placeholder_dirs(recipe):
            # Cargo validates that a manifest has a target before it will fetch dependencies.
            # Project images intentionally contain descriptors only, so provide a harmless
            # image-local target. The real source tree replaces this path in the build workspace.
            prefix = "" if directory == "." else directory + "/"
            lines.append("COPY --chown=" + profile.user + " " + json.dumps(
                ["cargo-placeholder.rs", f"/opt/project/{prefix}src/main.rs"],
                separators=(",", ":")))
        lines.extend((_json_instruction("RUN", ("chown", "-R", f"{uid}:{gid}",
                                                   "/opt/project", "/opt/project-home",
                                                   "/opt/project-deps")),
                      f"USER {profile.user}", "ENV HOME=/opt/project-home"))
        for key, value in sorted(project_dependency_environment(recipe).items()):
            lines.append(f"ENV {key}={value}")
        # Typed image-repair environment precedes every restore, so it governs them too.
        for key, value in repair_environment(recipe).items():
            lines.append(f"ENV {key}={json.dumps(value)}")
        workdir = f"WORKDIR /opt/project/{recipe['source_dir']}"
        lines.append(workdir)
        restore = _restore_command({**recipe, "build_system": recipe.get("build_system")})
        if bool(recipe.get("network_required")):
            if restore is None:
                raise ValueError("network-required recipe has no supported deterministic dependency restore")
            lines.append(_json_instruction("RUN", restore))
        repair_restores = repair_restore_commands(recipe)
        for directory, argv in repair_restores:
            lines.extend((f"WORKDIR {directory}", _json_instruction("RUN", argv)))
        if node_workspace_layout(recipe):
            lines.append(_json_instruction("RUN", node_workspace_layout_command(recipe)))
        if repair_restores:
            lines.append(workdir)
        return identity, ("\n".join(lines) + "\n").encode("utf-8")

    def resolve(self, recipe: Mapping[str, Any], profile: BuildProfile) -> tuple[ProjectImage, bytes, bytes]:
        from .image_builder import bounded_image_preparation, builder_namespace, verify_builder_receipt
        from appsec_review.storage.shared import safe_path
        hashes = dependency_hashes(self.target_root, recipe)
        identity, dockerfile = self._definition(recipe, profile, hashes)
        customized = (bool(recipe.get("system_packages")) or bool(recipe.get("network_required")) or
                      bool(recipe.get("image_repairs")))
        if self._inspect(profile.tag) != profile.image_id:
            raise ValueError(f"base build image identity changed: {profile.name}")
        if not customized:
            return ProjectImage(SCHEMA, identity, profile.name, profile.image_id, profile.tag,
                                profile.image_id, None, False, False, hashes,
                                cache_disposition="NOT_APPLICABLE"), b"", b""
        namespace = builder_namespace() or self.cache_namespace
        cache_root = self.metadata_root / "project-images" / namespace / identity
        manifest_path = cache_root / "manifest.json"
        tag = f"appsec-review-project-{profile.name}:{namespace[:12]}{identity[:12]}"
        cache_root.mkdir(parents=True, exist_ok=True)
        with FileLock(cache_root / "build.lock"):
            reusable, rejection_reason = self.releases.require("platform", "build_toolchain")
            declarations = {key: self.releases.values.get(key) for key in ("platform", "build_toolchain")}
            if reusable and manifest_path.is_file():
                try:
                    value = json.loads(manifest_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    value = {}
                image_id = self._inspect(tag)
                retained_definition = (safe_path(self.metadata_root, value["dockerfile_path"])
                                       if isinstance(value.get("dockerfile_path"), str)
                                       else cache_root / "context" / "Dockerfile")
                if (value.get("schema") == SCHEMA and value.get("recipe_identity") == identity and
                        image_id == value.get("image_id") and retained_definition.is_file() and
                        not retained_definition.is_symlink() and value.get("component_releases") == declarations):
                    if builder_namespace() is not None:
                        verify_builder_receipt(value["preparation_receipt"], identity=identity, tag=tag,
                                               image_id=image_id)
                    return ProjectImage(**{**value, "reused": True,
                                           "cache_disposition": "HIT",
                                           "cache_rejection_reason": None,
                                           "saved_build_count": 1}), b"", b""
                rejection_reason = ("image_missing_or_changed" if image_id != value.get("image_id") else
                                    "dockerfile_unavailable" if not retained_definition.is_file() or
                                    retained_definition.is_symlink() else
                                    "manifest_identity_mismatch")
            from appsec_review.runtime.resources import require_bounded_image_builder
            require_bounded_image_builder()
            with bounded_image_preparation(identity=identity, tag=tag,
                                           timeout_seconds=self.timeout_seconds) as builder:
                context = builder.context if builder is not None else cache_root / "context"
                if builder is None and context.exists():
                    shutil.rmtree(context)
                inputs = context / "inputs"
                inputs.mkdir(parents=True)
                for ordinal, relative in enumerate(sorted(hashes)):
                    source = _safe_dependency(self.target_root, relative)
                    staged = inputs / f"{ordinal:04d}"
                    shutil.copyfile(source, staged)
                if _cargo_placeholder_dirs(recipe):
                    (context / "cargo-placeholder.rs").write_text("fn main() {}\n", encoding="utf-8")
                dockerfile_path = context / "Dockerfile"
                if builder is not None:
                    base_alias = f"appsec-review-project-base:{namespace[:12]}{profile.image_id[7:31]}"
                    bound_dockerfile = (f"FROM {base_alias}\n".encode() + dockerfile.partition(b"\n")[2])
                    dockerfile_path.write_bytes(bound_dockerfile)
                    code, stdout, stderr, timed_out = builder.build(
                        network="default", image_inputs={base_alias: profile.image_id})
                else:
                    dockerfile_path.write_bytes(dockerfile)
                    build_context = context.resolve()
                    with bounded_file_lock(self.metadata_root / "project-images" / "docker-build.lock",
                                           self.timeout_seconds):
                        code, stdout, stderr, timed_out = self.runner((
                            "docker", "buildx", "build", "--load", "--pull=false", "--network", "default", "--tag", tag,
                            "--file", str(build_context / "Dockerfile"), str(build_context)), self.timeout_seconds)
            if timed_out or code != 0:
                raise ProjectImageBuildError(
                    "project build image creation timed out" if timed_out else
                    f"project build image creation exited {code}",
                    stdout=stdout[:self.output_bytes], stderr=stderr[:self.output_bytes])
            image_id = self._inspect(tag)
            if image_id is None:
                raise RuntimeError("project build image was not resolvable after creation")
            if builder is not None and image_id != builder.output_image_id:
                raise ValueError("bounded builder output image differs from local image binding")
            value = asdict(ProjectImage(SCHEMA, identity, profile.name, profile.image_id, tag,
                                        image_id, None, True,
                                        False, hashes,
                                        manifest_path.relative_to(self.metadata_root).as_posix(),
                                        dockerfile_path.relative_to(self.metadata_root).as_posix(),
                                        "REJECTED" if rejection_reason else "MISS", rejection_reason, 0,
                                        declarations, builder.receipt() if builder is not None else None))
            atomic_json(manifest_path, value)
            return ProjectImage(**value), stdout[:self.output_bytes], stderr[:self.output_bytes]
