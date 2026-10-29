"""Real-Docker helpers shared by the derived CodeQL runtime integration tests.

This is not a test module. ``tests/integration/test_codeql_derived_*.py`` import it, and
``tests/conftest.py`` keeps those modules out of implicit collection unless their paths are
selected explicitly.

The helpers drive the production resolver and executor (``appsec_review.codeql.runtime``) against
the shipped ``appsec-review.toml`` without modifying its declarations. Profile pins are host-specific
build results, so each profile resolves at the identity of its locally built tag: an environment
counts as declared only when that local identity equals a shipped declaration.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
import json
from pathlib import Path
import shutil
import socket
import subprocess
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4
import zipfile

import pytest

from appsec_review.codeql.runtime import CodeQLExecution, CodeQLExecutor, CodeQLImage, CodeQLImageResolver, tree_manifest
from appsec_review.config import load_config
from appsec_review.container_runtime import profiles_from_settings
from appsec_review.container_runtime.build_executor import _run
from appsec_review.container_runtime.identity import application_runtime_user
from appsec_review.container_runtime.project_images import project_dependency_environment
from tests.test_live_codeql_toolchains import _write_replay


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "build_toolchains"
TARGET = ROOT / "targets" / "appsec-multi-vuln"
NOMINAL_USER = "10001:10001"
# The toolchain environment that the derived layer must leave exactly as the build image set it.
TOOLCHAIN_ENV = ("JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT", "GRADLE_OPTS", "MAVEN_OPTS",
                 "GRADLE_USER_HOME", "GOTOOLCHAIN", "GOMODCACHE", "NUGET_PACKAGES", "PYTHONPATH",
                 "NODE_PATH", "CARGO_HOME", "HOME")
DATABASE_TIMEOUT_SECONDS = 900


def docker_usable() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=60,
                              check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def local_image_id(reference: str) -> str | None:
    try:
        result = subprocess.run(["docker", "image", "inspect", reference, "--format", "{{.Id}}"],
                                capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and value.startswith("sha256:") else None


def image_config(reference: str) -> Mapping[str, Any]:
    result = subprocess.run(["docker", "image", "inspect", reference, "--format", "{{json .Config}}"],
                            capture_output=True, text=True, timeout=60, check=True)
    return json.loads(result.stdout)


def environment_of(config: Mapping[str, Any]) -> dict[str, str]:
    return dict(item.split("=", 1) for item in config.get("Env") or ())


def require_dependency_host(url: str) -> None:
    """Skip, naming the host, when a fixture image's dependency restore cannot reach it."""
    parsed = urlparse(url)
    try:
        socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10).close()
    except OSError as exc:
        pytest.skip(f"fixture dependency host {parsed.hostname} is unreachable: {exc}")


class RecordingRunner:
    """The production Docker runner, recording every argv; ``offline`` forces ``--network none``."""

    def __init__(self, *, offline: bool = False) -> None:
        self.offline = offline
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[str], timeout: int):
        values = list(argv)
        if self.offline and values[:2] == ["docker", "run"] and "--network" in values:
            values[values.index("--network") + 1] = "none"
        self.calls.append(tuple(values))
        return _run(tuple(values), timeout)

    def builds(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[:3] == ("docker", "buildx", "build")]

    def tags(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[:3] == ("docker", "image", "tag")]

    def runs(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[:2] == ("docker", "run")]


def run_in_image(image_id: str, entrypoint: str, *arguments: str, network: str = "none",
                 environment: Mapping[str, str] | None = None, user: str | None = None,
                 timeout: int = 300) -> subprocess.CompletedProcess[str]:
    """Run with the CodeQL executor's container restrictions and (by default) its runtime user."""
    command = ["docker", "run", "--rm", "--network", network, "--read-only",
               "--user", user or application_runtime_user(NOMINAL_USER), "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
               "--env", "HOME=/tmp/codeql-home"]
    for key, value in (environment or {}).items():
        command.extend(("--env", f"{key}={value}"))
    command.extend(("--entrypoint", entrypoint, image_id, *arguments))
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)


def database_sources(database: Path) -> set[str]:
    archive = database / "src.zip"
    if not archive.is_file():
        return set()
    with zipfile.ZipFile(archive) as opened:
        return set(opened.namelist())


@dataclass
class DerivedEnvironment:
    config: Any
    settings: Any
    releases: Any
    profiles: Mapping[str, Any]
    root: Path
    cleanup_tags: list[str] = field(default_factory=list)

    @property
    def run_root(self) -> Path:
        return self.root / "run"

    @property
    def metadata_root(self) -> Path:
        return self.root / "metadata"

    def profile(self, name: str) -> tuple[str, str]:
        tag = self.profiles[name].tag
        image_id = local_image_id(tag)
        if image_id is None:
            pytest.skip(f"build profile image {tag} is not built locally (containers/catalog.toml)")
        return tag, image_id

    def declaration(self, build_image_id: str):
        matches = [item for item in self.settings.preinstalled_runtimes
                   if item.build_image_id == build_image_id]
        return matches[0] if matches else None

    def require_declared_runtime(self, build_image_id: str) -> None:
        """Skip when a declared environment cannot run on this host as shipped."""
        declared = self.declaration(build_image_id)
        effective = application_runtime_user(self.settings.runtime_user)
        if declared.runtime_user != effective:
            pytest.skip(f"shipped declaration is for {declared.runtime_user}; this host runs as {effective}")
        if local_image_id(declared.runtime_image_id) != declared.runtime_image_id:
            pytest.skip(f"declared preinstalled runtime {declared.runtime_image_id} is not present locally")

    def resolver(self, *, runner=None, settings=None, metadata_root: Path | None = None) -> CodeQLImageResolver:
        return CodeQLImageResolver(
            repository_root=ROOT, metadata_root=metadata_root or self.metadata_root,
            settings=settings or self.settings, timeout_seconds=1800, releases=self.releases,
            runner=runner)

    def resolve(self, tag: str, image_id: str, *, runner=None, customized: bool = False,
                metadata_root: Path | None = None) -> CodeQLImage:
        image = self.resolver(runner=runner, metadata_root=metadata_root).resolve(
            build_image_tag=tag, build_image_id=image_id, runtime_user=self.settings.runtime_user)[0]
        if customized and not image.preinstalled:
            self.cleanup_tags.append(image.image_tag)
        return image

    def build_customized(self, name: str, profile_name: str, *, recipe: Mapping[str, Any],
                         files: Mapping[str, str | bytes] | None = None,
                         root_lines: Sequence[str] = (), user_lines: Sequence[str] = (),
                         network: str = "none") -> tuple[str, str]:
        """Build a per-run style project image the way ``ProjectImageResolver`` lays it out.

        ``FROM`` the profile tag, ``/opt/project``, ``/opt/project-home`` and ``/opt/project-deps``
        owned by the profile user, ``HOME=/opt/project-home``, and the recipe's dependency
        environment from ``project_dependency_environment``. ``root_lines`` run as root before the
        ownership change; ``user_lines`` run as the profile user (dependency restores, and the
        owner's own permission changes).
        """
        base_tag, _base_id = self.profile(profile_name)
        user = self.profiles[profile_name].user
        context = self.root / "customized" / name
        shutil.rmtree(context, ignore_errors=True)
        (context / "inputs").mkdir(parents=True)
        for relative, content in (files or {}).items():
            path = context / "inputs" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8")
        source_dir = str(recipe.get("source_dir", "."))
        lines = [f"FROM {base_tag}", "USER 0:0",
                 'RUN ["mkdir","-p","/opt/project","/opt/project-home","/opt/project-deps"]',
                 f"COPY --chown={user} inputs/ /opt/project/", *root_lines,
                 f'RUN ["chown","-R","{user}","/opt/project","/opt/project-home","/opt/project-deps"]',
                 f"USER {user}", "ENV HOME=/opt/project-home"]
        lines.extend(f"ENV {key}={value}" for key, value in sorted(project_dependency_environment(recipe).items()))
        lines.append(f"WORKDIR /opt/project/{source_dir}")
        lines.extend(user_lines)
        (context / "Dockerfile").write_text("\n".join(lines) + "\n", encoding="utf-8")
        tag = f"appsec-review-integ-project-{profile_name}:{name}-{uuid4().hex[:12]}"
        result = subprocess.run(
            ["docker", "buildx", "build", "--load", "--pull=false", "--network", network, "--tag", tag,
             "--file", str(context / "Dockerfile"), str(context)],
            capture_output=True, text=True, timeout=3600, check=False)
        assert result.returncode == 0, f"customized image {name} failed to build:\n{result.stderr[-8000:]}"
        self.cleanup_tags.append(tag)
        image_id = local_image_id(tag)
        assert image_id is not None
        return tag, image_id

    def executor(self, image: CodeQLImage, *, runner=None) -> CodeQLExecutor:
        settings = replace(self.settings, database_timeout_seconds=DATABASE_TIMEOUT_SECONDS)
        return CodeQLExecutor(image=image, run_root=self.run_root, settings=settings, runner=runner)

    def database(self, name: str, image: CodeQLImage, *, language: str, mode: str, workspace: Path,
                 commands: tuple[tuple[str, tuple[str, ...], dict[str, str]], ...] = (),
                 source_subroot: str = ".", runner=None) -> tuple[CodeQLExecution, Path, str]:
        """Create one database through the production executor; returns execution, scratch, stderr."""
        scratch = self.run_root / f"scope-{name}-{uuid4().hex[:8]}"
        shutil.copytree(workspace, scratch / "workspace", symlinks=True)
        arguments = ["--mode", mode, "--language", language, "--workspace", "workspace",
                     "--source-subroot", source_subroot, "--database", "database",
                     "--threads", str(self.settings.threads), "--ram", str(self.settings.ram_mb)]
        if commands:
            _write_replay(scratch / "replay.json", self.run_root, image.build_image_id, commands)
            arguments[4:4] = ["--replay", "replay.json"]
        execution = self.executor(image, runner=runner).execute("database", tuple(arguments),
                                                                scratch_root=scratch)
        detail = (self.run_root / execution.stderr_path).read_text(encoding="utf-8", errors="replace")
        return execution, scratch, detail

    def assert_database(self, execution: CodeQLExecution, scratch: Path, detail: str) -> set[str]:
        assert not execution.timed_out, f"database creation exceeded {DATABASE_TIMEOUT_SECONDS}s"
        assert execution.exit_code == 0, detail[-12000:]
        manifest = tree_manifest(scratch / "database", file_limit=self.settings.database_file_limit,
                                 bytes_limit=self.settings.database_bytes_limit)
        assert manifest["file_count"] > 0 and manifest["tree_sha256"]
        sources = database_sources(scratch / "database")
        assert sources, "database has no source archive entries"
        return sources

    def remove_tags(self) -> None:
        for tag in reversed(self.cleanup_tags):
            subprocess.run(["docker", "image", "rm", tag], capture_output=True, timeout=120, check=False)
        self.cleanup_tags.clear()


def derived_environment(tmp_path_factory: pytest.TempPathFactory, name: str) -> DerivedEnvironment:
    """Gate on Docker and the licensed source image, then load the unmodified shipped settings."""
    if not docker_usable():
        pytest.skip("Docker is not usable")
    config = load_config(ROOT / "appsec-review.toml")
    settings = config.job("job_codeql_analysis").typed_settings
    assert settings is not None and settings.preinstalled_undeclared == "derive"
    if local_image_id(settings.source_image_tag) != settings.source_image_id:
        pytest.skip(f"licensed CodeQL source image {settings.source_image_tag} is not present at its pinned id")
    profiles = profiles_from_settings(config.job("job_project_build").settings["profiles"])
    root = tmp_path_factory.mktemp(name)
    (root / "run").mkdir()
    return DerivedEnvironment(config, settings, config.review_policy.releases, profiles, root)
