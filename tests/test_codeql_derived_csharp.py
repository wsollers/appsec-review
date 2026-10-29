"""CodeQL C# scopes on dotnet build images under the ``preinstalled_undeclared`` policy.

Every C# scope is a manual scope whose CodeQL runtime is selected from the accepted build
receipt's dotnet image (the shipped profile image or a customized project image derived from
it). The shipped declarations name neither, so the policy decides between a derived image and a
named failure. These tests use the real shipped configuration and the real resolver and job
helper with a fake Docker boundary; no Docker, Dagster or network process runs.
"""
from __future__ import annotations

import ast
from collections.abc import Mapping
import hashlib
import os
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

import pytest

from appsec_review.codeql import runtime
from appsec_review.config import load_config
from appsec_review.config.codeql import parse_codeql_settings
from appsec_review.container_runtime.build_executor import BuildProfile
from appsec_review.container_runtime.project_images import (
    SCHEMA as PROJECT_IMAGE_SCHEMA, ProjectImage, ProjectImageResolver, project_recipe_identity,
)
from appsec_review.jobs.job_codeql_analysis import job as codeql
from appsec_review.jobs.job_codeql_analysis.planning import _COMPILED_FAMILIES
from appsec_review.jobs.job_project_build.job import _image_dict
from appsec_review.storage import canonical_json

ROOT = Path(__file__).resolve().parents[1]
CODEQL_DOCKERFILE = ROOT / "containers/tools/codeql/Dockerfile"
DOTNET_DOCKERFILE = ROOT / "containers/buildenv/dotnet/Dockerfile"
RUNNER = ROOT / "containers/tools/codeql/codeql_runner.py"
CUSTOMIZED_ID = "sha256:" + "c" * 64
CUSTOMIZED_TAG = "appsec-review-project-dotnet:" + "0" * 12 + "c" * 12
DERIVED_ID = "sha256:" + "d" * 64
NUMERIC_NON_ROOT = r"[1-9][0-9]*:[1-9][0-9]*"


@pytest.fixture(scope="module")
def config():
    return load_config(ROOT / "appsec-review.toml")


@pytest.fixture(scope="module")
def dotnet_profile(config) -> BuildProfile:
    value = config.job("job_project_build").settings["profiles"]["dotnet"]
    return BuildProfile("dotnet", str(value["tag"]), str(value["image_id"]), str(value["user"]))


@pytest.fixture(autouse=True)
def no_real_processes(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("csharp derived-runtime test attempted an external process")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    for name in [name for name in os.environ if name.startswith("APPSEC_NATIVE_")]:
        monkeypatch.delenv(name)


def _plain(value):
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _settings(config, policy: str, **changes):
    value = _plain(config.job("job_codeql_analysis").settings)
    value.update(preinstalled_undeclared=policy, **changes)
    return parse_codeql_settings(value)


def _effective(monkeypatch, user: str) -> None:
    monkeypatch.setattr(runtime, "application_runtime_user", lambda nominal: user)


def _forbidden_runner(argv, timeout):
    pytest.fail(f"identity derivation must not call Docker: {argv}")


def _resolver(config, settings, runner=_forbidden_runner, metadata_root=None):
    return runtime.CodeQLImageResolver(
        repository_root=ROOT, metadata_root=metadata_root or ROOT / "test/tmp/unused",
        settings=settings, runner=runner, releases=config.review_policy.releases)


def _derived_identity(config, settings, build_image_id: str, runtime_user: str) -> str:
    releases = config.review_policy.releases.values
    return hashlib.sha256(canonical_json({
        "schema": runtime.IMAGE_SCHEMA, "source_image_id": settings.source_image_id,
        "build_image_id": build_image_id, "runtime_user": runtime_user,
        "component_release_id": releases.get("codeql"),
        "runner_release_id": releases.get("codeql_runner"),
    })).hexdigest()


def _receipt_image(profile: BuildProfile, *, customized: bool) -> dict:
    """The accepted project-build receipt image, recorded by the real project-build helper."""
    image = ProjectImage(
        PROJECT_IMAGE_SCHEMA, "f" * 64, profile.name, profile.image_id,
        CUSTOMIZED_TAG if customized else profile.tag,
        CUSTOMIZED_ID if customized else profile.image_id,
        "e" * 64 if customized else None, customized, False, {"App.csproj": "a" * 64})
    return _image_dict(image, profile.user)


def _instructions(path: Path) -> list[tuple[str, str]]:
    result, pending = [], ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not pending and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        keyword, _, rest = (pending + line).partition(" ")
        result.append((keyword.upper(), rest.strip()))
        pending = ""
    return result


# --- Shipped configuration facts ------------------------------------------------------------

def test_shipped_csharp_scopes_replay_on_undeclared_dotnet_images(config, dotnet_profile):
    settings = config.job("job_codeql_analysis").typed_settings
    assert _COMPILED_FAMILIES["dotnet"] == "csharp"
    assert settings.languages["csharp"].mode == "build"
    assert settings.preinstalled_undeclared in {"fail", "derive"}
    assert re.fullmatch(NUMERIC_NON_ROOT, dotnet_profile.user)
    declared = {item.build_image_id for item in settings.preinstalled_runtimes}
    assert declared and dotnet_profile.image_id not in declared
    assert CUSTOMIZED_ID not in declared
    runner = ast.parse(RUNNER.read_text(encoding="utf-8"))
    sets = {node.targets[0].id: ast.literal_eval(node.value) for node in runner.body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in {"MANUAL_LANGUAGES", "NONE_LANGUAGES"}}
    assert "csharp" in sets["MANUAL_LANGUAGES"] and "csharp" not in sets["NONE_LANGUAGES"]


# --- Identity under the policy ----------------------------------------------------------------

@pytest.mark.parametrize("customized", [False, True], ids=["profile", "customized"])
@pytest.mark.parametrize("effective_user", ["1000:1000", "10001:10001"])
def test_derive_gives_derived_identity_for_dotnet_images(
        config, dotnet_profile, monkeypatch, customized, effective_user):
    _effective(monkeypatch, effective_user)
    settings = _settings(config, "derive")
    image = _receipt_image(dotnet_profile, customized=customized)
    identity = _resolver(config, settings).declared_identity(
        build_image_id=image["image_id"], runtime_user=image["user"])
    expected = _derived_identity(config, settings, image["image_id"], dotnet_profile.user)
    undeclared = _resolver(config, _settings(config, "fail", preinstalled_runtimes=[]))
    assert identity == expected == undeclared.declared_identity(
        build_image_id=image["image_id"], runtime_user=image["user"])


def test_derived_identity_separates_profile_and_customized_images(config, dotnet_profile, monkeypatch):
    _effective(monkeypatch, "1000:1000")
    resolver = _resolver(config, _settings(config, "derive"))
    identities = {resolver.declared_identity(build_image_id=image_id, runtime_user=dotnet_profile.user)
                  for image_id in (dotnet_profile.image_id, CUSTOMIZED_ID)}
    assert len(identities) == 2


@pytest.mark.parametrize("customized", [False, True], ids=["profile", "customized"])
def test_fail_names_dotnet_image_and_effective_user(config, dotnet_profile, monkeypatch, customized):
    _effective(monkeypatch, "1000:1000")
    image = _receipt_image(dotnet_profile, customized=customized)
    with pytest.raises(ValueError) as caught:
        _resolver(config, _settings(config, "fail")).declared_identity(
            build_image_id=image["image_id"], runtime_user=image["user"])
    message = str(caught.value)
    assert "one exact environment/user declaration" in message
    assert f"build_image_id={image['image_id']}" in message
    assert "effective_user=1000:1000" in message


def test_derive_keeps_shipped_declarations_preinstalled(config, monkeypatch):
    settings = _settings(config, "derive")
    resolver = _resolver(config, settings)
    for declaration in settings.preinstalled_runtimes:
        _effective(monkeypatch, declaration.runtime_user)
        assert resolver._preinstalled(build_image_id=declaration.build_image_id,
                                      runtime_user=settings.runtime_user) == declaration
        assert resolver.declared_identity(
            build_image_id=declaration.build_image_id, runtime_user=settings.runtime_user,
        ) != _derived_identity(config, settings, declaration.build_image_id, settings.runtime_user)


def test_derive_does_not_cover_declared_image_with_other_user(config, monkeypatch):
    settings = _settings(config, "derive")
    declaration = settings.preinstalled_runtimes[0]
    other = "10001:10001" if declaration.runtime_user != "10001:10001" else "10002:10002"
    _effective(monkeypatch, other)
    with pytest.raises(ValueError, match=f"effective_user={other}"):
        _resolver(config, settings).declared_identity(
            build_image_id=declaration.build_image_id, runtime_user=settings.runtime_user)


# --- Real job helper with a fake Docker boundary ----------------------------------------------

class _Events:
    def __init__(self):
        self.records = []

    def write(self, name, **values):
        self.records.append((name, values))


class _FakeDocker:
    def __init__(self, images):
        self.images = dict(images)
        self.calls, self.builds = [], []

    def __call__(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        assert timeout > 0
        if argv[:3] == ("docker", "image", "inspect"):
            image = self.images.get(argv[3])
            return (0, (image + "\n").encode(), b"", False) if image else (1, b"", b"missing", False)
        if argv[:3] == ("docker", "image", "tag"):
            assert argv[3] in self.images.values()
            self.images[argv[4]] = argv[3]
            return 0, b"", b"", False
        if argv[:3] == ("docker", "buildx", "build"):
            context = Path(argv[-1])
            self.builds.append({
                "argv": argv,
                "dockerfile": Path(argv[argv.index("--file") + 1]).read_bytes(),
                "runner": (context / "codeql_runner.py").read_bytes(),
            })
            self.images[argv[argv.index("--tag") + 1]] = DERIVED_ID
            return 0, b"built", b"", False
        pytest.fail(f"unexpected Docker operation: {argv}")


def _unit(config, settings, tmp_path):
    job = SimpleNamespace(events=_Events(), repository_root=ROOT, metadata_root=tmp_path / "metadata",
                          config=SimpleNamespace(typed_settings=settings),
                          review_policy=config.review_policy)
    return SimpleNamespace(unit_id="build-unit-csharp", job=job)


def _database_one_arguments(receipt: Mapping, settings) -> dict[str, str]:
    """The image selection ``_database_one`` makes for a receipt-bearing manual scope."""
    image = receipt["image"]
    return {"build_image_tag": str(image["image_tag"]), "build_image_id": str(image["image_id"]),
            "runtime_user": str(image.get("user") or settings.runtime_user)}


@pytest.mark.parametrize("customized", [False, True], ids=["profile", "customized"])
def test_job_resolves_derived_runtime_for_csharp_receipt(
        config, dotnet_profile, tmp_path, monkeypatch, customized):
    _effective(monkeypatch, "1000:1000")
    settings = _settings(config, "derive")
    receipt = {"image": _receipt_image(dotnet_profile, customized=customized)}
    arguments = _database_one_arguments(receipt, settings)
    docker = _FakeDocker({settings.source_image_tag: settings.source_image_id,
                          arguments["build_image_tag"]: arguments["build_image_id"]})
    monkeypatch.setattr(runtime, "_run", docker)
    unit = _unit(config, settings, tmp_path)

    image, _stdout, _stderr = codeql._resolve_image(unit, scope_id="csharp-scope", **arguments)

    assert not image.preinstalled and image.image_build_performed is True
    assert image.schema == runtime.IMAGE_SCHEMA and image.image_id == DERIVED_ID
    assert image.build_image_id == arguments["build_image_id"]
    assert image.runtime_user == dotnet_profile.user
    assert image.identity == _derived_identity(
        config, settings, arguments["build_image_id"], dotnet_profile.user)
    assert not any(call[:2] == ("docker", "run") for call in docker.calls)
    [build] = docker.builds
    argv = build["argv"]
    assert build["dockerfile"] == CODEQL_DOCKERFILE.read_bytes()
    assert build["runner"] == RUNNER.read_bytes()
    assert argv[argv.index("--network") + 1] == "none" and "--pull=false" in argv
    build_args = dict(argv[index + 1].split("=", 1)
                      for index, value in enumerate(argv) if value == "--build-arg")
    base_tag = f"appsec-review-codeql-base:{arguments['build_image_id'][7:31]}"
    assert build_args == {
        "CODEQL_SOURCE_IMAGE": f"appsec-review-codeql-source:{settings.source_image_id[7:31]}",
        "RUNTIME_USER": dotnet_profile.user, "BUILD_IMAGE": base_tag}
    assert docker.images[base_tag] == arguments["build_image_id"]
    [resolved] = [values for name, values in unit.job.events.records if name == "CODEQL_RUNTIME_RESOLVED"]
    assert resolved["preparation_kind"] == "derived"
    assert resolved["build_image_id"] == arguments["build_image_id"]
    assert resolved["requested_runtime_user"] == resolved["runtime_user"] == dotnet_profile.user


@pytest.mark.parametrize("customized", [False, True], ids=["profile", "customized"])
def test_job_fail_policy_rejects_csharp_receipt_before_docker(
        config, dotnet_profile, tmp_path, monkeypatch, customized):
    _effective(monkeypatch, "1000:1000")
    settings = _settings(config, "fail")
    arguments = _database_one_arguments(
        {"image": _receipt_image(dotnet_profile, customized=customized)}, settings)
    docker = _FakeDocker({})
    monkeypatch.setattr(runtime, "_run", docker)
    with pytest.raises(ValueError) as caught:
        codeql._resolve_image(_unit(config, settings, tmp_path), scope_id="csharp-scope", **arguments)
    assert f"build_image_id={arguments['build_image_id']}" in str(caught.value)
    assert "effective_user=1000:1000" in str(caught.value)
    assert docker.calls == []


# --- Static compatibility of the derived layer on dotnet images -------------------------------

def test_dotnet_buildenv_is_a_glibc_base_with_sdk_shell_and_python(dotnet_profile):
    instructions = _instructions(DOTNET_DOCKERFILE)
    froms = [rest for keyword, rest in instructions if keyword == "FROM"]
    assert froms == [froms[0]] and re.fullmatch(r"ubuntu:24\.04@sha256:[0-9a-f]{64}", froms[0])
    text = DOTNET_DOCKERFILE.read_text(encoding="utf-8").lower()
    assert "alpine" not in text and "apk " not in text and "musl" not in text
    install = next(rest for keyword, rest in instructions if keyword == "RUN" and "apt-get install" in rest)
    for package in ("bash", "coreutils", "dotnet-sdk-8.0", "dotnet-sdk-10.0", "python3"):
        assert re.search(rf"(?<![\w.-]){re.escape(package)}=", install), package
    assert "test -d /usr/lib/dotnet/packs/" in install
    environment = " ".join(rest for keyword, rest in instructions if keyword == "ENV")
    path = re.search(r"\bPATH=(\S+)", environment).group(1).split(":")
    assert "/usr/bin" in path and "/bin" in path
    assert "DOTNET_ROOT" not in environment and "DOTNET_CLI_HOME" not in environment
    users = [rest for keyword, rest in instructions if keyword == "USER"]
    assert users[0] == "0:0" and users[-1] == dotnet_profile.user
    uid, gid = dotnet_profile.user.split(":")
    setup = " ".join(rest for keyword, rest in instructions if keyword == "RUN")
    assert re.search(r"mkdir -p [^&]*/scratch", setup)
    assert re.search(rf"chown -R {uid}:{gid} [^&]*/scratch", setup)
    assert ("ENTRYPOINT", "[]") in instructions


def test_codeql_layer_needs_only_root_shell_chmod_and_keeps_base_path():
    instructions = _instructions(CODEQL_DOCKERFILE)
    keywords = [keyword for keyword, _ in instructions]
    assert instructions[:4] == [("ARG", "CODEQL_SOURCE_IMAGE"), ("ARG", "BUILD_IMAGE"),
                                ("FROM", "${CODEQL_SOURCE_IMAGE} AS codeql_source"),
                                ("FROM", "${BUILD_IMAGE}")]
    final = instructions[3:]
    assert ("ARG", "RUNTIME_USER=10001:10001") in final
    root = final.index(("USER", "0:0"))
    for keyword in ("COPY", "RUN"):
        assert all(index > root for index, (name, _) in enumerate(final) if name == keyword)
    assert ("COPY", "--from=codeql_source /opt/codeql /opt/codeql") in final
    [command] = [rest for keyword, rest in final if keyword == "RUN"]
    assert {part.split()[0] for part in command.split("&&")} == {"chmod"}
    assert ("ENV", "PATH=/opt/codeql:${PATH}") in final
    assert final[-2:] == [("USER", "${RUNTIME_USER}"), ("WORKDIR", "/scratch")]
    assert "ENTRYPOINT" not in keywords and "CMD" not in keywords
    assert not any(keyword == "ENV" and "HOME" in rest for keyword, rest in final)


@pytest.mark.parametrize("variant", ["network_restore", "system_packages"])
def test_customized_dotnet_image_keeps_layer_prerequisites(dotnet_profile, tmp_path, config, variant):
    recipe = {"source_dir": "src/App", "build_system": "dotnet",
              "dependency_files": ["src/App/App.csproj"], "configure_commands": [],
              "build_commands": [["dotnet", "build"]], "network_required": variant == "network_restore",
              "system_packages": ["libicu74"] if variant == "system_packages" else []}
    hashes = {"src/App/App.csproj": "a" * 64}
    resolver = ProjectImageResolver(metadata_root=tmp_path / "metadata", target_root=tmp_path,
                                    runner=_forbidden_runner, releases=config.review_policy.releases)
    identity, dockerfile = resolver._definition(recipe, dotnet_profile, hashes)
    assert identity == project_recipe_identity(recipe, dotnet_profile, hashes,
                                               releases=config.review_policy.releases)
    path = tmp_path / "Dockerfile"
    path.write_bytes(dockerfile)
    instructions = _instructions(path)
    assert instructions[0] == ("FROM", dotnet_profile.tag)
    users = [rest for keyword, rest in instructions if keyword == "USER"]
    assert users[-1] == dotnet_profile.user
    environment = [rest for keyword, rest in instructions if keyword == "ENV"]
    assert "NUGET_PACKAGES=/opt/project-deps/nuget" in environment
    assert not any(value.startswith("PATH=") for value in environment)
    assert all(rest.startswith("[") for keyword, rest in instructions if keyword == "RUN")
    if variant == "network_restore":
        assert ("RUN", '["dotnet","restore"]') in instructions
