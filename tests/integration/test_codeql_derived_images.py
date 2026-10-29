"""Real-Docker integration tests for the derived CodeQL runtime path.

Under the shipped ``preinstalled_undeclared = "derive"`` policy every build environment without a
declaration, including per-run customized project images, gets ``containers/tools/codeql/Dockerfile``
layered on top of it. These tests build those derived images from the locally built language
profiles and from representative customized project images, inspect them, run CodeQL in them with
the executor's restrictions, and cover reuse, the runtime-user mismatch, environment leakage into
the trusted runner, and the fail-policy preflight. Replays run on the bridge network with an
executable ``/tmp`` only when they launch Gradle (including the appsec-multi-vuln Android case),
and Go ``-mod=mod`` replays read the image module cache as their first ``GOPROXY``.

Gates (environment, never outcome):

* Docker must be usable.
* The licensed CodeQL source image must be present at the shipped pin.
* A profile's image must be built locally from ``containers/catalog.toml``. Profiles resolve at the
  identity of their local tag, because the shipped pins are host-specific.
* A declared environment, such as the native profile when its local id equals the shipped pin, is
  exercised only when this host's effective user and preinstalled runtime image match the
  declaration.

Integration only, so never run implicitly. Select this file explicitly:

    python -m pytest tests/integration/test_codeql_derived_images.py --basetemp=test/tmp/codeql-derived
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
import zipfile

import pytest

from appsec_review.codeql import predecessor, runtime
from appsec_review.codeql.runtime import IMAGE_SCHEMA, PREINSTALLED_IMAGE_SCHEMA
from appsec_review.config import load_config
from appsec_review.container_runtime.identity import application_runtime_user
from appsec_review.container_runtime.project_images import project_dependency_environment
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_codeql_analysis import job as codeql
from appsec_review.jobs.job_codeql_analysis.datasets import DATASETS
from appsec_review.jobs.job_codeql_analysis.planning import SCOPE_SCHEMA, CodeQLScope
from appsec_review.jobs.job_project_build.job import _probe_environment
from appsec_review.runtime import Job, JobRunner, Unit, UnitContext
from tests.capture_fakes import build_capture_toml
from tests.integration.codeql_derived_support import (
    FIXTURE, NOMINAL_USER, TARGET, TOOLCHAIN_ENV, RecordingRunner, derived_environment, environment_of,
    image_config, local_image_id, require_dependency_host, run_in_image,
)
from tests.test_codeql_predecessor import _table
from tests.test_codeql_preinstalled import settings_value


DECLARATION_ERROR = "requires one exact environment/user declaration"


@pytest.fixture(scope="module")
def env(tmp_path_factory: pytest.TempPathFactory):
    environment = derived_environment(tmp_path_factory, "codeql-derived-images")
    yield environment
    environment.remove_tags()


class LeakDetected(Exception):
    """A customized image's environment reached the trusted CodeQL runner or extractor."""


def _assert_derived_layer(base_reference: str, derived_reference: str) -> dict[str, str]:
    base, derived = image_config(base_reference), image_config(derived_reference)
    base_env, derived_env = environment_of(base), environment_of(derived)
    assert derived["User"] == NOMINAL_USER
    assert derived["WorkingDir"] == "/scratch"
    assert derived_env["PATH"].split(":")[0] == "/opt/codeql"
    assert derived_env["PATH"] == "/opt/codeql:" + base_env["PATH"]
    # The derived layer adds CodeQL to PATH and nothing else: every toolchain variable, including
    # JAVA_HOME, ANDROID_*, GRADLE_*, MAVEN_OPTS, GOTOOLCHAIN and DOTNET_*, is the base's.
    assert {key: value for key, value in derived_env.items() if key != "PATH"} == {
        key: value for key, value in base_env.items() if key != "PATH"}
    for key in (*TOOLCHAIN_ENV, *(key for key in base_env if key.startswith("DOTNET_"))):
        assert derived_env.get(key) == base_env.get(key), key
    return derived_env


def _assert_codeql_runs(env, image_id: str, language: str) -> None:
    version = run_in_image(image_id, "codeql", "version", "--format=json")
    assert version.returncode == 0, version.stdout + version.stderr
    assert json.loads(version.stdout)["version"] == env.settings.version
    languages = run_in_image(image_id, "codeql", "resolve", "languages", "--format=json")
    assert languages.returncode == 0, languages.stdout + languages.stderr
    assert language in json.loads(languages.stdout)
    runner = run_in_image(image_id, "python3", "-c",
                          "import os; assert os.access('/opt/appsec/codeql_runner.py', os.R_OK)")
    assert runner.returncode == 0, runner.stdout + runner.stderr


# (profile, CodeQL language, base-image toolchain variables the profile must define)
PROFILES = (
    ("go", "go", ("GOTOOLCHAIN",)),
    ("java", "java", ("JAVA_HOME", "GRADLE_OPTS")),
    ("android", "java", ("JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT", "GRADLE_USER_HOME")),
    ("dotnet", "csharp", ("DOTNET_CLI_TELEMETRY_OPTOUT", "DOTNET_NOLOGO")),
    ("node", "javascript", ()),
    ("python", "python", ()),
    ("native", "cpp", ()),
    ("rust", "rust", ()),
)


@pytest.mark.parametrize(("profile", "language", "required"), PROFILES, ids=[item[0] for item in PROFILES])
def test_derived_image_on_each_language_profile_keeps_the_build_environment(
        env, profile: str, language: str, required: tuple[str, ...]) -> None:
    tag, image_id = env.profile(profile)
    if env.declaration(image_id) is not None:
        pytest.skip(f"{profile} is declared at this host's local id; see the declared-native test")
    recorder = RecordingRunner()
    image = env.resolve(tag, image_id, runner=recorder)
    assert image.schema == IMAGE_SCHEMA and not image.preinstalled
    assert image.build_image_id == image_id and image.build_image_tag == tag
    assert image.runtime_user == NOMINAL_USER and image.runner_source == "image"
    assert image.image_tag.startswith("appsec-review-codeql:")
    assert local_image_id(image.image_tag) == image.image_id
    assert all(DECLARATION_ERROR not in " ".join(call) for call in recorder.calls)
    base_env = environment_of(image_config(image_id))
    assert all(key in base_env for key in required), sorted(set(required) - set(base_env))
    _assert_derived_layer(image_id, image.image_id)
    _assert_codeql_runs(env, image.image_id, language)


def test_declared_native_environment_resolves_to_its_preinstalled_runtime(env) -> None:
    tag, image_id = env.profile("native")
    if env.declaration(image_id) is None:
        pytest.skip("local native image differs from the shipped declaration; it takes the derived path")
    env.require_declared_runtime(image_id)
    recorder = RecordingRunner()
    image = env.resolve(tag, image_id, runner=recorder)
    declared = env.declaration(image_id)
    assert image.schema == PREINSTALLED_IMAGE_SCHEMA and image.preinstalled
    assert image.image_id == declared.runtime_image_id and image.image_build_performed is False
    assert recorder.builds() == [] and recorder.tags() == []
    _assert_codeql_runs(env, image.image_id, "cpp")


# (case, profile, CodeQL language, recipe) for per-run customized project images.
CUSTOMIZED = (
    ("go-modcache", "go", "go", {"build_system": "go", "source_dir": "."}),
    ("java-maven", "java", "java", {"build_system": "maven", "source_dir": "."}),
    ("java-gradle", "java", "java", {"build_system": "gradle", "source_dir": "."}),
    ("android-gradle", "android", "java", {"build_system": "gradle", "source_dir": "."}),
    ("dotnet-nuget", "dotnet", "csharp", {"build_system": "dotnet", "source_dir": "."}),
    ("node-npm", "node", "javascript", {"build_system": "node", "source_dir": "."}),
    ("python-deps", "python", "python", {"build_system": "python", "source_dir": "."}),
    ("native-custom", "native", "cpp", {"build_system": "cmake", "source_dir": "."}),
    ("rust-cargo", "rust", "rust", {"build_system": "cargo", "source_dir": "."}),
)


@pytest.mark.parametrize(("case", "profile", "language", "recipe"), CUSTOMIZED,
                         ids=[item[0] for item in CUSTOMIZED])
def test_customized_project_image_derives_and_keeps_its_dependency_environment(
        env, case: str, profile: str, language: str, recipe: dict) -> None:
    tag, image_id = env.build_customized(case, profile, recipe=recipe,
                                         files={"README.fixture": "customized project image\n"})
    assert env.declaration(image_id) is None
    image = env.resolve(tag, image_id, customized=True)
    # Customized images are never declared; the shipped derive policy layers CodeQL onto them,
    # including the customized native image whose base is the declared native profile.
    assert image.schema == IMAGE_SCHEMA and not image.preinstalled and image.build_image_id == image_id
    derived_env = _assert_derived_layer(image_id, image.image_id)
    assert derived_env["HOME"] == "/opt/project-home"
    for key, value in project_dependency_environment(recipe).items():
        if key != "PATH":
            assert derived_env[key] == value, key
    _assert_codeql_runs(env, image.image_id, language)


def test_second_resolution_reuses_the_derived_image_without_rebuilding(env, tmp_path: Path) -> None:
    for profile in ("go", "python", "rust", "java", "dotnet", "node"):
        tag, image_id = env.profiles[profile].tag, local_image_id(env.profiles[profile].tag)
        if image_id is not None and env.declaration(image_id) is None:
            break
    else:
        pytest.skip("no undeclared language profile image is built locally")
    metadata = tmp_path / "metadata"
    first_runner = RecordingRunner()
    first = env.resolve(tag, image_id, runner=first_runner, metadata_root=metadata)
    assert first.image_build_performed is True and first.reused is False
    [build] = first_runner.builds()
    assert build[build.index("--network") + 1] == "none"
    assert f"RUNTIME_USER={NOMINAL_USER}" in build and "--tag" in build
    assert build[build.index("--tag") + 1] == first.image_tag
    manifest = metadata / first.manifest_path
    recorded = manifest.read_bytes()

    for _attempt in range(2):
        runner = RecordingRunner()
        again = env.resolve(tag, image_id, runner=runner, metadata_root=metadata)
        assert again.reused is True and again.image_build_performed is False
        assert (again.identity, again.image_tag, again.image_id) == (
            first.identity, first.image_tag, first.image_id)
        assert runner.builds() == [] and runner.tags() == []
        assert manifest.read_bytes() == recorded
    assert local_image_id(first.image_tag) == first.image_id


HELPER = 'package dep;\npublic final class Helper { public static String name() { return "helper"; } }\n'
MAIN = ('import dep.Helper;\npublic class Main {\n'
        '  public static void main(String[] args) { System.out.println(Helper.name()); }\n}\n')


def test_runtime_user_mismatch_on_private_dependency_cache_is_readable_or_a_clear_gap(
        env, tmp_path: Path) -> None:
    effective = application_runtime_user(NOMINAL_USER)
    if effective == NOMINAL_USER:
        pytest.skip("this host runs as the nominal derived-image user; there is no mismatch")
    tag, image_id = env.build_customized(
        "java-private-cache", "java", recipe={"build_system": "maven", "source_dir": "."},
        files={"dep/src/dep/Helper.java": HELPER},
        user_lines=('RUN ["javac","-d","/opt/project-deps/classes","/opt/project/dep/src/dep/Helper.java"]',
                    # The cache owner (10001) leaves it private: directories 0700, files 0600.
                    'RUN ["chmod","-R","go-rwx","/opt/project-deps/classes"]'))
    probe = run_in_image(image_id, "stat", "-c", "%u %a", "/opt/project-deps/classes",
                         "/opt/project-deps/classes/dep/Helper.class", user=NOMINAL_USER)
    assert probe.returncode == 0 and probe.stdout.split() == ["10001", "700", "10001", "600"], probe.stdout
    image = env.resolve(tag, image_id, customized=True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "Main.java").write_text(MAIN, encoding="utf-8")
    execution, scratch, detail = env.database(
        "private-cache", image, language="java", mode="manual", workspace=workspace,
        commands=((".", ("javac", "-cp", "/opt/project-deps/classes", "-d", "out", "Main.java"), {}),),
        runner=RecordingRunner(offline=True))
    # Never a hang: the bounded executor timeout is the only way out of a stuck replay.
    assert not execution.timed_out
    if execution.exit_code == 0:
        sources = env.assert_database(execution, scratch, detail)
        assert any(name.endswith("/Main.java") for name in sources), sorted(sources)
    else:
        # A clear, attributable failure that the job records as a scope gap
        # ("CodeQL database creation exited N"), never an empty database presented as success.
        assert "CodeQL child process exited" in detail, detail[-6000:]
        assert "Helper" in detail or "permission denied" in detail.lower(), detail[-6000:]


JSON_SHIM = '''"""Planted by an integration test: shadows the standard-library json module."""
import os as _os
import sys as _sys

try:
    _os.makedirs("/scratch/leak-markers", exist_ok=True)
    with open("/scratch/leak-markers/python-json", "a", encoding="utf-8") as _marker:
        _marker.write(repr(_sys.argv) + "\\n")
except OSError:
    pass

_here = _os.path.dirname(_os.path.abspath(__file__))
_sys.path[:] = [entry for entry in _sys.path if _os.path.abspath(entry or ".") != _here]
del _sys.modules[__name__]
import json as _real  # noqa: E402  the genuine standard-library module
_sys.modules[__name__] = _real
globals().update({key: value for key, value in vars(_real).items() if not key.startswith("__")})
'''

NODE_REQUIRE = '''try {
  const fs = require("fs");
  fs.mkdirSync("/scratch/leak-markers", { recursive: true });
  fs.appendFileSync("/scratch/leak-markers/node-options", JSON.stringify(process.argv) + "\\n");
} catch (error) {}
'''

NODE_PATH_SHADOW = '''try {
  const fs = require("fs");
  fs.mkdirSync("/scratch/leak-markers", { recursive: true });
  fs.appendFileSync("/scratch/leak-markers/node-path", JSON.stringify(process.argv) + "\\n");
} catch (error) {}
throw new Error("NODE_PATH shadow module was loaded by the CodeQL extractor");
'''


def _marker(scratch: Path, name: str) -> str | None:
    path = scratch / "leak-markers" / name
    return path.read_text(encoding="utf-8") if path.is_file() else None


@pytest.mark.xfail(strict=True, raises=LeakDetected, reason=(
    "known leak: the derived image inherits the customized image's ENV PYTHONPATH=/opt/project-deps, "
    "the executor starts the runner as plain `python3 /opt/appsec/codeql_runner.py` (no -I/-E), and "
    "codeql_runner._environment() copies os.environ into every CodeQL child, so a project-supplied "
    "json.py shadows the stdlib in trusted code"))
def test_customized_pythonpath_does_not_reach_the_trusted_runner_or_extractor(env) -> None:
    recipe = {"build_system": "python", "source_dir": "."}
    tag, image_id = env.build_customized(
        "python-pythonpath-leak", "python", recipe=recipe, files={"leak/json.py": JSON_SHIM},
        user_lines=('RUN ["cp","/opt/project/leak/json.py","/opt/project-deps/json.py"]',))
    assert environment_of(image_config(image_id))["PYTHONPATH"] == "/opt/project-deps"
    image = env.resolve(tag, image_id, customized=True)
    execution, scratch, detail = env.database(
        "pythonpath-leak", image, language="python", mode="none", workspace=FIXTURE / "python",
        runner=RecordingRunner(offline=True))
    env.assert_database(execution, scratch, detail)
    marker = _marker(scratch, "python-json")
    if marker is not None:
        raise LeakDetected(f"planted /opt/project-deps/json.py was imported by: {marker}")


@pytest.fixture(scope="module")
def node_leak_image(env):
    recipe = {"build_system": "node", "source_dir": "."}
    tag, image_id = env.build_customized(
        "node-options-leak", "node", recipe=recipe,
        files={"leak/leak.js": NODE_REQUIRE,
               "node_modules/typescript/package.json":
                   '{"name": "typescript", "version": "0.0.0-leak", "main": "index.js"}\n',
               "node_modules/typescript/index.js": NODE_PATH_SHADOW},
        user_lines=('RUN ["cp","/opt/project/leak/leak.js","/opt/project-deps/leak.js"]',
                    'ENV NODE_OPTIONS="--require /opt/project-deps/leak.js"'))
    configured = environment_of(image_config(image_id))
    assert configured["NODE_PATH"] == "/opt/project/node_modules"
    image = env.resolve(tag, image_id, customized=True)
    execution, scratch, detail = env.database(
        "node-leak", image, language="javascript", mode="none", workspace=FIXTURE / "typescript",
        runner=RecordingRunner(offline=True))
    return execution, scratch, detail


@pytest.mark.xfail(strict=True, raises=LeakDetected, reason=(
    "known leak: the derived image inherits the customized image's ENV NODE_OPTIONS, and "
    "codeql_runner._environment() copies os.environ into the JavaScript/TypeScript extractor's "
    "Node.js process, so a project-supplied --require module runs inside trusted extraction"))
def test_customized_node_options_do_not_reach_the_javascript_extractor(env, node_leak_image) -> None:
    execution, scratch, detail = node_leak_image
    env.assert_database(execution, scratch, detail)
    marker = _marker(scratch, "node-options")
    if marker is not None:
        raise LeakDetected(f"NODE_OPTIONS --require module ran in: {marker}")


def test_customized_node_path_does_not_shadow_extractor_modules(env, node_leak_image) -> None:
    # Expected to hold: the extractor resolves its bundled TypeScript relative to its own install,
    # so NODE_PATH is only a fallback. A failure here is a newly found leak, not flakiness.
    execution, scratch, detail = node_leak_image
    sources = env.assert_database(execution, scratch, detail)
    assert any(name.endswith(".ts") for name in sources), sorted(sources)
    assert _marker(scratch, "node-path") is None, _marker(scratch, "node-path")


# --- Replay /tmp mount and dependency environment (594ffdddd) ----------------------------------

EXEC_TMP = "/tmp:rw,exec,nosuid,size=2g"
NOEXEC_TMP = "/tmp:rw,noexec,nosuid,size=2g"
GRADLE_ENVIRONMENT = _probe_environment({"environment": {}, "source_dir": ".", "build_system": "gradle"})
IMAGE_GO_PROXY = "file:///opt/project-deps/go/cache/download"
ANDROID_PROJECT = TARGET / "projects" / "android" / "case-092"


def _option(call: tuple[str, ...], flag: str) -> str:
    assert call.count(flag) == 1, call
    return call[call.index(flag) + 1]


def _database_run(recorder: RecordingRunner) -> tuple[str, ...]:
    """The one ``docker run`` that starts the trusted runner's ``database`` action."""
    calls = [call for call in recorder.runs() if runtime.RUNNER_CONTAINER_PATH in call
             and call[call.index(runtime.RUNNER_CONTAINER_PATH) + 1] == "database"]
    assert len(calls) == 1, recorder.runs()
    return calls[0]


def _recorded_replay_environment(scratch: Path) -> dict[str, str]:
    [command] = json.loads((scratch / "replay.json").read_text(encoding="utf-8"))["commands"]
    return dict(command["environment"])


def _profile_image(env, profile: str):
    tag, image_id = env.profile(profile)
    if env.declaration(image_id) is not None:
        env.require_declared_runtime(image_id)
    return env.resolve(tag, image_id)


def _assert_database_container(recorder: RecordingRunner, execution, *, executable: bool) -> None:
    run = _database_run(recorder)
    assert _option(run, "--tmpfs") == (EXEC_TMP if executable else NOEXEC_TMP)
    # Database replays are networked like the accepted build; only export and compile are offline.
    assert _option(run, "--network") == "bridge"
    assert execution.limits["tmp_executable"] is executable
    assert execution.limits["network"] == "bridge"


JAVA_MAIN = 'public class Main { public static void main(String[] args) { System.out.println("replay"); } }\n'

# (case, replay argv, replay environment, whether /tmp must be executable)
JVM_REPLAYS = (
    ("gradle", ("gradle", "--no-daemon", "--offline", "compileJava"), GRADLE_ENVIRONMENT, True),
    ("javac", ("javac", "-d", "out", "src/main/java/Main.java"), {}, False),
)


@pytest.mark.parametrize(("case", "argv", "environment", "executable"), JVM_REPLAYS,
                         ids=[item[0] for item in JVM_REPLAYS])
def test_java_replay_mounts_an_executable_tmp_only_for_gradle(
        env, tmp_path: Path, case: str, argv: tuple[str, ...], environment: dict, executable: bool) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "src" / "main" / "java").mkdir(parents=True)
    (workspace / "settings.gradle").write_text("rootProject.name = 'codeql-replay-fixture'\n", encoding="utf-8")
    # The java plugin is built into Gradle, so the offline build needs no dependency download.
    (workspace / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
    (workspace / "src" / "main" / "java" / "Main.java").write_text(JAVA_MAIN, encoding="utf-8")
    image = _profile_image(env, "java")
    recorder = RecordingRunner()
    execution, scratch, detail = env.database(
        f"java-{case}", image, language="java", mode="manual", workspace=workspace,
        commands=((".", argv, dict(environment)),), runner=recorder)
    assert runtime.replay_needs_executable_tmp(scratch, ("--replay", "replay.json")) is executable
    if executable:
        assert _recorded_replay_environment(scratch)["GRADLE_USER_HOME"] == "/tmp/appsec-review-gradle"
    _assert_database_container(recorder, execution, executable=executable)
    sources = env.assert_database(execution, scratch, detail)
    assert any(name.endswith("/Main.java") for name in sources), sorted(sources)


@pytest.mark.requires_target("appsec-multi-vuln")
def test_android_gradle_replay_builds_its_database_with_an_executable_tmp(env) -> None:
    # Gradle and AAPT2 extract and run native binaries beneath GRADLE_USER_HOME, which the
    # accepted environment keeps on /tmp. This replay is expected to succeed, not xfail.
    if not ANDROID_PROJECT.is_dir():
        pytest.skip("appsec-multi-vuln Android case-092 is unavailable")
    for host in ("https://dl.google.com", "https://repo.maven.apache.org", "https://plugins.gradle.org"):
        require_dependency_host(host)
    image = _profile_image(env, "android")
    recorder = RecordingRunner()
    execution, scratch, detail = env.database(
        "android-gradle", image, language="java", mode="manual", workspace=ANDROID_PROJECT,
        commands=((".", ("gradle", "--no-daemon", ":app:assembleDebug"), dict(GRADLE_ENVIRONMENT)),),
        runner=recorder)
    recorded = _recorded_replay_environment(scratch)
    assert recorded["GRADLE_USER_HOME"] == "/tmp/appsec-review-gradle"
    assert recorded["GRADLE_RO_DEP_CACHE"] == "/opt/project-deps/gradle/caches"
    _assert_database_container(recorder, execution, executable=True)
    sources = env.assert_database(execution, scratch, detail)
    assert any(name.endswith("/MainActivity.java") for name in sources), sorted(sources)


GO_DEPENDENCY = "example.test/dep"
GO_DEPENDENCY_MOD = "module example.test/dep\n\ngo 1.22\n"
GO_DEPENDENCY_SOURCE = 'package dep\n\nfunc Name() string { return "image-cache" }\n'
GO_MAIN = ('package main\n\nimport (\n\t"fmt"\n\n\t"example.test/dep"\n)\n\n'
           'func main() { fmt.Println(dep.Name()) }\n')


def _go_module_zip(version: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        prefix = f"{GO_DEPENDENCY}@{version}/"
        archive.writestr(prefix + "go.mod", GO_DEPENDENCY_MOD)
        archive.writestr(prefix + "dep.go", GO_DEPENDENCY_SOURCE)
    return buffer.getvalue()


def test_go_mod_mod_replay_serves_modules_from_the_image_cache_first(env, tmp_path: Path) -> None:
    recipe = {"build_system": "go", "source_dir": ".", "network_required": True,
              "environment": {"GOFLAGS": "-mod=mod", "GONOSUMDB": "example.test"}}
    assert project_dependency_environment(recipe)["GOMODCACHE"] == "/opt/project-deps/go"
    environment = _probe_environment(recipe)
    assert environment["GOMODCACHE"] == "/tmp/appsec-go-mod"
    assert environment["GOPROXY"].split(",") == [IMAGE_GO_PROXY, "https://proxy.golang.org", "direct"]
    download = f"proxy/{GO_DEPENDENCY}/@v/"
    tag, image_id = env.build_customized(
        "go-mod-image-proxy", "go", recipe=recipe,
        files={download + "list": "v1.0.0\n",
               download + "v1.0.0.info": '{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}\n',
               download + "v1.0.0.mod": GO_DEPENDENCY_MOD,
               download + "v1.0.0.zip": _go_module_zip("v1.0.0")},
        user_lines=('RUN ["mkdir","-p","/opt/project-deps/go/cache/download"]',
                    'RUN ["cp","-R","/opt/project/proxy/.","/opt/project-deps/go/cache/download/"]',
                    'RUN ["chmod","-R","a+rX","/opt/project-deps/go"]'))
    assert environment_of(image_config(image_id))["GOMODCACHE"] == "/opt/project-deps/go"
    image = env.resolve(tag, image_id, customized=True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "go.mod").write_text(
        f"module integfixture\n\ngo 1.22\n\nrequire {GO_DEPENDENCY} v1.0.0\n", encoding="utf-8")
    (workspace / "main.go").write_text(GO_MAIN, encoding="utf-8")
    # The production network (bridge), never offline: builds keep egress until a dependency proxy exists.
    recorder = RecordingRunner()
    execution, scratch, detail = env.database(
        "go-mod-image-proxy", image, language="go", mode="manual", workspace=workspace,
        commands=((".", ("go", "build", "-o", "codeql-app", "."), environment),), runner=recorder)
    recorded = _recorded_replay_environment(scratch)
    assert recorded["GOMODCACHE"] == "/tmp/appsec-go-mod"
    proxies = recorded["GOPROXY"].split(",")
    assert proxies[0] == IMAGE_GO_PROXY and "off" not in proxies
    assert recorded["GOFLAGS"] == "-mod=mod"
    _assert_database_container(recorder, execution, executable=False)
    # example.test does not exist upstream, so a successful build proves the image cache served it.
    sources = env.assert_database(execution, scratch, detail)
    assert any(name.endswith("/main.go") for name in sources), sorted(sources)


# --- Fail-policy preflight over real local environments ----------------------------------------

# (profile, CodeQL language, mode); one scope per locally built profile, plus a source scope.
MIXED = (("native", "cpp", "manual"), ("go", "go", "manual"), ("java", "java", "manual"),
         ("android", "java", "manual"), ("dotnet", "csharp", "manual"), ("node", "javascript", "none"),
         ("python", "python", "none"), ("rust", "rust", "none"))


def _unit(tmp_path: Path, settings: dict, releases: dict) -> UnitContext:
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("print('fixture')\n")
    policy = {
        "mode": "strict", "project_id": "fixture", "approved_first_party_projects": ["fixture"],
        "target_root": str(target), "custody": "application_private_v1",
        "store_authorization": {"tenant_id": "fixture-tenant", "runs_root": str(tmp_path / "runs")},
        "releases": {"platform": "fixture-v1", "validation": "fixture-v1",
                     "build_toolchain": "fixture-v1", **releases},
    }
    path = tmp_path / "appsec-review.toml"
    path.write_text(
        '[runtime]\nruns_dir = "runs"\ndata_dir = "data"\n' + build_capture_toml()
        + '\n[jobs.job_codeql_analysis]\nname = "fixture"\nworkers = 1\n'
        + _table("jobs.job_codeql_analysis.settings",
                 {key: value for key, value in settings.items() if key != "preinstalled_runtimes"})
        + "".join(_table("[jobs.job_codeql_analysis.settings.preinstalled_runtimes]", entry)
                  for entry in settings["preinstalled_runtimes"])
        + _table("review_policy", policy))
    job = Job(predecessor.JOB, "fixture", lambda context: {},
              units=(Unit("execution.scopes", lambda context: {}),), datasets=DATASETS)
    runner = JobRunner(load_config(path))
    claim = runner.begin_attempt(job, target_root=target, source_fingerprint=source_fingerprint(target),
                                 now=datetime(2026, 10, 29, tzinfo=timezone.utc))
    context = runner._context_from_claim(job, claim)
    return UnitContext(context, "execution.scopes", "execution", "scopes",
                       context.attempt_root / "steps/execution/tasks/scopes", {"plan.inventory": {}})


@pytest.fixture
def mixed_environments(env, tmp_path: Path, monkeypatch):
    """The shipped source declaration only, and one scope per locally built profile environment."""
    declared = next(item for item in env.settings.preinstalled_runtimes
                    if item.build_image_id == env.settings.source_image_id)
    scopes, receipts = [CodeQLScope(SCOPE_SCHEMA, "codeql-unit-" + "0" * 24, "python", ("python",), "none",
                                    ".", (), None, None, "source", False)], {}
    for index, (profile, language, mode) in enumerate(MIXED, 1):
        image_id = local_image_id(env.profiles[profile].tag)
        if image_id is None:
            continue
        unit_id = f"build-{profile}"
        scopes.append(CodeQLScope(SCOPE_SCHEMA, f"codeql-unit-{index:024d}", language, (language,), mode,
                                  ".", (), unit_id, None, profile, mode == "manual"))
        receipts[unit_id] = {"image": {"image_tag": env.profiles[profile].tag, "image_id": image_id,
                                       "user": env.profiles[profile].user}}
    if len(receipts) < 2:
        pytest.skip("fewer than two language profile images are built locally")
    calls, reservations, imports = [], [], []

    def no_docker(argv, timeout):
        calls.append(tuple(argv))
        return 1, b"", b"preflight must not reach Docker", False

    def reserve(self, request, **kwargs):
        reservations.append(kwargs.get("scope_id"))
        raise AssertionError("a scope was admitted after a failed preflight")

    def import_databases(*args, **kwargs):
        imports.append(args[1])
        raise AssertionError("predecessor databases were imported after a failed preflight")

    monkeypatch.setattr(runtime, "_run", no_docker)
    monkeypatch.setattr(codeql.ResourceAdmission, "reserve", reserve)
    monkeypatch.setattr(codeql, "_import_predecessor_databases", import_databases)
    monkeypatch.setattr(codeql, "_plan_from", lambda unit: SimpleNamespace(scopes=tuple(scopes)))
    monkeypatch.setattr(codeql, "_receipt_map", lambda unit: receipts)

    def settings(policy: str) -> dict:
        value = settings_value()
        value.update(source_image_tag=env.settings.source_image_tag,
                     source_image_id=env.settings.source_image_id, runtime_user=NOMINAL_USER,
                     preinstalled_undeclared=policy, preinstalled_runtimes=[asdict(declared)])
        return value

    releases = {"codeql": declared.codeql_release_id, "codeql_runner": declared.runner_release_id}
    environments: dict[tuple[str, str], list[str]] = {}
    for scope in scopes:
        image = receipts[scope.build_unit_id]["image"] if scope.build_unit_id else {
            "image_id": env.settings.source_image_id, "user": NOMINAL_USER}
        environments.setdefault((image["image_id"], image["user"]), []).append(scope.scope_id)
    effective = application_runtime_user(NOMINAL_USER)
    # The resolver matches a declaration against the host's effective user, not the receipt user.
    declared_satisfied = declared.runtime_user == effective
    undeclared = {key: ids for key, ids in environments.items() if key[0] != declared.build_image_id}
    mismatched = {key: ids for key, ids in environments.items()
                  if key[0] == declared.build_image_id and not declared_satisfied}
    return SimpleNamespace(unit=lambda policy: _unit(tmp_path / policy, settings(policy), releases),
                           scopes=tuple(scopes), receipts=receipts, environments=environments,
                           undeclared=undeclared, mismatched=mismatched, effective=effective,
                           calls=calls, reservations=reservations, imports=imports)


def _assert_named(message: str, environments: dict, effective: str) -> None:
    for (image_id, user), scope_ids in environments.items():
        assert (f"image_id={image_id} runtime_user={user} effective_user={effective} "
                f"scopes=[{', '.join(scope_ids)}]") in message, image_id


def test_fail_policy_job_rejects_every_undeclared_real_environment_before_any_container(
        mixed_environments) -> None:
    case = mixed_environments
    unit = case.unit("fail")
    execution = next(item for item in codeql.build_job().units if item.unit_id == "execution.scopes")
    with pytest.raises(ValueError) as raised:
        execution.handler(unit)
    message = str(raised.value)
    failing = {**case.undeclared, **case.mismatched}
    assert message.startswith(f"CodeQL runtime preflight rejected {len(failing)} of "
                              f"{len(case.environments)} environment(s) (preinstalled_undeclared=fail)")
    _assert_named(message, failing, case.effective)
    assert message.count(DECLARATION_ERROR) == len(failing)
    for image_id, _user in set(case.environments) - set(failing):
        assert f"image_id={image_id}" not in message
    assert case.calls == [] and case.reservations == [] and case.imports == []
    assert not list(unit.job.run_root.glob("data/codeql/scopes/*"))
    assert not list(unit.job.metadata_root.glob("codeql-images/**/manifest.json"))


def test_derive_policy_admits_the_same_real_environments_in_preflight(mixed_environments) -> None:
    case = mixed_environments
    unit = case.unit("derive")
    settings = codeql._settings(unit)
    assert settings.preinstalled_undeclared == "derive"
    if case.mismatched:
        # A declared environment still needs its exact user; derive never overrides a declaration.
        with pytest.raises(ValueError) as raised:
            codeql._preflight_runtime_environments(unit, case.scopes, case.receipts, settings)
        _assert_named(str(raised.value), case.mismatched, case.effective)
        for image_id, _user in case.undeclared:
            assert f"image_id={image_id}" not in str(raised.value)
    else:
        assert codeql._preflight_runtime_environments(unit, case.scopes, case.receipts, settings) is None
    assert case.calls == []
