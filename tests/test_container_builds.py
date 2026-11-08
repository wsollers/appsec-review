from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import threading
import time
import tomllib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BUILD_PATH = ROOT / "containers" / "build.py"
SPEC = importlib.util.spec_from_file_location("container_build", BUILD_PATH)
assert SPEC and SPEC.loader
container_build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(container_build)


def _usable_bash() -> bool:
    executable = shutil.which("bash")
    if not executable:
        return False
    probe = subprocess.run([executable, "-lc", "exit 0"], capture_output=True, timeout=10)
    return probe.returncode == 0


def test_catalog_accounts_for_every_audited_image() -> None:
    catalog = container_build.load_catalog()
    assert container_build.validate(catalog) == []
    audited = [item for item in catalog["images"] if "legacy_class" in item]
    assert audited
    assert {item["state"] for item in audited} <= {"enabled", "deferred", "replaced", "retired"}


def test_catalog_validation_rejects_tool_runtime_policy_drift(monkeypatch, tmp_path: Path) -> None:
    catalog = container_build.load_catalog()
    relative = Path("containers/tools/clang-static-analysis/tool.toml")
    source = ROOT / relative
    drifted = tmp_path / "tool.toml"
    drifted.write_text(source.read_text(encoding="utf-8").replace(
        'memory = "1g"', 'memory = "2g"'), encoding="utf-8")
    original_safe_path = container_build.safe_path

    def safe_path(value):
        return drifted if Path(value) == relative else original_safe_path(value)

    monkeypatch.setattr(container_build, "safe_path", safe_path)
    assert "tool-clang-static-analysis: memory does not match central runtime policy" in (
        container_build.validate(catalog))


def test_container_docs_track_current_enabled_inventory() -> None:
    catalog = container_build.load_catalog()
    enabled = [item for item in catalog["images"] if item["state"] == "enabled"]
    counts = {kind: sum(item.get("kind") == kind for item in enabled)
              for kind in ("tool", "base", "buildenv")}
    readme = " ".join((ROOT / "containers" / "README.md").read_text(encoding="utf-8").split())
    migration = " ".join((ROOT / "docs" / "reviews" / "container-migration.md")
                         .read_text(encoding="utf-8").split())
    assert f"contains {len(enabled)} images: {counts['tool']} tool images" in readme
    assert f"{counts['tool']} enabled tool images plus {counts['base']} bases" in migration
    assert {item.get("kind") for item in enabled} == set(counts)


def test_dependency_order_puts_base_before_tool() -> None:
    catalog = container_build.load_catalog()
    order = container_build.dependency_order(["tool-gitleaks"], catalog)
    assert order == ["base-ubuntu", "tool-gitleaks"]


def test_android_buildenv_is_hash_locked_and_registered_by_image_id() -> None:
    catalog = container_build.load_catalog()
    image = catalog["by_id"]["audit-buildenv-android"]
    assert image["kind"] == "buildenv"
    assert image["build_network"] == "default"
    assert image["image_id"].startswith("sha256:") and len(image["image_id"]) == 71
    lock_path = ROOT / image["assets_lock"]
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    assert {item["version"] for item in lock["artifacts"]} == {
        "8.9", "15859902", "35_r02", "35.0.0", "37.0.1"}
    assert all(len(item["sha256"]) == 64 and item["bytes"] > 0 for item in lock["artifacts"])
    assert all(item["signature_verification"]["status"] in {
        "verified", "not-performed", "not-published"} for item in lock["artifacts"])

    with (ROOT / "appsec-review.toml").open("rb") as stream:
        config = tomllib.load(stream)
    profile = config["jobs"]["job_project_build"]["settings"]["profiles"]["android"]
    assert profile == {"tag": image["tag"], "image_id": image["image_id"],
                       "user": "10001:10001"}


def test_continue_on_error_still_returns_failure(monkeypatch, tmp_path: Path) -> None:
    catalog = container_build.load_catalog()
    monkeypatch.setattr(container_build, "RUN_ROOT", tmp_path)

    def fake_build(item, run_dir, **_options):
        status = "failed" if item["id"] == "base-ubuntu" else "passed"
        return {"id": item["id"], "tag": item["tag"], "status": status,
                "duration_seconds": 0.01, "digest": None, "fetch_log": None,
                "build_log": None, **({"error": "fixture"} if status == "failed" else {})}

    monkeypatch.setattr(container_build, "build_one", fake_build)
    args = argparse.Namespace(ids=["tool-gitleaks", "base-python"], all=False,
                              jobs=2, continue_on_error=True)
    assert container_build.execute_build(args, catalog) == 1
    summary = json.loads(next(tmp_path.glob("*/summary.json")).read_text())
    by_id = {item["id"]: item for item in summary["results"]}
    assert by_id["base-ubuntu"]["status"] == "failed"
    assert by_id["tool-gitleaks"]["status"] == "blocked"
    assert by_id["base-python"]["status"] == "passed"


@pytest.mark.parametrize("family", ["native-toolchain", "java", "dotnet"])
def test_ubuntu_buildenv_snapshot_has_pinned_https_bootstrap(family: str) -> None:
    dockerfile = (ROOT / "containers" / "buildenv" / family / "Dockerfile").read_text()
    trust_source = _final_base(ROOT / "containers" / "bases" / "python" / "Dockerfile")
    bootstrap = (
        f"COPY --from={trust_source} /etc/ssl/certs/ca-certificates.crt "
        "/etc/ssl/certs/ca-certificates.crt"
    )
    assert "@sha256:" in trust_source
    assert bootstrap in dockerfile
    assert 'APT::Snapshot "20261015T070000Z";' in dockerfile
    assert "/etc/apt/apt.conf.d/50snapshot" in dockerfile
    assert dockerfile.index(bootstrap) < dockerfile.index("apt-get")
    assert "apt-get -o APT::Update::Error-Mode=any update" in dockerfile


def test_parallel_builds_never_exceed_jobs(monkeypatch, tmp_path: Path) -> None:
    catalog = container_build.load_catalog()
    monkeypatch.setattr(container_build, "RUN_ROOT", tmp_path)
    guard = threading.Lock()
    active = 0
    maximum = 0

    def fake_build(item, run_dir, **_options):
        nonlocal active, maximum
        with guard:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.05)
        with guard:
            active -= 1
        return {"id": item["id"], "tag": item["tag"], "status": "passed",
                "duration_seconds": 0.05, "digest": "sha256:fixture",
                "fetch_log": None, "build_log": None}

    monkeypatch.setattr(container_build, "build_one", fake_build)
    args = argparse.Namespace(ids=["base-ubuntu", "base-python", "base-php", "base-jre"],
                              all=False, jobs=2, continue_on_error=True)
    assert container_build.execute_build(args, catalog) == 0
    assert maximum == 2


def test_osv_functional_smoke_allows_the_runtime_user_to_write(monkeypatch, tmp_path: Path) -> None:
    feed = tmp_path / "data" / "feeds" / "osv"
    snapshot = feed / "snapshots" / "fixture"
    (snapshot / "sources").mkdir(parents=True)
    data = b"fixture database"
    (snapshot / "sources" / "PyPI.zip").write_bytes(data)
    (snapshot / "manifest.json").write_text(json.dumps({
        "files": {"sources/PyPI.zip": {
            "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        }},
    }))
    (feed / "current.json").write_text(json.dumps({"snapshot_id": "fixture"}))
    monkeypatch.setattr(container_build, "ROOT", tmp_path)
    monkeypatch.setattr(container_build, "RUN_ROOT", tmp_path / "runs")
    monkeypatch.setattr(container_build, "runtime_args", lambda policy: ["docker", "run"])

    def run(argv, **kwargs):
        mount = next(value for value in argv if value.endswith(",dst=/scratch"))
        output = Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])
        assert output.stat().st_mode & 0o002
        (output / "result.json").write_text('{"package": "django"}')
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(container_build.subprocess, "run", run)
    catalog = {"by_id": {"tool-osv-scanner": {"tag": "fixture/osv"}}}
    assert container_build.functional_smoke(
        ["tool-osv-scanner"], catalog, {"timeout_seconds": 10},
    ) == 0


@pytest.mark.skipif(not _usable_bash() or not shutil.which("pwsh"),
                    reason="Bash and PowerShell are both required for launcher parity")
def test_bash_and_powershell_selection_parity() -> None:
    ids = ["tool-gitleaks", "tool-semgrep"]
    bash = subprocess.run(["bash", "containers/build-all.sh",
                           "list", "--json", *ids], cwd=ROOT, capture_output=True,
                          text=True, check=True)
    powershell = subprocess.run(["pwsh", "-NoProfile", "-File",
                                 str(ROOT / "containers" / "build-all.ps1"),
                                 "list", "--json", *ids], cwd=ROOT, capture_output=True,
                                text=True, check=True)
    assert json.loads(bash.stdout) == json.loads(powershell.stdout)


def test_named_build_contexts_are_validated_and_passed_to_docker(monkeypatch, tmp_path: Path) -> None:
    catalog = container_build.load_catalog()
    item = dict(catalog["by_id"]["tool-joern"])
    assert item["build_contexts"] == {"shared": "containers/tools/shared"}
    catalog["by_id"]["tool-joern"] = catalog["images"][[i["id"] for i in catalog["images"]].index(
        "tool-joern")] = {**item, "build_contexts": {"shared": "../outside"}}
    assert any("tool-joern" in error and "escapes" in error for error in container_build.validate(catalog))

    calls = []
    monkeypatch.setattr(container_build, "fetch_one", lambda item, log: None)
    monkeypatch.setattr(container_build, "run_logged", lambda argv, log, timeout: calls.append(argv) or
                        subprocess.CompletedProcess(argv, 1))
    container_build.build_one(item, tmp_path)
    (argv,) = calls
    assert argv[argv.index("--build-context") + 1] == (
        "shared=" + str(container_build.safe_path("containers/tools/shared")))
    assert "--network=none" in argv


def test_build_timeout_is_passed_to_each_image_and_bounded(monkeypatch, tmp_path: Path) -> None:
    catalog = container_build.load_catalog()
    monkeypatch.setattr(container_build, "RUN_ROOT", tmp_path)
    seen = []

    def fake_build(item, run_dir, *, timeout_seconds):
        seen.append(timeout_seconds)
        return {"id": item["id"], "tag": item["tag"], "status": "passed", "duration_seconds": 0.01,
                "digest": "sha256:fixture", "fetch_log": None, "build_log": None}

    monkeypatch.setattr(container_build, "build_one", fake_build)
    args = container_build.parser().parse_args(["build", "base-ubuntu", "--timeout-seconds", "120"])
    assert container_build.execute_build(args, catalog) == 0
    assert seen == [120]
    assert json.loads(next(tmp_path.glob("*/summary.json")).read_text())["timeout_seconds"] == 120
    with pytest.raises(ValueError, match="build timeout"):
        container_build.execute_build(container_build.parser().parse_args(
            ["build", "base-ubuntu", "--timeout-seconds", "5"]), catalog)


def test_a_docker_build_timeout_is_a_failed_image(monkeypatch, tmp_path: Path) -> None:
    item = container_build.load_catalog()["by_id"]["base-ubuntu"]
    monkeypatch.setattr(container_build, "fetch_one", lambda item, log: None)

    def expire(argv, log, timeout):
        raise subprocess.TimeoutExpired(argv, timeout)

    monkeypatch.setattr(container_build, "run_logged", expire)
    result = container_build.build_one(item, tmp_path, timeout_seconds=60)
    assert result["status"] == "failed" and result["error"] == "docker build timed out after 60 seconds"


def _final_base(dockerfile: Path) -> str:
    """Resolve the final stage's base image through named build stages."""
    stages: dict[str, str] = {}
    base = ""
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].upper() == "FROM":
            image = parts[1]
            base = stages.get(image, image)
            if len(parts) >= 4 and parts[2].upper() == "AS":
                stages[parts[3]] = base
    return base


def test_tool_manifest_dependency_names_the_dockerfile_final_base() -> None:
    mismatches = {}
    for manifest in sorted((ROOT / "containers" / "tools").glob("*/tool.toml")):
        dockerfile = manifest.parent / "Dockerfile"
        dependency = tomllib.loads(manifest.read_text(encoding="utf-8")).get("dependency")
        if dependency is None or not dockerfile.is_file():
            continue
        if _final_base(dockerfile) != dependency:
            mismatches[manifest.parent.name] = (dependency, _final_base(dockerfile))
    assert mismatches == {}


BUILDKIT_LOG = """\
#1 [internal] load build definition from Dockerfile
#1 transferring dockerfile: 1.20kB done
#1 DONE 0.0s

#2 [internal] load metadata for ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
#2 DONE 0.0s

#3 [unpack 1/3] FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
#3 CACHED

#4 [unpack 2/3] COPY downloads/gitleaks.tar.gz /tmp/asset
#4 DONE 0.3s

#5 [unpack 3/3] RUN mkdir -p /opt/tool/bin && tar -xzf /tmp/asset -C /opt/tool/bin gitleaks
#5 1.204 extracting
#5 DONE 12.5s

#6 [stage-1 2/3] COPY --from=unpack /opt/tool/bin/gitleaks /opt/tool/bin/gitleaks
#6 CACHED

#7 [stage-1 3/3] RUN /opt/tool/bin/gitleaks version 2>&1 | grep -F "8.21.2"
#7 0.412 v8.21.2
#7 DONE 0.6s

#8 exporting to image
#8 exporting layers done
#8 DONE 0.4s
"""


def test_buildkit_log_telemetry_counts_cached_and_executed_steps() -> None:
    steps = container_build.parse_buildkit_log(BUILDKIT_LOG)
    assert steps["steps"] == 8 and steps["cached_steps"] == 2 and steps["executed_steps"] == 6
    assert steps["errored_steps"] == 0 and steps["unfinished_steps"] == 0
    assert steps["executed_seconds"] == 13.8
    assert steps["slowest_step"] == {"step": "[unpack 3/3] RUN mkdir -p /opt/tool/bin && tar -xzf /tmp/asset -C /opt/tool/bin gitleaks",
                                     "seconds": 12.5}
    truncated = BUILDKIT_LOG.split("#7 DONE")[0]  # a build that timed out inside step 7
    assert container_build.parse_buildkit_log(truncated)["unfinished_steps"] == 1  # #7 never closes
    assert container_build.parse_buildkit_log("not a buildkit log\n") == {
        "steps": 0, "cached_steps": 0, "executed_steps": 0, "errored_steps": 0, "unfinished_steps": 0,
        "executed_seconds": 0.0, "slowest_step": None}


def test_build_one_records_fetch_and_build_timings_steps_and_image_size(monkeypatch, tmp_path: Path) -> None:
    item = container_build.load_catalog()["by_id"]["tool-gitleaks"]
    monkeypatch.setattr(container_build, "fetch_one", lambda item, log: {"current": 1, "fetched": 0, "bytes": 1000})

    def build(argv, log, timeout):
        assert "--progress=plain" in argv
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(BUILDKIT_LOG, encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0)

    def inspect(argv, **kwargs):
        assert argv[-1] == "{{.Id}} {{.Size}}"
        return subprocess.CompletedProcess(argv, 0, stdout="sha256:" + "ab" * 32 + " 123456789\n", stderr="")

    monkeypatch.setattr(container_build, "run_logged", build)
    monkeypatch.setattr(container_build.subprocess, "run", inspect)
    result = container_build.build_one(item, tmp_path, timeout_seconds=60)
    assert result["status"] == "passed" and result["digest"] == "sha256:" + "ab" * 32
    assert result["size_bytes"] == 123456789 and result["assets"] == {"current": 1, "fetched": 0, "bytes": 1000}
    assert result["steps"]["cached_steps"] == 2 and result["steps"]["executed_steps"] == 6
    assert 0 <= result["fetch_seconds"] <= result["duration_seconds"]
    assert 0 <= result["build_seconds"] <= result["duration_seconds"]


def _fake_results(durations: dict[str, float], statuses: dict[str, str] | None = None) -> list[dict]:
    statuses = statuses or {}
    return [{"id": image_id, "tag": f"appsec-review/{image_id}", "status": statuses.get(image_id, "passed"),
             "duration_seconds": seconds, "build_seconds": seconds * 0.9, "fetch_seconds": seconds * 0.1,
             "digest": "sha256:fixture", "fetch_log": None, "build_log": None, "size_bytes": 1_000_000,
             "assets": {"current": 1, "fetched": 1, "bytes": 10},
             "steps": {"steps": 4, "cached_steps": 1, "executed_steps": 3, "errored_steps": 0,
                       "unfinished_steps": 0, "executed_seconds": seconds, "slowest_step": None}}
            for image_id, seconds in durations.items()]


def test_build_metrics_find_the_dependency_critical_path_not_the_slowest_image() -> None:
    catalog = container_build.load_catalog()
    # base-ubuntu -> buildenv-native-toolchain -> audit-buildenv-cpp is a chain of 10 + 100 + 50 = 160 s;
    # tool-svf alone takes 150 s but its chain (tool-native-cpp 5 s) is shorter.
    summary = {"results": _fake_results({"base-ubuntu": 10, "buildenv-native-toolchain": 100,
                                          "audit-buildenv-cpp": 50, "tool-native-cpp": 5, "tool-svf": 150,
                                          "base-python": 3, "tool-zizmor": 2})}
    metrics = container_build.build_metrics(summary, catalog)
    assert metrics["critical_path"] == {"seconds": 160.0, "images": ["base-ubuntu", "buildenv-native-toolchain", "audit-buildenv-cpp"]}
    assert metrics["slowest"][0] == {"id": "tool-svf", "seconds": 150.0, "status": "passed"}
    assert metrics["images"] == 7 and metrics["by_status"] == {"passed": 7}
    assert metrics["cached_steps"] == 7 and metrics["executed_steps"] == 21
    assert metrics["assets_fetched"] == 7 and metrics["size_bytes"] == 7_000_000
    assert metrics["build_seconds"] == round(320 * 0.9, 3)


def test_execute_build_writes_schema_2_summary_with_metrics_and_prints_the_report(monkeypatch, tmp_path: Path, capsys) -> None:
    catalog = container_build.load_catalog()
    monkeypatch.setattr(container_build, "RUN_ROOT", tmp_path)

    def fake_build(item, run_dir, **_options):
        return _fake_results({item["id"]: 1.5})[0]

    monkeypatch.setattr(container_build, "build_one", fake_build)
    args = argparse.Namespace(ids=["tool-gitleaks"], all=False, jobs=2, continue_on_error=False)
    assert container_build.execute_build(args, catalog) == 0
    summary = json.loads(next(tmp_path.glob("*/summary.json")).read_text())
    assert summary["schema"] == "appsec-review/container-build-summary/2"
    assert summary["metrics"]["critical_path"]["images"] == ["base-ubuntu", "tool-gitleaks"]
    assert summary["wall_seconds"] >= 0 and summary["started_at"].endswith("+00:00")
    out = capsys.readouterr().out
    assert "critical path 3.0s: base-ubuntu -> tool-gitleaks" in out
    assert re.search(r"^PASSED\s+1\.5\s+0\.2\s+1c/3x\s+1MB\s+tool-gitleaks$", out, re.M)
    # `report` re-reads the summary; a schema-1 summary gets metrics computed on the fly.
    code = container_build.main(["report", str(next(tmp_path.glob("*/summary.json"))), "--json"])
    assert code == 0 and json.loads(capsys.readouterr().out)["images"] == 2
    old = {"schema": "appsec-review/container-build-summary/1", "results": _fake_results({"base-ubuntu": 2})}
    (tmp_path / "old.json").write_text(json.dumps(old), encoding="utf-8")
    assert container_build.main(["report", str(tmp_path / "old.json")]) == 0
    assert "critical path 2.0s: base-ubuntu" in capsys.readouterr().out


BUILD_DRIVERS = {"autoconf": "2.71", "automake": "1.16.5", "cmake": "3.28.3", "libtool": "2.4.7",
                 "meson": "1.3.2", "ninja-build": "1.11.1", "pkg-config": "1.8.1"}


def test_build_drivers_live_in_the_shared_toolchain_and_nowhere_else() -> None:
    """T-058: one pinned set of build drivers for every family that builds FROM the toolchain."""
    toolchain = ROOT / "containers" / "buildenv" / "native-toolchain"
    pins = dict(line.split("=", 1) for line in (toolchain / "packages.lock").read_text(encoding="utf-8").splitlines()
                if line and not line.startswith("#"))
    for package, version in BUILD_DRIVERS.items():
        assert package in pins, package
        upstream = pins[package].split(":", 1)[-1] if ":" in pins[package] else pins[package]  # drop the epoch
        assert upstream.startswith(version), (package, pins[package])
    probes = (toolchain / "check-toolchain.sh").read_text(encoding="utf-8")
    for probe in ("cmake --version", "ninja --version", "meson --version", "autoconf --version",
                  "automake --version", "libtool --version"):
        assert probe in probes
    assert "Bazel" in (toolchain / "packages.lock").read_text(encoding="utf-8"), "the lock records why Bazel is absent"
    for family in ("cpp", "go", "php", "python", "rust-wasm", "typescript"):
        dockerfile = (toolchain.parent / family / "Dockerfile").read_text(encoding="utf-8")
        installs = " ".join(line for line in dockerfile.splitlines() if not line.lstrip().startswith("#"))
        for package in BUILD_DRIVERS:
            assert f" {package}=" not in installs, f"{family} re-installs {package}, which the toolchain carries"
    catalog = container_build.load_catalog()["by_id"]
    assert "cmake version 3.28.3" in catalog["buildenv-native-toolchain"]["probe_expect"]
    assert "1.3.2" in catalog["buildenv-native-toolchain"]["probe_expect"]
