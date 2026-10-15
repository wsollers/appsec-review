"""Real-image project and language builds for the JVM and .NET multivuln projects.

One module-scoped pipeline run drives the same jobs a review runs: intake, catalog and planning
(with a fixed recipe model standing in for inference), job_project_build (derived project images,
captured probes, repair-free dispatch) and job_language_build. Every project is then asserted
individually.

Gates (environment, never outcome): Docker must be usable, the local ``targets/appsec-multi-vuln``
checkout must exist, and a profile's image must be built locally from ``containers/catalog.toml``.
Profile image ids in ``appsec-review.toml`` are host-specific build results, so the copied test
configuration pins each profile to the identity of the locally built catalog tag.

A project whose dependencies come from a public repository is asserted as built when the build
container can reach that repository, and otherwise as a truthful, named image/probe gap. It is
never skipped for that reason.

Run with a unique ``--basetemp=test/tmp/<session>``; all run output stays under it.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import CaptureScope, profiles_from_settings, verify_capture_record
from appsec_review.inference import ModelResult
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_project_build import build_job as build_projects, load_accepted_builds
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner
from appsec_review.storage import file_sha256


ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "targets" / "appsec-multi-vuln"

pytestmark = [pytest.mark.requires_target("appsec-multi-vuln")]


@dataclass(frozen=True)
class Project:
    root: str
    profile: str
    build_system: str
    artifacts: tuple[str, ...]
    dependency_host: str | None = None


def _javac(case: str) -> Project:
    return Project(f"projects/java/{case}", "java", "javac",
                   ("build/classes/Main.class", "build/appsec-review.jar"))


PROJECTS = (
    *(_javac(case) for case in ("case-016", "case-017", "case-041", "case-042",
                                "case-049", "case-058", "case-068")),
    # pom.xml declares commons-collections 3.2.1, and Maven plugins always resolve remotely.
    Project("projects/java/case-034", "java", "maven",
            ("target/classes/Main.class", "target/case-034-0.1.0.jar"),
            dependency_host="https://repo.maven.apache.org/maven2/"),
    Project("projects/kotlin/case-084", "java", "javac",
            ("build/classes/fixture/case084/Case084Kt.class", "build/appsec-review.jar")),
    # The Android Gradle plugin and its dependencies resolve from Google's Maven repository.
    Project("projects/android/case-092", "android", "gradle",
            ("app/build/outputs/apk/debug/app-debug.apk",),
            dependency_host="https://dl.google.com/dl/android/maven2/"),
    *(Project(f"projects/dotnet/{case}", "dotnet", "dotnet",
              (f"bin/Debug/net8.0/{case}.dll", f"bin/Debug/net8.0/{case}.pdb"),
              # case-035.csproj references Newtonsoft.Json 12.0.1 from nuget.org.
              dependency_host="https://api.nuget.org/v3/index.json" if case == "case-035" else None)
      for case in ("case-014", "case-015", "case-035", "case-043", "case-044", "case-050",
                   "case-059", "case-069", "case-071")),
)


def _docker_usable() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=60,
                              check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _image_id(tag: str) -> str | None:
    result = subprocess.run(["docker", "image", "inspect", tag, "--format", "{{.Id}}"],
                            capture_output=True, text=True, timeout=60, check=False)
    value = result.stdout.strip()
    return value if result.returncode == 0 and value.startswith("sha256:") else None


def _egress(tag: str, url: str) -> bool:
    """Whether a build container on the executor's network can complete TLS to ``url``.

    Any HTTP response, an error status included, proves connectivity: repository roots such as
    Google's Maven repository serve no index and answer 404, while builds fetch concrete paths."""
    probe = ("import sys, urllib.error, urllib.request\n"
             "try:\n urllib.request.urlopen(sys.argv[1], timeout=20)\n"
             "except urllib.error.HTTPError:\n pass\n"
             "except Exception as exc:\n print(type(exc).__name__, exc); sys.exit(1)\n")
    result = subprocess.run(["docker", "run", "--rm", "--network", "bridge", "--entrypoint",
                             "python3", tag, "-c", probe, url],
                            capture_output=True, text=True, timeout=120, check=False)
    return result.returncode == 0


class MultivulnRecipeModel:
    """Fixed recipes of the shape recipe inference returns for these build units."""

    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            root, system = unit["root"], unit["build_system"]
            markers = [item["path"] for item in unit["markers"]]
            profile = unit["required_image_profile"]
            recipe: dict[str, Any] = {
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": profile, "source_dir": root, "system_packages": [],
                "environment": {}, "dependency_files": markers, "configure_commands": [],
                "network_required": False, "reason": "multivuln integration recipe"}
            if system == "javac":
                sources = [PurePosixPath(path).relative_to(root).as_posix() for path in markers]
                compiler = "kotlinc" if any(path.endswith(".kt") for path in sources) else "javac"
                recipe.update(build_dir=f"{root}/build", expected_outputs=[f"{root}/build"],
                              build_commands=[[compiler, *sources, "-d", "build/classes"]])
            elif system == "maven":
                recipe.update(build_dir=f"{root}/target", expected_outputs=[f"{root}/target"],
                              build_commands=[["mvn", "-B", "-DskipTests", "package"]],
                              network_required=True)
            elif system == "gradle":
                documents = [item["path"] for item in unit["descriptor_package"]["documents"]]
                recipe.update(build_dir=f"{root}/app/build", dependency_files=documents,
                              expected_outputs=[f"{root}/app/build/outputs/apk/debug/app-debug.apk"],
                              build_commands=[["gradle", "--no-daemon", ":app:assembleDebug"]],
                              network_required=True)
            elif system == "dotnet":
                project = PurePosixPath(markers[0]).name
                packages = any("<PackageReference" in str(item.get("content", ""))
                               for item in unit["descriptor_package"]["documents"])
                recipe.update(build_dir=f"{root}/bin", expected_outputs=[f"{root}/bin"],
                              configure_commands=[["dotnet", "restore", project]],
                              build_commands=[["dotnet", "build", project, "--nologo"]],
                              network_required=packages)
            else:
                raise AssertionError(f"unexpected build unit: {root} {system}")
            recipes.append(recipe)
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
                            "build_recipes": recipes})


@pytest.fixture(scope="module")
def pipeline(tmp_path_factory) -> dict[str, Any]:
    if not _docker_usable():
        pytest.skip("Docker daemon is unavailable")
    base = tmp_path_factory.mktemp("jvm-dotnet")
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    config = load_config(ROOT / "appsec-review.toml")
    profiles = profiles_from_settings(config.job("job_project_build").settings["profiles"])
    available: dict[str, str] = {}
    for name in ("java", "android", "dotnet"):
        local = _image_id(profiles[name].tag)
        if local is None:
            continue
        available[name] = profiles[name].tag
        # Pins are host-specific; see the module docstring. Rewrite every occurrence of the
        # pinned id for this tag (the profile and any catalog mirror) in the copied config.
        text = text.replace(profiles[name].image_id, local)
    if not available:
        pytest.skip("no JVM or .NET build image is built locally")
    config_path = base / "appsec-review.toml"
    config_path.write_text(text, encoding="utf-8")
    config = load_config(config_path)
    assert config.runtime.runs_dir.resolve().is_relative_to(base.resolve())

    target = base / "target"
    selected = [project for project in PROJECTS if project.profile in available]
    for project in selected:
        shutil.copytree(TARGET / project.root, target / project.root)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan(
        infer=MultivulnRecipeModel().complete)]).run(target_root=target, source_fingerprint=fingerprint)
    assert upstream["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}, upstream
    plan_gaps = json.loads((config.runtime.runs_dir / upstream["run_id"] / "data" / "jobs" /
                            "job_target_analysis_plan" / "attempts" / "attempt_0001" / "steps" /
                            "plan_acceptance" / "tasks" / "validate_plan" / "result.json"
                            ).read_text(encoding="utf-8"))["gaps"]
    assert not [gap for gap in plan_gaps if "recipe" in gap], plan_gaps
    run_id = upstream["run_id"]
    project = GraphRunner(config, [build_projects()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    language = GraphRunner(config, [build_language()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    run_root = config.runtime.runs_dir / run_id
    egress = {project.dependency_host: _egress(available[project.profile], project.dependency_host)
              for project in selected if project.dependency_host}
    return {"run_root": run_root, "run_id": run_id, "available": available, "egress": egress,
            "project_status": project["status"], "language_status": language["status"],
            "accepted": load_accepted_builds(run_root),
            "language": load_accepted_language_build(run_root)}


def _diagnostics(run_root: Path, receipt: dict[str, Any]) -> str:
    lines = [json.dumps(receipt.get("gaps", []), indent=1)]
    for command in receipt.get("commands", ()):
        for name in ("stdout", "stderr"):
            stream = command.get(name)
            if isinstance(stream, dict) and (run_root / stream["path"]).is_file():
                lines.append(f"--- command {command.get('ordinal')} {name}")
                lines.append((run_root / stream["path"]).read_text(errors="replace")[-4000:])
    return "\n".join(lines)


@pytest.mark.parametrize("project", PROJECTS, ids=lambda project: project.root.removeprefix("projects/"))
def test_multivuln_jvm_dotnet_project_builds_through_the_pipeline(pipeline, project: Project) -> None:
    if project.profile not in pipeline["available"]:
        pytest.skip(f"build image for profile {project.profile} is not built on this host")
    run_root: Path = pipeline["run_root"]
    probe = next(item for item in pipeline["accepted"]["probe_receipts"] if item["root"] == project.root)
    if project.dependency_host and not pipeline["egress"][project.dependency_host]:
        # Environment cannot reach the dependency repository: the pipeline must say so with a
        # named gap and retained diagnostics, never dispatch a build or report success.
        assert probe["terminal_status"] in {"BLOCKED", "FAILED"}, probe
        assert probe["gaps"], probe
        image = next(entry for family in pipeline["accepted"]["images"].values()
                     for entry in family["entries"] if entry["action"]["root"] == project.root)
        assert image["terminal_status"] == "FAILED" or probe["terminal_status"] == "FAILED"
        assert not any(item["root"] == project.root for item in pipeline["accepted"]["build_dispatches"])
        if image["terminal_status"] == "FAILED":
            assert any("project image resolution failed" in gap for gap in image["gaps"])
            stderr = (run_root / image["streams"]["stderr"]["path"]).read_bytes()
            stdout = (run_root / image["streams"]["stdout"]["path"]).read_bytes()
            assert stderr or stdout, "image-build diagnostics were not retained"
        return

    detail = _diagnostics(run_root, probe)
    assert probe["terminal_status"] == "SUCCEEDED" and probe["gaps"] == [], detail
    for command in probe["commands"]:
        capture = command["execution_capture"]
        assert capture["complete"] is True, detail
        record = run_root / capture["path"]
        verified = verify_capture_record(record, run_root=run_root, scope=CaptureScope(
            pipeline["run_id"], "job_project_build", probe["commands"][0]["attempt_identity"].split(":")[0],
            probe["build_unit_id"], probe["family"]))
        assert verified.gaps == ()
        raw = verified.document["raw_traces"]
        assert raw["enabled"] is True and raw["records"], "raw strace files were not retained"
        assert all((record.parent / item["uri"]).is_file() and
                   file_sha256(record.parent / item["uri"]) == item["sha256"]
                   for item in raw["records"] if item["retained"])
    assert any(item["root"] == project.root for item in pipeline["accepted"]["build_dispatches"])

    receipt = next(item for item in pipeline["language"]["receipts"] if item["root"] == project.root)
    detail = _diagnostics(run_root, receipt)
    assert receipt["terminal_status"] == "SUCCEEDED" and receipt["gaps"] == [], detail
    assert all(decision["disposition"] != "GAP" for decision in receipt.get("processing_decisions", ()))
    artifacts = {item["workspace_path"]: item for item in receipt["artifacts"]}
    for relative in project.artifacts:
        logical = f"{project.root}/{relative}"
        assert logical in artifacts, sorted(artifacts)
        assert file_sha256(run_root / artifacts[logical]["path"]) == artifacts[logical]["sha256"]
    if project.profile in {"java", "android"}:
        tools = {item["tool"] for item in receipt["tool_invocations"]}
        expected = "kotlinc" if "kotlin" in project.root else "javac"
        assert expected in tools, tools
    else:
        assert receipt["capture_provenance"]["complete"] is True
        assert "compiler" in receipt["capture_provenance"]["observed_tool_kinds"]


def test_multivuln_pipeline_reports_exact_dispositions(pipeline) -> None:
    """Every selected project either dispatched a build or carries a named gap; none vanish."""
    roots = {project.root for project in PROJECTS if project.profile in pipeline["available"]}
    probed = {item["root"] for item in pipeline["accepted"]["probe_receipts"]}
    assert roots == probed
    for receipt in pipeline["accepted"]["probe_receipts"]:
        assert receipt["terminal_status"] == "SUCCEEDED" or receipt["gaps"], receipt
    assert all(re.fullmatch(r"build-unit-[0-9a-f]{20}", item["build_unit_id"])
               for item in pipeline["accepted"]["build_dispatches"])
