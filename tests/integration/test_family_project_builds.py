"""Real-image project and language builds of the multivuln native, rust, wasm, go, python and
php projects.

Each case copies one project of ``targets/appsec-multi-vuln`` (at its own relative path) into a
run-owned target and drives the review pipeline exactly as a run does: intake, catalog, analysis
plan, ``job_project_build`` (real derived images, real probe containers, real execution capture)
and ``job_language_build`` (real build containers and capture). Only recipe inference is replaced:
``RECIPES`` holds the recipe a build engineer derives from each project's own build files and
README, standing in for the planning model. Deterministic recipes (CMake, phpize) come from the
pipeline itself and are not listed.

Gating mirrors ``tests/test_live_build_image_hello.py``: a missing Docker daemon or build image
skips. A build image whose local id differs from its pinned ``image_id`` fails, because the pin is
the identity a run accepts; set ``APPSEC_REVIEW_BUILDENV_PINS=local`` to run against locally built
images, which rewrites only this test's temporary configuration.

Run explicitly, one family at a time on a host with little disk:

    python -m pytest tests/integration/test_family_project_builds.py --basetemp=test/tmp/<name> -k go
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tomllib
from typing import Any, Callable

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import profiles_from_settings
from appsec_review.inference import ModelResult
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_cpp_compiled_analysis.job import native_analysis_actions
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_project_build.job import load_accepted_builds
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner


ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "targets" / "appsec-multi-vuln"
pytestmark = pytest.mark.requires_target("appsec-multi-vuln")

# Interpreted projects with no build descriptor: positively not applicable for build processing.
SOURCE_ONLY = [
    *(f"python/case-{number:03d}" for number in range(73, 81)),
    "php/case-018", "php/case-052", "php/case-060", "php/case-070",
]
BUILT = [
    "native/case-083", "native/linux-calibration",
    *(f"rust/case-{number}" for number in ("004", "005", "006", "033", "040", "051", "065")),
    "wasm/case-091",
    *(f"go/case-{number}" for number in ("007", "008", "009", "039", "046", "055", "064")),
    "python-package/case-085",
    "php-composer/case-089", "php-extension/case-090",
]


def _recipe(unit: dict[str, Any], target: Path) -> dict[str, Any] | None:
    """The recipe each project's own build files and README call for (the inference stand-in)."""
    root, family = str(unit["root"]), str(unit["family"])
    project = target / root
    documents = [str(item["path"]) for item in unit["descriptor_package"]["documents"]]
    base = {"schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
            "image_profile": family, "source_dir": root, "system_packages": [], "environment": {}}
    if family == "rust":
        manifest = tomllib.loads((project / "Cargo.toml").read_text(encoding="utf-8"))
        name = manifest["package"]["name"]
        return {**base, "build_dir": f"{root}/target", "dependency_files": [f"{root}/Cargo.toml"],
                "configure_commands": [], "build_commands": [["cargo", "build"]],
                "expected_outputs": [f"{root}/target/debug/{name}"],
                "network_required": bool(manifest.get("dependencies")),
                "reason": "Cargo package build; registry dependencies are restored when declared."}
    if family == "go":
        # The recipe the live planning model produced for every multivuln Go module.
        module = re.search(r"^module\s+(\S+)", (project / "go.mod").read_text(encoding="utf-8"), re.M)
        assert module is not None
        return {**base, "build_dir": root, "dependency_files": [f"{root}/go.mod"],
                "configure_commands": [],
                "build_commands": [["go", "mod", "download"], ["go", "mod", "verify"],
                                   ["go", "build", "./..."]],
                "expected_outputs": [f"{root}/{module.group(1)}"], "network_required": False,
                "reason": "Go module build with module download and checksum verification."}
    if family == "wasm":
        # build.sh: clang --target=wasm32 -std=c17 -Oz -nostdlib -Wl,... -o build/case091.wasm src/*.c
        sources = sorted(str(item["path"])[len(root) + 1:] for item in unit.get("native_components", ()))
        return {**base, "build_dir": root, "dependency_files": [f"{root}/build.sh"],
                "configure_commands": [],
                "build_commands": [["clang", "--target=wasm32", "-std=c17", "-Oz", "-nostdlib",
                                    "-Wl,--no-entry", "-Wl,--export=copy_input", "-Wl,--strip-all",
                                    "-o", "case091.wasm", *sources]],
                "expected_outputs": [f"{root}/case091.wasm"], "network_required": False,
                "reason": "Translation of build.sh: one clang wasm32 compile and link."}
    if family == "python":
        requirements = [path for path in documents if PurePosixPath(path).name.startswith("requirements")]
        markers = [str(item["path"]) for item in unit["markers"]]
        return {**base, "build_dir": f"{root}/build",
                "dependency_files": sorted({*markers, *requirements}),
                "configure_commands": [],
                "build_commands": [["python", "-m", "pip", "wheel", ".", "--no-deps",
                                    "--no-build-isolation", "--wheel-dir", "dist"]],
                "expected_outputs": [f"{root}/dist"], "network_required": bool(requirements),
                "reason": "README wheel build; pinned build backend restored from requirements."}
    if family == "php" and unit["build_system"] == "composer":
        files = [path for path in documents if PurePosixPath(path).name in {"composer.json", "composer.lock"}]
        return {**base, "build_dir": root, "dependency_files": sorted(files),
                "configure_commands": [["composer", "install", "--no-interaction"]],
                "build_commands": [["composer", "run", "build"]],
                "expected_outputs": [f"{root}/vendor"], "network_required": False,
                "reason": "README: composer install && composer run build; the lock has no packages."}
    return None


class RecipeModel:
    def __init__(self, target: Path) -> None:
        self.target = target

    def __call__(self, request, *, timeout_seconds: int) -> ModelResult:
        recipes = [recipe for unit in request.summary["build_units"]
                   if (recipe := _recipe(unit, self.target)) is not None]
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
                            "build_recipes": recipes})


def _docker_image_id(tag: str) -> str | None:
    try:
        completed = subprocess.run(["docker", "image", "inspect", tag, "--format", "{{.Id}}"],
                                   capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None


def _config(tmp_path: Path, families: set[str]):
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    profiles = profiles_from_settings(tomllib.loads(text)["jobs"]["job_project_build"]["settings"]["profiles"])
    for family in sorted(families):
        profile = profiles[family]
        local = _docker_image_id(profile.tag)
        if local is None:
            pytest.skip(f"live build image is unavailable: {profile.tag}")
        if local != profile.image_id:
            if os.environ.get("APPSEC_REVIEW_BUILDENV_PINS") != "local":
                pytest.fail(f"{profile.tag} is {local}, not the pinned {profile.image_id}; rebuild it "
                            "from containers/buildenv or update the pin (see containers/buildenv/README.md)")
            text = text.replace(f'image_id = "{profile.image_id}"', f'image_id = "{local}"')
    path = tmp_path / "appsec-review.toml"
    path.write_text(text, encoding="utf-8")
    return load_config(path)


def _target(tmp_path: Path, project: str) -> Path:
    target = tmp_path / "target"
    source = TARGET / "projects" / project
    shutil.copytree(source, target / "projects" / project)
    return target


def _pipeline(tmp_path: Path, project: str, families: set[str]):
    config = _config(tmp_path, families)
    target = _target(tmp_path, project)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel(target))]).run(
        target_root=target, source_fingerprint=fingerprint)
    run_id = upstream["run_id"]
    GraphRunner(config, [build_projects()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    run_root = config.runtime.runs_dir / run_id
    return config, target, fingerprint, run_id, run_root


def _family(project: str) -> str:
    head = project.split("/", 1)[0]
    return {"native": "native", "rust": "rust", "wasm": "wasm", "go": "go", "python-package": "python",
            "php-composer": "php", "php-extension": "php"}[head]


def _diagnostics(run_root: Path, receipt: dict[str, Any]) -> str:
    lines = [f"status={receipt.get('terminal_status')} gaps={receipt.get('gaps')}"]
    for command in receipt.get("commands", ()):
        for stream in ("stdout", "stderr"):
            identity = command.get(stream)
            if isinstance(identity, dict) and identity.get("path"):
                path = run_root / identity["path"]
                if path.is_file():
                    lines.append(f"--- command {command.get('ordinal')} {stream}\n" +
                                 path.read_bytes()[-4000:].decode("utf-8", "replace"))
    return "\n".join(lines)


@pytest.mark.parametrize("project", SOURCE_ONLY)
def test_interpreted_project_is_recorded_not_applicable_for_build(tmp_path: Path, project: str) -> None:
    shutil.copy(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    config = load_config(tmp_path / "appsec-review.toml")
    target = _target(tmp_path, project)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel(target))]).run(
        target_root=target, source_fingerprint=fingerprint)
    GraphRunner(config, [build_projects()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    accepted = load_accepted_builds(config.runtime.runs_dir / upstream["run_id"])
    assert accepted["build_dispatches"] == [] and accepted["probe_receipts"] == []
    decisions = {(item["feature"], item["disposition"], item["reason_code"])
                 for item in accepted["processing_decisions"]}
    assert decisions == {
        ("build-execution-capture", "SKIPPED_NA", "MATERIAL_BUILD_ABSENT"),
        ("compiler-artifact-collection", "SKIPPED_NA", "ARTIFACT_CAPABILITY_ABSENT"),
    }, accepted["processing_decisions"]
    assert all(item["project_id"].startswith("source-scope-") for item in accepted["processing_decisions"])


@pytest.mark.parametrize("project", BUILT)
def test_family_project_builds_in_its_pinned_image(tmp_path: Path, project: str) -> None:
    family = _family(project)
    config, target, fingerprint, run_id, run_root = _pipeline(tmp_path, project, {family})
    accepted = load_accepted_builds(run_root)
    probes = accepted["probe_receipts"]
    # One unit per project: mixed C/C++ sources never become a second direct-native unit.
    assert [(item["family"], item["root"]) for item in probes] == [(family, f"projects/{project}")], probes
    probe = probes[0]
    assert probe["terminal_status"] == "SUCCEEDED", probe.get("gaps")
    GraphRunner(config, [build_language()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    language = load_accepted_language_build(run_root)
    receipts = [item for item in language["receipts"] if item.get("build_unit_id") == probe["build_unit_id"]]
    assert len(receipts) == 1, language["receipts"]
    receipt = receipts[0]
    detail = _diagnostics(run_root, receipt)
    assert receipt["terminal_status"] == "SUCCEEDED", detail
    assert receipt.get("gaps", []) == [], detail
    decisions = {item["feature"]: (item["disposition"], item["reason_code"])
                 for item in receipt.get("processing_decisions", ())}
    if decisions:
        assert set(decisions.values()) == {("SUCCEEDED", "PROCESSING_SUCCEEDED")}, decisions
    kinds = {item["kind"] for item in receipt["artifacts"]}
    expected: dict[str, set[str]] = {
        "native": {"executable"}, "rust": {"executable"}, "go": {"executable"},
        "wasm": {"wasm-module"},
    }
    if project == "native/linux-calibration":
        expected["native"] = {"executable", "shared-library", "static-library", "compile-database"}
    if project == "python-package/case-085":
        assert {"wheel", "native-extension"} <= kinds, detail
    elif project == "php-composer/case-089":
        assert "generated-autoload" in kinds, detail
        assert (run_root / receipt["workspace"] / f"projects/{project}/.build/composer.marker").is_file()
    elif project == "php-extension/case-090":
        assert "native-extension" in kinds, detail
    else:
        assert expected[family] <= kinds, (kinds, detail)
    if project in {"python-package/case-085", "php-extension/case-090", "wasm/case-091"}:
        # The family build's single capture recorded the C compile; it reaches native analysis.
        database = receipt["native_compile_database"]
        assert database["entry_count"] >= 1 and database["family"] == family
        assert {item["path"] for item in receipt["native_components"]}
        actions = native_analysis_actions(language, target)
        selected = [item for item in actions if item["build_unit_id"] == receipt["build_unit_id"]]
        assert len(selected) == 1 and selected[0]["family"] == family
        assert selected[0]["compile_database_origin"] == "captured-native-components"
