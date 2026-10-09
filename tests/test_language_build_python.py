from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import BuildCommandResult, ProjectImage
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_language_build import python as python_adapter
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner, plan_jobs
from tests.capture_fakes import capturing_fake


ROOT = Path(__file__).parents[1]


class PythonRecipeModel:
    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            if unit["family"] != "python":
                continue
            root = unit["root"]
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": "python", "source_dir": root, "build_dir": f"{root}/build",
                "system_packages": [], "environment": {},
                "dependency_files": [item["path"] for item in unit["descriptor_package"]["documents"]],
                "configure_commands": [],
                "build_commands": [["python", "-m", "build", "--no-isolation", "--wheel", "--sdist", "."]],
                "expected_outputs": [f"{root}/dist"], "network_required": True,
                "reason": "locked offline Python package build",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
                            "build_recipes": recipes})


class ImageResolver:
    def __init__(self, target: Path):
        self.target = target

    def resolve(self, recipe, profile):
        hashes = dependency_hashes(self.target, recipe)
        identity = project_recipe_identity(recipe, profile, hashes)
        image_id = "sha256:" + "d" * 64
        return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
            profile.image_id, "derived-python:local", image_id, "f" * 64, True, False, hashes), b"", b""


class PythonExecutor:
    def __init__(self, *, fail_real: bool = False, truncate: bool = False):
        self.fail_real, self.truncate = fail_real, truncate
        self.calls: list[tuple[str, ...]] = []

    def resolve(self):
        return None

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append(tuple(argv))
        real = "/build/python/" in workspace.as_posix()
        if real and self.fail_real:
            return BuildCommandResult(tuple(argv), 2, b"", b"package build failed", False)
        root = workspace / working_directory
        dist, generated, bytecode = root / "dist", root / "build", root / "sample" / "__pycache__"
        dist.mkdir(parents=True, exist_ok=True); generated.mkdir(parents=True, exist_ok=True)
        bytecode.mkdir(parents=True, exist_ok=True)
        wheel = dist / "sample-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("sample/__init__.py", "")
            archive.writestr("sample-1.0.0.dist-info/METADATA", "Name: sample\nVersion: 1.0.0\n")
        with tarfile.open(dist / "sample-1.0.0.tar.gz", "w:gz") as archive:
            content = b"[build-system]\nrequires=[]\n"
            info = tarfile.TarInfo("sample-1.0.0/pyproject.toml"); info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        (generated / "generated.c").write_text("int generated(void) { return 1; }\n", encoding="utf-8")
        (bytecode / "__init__.cpython-313.pyc").write_bytes(b"pyc")
        stdout = b"SENSITIVE-RAW-OUTPUT\n" + b"x" * (128 if self.truncate else 0)
        stderr = b"gcc -c build/generated.c -o build/generated.o\n"
        return BuildCommandResult(tuple(argv), 0, stdout[:32], stderr, False,
                                  len(stdout), len(stderr), self.truncate, False,
                                  stdout[-16:] if self.truncate else b"", b"")


def _fixture(tmp_path: Path):
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"), encoding="utf-8")
    target = tmp_path / "target" / "packages" / "sample"
    (target / "src" / "sample").mkdir(parents=True)
    (target / "pyproject.toml").write_text(
        "[build-system]\nrequires=['setuptools==75.0.0']\nbuild-backend='setuptools.build_meta'\n"
        "[project]\nname='sample'\nversion='1.0.0'\ndependencies=['idna==3.10']\n",
        encoding="utf-8")
    (target / "poetry.lock").write_text("package = []\n", encoding="utf-8")
    (target / "src" / "sample" / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    return load_config(config_path), tmp_path / "target"


def _run_project(config, target, executor):
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(),
        build_plan(infer=PythonRecipeModel().complete)]).run(target_root=target, source_fingerprint=fingerprint)
    GraphRunner(config, [build_projects(executor_factory=lambda unit, profile: capturing_fake(profile, executor),
        image_resolver_factory=lambda unit: ImageResolver(target))]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    return upstream["run_id"], fingerprint


def test_python_build_catalogs_packages_provenance_streams_and_mcp(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    executor = PythonExecutor(truncate=True)
    run_id, fingerprint = _run_project(config, target, executor)
    outcome = GraphRunner(config, [build_language(executor_factory=lambda unit, profile: executor)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert receipt["family"] == "python" and receipt["terminal_status"] == "SUCCEEDED"
    assert {item["kind"] for item in receipt["artifacts"]} >= {
        "wheel", "source-distribution", "generated-source", "bytecode"}
    assert {item["tool_kind"] for item in receipt["tool_invocations"]} >= {
        "package-builder", "build-backend", "compiler-driver"}
    assert all("argv" not in item for item in receipt["tool_invocations"])
    assert receipt["package_relationships"] and receipt["package_members"]
    command = receipt["commands"][0]
    assert command["stdout"]["truncated"] is True
    assert command["stdout"]["total_bytes"] > command["stdout"]["captured_bytes"]
    assert command["stdout"]["diagnostic_tail"]["sha256"]
    protected = config.runtime.runs_dir / run_id / command["protected_argv"]["path"]
    assert "--no-isolation" in protected.read_text(encoding="utf-8")
    response = RetrievalCore(config.runtime.runs_dir, run_id).search(query="wheel", indexes=("build",))
    encoded = json.dumps(response)
    assert response["results"] and "SENSITIVE-RAW-OUTPUT" not in encoded and "--no-isolation" not in encoded
    graph = plan_jobs((build_language(executor_factory=lambda unit, profile: executor),), config)
    assert graph.node("job_language_build.execute.python").dependencies == ("job_language_build.load.python",)


def test_python_recipe_validation_is_package_only_and_allows_dependency_download(tmp_path: Path) -> None:
    setup = tmp_path / "setup.py"
    setup.write_text("from setuptools import setup\nsetup(name='sample')\n", encoding="utf-8")
    base = {"family": "python", "recipe": {"dependency_files": ["setup.py"],
        "network_required": False, "configure_commands": [],
        "build_commands": [["python", "setup.py", "sdist", "bdist_wheel"]]}}
    assert python_adapter.validate_dispatch(base, tmp_path) == []
    unsafe = {"family": "python", "recipe": {**base["recipe"],
        "build_commands": [["python", "-m", "pytest"]]}}
    assert any("allowlist" in gap for gap in python_adapter.validate_dispatch(unsafe, tmp_path))
    unlocked = {"family": "python", "recipe": {**base["recipe"], "network_required": True}}
    assert python_adapter.validate_dispatch(unlocked, tmp_path) == []


def test_python_failure_is_gap_and_checkpoint_tamper_stops_reuse(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    probe = PythonExecutor()
    run_id, fingerprint = _run_project(config, target, probe)
    outcome = GraphRunner(config, [build_language(executor_factory=lambda unit, profile:
        PythonExecutor(fail_real=True))]).run(target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    assert load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]["terminal_status"] == "FAILED"

    good = PythonExecutor()
    GraphRunner(config, [build_language(executor_factory=lambda unit, profile: good)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id, force_from="job_language_build")
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    artifact = config.runtime.runs_dir / run_id / receipt["artifacts"][0]["path"]
    artifact.write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="execute.python"):
        GraphRunner(config, [build_language(executor_factory=lambda unit, profile: PythonExecutor())]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id,
            force_from="job_language_build")
