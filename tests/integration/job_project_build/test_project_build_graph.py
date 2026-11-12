"""Shared pre-walk graph helpers. T-113 moved the cases to tests/acceptance/job_project_build/.

This module has no tests; its existing imports are retained for callers owned by other walks.
"""
from __future__ import annotations

from dataclasses import replace
import json
import hashlib
from pathlib import Path


from appsec_review.config import load_config
from tests.release_support import declare_releases
from appsec_review.container_runtime import BuildCommandResult, ProjectImage
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_project_build.repair import REPAIR_SCHEMA


ROOT = Path(__file__).resolve().parents[3]


class RecipeModel:
    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            root = unit["root"]
            system = unit["build_system"]
            if system == "cmake":
                configure = [["cmake", "-S", root, "-B", f"{root}/build"]]
                build = [["cmake", "--build", f"{root}/build"]]
            else:
                configure = []
                build = [["cargo", "build", "--manifest-path", f"{root}/Cargo.toml"]]
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": unit["family"], "source_dir": root,
                "build_dir": f"{root}/{'build' if system == 'cmake' else 'target'}",
                "system_packages": [], "environment": {},
                "dependency_files": [item["path"] for item in unit["markers"]],
                "configure_commands": configure, "build_commands": build,
                "expected_outputs": [f"{root}/{'build' if system == 'cmake' else 'target'}"],
                "network_required": system == "cargo", "reason": "fixture recipe",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "action": "final", "hints": [], "abstentions": [],
                            "component_proposals": [],
                            "build_recipes": recipes})


class NodeRestoreRecipeModel:
    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            root = unit["root"]
            addon = root.endswith("case-087")
            output = (f"{root}/build/Release/case087.node" if addon
                      else f"{root}/dist/bundle.js")
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": "node", "source_dir": root,
                "build_dir": f"{root}/{'build' if addon else 'dist'}",
                "system_packages": [], "environment": {},
                "dependency_files": [f"{root}/package.json", f"{root}/package-lock.json"],
                "configure_commands": [["npm", "ci"]],
                "build_commands": [["npm", "run", "build"]],
                "expected_outputs": [output], "network_required": True,
                "reason": "locked fixture restore and build",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "action": "final", "hints": [], "abstentions": [],
                            "component_proposals": [],
                            "build_recipes": recipes})


class FakeBuildExecutor:
    def __init__(self, calls):
        self.calls = calls

    def resolve(self):
        return None

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append(tuple(argv))
        if argv[0] == "cmake" and "--build" in argv:
            output = workspace / "native" / "build" / "observer"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(b"\x7fELFfixture")
        if argv[0] == "cargo":
            output = workspace / "rust" / "target" / "debug" / "sample"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(b"\x7fELFfixture")
        return BuildCommandResult(tuple(argv), 0, b"ok", b"", False)

    def execute_captured(self, argv, *, workspace, working_directory, environment,
                         capture_directory, capture_config, scope, **_options):
        result = self.execute(argv, workspace=workspace, working_directory=working_directory,
                              environment=environment)
        capture_directory.mkdir(parents=True)
        events = capture_directory / "events.jsonl"
        stdout = capture_directory / "stdout"
        stderr = capture_directory / "stderr"
        events.write_bytes(b"")
        stdout.write_bytes(b"ok")
        stderr.write_bytes(b"")
        secret_scan = capture_directory / "secret-scan"
        secret_scan.mkdir()
        scan_stdout, scan_stderr = secret_scan / "stdout", secret_scan / "stderr"
        report, findings = secret_scan / "gitleaks.json", secret_scan / "findings.json"
        execution = secret_scan / "execution.json"
        scan_stdout.write_bytes(b"")
        scan_stderr.write_bytes(b"")
        report.write_text("[]\n", encoding="utf-8")
        findings.write_text(json.dumps({
            "schema": "appsec-review/build-capture-secret-findings/1",
            "scanner": {"tool_id": "tool-gitleaks"}, "observed": 0,
            "retained": 0, "capped": False, "findings": [],
        }, sort_keys=True) + "\n", encoding="utf-8")
        execution.write_text(json.dumps({
            "schema": "appsec-review/build-capture-secret-scan-execution/1",
            "tool_id": "tool-gitleaks", "exit_code": 0, "timed_out": False,
            "stdout": {"uri": "stdout", "sha256": hashlib.sha256(b"").hexdigest()},
            "stderr": {"uri": "stderr", "sha256": hashlib.sha256(b"").hexdigest()},
            "report": {"uri": "gitleaks.json", "sha256": hashlib.sha256(report.read_bytes()).hexdigest()},
        }, sort_keys=True) + "\n", encoding="utf-8")
        record = capture_directory / "record.json"
        record.write_text(json.dumps({
            "schema": "appsec-review/build-execution-record/1",
            "scope": {"run_id": scope.run_id, "job_id": scope.job_id,
                      "attempt_id": scope.attempt_id, "build_unit_id": scope.build_unit_id,
                      "family": scope.family},
            "coverage": {"complete": True, "gaps": []},
            "events": {"uri": "events.jsonl", "sha256": hashlib.sha256(b"").hexdigest()},
            "streams": {
                "stdout": {"uri": "stdout", "sha256": hashlib.sha256(b"ok").hexdigest()},
                "stderr": {"uri": "stderr", "sha256": hashlib.sha256(b"").hexdigest()},
            },
            "tool_calls": {"records": []},
            "secret_scan": {
                "scanner": "tool-gitleaks",
                "findings": {"uri": "secret-scan/findings.json",
                             "sha256": hashlib.sha256(findings.read_bytes()).hexdigest(),
                             "count": 0, "capped": False},
                "execution": {"uri": "secret-scan/execution.json",
                              "sha256": hashlib.sha256(execution.read_bytes()).hexdigest()},
            },
        }, sort_keys=True) + "\n", encoding="utf-8")
        return replace(result, capture_record=record)


class NodeRestoreExecutor(FakeBuildExecutor):
    def prepare_node_dependencies(self, **_kwargs):
        raise AssertionError("npm ci must not receive the immutable image dependency view")

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append(tuple(argv))
        assert environment["NPM_CONFIG_CACHE"] == "/tmp/appsec-npm-cache"
        if tuple(argv) == ("npm", "run", "build"):
            root = workspace / working_directory
            if working_directory.endswith("case-087"):
                output = root / "build" / "Release" / "case087.node"
                data = b"native-addon"
            else:
                output = root / "dist" / "bundle.js"
                data = b"const bundled = true;\n"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
        return BuildCommandResult(tuple(argv), 0, b"ok", b"", False)


class CaptureGapExecutor(FakeBuildExecutor):
    def execute_captured(self, *args, **kwargs):
        result = super().execute_captured(*args, **kwargs)
        record = json.loads(result.capture_record.read_text(encoding="utf-8"))
        record["coverage"] = {"complete": False, "gaps": ["temporary response file was not retained"]}
        result.capture_record.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        return result


class FakeImageResolver:
    def resolve(self, recipe, profile):
        identity = __import__("hashlib").sha256(
            __import__("json").dumps(recipe, sort_keys=True).encode()).hexdigest()
        return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
                            profile.image_id, profile.tag, profile.image_id, None, False, True,
                            {}), b"", b""


class RepairModel:
    def __init__(self, packages):
        self.packages = list(packages)
        self.calls = 0

    def complete(self, request, *, timeout_seconds):
        assert request.schema == REPAIR_SCHEMA
        packages = self.packages[min(self.calls, len(self.packages) - 1)]
        self.calls += 1
        return ModelResult({"schema": REPAIR_SCHEMA, "system_packages": packages,
                            "environment": {}, "package_manager": None,
                            "dependency_restores": [], "reason": "bounded fixture repair"})


class RepairImageResolver:
    def __init__(self, root: Path):
        self.root = root
        self.resolutions = []

    @staticmethod
    def _identity(recipe) -> str:
        return hashlib.sha256(json.dumps(recipe, sort_keys=True).encode()).hexdigest()

    def definition(self, recipe, profile):
        identity = self._identity(recipe)
        packages = " ".join(recipe.get("system_packages", ()))
        return identity, f"FROM {profile.tag}\nRUN apt-get install {packages}\n".encode()

    def resolve(self, recipe, profile):
        identity, dockerfile = self.definition(recipe, profile)
        packages = tuple(recipe.get("system_packages", ()))
        self.resolutions.append(packages)
        if not packages:
            return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
                                profile.image_id, profile.tag, profile.image_id, None, False, True,
                                {}), b"", b""
        image_id = "sha256:" + hashlib.sha256((identity + "image").encode()).hexdigest()
        context = self.root / "project-images" / identity / "context"
        context.mkdir(parents=True, exist_ok=True)
        dockerfile_path = context / "Dockerfile"
        dockerfile_path.write_bytes(dockerfile)
        relative = dockerfile_path.relative_to(self.root).as_posix()
        package_tag = "-".join(packages)
        return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
                            profile.image_id, f"repair-{profile.name}:{package_tag}", image_id,
                            hashlib.sha256(dockerfile).hexdigest(), True, False, {},
                            f"project-images/{identity}/manifest.json", relative), b"built", b""


class RepairingExecutor(FakeBuildExecutor):
    def __init__(self, calls, profile, *, success_package: str | None):
        super().__init__(calls)
        self.profile = profile
        self.success_package = success_package

    def execute(self, argv, *, workspace, working_directory, environment):
        if self.profile.name == "native" and argv[0] == "cmake" and "--build" not in argv:
            if self.success_package is None or self.success_package not in self.profile.tag:
                self.calls.append(tuple(argv))
                return BuildCommandResult(tuple(argv), 1, b"", b"fatal error: fixture.h: missing", False)
        return super().execute(argv, workspace=workspace,
                               working_directory=working_directory, environment=environment)


def _producers(infer=None):
    """The producers job_project_build consumes; a graph supplies only producers that are in it."""
    return [build_intake(), build_catalog(), build_plan(infer=infer) if infer is not None else build_plan()]


def _fixture(tmp_path: Path, *, declared_releases: bool = False):
    config_path = tmp_path / "appsec-review.toml"
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if declared_releases:
        text = declare_releases(text, platform="fixture-platform", build_toolchain="fixture-build",
                                validation="fixture-validation")
    config_path.write_text(text, encoding="utf-8")
    target = tmp_path / "target"
    (target / "native").mkdir(parents=True)
    (target / "native" / "CMakeLists.txt").write_text("project(sample)\n", encoding="utf-8")
    (target / "native" / "main.cpp").write_text("int main(){}\n", encoding="utf-8")
    (target / "rust" / "src").mkdir(parents=True)
    (target / "rust" / "Cargo.toml").write_text(
        "[package]\nname='sample'\nversion='0.1.0'\n", encoding="utf-8")
    (target / "rust" / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    return load_config(config_path), target
