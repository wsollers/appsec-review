from __future__ import annotations

import json
from pathlib import Path

from appsec_review.config import load_config
from appsec_review.container_runtime import BuildCommandResult
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_project_build import build_job as build_projects, load_accepted_builds
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_target_analysis_plan import ModelResult, build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.runtime import GraphRunner, plan_jobs


ROOT = Path(__file__).parents[1]


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
                "network_required": False, "reason": "fixture recipe",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
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


def _fixture(tmp_path: Path):
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"), encoding="utf-8")
    target = tmp_path / "target"
    (target / "native").mkdir(parents=True)
    (target / "native" / "CMakeLists.txt").write_text("project(sample)\n", encoding="utf-8")
    (target / "native" / "main.cpp").write_text("int main(){}\n", encoding="utf-8")
    (target / "rust" / "src").mkdir(parents=True)
    (target / "rust" / "Cargo.toml").write_text(
        "[package]\nname='sample'\nversion='0.1.0'\n", encoding="utf-8")
    (target / "rust" / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    return load_config(config_path), target


def test_project_build_executes_accepted_recipes_and_retains_binaries(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan(model_client=RecipeModel())]).run(
        target_root=target, source_fingerprint=fingerprint)
    calls = []
    job = build_projects(executor_factory=lambda unit, profile: FakeBuildExecutor(calls))
    outcome = GraphRunner(config, [job]).run(target_root=target, source_fingerprint=fingerprint,
                                             run_id=upstream["run_id"])
    assert outcome["status"] == "SUCCEEDED"
    accepted = load_accepted_builds(config.runtime.runs_dir / upstream["run_id"])
    assert accepted["artifact_count"] == 2
    assert {item["family"] for item in accepted["builds"]} == {"native", "rust"}
    assert all(item["executor_identity"] == "appsec-review/build-container-executor/2"
               for item in accepted["builds"])
    assert all((config.runtime.runs_dir / upstream["run_id"] / artifact["path"]).is_file()
               for build in accepted["builds"] for artifact in build["artifacts"])
    assert calls == [
        ("cmake", "-S", ".", "-B", "build"),
        ("cmake", "--build", "build"),
        ("cargo", "build", "--manifest-path", "Cargo.toml"),
    ]


def test_project_build_has_independent_language_branches(tmp_path: Path) -> None:
    config, _target = _fixture(tmp_path)
    job = build_projects(executor_factory=lambda unit, profile: FakeBuildExecutor([]))
    graph = plan_jobs((job,), config)
    for family in ("native", "rust", "go", "java", "node", "dotnet", "python", "php", "wasm"):
        assert graph.node(f"job_project_build.build.{family}").dependencies == (
            "job_project_build.plan.load_recipes",)
    assert len(graph.node("job_project_build.acceptance.publish_handoff").dependencies) == 9


def test_build_failure_is_a_gap_and_preserves_other_family_outputs(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan(model_client=RecipeModel())]).run(
        target_root=target, source_fingerprint=fingerprint)

    class Selective(FakeBuildExecutor):
        def execute(self, argv, *, workspace, working_directory, environment):
            if argv[0] == "cargo":
                self.calls.append(tuple(argv))
                return BuildCommandResult(tuple(argv), 2, b"", b"failed", False)
            return super().execute(argv, workspace=workspace,
                                   working_directory=working_directory,
                                   environment=environment)

    job = build_projects(executor_factory=lambda unit, profile: Selective([]))
    outcome = GraphRunner(config, [job]).run(target_root=target, source_fingerprint=fingerprint,
                                             run_id=upstream["run_id"])
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_builds(config.runtime.runs_dir / upstream["run_id"])
    native = next(item for item in accepted["builds"] if item["family"] == "native")
    rust = next(item for item in accepted["builds"] if item["family"] == "rust")
    assert native["terminal_status"] == "SUCCEEDED" and native["artifacts"]
    assert rust["terminal_status"] == "FAILED" and rust["gaps"]
