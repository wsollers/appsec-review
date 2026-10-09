from __future__ import annotations

import json
from pathlib import Path
import pytest

from appsec_review.config import GoBuildSettings, LanguageBuildSettings, load_config
from appsec_review.container_runtime import BuildCommandResult, ProjectImage
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner, plan_jobs
from tests.capture_fakes import capturing_fake


ROOT = Path(__file__).parents[1]


class GoRecipeModel:
    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            root = unit["root"]
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": "go", "source_dir": root, "build_dir": f"{root}/bin",
                "system_packages": [], "environment": {"CGO_ENABLED": "1"},
                "dependency_files": [item["path"] for item in unit["markers"]],
                "configure_commands": [],
                "build_commands": [["go", "build", "-tags", "accepted", "-o", f"{root}/bin/app", "./cmd/app"]],
                "expected_outputs": [f"{root}/bin/app"], "network_required": True,
                "reason": "bounded offline Go fixture",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
                            "build_recipes": recipes})


class ImageResolver:
    def __init__(self, target: Path): self.target = target

    def resolve(self, recipe, profile):
        hashes = dependency_hashes(self.target, recipe)
        identity = project_recipe_identity(recipe, profile, hashes)
        return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
            profile.image_id, "derived-go:local", "sha256:" + "d" * 64, "f" * 64,
            True, False, hashes), b"", b""


class GoExecutor:
    def __init__(self, calls: list[tuple[str, ...]], *, fail_roots: set[str] | None = None):
        self.calls, self.fail_roots = calls, fail_roots or set()

    def resolve(self): return None

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append(tuple(argv))
        if working_directory in self.fail_roots and argv[:2] == ("go", "build"):
            return BuildCommandResult(tuple(argv), 2, b"", b"compile failed", False)
        if argv[:2] == ("go", "build"):
            output = Path(argv[argv.index("-o") + 1])
            path = workspace / working_directory / output
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"\x7fELFgo-fixture")
            generated = workspace / working_directory / "cmd" / "app" / "generated.go"
            generated.write_text("package main\nconst Generated = true\n", encoding="utf-8")
            trace = (b"WORK=/tmp/go-build\n"
                     b"/usr/local/go/pkg/tool/linux_amd64/compile -o /tmp/go-build/main.a ./cmd/app/main.go\n"
                     b"GOROOT=/usr/local/go /usr/local/go/pkg/tool/linux_amd64/link -o bin/app /tmp/go-build/main.a\n")
            return BuildCommandResult(tuple(argv), 0, b"built\n", trace, False,
                stdout_bytes=9000000, stderr_bytes=len(trace), stdout_truncated=True,
                stdout_tail=b"useful-tail")
        if argv[:4] == ("go", "list", "-deps", "-json"):
            payload = json.dumps({"ImportPath": "example.test/app/cmd/app", "GoFiles": ["main.go"],
                                  "Imports": ["fmt"], "Module": {"Path": "example.test/app"}}).encode()
            return BuildCommandResult(tuple(argv), 0, payload, b"", False)
        if argv[:3] == ("go", "tool", "buildid"):
            return BuildCommandResult(tuple(argv), 0, b"fixture-build-id\n", b"", False)
        return BuildCommandResult(tuple(argv), 0, b"", b"", False)


def _fixture(tmp_path: Path):
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"), encoding="utf-8")
    target = tmp_path / "target"
    (target / "go" / "cmd" / "app").mkdir(parents=True)
    (target / "go" / "go.mod").write_text("module example.test/app\n\ngo 1.23\n", encoding="utf-8")
    (target / "go" / "cmd" / "app" / "main.go").write_text(
        "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"ok\") }\n", encoding="utf-8")
    return load_config(config_path), target


def _accepted(config, target, calls):
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(),
        build_plan(infer=GoRecipeModel().complete)]).run(target_root=target, source_fingerprint=fingerprint)
    GraphRunner(config, [build_projects(executor_factory=lambda unit, profile: capturing_fake(profile, GoExecutor(calls)),
        image_resolver_factory=lambda unit: ImageResolver(target))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    return upstream["run_id"], fingerprint


def test_go_settings_are_typed_and_graph_has_independent_go_lane(tmp_path: Path) -> None:
    config, _target = _fixture(tmp_path)
    assert isinstance(config.job("job_language_build").typed_settings, LanguageBuildSettings)
    assert isinstance(config.job("job_language_build").typed_settings.go, GoBuildSettings)
    graph = plan_jobs((build_language(executor_factory=lambda unit, profile: GoExecutor([])),), config)
    assert graph.node("job_language_build.execute.go").dependencies == ("job_language_build.load.go",)


def test_go_build_retains_streams_provenance_packages_artifacts_and_sanitized_mcp(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    calls: list[tuple[str, ...]] = []
    run_id, fingerprint = _accepted(config, target, calls)
    outcome = GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: GoExecutor(calls))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert receipt["family"] == "go" and receipt["terminal_status"] == "SUCCEEDED"
    assert {value["tool_kind"] for value in receipt["tool_invocations"]} >= {"compiler", "linker"}
    assert receipt["module_metadata"][0]["kind"] == "go-module-metadata"
    assert receipt["package_relationships"][0]["dependencies"] == ["fmt"]
    assert receipt["build_metadata"][0]["build_id_sha256"]
    build = next(value for value in receipt["commands"] if value["role"] == "build")
    assert build["stdout"]["truncated"] is True and build["stdout"]["total_bytes"] == 9000000
    assert "diagnostic_tail" in build["stdout"]
    serialized = json.dumps(receipt["tool_invocations"])
    assert '"argv"' not in serialized and "useful-tail" not in serialized

    adapter = RetrievalMcpAdapter(RetrievalCore(config.runtime.runs_dir, run_id))
    response = adapter.call("search", {"query": "build-driver", "indexes": ["build"]})
    artifact_response = adapter.call("search", {"query": "executable", "indexes": ["build"]})
    assert response["results"] and artifact_response["results"]
    public = json.dumps([response, artifact_response])
    assert "protected-commands" not in public and "useful-tail" not in public


def test_go_failed_sibling_does_not_discard_successful_unit(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    sibling = target / "broken" / "cmd" / "app"
    sibling.mkdir(parents=True)
    (target / "broken" / "go.mod").write_text("module example.test/broken\n\ngo 1.23\n", encoding="utf-8")
    (sibling / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    run_id, fingerprint = _accepted(config, target, [])
    GraphRunner(config, [build_language(executor_factory=lambda unit, profile:
        GoExecutor([], fail_roots={"broken"}))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    receipts = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"]
    assert {value["root"]: value["terminal_status"] for value in receipts} == {
        "broken": "FAILED", "go": "SUCCEEDED"}


def test_go_resume_reuses_checkpoint_and_stream_tamper_stops_publication(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted(config, target, [])
    job = build_language(executor_factory=lambda unit, profile: GoExecutor([]))
    GraphRunner(config, [job]).run(target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    resumed = GraphRunner(config, [job]).run(target_root=target, source_fingerprint=fingerprint,
                                             run_id=run_id, force_from="job_language_build")
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert resumed["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    assert receipt["checkpoint_reused"] is True

    stream = config.runtime.runs_dir / run_id / receipt["commands"][0]["stdout"]["path"]
    stream.write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="job reported partial failure: execute.go"):
        GraphRunner(config, [job]).run(target_root=target, source_fingerprint=fingerprint,
                                       run_id=run_id, force_from="job_language_build")
