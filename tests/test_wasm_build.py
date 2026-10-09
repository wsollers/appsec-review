from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.config import LanguageBuildSettings, load_config
from appsec_review.container_runtime import BuildCommandResult, ProjectImage
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import ModelResult, build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_language_build.wasm import _kind, _producer_rules, _select_producer
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner, plan_jobs
from appsec_review.storage import file_sha256
from tests.capture_fakes import capturing_fake


ROOT = Path(__file__).parents[1]


class RustWasmRecipeModel:
    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            root = unit["root"]
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": unit["family"], "source_dir": root, "build_dir": f"{root}/target",
                "system_packages": [], "environment": {"RUSTFLAGS": "-g"},
                "dependency_files": [item["path"] for item in unit["markers"]],
                "configure_commands": [],
                "build_commands": [["cargo", "build", "--target", "wasm32-unknown-unknown", "--release"]],
                "expected_outputs": [f"{root}/target/wasm32-unknown-unknown/release/demo.wasm"],
                "network_required": True, "reason": "bounded Rust WebAssembly fixture",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
                            "build_recipes": recipes})


class ImageResolver:
    def __init__(self, target: Path):
        self.target = target

    def resolve(self, recipe, profile):
        hashes = dependency_hashes(self.target, recipe)
        identity = project_recipe_identity(recipe, profile, hashes)
        return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
            profile.image_id, "derived-rust-wasm:local", "sha256:" + "d" * 64,
            "f" * 64, True, False, hashes), b"", b""


class WasmExecutor:
    def __init__(self, calls: list[str], *, fail_roots: set[str] | None = None):
        self.calls, self.fail_roots = calls, fail_roots or set()

    def resolve(self):
        return None

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append(working_directory)
        if working_directory in self.fail_roots:
            return BuildCommandResult(tuple(argv), 2, b"0123", b"boun", False,
                                      10, 24, True, True, b"6789", b"failure")
        output = workspace / working_directory / "target" / "wasm32-unknown-unknown" / "release"
        output.mkdir(parents=True, exist_ok=True)
        (output / "demo.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
        (output / "demo.wat").write_text("(module)", encoding="utf-8")
        (output / "demo.js").write_text("export const ready = true;", encoding="utf-8")
        return BuildCommandResult(tuple(argv), 0, b"0123", b"diag", False,
                                  10, 10, True, True, b"6789", b"ostic")


def _fixture(tmp_path: Path):
    config_path = tmp_path / "appsec-review.toml"
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    text = text.replace(
        "[jobs.job_language_build.settings]\ncommand_timeout_seconds = 600\noutput_bytes = 8388608",
        "[jobs.job_language_build.settings]\ncommand_timeout_seconds = 600\noutput_bytes = 4",
    )
    config_path.write_text(text, encoding="utf-8")
    target = tmp_path / "target"
    (target / "crate").mkdir(parents=True)
    (target / "crate" / "Cargo.toml").write_text(
        '[package]\nname="demo"\nversion="0.1.0"\n', encoding="utf-8")
    (target / "crate" / "Cargo.lock").write_text("# fixture\n", encoding="utf-8")
    (target / "crate" / "src").mkdir()
    (target / "crate" / "src" / "lib.rs").write_text("pub fn demo() {}\n", encoding="utf-8")
    return load_config(config_path), target


def _accepted_project(config, target, calls):
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(),
        build_plan(model_client=RustWasmRecipeModel())]).run(
            target_root=target, source_fingerprint=fingerprint)
    GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: capturing_fake(profile, WasmExecutor(calls)),
        image_resolver_factory=lambda unit: ImageResolver(target))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    return upstream["run_id"], fingerprint


def test_wasm_producer_validation_and_output_classification(tmp_path: Path) -> None:
    config, _target = _fixture(tmp_path)
    assert isinstance(config.job("job_language_build").typed_settings, LanguageBuildSettings)
    graph = plan_jobs((build_language(executor_factory=lambda unit, profile: WasmExecutor([])),), config)
    assert graph.node("job_language_build.execute.wasm").dependencies == (
        "job_language_build.load.wasm",)
    rules = _producer_rules(config.job("job_language_build").settings["wasm"])
    dispatch = {"family": "rust", "recipe": {"configure_commands": [],
        "build_commands": [["cargo", "build", "--target", "wasm32-wasi"]], "expected_outputs": []}}
    assert _select_producer(dispatch, rules) == "rust"
    module = tmp_path / "module.bin"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    assert _kind(module) == "wasm-module"


def test_wasm_build_retains_protected_streams_indexes_sanitized_evidence_and_reuses(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    calls: list[str] = []
    run_id, fingerprint = _accepted_project(config, target, calls)
    outcome = GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: WasmExecutor(calls))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_language_build(config.runtime.runs_dir / run_id)
    receipt = accepted["receipts"][0]
    assert receipt["source_family"] == "rust" and receipt["producer"] == "rust"
    assert {item["kind"] for item in receipt["artifacts"]} >= {"wasm-module", "wasm-text", "binding"}
    command = receipt["commands"][0]
    assert command["stdout"]["truncated"] and command["stdout"]["observed_bytes"] == 10
    assert command["stdout"]["capture_limit_bytes"] == 4 and command["stdout"]["diagnostic_tail"]
    for identity in (command["stdout"], command["stderr"], command["protected_argv"],
                     receipt["workspace_manifest"]):
        path = config.runtime.runs_dir / run_id / identity["path"]
        assert path.is_file() and file_sha256(path) == identity["sha256"]
    serialized = json.dumps(receipt)
    assert "0123456789" not in serialized and "bounded compiler failure" not in serialized
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    result = RetrievalMcpAdapter(core).call("search", {"query": "wasm-module", "indexes": ["build"]})
    response = json.dumps(result)
    assert "demo.wasm" in response and "0123456789" not in response and "protected-commands" not in response

    resumed = GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: WasmExecutor(calls))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id,
        force_from="job_language_build")
    second = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert resumed["status"] == "COMPLETED_WITH_GAPS" and second["checkpoint_reused"] is True
    assert len(calls) == 2  # one project-build probe and one real WASM build


def test_wasm_checkpoint_tamper_is_framework_failure(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted_project(config, target, [])
    GraphRunner(config, [build_language(executor_factory=lambda unit, profile: WasmExecutor([]))]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    latest = config.runtime.runs_dir / run_id / "data" / "jobs" / "job_language_build" / "latest.json"
    accepted_pointer = latest.read_bytes()
    artifact = config.runtime.runs_dir / run_id / receipt["artifacts"][0]["path"]
    artifact.write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="partial failure"):
        GraphRunner(config, [build_language(executor_factory=lambda unit, profile: WasmExecutor([]))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id,
            force_from="job_language_build")
    assert latest.read_bytes() == accepted_pointer


def test_wasm_sibling_failure_isolated(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    sibling = target / "sibling"
    (sibling / "src").mkdir(parents=True)
    (sibling / "Cargo.toml").write_text('[package]\nname="sibling"\nversion="0.1.0"\n', encoding="utf-8")
    (sibling / "Cargo.lock").write_text("# fixture\n", encoding="utf-8")
    (sibling / "src" / "lib.rs").write_text("pub fn sibling() {}\n", encoding="utf-8")
    run_id, fingerprint = _accepted_project(config, target, [])
    outcome = GraphRunner(config, [build_language(executor_factory=lambda unit, profile:
        WasmExecutor([], fail_roots={"sibling"}))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    receipts = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"]
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    assert {item["root"]: item["terminal_status"] for item in receipts} == {
        "crate": "SUCCEEDED", "sibling": "FAILED"}
