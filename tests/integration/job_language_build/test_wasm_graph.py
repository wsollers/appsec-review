"""job_language_build WebAssembly: the pre-walk whole-graph suite, moved out of the unit path by T-113.

Every case runs the intake, catalog, plan, project-build and language-build jobs through GraphRunner
with fake executors and image resolvers. They are integration tests pending replacement by the
code-level tests in tests/unit/job_language_build/ and run only when named explicitly
(``scripts/run-tests.sh --allow-heavy -- <file>``).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.container_runtime import ProjectImage
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner
from appsec_review.storage import file_sha256
from tests.capture_fakes import capturing_fake
from tests.unit.job_language_build.test_wasm import WasmExecutor, _fixture



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
    def __init__(self, target: Path, releases=None):
        self.target, self.releases = target, releases

    def resolve(self, recipe, profile):
        hashes = dependency_hashes(self.target, recipe)
        identity = project_recipe_identity(recipe, profile, hashes, releases=self.releases)
        return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
            profile.image_id, "derived-rust-wasm:local", "sha256:" + "d" * 64,
            "f" * 64, True, False, hashes), b"", b""


def _accepted_project(config, target, calls):
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(),
        build_plan(infer=RustWasmRecipeModel().complete)]).run(
            target_root=target, source_fingerprint=fingerprint)
    GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: capturing_fake(profile, WasmExecutor(calls)),
        image_resolver_factory=lambda unit: ImageResolver(target, config.review_policy.releases))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    return upstream["run_id"], fingerprint


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
    assert len(calls) == 1  # one authoritative captured build, reused on resume


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
    from appsec_review.jobs.build_workspace import ReconstructionMiss
    with pytest.raises(ReconstructionMiss, match="retained file is missing or changed"):
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
    from appsec_review.runtime.handoff import verify_handoff_integrity
    run_root = config.runtime.runs_dir / run_id
    latest = json.loads((run_root / "data" / "jobs" / "job_language_build" / "latest.json").read_text())
    first_handoff = json.loads((run_root / latest["handoff_path"]).read_text())
    first_by_root = {item["root"]: item for item in receipts}
    GraphRunner(config, [build_language(executor_factory=lambda unit, profile: WasmExecutor([]))]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id,
        force_from="job_language_build")
    verify_handoff_integrity(run_root, first_handoff)
    resumed = load_accepted_language_build(run_root)["receipts"]
    second_by_root = {item["root"]: item for item in resumed}
    assert second_by_root["crate"]["checkpoint_reused"] is True
    assert second_by_root["crate"]["workspace"] == first_by_root["crate"]["workspace"]
    assert second_by_root["sibling"]["checkpoint_reused"] is False
    assert second_by_root["sibling"]["workspace"] == first_by_root["sibling"]["workspace"]
    assert second_by_root["sibling"]["attempt_id"] != first_by_root["sibling"]["attempt_id"]
