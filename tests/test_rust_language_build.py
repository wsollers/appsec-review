from __future__ import annotations

import json
from pathlib import Path
import stat

import pytest

from appsec_review.config import RustBuildSettings, load_config
from appsec_review.container_runtime import BuildCommandResult, ProjectImage
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_language_build import rust
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import ModelResult, build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner


ROOT = Path(__file__).parents[1]


class RustRecipeModel:
    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            root = unit["root"]
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": "rust", "source_dir": root, "build_dir": f"{root}/target",
                "system_packages": [], "environment": {"CARGO_TERM_COLOR": "never"},
                "dependency_files": [f"{root}/Cargo.toml", f"{root}/Cargo.lock"],
                "configure_commands": [], "build_commands": [["cargo", "build", "--workspace",
                    "--package", "sample", "--features", "serde", "--locked", "--offline",
                    "--target", "x86_64-unknown-linux-gnu", "--profile", "dev"]],
                "expected_outputs": [f"{root}/target"], "network_required": True,
                "reason": "bounded Rust fixture recipe",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
                            "build_recipes": recipes})


class RustImageResolver:
    def __init__(self, target: Path):
        self.target = target

    def resolve(self, recipe, profile):
        hashes = dependency_hashes(self.target, recipe)
        identity = project_recipe_identity(recipe, profile, hashes)
        image_id = "sha256:" + "d" * 64
        return ProjectImage("appsec-review/project-build-image/1", identity, "rust",
            profile.image_id, "derived-rust:local", image_id, "e" * 64, True, False, hashes), b"", b""


class RustExecutor:
    def __init__(self, calls: list[tuple[str, ...]], *, fail_root: str | None = None):
        self.calls, self.fail_root = calls, fail_root

    def resolve(self):
        return None

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append(tuple(argv))
        if argv[:2] == ("cargo", "metadata"):
            metadata = {"version": 1, "workspace_root": f"/workspace/{working_directory}",
                "target_directory": f"/workspace/{working_directory}/target",
                "workspace_members": ["sample 0.1.0 (path+file:///workspace/rust)"],
                "packages": [{"id": "sample 0.1.0 (path+file:///workspace/rust)", "name": "sample",
                    "version": "0.1.0", "manifest_path": f"/workspace/{working_directory}/Cargo.toml",
                    "features": {"serde": []}, "targets": [{"name": "sample", "kind": ["bin"],
                    "crate_types": ["bin"], "src_path": f"/workspace/{working_directory}/src/main.rs"}]},
                    {"id": "helper 0.1.0", "name": "helper", "version": "0.1.0",
                     "manifest_path": "/cargo/helper/Cargo.toml", "features": {},
                     "targets": [{"name": "helper_derive", "kind": ["proc-macro"],
                         "crate_types": ["proc-macro"], "src_path": "/cargo/helper/src/lib.rs"}]}],
                "resolve": {"nodes": [{"id": "sample 0.1.0 (path+file:///workspace/rust)",
                                         "dependencies": ["helper 0.1.0"]}]}}
            return BuildCommandResult(tuple(argv), 0, json.dumps(metadata).encode(), b"", False)
        if self.fail_root == working_directory:
            return BuildCommandResult(tuple(argv), 2, b"partial", b"cargo failed", False)
        root = workspace / working_directory / "target" / "x86_64-unknown-linux-gnu" / "debug"
        deps, generated = root / "deps", root / "build" / "sample-hash" / "out"
        deps.mkdir(parents=True, exist_ok=True); generated.mkdir(parents=True, exist_ok=True)
        (root / "sample").write_bytes(b"\x7fELFrust")
        (deps / "libsample.rlib").write_bytes(b"rlib")
        (deps / "libsample.rmeta").write_bytes(b"rmeta")
        (deps / "libsample.a").write_bytes(b"archive")
        (deps / "sample.o").write_bytes(b"object")
        (generated / "generated.rs").write_text("pub const GENERATED: bool = true;\n", encoding="utf-8")
        capture = workspace / ".appsec-review" / "rust-capture" / "invocations"
        capture.mkdir(parents=True, exist_ok=True)
        (capture / "rustc.101").write_bytes(("/usr/bin/rustc\0--crate-name\0sample\0"
            f"/workspace/{working_directory}/src/main.rs\0--crate-type\0bin\0"
            f"-o\0/workspace/{working_directory}/target/x86_64-unknown-linux-gnu/debug/sample\0").encode())
        (capture / "linker.102").write_bytes((f"-o\0/workspace/{working_directory}/target/"
            f"x86_64-unknown-linux-gnu/debug/sample\0/workspace/{working_directory}/target/"
            "x86_64-unknown-linux-gnu/debug/deps/sample.o\0").encode())
        (capture / "archiver.103").write_bytes((f"crs\0/workspace/{working_directory}/target/"
            f"x86_64-unknown-linux-gnu/debug/deps/libsample.a\0/workspace/{working_directory}/target/"
            "x86_64-unknown-linux-gnu/debug/deps/sample.o\0").encode())
        stderr = (f"Running `/workspace/{working_directory}/target/debug/build/"
                  "sample-hash/build-script-build`\n").encode()
        return BuildCommandResult(tuple(argv), 0, b"built", stderr, False,
            stdout_bytes=5, stderr_bytes=len(stderr) + 11, stderr_truncated=True,
            stderr_tail=stderr)


def _fixture(tmp_path: Path):
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"), encoding="utf-8")
    target = tmp_path / "target"
    (target / "rust" / "src").mkdir(parents=True)
    (target / "rust" / "Cargo.toml").write_text(
        "[package]\nname='sample'\nversion='0.1.0'\n[features]\nserde=[]\n", encoding="utf-8")
    (target / "rust" / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
    (target / "rust" / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    return load_config(config_path), target


def _accepted_project(config, target, calls):
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(),
        build_plan(model_client=RustRecipeModel())]).run(target_root=target, source_fingerprint=fingerprint)
    GraphRunner(config, [build_projects(executor_factory=lambda unit, profile: RustExecutor(calls),
        image_resolver_factory=lambda unit: RustImageResolver(target))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    return upstream["run_id"], fingerprint


def test_rust_option_validation_rejects_target_execution_and_accepts_bounded_choices() -> None:
    settings = RustBuildSettings("stable", None, "dev", (), True, True, True, 32768)
    dispatch = {"build_system": "cargo", "recipe": {"dependency_files": ["Cargo.toml", "Cargo.lock"],
        "configure_commands": [], "build_commands": [["cargo", "build", "--workspace", "--package",
        "sample", "--features", "serde", "--target", "x86_64-unknown-linux-gnu", "--profile", "dev"]]}}
    assert rust.validate_dispatch(dispatch, settings) == ()
    bad = {**dispatch, "recipe": {**dispatch["recipe"], "build_commands": [["cargo", "test"]]}}
    assert any("unsupported" in gap for gap in rust.validate_dispatch(bad, settings))


@pytest.mark.skipif(__import__("os").name == "nt", reason="POSIX mode contract")
def test_rust_capture_directory_is_writable_by_the_pinned_container_user(tmp_path: Path) -> None:
    settings = RustBuildSettings("stable", None, "dev", (), True, True, True, 32768)
    _environment, invocations = rust.install_capture_wrappers(tmp_path, settings)
    assert stat.S_IMODE(invocations.stat().st_mode) == 0o733
    assert stat.S_IMODE(invocations.parent.stat().st_mode) == 0o755


def test_rust_build_retains_streams_provenance_artifacts_metadata_and_sanitized_mcp(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    calls: list[tuple[str, ...]] = []
    run_id, fingerprint = _accepted_project(config, target, calls)
    outcome = GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: RustExecutor(calls))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    receipt = next(item for item in load_accepted_language_build(
        config.runtime.runs_dir / run_id)["receipts"] if item["family"] == "rust")
    assert receipt["terminal_status"] == "SUCCEEDED"
    assert {item["kind"] for item in receipt["artifacts"]} >= {
        "rust-library", "rust-metadata", "static-library", "generated-source", "executable"}
    assert {item["tool_kind"] for item in receipt["tool_invocations"]} >= {
        "compiler", "linker-driver", "archiver", "code-generator"}
    assert receipt["cargo_metadata"]["relationships"]
    assert receipt["cargo_metadata"]["proc_macro_targets"] == [{
        "package_id": "helper 0.1.0", "package_name": "helper", "target": "helper_derive"}]
    assert receipt["link_database"]["relationship_count"] >= 2
    assert receipt["commands"][1]["stderr"]["truncated"] is True
    assert receipt["commands"][1]["stderr"]["diagnostic_tail"]["sha256"]
    protected = config.runtime.runs_dir / run_id / receipt["protected_compile_commands"]["path"]
    assert "rustc" in protected.read_text(encoding="utf-8")
    assert not any(command[1] in {"run", "test", "bench"} for command in calls if len(command) > 1)

    result = RetrievalMcpAdapter(RetrievalCore(config.runtime.runs_dir, run_id)).call(
        "search", {"query": "rust-library", "indexes": ["build"], "limit": 10})
    encoded = json.dumps(result)
    assert result["results"] and "build-script-build" not in encoded and "cargo failed" not in encoded


def test_rust_checkpoint_detects_tampered_retained_artifact(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted_project(config, target, [])
    GraphRunner(config, [build_language(executor_factory=lambda unit, profile: RustExecutor([]))]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    receipt = next(item for item in load_accepted_language_build(
        config.runtime.runs_dir / run_id)["receipts"] if item["family"] == "rust")
    artifact = config.runtime.runs_dir / run_id / receipt["artifacts"][0]["path"]
    artifact.write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="job reported partial failure"):
        GraphRunner(config, [build_language(executor_factory=lambda unit, profile: RustExecutor([]))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id,
            force_from="job_language_build")
