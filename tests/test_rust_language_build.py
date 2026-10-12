from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.config import RustBuildSettings, load_config
from appsec_review.container_runtime import CaptureScope, ProjectImage
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_language_build import rust
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner
from appsec_review.storage import file_sha256
from tests.capture_fakes import SYNTHETIC_SECRET, failing_scanner, minimal_elf, simulated_executor


ROOT = Path(__file__).parents[1]
TOOLCHAIN = "/usr/local/rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin"
NAMED_TOKEN = "unit-token-redacted-by-exact-name"
REDACTED = "<redacted: secret scan disposition>"


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


def _metadata(working_directory: str) -> bytes:
    return json.dumps({"version": 1, "workspace_root": f"/workspace/{working_directory}",
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
                                 "dependencies": ["helper 0.1.0"]}]}}).encode()


def rust_container(calls: list[tuple[str, ...]], *, leak: str | None = None,
                   phantom_archiver: bool = False, spoofed_toolchain: bool = False):
    """A Cargo build as the syscall collector and PATH wrappers would observe it."""
    def behavior(argv, workspace, working_directory, environment, container):
        calls.append(argv)
        # The PATH launcher is a shell script below the writable capture mount.
        container.exec("/capture/wrappers/cargo", ["cargo", *argv[1:]])
        container.exec("/usr/local/cargo/bin/cargo", ["/usr/local/cargo/bin/cargo", *argv[1:]])
        container.tool_call("cargo", argv[1:], executable="/usr/local/cargo/bin/cargo")
        # Cargo asks the compiler for its version under every command, with identical argv.
        container.exec(f"{TOOLCHAIN}/rustc", [f"{TOOLCHAIN}/rustc", "-vV"])
        container.connect("192.0.2.10", 443)
        if argv[:2] == ("cargo", "metadata"):
            return 0, _metadata(working_directory), b""
        logical = f"/workspace/{working_directory}"
        debug = f"{logical}/target/x86_64-unknown-linux-gnu/debug"
        root = workspace / working_directory / "target" / "x86_64-unknown-linux-gnu" / "debug"
        deps, generated = root / "deps", root / "build" / "sample-hash" / "out"
        deps.mkdir(parents=True, exist_ok=True); generated.mkdir(parents=True, exist_ok=True)
        (root / "sample").write_bytes(minimal_elf())
        (deps / "libsample.rlib").write_bytes(b"rlib")
        (deps / "libsample.rmeta").write_bytes(b"rmeta")
        (deps / "libsample.a").write_bytes(b"archive")
        (deps / "sample.o").write_bytes(b"object")
        (generated / "generated.rs").write_text("pub const GENERATED: bool = true;\n", encoding="utf-8")
        inherited = sorted(f"{key}={value}" for key, value in environment.items())
        # A spoofed toolchain lives in the target-writable workspace under a toolchain-shaped path.
        toolchain = f"{logical}/toolchain/bin" if spoofed_toolchain else TOOLCHAIN
        compile_argv = ["--crate-name", "sample", f"{logical}/src/main.rs", "--crate-type", "bin",
                        "--out-dir", f"{debug}/deps"]
        # Cargo starts the toolchain compiler by absolute path, which no PATH wrapper sees, and
        # exports a variable that only this later exec carries.
        container.exec(f"{toolchain}/rustc", [f"{toolchain}/rustc", *compile_argv],
                       envp=[*inherited, f"GITHUB_TOKEN={NAMED_TOKEN}"])
        container.open(f"{logical}/src/main.rs")
        if spoofed_toolchain:
            # A target program may also claim any argv[0] it likes, or a build-script name.
            container.exec(f"{logical}/tool.sh", [f"{TOOLCHAIN}/rustc", *compile_argv])
            container.exec("./rustc", [f"{TOOLCHAIN}/rustc", *compile_argv])
            container.exec("/tmp/build-script-build", [f"{TOOLCHAIN}/rustc", *compile_argv])
        link = ["-o", f"{debug}/sample", f"{debug}/deps/sample.o"]
        container.exec("/usr/local/bin/cc", ["cc", *link], succeeded=False)
        container.exec("/capture/wrappers/cc", ["cc", *link])
        container.exec("/usr/bin/cc", ["/usr/bin/cc", *link])
        container.tool_call("cc", link, executable="/usr/bin/cc")
        archive = ["crs", f"{debug}/deps/libsample.a", f"{debug}/deps/sample.o"]
        # A wrapper record alone, or beside only a failed exec, is not an observed execution.
        container.exec("/usr/bin/ar", ["ar", *archive], succeeded=not phantom_archiver)
        container.tool_call("ar", archive, executable="/usr/bin/ar")
        # Cargo compiles a build script into the workspace target directory and runs it there.
        script = f"{logical}/target/debug/build/sample-hash/build-script-build"
        container.exec(script, [script],
                       envp=[*inherited, *([f"RELEASE_SIGNING_VALUE={leak}"] if leak else [])])
        stderr = b"warning: unused variable\n" * 400 + (f"signing with {leak}\n".encode() if leak else b"")
        return 0, b"built", stderr
    return behavior


def _fixture(tmp_path: Path, *, capture: str = "event_count_limit = 250000"):
    config_path = tmp_path / "appsec-review.toml"
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    section = "[jobs.job_language_build.settings.build_capture]\nevent_count_limit = 250000\n"
    assert section in text
    config_path.write_text(text.replace(
        section, f"[jobs.job_language_build.settings.build_capture]\n{capture}\n"), encoding="utf-8")
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
        build_plan(infer=RustRecipeModel().complete)]).run(target_root=target, source_fingerprint=fingerprint)
    GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: simulated_executor(profile, rust_container(calls)),
        image_resolver_factory=lambda unit: RustImageResolver(target))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    return upstream["run_id"], fingerprint


def _language(config, target, fingerprint, run_id, factory, **options):
    return GraphRunner(config, [build_language(executor_factory=factory)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id, **options)


def _rust_receipt(config, run_id):
    return next(item for item in load_accepted_language_build(
        config.runtime.runs_dir / run_id)["receipts"] if item["family"] == "rust")


def _retained_text(root: Path) -> str:
    return "".join(path.read_text(encoding="utf-8", errors="replace")
                   for path in root.rglob("*") if path.is_file())


def _events(run_root: Path, command) -> list[dict]:
    path = run_root / command["execution_capture"]["events"]["path"]
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _version_queries(rows, run_root: Path, receipt) -> set[str]:
    """Origins of the rows whose observed exec was only a `rustc -vV` version query."""
    origins = set()
    for index, command in enumerate(receipt["commands"], 1):
        for event in _events(run_root, command):
            if event["kind"] == "process_exec" and event["argv"][1:] == ["-vV"]:
                origins.add(f"execution-capture:command-{index:03d}:event-{event['ordinal']}")
    return origins & {item["origin"] for item in rows}


def _checkpoints(config) -> tuple[Path, ...]:
    return tuple((config.runtime.metadata_dir / "language-builds").glob("*/accepted.json"))


def test_rust_option_validation_rejects_target_execution_and_accepts_bounded_choices() -> None:
    settings = RustBuildSettings("stable", None, "dev", (), True, True, True, 32768)
    dispatch = {"build_system": "cargo", "recipe": {"dependency_files": ["Cargo.toml", "Cargo.lock"],
        "configure_commands": [], "build_commands": [["cargo", "build", "--workspace", "--package",
        "sample", "--features", "serde", "--target", "x86_64-unknown-linux-gnu", "--profile", "dev"]]}}
    assert rust.validate_dispatch(dispatch, settings) == ()
    bad = {**dispatch, "recipe": {**dispatch["recipe"], "build_commands": [["cargo", "test"]]}}
    assert any("unsupported" in gap for gap in rust.validate_dispatch(bad, settings))


def test_rust_tool_classification_uses_only_the_kernel_resolved_executable_path() -> None:
    assert rust.tool_identity(f"{TOOLCHAIN}/rustc", ["rustc", "-vV"]) == ("rustc", "compiler")
    assert rust.tool_identity("/usr/local/cargo/bin/rustc", ["rustc"]) == ("rustc", "compiler")
    assert rust.tool_identity("/usr/bin/x86_64-linux-gnu-gcc-13", ["cc", "-o", "app", "main.o"]) == (
        "x86_64-linux-gnu-gcc-13", "linker-driver")
    assert rust.tool_identity("/usr/bin/cc", ["cc", "-c", "shim.c", "-o", "shim.o"]) == (
        "cc", "compiler-driver")
    assert rust.tool_identity(f"{TOOLCHAIN}/rust-lld", ["rust-lld", "-flavor", "gnu"]) == (
        "rust-lld", "linker")
    assert rust.tool_identity("/usr/bin/llvm-ar", ["llvm-ar", "crs", "libx.a"]) == ("llvm-ar", "archiver")
    assert rust.tool_identity("/usr/bin/python3", ["python3", "tool-wrapper.py", "rustc"]) is None
    assert rust.tool_identity("/usr/local/cargo/bin/cargo", ["cargo", "build"]) is None
    # Nothing below a build-writable mount is a toolchain tool, whatever its path or argv[0] claims.
    for executable in ("/capture/wrappers/rustc", "/capture/wrappers/cc", "/workspace/rust/toolchain/bin/rustc",
                       f"/workspace{TOOLCHAIN}/rustc", "/tmp/cargo/bin/rustc", "/proc/self/fd/3",
                       "/dev/shm/cc", "/usr/../workspace/rust/rustc", f"{TOOLCHAIN}/./rustc",
                       "bin/rustc", "./rustc", "rustc", "", "/usr//bin/cc"):
        assert rust.tool_identity(executable, [f"{TOOLCHAIN}/rustc", "--crate-name", "x"]) is None, executable
    # A build script is target-built code that Cargo runs from its own build directory. It is
    # recognized only there, and never as anything but a build script.
    for executable in ("/workspace/rust/target/debug/build/sample-0123abcd/build-script-build",
                       "/workspace/target/x86_64-unknown-linux-gnu/release/build/libc-9f/build_script_build-9f"):
        name = executable.rsplit("/", 1)[1]
        assert rust.tool_identity(executable, [f"{TOOLCHAIN}/rustc"]) == (name, "code-generator")
    for executable in ("/usr/bin/build-script-build", "/tmp/build/x/build-script-build",
                       "/workspace/rust/build-script-build", "/workspace/build/build-script-build",
                       "/workspace/rust/target/debug/build/../build/x/build-script-build",
                       "target/debug/build/x/build-script-build"):
        assert rust.tool_identity(executable, [executable]) is None, executable
    # A record's tool name only selects wrapper records to reconcile onto an observed exec.
    assert rust.tool_kind("rustc", ["rustc", "-vV"]) == "compiler"
    assert rust.tool_kind("python3", ["python3", "tool-wrapper.py", "rustc"]) is None


def test_rust_required_compiler_check_needs_a_compilation_not_a_version_query() -> None:
    required = rust.CAPTURE_DESCRIPTOR.required_execution
    assert required({"tool": "rustc", "argv": ["rustc", "--crate-name", "sample", "src/main.rs",
                                               "--out-dir", "target/debug/deps"]})
    assert not required({"tool": "rustc", "argv": ["rustc", "-vV"]})
    assert not required({"tool": "rustc", "argv": ["rustc", "-", "--crate-name", "___",
                                                   "--print=file-names"]})
    assert not required({"tool": "cc", "argv": ["cc", "--crate-name", "x", "-o", "app"]})


def test_rust_build_retains_streams_provenance_artifacts_metadata_and_sanitized_mcp(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    calls: list[tuple[str, ...]] = []
    run_id, fingerprint = _accepted_project(config, target, calls)
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, rust_container(calls), output_bytes=4096))
    assert outcome["status"] == "SUCCEEDED"
    run_root = config.runtime.runs_dir / run_id
    receipt = _rust_receipt(config, run_id)
    assert receipt["terminal_status"] == "SUCCEEDED" and receipt["gaps"] == []
    assert receipt["capture_identity"] == rust.CAPTURE_IDENTITY
    executable = next(item for item in receipt["artifacts"] if item["kind"] == "executable")
    assert executable["loader_dependencies"] == ["libc.so.6"]
    assert executable["loader_dependency_status"] == "resolved" and executable["loader_linkage"] == "dynamic"
    assert {item["kind"] for item in receipt["artifacts"]} >= {
        "rust-library", "rust-metadata", "static-library", "generated-source", "executable"}
    assert not any("execution-capture" in item["path"] for item in receipt["artifacts"])
    assert receipt["cargo_metadata"]["relationships"]
    assert receipt["cargo_metadata"]["proc_macro_targets"] == [{
        "package_id": "helper 0.1.0", "package_name": "helper", "target": "helper_derive"}]
    assert receipt["link_database"]["relationship_count"] >= 2
    build_stderr = receipt["commands"][1]["stderr"]
    assert build_stderr["storage"] == "complete-file"
    assert build_stderr["truncated"] is False and build_stderr["preview_truncated"] is True
    assert build_stderr["capture_limit_bytes"] is None
    assert build_stderr["preview_limit_bytes"] == 4096
    assert build_stderr["captured_bytes"] == build_stderr["total_bytes"] > 4096
    assert file_sha256(run_root / build_stderr["path"]) == build_stderr["sha256"]
    assert not any(command[1] in {"run", "test", "bench"} for command in calls if len(command) > 1)

    # Cargo metadata and the build each carry a hash-verified, correctly scoped capture identity.
    assert [command["role"] for command in receipt["commands"]] == ["metadata", "build"]
    for ordinal, command in enumerate(receipt["commands"], 1):
        identity = command["execution_capture"]
        attempt = identity["scope"]["attempt_id"]
        assert identity["scope"] == {"run_id": run_id, "job_id": "job_language_build", "attempt_id": attempt,
                                     "build_unit_id": receipt["build_unit_id"], "family": "rust"}
        assert identity["path"] == (f"data/build/rust/units/{receipt['build_unit_id']}/attempts/{attempt}/"
                                    f"execution-capture/command-{ordinal:03d}/record.json")
        assert identity["complete"] is True and identity["envp_captured"] is True
        assert "connect" in identity["collector"]["event_kinds"]
        assert identity["events"]["counts"]["process_exec"] > 0
        assert identity["events"]["counts"]["connect"] == 1
        nested = [identity, identity["events"], identity["secret_findings"],
                  identity["secret_scan"]["execution"], identity["secret_scan"]["report"]]
        assert all(file_sha256(run_root / member["path"]) == member["sha256"] for member in nested)
        assert identity["secret_scan"]["exit_code"] == 0 and identity["secret_findings"]["count"] == 0
        capture_root = (run_root / identity["path"]).parent
        assert not tuple(capture_root.glob("trace*")) and not (capture_root / ".secret-scan-input").exists()

    # Tool provenance is derived from successful process-exec events at trusted paths.
    invocations = receipt["tool_invocations"]
    rows = {item["tool"]: item for item in invocations
            if item["origin"] not in _version_queries(invocations, run_root, receipt)}
    assert sorted(item["tool"] for item in invocations) == [
        "ar", "build-script-build", "cc", "rustc", "rustc", "rustc"]
    assert all(item["mapping"].startswith("syscall-process-exec") for item in invocations)
    assert all(item["evidence"]["process_exec"]["count"] == 1 for item in invocations)
    # The identical `rustc -vV` argv under two commands is two rows, each resolving in its own record.
    events = {command["execution_capture"]["sha256"]: {event["ordinal"]: event for event in _events(run_root, command)}
              for command in receipt["commands"]}
    for item in invocations:
        observed = item["evidence"]["process_exec"]
        resolved = [events[item["evidence"]["capture_record_sha256"]][ordinal]
                    for ordinal in observed["event_ordinals"]]
        assert resolved and all(event["kind"] == "process_exec" and event["result"] == 0 and
                                event["executable"] == observed["executable"] for event in resolved)
    assert len({item["evidence"]["capture_record_sha256"] for item in invocations
                if item["tool"] == "rustc"}) == 2
    assert all(item["evidence"]["process_exec"]["executable"].startswith("/usr/")
               for item in invocations if item["tool"] != "build-script-build")
    assert set(rows) == {"ar", "build-script-build", "cc", "rustc"}
    assert rows["rustc"]["mapping"] == "syscall-process-exec"
    assert rows["rustc"]["evidence"]["tool_call"] is None
    assert rows["rustc"]["evidence"]["process_exec"]["executable"] == f"{TOOLCHAIN}/rustc"
    # The launcher and the failed PATH probe are not counted with the real cc.
    assert rows["cc"]["mapping"] == "syscall-process-exec+tool-call"
    assert rows["cc"]["tool_kind"] == "linker-driver"
    assert rows["cc"]["evidence"]["process_exec"]["executable"] == "/usr/bin/cc"
    assert rows["cc"]["evidence"]["tool_call"]["exit_code"] == 0
    assert rows["ar"]["evidence"]["tool_call"]["sha256"]
    assert rows["build-script-build"]["mapping"] == "syscall-process-exec"
    assert rows["build-script-build"]["tool_kind"] == "code-generator"
    assert rows["build-script-build"]["evidence"]["process_exec"]["executable"] == (
        "/workspace/rust/target/debug/build/sample-hash/build-script-build")
    assert all(item["evidence"]["capture_record_sha256"] ==
               receipt["commands"][1]["execution_capture"]["sha256"] for item in rows.values())
    provenance = receipt["capture_provenance"]
    assert provenance["schema"] == "appsec-review/rust-capture-provenance/1"
    assert provenance["complete"] is True and provenance["command_count"] == 2
    assert provenance["failed_exec_events"] == 1 and provenance["redacted_exec_events"] == 0
    assert provenance["untrusted_location_exec_events"] == 3  # two cargo launchers and the cc launcher
    assert provenance["truncated_tool_exec_events"] == 0 and provenance["malformed_records"] == 0
    assert provenance["connect_events"] == 2 and provenance["unreconciled_tool_calls"] == 0
    assert provenance["observed_tool_kinds"] == ["archiver", "code-generator", "compiler", "linker-driver"]
    assert len(_checkpoints(config)) == 1

    # Envp is captured on the later exec, and exact-name redaction removed its value.
    compiler = next(event for event in _events(run_root, receipt["commands"][1])
                    if event["kind"] == "process_exec" and event["executable"].endswith("/rustc")
                    and "--crate-name" in event["argv"])
    assert {"name": "GITHUB_TOKEN", "redacted": True, "value": "<redacted>"} in compiler["envp"]
    assert {"name": "CARGO_TERM_COLOR", "redacted": False, "value": "never"} in compiler["envp"]
    assert provenance["envp_redacted_names"] == ["GITHUB_TOKEN"]
    assert NAMED_TOKEN not in _retained_text(run_root)

    # Exact argv stays protected; receipts and retrieval expose hashes and bounded facts only.
    protected = run_root / receipt["protected_compile_commands"]["path"]
    assert "--crate-name" in protected.read_text(encoding="utf-8")
    assert "--crate-name" not in json.dumps(receipt["tool_invocations"])
    assert "never" not in json.dumps(receipt["commands"])
    result = RetrievalMcpAdapter(RetrievalCore(config.runtime.runs_dir, run_id)).call(
        "search", {"query": "rust-library", "indexes": ["build"], "limit": 10})
    encoded = json.dumps(result)
    assert result["results"] and "build-script-build" not in encoded and "--crate-name" not in encoded
    commands = json.dumps(RetrievalMcpAdapter(RetrievalCore(config.runtime.runs_dir, run_id)).call(
        "search", {"query": "cargo command", "indexes": ["build"], "limit": 10}))
    assert receipt["commands"][1]["execution_capture"]["sha256"] in commands
    assert "--crate-name" not in commands and "GITHUB_TOKEN" not in commands


def test_rust_capture_secret_is_detected_recorded_and_absent_from_every_retained_file(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted_project(config, target, [])
    _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, rust_container([], leak=SYNTHETIC_SECRET)))
    run_root = config.runtime.runs_dir / run_id
    receipt = _rust_receipt(config, run_id)
    metadata, build = receipt["commands"]
    assert metadata["execution_capture"]["secret_findings"]["count"] == 0
    identity = build["execution_capture"]
    # Raw strace, the normalized exec event, and stderr each held the secret.
    assert identity["secret_findings"]["count"] == 3 and identity["secret_scan"]["exit_code"] == 1
    assert identity["complete"] is True
    findings = json.loads((run_root / identity["secret_findings"]["path"]).read_text(encoding="utf-8"))
    assert file_sha256(run_root / identity["secret_findings"]["path"]) == identity["secret_findings"]["sha256"]
    assert {item["source"].split("/")[0] for item in findings["findings"]} == {
        "syscalls", "events.jsonl", "streams"}
    assert all(item["secret_redacted"] for item in findings["findings"])
    assert SYNTHETIC_SECRET not in _retained_text(run_root)
    assert (run_root / build["stderr"]["path"]).read_text(encoding="utf-8").strip() == REDACTED
    capture_root = (run_root / identity["path"]).parent
    assert not tuple(capture_root.glob("trace*")) and not (capture_root / ".secret-scan-input").exists()
    # The redacted exec is reported as lost provenance instead of being reconstructed.
    assert receipt["capture_provenance"]["redacted_exec_events"] == 1
    assert receipt["capture_provenance"]["complete"] is False
    assert "code-generator" not in {item["tool_kind"] for item in receipt["tool_invocations"]}
    assert any("redacted by the secret scan" in gap for gap in receipt["gaps"])
    assert not tuple((config.runtime.metadata_dir / "language-builds").glob("*/accepted.json"))


def test_rust_tool_call_without_a_successful_exec_is_never_tool_provenance(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted_project(config, target, [])
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, rust_container([], phantom_archiver=True)))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    receipt = _rust_receipt(config, run_id)
    # The wrapper wrote an `ar` record, but the only `ar` execve the collector saw failed.
    assert all(command["execution_capture"]["complete"] for command in receipt["commands"])
    assert all(item["evidence"]["process_exec"]["count"] >= 1 for item in receipt["tool_invocations"])
    assert {item["mapping"] for item in receipt["tool_invocations"]} <= {
        "syscall-process-exec", "syscall-process-exec+tool-call"}
    assert "archiver" not in {item["tool_kind"] for item in receipt["tool_invocations"]}
    provenance = receipt["capture_provenance"]
    assert provenance["unreconciled_tool_calls"] == 1 and provenance["complete"] is False
    assert "archiver" not in provenance["observed_tool_kinds"]
    assert ("1 tool-call records had no matching successful process-exec event and are not claimed "
            "as tool execution") in receipt["gaps"]
    assert "Rust archiver execution could not be established from an incomplete capture" in receipt["gaps"]
    assert receipt["link_database"]["relationship_count"] == 1
    assert not tuple((config.runtime.metadata_dir / "language-builds").glob("*/accepted.json"))


def test_rust_secondary_evidence_cannot_satisfy_the_required_compiler_check(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted_project(config, target, [])
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, rust_container([], spoofed_toolchain=True)))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / run_id
    receipt = _rust_receipt(config, run_id)
    build = receipt["commands"][1]
    # Everything short of a successful exec of the image-owned compiler is present: a
    # toolchain-shaped path ran from the workspace, target programs used the real compiler path
    # as argv[0], one of them is named like a build script, and the output binary exists.
    assert build["execution_capture"]["complete"] is True
    executed = [event for event in _events(run_root, build)
                if event["kind"] == "process_exec" and event["result"] == 0]
    assert any(event["executable"] == "/workspace/rust/toolchain/bin/rustc" for event in executed)
    assert {event["executable"] for event in executed if event["argv"][0] == f"{TOOLCHAIN}/rustc"
            and "--crate-name" in event["argv"]} == {
        "/workspace/rust/tool.sh", "./rustc", "/tmp/build-script-build"}
    assert any(item["kind"] == "executable" for item in receipt["artifacts"])
    invocations = receipt["tool_invocations"]
    assert {item["tool"] for item in invocations} == {"rustc", "cc", "ar", "build-script-build"}
    # The real compiler did run, but only to report its version: an observed tool kind is not
    # an observed compilation.
    assert all(item["origin"] in _version_queries(invocations, run_root, receipt)
               for item in invocations if item["tool"] == "rustc")
    assert [item["evidence"]["process_exec"]["executable"] for item in invocations
            if item["tool"] == "build-script-build"] == [
        "/workspace/rust/target/debug/build/sample-hash/build-script-build"]
    assert all(item["evidence"]["process_exec"]["executable"].startswith("/usr/")
               for item in invocations if item["tool"] != "build-script-build")
    provenance = receipt["capture_provenance"]
    assert "compiler" in provenance["observed_tool_kinds"]
    # Two cargo launchers, the cc launcher, and the four target-controlled compiler stand-ins.
    assert provenance["untrusted_location_exec_events"] == 7 and provenance["complete"] is False
    assert "Rust compiler execution was not observed in the standardized capture" in receipt["gaps"]
    assert not _checkpoints(config)


def test_rust_truncated_toolchain_argv_is_a_named_gap_not_a_hashed_command(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, capture="event_count_limit = 250000\nargv_count_limit = 4")
    run_id, fingerprint = _accepted_project(config, target, [])
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, rust_container([])))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / run_id
    receipt = _rust_receipt(config, run_id)
    invocations = receipt["tool_invocations"]
    provenance = receipt["capture_provenance"]
    # Only the compilation exceeds four arguments; its version queries and the link do not.
    assert provenance["truncated_tool_exec_events"] == 1 and provenance["complete"] is False
    assert all(item["origin"] in _version_queries(invocations, run_root, receipt)
               for item in invocations if item["tool"] == "rustc")
    assert "linker-driver" in provenance["observed_tool_kinds"]
    assert ("1 toolchain process-exec events had truncated argv; their tool provenance is "
            "unavailable") in receipt["gaps"]
    assert "Rust compiler execution was not observed in the standardized capture" in receipt["gaps"]
    assert not _checkpoints(config)


def test_rust_invocation_secret_is_not_reintroduced_by_the_protected_command(tmp_path: Path) -> None:
    class SecretEnvironment:
        def __init__(self, inner):
            self.inner = inner

        def resolve(self):
            return self.inner.resolve()

        def execute_captured(self, argv, *, environment, **options):
            return self.inner.execute_captured(
                argv, environment={**environment, "RELEASE_SIGNING_VALUE": SYNTHETIC_SECRET}, **options)

    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted_project(config, target, [])
    _language(config, target, fingerprint, run_id, lambda unit, profile: SecretEnvironment(
        simulated_executor(profile, rust_container([]))))
    run_root = config.runtime.runs_dir / run_id
    receipt = _rust_receipt(config, run_id)
    for command in receipt["commands"]:
        assert command["execution_capture"]["secret_findings"]["count"] >= 1
        exact = json.loads((run_root / command["protected_argv"]["path"]).read_text(encoding="utf-8"))
        assert exact["argv"] == ["<redacted: secret detected by gitleaks>"]
        assert set(exact["environment"].values()) == {REDACTED}
    assert SYNTHETIC_SECRET not in _retained_text(run_root)
    # Every exec inherited the secret, so no tool provenance may be claimed.
    assert receipt["tool_invocations"] == []
    assert "Rust compiler execution was not observed in the standardized capture" in receipt["gaps"]
    assert receipt["capture_provenance"]["complete"] is False and not _checkpoints(config)


def test_rust_scanner_failure_fails_closed_as_an_explicit_gap_and_is_not_checkpointed(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted_project(config, target, [])
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, rust_container([], leak=SYNTHETIC_SECRET), scanner=failing_scanner))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / run_id
    receipt = _rust_receipt(config, run_id)
    assert receipt["terminal_status"] == "SUCCEEDED" and receipt["capture_provenance"]["complete"] is False
    for ordinal, command in enumerate(receipt["commands"], 1):
        identity = command["execution_capture"]
        assert identity["complete"] is False and identity["secret_scan"]["coverage_gap"] is True
        assert identity["secret_scan"]["exit_code"] == 2 and identity["secret_scan"]["report"] is None
        assert identity["secret_findings"]["count"] == 0
        assert f"execution capture command {ordinal}: gitleaks capture scan failed: scanner exited 2" \
            in receipt["gaps"]
        assert all(event["argv"] == [REDACTED] for event in _events(run_root, command)
                   if event["kind"] == "process_exec")
        capture_root = (run_root / identity["path"]).parent
        assert not tuple(capture_root.glob("trace*")) and not (capture_root / ".secret-scan-input").exists()
    assert SYNTHETIC_SECRET not in _retained_text(run_root)
    assert receipt["tool_invocations"] == []
    assert "Rust compiler execution was not observed in the standardized capture" in receipt["gaps"]
    assert "Rust linker-driver execution could not be established from an incomplete capture" in receipt["gaps"]
    assert "Cargo metadata was unavailable" in receipt["gaps"]
    assert not tuple((config.runtime.metadata_dir / "language-builds").glob("*/accepted.json"))


@pytest.mark.parametrize(("capture", "expected", "leak"), [
    ("event_count_limit = 6", "syscall event retention limit reached", None),
    ("event_count_limit = 250000\ntool_call_count_limit = 1", "tool call retention limit reached", None),
    ("event_count_limit = 250000\nsecret_finding_count_limit = 1",
     "gitleaks capture finding retention limit reached", SYNTHETIC_SECRET),
], ids=["events", "tool-calls", "findings"])
def test_rust_capture_caps_are_explicit_gaps_and_never_limit_sanitization(
        tmp_path: Path, capture: str, expected: str, leak: str | None) -> None:
    config, target = _fixture(tmp_path, capture=capture)
    run_id, fingerprint = _accepted_project(config, target, [])
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, rust_container([], leak=leak)))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / run_id
    receipt = _rust_receipt(config, run_id)
    build = receipt["commands"][1]
    assert build["execution_capture"]["complete"] is False
    assert f"execution capture command 2: {expected}" in receipt["gaps"]
    assert receipt["capture_provenance"]["complete"] is False
    assert not tuple((config.runtime.metadata_dir / "language-builds").glob("*/accepted.json"))
    if leak:
        assert build["execution_capture"]["secret_findings"]["count"] == 1
        assert SYNTHETIC_SECRET not in _retained_text(run_root)


class TamperingExecutor:
    def __init__(self, inner, mode: str):
        self.inner, self.mode = inner, mode

    def resolve(self):
        return self.inner.resolve()

    def execute_captured(self, argv, *, capture_directory, scope, **options):
        if self.mode == "scope":
            scope = CaptureScope(scope.run_id, scope.job_id, scope.attempt_id,
                                 "build-unit-" + "0" * 20, scope.family)
        if self.mode == "path":
            capture_directory = capture_directory.with_name("relocated")
        result = self.inner.execute_captured(argv, capture_directory=capture_directory, scope=scope, **options)
        record = result.capture_record
        if self.mode == "hash":
            with (record.parent / "events.jsonl").open("a", encoding="utf-8") as stream:
                stream.write("\n")
        if self.mode == "schema":
            document = json.loads(record.read_text(encoding="utf-8"))
            record.write_text(json.dumps({**document, "schema": "appsec-review/build-execution-record/0"}),
                              encoding="utf-8")
        if self.mode == "findings":
            (record.parent / "secret-scan" / "findings.json").write_text("{}", encoding="utf-8")
        if self.mode == "missing":
            return replace(result, capture_record=None)
        return result


@pytest.mark.parametrize("mode", ["hash", "schema", "path", "scope", "findings", "missing"])
def test_rust_capture_tampering_is_a_framework_integrity_failure(tmp_path: Path, mode: str) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted_project(config, target, [])
    with pytest.raises(RuntimeError, match="job reported partial failure: execute.rust"):
        _language(config, target, fingerprint, run_id, lambda unit, profile: TamperingExecutor(
            simulated_executor(profile, rust_container([])), mode))


def test_rust_uncaptured_executor_is_rejected(tmp_path: Path) -> None:
    class Uncaptured:
        def resolve(self):
            return None

        def execute(self, argv, **_options):
            raise AssertionError("Rust commands must not run outside execution capture")

    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted_project(config, target, [])
    with pytest.raises(RuntimeError, match="job reported partial failure: execute.rust"):
        _language(config, target, fingerprint, run_id, lambda unit, profile: Uncaptured())


@pytest.mark.parametrize("tampered", ["artifact", "capture-events", "capture-findings"])
def test_rust_checkpoint_reuses_verified_captures_and_detects_tampering(tmp_path: Path, tampered: str) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted_project(config, target, [])
    factory = lambda unit, profile: simulated_executor(profile, rust_container([]))
    _language(config, target, fingerprint, run_id, factory)
    receipt = _rust_receipt(config, run_id)
    _language(config, target, fingerprint, run_id, factory, force_from="job_language_build")
    reused = _rust_receipt(config, run_id)
    assert reused["checkpoint_reused"] is True
    assert reused["gaps"] == receipt["gaps"] == []
    assert [command["execution_capture"] for command in reused["commands"]] == [
        command["execution_capture"] for command in receipt["commands"]]
    run_root = config.runtime.runs_dir / run_id
    identity = receipt["commands"][1]["execution_capture"]
    path = run_root / {"artifact": receipt["artifacts"][0]["path"],
                       "capture-events": identity["events"]["path"],
                       "capture-findings": identity["secret_findings"]["path"]}[tampered]
    path.write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="job reported partial failure"):
        _language(config, target, fingerprint, run_id, factory, force_from="job_language_build")
