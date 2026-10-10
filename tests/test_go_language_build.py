from __future__ import annotations

import json
from pathlib import Path
import pytest

from appsec_review.config import GoBuildSettings, LanguageBuildSettings, load_config
from appsec_review.container_runtime import ProjectImage
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, go, load_accepted_language_build
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_project_build.job import _probe_environment
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan, load_accepted_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner, plan_jobs
from appsec_review.storage import file_sha256
from tests.capture_fakes import (
    GO_BUILD_ID, SYNTHETIC_SECRET, failing_scanner, minimal_go_elf, simulated_executor,
)
from tests.test_rust_language_build import TamperingExecutor


ROOT = Path(__file__).parents[1]
GOROOT = "/usr/local/go"
TOOLS = f"{GOROOT}/pkg/tool/linux_amd64"
NAMED_TOKEN = "unit-token-redacted-by-exact-name"
REDACTED = "<redacted: secret scan disposition>"
BUILD = ["go", "build", "-tags", "accepted", "-o", "{root}/bin/app", "./cmd/app"]


class GoRecipeModel:
    def __init__(self, build: list[str] | None = None):
        self.build = build or BUILD

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
                "build_commands": [[value.format(root=root) for value in self.build]],
                "expected_outputs": [f"{root}/bin/app"], "network_required": True,
                "reason": "fixed Go capture fixture recipe",
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


def _catalog(working_directory: str) -> bytes:
    return "\n".join(json.dumps(item) for item in (
        {"ImportPath": "fmt", "Name": "fmt", "Standard": True, "Dir": f"{GOROOT}/src/fmt",
         "GoFiles": ["print.go"]},
        {"ImportPath": "example.test/app/cmd/app", "Name": "main",
         "Dir": f"/workspace/{working_directory}/cmd/app", "GoFiles": ["main.go"], "CgoFiles": ["native.go"],
         "Imports": ["fmt"], "Module": {"Path": "example.test/app"}})).encode()


def go_container(calls: list[tuple[str, ...]], *, leak: str | None = None, phantom_gcc: bool = False,
                 spoofed_toolchain: bool = False, output: bytes | None = None,
                 catalog: bytes | None = None, catalog_exit: int = 0, fail_roots: frozenset[str] = frozenset()):
    """A `go build` and `go list` as the syscall collector and PATH wrappers would observe them."""
    def behavior(argv, workspace, working_directory, environment, container):
        calls.append(argv)
        # The PATH launcher is a shell script below the writable capture mount.
        container.exec("/capture/wrappers/go", ["go", *argv[1:]])
        container.exec(f"{GOROOT}/bin/go", [f"{GOROOT}/bin/go", *argv[1:]])
        container.tool_call("go", argv[1:], executable=f"{GOROOT}/bin/go")
        # cmd/go fingerprints its tools under every command, with identical argv each time.
        for tool in ("compile", "link"):
            container.exec(f"{TOOLS}/{tool}", [f"{TOOLS}/{tool}", "-V=full"])
        if argv[:2] == ("go", "list"):
            return catalog_exit, (_catalog(working_directory) if catalog is None else catalog), b""
        if working_directory in fail_roots:
            return 2, b"", b"compile failed"
        container.connect("192.0.2.10", 443)
        logical = f"/workspace/{working_directory}"
        work = "/tmp/go-build1"
        inherited = sorted(f"{key}={value}" for key, value in environment.items())
        # A spoofed toolchain lives in the target-writable workspace under toolchain-shaped paths.
        tools = f"{logical}/pkg/tool/linux_amd64" if spoofed_toolchain else TOOLS
        container.exec(f"{TOOLS}/asm", [f"{TOOLS}/asm", "-p", "internal/cpu", "-o", f"{work}/b002/cpu.o",
                                        "./cpu_x86.s"])
        compile_argv = ["-o", f"{work}/b001/_pkg_.a", "-trimpath", f"{work}/b001=>", "-p", "main",
                        "-buildid", "aaa/bbb", "./main.go"]
        # cmd/go starts toolchain tools by absolute path and exports variables only later
        # process-exec events carry.
        container.exec(f"{tools}/compile", [f"{tools}/compile", *compile_argv],
                       envp=[*inherited, f"GITHUB_TOKEN={NAMED_TOKEN}"])
        container.open(f"{logical}/cmd/app/main.go")
        if spoofed_toolchain:
            # A target script may also claim any argv[0] it likes.
            container.exec(f"{logical}/tool.sh", [f"{TOOLS}/compile", *compile_argv])
            container.exec("./compile", [f"{TOOLS}/link", "-o", "bin/app"])
        container.exec(f"{TOOLS}/cgo", [f"{TOOLS}/cgo", "-objdir", f"{work}/b001/", "-importpath",
                                        "example.test/app/cmd/app", "--", "./native.go"])
        native = ["-I", ".", "-fPIC", "-c", "-o", f"{work}/b001/_x001.o", "_cgo_export.c"]
        container.exec(f"{GOROOT}/bin/gcc", ["gcc", *native], succeeded=False)
        container.exec("/capture/wrappers/gcc", ["gcc", *native])
        # A wrapper record alone, or beside only its launcher and a failed exec, is not an
        # observed execution of the real tool.
        container.exec("/usr/bin/gcc", ["/usr/bin/gcc", *native], succeeded=not phantom_gcc)
        container.tool_call("gcc", native, executable="/usr/bin/gcc")
        container.exec(f"{tools}/link", [f"{tools}/link", "-o", f"{work}/b001/exe/a.out", "-buildmode=exe",
                                         f"{work}/b001/_pkg_.a"],
                       envp=[*inherited, *([f"RELEASE_SIGNING_VALUE={leak}"] if leak else [])])
        binary = workspace / working_directory / argv[argv.index("-o") + 1]
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(minimal_go_elf() if output is None else output)
        generated = workspace / working_directory / "cmd" / "app" / "generated.go"
        generated.write_text("package main\nconst Generated = true\n", encoding="utf-8")
        # `go build -x` prints the real toolchain commands no matter what actually ran.
        trace = (f"WORK={work}\n{TOOLS}/compile -o {work}/b001/_pkg_.a -p main ./main.go\n"
                 f"{TOOLS}/link -o {work}/b001/exe/a.out {work}/b001/_pkg_.a\n").encode() * 200
        return 0, b"built\n", trace + (f"signing with {leak}\n".encode() if leak else b"")
    return behavior


def _fixture(tmp_path: Path, *, capture: str = "event_count_limit = 250000"):
    config_path = tmp_path / "appsec-review.toml"
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    section = "[jobs.job_language_build.settings.build_capture]\nevent_count_limit = 250000\n"
    assert section in text
    config_path.write_text(text.replace(
        section, f"[jobs.job_language_build.settings.build_capture]\n{capture}\n"), encoding="utf-8")
    target = tmp_path / "target"
    (target / "go" / "cmd" / "app").mkdir(parents=True)
    (target / "go" / "go.mod").write_text("module example.test/app\n\ngo 1.23\n", encoding="utf-8")
    (target / "go" / "cmd" / "app" / "main.go").write_text(
        "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"ok\") }\n", encoding="utf-8")
    return load_config(config_path), target


def _accepted(config, target, calls, *, build: list[str] | None = None):
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(),
        build_plan(infer=GoRecipeModel(build).complete)]).run(target_root=target, source_fingerprint=fingerprint)
    GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: simulated_executor(profile, go_container(calls)),
        image_resolver_factory=lambda unit: ImageResolver(target))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    return upstream["run_id"], fingerprint


def _language(config, target, fingerprint, run_id, factory, **options):
    return GraphRunner(config, [build_language(executor_factory=factory)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id, **options)


def _receipt(config, run_id, root: str = "go"):
    return next(item for item in load_accepted_language_build(
        config.runtime.runs_dir / run_id)["receipts"] if item["family"] == "go" and item["root"] == root)


def _retained_text(root: Path) -> str:
    return "".join(path.read_text(encoding="utf-8", errors="replace")
                   for path in root.rglob("*") if path.is_file())


def _events(run_root: Path, command) -> list[dict]:
    path = run_root / command["execution_capture"]["events"]["path"]
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _version_queries(rows, run_root: Path, receipt) -> set[str]:
    """Origins of the rows whose observed exec was only a `-V=full` tool fingerprint."""
    origins = set()
    for index, command in enumerate(receipt["commands"], 1):
        for event in _events(run_root, command):
            if event["kind"] == "process_exec" and event["argv"][1:] == ["-V=full"]:
                origins.add(f"execution-capture:command-{index:03d}:event-{event['ordinal']}")
    return origins & {item["origin"] for item in rows}


def _checkpoints(config) -> tuple[Path, ...]:
    return tuple((config.runtime.metadata_dir / "language-builds").glob("*/accepted.json"))


def test_go_settings_are_typed_and_graph_has_independent_go_lane(tmp_path: Path) -> None:
    config, _target = _fixture(tmp_path)
    assert isinstance(config.job("job_language_build").typed_settings, LanguageBuildSettings)
    assert isinstance(config.job("job_language_build").typed_settings.go, GoBuildSettings)
    graph = plan_jobs((build_language(executor_factory=lambda unit, profile: None),), config)
    assert graph.node("job_language_build.execute.go").dependencies == ("job_language_build.load.go",)


def test_go_command_policy_accepts_bounded_builds_and_rejects_toolchain_substitution() -> None:
    def errors(*commands: list[str], environment: dict[str, str] | None = None) -> tuple[str, ...]:
        return go.validate_dispatch({"recipe": {"configure_commands": [], "build_commands": list(commands),
                                                "environment": environment or {}}})

    assert errors(["go", "build", "-tags", "accepted", "-o", "bin/app", "./cmd/app"]) == ()
    assert errors(["go", "mod", "download"], ["go", "generate", "./..."], ["go", "build", "./..."]) == ()
    assert errors(["make", "build"]) == ("Go recipes may execute go commands only",
                                         "Go recipe must contain a go build command")
    assert "go subcommand is unsupported: test" in errors(["go", "test", "./..."])
    assert "go subcommand is unsupported: run" in errors(["go", "run", "."], ["go", "build", "."])
    assert "go mod subcommand is unsupported: tidy" in errors(["go", "mod", "tidy"], ["go", "build", "."])
    assert "Go recipe must contain a go build command" in errors(["go", "mod", "download"])
    for option in ("-toolexec", "-exec", "-overlay", "-C", "-modfile"):
        assert f"go option is forbidden: {option}" in errors(["go", "build", option, "value", "."])
        assert f"go option is forbidden: {option}" in errors(["go", "build", f"{option}=value", "."])
        assert f"go option is forbidden: {option}" in errors(["go", "build", f"-{option}=value", "."])
    # GOFLAGS is the same option surface delivered through the environment.
    assert "go option is forbidden: -toolexec" in errors(
        ["go", "build", "."], environment={"GOFLAGS": "-trimpath -toolexec=/workspace/wrap"})
    for output in ("/usr/local/bin/app", "../app", "bin/../../app"):
        assert "go build output must stay inside the accepted build unit" in errors(
            ["go", "build", "-o", output, "."])
        assert "go build output must stay inside the accepted build unit" in errors(
            ["go", "build", f"-o={output}", "."])


def test_go_build_argv_environment_and_catalog_argv_are_deterministic(tmp_path: Path) -> None:
    assert go.build_argv(("go", "build", "-o", "bin/app", ".")) == ("go", "build", "-x", "-o", "bin/app", ".")
    assert go.build_argv(("go", "build", "-x", ".")) == ("go", "build", "-x", ".")
    assert go.build_argv(("go", "list", "-deps", "-json", "./...")) == ("go", "list", "-deps", "-json", "./...")
    assert go.list_argv([["go", "mod", "download"], ["go", "build", "-tags", "accepted", "-ldflags", "-s -w",
                                                     "-o", "bin/app", "-mod=vendor", "./cmd/app"]]) == (
        "go", "list", "-deps", "-json", "-tags", "accepted", "-mod=vendor", "./cmd/app")
    assert go.list_argv([["go", "build", "-o", "bin/app"]]) == ("go", "list", "-deps", "-json", "./...")
    assert go.environment({"CGO_ENABLED": "1"}, tmp_path, ".") == {
        "CGO_ENABLED": "1", "GOCACHE": "/tmp/appsec-go-cache"}
    (tmp_path / "vendor").mkdir()
    assert go.environment({"GOFLAGS": "-trimpath"}, tmp_path, ".")["GOFLAGS"] == "-trimpath -mod=vendor"
    assert go.environment({"GOFLAGS": "-mod=mod"}, tmp_path, ".")["GOFLAGS"] == "-mod=mod"


def test_go_tool_classification_uses_only_the_kernel_resolved_image_owned_path() -> None:
    assert go.tool_identity(f"{TOOLS}/compile", [f"{TOOLS}/compile", "-p", "main"]) == ("compile", "compiler")
    assert go.tool_identity(f"{TOOLS}/asm", ["asm"]) == ("asm", "assembler")
    assert go.tool_identity(f"{TOOLS}/link", ["link"]) == ("link", "linker")
    assert go.tool_identity(f"{TOOLS}/cgo", ["cgo"]) == ("cgo", "cgo")
    assert go.tool_identity(f"{TOOLS}/pack", ["pack"]) == ("pack", "package-builder")
    assert go.tool_identity("/usr/lib/go-1.22/pkg/tool/linux_arm64/compile", ["compile"]) == (
        "compile", "compiler")
    assert go.tool_identity(f"{GOROOT}/bin/go", ["go", "build"]) == ("go", "build-driver")
    assert go.tool_identity("/usr/bin/gcc", ["gcc", "-c", "x.c"]) == ("gcc", "compiler-driver")
    assert go.tool_identity("/usr/bin/x86_64-linux-gnu-gcc-13", ["gcc", "-o", "app", "x.o"]) == (
        "x86_64-linux-gnu-gcc-13", "linker-driver")
    assert go.tool_identity("/usr/bin/ld", ["ld"]) == ("ld", "linker")
    assert go.tool_identity("/usr/bin/ar", ["ar", "rcs"]) == ("ar", "archiver")
    # A toolchain name outside a toolchain directory, and unrelated programs, are not tools.
    assert go.tool_identity("/usr/bin/compile", ["compile"]) is None
    assert go.tool_identity("/usr/bin/link", ["link"]) is None
    assert go.tool_identity(f"{TOOLS}/vet", ["vet"]) is None
    assert go.tool_identity("/usr/bin/python3", ["python3", "tool-wrapper.py", "go"]) is None
    assert go.tool_identity("/opt/go", ["go"]) is None
    # Nothing below a build-writable mount is evidence, whatever its path or argv[0] claims.
    for executable in ("/capture/wrappers/go", "/capture/wrappers/gcc",
                       "/workspace/go/pkg/tool/linux_amd64/compile", "/workspace/usr/local/go/bin/go",
                       "/tmp/go-build1/b001/exe/gcc", "/proc/self/fd/3", "/dev/shm/link",
                       f"/usr/../workspace/go/pkg/tool/linux_amd64/compile", f"{TOOLS}/./compile",
                       "pkg/tool/linux_amd64/compile", "./compile", "", f"/usr//local/go/bin/go"):
        assert go.tool_identity(executable, [f"{TOOLS}/compile", "-p", "main"]) is None, executable
        assert not go.image_owned(executable), executable


def test_go_build_retains_streams_provenance_packages_artifacts_and_sanitized_mcp(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    calls: list[tuple[str, ...]] = []
    run_id, fingerprint = _accepted(config, target, calls)
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, go_container(calls), output_bytes=4096))
    assert outcome["status"] == "SUCCEEDED"
    run_root = config.runtime.runs_dir / run_id
    receipt = _receipt(config, run_id)
    assert receipt["terminal_status"] == "SUCCEEDED" and receipt["gaps"] == []
    assert receipt["capture_identity"] == go.CAPTURE_IDENTITY
    assert not any(command[1] in {"run", "test", "tool"} for command in calls)
    assert calls[-2:] == [("go", "build", "-x", "-tags", "accepted", "-o", "bin/app", "./cmd/app"),
                          ("go", "list", "-deps", "-json", "-tags", "accepted", "./cmd/app")]

    # Every go command, including the package catalog, carries a hash-verified capture identity.
    assert [command["role"] for command in receipt["commands"]] == ["build", "catalog"]
    assert [command["tool_kind"] for command in receipt["commands"]] == ["build-driver", "package-catalog"]
    for ordinal, command in enumerate(receipt["commands"], 1):
        identity = command["execution_capture"]
        attempt = identity["scope"]["attempt_id"]
        assert identity["scope"] == {"run_id": run_id, "job_id": "job_language_build", "attempt_id": attempt,
                                     "build_unit_id": receipt["build_unit_id"], "family": "go"}
        assert identity["path"] == (f"data/build/go/units/{receipt['build_unit_id']}/attempts/{attempt}/"
                                    f"execution-capture/command-{ordinal:03d}/record.json")
        assert identity["complete"] is True and identity["envp_captured"] is True
        assert "connect" in identity["collector"]["event_kinds"]
        assert identity["events"]["counts"]["process_exec"] > 0
        nested = [identity, identity["events"], identity["secret_findings"],
                  identity["secret_scan"]["execution"], identity["secret_scan"]["report"]]
        assert all(file_sha256(run_root / member["path"]) == member["sha256"] for member in nested)
        assert identity["secret_scan"]["exit_code"] == 0 and identity["secret_findings"]["count"] == 0
        capture_root = (run_root / identity["path"]).parent
        assert not tuple(capture_root.glob("trace*")) and not (capture_root / ".secret-scan-input").exists()
    build = receipt["commands"][0]
    assert build["execution_capture"]["events"]["counts"]["connect"] == 1
    assert build["stderr"]["storage"] == "complete-file"
    assert build["stderr"]["truncated"] is False and build["stderr"]["preview_truncated"] is True
    assert build["stderr"]["captured_bytes"] == build["stderr"]["total_bytes"] > 4096

    # Tool provenance is derived from successful process-exec events at image-owned paths.
    rows = receipt["tool_invocations"]
    by_tool = {item["tool"]: item for item in rows
               if item["tool"] != "go" and item["origin"] not in _version_queries(rows, run_root, receipt)}
    assert sorted(item["tool"] for item in rows) == [
        "asm", "cgo", "compile", "compile", "compile", "gcc", "go", "go", "link", "link", "link"]
    assert all(item["mapping"].startswith("syscall-process-exec") for item in rows)
    assert all(item["evidence"]["process_exec"]["count"] == 1 for item in rows)
    # The identical `-V=full` argv under two commands is two rows, each resolving in its own record.
    events = {command["execution_capture"]["sha256"]: {event["ordinal"]: event for event in _events(run_root, command)}
              for command in receipt["commands"]}
    for item in rows:
        observed = item["evidence"]["process_exec"]
        resolved = [events[item["evidence"]["capture_record_sha256"]][ordinal] for ordinal in observed["event_ordinals"]]
        assert resolved and all(event["kind"] == "process_exec" and event["result"] == 0 and
                                event["executable"] == observed["executable"] for event in resolved)
    assert len({item["evidence"]["capture_record_sha256"] for item in rows if item["tool"] == "compile"}) == 2
    assert all(item["evidence"]["process_exec"]["executable"].startswith("/usr/") for item in rows)
    assert by_tool["compile"]["mapping"] == "syscall-process-exec"
    assert by_tool["compile"]["evidence"]["tool_call"] is None
    assert by_tool["compile"]["evidence"]["process_exec"]["executable"] == f"{TOOLS}/compile"
    assert by_tool["compile"]["package"] == "main"
    # The catalog directory resolves the compiler's relative source argument to an exact file.
    assert by_tool["compile"]["inputs"] == [{
        "workspace_path": "go/cmd/app/main.go", "mapping": "exact-workspace-path", "mapping_confidence": 1.0,
        "sha256": file_sha256(target / "go/cmd/app/main.go"),
        "size_bytes": (target / "go/cmd/app/main.go").stat().st_size}]
    assert by_tool["asm"]["inputs"] == [] and by_tool["link"]["outputs"] == []
    # The launcher and the failed PATH probe are not counted with the real gcc.
    assert by_tool["gcc"]["mapping"] == "syscall-process-exec+tool-call"
    assert by_tool["gcc"]["tool_kind"] == "compiler-driver"
    assert by_tool["gcc"]["evidence"]["process_exec"]["executable"] == "/usr/bin/gcc"
    assert by_tool["gcc"]["evidence"]["tool_call"]["exit_code"] == 0
    assert all(item["evidence"]["capture_record_sha256"] == build["execution_capture"]["sha256"]
               for item in by_tool.values())
    assert set(by_tool) == {"asm", "cgo", "compile", "gcc", "link"}
    provenance = receipt["capture_provenance"]
    assert provenance["schema"] == "appsec-review/go-capture-provenance/1"
    assert provenance["complete"] is True and provenance["command_count"] == 2
    assert provenance["observed_tool_kinds"] == [
        "assembler", "build-driver", "cgo", "compiler", "compiler-driver", "linker"]
    assert provenance["failed_exec_events"] == 1 and provenance["redacted_exec_events"] == 0
    assert provenance["untrusted_location_exec_events"] == 3  # two go launchers and the gcc launcher
    assert provenance["tool_call_records"] == 3 and provenance["unreconciled_tool_calls"] == 0
    assert provenance["connect_events"] == 1 and provenance["truncated_tool_exec_events"] == 0

    # Envp is captured on the later exec, and exact-name redaction removed its value.
    compiler = next(event for event in _events(run_root, build)
                    if event["kind"] == "process_exec" and event["executable"].endswith("/compile")
                    and "-p" in event["argv"])
    assert {"name": "GITHUB_TOKEN", "redacted": True, "value": "<redacted>"} in compiler["envp"]
    assert {"name": "CGO_ENABLED", "redacted": False, "value": "1"} in compiler["envp"]
    assert {"name": "GOCACHE", "redacted": False, "value": "/tmp/appsec-go-cache"} in compiler["envp"]
    assert provenance["envp_redacted_names"] == ["GITHUB_TOKEN"] and provenance["envp_events"] > 0
    assert NAMED_TOKEN not in _retained_text(run_root)

    # Artifacts and metadata come from validated parsers, never from running a produced file.
    artifacts = {item["workspace_path"]: item for item in receipt["artifacts"]}
    executable = artifacts["go/bin/app"]
    assert executable["kind"] == "executable" and executable["loader_dependency_status"] == "resolved"
    assert executable["loader_linkage"] == "static" and executable["go_build_status"] == "resolved"
    assert executable["go_build_parser"] == go.BUILD_FACTS_PARSER
    assert artifacts["go/cmd/app/generated.go"]["kind"] == "generated-source"
    assert not any("execution-capture" in item["path"] for item in receipt["artifacts"])
    metadata, = receipt["build_metadata"]
    assert metadata["workspace_path"] == "go/bin/app" and metadata["sha256"] == executable["sha256"]
    assert metadata["build_id_sha256"] == executable["build_id_sha256"] == go.hashlib.sha256(
        GO_BUILD_ID.encode()).hexdigest()
    assert metadata["go_version"] == "go1.23.12" and metadata["debug_data"]["dwarf"] == "embedded"
    assert metadata["dependency_modules"][0]["path"] == "github.com/google/uuid"
    assert receipt["module_metadata"] == [{
        "workspace_path": "go/go.mod", "kind": "go-module-metadata",
        "sha256": file_sha256(target / "go/go.mod"), "size_bytes": (target / "go/go.mod").stat().st_size}]
    packages = {item["import_path"]: item for item in receipt["package_relationships"]}
    assert packages["example.test/app/cmd/app"]["dependencies"] == ["fmt"]
    assert packages["example.test/app/cmd/app"]["module_path"] == "example.test/app"
    assert packages["fmt"]["standard"] is True

    # Exact argv stays protected; receipts and retrieval expose hashes and bounded facts only.
    protected = (run_root / receipt["protected_compile_commands"]["path"]).read_text(encoding="utf-8")
    assert "-trimpath" in protected
    serialized = json.dumps([receipt["tool_invocations"], receipt["commands"]])
    assert '"argv"' not in serialized and "-trimpath" not in serialized and "/tmp/appsec-go-cache" not in serialized
    adapter = RetrievalMcpAdapter(RetrievalCore(config.runtime.runs_dir, run_id))
    response = adapter.call("search", {"query": "build-driver", "indexes": ["build"]})
    artifact_response = adapter.call("search", {"query": "executable", "indexes": ["build"]})
    assert response["results"] and artifact_response["results"]
    public = json.dumps([response, artifact_response])
    assert build["execution_capture"]["sha256"] in public
    assert "protected-commands" not in public and "-trimpath" not in public and "GITHUB_TOKEN" not in public


def test_go_capture_secret_is_detected_recorded_and_absent_from_every_retained_file(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted(config, target, [])
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, go_container([], leak=SYNTHETIC_SECRET)))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / run_id
    receipt = _receipt(config, run_id)
    build, catalog = receipt["commands"]
    assert catalog["execution_capture"]["secret_findings"]["count"] == 0
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
    # The redacted linker exec is lost provenance: it is reported, never reconstructed.
    provenance = receipt["capture_provenance"]
    assert provenance["redacted_exec_events"] == 1 and provenance["complete"] is False
    # Only the linker's version queries remain; the link itself is gone.
    assert all(item["origin"] in _version_queries(receipt["tool_invocations"], run_root, receipt)
               for item in receipt["tool_invocations"] if item["tool"] == "link")
    assert ("1 process-exec events were redacted by the secret scan; their tool provenance is "
            "unavailable") in receipt["gaps"]
    assert "Go linker execution was not observed for a cataloged executable" in receipt["gaps"]
    assert not _checkpoints(config)


def test_go_tool_call_without_a_successful_exec_is_never_tool_provenance(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted(config, target, [])
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, go_container([], phantom_gcc=True)))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / run_id
    receipt = _receipt(config, run_id)
    build = receipt["commands"][0]
    # The capture itself is complete: the wrapper wrote a gcc record and its launcher ran, but
    # the only exec of the real gcc the collector saw failed.
    assert all(command["execution_capture"]["complete"] for command in receipt["commands"])
    record = json.loads((run_root / build["execution_capture"]["path"]).read_text(encoding="utf-8"))
    assert any(item["uri"].endswith("-gcc/record.json") for item in record["tool_calls"]["records"])
    attempts = [event for event in _events(run_root, build)
                if event["kind"] == "process_exec" and event["executable"].endswith("/gcc")]
    assert [(event["executable"], event["result"]) for event in attempts] == [
        (f"{GOROOT}/bin/gcc", -1), ("/capture/wrappers/gcc", 0), ("/usr/bin/gcc", -1)]
    rows = receipt["tool_invocations"]
    assert "gcc" not in {item["tool"] for item in rows}
    assert "compiler-driver" not in {item["tool_kind"] for item in rows}
    assert all(item["evidence"]["process_exec"]["count"] >= 1 for item in rows)
    assert {item["mapping"] for item in rows} <= {"syscall-process-exec", "syscall-process-exec+tool-call"}
    provenance = receipt["capture_provenance"]
    assert provenance["unreconciled_tool_calls"] == 1 and provenance["complete"] is False
    assert provenance["failed_exec_events"] == 2
    assert "compiler-driver" not in provenance["observed_tool_kinds"]
    assert ("1 tool-call records had no matching successful process-exec event and are not claimed "
            "as tool execution") in receipt["gaps"]
    assert receipt["terminal_status"] == "SUCCEEDED"
    assert not _checkpoints(config)


def test_go_secondary_evidence_cannot_satisfy_the_required_compiler_and_linker_checks(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted(config, target, [])
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, go_container([], spoofed_toolchain=True)))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / run_id
    receipt = _receipt(config, run_id)
    build = receipt["commands"][0]
    # Everything short of a successful exec of the image-owned tool is present: the `-x` build
    # log names the real compiler and linker, toolchain-shaped paths ran from the workspace, a
    # target script used the real compiler path as argv[0], and the output binary exists.
    assert build["execution_capture"]["complete"] is True
    executed = [event for event in _events(run_root, build)
                if event["kind"] == "process_exec" and event["result"] == 0]
    assert any(event["executable"] == "/workspace/go/pkg/tool/linux_amd64/compile" for event in executed)
    assert any(event["argv"][0] == f"{TOOLS}/compile" and event["executable"] == "/workspace/go/tool.sh"
               for event in executed)
    assert f"{TOOLS}/link" in (run_root / build["stderr"]["path"]).read_text(encoding="utf-8")
    assert any(item["workspace_path"] == "go/bin/app" and item["kind"] == "executable"
               for item in receipt["artifacts"])
    tools = {item["tool"] for item in receipt["tool_invocations"]}
    assert tools == {"go", "asm", "cgo", "gcc", "compile", "link"}
    # The real compiler and linker did run, but only to report their versions: an observed tool
    # kind is not an observed compilation or link.
    assert all(item["origin"] in _version_queries(receipt["tool_invocations"], run_root, receipt)
               for item in receipt["tool_invocations"] if item["tool"] in {"compile", "link"})
    provenance = receipt["capture_provenance"]
    assert {"compiler", "linker"} <= set(provenance["observed_tool_kinds"])
    assert provenance["untrusted_location_exec_events"] == 7 and provenance["complete"] is False
    assert "Go compiler execution was not observed in the standardized capture" in receipt["gaps"]
    assert "Go linker execution was not observed for a cataloged executable" in receipt["gaps"]
    assert not _checkpoints(config)


def test_go_invocation_secret_is_not_reintroduced_by_the_protected_command(tmp_path: Path) -> None:
    class SecretEnvironment:
        def __init__(self, inner):
            self.inner = inner

        def resolve(self):
            return self.inner.resolve()

        def execute_captured(self, argv, *, environment, **options):
            return self.inner.execute_captured(
                argv, environment={**environment, "RELEASE_SIGNING_VALUE": SYNTHETIC_SECRET}, **options)

    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted(config, target, [])
    _language(config, target, fingerprint, run_id, lambda unit, profile: SecretEnvironment(
        simulated_executor(profile, go_container([]))))
    run_root = config.runtime.runs_dir / run_id
    receipt = _receipt(config, run_id)
    for command in receipt["commands"]:
        assert command["execution_capture"]["secret_findings"]["count"] >= 1
        exact = json.loads((run_root / command["protected_argv"]["path"]).read_text(encoding="utf-8"))
        assert exact["argv"] == ["<redacted: secret detected by gitleaks>"]
        assert set(exact["environment"].values()) == {REDACTED}
    assert SYNTHETIC_SECRET not in _retained_text(run_root)
    # Every exec inherited the secret, so no tool provenance may be claimed.
    assert receipt["tool_invocations"] == []
    assert "Go compiler execution was not observed in the standardized capture" in receipt["gaps"]
    assert receipt["capture_provenance"]["complete"] is False and not _checkpoints(config)


def test_go_scanner_failure_fails_closed_as_an_explicit_gap_and_is_not_checkpointed(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted(config, target, [])
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, go_container([], leak=SYNTHETIC_SECRET), scanner=failing_scanner))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / run_id
    receipt = _receipt(config, run_id)
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
    assert receipt["tool_invocations"] == [] and receipt["package_relationships"] == []
    assert "Go compiler execution was not observed in the standardized capture" in receipt["gaps"]
    assert "go package relationship catalog was truncated, redacted, or not parseable" in receipt["gaps"]
    assert not _checkpoints(config)


@pytest.mark.parametrize(("capture", "expected", "leak"), [
    ("event_count_limit = 6", "syscall event retention limit reached", None),
    ("event_count_limit = 250000\ntool_call_count_limit = 1", "tool call retention limit reached", None),
    ("event_count_limit = 250000\nsecret_finding_count_limit = 1",
     "gitleaks capture finding retention limit reached", SYNTHETIC_SECRET),
], ids=["events", "tool-calls", "findings"])
def test_go_capture_caps_are_explicit_gaps_and_never_limit_sanitization(
        tmp_path: Path, capture: str, expected: str, leak: str | None) -> None:
    config, target = _fixture(tmp_path, capture=capture)
    run_id, fingerprint = _accepted(config, target, [])
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, go_container([], leak=leak)))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / run_id
    receipt = _receipt(config, run_id)
    build = receipt["commands"][0]
    assert build["execution_capture"]["complete"] is False
    assert f"execution capture command 1: {expected}" in receipt["gaps"]
    assert receipt["capture_provenance"]["complete"] is False
    assert not _checkpoints(config)
    if leak:
        assert build["execution_capture"]["secret_findings"]["count"] == 1
        assert SYNTHETIC_SECRET not in _retained_text(run_root)


def test_go_truncated_toolchain_argv_is_a_named_gap_not_a_hashed_command(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, capture="event_count_limit = 250000\nargv_count_limit = 4")
    run_id, fingerprint = _accepted(config, target, [])
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, go_container([])))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / run_id
    receipt = _receipt(config, run_id)
    provenance = receipt["capture_provenance"]
    assert provenance["truncated_tool_exec_events"] >= 3 and provenance["complete"] is False
    assert all(item["origin"] in _version_queries(receipt["tool_invocations"], run_root, receipt)
               for item in receipt["tool_invocations"] if item["tool"] in {"compile", "link"})
    assert any(gap.endswith("toolchain process-exec events had truncated argv; their tool provenance "
                            "is unavailable") for gap in receipt["gaps"])
    assert "Go compiler execution was not observed in the standardized capture" in receipt["gaps"]
    assert not _checkpoints(config)


@pytest.mark.parametrize("mode", ["hash", "schema", "path", "scope", "findings", "missing"])
def test_go_capture_tampering_is_a_framework_integrity_failure(tmp_path: Path, mode: str) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted(config, target, [])
    with pytest.raises(RuntimeError, match="job reported partial failure: execute.go"):
        _language(config, target, fingerprint, run_id, lambda unit, profile: TamperingExecutor(
            simulated_executor(profile, go_container([])), mode))


def test_go_uncaptured_executor_is_rejected(tmp_path: Path) -> None:
    class Uncaptured:
        def resolve(self):
            return None

        def execute(self, argv, **_options):
            raise AssertionError("Go commands must not run outside execution capture")

    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted(config, target, [])
    with pytest.raises(RuntimeError, match="job reported partial failure: execute.go"):
        _language(config, target, fingerprint, run_id, lambda unit, profile: Uncaptured())


@pytest.mark.parametrize(("output", "expected"), [
    (b"\x7fELFgo-fixture", ("loader dependencies were not parseable", "Go build metadata was not parseable")),
    (minimal_go_elf().replace(b".note.go.buildid\0", b".note.xx.buildid\0"),
     ("Go build metadata was not parseable: ELF file has no .note.go.buildid section",)),
    (minimal_go_elf().replace(b"\xff Go buildinf:", b"\xff Go buildinf;"),
     ("Go build metadata was not parseable: Go build information header is invalid",)),
], ids=["not-elf", "no-build-id", "corrupt-build-info"])
def test_go_malformed_build_output_is_an_unparsed_gap_never_resolved_metadata(
        tmp_path: Path, output: bytes, expected: tuple[str, ...]) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted(config, target, [])
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, go_container([], output=output)))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    receipt = _receipt(config, run_id)
    executable = next(item for item in receipt["artifacts"] if item["workspace_path"] == "go/bin/app")
    assert executable["go_build_status"] == "unparsed" and "build_id_sha256" not in executable
    assert receipt["build_metadata"] == []
    for fragment in expected:
        assert any(gap.startswith("go/bin/app: ") and fragment in gap for gap in receipt["gaps"])
    if len(expected) == 2:
        assert executable["loader_dependency_status"] == "unparsed" and executable["loader_dependencies"] == []
    # The tool provenance is unaffected: the capture, not the output file, establishes it.
    assert receipt["capture_provenance"]["complete"] is True


@pytest.mark.parametrize(("options", "expected"), [
    ({"catalog_exit": 1}, "go package relationship catalog was unavailable"),
    ({"catalog": _catalog("go")[:-20]}, "go package relationship catalog was truncated, redacted, or not parseable"),
    ({"catalog": b""}, "go package relationship catalog was truncated, redacted, or not parseable"),
], ids=["failed", "partial", "empty"])
def test_go_package_catalog_failure_is_a_gap_and_publishes_no_relationships(
        tmp_path: Path, options: dict, expected: str) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted(config, target, [])
    outcome = _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, go_container([], **options)))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    receipt = _receipt(config, run_id)
    assert receipt["terminal_status"] == "SUCCEEDED" and receipt["gaps"][0] == expected
    assert set(receipt["gaps"][1:]) == {
        "build-execution-capture: EVIDENCE_INCOMPLETE",
        "compiler-artifact-collection: EVIDENCE_INCOMPLETE",
    }
    assert receipt["package_relationships"] == []
    # Without a catalog directory the compiler's relative source argument stays unmapped.
    compiler = next(item for item in receipt["tool_invocations"] if item["tool"] == "compile")
    assert compiler["inputs"] == []


def test_go_recipe_that_substitutes_the_toolchain_is_rejected_at_plan_time_and_never_runs(
        tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    calls: list[tuple[str, ...]] = []
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan(infer=GoRecipeModel([
        "go", "build", "-toolexec", "{root}/wrap.sh", "-o", "{root}/bin/app", "./cmd/app"]).complete)]).run(
            target_root=target, source_fingerprint=fingerprint)
    run_root = config.runtime.runs_dir / upstream["run_id"]
    # The shared recipe validator applies the Go command policy, so the proposal is rejected
    # (and offered for bounded repair) before any image or container exists.
    plan = load_accepted_plan(run_root)
    action, = [item for item in plan["build_topology"]["build_actions"] if item["family"] == "go"]
    assert action["recipe"] is None and plan["model"]["status"] == "REJECTED"
    assert plan["contradictions"] == ["build_recipes[0]: go option is forbidden: -toolexec"]
    GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: simulated_executor(profile, go_container(calls)),
        image_resolver_factory=lambda unit: ImageResolver(target))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    _language(config, target, fingerprint, upstream["run_id"], lambda unit, profile: simulated_executor(
        profile, go_container(calls)))
    assert calls == []
    assert not [item for item in load_accepted_language_build(run_root)["receipts"] if item["family"] == "go"]


def test_go_adapter_rechecks_the_command_policy_of_an_accepted_dispatch() -> None:
    # Defense in depth: a dispatch that reached the adapter is validated again before execution.
    recipe = {"configure_commands": [], "environment": {},
              "build_commands": [["go", "build", "-toolexec", "wrap.sh", "."]]}
    assert go.validate_dispatch({"recipe": recipe}) == ("go option is forbidden: -toolexec",)
    assert go.validate_dispatch({"recipe": None}) == ("Go execution requires an accepted recipe",)


def test_go_probe_environment_gives_an_undeclared_dependency_build_a_writable_module_cache() -> None:
    recipe = {"build_system": "go", "source_dir": "go", "environment": {"CGO_ENABLED": "1"}}
    # Only a dependency-bearing project image carries a module cache; otherwise the cache would
    # be the read-only image root and any declared module would fail to resolve.
    assert _probe_environment({**recipe, "network_required": False}) == {
        "CGO_ENABLED": "1", "GOMODCACHE": "/tmp/appsec-go-mod"}
    assert _probe_environment({**recipe, "network_required": True}) == {"CGO_ENABLED": "1"}
    # A recipe cannot point the cache at the unwritable image path either.
    assert _probe_environment({**recipe, "network_required": False,
                               "environment": {"GOMODCACHE": "/go/pkg/mod"}})["GOMODCACHE"] == "/tmp/appsec-go-mod"
    assert _probe_environment({**recipe, "network_required": True,
                               "environment": {"GOMODCACHE": "/go/pkg/mod"}})["GOMODCACHE"] == "/opt/project-deps/go"


def test_go_failed_sibling_does_not_discard_successful_unit(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    sibling = target / "broken" / "cmd" / "app"
    sibling.mkdir(parents=True)
    (target / "broken" / "go.mod").write_text("module example.test/broken\n\ngo 1.23\n", encoding="utf-8")
    (sibling / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    run_id, fingerprint = _accepted(config, target, [])
    _language(config, target, fingerprint, run_id, lambda unit, profile: simulated_executor(
        profile, go_container([], fail_roots=frozenset({"broken"}))))
    receipts = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"]
    assert {value["root"]: value["terminal_status"] for value in receipts} == {
        "broken": "FAILED", "go": "SUCCEEDED"}
    broken = _receipt(config, run_id, "broken")
    assert "build command 1 exited 2" in broken["gaps"]
    assert [command["role"] for command in broken["commands"]] == ["build"]
    assert _receipt(config, run_id)["gaps"] == []


@pytest.mark.parametrize("tampered", ["artifact", "stream", "capture-events", "capture-findings"])
def test_go_checkpoint_reuses_verified_captures_and_detects_tampering(tmp_path: Path, tampered: str) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted(config, target, [])
    calls: list[tuple[str, ...]] = []
    factory = lambda unit, profile: simulated_executor(profile, go_container(calls))
    _language(config, target, fingerprint, run_id, factory)
    receipt = _receipt(config, run_id)
    assert len(_checkpoints(config)) == 1 and len(calls) == 2
    resumed = _language(config, target, fingerprint, run_id, factory, force_from="job_language_build")
    reused = _receipt(config, run_id)
    assert resumed["status"] == "SUCCEEDED" and reused["checkpoint_reused"] is True and len(calls) == 2
    assert reused["gaps"] == receipt["gaps"] == []
    assert [command["execution_capture"] for command in reused["commands"]] == [
        command["execution_capture"] for command in receipt["commands"]]
    run_root = config.runtime.runs_dir / run_id
    identity = receipt["commands"][0]["execution_capture"]
    path = run_root / {"artifact": receipt["artifacts"][0]["path"],
                       "stream": receipt["commands"][0]["stdout"]["path"],
                       "capture-events": identity["events"]["path"],
                       "capture-findings": identity["secret_findings"]["path"]}[tampered]
    path.write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="job reported partial failure: execute.go"):
        _language(config, target, fingerprint, run_id, factory, force_from="job_language_build")
