"""Go build adapter: typed settings, command policy, argv and tool classification (code level)."""
from __future__ import annotations

from pathlib import Path

from appsec_review.config import GoBuildSettings, LanguageBuildSettings, load_config
from appsec_review.jobs.job_language_build import build_job as build_language, go
from appsec_review.runtime import plan_jobs

ROOT = Path(__file__).parents[3]
GOROOT = "/usr/local/go"
TOOLS = f"{GOROOT}/pkg/tool/linux_amd64"


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


def test_go_adapter_rechecks_the_command_policy_of_an_accepted_dispatch() -> None:
    # Defense in depth: a dispatch that reached the adapter is validated again before execution.
    recipe = {"configure_commands": [], "environment": {},
              "build_commands": [["go", "build", "-toolexec", "wrap.sh", "."]]}
    assert go.validate_dispatch({"recipe": recipe}) == ("go option is forbidden: -toolexec",)
    assert go.validate_dispatch({"recipe": None}) == ("Go execution requires an accepted recipe",)
