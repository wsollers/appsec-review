"""Rust build adapter: option validation and kernel-resolved tool classification (code level)."""
from __future__ import annotations



from appsec_review.config import RustBuildSettings
from appsec_review.jobs.job_language_build import rust

TOOLCHAIN = "/usr/local/rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin"


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
