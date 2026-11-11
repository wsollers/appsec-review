from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from appsec_review.jobs.build_recipe_commands import normalize_recipe_command, prepare_recipe_command


@pytest.fixture
def native_command(tmp_path: Path):
    workspace = tmp_path / "workspace"
    source = workspace / "B"
    source.mkdir(parents=True)
    documents = []
    for name, content in {
        "CMakeLists.txt": b"project(B)\nadd_executable(B b.c)\n",
        "Makefile": b"all:\n\tcc b.c -o build/B\nB/target: all\n",
    }.items():
        (source / name).write_bytes(content)
        documents.append({"path": "B/" + name, "sha256": hashlib.sha256(content).hexdigest()})
    (source / "b.c").write_bytes(b"int main(void) { return 0; }\n")
    recipe = {"source_dir": "B", "build_dir": "B/build"}
    accepted = {"root": "B", "descriptor_package": {"documents": documents}}
    return workspace, accepted, recipe


@pytest.mark.parametrize("explicit_cwd", [False, True])
@pytest.mark.parametrize("driver", ["cmake", "make"])
def test_native_normalization_rebases_only_path_operands(native_command, explicit_cwd, driver):
    workspace, accepted, recipe = native_command
    if explicit_cwd:
        recipe["execution_cwd"] = {"build": "B/build"}
    before = deepcopy(recipe)
    if driver == "cmake":
        raw = ("cmake", "--build", "B/build", "--target", "B/target", "B/another", "--config", "B/Release")
        expected = ("cmake", "--build", "." if explicit_cwd else "build",
                    "--target", "B/target", "B/another", "--config", "B/Release")
    else:
        raw = ("make", "-f", "Makefile", "-C", "B", "B/target", "VALUE=B/flag")
        expected = ("make", "-f", "Makefile", "-C", ".." if explicit_cwd else ".",
                    "B/target", "VALUE=B/flag")
    assert normalize_recipe_command(recipe, "build", raw) == (
        expected, "B/build" if explicit_cwd else "B")
    assert recipe == before and not (workspace / "B/build").exists()


@pytest.mark.parametrize("source_operand", ["..", "B"])
def test_cmake_out_of_source_cwd_binds_accepted_source(native_command, source_operand):
    workspace, accepted, recipe = native_command
    recipe["execution_cwd"] = {"configure": "B/build", "build": "B/build"}
    assert prepare_recipe_command(workspace, accepted, recipe, "configure",
                                  ("cmake", "-S", source_operand, "-B", ".")) == (
        ("cmake", "-S", "..", "-B", "."), "B/build")
    raw = ("cmake", "--build", "B/build", "--target", "B/target")
    prepared = prepare_recipe_command(workspace, accepted, recipe, "build", raw)
    assert prepared == normalize_recipe_command(recipe, "build", raw)
    assert prepare_recipe_command(workspace, accepted, recipe, "build", prepared[0],
                                  normalized=True) == prepared
    with pytest.raises(ValueError, match="wrong accepted source/build"):
        prepare_recipe_command(workspace, accepted, recipe, "configure",
                               ("cmake", "-S", ".", "-B", "."))


@pytest.mark.parametrize("raw", [
    ("cmake", "-S", "..", "-S", "..", "-B", "."),
    ("cmake", "--preset", "B/preset"),
    ("cmake", "--build=.", "--target", "B/target"),
    ("cmake", "--build", "../another-build"),
    ("make", "-jC..", "B/target"),
    ("make", "-C", "../../../", "B/target"),
    ("make", "-f"),
])
def test_ambiguous_or_escaping_driver_authority_is_refused(native_command, raw):
    workspace, accepted, recipe = native_command
    recipe["execution_cwd"] = {"build": "B/build"}
    with pytest.raises(ValueError):
        prepare_recipe_command(workspace, accepted, recipe, "build", raw)


@pytest.mark.parametrize("directory", [("-C", ".."), ("--directory=..",)])
@pytest.mark.parametrize("driver", [("-f", "Makefile"), ("--file=Makefile",)])
def test_make_directory_precedes_driver_resolution_and_rechecks_accepted_bytes(
        native_command, directory, driver):
    workspace, accepted, recipe = native_command
    recipe["execution_cwd"] = {"build": "B/build"}
    raw = ("make", *driver, *directory, "B/target")
    assert prepare_recipe_command(workspace, accepted, recipe, "build", raw) == (raw, "B/build")
    with pytest.raises(ValueError, match="default driver is absent"):
        prepare_recipe_command(workspace, accepted, recipe, "build", ("make", "-C", ".", "B/target"))
    (workspace / "B/Makefile").write_bytes(b"replaced\n")
    with pytest.raises(ValueError, match="unchanged accepted source descriptor"):
        prepare_recipe_command(workspace, accepted, recipe, "build", raw)


def test_each_phase_rechecks_cwd_symlinks_and_cmake_source_cache(native_command):
    workspace, accepted, recipe = native_command
    prepare_recipe_command(workspace, accepted, recipe, "configure", ("cmake", "-S", ".", "-B", "build"))
    cache = workspace / "B/build/CMakeCache.txt"
    cache.write_text("CMAKE_HOME_DIRECTORY:INTERNAL=/workspace/somewhere-else\n")
    with pytest.raises(ValueError, match="different accepted source"):
        prepare_recipe_command(workspace, accepted, recipe, "build", ("cmake", "--build", "build"))
    cache.unlink()
    (workspace / "B/build").rmdir()
    (workspace / "B/build").symlink_to(workspace / "B", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        prepare_recipe_command(workspace, accepted, recipe, "build", ("cmake", "--build", "build"))


def test_unproven_cwd_and_changed_accepted_descriptor_are_refused(native_command):
    workspace, accepted, recipe = native_command
    (workspace / "B/elsewhere").mkdir()
    recipe["execution_cwd"] = {"build": "B/elsewhere"}
    with pytest.raises(ValueError, match="differs from accepted source/build authority"):
        prepare_recipe_command(workspace, accepted, recipe, "build", ("make",))
    recipe.pop("execution_cwd")
    (workspace / "B/CMakeLists.txt").write_bytes(b"project(other)\n")
    with pytest.raises(ValueError, match="unchanged accepted source descriptor"):
        prepare_recipe_command(workspace, accepted, recipe, "build", ("cmake", "--build", "build"))


def test_target_root_source_and_explicit_nested_build_directory_are_contained(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    content = b"project(root)\n"
    (workspace / "CMakeLists.txt").write_bytes(content)
    accepted = {"root": ".", "descriptor_package": {"documents": [
        {"path": "CMakeLists.txt", "sha256": hashlib.sha256(content).hexdigest()}]}}
    recipe = {"source_dir": ".", "build_dir": "build", "execution_cwd": {"configure": "build"}}
    assert prepare_recipe_command(workspace, accepted, recipe, "configure",
                                  ("cmake", "-S", "..", "-B", ".")) == (
        ("cmake", "-S", "..", "-B", "."), "build")
    (workspace / "build/CMakeCache.txt").symlink_to(workspace / "CMakeLists.txt")
    with pytest.raises(ValueError, match="cache traverses a symlink"):
        prepare_recipe_command(workspace, accepted, recipe, "build", ("cmake", "--build", "build"))


@pytest.mark.parametrize("source_dir", [".", "B"])
def test_guest_cmake_home_cache_accepts_the_exact_root_or_nested_unit(tmp_path, source_dir):
    workspace = tmp_path / "workspace"
    source = workspace / source_dir
    source.mkdir(parents=True)
    content = b"project(accepted)\n"
    descriptor = source / "CMakeLists.txt"
    descriptor.write_bytes(content)
    accepted = {"root": source_dir, "descriptor_package": {"documents": [{
        "path": descriptor.relative_to(workspace).as_posix(), "sha256": hashlib.sha256(content).hexdigest()}]}}
    build_dir = "build" if source_dir == "." else "B/build"
    recipe = {"source_dir": source_dir, "build_dir": build_dir,
              "execution_cwd": {"configure": build_dir, "build": build_dir}}
    prepare_recipe_command(workspace, accepted, recipe, "configure", ("cmake", "-S", "..", "-B", "."))
    guest_home = "/workspace" if source_dir == "." else "/workspace/B"
    (workspace / build_dir / "CMakeCache.txt").write_text(f"CMAKE_HOME_DIRECTORY:INTERNAL={guest_home}\n")
    assert prepare_recipe_command(workspace, accepted, recipe, "build", ("cmake", "--build", ".")) == (
        ("cmake", "--build", "."), build_dir)


@pytest.fixture
def phpize_command(tmp_path: Path):
    """A phpize extension after its configure phase: config.m4 is accepted, the Makefile is generated."""
    workspace = tmp_path / "workspace"
    source = workspace / "ext"
    source.mkdir(parents=True)
    marker = b"PHP_NEW_EXTENSION([case], [case.c], [$ext_shared])\n"
    (source / "config.m4").write_bytes(marker)
    (source / "Makefile").write_bytes(b"all:\n\tcc -shared case.c -o modules/case.so\n")
    accepted = {"root": "ext", "family": "php", "build_system": "phpize", "descriptor_package": {"documents": [
        {"path": "ext/config.m4", "sha256": hashlib.sha256(marker).hexdigest()}]}}
    recipe = {"source_dir": "ext", "build_dir": "ext",
              "configure_commands": [["phpize"], ["./configure", "--enable-case"]],
              "build_commands": [["make", "-j1"]]}
    return workspace, accepted, recipe


def test_phpize_generated_makefile_is_bound_to_the_accepted_config_m4(phpize_command):
    """Review 2026-11-11-0005: `make -j1` of a phpize unit was refused for its generated Makefile."""
    workspace, accepted, recipe = phpize_command
    assert prepare_recipe_command(workspace, accepted, recipe, "build", ("make", "-j1")) == (
        ("make", "-j1"), "ext")
    (workspace / "ext/config.m4").write_bytes(b"PHP_NEW_EXTENSION([other], [other.c], [$ext_shared])\n")
    with pytest.raises(ValueError, match="unchanged accepted source descriptor"):
        prepare_recipe_command(workspace, accepted, recipe, "build", ("make", "-j1"))


@pytest.mark.parametrize("change", ["make_build_system", "no_configure_phase", "explicit_makefile",
                                    "accepted_makefile_changed", "configure_phase"])
def test_generated_makefile_authority_is_limited_to_the_phpize_build_phase(phpize_command, change):
    workspace, accepted, recipe = phpize_command
    raw, phase = ("make", "-j1"), "build"
    if change == "make_build_system":
        accepted["build_system"] = "make"
    elif change == "no_configure_phase":
        recipe["configure_commands"] = []
    elif change == "explicit_makefile":
        raw = ("make", "-f", "Makefile")
    elif change == "accepted_makefile_changed":
        accepted["descriptor_package"]["documents"].append(
            {"path": "ext/Makefile", "sha256": hashlib.sha256(b"all:\n").hexdigest()})
    else:
        phase = "configure"
    with pytest.raises(ValueError, match="unchanged accepted source descriptor"):
        prepare_recipe_command(workspace, accepted, recipe, phase, raw)
