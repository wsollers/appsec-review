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
