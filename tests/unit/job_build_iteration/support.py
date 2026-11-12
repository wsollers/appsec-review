"""Shared fixtures for the job_build_iteration tiers: a discovered two-unit CMake source tree with
recipes and a selected graph, a controller over it, and the synthetic native ELF bytes and compiler
metadata the replay and executor tests bind products to. Nothing here runs a job, a container, a
model or Dagster; the integration files import these too."""
from __future__ import annotations

import hashlib
import struct

from appsec_review.jobs.build_discovery import descriptor_package, discover_build_units
from appsec_review.jobs.build_iterations import BuildIterations, digest, selected_graph
from appsec_review.storage.atomic import canonical_json_sha256
from tests.test_native_target_enforcement import _profile


VARIANT = {"configuration": "release", "target_arch": "x86_64", "execution_role": "target",
           "linkage": "static", "toolchain": "fixture/1", "abi": "fixture-abi/1"}
RELEASES = {"platform": "fixture/1", "build_toolchain": "fixture/1", "validation": "fixture/1"}


def fixture(tmp_path, *, independent=False, ambiguous=False):
    source = tmp_path / "source"
    documents = {
        "a/CMakeLists.txt": "project(a)\nadd_library(A STATIC a.c)\n",
        "a/a.c": "int a(void) { return 1; }\n",
        "b/CMakeLists.txt": "project(b)\nadd_executable(B b.c)\ntarget_link_libraries(B PRIVATE A)\n",
        "b/b.c": "int main(void) { return 0; }\n",
        "build/checked-in.txt": "keep build inputs\n",
        "bin/checked-in.txt": "keep bin inputs\n",
        "obj/checked-in.txt": "keep obj inputs\n",
        "target/checked-in.txt": "keep target inputs\n",
        "shared.conf": "original\n",
    }
    if independent:
        documents.update({
            "later-independent/CMakeLists.txt": "project(C)\nadd_executable(C c.c)\n",
            "later-independent/c.c": "int main(void) { return 0; }\n",
        })
    if ambiguous:
        documents.update({
            "unsupported/legacy.vcproj": '<VisualStudioProject ProjectType="Visual C++"/>\n',
            "unresolved/CMakeLists.txt": "add_library(C STATIC c.c)\n",
            "unresolved/c.c": "int c(void) { return 0; }\n",
        })
    files = []
    for relative, content in documents.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        files.append({"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                      "size_bytes": path.stat().st_size})
    units = discover_build_units(files)
    for unit in units:
        unit["descriptor_package"] = descriptor_package(source, unit, files)
        unit["build_variant"] = dict(VARIANT)
        unit["recipe"] = {
            "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
            "image_profile": "native", "source_dir": unit["root"], "build_dir": unit["root"] + "/build",
            "environment": {}, "system_packages": [],
            "dependency_files": [item["path"] for item in unit["markers"]],
            "configure_commands": [], "build_commands": [["cmake", "--build", "build"]],
            "expected_outputs": [unit["root"] + "/build"], "network_required": False, "reason": "fixture",
        }
    run = tmp_path / "runs" / "fixture"
    run.mkdir(parents=True)
    graph = selected_graph(units, source_fingerprint=digest(files), relationships=[], variants={})
    dispatches = [{**unit, "image": {"image_id": "sha256:" + "a" * 64}} for unit in units]
    return source, documents, run, graph, dispatches


def controller(source, run, graph, dispatches, releases=RELEASES):
    return BuildIterations(run, source, graph, dispatches, configuration={"fixture": 1},
                           releases=releases, execution_identity="fixture-executor/1",
                           output_policy_identity=digest("outputs"))


TARGET = "--target=x86_64-unknown-linux-gnu"
_ELF_IDENT = b"\x7fELF\x02\x01\x01" + bytes(9)
_EXIT_CODE = b"\xb8\x3c\0\0\0\x31\xff\x0f\x05"
NATIVE_OUTPUT = (
    struct.pack("<16sHHIQQQIHHHHHH", _ELF_IDENT, 2, 62, 1, 0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 120 + len(_EXIT_CODE), 120 + len(_EXIT_CODE), 4096)
    + _EXIT_CODE)
NATIVE_OBJECT = (
    struct.pack("<16sHHIQQQIHHHHHH", _ELF_IDENT, 1, 62, 1, 0, 0, 64, 0, 64, 0, 0, 64, 1, 0)
    + bytes(64))
NATIVE_AXES = {"os": "linux", "isa": "x86_64", "abi": "gnu", "sdk": None,
               "deployment": None, "device_kind": None, "hardware_generation": None}


def _compiler_metadata(image_identity, recipe=None):
    profile = {**_profile(), "image_digest": image_identity}
    if recipe is not None:
        profile["image_recipe_digest"] = canonical_json_sha256(recipe)
    return profile
