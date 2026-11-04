from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from appsec_review.jobs.build_discovery import descriptor_package, discover_build_units
from appsec_review.jobs.build_topology import (
    compile_build_topology, ready_build_units, topological_order, topology_identity,
    validate_build_topology,
)


VARIANT = {"configuration": "release", "target_arch": "x86_64", "execution_role": "target",
           "linkage": "static", "toolchain": "clang-17", "abi": "linux-gnu"}


def _units(tmp_path: Path, values: dict[str, str], *, recipes=True):
    files = []
    for relative, text in values.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode())
        files.append({"path": relative, "sha256": hashlib.sha256(text.encode()).hexdigest(),
                      "size_bytes": len(text.encode())})
    units = discover_build_units(files)
    for unit in units:
        unit["descriptor_package"] = descriptor_package(tmp_path, unit, files)
        unit["build_variant"] = dict(VARIANT)
        root = unit["root"]
        build = f"{root}/build" if root != "." else "build"
        unit["recipe"] = {
            "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
            "image_profile": unit["family"], "source_dir": root, "build_dir": build,
            "system_packages": [], "environment": {},
            "dependency_files": [item["path"] for item in unit["markers"]],
            "configure_commands": [],
            "build_commands": [["make"]] if unit["build_system"] == "make" else [["cmake", "--build", build]],
            "expected_outputs": [build], "network_required": False, "reason": "accepted descriptor recipe",
        } if recipes else None
    return units


def _pair(tmp_path: Path):
    return _units(tmp_path, {
        "z-library/CMakeLists.txt": "project(library)\nadd_library(A STATIC a.c)\n",
        "a-consumer/CMakeLists.txt": "project(consumer)\nadd_executable(B b.c)\ntarget_link_libraries(B PRIVATE A)\n",
    })


def _ids(graph):
    return {node["root"]: node["build_unit_id"] for node in graph["nodes"]}


def _record(graph):
    edge = graph["edges"][0]
    producer = next(node for node in graph["nodes"] if node["build_unit_id"] == edge["producer_build_unit_id"])
    return {**copy.deepcopy(edge["requirement"]), "producer_build_unit_id": producer["build_unit_id"],
            "topology_id": graph["topology_id"], "recipe_revision": producer["recipe_revision"],
            "path": "install/libA.a", "sha256": hashlib.sha256(b"archive").hexdigest()}


def test_reverse_discovery_order_is_real_dependency_order_and_stable_identity(tmp_path: Path):
    units = _pair(tmp_path)
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    reverse = compile_build_topology(list(reversed(units)), source_fingerprint="snapshot")
    assert graph == reverse
    ids = _ids(graph)
    assert topological_order(graph) == [ids["z-library"], ids["a-consumer"]]
    assert ready_build_units(graph, {})["ready"] == [ids["z-library"]]
    edge = graph["edges"][0]
    assert edge["producer_build_unit_id"] == ids["z-library"]
    assert edge["consumer_build_unit_id"] == ids["a-consumer"]
    assert edge["requirement"]["interface"] == "cmake-target:A"
    assert edge["evidence"][0]["line"] == 3
    assert edge["evidence"][0]["declaration"] == "target_link_libraries(B PRIVATE A)"
    assert any(gap["code"] == "incomplete_dependency_discovery" and not gap["blocking"]
               for gap in graph["coverage_gaps"])


def test_contained_fragment_belongs_to_exact_parent_and_is_not_built_twice(tmp_path: Path):
    graph = compile_build_topology(_units(tmp_path, {
        "owner/CMakeLists.txt": "project(owner)\nadd_subdirectory(lib)\n",
        "owner/lib/CMakeLists.txt": "add_library(A STATIC a.c)\n",
        "owner/unrelated/CMakeLists.txt": "project(other)\nadd_library(unrelated STATIC x.c)\n",
        "consumer/CMakeLists.txt": "project(app)\nadd_executable(B b.c)\ntarget_link_libraries(B PRIVATE A)\n",
    }), source_fingerprint="snapshot")
    ids = _ids(graph)
    fragment = next(node for node in graph["nodes"] if node["root"] == "owner/lib")
    assert fragment["disposition"] == "contained"
    assert fragment["owner_build_unit_id"] == ids["owner"]
    assert ids["owner/lib"] not in topological_order(graph)
    assert graph["edges"][0]["producer_build_unit_id"] == ids["owner"]
    assert ids["owner/unrelated"] in topological_order(graph)
    assert not any(edge["consumer_build_unit_id"] == ids["owner/lib"] for edge in graph["edges"])


def test_multiple_declared_owners_are_explicit_unresolved_coverage(tmp_path: Path):
    graph = compile_build_topology(_units(tmp_path, {
        "left/CMakeLists.txt": "project(left)\nadd_subdirectory(../shared)\n",
        "right/CMakeLists.txt": "project(right)\nadd_subdirectory(../shared)\n",
        "shared/CMakeLists.txt": "add_library(A STATIC a.c)\n",
    }), source_fingerprint="snapshot")
    shared = next(node for node in graph["nodes"] if node["root"] == "shared")
    assert shared["disposition"] == "unresolved" and shared["owner_build_unit_id"] is None
    assert any(gap["code"] == "ambiguous_owner" for gap in graph["coverage_gaps"])
    assert ready_build_units(graph, {})["ready"] == []


def test_cycles_report_exact_build_unit_cycle(tmp_path: Path):
    units = _units(tmp_path, {
        "one/CMakeLists.txt": "project(one)\nadd_library(A STATIC a.c)\ntarget_link_libraries(A PRIVATE B)\n",
        "two/CMakeLists.txt": "project(two)\nadd_library(B STATIC b.c)\ntarget_link_libraries(B PRIVATE A)\n",
    })
    with pytest.raises(ValueError, match="build dependency cycle:") as error:
        compile_build_topology(units, source_fingerprint="snapshot")
    assert all(unit["build_unit_id"] in str(error.value) for unit in units)


def test_source_self_dependency_and_ownership_cycle_are_not_hidden(tmp_path: Path):
    with pytest.raises(ValueError, match="self build dependency"):
        compile_build_topology(_units(tmp_path, {
            "CMakeLists.txt": "project(lib)\nadd_library(A STATIC a.c)\ntarget_link_libraries(A PRIVATE A)\n",
        }), source_fingerprint="snapshot")
    with pytest.raises(ValueError, match="build ownership cycle"):
        compile_build_topology(_units(tmp_path, {
            "one/CMakeLists.txt": "project(one)\nadd_subdirectory(../two)\n",
            "two/CMakeLists.txt": "project(two)\nadd_subdirectory(../one)\n",
        }), source_fingerprint="snapshot")


@pytest.mark.parametrize("mutation,match", [
    ("unknown", "unknown build edge endpoint"), ("self", "self build dependency"),
    ("duplicate", "duplicate build unit"), ("variant", "exact producer product/variant"),
    ("identity", "structural identity changed"),
])
def test_invalid_graphs_fail_closed(tmp_path: Path, mutation, match):
    graph = compile_build_topology(_pair(tmp_path), source_fingerprint="snapshot")
    if mutation == "unknown":
        graph["edges"][0]["producer_build_unit_id"] = "missing"
    elif mutation == "self":
        graph["edges"][0]["producer_build_unit_id"] = graph["edges"][0]["consumer_build_unit_id"]
    elif mutation == "duplicate":
        graph["nodes"].append(graph["nodes"][0])
    elif mutation == "variant":
        graph["edges"][0]["requirement"]["variant"]["abi"] = "incompatible"
    else:
        graph["source_fingerprint"] = "changed"
    with pytest.raises(ValueError, match=match):
        validate_build_topology(graph)


def test_readiness_verifies_actual_producer_product_not_attempt_or_image_status(tmp_path: Path):
    graph = compile_build_topology(_pair(tmp_path), source_fingerprint="snapshot")
    ids = _ids(graph)
    states = {ids["z-library"]: "SUCCEEDED"}
    record = _record(graph)
    output = tmp_path / record["path"]
    output.parent.mkdir()
    output.write_bytes(b"archive")

    def verify(value):
        return hashlib.sha256((tmp_path / value["path"]).read_bytes()).hexdigest() == value["sha256"]

    assert ready_build_units(graph, states)["ready"] == []
    assert ready_build_units(graph, states, products=[record], verify_product=verify)["ready"] == [ids["a-consumer"]]
    output.write_bytes(b"corrupted")
    assert ready_build_units(graph, states, products=[record], verify_product=verify)["ready"] == []
    for status in ("RUNNING", "FAILED", "IMAGE_PREPARED", "COMPLETED"):
        assert ids["a-consumer"] not in ready_build_units(
            graph, {ids["z-library"]: status}, products=[record], verify_product=verify)["ready"]


@pytest.mark.parametrize("field,value", [
    ("abi", "musl"), ("linkage", "shared"), ("execution_role", "host"),
    ("target_arch", "aarch64"), ("configuration", "debug"), ("toolchain", "other"),
])
def test_product_variants_are_not_substitutable(tmp_path: Path, field, value):
    graph = compile_build_topology(_pair(tmp_path), source_fingerprint="snapshot")
    record = _record(graph)
    record["variant"][field] = value
    assert ready_build_units(graph, {record["producer_build_unit_id"]: "SUCCEEDED"},
                             products=[record], verify_product=lambda _: True)["ready"] == []


def test_unknown_variants_and_consumer_abi_do_not_satisfy_readiness(tmp_path: Path):
    units = _pair(tmp_path)
    for unit in units:
        unit["build_variant"]["abi"] = None
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    record = _record(graph)
    result = ready_build_units(graph, {record["producer_build_unit_id"]: "SUCCEEDED"},
                               products=[record], verify_product=lambda _: True)
    assert result["ready"] == []
    assert "unresolved_product_variant" in result["blocked"][0]["reasons"][0]
    graph = compile_build_topology(_pair(tmp_path), source_fingerprint="snapshot")
    consumer = graph["edges"][0]["consumer_build_unit_id"]
    next(node for node in graph["nodes"] if node["build_unit_id"] == consumer)["variant"]["abi"] = "musl"
    graph["topology_id"] = topology_identity(graph)
    record = _record(graph)
    result = ready_build_units(graph, {record["producer_build_unit_id"]: "SUCCEEDED"},
                               products=[record], verify_product=lambda _: True)
    assert result["ready"] == []
    assert "incompatible_consumer_variant" in result["blocked"][0]["reasons"][0]


def test_b_recipe_revision_does_not_invalidate_structural_graph_or_a_product(tmp_path: Path):
    units = _pair(tmp_path)
    before = compile_build_topology(units, source_fingerprint="snapshot")
    consumer = next(unit for unit in units if unit["root"] == "a-consumer")
    consumer["recipe"]["environment"] = {"CFLAGS": "-O2"}
    after = compile_build_topology(units, source_fingerprint="snapshot")
    assert before["topology_id"] == after["topology_id"]
    producer = before["edges"][0]["producer_build_unit_id"]
    record = _record(before)
    assert ready_build_units(after, {producer: "SUCCEEDED"}, products=[record],
                             verify_product=lambda _: True)["ready"] == [_ids(after)["a-consumer"]]
    assert before != after
    producer_unit = next(unit for unit in units if unit["root"] == "z-library")
    producer_unit["recipe"]["environment"] = {"CFLAGS": "-O3"}
    changed_producer = compile_build_topology(units, source_fingerprint="snapshot")
    assert changed_producer["topology_id"] == before["topology_id"]
    assert ready_build_units(changed_producer, {producer: "SUCCEEDED"}, products=[record],
                             verify_product=lambda _: True)["ready"] == []


def test_cross_family_host_tool_dependency_survives_generic_contract(tmp_path: Path):
    graph = compile_build_topology(_pair(tmp_path), source_fingerprint="snapshot")
    producer = graph["edges"][0]["producer_build_unit_id"]
    node = next(node for node in graph["nodes"] if node["build_unit_id"] == producer)
    node["family"] = "java"
    node["variant"]["execution_role"] = "host"
    product = node["products"][0]
    product["kind"] = "executable"
    product["variant"]["execution_role"] = "host"
    graph["edges"][0].update(kind="requires_host_tool", requirement=copy.deepcopy(product))
    graph["topology_id"] = topology_identity(graph)
    record = _record(graph)
    assert topological_order(graph)[0] == producer
    assert ready_build_units(graph, {producer: "SUCCEEDED"}, products=[record],
                             verify_product=lambda _: True)["ready"] == [_ids(graph)["a-consumer"]]


@pytest.mark.parametrize("kind", ("order_only", "requires_generated_source"))
def test_order_only_and_generated_source_requirements_keep_distinct_semantics(tmp_path: Path, kind):
    graph = compile_build_topology(_pair(tmp_path), source_fingerprint="snapshot")
    producer = graph["edges"][0]["producer_build_unit_id"]
    edge = graph["edges"][0]
    if kind == "order_only":
        edge.update(kind=kind, requirement=None)
        graph["topology_id"] = topology_identity(graph)
        assert ready_build_units(graph, {producer: "SUCCEEDED"})["ready"] == [_ids(graph)["a-consumer"]]
    else:
        node = next(node for node in graph["nodes"] if node["build_unit_id"] == producer)
        node["products"][0]["kind"] = "generated_source"
        edge.update(kind=kind, requirement=copy.deepcopy(node["products"][0]))
        graph["topology_id"] = topology_identity(graph)
        record = _record(graph)
        assert ready_build_units(graph, {producer: "SUCCEEDED"}, products=[record],
                                 verify_product=lambda _: True)["ready"] == [_ids(graph)["a-consumer"]]


def test_unresolved_external_and_model_assertions_do_not_become_guessed_edges(tmp_path: Path):
    graph = compile_build_topology(_units(tmp_path, {
        "CMakeLists.txt": "project(app)\nadd_executable(B b.c)\ntarget_link_libraries(B PRIVATE unknown)\n",
    }), source_fingerprint="snapshot", component_relationships=[
        {"kind": "depends_on", "component_id": "B", "dependency_component_id": "A"}])
    assert graph["edges"] == []
    assert graph["external_requirements"][0]["interface"] == "unknown"
    assert {gap["code"] for gap in graph["coverage_gaps"]} >= {
        "external_requirement", "unresolved_component_dependency"}
    assert ready_build_units(graph, {})["ready"] == []


@pytest.mark.parametrize("text", [
    "project(parent)\nif(FALSE)\nadd_subdirectory(child)\nendif()\n",
    "project(parent)\n#[[\nadd_subdirectory(child)\n]]\n",
    'project(parent)\nmessage("text\nadd_subdirectory(child)\n")\n',
    "project(parent)\nadd_subdirectory(${CHILD})\n",
])
def test_unsupported_cmake_syntax_never_invents_ownership(tmp_path: Path, text):
    graph = compile_build_topology(_units(tmp_path, {
        "CMakeLists.txt": text, "child/CMakeLists.txt": "add_library(A STATIC a.c)\n",
    }), source_fingerprint="snapshot")
    child = next(node for node in graph["nodes"] if node["root"] == "child")
    assert child["disposition"] == "unresolved"
    assert graph["edges"] == []


def test_standalone_make_remains_ready_with_partial_topology_but_fragment_does_not(tmp_path: Path):
    graph = compile_build_topology(_units(tmp_path, {
        "standalone/Makefile": "all: main.o\nmain.o: main.c\n\t$(CC) -c main.c -o main.o\n",
        "fragment/Makefile": "include ../make.conf\n",
    }), source_fingerprint="snapshot")
    ids = _ids(graph)
    assert ready_build_units(graph, {})["ready"] == [ids["standalone"]]
    assert next(node for node in graph["nodes"] if node["root"] == "fragment")["disposition"] == "unresolved"


def test_supported_recursive_make_owns_child_once(tmp_path: Path):
    graph = compile_build_topology(_units(tmp_path, {
        "owner/Makefile": "all:\n\t$(MAKE) -C child\n",
        "owner/child/Makefile": "all: main.o\nmain.o: main.c\n\t$(CC) -c main.c -o main.o\n",
    }), source_fingerprint="snapshot")
    ids = _ids(graph)
    assert ready_build_units(graph, {})["ready"] == [ids["owner"]]
    child = next(node for node in graph["nodes"] if node["root"] == "owner/child")
    assert child["disposition"] == "contained" and child["owner_build_unit_id"] == ids["owner"]


def test_known_project_without_recipe_is_not_ready(tmp_path: Path):
    graph = compile_build_topology(_units(tmp_path, {
        "CMakeLists.txt": "project(app)\n",
    }, recipes=False), source_fingerprint="snapshot")
    result = ready_build_units(graph, {})
    assert result["ready"] == []
    assert result["blocked"][0]["reasons"] == ["missing_recipe_revision"]


def test_durable_logical_paths_are_supported_but_arbitrary_host_paths_are_not(tmp_path: Path):
    graph = compile_build_topology(_pair(tmp_path), source_fingerprint="snapshot")
    record = _record(graph)
    producer = record["producer_build_unit_id"]
    for path in ("/workspace/build/libA.a", "/install/lib/libA.a"):
        record["path"] = path
        assert ready_build_units(graph, {producer: "SUCCEEDED"}, products=[record],
                                 verify_product=lambda _: True)["ready"] == [_ids(graph)["a-consumer"]]
    for path in ("/etc/libA.a", "/install/../etc/libA.a", "C:\\host\\libA.a"):
        record["path"] = path
        assert ready_build_units(graph, {producer: "SUCCEEDED"}, products=[record],
                                 verify_product=lambda _: True)["ready"] == []


def test_topology_document_matches_versioned_schema(tmp_path: Path):
    graph = compile_build_topology(_pair(tmp_path), source_fingerprint="snapshot")
    schema = json.loads((Path(__file__).parents[1] / "docs/schemas/build-topology.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(graph, schema)
