from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import struct

import jsonschema
import pytest
from referencing import Registry, Resource

from appsec_review.jobs.build_discovery import descriptor_package, discover_build_units
from appsec_review.jobs.build_topology import (
    compile_build_topology as source_graph, ready_build_units, topological_order, topology_identity,
    validate_build_topology, refine_build_topology, refinement_unit, proven_product_axes,
    verify_product_contract, topology_evidence_bundle,
)
from appsec_review.storage import canonical_json


VARIANT = {"configuration": "release", "target_arch": "x86_64", "execution_role": "target",
           "linkage": "static", "toolchain": "clang-17", "abi": "linux-gnu"}
PROFILE = {
    "schema": "appsec-review/static-compiler-profile/1", "executable": "clang",
    "driver_semantics": "clang-target/1", "compiler_sha256": "b" * 64,
    "image_digest": "sha256:" + "a" * 64, "wrapper_closure": [],
    "target_axes": {"os": "linux", "isa": "x86_64", "abi": "gnu"},
    "provenance": {"origin": "synthetic-inline-core-unit", "revision": "1"},
}
RELEASES = {"platform": "synthetic-platform/1", "build_toolchain": "synthetic-toolchain/1",
            "validation": "synthetic-validation/1"}


def compile_build_topology(units, **kwargs):
    return source_graph(units, profiles=PROFILE, **kwargs)


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
        package = unit["descriptor_package"]
        for item in files:
            if (Path(item["path"]).parent.as_posix() == unit["root"] and item["path"].endswith(".c")
                    and item["path"] not in {doc["path"] for doc in package["documents"]}):
                package["documents"].append({**item, "content": values[item["path"]]})
        package["bounds"]["actual_files"] = len(package["documents"])
        package["bounds"]["actual_bytes"] = sum(len(doc["content"].encode()) for doc in package["documents"])
        unit["build_variant"] = dict(VARIANT)
        root = unit["root"]
        build = f"{root}/build" if root != "." else "build"
        unit["recipe"] = {
            "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
            "image_profile": unit["family"], "source_dir": root, "build_dir": build,
            "system_packages": [], "environment": {},
            "dependency_files": [item["path"] for item in package["documents"]],
            "configure_commands": [],
            "build_commands": [["clang", "--target=x86_64-unknown-linux-gnu", "-c",
                                next((Path(item["path"]).name for item in package["documents"]
                                      if item["path"].endswith(".c")), "uncaptured.c"),
                                "-o", "build/control.o"]],
            "expected_outputs": [build], "network_required": False, "reason": "accepted descriptor recipe",
        } if recipes else None
    return units


def _pair(tmp_path: Path, *, dependency="target_link_libraries(B PRIVATE A)", compiler_flags=None):
    flags = f'set(CMAKE_C_FLAGS "{compiler_flags}")\n' if compiler_flags else ""
    return _units(tmp_path, {
        "z-library/CMakeLists.txt": flags + "project(library)\nadd_library(A STATIC a.c)\n",
        "z-library/a.c": "int a(void) { return 1; }\n",
        "a-consumer/CMakeLists.txt": flags + f"project(consumer)\nadd_executable(B b.c)\n{dependency}\n",
        "a-consumer/b.c": "int main(void) { return 0; }\n",
    })


def _ids(graph):
    return {node["root"]: node["build_unit_id"] for node in graph["nodes"]}


def _refinement(graph, units):
    return refine_build_topology(graph, units, profiles=PROFILE, releases=RELEASES)


def _archive():
    head = bytearray(64)
    head[:7] = b"\x7fELF" + bytes([2, 1, 1])
    struct.pack_into("<HH", head, 16, 1, 62)
    member = ("control.o/".ljust(16) + "0".ljust(12) + "0".ljust(6) + "0".ljust(6)
              + "100644".ljust(8) + "64".ljust(10) + "`\n").encode()
    return b"!<arch>\n" + member + head


def _record(graph, refinement):
    edge = graph["edges"][0]
    producer = next(node for node in graph["nodes"] if node["build_unit_id"] == edge["producer_build_unit_id"])
    return {**copy.deepcopy(edge["requirement"]), "producer_build_unit_id": producer["build_unit_id"],
            "topology_id": graph["topology_id"],
            "recipe_revision": refinement_unit(graph, refinement, producer["build_unit_id"])["recipe_digest"],
            "role": "static_archive",
            "axes": proven_product_axes(refinement_unit(graph, refinement, producer["build_unit_id"])),
            "path": "install/libA.a", "sha256": hashlib.sha256(_archive()).hexdigest()}


def test_reverse_discovery_order_is_real_dependency_order_and_stable_identity(tmp_path: Path):
    units = _pair(tmp_path)
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    reverse = compile_build_topology(list(reversed(units)), source_fingerprint="snapshot")
    assert graph == reverse
    ids = _ids(graph)
    assert topological_order(graph) == [ids["z-library"], ids["a-consumer"]]
    refinement = _refinement(graph, units)
    assert all(unit["blockers"] == [] for unit in refinement["units"])
    assert ready_build_units(graph, {}, refinement=refinement)["ready"] == [ids["z-library"]]
    assert ready_build_units(graph, {})["ready"] == []
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
    ("identity", "changed graph/2 identity"),
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
    if mutation != "identity":
        graph["topology_id"] = topology_identity(graph)
    with pytest.raises(ValueError, match=match):
        validate_build_topology(graph)


def test_readiness_verifies_actual_producer_product_not_attempt_or_image_status(tmp_path: Path):
    units = _pair(tmp_path)
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    refinement = _refinement(graph, units)
    ids = _ids(graph)
    states = {ids["z-library"]: "SUCCEEDED"}
    record = _record(graph, refinement)
    output = tmp_path / record["path"]
    output.parent.mkdir()
    output.write_bytes(_archive())

    def verify(value):
        from appsec_review.jobs.build_workspace import ProductSpec, verify_native_product
        path = tmp_path / value["path"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != value["sha256"]:
            return False
        verify_native_product(path, ProductSpec(
            value["path"], value["kind"], value["product_id"], value["interface"], value["variant"],
            value["role"], value["axes"]))
        return True

    assert ready_build_units(graph, states, refinement=refinement)["ready"] == []
    assert ready_build_units(graph, states, products=[record], verify_product=verify,
                             refinement=refinement)["ready"] == [ids["a-consumer"]]
    output.write_bytes(b"corrupted")
    assert ready_build_units(graph, states, products=[record], verify_product=verify,
                             refinement=refinement)["ready"] == []
    for status in ("RUNNING", "FAILED", "IMAGE_PREPARED", "COMPLETED"):
        assert ids["a-consumer"] not in ready_build_units(
            graph, {ids["z-library"]: status}, products=[record], verify_product=verify,
            refinement=refinement)["ready"]


@pytest.mark.parametrize("field,value", [
    ("abi", "musl"), ("linkage", "shared"), ("execution_role", "host"),
    ("target_arch", "aarch64"), ("configuration", "debug"), ("toolchain", "other"),
])
def test_product_variants_are_not_substitutable(tmp_path: Path, field, value):
    units = _pair(tmp_path)
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    refinement = _refinement(graph, units)
    record = _record(graph, refinement)
    record["variant"][field] = value
    assert ready_build_units(graph, {record["producer_build_unit_id"]: "SUCCEEDED"},
                             products=[record], verify_product=lambda _: True,
                             refinement=refinement)["ready"] == []


def test_unknown_variants_and_consumer_abi_do_not_satisfy_readiness(tmp_path: Path):
    units = _pair(tmp_path)
    for unit in units:
        unit["build_variant"]["abi"] = None
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    refinement = _refinement(graph, units)
    record = _record(graph, refinement)
    result = ready_build_units(graph, {record["producer_build_unit_id"]: "SUCCEEDED"},
                               products=[record], verify_product=lambda _: True, refinement=refinement)
    assert result["ready"] == []
    assert any("unresolved_product_variant" in reason for row in result["blocked"] for reason in row["reasons"])
    units = _pair(tmp_path)
    next(unit for unit in units if unit["root"] == "a-consumer")["build_variant"]["abi"] = "musl"
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    refinement = _refinement(graph, units)
    record = _record(graph, refinement)
    result = ready_build_units(graph, {record["producer_build_unit_id"]: "SUCCEEDED"},
                               products=[record], verify_product=lambda _: True, refinement=refinement)
    assert result["ready"] == []
    assert any("incompatible_consumer_variant" in reason for row in result["blocked"] for reason in row["reasons"])


def test_b_recipe_revision_does_not_invalidate_structural_graph_or_a_product(tmp_path: Path):
    units = _pair(tmp_path)
    before = compile_build_topology(units, source_fingerprint="snapshot")
    initial = _refinement(before, units)
    retained_initial = copy.deepcopy(initial)
    consumer = next(unit for unit in units if unit["root"] == "a-consumer")
    consumer["recipe"]["build_commands"][0].append("-O2")
    after = compile_build_topology(units, source_fingerprint="snapshot")
    assert canonical_json(before) == canonical_json(after)
    replacement = _refinement(after, units)
    assert replacement["refinement_id"] != initial["refinement_id"]
    assert all(unit["blockers"] == [] for unit in replacement["units"])
    with pytest.raises(ValueError, match="matching immutable refinement"):
        refinement_unit(after, initial, consumer["build_unit_id"], consumer["recipe"])
    producer = before["edges"][0]["producer_build_unit_id"]
    record = _record(before, initial)
    assert ready_build_units(after, {producer: "SUCCEEDED"}, products=[record],
                             verify_product=lambda _: True, refinement=replacement)["ready"] == [_ids(after)["a-consumer"]]
    assert initial == retained_initial
    producer_unit = next(unit for unit in units if unit["root"] == "z-library")
    producer_unit["recipe"]["build_commands"][0].append("-O3")
    changed_producer = compile_build_topology(units, source_fingerprint="snapshot")
    assert canonical_json(changed_producer) == canonical_json(before)
    changed = _refinement(changed_producer, units)
    assert ready_build_units(changed_producer, {producer: "SUCCEEDED"}, products=[record],
                             verify_product=lambda _: True, refinement=changed)["ready"] == []
    assert ready_build_units(changed_producer, {producer: "SUCCEEDED"},
                             products=[_record(changed_producer, changed)], verify_product=lambda _: True,
                             refinement=changed)["ready"] == [_ids(after)["a-consumer"]]


def test_b_execution_cwd_changes_only_recipe_revision_not_structure_or_a_readiness(tmp_path: Path):
    units = _pair(tmp_path)
    original = copy.deepcopy(units)
    before = compile_build_topology(units, source_fingerprint="snapshot")
    initial = _refinement(before, units)
    consumer = next(unit for unit in units if unit["root"] == "a-consumer")
    consumer["recipe"]["execution_cwd"] = {"configure": "a-consumer", "build": "a-consumer/build"}
    consumer["recipe"]["build_commands"][0][3] = "../b.c"
    consumer["recipe"]["build_commands"][0][-1] = "control.o"
    after = compile_build_topology(units, source_fingerprint="snapshot")
    assert canonical_json(before) == canonical_json(after)
    replacement = _refinement(after, units)
    assert replacement["refinement_id"] != initial["refinement_id"]
    assert all(unit["blockers"] == [] for unit in replacement["units"])
    with pytest.raises(ValueError, match="matching immutable refinement"):
        refinement_unit(after, initial, consumer["build_unit_id"], consumer["recipe"])
    producer_id = before["edges"][0]["producer_build_unit_id"]
    consumer_id = before["edges"][0]["consumer_build_unit_id"]
    before_nodes = {node["build_unit_id"]: node for node in before["nodes"]}
    after_nodes = {node["build_unit_id"]: node for node in after["nodes"]}
    assert before_nodes[producer_id] == after_nodes[producer_id]
    assert before_nodes[consumer_id] == after_nodes[consumer_id]
    assert before_nodes[consumer_id]["recipe_revision"] is None
    assert ready_build_units(after, {producer_id: "SUCCEEDED"}, products=[_record(before, initial)],
                             verify_product=lambda _: True, refinement=replacement)["ready"] == [consumer_id]
    assert original != units and all("execution_cwd" not in unit["recipe"] for unit in original)


def test_cross_family_host_projection_preserves_order_but_requires_source_bound_refinement(tmp_path: Path):
    units = _pair(tmp_path)
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    accepted = copy.deepcopy(graph)
    refinement = _refinement(graph, units)
    producer = graph["edges"][0]["producer_build_unit_id"]
    node = next(node for node in graph["nodes"] if node["build_unit_id"] == producer)
    node["family"] = "java"
    node["variant"]["execution_role"] = "host"
    product = node["products"][0]
    product["kind"] = "executable"
    product["variant"]["execution_role"] = "host"
    graph["edges"][0].update(kind="requires_host_tool", requirement=copy.deepcopy(product))
    graph["topology_id"] = topology_identity(graph)
    # A model's structurally plausible cross-family host-tool projection is not a
    # new source declaration or an accepted refinement.
    assert topological_order(graph)[0] == producer
    validate_build_topology(graph)
    with pytest.raises(ValueError, match="complete accepted source bundle"):
        _refinement(graph, units)
    with pytest.raises(ValueError, match="foreign accepted identities"):
        ready_build_units(graph, {producer: "SUCCEEDED"}, refinement=refinement)
    assert accepted != graph


@pytest.mark.parametrize("kind", ("order_only", "requires_generated_source"))
def test_order_only_and_generated_source_requirements_keep_distinct_semantics(tmp_path: Path, kind):
    units = _pair(tmp_path, dependency="add_dependencies(B A)" if kind == "order_only"
                  else "target_link_libraries(B PRIVATE A)")
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    refinement = _refinement(graph, units)
    producer = graph["edges"][0]["producer_build_unit_id"]
    edge = graph["edges"][0]
    if kind == "order_only":
        assert edge["kind"] == kind and edge["requirement"] is None
        assert ready_build_units(graph, {producer: "SUCCEEDED"},
                                 refinement=refinement)["ready"] == [_ids(graph)["a-consumer"]]
    else:
        node = next(node for node in graph["nodes"] if node["build_unit_id"] == producer)
        node["products"][0]["kind"] = "generated_source"
        edge.update(kind=kind, requirement=copy.deepcopy(node["products"][0]))
        graph["topology_id"] = topology_identity(graph)
        validate_build_topology(graph)
        with pytest.raises(ValueError, match="complete accepted source bundle"):
            _refinement(graph, units)
        with pytest.raises(ValueError, match="foreign accepted identities"):
            ready_build_units(graph, {producer: "SUCCEEDED"}, refinement=refinement)


def test_unresolved_external_and_model_assertions_do_not_become_guessed_edges(tmp_path: Path):
    units = _units(tmp_path, {
        "CMakeLists.txt": "project(app)\nadd_executable(B b.c)\ntarget_link_libraries(B PRIVATE unknown)\n",
        "b.c": "int main(void) { return 0; }\n",
    })
    graph = compile_build_topology(units, source_fingerprint="snapshot", component_relationships=[
        {"kind": "depends_on", "component_id": "B", "dependency_component_id": "A"}])
    assert graph == compile_build_topology(units, source_fingerprint="snapshot")
    assert graph["edges"] == []
    assert graph["external_requirements"][0]["interface"] == "unknown"
    assert "external_requirement" in {gap["code"] for gap in graph["coverage_gaps"]}
    assert ready_build_units(graph, {}, refinement=_refinement(graph, units))["ready"] == []


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
    units = _units(tmp_path, {
        "standalone/Makefile": "all: main.o\nmain.o: main.c\n\t$(CC) -c main.c -o main.o\n",
        "standalone/main.c": "int main(void) { return 0; }\n",
        "fragment/Makefile": "include ../make.conf\n",
    })
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    ids = _ids(graph)
    assert ready_build_units(graph, {}, refinement=_refinement(graph, units))["ready"] == [ids["standalone"]]
    assert next(node for node in graph["nodes"] if node["root"] == "fragment")["disposition"] == "unresolved"


def test_recursive_make_invocation_is_not_unproven_whole_unit_precedence(tmp_path: Path):
    units = _units(tmp_path, {
        "owner/Makefile": "all:\n\t$(MAKE) -C child\n",
        "owner/child/Makefile": "all: main.o\nmain.o: main.c\n\t$(CC) -c main.c -o main.o\n",
        "owner/child/main.c": "int main(void) { return 0; }\n",
    })
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    ids = _ids(graph)
    invokes = [relation for relation in graph["relations"] if relation["kind"] == "invokes_unit"]
    assert len(invokes) == 1
    assert invokes[0]["consumer_build_unit_id"] == ids["owner"]
    assert invokes[0]["producer_build_unit_id"] == ids["owner/child"]
    assert invokes[0]["resolution"] == "candidate" and invokes[0]["required"] is False
    assert graph["edges"] == []
    assert ids["owner"] not in ready_build_units(
        graph, {}, refinement=_refinement(graph, units))["ready"]


def test_known_project_without_recipe_is_not_ready(tmp_path: Path):
    units = _units(tmp_path, {
        "CMakeLists.txt": "project(app)\n",
    }, recipes=False)
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    refinement = _refinement(graph, units)
    result = ready_build_units(graph, {}, refinement=refinement)
    assert result["ready"] == []
    assert result["blocked"][0]["reasons"] == ["recipe_missing", "unenforced_native_target"]
    assert all(proof["status"] == "unknown" and proof["recipe_digest"] is None
               for proof in refinement["units"][0]["enforcement"])


def test_durable_logical_paths_are_supported_but_arbitrary_host_paths_are_not(tmp_path: Path):
    units = _pair(tmp_path)
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    refinement = _refinement(graph, units)
    record = _record(graph, refinement)
    producer = record["producer_build_unit_id"]
    for path in ("/workspace/build/libA.a", "/install/lib/libA.a"):
        record["path"] = path
        assert ready_build_units(graph, {producer: "SUCCEEDED"}, products=[record],
                                 verify_product=lambda _: True, refinement=refinement)["ready"] == [_ids(graph)["a-consumer"]]
    for path in ("/etc/libA.a", "/install/../etc/libA.a", "C:\\host\\libA.a"):
        record["path"] = path
        assert ready_build_units(graph, {producer: "SUCCEEDED"}, products=[record],
                                 verify_product=lambda _: True, refinement=refinement)["ready"] == []


def test_topology_document_matches_versioned_schema(tmp_path: Path):
    graph = compile_build_topology(_pair(tmp_path), source_fingerprint="snapshot")
    directory = Path(__file__).parents[1] / "docs" / "schemas"
    schemas = {}
    resources = []
    for name in ("build-topology", "build-topology-v2"):
        path = directory / f"{name}.schema.json"
        schema = json.loads(path.read_text())
        schema["$id"] = path.as_uri()
        jsonschema.Draft202012Validator.check_schema(schema)
        schemas[name] = schema
        resources.append((path.as_uri(), Resource.from_contents(schema)))
    registry = Registry().with_resources(resources)
    jsonschema.Draft202012Validator(schemas["build-topology-v2"], registry=registry).validate(graph)
    assert not jsonschema.Draft202012Validator(schemas["build-topology"], registry=registry).is_valid(graph)


@pytest.mark.parametrize("selection", ["empty", "all", "subset", "reordered"])
def test_whole_bundle_and_source_facts_ignore_model_selection_hints(tmp_path: Path, selection):
    units = _pair(tmp_path)
    original = copy.deepcopy(units)
    all_hints = [{"build_unit_id": unit["build_unit_id"], "invented_target": "windows-x86"} for unit in units]
    hints = {"empty": [], "all": all_hints, "subset": all_hints[:1],
             "reordered": list(reversed(all_hints))}[selection]
    bundle = topology_evidence_bundle(units, source_fingerprint="snapshot", profiles=PROFILE)
    before = compile_build_topology(units, source_fingerprint="snapshot")
    after = compile_build_topology(list(reversed(units)), source_fingerprint="snapshot", hints=hints,
                                   component_relationships=[{"kind": "depends_on", "source": "invented"}])
    assert canonical_json(before) == canonical_json(after)
    assert topology_evidence_bundle(units, source_fingerprint="snapshot", profiles=PROFILE) == bundle
    assert units == original
    assert {node["build_unit_id"] for node in after["nodes"]} == {unit["build_unit_id"] for unit in units}
    assert before["facts"] and before["bindings"] and before["declarations"]


@pytest.mark.parametrize("field,value", [
    ("role", "runtime_shared"), ("axes", {"os": "windows"}), ("axes", {"isa": "x86"}),
    ("sha256", "invalid"), ("recipe_revision", "c" * 64), ("topology_id", "d" * 64),
])
def test_typed_product_role_axes_and_custody_identity_cannot_be_substituted(tmp_path, field, value):
    units = _pair(tmp_path)
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    refinement = _refinement(graph, units)
    record = _record(graph, refinement)
    states = {record["producer_build_unit_id"]: "SUCCEEDED"}
    assert ready_build_units(graph, states, products=[record], verify_product=lambda _: True,
                             refinement=refinement)["ready"] == [_ids(graph)["a-consumer"]]
    if field == "axes":
        record[field].update(value)
    else:
        record[field] = value
    assert ready_build_units(graph, states, products=[record], verify_product=lambda _: True,
                             refinement=refinement)["ready"] == []


def test_graph1_is_inspectable_but_has_no_graph2_readiness_or_recipe_reuse(tmp_path):
    units = _pair(tmp_path)
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    legacy = {key: copy.deepcopy(graph[key]) for key in (
        "schema", "source_fingerprint", "nodes", "edges", "external_requirements", "coverage_gaps")}
    legacy["schema"] = "appsec-review/build-topology/1"
    for node in legacy["nodes"]:
        node["recipe_revision"] = "e" * 64
    legacy["topology_id"] = topology_identity(legacy)
    serialized = canonical_json(legacy)
    decoded = json.loads(serialized)
    validate_build_topology(decoded)
    schema = json.loads((Path(__file__).parents[1] / "docs/schemas/build-topology.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(decoded)
    assert topological_order(decoded) == topological_order(graph)
    assert canonical_json(decoded) == serialized
    result = ready_build_units(decoded, {}, products=[_record(graph, _refinement(graph, units))],
                               verify_product=lambda _: True)
    assert result["ready"] == []
    assert all(row["reasons"] == ["legacy_graph_requires_accepted_replanning"] for row in result["blocked"])
    with pytest.raises(ValueError, match="graph/1 is inspectable"):
        _refinement(decoded, units)


def test_observed_32bit_declarations_are_preserved_but_never_native_execution_authority(tmp_path):
    units = _pair(tmp_path, compiler_flags="-m32")
    for unit in units:
        unit["build_variant"]["target_arch"] = "x86"
        unit["recipe"]["build_commands"][0].append("-m32")
    original = copy.deepcopy(units)
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    refinement = _refinement(graph, units)
    assert all(node["variant"]["target_arch"] == "x86" for node in graph["nodes"])
    assert any(fact["predicate"] == "cmake:set" and "-m32" in fact["value"] for fact in graph["facts"])
    assert all(proof["status"] == "incompatible" for unit in refinement["units"] for proof in unit["enforcement"])
    assert ready_build_units(graph, {}, refinement=refinement)["ready"] == []
    assert units == original


@pytest.mark.parametrize("role", ["static_archive", "executable", "native_object", "generated_source", "headers"])
def test_typed_roles_require_exact_axes_without_borrowing_native_compatibility(tmp_path, role):
    units = _pair(tmp_path)
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    refinement = _refinement(graph, units)
    bound = refinement["units"][0]
    product = {"role": role, "axes": proven_product_axes(bound)}
    verify_product_contract(bound, [product])
    if role in {"static_archive", "executable", "native_object"}:
        product["axes"]["isa"] = "x86"
        with pytest.raises(ValueError, match="axis is unresolved or incompatible"):
            verify_product_contract(bound, [product])
    with pytest.raises(ValueError, match="legacy untyped products"):
        verify_product_contract(bound, [{"role": role}])


def test_graph2_readiness_rejects_unknown_state_units(tmp_path):
    units = _pair(tmp_path)
    graph = compile_build_topology(units, source_fingerprint="snapshot")
    with pytest.raises(ValueError, match="state names an unknown build unit"):
        ready_build_units(graph, {"unknown": "SUCCEEDED"}, refinement=_refinement(graph, units))
