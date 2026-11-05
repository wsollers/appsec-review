"""A2: immutability, ordering, typed custody and honest unknowns. AUTHORED - NOT RUN.

R1/R2/R3/R5/R6/R9/R10/R11 and C1: expected results below were fixed
independently of compiler output. No passing claim covers the full cached replay.
"""

from __future__ import annotations

import copy
import hashlib
import json
import struct

import pytest

from appsec_review.jobs.build_discovery import descriptor_package, discover_build_units
from appsec_review.jobs.build_topology import (
    compile_build_topology, proven_product_axes, ready_build_units, refine_build_topology,
    refinement_unit, topological_order, topology_identity, validate_build_topology,
)
from appsec_review.jobs.build_workspace import native_product_axes
from appsec_review.storage import canonical_json
from tests.integration.test_build_topology_catalog_planner_publication import offline_reporting
from tests.integration.test_build_topology_consumers_recovery import compiler_profile


def pair(tmp_path, *, relation="target_link_libraries(app PRIVATE core)"):
    texts = {
        "z-shared/CMakeLists.txt": "project(shared)\nadd_library(core STATIC core.c)\n",
        "z-shared/core.c": "int core(void) { return 7; }\n",
        "a-app/CMakeLists.txt": "project(app)\nadd_executable(app main.c)\n" + relation + "\n",
        "a-app/main.c": "int main(void) { return 0; }\n",
    }
    files = []
    for relative, content in texts.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode())
        files.append({"path": relative, "sha256": hashlib.sha256(content.encode()).hexdigest(),
                      "size_bytes": len(content.encode())})
    units = discover_build_units(files)
    for unit in units:
        unit["descriptor_package"] = descriptor_package(tmp_path, unit, files)
        docs = unit["descriptor_package"]["documents"]
        for item in files:
            if item["path"].endswith(".c") and item["path"].split("/")[0] == unit["root"]:
                if not any(d["path"] == item["path"] for d in docs):
                    docs.append({**item, "content": texts[item["path"]]})
        unit["build_variant"] = {
            "configuration": "Release", "target_arch": "x86_64", "execution_role": "target",
            "linkage": "static", "toolchain": "independent-clang-profile/1", "abi": "gnu",
        }
        source = next(d["path"].rsplit("/", 1)[1] for d in docs if d["path"].endswith(".c"))
        unit["recipe"] = {
            "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
            "image_profile": "native", "source_dir": unit["root"], "build_dir": unit["root"] + "/build",
            "system_packages": [], "environment": {}, "dependency_files": [d["path"] for d in docs],
            "configure_commands": [],
            "build_commands": [["clang", "--target=x86_64-unknown-linux-gnu",
                                "-c", source, "-o", "build/control.o"]],
            "expected_outputs": [unit["root"] + "/build"], "network_required": False,
            "reason": "explicit synthetic command, never run in these acceptance cases",
        }
    return units


def compiled_pair(tmp_path, *, relation="target_link_libraries(app PRIVATE core)"):
    units = pair(tmp_path, relation=relation)
    graph = compile_build_topology(units, source_fingerprint="independent-pair", profiles=compiler_profile())
    bound = refine_build_topology(graph, units, profiles=compiler_profile())
    assert all(unit["blockers"] == [] for unit in bound["units"])
    return units, graph, bound


def elf(isa):
    head = bytearray(64)
    head[:7] = b"\x7fELF" + bytes([2 if isa == "x86_64" else 1, 1, 1])
    struct.pack_into("<HH", head, 16, 1, 62 if isa == "x86_64" else 3)
    return bytes(head)


def archive(*isas):
    value = b"!<arch>\n"
    for index, isa in enumerate(isas):
        body = elf(isa)
        header = (f"item{index}.o/".ljust(16) + "0".ljust(12) + "0".ljust(6) + "0".ljust(6)
                  + "100644".ljust(8) + str(len(body)).ljust(10) + "`\n").encode()
        value += header + body
    return value


def test_order_recipe_and_model_hint_changes_do_not_change_source_graph_or_original_inputs(tmp_path):
    units, graph, bound = compiled_pair(tmp_path)
    original = copy.deepcopy(units)
    modified = copy.deepcopy(units)
    for unit in modified:
        unit["recipe"]["build_commands"][0].append("-g")
        unit["descriptor_package"]["documents"].reverse()
    recompiled = compile_build_topology(
        list(reversed(modified)), source_fingerprint="independent-pair", profiles=compiler_profile(),
        hints=[{"producer": "imaginary", "consumer": "a-app", "erase": True}],
        component_relationships=[{"kind": "depends_on", "component_id": "unrelated"}])
    assert canonical_json(graph) == canonical_json(recompiled)
    second = refine_build_topology(graph, modified, profiles=compiler_profile())
    assert second["refinement_id"] != bound["refinement_id"]
    assert all(node["recipe_revision"] is None for node in graph["nodes"])
    assert units == original
    roots = {node["build_unit_id"]: node["root"] for node in graph["nodes"]}
    assert [roots[uid] for uid in topological_order(graph)] == ["z-shared", "a-app"]
    assert ready_build_units(graph, {})["ready"] == []


def test_product_readiness_checks_real_retained_bytes_role_axes_and_recipe_before_consumer(tmp_path):
    _units, graph, bound = compiled_pair(tmp_path)
    edge, = graph["edges"]
    producer, consumer = edge["producer_build_unit_id"], edge["consumer_build_unit_id"]
    product = tmp_path / "retained.a"
    product.write_bytes(archive("x86_64"))
    record = {
        **copy.deepcopy(edge["requirement"]), "producer_build_unit_id": producer,
        "topology_id": graph["topology_id"],
        "recipe_revision": refinement_unit(graph, bound, producer)["recipe_digest"],
        "role": "static_archive", "axes": proven_product_axes(refinement_unit(graph, bound, producer)),
        "path": "install/retained.a", "sha256": hashlib.sha256(product.read_bytes()).hexdigest(),
    }
    verified = []

    def verify(item):
        verified.append(item["path"])
        return (hashlib.sha256(product.read_bytes()).hexdigest() == item["sha256"]
                and native_product_axes(product)["isa"] == item["axes"]["isa"])

    states = {producer: "SUCCEEDED"}
    assert consumer not in ready_build_units(graph, states, refinement=bound)["ready"]
    assert ready_build_units(graph, states, products=[record], verify_product=verify,
                             refinement=bound)["ready"] == [consumer]
    assert verified == ["install/retained.a"]
    for bad in [
        {**record, "role": "runtime_shared"},
        {**record, "axes": {**record["axes"], "isa": "x86"}},
        {**record, "recipe_revision": "e" * 64},
        {**record, "topology_id": "f" * 64},
    ]:
        assert ready_build_units(graph, states, products=[bad], verify_product=verify,
                                 refinement=bound)["ready"] == []
    product.write_bytes(archive("x86"))
    assert ready_build_units(graph, states, products=[record], verify_product=verify,
                             refinement=bound)["ready"] == []


def test_order_only_is_a_real_ordering_edge_without_an_invented_product_obligation(tmp_path):
    _units, graph, bound = compiled_pair(tmp_path, relation="add_dependencies(app core)")
    edge, = graph["edges"]
    assert edge["kind"] == "order_only" and edge["requirement"] is None
    producer, consumer = edge["producer_build_unit_id"], edge["consumer_build_unit_id"]
    assert consumer not in ready_build_units(graph, {}, refinement=bound)["ready"]
    assert ready_build_units(graph, {producer: "SUCCEEDED"}, products=(),
                             refinement=bound)["ready"] == [consumer]


def test_ambiguous_producer_candidates_remain_required_gaps_not_false_execution_edges(tmp_path):
    units = pair(tmp_path)
    duplicate = copy.deepcopy(next(unit for unit in units if unit["root"] == "z-shared"))
    duplicate["build_unit_id"] = "independent-other-producer"
    duplicate["root"] = "other-shared"
    for doc in duplicate["descriptor_package"]["documents"]:
        doc["path"] = doc["path"].replace("z-shared/", "other-shared/")
    duplicate["markers"] = [
        {**marker, "path": marker["path"].replace("z-shared/", "other-shared/")}
        for marker in duplicate["markers"]]
    duplicate["recipe"] = None
    graph = compile_build_topology([*units, duplicate], source_fingerprint="synthetic-candidate-collision")
    consumer = next(node["build_unit_id"] for node in graph["nodes"] if node["root"] == "a-app")
    assert not any(edge["consumer_build_unit_id"] == consumer for edge in graph["edges"])
    assert any(gap["code"] == "ambiguous_producer" and gap["blocking"]
               and consumer in gap["build_unit_ids"] for gap in graph["coverage_gaps"])
    bound = refine_build_topology(graph, [*units, duplicate])
    consumer_bound = refinement_unit(graph, bound, consumer)
    assert "active_coverage_gap:ambiguous_producer" in consumer_bound["blockers"]
    assert consumer not in ready_build_units(graph, {}, refinement=bound)["ready"]


def test_untrusted_or_mixed_archive_members_cannot_be_promoted_by_a_filename(tmp_path):
    from appsec_review.jobs.build_workspace import WorkspaceError

    path = tmp_path / "claims-linux-x64.lib"
    path.write_bytes(archive("x86_64", "x86"))
    with pytest.raises(WorkspaceError, match="mixed"):
        native_product_axes(path)
    path.write_bytes(b"not an inspected native archive")
    with pytest.raises(WorkspaceError):
        native_product_axes(path)
    path.write_bytes(archive("x86_64", "x86_64"))
    axes = native_product_axes(path)
    assert axes["isa"] == "x86_64" and axes["import_library"] is False
    assert axes.get("os") is None and axes.get("hardware_generation") is None


def test_legacy_serialized_graph_is_inspectable_but_has_no_execution_or_refinement_authority(tmp_path):
    units, graph, _bound = compiled_pair(tmp_path)
    legacy = {key: copy.deepcopy(graph[key]) for key in (
        "schema", "source_fingerprint", "nodes", "edges", "external_requirements", "coverage_gaps")}
    legacy["schema"] = "appsec-review/build-topology/1"
    for node in legacy["nodes"]:
        node["recipe_revision"] = "d" * 64
    legacy["topology_id"] = topology_identity(legacy)
    raw = canonical_json(legacy)
    decoded = json.loads(raw)
    validate_build_topology(decoded)
    assert topological_order(decoded) == topological_order(graph)
    result = ready_build_units(decoded, {})
    assert result["ready"] == []
    assert all(item["reasons"] == ["legacy_graph_requires_accepted_replanning"]
               for item in result["blocked"])
    with pytest.raises(ValueError):
        refine_build_topology(decoded, units, profiles=compiler_profile())
    assert canonical_json(decoded) == raw
