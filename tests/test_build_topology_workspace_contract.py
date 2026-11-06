from __future__ import annotations

import copy
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path, PurePosixPath
import struct
from typing import Any
from unittest.mock import Mock

import pytest

from appsec_review.jobs.build_discovery import descriptor_package, discover_build_units
from appsec_review.jobs.build_topology import (
    compile_build_topology, proven_product_axes, ready_build_units, refine_build_topology,
    refinement_unit,
)
from appsec_review.jobs.build_workspace import (
    BuildWorkspace, NodeBinding, ProductRecord, ProductSpec, ReconstructionMiss, WorkspaceWriter,
)
from appsec_review.storage import canonical_json
from appsec_review.storage.atomic import canonical_json_sha256


VARIANT = {
    "configuration": "release", "target_arch": "x86_64", "execution_role": "target",
    "linkage": "static", "toolchain": "fixture-toolchain/1", "abi": "fixture-abi/1",
}
PROFILE = {
    "schema": "appsec-review/static-compiler-profile/1", "executable": "clang",
    "driver_semantics": "clang-target/1", "compiler_sha256": "b" * 64,
    "image_digest": "sha256:" + "a" * 64, "wrapper_closure": [],
    "target_axes": {"os": "linux", "isa": "x86_64", "abi": "gnu"},
    "provenance": {"origin": "synthetic-workspace-contract-unit", "revision": "1"},
}
RELEASES = {"platform": "fixture/1", "build_toolchain": "fixture-toolchain/1", "validation": "fixture/1"}


def _archive() -> bytes:
    """A minimal x86-64 ELF static archive, so retained-product role/ISA checks are real."""
    head = bytearray(64)
    head[:7] = b"\x7fELF" + bytes([2, 1, 1])
    struct.pack_into("<HH", head, 16, 1, 62)
    member = ("a.o/".ljust(16) + "0".ljust(12) + "0".ljust(6) + "0".ljust(6)
              + "100644".ljust(8) + "64".ljust(10) + "`\n").encode()
    return b"!<arch>\n" + member + head


LIBRARY = _archive()


def _refine(graph: dict[str, Any], units: list[dict[str, Any]]) -> dict[str, Any]:
    return refine_build_topology(graph, units, profiles=PROFILE, releases=RELEASES)


@dataclass
class Contract:
    units: list[dict[str, Any]]
    graph: dict[str, Any]
    refinement: dict[str, Any]
    workspace: BuildWorkspace
    producer: dict[str, Any]
    consumer: dict[str, Any]
    binding: NodeBinding
    record: ProductRecord
    generation: str
    compile_a: Mock


@pytest.fixture
def contract(tmp_path: Path):
    source = tmp_path / "source"
    original = {
        "z-library/CMakeLists.txt": b"project(library)\nadd_library(A STATIC a.c)\n",
        "z-library/a.c": b"int a(void) { return 1; }\n",
        "a-consumer/CMakeLists.txt": (
            b"project(consumer)\nadd_executable(B b.c)\ntarget_link_libraries(B PRIVATE A)\n"
        ),
        "a-consumer/b.c": b"int a(void); int main(void) { return a(); }\n",
        "shared.conf": b"original configuration\n",
    }
    files = []
    for relative, content in original.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        files.append({"path": relative, "sha256": hashlib.sha256(content).hexdigest(),
                      "size_bytes": len(content)})
    source_identity = canonical_json_sha256(files)
    units = discover_build_units(files)
    for unit in units:
        package = descriptor_package(source, unit, files)
        root = unit["root"]
        # The compiler-source closure needs the accepted translation-unit bytes, not just markers.
        for item in files:
            if (PurePosixPath(item["path"]).parent.as_posix() == root and item["path"].endswith(".c")
                    and item["path"] not in {document["path"] for document in package["documents"]}):
                package["documents"].append({**item, "content": original[item["path"]].decode()})
        package["bounds"]["actual_files"] = len(package["documents"])
        package["bounds"]["actual_bytes"] = sum(len(item["content"].encode()) for item in package["documents"])
        unit["descriptor_package"] = package
        unit["build_variant"] = dict(VARIANT)
        translation_unit = next(PurePosixPath(item["path"]).name for item in package["documents"]
                                if item["path"].endswith(".c"))
        unit["recipe"] = {
            "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
            "image_profile": unit["family"], "source_dir": root, "build_dir": f"{root}/build",
            "system_packages": [], "environment": {},
            "dependency_files": sorted(item["path"] for item in package["documents"]),
            "configure_commands": [],
            "build_commands": [["clang", "--target=x86_64-unknown-linux-gnu", "-c", translation_unit,
                                "-o", "build/control.o"]],
            "expected_outputs": [f"{root}/build"], "network_required": False,
            "reason": "source-backed fixture recipe; external compiler is faked",
        }
    graph = compile_build_topology(units, source_fingerprint=source_identity, profiles=PROFILE)
    refinement = _refine(graph, units)
    assert all(unit["blockers"] == [] for unit in refinement["units"])
    producer = next(node for node in graph["nodes"] if node["root"] == "z-library")
    consumer = next(node for node in graph["nodes"] if node["root"] == "a-consumer")
    assert producer["recipe_revision"] is None and consumer["recipe_revision"] is None
    # graph/2 is structural only: no unit is ready without an accepted recipe-bound refinement.
    assert ready_build_units(graph, {})["ready"] == []
    assert ready_build_units(graph, {}, refinement=refinement)["ready"] == [producer["build_unit_id"]]
    producer_bound = refinement_unit(graph, refinement, producer["build_unit_id"])
    run = tmp_path / "runs" / "fixture"
    run.mkdir(parents=True)
    workspace = BuildWorkspace(run)
    initial = workspace.materialize(source, source_identity)
    binding = NodeBinding(
        node_id=producer["build_unit_id"], source_identity=source_identity,
        graph_identity=graph["topology_id"],
        configuration_identity=canonical_json_sha256({"releases": RELEASES, "variant": VARIANT}),
        recipe_identity=producer_bound["recipe_digest"], image_identity="sha256:" + "1" * 64,
        toolchain_identity=VARIANT["toolchain"], upstream_products=(),
        execution_identity="fixture-capture/1", output_policy_identity="fixture-products/1",
    )

    def fake_compile_a() -> None:
        for relative, content in {
            "lib/libA.a": LIBRARY,
            "include/a.h": b"int a(void);\n",
            "lib/pkgconfig/a.pc": b"Name: A\nLibs: -L/install/lib -lA\n",
        }.items():
            path = workspace.paths.install / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        (workspace.paths.install / "lib/libA.a").chmod(0o755)
        (workspace.paths.target / "generated.h").write_bytes(b"#define A 1\n")
        (workspace.paths.target / "shared.conf").write_bytes(b"accepted A configuration\n")

    compile_a = Mock(side_effect=fake_compile_a)
    with workspace.writer() as writer:
        writer.begin_attempt(binding, "A-1", initial)
        compile_a()
        record = writer.commit([
            ProductSpec("install/lib/libA.a", **producer["products"][0], role="static_archive",
                        axes=proven_product_axes(producer_bound)),
            ProductSpec("install/include/a.h", "headers", "include:A", "include:A", dict(VARIANT)),
            ProductSpec("install/lib/pkgconfig/a.pc", "package_metadata", "pkg:A", "pkg:A", dict(VARIANT)),
        ])
        generation = writer.state()["generation"]
    yield Contract(units, graph, refinement, workspace, producer, consumer, binding, record, generation,
                   compile_a)
    compile_a.assert_called_once_with()
    assert {path.relative_to(source).as_posix(): path.read_bytes()
            for path in source.rglob("*") if path.is_file()} == original


def _ready(contract: Contract, writer: WorkspaceWriter, refinement=None, products=None):
    if products is None:
        products = writer.product_interfaces(contract.record.reference, contract.binding)

    def verify(record):
        return writer.verify_product(
            record["workspace_product"], contract.binding).identity == contract.record.identity

    return ready_build_units(
        contract.graph, {contract.producer["build_unit_id"]: "SUCCEEDED"},
        products=products, verify_product=verify,
        refinement=contract.refinement if refinement is None else refinement,
    )


def _consumer_binding(contract: Contract, refinement: dict[str, Any]) -> NodeBinding:
    bound = refinement_unit(contract.graph, refinement, contract.consumer["build_unit_id"])
    return replace(contract.binding, node_id=contract.consumer["build_unit_id"],
                   recipe_identity=bound["recipe_digest"],
                   upstream_products=(contract.record.identity,))


def _revised_consumer(contract: Contract, environment: dict[str, str]) -> dict[str, Any]:
    """Revise only B's recipe; the structural graph must not change, only its refinement."""
    units = copy.deepcopy(contract.units)
    next(unit for unit in units if unit["build_unit_id"] == contract.consumer["build_unit_id"])[
        "recipe"]["environment"] = environment
    revised_graph = compile_build_topology(
        units, source_fingerprint=contract.binding.source_identity, profiles=PROFILE)
    assert canonical_json(revised_graph) == canonical_json(contract.graph)
    revised = _refine(revised_graph, units)
    assert all(unit["blockers"] == [] for unit in revised["units"])
    assert revised["refinement_id"] != contract.refinement["refinement_id"]
    assert (refinement_unit(contract.graph, revised, contract.producer["build_unit_id"])["recipe_digest"]
            == contract.binding.recipe_identity)
    return revised


def _publish_consumer(contract: Contract, writer: WorkspaceWriter) -> ProductRecord:
    library = (writer.paths.install / "lib/libA.a").read_bytes()
    assert library == LIBRARY
    assert (writer.paths.install / "include/a.h").read_bytes() == b"int a(void);\n"
    assert b"-L/install/lib -lA" in (writer.paths.install / "lib/pkgconfig/a.pc").read_bytes()
    (writer.paths.install / "bin").mkdir()
    (writer.paths.install / "bin/B").write_bytes(b"fixture B consuming " + library)
    (writer.paths.install / "lib/pkgconfig/b.pc").write_bytes(b"Name: B\nRequires: A\n")
    return writer.commit([
        ProductSpec("install/bin/B", **contract.consumer["products"][0]),
        ProductSpec("install/lib/pkgconfig/b.pc", "package_metadata", "pkg:B", "pkg:B", dict(VARIANT)),
    ])


@pytest.mark.parametrize("field,value", [
    ("producer_build_unit_id", "wrong-producer"),
    ("interface", "cmake-target:unrelated"),
    ("configuration", "debug"), ("target_arch", "aarch64"),
    ("execution_role", "host"), ("linkage", "shared"),
    ("toolchain", "other-toolchain"), ("abi", "other-abi"),
])
def test_durable_product_adapter_refuses_wrong_producer_interface_and_variant(contract, field, value):
    with contract.workspace.writer() as writer:
        products = writer.product_interfaces(contract.record.reference, contract.binding)
        assert products[0]["workspace_product"] == contract.record.reference
        assert products[0]["path"] == "/install/lib/libA.a"
        assert _ready(contract, writer, products=products)["ready"] == [contract.consumer["build_unit_id"]]
        changed = copy.deepcopy(products)
        if field in VARIANT:
            changed[0]["variant"][field] = value
        else:
            changed[0][field] = value
        refused = _ready(contract, writer, products=changed)
        assert refused["ready"] == []
        assert refused["blocked"] == [{
            "build_unit_id": contract.consumer["build_unit_id"],
            "reasons": [f"required_product_unverified:{contract.producer['build_unit_id']}"],
        }]
        with pytest.raises(ReconstructionMiss, match="binding changed"):
            writer.verify_product(contract.record.reference, _consumer_binding(contract, contract.refinement))


def test_b_recipe_revision_keeps_structural_topology_and_durable_a_ready(contract):
    revised = _revised_consumer(contract, {"FIXTURE_RECIPE": "corrected"})
    assert (_consumer_binding(contract, revised).recipe_identity
            != _consumer_binding(contract, contract.refinement).recipe_identity)
    with contract.workspace.writer() as writer:
        before = writer.product_interfaces(contract.record.reference, contract.binding)
        assert _ready(contract, writer, revised)["ready"] == [contract.consumer["build_unit_id"]]
        assert writer.verify_product(contract.record.reference, contract.binding) == contract.record
        assert writer.product_interfaces(contract.record.reference, contract.binding) == before
        assert writer.state()["generation"] == contract.generation
    contract.compile_a.assert_called_once_with()


def test_failed_b_overwrite_and_deletion_restore_a_before_revised_b_without_rebuild(contract):
    library = contract.workspace.paths.install / "lib/libA.a"
    generated = contract.workspace.paths.target / "generated.h"
    library_stat, generated_stat = library.stat(), generated.stat()
    with contract.workspace.writer() as writer:
        writer.begin_attempt(_consumer_binding(contract, contract.refinement), "B-failed", contract.generation)
        library.write_bytes(b"overwritten by failed B")
        library.chmod(0o600)
        (writer.paths.install / "include/a.h").unlink()
        generated.unlink()
        (writer.paths.target / "shared.conf").unlink()
        (writer.paths.target / "failed-only").write_bytes(b"uncommitted")
        writer.fail_attempt("fixture_command_exit_2")
        assert writer.state()["generation"] == contract.generation

    restarted = BuildWorkspace(contract.workspace.run_dir)
    with restarted.writer() as writer:
        with pytest.raises(ReconstructionMiss, match="restored"):
            writer.product_interfaces(contract.record.reference, contract.binding)
        assert writer.restore() == contract.generation
        assert library.read_bytes() == LIBRARY
        assert library.stat().st_mode == library_stat.st_mode
        assert library.stat().st_mtime_ns == library_stat.st_mtime_ns
        assert generated.read_bytes() == b"#define A 1\n"
        assert generated.stat().st_mtime_ns == generated_stat.st_mtime_ns
        assert (writer.paths.target / "shared.conf").read_bytes() == b"accepted A configuration\n"
        assert not (writer.paths.target / "failed-only").exists()
        assert _ready(contract, writer)["ready"] == [contract.consumer["build_unit_id"]]
        revised = _revised_consumer(contract, {"FIXTURE_RECIPE": "fixed-after-failure"})
        writer.begin_attempt(_consumer_binding(contract, revised), "B-revised", contract.generation)
        second = _publish_consumer(contract, writer)
        assert second.binding["upstream_products"] == [contract.record.identity]
        assert writer.verify_product(contract.record.reference, contract.binding) == contract.record
    contract.compile_a.assert_called_once_with()


def test_additive_b_install_publication_keeps_a_product_and_interface_valid(contract):
    with contract.workspace.writer() as writer:
        original_interfaces = writer.product_interfaces(contract.record.reference, contract.binding)
        assert _ready(contract, writer)["ready"] == [contract.consumer["build_unit_id"]]
        writer.begin_attempt(_consumer_binding(contract, contract.refinement), "B-clean", contract.generation)
        second = _publish_consumer(contract, writer)
        assert writer.state()["generation"] != contract.generation
        assert writer.verify_product(second.reference, _consumer_binding(contract, contract.refinement)) == second
        assert writer.verify_product(contract.record.reference, contract.binding) == contract.record
        assert writer.product_interfaces(contract.record.reference, contract.binding) == original_interfaces
        assert _ready(contract, writer)["ready"] == [contract.consumer["build_unit_id"]]
        assert (writer.paths.install / "bin/B").read_bytes() == b"fixture B consuming " + LIBRARY
    contract.compile_a.assert_called_once_with()
