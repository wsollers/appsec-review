from __future__ import annotations

import copy
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from appsec_review.jobs.build_discovery import descriptor_package, discover_build_units
from appsec_review.jobs.build_topology import compile_build_topology, ready_build_units
from appsec_review.jobs.build_workspace import (
    BuildWorkspace, NodeBinding, ProductRecord, ProductSpec, ReconstructionMiss, WorkspaceWriter,
)
from appsec_review.storage.atomic import canonical_json_sha256


VARIANT = {
    "configuration": "release", "target_arch": "x86_64", "execution_role": "target",
    "linkage": "static", "toolchain": "fixture-toolchain/1", "abi": "fixture-abi/1",
}


@dataclass
class Contract:
    units: list[dict[str, Any]]
    graph: dict[str, Any]
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
        unit["descriptor_package"] = descriptor_package(source, unit, files)
        unit["build_variant"] = dict(VARIANT)
        root = unit["root"]
        unit["recipe"] = {
            "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
            "image_profile": unit["family"], "source_dir": root, "build_dir": f"{root}/build",
            "system_packages": [], "environment": {},
            "dependency_files": [marker["path"] for marker in unit["markers"]],
            "configure_commands": [], "build_commands": [["cmake", "--build", f"{root}/build"]],
            "expected_outputs": [f"{root}/build"], "network_required": False,
            "reason": "source-backed fixture recipe; external compiler is faked",
        }
    graph = compile_build_topology(units, source_fingerprint=source_identity)
    producer = next(node for node in graph["nodes"] if node["root"] == "z-library")
    consumer = next(node for node in graph["nodes"] if node["root"] == "a-consumer")
    assert ready_build_units(graph, {})["ready"] == [producer["build_unit_id"]]
    run = tmp_path / "runs" / "fixture"
    run.mkdir(parents=True)
    workspace = BuildWorkspace(run)
    initial = workspace.materialize(source, source_identity)
    binding = NodeBinding(
        node_id=producer["build_unit_id"], source_identity=source_identity,
        graph_identity=graph["topology_id"],
        configuration_identity=canonical_json_sha256({
            "releases": {"platform": "fixture/1", "validation": "fixture/1"}, "variant": VARIANT,
        }),
        recipe_identity=producer["recipe_revision"], image_identity="sha256:" + "1" * 64,
        toolchain_identity=VARIANT["toolchain"], upstream_products=(),
        execution_identity="fixture-capture/1", output_policy_identity="fixture-products/1",
    )

    def fake_compile_a() -> None:
        for relative, content in {
            "lib/libA.a": b"fixture A library",
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
            ProductSpec("install/lib/libA.a", **producer["products"][0]),
            ProductSpec("install/include/a.h", "headers", "include:A", "include:A", dict(VARIANT)),
            ProductSpec("install/lib/pkgconfig/a.pc", "package_metadata", "pkg:A", "pkg:A", dict(VARIANT)),
        ])
        generation = writer.state()["generation"]
    yield Contract(units, graph, workspace, producer, consumer, binding, record, generation, compile_a)
    compile_a.assert_called_once_with()
    assert {path.relative_to(source).as_posix(): path.read_bytes()
            for path in source.rglob("*") if path.is_file()} == original


def _ready(contract: Contract, writer: WorkspaceWriter, graph=None, products=None):
    if products is None:
        products = writer.product_interfaces(contract.record.reference, contract.binding)

    def verify(record):
        return writer.verify_product(
            record["workspace_product"], contract.binding).identity == contract.record.identity

    return ready_build_units(
        contract.graph if graph is None else graph,
        {contract.producer["build_unit_id"]: "SUCCEEDED"},
        products=products, verify_product=verify,
    )


def _consumer_binding(contract: Contract, graph: dict[str, Any]) -> NodeBinding:
    consumer = next(node for node in graph["nodes"]
                    if node["build_unit_id"] == contract.consumer["build_unit_id"])
    return replace(contract.binding, node_id=consumer["build_unit_id"],
                   recipe_identity=consumer["recipe_revision"],
                   upstream_products=(contract.record.identity,))


def _publish_consumer(contract: Contract, writer: WorkspaceWriter) -> ProductRecord:
    library = (writer.paths.install / "lib/libA.a").read_bytes()
    assert library == b"fixture A library"
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
            writer.verify_product(contract.record.reference, _consumer_binding(contract, contract.graph))


def test_b_recipe_revision_keeps_structural_topology_and_durable_a_ready(contract):
    units = copy.deepcopy(contract.units)
    consumer = next(unit for unit in units if unit["build_unit_id"] == contract.consumer["build_unit_id"])
    consumer["recipe"]["environment"] = {"FIXTURE_RECIPE": "corrected"}
    revised = compile_build_topology(units, source_fingerprint=contract.binding.source_identity)
    assert revised != contract.graph
    assert revised["topology_id"] == contract.graph["topology_id"]
    assert _consumer_binding(contract, revised).recipe_identity != contract.consumer["recipe_revision"]
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
        writer.begin_attempt(_consumer_binding(contract, contract.graph), "B-failed", contract.generation)
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
        assert library.read_bytes() == b"fixture A library"
        assert library.stat().st_mode == library_stat.st_mode
        assert library.stat().st_mtime_ns == library_stat.st_mtime_ns
        assert generated.read_bytes() == b"#define A 1\n"
        assert generated.stat().st_mtime_ns == generated_stat.st_mtime_ns
        assert (writer.paths.target / "shared.conf").read_bytes() == b"accepted A configuration\n"
        assert not (writer.paths.target / "failed-only").exists()
        assert _ready(contract, writer)["ready"] == [contract.consumer["build_unit_id"]]
        units = copy.deepcopy(contract.units)
        next(unit for unit in units if unit["build_unit_id"] == contract.consumer["build_unit_id"])[
            "recipe"]["environment"] = {"FIXTURE_RECIPE": "fixed-after-failure"}
        revised = compile_build_topology(units, source_fingerprint=contract.binding.source_identity)
        assert revised["topology_id"] == contract.graph["topology_id"]
        writer.begin_attempt(_consumer_binding(contract, revised), "B-revised", contract.generation)
        second = _publish_consumer(contract, writer)
        assert second.binding["upstream_products"] == [contract.record.identity]
        assert writer.verify_product(contract.record.reference, contract.binding) == contract.record
    contract.compile_a.assert_called_once_with()


def test_additive_b_install_publication_keeps_a_product_and_interface_valid(contract):
    with contract.workspace.writer() as writer:
        original_interfaces = writer.product_interfaces(contract.record.reference, contract.binding)
        assert _ready(contract, writer)["ready"] == [contract.consumer["build_unit_id"]]
        writer.begin_attempt(_consumer_binding(contract, contract.graph), "B-clean", contract.generation)
        second = _publish_consumer(contract, writer)
        assert writer.state()["generation"] != contract.generation
        assert writer.verify_product(second.reference, _consumer_binding(contract, contract.graph)) == second
        assert writer.verify_product(contract.record.reference, contract.binding) == contract.record
        assert writer.product_interfaces(contract.record.reference, contract.binding) == original_interfaces
        assert _ready(contract, writer)["ready"] == [contract.consumer["build_unit_id"]]
        assert (writer.paths.install / "bin/B").read_bytes() == b"fixture B consuming fixture A library"
    contract.compile_a.assert_called_once_with()
