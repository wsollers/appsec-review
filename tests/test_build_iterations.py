from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from unittest.mock import Mock

import pytest

from appsec_review.jobs.build_discovery import descriptor_package, discover_build_units
from appsec_review.jobs.build_iterations import (
    BuildIterations, IterationOutcome, digest, prepare_recipe_command, selected_graph,
)
from appsec_review.jobs.build_workspace import BuildWorkspace, ProductSpec


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


def test_failed_destructive_consumer_restart_and_revision_preserves_producer(tmp_path):
    source, documents, run, graph, dispatches = fixture(tmp_path)
    workspace = BuildWorkspace(run)
    calls = []
    invocations = []
    fail = True

    def worker(request, dagster_id):
        nonlocal fail
        uid = request["node_id"]
        node = next(item for item in graph["nodes"] if item["build_unit_id"] == uid)
        calls.append(node["root"])
        if node["root"] == "b":
            assert request["interfaces"][0]["interface"] == "cmake-target:A"
            assert (workspace.paths.target / "a/build/libA.a").read_bytes() == b"A"
            if fail:
                (workspace.paths.target / "shared.conf").write_bytes(b"destroyed")
                (workspace.paths.target / "a/build/libA.a").unlink()
                (workspace.paths.install / "foreign").write_bytes(b"dirt")
                return IterationOutcome({"terminal_status": "FAILED", "gaps": ["compiler"]}, (), True)
        product = node["products"][0]
        relative = f"{node['root']}/build/" + ("libA.a" if node["root"] == "a" else "B")
        path = workspace.paths.target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(node["root"].upper().encode())
        return IterationOutcome({"build_unit_id": uid, "family": node["family"], "terminal_status": "SUCCEEDED",
                                 "gaps": [], "artifacts": []},
                                (ProductSpec("target/" + relative, product["kind"], product["product_id"],
                                             product["interface"], product["variant"]),), True)

    def invoke(request, label, execute):
        run_id = "dagster-" + str(len(invocations))
        invocations.append((dict(request), label, run_id))
        return execute(request, run_id)

    first = controller(source, run, graph, dispatches).run(worker, invoke=invoke)
    assert sorted(first["states"].values()) == ["FAILED", "SUCCEEDED"]
    assert calls == ["a", "b"]
    assert (workspace.paths.target / "shared.conf").read_bytes() == b"original\n"
    assert (workspace.paths.target / "a/build/libA.a").read_bytes() == b"A"
    assert not (workspace.paths.install / "foreign").exists()
    fail = False
    revised = copy.deepcopy(dispatches)
    revised_b = next(item for item in revised if item["root"] == "b")
    revised_b["recipe"]["build_commands"] = [["cmake", "--build", "build", "--verbose"]]
    graph2 = selected_graph(revised, source_fingerprint=graph["source_fingerprint"],
                            relationships=[], variants={})
    assert graph2["topology_id"] == graph["topology_id"]
    second = controller(source, run, graph2, revised).run(worker, invoke=invoke)
    assert set(second["states"].values()) == {"SUCCEEDED"}
    assert calls == ["a", "b", "b"]
    assert [value[1] for value in invocations] == ["build_cpp", "build_cpp1", "build_cpp1"]
    assert len({value[2] for value in invocations}) == 3
    for relative, content in documents.items():
        assert (source / relative).read_text() == content
        assert (workspace.paths.target / relative).is_file()


def test_a_refused_dispatch_reports_a_producer_status(tmp_path):
    """A dispatch whose inputs are refused is a unit output, so its status is a ProducerStatus.

    Review 2026-11-11-0003 failed at ``language_build`` publication because this result said
    ``BLOCKED_BY_DEPENDENCY``, which is not in the closed vocabulary. Why it is blocked is a fact.
    """
    from appsec_review.interchange import ProducerStatus

    source, _documents, run, graph, dispatches = fixture(tmp_path)
    worker = Mock()
    result = controller(source, run, graph, dispatches, releases={}).run(worker, invoke=Mock())
    worker.assert_not_called()
    statuses = {status.value for status in ProducerStatus}
    assert result["terminal_status"] == ProducerStatus.BLOCKED.value
    assert result["availability"] == "blocked_by_dependency"
    assert result["gaps"], "a blocked dispatch names why"
    assert set(result["states"].values()) <= statuses
    assert {item["terminal_status"] for item in result["receipts"]} <= statuses


def test_missing_release_evidence_never_dispatches_or_reuses(tmp_path):
    source, _documents, run, graph, dispatches = fixture(tmp_path)
    worker = Mock()
    result = controller(source, run, graph, dispatches, releases={}).run(worker, invoke=Mock())
    worker.assert_not_called()
    assert all(item["terminal_status"] == "BLOCKED" for item in result["receipts"])
    assert any("missing release evidence" in gap for gap in result["gaps"])


@pytest.mark.parametrize("family", ["native", "dotnet", "go", "java", "node", "php", "python", "ruby"])
@pytest.mark.parametrize("failed", [False, True])
def test_gap_receipt_preserves_language_contract_and_negative_evidence(tmp_path, family, failed):
    source, _documents, run, graph, dispatches = fixture(tmp_path)
    dispatches[0]["family"] = family
    scheduler = controller(source, run, graph, dispatches)
    receipt = scheduler._gap(dispatches[0]["build_unit_id"], "unavailable prerequisite", failed=failed)
    assert receipt == {
        "schema": "appsec-review/language-build-receipt/1",
        "source_fingerprint": graph["source_fingerprint"],
        "build_unit_id": dispatches[0]["build_unit_id"], "family": family,
        "root": dispatches[0]["root"], "terminal_status": "FAILED" if failed else "BLOCKED",
        "artifacts": [], "commands": [], "gaps": ["unavailable prerequisite"],
    }


@pytest.mark.parametrize("terminal", ["BLOCKED", "SKIPPED_POLICY"])
def test_omitted_dispatch_retains_named_receipt_and_blocks_exact_dependents(tmp_path, terminal):
    source, _documents, run, graph, dispatches = fixture(tmp_path)
    producer = next(item for item in dispatches if item["root"] == "a")
    uid = producer["build_unit_id"]
    omitted = {"build_unit_id": uid, "family": "native", "root": "a",
               "terminal_status": terminal, "commands": [], "artifacts": [],
               "gaps": ["image preparation failed"] if terminal == "BLOCKED" else []}
    scheduler = BuildIterations(
        run, source, graph, [item for item in dispatches if item["build_unit_id"] != uid],
        configuration={"fixture": 1}, releases=RELEASES, execution_identity="fixture/1",
        output_policy_identity="outputs/1", omitted_receipts={uid: omitted})
    worker, invoke = Mock(), Mock()
    result = scheduler.run(worker, invoke=invoke)
    worker.assert_not_called()
    invoke.assert_not_called()
    receipts = {item["build_unit_id"]: item for item in result["receipts"]}
    assert receipts[uid] == omitted
    assert next(item for item in receipts.values() if item["root"] == "b")["terminal_status"] == "BLOCKED"
    assert all(item["family"] == "native" for item in receipts.values())


def test_unknown_variant_facts_remain_unknown_and_input_units_are_unchanged(tmp_path):
    _source, _documents, _run, graph, dispatches = fixture(tmp_path)
    original = copy.deepcopy(dispatches)
    for item in dispatches:
        item["build_variant"] = dict.fromkeys(VARIANT)
    before = copy.deepcopy(dispatches)
    unknown = selected_graph(dispatches, source_fingerprint=graph["source_fingerprint"],
                             relationships=[], variants={})
    assert dispatches == before
    assert any(node["variant"]["abi"] is None for node in unknown["nodes"])
    with pytest.raises(ValueError, match="contradicts"):
        selected_graph(original, source_fingerprint=graph["source_fingerprint"], relationships=[],
                       variants={"native": {"abi": "different"}})


@pytest.mark.parametrize("stage", ["before-commit", "after-commit"])
def test_restart_reconciles_command_and_commit_crash_boundaries(tmp_path, monkeypatch, stage):
    from appsec_review.jobs.build_workspace import WorkspaceWriter
    source, _documents, run, graph, dispatches = fixture(tmp_path)
    workspace = BuildWorkspace(run)
    calls = []
    original = WorkspaceWriter.commit
    crash = True

    def commit(writer, products):
        nonlocal crash
        is_b = writer.state()["attempt"]["binding"]["node_id"] == next(
            item["build_unit_id"] for item in graph["nodes"] if item["root"] == "b")
        if crash and is_b:
            crash = False
            if stage == "after-commit":
                original(writer, products)
            raise SystemExit("controller interruption")
        return original(writer, products)

    monkeypatch.setattr(WorkspaceWriter, "commit", commit)

    def worker(request, run_id):
        node = next(item for item in graph["nodes"] if item["build_unit_id"] == request["node_id"])
        calls.append(node["root"])
        name = "libA.a" if node["root"] == "a" else "B"
        relative = f"{node['root']}/build/{name}"
        path = workspace.paths.target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(node["root"].encode())
        product = node["products"][0]
        return IterationOutcome({"build_unit_id": request["node_id"], "terminal_status": "SUCCEEDED",
                                 "gaps": []}, (ProductSpec(
            "target/" + relative, product["kind"], product["product_id"], product["interface"],
            product["variant"]),), True)

    def invoke(ref, label, execute):
        return execute(ref, "dagster-" + str(len(calls)))

    with pytest.raises(SystemExit, match="interruption"):
        controller(source, run, graph, dispatches).run(worker, invoke=invoke)
    result = controller(source, run, graph, dispatches).run(worker, invoke=invoke)
    assert set(result["states"].values()) == {"SUCCEEDED"}
    assert calls.count("a") == 1
    assert calls.count("b") == (2 if stage == "before-commit" else 1)


def test_actual_dagster_invocations_have_distinct_ids_and_immutable_inputs(tmp_path):
    from appsec_review.jobs.job_build_iteration.job import invoke_iteration
    observed = []

    def worker(reference, run_id):
        observed.append((reference, run_id))
        return {"completion": dict(reference)}

    ref = {"path": "artifacts/request.json", "sha256": "a" * 64}
    for label in ("build_cpp", "build_cpp1"):
        assert invoke_iteration(ref, label, worker) == {"completion": ref}
    assert len({run_id for _, run_id in observed}) == 2
    assert all(value == ref for value, _ in observed)


def test_phase_cwd_binds_cmake_source_and_build_and_preserves_target_operands(tmp_path):
    source, _documents, run, graph, dispatches = fixture(tmp_path)
    workspace = BuildWorkspace(run)
    workspace.materialize(source, graph["source_fingerprint"])
    accepted = next(item for item in dispatches if item["root"] == "b")
    recipe = {**accepted["recipe"], "execution_cwd": {"configure": "b/build", "build": "b/build"}}
    configure = ("cmake", "-S", "..", "-B", ".")
    assert prepare_recipe_command(workspace.paths.target, accepted, recipe, "configure", configure) == (
        configure, "b/build")
    build = ("cmake", "--build", ".", "--target", "b", "--", "b/target")
    assert prepare_recipe_command(workspace.paths.target, accepted, recipe, "build", build) == (build, "b/build")
    with pytest.raises(ValueError, match="wrong accepted source"):
        prepare_recipe_command(workspace.paths.target, accepted, recipe, "configure",
                               ("cmake", "-S", ".", "-B", "."))
    assert prepare_recipe_command(
        workspace.paths.target, accepted, recipe, "configure", ("cmake", "-Sb", "-Bb/build")) == (
            configure[:1] + ("-S..", "-B."), "b/build")
    assert not (source / "b/build").exists()


def test_make_applies_all_directory_operands_before_explicit_driver_without_rebasing_targets(tmp_path):
    source, _documents, run, graph, dispatches = fixture(tmp_path)
    makefile = source / "b/Makefile"
    makefile.write_bytes(b"b/target:\n\tcc b.c -o build/B\n")
    workspace = BuildWorkspace(run)
    workspace.materialize(source, graph["source_fingerprint"])
    accepted = next(item for item in dispatches if item["root"] == "b")
    accepted["descriptor_package"]["documents"].append({
        "path": "b/Makefile", "sha256": hashlib.sha256(makefile.read_bytes()).hexdigest()})
    recipe = {**accepted["recipe"], "execution_cwd": {"build": "b/build"}}
    command = ("make", "-f", "Makefile", "-C", "..", "b/target")
    assert prepare_recipe_command(workspace.paths.target, accepted, recipe, "build", command) == (
        command, "b/build")
    wrong = ("make", "-C", ".", "b/target")
    with pytest.raises(ValueError, match="default driver is absent"):
        prepare_recipe_command(workspace.paths.target, accepted, recipe, "build", wrong)
    (workspace.paths.target / "b/Makefile").write_bytes(b"replaced\n")
    with pytest.raises(ValueError, match="unchanged accepted source descriptor"):
        prepare_recipe_command(workspace.paths.target, accepted, recipe, "build", command)


def test_each_phase_rechecks_cwd_after_configure_and_refuses_symlinked_build(tmp_path):
    source, _documents, run, graph, dispatches = fixture(tmp_path)
    workspace = BuildWorkspace(run)
    workspace.materialize(source, graph["source_fingerprint"])
    accepted = next(item for item in dispatches if item["root"] == "b")
    recipe = {**accepted["recipe"], "execution_cwd": {"build": "b/build"}}
    assert prepare_recipe_command(
        workspace.paths.target, accepted, recipe, "configure",
        ("cmake", "-S", ".", "-B", "build"))[1] == "b"
    (workspace.paths.target / "b/build").rmdir()
    (workspace.paths.target / "b/build").symlink_to(workspace.paths.target / "a", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        prepare_recipe_command(workspace.paths.target, accepted, recipe, "build",
                               ("cmake", "--build", "."))


@pytest.mark.parametrize("interrupt_after_recomposition", [False, True])
def test_exact_invalidation_retains_later_independent_node_and_recovers_commit_before_ledger(
        tmp_path, monkeypatch, interrupt_after_recomposition):
    from appsec_review.jobs.build_topology import topological_order
    from appsec_review.jobs.build_workspace import WorkspaceWriter
    source, _documents, run, graph, dispatches = fixture(tmp_path, independent=True)
    roots = {item["build_unit_id"]: item["root"] for item in graph["nodes"]}
    assert [roots[uid] for uid in topological_order(graph)] == ["a", "b", "later-independent"]
    workspace = BuildWorkspace(run)
    calls = []

    def worker(request, dagster_id):
        node = next(item for item in graph["nodes"] if item["build_unit_id"] == request["node_id"])
        calls.append(node["root"])
        (workspace.paths.install / "lib").mkdir(exist_ok=True)
        relative = {"a": "lib/libA.a", "b": "B", "later-independent": "C"}[node["root"]]
        (workspace.paths.install / relative).write_bytes(node["root"].encode())
        return IterationOutcome({
            "build_unit_id": request["node_id"], "terminal_status": "SUCCEEDED", "gaps": []},
            (ProductSpec("install/" + relative, **node["products"][0]),), True)

    invoke = lambda ref, label, execute: execute(ref, "fixture-" + str(len(calls)))
    assert set(controller(source, run, graph, dispatches).run(worker, invoke=invoke)["states"].values()) == {"SUCCEEDED"}
    original = WorkspaceWriter.invalidate_nodes
    interrupted = False

    def invalidate(writer, *args, **kwargs):
        nonlocal interrupted
        result = original(writer, *args, **kwargs)
        if interrupt_after_recomposition and not interrupted:
            interrupted = True
            raise SystemExit("recomposition committed before C ledger")
        return result

    monkeypatch.setattr(WorkspaceWriter, "invalidate_nodes", invalidate)
    revised = copy.deepcopy(dispatches)
    next(item for item in revised if item["root"] == "b")["recipe"]["build_commands"][0].append("--verbose")
    graph2 = selected_graph(revised, source_fingerprint=graph["source_fingerprint"], relationships=[], variants={})
    if interrupt_after_recomposition:
        with pytest.raises(SystemExit, match="before C ledger"):
            controller(source, run, graph2, revised).run(worker, invoke=invoke)
    result = controller(source, run, graph2, revised).run(worker, invoke=invoke)
    assert set(result["states"].values()) == {"SUCCEEDED"}
    assert calls == ["a", "b", "later-independent", "b"]
    again = controller(source, run, graph2, revised).run(worker, invoke=invoke)
    assert set(again["states"].values()) == {"SUCCEEDED"}
    assert calls == ["a", "b", "later-independent", "b"]
    assert (workspace.paths.install / "lib/libA.a").read_bytes() == b"a"
    assert (workspace.paths.install / "C").read_bytes() == b"later-independent"
    next(item for item in revised if item["root"] == "b")["recipe"]["build_commands"][0].append("--clean-first")
    graph3 = selected_graph(revised, source_fingerprint=graph["source_fingerprint"], relationships=[], variants={})
    third = controller(source, run, graph3, revised).run(worker, invoke=invoke)
    assert set(third["states"].values()) == {"SUCCEEDED"}
    assert calls == ["a", "b", "later-independent", "b", "b"]
    assert (workspace.paths.install / "lib/libA.a").read_bytes() == b"a"
    assert (workspace.paths.install / "C").read_bytes() == b"later-independent"
