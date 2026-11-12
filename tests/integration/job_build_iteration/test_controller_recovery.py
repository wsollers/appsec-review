"""job_build_iteration: the pre-walk controller suite, moved out of the unit path by T-113.

These cases drive BuildIterations.run through failure, restart, invalidation and recovery with a
fake worker and invoker, and one case runs a real Dagster execute_in_process. They are integration
tests pending replacement by code-level tests in tests/unit/job_build_iteration/ and run only when
named explicitly (``scripts/run-tests.sh --allow-heavy -- <file>``). At the walk's HEAD (52b3daab)
nine of the ten cases already failed: the fixture's selected graph has no admitted selected inputs,
so the controller now answers BLOCKED ("shared workspace recovery withheld until selected inputs
are admitted") where the cases expect FAILED/SUCCEEDED, restart and invalidation paths.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from unittest.mock import Mock

import pytest

from appsec_review.jobs.build_iterations import (
    BuildIterations, IterationOutcome, digest, prepare_recipe_command, selected_graph,
)
from appsec_review.jobs.build_workspace import BuildWorkspace, ProductSpec
from tests.unit.job_build_iteration.support import RELEASES, VARIANT, controller, fixture


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


def test_missing_release_evidence_never_dispatches_or_reuses(tmp_path):
    source, _documents, run, graph, dispatches = fixture(tmp_path)
    worker = Mock()
    result = controller(source, run, graph, dispatches, releases={}).run(worker, invoke=Mock())
    worker.assert_not_called()
    assert all(item["terminal_status"] == "BLOCKED" for item in result["receipts"])
    assert any("missing release evidence" in gap for gap in result["gaps"])


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
