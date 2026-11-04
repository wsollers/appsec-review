from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os

import pytest

from appsec_review.jobs.build_workspace import (
    ProductSpec, ReconstructionMiss, WorkspaceError,
)
from tests.test_build_workspace import binding, build_a, make_workspace, product


def test_separate_b_invocation_opens_a_products_without_rebuilding_a(tmp_path):
    workspace, source, initial = make_workspace(tmp_path)
    record, generation = build_a(workspace, initial)
    with workspace.writer() as writer:
        assert writer.verify_product(record, binding()).identity == record.identity
        writer.begin_attempt(binding("B", (record.identity,)), "B-1", generation)
        assert (writer.paths.install / "lib/liba.so").read_bytes() == b"verified-A-library"
        assert (writer.paths.install / "a.h").read_bytes() == b"int a(void);\n"
        (writer.paths.target / "consumer.o").write_bytes(b"B using A")
        second = writer.commit([product("target/consumer.o", "executable")])
        assert writer.verify_product(record, binding()) == record
        assert second.binding["upstream_products"] == [record.identity]
    assert (source / "make.conf").read_bytes() == b"CC=cc\n"


def test_failed_b_destructive_mutations_restore_all_a_state_and_metadata(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    record, generation = build_a(workspace, initial)
    library = workspace.paths.install / "lib/liba.so.1.2"
    details = library.stat()
    generated_details = (workspace.paths.target / "generated.h").stat()
    with workspace.writer() as writer:
        writer.begin_attempt(binding("B", (record.identity,)), "B-bad", generation)
        library.write_bytes(b"corrupted")
        library.chmod(0o600)
        (writer.paths.install / "lib/liba.so.1").unlink()
        (writer.paths.target / "make.conf").unlink()
        (writer.paths.target / "generated.h").unlink()
        (writer.paths.target / "gtest/samples/sample1.cc").write_bytes(b"broken source")
        (writer.paths.target / "failed-output").write_bytes(b"uncommitted")
        (writer.paths.install / "host-link").symlink_to("/etc")
        writer.fail_attempt("command_exit_2")
    with workspace.writer() as writer:
        with pytest.raises(ReconstructionMiss, match="restore"):
            writer.verify_product(record, binding())
        assert writer.restore() == generation
        assert writer.verify_product(record, binding()).identity == record.identity
        assert library.read_bytes() == b"verified-A-library"
        assert library.stat().st_mode == details.st_mode
        assert library.stat().st_mtime_ns == details.st_mtime_ns
        assert (writer.paths.install / "lib/liba.so.1").is_symlink()
        assert os.readlink(writer.paths.install / "lib/liba.so.1") == "liba.so.1.2"
        assert (writer.paths.target / "make.conf").read_bytes() == b"CC=prepared-cc\n"
        assert (writer.paths.target / "generated.h").stat().st_mtime_ns == generated_details.st_mtime_ns
        assert not (writer.paths.target / "failed-output").exists()
        assert not (writer.paths.install / "host-link").exists()
        assert not (writer.paths.target / "removed-by-A").exists()
        writer.begin_attempt(replace(binding("B", (record.identity,)), recipe_identity="B-fixed"),
                             "B-fixed-2", generation)
        (writer.paths.target / "consumer.o").write_bytes(b"success")
        writer.commit([product("target/consumer.o", "executable")])
        assert writer.verify_product(record, binding()).identity == record.identity


def test_crash_before_commit_is_not_success_and_requires_reconstruction(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    record, generation = build_a(workspace, initial)
    with workspace.writer() as writer:
        writer.begin_attempt(binding("B", (record.identity,)), "B-crash", generation)
        (writer.paths.target / "finished-but-uncommitted.o").write_bytes(b"not accepted")
    with workspace.writer() as writer:
        assert writer.state()["condition"] == "running"
        with pytest.raises(ReconstructionMiss, match="interrupted"):
            writer.begin_attempt(binding("B", (record.identity,)), "B-retry", generation)
        writer.restore()
        assert not (writer.paths.target / "finished-but-uncommitted.o").exists()
        assert writer.verify_product(record, binding()).identity == record.identity


def test_crash_after_product_publication_before_pointer_commit_is_not_accepted(tmp_path, monkeypatch):
    workspace, _, initial = make_workspace(tmp_path)
    record, generation = build_a(workspace, initial)
    with workspace.writer() as writer:
        writer.begin_attempt(binding("B", (record.identity,)), "B-publication-crash", generation)
        (writer.paths.target / "b.o").write_bytes(b"B")
        original = writer._write_state

        def crash_on_clean(value):
            if value["condition"] == "clean":
                raise OSError("simulated controller crash before state publication")
            return original(value)

        monkeypatch.setattr(writer, "_write_state", crash_on_clean)
        with pytest.raises(OSError, match="simulated"):
            writer.commit([product("target/b.o", "executable")])
    with workspace.writer() as writer:
        assert writer.state()["generation"] == generation
        writer.restore()
        assert not (writer.paths.target / "b.o").exists()
        assert writer.verify_product(record, binding()).identity == record.identity


@pytest.mark.parametrize("field", [
    "source_identity", "graph_identity", "configuration_identity", "recipe_identity",
    "image_identity", "toolchain_identity", "execution_identity", "output_policy_identity",
])
def test_changed_producer_inputs_reject_stale_reuse(tmp_path, field):
    workspace, _, initial = make_workspace(tmp_path)
    record, _ = build_a(workspace, initial)
    with workspace.writer() as writer:
        with pytest.raises(ReconstructionMiss, match="binding changed"):
            writer.verify_product(record, replace(binding(), **{field: "changed"}))


def test_unknown_or_changed_upstream_record_rejects_reuse(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    record, generation = build_a(workspace, initial)
    with workspace.writer() as writer:
        with pytest.raises(ReconstructionMiss, match="binding changed"):
            writer.verify_product(record, replace(binding(), upstream_products=("e" * 64,)))
        with pytest.raises(ReconstructionMiss, match="not accepted"):
            writer.begin_attempt(binding("B", ("f" * 64,)), "B-missing-upstream", generation)
        assert writer.state()["condition"] == "clean"


def test_modified_middle_symlink_is_not_a_verified_library(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    record, _ = build_a(workspace, initial)
    (workspace.paths.install / "alternate").write_bytes(b"wrong library")
    middle = workspace.paths.install / "lib/liba.so.1"
    middle.unlink()
    middle.symlink_to("../alternate")
    with workspace.writer() as writer:
        with pytest.raises(ReconstructionMiss, match="overwritten"):
            writer.verify_product(record, binding())
        writer.restore()
        assert writer.verify_product(record, binding()).identity == record.identity


def test_missing_durable_bytes_refuse_restore_before_deleting_working_tree(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    _, generation = build_a(workspace, initial)
    manifest = json.loads((workspace.run_dir / (
        f"artifacts/build/workspace/generations/{generation}.json")).read_bytes())
    digest = manifest["entries"]["install/lib/liba.so.1.2"]["sha256"]
    (workspace.run_dir / f"data/shared/objects/{digest}").unlink()
    (workspace.paths.target / "still-here").write_bytes(b"diagnostic")
    with workspace.writer() as writer:
        with pytest.raises(ReconstructionMiss, match="missing or changed"):
            writer.restore()
    assert (workspace.paths.target / "still-here").read_bytes() == b"diagnostic"


def test_untracked_mutations_require_restore_before_command(tmp_path):
    workspace, _, generation = make_workspace(tmp_path)
    (workspace.paths.target / "make.conf").write_bytes(b"unexpected change")
    with workspace.writer() as writer:
        with pytest.raises(ReconstructionMiss, match="uncommitted"):
            writer.begin_attempt(binding(), "A-1", generation)
        assert writer.state()["condition"] == "tainted"
        writer.restore()
        writer.begin_attempt(binding(), "A-2", generation)


def test_empty_help_only_or_missing_products_cannot_commit(tmp_path):
    workspace, _, generation = make_workspace(tmp_path)
    with workspace.writer() as writer:
        writer.begin_attempt(binding(), "help-only", generation)
        with pytest.raises(WorkspaceError, match="requires unique"):
            writer.commit([])
        with pytest.raises(WorkspaceError, match="missing"):
            writer.commit([product("target/missing.a", "library")])
        assert writer.state()["generation"] == generation


def test_successful_b_cannot_overwrite_accepted_a_product(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    record, generation = build_a(workspace, initial)
    with workspace.writer() as writer:
        writer.begin_attempt(binding("B", (record.identity,)), "B-1", generation)
        (writer.paths.install / "a.h").write_bytes(b"corrupted header")
        (writer.paths.target / "b.o").write_bytes(b"B")
        with pytest.raises(ReconstructionMiss, match="overwritten"):
            writer.commit([product("target/b.o", "executable")])
        assert writer.state()["generation"] == generation


def test_product_interfaces_are_durably_bound_to_producer_and_content(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    record, _ = build_a(workspace, initial)
    with workspace.writer() as writer:
        refs = writer.product_interfaces(record, binding())
        assert refs[0] == {
            "producer_build_unit_id": "A", "product_id": "install/lib/liba.so",
            "kind": "library", "interface": "test:install/lib/liba.so",
            "variant": dict(record.products[0].variant), "path": "/install/lib/liba.so",
            "sha256": hashlib.sha256(b"verified-A-library").hexdigest(),
            "topology_id": "structural-topology", "recipe_revision": "recipe-A",
            "workspace_product": dict(record.reference),
        }
        assert refs[1]["kind"] == "headers"
        assert refs[1]["workspace_product"] == refs[0]["workspace_product"]
    stored = json.loads((workspace.run_dir / record.reference["path"]).read_bytes())
    assert stored["products"][0]["variant"]["abi"] == "test-abi"
    assert stored["products"][0]["interface"] == refs[0]["interface"]


@pytest.mark.parametrize("variant", [
    {}, {"configuration": "release"},
    {"configuration": "release", "target_arch": "x86", "execution_role": "invalid",
     "linkage": None, "toolchain": None, "abi": None},
])
def test_malformed_product_variant_refused(variant):
    with pytest.raises(ValueError, match="variant"):
        ProductSpec("install/a.h", "headers", "a", "include:a", variant)


def test_detached_replay_reconstructs_checkpoint_not_failed_production(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    record, generation = build_a(workspace, initial)
    with workspace.writer() as writer:
        writer.begin_attempt(binding("B", (record.identity,)), "B-failure", generation)
        (writer.paths.install / "a.h").write_bytes(b"corrupted by B")
        (writer.paths.target / "make.conf").unlink()
        production_state = writer.state()
        replay = writer.create_replay("B-recipe-candidate/opaque-id", generation)
        assert writer.state() == production_state
        assert (writer.paths.install / "a.h").read_bytes() == b"corrupted by B"
        assert not (writer.paths.target / "make.conf").exists()
    with replay.writer() as writer:
        assert writer.verify_product(record, binding()).identity == record.identity
        assert (writer.paths.target / "make.conf").read_bytes() == b"CC=prepared-cc\n"
        assert writer.paths.target_container == "/workspace"
        assert writer.paths.install_container == "/install"
        writer.begin_attempt(binding("B", (record.identity,)), "B-trial", generation)
        (writer.paths.target / "b").write_bytes(b"trial")
        writer.commit([product("target/b", "executable")])
    assert not (workspace.paths.target / "b").exists()
    assert replay.run_dir == workspace.run_dir
    assert replay.root.parent == workspace.run_dir / "workspace/build-replays"
    assert replay.root not in (workspace.run_dir / replay.owner_relative).parents
    assert replay.root not in (workspace.run_dir / record.reference["path"]).parents


def test_replay_duplicate_and_symlink_escape_are_explicitly_refused(tmp_path):
    workspace, source, initial = make_workspace(tmp_path)
    with workspace.writer() as writer:
        replay = writer.create_replay("one", initial)
        with pytest.raises(WorkspaceError, match="already exists"):
            writer.create_replay("one", initial)
    replay.root.rename(replay.root.with_name("saved"))
    replay.root.symlink_to(source, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        type(workspace)(workspace.run_dir, replay_id="one")


def test_changed_nonproduct_source_also_rejects_reuse(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    record, _ = build_a(workspace, initial)
    (workspace.paths.target / "gtest/samples/sample1.cc").write_bytes(b"changed input")
    with workspace.writer() as writer:
        with pytest.raises(ReconstructionMiss, match="uncommitted"):
            writer.verify_product(record, binding())


def test_attempt_identity_and_failure_evidence_survive_restore(tmp_path):
    workspace, _, generation = make_workspace(tmp_path)
    with workspace.writer() as writer:
        writer.begin_attempt(binding(), "A-failed-1", generation)
        writer.fail_attempt("compiler_exit_2")
        writer.restore()
        with pytest.raises(WorkspaceError, match="already used"):
            writer.begin_attempt(binding(), "A-failed-1", generation)
        intent = json.loads((workspace.run_dir / writer._attempt_path("A-failed-1", "intent")).read_bytes())
        failure = json.loads((workspace.run_dir / writer._attempt_path("A-failed-1", "failure")).read_bytes())
        recovery = json.loads((workspace.run_dir / writer._attempt_path("A-failed-1", "recovery")).read_bytes())
        assert intent["generation"] == generation
        assert intent["binding"] == binding().view()
        assert failure["reason"] == "compiler_exit_2"
        assert recovery["reason"] == "compiler_exit_2"
        writer.begin_attempt(binding(), "A-retry-2", generation)


def test_empty_declared_interface_is_not_hidden_by_another_real_product(tmp_path):
    workspace, _, generation = make_workspace(tmp_path)
    with workspace.writer() as writer:
        writer.begin_attempt(binding(), "A-1", generation)
        (writer.paths.install / "empty-headers").mkdir()
        (writer.paths.install / "library.a").write_bytes(b"A")
        with pytest.raises(WorkspaceError, match="no regular file bytes"):
            writer.commit([product("install/library.a", "library"),
                           product("install/empty-headers", "headers")])
        assert writer.state()["generation"] == generation


def test_contained_symlink_with_redundant_separators_round_trips(tmp_path):
    workspace, _, generation = make_workspace(tmp_path)
    with workspace.writer() as writer:
        writer.begin_attempt(binding(), "A-1", generation)
        (writer.paths.install / "lib").mkdir()
        (writer.paths.install / "lib/a.so.1").write_bytes(b"A")
        (writer.paths.install / "a.so").symlink_to("lib//a.so.1")
        record = writer.commit([product("install/a.so", "library")])
        writer.restore()
        assert os.readlink(writer.paths.install / "a.so") == "lib//a.so.1"
        assert writer.verify_product(record, binding()).identity == record.identity


def test_failed_build_readonly_directories_restore_without_traversing_links(tmp_path):
    workspace, source, generation = make_workspace(tmp_path)
    original_mode = source.stat().st_mode
    with workspace.writer() as writer:
        writer.begin_attempt(binding(), "A-readonly-failure", generation)
        (writer.paths.target / "external").symlink_to(source, target_is_directory=True)
        (writer.paths.target / "gtest/samples").chmod(0o000)
        writer.paths.target.chmod(0o555)
        writer.fail_attempt("destructive_permission_change")
        writer.restore()
        assert writer.paths.target.stat().st_mode & 0o700 == 0o700
        assert (writer.paths.target / "gtest/samples/sample1.cc").read_bytes() == b"int main() { return 0; }\n"
        assert not (writer.paths.target / "external").exists()
        assert source.stat().st_mode == original_mode


def test_committed_generation_verifies_durable_a_without_mutating_failed_b_tree(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    record, generation = build_a(workspace, initial)
    with workspace.writer() as writer:
        writer.begin_attempt(binding("B", (record.identity,)), "B-dirty", generation)
        (writer.paths.install / "a.h").write_bytes(b"corrupted by B")
        (writer.paths.target / "make.conf").unlink()
        (writer.paths.target / "escaping-failed-link").symlink_to("/etc")
        writer.fail_attempt("compiler_exit_2")
        state_path = workspace.run_dir / workspace.state_relative
        before_state = state_path.read_bytes()
        before_generation = (workspace.run_dir / (
            f"artifacts/build/workspace/generations/{generation}.json")).read_bytes()
        manifest = writer.committed_generation()
        assert manifest["accepted"] == {"A": dict(record.reference)}
        assert manifest["entries"]["install/a.h"]["sha256"] == hashlib.sha256(b"int a(void);\n").hexdigest()
        producer = json.loads((workspace.run_dir / manifest["accepted"]["A"]["path"]).read_bytes())
        assert producer["binding"] == binding().view()
        assert writer.committed_generation(generation) == manifest
        assert writer.committed_generation(initial)["accepted"] == {}
        assert state_path.read_bytes() == before_state
        assert (workspace.run_dir / (
            f"artifacts/build/workspace/generations/{generation}.json")).read_bytes() == before_generation
        assert (writer.paths.install / "a.h").read_bytes() == b"corrupted by B"
        assert not (writer.paths.target / "make.conf").exists()
        assert os.readlink(writer.paths.target / "escaping-failed-link") == "/etc"
        manifest["accepted"]["A"]["sha256"] = "0" * 64
        manifest["entries"]["install/a.h"]["mode"] = 0
        verified_again = writer.committed_generation()
        assert verified_again["accepted"]["A"] == record.reference
        assert verified_again["entries"]["install/a.h"]["mode"] != 0


def test_committed_generation_refuses_missing_or_changed_cas_without_mutating_dirty_tree(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    record, generation = build_a(workspace, initial)
    with workspace.writer() as writer:
        digest = writer.committed_generation()["entries"]["install/a.h"]["sha256"]
        writer.begin_attempt(binding("B", (record.identity,)), "B-interrupted", generation)
        (writer.paths.install / "a.h").write_bytes(b"dirty evidence")
        before_state = (workspace.run_dir / workspace.state_relative).read_bytes()
        retained = workspace.run_dir / f"data/shared/objects/{digest}"
        retained.write_bytes(b"tampered accepted product")
        with pytest.raises(ReconstructionMiss, match="missing or changed"):
            writer.committed_generation(generation)
        retained.unlink()
        with pytest.raises(ReconstructionMiss, match="missing or changed"):
            writer.committed_generation(generation)
        assert (workspace.run_dir / workspace.state_relative).read_bytes() == before_state
        assert (writer.paths.install / "a.h").read_bytes() == b"dirty evidence"


def test_committed_generation_requires_writer_claim(tmp_path):
    workspace, _, _ = make_workspace(tmp_path)
    with workspace.writer() as writer:
        assert writer.committed_generation()["accepted"] == {}
    with pytest.raises(WorkspaceError, match="released"):
        writer.committed_generation()


@pytest.mark.parametrize("damage", [
    "unknown_generation", "missing_generation", "tampered_generation",
    "missing_state", "tampered_state", "missing_product", "tampered_product",
])
def test_committed_generation_refuses_unknown_tampered_or_missing_retained_state(tmp_path, damage):
    workspace, _, initial = make_workspace(tmp_path)
    record, generation = build_a(workspace, initial)
    with workspace.writer() as writer:
        writer.begin_attempt(binding("B", (record.identity,)), "B-uncommitted", generation)
        (writer.paths.install / "a.h").write_bytes(b"retain failed-build evidence")
        generation_path = workspace.run_dir / f"artifacts/build/workspace/generations/{generation}.json"
        product_path = workspace.run_dir / record.reference["path"]
        state_path = workspace.run_dir / workspace.state_relative
        requested = None
        if damage == "unknown_generation":
            requested = "0" * 64
        elif damage == "missing_generation":
            generation_path.unlink()
        elif damage == "tampered_generation":
            manifest = json.loads(generation_path.read_bytes())
            manifest["accepted"].clear()
            generation_path.write_text(json.dumps(manifest))
        elif damage == "missing_state":
            state_path.unlink()
        elif damage == "tampered_state":
            state_path.write_bytes(b'{"schema":"wrong"}\n')
        elif damage == "missing_product":
            product_path.unlink()
        else:
            product_path.write_bytes(b'{"forged":"accepted-product"}\n')
        state_after_damage = state_path.read_bytes() if state_path.exists() else None
        with pytest.raises(ReconstructionMiss):
            writer.committed_generation(requested)
        assert (state_path.read_bytes() if state_path.exists() else None) == state_after_damage
        assert (writer.paths.install / "a.h").read_bytes() == b"retain failed-build evidence"


def accept_independent_nodes(workspace, initial, *, descendant=False, mutation=None):
    invocations = {}
    checkpoints = []
    records = {}
    generation = initial
    for node in ("A", "B", "C", "D") if descendant else ("A", "B", "C"):
        upstream = (records["A"].identity,) if node == "B" else (
            (records["B"].identity,) if node == "D" else ())
        with workspace.writer() as writer:
            writer.begin_attempt(binding(node, upstream), f"{node}-initial", generation)
            invocations[node] = invocations.get(node, 0) + 1
            directory = writer.paths.target / node
            directory.mkdir()
            (directory / "output").write_bytes(f"compiled-{node}".encode())
            library = writer.paths.install / f"lib{node}.a"
            library.write_bytes(f"library-{node}".encode())
            library.chmod(0o640)
            (writer.paths.install / f"lib{node}.so").symlink_to(library.name)
            if mutation:
                mutation(writer, node)
            record = writer.commit([product(f"target/{node}/output", "executable"),
                                    product(f"install/lib{node}.so", "library")])
            after = writer.state()["generation"]
            checkpoints.append((node, generation, after))
            records[node] = record
            generation = after
    return invocations, checkpoints, records


def invalidate(writer, node_ids, checkpoints, operation_id=None):
    return writer.invalidate_nodes(
        node_ids, checkpoints, operation_id=operation_id or "invalidate-" + "-".join(node_ids),
        expected_generation=writer.state()["generation"])


def test_selective_invalidation_retries_b_without_rebuilding_a_or_later_independent_c(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    invocations, checkpoints, records = accept_independent_nodes(workspace, initial)
    with workspace.writer() as writer:
        retained = {node: dict(records[node].reference) for node in ("A", "C")}
        c_metadata = (writer.paths.target / "C/output").stat()
        c_library_metadata = (writer.paths.install / "libC.a").stat()
        c_link_metadata = (writer.paths.install / "libC.so").lstat()
        operation = invalidate(writer, ["B"], checkpoints)
        generation = operation["after_generation"]
        assert writer.committed_generation()["accepted"] == retained
        assert not (writer.paths.target / "B").exists()
        assert not (writer.paths.install / "libB.a").exists()
        assert not (writer.paths.install / "libB.so").exists()
        assert (writer.paths.target / "C/output").read_bytes() == b"compiled-C"
        assert (writer.paths.target / "C/output").stat().st_mtime_ns == c_metadata.st_mtime_ns
        assert (writer.paths.install / "libC.a").stat().st_mtime_ns == c_library_metadata.st_mtime_ns
        assert (writer.paths.install / "libC.a").stat().st_mode == c_library_metadata.st_mode
        assert (writer.paths.install / "libC.so").lstat().st_mtime_ns == c_link_metadata.st_mtime_ns
        assert os.readlink(writer.paths.install / "libC.so") == "libC.a"
        assert writer.verify_product(records["A"], binding("A")) == records["A"]
        assert writer.verify_product(records["C"], binding("C")) == records["C"]
        fixed = replace(binding("B", (records["A"].identity,)), recipe_identity="recipe-B-r2")
        writer.begin_attempt(fixed, "B-fixed", generation)
        invocations["B"] += 1
        (writer.paths.target / "B").mkdir()
        (writer.paths.target / "B/output").write_bytes(b"compiled-B-r2")
        new_b = writer.commit([product("target/B/output", "executable")])
        assert writer.verify_product(new_b, fixed) == new_b
        assert writer.verify_product(records["C"], binding("C")) == records["C"]
    assert invocations == {"A": 1, "B": 2, "C": 1}
    receipts = list((workspace.run_dir / "artifacts/build/workspace/invalidations").glob("*.json"))
    assert len(receipts) == 1
    receipt = json.loads(receipts[0].read_bytes())
    assert receipt["invalid_nodes"] == ["B"]
    assert receipt["retained"] == retained


def test_selective_descendant_closure_preserves_independent_later_branch(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    invocations, checkpoints, records = accept_independent_nodes(workspace, initial, descendant=True)
    with workspace.writer() as writer:
        invalidate(writer, ["B", "D"], checkpoints)
        assert set(writer.committed_generation()["accepted"]) == {"A", "C"}
        assert not (writer.paths.target / "B").exists()
        assert not (writer.paths.target / "D").exists()
        assert writer.verify_product(records["A"], binding("A")) == records["A"]
        assert writer.verify_product(records["C"], binding("C")) == records["C"]
    assert invocations == {"A": 1, "B": 1, "C": 1, "D": 1}


def test_repeated_selective_invalidation_accepts_noncontiguous_surviving_provenance(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    invocations, checkpoints, records = accept_independent_nodes(workspace, initial)
    with workspace.writer() as writer:
        operation = invalidate(writer, ["B"], checkpoints)
        recomposed = operation["after_generation"]
        fixed = replace(binding("B", (records["A"].identity,)), recipe_identity="recipe-B-fixed")
        writer.begin_attempt(fixed, "B-fixed", recomposed)
        invocations["B"] += 1
        (writer.paths.target / "B").mkdir()
        (writer.paths.target / "B/output").write_bytes(b"new-B")
        fixed_record = writer.commit([product("target/B/output", "executable")])
        updated = [tuple(item) for item in operation["retained_checkpoints"]]
        updated.append(("B", recomposed, writer.state()["generation"]))
        invalidate(writer, ["C"], updated)
        assert set(writer.committed_generation()["accepted"]) == {"A", "B"}
        assert writer.verify_product(fixed_record, fixed) == fixed_record
        assert writer.verify_product(records["A"], binding("A")) == records["A"]
        assert not (writer.paths.target / "C").exists()
    assert invocations == {"A": 1, "B": 2, "C": 1}


def test_selective_invalidation_reconstructs_over_failed_uncommitted_attempt(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    _, checkpoints, records = accept_independent_nodes(workspace, initial)
    with workspace.writer() as writer:
        generation = writer.state()["generation"]
        writer.begin_attempt(binding("D"), "D-crashed", generation)
        (writer.paths.target / "A/output").unlink()
        (writer.paths.target / "C/output").write_bytes(b"tainted")
        (writer.paths.target / "failed-link").symlink_to("/etc")
        writer.fail_attempt("destructive-failure")
        invalidate(writer, ["B"], checkpoints)
        assert writer.verify_product(records["A"], binding("A")) == records["A"]
        assert writer.verify_product(records["C"], binding("C")) == records["C"]
        assert not (writer.paths.target / "failed-link").exists()
        assert writer.state()["attempt"] is None


@pytest.mark.parametrize("overlap", ["same_file", "shared_directory"])
def test_overlapping_invalid_retained_mutations_refuse_without_touching_state(tmp_path, overlap):
    workspace, _, initial = make_workspace(tmp_path)

    def mutation(writer, node):
        if node not in {"B", "C"}:
            return
        if overlap == "same_file":
            (writer.paths.target / "shared.conf").write_bytes(node.encode())
        else:
            shared = writer.paths.target / "shared"
            if node == "B":
                shared.mkdir()
            else:
                (shared / "C-generated").write_bytes(b"C")

    _, checkpoints, _ = accept_independent_nodes(workspace, initial, mutation=mutation)
    with workspace.writer() as writer:
        before_state = (workspace.run_dir / workspace.state_relative).read_bytes()
        with pytest.raises(ReconstructionMiss, match="overlapping"):
            invalidate(writer, ["B"], checkpoints)
        assert (workspace.run_dir / workspace.state_relative).read_bytes() == before_state
        assert (writer.paths.target / "B/output").read_bytes() == b"compiled-B"
        assert (writer.paths.target / "C/output").read_bytes() == b"compiled-C"


def test_incomplete_descendant_closure_refuses_dangling_upstream_without_mutation(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    _, checkpoints, _ = accept_independent_nodes(workspace, initial, descendant=True)
    with workspace.writer() as writer:
        state = writer.state()
        with pytest.raises(ReconstructionMiss, match="missing or unordered upstream"):
            invalidate(writer, ["B"], checkpoints)
        assert writer.state() == state
        assert (writer.paths.target / "D/output").read_bytes() == b"compiled-D"


@pytest.mark.parametrize("damage", ["missing", "unknown", "duplicate", "wrong_transition", "wrong_order"])
def test_selective_invalidation_refuses_incomplete_or_unproven_checkpoint_inputs(tmp_path, damage):
    workspace, _, initial = make_workspace(tmp_path)
    _, checkpoints, _ = accept_independent_nodes(workspace, initial)
    if damage == "missing":
        checkpoints = checkpoints[:-1]
    elif damage == "unknown":
        checkpoints[-1] = ("C", checkpoints[-1][1], "0" * 64)
    elif damage == "duplicate":
        checkpoints.append(checkpoints[0])
    elif damage == "wrong_transition":
        checkpoints[-1] = ("C", initial, checkpoints[-1][2])
    else:
        checkpoints[0], checkpoints[1] = checkpoints[1], checkpoints[0]
    with workspace.writer() as writer:
        state = writer.state()
        with pytest.raises(ReconstructionMiss):
            invalidate(writer, ["B"], checkpoints)
        assert writer.state() == state
        assert (writer.paths.target / "B/output").read_bytes() == b"compiled-B"


def test_selective_invalidation_restores_invalid_node_input_deletion_and_mutation_metadata(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    original = (workspace.paths.target / "gtest/samples/sample1.cc").stat()

    def mutation(writer, node):
        if node == "B":
            (writer.paths.target / "gtest/samples/sample1.cc").unlink()
            (writer.paths.target / "make.conf").write_bytes(b"B-only config")
            (writer.paths.target / "make.conf").chmod(0o600)
        if node == "C":
            (writer.paths.target / "C/config-link").symlink_to("../C/output")

    _, checkpoints, records = accept_independent_nodes(workspace, initial, mutation=mutation)
    with workspace.writer() as writer:
        invalidate(writer, ["B"], checkpoints)
        restored = writer.paths.target / "gtest/samples/sample1.cc"
        assert restored.read_bytes() == b"int main() { return 0; }\n"
        assert restored.stat().st_mode == original.st_mode
        assert restored.stat().st_mtime_ns == original.st_mtime_ns
        assert (writer.paths.target / "make.conf").read_bytes() == b"CC=cc\n"
        assert os.readlink(writer.paths.target / "C/config-link") == "../C/output"
        assert writer.verify_product(records["C"], binding("C")) == records["C"]


@pytest.mark.parametrize("when", ["during_restore", "after_commit"])
def test_selective_invalidation_crash_reopen_exact_retry_is_idempotent(tmp_path, monkeypatch, when):
    workspace, _, initial = make_workspace(tmp_path)
    _, checkpoints, records = accept_independent_nodes(workspace, initial)
    operation_id = "B-change-durable-operation"
    with workspace.writer() as writer:
        before = writer.state()["generation"]
        if when == "during_restore":
            actual_write = writer._write_state

            def crash(value):
                if value["condition"] == "clean":
                    raise OSError("crash before committed pointer")
                actual_write(value)

            monkeypatch.setattr(writer, "_write_state", crash)
        else:
            actual_restore = writer.restore

            def crash(identity=None):
                actual_restore(identity)
                raise OSError("crash after committed pointer but before caller ledger")

            monkeypatch.setattr(writer, "restore", crash)
        with pytest.raises(OSError, match="crash"):
            writer.invalidate_nodes(["B"], checkpoints, operation_id=operation_id, expected_generation=before)
    reopened = type(workspace)(workspace.run_dir)
    with reopened.writer() as writer:
        result = writer.invalidate_nodes(
            ["B"], checkpoints, operation_id=operation_id, expected_generation=before)
        assert writer.state()["generation"] == result["after_generation"]
        assert writer.verify_product(records["A"], binding("A")) == records["A"]
        assert writer.verify_product(records["C"], binding("C")) == records["C"]
        assert not (writer.paths.install / "libB.a").exists()
        state_bytes = (workspace.run_dir / workspace.state_relative).read_bytes()
        receipt_files = list((workspace.run_dir / "artifacts/build/workspace/invalidations").glob("*.json"))
        repeated = writer.invalidate_nodes(
            ["B"], checkpoints, operation_id=operation_id, expected_generation=before)
        assert repeated == result
        assert (workspace.run_dir / workspace.state_relative).read_bytes() == state_bytes
        assert list((workspace.run_dir / "artifacts/build/workspace/invalidations").glob("*.json")) == receipt_files
        repeated["retained"]["A"]["sha256"] = "0" * 64
        assert writer.invalidate_nodes(
            ["B"], checkpoints, operation_id=operation_id, expected_generation=before) == result


@pytest.mark.parametrize("newer", ["committed", "running", "untracked"])
def test_stale_invalidation_retry_never_removes_newer_work(tmp_path, newer):
    workspace, _, initial = make_workspace(tmp_path)
    _, checkpoints, _ = accept_independent_nodes(workspace, initial)
    with workspace.writer() as writer:
        before = writer.state()["generation"]
        result = writer.invalidate_nodes(
            ["B"], checkpoints, operation_id="B-change", expected_generation=before)
        if newer != "untracked":
            writer.begin_attempt(binding("D"), "newer-D", result["after_generation"])
        (writer.paths.target / "newer-output").write_bytes(b"must not delete")
        if newer == "committed":
            writer.commit([product("target/newer-output", "executable")])
        state = (workspace.run_dir / workspace.state_relative).read_bytes()
        with pytest.raises(ReconstructionMiss, match="newer|uncommitted"):
            writer.invalidate_nodes(["B"], checkpoints, operation_id="B-change", expected_generation=before)
        assert (writer.paths.target / "newer-output").read_bytes() == b"must not delete"
        assert (workspace.run_dir / workspace.state_relative).read_bytes() == state


@pytest.mark.parametrize("damage", ["cas", "product_ref", "generation", "operation_ref"])
def test_selective_invalidation_integrity_failure_preserves_working_tree(tmp_path, damage):
    workspace, _, initial = make_workspace(tmp_path)
    _, checkpoints, records = accept_independent_nodes(workspace, initial)
    with workspace.writer() as writer:
        before = writer.state()["generation"]
        if damage == "cas":
            digest = writer.committed_generation()["entries"]["install/libC.a"]["sha256"]
            (workspace.run_dir / f"data/shared/objects/{digest}").write_bytes(b"changed")
        elif damage == "product_ref":
            (workspace.run_dir / records["C"].reference["path"]).unlink()
        elif damage == "generation":
            (workspace.run_dir / f"artifacts/build/workspace/generations/{checkpoints[1][1]}.json").unlink()
        else:
            writer.invalidate_nodes(["B"], checkpoints, operation_id="B-change", expected_generation=before)
            operation = next((workspace.run_dir / (
                "artifacts/build/workspace/invalidations/operations")).iterdir())
            operation.write_bytes(b'{"receipt":{"path":"../../external","sha256":"wrong"}}\n')
        state = (workspace.run_dir / workspace.state_relative).read_bytes()
        c_bytes = (writer.paths.install / "libC.a").read_bytes()
        with pytest.raises((ReconstructionMiss, WorkspaceError)):
            writer.invalidate_nodes(["B"], checkpoints, operation_id="B-change", expected_generation=before)
        assert (workspace.run_dir / workspace.state_relative).read_bytes() == state
        assert (writer.paths.install / "libC.a").read_bytes() == c_bytes


def test_invalidation_operation_identity_and_expected_generation_are_not_reusable_for_different_request(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    _, checkpoints, _ = accept_independent_nodes(workspace, initial)
    with workspace.writer() as writer:
        before = writer.state()["generation"]
        with pytest.raises(ReconstructionMiss, match="expected generation"):
            writer.invalidate_nodes(["B"], checkpoints, operation_id="wrong-base", expected_generation=initial)
        writer.invalidate_nodes(["B"], checkpoints, operation_id="B-change", expected_generation=before)
        state = writer.state()
        with pytest.raises(ReconstructionMiss, match="different request"):
            writer.invalidate_nodes(["C"], checkpoints, operation_id="B-change", expected_generation=before)
        assert writer.state() == state


def test_selective_invalidation_refuses_unknown_live_mutations_without_deleting_them(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    _, checkpoints, _ = accept_independent_nodes(workspace, initial)
    with workspace.writer() as writer:
        (writer.paths.target / "unknown-generated-input").write_bytes(b"not owned by an attempt")
        before_state = (workspace.run_dir / workspace.state_relative).read_bytes()
        with pytest.raises(ReconstructionMiss, match="untracked"):
            invalidate(writer, ["B"], checkpoints)
        assert (workspace.run_dir / workspace.state_relative).read_bytes() == before_state
        assert (writer.paths.target / "unknown-generated-input").read_bytes() == b"not owned by an attempt"
        assert (writer.paths.target / "B/output").read_bytes() == b"compiled-B"


def test_selective_invalidation_refuses_current_durable_mutations_without_node_provenance(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    _, checkpoints, _ = accept_independent_nodes(workspace, initial)
    with workspace.writer() as writer:
        # Model a durable state publication not backed by a ledger node transition.
        original = writer.committed_generation()
        (writer.paths.target / "undeclared-input").write_bytes(b"no node provenance")
        entries = writer._capture()
        invalid_generation = writer._publish_generation(entries, dict(original["accepted"]),
                                                         original["input_identity"])
        state = writer.state()
        state["generation"] = invalid_generation
        writer._write_state(state)
        before_state = (workspace.run_dir / workspace.state_relative).read_bytes()
        with pytest.raises(ReconstructionMiss, match="outside the supplied checkpoints"):
            invalidate(writer, ["B"], checkpoints)
        assert (workspace.run_dir / workspace.state_relative).read_bytes() == before_state
        assert (writer.paths.target / "undeclared-input").read_bytes() == b"no node provenance"


def test_selective_invalidation_refuses_unknown_ids_without_mutation(tmp_path):
    workspace, _, initial = make_workspace(tmp_path)
    _, checkpoints, _ = accept_independent_nodes(workspace, initial)
    with workspace.writer() as writer:
        before_state = writer.state()
        with pytest.raises(ReconstructionMiss, match="not in the committed"):
            invalidate(writer, ["unknown-node"], checkpoints)
        assert writer.state() == before_state
