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
