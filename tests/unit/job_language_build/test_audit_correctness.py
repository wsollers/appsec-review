"""Offline regressions for T-5147 through T-5150; no compiler or container is run."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.config.build_selection import parse_build_selection
from appsec_review.jobs.build_topology_artifacts import bind_actions
from appsec_review.jobs.job_language_build import capture, dotnet, job, jvm, native, rust
from appsec_review.retrieval.index import load_verified_manifest, write_manifest
from appsec_review.storage import file_sha256
from tests.accepted_topology_fixture import accept_isolated_dispatch
from tests.capture_fakes import simulated_executor
from tests.unit.job_language_build import support
from tests.unit.job_language_build.test_captured_build_reconciliation import Capture, _call, _exec


def _jvm_receipt():
    return {
        "build_unit_id": "build-unit-" + "1" * 20, "family": "java", "build_system": "maven",
        "image": {"image_id": "sha256:" + "5" * 64}, "fingerprint": "a" * 64,
        "commands": [{"command_id": "old-command", "ordinal": 1, "tool": "mvn",
                      "tool_kind": "build-driver", "argv_sha256": "b" * 64}],
        "tool_invocations": [{"ordinal": 1, "tool": "javac", "tool_kind": "compiler",
                              "parent_command_id": "old-command", "argv_sha256": "c" * 64}],
        "declared_compilations": [{"ordinal": 1, "tool": "javac", "tool_kind": "compiler",
                                  "parent_command_id": "old-command", "task_path": ":compileJava"}],
        "artifacts": [{"workspace_path": "target/App.class", "sha256": "d" * 64,
                       "size_bytes": 4, "kind": "jvm-class", "build_unit_id": "build-unit-" + "1" * 20,
                       "mapping": "exact-workspace-path", "mapping_confidence": 1.0}],
        "terminal_status": "SUCCEEDED", "gaps": [],
    }


def _index_rows(root, indexed):
    with sqlite3.connect(root / indexed["identity"]["relative_path"]) as database:
        return database.execute("SELECT payload_json FROM entities ORDER BY identity").fetchall(), \
            database.execute("SELECT * FROM coverage").fetchall()


@pytest.mark.parametrize("change", ["command", "invocation", "declaration", "coverage", "artifact-path"])
def test_jvm_same_artifact_bytes_do_not_reuse_changed_indexed_facts(tmp_path, change):
    unit = support.unit_context(tmp_path, "execute.java")
    receipt = _jvm_receipt()
    before = jvm._index(unit, receipt)
    original_rows = _index_rows(unit.job.run_root, before)
    changed = deepcopy(receipt)
    if change == "command":
        changed["commands"][0].update(command_id="new-command", argv_sha256="e" * 64)
        changed["tool_invocations"][0]["parent_command_id"] = "new-command"
        changed["declared_compilations"][0]["parent_command_id"] = "new-command"
    elif change == "invocation":
        changed["tool_invocations"][0]["argv_sha256"] = "e" * 64
    elif change == "declaration":
        changed["declared_compilations"][0]["task_path"] = ":compileOther"
    elif change == "coverage":
        changed.update(gaps=["compiler provenance incomplete"], terminal_status="COMPLETED_WITH_GAPS")
    else:
        changed["artifacts"][0]["workspace_path"] = "other/App.class"
    after = jvm._index(unit, changed)
    assert after["identity"]["fingerprint"] != before["identity"]["fingerprint"]
    assert after["reused"] is False
    assert _index_rows(unit.job.run_root, after) != original_rows
    assert _index_rows(unit.job.run_root, before) == original_rows
    assert jvm._index(unit, changed)["reused"] is True


@pytest.mark.parametrize("damage", ["none", "hash", "shard", "target"])
def test_publication_composes_and_verifies_actual_jvm_shards(tmp_path, damage):
    unit = support.unit_context(tmp_path, "acceptance.publish_handoff")
    root = unit.job.run_root
    manifest = root / "data" / "indices" / "input.json"
    write_manifest(manifest, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                   target_root=unit.job.target_root, indexes=[])
    unit.job.input_manifest_path, unit.job.input_manifest_sha256 = manifest, file_sha256(manifest)
    receipt = _jvm_receipt()
    if damage == "target":
        unit.job.source_fingerprint = "0" * 64
    receipt["retrieval_index"] = jvm._index(unit, receipt)
    unit.job.source_fingerprint = support.SOURCE_FINGERPRINT
    identity = receipt["retrieval_index"]["identity"]
    if damage == "hash":
        identity["sha256"] = "0" * 64
    elif damage == "shard":
        identity["shard_id"] = "jvm-other"
    if damage != "none":
        with pytest.raises(ValueError):
            job._publish_build_index(unit, [receipt])
        return
    published = job._publish_build_index(unit, [receipt])
    document, _ = load_verified_manifest(root, root / published["path"], published["sha256"])
    assert {row["shard_id"] for row in document["indexes"]} == {
        "language-build", "jvm-" + receipt["build_unit_id"]}
    assert next(row for row in document["indexes"] if row["shard_id"].startswith("jvm-")) == {
        **identity, "gaps": list(identity["gaps"])}
    assert any("javac" in row[0] for row in _index_rows(root, receipt["retrieval_index"])[0])


def test_publication_replaces_prior_jvm_revision_and_preserves_unrelated_shards(tmp_path):
    unit = support.unit_context(tmp_path, "acceptance.publish_handoff")
    root = unit.job.run_root
    receipt = _jvm_receipt()
    before = jvm._index(unit, receipt)
    sibling = {**_jvm_receipt(), "build_unit_id": "build-unit-" + "2" * 20}
    sibling_index = jvm._index(unit, sibling)
    from appsec_review.retrieval.index import IndexIdentity
    manifest = root / "data" / "indices" / "input.json"
    write_manifest(manifest, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                   target_root=unit.job.target_root,
                   indexes=[IndexIdentity(**value["identity"]) for value in (before, sibling_index)])
    unit.job.input_manifest_path, unit.job.input_manifest_sha256 = manifest, file_sha256(manifest)
    receipt["tool_invocations"][0]["argv_sha256"] = "e" * 64
    receipt["retrieval_index"] = jvm._index(unit, receipt)
    published = job._publish_build_index(unit, [receipt])
    document, _ = load_verified_manifest(root, root / published["path"], published["sha256"])
    indexes = {value["shard_id"]: value for value in document["indexes"]}
    assert len(indexes) == 3
    assert indexes[before["identity"]["shard_id"]]["sha256"] == receipt["retrieval_index"]["identity"]["sha256"]
    assert indexes[before["identity"]["shard_id"]]["sha256"] != before["identity"]["sha256"]
    assert indexes[sibling_index["identity"]["shard_id"]]["sha256"] == sibling_index["identity"]["sha256"]


def _execution(tmp_path, family, command, *, files=None, options=None):
    defaults = {
        "dotnet": ("dotnet", "App.csproj", '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                   '<TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>'),
        "php": ("composer", "composer.json", '{"name":"example/app"}'),
        "rust": ("cargo", "Cargo.toml", '[package]\nname="app"\nversion="0.1.0"\n'
                 '[lib]\npath="src/lib.rs"\n'),
        "go": ("go", "go.mod", "module example.test/app\n\ngo 1.23\n"),
        "python": ("pyproject", "pyproject.toml", '[build-system]\nbuild-backend="setuptools.build_meta"\n'),
        "node": ("node", "package.json", '{"name":"app","scripts":{"build":"tsc"}}'),
    }
    system, descriptor, contents = defaults[family]
    target = tmp_path / "target"
    target.mkdir()
    source_files = {descriptor: contents, **(files or {})}
    for relative, content in source_files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    config = support.real_job()
    if options:
        typed = replace(config.typed_settings, **{
            family: replace(getattr(config.typed_settings, family), **options)})
        settings = {**config.settings, family: {**config.settings[family], **options}}
        config = replace(config, typed_settings=typed, settings=settings)
    dispatch = support.dispatch("build-unit-" + "1" * 20, family, build_system=system, commands=[command])
    dispatch.pop("descriptor_package")
    dispatch["source_fingerprint"] = source_fingerprint(target)
    dispatch["build_variant"] = {"configuration": "release", "target_arch": "x86_64",
                                  "execution_role": "target", "linkage": "static",
                                  "toolchain": "fixture/1", "abi": "linux-gnu"}
    environment = {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"} if family == "go" else {}
    dispatch["recipe"].update(schema="appsec-review/build-recipe/1", build_unit_id=dispatch["build_unit_id"],
                              image_profile=family, system_packages=[], reason="offline regression",
                              environment=environment, dependency_files=list(source_files),
                              expected_outputs=["build"], network_required=False)
    dispatch["image"].update(image_tag=family + ":test", user="1000:1000",
                             dependency_hashes={name: file_sha256(target / name) for name in source_files})
    root, dispatch = accept_isolated_dispatch(tmp_path / "admission", target, dispatch,
                                              list(source_files), releases=support.RELEASES)
    if family == "go":
        policy = parse_build_selection({
            "schema": "appsec-review/build-selection-policy/1", "policy_id": "fixture/1",
            "ambiguity_policy": "block", "rules": [{
                "selectors": {"build_system": system}, "axes": {"os": "linux", "isa": "x86_64"},
                "provenance": "synthetic offline test"}]})
        dispatch, = bind_actions(root, [dispatch], policy=policy.view(), releases=support.RELEASES)
    unit = support.unit_context(tmp_path, "execute." + family, target_root=target, run_root=root,
                                config=config, source_fingerprint=dispatch["source_fingerprint"])
    job._validate_config(unit.job, None)
    return unit, dispatch


def _execute(unit, dispatch, calls):
    def behavior(argv, workspace, cwd, environment, simulator):
        calls.append(tuple(argv))
        simulator.exec("/usr/bin/" + argv[0], argv)
        if argv[:2] == ("cargo", "metadata"):
            return 0, b'{"version":1,"packages":[]}', b""
        if dispatch["family"] == "rust":
            simulator.exec("/usr/bin/rustc", ["rustc", "--crate-name", "app", "src/lib.rs"])
        output = workspace / "build" / "result.txt"
        output.parent.mkdir(exist_ok=True)
        output.write_bytes(b"fixture")
        return 0, b"output", b""
    return job._execute_one(unit, dispatch, support.accepted(dispatch),
                           lambda _unit, profile: simulated_executor(profile, behavior))


def test_rust_execution_keeps_metadata_options_separate_from_build(tmp_path):
    settings = replace(support.real_job().typed_settings.rust,
                       target="x86_64-unknown-linux-gnu", profile="release", locked=True)
    recipe = {"configure_commands": [], "build_commands": [["cargo", "build"]],
              "dependency_files": ["Cargo.toml", "Cargo.lock"]}
    assert not rust.validate_dispatch({"build_system": "cargo", "recipe": recipe}, settings)
    metadata = rust.build_argv(rust.metadata_argv(recipe, settings), settings)
    build = rust.build_argv(recipe["build_commands"][0], settings)
    assert metadata[:2] == ("cargo", "metadata")
    assert "--target" not in metadata and "--profile" not in metadata and "-vv" not in metadata
    assert build[build.index("--target") + 1] == "x86_64-unknown-linux-gnu"
    assert build[build.index("--profile") + 1] == "release"
    assert "--locked" in metadata and "--locked" in build


@pytest.mark.parametrize("policy,command", [
    ("allow_publish", ["dotnet", "publish", "App.csproj"]),
    ("allow_pack", ["dotnet", "pack", "App.csproj"]),
], ids=["publish", "pack"])
@pytest.mark.parametrize("allowed", [False, True])
def test_dotnet_execution_obeys_frozen_operation_policy(tmp_path, policy, command, allowed):
    unit, dispatch = _execution(tmp_path, "dotnet", command, options={policy: allowed})
    calls = []
    receipt = _execute(unit, dispatch, calls)
    if allowed:
        assert calls and receipt["commands"]
    else:
        assert calls == [] and receipt["commands"] == []
        assert receipt["terminal_status"] == "BLOCKED"
        assert any(policy in str(gap) for gap in receipt["gaps"])


@pytest.mark.parametrize("required,lock", [
    (False, "absent"), (True, "absent"), (True, "accepted"), (True, "unbound"), (True, "changed"),
], ids=["unlocked", "required-missing", "locked", "unbound", "changed"])
def test_php_execution_requires_admitted_lock_bytes_only_when_configured(tmp_path, required, lock):
    files = {} if lock == "absent" else {"composer.lock": '{"packages":[],"packages-dev":[]}'}
    unit, dispatch = _execution(tmp_path, "php", ["composer", "install"], files=files,
                                options={"require_lockfile": required})
    if lock == "unbound":
        dispatch["image"]["dependency_hashes"].pop("composer.lock")
    elif lock == "changed":
        dispatch["image"]["dependency_hashes"]["composer.lock"] = "0" * 64
    calls = []
    if required and lock != "accepted":
        with pytest.raises(ValueError, match="composer.lock"):
            _execute(unit, dispatch, calls)
        assert calls == []
    else:
        receipt = _execute(unit, dispatch, calls)
        assert calls and receipt["composer_policy"]["require_lockfile"] is required
        assert "--no-plugins" in calls[0]
        assert receipt["composer"]["root_package"] == "example/app"


@pytest.mark.parametrize("command,policy", [
    (["dotnet", "publish", "-p:PublishAot=true"], "allow_aot"),
    (["dotnet", "publish", "/property:NativeAot=true"], "allow_aot"),
    (["dotnet", "msbuild", "/t:Build;Publish"], "allow_publish"),
    (["msbuild", "-target:Pack"], "allow_pack"),
    (["dotnet", "publish", "--property", "PublishAot=true"], "allow_aot"),
], ids=["aot", "aot-long-option", "publish-target", "pack-target", "aot-separate"])
@pytest.mark.parametrize("allowed", [False, True])
def test_dotnet_policy_covers_msbuild_targets_and_aot_properties(command, policy, allowed):
    settings = replace(support.real_job().typed_settings.dotnet, **{policy: allowed})
    errors = dotnet.validate_recipe({"configure_commands": [], "build_commands": [command]},
                                    settings=settings)
    assert bool(errors) is not allowed
    if not allowed:
        assert any(policy in error for error in errors)


@pytest.mark.parametrize("allowed", [False, True])
def test_dotnet_policy_checks_selected_aot_operation_from_project(allowed):
    settings = replace(support.real_job().typed_settings.dotnet, allow_aot=allowed)
    errors = dotnet.validate_recipe({"build_commands": [["dotnet", "publish", "App.csproj"]]},
                                    settings=settings, operations=[{"kind": "native_aot"}])
    assert bool(errors) is not allowed


def test_dotnet_policy_does_not_forbid_explicitly_disabled_aot():
    settings = replace(support.real_job().typed_settings.dotnet, allow_aot=False)
    assert not dotnet.validate_recipe(
        {"build_commands": [["dotnet", "publish", "-p:PublishAot=false"]]}, settings=settings)


@pytest.mark.parametrize("with_wrapper", [False, True])
def test_capture_preserves_equal_argv_in_different_cwds(tmp_path, with_wrapper):
    argv = ["clang", "-c", "main.c", "-o", "main.o"]
    events = []
    for index, directory in enumerate(("a", "b"), 1):
        (tmp_path / directory).mkdir()
        (tmp_path / directory / "main.c").write_text("int main(){}")
        (tmp_path / directory / "main.o").write_bytes(b"object")
        events.extend([
            {"kind": "directory_change", "pid": index, "ordinal": index * 2 - 1,
             "path": "/workspace/" + directory, "result": 0},
            {**_exec("/usr/bin/clang", argv, ordinal=index * 2), "pid": index},
        ])
    calls = [_call("clang", argv)] if with_wrapper else []
    observed = Capture(events, calls=calls)
    result = capture.reconcile_captured_build([(1, observed)], tmp_path, ".", native.CAPTURE_DESCRIPTOR)
    assert len(result.rows) == 2
    assert {row["working_directory"] for row in result.rows} == {"a", "b"}
    assert {value["workspace_path"] for row in result.rows for value in row["outputs"]} == {"a/main.o", "b/main.o"}
    assert all(row["evidence"]["process_exec"]["count"] == 1 for row in result.rows)
    if with_wrapper:
        assert all(row["evidence"]["tool_call"] is None for row in result.rows)
        assert result.facts["unreconciled_tool_calls"] == 1
    else:
        assert not result.gaps


def test_optional_link_metadata_does_not_overwrite_another_cwd(tmp_path):
    argv = ["clang", "main.o", "-o", "app"]
    events = []
    for index, directory in enumerate(("a", "b"), 1):
        (tmp_path / directory).mkdir()
        (tmp_path / directory / "main.o").write_bytes(b"object")
        (tmp_path / directory / "app").write_bytes(directory.encode())
        events.extend([
            {"kind": "directory_change", "pid": index, "ordinal": 2 * index - 1,
             "path": "/workspace/" + directory, "result": 0},
            {**_exec("/usr/bin/clang", argv, ordinal=2 * index), "pid": index},
        ])
    link = tmp_path / "a" / "CMakeFiles" / "app.dir" / "link.txt"
    link.parent.mkdir(parents=True)
    link.write_text("clang main.o -o app\n")
    observed = capture.reconcile_captured_build([(1, Capture(events))], tmp_path, ".", native.CAPTURE_DESCRIPTOR)
    assert not job._apply_native_link_metadata(observed.rows, tmp_path, ".", "a")
    assert len(observed.rows) == 2
    first, second = observed.rows
    assert first["outputs"][0]["workspace_path"] == "a/app"
    assert first["metadata_origin"] == "a/CMakeFiles/app.dir/link.txt"
    assert second["outputs"][0]["workspace_path"] == "b/app"
    assert second["outputs"][0]["sha256"] == file_sha256(tmp_path / "b" / "app")
    assert "metadata_origin" not in second


@pytest.mark.parametrize("family,command", [
    ("go", ["go", "build", "."]), ("node", ["npm", "run", "build"]),
    ("python", ["python3", "-m", "build"]), ("php", ["composer", "install"]),
])
def test_every_configured_generic_family_retains_byte_bounded_diagnostic_tail(tmp_path, family, command):
    files = {"Cargo.lock": "version = 3\n", "src/lib.rs": ""} if family == "rust" else None
    unit, dispatch = _execution(tmp_path, family, command, files=files, options={"diagnostic_tail_bytes": 7})
    data = ("diagnostic é\n" * 12).encode()

    def behavior(argv, workspace, cwd, environment, simulator):
        simulator.exec("/usr/bin/" + argv[0], argv)
        return 1, data, data

    receipt = job._execute_one(unit, dispatch, support.accepted(dispatch),
                               lambda _unit, profile: simulated_executor(profile, behavior, output_bytes=8))
    for name in ("stdout", "stderr"):
        stream = receipt["commands"][0][name]
        assert (unit.job.run_root / stream["path"]).read_bytes() == data
        tail = stream["diagnostic_tail"]
        assert (unit.job.run_root / tail["path"]).read_bytes() == data[-7:]
        assert tail["size_bytes"] == 7
        assert tail["sha256"] == hashlib.sha256(data[-7:]).hexdigest()


@pytest.mark.parametrize("limit", [0, 3, 64])
def test_truncated_preview_tail_honors_configured_byte_limit(tmp_path, limit):
    path = tmp_path / "stdout"
    path.write_bytes(b"head")
    result = SimpleNamespace(stdout=b"head", stdout_bytes=100, stdout_truncated=True,
                              stdout_tail=b"end-of-diagnostic")
    stream = job._stream_identity(tmp_path, path, result, "stdout", 4, tail_limit=limit)
    if limit:
        tail = stream["diagnostic_tail"]
        assert (tmp_path / tail["path"]).read_bytes() == result.stdout_tail[-limit:]
    else:
        assert "diagnostic_tail" not in stream


def test_rust_diagnostics_can_retain_more_than_the_executor_preview_tail(tmp_path):
    settings = replace(support.real_job().typed_settings.rust, diagnostic_tail_bytes=40000)
    data = b"x" * 42000 + b"compiler failure"
    complete = tmp_path / "captured"
    complete.write_bytes(data)
    retained = tmp_path / "stderr"
    retained.write_bytes(data[:8])
    result = SimpleNamespace(stderr=data[:8], stderr_file=complete, stderr_truncated=True,
                              stderr_tail=data[-8:])
    identity = job._stream_identity(tmp_path, retained, result, "stderr", 8,
                                    tail_limit=settings.diagnostic_tail_bytes)
    assert retained.read_bytes() == data
    assert (tmp_path / identity["diagnostic_tail"]["path"]).read_bytes() == data[-40000:]
