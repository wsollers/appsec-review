"""Unit tests for job_language_build/job.py and jvm.py execution lanes, dispatch guards, checkpoints, and indexing."""

from __future__ import annotations

from dataclasses import make_dataclass
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
import zipfile

import pytest

from appsec_review.applicability import (
    DECISION_SCHEMA, ApplicabilityAction, ApplicabilityDecision, ProcessingFeature, ReasonCode,
)
from appsec_review.container_runtime import BuildCommandResult, BuildProfile
from appsec_review.container_runtime.project_images import project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import job as lb_job, jvm
from appsec_review.retrieval import write_manifest
from appsec_review.runtime import consume
from appsec_review.runtime.contracts import InputRequirement, JobContract
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from tests.capture_fakes import minimal_elf, minimal_go_elf, simulated_executor
from tests.handoff_fixture import write_fixture_handoff
from tests.unit.job_language_build import support


def _make_exec_result(
    argv: tuple[str, ...],
    *,
    exit_code: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    timed_out: bool = False,
) -> BuildCommandResult:
    return BuildCommandResult(
        argv=argv,
        working_directory=".",
        image_id="sha256:" + "5" * 64,
        exit_code=exit_code,
        timed_out=timed_out,
        duration_ms=5,
        stdout=stdout,
        stderr=stderr,
        cleanup_complete=True,
    )


def test_load_accepted_language_build_and_stream_and_metadata_helpers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sub1 = tmp_path / "s1"
    run_root = sub1 / "run"
    unit = support.unit_context(sub1, "acceptance.publish_handoff")
    receipt = {
        "build_unit_id": "build-unit-" + "1" * 20,
        "terminal_status": "SUCCEEDED",
        "gaps": [],
    }
    identity = lb_job._artifact(
        unit, "accepted-language-builds.json",
        {"schema": lb_job.SCHEMA, "receipts": [receipt], "gaps": []},
    )
    (run_root / "data" / "configuration" / "resolved.json").unlink(missing_ok=True)
    handoff_path = write_fixture_handoff(
        run_root,
        run_root / "data" / "jobs" / "job_language_build" / "attempts" / "attempt_0001" / "handoff.json",
        {
            "job_id": "job_language_build",
            "attempt_id": "attempt_0001",
            "outputs": {
                "acceptance.publish_handoff": {
                    "schema": lb_job.SCHEMA,
                    "output_kind": "language_build_receipts",
                    "terminal_status": "SUCCEEDED",
                    "artifact": identity,
                    "gaps": [],
                },
            },
        },
        target_snapshot=support.SOURCE_FINGERPRINT,
    )
    handoff_sha = file_sha256(handoff_path)
    atomic_json(
        run_root / "data" / "jobs" / "job_language_build" / "latest.json",
        {
            "schema": "appsec-review/latest-handoff/1",
            "attempt_id": "attempt_0001",
            "handoff_path": handoff_path.relative_to(run_root).as_posix(),
            "handoff_sha256": handoff_sha,
        },
    )
    guarded: list[str] = []
    monkeypatch.setattr(
        "appsec_review.jobs.build_topology_artifacts.guard_cache_action",
        lambda _rr, r, **_kw: guarded.append(r["build_unit_id"]),
    )
    req = (
        InputRequirement("job_language_build", "handoff", "appsec-review/job-handoff/2"),
        InputRequirement("job_language_build", "language_build_receipts", lb_job.SCHEMA),
    )
    with consume.upstream_scope(
        run_root,
        "job_artifact_indexing",
        {"job_language_build": handoff_sha},
        contract=JobContract(inputs=req),
    ):
        with pytest.raises(ValueError, match="must be explicit"):
            lb_job.load_accepted_language_build(run_root, for_execution="yes")  # type: ignore[arg-type]
        loaded = lb_job.load_accepted_language_build(run_root, for_execution=True)
        assert loaded["receipts"][0]["build_unit_id"] == receipt["build_unit_id"]
        assert guarded == [receipt["build_unit_id"]]

    # _stream_identity complete_file and truncated tail branches
    complete_src = tmp_path / "complete.out"
    complete_src.write_bytes(b"full stream payload\n")
    dest1 = run_root / "data" / "build" / "logs" / "001.stdout"
    dest1.parent.mkdir(parents=True, exist_ok=True)
    dest1.write_bytes(b"full")
    res_complete = SimpleNamespace(
        stdout=b"full", stdout_file=complete_src, stdout_truncated=True,
    )
    st_complete = lb_job._stream_identity(run_root, dest1, res_complete, "stdout", 1024)
    assert st_complete["storage"] == "complete-file" and st_complete["preview_truncated"] is True

    dest2 = run_root / "data" / "build" / "logs" / "002.stdout"
    dest2.write_bytes(b"head")
    res_tail = SimpleNamespace(
        stdout=b"head", stdout_bytes=100, stdout_truncated=True, stdout_tail=b"tail-diagnostics",
    )
    st_tail = lb_job._stream_identity(run_root, dest2, res_tail, "stdout", 4)
    assert st_tail["truncated"] is True and "diagnostic_tail" in st_tail
    assert (run_root / st_tail["diagnostic_tail"]["path"]).read_bytes() == b"tail-diagnostics"

    # _compile_rows, _link_rows, _apply_native_link_metadata, _workspace_path
    ws = tmp_path / "native_ws"
    (ws / "build" / "CMakeFiles" / "app.dir").mkdir(parents=True)
    (ws / "src.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    assert lb_job._compile_rows(ws, ".", "build")[1] == [
        "compile database was not emitted; compiler-to-artifact mappings are unavailable"
    ]
    (ws / "build" / "compile_commands.json").write_text("not-json", encoding="utf-8")
    assert "not parseable" in lb_job._compile_rows(ws, ".", "build")[1][0]

    (ws / "build" / "compile_commands.json").write_text(json.dumps([
        {"directory": "/workspace", "command": "/usr/bin/clang -c src.c -o build/src.o", "file": "src.c"},
    ]), encoding="utf-8")
    c_rows, c_gaps = lb_job._compile_rows(ws, ".", "build")
    assert c_gaps == [] and len(c_rows) == 1 and c_rows[0]["output"] == "build/src.o"

    (ws / "build" / "CMakeFiles" / "app.dir" / "link.txt").write_text(
        "/usr/bin/clang src.o -o app\n/usr/bin/ar qc libapp.a src.o\n",
        encoding="utf-8",
    )
    l_rows, l_gaps = lb_job._link_rows(ws, "build")
    assert l_gaps == [] and len(l_rows) == 2
    cap_rows = [{"argv": ["/usr/bin/clang", "src.o", "-o", "app"], "inputs": [], "outputs": []}]
    meta_gaps = lb_job._apply_native_link_metadata(cap_rows, ws, ".", "build")
    assert meta_gaps == [] and cap_rows[0]["metadata_origin"].endswith("link.txt")

    (ws / "build" / "CMakeFiles" / "app.dir" / "link.txt").write_bytes(b"bad\x00row\n")
    assert "not parseable" in lb_job._link_rows(ws, "build")[1][0]

    assert lb_job._workspace_path(ws, "/workspace", str((ws / "src.c").resolve())) == (ws / "src.c").resolve()
    assert lb_job._workspace_path(ws, "/etc", "rel.c") is None
    assert lb_job._workspace_path(ws, "/workspace", "../escape.c") is None


def test_dispatches_enforces_snapshot_probe_recipe_and_iterative_contracts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sub = tmp_path / "disp"
    target = sub / "target"
    target.mkdir(parents=True)
    (target / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")
    fp = source_fingerprint(target)
    unit = support.unit_context(sub, "load.python", target_root=target, source_fingerprint=fp)
    dep_sha = file_sha256(target / "pyproject.toml")
    profile = BuildProfile("python", "appsec-build-python:test", "sha256:" + "5" * 64, "1000:1000")
    recipe = {
        "schema": "appsec-review/build-recipe/1",
        "build_unit_id": "build-unit-" + "a" * 20,
        "image_profile": "python",
        "source_dir": ".",
        "build_dir": "dist",
        "system_packages": [],
        "environment": {},
        "dependency_files": ["pyproject.toml"],
        "configure_commands": [],
        "build_commands": [["python3", "-m", "build"]],
        "expected_outputs": ["dist"],
        "network_required": False,
        "reason": "test",
    }
    rec_id = project_recipe_identity(
        {**recipe, "build_system": "pyproject"},
        profile,
        {"pyproject.toml": dep_sha},
        releases=unit.job.review_policy.releases,
    )
    uid = "build-unit-" + "a" * 20
    probe = {
        "build_unit_id": uid,
        "family": "python",
        "root": ".",
        "build_system": "pyproject",
        "terminal_status": "SUCCEEDED",
        "recipe_identity": rec_id,
        "image_id": profile.image_id,
        "gaps": [],
    }
    probe_id = hashlib.sha256(canonical_json(probe)).hexdigest()
    valid_dispatch = {
        "workflow": "lang_jobflow_build",
        "build_unit_id": uid,
        "family": "python",
        "root": ".",
        "build_system": "pyproject",
        "source_fingerprint": fp,
        "recipe_identity": rec_id,
        "probe_identity": probe_id,
        "image": {
            "image_tag": profile.tag,
            "base_image_id": profile.image_id,
            "image_id": profile.image_id,
            "user": profile.user,
            "dependency_hashes": {"pyproject.toml": dep_sha},
        },
        "recipe": recipe,
        "build_dependencies": [],
    }
    base_accepted = {
        "schema": "appsec-review/project-build-dispatch/3",
        "execution_mode": "legacy",
        "source_fingerprint": fp,
        "project_build_handoff_sha256": "6" * 64,
        "build_dispatches": [valid_dispatch],
        "probe_receipts": [probe],
    }

    current_doc: dict[str, Any] = base_accepted
    monkeypatch.setattr(lb_job, "load_accepted_builds", lambda _rr, **_kw: current_doc)

    loaded, _ = lb_job._dispatches(unit, families=frozenset({"python"}))
    assert len(loaded) == 1 and loaded[0]["build_unit_id"] == uid

    # Error cases
    bad_cases = [
        ({**base_accepted, "source_fingerprint": "0" * 64}, "target snapshot differs"),
        ({**base_accepted, "probe_receipts": [probe, probe]}, "duplicate build units"),
        ({**base_accepted, "build_dispatches": [{**valid_dispatch, "workflow": "bad"}]}, "unknown build workflow"),
        ({**base_accepted, "build_dispatches": [{**valid_dispatch, "build_unit_id": "bad"}]}, "unknown or duplicate build unit"),
        ({**base_accepted, "build_dispatches": [{**valid_dispatch, "family": ""}]}, "invalid build family"),
        ({**base_accepted, "build_dispatches": [{**valid_dispatch, "probe_identity": "0" * 64}]}, "probe identity mismatch"),
        ({**base_accepted, "build_dispatches": [{**valid_dispatch, "recipe_identity": "0" * 64}]}, "recipe, image, or probe identity mismatch"),
        ({**base_accepted, "build_dispatches": [{**valid_dispatch, "build_dependencies": [uid]}]}, "dependencies are invalid"),
        ({**base_accepted, "execution_mode": "iterative", "images": {}}, "no matching immutable image preparation"),
    ]
    for doc, expected_msg in bad_cases:
        current_doc = doc
        with pytest.raises(ValueError, match=expected_msg):
            lb_job._dispatches(unit, families=frozenset({"python"}))


def test_execute_one_python_php_dotnet_and_checkpoint_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "appsec_review.jobs.build_topology_artifacts.guard_cache_action",
        lambda _rr, _d, **_kw: {"enforcement": [{"proof_kind": "go_explicit_target", "status": "proven"}]},
    )

    # 1. Python _execute_one builds wheel + reuses checkpoint on second call + detects tampered checkpoint
    py_sub = tmp_path / "py"
    py_target = py_sub / "target"
    py_target.mkdir(parents=True)
    (py_target / "pyproject.toml").write_text(
        '[build-system]\nbuild-backend = "setuptools.build_meta"\n[project]\nname = "demo"\n',
        encoding="utf-8",
    )
    py_fp = source_fingerprint(py_target)
    py_unit = support.unit_context(py_sub, "execute.python", target_root=py_target, source_fingerprint=py_fp)
    py_uid = "build-unit-" + "1" * 20
    py_dispatch = {
        **support.dispatch(py_uid, "python", build_system="pyproject", commands=[["python3", "-m", "build"]]),
        "source_fingerprint": py_fp,
        "topology_refinement": {"path": "data/build/topology/refinements/r.json", "sha256": "7" * 64},
        "image": {"image_tag": "py:1", "image_id": "sha256:" + "5" * 64, "user": "1000:1000", "dependency_hashes": {}},
        "recipe": {
            "source_dir": ".", "build_dir": "dist",
            "environment": {},
            "dependency_files": ["pyproject.toml"],
            "configure_commands": [], "build_commands": [["python3", "-m", "build"]],
            "expected_outputs": ["dist"], "network_required": False,
        },
    }
    py_accepted = support.accepted(py_dispatch)

    class NonCapturedExecutor:
        def resolve(self) -> None:
            return None

    with pytest.raises(lb_job.FrameworkIntegrityError, match="require execution capture"):
        lb_job._execute_one(py_unit, py_dispatch, py_accepted, lambda _u, _p: NonCapturedExecutor())

    def py_behavior(argv: tuple[str, ...], ws: Path, _cwd: str, _env: dict[str, str], sim: Any):
        sim.exec("/usr/bin/python3", argv)
        whl = ws / "dist" / "demo-0.1.0-py3-none-any.whl"
        whl.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(whl, "w") as zf:
            zf.writestr("demo/__init__.py", "v = 1\n")
        return 0, b"/usr/bin/gcc -c ext.c -o ext.o\n", b""

    py_receipt = lb_job._execute_one(
        py_unit, py_dispatch, py_accepted,
        lambda _u, prof: simulated_executor(prof, py_behavior),
    )
    assert py_receipt["terminal_status"] == "SUCCEEDED"
    assert py_receipt["checkpoint_reused"] is False
    assert len(py_receipt["package_members"]) == 1
    assert any(r["tool_kind"] == "build-backend" for r in py_receipt["tool_invocations"])

    # Second call hits checkpoint reuse!
    reused = lb_job._execute_one(
        py_unit, py_dispatch, py_accepted,
        lambda _u, prof: simulated_executor(prof, py_behavior),
    )
    assert reused["checkpoint_reused"] is True

    # Corrupting workspace file triggers FrameworkIntegrityError in _validate_checkpoint_artifacts
    whl_in_ws = py_unit.job.run_root / py_receipt["workspace"] / "dist" / "demo-0.1.0-py3-none-any.whl"
    whl_in_ws.write_bytes(b"tampered")
    with pytest.raises(lb_job.FrameworkIntegrityError, match="checkpoint"):
        lb_job._execute_one(
            py_unit, py_dispatch, py_accepted,
            lambda _u, prof: simulated_executor(prof, py_behavior),
        )

    # 2. PHP _execute_one with composer metadata + generated autoloader
    php_sub = tmp_path / "php"
    php_target = php_sub / "target"
    php_target.mkdir(parents=True)
    (php_target / "composer.json").write_text(json.dumps({"name": "acme/app", "require": {"psr/log": "^3.0"}}), encoding="utf-8")
    php_fp = source_fingerprint(php_target)
    php_unit = support.unit_context(php_sub, "execute.php", target_root=php_target, source_fingerprint=php_fp)
    php_uid = "build-unit-" + "2" * 20
    php_dispatch = {
        **support.dispatch(php_uid, "php", build_system="composer", commands=[["composer", "install"]]),
        "source_fingerprint": php_fp,
        "topology_refinement": {"path": "data/build/topology/refinements/r.json", "sha256": "7" * 64},
        "image": {"image_tag": "php:1", "image_id": "sha256:" + "5" * 64, "user": "1000:1000", "dependency_hashes": {}},
        "recipe": {
            "source_dir": ".", "build_dir": "vendor",
            "environment": {},
            "dependency_files": ["composer.json"],
            "configure_commands": [], "build_commands": [["composer", "install"]],
            "expected_outputs": ["vendor"], "network_required": True,
        },
    }

    def php_behavior(argv: tuple[str, ...], ws: Path, _cwd: str, _env: dict[str, str], sim: Any):
        sim.exec("/usr/bin/composer", argv)
        autoload = ws / "vendor" / "composer" / "autoload_real.php"
        autoload.parent.mkdir(parents=True, exist_ok=True)
        autoload.write_text("<?php // generated\n", encoding="utf-8")
        return 0, b"", b""

    php_receipt = lb_job._execute_one(
        php_unit, php_dispatch, support.accepted(php_dispatch),
        lambda _u, prof: simulated_executor(prof, php_behavior),
    )
    assert php_receipt["terminal_status"] == "SUCCEEDED"
    assert php_receipt["composer"]["root_package"] == "acme/app"

    # 3. .NET platform_gaps -> NOT_APPLICABLE and recipe_gaps -> BLOCKED
    dn_sub = tmp_path / "dn"
    dn_target = dn_sub / "target"
    dn_target.mkdir(parents=True)
    (dn_target / "App.csproj").write_text("<Project/>", encoding="utf-8")
    dn_fp = source_fingerprint(dn_target)
    dn_unit = support.unit_context(dn_sub, "execute.dotnet", target_root=dn_target, source_fingerprint=dn_fp)
    dn_uid = "build-unit-" + "3" * 20
    dn_dispatch = {
        **support.dispatch(dn_uid, "dotnet", build_system="dotnet", commands=[["dotnet", "test"]]),
        "source_fingerprint": dn_fp,
        "topology_refinement": {"path": "data/build/topology/refinements/r.json", "sha256": "7" * 64},
        "image": {"image_tag": "dn:1", "image_id": "sha256:" + "5" * 64, "user": "1000:1000", "dependency_hashes": {}},
        "recipe": {
            "source_dir": ".", "build_dir": "bin",
            "environment": {},
            "dependency_files": ["App.csproj"],
            "configure_commands": [], "build_commands": [["dotnet", "test"]],
            "expected_outputs": ["bin"], "network_required": False,
        },
    }
    monkeypatch.setattr(
        "appsec_review.jobs.job_language_build.dotnet.selected_project_topology",
        lambda *_a, **_kw: ([{"path": "App.csproj"}], [], ["Windows-only target"]),
    )
    na_receipt = lb_job._execute_one(dn_unit, dn_dispatch, support.accepted(dn_dispatch))
    assert na_receipt["terminal_status"] == "NOT_APPLICABLE"

    monkeypatch.setattr(
        "appsec_review.jobs.job_language_build.dotnet.selected_project_topology",
        lambda *_a, **_kw: ([{"path": "App.csproj"}], [], []),
    )
    blk_receipt = lb_job._execute_one(dn_unit, dn_dispatch, support.accepted(dn_dispatch))
    assert blk_receipt["terminal_status"] == "BLOCKED"


def test_execute_one_captured_go_and_rust_and_index_builders(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "appsec_review.jobs.build_topology_artifacts.guard_cache_action",
        lambda _rr, _d, **_kw: {"enforcement": [{"proof_kind": "go_explicit_target", "status": "proven"}]},
    )

    # 1. Captured Go _execute_one producing verified Go ELF + package catalog
    go_sub = tmp_path / "go"
    go_target = go_sub / "target"
    go_target.mkdir(parents=True)
    (go_target / "go.mod").write_text("module example.test/app\n\ngo 1.23\n", encoding="utf-8")
    (go_target / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    go_fp = source_fingerprint(go_target)
    go_unit = support.unit_context(go_sub, "execute.go", target_root=go_target, source_fingerprint=go_fp)
    go_uid = "build-unit-" + "4" * 20
    go_dispatch = {
        **support.dispatch(go_uid, "go", build_system="go", commands=[["go", "build", "-o", "bin/app", "."]]),
        "source_fingerprint": go_fp,
        "topology_refinement": {"path": "data/build/topology/refinements/r.json", "sha256": "7" * 64},
        "image": {"image_tag": "go:1", "image_id": "sha256:" + "5" * 64, "user": "1000:1000", "dependency_hashes": {}},
        "recipe": {
            "source_dir": ".", "build_dir": "bin",
            "dependency_files": ["go.mod"],
            "environment": {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "1"},
            "configure_commands": [], "build_commands": [["go", "build", "-o", "bin/app", "."]],
            "expected_outputs": ["bin/app"], "network_required": False,
        },
    }

    def go_behavior(argv: tuple[str, ...], ws: Path, _cwd: str, _env: dict[str, str], sim: Any):
        if "list" in argv:
            sim.exec("/usr/local/go/bin/go", argv)
            pkg_json = json.dumps({
                "ImportPath": "example.test/app", "Name": "main",
                "Dir": "/workspace", "Imports": ["fmt"],
                "Module": {"Path": "example.test/app", "Main": True},
            }).encode("utf-8")
            return 0, pkg_json, b""
        sim.exec("/usr/local/go/pkg/tool/linux_amd64/compile", ["compile", "-p", "example.test/app", "-o", "/workspace/bin/pkg.a", "main.go"])
        sim.exec("/usr/local/go/pkg/tool/linux_amd64/link", ["link", "-o", "/workspace/bin/app", "/workspace/bin/pkg.a"])
        out_bin = ws / "bin" / "app"
        out_bin.parent.mkdir(parents=True, exist_ok=True)
        out_bin.write_bytes(minimal_go_elf())
        return 0, b"", b""

    go_receipt = lb_job._execute_one(
        go_unit, go_dispatch, support.accepted(go_dispatch),
        lambda _u, prof: simulated_executor(prof, go_behavior),
    )
    assert go_receipt["terminal_status"] == "SUCCEEDED"
    assert len(go_receipt["build_metadata"]) == 1
    assert go_receipt["capture_provenance"]["schema"] == "appsec-review/go-capture-provenance/1"

    # 2. Captured Rust _execute_one with cargo metadata + rustc exec
    rs_sub = tmp_path / "rs"
    rs_target = rs_sub / "target"
    rs_target.mkdir(parents=True)
    (rs_target / "Cargo.toml").write_text('[package]\nname = "demo"\nversion = "0.1.0"\n', encoding="utf-8")
    (rs_target / "Cargo.lock").write_text("# lock\n", encoding="utf-8")
    rs_fp = source_fingerprint(rs_target)
    rs_unit = support.unit_context(rs_sub, "execute.rust", target_root=rs_target, source_fingerprint=rs_fp)
    rs_uid = "build-unit-" + "5" * 20
    rs_dispatch = {
        **support.dispatch(rs_uid, "rust", build_system="cargo", commands=[["cargo", "build"]]),
        "source_fingerprint": rs_fp,
        "topology_refinement": {"path": "data/build/topology/refinements/r.json", "sha256": "7" * 64},
        "image": {"image_tag": "rs:1", "image_id": "sha256:" + "5" * 64, "user": "1000:1000", "dependency_hashes": {}},
        "recipe": {
            "source_dir": ".", "build_dir": "target",
            "dependency_files": ["Cargo.toml", "Cargo.lock"],
            "environment": {},
            "configure_commands": [], "build_commands": [["cargo", "build"]],
            "expected_outputs": ["target"], "network_required": False,
        },
    }

    def rs_behavior(argv: tuple[str, ...], ws: Path, _cwd: str, _env: dict[str, str], sim: Any):
        if argv[1] == "metadata":
            sim.exec("/usr/bin/cargo", argv)
            meta = {
                "version": 1, "workspace_root": "/workspace", "target_directory": "/workspace/target",
                "workspace_members": ["demo#0.1.0"],
                "packages": [
                    {"id": "demo#0.1.0", "name": "demo", "version": "0.1.0", "manifest_path": "/workspace/Cargo.toml", "targets": []},
                    {"id": "dep#0.2.0", "name": "dep", "version": "0.2.0", "manifest_path": "/cargo/dep/Cargo.toml", "targets": []},
                ],
                "resolve": {"nodes": [{"id": "demo#0.1.0", "dependencies": ["dep#0.2.0"]}]},
            }
            return 0, json.dumps(meta).encode("utf-8"), b""
        sim.exec("/usr/bin/rustc", ["rustc", "--crate-name", "demo", "src/main.rs", "--out-dir", "/workspace/target/debug"])
        out_bin = ws / "target" / "debug" / "demo"
        out_bin.parent.mkdir(parents=True, exist_ok=True)
        out_bin.write_bytes(minimal_elf())
        return 0, b"", b""

    rs_receipt = lb_job._execute_one(
        rs_unit, rs_dispatch, support.accepted(rs_dispatch),
        lambda _u, prof: simulated_executor(prof, rs_behavior),
    )
    assert rs_receipt["terminal_status"] == "SUCCEEDED"
    assert len(rs_receipt["cargo_metadata"]["packages"]) == 2

    # 3. _publish_build_index over go_receipt + rs_receipt
    prior_manifest = rs_unit.job.run_root / "data" / "indices" / "manifests" / "prior.json"
    prior_manifest.parent.mkdir(parents=True, exist_ok=True)
    write_manifest(
        prior_manifest,
        run_id=rs_unit.job.run_id,
        target_snapshot=rs_fp,
        target_root=rs_target,
        indexes=(),
    )
    prior_sha = file_sha256(prior_manifest)
    monkeypatch.setattr(lb_job, "resolve_context_manifest", lambda _j: (prior_manifest, prior_sha))
    idx_manifest = lb_job._publish_build_index(rs_unit, [go_receipt, rs_receipt])
    assert (rs_unit.job.run_root / idx_manifest["path"]).is_file()

    # 4. jvm._index first build and second call reuse
    jvm_sub = tmp_path / "jvm_idx"
    jvm_unit = support.unit_context(jvm_sub, "execute.java")
    jvm_receipt = {
        "build_unit_id": "build-unit-" + "6" * 20,
        "build_system": "gradle",
        "image": {"image_id": "sha256:" + "5" * 64},
        "terminal_status": "COMPLETED_WITH_GAPS",
        "gaps": ["partial gradle provenance"],
        "commands": [{
            "command_id": "cmd-1", "ordinal": 1, "tool": "gradle", "tool_kind": "build-driver",
            "argv_sha256": "1" * 64, "working_directory": ".", "environment_facts": {},
            "exit_code": 0, "timed_out": False, "duration_ms": 12,
            "image_id": "sha256:" + "5" * 64, "attempt_identity": "attempt_0001", "wrapper_resolution": None,
        }],
        "tool_invocations": [{
            "ordinal": 1, "tool": "javac", "tool_kind": "compiler",
            "argv_sha256": "2" * 64, "expanded_argv_sha256": "2" * 64,
            "launcher": "gradle", "evidence_kind": "observed",
            "parent_command_id": "cmd-1", "working_directory": ".",
            "inputs": [], "outputs": [], "mapping": "syscall", "mapping_confidence": 1.0,
        }],
        "declared_compilations": [{
            "ordinal": 1, "tool": "javac", "tool_kind": "compiler",
            "evidence_kind": "declared", "task_path": ":compileJava", "task_type": "JavaCompile",
            "parent_command_id": "cmd-1", "did_work": True,
            "declared_arguments_sha256": "3" * 64, "declared_settings": {},
            "inputs": [], "outputs": [], "observed_invocation_ordinals": [1],
            "mapping": "gradle-init", "mapping_confidence": 0.7,
        }],
        "artifacts": [{
            "workspace_path": "build/libs/app.jar", "sha256": "4" * 64, "size_bytes": 128,
            "kind": "jar", "build_unit_id": "build-unit-" + "6" * 20,
            "mapping": "workspace", "mapping_confidence": 1.0,
        }],
    }
    first_idx = jvm._index(jvm_unit, jvm_receipt)
    assert first_idx["reused"] is False
    second_idx = jvm._index(jvm_unit, jvm_receipt)
    assert second_idx["reused"] is True


def test_production_iteration_and_node_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "appsec_review.jobs.build_topology_artifacts.guard_cache_action",
        lambda _rr, _d, **_kw: {"enforcement": [{"proof_kind": "go_explicit_target", "status": "proven"}]},
    )
    monkeypatch.setattr(
        "appsec_review.jobs.build_topology_artifacts.guard_action",
        lambda _rr, _d, **_kw: {"enforcement": [{"proof_kind": "go_explicit_target", "status": "proven"}]},
    )

    # 1. _production_iteration over Python unit with promoted_profile + processing_decisions
    it_sub = tmp_path / "iter"
    it_target = it_sub / "target"
    it_target.mkdir(parents=True)
    (it_target / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")
    it_fp = source_fingerprint(it_target)
    raw_unit = support.unit_context(it_sub, "execute.python", target_root=it_target, source_fingerprint=it_fp)

    job_fields = {**vars(raw_unit.job), "orchestration": None}
    JobCls = make_dataclass("_JobCtx", [(k, Any) for k in job_fields])
    unit_fields = {**vars(raw_unit), "job": JobCls(**job_fields)}
    UnitCls = make_dataclass("_UnitCtx", [(k, Any) for k in unit_fields])
    it_unit: Any = UnitCls(**unit_fields)
    it_uid = "build-unit-" + "7" * 20
    ws = lb_job.BuildWorkspace(it_unit.job.run_root)
    ws.paths.target.mkdir(parents=True, exist_ok=True)
    ws.paths.install.mkdir(parents=True, exist_ok=True)
    (ws.paths.target / "pyproject.toml").write_text('[project]\nname = "demo"\n', encoding="utf-8")

    graph_doc = {"nodes": [{"build_unit_id": it_uid, "family": "python"}], "declarations": []}
    graph_path = it_unit.job.run_root / "data" / "build" / "iterations" / "graph.json"
    atomic_json(graph_path, graph_doc)
    graph_ref = {
        "path": graph_path.relative_to(it_unit.job.run_root).as_posix(),
        "sha256": file_sha256(graph_path),
        "size_bytes": graph_path.stat().st_size,
    }

    dec_raw = {
        "schema": DECISION_SCHEMA,
        "feature": ProcessingFeature.COMPILER_ARTIFACTS.value,
        "project_id": it_uid,
        "language": "python",
        "resolved_policy": "auto",
        "configuration_sha256": "9" * 64,
        "action": ApplicabilityAction.RUN.value,
        "disposition": None,
        "reason_code": ReasonCode.MATERIAL_BUILD_CONFIRMED.value,
        "selected_capability": None,
        "inspected_facts": ["pyproject"],
        "sources": [],
        "decision_sha256": "0" * 64,
    }
    dec_raw["decision_sha256"] = hashlib.sha256(canonical_json(dec_raw)).hexdigest()
    it_dispatch = {
        **support.dispatch(it_uid, "python", build_system="pyproject", commands=[["python3", "-m", "build"]]),
        "source_fingerprint": it_fp,
        "topology_refinement": {"path": "data/build/topology/refinements/r.json", "sha256": "7" * 64},
        "promoted_profile": {"name": "python", "tag": "py:promoted", "image_id": "sha256:" + "8" * 64, "user": "1000:1000"},
        "image": {"image_tag": "py:1", "image_id": "sha256:" + "5" * 64, "user": "1000:1000", "dependency_hashes": {}},
        "recipe": {
            "source_dir": ".", "build_dir": "dist", "environment": {},
            "dependency_files": ["pyproject.toml"],
            "configure_commands": [], "build_commands": [["python3", "-m", "build"]],
            "expected_outputs": ["dist"], "network_required": False,
        },
        "processing_decisions": [dec_raw],
    }
    it_accepted = {
        **support.accepted(it_dispatch),
        "execution_actions": [{"build_unit_id": it_uid, "root": ".", "source_dir": ".", "build_dir": "dist"}],
    }

    def it_behavior(argv: tuple[str, ...], ws_dir: Path, _cwd: str, _env: dict[str, str], sim: Any):
        sim.exec("/usr/bin/python3", argv)
        whl = ws_dir / "dist" / "demo-0.1.0-py3-none-any.whl"
        whl.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(whl, "w") as zf:
            zf.writestr("demo/__init__.py", "v = 1\n")
        return 0, b"", b""

    outcome = lb_job._production_iteration(
        it_unit,
        {
            "dispatch": it_dispatch,
            "graph": graph_ref,
            "node_id": it_uid,
            "attempt_id": "attempt_0001",
            "display_label": "python:demo",
            "interfaces": [],
            "products": [],
        },
        "dagster-run-1",
        it_accepted,
        lambda _u, prof: simulated_executor(prof, it_behavior),
    )
    assert outcome.receipt["terminal_status"] == "SUCCEEDED"
    assert outcome.cleanup_complete is True
    assert len(outcome.receipt["processing_decisions"]) == 1

    # 2. Node _execute_one gap receipt when lockfile missing
    node_sub = tmp_path / "node"
    node_target = node_sub / "target"
    node_target.mkdir(parents=True)
    (node_target / "package.json").write_text(json.dumps({"name": "web", "scripts": {"build": "tsc"}}), encoding="utf-8")
    node_fp = source_fingerprint(node_target)
    node_unit = support.unit_context(node_sub, "execute.node", target_root=node_target, source_fingerprint=node_fp)
    node_uid = "build-unit-" + "8" * 20
    node_dispatch = {
        **support.dispatch(node_uid, "node", build_system="npm", commands=[["npm", "run", "build"]]),
        "source_fingerprint": node_fp,
        "topology_refinement": {"path": "data/build/topology/refinements/r.json", "sha256": "7" * 64},
        "image": {"image_tag": "node:1", "image_id": "sha256:" + "5" * 64, "user": "1000:1000", "dependency_hashes": {}},
        "recipe": {
            "source_dir": ".", "build_dir": "dist", "environment": {},
            "dependency_files": ["package.json"],
            "configure_commands": [], "build_commands": [["npm", "run", "build"]],
            "expected_outputs": ["dist"], "network_required": False,
        },
    }
    node_gap = lb_job._execute_one(node_unit, node_dispatch, support.accepted(node_dispatch))
    assert node_gap["terminal_status"] == "BLOCKED"
    assert node_gap["gaps"]

