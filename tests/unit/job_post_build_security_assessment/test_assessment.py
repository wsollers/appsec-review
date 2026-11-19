from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from appsec_review.jobs.job_post_build_security_assessment.assessment import (
    MAX_ARGV,
    INFERENCE_PROPOSAL_SCHEMA,
    _bounded_c_string,
    _check,
    _safe_path,
    _split_command,
    classify_action,
    command_fingerprint,
    deterministic_checks,
    discover_io,
    normalize_action,
    redact_argv,
    sanitize_environment,
    shard_fingerprint,
    validate_inference,
)
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import (
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RetrievalCore,
    write_manifest,
)
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff

RUN_ID = "2026-10-08-9001"


def test_safe_path_redacts_host_paths_and_remaps_longest_matching_roots() -> None:
    roots = {
        "/tmp/run": "<run>",
        "/tmp/run/source": "pkg/native",
    }
    assert _safe_path("/tmp/run/source/main.c", roots=roots) == "pkg/native/main.c"
    assert _safe_path("/tmp/run/source", roots=roots) == "pkg/native"
    assert _safe_path("/tmp/run/build/app.o", roots=roots) == "<run>/build/app.o"
    assert _safe_path("C:\\Users\\alice\\proj\\a.cpp") == "<external-path>/a.cpp"
    assert _safe_path("-I/home/alice/private/include") == "-I<external-path>"
    assert _safe_path("//") == "<external-path>"
    assert _safe_path("relative/src/file.c") == "relative/src/file.c"
    assert _bounded_c_string(b"hello\x00world", -1) == ""
    assert _bounded_c_string(b"hello\x00world", 99) == ""
    assert _bounded_c_string(b"hello\x00world", 0) == "hello"


def test_redact_argv_and_sanitize_environment_enforce_bounds_and_strip_secrets() -> None:
    argv = [
        "clang++",
        "-DAPI_TOKEN=top-secret",
        "--password",
        "also-secret",
        "/secret/inline/path",
        "C:\\Users\\victim\\project\\main.cpp",
        "-I/home/victim/private/include",
        "@/tmp/build.rsp",
        "@build/flags.rsp",
    ]
    redacted = redact_argv(argv)
    encoded = json.dumps(redacted)
    assert "top-secret" not in encoded
    assert "also-secret" not in encoded
    assert "/secret/inline/path" not in encoded
    assert "C:/Users/victim" not in encoded
    assert "/tmp/build.rsp" not in encoded
    assert "/home/victim" not in encoded
    assert redacted[1] == "-DAPI_TOKEN=<redacted>"
    assert redacted[2:5] == ["--password", "<redacted>", "<redacted>"]
    assert redacted[7] == "@<external-path>/build.rsp"
    assert redacted[8] == "@build/flags.rsp"

    with pytest.raises(ValueError, match="exceeds configured provenance bounds"):
        redact_argv([])
    with pytest.raises(ValueError, match="exceeds configured provenance bounds"):
        redact_argv(["a"] * (MAX_ARGV + 1))
    with pytest.raises(ValueError, match="exceeds configured provenance bounds"):
        redact_argv(["a" * (1024 * 1024 + 1)])
    with pytest.raises(ValueError, match="invalid value"):
        redact_argv(["clang", "bad\0argument"])
    with pytest.raises(ValueError, match="invalid value"):
        redact_argv(["clang", 123])  # type: ignore[list-item]

    env = sanitize_environment(
        {
            "CFLAGS": "-O2 -I/home/victim/inc",
            "CC": "/usr/bin/clang",
            "API_TOKEN": "secret-val",
            "LDFLAGS": "-Wl,--token=leak",
            "UNLISTED_VAR": "value",
        }
    )
    assert set(env["facts"]) == {"CC", "CFLAGS"}
    assert env["facts"]["CFLAGS"]["value"] == "-O2 -I<external-path>"
    assert env["omitted_count"] == 3


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ([], "unknown"),
        (["clang", "-c", "a.c"], "compiler"),
        (["cl.exe", "/c", "a.cpp"], "compiler"),
        (["clang++", "a.o", "-o", "app"], "linker_driver"),
        (["gcc", "a.c"], "linker_driver"),
        (["clang", "-E", "a.c"], "unknown"),
        (["as", "a.s"], "assembler"),
        (["ml64.exe", "a.asm"], "assembler"),
        (["windres", "a.rc"], "resource_compiler"),
        (["llvm-ar", "rcs", "lib.a", "a.o"], "archiver"),
        (["lib.exe", "/OUT:x.lib", "a.obj"], "librarian"),
        (["ld.lld", "a.o"], "linker"),
        (["llvm-strip", "app"], "post_link"),
        (["python3", "script.py"], "unknown"),
    ],
)
def test_classify_action_covers_all_toolchains(argv: list[str], expected: str) -> None:
    assert classify_action(argv) == expected


def test_split_command_discover_io_and_normalize_action() -> None:
    assert _split_command({"arguments": ["clang", "-c", "a.c"]}) == ["clang", "-c", "a.c"]
    assert _split_command({"command": "clang -c 'src/a.c' -o a.o"}) == ["clang", "-c", "src/a.c", "-o", "a.o"]
    with pytest.raises(ValueError, match="bounded arguments or command"):
        _split_command({})
    with pytest.raises(ValueError, match="bounded arguments or command"):
        _split_command({"command": "x" * (1024 * 1024 + 5)})

    inputs, outputs = discover_io(
        ["cl.exe", "/c", "src/main.cpp", "res/icon.rc", "/Fobuild/main.obj", "/Fe", "bin/app.exe"],
        working_directory="build",
    )
    assert inputs == ["res/icon.rc", "src/main.cpp"]
    assert outputs == ["bin/app.exe", "build/main.obj"]

    ar_in, ar_out = discover_io(["llvm-ar", "rcs", "libfoo.a", "a.o", "b.o"], working_directory="build")
    assert ar_in == ["a.o", "b.o"]
    assert ar_out == ["libfoo.a"]

    ranlib_in, ranlib_out = discover_io(["ranlib", "--version"], working_directory="build")
    assert ranlib_in == [] and ranlib_out == []

    compile_action = normalize_action(
        {"arguments": ["clang", "-c", "src/a.c", "-o", "a.o", "-DSECRET=value"], "file": "src/a.c",
         "directory": "/home/user/build"},
        action_id="act-1",
        run_id=RUN_ID,
        target_snapshot="snap",
        project="proj",
        build_root="build",
        configuration="Release",
        producer={"job": "compile", "task": "a"},
        toolchain={"executable": "clang", "image_digest": "sha256:" + "1" * 64},
        protected_artifact={"path": "protected/act-1.json", "sha256": "2" * 64},
    )
    assert compile_action["compile_unit_id"] is not None
    assert "value" not in json.dumps(compile_action["argv"])
    assert compile_action["declared_inputs"] == ["src/a.c"]
    assert compile_action["outputs"] == ["a.o"]
    assert compile_action["working_directory"] == "<external-path>/build"

    link_action = normalize_action(
        {"command": "ld.lld a.o -o app"},
        action_id="act-2",
        run_id=RUN_ID,
        target_snapshot="snap",
        project="proj",
        build_root="build",
        configuration="Release",
        producer={"job": "compile", "task": "b"},
        toolchain={"executable": "ld.lld"},
        protected_artifact={"path": "protected/act-2.json", "sha256": "3" * 64},
    )
    assert link_action["compile_unit_id"] is None
    assert command_fingerprint(compile_action) != command_fingerprint(link_action)


def test_deterministic_checks_cover_msvc_gnu_elf_pe_mismatches_and_cross_tu() -> None:
    with pytest.raises(ValueError, match="invalid deterministic check status"):
        _check("x", "BOGUS", "scope", ["e"], "why")

    msvc_actions = [
        {"classification": "compiler", "argv": ["cl.exe", "/c", "a.cpp", "/GS", "/guard:cf", "/sdl"],
         "build_action_id": "m1", "compile_unit_id": "cu-m1", "project": "winproj"},
        {"classification": "compiler", "argv": ["clang-cl.exe", "/c", "b.cpp", "/GS-"],
         "build_action_id": "m2", "compile_unit_id": "cu-m2", "project": "winproj"},
        {"classification": "compiler", "argv": ["cl.exe", "/c", "c.cpp"],
         "build_action_id": "m3", "compile_unit_id": "cu-m3", "project": "winproj2"},
    ]
    pe64 = {
        "artifact_id": "pe64",
        "sha256": "b" * 64,
        "format": "PE/COFF",
        "kind": "executable",
        "bits": 64,
        "hardening": {
            "dynamic_base": False,
            "nx_compat": False,
            "high_entropy_va": False,
            "guard_cf": False,
            "safe_seh": None,
            "gs": None,
        },
    }
    pe32 = {
        "artifact_id": "pe32",
        "sha256": "c" * 64,
        "format": "PE/COFF",
        "kind": "dll",
        "bits": 32,
        "hardening": {
            "dynamic_base": True,
            "nx_compat": True,
            "high_entropy_va": False,
            "guard_cf": True,
            "safe_seh": True,
            "gs": True,
        },
    }
    win_link = {
        "classification": "linker",
        "argv": ["link.exe", "/DYNAMICBASE", "/NXCOMPAT", "/HIGHENTROPYVA", "/GUARD:CF", "a.obj"],
        "build_action_id": "mlink",
        "linked_artifact_ids": ["pe64"],
        "project": "winproj",
    }
    win_checks = {(c["check_id"], c["scope"]): c for c in deterministic_checks([*msvc_actions, win_link], [pe64, pe32])}
    assert win_checks[("msvc.gs", "cu-m1")]["status"] == "PASS"
    assert win_checks[("msvc.guard_cf.requested", "cu-m1")]["status"] == "PASS"
    assert win_checks[("msvc.sdl", "cu-m1")]["status"] == "PASS"
    assert win_checks[("msvc.gs", "cu-m2")]["status"] == "FAIL"
    assert win_checks[("msvc.gs", "cu-m3")]["status"] == "UNKNOWN"
    assert win_checks[("cross_tu.inconsistent.msvc_gs", "winproj")]["status"] == "FAIL"
    assert win_checks[("pe.safe_seh", "pe64")]["status"] == "NOT_APPLICABLE"
    assert win_checks[("pe.safe_seh", "pe32")]["status"] == "PASS"
    for prop in ("dynamic_base", "nx_compat", "high_entropy_va", "guard_cf"):
        assert win_checks[(f"command_binary.{prop}_mismatch", "pe64")]["status"] == "FAIL"

    gnu_actions = [
        {
            "classification": "compiler",
            "argv": [
                "clang", "-c", "a.c", "-fstack-protector-strong", "-O2", "-D_FORTIFY_SOURCE=2",
                "-fcf-protection=full", "-fvisibility=hidden", "-fPIE",
            ],
            "build_action_id": "g1",
            "compile_unit_id": "cu-g1",
            "project": "linproj",
        },
        {
            "classification": "compiler",
            "argv": [
                "gcc", "-c", "b.c", "-fno-stack-protector", "-D_FORTIFY_SOURCE=2",
                "-fcf-protection=none", "-Wl,-z,relro,-z,now",
            ],
            "build_action_id": "g2",
            "compile_unit_id": "cu-g2",
            "project": "linproj",
        },
        {
            "classification": "compiler",
            "argv": ["gcc", "-c", "c.c", "-U_FORTIFY_SOURCE"],
            "build_action_id": "g3",
            "compile_unit_id": "cu-g3",
            "project": "linproj2",
        },
    ]
    elf_exe = {
        "artifact_id": "elf-exe",
        "sha256": "a" * 64,
        "format": "ELF",
        "kind": "executable",
        "hardening": {
            "pie": False,
            "relro": False,
            "now": False,
            "nx_stack": True,
            "control_flow": None,
            "stack_canary": True,
            "fortify": False,
        },
    }
    elf_so = {
        "artifact_id": "elf-so",
        "sha256": "d" * 64,
        "format": "ELF",
        "kind": "shared_library",
        "hardening": {"pie": None, "relro": True, "now": True, "nx_stack": True},
    }
    elf_obj = {
        "artifact_id": "elf-obj",
        "sha256": "e" * 64,
        "format": "ELF",
        "kind": "object",
        "hardening": {},
    }
    gnu_link = {"classification": "linker", "build_action_id": "glink", "linked_artifact_ids": ["elf-exe"],
                "argv": ["ld", "-pie", "-z", "relro", "-z", "now", "-o", "elf-exe"]}
    lin_checks = {(c["check_id"], c["scope"]): c for c in deterministic_checks(
        [*gnu_actions, gnu_link], [elf_exe, elf_so, elf_obj])}
    assert lin_checks[("gnu.fortify", "cu-g1")]["status"] == "PASS"
    assert lin_checks[("gnu.fortify", "cu-g2")]["status"] == "FAIL"
    assert lin_checks[("gnu.fortify", "cu-g3")]["status"] == "FAIL"
    assert lin_checks[("gnu.control_flow", "cu-g1")]["status"] == "PASS"
    assert lin_checks[("gnu.control_flow", "cu-g2")]["status"] == "FAIL"
    assert lin_checks[("gnu.visibility", "cu-g1")]["status"] == "PASS"
    assert lin_checks[("gnu.insecure_override", "cu-g1")]["status"] == "PASS"
    assert lin_checks[("gnu.insecure_override", "cu-g2")]["status"] == "FAIL"
    assert lin_checks[("elf.pie", "elf-so")]["status"] == "NOT_APPLICABLE"
    assert lin_checks[("elf.pie", "elf-obj")]["status"] == "NOT_APPLICABLE"
    assert lin_checks[("elf.relro", "elf-obj")]["status"] == "NOT_APPLICABLE"
    assert lin_checks[("command_binary.pie_mismatch", "elf-exe")]["status"] == "FAIL"
    assert lin_checks[("command_binary.relro_mismatch", "elf-exe")]["status"] == "FAIL"
    assert lin_checks[("command_binary.now_mismatch", "elf-exe")]["status"] == "FAIL"
    assert lin_checks[("cross_tu.inconsistent.gnu_stack_protector", "linproj")]["status"] == "FAIL"
    assert lin_checks[("cross_tu.inconsistent.gnu_fortify", "linproj")]["status"] == "FAIL"
    assert lin_checks[("cross_tu.inconsistent.gnu_control_flow", "linproj")]["status"] == "FAIL"


def test_validate_inference_dispositions_scope_disambiguation_and_rejections() -> None:
    checks: list[dict[str, Any]] = [
        {"check_id": "gnu.stack_protector", "status": "FAIL", "scope": "cu-1", "evidence": ["act-1"]},
        {"check_id": "gnu.stack_protector", "status": "PASS", "scope": "cu-2", "evidence": ["act-2"]},
        {"check_id": "elf.control_flow", "status": "UNKNOWN", "scope": "bin-1", "evidence": ["sha-1"]},
    ]
    proposal = {
        "schema": INFERENCE_PROPOSAL_SCHEMA,
        "observations": [
            {"claim": "missing stack protector in cu-1", "check_id": "gnu.stack_protector", "evidence_ids": ["act-1"]},
            {"claim": "scoped claim on cu-2", "check_id": "gnu.stack_protector", "scope": "cu-2", "evidence_ids": ["act-2"]},
            {"claim": "needs manual CET note verification", "check_id": "elf.control_flow", "evidence_ids": ["sha-1"]},
            "not-an-object",
            {"claim": "unresolved evidence", "check_id": "elf.control_flow", "evidence_ids": ["invented"]},
            {"claim": "", "check_id": "elf.control_flow", "evidence_ids": ["sha-1"]},
            {"claim": "unknown check", "check_id": "nonexistent", "evidence_ids": ["sha-1"]},
        ]
    }
    validated = validate_inference(proposal, checks=checks, evidence_ids={"act-1", "act-2", "sha-1"})
    assert [obs["validation"] for obs in validated["observations"]] == [
        "CONFIRMED",
        "REFUTED",
        "UNVALIDATED",
    ]
    assert validated["confirmed_count"] == 1
    assert validated["refuted_count"] == 1
    assert validated["unvalidated_count"] == 1
    assert [rej["reason"] for rej in validated["rejections"]] == [
        "observation is not an object",
        "observation has unresolved evidence",
        "observation lacks a known deterministic check",
        "observation lacks a known deterministic check",
    ]

    with pytest.raises(ValueError, match="inference observations exceed bound"):
        validate_inference({"schema": INFERENCE_PROPOSAL_SCHEMA, "observations": "not-a-list"},
                           checks=checks, evidence_ids={"act-1"})
    with pytest.raises(ValueError, match="inference observations exceed bound"):
        validate_inference({"schema": INFERENCE_PROPOSAL_SCHEMA, "observations": [{}] * 101},
                           checks=checks, evidence_ids={"act-1"})


def test_shard_fingerprint_and_retrieval_mcp_query_scopes(tmp_path: Path) -> None:
    base = dict(
        command_artifacts=[{"sha256": "1" * 64}],
        binary_hashes=["2" * 64],
        tool_identity={"image": "3" * 64},
        model_identity={"model": "m"},
        upstream_manifest_sha256="4" * 64,
    )
    first = shard_fingerprint(**base)
    assert first == shard_fingerprint(**base)
    assert first != shard_fingerprint(**{**base, "command_artifacts": [{"sha256": "5" * 64}]})
    assert first != shard_fingerprint(**{**base, "binary_hashes": ["6" * 64]})

    runs, run_root = tmp_path / "runs", tmp_path / "runs" / RUN_ID
    target = tmp_path / "target"
    target.mkdir()
    attempt = run_root / "data" / "jobs" / "post" / "attempts" / "attempt_0001"
    attempt.mkdir(parents=True)
    shard = "build-security-case-001"
    db_path = run_root / "data" / "indices" / "build_security" / "fixture.sqlite"
    builder = IndexBuilder(
        db_path,
        name="build_security",
        fingerprint="1" * 64,
        target_snapshot="snapshot",
        shard_id=shard,
    )
    identity = LogicalIdentity.derive(EntityKind.BUILD_ACTION, "snapshot", {"id": "action-1"})
    builder.add_entity(
        EntityRecord(
            identity,
            "action-1",
            "action-1",
            "clang redacted",
            {
                "project": "project-a",
                "build_root": "build-a",
                "configuration": "Release",
                "build_action_id": "action-1",
                "compile_unit_id": "cu-1",
                "linked_artifact_ids": ["bin-1"],
                "producer": {"job": "compile-job"},
                "shard": shard,
            },
        )
    )
    builder.add_coverage("post-build-security", "partial", "exact link timing unavailable")
    sha = builder.build()
    index = IndexIdentity(
        "build_security",
        "appsec-review/retrieval-index/2",
        sha,
        "1" * 64,
        db_path.relative_to(run_root).as_posix(),
        {"job": "post"},
        ("exact link timing unavailable",),
        shard,
    )
    manifest_path = run_root / "data" / "indices" / "manifest.json"
    write_manifest(manifest_path, run_id=RUN_ID, target_snapshot="snapshot", target_root=target, indexes=(index,))
    artifact = {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest_path)}
    handoff_path = attempt / "handoff.json"
    write_fixture_handoff(
        run_root,
        handoff_path,
        {"source_fingerprint": "snapshot", "status": "ACCEPTED", "job_id": "post", "artifacts": [artifact]},
    )
    atomic_json(
        run_root / "data" / "indices" / "accepted.json",
        {
            "schema": "appsec-review/accepted-index-set/1",
            "run_id": RUN_ID,
            "handoff_path": handoff_path.relative_to(run_root).as_posix(),
            "handoff_sha256": file_sha256(handoff_path),
            "manifest_path": artifact["path"],
            "manifest_sha256": artifact["sha256"],
        },
    )
    adapter = RetrievalMcpAdapter(RetrievalCore(runs, RUN_ID))
    for key, value in {
        "project": "project-a",
        "build_root": "build-a",
        "build_action": "action-1",
        "configuration": "Release",
        "compile_unit": "cu-1",
        "linked_artifact": "bin-1",
        "producer": "compile-job",
        "shard": shard,
    }.items():
        response = adapter.call("query_build_security", {key: value})
        assert len(response["results"]) == 1
        assert any("exact link timing unavailable" in gap for gap in response["coverage_gaps"])
    assert adapter.call("query_build_security", {"project": "missing"})["results"] == []
