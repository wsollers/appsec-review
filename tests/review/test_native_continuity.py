"""``same_native_executable``: continuity derived from accepted build facts, never from prose."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds
from appsec_review.review import native_continuity as native
from appsec_review.review.models import IntegrityError

COMPILE_REF = {"path": "data/build/protected-commands/compile-database.json", "sha256": "3" * 64}
LINK_REF = {"path": "data/build/link-commands.json", "sha256": "4" * 64}
OBJECT = "build/CMakeFiles/smoke_server.dir/src/{name}.o"


def _compile_row(source: str, output: str, argv_sha: str) -> dict:
    return {"argv_sha256": argv_sha, "tool_kind": "compiler", "tool": "clang++",
            "inputs": [{"workspace_path": source, "sha256": hashlib.sha256(source.encode()).hexdigest(),
                        "mapping": "exact-workspace-path"}],
            "outputs": [{"workspace_path": output, "sha256": hashlib.sha256(output.encode()).hexdigest(),
                         "mapping": "exact-workspace-path"}]}


def compile_rows() -> list[dict]:
    """The shape of run 2026-11-16-0003's protected compile database: server sources, a vendored library, a tool."""
    return [
        {"argv_sha256": "a" * 64, "tool_kind": "linker-driver", "tool": "clang++", "inputs": [], "outputs": []},
        _compile_row("src/request.cpp", OBJECT.format(name="request.cpp"), "b" * 64),
        _compile_row("src/session.cpp", OBJECT.format(name="session.cpp"), "c" * 64),
        _compile_row("third_party/zlib/adler32.c", "build/CMakeFiles/smoke_zlib.dir/third_party/zlib/adler32.c.o", "d" * 64),
        _compile_row("src/synthetic.cpp", "build/CMakeFiles/smoke_synthetic.dir/src/synthetic.cpp.o", "e" * 64),
    ]


def link_rows() -> list[dict]:
    """Objects and static libraries link into ``smoke_server``; the tool links alone. Rows repeat per capture event."""
    server = {"command_sha256": "f" * 64, "output_path": "build/smoke_server", "receipt": "execution-capture:1",
              "input_paths": [OBJECT.format(name="request.cpp"), OBJECT.format(name="session.cpp"),
                              "build/libsmoke_zlib.a"]}
    return [
        {"command_sha256": "0" * 64, "output_path": "build/libsmoke_zlib.a", "receipt": "execution-capture:2",
         "input_paths": ["build/CMakeFiles/smoke_zlib.dir/third_party/zlib/adler32.c.o"]},
        server, dict(server),
        {"command_sha256": "9" * 64, "output_path": "build/smoke_synthetic", "receipt": "execution-capture:3",
         "input_paths": ["build/CMakeFiles/smoke_synthetic.dir/src/synthetic.cpp.o"]},
    ]


def facts() -> native.NativeLinkFacts:
    unit = native.UnitLinkFacts.from_rows("build-unit-fixture", compile_rows(), link_rows(),
                                          compile_database=COMPILE_REF, link_database=LINK_REF)
    return native.NativeLinkFacts([unit])


def test_two_objects_linked_into_one_executable_establish_the_derivation_with_bound_rows() -> None:
    derived = facts().derive("src/request.cpp", "src/session.cpp")
    assert derived.established and derived.reason == "same_native_executable"
    assert derived.link_database_sha256 == LINK_REF["sha256"]
    document = derived.document
    assert document["policy"] == "same_native_executable" and document["basis"] == native.BASIS
    assert document["bound_files"] == {"protected_compile_commands": COMPILE_REF, "link_database": LINK_REF}
    assert document["left"]["object_path"] == OBJECT.format(name="request.cpp")
    assert document["left"]["argv_sha256"] == "b" * 64 and document["right"]["argv_sha256"] == "c" * 64
    assert document["link"] == {"output_path": "build/smoke_server", "command_sha256": "f" * 64,
                                "left_via": None, "right_via": None}


def test_a_static_library_is_followed_one_hop_into_the_executable() -> None:
    derived = facts().derive("third_party/zlib/adler32.c", "src/request.cpp")
    assert derived.established
    assert derived.document["link"]["left_via"] == "build/libsmoke_zlib.a"
    assert derived.document["link"]["right_via"] is None
    assert derived.document["link"]["output_path"] == "build/smoke_server"


@pytest.mark.parametrize("left,right,reason", [
    ("src/request.cpp", "src/synthetic.cpp", "objects_not_linked_into_one_accepted_executable"),
    ("src/request.cpp", "src/never_built.cpp", "source_not_compiled_by_accepted_native_build"),
    ("src/request.cpp", None, "entity_has_no_accepted_source_location"),
])
def test_different_binaries_or_unknown_sources_are_unresolved_never_contradicted(left, right, reason) -> None:
    derived = facts().derive(left, right)
    assert not derived.established and derived.reason == reason
    assert derived.document["link"] is None
    assert derived.document["bound_files"]["link_database"] == LINK_REF


def _bound_run(run_root: Path, *, tamper: bool = False) -> dict:
    compile_doc = json.dumps({"schema": "appsec-review/protected-compile-commands/1", "rows": compile_rows()}).encode()
    link_doc = json.dumps(link_rows()).encode()
    compile_path = run_root / "data/build/compile-database.json"
    link_path = run_root / "data/build/link-commands.json"
    for path, payload in ((compile_path, compile_doc), (link_path, link_doc)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    if tamper:
        link_path.write_bytes(link_doc + b"\n")
    return {"family": "native", "terminal_status": "COMPLETED_WITH_GAPS", "build_unit_id": "build-unit-run",
            "protected_compile_commands": {"path": compile_path.relative_to(run_root).as_posix(),
                                           "sha256": hashlib.sha256(compile_doc).hexdigest()},
            "link_database": {"path": link_path.relative_to(run_root).as_posix(),
                              "sha256": hashlib.sha256(link_doc).hexdigest(), "relationship_count": 4}}


def test_facts_load_from_the_accepted_build_with_hash_bound_files(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    receipt = _bound_run(run_root)
    loaded = native.NativeLinkFacts.from_run(run_root, loader=lambda _root: {"receipts": [receipt]})
    assert loaded is not None and loaded.units[0].build_unit_id == "build-unit-run"
    derived = loaded.derive("src/request.cpp", "src/session.cpp")
    assert derived.established
    assert derived.document["bound_files"]["link_database"] == {
        "path": receipt["link_database"]["path"], "sha256": receipt["link_database"]["sha256"]}
    # No accepted native build at all: no facts, not an error.
    assert native.NativeLinkFacts.from_run(run_root, loader=lambda _root: {"receipts": []}) is None
    failed = {**receipt, "terminal_status": "FAILED"}
    assert native.NativeLinkFacts.from_run(run_root, loader=lambda _root: {"receipts": [failed]}) is None


def test_a_link_database_changed_after_acceptance_fails_closed(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    receipt = _bound_run(run_root, tamper=True)
    builds = AcceptedBuilds(run_root, loader=lambda _root: {"receipts": [receipt]})
    with pytest.raises(IntegrityError, match="link database changed after acceptance"):
        builds.native_link_facts()
