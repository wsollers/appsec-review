from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
from types import MappingProxyType
from typing import Any
import zipfile

import pytest

from appsec_review.config import JobConfig, load_config
from appsec_review.inference import ModelRequest, ModelResult
from appsec_review.inference.errors import ProviderError
from appsec_review.jobs.job_cpp_compiled_analysis.datasets import DATASETS as CPP_DATASETS
from appsec_review.jobs.job_language_build.datasets import DATASETS as LANG_DATASETS
from appsec_review.jobs.job_post_build_security_assessment import build_job
from appsec_review.jobs.job_post_build_security_assessment import job as job_mod
from appsec_review.jobs.job_post_build_security_assessment.datasets import CONTRACT
from appsec_review.observability import EventLog
from appsec_review.retrieval import (
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RetrievalCore,
    write_manifest,
)
from appsec_review.runtime.consume import upstream_scope
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.job import JobContext
from appsec_review.runtime.units import UnitContext
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff

ROOT = Path(__file__).resolve().parents[3]
RUN_ID = "2026-10-08-9100"
JOB_ID = "job_post_build_security_assessment"


def _write_elf64_with_dep(path: Path, *, executable: bool = True) -> None:
    if not executable:
        ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
        hdr = struct.pack("<HHIQQQIHHHHHH", 1, 62, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0)
        path.write_bytes(ident + hdr)
        return
    dynstr = b"\x00libm.so.6\x00"
    phoff = 64
    phnum = 3
    dynstr_off = phoff + phnum * 56
    dyn_entries = b"".join(
        struct.pack("<qQ", tag, val)
        for tag, val in [(5, dynstr_off), (10, len(dynstr)), (1, 1), (0, 0)]
    )
    dyn_off = dynstr_off + len(dynstr)
    total = dyn_off + len(dyn_entries)
    phdrs = b"".join(
        [
            struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 4096),
            struct.pack("<IIQQQQQQ", 2, 6, dyn_off, dyn_off, 0, len(dyn_entries), len(dyn_entries), 8),
            struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16),
        ]
    )
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    hdr = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x1000, phoff, 0, 0, 64, 56, phnum, 64, 0, 0)
    path.write_bytes(ident + hdr + phdrs + dynstr + dyn_entries)


def _write_archive(path: Path) -> None:
    payload = b"object"
    header = (
        "member.o/".ljust(16)
        + "0".ljust(12)
        + "0".ljust(6)
        + "0".ljust(6)
        + "100644".ljust(8)
        + str(len(payload)).ljust(10)
        + "`\n"
    ).encode("ascii")
    path.write_bytes(b"!<arch>\n" + header + payload)


def _pe_bytes(*, managed: bool, pe64: bool = True) -> bytes:
    dos = bytearray(64)
    dos[:2] = b"MZ"
    dos[0x3C:0x40] = (64).to_bytes(4, "little")
    optional = bytearray(240 if pe64 else 224)
    optional[:2] = (0x20B if pe64 else 0x10B).to_bytes(2, "little")
    count_at, dirs_at = (108, 112) if pe64 else (92, 96)
    optional[count_at : count_at + 4] = (16).to_bytes(4, "little")
    if managed:
        entry = dirs_at + 14 * 8
        optional[entry : entry + 8] = (0x2008).to_bytes(4, "little") + (72).to_bytes(4, "little")
    coff = bytearray(20)
    coff[16:18] = len(optional).to_bytes(2, "little")
    return bytes(dos) + b"PE\0\0" + bytes(coff) + bytes(optional)


def _job_config(*, model_enabled: bool = False, max_input_tokens: int = 32000, retries: int = 0) -> JobConfig:
    base = load_config(ROOT / "appsec-review.toml").job(JOB_ID)
    model = {
        **dict(base.settings["model"]),
        "enabled": model_enabled,
        "provider": "fixture",
        "model": "fixture",
        "reasoning": "medium",
        "max_input_tokens": max_input_tokens,
        "max_output_tokens": 1000,
        "timeout_seconds": 10,
        "retries": retries,
    }
    return replace(base, settings=MappingProxyType({"model": MappingProxyType(model)}))


def _make_ctx(
    run_root: Path,
    target_root: Path,
    pins: dict[str, str],
    *,
    attempt_id: str = "attempt_0001",
    source_fingerprint: str = "snapshot",
    config: JobConfig | None = None,
) -> JobContext:
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / attempt_id
    attempt_root.mkdir(parents=True, exist_ok=True)
    metadata_root = run_root / "metadata"
    metadata_root.mkdir(parents=True, exist_ok=True)
    events = EventLog(metadata_root / f"{attempt_id}.events.jsonl")
    return JobContext(
        run_id=RUN_ID,
        attempt_id=attempt_id,
        trigger="unit_test",
        repository_root=ROOT,
        run_root=run_root,
        attempt_root=attempt_root,
        metadata_root=metadata_root,
        orchestration=MappingProxyType({"driver": "unit"}),
        config=config or _job_config(),
        events=events,
        target_root=target_root,
        source_fingerprint=source_fingerprint,
        upstream_handoffs=MappingProxyType(dict(pins)),
        contract=CONTRACT,
    )


def _publish_cpp_handoff(
    run_root: Path,
    target_root: Path,
    projects: dict[str, Any],
    *,
    extra_indexes: tuple[IndexIdentity, ...] = (),
) -> str:
    cpp_root = run_root / "data" / "cpp"
    material = tuple(p for p in sorted(cpp_root.rglob("*")) if p.is_file() and not p.is_symlink()) if cpp_root.is_dir() else ()
    outputs: dict[str, Any] = {"catalog.projects": {"projects": projects}}
    manifest_path = run_root / "data" / "indices" / "manifests" / "cpp.json"
    write_manifest(manifest_path, run_id=RUN_ID, target_snapshot="snapshot", target_root=target_root, indexes=extra_indexes)
    manifest_artifact = {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest_path)}
    outputs["acceptance.publish_handoff"] = {"index_manifest": manifest_artifact}

    attempt = run_root / "data" / "jobs" / "job_cpp_compiled_analysis" / "attempts" / "attempt_0001"
    result_path = attempt / "result.json"
    atomic_json(
        result_path,
        {
            "schema": "appsec-review/unit-execution/2",
            "status": "SUCCEEDED",
            "steps": {},
            "units": {},
            "outputs": outputs,
            "failed_units": [],
            "skipped_units": [],
        },
    )
    result_artifact = {"path": result_path.relative_to(run_root).as_posix(), "sha256": file_sha256(result_path)}
    atomic_json(
        attempt / "claim.json",
        {
            "dataset_contract": dataset_contract(
                "job_cpp_compiled_analysis",
                sorted({item.step for item in CPP_DATASETS} | {u.split(".")[0] for u in outputs}),
                CPP_DATASETS,
            )
        },
    )
    handoff_path = attempt / "handoff.json"
    write_fixture_handoff(
        run_root,
        handoff_path,
        {
            "job_id": "job_cpp_compiled_analysis",
            "attempt_id": "attempt_0001",
            "status": "ACCEPTED",
            "completion_status": "SUCCEEDED",
            "source_fingerprint": "snapshot",
            "artifacts": [
                result_artifact,
                manifest_artifact,
                *({"path": p.relative_to(run_root).as_posix(), "sha256": file_sha256(p)} for p in material),
            ],
            "resolving_paths": {"result": result_artifact["path"]},
            "outputs": outputs,
        },
    )
    sha = file_sha256(handoff_path)
    atomic_json(
        run_root / "data" / "jobs" / "job_cpp_compiled_analysis" / "latest.json",
        {
            "schema": "appsec-review/latest-handoff/1",
            "attempt_id": "attempt_0001",
            "handoff_path": handoff_path.relative_to(run_root).as_posix(),
            "handoff_sha256": sha,
        },
    )
    return sha


def _publish_language_build_handoff(run_root: Path, receipts: list[dict[str, Any]]) -> str:
    attempt = run_root / "data" / "jobs" / "job_language_build" / "attempts" / "attempt_0001"
    doc_path = attempt / "language-build.json"
    atomic_json(
        doc_path,
        {
            "schema": "appsec-review/language-build-handoff/2",
            "source_fingerprint": "snapshot",
            "receipts": receipts,
        },
    )
    doc_artifact = {"path": doc_path.relative_to(run_root).as_posix(), "sha256": file_sha256(doc_path)}
    outputs = {"acceptance.publish_handoff": {"artifact": doc_artifact}}
    atomic_json(
        attempt / "claim.json",
        {
            "dataset_contract": dataset_contract(
                "job_language_build",
                sorted({item.step for item in LANG_DATASETS} | {"acceptance"}),
                LANG_DATASETS,
            )
        },
    )
    build_dir = run_root / "data" / "build"
    material = tuple(p for p in sorted(build_dir.rglob("*")) if p.is_file() and not p.is_symlink()) if build_dir.is_dir() else ()
    handoff_path = attempt / "handoff.json"
    write_fixture_handoff(
        run_root,
        handoff_path,
        {
            "job_id": "job_language_build",
            "attempt_id": "attempt_0001",
            "status": "ACCEPTED",
            "completion_status": "SUCCEEDED",
            "source_fingerprint": "snapshot",
            "artifacts": [
                doc_artifact,
                *({"path": p.relative_to(run_root).as_posix(), "sha256": file_sha256(p)} for p in material),
            ],
            "outputs": outputs,
        },
    )
    sha = file_sha256(handoff_path)
    atomic_json(
        run_root / "data" / "jobs" / "job_language_build" / "latest.json",
        {
            "schema": "appsec-review/latest-handoff/1",
            "attempt_id": "attempt_0001",
            "handoff_path": handoff_path.relative_to(run_root).as_posix(),
            "handoff_sha256": sha,
        },
    )
    return sha


def test_job_module_helpers_custody_managed_pe_and_family_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_root = tmp_path / "runs" / RUN_ID
    target = tmp_path / "target"
    target.mkdir()
    ctx = _make_ctx(run_root, target, {})
    unit = UnitContext(ctx, "provenance.native_units", "provenance", "case-1", ctx.attempt_root / "u1", {})
    unit.unit_root.mkdir(parents=True, exist_ok=True)

    art_file = run_root / "data" / "sample.json"
    art_meta = job_mod._artifact(run_root, art_file, {"ok": True})
    assert job_mod._read_json_artifact(run_root, art_meta) == {"ok": True}
    assert job_mod._artifact(run_root, art_file)["sha256"] == art_meta["sha256"]

    with pytest.raises(ValueError, match="unavailable or outside the run"):
        job_mod._read_json_artifact(run_root, {"path": "../outside.json", "sha256": "0" * 64})
    with pytest.raises(ValueError, match="identity changed"):
        job_mod._read_json_artifact(run_root, {**art_meta, "sha256": "f" * 64})
    with pytest.raises(ValueError, match="case root escapes the run"):
        job_mod._case_root(unit, "../../../../escape")
    with pytest.raises(ValueError, match="output is unavailable"):
        job_mod._stage_case(
            UnitContext(ctx, "x", "x", "c", unit.unit_root, {"provenance.native_units": {"projects": {}}}),
            "provenance",
            "missing",
        )
    with pytest.raises(ValueError, match="accepted C\\+\\+ catalog is unavailable"):
        job_mod._case_catalog(
            UnitContext(ctx, "x", "x", "c", unit.unit_root, {"load.accepted_cpp_build": {"cases": {}}}),
            "missing",
        )

    raw_root = tmp_path / "raw"
    (raw_root / "source").mkdir(parents=True)
    with pytest.raises(ValueError, match="bounded raw compile database is unavailable"):
        job_mod._raw_rows(raw_root)
    (raw_root / "source" / "compile_commands.json").write_text(json.dumps(["bad"]), encoding="utf-8")
    with pytest.raises(ValueError, match="raw compile database is invalid"):
        job_mod._raw_rows(raw_root)
    (raw_root / "source" / "compile_commands.json").write_text(json.dumps([{"command": "cc -c a.c"}]), encoding="utf-8")
    assert len(job_mod._raw_rows(raw_root)) == 1

    (raw_root / "build" / "sub").mkdir(parents=True)
    real_link = raw_root / "build" / "sub" / "link.txt"
    real_link.write_text("\n  \ncc a.o -o app\n", encoding="utf-8")
    (raw_root / "build" / "sym_link.txt").symlink_to(real_link)
    links = job_mod._link_rows(raw_root)
    assert len(links) == 1 and links[0]["command"] == "cc a.o -o app"

    assert job_mod._argv({"argv": ["cc", "-c", "a.c"]}) == ["cc", "-c", "a.c"]
    assert job_mod._argv({"arguments": ["cc", "a.o"]}) == ["cc", "a.o"]
    assert job_mod._argv({"command": "cc -O2 a.c"}) == ["cc", "-O2", "a.c"]

    assert job_mod._is_binary(tmp_path / "nonexistent") is False
    assert job_mod._is_managed_pe(tmp_path / "nonexistent") is False

    for name, payload, expected_managed in [
        ("short.exe", b"MZshort", False),
        ("badpe.exe", b"MZ" + bytes(62) + b"NOPE" + bytes(40), False),
        ("badmagic.exe", b"MZ" + bytes(58) + (64).to_bytes(4, "little") + b"PE\0\0" + bytes(20) + b"\x99\x99" + bytes(40), False),
        ("lowdirs.exe", b"MZ" + bytes(58) + (64).to_bytes(4, "little") + b"PE\0\0" + bytes(20) + (0x20B).to_bytes(2, "little") + bytes(200), False),
        ("il64.dll", _pe_bytes(managed=True, pe64=True), True),
        ("il32.dll", _pe_bytes(managed=True, pe64=False), True),
        ("aot64.exe", _pe_bytes(managed=False, pe64=True), False),
    ]:
        p = tmp_path / name
        p.write_bytes(payload)
        assert job_mod._is_managed_pe(p) is expected_managed, name

    # Family provenance: regular binary, wheel with > limit & oversized member, bad wheel, tampered binary
    elf_file = run_root / "data" / "build" / "go" / "u1" / "svc"
    elf_file.parent.mkdir(parents=True, exist_ok=True)
    _write_elf64_with_dep(elf_file)
    tampered = run_root / "data" / "build" / "go" / "u1" / "tampered"
    _write_elf64_with_dep(tampered)
    bad_wheel = run_root / "data" / "build" / "py" / "u1" / "corrupt.whl"
    bad_wheel.parent.mkdir(parents=True, exist_ok=True)
    bad_wheel.write_bytes(b"not-a-zip")
    good_wheel = run_root / "data" / "build" / "py" / "u1" / "pkg.whl"
    with zipfile.ZipFile(good_wheel, "w") as zf:
        zf.writestr("pkg/a.so", elf_file.read_bytes())
        zf.writestr("pkg/b.so", elf_file.read_bytes())
        zf.writestr("pkg/__init__.py", "x = 1\n")

    # Also test family_build_cases skipping escaping/symlink paths
    sym_bin = run_root / "data" / "build" / "go" / "u1" / "sym"
    sym_bin.symlink_to(elf_file)
    cases = job_mod.family_build_cases(
        {
            "receipts": [
                {
                    "build_unit_id": "go1",
                    "family": "go",
                    "terminal_status": "SUCCEEDED",
                    "artifacts": [
                        {"path": "../escape", "sha256": "0" * 64, "size_bytes": 1, "kind": "executable"},
                        {"path": sym_bin.relative_to(run_root).as_posix(), "sha256": "0" * 64, "size_bytes": 1, "kind": "executable"},
                        {"path": elf_file.relative_to(run_root).as_posix(), "sha256": file_sha256(elf_file), "size_bytes": elf_file.stat().st_size, "kind": "executable"},
                    ],
                },
                {
                    "build_unit_id": "native1",
                    "family": "native",
                    "terminal_status": "SUCCEEDED",
                    "artifacts": [],
                },
            ]
        },
        run_root,
    )
    assert list(cases) == ["family-go1"]

    monkeypatch.setattr(job_mod, "_ARCHIVE_MEMBER_LIMIT", 1)
    fam_prov = job_mod._family_provenance(
        unit,
        "family-mixed",
        {
            "family": "python",
            "artifacts": [
                {"path": elf_file.relative_to(run_root).as_posix(), "sha256": file_sha256(elf_file), "kind": "executable"},
                {"path": tampered.relative_to(run_root).as_posix(), "sha256": "0" * 64, "kind": "executable"},
                {"path": good_wheel.relative_to(run_root).as_posix(), "sha256": file_sha256(good_wheel), "kind": "wheel"},
                {"path": bad_wheel.relative_to(run_root).as_posix(), "sha256": file_sha256(bad_wheel), "kind": "wheel"},
            ],
        },
    )
    assert fam_prov["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert len(fam_prov["artifacts"]) == 2
    assert any("identity changed: tampered" in g for g in fam_prov["gaps"])
    assert any("binary member bound reached" in g for g in fam_prov["gaps"])
    assert any("package archive could not be inspected" in g for g in fam_prov["gaps"])


def test_handler_executes_native_family_na_and_blocked_cases_and_reuses_shards(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    run_root = runs / RUN_ID
    target = tmp_path / "target"
    target.mkdir()

    # Upstream index from another producer to verify publish() preserves non-build_security indexes
    other_db = run_root / "data" / "indices" / "cpp" / "other.sqlite"
    other_builder = IndexBuilder(other_db, name="compiled", fingerprint="9" * 64, target_snapshot="snapshot", shard_id="cpp-0")
    other_builder.add_entity(
        EntityRecord(
            LogicalIdentity.derive(EntityKind.BUILD_ACTION, "snapshot", {"id": "cpp-act"}),
            "cpp-act",
            "cpp-act",
            "upstream action",
            {"project": "unit-a"},
        )
    )
    other_sha = other_builder.build()
    other_index = IndexIdentity(
        "compiled",
        "appsec-review/retrieval-index/2",
        other_sha,
        "9" * 64,
        other_db.relative_to(run_root).as_posix(),
        {"job": "job_cpp_compiled_analysis"},
        (),
        "cpp-0",
    )

    case_root = run_root / "data" / "cpp" / "projects" / "unit-a"
    (case_root / "build" / "CMakeFiles" / "app.dir").mkdir(parents=True)
    (case_root / "source").mkdir()
    source = case_root / "source" / "main.cpp"
    source.write_text("int main() { return 0; }\n", encoding="utf-8")
    binary = case_root / "build" / "app"
    _write_elf64_with_dep(binary, executable=True)
    obj = case_root / "build" / "app.o"
    _write_elf64_with_dep(obj, executable=False)
    archive = case_root / "build" / "libapp.a"
    _write_archive(archive)
    for variant in ("var_a", "var_b"):
        dup = case_root / "build" / variant / "dup.cpp.o"
        dup.parent.mkdir(parents=True)
        _write_elf64_with_dep(dup, executable=False)
    # Uncataloged bitcode + ignored plain text in build/
    (case_root / "build" / "extra.bc").write_bytes(b"BC\xc0\xde\x00\x00\x00\x00")
    (case_root / "build" / "README.txt").write_text("ignored", encoding="utf-8")
    mismatched = case_root / "build" / "stale.o"
    _write_elf64_with_dep(mismatched, executable=False)

    (case_root / "build" / "CMakeFiles" / "app.dir" / "link.txt").write_text(
        f"llvm-ar rcs {archive} {obj} {case_root / 'build/var_a/dup.cpp.o'} {case_root / 'build/var_b/dup.cpp.o'}\n"
        f"clang++ {obj} -Wl,-z,relro,-z,now -pie -o {binary}\n",
        encoding="utf-8",
    )
    (case_root / "analysis" / "binary").mkdir(parents=True)
    (case_root / "analysis" / "binary" / "records.json").write_text(
        json.dumps(
            [
                {
                    "path": "build/app",
                    "kind": "executable",
                    "sha256": file_sha256(binary),
                    "symbols": ["main T 0 1"],
                    "metadata": "ELF metadata",
                }
            ]
        ),
        encoding="utf-8",
    )
    (case_root / "build" / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(case_root / "build"),
                    "file": str(source),
                    "arguments": [
                        "clang++",
                        "-c",
                        str(source),
                        "-o",
                        "app.o",
                        "-fstack-protector-strong",
                        "-fPIE",
                        "-DAPI_TOKEN=super-secret",
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )

    projects = {
        "unit-a": {
            "terminal_status": "SUCCEEDED",
            "mapping": {"root": "projects/cpp/unit-a", "build_system": "cmake"},
            "outputs": [
                {"path": "build/app", "kind": "executable", "sha256": file_sha256(binary), "size_bytes": binary.stat().st_size},
                {"path": "build/app.o", "kind": "object", "sha256": file_sha256(obj), "size_bytes": obj.stat().st_size},
                {"path": "build/libapp.a", "kind": "library", "sha256": file_sha256(archive), "size_bytes": archive.stat().st_size},
                {"path": "build/missing.o", "kind": "object", "sha256": "0" * 64, "size_bytes": 1},
                {"path": "build/stale.o", "kind": "object", "sha256": "1" * 64, "size_bytes": 1},
            ],
            "image_id": "sha256:" + "1" * 64,
        },
        "unit-na": {
            "terminal_status": "NOT_APPLICABLE",
        },
        "unit-blocked": {
            "terminal_status": "COMPLETED_WITH_GAPS",
            "gaps": ["upstream native build was blocked"],
        },
    }
    cpp_sha = _publish_cpp_handoff(run_root, target, projects, extra_indexes=(other_index,))

    go_bin = run_root / "data" / "build" / "go" / "go-1" / "svc"
    go_bin.parent.mkdir(parents=True, exist_ok=True)
    _write_elf64_with_dep(go_bin, executable=True)
    lang_sha = _publish_language_build_handoff(
        run_root,
        [
            {
                "build_unit_id": "go-1",
                "family": "go",
                "root": "services/go-1",
                "terminal_status": "SUCCEEDED",
                "image": {"image_id": "sha256:" + "2" * 64},
                "artifacts": [
                    {
                        "path": go_bin.relative_to(run_root).as_posix(),
                        "sha256": file_sha256(go_bin),
                        "size_bytes": go_bin.stat().st_size,
                        "kind": "executable",
                    }
                ],
            }
        ],
    )
    pins = {"job_cpp_compiled_analysis": cpp_sha, "job_language_build": lang_sha}
    job = build_job()

    ctx1 = _make_ctx(run_root, target, pins, attempt_id="attempt_0001")
    with upstream_scope(run_root, JOB_ID, pins, contract=CONTRACT):
        first = job.handler(ctx1)
    assert first["status"] == "COMPLETED_WITH_GAPS"
    outputs1 = first["outputs"]
    assert outputs1["publication.publish_handoff"]["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert outputs1["provenance.native_units"]["projects"]["unit-na"]["terminal_status"] == "NOT_APPLICABLE"
    assert outputs1["inspection.native_units"]["projects"]["unit-na"]["terminal_status"] == "NOT_APPLICABLE"
    assert outputs1["deterministic.native_units"]["projects"]["unit-na"]["terminal_status"] == "NOT_APPLICABLE"
    assert outputs1["inference.native_units"]["projects"]["unit-na"]["terminal_status"] == "NOT_APPLICABLE"
    assert outputs1["inference.native_units"]["projects"]["unit-blocked"]["model_calls"] == 0
    assert outputs1["provenance.native_units"]["projects"]["family-go-1"]["family"] == "go"

    unit_a_prov = outputs1["provenance.native_units"]["projects"]["unit-a"]
    assert any("cataloged artifact unavailable: missing.o" in g for g in unit_a_prov["gaps"])
    assert any("cataloged artifact hash mismatch: stale.o" in g for g in unit_a_prov["gaps"])
    assert unit_a_prov["actions"][0]["discovered_inputs"][0]["path"] == "source/main.cpp"

    indexed1 = outputs1["index.native_units"]["projects"]
    assert set(indexed1) == {"family-go-1", "unit-a", "unit-blocked", "unit-na"}
    assert all(item["index_reused"] is False for item in indexed1.values())

    # Second run reuses every immutable shard via attest_existing()
    ctx2 = _make_ctx(run_root, target, pins, attempt_id="attempt_0002")
    with upstream_scope(run_root, JOB_ID, pins, contract=CONTRACT):
        second = job.handler(ctx2)
    indexed2 = second["outputs"]["index.native_units"]["projects"]
    assert all(item["index_reused"] is True for item in indexed2.values())

    # Bind accepted.json to inspect build_security relations via RetrievalCore
    pub = second["outputs"]["publication.publish_handoff"]
    pub_handoff = ctx2.attempt_root / "handoff.json"
    write_fixture_handoff(
        run_root,
        pub_handoff,
        {
            "job_id": JOB_ID,
            "attempt_id": "attempt_0002",
            "status": "ACCEPTED",
            "source_fingerprint": "snapshot",
            "artifacts": [pub["index_manifest"], pub["artifact"]],
        },
    )
    atomic_json(
        run_root / "data" / "indices" / "accepted.json",
        {
            "schema": "appsec-review/accepted-index-set/1",
            "run_id": RUN_ID,
            "handoff_path": pub_handoff.relative_to(run_root).as_posix(),
            "handoff_sha256": file_sha256(pub_handoff),
            "manifest_path": pub["index_manifest"]["path"],
            "manifest_sha256": pub["index_manifest"]["sha256"],
        },
    )
    manifest_doc = json.loads((run_root / pub["index_manifest"]["path"]).read_text(encoding="utf-8"))
    assert any(idx["name"] == "compiled" for idx in manifest_doc["indexes"])
    core = RetrievalCore(runs, RUN_ID)
    dups = core.find(name="dup.cpp.o", indexes=("build_security",))["results"]
    assert len(dups) == 2
    for item in dups:
        traced = core.trace(identity=item["identity"], relations=("LINKS_INTO",), depth=1)
        assert len(traced["results"]) == 1
    app_res = core.find(name="app", indexes=("build_security",))["results"]
    assert any(
        core.trace(identity=item["identity"], relations=("DEPENDS_ON",), depth=1)["results"]
        for item in app_res
    )


def test_handler_generic_protected_provenance_and_fallback_branches(tmp_path: Path) -> None:
    run_root = tmp_path / "runs" / RUN_ID
    target = tmp_path / "target"
    target.mkdir()

    # Case 1: valid generic protected_compile_commands + valid execution receipt + invalid pinned records.json
    c1 = run_root / "data" / "cpp" / "projects" / "unit-generic"
    (c1 / "build").mkdir(parents=True)
    (c1 / "analysis" / "binary").mkdir(parents=True)
    bin1 = c1 / "build" / "tool"
    _write_elf64_with_dep(bin1, executable=True)
    prot_path = c1 / "protected-cmds.json"
    atomic_json(
        prot_path,
        {
            "schema": "appsec-review/protected-compile-commands/1",
            "rows": [
                {"command": "   "},
                {
                    "argv": ["clang", "-c", "a.c", "-o", "tool"],
                    "start": "2026-10-08T00:00:00Z",
                    "end": "2026-10-08T00:00:01Z",
                    "exit_status": 0,
                },
            ],
        },
    )
    exec_path = c1 / "exec.json"
    atomic_json(
        exec_path,
        {"started_at": "2026-10-08T00:00:00Z", "completed_at": "2026-10-08T00:00:02Z", "exit_code": 0},
    )

    # Case 2: invalid protected_compile_commands schema + broken execution receipt + no compile_commands/link.txt
    c2 = run_root / "data" / "cpp" / "projects" / "unit-fallback"
    (c2 / "build").mkdir(parents=True)
    bad_prot = c2 / "bad-protected.json"
    atomic_json(bad_prot, {"schema": "wrong/1", "rows": []})

    projects = {
        "unit-generic": {
            "terminal_status": "SUCCEEDED",
            "mapping": {"root": "pkg/gen", "build_system": "make"},
            "build_receipt": {
                "protected_compile_commands": {
                    "path": prot_path.relative_to(run_root).as_posix(),
                    "sha256": file_sha256(prot_path),
                },
                "execution": {
                    "path": exec_path.relative_to(run_root).as_posix(),
                    "sha256": file_sha256(exec_path),
                },
            },
            "outputs": [
                {"path": "build/tool", "kind": "executable", "sha256": file_sha256(bin1), "size_bytes": bin1.stat().st_size}
            ],
        },
        "unit-fallback": {
            "terminal_status": "SUCCEEDED",
            "mapping": {"root": "pkg/fb", "build_system": "custom"},
            "build_receipt": {
                "protected_compile_commands": {
                    "path": bad_prot.relative_to(run_root).as_posix(),
                    "sha256": file_sha256(bad_prot),
                },
                "execution": {"path": "missing.json", "sha256": "0" * 64},
            },
            "outputs": [],
        },
    }
    cpp_sha = _publish_cpp_handoff(run_root, target, projects)
    (c1 / "analysis" / "binary" / "records.json").write_text("{invalid-json", encoding="utf-8")
    pins = {"job_cpp_compiled_analysis": cpp_sha}
    ctx = _make_ctx(run_root, target, pins)
    with upstream_scope(run_root, JOB_ID, pins, contract=CONTRACT):
        res = build_job().handler(ctx)

    load_out = res["outputs"]["load.accepted_cpp_build"]
    assert any("accepted language-build handoff is unavailable" in g for g in load_out["gaps"])

    gen_prov = res["outputs"]["provenance.native_units"]["projects"]["unit-generic"]
    assert any("build action 0 had no parseable argv" in g for g in gen_prov["gaps"])
    assert gen_prov["actions"][0]["timing_granularity"] == "action"
    assert gen_prov["actions"][0]["argv_source"] == "generic-build-protected-argv"

    gen_insp = res["outputs"]["inspection.native_units"]["projects"]["unit-generic"]
    assert any("pinned native binary-tool output was invalid" in g for g in gen_insp["gaps"])
    assert any("pinned nm/readelf observation was unavailable" in g for g in gen_insp["gaps"])

    fb_prov = res["outputs"]["provenance.native_units"]["projects"]["unit-fallback"]
    assert any("generic build action provenance unavailable" in g for g in fb_prov["gaps"])
    assert any("compile action provenance unavailable" in g for g in fb_prov["gaps"])
    assert any("exact linker/archiver provenance was not emitted" in g for g in fb_prov["gaps"])
    assert any("accepted build execution receipt is unavailable" in g for g in fb_prov["gaps"])


def test_handler_inference_modes_retries_empty_cases_and_snapshot_drift(tmp_path: Path) -> None:
    # 1. Empty cases -> aggregate NOT_APPLICABLE, publish SUCCEEDED
    empty_root = tmp_path / "empty_run" / RUN_ID
    target = tmp_path / "target"
    target.mkdir()
    empty_cpp = _publish_cpp_handoff(empty_root, target, {})
    empty_lang = _publish_language_build_handoff(empty_root, [])
    empty_pins = {"job_cpp_compiled_analysis": empty_cpp, "job_language_build": empty_lang}
    with upstream_scope(empty_root, JOB_ID, empty_pins, contract=CONTRACT):
        empty_res = build_job().handler(_make_ctx(empty_root, target, empty_pins))
    assert empty_res["outputs"]["provenance.native_units"]["terminal_status"] == "NOT_APPLICABLE"
    assert empty_res["outputs"]["publication.publish_handoff"]["terminal_status"] == "SUCCEEDED"
    with upstream_scope(empty_root, JOB_ID, empty_pins, contract=CONTRACT):
        drifted_res = build_job().handler(
            _make_ctx(empty_root, target, empty_pins, attempt_id="attempt_drift", source_fingerprint="drifted")
        )
    assert drifted_res["status"] == "FAILED"
    assert (
        "target snapshot differs from accepted build"
        in drifted_res["units"]["load.accepted_cpp_build"]["error"]["message"]
    )

    # 2. Model enabled modes: infer=None, budget exceeded, retry->success, and retry->exhausted
    run_root = tmp_path / "inf_run" / RUN_ID
    case_root = run_root / "data" / "cpp" / "projects" / "unit-inf"
    (case_root / "build").mkdir(parents=True)
    (case_root / "source").mkdir()
    src = case_root / "source" / "a.c"
    src.write_text("int f(void){return 0;}\n", encoding="utf-8")
    exe = case_root / "build" / "app"
    _write_elf64_with_dep(exe, executable=True)
    (case_root / "build" / "compile_commands.json").write_text(
        json.dumps([{"directory": str(case_root / "build"), "file": str(src), "arguments": ["clang", "-c", "a.c", "-o", "app"]}]),
        encoding="utf-8",
    )
    cpp_sha = _publish_cpp_handoff(
        run_root,
        target,
        {
            "unit-inf": {
                "terminal_status": "SUCCEEDED",
                "mapping": {"root": "pkg/inf", "build_system": "cmake"},
                "outputs": [{"path": "build/app", "kind": "executable", "sha256": file_sha256(exe), "size_bytes": exe.stat().st_size}],
            }
        },
    )
    lang_sha = _publish_language_build_handoff(run_root, [])
    pins = {"job_cpp_compiled_analysis": cpp_sha, "job_language_build": lang_sha}

    # infer=None with model enabled
    with upstream_scope(run_root, JOB_ID, pins, contract=CONTRACT):
        unavail = build_job(infer=None).handler(
            _make_ctx(run_root, target, pins, attempt_id="attempt_unavail", config=_job_config(model_enabled=True))
        )
    assert any(
        "inference model is unavailable" in g
        for g in unavail["outputs"]["inference.native_units"]["projects"]["unit-inf"]["gaps"]
    )

    # max_input_tokens=1 -> budget exceeded
    with upstream_scope(run_root, JOB_ID, pins, contract=CONTRACT):
        over = build_job(infer=None).handler(
            _make_ctx(
                run_root,
                target,
                pins,
                attempt_id="attempt_budget",
                config=_job_config(model_enabled=True, max_input_tokens=1),
            )
        )
    assert any(
        "exceeded its configured input budget" in g
        for g in over["outputs"]["inference.native_units"]["projects"]["unit-inf"]["gaps"]
    )

    # Retry on invalid model proposal (ValueError -> ModelOutputError) then succeed on attempt 2
    attempts = {"count": 0}

    def flaky_infer(request: ModelRequest, *, timeout_seconds: int) -> ModelResult:
        attempts["count"] += 1
        if attempts["count"] == 1:
            return ModelResult({"schema": job_mod.INFERENCE_PROPOSAL_SCHEMA, "observations": "not-a-list"},
                               input_tokens=5, output_tokens=2, cache_tokens=0)
        act = request.summary["actions"][0]
        art = request.summary["artifacts"][0]
        return ModelResult(
            {
                "schema": job_mod.INFERENCE_PROPOSAL_SCHEMA,
                "observations": [
                    {"claim": "non-PIE binary", "check_id": "elf.pie", "evidence_ids": [art["sha256"]]},
                    {"claim": "no insecure override", "check_id": "gnu.insecure_override", "evidence_ids": [act["build_action_id"]]},
                    {"claim": "bad ref", "check_id": "elf.pie", "evidence_ids": ["nonexistent"]},
                ]
            },
            input_tokens=15,
            output_tokens=10,
            cache_tokens=1,
        )

    with upstream_scope(run_root, JOB_ID, pins, contract=CONTRACT):
        retried = build_job(infer=flaky_infer).handler(
            _make_ctx(
                run_root,
                target,
                pins,
                attempt_id="attempt_retry_ok",
                config=_job_config(model_enabled=True, retries=1),
            )
        )
    inf_ok = retried["outputs"]["inference.native_units"]["projects"]["unit-inf"]
    assert inf_ok["model_calls"] == 2
    assert inf_ok["confirmed_count"] == 1 and inf_ok["refuted_count"] == 1
    assert any("1 inference observations were rejected" in g for g in inf_ok["gaps"])

    # Exhausted retries on ProviderError
    def failing_infer(_request: ModelRequest, *, timeout_seconds: int) -> ModelResult:
        raise ProviderError("simulated provider outage")

    with upstream_scope(run_root, JOB_ID, pins, contract=CONTRACT):
        failed = build_job(infer=failing_infer).handler(
            _make_ctx(
                run_root,
                target,
                pins,
                attempt_id="attempt_retry_fail",
                config=_job_config(model_enabled=True, retries=0),
            )
        )
    inf_fail = failed["outputs"]["inference.native_units"]["projects"]["unit-inf"]
    assert any("failed after bounded retries (ProviderError)" in g for g in inf_fail["gaps"])
