from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import struct

import pytest

from appsec_review.inference import ModelResult
from appsec_review.jobs.job_post_build_security_assessment import assessment, build_job
from appsec_review.runtime.units import UnitContext
from appsec_review.storage import atomic_json, file_sha256
from tests.unit.job_post_build_security_assessment.test_handlers import (
    RUN_ID, _job_config, _make_ctx, _pe_bytes, _write_elf64_with_dep,
)


def _action(argv, action_id="compile"):
    return assessment.normalize_action(
        {"arguments": argv, "directory": "/workspace/build", "file": "a.c"},
        action_id=action_id, run_id=RUN_ID, target_snapshot="snapshot",
        project="project", build_root="build", configuration="Release",
        producer={"job": "job_language_build"}, toolchain={"executable": argv[0]},
        protected_artifact={"path": "commands.json", "sha256": "1" * 64},
    )


@pytest.mark.parametrize("compiler", ["cc", "c++", "cl", "ccache", "sccache"])
def test_compiler_aliases_keep_compile_checks(compiler):
    argv = ([compiler, "cc"] if compiler in {"ccache", "sccache"} else [compiler])
    argv += (["/c", "a.c", "/GS-"] if compiler == "cl" else
             ["-c", "a.c", "-o", "a.o", "-fno-stack-protector"])
    action = _action(argv)
    assert action["classification"] == "compiler"
    assert action["compile_unit_id"]
    checks = assessment.deterministic_checks([action], [])
    assert next(c for c in checks if c["check_id"] in {"gnu.stack_protector", "msvc.gs"})["status"] == "FAIL"


@pytest.mark.parametrize(("flags", "check", "status"), [
    (["-O2", "-O0", "-D_FORTIFY_SOURCE=2"], "gnu.fortify", "FAIL"),
    (["-O0", "-O2", "-D_FORTIFY_SOURCE=2"], "gnu.fortify", "PASS"),
    (["-O2", "-D_FORTIFY_SOURCE=2", "-U_FORTIFY_SOURCE"], "gnu.fortify", "FAIL"),
    (["-O2", "-U_FORTIFY_SOURCE", "-D", "_FORTIFY_SOURCE=2"], "gnu.fortify", "PASS"),
    (["-fcf-protection=full", "-fcf-protection=none"], "gnu.control_flow", "FAIL"),
    (["-fcf-protection=none", "-fcf-protection=full"], "gnu.control_flow", "PASS"),
    (["-fno-stack-protector", "-fstack-protector-strong"], "gnu.stack_protector", "PASS"),
    (["-fno-stack-protector", "-fstack-protector-strong"], "gnu.insecure_override", "PASS"),
    (["-O2", "-D_FORTIFY_SOURCE=2", "@flags.rsp"], "gnu.fortify", "UNKNOWN"),
    (["-fcf-protection=full", "@flags.rsp"], "gnu.control_flow", "UNKNOWN"),
])
def test_effective_flags_preserve_override_order(flags, check, status):
    checks = assessment.deterministic_checks([_action(["gcc", "-c", "a.c", *flags])], [])
    assert next(c for c in checks if c["check_id"] == check)["status"] == status


@pytest.mark.parametrize("bits", [32, 64])
def test_pe_high_entropy_is_architecture_applicable(tmp_path, bits):
    path = tmp_path / "image.exe"
    path.write_bytes(_pe_bytes(managed=False, pe64=bits == 64))
    record = {**assessment.inspect_binary(path), "artifact_id": "image"}
    link = {**_action(["link.exe", "/HIGHENTROPYVA", "/OUT:image.exe"]),
            "linked_artifact_ids": ["image"]}
    checks = assessment.deterministic_checks([link], [record])
    high = next(c for c in checks if c["check_id"] == "pe.high_entropy_va")
    assert high["status"] == ("NOT_APPLICABLE" if bits == 32 else "FAIL")
    assert high["applicable"] is (bits == 64)
    assert any(c["check_id"] == "command_binary.high_entropy_va_mismatch" for c in checks) is (bits == 64)


def test_requested_flags_apply_only_to_exact_linked_output():
    link = {**_action(["ld", "-pie", "-z", "relro", "-z", "now", "-o", "one"], "link"),
            "linked_artifact_ids": ["one"]}
    artifacts = [{"artifact_id": name, "sha256": name + "-hash", "format": "ELF", "kind": kind,
                  "hardening": {"pie": False, "relro": False, "now": False}}
                 for name, kind in [("one", "executable"), ("two", "executable"), ("object", "object")]]
    mismatches = [c for c in assessment.deterministic_checks([link], artifacts)
                  if c["check_id"].startswith("command_binary.")]
    assert {c["scope"] for c in mismatches} == {"one"}
    assert len(mismatches) == 3
    assert all(c["evidence"] == ["link", "one-hash"] for c in mismatches)
    link["argv"] += ["-no-pie", "-z", "norelro", "-z", "lazy"]
    assert not [c for c in assessment.deterministic_checks([link], artifacts)
                if c["check_id"].startswith("command_binary.")]


@pytest.mark.parametrize(("bits", "endian"), [(32, "<"), (32, ">"), (64, "<"), (64, ">")])
def test_macho_object_magic_precedes_coff_suffix(tmp_path, bits, endian):
    path = tmp_path / "unit.o"
    values = [0xFEEDFACF if bits == 64 else 0xFEEDFACE, 0x01000007 if bits == 64 else 7,
              3, 1, 0, 0, 0]
    if bits == 64:
        values.append(0)
    path.write_bytes(struct.pack(endian + "IiiIIII" + ("I" if bits == 64 else ""), *values))
    record = assessment.inspect_binary(path)
    assert (record["format"], record["kind"], record["bits"]) == ("Mach-O", "object", bits)
    assert not any("malformed" in gap for gap in record["gaps"])


@pytest.mark.parametrize("problem", ["extent", "entry-size", "dynamic-payload"])
def test_truncated_elf_does_not_invent_absent_protections(tmp_path, problem):
    path = tmp_path / "truncated"
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    if problem == "dynamic-payload":
        header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
        phdr = struct.pack("<IIQQQQQQ", 2, 6, 120, 120, 0, 64, 64, 8)
        payload = struct.pack("<qQ", 5, 120)
    else:
        header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 4096 if problem == "extent" else 64,
                             8192, 0, 64, 56 if problem == "extent" else 0, 1, 64, 1, 0)
        phdr, payload = b"", b""
    path.write_bytes(ident + header + phdr + payload)
    record = assessment.inspect_binary(path)
    assert record["format"] == "ELF"
    assert record["gaps"]
    key = "now" if problem == "dynamic-payload" else "relro"
    assert record["hardening"][key] is None
    check = next(c for c in assessment.deterministic_checks([], [record]) if c["check_id"] == f"elf.{key}")
    assert check["status"] == "UNKNOWN"
    if problem != "dynamic-payload":
        assert record["symbols"]["stripped"] is None
        assert record["debug"]["present"] is None


def test_inference_requires_subject_bound_evidence_and_retains_scope():
    check = {"check_id": "elf.pie", "scope": "A", "status": "FAIL", "evidence": ["hash-A"]}
    proposal = {"schema": assessment.INFERENCE_PROPOSAL_SCHEMA, "observations": [
        {"claim": "non-PIE", "check_id": "elf.pie", "scope": "A", "evidence_ids": ["hash-B"]},
        {"claim": "non-PIE", "check_id": "elf.pie", "scope": "A", "evidence_ids": ["hash-A"]},
    ]}
    result = assessment.validate_inference(proposal, checks=[check], evidence_ids=["hash-A", "hash-B"])
    assert result["confirmed_count"] == 1
    assert len(result["rejections"]) == 1
    assert result["observations"][0]["scope"] == "A"
    assert result["observations"][0]["evidence_ids"] == ["hash-A"]


@pytest.mark.parametrize("proposal", [
    {"schema": assessment.INFERENCE_PROPOSAL_SCHEMA, "error": "unable to assess"},
    {"schema": assessment.INFERENCE_PROPOSAL_SCHEMA, "observations": [], "error": "unable to assess"},
    {"schema": "wrong", "observations": []},
])
def test_error_shaped_inference_is_not_an_empty_success(proposal):
    with pytest.raises(ValueError):
        assessment.validate_inference(proposal, checks=[], evidence_ids=[])


def _fixture(tmp_path, *, rows=None, outputs=None):
    run_root = tmp_path / "runs" / RUN_ID
    root = run_root / "data" / "cpp" / "projects" / "case"
    (root / "build").mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir()
    ctx = _make_ctx(run_root, target, {})
    if rows is None:
        rows = [{"directory": str(root / "build"), "arguments": ["cc", "-c", "a.c", "-o", "a.o"]}]
    if outputs is None:
        binary = root / "build" / "a.o"
        _write_elf64_with_dep(binary, executable=False)
        outputs = [{"path": "build/a.o", "kind": "object", "sha256": file_sha256(binary)}]
    atomic_json(root / "build" / "compile_commands.json", rows)
    from appsec_review.retrieval import write_manifest
    manifest = run_root / "data" / "indices" / "manifests" / "cpp.json"
    write_manifest(manifest, run_id=RUN_ID, target_snapshot="snapshot", target_root=target, indexes=())
    state = {"load.accepted_cpp_build": {
        "cases": {"case": {"terminal_status": "SUCCEEDED", "mapping": {"root": "project"}, "outputs": outputs}},
        "upstream_manifest": {"path": manifest.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest)},
    }}
    return ctx, root, state


def _stage(ctx, state, stage, *, infer=None):
    job = build_job(infer=infer)
    unit_id = f"{stage}.native_units" if stage != "publication" else "publication.publish_handoff"
    unit = next(unit for unit in job.units if unit.unit_id == unit_id)
    directory = ctx.attempt_root / "steps" / stage / "tasks" / "native_units"
    directory.mkdir(parents=True, exist_ok=True)
    result = unit.handler(UnitContext(ctx, unit_id, stage, "native_units", directory, state))
    state[unit_id] = result
    return result if stage == "publication" else result["projects"]["case"]


def _through_index(ctx, state, *, infer=None):
    for stage in ("provenance", "inspection", "deterministic", "inference", "index"):
        result = _stage(ctx, state, stage, infer=infer)
    return result


@pytest.mark.parametrize("ambiguous", [False, True])
def test_exact_provenance_uses_cwd_not_basename(tmp_path, ambiguous):
    ctx, root, state = _fixture(tmp_path, rows=[], outputs=[])
    rows, artifacts = [], []
    for directory in ("one", "two"):
        path = root / "build" / directory / "dup.o"
        path.parent.mkdir()
        _write_elf64_with_dep(path, executable=False)
        rows.append({"directory": str(path.parent), "arguments": ["cc", "-c", f"{directory}.c", "-o", "dup.o"]})
        artifacts.append({"path": path.relative_to(root).as_posix(), "kind": "object", "sha256": file_sha256(path)})
    if ambiguous:
        rows.append({**rows[0], "arguments": ["clang", "-c", "other.c", "-o", "dup.o"]})
    atomic_json(root / "build" / "compile_commands.json", rows)
    state["load.accepted_cpp_build"]["cases"]["case"]["outputs"] = artifacts
    provenance = _stage(ctx, state, "provenance")
    by_path = {a["path"]: a["artifact_id"] for a in provenance["artifacts"]}
    assert provenance["actions"][0]["linked_artifact_ids"] == ([] if ambiguous else [by_path["build/one/dup.o"]])
    assert provenance["actions"][1]["linked_artifact_ids"] == [by_path["build/two/dup.o"]]
    assert provenance["relationships_exact"] is (not ambiguous)
    if ambiguous:
        assert provenance["actions"][2]["linked_artifact_ids"] == []
        assert any("producing action" in gap for gap in provenance["gaps"])


def test_rejected_catalog_hash_is_not_rediscovered(tmp_path):
    ctx, root, state = _fixture(tmp_path)
    state["load.accepted_cpp_build"]["cases"]["case"]["outputs"][0]["sha256"] = "0" * 64
    result = _through_index(ctx, state)
    assert state["provenance.native_units"]["projects"]["case"]["artifacts"] == []
    assert state["inspection.native_units"]["projects"]["case"]["records"] == []
    assert any("hash mismatch" in gap for gap in result["gaps"])
    assert _stage(ctx, state, "publication")["terminal_status"] == "COMPLETED_WITH_GAPS"


def test_oversized_binary_publishes_an_indexable_gap(tmp_path, monkeypatch):
    ctx, root, state = _fixture(tmp_path)
    monkeypatch.setattr(assessment, "MAX_BINARY_BYTES", 4)
    result = _through_index(ctx, state)
    record = state["inspection.native_units"]["projects"]["case"]["records"][0]
    assert record["kind"] == "unknown" and record["executed"] is False
    assert any("byte bound" in gap for gap in result["gaps"])
    assert _stage(ctx, state, "publication")["terminal_status"] == "COMPLETED_WITH_GAPS"
    with sqlite3.connect(ctx.run_root / result["artifact"]["path"]) as db:
        assert db.execute("SELECT COUNT(*) FROM entities WHERE native_id=?", (record["artifact_id"],)).fetchone()[0] == 1


@pytest.mark.parametrize("changed_stage", ["provenance", "inspection", "deterministic", "inference"])
def test_shards_bind_actual_stage_results_even_when_binary_is_unchanged(tmp_path, changed_stage):
    ctx, root, state = _fixture(tmp_path)
    first = _through_index(ctx, state)
    assert _stage(ctx, state, "index")["index_reused"] is True
    first_hash = first["artifact"]["sha256"]
    value = state[f"{changed_stage}.native_units"]["projects"]["case"]
    document = json.loads((ctx.run_root / value["artifact"]["path"]).read_text())
    document["gaps"].append("new assessment evidence")
    if changed_stage == "inference":
        document["observations"] = [{"observation_id": "new-observation", "claim": "new assessment",
                                    "check_id": "gnu.stack_protector", "scope": "compile",
                                    "evidence_ids": [], "validation": "UNVALIDATED"}]
    path = ctx.attempt_root / f"changed-{changed_stage}.json"
    atomic_json(path, document)
    value.update(document)
    value["artifact"] = {"path": path.relative_to(ctx.run_root).as_posix(), "sha256": file_sha256(path),
                         "size_bytes": path.stat().st_size}
    second = _stage(ctx, state, "index")
    assert second["index_reused"] is False
    assert second["artifact"]["path"] != first["artifact"]["path"]
    assert file_sha256(ctx.run_root / first["artifact"]["path"]) == first_hash
    assert value["artifact"] in second["source_artifacts"]
    if changed_stage == "inference":
        with sqlite3.connect(ctx.run_root / second["artifact"]["path"]) as db:
            assert db.execute("SELECT COUNT(*) FROM entities WHERE native_id='new-observation'").fetchone()[0] == 1
    published = _stage(ctx, state, "publication")
    manifest = json.loads((ctx.run_root / published["index_manifest"]["path"]).read_text())
    assert manifest["indexes"][0]["sha256"] == second["artifact"]["sha256"]


@pytest.mark.parametrize("recover", [False, True])
def test_handler_retries_error_shaped_response_and_records_exhaustion(tmp_path, recover):
    ctx, root, state = _fixture(tmp_path)
    ctx = replace(ctx, config=_job_config(model_enabled=True, retries=1))
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        if recover and len(calls) == 2:
            return ModelResult({"schema": assessment.INFERENCE_PROPOSAL_SCHEMA, "observations": []},
                               input_tokens=1, output_tokens=1)
        return ModelResult({"schema": assessment.INFERENCE_PROPOSAL_SCHEMA, "error": "unable to assess"},
                           input_tokens=1, output_tokens=1)

    _through_index(ctx, state, infer=infer)
    result = state["inference.native_units"]["projects"]["case"]
    assert result["model_calls"] == 2
    assert result["terminal_status"] == ("SUCCEEDED" if recover else "COMPLETED_WITH_GAPS")
    assert bool(result["gaps"]) is (not recover)
    if not recover:
        assert any("ModelOutputError" in gap for gap in result["gaps"])


@pytest.mark.parametrize("captured", [False, True])
def test_link_edges_require_exact_cwd_and_input_paths(tmp_path, captured):
    ctx, root, state = _fixture(tmp_path, rows=[], outputs=[])
    rows, artifacts = [], []
    for directory in ("one", "two"):
        build = root / "build" / directory
        build.mkdir()
        for name in ("dup.o", "app"):
            path = build / name
            _write_elf64_with_dep(path, executable=name == "app")
            artifacts.append({"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path)})
        if captured:
            rows.append({"directory": f"/workspace/out/{directory}",
                         "argv": ["cc", "-Wl,-z,relro", "dup.o", "-o", "app"]})
        else:
            (build / "link.txt").write_text("cc -Wl,-z,relro dup.o -o app\n")
    catalog = state["load.accepted_cpp_build"]["cases"]["case"]
    catalog["outputs"] = artifacts
    if captured:
        protected = root / "commands.json"
        atomic_json(protected, {"schema": "appsec-review/protected-compile-commands/1", "rows": rows})
        catalog["build_receipt"] = {
            "workspace": "data/build/native/workspace", "recipe": {"build_dir": "out"},
            "protected_compile_commands": {"path": protected.relative_to(ctx.run_root).as_posix(),
                                           "sha256": file_sha256(protected)},
        }
    indexed = _through_index(ctx, state)
    provenance = state["provenance.native_units"]["projects"]["case"]
    checks = state["deterministic.native_units"]["projects"]["case"]["checks"]
    mismatches = [check for check in checks if check["check_id"].startswith("command_binary.")]
    with sqlite3.connect(ctx.run_root / indexed["artifact"]["path"]) as db:
        edges = db.execute("""
            SELECT s.native_id, t.native_id FROM relations r
            JOIN entities s ON s.identity=r.source_id JOIN entities t ON t.identity=r.target_id
            WHERE r.kind='LINKS_INTO'
        """).fetchall()
    artifacts_by_path = {a["path"]: a["artifact_id"] for a in provenance["artifacts"]}
    if captured:
        assert len(mismatches) == 2
        for directory in ("one", "two"):
            obj, app = (artifacts_by_path[f"build/{directory}/{name}"] for name in ("dup.o", "app"))
            assert (obj, app) in edges
            other = artifacts_by_path[f"build/{'two' if directory == 'one' else 'one'}/dup.o"]
            assert (other, app) not in edges
    else:
        assert edges == []
        assert mismatches == []
        assert any("working directory unavailable" in gap for gap in provenance["gaps"])


def test_inspection_does_not_accept_post_provenance_byte_drift(tmp_path):
    ctx, root, state = _fixture(tmp_path)
    _stage(ctx, state, "provenance")
    (root / "build" / "a.o").write_bytes(b"changed")
    result = _stage(ctx, state, "inspection")
    assert result["records"] == []
    assert any("hash changed before inspection" in gap for gap in result["gaps"])


def test_real_model_results_and_enabled_state_invalidate_only_derived_shards(tmp_path):
    ctx, root, state = _fixture(tmp_path)
    ctx = replace(ctx, config=_job_config(model_enabled=True))
    claim = "first explanation"

    def infer(request, *, timeout_seconds):
        assert request.summary["response_schema"]["additionalProperties"] is False
        action = request.summary["actions"][0]
        return ModelResult({"schema": assessment.INFERENCE_PROPOSAL_SCHEMA, "observations": [{
            "claim": claim, "check_id": "gnu.stack_protector", "scope": action["compile_unit_id"],
            "evidence_ids": [action["compile_unit_id"]],
        }]}, input_tokens=1, output_tokens=1)

    first = _through_index(ctx, state, infer=infer)
    original_binary = file_sha256(root / "build" / "a.o")
    first_observation = state["inference.native_units"]["projects"]["case"]["observations"][0]
    claim = "second explanation"
    ctx = replace(ctx, attempt_id="attempt_0002", attempt_root=ctx.attempt_root.parent / "attempt_0002")
    _stage(ctx, state, "inference", infer=infer)
    second = _stage(ctx, state, "index")
    assert not second["index_reused"]
    assert second["artifact"]["path"] != first["artifact"]["path"]
    assert file_sha256(root / "build" / "a.o") == original_binary
    second_observation = state["inference.native_units"]["projects"]["case"]["observations"][0]
    assert second_observation["observation_id"] != first_observation["observation_id"]
    with sqlite3.connect(ctx.run_root / second["artifact"]["path"]) as db:
        assert db.execute("SELECT text FROM entities WHERE native_id=?",
                          (second_observation["observation_id"],)).fetchone() == (claim,)
        assert db.execute("SELECT COUNT(*) FROM relations r JOIN entities e ON e.identity=r.source_id "
                          "WHERE e.native_id=? AND r.kind='OBSERVED_AT'",
                          (second_observation["observation_id"],)).fetchone()[0] == 1
    disabled = replace(ctx, config=_job_config(model_enabled=False))
    _stage(disabled, state, "inference", infer=infer)
    third = _stage(disabled, state, "index")
    assert third["index_reused"] is False
    assert third["artifact"]["path"] not in {first["artifact"]["path"], second["artifact"]["path"]}
    assert any("disabled" in gap for gap in third["gaps"])


def test_index_rejects_unbound_in_memory_stage_content(tmp_path):
    ctx, root, state = _fixture(tmp_path)
    _through_index(ctx, state)
    state["deterministic.native_units"]["projects"]["case"]["checks"][0]["status"] = "FAIL"
    with pytest.raises(ValueError, match="stage content differs"):
        _stage(ctx, state, "index")


def test_artifact_alias_cannot_confirm_a_different_path_with_identical_bytes():
    checks = [{"check_id": "elf.pie", "scope": scope, "status": "FAIL", "evidence": ["same-hash"]}
              for scope in ("A", "B")]
    proposal = {"schema": assessment.INFERENCE_PROPOSAL_SCHEMA, "observations": [
        {"claim": "non-PIE", "check_id": "elf.pie", "scope": "A", "evidence_ids": ["B"]},
        {"claim": "non-PIE", "check_id": "elf.pie", "scope": "A", "evidence_ids": ["A"]},
    ]}
    result = assessment.validate_inference(proposal, checks=checks, evidence_ids=["A", "B", "same-hash"],
                                          evidence_aliases={"A": "same-hash", "B": "same-hash"})
    assert result["confirmed_count"] == 1 and len(result["rejections"]) == 1
    assert result["observations"][0]["evidence_ids"] == ["A"]


@pytest.mark.parametrize("invalid", [{"claim": 42}, {"evidence_ids": [42]}, {"error": "failed"}])
def test_model_observations_do_not_coerce_types_or_accept_error_fields(invalid):
    observation = {"claim": "no PIE", "check_id": "elf.pie", "evidence_ids": ["hash"], **invalid}
    result = assessment.validate_inference(
        {"schema": assessment.INFERENCE_PROPOSAL_SCHEMA, "observations": [observation]},
        checks=[{"check_id": "elf.pie", "scope": "A", "status": "FAIL", "evidence": ["hash"]}],
        evidence_ids=["hash", "42"])
    assert result["observations"] == [] and len(result["rejections"]) == 1


def test_unrecognized_compiler_does_not_get_exact_producing_edges(tmp_path):
    ctx, root, state = _fixture(tmp_path)
    atomic_json(root / "build" / "compile_commands.json", [
        {"directory": str(root / "build"), "arguments": ["unknown-compiler", "-c", "a.c", "-o", "a.o"]},
    ])
    provenance = _stage(ctx, state, "provenance")
    assert provenance["actions"][0]["classification"] == "unknown"
    assert provenance["actions"][0]["linked_artifact_ids"] == []
    assert any("could not be classified" in gap for gap in provenance["gaps"])


@pytest.mark.parametrize(("flags", "expected"), [
    (["/GS-", "/GS"], "PASS"),
    (["/GS", "/GS-"], "FAIL"),
])
def test_msvc_override_order_is_preserved(flags, expected):
    checks = assessment.deterministic_checks([_action(["cl", "/c", "a.c", *flags])], [])
    assert next(check for check in checks if check["check_id"] == "msvc.gs")["status"] == expected


def test_same_hash_observed_at_edges_retain_the_selected_artifact(tmp_path):
    ctx, root, state = _fixture(tmp_path, rows=[], outputs=[])
    outputs = []
    for name in ("one", "two"):
        binary = root / "build" / name
        _write_elf64_with_dep(binary)
        outputs.append({"path": f"build/{name}", "sha256": file_sha256(binary)})
    state["load.accepted_cpp_build"]["cases"]["case"]["outputs"] = outputs
    result = _through_index(ctx, state)
    with sqlite3.connect(ctx.run_root / result["artifact"]["path"]) as db:
        rows = db.execute("""
            SELECT json_extract(s.payload_json, '$.scope'), t.native_id
            FROM relations r JOIN entities s ON s.identity=r.source_id
            JOIN entities t ON t.identity=r.target_id
            WHERE r.kind='OBSERVED_AT' AND s.name='elf.pie'
        """).fetchall()
    assert len(rows) == 2
    assert all(scope == artifact for scope, artifact in rows)
