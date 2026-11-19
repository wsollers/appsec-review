"""Real bounded parsers and artifact producer-to-priority regressions for T-5103/5104/5105."""

from __future__ import annotations

import io
from copy import deepcopy
from fnmatch import fnmatch
import json
from pathlib import Path
import sqlite3
import struct
import tarfile
import zipfile

import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

from appsec_review.jobs.job_artifact_security_analysis import job as security
from appsec_review.jobs.job_artifact_indexing import canonical_artifact_identity
from appsec_review.jobs.job_artifact_security_analysis.formats import (
    ArchiveLimits, builtin_observation, classify, parse_wasm,
)
from appsec_review.jobs.job_review_prioritization.composite import _load_artifact_leads, apply_composite_prioritization
from appsec_review.retrieval import EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, write_manifest
from appsec_review.retrieval.index import INDEX_SCHEMA
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner
from appsec_review.tool_inputs import partition_artifacts
from tests.handoff_fixture import write_fixture_handoff

from .test_formats import _leb128, _minimal_jvm_class, _wasm_name, _wasm_section
from .test_job_graph import _seed_artifact, _unit_context
from .test_lead_promotion import _minimal_elf64
from .support import ROOT


@pytest.mark.parametrize("defined", [False, True], ids=["imported-only", "mixed"])
def test_imported_wasm_resources_contribute_features_without_losing_origin(defined):
    imports = b"\x02" + _wasm_name("env") + _wasm_name("memory") + b"\x02\x07\x01\x02"
    imports += _wasm_name("env") + _wasm_name("table") + b"\x01\x6f\x00\x01"
    data = b"\0asm\x01\0\0\0" + _wasm_section(2, imports)
    if defined:
        data += _wasm_section(5, b"\x01\x00\x01")
    facts = parse_wasm(data)
    assert facts["has_memory"] is True and facts["has_tables"] is True
    assert facts["features"] == {"shared_memory": True, "memory64": True,
                                 "multiple_memories": defined, "reference_tables": True}
    assert len(facts["imports"]) == 2
    assert facts["memories"] == ([{"minimum": 1, "shared": 0, "memory64": 0}] if defined else [])
    assert facts["tables"] == []


def test_imported_memory64_keeps_full_width_limits():
    imports = b"\x01" + _wasm_name("env") + _wasm_name("memory") + b"\x02\x05"
    imports += _leb128(2**40) + _leb128(2**41)
    facts = parse_wasm(b"\0asm\x01\0\0\0" + _wasm_section(2, imports))
    assert facts["features"]["memory64"] is True
    assert facts["imports"][0]["limits"]["maximum"] == 2**41


def test_imported_wasm_limits_cannot_borrow_the_next_section_bytes(tmp_path):
    imports = b"\x01" + _wasm_name("env") + _wasm_name("memory") + b"\x02\x00"
    path = tmp_path / "module.wasm"
    path.write_bytes(b"\0asm\x01\0\0\0" + _wasm_section(2, imports) + _wasm_section(0, b"\0"))
    facts, gaps = builtin_observation(path, classify(path, {}), "wasm", ArchiveLimits())
    assert facts == {} and any("parse failure" in gap for gap in gaps)


def _fat_macho(*, endian=">", wide=False):
    magic = (b"\xca\xfe\xba\xbf" if wide else b"\xca\xfe\xba\xbe")
    if endian == "<":
        magic = magic[::-1]
    thin = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 0, 0, 0, 0)
    offset = 40 if wide else 32
    arch = struct.pack(endian + ("IIQQII" if wide else "IIIII"),
                       0x01000007, 3, offset, len(thin), 3, *([0] if wide else []))
    return magic + struct.pack(endian + "I", 1) + arch + b"\0" * (offset - 8 - len(arch)) + thin


@pytest.mark.parametrize(("endian", "wide"), [(">", False), ("<", False), (">", True), ("<", True)],
                         ids=["fat", "cigam", "fat64", "cigam64"])
def test_universal_macho_is_native_and_never_routed_to_spotbugs(tmp_path, endian, wide):
    path = tmp_path / "misleading.class"
    path.write_bytes(_fat_macho(endian=endian, wide=wide))
    facts = classify(path, {"kind": "executable"})
    assert facts["format"] == "macho" and facts["family"] == "native"
    assert facts["universal"] is True and facts["architecture_count"] == 1
    for tool in ("blint", "cve-bin-tool"):
        assert not partition_artifacts("artifact:tool-" + tool, (("a", path.name, facts["format"]),)).not_applicable
    assert partition_artifacts("artifact:tool-spotbugs", (("a", path.name, facts["format"]),)).not_applicable


@pytest.mark.parametrize("damage", ["truncated-table", "slice-outside", "wrong-slice", "overlap"])
def test_malformed_fat_headers_do_not_become_java_coverage(tmp_path, damage):
    data = bytearray(_fat_macho())
    if damage == "truncated-table":
        data = data[:16]
    elif damage == "slice-outside":
        data[16:20] = struct.pack(">I", 4096)
    elif damage == "wrong-slice":
        data[32:36] = b"nope"
    else:
        data[4:8] = struct.pack(">I", 2)
        arch = struct.pack(">IIIII", 0x01000007, 3, 48, 32, 3)
        data = bytearray(data[:8] + arch + arch + data[32:])
    path = tmp_path / "broken.class"
    path.write_bytes(data)
    facts = classify(path, {})
    assert facts["format"] != "jvm-class"
    assert facts.get("gaps")
    _, gaps = builtin_observation(path, facts, "inventory", ArchiveLimits())
    assert gaps


def test_shared_magic_still_recognizes_real_java_class_header(tmp_path):
    path = tmp_path / "native"
    path.write_bytes(_minimal_jvm_class())
    assert classify(path, {"kind": "executable"})["format"] == "jvm-class"


def _context(root, artifacts, *, attempt="attempt_0001", releases=True, capability="blint",
             producer_gaps=(), settings=None):
    ctx, _ = _unit_context(root, unit_id="analyze." + capability, attempt_id=attempt,
                           declared_releases=releases, settings_override=settings)
    if "resolved_config_sha256" not in json.loads((ctx.job.attempt_root / "claim.json").read_text()):
        write_fixture_handoff(root, ctx.job.attempt_root / "handoff.json", {
            "job_id": "job_artifact_security_analysis", "attempt_id": attempt,
            "source_fingerprint": ctx.job.source_fingerprint, "outputs": {}})
        (ctx.job.attempt_root / "result.json").unlink()
    for artifact in artifacts:
        artifact["canonical_identity"] = canonical_artifact_identity(
            ctx.job.source_fingerprint, artifact["build_unit_id"], artifact).value
    manifest = root / "data/indices/manifests/upstream.json"
    if not manifest.exists():
        path = root / "data/indices/artifacts/upstream.sqlite"
        sha = IndexBuilder(path, name="artifacts", fingerprint="b" * 64,
                           target_snapshot=ctx.job.source_fingerprint).build()
        identity = IndexIdentity("artifacts", INDEX_SCHEMA, sha, "b" * 64,
                                 path.relative_to(root).as_posix(), {"job": "job_artifact_indexing"})
        write_manifest(manifest, run_id=root.name, target_snapshot=ctx.job.source_fingerprint,
                       target_root=root, indexes=[identity])
    outputs = {"load.accepted_artifacts": {
        "source_fingerprint": ctx.job.source_fingerprint, "language_build_handoff_sha256": "b" * 64,
        "artifact_index": security._identity(root, manifest), "artifacts": artifacts,
        "artifact_count": len(artifacts), "producer_gaps": list(producer_gaps)},
        **{"analyze." + cap: {"observations": [], "gaps": []} for cap in security.CAPABILITIES}}
    ctx.output = outputs.__getitem__
    return ctx, outputs


def _run(ctx, outputs, capability, runner=None):
    units = {unit.unit_id: unit.handler for unit in security.build_job(scanner_runner=runner).units}
    with publication_scope_for_owner(SharedArtifacts.for_job(ctx.job)):
        outputs["analyze." + capability] = units["analyze." + capability](ctx)
        outputs["index.observations"] = units["index.observations"](ctx)
        outputs["acceptance.publish_handoff"] = units["acceptance.publish_handoff"](ctx)
    return outputs


def _entities(root, outputs):
    path = root / outputs["index.observations"]["index_identity"]["relative_path"]
    with sqlite3.connect(path) as db:
        return [json.loads(row[0]) for row in db.execute(
            "SELECT payload_json FROM entities WHERE kind = 'tool_observation' ORDER BY identity")]


def _accept(ctx, outputs):
    path = ctx.job.attempt_root / "handoff.json"
    write_fixture_handoff(ctx.job.run_root, path, {
        "job_id": "job_artifact_security_analysis", "attempt_id": ctx.job.attempt_id,
        "source_fingerprint": ctx.job.source_fingerprint, "outputs": outputs})
    atomic_json(ctx.job.run_root / "data/jobs/job_artifact_security_analysis/latest.json", {
        "handoff_path": path.relative_to(ctx.job.run_root).as_posix(), "handoff_sha256": file_sha256(path)})


def _scanner(ctx, findings):
    receipt = ctx.job.attempt_root / "artifacts/asa/execution.json"
    atomic_json(receipt, {"exit_code": 0})

    def run(*args):
        return {"payload": json.dumps({"findings": findings, "analyzed": [{"report": "fixture"}]}).encode(),
                "exit_code": 0, "execution_receipt": security._identity(ctx.job.run_root, receipt)}
    return run


@pytest.mark.parametrize("archive_format", ["zip", "tar"])
def test_packaged_risk_task_indexes_redacted_uncertain_findings(tmp_path, archive_format):
    stream = io.BytesIO()
    text = b"services:\n  api:\n    privileged: true\n    client_secret: fixture_secret_value_123456\n"
    if archive_format == "zip":
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("compose.yml", text)
    else:
        with tarfile.open(fileobj=stream, mode="w") as archive:
            info = tarfile.TarInfo("compose.yml")
            info.size = len(text)
            archive.addfile(info, io.BytesIO(text))
    root = tmp_path / "run"
    artifact = _seed_artifact(root, "data/build/package.bin", stream.getvalue(), kind="package")
    ctx, outputs = _context(root, [artifact], capability="packages")
    _run(ctx, outputs, "packages")
    findings = [row for row in _entities(root, outputs) if row.get("record_kind") == "finding"]
    assert {row["common"]["rule_id"] for row in findings} == {
        "SECRET_HARDCODED_CREDENTIAL", "CONTAINER_PRIVILEGED_MODE"}
    for row in findings:
        assert row["severity"] is None and row["severity_hint"] == "unknown"
        assert row["member_path"] == "compose.yml" and row["subject_artifact"] == artifact["canonical_identity"]
        assert row["common"]["evidence_refs"][0]["selector"]["value"].startswith("/security_risks/")
        assert "fixture_secret_value_123456" not in json.dumps(row)
    assert outputs["index.observations"]["terminal_status"] == "COMPLETED_WITH_GAPS"


@pytest.mark.parametrize("damage", ["duplicate", "oversize", "encoding", "link", "traversal"])
def test_packaged_risk_task_retains_explicit_gaps_for_uninspectable_members(tmp_path, damage):
    stream = io.BytesIO()
    text = b"privileged: true\n"
    with zipfile.ZipFile(stream, "w") as archive:
        info = zipfile.ZipInfo("../compose.yml" if damage == "traversal" else "compose.yml")
        if damage == "link":
            info.external_attr = 0o120777 << 16
        archive.writestr(info, b"\xff" if damage == "encoding" else text)
        if damage == "duplicate":
            with pytest.warns(UserWarning, match="Duplicate name"):
                archive.writestr("compose.yml", b"privileged: false\n")
    root = tmp_path / "run"
    artifact = _seed_artifact(root, payload=stream.getvalue(), kind="package")
    ctx, outputs = _context(root, [artifact], capability="packages",
                            settings={"archive_member_bytes": 4} if damage == "oversize" else None)
    _run(ctx, outputs, "packages")
    assert outputs["index.observations"]["finding_count"] == 0
    gaps = outputs["index.observations"]["gaps"]
    expected = {"duplicate": "duplicate packaged member", "oversize": "member byte limit",
                "encoding": "not UTF-8", "link": "member rejected", "traversal": "member rejected"}[damage]
    assert any(expected in gap for gap in gaps)
    assert outputs["acceptance.publish_handoff"]["terminal_status"] == "COMPLETED_WITH_GAPS"


@pytest.mark.parametrize("truncated", [False, True], ids=["complete", "partial"])
def test_native_risk_task_never_infers_canary_or_relro_from_missing_bytes(tmp_path, truncated):
    root = tmp_path / "run"
    data = _minimal_elf64()
    if truncated:
        data = data[:70]
    artifact = _seed_artifact(root, payload=data)
    ctx, outputs = _context(root, [artifact], capability="native")
    _run(ctx, outputs, "native")
    findings = [row for row in _entities(root, outputs) if row.get("record_kind") == "finding"]
    rules = {row["rule_id"] for row in findings}
    assert rules == ({"CHECK_PIE"} if truncated else {"CHECK_PIE", "CHECK_NX", "CHECK_RELRO"})
    assert all(row["severity"] is None and row["severity_hint"] == "unknown" for row in findings)
    assert "CHECK_CANARY" not in rules
    gaps = outputs["index.observations"]["gaps"]
    assert any("canary" in gap for gap in gaps)
    if truncated:
        assert any("program header" in gap and "truncated" in gap for gap in gaps)


@pytest.mark.parametrize("damage", ["class", "version", "size"])
def test_malformed_elf_headers_do_not_generate_hardening_claims(tmp_path, damage):
    root = tmp_path / "run"
    data = bytearray(_minimal_elf64())
    if damage == "class":
        data[4] = 0
    elif damage == "version":
        data[6] = 0
    else:
        data[52:54] = b"\0\0"
    artifact = _seed_artifact(root, payload=data)
    ctx, outputs = _context(root, [artifact], capability="native")
    _run(ctx, outputs, "native")
    assert outputs["index.observations"]["finding_count"] == 0
    assert any("ELF header is invalid" in gap for gap in outputs["index.observations"]["gaps"])


def test_priority_reads_distinct_artifact_findings_and_preserves_unknown(tmp_path):
    root = tmp_path / "run"
    artifacts = [_seed_artifact(root, f"data/build/{name}", _minimal_elf64()) for name in ("server", "client")]
    ctx, outputs = _context(root, artifacts)
    _run(ctx, outputs, "blint", _scanner(ctx, [
        {"id": "CHECK_NX", "title": "NX indicator", "filename": "binary"},
        {"id": "CHECK_NX", "title": "second NX indicator", "filename": "binary", "severity": "medium"}]))
    _accept(ctx, outputs)
    _, leads = _load_artifact_leads(root, True)
    assert len(leads) == 4 and len({row["lead_id"] for row in leads}) == 4
    assert {row["severity_hint"] for row in leads} == {"unknown", "medium"}
    assert {row["subject_artifact"] for row in leads} == {row["canonical_identity"] for row in artifacts}
    for row in leads:
        assert row["path"] is None and row["line"] is None
        assert row["observation_identity"].startswith("asr:tool_observation:")
        assert row["subject"] == "binary" and row["evidence_refs"]
    _, _, document = apply_composite_prioritization(
        root, target_snapshot=ctx.job.source_fingerprint, settings={"sources": {
            key: key == "artifact_security" for key in ("change_context", "test_coverage", "profile_data",
                "ci_configuration", "artifact_security", "dependency_intelligence", "sast_silence_hunt")}},
        semantic_doc={}, ranked_files=[], ranked_functions=[])
    schema = json.loads((ROOT / "docs/schemas/review-prioritization/prioritization-signals.schema.json").read_text())
    interchange = json.loads((ROOT / "docs/schemas/job-interchange.schema.json").read_text())
    validator = Draft202012Validator(schema, registry=Registry().with_resource(
        interchange["$id"], Resource.from_contents(interchange)))
    validator.validate(document)
    assert document["promoted_leads"] == leads
    legacy = deepcopy(document)
    for lead in legacy["promoted_leads"]:
        for field in ("observation_identity", "subject_artifact", "subject", "evidence_refs"):
            del lead[field]
    validator.validate(legacy)
    invalid_values = [
        (("observation_identity",), "not-an-observation"),
        (("observation_identity",), 42),
        (("subject_artifact",), "data/build/server"),
        (("subject_artifact",), {}),
        (("subject",), []),
        (("subject",), ""),
        (("evidence_refs",), {}),
        (("evidence_refs", 0, "unexpected"), True),
        (("evidence_refs", 0, "complete"), "yes"),
        (("evidence_refs", 0, "artifact", "sha256"), "not-a-hash"),
        (("evidence_refs", 0, "artifact", "path"), "../outside"),
        (("evidence_refs", 0, "artifact", "size_bytes"), -1),
        (("evidence_refs", 0, "selector", "value"), "not-a-pointer"),
        (("evidence_refs", 0, "selector", "unexpected"), True),
        (("evidence_refs", 0, "retention_receipt", "sha256"), "not-a-hash"),
    ]
    for keys, value in invalid_values:
        malformed = deepcopy(document)
        node = malformed["promoted_leads"][0]
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value
        with pytest.raises(ValidationError):
            validator.validate(malformed)


@pytest.mark.parametrize("conflict", [False, True], ids=["identical", "conflict"])
def test_priority_duplicate_observation_identity_is_never_last_wins(tmp_path, conflict):
    root = tmp_path / "run"
    artifact = _seed_artifact(root, payload=_minimal_elf64())
    ctx, outputs = _context(root, [artifact])
    _run(ctx, outputs, "blint", _scanner(ctx, [
        {"id": "CHECK_NX", "filename": "binary", "severity": "medium"}]))
    original = outputs["index.observations"]["index_identity"]
    with sqlite3.connect(root / original["relative_path"]) as db:
        identity, raw = db.execute(
            "SELECT identity,payload_json FROM entities WHERE json_extract(payload_json,'$.record_kind')='finding'"
        ).fetchone()
    payload = json.loads(raw)
    if conflict:
        payload["severity_hint"] = "critical"
    path = root / "data/indices/observations/duplicate.sqlite"
    builder = IndexBuilder(path, name="observations", fingerprint="d" * 64,
                           target_snapshot=ctx.job.source_fingerprint, shard_id="duplicate")
    builder.add_entity(EntityRecord(LogicalIdentity.parse(identity), "duplicate", "CHECK_NX", "duplicate", payload))
    duplicate = IndexIdentity("observations", INDEX_SCHEMA, builder.build(), "d" * 64,
                              path.relative_to(root).as_posix(), {"job": "job_artifact_security_analysis"},
                              (), "duplicate")
    manifest = root / "data/indices/manifests/duplicate.json"
    write_manifest(manifest, run_id=root.name, target_snapshot=ctx.job.source_fingerprint,
                   target_root=root, indexes=[IndexIdentity(**original), duplicate])
    outputs["index.observations"]["index_manifest"] = security._identity(root, manifest)
    publish = next(unit.handler for unit in security.build_job().units
                   if unit.unit_id == "acceptance.publish_handoff")
    outputs["acceptance.publish_handoff"] = publish(ctx)
    _accept(ctx, outputs)
    if conflict:
        with pytest.raises(ValueError, match="conflicting artifact finding identity"):
            _load_artifact_leads(root, True)
    else:
        _, leads = _load_artifact_leads(root, True)
        assert len(leads) == 1 and leads[0]["severity_hint"] == "medium"


@pytest.mark.parametrize("change", ["new-finding", "same-count", "same-attempt", "coverage"])
def test_nonreusable_results_and_indexes_bind_current_content_without_mutation(tmp_path, change):
    root = tmp_path / "run"
    artifact = _seed_artifact(root, payload=_minimal_elf64())
    first_findings = [] if change == "new-finding" else [
        {"id": "CHECK_PIE", "title": "first", "filename": "binary", "severity": "high"}]
    ctx, first = _context(root, [artifact], releases=False)
    _run(ctx, first, "blint", _scanner(ctx, first_findings))
    scan1 = first["analyze.blint"]["observations"][0]
    bound = [scan1["result_artifact"], *scan1["raw_artifacts"], first["index.observations"]["index_manifest"]]
    original = {ref["path"]: (root / ref["path"]).read_bytes() for ref in bound}
    ctx2, second = _context(root, [artifact], releases=False,
                            attempt="attempt_0001" if change == "same-attempt" else "attempt_0002",
                            producer_gaps=["upstream coverage unavailable"] if change == "coverage" else [])
    current = first_findings if change == "coverage" else [
        {"id": "CHECK_NX", "title": "second", "filename": "binary", "severity": "low"}]
    _run(ctx2, second, "blint", _scanner(ctx2, current))
    scan2 = second["analyze.blint"]["observations"][0]
    assert scan1["fingerprint"] == scan2["fingerprint"] and not scan2["reused"]
    assert original == {path: (root / path).read_bytes() for path in original}
    assert first["index.observations"]["index_manifest"] != second["index.observations"]["index_manifest"]
    findings = [row for row in _entities(root, second) if row.get("record_kind") == "finding"]
    assert len(findings) == second["acceptance.publish_handoff"]["finding_count"] == len(current)
    assert [row["rule_id"] for row in findings] == [row["id"] for row in current]
    assert all(row["result_artifact"] == scan2["result_artifact"] for row in findings)


def test_released_input_reuses_exact_result_and_rejects_changed_bound_content(tmp_path):
    root = tmp_path / "run"
    artifact = _seed_artifact(root, payload=_minimal_elf64())
    ctx, outputs = _context(root, [artifact])
    _run(ctx, outputs, "blint", _scanner(ctx, [
        {"id": "CHECK_PIE", "filename": "binary", "severity": "high"}]))
    first = outputs["analyze.blint"]["observations"][0]
    from appsec_review.jobs.job_artifact_security_analysis.datasets import DATASETS
    for path in sorted((root / "data/artifact-security").rglob("*.json")):
        relative = path.relative_to(root).as_posix()
        owners = [declaration for declaration in DATASETS
                  if any(fnmatch(relative, pattern) for pattern in declaration.artifacts)]
        assert len(owners) == 1
        assert owners[0].output_kind == ("artifact_scanner_io" if "/checkpoints/" in relative
                                        else "artifact_security_results")
    ctx2, next_outputs = _context(root, [artifact], attempt="attempt_0002")

    def unexpected_execution(*args):
        pytest.fail("unchanged released input must reuse the bound result")

    _run(ctx2, next_outputs, "blint", unexpected_execution)
    reused = next_outputs["analyze.blint"]["observations"][0]
    assert reused["reused"] and reused["result_artifact"] == first["result_artifact"]
    assert next_outputs["index.observations"]["index_manifest"] == outputs["index.observations"]["index_manifest"]
    path = root / reused["result_artifact"]["path"]
    changed = json.loads(path.read_text())
    changed["observation"]["findings"][0]["severity"] = "low"
    atomic_json(path, changed)
    with publication_scope_for_owner(SharedArtifacts.for_job(ctx2.job)):
        with pytest.raises(security.FrameworkIntegrityError, match="identity changed"):
            security._scan_one(ctx2, artifact, "blint", unexpected_execution)


def test_reused_scan_reindexes_changed_coverage_without_rerunning_scanner(tmp_path):
    root = tmp_path / "run"
    artifact = _seed_artifact(root, payload=_minimal_elf64())
    ctx, first = _context(root, [artifact])
    _run(ctx, first, "blint", _scanner(ctx, []))
    ctx2, second = _context(root, [artifact], attempt="attempt_0002", producer_gaps=["upstream incomplete"])
    _run(ctx2, second, "blint", lambda *args: pytest.fail("released scan must be reused"))
    assert second["analyze.blint"]["observations"][0]["reused"]
    assert first["index.observations"]["index_manifest"] != second["index.observations"]["index_manifest"]
    path = root / second["index.observations"]["index_identity"]["relative_path"]
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT status FROM coverage").fetchall() == [("partial",)]
    assert "upstream incomplete" in second["acceptance.publish_handoff"]["gaps"]
