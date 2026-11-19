"""Code-level unit tests for job_binary_evidence_indexing helpers, shard builder, and units."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest

from appsec_review.binary_decompilation import decompile_binary, store_root
from appsec_review.config import BinaryDecompilationSettings, BinaryRequest, load_config
from appsec_review.indexing.inventory import Claim, FileClaims, runtime_claims, scan_run_tree
from appsec_review.jobs.job_binary_evidence_indexing.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_binary_evidence_indexing.job import (
    INTAKE_SCHEMA,
    JOB_ID,
    SCHEMA,
    SETTINGS,
    _Binary,
    _clip,
    _line_of,
    _read_verified,
    _settings,
    _short,
    accepted_binary_evidence,
    build_job,
    index_binary,
    managed_routing,
    verified_publication,
)
from appsec_review.observability import EventLog
from appsec_review.retrieval import EntityKind, IndexBuilder, RetrievalCore, write_manifest
from appsec_review.runtime import UnitContext
from appsec_review.runtime.consume import UpstreamNotPinnedError, upstream_scope
from appsec_review.storage import atomic_json, canonical_json, file_sha256, run_artifact
from tests.binary_decompilation_fakes import FakeDocker, write_export
from tests.handoff_fixture import write_fixture_handoff


REPO_ROOT = Path(__file__).resolve().parents[3]
BINARY_BYTES = b"\x7fELF synthetic vendor library"
BINARY_SHA = hashlib.sha256(BINARY_BYTES).hexdigest()
SNAPSHOT = "b" * 64


def _unit_context(
    run_root: Path,
    unit_id: str,
    *,
    outputs: dict[str, Any] | None = None,
    settings_override: dict[str, Any] | None = None,
    input_manifest_path: str | None = None,
    input_manifest_sha256: str | None = None,
) -> UnitContext:
    config = load_config(REPO_ROOT / "appsec-review.toml")
    raw_settings = dict(config.job(JOB_ID).settings)
    if settings_override:
        raw_settings.update(settings_override)
    job_cfg = SimpleNamespace(
        steps=config.job(JOB_ID).steps,
        step=config.job(JOB_ID).step,
        settings=MappingProxyType(raw_settings),
    )
    step_id, task_id = unit_id.split(".", 1)
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / "attempt-1"
    unit_root = attempt_root / "steps" / step_id / "tasks" / task_id
    unit_root.mkdir(parents=True, exist_ok=True)
    target_root = run_root.parent / "target"
    target_root.mkdir(parents=True, exist_ok=True)
    job_ctx = SimpleNamespace(
        run_id=run_root.name,
        attempt_id="attempt-1",
        repository_root=REPO_ROOT,
        run_root=run_root,
        attempt_root=attempt_root,
        target_root=target_root,
        source_fingerprint=SNAPSHOT,
        config=job_cfg,
        events=EventLog(run_root / "metadata" / "events.jsonl"),
        input_manifest_path=input_manifest_path,
        input_manifest_sha256=input_manifest_sha256,
    )
    return UnitContext(
        job=job_ctx,
        unit_id=unit_id,
        step_id=step_id,
        task_id=task_id,
        unit_root=unit_root,
        outputs=outputs or {},
    )


def _write_intake_handoff(
    run_root: Path,
    binary_doc: dict[str, Any] | list[Any],
    *,
    intake_schema: str = "appsec-review/review-intake/1",
    binary_ref_override: Any = ...,
) -> str:
    attempt = run_root / "data" / "jobs" / "job_review_intake" / "attempts" / "attempt-1"
    bin_path = attempt / "steps" / "binary_evidence" / "tasks" / "resolve_publications" / "binary-evidence.json"
    atomic_json(bin_path, binary_doc)
    bin_art = run_artifact(run_root, bin_path)

    intake_path = attempt / "steps" / "publish_intake" / "tasks" / "publish_handoff" / "review-intake.json"
    binary_ref = (
        {"schema": INTAKE_SCHEMA, "artifact": bin_art}
        if binary_ref_override is ...
        else binary_ref_override
    )
    intake_payload: dict[str, Any] = {
        "schema": intake_schema,
        "target_snapshot": SNAPSHOT,
        "binary_evidence": binary_ref,
    }
    atomic_json(intake_path, intake_payload)
    intake_art = run_artifact(run_root, intake_path)

    handoff_path = attempt / "handoff.json"
    write_fixture_handoff(
        run_root,
        handoff_path,
        {
            "job_id": "job_review_intake",
            "attempt_id": "attempt-1",
            "target_snapshot": SNAPSHOT,
            "outputs": {
                "publish_intake.publish_handoff": {
                    "schema": intake_schema,
                    "artifact": intake_art,
                }
            },
        },
        target_snapshot=SNAPSHOT,
    )
    handoff_sha = file_sha256(handoff_path)
    atomic_json(
        run_root / "data" / "jobs" / "job_review_intake" / "latest.json",
        {
            "job_id": "job_review_intake",
            "attempt_id": "attempt-1",
            "handoff_path": handoff_path.relative_to(run_root).as_posix(),
            "handoff_sha256": handoff_sha,
        },
    )
    return handoff_sha


def _publish_fixture_binary(
    base: Path, *, binary_id: str = "vendor", export: Callable[[Path, str], None] | None = None,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    data_dir = base / "data"
    bin_path = base / "inputs" / "libvendor.so"
    bin_path.parent.mkdir(parents=True, exist_ok=True)
    bin_path.write_bytes(BINARY_BYTES)
    pub = decompile_binary(
        repository_root=REPO_ROOT,
        data_dir=data_dir,
        settings=BinaryDecompilationSettings(),
        request=BinaryRequest(binary_id, bin_path, BINARY_SHA, "owned unit test input"),
        runner=FakeDocker(export=export),
    )
    entry = {
        "binary_id": binary_id,
        "status": "resolved",
        "binary_sha256": BINARY_SHA,
        "identity": pub["identity"],
        "manifest_sha256": pub["manifest_sha256"],
        "publication": Path(pub["path"]).relative_to(store_root(data_dir)).as_posix(),
    }
    doc = {
        "schema": INTAKE_SCHEMA,
        "data_dir": data_dir.as_posix(),
        "binaries": [entry],
        "gaps": [],
    }
    return data_dir, doc, entry


@pytest.mark.parametrize("bad_value", [True, False, 0, -3, "10", None])
def test_settings_rejects_non_positive_or_non_int_values(tmp_path: Path, bad_value: Any) -> None:
    unit = _unit_context(tmp_path / "run", "load.accepted_publications",
                         settings_override={SETTINGS[0]: bad_value})
    with pytest.raises(ValueError, match="binary evidence index settings must be positive integers"):
        _settings(unit)


def test_settings_accepts_positive_integers(tmp_path: Path) -> None:
    unit = _unit_context(tmp_path / "run", "load.accepted_publications")
    limits = _settings(unit)
    assert set(limits) == set(SETTINGS)
    assert all(type(v) is int and v >= 1 for v in limits.values())


def test_read_verified_validates_custody_hash_and_json_type(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="unavailable or outside the run"):
        _read_verified(run_root, {"path": "../outside.json", "sha256": file_sha256(outside)})

    with pytest.raises(ValueError, match="unavailable or outside the run"):
        _read_verified(run_root, {"path": "missing.json", "sha256": "0" * 64})

    valid = run_root / "obj.json"
    valid.write_text('{"ok": 1}', encoding="utf-8")
    with pytest.raises(ValueError, match="hash changed"):
        _read_verified(run_root, {"path": "obj.json", "sha256": "0" * 64})

    assert _read_verified(run_root, {"path": "obj.json", "sha256": file_sha256(valid)}) == {"ok": 1}

    arr = run_root / "arr.json"
    arr.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ValueError, match="must be an object"):
        _read_verified(run_root, {"path": "arr.json", "sha256": file_sha256(arr)})


def test_accepted_binary_evidence_validates_pin_and_schemas(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    doc = {"schema": INTAKE_SCHEMA, "data_dir": (tmp_path / "data").as_posix(), "binaries": []}
    sha = _write_intake_handoff(run_root, doc)

    with upstream_scope(run_root, JOB_ID, {}, contract=CONTRACT):
        with pytest.raises(UpstreamNotPinnedError):
            accepted_binary_evidence(run_root)

    with upstream_scope(run_root, JOB_ID, {"job_review_intake": sha}, contract=CONTRACT):
        loaded, got_sha = accepted_binary_evidence(run_root)
    assert loaded == doc and got_sha == sha

    sha_bad_intake = _write_intake_handoff(tmp_path / "run_bad_intake", doc, intake_schema="wrong/1")
    with upstream_scope(tmp_path / "run_bad_intake", JOB_ID, {"job_review_intake": sha_bad_intake}, contract=CONTRACT):
        with pytest.raises(ValueError, match="accepted review intake uses an unsupported schema"):
            accepted_binary_evidence(tmp_path / "run_bad_intake")

    sha_no_ref = _write_intake_handoff(tmp_path / "run_no_ref", doc, binary_ref_override=None)
    with upstream_scope(tmp_path / "run_no_ref", JOB_ID, {"job_review_intake": sha_no_ref}, contract=CONTRACT):
        with pytest.raises(ValueError, match="accepted review intake has no binary-evidence record"):
            accepted_binary_evidence(tmp_path / "run_no_ref")

    sha_bad_doc = _write_intake_handoff(
        tmp_path / "run_bad_doc",
        {"schema": INTAKE_SCHEMA, "binaries": "not-a-list"},
    )
    with upstream_scope(tmp_path / "run_bad_doc", JOB_ID, {"job_review_intake": sha_bad_doc}, contract=CONTRACT):
        with pytest.raises(ValueError, match="binary-evidence record uses an unsupported schema"):
            accepted_binary_evidence(tmp_path / "run_bad_doc")


def test_verified_publication_rejects_escape_and_manifest_drift(tmp_path: Path) -> None:
    _, doc, entry = _publish_fixture_binary(tmp_path)
    root, manifest = verified_publication(doc, entry)
    assert root.is_dir() and manifest["identity"] == entry["identity"]

    with pytest.raises(ValueError, match="publication is outside the store"):
        verified_publication(doc, {**entry, "publication": "../escape"})

    with pytest.raises(ValueError, match="publication is outside the store"):
        verified_publication(doc, {**entry, "publication": "f" * 64})

    with pytest.raises(ValueError, match="publication changed after intake froze it"):
        verified_publication(doc, {**entry, "manifest_sha256": "0" * 64})

    with pytest.raises(ValueError, match="publication changed after intake froze it"):
        verified_publication(doc, {**entry, "identity": "0" * 64})

    with pytest.raises(ValueError, match="publication changed after intake froze it"):
        verified_publication(doc, {**entry, "binary_sha256": "0" * 64})


def test_text_and_routing_helpers_cover_edge_cases() -> None:
    assert managed_routing({"coverage": {"managed_code": False}}) is None
    fallback = managed_routing({"coverage": {"managed_code": True}, "program": {}})
    assert fallback is not None and "managed runtime needs a managed-code decompiler" in fallback

    assert _clip("hello", 10) == "hello"
    assert _clip("hello world", 5) == "hello"
    assert _short("std::vector::push_back") == "push_back"
    assert _short(None) == ""

    assert _line_of("void f() {\n  foo();\n}\n", "") is None
    assert _line_of("void f() {\n  foo();\n}\n", "<bad>") is None
    assert _line_of("void f() {\n  bar();\n}\n", "foo") is None

    unique = _line_of("void f() {\n  int x = 1;\n  foo(x);\n}\n", "foo")
    assert unique is not None and unique[0] == 3 and unique[4] is False

    ambiguous = _line_of("void f() {\n  foo(1);\n  foo(2);\n}\n", "foo")
    assert ambiguous is not None and ambiguous[0] == 2 and ambiguous[4] is True


def _write_raw_tables(pub_root: Path, tables: dict[str, list[dict[str, Any]]]) -> None:
    pub_root.mkdir(parents=True, exist_ok=True)
    for name, rows in tables.items():
        (pub_root / f"{name}.jsonl").write_bytes(b"".join(canonical_json(row) for row in rows))


def _small_publication(
    base: Path, *, text: str = "void f(void)\n{\n  sink();\n}\n",
    calls: list[dict[str, Any]] | None = None,
    imports: list[dict[str, Any]] | None = None,
    strings: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    def export(root: Path, sha: str) -> None:
        write_export(root, sha)
        _write_raw_tables(root, {
            "functions": [{"address": "0x100", "name": "f", "decompile_status": "ok"}],
            "decompiled": [{"address": "0x100", "c": text, "truncated": False}],
            "pcode": [], "exports": [], "gaps": [],
            "calls": calls or [], "imports": imports or [], "strings": strings or [],
        })
        complete = json.loads((root / "complete.json").read_text())
        complete["counts"].update(functions=1, strings=len(strings or []))
        atomic_json(root / "complete.json", complete)

    _, document, entry = _publish_fixture_binary(base, export=export)
    return document, entry


def _published_core(
    base: Path, document: dict[str, Any], *, settings: dict[str, int] | None = None,
) -> tuple[RetrievalCore, dict[str, Any], dict[str, Any]]:
    run_root = base / "runs" / "2026-11-19-0001"
    pin = _write_intake_handoff(run_root, document)
    upstream = run_root / "data" / "catalog.json"
    write_manifest(upstream, run_id=run_root.name, target_snapshot=SNAPSHOT,
                   target_root=base / "target", indexes=())
    outputs: dict[str, Any] = {}
    with upstream_scope(run_root, JOB_ID, {"job_review_intake": pin}, contract=CONTRACT):
        for unit in build_job().units:
            context = _unit_context(run_root, unit.unit_id, outputs=outputs, settings_override=settings,
                                    input_manifest_path=upstream.as_posix(),
                                    input_manifest_sha256=file_sha256(upstream))
            outputs[unit.unit_id] = dict(unit.handler(context))
    result = outputs["acceptance.publish_handoff"]
    summary = json.loads((run_root / result["artifact"]["path"]).read_text())
    core = RetrievalCore(base / "runs", run_root.name,
                         manifest_path=run_root / result["index_manifest"]["path"],
                         manifest_sha256=result["index_manifest"]["sha256"])
    return core, result, summary


@pytest.mark.parametrize(("resolution", "libraries", "expected_library"), [
    ({}, ["KERNEL32.DLL"], "KERNEL32.DLL"),
    ({"resolved_library": "KERNEL32.DLL"}, ["OTHER.DLL", "KERNEL32.DLL"], "KERNEL32.DLL"),
    ({"resolved_name": "KERNEL32.DLL::sink"}, ["OTHER.DLL", "KERNEL32.DLL"], "KERNEL32.DLL"),
    ({}, ["OTHER.DLL", "KERNEL32.DLL"], None),
    ({"resolved_library": "ABSENT.DLL"}, ["KERNEL32.DLL"], None),
], ids=["legacy-bare", "explicit-library", "legacy-qualified", "ambiguous-bare", "missing-library"])
def test_external_call_resolves_only_the_matching_import(
    tmp_path: Path, resolution: dict[str, str], libraries: list[str], expected_library: str | None,
) -> None:
    call = {"from_function": "0x100", "call_site": "0x110", "to": None,
            "resolved_external": True, "resolved_name": "sink", "kind": "call", **resolution}
    document, entry = _small_publication(
        tmp_path, calls=[call],
        imports=[{"library": library, "name": "sink", "kind": "function"} for library in libraries])
    core, result, _ = _published_core(tmp_path, document)
    site, = core.find(kind="binary_call_site", indexes=("binary",))["results"]
    assert site["payload"]["binary_sha256"] == BINARY_SHA
    assert site["payload"]["publication_identity"] == entry["identity"]
    relations = core.trace(identity=site["identity"], relations=("CALLS",), depth=1)["results"]
    if expected_library is None:
        assert relations == []
        assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
        assert "vendor: unresolved_call: 0x110" in result["gaps"]
    else:
        edge, = relations
        imported, = core.find(identity=edge["target_id"])["results"]
        assert imported["payload"]["library"] == expected_library
        assert imported["payload"]["name"] == "sink"
        assert imported.get("location") is None
        assert core.read_excerpt(identity=imported["identity"])["results"] == []
        assert result["terminal_status"] == "SUCCEEDED"
        assert core.read_excerpt(identity=site["identity"], context_lines=0)["results"][0]["excerpt"] == "  sink();"


def test_external_names_remain_ambiguous_when_imports_are_bounded(tmp_path: Path) -> None:
    document, _ = _small_publication(
        tmp_path, calls=[{"from_function": "0x100", "call_site": "0x110", "to": None,
                         "resolved_external": True, "resolved_name": "sink", "kind": "call"}],
        imports=[{"library": name, "name": "sink", "kind": "function"} for name in ("A.DLL", "B.DLL")])
    core, result, _ = _published_core(tmp_path, document, settings={"max_imports_per_binary": 1})
    site, = core.find(kind="binary_call_site", indexes=("binary",))["results"]
    assert core.trace(identity=site["identity"], relations=("CALLS",), depth=1)["results"] == []
    assert result["gaps"] == ["vendor: imports_truncated: indexed 1 of 2", "vendor: unresolved_call: 0x110"]


def test_external_symbol_identity_does_not_alias_program_offsets_or_other_libraries(tmp_path: Path) -> None:
    document, _ = _small_publication(
        tmp_path, text="void f(void)\n{\n  f();\n  sink();\n}\n",
        imports=[{"library": name, "name": "ns::sink", "kind": "function", "address": "0x100"}
                 for name in ("A.DLL", "B.DLL")],
        calls=[
            {"from_function": "0x100", "call_site": "0x110", "to": "0x100",
             "resolved_name": "f", "resolved_external": False, "kind": "call"},
            *[{"from_function": "0x100", "call_site": "0x120", "to": None,
               "resolved_name": "ns::sink", "resolved_library": name, "resolved_external": True, "kind": "call"}
              for name in ("A.DLL", "B.DLL")],
        ])
    core, result, _ = _published_core(tmp_path, document)
    assert result["counts"]["call_sites"] == 3
    targets = {}
    for site in core.find(kind="binary_call_site", indexes=("binary",))["results"]:
        edge, = core.trace(identity=site["identity"], relations=("CALLS",), depth=1)["results"]
        target, = core.find(identity=edge["target_id"])["results"]
        targets[site["payload"]["resolved_library"]] = target
    assert targets[None]["kind"] == "binary_function"
    assert targets[None]["payload"]["function_address"] == "0x100"
    for library in ("A.DLL", "B.DLL"):
        assert targets[library]["kind"] == "binary_import"
        assert targets[library]["payload"]["library"] == library
        assert targets[library]["payload"]["name"] == "ns::sink"


@pytest.mark.parametrize(("text", "line"), [
    ('void f(void) {\n  puts("sink(");\n}\n', None),
    ("void f(void) {\n  custom_type *sink(void);\n}\n", None),
    ("void f(void) {\n  int x = sizeof(sink());\n}\n", None),
    ('void f(void) {\n  puts("\\\"sink("); /* sink(); */\n  sink();\n}\n', 3),
    ("void f(void) {\n  // sink(); \\\n  sink();\n}\n", None),
    ("void f(void) {\n  if (ready) sink();\n}\n", 2),
    ("void f(void) {\n  int value = sink();\n}\n", 2),
    ("void f(void) {\n#define name sink()\n  sink();\n}\n", 3),
    ("void f(void) {\n  ns::sink();\n}\n", 2),
    ("void f(void) {\n  extern void ns::sink(void);\n}\n", None),
], ids=["literal-only", "typed-prototype", "unevaluated", "escaped-quote", "continued-comment",
        "conditional", "initializer", "preprocessor", "qualified-call", "qualified-prototype"])
def test_lexical_call_candidates_exclude_non_calls(text: str, line: int | None) -> None:
    found = _line_of(text, "sink")
    assert (found[0] if found else None) == line


@pytest.mark.parametrize(("text", "expected_line", "line_match"), [
    ("void f(void)\n{\n  f();\n}\n", 3, "unique"),
    ('void f(void)\n{\n  puts("f(");\n}\n', None, "unlocated"),
    ("void f(void)\n{\n  /* f(); */\n  // f();\n  extern void f(void);\n}\n", None, "unlocated"),
    ("void f(void)\n{\n  f(); f();\n}\n", None, "ambiguous"),
    ("void f(void)\n{\n  f();\n  f();\n}\n", None, "ambiguous"),
    ('void f(void)\n{\n  puts("λ");\n  return f\n    ();\n}\n', 4, "unique"),
], ids=["recursive", "literal", "comments-prototype", "same-line", "two-lines", "utf8-multiline"])
def test_call_excerpt_is_an_actual_unique_expression(
    tmp_path: Path, text: str, expected_line: int | None, line_match: str,
) -> None:
    document, entry = _small_publication(
        tmp_path, text=text,
        calls=[{"from_function": "0x100", "call_site": "0x110", "to": "0x100",
                "resolved_name": "f", "resolved_external": False, "kind": "call"}])
    core, _, summary = _published_core(tmp_path, document)
    site, = core.find(kind="binary_call_site", indexes=("binary",))["results"]
    assert site["payload"]["line_match"] == line_match
    assert site["payload"]["function_address"] == "0x100"
    excerpt = core.read_excerpt(identity=site["identity"], context_lines=0)
    if expected_line is None:
        assert site.get("location") is None
        assert excerpt["results"] == []
        assert summary["counts"]["located_call_sites"] == 0
    else:
        source = text.encode("utf-8")
        location = site["location"]
        assert location["start_line"] == location["end_line"] == expected_line
        assert location["path"] == f"@binary/{BINARY_SHA}/0x100.c"
        assert location["file_sha256"] == hashlib.sha256(source).hexdigest()
        assert source[location["start_byte"]:location["end_byte"]].decode() == text.splitlines()[expected_line - 1]
        assert excerpt["results"][0]["excerpt"] == text.splitlines()[expected_line - 1]
        assert site["payload"]["publication_identity"] == entry["identity"]


def test_relation_counts_match_persisted_edges_on_build_and_reuse(tmp_path: Path) -> None:
    document, entry = _small_publication(
        tmp_path, text="void f(void)\n{\n  f();\n  f();\n}\n",
        calls=[{"from_function": "0x100", "call_site": site, "to": "0x100",
                "resolved_name": "f", "kind": "call"} for site in ("0x110", "0x120")])
    core, result, summary = _published_core(tmp_path, document)
    shard = core.run_root / summary["binaries"][0]["index_identity"]["relative_path"]
    with closing(sqlite3.connect(f"{shard.as_uri()}?mode=ro", uri=True)) as db:
        stored = db.execute("SELECT COUNT(*) FROM relations").fetchone()[0]
        assert stored == 5
        assert db.execute("SELECT value FROM metadata WHERE key='relation_duplicates_merged'").fetchone()[0] == "1"
        assert db.execute("SELECT COUNT(*) FROM relations WHERE kind='CALLS'").fetchone()[0] == 3
    unit = _unit_context(core.run_root, "index.binaries")
    reused = index_binary(unit, document, entry, _settings(unit))
    assert result["counts"]["relations"] == summary["counts"]["relations"] == stored
    assert reused["counts"]["relations"] == stored
    assert canonical_json(reused["index_identity"]) == canonical_json(summary["binaries"][0]["index_identity"])


@pytest.mark.parametrize(("value", "upstream_truncated", "partial"), [
    ("public-SECRETTAIL", False, True),
    ("public", True, True),
    ("public", False, False),
], ids=["index-clipped", "export-clipped", "exact-bound"])
def test_string_truncation_reaches_summary_and_retrieval_coverage(
    tmp_path: Path, value: str, upstream_truncated: bool, partial: bool,
) -> None:
    document, _ = _small_publication(tmp_path, strings=[
        {"address": "0x200", "value": value, "length": 17 if upstream_truncated else len(value),
         "truncated": upstream_truncated}])
    core, result, summary = _published_core(tmp_path, document, settings={"max_string_chars": 6})
    found = core.find(kind="binary_string", indexes=("binary",))
    string, = found["results"]
    assert string["payload"]["value"] == "public"
    assert string["payload"]["truncated"] is partial
    assert string.get("location") is None
    assert core.read_excerpt(identity=string["identity"])["results"] == []
    gap = "vendor: string_value_truncated: 0x200"
    expected_gaps = [gap] if partial else []
    assert result["gaps"] == summary["gaps"] == expected_gaps
    assert summary["binaries"][0]["gaps"] == expected_gaps
    assert result["terminal_status"] == ("COMPLETED_WITH_GAPS" if partial else "SUCCEEDED")
    assert any("string_value_truncated: 0x200" in gap for gap in found["coverage_gaps"]) is partial
    shard = core.run_root / summary["binaries"][0]["index_identity"]["relative_path"]
    with closing(sqlite3.connect(f"{shard.as_uri()}?mode=ro", uri=True)) as db:
        assert db.execute("SELECT status FROM coverage").fetchone()[0] == ("partial" if partial else "complete")


def test_binary_shard_builder_covers_gaps_truncation_thunks_calls_and_strings(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    unit = _unit_context(run_root, "index.binaries")
    pub_root = tmp_path / "pub"
    (pub_root / "pseudo-c").mkdir(parents=True)

    c_func1 = b"void alpha(void)\n{\n  dup_call(1);\n  dup_call(2);\n  ext_fn();\n}\n"
    c_empty = b""
    (pub_root / "pseudo-c" / "0x101100.c").write_bytes(c_func1)
    (pub_root / "pseudo-c" / "0x101200.c").write_bytes(c_empty)

    tables = {
        "imports": [
            {"name": "ext_fn", "library": "libc.so", "kind": "function", "thunks": ["0x101010", "not-addr"]},
            {"name": "dropped_imp", "library": "libc.so", "kind": "function", "thunks": None},
        ],
        "functions": [
            {
                "address": "0x101010",
                "name": "ext_fn",
                "qualified_name": "libc.so::ext_fn",
                "is_thunk": True,
                "decompile_status": "skipped_thunk",
            },
            {
                "address": "0x101100",
                "name": "alpha",
                "decompile_status": "ok",
                "pseudo_c": {
                    "path": "pseudo-c/0x101100.c",
                    "sha256": hashlib.sha256(c_func1).hexdigest(),
                    "bytes": len(c_func1),
                    "lines": 6,
                    "truncated": True,
                },
            },
            {
                "address": "0x101200",
                "name": "dup_call",
                "decompile_status": "ok",
                "pseudo_c": {
                    "path": "pseudo-c/0x101200.c",
                    "sha256": hashlib.sha256(c_empty).hexdigest(),
                    "bytes": 0,
                    "lines": 0,
                    "truncated": False,
                },
            },
            {"address": "0x101300", "name": "dropped_fn", "decompile_status": "ok"},
        ],
        "calls": [
            {"from_function": "0x999999", "call_site": "0x999999", "to": "0x101100"},
            {"from_function": "0x101100", "call_site": "invalid-site", "to": "0x101200"},
            {
                "from_function": "0x101100",
                "call_site": "0x101110",
                "to": "0x101200",
                "to_name": "dup_call",
                "resolved_external": False,
                "computed": False,
            },
            {
                "from_function": "0x101100",
                "call_site": "0x101120",
                "to": "0x101010",
                "to_name": "ext_fn",
                "resolved_external": False,
                "computed": False,
            },
            {
                "from_function": "0x101010",
                "call_site": "0x101014",
                "to": "0x200000",
                "resolved_name": "libc.so::ext_fn",
                "resolved_external": True,
                "computed": False,
            },
            {
                "from_function": "0x101100",
                "call_site": "0x101130",
                "to": None,
                "to_name": "indirect_reg",
                "resolved_external": False,
                "computed": True,
            },
            {
                "from_function": "0x101100",
                "call_site": "0x101140",
                "to": "0x101300",
                "to_name": "dropped_fn",
                "resolved_external": False,
                "computed": False,
            },
            {
                "from_function": "0x101100",
                "call_site": "0x101150",
                "to": "0x101200",
                "to_name": "dropped_call_site",
                "resolved_external": False,
                "computed": False,
            },
        ],
        "strings": [
            {"address": "not-an-address", "value": "skip"},
            {
                "address": "0x200100",
                "value": "secret-token-value",
                "length": 18,
                "truncated": False,
                "xrefs_truncated": False,
                "xrefs": [
                    "ignore-non-mapping",
                    {"from": "0x101112", "function": "0x101100"},
                    {"from": "0x101999", "function": "0x999999"},
                ],
            },
            {"address": "0x200200", "value": "dropped-string", "length": 14},
        ],
        "gaps": [
            {"kind": "managed_code"},
            {"kind": "decompile_timeout", "address": "0x101888"},
            {"kind": "pcode_overflow"},
        ],
    }
    _write_raw_tables(pub_root, tables)

    entry = {
        "binary_id": "edge",
        "binary_sha256": BINARY_SHA,
        "identity": "c" * 64,
        "manifest_sha256": "d" * 64,
    }
    manifest = {
        "coverage": {
            "analysis_timed_out": True,
            "functions_not_exported": 2,
            "strings_not_exported": 1,
        }
    }
    limits = {
        "max_functions_per_binary": 3,
        "max_call_sites_per_binary": 6,
        "max_imports_per_binary": 1,
        "max_strings_per_binary": 2,
        "max_string_xrefs": 1,
        "max_entity_text_bytes": 16,
        "max_string_chars": 6,
    }
    shard_path = run_root / "data" / "indices" / "binary" / "edge.sqlite"
    builder = IndexBuilder(shard_path, name="binary", fingerprint="e" * 64,
                           target_snapshot=SNAPSHOT, shard_id="binary-edge")
    binary = _Binary(unit, entry, pub_root, manifest, limits, builder)
    binary.build(None)
    binary.publish()

    assert binary.counts == {
        "functions": 3,
        "located_functions": 2,
        "call_sites": 5,
        "located_call_sites": 1,
        "imports": 1,
        "strings": 1,
        "relations": 13,
    }
    expected_gaps = {
        "publication_gap: decompile_timeout at 0x101888",
        "publication_gap: pcode_overflow",
        "publication_coverage: analysis_timed_out",
        "publication_coverage: functions_not_exported",
        "publication_coverage: strings_not_exported",
        "imports_truncated: indexed 1 of 2",
        "functions_truncated: indexed 3 of 4",
        "pseudo_c_truncated: 0x101100",
        "call_sites_truncated: indexed 6 of 7",
        "call_site_unaddressed: 0x101100",
        "unresolved_call: 0x101130",
        "strings_truncated: indexed 2 of 3",
        "string_xrefs_truncated: 0x200100",
        "string_value_truncated: 0x200100",
    }
    assert expected_gaps <= set(binary.gaps)


def test_binary_shard_builder_handles_managed_mode_and_tampered_pseudo_c(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    unit = _unit_context(run_root, "index.binaries")
    limits = _settings(unit)
    pub_root = tmp_path / "pub"
    (pub_root / "pseudo-c").mkdir(parents=True)
    c_file = pub_root / "pseudo-c" / "0x101100.c"
    c_file.write_bytes(b"void f(void) {}\n")

    tables = {
        "imports": [],
        "functions": [
            {
                "address": "0x101100",
                "name": "f",
                "decompile_status": "ok",
                "pseudo_c": {
                    "path": "pseudo-c/0x101100.c",
                    "sha256": file_sha256(c_file),
                    "bytes": c_file.stat().st_size,
                    "lines": 1,
                    "truncated": False,
                },
            }
        ],
        "calls": [],
        "strings": [],
        "gaps": [],
    }
    _write_raw_tables(pub_root, tables)
    entry = {"binary_id": "m", "binary_sha256": BINARY_SHA, "identity": "c" * 64, "manifest_sha256": "d" * 64}
    manifest = {"coverage": {}}

    builder_managed = IndexBuilder(
        run_root / "data" / "indices" / "binary" / "managed.sqlite",
        name="binary",
        fingerprint="1" * 64,
        target_snapshot=SNAPSHOT,
        shard_id="binary-m",
    )
    managed_bin = _Binary(unit, entry, pub_root, manifest, limits, builder_managed)
    managed_bin.build("managed_code: CIL needs ILSpy")
    assert managed_bin.counts["functions"] == 1 and managed_bin.counts["located_functions"] == 0
    assert "managed_code: CIL needs ILSpy" in managed_bin.gaps

    c_file.write_bytes(b"void tampered(void) {}\n")
    builder_tampered = IndexBuilder(
        run_root / "data" / "indices" / "binary" / "tampered.sqlite",
        name="binary",
        fingerprint="2" * 64,
        target_snapshot=SNAPSHOT,
        shard_id="binary-t",
    )
    tampered_bin = _Binary(unit, entry, pub_root, manifest, limits, builder_tampered)
    with pytest.raises(ValueError, match="pseudo-C 0x101100 changed after verification"):
        tampered_bin.build(None)


def test_build_job_units_succeeded_and_inventory_claims(tmp_path: Path) -> None:
    _, doc, entry = _publish_fixture_binary(tmp_path)
    run_root = tmp_path / "runs" / "2026-11-15-0001"
    sha = _write_intake_handoff(run_root, doc)

    upstream_manifest = run_root / "data" / "jobs" / "job_target_catalog" / "manifest.json"
    write_manifest(
        upstream_manifest,
        run_id=run_root.name,
        target_snapshot=SNAPSHOT,
        target_root=tmp_path / "target",
        indexes=(),
    )
    upstream_sha = file_sha256(upstream_manifest)

    job = build_job()
    units = {u.unit_id: u.handler for u in job.units}

    with upstream_scope(run_root, JOB_ID, {"job_review_intake": sha}, contract=CONTRACT):
        u_load = _unit_context(run_root, "load.accepted_publications")
        loaded = dict(units["load.accepted_publications"](u_load))
        assert loaded["unavailable"] == {}
        assert [b["binary_id"] for b in loaded["binaries"]] == ["vendor"]

        u_index = _unit_context(run_root, "index.binaries",
                                outputs={"load.accepted_publications": loaded})
        indexed = dict(units["index.binaries"](u_index))
        assert indexed["terminal_status"] == "SUCCEEDED"
        assert indexed["gaps"] == []
        assert indexed["binaries"][0]["terminal_status"] == "SUCCEEDED"

        u_pub = _unit_context(
            run_root,
            "acceptance.publish_handoff",
            outputs={"load.accepted_publications": loaded, "index.binaries": indexed},
            input_manifest_path=upstream_manifest.as_posix(),
            input_manifest_sha256=upstream_sha,
        )
        published = dict(units["acceptance.publish_handoff"](u_pub))

    assert published["schema"] == SCHEMA
    assert published["terminal_status"] == "SUCCEEDED"
    assert published["item_count"] == 3
    assert published["counts"]["functions"] == 3
    assert published["counts"]["located_functions"] == 2

    core = RetrievalCore(
        tmp_path / "runs",
        "2026-11-15-0001",
        manifest_path=run_root / published["index_manifest"]["path"],
        manifest_sha256=published["index_manifest"]["sha256"],
    )
    funcs = core.find(kind=EntityKind.BINARY_FUNCTION.value, name="print_label", indexes=("binary",))["results"]
    assert len(funcs) == 1
    excerpt = core.read_excerpt(identity=funcs[0]["identity"], context_lines=0)["results"][0]
    assert "strcpy(label,input);" in excerpt["excerpt"]

    config = load_config(REPO_ROOT / "appsec-review.toml")
    steps = list(config.job(JOB_ID).steps)
    claims = runtime_claims({JOB_ID: steps}) + [
        Claim(JOB_ID, item.step, item.output_kind, item) for item in DATASETS
    ]
    scan = scan_run_tree(run_root, FileClaims(claims), max_files=100_000)
    mine = [
        p
        for p in scan.unaccounted
        if p.startswith(("data/binary-evidence", f"data/jobs/{JOB_ID}"))
    ]
    assert mine == []
    assert scan.claim_errors == []


def test_build_job_units_not_applicable_unavailable_and_drift_errors(tmp_path: Path) -> None:
    job = build_job()
    units = {u.unit_id: u.handler for u in job.units}

    # 1. NOT_APPLICABLE when no binaries are configured
    run_empty = tmp_path / "run_empty"
    sha_empty = _write_intake_handoff(
        run_empty,
        {"schema": INTAKE_SCHEMA, "data_dir": (tmp_path / "data").as_posix(), "binaries": []},
    )
    with upstream_scope(run_empty, JOB_ID, {"job_review_intake": sha_empty}, contract=CONTRACT):
        loaded_empty = dict(units["load.accepted_publications"](_unit_context(run_empty, "load.accepted_publications")))
        indexed_empty = dict(
            units["index.binaries"](
                _unit_context(run_empty, "index.binaries", outputs={"load.accepted_publications": loaded_empty})
            )
        )
    assert indexed_empty["terminal_status"] == "NOT_APPLICABLE" and indexed_empty["binaries"] == []

    # 2. COMPLETED_WITH_GAPS when a binary is unavailable, plus index_binary partial status
    _, doc, entry = _publish_fixture_binary(tmp_path / "avail")
    doc_mixed = {
        **doc,
        "binaries": [
            entry,
            {"binary_id": "missing_bin", "status": "unavailable", "reason": "no matching publication"},
        ],
    }
    run_mixed = tmp_path / "run_mixed"
    sha_mixed = _write_intake_handoff(run_mixed, doc_mixed)
    with upstream_scope(run_mixed, JOB_ID, {"job_review_intake": sha_mixed}, contract=CONTRACT):
        loaded_mixed = dict(units["load.accepted_publications"](_unit_context(run_mixed, "load.accepted_publications")))
        assert "missing_bin" in loaded_mixed["unavailable"]
        u_idx = _unit_context(
            run_mixed,
            "index.binaries",
            outputs={"load.accepted_publications": loaded_mixed},
            settings_override={"max_functions_per_binary": 2},
        )
        indexed_mixed = dict(units["index.binaries"](u_idx))
    assert indexed_mixed["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert indexed_mixed["binaries"][0]["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("missing_bin: binary_decompilation_unavailable" in g for g in indexed_mixed["gaps"])

    # 3. load rejects resolved entry lacking 64-hex identity or manifest_sha256
    run_bad_id = tmp_path / "run_bad_id"
    sha_bad_id = _write_intake_handoff(
        run_bad_id,
        {
            "schema": INTAKE_SCHEMA,
            "data_dir": (tmp_path / "data").as_posix(),
            "binaries": [{"binary_id": "v", "status": "resolved", "identity": "short", "manifest_sha256": "a" * 64}],
        },
    )
    with upstream_scope(run_bad_id, JOB_ID, {"job_review_intake": sha_bad_id}, contract=CONTRACT):
        with pytest.raises(ValueError, match="intake record has no publication identity"):
            units["load.accepted_publications"](_unit_context(run_bad_id, "load.accepted_publications"))

    # 4. index rejects drift between load.accepted_publications and intake document
    with upstream_scope(run_mixed, JOB_ID, {"job_review_intake": sha_mixed}, contract=CONTRACT):
        drifted = _unit_context(
            run_mixed,
            "index.binaries",
            outputs={"load.accepted_publications": {"binaries": [], "unavailable": {}}},
        )
        with pytest.raises(ValueError, match="frozen binary publications changed between load and index"):
            units["index.binaries"](drifted)
