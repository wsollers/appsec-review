"""Focused unit regressions for Epoch 6 repairs (seq=20..25)."""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from appsec_review.config.loader import load_config
from appsec_review.jobs.job_dossier_publication.job import DossierPublicationSettings
from appsec_review.jobs.job_openvex_export.contracts import ArtifactRef
from appsec_review.jobs.job_openvex_export.settings import OpenVexExportSettings
from appsec_review.jobs import bound_artifacts
from appsec_review.jobs.job_dossier_publication import job as dossier_job
from appsec_review.jobs.job_openvex_export import inputs as openvex_inputs
from appsec_review.jobs.job_openvex_export import validation as openvex_validation
from appsec_review.jobs.job_poc_generation import brief as poc_brief
from appsec_review.jobs.job_poc_generation import buildctx as poc_buildctx
from appsec_review.jobs.job_poc_generation import candidates as poc_candidates
from appsec_review.jobs.job_poc_generation import inputs as poc_inputs
from appsec_review.jobs.job_poc_generation.settings import PocGenerationSettings
from appsec_review.reporting.dossiers import DossierLimits, _Projection
from appsec_review.jobs.bound_artifacts import SOURCE_CONTEXT_TIMEOUT_MS
from appsec_review.review.secret_redaction import redact_code_secrets, redact_source_line
from appsec_review.storage.shared import validation_scope


class _FakeCore:
    def __init__(self, rows: dict[str, list[dict[str, Any]]], excerpts: dict[str, str] | None = None) -> None:
        self._rows = rows
        self._excerpts = excerpts or {}

    def find(
        self,
        *,
        identity: str | None = None,
        path: str | None = None,
        kind: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if identity is not None:
            return {"results": list(self._rows.get(identity, ()))[:limit]}
        matched: list[dict[str, Any]] = []
        for items in self._rows.values():
            for row in items:
                loc = row.get("location") or {}
                row_path = row.get("path") or loc.get("path")
                if path is not None and row_path != path:
                    continue
                if kind is not None and row.get("kind") != kind:
                    continue
                matched.append(row)
                if len(matched) >= limit:
                    return {"results": matched}
        return {"results": matched}

    def read_excerpt(
        self,
        *,
        identity: str | None = None,
        path: str | None = None,
        start_line: int = 1,
        end_line: int = 1,
        context_lines: int = 2,
    ) -> dict[str, Any]:
        if identity is not None:
            text = self._excerpts.get(identity)
            if text is None:
                return {"results": [], "truncated": False}
            row = (self._rows.get(identity) or [{}])[0]
            loc = row.get("location") or {}
            return {
                "results": [{
                    "identity": identity,
                    "path": row.get("path") or loc.get("path") or "src/request.cpp",
                    "start_line": int(row.get("start_line") or loc.get("start_line") or 1),
                    "end_line": int(row.get("end_line") or loc.get("end_line") or 2),
                    "excerpt": text,
                }],
                "truncated": False,
            }
        return {"results": [], "truncated": False}


def test_seq20_hunt_sink_of_and_tu_declarations(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    cpp = src / "request.cpp"
    cpp_bytes = (
        b'#include "request.h"\n'
        b"void log_message(const char *fmt) {\n"
        b"    printf(fmt);\n"
        b"}\n"
        b"int handle_request(int sock, const char *buf) {\n"
        b"    log_message(buf);\n"
        b"    return 0;\n"
        b"}\n"
    )
    cpp.write_bytes(cpp_bytes)
    hdr = src / "request.h"
    hdr_bytes = b"#pragma once\nvoid public_api();\n"
    hdr.write_bytes(hdr_bytes)

    hunt_pkg = {
        "schema": "appsec-review/review-package/7",
        "neighborhood": {
            "function": None,
            "sinks": [{"ref": "asr:sink_site:8c82", "path": "src/request.cpp", "line": 3, "symbol": "printf"}],
            "entries": [],
            "flows": [],
        },
        "scope": {
            "operation": {
                "path": "src/request.cpp",
                "line": 3,
                "anchor_ids": ["asr:sink_site:8c82"],
            }
        },
    }
    core = _FakeCore({
        "asr:fn:log_message": [{
            "identity": "asr:fn:log_message",
            "kind": "symbol",
            "name": "log_message",
            "location": {"path": "src/request.cpp", "start_line": 2, "end_line": 4},
        }],
    })
    sink = poc_inputs.sink_of(hunt_pkg, core=core)
    assert sink is not None
    assert sink["name"] == "log_message"
    assert sink["path"] == "src/request.cpp"
    assert sink["line"] == 2

    manifest = {
        "src/request.cpp": hashlib.sha256(cpp_bytes).hexdigest(),
        "src/request.h": hashlib.sha256(hdr_bytes).hexdigest(),
    }
    cmd = poc_buildctx.CompileCommand(
        argv=("clang++", "-I/workspace/src", "-c", "/workspace/src/request.cpp"),
        source="src/request.cpp",
        language="cxx",
        working_directory=".",
        basis="exact",
    )
    unit = poc_buildctx.BuildUnit(
        build_unit_id="bu-1",
        build_system="cmake",
        root=".",
        receipt_fingerprint="fp-1",
        workspace=tmp_path,
        workspace_manifest=manifest,
        manifest_sha256="a" * 64,
        image_tag="tool-native-cpp:1.0.0",
        image_id="sha256:" + "b" * 64,
        image_user="1000:1000",
        command=cmd,
        objects=("build/request.o",),
        shared_libraries=(),
    )
    headers = poc_buildctx.Headers(unit)
    cfg = load_config(Path("appsec-review.toml"))
    settings = PocGenerationSettings.from_mapping(cfg.jobs["job_poc_generation"].settings)
    decls, synth = poc_buildctx.tu_declarations(
        unit,
        [],
        ["log_message", "handle_request"],
        headers=headers,
        allowed_std_headers=tuple(settings.policy.allowed_std_headers),
        source_bytes=65536,
        max_lines=12,
    )
    assert any("log_message" in "\n".join(row["text"]) for row in decls)
    assert synth is not None
    assert "void log_message(const char *fmt);" in synth
    assert "int handle_request(int sock, const char *buf);" in synth


def test_seq20_build_brief_resolves_hunt_basis_via_core_fallback(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    cpp = src / "request.cpp"
    cpp_bytes = b"void log_message(const char *fmt) {\n    printf(fmt);\n}\n"
    cpp.write_bytes(cpp_bytes)
    manifest = {"src/request.cpp": hashlib.sha256(cpp_bytes).hexdigest()}
    cmd = poc_buildctx.CompileCommand(
        argv=("clang++", "-c", "/workspace/src/request.cpp"),
        source="src/request.cpp",
        language="cxx",
        working_directory=".",
        basis="exact",
    )
    unit = poc_buildctx.BuildUnit(
        build_unit_id="bu-1",
        build_system="cmake",
        root=".",
        receipt_fingerprint="fp-1",
        workspace=tmp_path,
        workspace_manifest=manifest,
        manifest_sha256="a" * 64,
        image_tag="tool-native-cpp:1.0.0",
        image_id="sha256:" + "b" * 64,
        image_user="1000:1000",
        command=cmd,
        objects=("build/request.o",),
        shared_libraries=(),
    )
    entry_id = "asr:entry_point:" + "3" * 64
    path_id = "asr:dataflow_path:" + "4" * 64
    sink_id = "asr:sink_site:" + "8" * 64
    core = _FakeCore({
        entry_id: [{
            "identity": entry_id,
            "kind": "entry_point",
            "name": "handle_request",
            "location": {"path": "src/request.cpp", "start_line": 1, "end_line": 2},
            "payload": {"function": "handle_request"},
        }],
        path_id: [{
            "identity": path_id,
            "kind": "dataflow_path",
            "name": "handle_request->log_message",
            "location": {"path": "src/request.cpp", "start_line": 1, "end_line": 2},
            "payload": {"caller": "handle_request", "callee": "log_message"},
        }],
    })
    view_artifact = SimpleNamespace(
        document={"sinks": [{"ref": sink_id, "label": "S1", "path": "src/request.cpp", "lines": "2", "summary": "printf"}]},
        path=tmp_path / "view.json",
        sha256="c" * 64,
    )
    basis = poc_candidates.PocBasis(
        entry=(entry_id,),
        path=(path_id,),
        trigger=(),
        input_format="bytes",
        preconditions=(),
        expected_observation="compile_verified",
        unknowns=(),
        sha256="d" * 64,
    )
    candidate = SimpleNamespace(
        claim_id="claim-" + "1" * 64,
        finding_package_id="pkg-" + "2" * 64,
        state="poc_candidate",
        judge_verdict="poc_candidate",
        poc_basis=basis,
    )
    sink = {"name": "log_message", "path": "src/request.cpp", "line": 2, "symbol": "log_message"}
    brief = poc_brief.build_brief(
        candidate,
        finding={"label": "F1", "title": "Format string", "lane": "hunt", "missing_predicates": []},
        package={"package_id": "hunt-" + "5" * 64, "cwe": "CWE-134"},
        view=view_artifact,
        sink=sink,
        unit=unit,
        headers=poc_buildctx.Headers(unit),
        settings=PocGenerationSettings.from_mapping(load_config(Path("appsec-review.toml")).jobs["job_poc_generation"].settings),
        core=core,
    )
    assert brief.gaps == ()
    assert entry_id in brief.document["poc_basis_labels"]
    assert path_id in brief.document["poc_basis_labels"]
    assert brief.synthesized_header is not None
    assert "void log_message(const char *fmt);" in brief.synthesized_header


def test_seq22_source_context_datasets_include_alternate_cpg_and_debug_symbols() -> None:
    mapping = bound_artifacts.source_context_datasets()
    assert {d.output_kind for d in mapping["job_code_graph_index"]} == {"code_graph_facts", "alternate_cpg_index"}
    assert {d.output_kind for d in mapping["job_debug_symbol_indexing"]} == {"normalized_symbols"}
    assert SOURCE_CONTEXT_TIMEOUT_MS >= 30_000


def test_seq23_secret_redaction_preserves_markdown_backticks_ids_and_cpp_code() -> None:
    prose = (
        "Replace `printf(fmt)` with `fputs(fmt, stdout)` in `log_message`; "
        "upstream gap-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef and "
        "asr:ast_node:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 remain cited."
    )
    out = redact_source_line(prose, assignments=False)
    assert "`printf(fmt)`" in out
    assert "`fputs(fmt, stdout)`" in out
    assert "`log_message`" in out
    assert "gap-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" in out
    assert "asr:ast_node:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" in out

    leaked = "Token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 leaked in 'supersecretvalue123'."
    redacted_prose = redact_source_line(leaked, assignments=False)
    assert "ghp_" not in redacted_prose
    assert "supersecretvalue123" not in redacted_prose

    cpp_patch = (
        '  const char allowed[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";\n'
        '  std::size_t n = static_cast<std::size_t>(strlen(buf)) + sizeof(hdr);\n'
        '  const char *msg = "Invalid HTTP request header";\n'
    )
    assert redact_code_secrets(cpp_patch) == cpp_patch

    proj = _Projection(DossierLimits(), secret_context=False)
    assert proj.source(cpp_patch, "remediation.patch.src/request.cpp.new", exact_newlines=True) == cpp_patch

    stripe_prefix = "sk_" + "live_"
    cpp_secret = f'  const char *api_secret = "{stripe_prefix}9876543210abcdefghijklmnop";'
    assert stripe_prefix not in redact_code_secrets(cpp_secret)


def test_seq23_dossier_source_excerpt_cap_is_display_note_only() -> None:
    rels = [
        {"relation_id": f"evrel-{i:064x}", "entity_id": f"asr:ast_node:{i:064x}"}
        for i in range(1, 12)
    ]
    rows = {
        r["entity_id"]: [{"identity": r["entity_id"], "path": "src/request.cpp", "start_line": i, "end_line": i + 1}]
        for i, r in enumerate(rels, start=1)
    }
    excerpts = {r["entity_id"]: f"line {i}" for i, r in enumerate(rels, start=1)}
    core = _FakeCore(rows, excerpts)
    finding = {"finding_package_id": "pkg-1", "direct_evidence": [r["relation_id"] for r in rels]}
    dos_settings = DossierPublicationSettings.from_mapping(load_config(Path("appsec-review.toml")).jobs["job_dossier_publication"].settings)
    rendered_excerpts, item_gaps = dossier_job._excerpts(core, rels, finding, dos_settings)
    assert len(rendered_excerpts) == 4
    assert any(g.startswith("source_excerpt_cap:") for g in item_gaps)
    job_gaps = sorted({gap for gap in item_gaps if not str(gap).startswith("source_excerpt_cap:")})
    assert job_gaps == []


def test_seq25_openvex_validation_scope_and_seed_inventory(tmp_path: Path) -> None:
    f = tmp_path / "payload.bin"
    payload = b"hello-openvex"
    f.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()

    schema_unique = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "array",
        "uniqueItems": True,
        "items": {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]},
    }
    items = [{"id": i} for i in range(500)]
    openvex_validation._FastValidator(schema_unique).validate(items)

    vex_settings = OpenVexExportSettings.from_mapping(
        load_config(Path("appsec-review.toml")).jobs["job_openvex_export"].settings
    )
    ref = ArtifactRef("payload.bin", digest)
    with validation_scope(tmp_path):
        reader1 = openvex_inputs.BoundedInputReader(tmp_path, vex_settings)
        assert reader1.read(ref) == payload
        inv = reader1.inventory
        assert len(inv) == 1
        reader2 = openvex_inputs.BoundedInputReader(
            tmp_path,
            vex_settings,
            seed_inventory=inv,
        )
        reader2.reprove(skip_seeded=True)
        assert reader2.inventory == inv
