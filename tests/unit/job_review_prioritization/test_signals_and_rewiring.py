"""Focused unit regressions for T-171: 9-language heuristic rules, engineering-signal rewiring, and SAST-silence hunt."""

from __future__ import annotations

from dataclasses import replace
from copy import deepcopy
import gzip
import hashlib
import json
import math
from pathlib import Path
import shutil
from types import SimpleNamespace
from typing import Any

import jsonschema
import pytest
from referencing import Registry, Resource

from appsec_review.config import load_config
from appsec_review.jobs.job_review_prioritization import (
    HUNT_PRIORITY_REASON_ZERO_SAST,
    PRIORITIZATION_SIGNALS_SCHEMA,
    CompositePrioritizationSettings,
    build_job,
    load_accepted_prioritization,
)
from appsec_review.jobs.job_review_prioritization.datasets import CONTRACT
from appsec_review.jobs.job_review_prioritization.composite import apply_composite_prioritization
from appsec_review.jobs.job_review_prioritization import scoring
from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.job_review_prioritization.heuristics import Extractor
from appsec_review.jobs.job_review_prioritization.languages import SPECS
from appsec_review.jobs.job_review_prioritization.inputs import read_json
from appsec_review.jobs.job_review_prioritization.job import JOB_ID
from appsec_review.jobs.job_review_prioritization.syntax import Node, SourceFile, build_tree
from appsec_review.review.lead_families import LeadCollection
from appsec_review.review.ranking import RankWeights
from appsec_review.review.scope import SourceFile as ReviewSourceFile, accept_manifest
from appsec_review.review.units import build_units, rank_units
from appsec_review.retrieval import (
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    SourceLocation,
    write_manifest,
)
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff
from tests.unit.job_review_prioritization.test_contract import _job_context, _seed_upstream_run


ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "tests" / "fixtures" / "review_prioritization"
TARGET = FIXTURE / "target"
GOLDEN = json.loads(gzip.decompress((FIXTURE / "ast-golden.json.gz").read_bytes()))
BASE_CONFIG = load_config(ROOT / "appsec-review.toml")
SIGNALS_SCHEMA = json.loads(
    (ROOT / "docs" / "schemas" / "review-prioritization" / "prioritization-signals.schema.json").read_text(encoding="utf-8")
)
INTERCHANGE_SCHEMA = json.loads((ROOT / "docs/schemas/job-interchange.schema.json").read_text(encoding="utf-8"))
SIGNALS_REGISTRY = Registry().with_resource(INTERCHANGE_SCHEMA["$id"], Resource.from_contents(INTERCHANGE_SCHEMA))


def _sources(*enabled: str) -> dict[str, bool]:
    return {key: key in enabled for key in (
        "history", "semgrep", "codeql", "change_context", "test_coverage", "profile_data",
        "ci_configuration", "artifact_security", "dependency_intelligence", "sast_silence_hunt",
    )}


class _Events:
    def __init__(self) -> None:
        self.records: list[tuple[str, dict[str, Any]]] = []

    def write(self, event_type: str, **payload: Any) -> None:
        self.records.append((event_type, payload))


def _mk_node(
    code: bytes,
    ntype: str,
    snippet: bytes,
    *,
    field: str | None = None,
    named: bool = True,
    children: list[Node] | None = None,
) -> Node:
    idx = code.index(snippet)
    end = idx + len(snippet)
    line = code[:idx].count(b"\n") + 1
    end_line = code[:end].count(b"\n") + 1
    node = Node(ntype, field, named, False, idx, end, line, end_line, 1, max(1, len(snippet)), list(children or ()))
    for ch in node.children:
        ch.parent = node
    return node


def _extract_rules(grammar: str, language: str, path: str, code_str: str, children: list[Node],
                   units: list[dict[str, Any]] | None = None) -> set[str]:
    data = code_str.encode("utf-8")
    root = Node("program", None, True, False, 0, len(data), 1, max(1, data.count(b"\n") + 1), 1, 1, children)
    for ch in children:
        ch.parent = root
    sf = SourceFile(path, hashlib.sha256(data).hexdigest(), grammar, language, data, root, 0)
    ext = Extractor(sf, SPECS[grammar], list(units or ()), (), BASE_CONFIG.job(JOB_ID).settings)
    ext.run()
    return {s["rule_id"] for s in ext.signals}


def test_rust_security_surface_signal_rules() -> None:
    code = (
        "#[post(\"/exec\")]\n"
        "fn run(ptr: *mut u8, raw: &str, sql: &str) {\n"
        "    unsafe { let _v = *ptr; std::mem::transmute::<u64, usize>(1); }\n"
        "    Command::new(\"sh\");\n"
        "    sqlx::query(sql);\n"
        "    serde_json::from_str::<Val>(raw);\n"
        "}\n"
    )
    b = code.encode("utf-8")
    attr = _mk_node(b, "attribute_item", b"#[post(\"/exec\")]")
    deref = _mk_node(b, "unary_expression", b"*ptr", children=[
        _mk_node(b, "*", b"*", field="operator", named=False),
        _mk_node(b, "identifier", b"ptr"),
    ])
    transmute_fn = _mk_node(b, "scoped_identifier", b"std::mem::transmute", field="function")
    transmute_call = _mk_node(b, "call_expression", b"std::mem::transmute::<u64, usize>(1)", children=[transmute_fn])
    unsafe_blk = _mk_node(b, "unsafe_block", b"unsafe { let _v = *ptr; std::mem::transmute::<u64, usize>(1); }",
                          children=[deref, transmute_call])
    cmd_call = _mk_node(b, "call_expression", b"Command::new(\"sh\")", children=[
        _mk_node(b, "scoped_identifier", b"Command::new", field="function"),
    ])
    sql_call = _mk_node(b, "call_expression", b"sqlx::query(sql)", children=[
        _mk_node(b, "scoped_identifier", b"sqlx::query", field="function"),
    ])
    serde_call = _mk_node(b, "call_expression", b"serde_json::from_str::<Val>(raw)", children=[
        _mk_node(b, "scoped_identifier", b"serde_json::from_str", field="function"),
    ])
    rules = _extract_rules("rust", "Rust", "src/lib.rs", code, [attr, unsafe_blk, cmd_call, sql_call, serde_call])
    assert {
        "privilege.unsafe_block.rust",
        "sink.memory.rust-raw-pointer-deref",
        "privilege.unsafe_cast.rust-transmute",
        "sink.command_exec.rust",
        "sink.sql.rust",
        "wrapper.deserialization.rust-serde",
    } <= rules


def test_ruby_security_surface_signal_rules() -> None:
    code = (
        "Marshal.load(blob)\n"
        "YAML.load(doc)\n"
        "target.public_send(action)\n"
        "ERB.new(tmpl)\n"
        "system(cmd)\n"
        "`uname -a`\n"
        "params.permit!\n"
    )
    b = code.encode("utf-8")
    marshal = _mk_node(b, "call", b"Marshal.load(blob)", children=[
        _mk_node(b, "constant", b"Marshal", field="receiver"),
        _mk_node(b, "identifier", b"load", field="method"),
    ])
    yaml = _mk_node(b, "call", b"YAML.load(doc)", children=[
        _mk_node(b, "constant", b"YAML", field="receiver"),
        _mk_node(b, "identifier", b"load", field="method"),
    ])
    psend = _mk_node(b, "call", b"target.public_send(action)", children=[
        _mk_node(b, "identifier", b"target", field="receiver"),
        _mk_node(b, "identifier", b"public_send", field="method"),
    ])
    erb = _mk_node(b, "call", b"ERB.new(tmpl)", children=[
        _mk_node(b, "constant", b"ERB", field="receiver"),
        _mk_node(b, "identifier", b"new", field="method"),
    ])
    sysc = _mk_node(b, "call", b"system(cmd)", children=[
        _mk_node(b, "identifier", b"system", field="method"),
    ])
    subsh = _mk_node(b, "subshell", b"`uname -a`")
    permit = _mk_node(b, "call", b"params.permit!", children=[
        _mk_node(b, "identifier", b"params", field="receiver"),
        _mk_node(b, "identifier", b"permit!", field="method"),
    ])
    rules = _extract_rules("ruby", "Ruby", "app/controllers/c.rb", code,
                           [marshal, yaml, psend, erb, sysc, subsh, permit])
    assert {
        "sink.deserialization.ruby",
        "sink.dynamic_dispatch.ruby",
        "sink.template.ruby-erb",
        "sink.command_exec.ruby",
        "sink.command_exec.ruby-subshell",
        "privilege.mass_assignment.ruby",
    } <= rules


def test_php_security_surface_signal_rules() -> None:
    code = (
        "<?php\n"
        "unserialize($raw);\n"
        "eval($expr);\n"
        "preg_replace($pat, $rep, $s);\n"
        "include $mod;\n"
        "shell_exec($cmd);\n"
        "$pdo->query(\"SELECT * FROM users WHERE id = \" . $id);\n"
        "extract($_POST);\n"
    )
    b = code.encode("utf-8")
    unser = _mk_node(b, "function_call_expression", b"unserialize($raw)", children=[
        _mk_node(b, "name", b"unserialize", field="function"),
    ])
    ev = _mk_node(b, "function_call_expression", b"eval($expr)", children=[
        _mk_node(b, "name", b"eval", field="function"),
    ])
    preg = _mk_node(b, "function_call_expression", b"preg_replace($pat, $rep, $s)", children=[
        _mk_node(b, "name", b"preg_replace", field="function"),
    ])
    inc = _mk_node(b, "include_expression", b"include $mod", children=[
        _mk_node(b, "variable_name", b"$mod"),
    ])
    sh = _mk_node(b, "function_call_expression", b"shell_exec($cmd)", children=[
        _mk_node(b, "name", b"shell_exec", field="function"),
    ])
    concat_arg = _mk_node(b, "binary_expression", b"\"SELECT * FROM users WHERE id = \" . $id", children=[
        _mk_node(b, "string", b"\"SELECT * FROM users WHERE id = \""),
        _mk_node(b, ".", b".", field="operator", named=False),
        _mk_node(b, "variable_name", b"$id"),
    ])
    args = _mk_node(b, "arguments", b"(\"SELECT * FROM users WHERE id = \" . $id)", field="arguments",
                    children=[concat_arg])
    sql = _mk_node(b, "member_call_expression", b"$pdo->query(\"SELECT * FROM users WHERE id = \" . $id)", children=[
        _mk_node(b, "variable_name", b"$pdo", field="object"),
        _mk_node(b, "name", b"query", field="name"),
        args,
    ])
    ext = _mk_node(b, "function_call_expression", b"extract($_POST)", children=[
        _mk_node(b, "name", b"extract", field="function"),
    ])
    rules = _extract_rules("php", "PHP", "src/Controller.php", code, [unser, ev, preg, inc, sh, sql, ext])
    assert {
        "sink.deserialization.php",
        "sink.eval.php",
        "sink.file_inclusion.php",
        "sink.command_exec.php",
        "sink.sql.php-concat",
        "privilege.variable_overwrite.php-extract",
    } <= rules


def test_csharp_security_surface_signal_rules() -> None:
    code = (
        "[AllowAnonymous]\n"
        "public void Handle(byte[] src, IntPtr dst, string q) {\n"
        "    formatter.Deserialize(stream);\n"
        "    cfg.TypeNameHandling = TypeNameHandling.All;\n"
        "    Process.Start(q);\n"
        "    ctx.Users.FromSqlRaw(q);\n"
        "    unsafe { Marshal.Copy(src, 0, dst, src.Length); }\n"
        "    doc.XmlResolver = new XmlUrlResolver();\n"
        "}\n"
    )
    b = code.encode("utf-8")
    anon = _mk_node(b, "attribute", b"AllowAnonymous", children=[
        _mk_node(b, "identifier", b"AllowAnonymous", field="name"),
    ])
    deser = _mk_node(b, "invocation_expression", b"formatter.Deserialize(stream)", children=[
        _mk_node(b, "member_access_expression", b"formatter.Deserialize", field="function"),
    ])
    tnh = _mk_node(b, "assignment_expression", b"cfg.TypeNameHandling = TypeNameHandling.All", children=[
        _mk_node(b, "member_access_expression", b"cfg.TypeNameHandling", field="left"),
        _mk_node(b, "member_access_expression", b"TypeNameHandling.All", field="right"),
    ])
    proc = _mk_node(b, "invocation_expression", b"Process.Start(q)", children=[
        _mk_node(b, "member_access_expression", b"Process.Start", field="function"),
    ])
    sql = _mk_node(b, "invocation_expression", b"ctx.Users.FromSqlRaw(q)", children=[
        _mk_node(b, "member_access_expression", b"ctx.Users.FromSqlRaw", field="function"),
    ])
    mcopy = _mk_node(b, "invocation_expression", b"Marshal.Copy(src, 0, dst, src.Length)", children=[
        _mk_node(b, "member_access_expression", b"Marshal.Copy", field="function"),
    ])
    uns = _mk_node(b, "unsafe_statement", b"unsafe { Marshal.Copy(src, 0, dst, src.Length); }", children=[mcopy])
    xxe = _mk_node(b, "assignment_expression", b"doc.XmlResolver = new XmlUrlResolver()", children=[
        _mk_node(b, "member_access_expression", b"doc.XmlResolver", field="left"),
        _mk_node(b, "object_creation_expression", b"new XmlUrlResolver()", field="right"),
    ])
    rules = _extract_rules("csharp", "C#", "Controllers/AccountController.cs", code,
                           [anon, deser, tnh, proc, sql, uns, xxe])
    assert {
        "annotation.access-control-bypass",
        "wrapper.deserialization-member",
        "sink.deserialization.csharp-typenamehandling",
        "sink.command_exec.csharp",
        "sink.sql.csharp-ef-raw",
        "privilege.unsafe_block.csharp",
        "sink.memory.csharp-marshal",
        "privilege.xxe.csharp-xmlresolver",
    } <= rules


def _artifact_ref(run_root: Path, path: Path, value: Any | None = None) -> dict[str, Any]:
    if value is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(path, value)
    return {
        "path": path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(path),
        "size_bytes": path.stat().st_size,
    }


def _publish_handoff(
    run_root: Path,
    job_id: str,
    outputs: dict[str, Any],
    *,
    terminal_status: str = "SUCCEEDED",
    attempt_id: str = "att_0001",
) -> str:
    attempt = run_root / "data" / "jobs" / job_id / "attempts" / attempt_id
    attempt.mkdir(parents=True, exist_ok=True)
    handoff = attempt / "handoff.json"
    write_fixture_handoff(run_root, handoff, {
        "status": "ACCEPTED",
        "job_id": job_id,
        "attempt_id": attempt_id,
        "terminal_status": terminal_status,
        "outputs": outputs,
    })
    sha = file_sha256(handoff)
    atomic_json(run_root / "data" / "jobs" / job_id / "latest.json", {
        "handoff_path": handoff.relative_to(run_root).as_posix(),
        "handoff_sha256": sha,
    })
    return sha


def _seed_polyglot_run(tmp_path: Path) -> tuple[Path, Path, str, dict[str, str]]:
    golden_paths = (
        "rust/src/lib.rs",
        "ruby/lib/processor.rb",
        "php/src/Controller.php",
        "dotnet/Controllers/AccountController.cs",
        "go/server/handler.go",
        "web/src/server.js",
    )
    run_root = tmp_path / "runs" / "2026-11-17-ws-b"
    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)
    lang_by_suffix = {
        ".go": "Go", ".js": "JavaScript", ".rb": "Ruby",
        ".php": "PHP", ".rs": "Rust", ".cs": "C#",
    }
    catalog_files: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for rel in golden_paths:
        dst = target / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(TARGET / rel, dst)
        catalog_files.append({
            "path": rel,
            "sha256": file_sha256(dst),
            "size_bytes": dst.stat().st_size,
            "language": lang_by_suffix[dst.suffix],
            "generated": False,
            "delivery_role": "production",
            "first_party": True,
            "vendored": False,
        })
        rec = GOLDEN["files"][rel]
        for node in rec["nodes"]:
            rows.append({
                "schema": "appsec-review/tree-sitter-ast-node/1",
                "path": rel,
                "file_sha256": rec["sha256"],
                "grammar_native_type": node["type"],
                "field": node["field"],
                "named": node["named"],
                "error": node["error"],
                "missing": node["missing"],
                "location": {
                    "producer_location": {"grammar": rec["grammar"], "ordinal_path": node["ordinal_path"]},
                    "start_byte": node["start_byte"],
                    "end_byte": node["end_byte"],
                    "start_line": node["start_point"][0] + 1,
                    "end_line": node["end_point"][0] + 1,
                    "start_column": node["start_point"][1] + 1,
                    "end_column": node["end_point"][1] + 1,
                },
            })

    snapshot = hashlib.sha256(json.dumps(sorted(f["path"] for f in catalog_files)).encode()).hexdigest()
    intake_ref = _artifact_ref(run_root, run_root / "fixture" / "intake.json", {
        "schema": "appsec-review/review-intake/1",
        "fingerprint": {"sha256": snapshot},
    })
    intake_sha = _publish_handoff(run_root, "job_review_intake", {
        "publish_intake.publish_handoff": {"artifact": intake_ref},
    })
    part_ref = _artifact_ref(run_root, run_root / "fixture" / "partition.json", {"files": catalog_files})
    comp_ref = _artifact_ref(run_root, run_root / "fixture" / "components.json", {
        "components": [{"component_id": "comp:root", "root": "."}],
    })
    cat_mf = run_root / "data" / "indices" / "manifests" / "catalog.json"
    write_manifest(cat_mf, run_id=run_root.name, target_snapshot=snapshot, target_root=target, indexes=[])
    cat_ref = _artifact_ref(run_root, run_root / "fixture" / "catalog.json", {
        "schema": "appsec-review/target-catalog/1",
        "source_fingerprint": snapshot,
        "artifacts": {
            "repository_discovery.partition_repository": part_ref,
            "component_discovery.catalog_components": comp_ref,
        },
    })
    cat_sha = _publish_handoff(run_root, "job_target_catalog", {
        "publish_catalog.publish_handoff": {
            "artifact": cat_ref,
            "index_manifest": _artifact_ref(run_root, cat_mf),
        },
    })
    shard_path = run_root / "data" / "treesitter" / "shards" / ("b" * 64 + ".jsonl")
    shard_path.parent.mkdir(parents=True, exist_ok=True)
    shard_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    ts_ref = _artifact_ref(run_root, run_root / "fixture" / "tree-sitter.json", {
        "schema": "appsec-review/tree-sitter-ast/1",
        "target_snapshot": snapshot,
        "dispositions": [{
            "scope_id": "scope-polyglot",
            "language": "Rust",
            "terminal_status": "SUCCEEDED",
            "artifact": _artifact_ref(run_root, shard_path),
            "gaps": [],
        }],
        "generated_sources": [],
    })
    ts_sha = _publish_handoff(run_root, "job_tree_sitter_ast", {
        "acceptance.publish_handoff": {"artifact": ts_ref},
    })
    return run_root, target, snapshot, {
        "job_review_intake": intake_sha,
        "job_target_catalog": cat_sha,
        "job_tree_sitter_ast": ts_sha,
    }


def test_end_to_end_engineering_signal_rewiring_and_sast_silence_hunt(tmp_path: Path) -> None:
    run_root, target, snapshot, handoffs = _seed_polyglot_run(tmp_path)

    # 1. Seed job_change_context_analysis
    cc_ref = _artifact_ref(run_root, run_root / "fixture" / "change-context.json", {
        "schema": "appsec-review/change-context-analysis/1",
        "priority": {
            "top": {
                "files": [{"path": "rust/src/lib.rs", "score": 92.0, "security_relevant": True, "fix_on_fix": True}],
                "functions": [{"path": "rust/src/lib.rs", "start_line": 1, "end_line": 80, "score": 95.0, "security_relevant": True}],
            },
        },
    })
    handoffs["job_change_context_analysis"] = _publish_handoff(run_root, "job_change_context_analysis", {
        "publish.publish_handoff": {"artifact": cc_ref},
    })

    # 2. Seed job_test_coverage (rust/src/lib.rs 0% covered, web/src/server.js 100% covered)
    tc_ref = _artifact_ref(run_root, run_root / "fixture" / "test-coverage.json", {
        "schema": "appsec-review/test-coverage-handoff/1",
        "build_units": [{
            "build_unit_id": "bu-cov",
            "files": [
                {"path": "rust/src/lib.rs", "totals": {"lines_total": 40, "lines_covered": 0}},
                {"path": "web/src/server.js", "totals": {"lines_total": 40, "lines_covered": 40}},
            ],
        }],
    })
    handoffs["job_test_coverage"] = _publish_handoff(run_root, "job_test_coverage", {
        "acceptance.publish_handoff": {"artifact": tc_ref},
    })

    # 3. Seed job_profile_data (ruby/lib/processor.rb hot path)
    pd_ref = _artifact_ref(run_root, run_root / "fixture" / "profile-data.json", {
        "schema": "appsec-review/profile-data-handoff/1",
        "build_units": [{
            "build_unit_id": "bu-prof",
            "rows": [
                {"source": "ruby/lib/processor.rb", "line": 5, "count": 5000, "hotness_rank": 1, "hotness_population": 20},
            ],
        }],
    })
    handoffs["job_profile_data"] = _publish_handoff(run_root, "job_profile_data", {
        "acceptance.publish_handoff": {"artifact": pd_ref},
    })

    # 4. Seed job_ci_configuration_analysis with promoted workflow findings
    ci_ref = _artifact_ref(run_root, run_root / "fixture" / "ci-config.json", {
        "schema": "appsec-review/ci-configuration-analysis/1",
        "security_findings": [
            {
                "rule_id": "CI-EXPRESSION-INJECTION",
                "path": ".github/workflows/pr.yml",
                "line": 24,
                "lead_candidate": True,
                "attack_class": "ci_expression_injection",
                "severity_hint": "critical",
                "message": "Untrusted github.event.pull_request.title interpolated in run shell",
            },
        ],
    })
    handoffs["job_ci_configuration_analysis"] = _publish_handoff(run_root, "job_ci_configuration_analysis", {
        "ci_coverage.publish_handoff": {"artifact": ci_ref},
    })

    # 5. Seed job_artifact_security_analysis with promoted observation entity
    art_shard = run_root / "data" / "indices" / "observations" / "artifact-security" / ("c" * 64 + ".sqlite")
    builder = IndexBuilder(art_shard, name="observations", fingerprint="c" * 64, target_snapshot=snapshot,
                           shard_id="artifact-security")
    obs_id = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"id": "art-1"})
    builder.add_entity(EntityRecord(
        obs_id,
        "art-1",
        "packaged-secret",
        "Hardcoded private key in container layer",
        {
            "findings": [{
                "code": "packaged_private_key",
                "lead_candidate": True,
                "attack_class": "hardcoded_packaged_secret",
                "severity_hint": "critical",
                "summary": "PEM private key packaged inside image config",
            }],
        },
        SourceLocation(snapshot, "php/src/Controller.php", GOLDEN["files"]["php/src/Controller.php"]["sha256"],
                       0, 10, 1, 1, 1, 10, {"job": "job_artifact_security_analysis"}, "exact", 1.0),
    ))
    builder.build()
    art_idx = IndexIdentity(
        "observations", "appsec-review/retrieval-index/2", file_sha256(art_shard), "c" * 64,
        art_shard.relative_to(run_root).as_posix(), {"job": "job_artifact_security_analysis"}, (), "artifact-security",
    )
    art_mf = run_root / "data" / "indices" / "manifests" / "artifact-sec.json"
    write_manifest(art_mf, run_id=run_root.name, target_snapshot=snapshot, target_root=target, indexes=[art_idx])
    art_doc = _artifact_ref(run_root, run_root / "fixture" / "artifact-sec.json", {
        "schema": "appsec-review/artifact-security-analysis/1",
    })
    handoffs["job_artifact_security_analysis"] = _publish_handoff(run_root, "job_artifact_security_analysis", {
        "acceptance.publish_handoff": {
            "artifact": art_doc,
            "index_manifest": _artifact_ref(run_root, art_mf),
        },
    })

    # 6. Native FFI is package context, not proof of vulnerable-symbol execution.
    sca_ref = _artifact_ref(run_root, run_root / "fixture" / "sca-reachability.json", {
        "schema": "appsec-review/sca-reachability/1",
        "osv_matching_mode": "index",
        "advisories": [
            {
                "advisory_id": "GHSA-xxxx-1111",
                "package_name": "openssl-sys",
                "ecosystem": "crates.io",
                "severity": "critical",
                "reachability": "package_imported",
                "ffi_mechanisms": ["rust_extern"],
                "call_sites": [{"path": "rust/src/lib.rs", "line": 10, "symbol": "crypto",
                               "kind": "ffi_boundary", "ffi_mechanism": "rust_extern"}],
            },
            {
                "advisory_id": "GHSA-yyyy-2222",
                "package_name": "unused-transitive",
                "ecosystem": "crates.io",
                "severity": "low",
                "reachability": "transitive_only",
                "call_sites": [],
            },
        ],
    })
    handoffs["job_dependency_intelligence"] = _publish_handoff(run_root, "job_dependency_intelligence", {
        "acceptance.publish_handoff": {"sca_reachability": sca_ref},
    })

    # 7. Seed job_evidence_collection covering ONLY web/src/server.js so other complex surface units are SAST-silent!
    ev_corr = _artifact_ref(run_root, run_root / "fixture" / "corroborated.json", {
        "schema": "appsec-review/corroborated-sast-evidence/1",
        "clusters": [
            {"path": "web/src/server.js", "start_line": 1, "end_line": 120, "cwe_family": "CWE-89",
             "corroborating_scanners": ["semgrep", "opengrep"], "corroboration_count": 2, "scanner_rule_ids": ["js.sqli"]},
        ],
    })
    ev_mf = run_root / "data" / "indices" / "manifests" / "evidence.json"
    write_manifest(ev_mf, run_id=run_root.name, target_snapshot=snapshot, target_root=target, indexes=[])
    ev_doc = _artifact_ref(run_root, run_root / "fixture" / "evidence.json", {
        "schema": "appsec-review/evidence-collection/1",
        "tools": {"semgrep": {"terminal_status": "SUCCEEDED", "gaps": []}},
    })
    handoffs["job_evidence_collection"] = _publish_handoff(run_root, "job_evidence_collection", {
        "evidence_publication.publish_handoff": {
            "artifact": ev_doc,
            "corroborated_sast_evidence": ev_corr,
            "index_manifest": _artifact_ref(run_root, ev_mf),
        },
    })

    job_cfg = replace(BASE_CONFIG.job(JOB_ID), settings={
        **BASE_CONFIG.job(JOB_ID).settings,
        "sast_silence_min_complexity": 2,
    })
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / "attempt_0001"
    attempt_root.mkdir(parents=True, exist_ok=True)
    metadata_root = tmp_path / "metadata"
    metadata_root.mkdir(parents=True, exist_ok=True)
    cat_mf = run_root / "data" / "indices" / "manifests" / "catalog.json"
    ctx = SimpleNamespace(
        job_id=JOB_ID,
        run_id=run_root.name,
        run_root=run_root,
        runs_dir=run_root.parent,
        repository_root=ROOT,
        target_root=target,
        source_fingerprint=snapshot,
        attempt_id="attempt_0001",
        attempt_root=attempt_root,
        metadata_root=metadata_root,
        input_manifest_path=cat_mf,
        input_manifest_sha256=file_sha256(cat_mf),
        config=job_cfg,
        tools=BASE_CONFIG.tools,
        review_policy=BASE_CONFIG.review_policy,
        upstream_handoffs=handoffs,
        events=_Events(),
        contract=CONTRACT,
    )

    built = build_job()
    result = built.execute(ctx)
    pub = result["outputs"]["publish.publish_handoff"]
    assert "prioritization_signals_artifact" in pub

    signals_doc = read_json(run_root, pub["prioritization_signals_artifact"])
    assert signals_doc["schema"] == PRIORITIZATION_SIGNALS_SCHEMA
    jsonschema.validate(instance=signals_doc, schema=SIGNALS_SCHEMA, registry=SIGNALS_REGISTRY)

    telemetry = signals_doc["telemetry"]
    assert telemetry["leads_promoted_ci"] == 1
    assert telemetry["leads_promoted_artifact"] == 1
    assert telemetry["leads_promoted_sca_reachable"] == 1
    assert telemetry["sast_silence_hunt_units"] >= 1
    assert telemetry["composite_boosted_units"] >= 3

    sources_seen = {lead["lead_source"] for lead in signals_doc["promoted_leads"]}
    assert sources_seen == {"ci_configuration", "artifact_security", "sca_reachable"}

    ranking = read_json(run_root, result["outputs"]["prioritize.score"]["artifact"])
    files_by_path = {f["path"]: f for f in ranking["files"]}
    assert ranking["score_normalization"]["maximum"] == 1.87
    for item in [*ranking["files"], *ranking["functions"], *signals_doc["hunt_queue"]]:
        assert item["raw_score"] == round(item["base_score"] + math.fsum(item["composite_modifiers"].values()), 6)
        assert item["score"] == item["raw_score"] / 1.87
        assert 0.0 <= item["score"] <= 1.0

    rust_mods = files_by_path["rust/src/lib.rs"]["composite_modifiers"]
    assert rust_mods["change_context_boost"] > 0.0
    assert rust_mods["uncovered_risk_boost"] > 0.0
    assert rust_mods["sca_reachability_boost"] > 0.0

    ruby_mods = files_by_path["ruby/lib/processor.rb"]["composite_modifiers"]
    assert ruby_mods["profile_hotpath_boost"] > 0.0

    # web/src/server.js is 100% covered AND covered by SAST -> zero uncovered boost and zero SAST-silence boost!
    js_mods = files_by_path["web/src/server.js"]["composite_modifiers"]
    assert js_mods["uncovered_risk_boost"] == 0.0
    assert js_mods["sast_silence_hunt_boost"] == 0.0
    assert "hunt_priority_reason" not in files_by_path["web/src/server.js"]

    # Hunt queue promotes SAST-silent high-surface complex units and excludes SAST-covered web/src/server.js
    hunt_paths = {h["path"] for h in signals_doc["hunt_queue"]}
    assert "web/src/server.js" not in hunt_paths
    assert len(hunt_paths) >= 1
    assert all(h["hunt_priority_reason"] == HUNT_PRIORITY_REASON_ZERO_SAST for h in signals_doc["hunt_queue"])

    completed_events = [payload for etype, payload in ctx.events.records if etype == "REVIEW_PRIORITIZATION_COMPLETED"]
    assert len(completed_events) == 1
    assert completed_events[0]["leads_promoted_ci"] == 1
    assert completed_events[0]["leads_promoted_artifact"] == 1
    assert completed_events[0]["leads_promoted_sca_reachable"] == 1
    assert completed_events[0]["sast_silence_hunt_units"] == telemetry["sast_silence_hunt_units"]


def _review_units_from_priority(run_root: Path, target: Path, result: dict[str, Any]):
    manifest = result["outputs"]["publish.publish_handoff"]["index_manifest"]
    scope = accept_manifest(run_root, manifest_path=run_root / manifest["path"],
                            manifest_sha256=manifest["sha256"])
    ranking = read_json(run_root, result["outputs"]["prioritize.score"]["artifact"])
    sources = tuple(ReviewSourceFile(
        item["path"],
        LogicalIdentity.derive(EntityKind.SOURCE_FILE, scope.target_snapshot, {
            "path": item["path"], "sha256": file_sha256(target / item["path"]),
        }).value,
        item["language"],
    ) for item in ranking["files"])
    scope = replace(scope, source_files=sources)
    units = build_units(scope, LeadCollection((), (), {}, None), unit_max_files=1)
    return ranking, scope, units


@pytest.mark.parametrize("boost", [0.0, 0.4, 0.5, 0.6, 1.5], ids=["zero", "below", "at", "above", "large"])
def test_composite_priority_publication_preserves_review_order(tmp_path: Path, boost: float) -> None:
    """T-5084: consume real published scores on both sides of the old 1.0 discontinuity."""
    run_root, target, snapshot, handoffs = _seed_upstream_run(
        tmp_path, golden_paths=("go/server/handler.go", "go/store/store.go"))
    changed = "go/store/store.go"
    change_ref = _artifact_ref(run_root, run_root / "fixture" / "change-context.json", {
        "schema": "appsec-review/change-context-analysis/1",
        "priority": {"top": {"files": [{"path": changed, "score": 1.0}]}},
    })
    handoffs["job_change_context_analysis"] = _publish_handoff(
        run_root, "job_change_context_analysis", {"publish.publish_handoff": {"artifact": change_ref}})
    settings = BASE_CONFIG.job(JOB_ID).settings
    override = {
        "priority_weights": {"public_api": 1.0, "cyclomatic": 1.0},
        "sources": _sources("change_context"),
        "composite_weights": {
            **{key: 0.0 for key in CompositePrioritizationSettings().weights_dict()},
            "change_context_boost": boost,
        },
        "index": {**settings["index"], "file_top_count": 2, "max_indexed_items": 2},
    }
    result = build_job().execute(_job_context(tmp_path, run_root, target, snapshot, handoffs,
                                              settings_override=override))
    ranking, scope, units = _review_units_from_priority(run_root, target, result)
    items = {item["path"]: item for item in ranking["files"]}
    assert items[changed]["base_score"] == 0.5
    assert items[changed]["raw_score"] == pytest.approx(0.5 + boost)
    assert items[changed]["score"] == pytest.approx((0.5 + boost) / (1.0 + boost))
    normalization = ranking["score_normalization"]
    assert normalization["maximum"] == 1.0 + boost
    assert normalization["rule"] == "appsec-review/composite-prioritization-score/1"
    published = read_json(run_root, result["outputs"]["publish.publish_handoff"]["artifact"])
    assert published["identities"]["score"] == normalization["rule"]
    assert published["score_normalization"] == normalization
    assert len(normalization["configuration_sha256"]) == 64
    assert normalization["configuration_sha256"] == hashlib.sha256(
        canonical_json({**settings, **override})).hexdigest()
    points = {unit.paths[0]: next(s.value for s in unit.signals if s.signal == "lps") for unit in units}
    if boost:
        assert points[changed] > points["go/server/handler.go"]
    else:
        assert points[changed] == points["go/server/handler.go"]
    assert [ranked.unit.paths[0] for ranked in rank_units(reversed(units))] == [
        item["path"] for item in ranking["files"]]
    for unit in units:
        expected = LogicalIdentity.derive(EntityKind.PRIORITY_ITEM, snapshot,
                                          {"item_id": items[unit.paths[0]]["item_id"]}).value
        contexts = [entry for entry in unit.context if entry.role == "priority"]
        assert [entry.id for entry in contexts] == [expected]
        assert contexts[0].shard_sha256 == scope.producer("review_prioritization").shards[0]["sha256"]
        assert unit.source_ids == (scope.source_for(unit.paths[0]).identity,)
    for weight in (0, 250, 1000):
        weighted = build_units(scope, LeadCollection((), (), {}, None), unit_max_files=1,
                               weights=RankWeights(lps=weight))
        for unit in weighted:
            [lps] = [signal for signal in unit.signals if signal.signal == "lps"]
            assert lps.value == round(items[unit.paths[0]]["score"] * weight)
            assert 0 <= lps.value <= weight


@pytest.mark.parametrize("weight,disabled", [
    (0.0, False), (2.0, False), (1e307, False), (0.00000051, False), (2.0, True),
], ids=["zero", "large", "large-finite", "rounded", "disabled"])
def test_composite_maximum_matches_attainable_factor_bounds(tmp_path: Path, weight: float, disabled: bool) -> None:
    """Use real loaders and scoring; every multiplier can reach one for files and functions."""
    run_root = tmp_path / "run"
    path = "src/parser.c"
    upstream = (
        ("job_change_context_analysis", "publish.publish_handoff", "artifact", {
            "schema": "appsec-review/change-context-analysis/1",
            "files": [{"path": path, "score": 1.0}],
        }),
        ("job_test_coverage", "acceptance.publish_handoff", "artifact", {
            "schema": "appsec-review/test-coverage-handoff/1",
            "files": [{"path": path, "totals": {"lines_total": 1, "lines_covered": 0}}],
        }),
        ("job_profile_data", "acceptance.publish_handoff", "artifact", {
            "schema": "appsec-review/profile-data-handoff/1",
            "rows": [{"source": path, "symbol": "parse", "line": 1, "hotness_rank": 1, "hotness_population": 1}],
        }),
        ("job_dependency_intelligence", "acceptance.publish_handoff", "sca_reachability", {
            "schema": "appsec-review/sca-reachability/1",
            "advisories": [{"advisory_id": "test", "package_name": "parser", "reachability": "symbol_reachable",
                           "call_sites": [{"path": path, "line": 1}]}],
        }),
    )
    for job, output, key, document in upstream:
        ref = _artifact_ref(run_root, run_root / "fixture" / f"{job}.json", document)
        _publish_handoff(run_root, job, {output: {key: ref}})
    weights = {key: weight for key in CompositePrioritizationSettings().weights_dict()}
    settings = {**BASE_CONFIG.job(JOB_ID).settings, "composite_weights": weights,
                "sources": _sources() if disabled else _sources(
                    "change_context", "test_coverage", "profile_data", "dependency_intelligence", "sast_silence_hunt")}

    def ranked(scope: str) -> list[dict[str, Any]]:
        return scoring.rank([{
            "item_id": f"{scope}:{path}", "scope": scope, "path": path, "name": "parse",
            "language": "C", "start_line": 1, "end_line": 1,
            "features": {"cyclomatic": 12, "ingress": 1, "public_api": 1, "sink": 1},
        }], {"cyclomatic": 1.0}, scoring.FEATURES, population="run")

    files, functions, signals = apply_composite_prioritization(
        run_root, target_snapshot="a" * 64, settings=settings, semantic_doc={},
        ranked_files=ranked("file"), ranked_functions=ranked("function"))
    maximum_boost = 0.0 if disabled else round(weight, 6)
    maximum = round(1.0 + 5 * maximum_boost, 6)
    assert signals["score_normalization"]["maximum"] == maximum
    for item in [*files, *functions]:
        assert item["base_score"] == 0.5
        assert set(item["composite_modifiers"].values()) == {maximum_boost}
        assert item["raw_score"] == round(0.5 + 5 * maximum_boost, 6)
        assert item["score"] == item["raw_score"] / maximum
        assert 0 <= item["score"] <= 1
    jsonschema.validate(signals, SIGNALS_SCHEMA, registry=SIGNALS_REGISTRY)


def test_normalization_is_configuration_bound_not_availability_bound(tmp_path: Path) -> None:
    run_root, target, snapshot, handoffs = _seed_upstream_run(
        tmp_path, golden_paths=("go/server/handler.go", "go/store/store.go"))
    settings = BASE_CONFIG.job(JOB_ID).settings
    override = {"priority_weights": {"public_api": 1.0, "cyclomatic": 1.0},
                "sources": _sources("change_context"),
                "composite_weights": {"change_context_boost": 1.5},
                "index": {**settings["index"], "file_top_count": 2, "max_indexed_items": 2}}
    built = build_job()
    before = built.execute(_job_context(tmp_path, run_root, target, snapshot, handoffs,
                                        settings_override=override, attempt_id="before"))
    before_ranking, _, before_units = _review_units_from_priority(run_root, target, before)
    assert before_ranking["engineering_sources"]["change_context"] == "UNAVAILABLE"
    ref = _artifact_ref(run_root, run_root / "fixture" / "change-context.json", {
        "schema": "appsec-review/change-context-analysis/1",
        "files": [{"path": "go/store/store.go", "score": 1.0},
                  {"path": "go/server/handler.go", "score": 0.5}],
    })
    handoffs["job_change_context_analysis"] = _publish_handoff(
        run_root, "job_change_context_analysis", {"publish.publish_handoff": {"artifact": ref}})
    after = built.execute(_job_context(tmp_path, run_root, target, snapshot, handoffs,
                                       settings_override=override, attempt_id="after"))
    after_ranking, _, after_units = _review_units_from_priority(run_root, target, after)
    assert before_ranking["score_normalization"] == after_ranking["score_normalization"]
    assert before_ranking["score_normalization"]["maximum"] == 2.5
    assert [item["raw_score"] for item in after_ranking["files"]] == [2.0, 1.25]
    assert [item["score"] for item in after_ranking["files"]] == [0.8, 0.5]
    assert [ranked.unit.score for ranked in rank_units(before_units)] == [200, 200]
    assert [ranked.unit.score for ranked in rank_units(after_units)] == [800, 500]
    assert before["outputs"]["publish.index_priority"]["index_identity"]["fingerprint"] != (
        after["outputs"]["publish.index_priority"]["index_identity"]["fingerprint"])


def test_priority_consumer_keeps_missing_and_unknown_contracts_unknown(tmp_path: Path, monkeypatch) -> None:
    run_root, target, snapshot, handoffs = _seed_upstream_run(
        tmp_path, golden_paths=("go/server/handler.go", "go/store/store.go"))
    settings = BASE_CONFIG.job(JOB_ID).settings
    override = {"sources": _sources(),
                "index": {**settings["index"], "file_top_count": 1, "max_indexed_items": 1}}
    result = build_job().execute(_job_context(tmp_path, run_root, target, snapshot, handoffs,
                                              settings_override=override))
    _, scope, units = _review_units_from_priority(run_root, target, result)
    assert sorted(s.state for u in units for s in u.signals if s.signal == "lps") == ["available", "unknown"]
    assert [s.reason for u in units for s in u.signals if s.signal == "lps" and s.value is None] == ["no_record"]
    original_entities = ShardSet.entities
    patches = [
        {"score_identity": "appsec-review/llm-prioritization-score/1", "score": 0.8},
        {"score_identity": "appsec-review/llm-prioritization-score/1", "score": 1.1},
        {"score_identity": "unknown"},
        {"score_normalization": None},
        {"score_normalization": {"rule": "appsec-review/composite-prioritization-score/1"}},
        {"raw_score": None}, {"raw_score": float("inf")}, {"raw_score": -1},
        {"score": 0.123456},
        {"score": None}, {"score": True}, {"score": -0.1}, {"score": 1.1},
        {"score": float("nan")}, {"score": float("inf")},
    ]
    for patch in patches:
        def entities(store, shards, *, kinds=()):
            for row in original_entities(store, shards, kinds=kinds):
                if row["kind"] == "priority_item":
                    row = {**row, "payload": {**row["payload"], **patch}}
                yield row
        monkeypatch.setattr(ShardSet, "entities", entities)
        consumed = build_units(scope, LeadCollection((), (), {}, None), unit_max_files=1)
        assert all(s.state == "unknown" and s.reason == "no_record"
                   for u in consumed for s in u.signals if s.signal == "lps"), patch
    missing = replace(scope, producers=tuple(
        replace(p, shards=()) if p.producer == "review_prioritization" else p for p in scope.producers))
    assert all(s.state == "unknown" and s.reason == "producer_unavailable"
               for u in build_units(missing, LeadCollection((), (), {}, None), unit_max_files=1)
               for s in u.signals if s.signal == "lps")


@pytest.mark.parametrize("change", ["legacy", "configuration"], ids=["old-raw", "other-run-settings"])
def test_publication_refuses_cached_ranking_with_different_score_contract(tmp_path: Path, change: str) -> None:
    run_root, target, snapshot, handoffs = _seed_upstream_run(tmp_path, golden_paths=("go/store/store.go",))
    ctx = _job_context(tmp_path, run_root, target, snapshot, handoffs)
    built = build_job()
    result = built.execute(ctx)
    outputs = deepcopy(result["outputs"])
    ranking = read_json(run_root, outputs["prioritize.score"]["artifact"])
    if change == "legacy":
        ranking["identity"] = "appsec-review/llm-prioritization-score/1"
        ranking.pop("score_normalization")
        for item in [*ranking["files"], *ranking["functions"]]:
            item["score"] = item["raw_score"]
    else:
        ranking["score_normalization"]["configuration_sha256"] = "0" * 64
    outputs["prioritize.score"]["artifact"] = _artifact_ref(
        run_root, run_root / "fixture" / "cached-ranking.json", ranking)
    for unit_id in ("publish.index_priority", "publish.publish_handoff"):
        unit = next(unit for unit in built.units if unit.unit_id == unit_id)
        with pytest.raises(ValueError, match="ranking score contract"):
            unit.handler(SimpleNamespace(job=ctx, unit_id=unit_id,
                                         unit_root=ctx.attempt_root / unit_id, output=outputs.__getitem__))
