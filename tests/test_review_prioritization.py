from __future__ import annotations

from dataclasses import replace
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_review_prioritization import build_job, load_accepted_prioritization
from appsec_review.jobs.job_review_prioritization.complexity import function_units
from appsec_review.jobs.job_review_prioritization.dependencies import GraphBuilder, extract, import_modules
from appsec_review.jobs.job_review_prioritization.heuristics import Extractor
from appsec_review.jobs.job_review_prioritization.languages import SPECS
from appsec_review.jobs.job_review_prioritization.scoring import percentiles, rank, selection_size
from appsec_review.jobs.job_review_prioritization.syntax import SourceFile, build_tree
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_tree_sitter_ast import build_job as build_tree_sitter
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RetrievalCore, SourceLocation,
    write_manifest,
)
from appsec_review.runtime import GraphRunner
from appsec_review.storage import atomic_json, file_sha256


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "review_prioritization"
TARGET = FIXTURE / "target"
GOLDEN = json.loads(gzip.decompress((FIXTURE / "ast-golden.json.gz").read_bytes()))
SETTINGS = {"custom_parsing_min_operations": 6, "custom_parsing_min_density": 0.5,
            "state_mutation_min_operations": 3}


def _rows(nodes: list[dict[str, Any]]):
    for node in nodes:
        yield {"grammar_native_type": node["type"], "field": node["field"], "named": node["named"],
               "error": node["error"], "missing": node["missing"],
               "location": {"producer_location": {"ordinal_path": node["ordinal_path"]},
                            "start_byte": node["start_byte"], "end_byte": node["end_byte"],
                            "start_line": node["start_point"][0] + 1, "end_line": node["end_point"][0] + 1,
                            "start_column": node["start_point"][1] + 1, "end_column": node["end_point"][1] + 1}}


def parsed(path: str) -> tuple[SourceFile, Any]:
    record = GOLDEN["files"][path]
    root, errors = build_tree(_rows(record["nodes"]))
    spec = SPECS[record["grammar"]]
    return SourceFile(path, record["sha256"], record["grammar"], spec.language, (TARGET / path).read_bytes(),
                      root, errors), spec


def units_of(path: str, *, count_error_propagation: bool = True) -> dict[str, dict[str, Any]]:
    source, spec = parsed(path)
    units, truncated = function_units(source, spec, count_error_propagation=count_error_propagation, limit=1000)
    assert not truncated
    return {unit["qualified_name"]: unit for unit in units}


def extracted(path: str) -> tuple[dict[str, dict[str, Any]], Extractor, list[dict[str, Any]]]:
    source, spec = parsed(path)
    units, _ = function_units(source, spec, count_error_propagation=True, limit=1000)
    records, _declarations = extract(source, spec)
    extractor = Extractor(source, spec, units, import_modules(records), SETTINGS)
    extractor.run()
    return {unit["qualified_name"]: unit for unit in units}, extractor, records


def by_rule(extractor: Extractor, rule_id: str) -> list[dict[str, Any]]:
    return [item for item in extractor.signals if item["rule_id"] == rule_id]


def fn(value: str | None) -> str | None:
    return value.split("#", 1)[1].rsplit("@", 1)[0] if value else None


# --- generated golden ----------------------------------------------------------------------------

def test_ast_golden_matches_fixture_bytes_and_locked_parser_versions() -> None:
    sources = {path.relative_to(TARGET).as_posix() for path in TARGET.rglob("*")
               if path.is_file() and path.suffix in {".c", ".h", ".cpp", ".java", ".cs", ".go", ".js", ".ts", ".rs",
                                                     ".php"}}
    assert set(GOLDEN["files"]) == sources
    for path, record in GOLDEN["files"].items():
        assert hashlib.sha256((TARGET / path).read_bytes()).hexdigest() == record["sha256"], (
            f"{path} changed; run tests/fixtures/review_prioritization/generate_ast.py")
    lock = json.loads((ROOT / "containers" / "tools" / "tree-sitter" / "assets.lock.json").read_text())
    assert GOLDEN["tool"] == {"tree_sitter": lock["tree_sitter"]["version"],
                              "language_pack": lock["language_pack"]["version"]}


def test_ast_golden_regenerates_identically_with_the_pinned_parser() -> None:
    from importlib.metadata import PackageNotFoundError, version
    try:
        installed = version("tree-sitter-language-pack")
    except PackageNotFoundError:
        pytest.skip("pinned tree-sitter-language-pack is not installed")
    if installed != GOLDEN["tool"]["language_pack"]:
        pytest.skip("installed tree-sitter-language-pack does not match the locked version")
    spec = importlib.util.spec_from_file_location("generate_ast", FIXTURE / "generate_ast.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    assert module.parse_records() == GOLDEN


# --- structural complexity -----------------------------------------------------------------------

def test_go_error_checks_are_error_propagation_branches() -> None:
    store = units_of("go/store/store.go")
    save = store["DB.Save"]
    assert save["cyclomatic"] == 4 and save["error_propagation"] == {"rust_try_operator": 0, "go_error_check": 3}
    assert save["cyclomatic_without_error_propagation"] == 1
    handler = units_of("go/server/handler.go")["Register.<callback:mux.HandleFunc>"]
    assert handler["cyclomatic"] == 5 and handler["cyclomatic_without_error_propagation"] == 3
    assert handler["anonymous"] and handler["parent_function"].endswith("#Register@15:1")
    assert units_of("go/store/store.go", count_error_propagation=False)["DB.Save"]["cyclomatic"] == 1


def test_rust_question_mark_closures_match_guards_and_recursion() -> None:
    units = units_of("rust/src/lib.rs")
    load = units["load"]
    assert load["error_propagation"]["rust_try_operator"] == 2
    assert load["decisions"] == {"guard": 1, "multiway_arm": 2}
    assert (load["cyclomatic"], load["cyclomatic_without_error_propagation"]) == (6, 4)
    assert load["cognitive"] == 1  # one match; `?` adds no cognitive increment
    closure = units["load.adjust"]
    assert closure["anonymous"] and closure["cyclomatic"] == 2 and closure["parent_function"].endswith("#load@11:1")
    walk = units["walk"]
    assert walk["cyclomatic"] == 5 and walk["recursive"]
    # loop(+1) if-let(+2 nested) if(+3 nested) if(+1) else(+1) recursion(+1)
    assert walk["cognitive"] == 9 and walk["max_nesting"] == 3
    assert units_of("rust/src/lib.rs", count_error_propagation=False)["load"]["cyclomatic"] == 4


def test_java_nested_control_flow_lambda_and_cognitive_sequences() -> None:
    units = units_of("java/src/main/java/com/example/web/UserController.java")
    score = units["UserController.score"]
    assert score["decisions"] == {"boolean": 2, "case": 2, "if": 2, "loop": 1} and score["cyclomatic"] == 8
    assert score["increments"] == {"boolean_sequence": 2, "else": 1, "else_if": 1, "if": 2, "loop": 1, "switch": 1}
    assert score["cognitive"] == 8
    lambda_unit = units["UserController.score.<callback:forEach>"]
    assert lambda_unit["cyclomatic"] == 3 and lambda_unit["parent_function"].endswith("#UserController.score@23:5")
    assert units["UserController.fact"]["recursive"] and units["UserController.fact"]["cognitive"] == 2


def test_c_cpp_cases_goto_lambda_and_cpp_stream_shifts() -> None:
    codec = units_of("native/src/codec.c")
    assert codec["classify"]["decisions"]["case"] == 3  # default is not a decision
    assert codec["classify"]["cyclomatic"] == 8 and codec["classify"]["increments"]["jump"] == 1
    assert codec["decode_frame"]["cyclomatic"] == 5 and codec["decode_frame"]["cognitive"] == 4
    image, extractor, _ = extracted("native/src/image.cpp")
    assert image["media.Loader.count_large"]["cyclomatic"] == 4
    assert image["media.Loader.count_large.above"]["cyclomatic"] == 2
    assert image["media.Loader.log_value"]["custom_parsing"]["bitwise"] == 1  # `value | 0`, not stream insertion


def test_csharp_php_and_typescript_multiway_and_null_coalescing() -> None:
    account = units_of("dotnet/Controllers/AccountController.cs")
    get = account["Example.Controllers.AccountController.Get"]
    assert get["decisions"] == {"catch": 1, "guard": 1, "multiway_arm": 2, "null_coalescing": 1}
    assert get["cyclomatic"] == 6 and get["cognitive"] == 2
    assert account["Example.Controllers.AccountController.Get.Local"]["cyclomatic"] == 2
    php = units_of("php/src/Controller.php")
    assert php["Controller.import"]["cyclomatic"] == 8 and php["Controller.import"]["cognitive"] == 4
    assert php["Controller.import.double"]["anonymous"]
    ts = units_of("web/src/api.ts")
    assert ts["handle"]["cyclomatic"] == 3 and ts["handle.pick"]["cyclomatic"] == 4
    js = units_of("web/src/server.js")
    assert js["<callback:app.post>.<callback:exec>"]["cyclomatic"] == 3


def test_parse_errors_mark_units_and_files() -> None:
    source, _spec = parsed("web/src/broken.js")
    assert source.error_count >= 1
    units = units_of("web/src/broken.js")
    assert units["broken"]["parse_error"] and not units["intact"]["parse_error"]


# --- heuristics and suppressions ----------------------------------------------------------------

def test_boundary_privilege_wrapper_and_mutation_signals() -> None:
    _units, controller, _ = extracted("java/src/main/java/com/example/web/UserController.java")
    assert fn(by_rule(controller, "annotation.access-control-bypass")[0]["function_id"]) == "UserController.importUsers"
    assert {item["category"] for item in controller.signals if fn(item["function_id"]) == "UserController.importUsers"} >= {
        "ingress", "public_api", "privilege_shift", "sink", "sensitive_wrapper"}
    _units, account, _ = extracted("dotnet/Controllers/AccountController.cs")
    assert by_rule(account, "privilege.insecure_verification.certificate-callback")[0]["basis"] == "observed_syntax"
    assert fn(by_rule(account, "annotation.access-control-bypass")[0]["function_id"]) == \
        "Example.Controllers.AccountController.Get"
    _units, handler, _ = extracted("go/server/handler.go")
    assert by_rule(handler, "privilege.insecure_verification.InsecureSkipVerify")
    assert fn(by_rule(handler, "route.handler")[0]["function_id"]) == "Register.<callback:mux.HandleFunc>"
    assert by_rule(handler, "sink.command_exec.go")[0]["basis"] == "heuristic_inference"
    _units, util, _ = extracted("web/src/util.js")
    assert by_rule(util, "privilege.insecure_verification.rejectUnauthorized")
    _units, php, _ = extracted("php/src/Controller.php")
    assert by_rule(php, "privilege.insecure_verification.curl_setopt")
    assert by_rule(php, "ingress.superglobal") and by_rule(php, "sink.deserialization.php")
    image, cpp, _ = extracted("native/src/image.cpp")
    assert fn(by_rule(cpp, "wrapper.xml")[0]["function_id"]) == "media.Loader.parse_manifest"
    rust, lib, _ = extracted("rust/src/lib.rs")
    assert fn(by_rule(lib, "wrapper.ffi.extern-call")[0]["function_id"]) == "load"
    assert rust["load"]["wrapper_surfaces"] == ["ffi"]
    store, go_store, _ = extracted("go/store/store.go")
    assert store["DB.Save"]["state_mutation"] == {"db_write": 1, "fs_write": 1, "transaction": 1,
                                                  "transaction_end": 3, "total": 6}
    assert fn(by_rule(go_store, "state.multi-mutation")[0]["function_id"]) == "DB.Save"
    java_store, _extractor, _ = extracted("java/src/main/java/com/example/store/UserStore.java")
    assert java_store["UserStore.save"]["state_mutation"]["total"] == 4
    codec, c_extractor, _ = extracted("native/src/codec.c")
    assert codec["decode_frame"]["custom_parsing"] == {"bitwise": 7, "slicing": 6, "total": 13, "density": 1.083333}
    assert fn(by_rule(c_extractor, "parsing.dense-manual-decoding")[0]["function_id"]) == "decode_frame"
    wire, _extractor, _ = extracted("rust/src/wire.rs")
    assert wire["read_header"]["custom_parsing"]["manual_serialization"] == 1


def test_false_positive_boundary_patterns_are_not_signals() -> None:
    _units, controller, _ = extracted("java/src/main/java/com/example/web/UserController.java")
    assert not [item for item in controller.signals if fn(item["function_id"]) == "UserController.helpText"
                and item["category"] != "public_api"]  # "Runtime...exec(cmd)" is a string literal
    _units, server, _ = extracted("web/src/server.js")
    assert len(by_rule(server, "sink.command_exec.node")) == 1  # child_process exec, not /re/.exec
    assert not [item for item in server.signals if item["category"] == "sink" and item["detail"].get("callee") == "eval"]
    _units, store, _ = extracted("go/store/store.go")
    assert not [item for item in store.signals if item["rule_id"].startswith("sink.command_exec")]
    image, _extractor, _ = extracted("native/src/image.cpp")
    assert not [item for item in _extractor.signals if item["category"] == "custom_parsing"]
    _units, util, _ = extracted("web/src/util.js")
    assert not [item for item in util.signals if item["category"] == "sink"]


def test_suppression_directives_are_language_and_category_specific() -> None:
    expected = {
        "native/src/codec.c": {("clang-tidy", "security", "line", "decode_frame")},
        "native/src/image.cpp": {("c-pragma", "compiler", "block_start", None)},
        "go/server/handler.go": {("golangci-lint", "security", "line", "Register.<callback:mux.HandleFunc>")},
        "web/src/server.js": {("eslint", "security", "next_line", "<callback:app.post>")},
        "web/src/api.ts": {("typescript", "type", "next_line", "handle"), ("typescript", "type", "expression", "handle")},
        "java/src/main/java/com/example/web/UserController.java": {("javac", "compiler", "declaration",
                                                                     "UserController.score")},
        "dotnet/Controllers/AccountController.cs": {
            ("csharp-pragma", "security", "block_start", None),
            ("dotnet-analyzers", "security", "declaration", "Example.Controllers.AccountController.Run")},
        "php/src/Controller.php": {("phpcs", "lint", "line", "Controller.import"),
                                   ("php", "compiler", "expression", "Controller.import"),
                                   ("psalm", "security", "declaration", "Controller.find")},
        "rust/src/lib.rs": {("clippy", "lint", "declaration", "load"), ("rustc", "compiler", "expression", "load")},
    }
    for path, values in expected.items():
        _units, extractor, _ = extracted(path)
        assert {(item["tool"], item["category"], item["scope"], fn(item["function_id"]))
                for item in extractor.suppressions} == values, path


# --- dependency graph ----------------------------------------------------------------------------

def _graph(min_confidence: float = 0.8) -> dict[str, Any]:
    files = {}
    for path in GOLDEN["files"]:
        source, spec = parsed(path)
        records, declarations = extract(source, spec)
        files[path] = {"grammar": spec.grammar, "imports": records, "declarations": declarations}
    inventory = [path.relative_to(TARGET).as_posix() for path in TARGET.rglob("*") if path.is_file()]
    components = {path: path.split("/", 1)[0] for path in inventory}
    return GraphBuilder(files, inventory, lambda path: (TARGET / path).read_bytes(), min_confidence=min_confidence,
                        max_records=1000).build(components)


def test_imports_resolve_conservatively_and_keep_unresolved_and_dynamic_gaps() -> None:
    graph = _graph()
    edges = {(edge["from"], edge["to"], edge["method"]) for edge in graph["edges"]}
    assert ("native/src/codec.c", "native/src/codec.h", "include-relative") in edges
    assert ("native/src/image.cpp", "native/src/codec.h", "include-relative") in edges
    assert ("go/server/handler.go", "go/store/store.go", "go-module-package") in edges
    assert ("java/src/main/java/com/example/web/UserController.java",
            "java/src/main/java/com/example/store/UserStore.java", "java-package-declaration") in edges
    assert ("web/src/api.ts", "web/src/util.js", "module-relative") in edges
    assert ("web/src/server.js", "web/src/util.js", "module-relative") in edges
    assert ("rust/src/lib.rs", "rust/src/wire.rs", "rust-module-file") in edges
    assert ("rust/src/lib.rs", "rust/src/wire.rs", "rust-module-path") in edges
    assert ("php/src/Controller.php", "php/src/Support/Helpers.php", "php-namespace-declaration") in edges
    assert ("php/src/Controller.php", "php/src/Support/Helpers.php", "php-dir-relative") in edges

    def statuses(path: str) -> set[tuple[str | None, str]]:
        return {(item["specifier"], item["status"]) for item in graph["files"][path]["imports"]}

    assert ("missing/config.h", "unresolved") in statuses("native/src/codec.c")
    assert ("example.com/app/missing", "unresolved") in statuses("go/server/handler.go")
    assert ("./missing", "unresolved") in statuses("web/src/api.ts")
    assert (None, "dynamic") in statuses("web/src/server.js") and (None, "dynamic") in statuses("php/src/Controller.php")
    assert ("zod", "external") in statuses("web/src/api.ts") and ("std::io::Read", "external") in statuses("rust/src/lib.rs")
    assert graph["files"]["web/src/server.js"]["coupling_lower_bound"]
    store = graph["files"]["go/store/store.go"]
    server = graph["files"]["go/server/handler.go"]
    assert (store["module"], store["afferent_coupling"], store["efferent_coupling"], store["instability"]) == (
        "go-package:go/store", 1, 0, 0.0)
    assert (server["afferent_coupling"], server["efferent_coupling"], server["instability"]) == (0, 1, 1.0)
    isolated = graph["files"]["dotnet/Controllers/AccountController.cs"]
    assert isolated["instability"] is None  # Ca + Ce == 0: undefined, not zero
    assert graph["files"]["native/src/codec.h"]["afferent_coupling"] == 2


# --- scoring --------------------------------------------------------------------------------------

def test_percentiles_are_zero_anchored_mid_ranks() -> None:
    assert percentiles({"a": 0, "b": 0, "c": 2, "d": 4}) == {"a": 0.0, "b": 0.0, "c": 0.625, "d": 0.875}


def test_missing_features_are_excluded_with_coverage_and_ties_break_deterministically() -> None:
    def item(item_id: str, path: str, **features: Any) -> dict[str, Any]:
        return {"item_id": item_id, "path": path, "name": path, "language": "Go", "start_line": 1,
                "features": features}

    items = [item("a", "b.go", cyclomatic=5, semantic_path=None, sink=1),
             item("b", "a.go", cyclomatic=5, semantic_path=None, sink=1),
             item("c", "c.go", cyclomatic=1, semantic_path=2, sink=0)]
    ranked = rank(items, {"cyclomatic": 1, "semantic_path": 3, "sink": 1}, ("cyclomatic", "semantic_path", "sink"),
                  population="run")
    # a and b tie on score (missing semantic_path is excluded, not zeroed); the path breaks the tie.
    assert [value["item_id"] for value in ranked] == ["b", "a", "c"]
    assert ranked[0]["missing_features"] == ["semantic_path"] and ranked[0]["feature_coverage"] == 0.4
    assert ranked[0]["score"] == 0.666667
    assert ranked[2]["percentiles"] == {"cyclomatic": 0.166667, "semantic_path": 0.5, "sink": 0.0}
    assert ranked[2]["score"] == 0.333333 and ranked[2]["feature_coverage"] == 1.0
    assert selection_size(10, fraction=0.25, count=0, ceiling=100) == 3
    assert selection_size(10, fraction=0.25, count=7, ceiling=5) == 5


# --- job integration --------------------------------------------------------------------------------

class GoldenTreeSitter:
    """Replay the locked Tree-sitter container output for fixture files without Docker."""

    image_id = "sha256:" + "7" * 64

    def __init__(self, run_root: Path):
        self.run_root = run_root

    def resolve_image(self, _tool) -> str:
        return self.image_id

    def execute(self, request) -> ExecutionResult:
        payload = json.loads((request.scratch_root / "request.json").read_text(encoding="utf-8"))
        lock = json.loads((ROOT / "containers" / "tools" / "tree-sitter" / "assets.lock.json").read_text())
        records, scope_nodes = [], 0
        for item in payload["files"]:
            golden = GOLDEN["files"][item["path"]]
            assert golden["sha256"] == item["sha256"]
            if (TARGET / item["path"]).stat().st_size > payload["max_file_bytes"]:
                records.append({"kind": "file", "path": item["path"], "status": "TRUNCATED", "reason": "file_byte_limit",
                                "sha256": item["sha256"], "bytes": 0})
                continue
            limit = min(payload["max_nodes"], payload["max_scope_nodes"] - scope_nodes)
            nodes = golden["nodes"][:max(0, limit)]
            truncated = len(nodes) < len(golden["nodes"])
            scope_nodes += len(nodes)
            records.append({"kind": "file", "path": item["path"], "status": "PARTIAL" if truncated else "SUCCEEDED",
                            "sha256": item["sha256"], "bytes": (TARGET / item["path"]).stat().st_size,
                            "grammar": golden["grammar"], "root_has_error": golden["root_has_error"],
                            "node_count": len(nodes), "truncated": truncated, "nodes": nodes})
        output = {"schema": "appsec-review/tree-sitter-container-output/1",
                  "tool": {"id": "tool-tree-sitter", "version": lock["tool_version"],
                           "tree_sitter": lock["tree_sitter"]["version"], "language_pack": lock["language_pack"]["version"],
                           "normalizer_schema": lock["normalizer_schema"], "architecture": "x86_64"},
                  "scope_id": payload["scope_id"], "language": payload["language"], "records": records}
        (request.scratch_root / "output.json").write_text(json.dumps(output), encoding="utf-8")
        now = "2026-10-10T00:00:00+00:00"
        return ExecutionResult("appsec-review/container-execution/1", "tool-tree-sitter", "tool-tree-sitter:test",
                               self.image_id, self.image_id, "golden", (), {}, now, now, 0, False, False, False, False,
                               "", "", "")


def configured(tmp_path: Path, *, max_nodes: int | None = None, extra: str = ""):
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if max_nodes is not None:
        text = text.replace("max_nodes_per_file = 20000", f"max_nodes_per_file = {max_nodes}")
    text += extra
    (tmp_path / "appsec-review.toml").write_text(text, encoding="utf-8")
    shutil.copytree(ROOT / "containers", tmp_path / "containers")
    shutil.copytree(ROOT / "rules" / "semgrep", tmp_path / "rules" / "semgrep")
    base = load_config(tmp_path / "appsec-review.toml")
    return replace(base, runtime=replace(base.runtime, runs_dir=tmp_path / "runs", data_dir=tmp_path / "data",
                                         metadata_dir=tmp_path / "metadata"))


def target_copy(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    shutil.copytree(TARGET, target)
    return target


def run_graph(config, target: Path, *, run_id: str | None = None, prioritize: bool = True):
    jobs = [build_intake(), build_catalog(),
            build_tree_sitter(executor_factory=lambda unit: GoldenTreeSitter(unit.job.run_root))]
    if prioritize:
        jobs.append(build_job())
    return GraphRunner(config, jobs).run(target_root=target, source_fingerprint=source_fingerprint(target),
                                         run_id=run_id)


def published(outcome) -> dict[str, Any]:
    return outcome["jobs"]["job_review_prioritization"]["result"]["outputs"]["publish.publish_handoff"]


def test_job_ranks_indexes_and_names_every_missing_producer(tmp_path: Path) -> None:
    config = configured(tmp_path)
    target = target_copy(tmp_path)
    outcome = run_graph(config, target)
    output = published(outcome)
    assert output["terminal_status"] == "PARTIAL"
    run_root = config.runtime.runs_dir / outcome["run_id"]
    document = load_accepted_prioritization(run_root)
    assert document is not None and document["sources"] == {
        "tree_sitter": "PARTIAL", "semgrep": "UNAVAILABLE", "codeql": "UNAVAILABLE", "history": "UNAVAILABLE"}
    gaps = "\n".join(document["gaps"])
    for expected in ("semantic_paths_unavailable", "semgrep_review_signals_unavailable",
                     "history_hotspots_unavailable", "web/src/broken.js: parse_errors",
                     "native/src/codec.c: unresolved_or_dynamic_imports: missing/config.h",
                     "web/src/server.js: unresolved_or_dynamic_imports: None (non_literal_specifier)"):
        assert expected in gaps
    assert document["summary"]["by_language"]["Go"]["function_count"] == 5
    ranking = json.loads((run_root / document["artifacts"]["ranking"]["path"]).read_text())
    first = ranking["functions"][0]
    assert set(first["features"]) >= {"cyclomatic", "cognitive", "semantic_path", "history_hotspot", "sink"}
    assert first["features"]["semantic_path"] is None and "semantic_path" in first["missing_features"]
    assert first["feature_coverage"] < 1.0 and first["evidence"]
    top = {item["name"] for item in document["top_functions"]}
    assert "UserController.importUsers" in top or "Register.<callback:mux.HandleFunc>" in top

    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    found = core.find(kind="priority_item", path="java/src/main/java/com/example/web/UserController.java",
                      indexes=("priority",))["results"]
    assert found and found[0]["payload"]["authority"].startswith("review-first")
    assert not core.find(kind="priority_item", path="php/src/Support/Helpers.php", indexes=("priority",))["results"]
    function_hit = next(item for item in core.search(query="priority function", indexes=("priority",),
                                                     kinds=("priority_item",), limit=50)["results"]
                        if item["payload"]["scope"] == "function")
    assert function_hit["location"]["mapping_method"] == "tree-sitter-byte-and-point-exact"
    traced = core.trace(identity=function_hit["identity"], relations=("DERIVED_FROM",), depth=1)
    assert any(row["kind"] == "DERIVED_FROM" and row["target_id"].startswith("asr:review_signal:")
               for row in traced["results"])
    coverage = {(row["area"], row["status"]) for item in core.coverage(indexes=("priority",))["results"]
                for row in item["coverage"]}
    assert ("codeql-semantic-paths", "unavailable") in coverage
    assert ("history-hotspots", "unavailable") in coverage
    assert ("semgrep-review-signals", "unavailable") in coverage
    assert ("complexity", "partial") in coverage

    resumed = run_graph(config, target, run_id=outcome["run_id"])
    assert [item["action"] for item in resumed["decisions"]] == ["REUSE"] * 4


def test_truncated_ast_is_a_named_gap_not_a_clean_file(tmp_path: Path) -> None:
    config = configured(tmp_path, max_nodes=400)
    target = target_copy(tmp_path)
    outcome = run_graph(config, target)
    document = load_accepted_prioritization(config.runtime.runs_dir / outcome["run_id"])
    assert document is not None
    assert any(gap.startswith("java/src/main/java/com/example/web/UserController.java: ast_truncated")
               for gap in document["gaps"])
    names = {item["path"] for item in document["top_files"]}
    assert "java/src/main/java/com/example/web/UserController.java" not in names


def _publish_handoff(run_root: Path, job_id: str, outputs: dict[str, Any]) -> None:
    attempt = run_root / "data" / "jobs" / job_id / "attempts" / "fixture"
    attempt.mkdir(parents=True, exist_ok=True)
    handoff = attempt / "handoff.json"
    atomic_json(handoff, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED", "job_id": job_id,
                          "outputs": outputs})
    atomic_json(run_root / "data" / "jobs" / job_id / "latest.json",
                {"handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff)})


def _artifact(run_root: Path, path: Path, value: Any) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(path, value)
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path)}


def _shard(run_root: Path, snapshot: str, target: Path, name: str, producer: dict[str, str],
           entities: list[tuple[dict[str, Any], dict[str, Any] | None]]) -> dict[str, Any]:
    fingerprint = hashlib.sha256(json.dumps([name, producer, len(entities)]).encode()).hexdigest()
    path = run_root / "data" / "indices" / name / f"fixture-{producer.get('producer', producer['job'])}.sqlite"
    builder = IndexBuilder(path, name=name, fingerprint=fingerprint, target_snapshot=snapshot, shard_id=path.stem)
    for index, (payload, location) in enumerate(entities):
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"fixture": producer, "index": index})
        source = None
        if location is not None:
            data = (target / location["path"]).read_bytes()
            source = SourceLocation(snapshot, location["path"], hashlib.sha256(data).hexdigest(), 0, len(data),
                                    location["start_line"], location["start_line"], 1, 1, {}, "fixture", 1.0)
        builder.add_entity(EntityRecord(identity, str(index), "fixture", "fixture", payload, source))
    builder.build()
    identity = IndexIdentity(name, "appsec-review/retrieval-index/2", file_sha256(path), fingerprint,
                             path.relative_to(run_root).as_posix(), producer, (), path.stem)
    manifest = run_root / "data" / "indices" / "manifests" / f"fixture-{path.stem}.json"
    write_manifest(manifest, run_id=run_root.name, target_snapshot=snapshot, target_root=target, indexes=[identity])
    return {"path": manifest.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest)}


def _step(path: str, line: int, column: int, target: Path, code_flow: int, ordinal: int) -> dict[str, Any]:
    digest = hashlib.sha256((target / path).read_bytes()).hexdigest()
    return {"ordinal": ordinal, "code_flow": code_flow, "thread_flow": 0, "message": "step",
            "location": {"path": path, "file_sha256": digest, "start_line": line, "end_line": line,
                         "start_column": column, "end_column": column + 1}}


def test_semantic_paths_semgrep_patterns_and_history_hotspots_feed_the_score(tmp_path: Path) -> None:
    config = configured(tmp_path)
    target = target_copy(tmp_path)
    first = run_graph(config, target, prioritize=False)
    run_root = config.runtime.runs_dir / first["run_id"]
    snapshot = source_fingerprint(target)
    handler = "go/server/handler.go"
    # Two alternative code flows for the same source and sink: only the shortest is kept.
    long_flow = [_step(handler, 18, 32, target, 0, 1), _step(handler, 22, 3, target, 0, 2),
                 _step(handler, 22, 15, target, 0, 3)]
    short_flow = [_step(handler, 18, 32, target, 1, 4), _step(handler, 22, 15, target, 1, 5)]
    codeql_manifest = _shard(run_root, snapshot, target, "observations", {"job": "job_codeql_analysis"}, [
        ({"producer": "codeql", "rule_id": "go/command-injection", "query_identity": "q" * 64, "language": "go",
          "message": "Command built from user input", "flows": [*long_flow, *short_flow]}, {"path": handler,
                                                                                            "start_line": 22}),
        ({"producer": "codeql", "rule_id": "go/no-flow", "query_identity": "q" * 64, "language": "go",
          "message": "single location", "flows": []}, {"path": handler, "start_line": 13}),
    ])
    summary = _artifact(run_root, run_root / "fixture" / "codeql-summary.json", {
        "schema": "appsec-review/codeql-analysis-handoff/1",
        "scopes": [{"language": "go", "terminal_status": "SUCCEEDED"}, {"language": "java", "terminal_status": "FAILED"}]})
    _publish_handoff(run_root, "job_codeql_analysis", {"acceptance.publish_handoff": {
        "artifact": summary, "index_manifest": codeql_manifest}})
    java = "java/src/main/java/com/example/web/UserController.java"
    semgrep_manifest = _shard(run_root, snapshot, target, "observations",
                              {"job": "job_evidence_collection", "producer": "tool-semgrep"}, [
        ({"tool_id": "tool-semgrep", "evidence_id": "evidence-1",
          "native_rule_id": "rules.appsec-review.review-signal.privilege_shift.spring-permit-all",
          "message": "anonymous access", "location": {"path": java, "start_line": 19, "end_line": 19}},
         {"path": java, "start_line": 19}),
        ({"tool_id": "tool-semgrep", "evidence_id": "evidence-2", "native_rule_id": "appsec-review.python-dangerous-eval",
          "message": "baseline rule", "location": {"path": java, "start_line": 20, "end_line": 20}},
         {"path": java, "start_line": 20}),
    ])
    evidence = _artifact(run_root, run_root / "fixture" / "evidence.json", {
        "schema": "appsec-review/evidence-collection-handoff/1",
        "dispositions": [{"tool_id": "tool-semgrep", "terminal_status": "SUCCEEDED", "gaps": []}]})
    _publish_handoff(run_root, "job_evidence_collection", {"evidence_publication.publish_handoff": {
        "artifact": evidence, "index_manifest": semgrep_manifest}})
    signals = _artifact(run_root, run_root / "fixture" / "history-signals.json", {"files": {
        "go/store/store.go": {"attention": {"rank": 1, "score": 0.9}},
        "web/src/util.js": {"attention": {"rank": 2, "score": 0.4}}}})
    history = _artifact(run_root, run_root / "fixture" / "source-history.json", {
        "schema": "appsec-review/source-history-analysis/1", "decision": "SUCCEEDED", "binding": "exact",
        "ranking": {"signals": signals}, "gaps": []})
    _publish_handoff(run_root, "job_source_history_analysis", {"publish.publish_handoff": {"artifact": history}})

    outcome = run_graph(config, target, run_id=first["run_id"])
    document = load_accepted_prioritization(run_root)
    assert document is not None
    assert document["sources"]["codeql"] == "PARTIAL" and document["sources"]["semgrep"] == "SUCCEEDED"
    assert document["sources"]["history"] == "EXACT"
    assert any("CodeQL java scope FAILED" in gap for gap in document["gaps"])
    semantic = json.loads((run_root / document["artifacts"]["semantic"]["path"]).read_text())
    [path] = semantic["semantic_paths"]
    assert path["steps"] == 2 and path["basis"] == "verified_semantic_path"
    assert path["source_function"].endswith("Register.<callback:mux.HandleFunc>@16:25")
    [pattern] = semantic["semgrep_signals"]
    assert pattern["category"] == "privilege_shift" and pattern["producer"] == "semgrep"
    assert pattern["function_id"].endswith("#UserController.importUsers@15:5")
    ranking = json.loads((run_root / document["artifacts"]["ranking"]["path"]).read_text())
    functions = {item["name"]: item for item in ranking["functions"]}
    handler_item = functions["Register.<callback:mux.HandleFunc>"]
    assert handler_item["features"]["semantic_path"] == 1 and path["signal_id"] in handler_item["evidence"]
    assert functions["UserController.importUsers"]["features"]["semantic_path"] is None  # Java CodeQL failed
    assert functions["UserController.importUsers"]["features"]["privilege_shift"] == 2  # Tree-sitter + Semgrep
    files = {item["path"]: item for item in ranking["files"]}
    assert files["go/store/store.go"]["features"]["history_hotspot"] == 0.9
    assert files["native/src/codec.c"]["features"]["history_hotspot"] == 0.0  # exact binding, no in-window change
    # Only Go has CodeQL coverage: four Go functions have no path (0) and the handler has one.
    assert handler_item["percentiles"]["semantic_path"] == 0.9
    weights = ranking["weights"]
    expected = sum(weights[name] * value for name, value in handler_item["percentiles"].items()) / sum(
        weights[name] for name in handler_item["percentiles"])
    assert handler_item["score"] == round(expected, 6)
    go_functions = [item for item in ranking["functions"] if item["language"] == "Go"]
    assert min(go_functions, key=lambda item: item["rank"]) is handler_item
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    hits = core.search(query="semantic_path", indexes=("priority",), kinds=("review_signal",))["results"]
    assert hits and hits[0]["payload"]["basis"] == "verified_semantic_path"
