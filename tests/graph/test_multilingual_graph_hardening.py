"""Trusted range-method metadata, semantic range coverage and native producer isolation."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import pytest

from appsec_review.graph.bounds import range_bounds_destination
from appsec_review.graph.catalog import load_catalog
from appsec_review.graph.contract import Coverage, Family, Producer
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.graph.normalize import export_columns, normalize_scope
from appsec_review.jobs.job_code_graph_index.scopes import (
    ANALYZER_JOBS, SECONDARY_PRODUCERS, assign_analyzers, assign_secondary,
)
from appsec_review.retrieval import EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation
from appsec_review.retrieval.index import INDEX_SCHEMA

CATALOG = load_catalog()
SNAPSHOT = "target-sha256:" + "3" * 64
SOURCE = SourceFile.from_bytes(b"void f() { sink(value); }\n")
TARGET_PATH = "src/sample.code"
NO_RANGE_LANGUAGES = ("javascript", "python", "ruby", "rust")
METHODS = (
    ("cpp", "codeql-simple-range-analysis"),
    ("java", "codeql-range-analysis"),
    ("csharp", "codeql-constant-and-sign-analysis"),
    ("go", "codeql-constant-and-dominating-guards"),
    ("swift", "codeql-literal-only"),
    *((language, "not-performed") for language in NO_RANGE_LANGUAGES),
)


def _exports(language: str, *applicabilities: str) -> dict:
    canonical = CATALOG.language(language).language
    columns = export_columns(canonical)
    exports = {
        query: {"columns": list(names), "rows": [], "row_count": 0, "truncated": False, "bqrs_sha256": "b" * 64}
        for query, names in columns.items()
    }
    model = next(rule["match"]["model"] for rule in CATALOG.language(language).sinks
                 if set(rule["match"]) == {"model"})
    for index, applicability in enumerate(applicabilities):
        location = {
            "sink_path": "sample.code", "sink_start_line": 1, "sink_end_line": 1,
            "sink_start_column": 12, "sink_end_column": 22, "argument_index": index,
            "operand_path": "sample.code", "operand_start_line": 1, "operand_end_line": 1,
            "operand_start_column": 17, "operand_end_column": 21,
        }
        sink = {
            **location, "model": model, "api": "sink", "declared_in": "", "sink_display": "sink(value)",
            "function_name": "f", "function_path": "sample.code", "function_start_line": 1,
            "function_start_column": 6, "dominating_sanitizer_count": 0,
        }
        integral = applicability == "integral"
        value_range = {
            **location, "applicability": applicability, "type_display": "int" if integral else "object",
            "signed": "true" if integral else "", "bits": 32 if integral else 0,
            "lower": "unknown" if integral else "", "upper": "unknown" if integral else "",
        }
        for query, row in (("sink_sites", sink), ("ranges", value_range)):
            exports[query]["rows"].append([row[name] for name in columns[query]])
            exports[query]["row_count"] += 1
    return exports


def _normalize(language: str, exports: dict):
    return normalize_scope(
        exports, scope={"scope_id": "test-scope", "language": language, "build_unit_id": "unit", "root": "src"},
        target_snapshot=SNAPSHOT, sources={TARGET_PATH: SOURCE}, catalog=CATALOG,
        tool_version="2.27.0", export_pack_sha256="e" * 64,
    )


@pytest.mark.parametrize(("language", "method"), METHODS)
def test_range_method_describes_the_actual_language_producer(language: str, method: str) -> None:
    applicability = "not_applicable" if language in NO_RANGE_LANGUAGES else "integral"
    result = _normalize(language, _exports(language, applicability))
    [fact] = [fact for fact in result.facts if fact.family is Family.RANGE_FACT]
    assert fact.payload["result"]["analysis"] == method
    assert [row.family for row in result.coverage] == list(Family)
    assert len(result.shards()) == 7
    fact.to_entity()


@pytest.mark.parametrize(("language", "method"), [
    ("c/c++", "codeql-simple-range-analysis"), ("Kotlin", "codeql-range-analysis"),
    ("java-kotlin", "codeql-range-analysis"), ("C#", "codeql-constant-and-sign-analysis"),
    ("TypeScript", "not-performed"), ("javascript-typescript", "not-performed"),
])
def test_range_method_uses_the_canonical_language(language: str, method: str) -> None:
    result = _normalize(language, _exports(language, "not_applicable"))
    [fact] = [fact for fact in result.facts if fact.family is Family.RANGE_FACT]
    assert fact.payload["result"]["analysis"] == method


@pytest.mark.parametrize("language", [language for language, _ in METHODS])
def test_placeholder_only_ranges_have_limited_family_coverage(language: str) -> None:
    result = _normalize(language, _exports(language, "not_applicable", "not_applicable"))
    coverage = result.coverage_for(Family.RANGE_FACT)
    assert coverage.status is Coverage.PARTIAL
    assert coverage.facts == 2
    assert any(gap.startswith("not_applicable:") for gap in coverage.gaps)
    for fact in result.facts:
        if fact.family is Family.RANGE_FACT:
            assert fact.payload["result"]["interval"] is None
            assert fact.payload["admissibility"]["direct_eligible"] is False
            assert "range_not_applicable" in fact.payload["admissibility"]["ineligibility_reasons"]
            assert not range_bounds_destination(fact.payload["result"], 16).bounds


@pytest.mark.parametrize("language", NO_RANGE_LANGUAGES)
def test_empty_exports_do_not_claim_semantic_range_analysis_in_unimplemented_languages(language: str) -> None:
    result = _normalize(language, _exports(language))
    coverage = result.coverage_for(Family.RANGE_FACT)
    assert coverage.status is Coverage.PARTIAL
    assert coverage.facts == 0
    assert any(gap.startswith("range_analysis_not_performed:") for gap in coverage.gaps)
    assert all(row.status is Coverage.COMPLETE for row in result.coverage if row.family is not Family.RANGE_FACT)


@pytest.mark.parametrize("language", NO_RANGE_LANGUAGES)
def test_missing_range_exports_remain_unavailable(language: str) -> None:
    exports = _exports(language)
    del exports["ranges"]
    result = _normalize(language, exports)
    coverage = result.coverage_for(Family.RANGE_FACT)
    assert coverage.status is Coverage.UNAVAILABLE
    assert any(gap.startswith("export_unavailable:") for gap in coverage.gaps)


@pytest.mark.parametrize("language", ["cpp", "java", "csharp", "go", "swift"])
def test_integral_unknown_bounds_and_mixed_operand_coverage_keep_existing_semantics(language: str) -> None:
    result = _normalize(language, _exports(language, "integral", "not_applicable"))
    assert result.coverage_for(Family.RANGE_FACT).status is Coverage.COMPLETE
    [fact] = [fact for fact in result.facts
              if fact.family is Family.RANGE_FACT and fact.payload["result"]["applicability"] == "integral"]
    assert fact.payload["result"]["interval"] == {"lower": "unknown", "upper": "unknown"}
    assert fact.payload["admissibility"]["direct_eligible"] is True
    assert not range_bounds_destination(fact.payload["result"], 16).bounds


def _scope(scope_id: str, language: str, *, root: str = ".", files: tuple[str, ...] = ("src/native.c",),
           status: str = "SUCCEEDED") -> dict:
    return {"scope_id": scope_id, "language": language, "root": root, "export_status": status,
            "files": [{"path": path, "sha256": "a" * 64} for path in files]}


def _secondary_shard(run_root: Path, producer: Producer) -> dict:
    path = run_root / "secondary.sqlite"
    identity = LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"name": "native"})
    location = SourceLocation(SNAPSHOT, "src/native.c", "a" * 64, 0, 1, 1, 1, 1, 2, {}, "exact-path", 1.0)
    builder = IndexBuilder(path, name="analysis", fingerprint="f" * 64, target_snapshot=SNAPSHOT)
    builder.add_entity(EntityRecord(identity, "native", "native", "native", {}, location))
    job, branch, shard_id = {
        Producer.CLANGD: ("job_cpp_symbol_index", "", "clangd-native"),
        Producer.LLVM_IR: ("job_cpp_compiled_analysis", "ir", "ir-native"),
        Producer.CLANG_AST: ("job_cpp_compiled_analysis", "ast", "ast-native"),
        Producer.SVF: ("job_svf_alias_analysis", "", "svf-native"),
    }[producer]
    return asdict(IndexIdentity(
        "analysis", INDEX_SCHEMA, builder.build(), "f" * 64, path.relative_to(run_root).as_posix(),
        {"job": job, "branch": branch}, (), shard_id,
    ))


@pytest.mark.parametrize("producer", SECONDARY_PRODUCERS)
@pytest.mark.parametrize("language", ["cpp", "c", "c++", "c/c++", " C/C++ "])
def test_native_secondary_shards_ignore_incompatible_scopes_before_overlap_assignment(
    tmp_path: Path, producer: Producer, language: str,
) -> None:
    shard = _secondary_shard(tmp_path, producer)
    scopes = [
        _scope("a-java", "java"), _scope("b-python", "python"), _scope("c-go", "go"),
        _scope("native", language), _scope("unrelated", "cpp", files=("elsewhere.c",)),
        _scope("failed", "cpp", status="FAILED"),
    ]
    assigned = assign_secondary(tmp_path, [shard], scopes)
    assert assigned["native"][producer.value] == [shard]
    assert "failed" not in assigned
    assert all(not values for scope_id, by_producer in assigned.items() if scope_id != "native"
               for values in by_producer.values())


@pytest.mark.parametrize("language", ["java", "kotlin", "python", "csharp", "go", "rust", "", "unknown"])
def test_non_native_only_scopes_cannot_acquire_native_secondary_shards(tmp_path: Path, language: str) -> None:
    shard = _secondary_shard(tmp_path, Producer.CLANGD)
    assigned = assign_secondary(tmp_path, [shard], [_scope("scope", language)])
    assert assigned == {"scope": {producer.value: [] for producer in SECONDARY_PRODUCERS}}


def test_native_secondary_assignment_keeps_single_owner_and_scope_id_tiebreak(tmp_path: Path) -> None:
    shard = _secondary_shard(tmp_path, Producer.CLANGD)
    assigned = assign_secondary(tmp_path, [shard], [_scope("z-native", "cpp"), _scope("a-native", "c")])
    assert assigned["a-native"]["clangd"] == [shard]
    assert assigned["z-native"]["clangd"] == []


@pytest.mark.parametrize(("job", "producer"), ANALYZER_JOBS.items())
@pytest.mark.parametrize("language", ["cpp", "c", "c++", "c/c++", " C/C++ "])
def test_native_analyzers_attach_only_to_compatible_scopes_at_the_same_root(
    job: str, producer: Producer, language: str,
) -> None:
    shard = {"name": "observations", "shard_id": "native", "producer": {"job": job, "project_root": "."}}
    scopes = [
        _scope("native", language), _scope("native-alias", "c/c++", root=""),
        _scope("other-root", "cpp", root="other"),
        *(_scope(name or "missing-language", name) for name in
          ("java", "kotlin", "python", "csharp", "go", "javascript", "rust", "swift", "", "unknown")),
    ]
    assigned = assign_analyzers([shard], scopes)
    assert assigned["native"][producer.value] == assigned["native-alias"][producer.value] == [shard]
    assert all(not values for scope_id, by_producer in assigned.items()
               if scope_id not in {"native", "native-alias"} for values in by_producer.values())
