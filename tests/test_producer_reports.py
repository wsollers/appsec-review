"""Run reports for detector scoring (acceptance.producer_reports; scoring design decisions 4-5)."""

from __future__ import annotations

import hashlib
import inspect
import json

import pytest

from appsec_review.acceptance import answer_key, producer_reports, system
from appsec_review.acceptance.producer_reports import (
    GAP_NO_OBSERVATION_INDEX, GAP_REVIEW_UNAVAILABLE, RULE_CWE_SCHEMA, load_rule_cwe, producer_name,
    reports_from_run)
from appsec_review.acceptance.scoring_model import RULE_CWE_REFERENCE, Report, normalize_cwe
from appsec_review.jobs.job_clang_static_analysis import job as clang_job
from appsec_review.jobs.job_cpp_compiled_analysis import job as cpp_job
from appsec_review.jobs.job_evidence_collection.adapters import ADAPTERS
from appsec_review.provenance import common_metadata
from appsec_review.retrieval.index import IndexBuilder
from appsec_review.retrieval.model import EntityKind, EntityRecord, LogicalIdentity, SourceLocation

SNAPSHOT = "snapshot-castle-b"

# Payload shapes follow the real producers: evidence collection (job_evidence_collection/job.py,
# ``{"tool_id": producer, **record}`` with ``common.scanner``), clang static analysis
# (job_clang_static_analysis/job.py, ``scanner`` = engine), Infer (job_cpp_compiled_analysis/job.py,
# ``tool = "infer"``) and CodeQL (job_codeql_analysis/sarif.py, ``producer = "codeql"`` with the SARIF rule).
_CPPCHECK_RECORD = {"tool_id": "tool-cppcheck", "native_rule_id": "nullPointer", "category": "source_sast",
                    "severity": "error"}
CPPCHECK = {**_CPPCHECK_RECORD, "common": common_metadata(
    _CPPCHECK_RECORD, evidence_refs=[], payload_schema="appsec-review/static-tool-evidence/2")}
CLANG = {"tool_id": "tool-clang-static-analysis", "scanner": "clang-static-analyzer",
         "native_rule_id": "core.NullDereference"}
INFER = {"tool": "infer", "rule_id": "USE_AFTER_FREE"}
CODEQL = {"producer": "codeql", "rule_id": "cpp/overflow-buffer",
          "rule": {"properties": {"tags": ["security", "external/cwe/cwe-787", "external/cwe/cwe-0120"]}}}
OPENGREP = {"tool_id": "tool-opengrep", "native_rule_id": "appsec-review.sei-cert.str31-c",
            "rule_mapping": {"cwe": ["CWE-676"]}}
TIDY_UNMAPPED = {"scanner": "clang-tidy", "native_rule_id": "performance-unnecessary-copy-initialization"}


def _entity(native: str, payload: dict, path: str | None = "src/a.c", start: int = 10,
            end: int | None = None) -> EntityRecord:
    identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"native": native})
    location = None if path is None else SourceLocation(
        SNAPSHOT, path, "0" * 64, 0, 1, start, end or start, 1, 1, {}, "producer-line-location", 1.0)
    return EntityRecord(identity, native, "observation", "", payload, location)


def _shard(run, entities, shard: str = "shard", subdirectory: str = ""):
    fingerprint = hashlib.sha256(shard.encode()).hexdigest()
    path = run / "data" / "indices" / "observations" / subdirectory / f"{fingerprint}-{fingerprint[:16]}.sqlite"
    builder = IndexBuilder(path, name="observations", fingerprint=fingerprint, target_snapshot=SNAPSHOT,
                           shard_id=shard)
    for entity in entities:
        builder.add_entity(entity)
    builder.add_coverage("test", "complete")
    builder.build()
    return path


def _by_producer(reports):
    return {report.producer: report for report in reports}


def test_producers_rules_cwes_and_evidence_from_a_real_observation_index(tmp_path):
    run = tmp_path / "run-1"
    index = _shard(run, [
        _entity("cppcheck", CPPCHECK, "<target>/src/a.c", 12),
        _entity("clang", CLANG, "src/b.c", 7, 9),
        _entity("infer", INFER, "src/c.c", 3),
        _entity("codeql", CODEQL, "src/d.c", 20, 21),
        _entity("opengrep", OPENGREP, "src/e.c", 4),
        _entity("unlocated", CPPCHECK, None),
    ])

    reports, gaps = reports_from_run(run)

    assert gaps == []
    found = _by_producer(reports)
    assert set(found) == {"cppcheck", "clang-static-analyzer", "infer", "codeql", "opengrep"}
    # common.scanner (evidence collection) without the image prefix; target prefix stripped; fallback CWE.
    assert found["cppcheck"] == Report("cppcheck", "src/a.c", 12, 12, "nullPointer", frozenset({"CWE-476"}),
                                       found["cppcheck"].evidence)
    # ``scanner`` wins over ``tool_id``; native rule id; fallback CWE from rule-cwe.json.
    assert (found["clang-static-analyzer"].path, found["clang-static-analyzer"].start_line,
            found["clang-static-analyzer"].end_line, found["clang-static-analyzer"].rule,
            found["clang-static-analyzer"].cwes) == ("src/b.c", 7, 9, "core.NullDereference", {"CWE-476"})
    assert (found["infer"].rule, found["infer"].cwes) == ("USE_AFTER_FREE", {"CWE-416"})
    # Payload CWEs (SARIF tags, rule_mapping) are normalized and used as given.
    assert found["codeql"].cwes == {"CWE-787", "CWE-120"}
    assert found["opengrep"].cwes == {"CWE-676"}
    relative = index.relative_to(run).as_posix()
    expected = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"native": "cppcheck"}).value
    assert found["cppcheck"].evidence == f"{relative}#{expected}"


def test_payload_cwes_take_precedence_over_the_rule_table(tmp_path):
    payload = {**CLANG, "rule_mapping": {"cwe": "CWE-690"}}
    run = tmp_path / "run-1"
    _shard(run, [_entity("clang", payload)])

    reports, _ = reports_from_run(run)

    assert reports[0].cwes == {"CWE-690"}


def test_tool_fallback_and_missing_producer_gap(tmp_path):
    run = tmp_path / "run-1"
    _shard(run, [_entity("infer", INFER), _entity("anonymous-1", {"rule_id": "x"}),
                 _entity("anonymous-2", {"scanner": "", "tool": "  ", "native_rule_id": "y"})])

    reports, gaps = reports_from_run(run)

    assert [report.producer for report in reports] == ["infer"]
    assert gaps == ["observations_without_producer:2"]


def test_unmapped_rule_has_no_cwe_and_names_the_producer_gap(tmp_path):
    run = tmp_path / "run-1"
    _shard(run, [_entity("tidy", TIDY_UNMAPPED), _entity("cppcheck", CPPCHECK),
                 _entity("cppcheck-style", {**CPPCHECK, "native_rule_id": "unusedFunction"})])

    reports, gaps = reports_from_run(run)

    tidy = [report for report in reports if report.producer == "clang-tidy"]
    assert [(report.rule, report.cwes) for report in tidy] == [
        ("performance-unnecessary-copy-initialization", frozenset())]
    assert gaps == ["producer_without_cwe:clang-tidy"]  # cppcheck has one report with a CWE


def test_missing_index_is_a_gap_and_unreadable_index_names_the_file(tmp_path):
    assert reports_from_run(tmp_path / "run-1") == ([], [GAP_NO_OBSERVATION_INDEX])

    bad = tmp_path / "run-2" / "data" / "indices" / "observations" / "bad.sqlite"
    bad.parent.mkdir(parents=True)
    bad.write_bytes(b"not a database" * 100)
    with pytest.raises(ValueError, match="bad.sqlite"):
        reports_from_run(tmp_path / "run-2")


def test_order_is_deterministic_across_shards_and_duplicates_are_kept(tmp_path):
    run = tmp_path / "run-1"
    _shard(run, [_entity("b", {**CPPCHECK, "native_rule_id": "zerodiv"}, "src/z.c", 2),
                 _entity("a", CODEQL, "src/a.c", 9)], shard="one", subdirectory="cpp-shard")
    _shard(run, [_entity("c", CPPCHECK, "src/a.c", 5), _entity("d", CPPCHECK, "src/a.c", 5)], shard="two")

    reports, _ = reports_from_run(run)

    keys = [(r.producer, r.path, r.start_line, r.rule, r.evidence) for r in reports]
    assert keys == sorted(keys)
    assert [(r.producer, r.path, r.start_line) for r in reports] == [
        ("codeql", "src/a.c", 9), ("cppcheck", "src/a.c", 5), ("cppcheck", "src/a.c", 5), ("cppcheck", "src/z.c", 2)]
    assert reports[1].identity == reports[2].identity and reports[1].evidence != reports[2].evidence
    assert reports_from_run(run) == (reports, [])


def test_include_review_adds_accepted_final_findings_with_claim_cwes(tmp_path, monkeypatch):
    run = tmp_path / "run-1"
    _shard(run, [_entity("cppcheck", CPPCHECK)])
    findings = [
        {"claim_id": "claim-1", "evidence_id": "rel:1", "record": {"path": "<target>/src/b.c", "start_line": 5}},
        {"claim_id": "claim-2", "evidence_id": "rel:2",
         "record": {"path": "src/c.c", "start_line": 8, "end_line": 11}},
    ]
    projection = {"claims": [{"claim_id": "claim-1", "weakness_cwe": "CWE-787"},
                             {"claim_id": "claim-2", "weakness_cwe": None}]}
    monkeypatch.setattr(answer_key, "current_report_findings", lambda root: findings)
    monkeypatch.setattr(system, "accepted_final_report", lambda root: ({}, None, projection))

    reports, gaps = reports_from_run(run, include_review=True)

    review = [report for report in reports if report.producer == producer_reports.REVIEW_PRODUCER]
    assert review == [Report("review", "src/b.c", 5, 5, "", frozenset({"CWE-787"}), "rel:1"),
                      Report("review", "src/c.c", 8, 11, "", frozenset(), "rel:2")]
    assert gaps == []


def test_include_review_with_an_empty_report_adds_nothing(tmp_path, monkeypatch):
    run = tmp_path / "run-1"
    _shard(run, [_entity("cppcheck", CPPCHECK)])
    monkeypatch.setattr(answer_key, "current_report_findings", lambda root: [])

    assert reports_from_run(run, include_review=True) == reports_from_run(run)


def test_include_review_without_a_final_report_is_a_gap(tmp_path):
    run = tmp_path / "run-1"
    _shard(run, [_entity("cppcheck", CPPCHECK)])

    reports, gaps = reports_from_run(run, include_review=True)

    assert [report.producer for report in reports] == ["cppcheck"]
    assert gaps == [GAP_REVIEW_UNAVAILABLE]


def test_rule_cwe_reference_is_valid_and_keyed_by_emitted_producer_names():
    document = json.loads(RULE_CWE_REFERENCE.read_text(encoding="utf-8"))
    assert document["schema"] == RULE_CWE_SCHEMA and document["source"].strip()
    table = load_rule_cwe()
    assert table and all(rules for rules in table.values())
    for rules in table.values():
        for cwes in rules.values():
            assert cwes and all(normalize_cwe(cwe) == cwe for cwe in cwes)
    assert '"tool": "infer"' in inspect.getsource(cpp_job)
    emitted = ({producer_name({"tool_id": tool_id}) for tool_id in ADAPTERS}
               | {producer_name({"tool_id": clang_job.TOOL_ID, "scanner": engine}) for engine in clang_job.ENGINES}
               | {producer_name(INFER), producer_name(CODEQL)})
    assert set(table) <= emitted
    assert {"cppcheck", "clang-static-analyzer", "clang-tidy", "infer"} <= set(table)


@pytest.mark.parametrize("change, message", [
    ({"schema": "other"}, "schema"),
    ({"producers": {"Cppcheck": {}}}, "lowercase"),
    ({"producers": {"cppcheck": {"nullPointer": {"cwes": ["476"], "rationale": "x"}}}}, "normalized"),
    ({"producers": {"cppcheck": {"nullPointer": {"cwes": [], "rationale": "x"}}}}, "normalized"),
    ({"producers": {"cppcheck": {"nullPointer": {"cwes": ["CWE-476"], "rationale": ""}}}}, "rationale"),
])
def test_rule_cwe_loader_rejects_invalid_tables(tmp_path, change, message):
    path = tmp_path / "rule-cwe.json"
    path.write_text(json.dumps({"schema": RULE_CWE_SCHEMA, "source": "test", "producers": {}, **change}))

    with pytest.raises(ValueError, match=message):
        load_rule_cwe(path)


def test_score_run_scores_a_real_observation_index_against_a_key(tmp_path):
    from appsec_review.acceptance.scoring import score_run

    run = tmp_path / "run-1"
    _shard(run, [_entity("cppcheck", CPPCHECK, "<target>/src/a.c", 12),
                 _entity("clang", CLANG, "src/b.c", 7, 9),
                 _entity("codeql", CODEQL, "other/d.c", 20, 21)])
    key = tmp_path / "expectations.toml"
    key.write_text('[corpus]\nname = "mini"\nscored_paths = ["src"]\n\n'
                   '[[defect]]\nid = "d1"\npath = "src/a.c"\nline = 12\ncwe = "CWE-476"\npair = "c1"\n\n'
                   '[[control]]\nid = "c1"\npath = "src/b.c"\nline = 8\ncwe = "CWE-476"\npair = "d1"\n'
                   'scope_start = 5\nscope_end = 10\n', encoding="utf-8")

    result = score_run(run, key).as_dict()

    by_producer = {row["producer"]: row for row in result["producers"]}
    assert by_producer["cppcheck"]["tp"] == 1 and by_producer["cppcheck"]["castle_score"] == 5 + 1 + 2  # B(CWE-476 rank 21) = 1; clean control
    assert by_producer["clang-static-analyzer"]["fp"] == 1
    assert by_producer["clang-static-analyzer"]["castle_score"] == 0 - 1  # silent on d1, one report on c1
    assert "codeql" not in by_producer or by_producer["codeql"]["tp"] == 0