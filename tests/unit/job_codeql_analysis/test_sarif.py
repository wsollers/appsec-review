"""Focused unit tests for SARIF location mapping and normalization in sarif.py."""

from __future__ import annotations

import pytest

from appsec_review.jobs.job_codeql_analysis.sarif import (
    _message,
    _region,
    _rules,
    map_location,
    normalize_sarif,
)


FILES = (
    {"path": "services/api/handler.py", "sha256": "a" * 64},
    {"path": "services/worker/task.py", "sha256": "b" * 64},
    {"path": "pkg/dup.py", "sha256": "c" * 64},
    {"path": "other/dup.py", "sha256": "d" * 64},
)


def test_region_and_map_location_cover_missing_rooted_suffix_ambiguous_and_empty_uris() -> None:
    assert _region({"region": {"startLine": "bad"}}) == (1, 1, 1, 1)
    assert _region({"region": {"startLine": 4, "endLine": 2, "startColumn": 5, "endColumn": 1}}) == (4, 4, 5, 5)

    missing = map_location({"region": {"startLine": 3}}, files=FILES, root=".")
    assert missing.path is None and missing.confidence == 0.0 and missing.candidates == ()

    non_str_uri = map_location({"artifactLocation": {"uri": 123}}, files=FILES, root=".")
    assert non_str_uri.path is None and non_str_uri.confidence == 0.0

    rooted = map_location(
        {"artifactLocation": {"uri": "/scratch/workspace/handler.py"}},
        files=FILES,
        root="services/api",
    )
    assert rooted.path == "services/api/handler.py"
    assert rooted.file_sha256 == "a" * 64
    assert rooted.confidence == 1.0
    assert rooted.ambiguous is False

    empty_after_strip = map_location(
        {"artifactLocation": {"uri": "/workspace/./"}},
        files=FILES,
        root=".",
    )
    assert empty_after_strip.path is None
    assert empty_after_strip.confidence == 0.0
    assert empty_after_strip.candidates == ()

    suffix_unique = map_location(
        {"artifactLocation": {"uri": "file:///workspace/worker/task.py"}},
        files=FILES,
        root=".",
    )
    assert suffix_unique.path == "services/worker/task.py"
    assert suffix_unique.confidence == 0.8

    ambiguous = map_location(
        {"artifactLocation": {"uri": "dup.py"}},
        files=FILES,
        root=".",
    )
    assert ambiguous.path is None
    assert ambiguous.ambiguous is True
    assert ambiguous.confidence == 0.5
    assert ambiguous.candidates == ("other/dup.py", "pkg/dup.py")


def test_rules_and_message_handle_malformed_inputs() -> None:
    run = {
        "tool": {
            "driver": {"rules": ["not-a-dict", {"id": 99}, {"id": "py/sql", "helpUri": "https://example.test"}]},
            "extensions": ["bad-ext", {"rules": [{"id": "py/xss"}]}],
        }
    }
    extracted = _rules(run)
    assert set(extracted) == {"py/sql", "py/xss"}
    assert _message({"markdown": "**md**"}, "fallback") == "**md**"
    assert _message("raw-string-not-mapping", "fallback-msg") == "fallback-msg"


def test_normalize_sarif_rejects_bad_contract_and_records_malformed_run_and_flow_gaps() -> None:
    with pytest.raises(ValueError, match="SARIF contract is unsupported"):
        normalize_sarif({"version": "2.0.0", "runs": []}, files=FILES, root=".", query_identity="q1", result_limit=10)

    empty_obs, empty_gaps = normalize_sarif(
        {"version": "2.1.0", "runs": [{"results": []}]},
        files=FILES,
        root=".",
        query_identity="q1",
        result_limit=10,
    )
    assert empty_obs == []
    assert empty_gaps == ["CodeQL query suite completed with zero observations; this is not a clean classification"]

    doc = {
        "version": "2.1.0",
        "runs": [
            "not-an-object",
            {"results": "not-a-list"},
            {
                "tool": {"driver": {"rules": [{"id": "py/taint", "helpUri": "https://example.test/rule"}]}},
                "results": [
                    "not-a-result",
                    {
                        "ruleId": "py/taint",
                        "message": "not-a-mapping-message",
                        "locations": [
                            "not-a-location-dict",
                            {"physicalLocation": "not-a-dict"},
                            {"physicalLocation": {"artifactLocation": {"uri": "unknown/missing.py"}}},
                        ],
                        "properties": "not-a-properties-mapping",
                        "codeFlows": [
                            "not-a-code-flow",
                            {
                                "threadFlows": [
                                    "not-a-thread-flow",
                                    {
                                        "locations": [
                                            {"location": {}},
                                            {
                                                "location": {
                                                    "message": "non-mapping",
                                                    "physicalLocation": {"artifactLocation": {"uri": "nowhere.py"}},
                                                }
                                            },
                                            {
                                                "location": {
                                                    "message": {"text": "sink step"},
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": "services/api/handler.py"},
                                                        "region": {"startLine": 10, "startColumn": 2},
                                                    },
                                                }
                                            },
                                        ]
                                    },
                                ]
                            },
                        ],
                    },
                    {
                        "ruleId": "py/taint",
                        "message": {"text": "second result hits limit"},
                        "locations": [],
                    },
                ],
            },
        ],
    }

    observations, gaps = normalize_sarif(
        doc, files=FILES, root=".", query_identity="qid-1", result_limit=1
    )
    assert len(observations) == 1
    obs = observations[0]
    assert obs["message"] == "py/taint"
    assert obs["payload"]["contradicting_relations"] == []
    assert len(obs["flows"]) == 2
    assert obs["flows"][0]["message"] == "flow step"
    assert obs["flows"][1]["location"]["path"] == "services/api/handler.py"
    assert "SARIF run 0 was not an object" in gaps
    assert "SARIF run 1 results were not a list" in gaps
    assert "SARIF result 2:0 was not an object" in gaps
    assert "CodeQL flow step for 2:1 had no physical location" in gaps
    assert "CodeQL flow step for 2:1 was unmapped or ambiguous" in gaps
    assert "CodeQL result 2:1 had no uniquely mapped source location" in gaps
    assert "CodeQL normalized result count reached its configured bound" in gaps
