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


def _normalize_location(physical, files, root):
    return normalize_sarif(
        {"version": "2.1.0", "runs": [{"results": [{
            "ruleId": "fixture/location", "locations": [{"physicalLocation": physical}],
            "codeFlows": [{"threadFlows": [{"locations": [{"location": {"physicalLocation": physical}}]}]}],
        }]}]},
        files=files, root=root, query_identity="query", result_limit=10,
    )


@pytest.mark.parametrize("base", [None, "%SRCROOT%", "%TARGET%"])
def test_planned_nested_root_requires_uri_base_to_disambiguate_primary_and_flow(base):
    from appsec_review.jobs.job_codeql_analysis.planning import build_codeql_plan
    from .test_planning import IMAGE, _file, _receipt

    plan = build_codeql_plan(
        source_fingerprint="snapshot", files=(
            _file("a.cpp", "c" * 64), _file("project/a.cpp", "a" * 64),
            _file("project/project/a.cpp", "b" * 64)),
        receipts=(_receipt("native", "native", root="project"),),
        supported_extractors=("cpp",), source_image_id=IMAGE)
    scope, = plan.scopes
    assert {item["path"] for item in scope.files} == {"project/a.cpp", "project/project/a.cpp"}
    artifact = {"uri": "project/a.cpp", **({"uriBaseId": base} if base else {})}
    physical = {"artifactLocation": artifact, "region": {"startLine": 2}}
    bases = {"%SRCROOT%": {"uri": "file:///scratch/workspace/project/"},
             "%TARGET%": {"uri": "file:///scratch/workspace/"}}
    document = {"version": "2.1.0", "runs": [{
        "originalUriBaseIds": bases,
        "results": [{"locations": [{"physicalLocation": physical}],
                     "codeFlows": [{"threadFlows": [{"locations": [
                         {"location": {"physicalLocation": physical}}]}]}]}],
    }]}
    observations, gaps = normalize_sarif(
        document, files=scope.files, root=scope.root, query_identity="fixture", result_limit=10)
    locations = (observations[0]["location"], observations[0]["flows"][0]["location"])
    if base is None:
        assert gaps
        assert all(item["path"] is None and item["ambiguous"] for item in locations)
        assert locations[0]["candidates"] == ("project/a.cpp", "project/project/a.cpp")
    else:
        expected = "project/project/a.cpp" if base == "%SRCROOT%" else "project/a.cpp"
        digest = "b" * 64 if base == "%SRCROOT%" else "a" * 64
        assert not gaps
        assert all(item["path"] == expected and item["file_sha256"] == digest for item in locations)


@pytest.mark.parametrize(("bases", "expected"), [
    ({"%SRCROOT%": {"uri": "file:///scratch/workspace/project/"},
      "CHILD": {"uri": ".hidden/", "uriBaseId": "%SRCROOT%"}}, "project/.hidden/a.cpp"),
    ({"%SRCROOT%": {"uri": "file:///scratch/workspace/project/"},
      "CHILD": {"uri": ".hidden\\", "uriBaseId": "%SRCROOT%"}}, "project/.hidden/a.cpp"),
    ({"CHILD": {"uri": "file:///scratch/workspace/project/.hidden%2f"}}, "project/.hidden/a.cpp"),
    ({"CHILD": {"uri": "file:///scratch/workspace/project/%252e/"}}, "project/%2e/a.cpp"),
    ({"CHILD": "not-a-base-record"}, None),
    ({}, None),
    ({"CHILD": {"uri": ".hidden/", "uriBaseId": "CHILD"}}, None),
    ({"CHILD": {"uri": ".hidden/", "uriBaseId": "OTHER"},
      "OTHER": {"uri": "./", "uriBaseId": "CHILD"}}, None),
    ({"CHILD": {"uri": "file://foreign/scratch/workspace/project/.hidden/"}}, None),
    ({"CHILD": {"uri": "file:///unknown/project/.hidden/"}}, None),
    ({"CHILD": {"uri": "file:///scratch/workspace/project/../.hidden/"}}, None),
    ({"CHILD": {"uri": "file:///scratch/workspace/project/"},
      "unused": {"uriBaseId": "unused"}}, "project/a.cpp"),
], ids=["chain-hidden", "backslash-base", "encoded-separator-base", "decode-once", "malformed",
        "missing", "self-cycle", "cycle", "foreign", "unknown-root", "traversal",
        "unused-cycle"])
def test_uri_base_resolution_is_bounded_and_never_falls_back_on_invalid_base(bases, expected):
    files = ({"path": "project/a.cpp", "sha256": "a" * 64},
             {"path": "project/.hidden/a.cpp", "sha256": "b" * 64},
             {"path": "project/%2e/a.cpp", "sha256": "c" * 64})
    physical = {"artifactLocation": {"uri": "a.cpp", "uriBaseId": "CHILD"}}
    observations, gaps = normalize_sarif(
        {"version": "2.1.0", "runs": [{"originalUriBaseIds": bases,
          "results": [{"locations": [{"physicalLocation": physical}]}]}]},
        files=files, root="project", query_identity="fixture", result_limit=10)
    assert observations[0]["location"]["path"] == expected
    if expected is None:
        assert gaps and observations[0]["location"]["file_sha256"] is None
    else:
        assert not gaps
        assert observations[0]["location"]["file_sha256"] == next(
            item["sha256"] for item in files if item["path"] == expected)


@pytest.mark.parametrize(("uri", "path", "alias", "root"), [
    ("workspace/a.cpp", "workspace/a.cpp", "a.cpp", "."),
    ("scratch/workspace/a.cpp", "scratch/workspace/a.cpp", "a.cpp", "."),
    ("./workspace/.hidden/a.cpp", "workspace/.hidden/a.cpp", ".hidden/a.cpp", "."),
    ("././scratch/workspace/.github/ci.yml", "scratch/workspace/.github/ci.yml", ".github/ci.yml", "."),
    ("workspace/./a.cpp", "workspace/a.cpp", "a.cpp", "."),
    ("scratch/workspace/./.hidden/a.cpp", "scratch/workspace/.hidden/a.cpp", ".hidden/a.cpp", "."),
    ("workspace/a.cpp", "project/workspace/a.cpp", "project/a.cpp", "project"),
    ("./scratch/workspace/.hidden/a.cpp", "project/scratch/workspace/.hidden/a.cpp",
     "project/.hidden/a.cpp", "project"),
], ids=["workspace", "scratch", "dot-hidden", "dots-github", "inner-dot", "inner-dot-hidden",
        "rooted-workspace", "rooted-scratch"])
def test_exact_relative_workspace_identity_precedes_virtual_alias(uri, path, alias, root):
    files = ({"path": path, "sha256": "a" * 64}, {"path": alias, "sha256": "b" * 64})
    physical = {"artifactLocation": {"uri": uri}, "region": {"startLine": 2}}
    mapped = map_location(physical, files=files, root=root)
    observations, gaps = _normalize_location(physical, files, root)
    assert (mapped.path, mapped.file_sha256, mapped.confidence, mapped.ambiguous) == (
        path, "a" * 64, 1.0, False)
    assert mapped.candidates == (path,)
    assert gaps == []
    for location in (observations[0]["location"], observations[0]["flows"][0]["location"]):
        assert location["path"] == path and location["file_sha256"] == "a" * 64


@pytest.mark.parametrize(("uri", "paths", "expected"), [
    ("workspace/a.cpp", ("a.cpp",), "a.cpp"),
    ("./scratch/workspace/.hidden/a.cpp", (".hidden/a.cpp",), ".hidden/a.cpp"),
    ("/workspace/a.cpp", ("workspace/a.cpp", "a.cpp"), "a.cpp"),
    ("file:///scratch/workspace/.hidden/a.cpp",
     ("scratch/workspace/.hidden/a.cpp", ".hidden/a.cpp"), ".hidden/a.cpp"),
    ("/workspace/./workspace/a.cpp", ("workspace/a.cpp", "a.cpp"), "workspace/a.cpp"),
    ("scratch/workspace/a.cpp", ("one/a.cpp", "two/a.cpp"), None),
], ids=["relative-alias", "relative-hidden-alias", "absolute-workspace", "absolute-file",
        "absolute-literal-child", "ambiguous-alias"])
def test_workspace_alias_compatibility_and_ambiguity(uri, paths, expected):
    files = tuple({"path": path, "sha256": str(index + 1) * 64} for index, path in enumerate(paths))
    physical = {"artifactLocation": {"uri": uri}, "region": {"startLine": 2}}
    mapped = map_location(physical, files=files, root=".")
    observations, gaps = _normalize_location(physical, files, ".")
    if expected is None:
        assert mapped.path is None and mapped.file_sha256 is None and mapped.ambiguous
        assert mapped.candidates == paths and mapped.confidence == 0.5
        assert any("no uniquely mapped source location" in gap for gap in gaps)
        assert any("unmapped or ambiguous" in gap for gap in gaps)
    else:
        digest = next(item["sha256"] for item in files if item["path"] == expected)
        assert (mapped.path, mapped.file_sha256, mapped.ambiguous) == (expected, digest, False)
        assert not gaps
        for location in (observations[0]["location"], observations[0]["flows"][0]["location"]):
            assert location["path"] == expected and location["file_sha256"] == digest


@pytest.mark.parametrize("prefix", ["", "./", "././", "/workspace/", "file:///scratch/workspace/"])
@pytest.mark.parametrize("path", [".github/workflows/ci.yml", ".hidden/tool.py", "..hidden/tool.py"])
def test_leading_dot_locations_keep_exact_source_identity(prefix: str, path: str) -> None:
    files = ({"path": path, "sha256": "a" * 64},
             {"path": path.lstrip("."), "sha256": "b" * 64})
    physical = {"artifactLocation": {"uri": prefix + path}, "region": {"startLine": 2}}
    observations, gaps = normalize_sarif(
        {"version": "2.1.0", "runs": [{"results": [{
            "ruleId": "fixture/hidden", "locations": [{"physicalLocation": physical}],
            "codeFlows": [{"threadFlows": [{"locations": [{"location": {"physicalLocation": physical}}]}]}],
        }]}]},
        files=files, root=".", query_identity="query", result_limit=10,
    )
    assert gaps == []
    assert observations[0]["location"]["path"] == path
    assert observations[0]["location"]["file_sha256"] == "a" * 64
    assert observations[0]["flows"][0]["location"]["path"] == path
    assert observations[0]["flows"][0]["location"]["file_sha256"] == "a" * 64


@pytest.mark.parametrize("uri", [
    "../.hidden/tool.py", "/workspace/../.hidden/tool.py", "%2e%2e/.hidden/tool.py",
    "/.hidden/tool.py", "file://foreign/workspace/.hidden/tool.py",
    "https://foreign/.hidden/tool.py", r"C:\workspace\.hidden\tool.py",
    r"\\foreign\workspace\.hidden\tool.py", "file:///other/.hidden/tool.py",
])
def test_traversal_and_foreign_paths_do_not_bind_to_local_hidden_files(uri: str) -> None:
    mapped = map_location(
        {"artifactLocation": {"uri": uri}},
        files=({"path": ".hidden/tool.py", "sha256": "a" * 64},
               {"path": "hidden/tool.py", "sha256": "b" * 64}), root=".",
    )
    assert mapped.path is None and mapped.file_sha256 is None
    assert mapped.candidates == () and mapped.confidence == 0.0


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


def test_normalize_sarif_takes_the_rule_default_level_and_security_severity_when_level_is_omitted() -> None:
    """CodeQL SARIF omits ``result.level`` when the rule default applies; the lead must not become unknown."""
    from appsec_review.retrieval.observations import normalize_reported_severity

    doc = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"rules": [
                {"id": "cpp/command-line-injection", "defaultConfiguration": {"level": "error"},
                 "properties": {"security-severity": "9.8"}},
                {"id": "cpp/path-injection", "defaultConfiguration": {"level": "error"},
                 "properties": {"security-severity": "7.5"}},
                {"id": "cpp/no-default", "properties": {}},
            ]}},
            "results": [
                {"ruleId": "cpp/command-line-injection", "message": {"text": "a"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "services/api/handler.py"},
                                                     "region": {"startLine": 3}}}]},
                {"ruleId": "cpp/path-injection", "message": {"text": "b"}, "level": "warning",
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "services/api/handler.py"},
                                                     "region": {"startLine": 4}}}]},
                {"ruleId": "cpp/no-default", "message": {"text": "c"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "services/api/handler.py"},
                                                     "region": {"startLine": 5}}}]},
            ],
        }],
    }
    observations, gaps = normalize_sarif(doc, files=FILES, root=".", query_identity="q", result_limit=10)
    assert gaps == []
    by_rule = {item["rule_id"]: item["payload"] for item in observations}
    assert by_rule["cpp/command-line-injection"]["producer_level"] == "error"
    assert by_rule["cpp/command-line-injection"]["security_severity"] == "9.8"
    assert normalize_reported_severity(by_rule["cpp/command-line-injection"]) == {
        "value": "critical", "native": "error", "basis": "security-severity-cvss-band",
        "rule": "appsec-review/reported-severity/1"}
    # An explicit result level wins over the default; the CVSS band still orders the lead.
    assert by_rule["cpp/path-injection"]["producer_level"] == "warning"
    assert normalize_reported_severity(by_rule["cpp/path-injection"])["value"] == "high"
    # No level anywhere and no score stays unknown; nothing is invented.
    assert by_rule["cpp/no-default"]["producer_level"] is None
    assert by_rule["cpp/no-default"]["security_severity"] is None
    assert normalize_reported_severity(by_rule["cpp/no-default"])["value"] == "unknown"


@pytest.mark.parametrize("base_id", ["%SRCROOT%", "SRCROOT"])
@pytest.mark.parametrize(
    "uri_bases",
    [
        None,
        {},
        {"OTHER": {"uri": "file:///scratch/workspace/other/"}},
        {"%SRCROOT%": {"description": {"text": "Symbolic SARIF root"}},
         "SRCROOT": {"description": {"text": "Symbolic SARIF root"}}},
        {"%SRCROOT%": {"uri": "file:///scratch/workspace"},
         "SRCROOT": {"uri": "file:///scratch/workspace"}},
        {"%SRCROOT%": {"uri": "file:///workspace"},
         "SRCROOT": {"uri": "file:///workspace"}},
        {"%SRCROOT%": {"uri": "/scratch/workspace"},
         "SRCROOT": {"uri": "/workspace"}},
    ],
    ids=[
        "omitted-bases",
        "empty-bases",
        "unmapped-symbol",
        "symbolic-root-without-uri",
        "file-scratch-no-trailing-slash",
        "file-workspace-no-trailing-slash",
        "posix-no-trailing-slash",
    ],
)
def test_srcroot_resolves_when_unmapped_or_without_trailing_slash(base_id: str, uri_bases: object) -> None:
    files = (
        {"path": "src/request.cpp", "sha256": "a" * 64},
        {"path": "src/session.cpp", "sha256": "b" * 64},
    )
    physical = {
        "artifactLocation": {"uri": "src/request.cpp", "uriBaseId": base_id, "index": 0},
        "region": {"startLine": 137, "startColumn": 9, "endColumn": 24},
    }
    flow_step = {
        "artifactLocation": {"uri": "src/session.cpp", "uriBaseId": base_id, "index": 1},
        "region": {"startLine": 34, "startColumn": 5, "endColumn": 18},
    }
    run: dict[str, object] = {
        "results": [{
            "ruleId": "cpp/command-line-injection",
            "message": {"text": "tainted command"},
            "locations": [{"physicalLocation": physical}],
            "codeFlows": [{"threadFlows": [{"locations": [
                {"location": {"message": {"text": "step"}, "physicalLocation": flow_step}},
            ]}]}],
        }],
    }
    if uri_bases is not None:
        run["originalUriBaseIds"] = uri_bases
    observations, gaps = normalize_sarif(
        {"version": "2.1.0", "runs": [run]},
        files=files, root=".", query_identity="q-srcroot", result_limit=10,
    )
    assert gaps == []
    assert observations[0]["location"]["path"] == "src/request.cpp"
    assert observations[0]["location"]["file_sha256"] == "a" * 64
    assert observations[0]["location"]["confidence"] == 1.0
    assert observations[0]["flows"][0]["location"]["path"] == "src/session.cpp"
    assert observations[0]["flows"][0]["location"]["file_sha256"] == "b" * 64
    assert observations[0]["flows"][0]["location"]["confidence"] == 1.0


def test_unmapped_srcroot_disambiguates_nested_scope_root_and_no_slash_subroot() -> None:
    files = (
        {"path": "project/a.cpp", "sha256": "a" * 64},
        {"path": "project/project/a.cpp", "sha256": "b" * 64},
    )
    nested_physical = {"artifactLocation": {"uri": "project/a.cpp", "uriBaseId": "%SRCROOT%"}}
    direct_physical = {"artifactLocation": {"uri": "a.cpp", "uriBaseId": "%SRCROOT%"}}
    for uri_bases in (None, {}, {"%SRCROOT%": {"uri": "file:///scratch/workspace/project"}}):
        nested = map_location(nested_physical, files=files, root="project", uri_bases=uri_bases)
        direct = map_location(direct_physical, files=files, root="project", uri_bases=uri_bases)
        assert (nested.path, nested.file_sha256, nested.confidence, nested.ambiguous) == (
            "project/project/a.cpp", "b" * 64, 1.0, False
        )
        assert (direct.path, direct.file_sha256, direct.confidence, direct.ambiguous) == (
            "project/a.cpp", "a" * 64, 1.0, False
        )


@pytest.mark.parametrize(
    ("artifact", "uri_bases"),
    [
        ({"uri": "src/request.cpp", "uriBaseId": "TMP"}, None),
        ({"uri": "src/request.cpp", "uriBaseId": "EXTERNAL"}, {}),
        ({"uri": "src/request.cpp", "uriBaseId": "TMP"}, {"TMP": {}}),
        ({"uri": "src/request.cpp", "uriBaseId": None}, None),
        ({"uri": "../src/request.cpp", "uriBaseId": "%SRCROOT%"}, None),
        ({"uri": "src/request.cpp", "uriBaseId": "%SRCROOT%"}, {"%SRCROOT%": "malformed"}),
        ({"uri": "src/request.cpp", "uriBaseId": "%SRCROOT%"}, {"%SRCROOT%": {"uri": "file:///etc"}}),
        ({"uri": "src/request.cpp", "uriBaseId": "%SRCROOT%"},
         {"%SRCROOT%": {"uri": "file://foreign/scratch/workspace"}}),
        ({"uri": "src/request.cpp", "uriBaseId": "%SRCROOT%"},
         {"%SRCROOT%": {"uri": "file:///scratch/workspace/../etc"}}),
        ({"uri": "src/request.cpp", "uriBaseId": "%SRCROOT%"},
         {"%SRCROOT%": {"uriBaseId": "%SRCROOT%"}}),
    ],
    ids=[
        "unmapped-tmp",
        "unmapped-external",
        "empty-tmp-record",
        "null-base-id",
        "artifact-traversal",
        "explicit-malformed-srcroot",
        "explicit-outside-workspace-srcroot",
        "explicit-foreign-srcroot",
        "explicit-traversal-srcroot",
        "explicit-cyclic-srcroot",
    ],
)
def test_invalid_or_foreign_uri_bases_still_fail_closed(artifact: dict[str, object], uri_bases: object) -> None:
    files = ({"path": "src/request.cpp", "sha256": "a" * 64},)
    mapped = map_location({"artifactLocation": artifact}, files=files, root=".", uri_bases=uri_bases)
    assert mapped.path is None and mapped.file_sha256 is None
    assert mapped.confidence == 0.0 and mapped.candidates == ()


def test_system_header_flow_steps_stay_unmapped_without_false_gaps_while_bad_steps_report_gaps() -> None:
    files = ({"path": "src/request.cpp", "sha256": "a" * 64},)
    primary = {
        "artifactLocation": {"uri": "src/request.cpp", "uriBaseId": "%SRCROOT%"},
        "region": {"startLine": 28, "startColumn": 10, "endColumn": 13},
    }
    sys_step = {
        "artifactLocation": {"uri": "file:///usr/include/string.h", "index": 2},
        "region": {"startLine": 235, "startColumn": 10, "endColumn": 26},
    }
    in_tree_step = {
        "artifactLocation": {"uri": "src/request.cpp", "uriBaseId": "%SRCROOT%", "index": 0},
        "region": {"startLine": 110, "startColumn": 15, "endColumn": 21},
    }
    observations, gaps = normalize_sarif(
        {"version": "2.1.0", "runs": [{"results": [{
            "ruleId": "cpp/non-constant-format",
            "locations": [{"physicalLocation": primary}],
            "codeFlows": [{"threadFlows": [{"locations": [
                {"location": {"message": {"text": "*call to __builtin_strchr"}, "physicalLocation": sys_step}},
                {"location": {"message": {"text": "*call to strchr"}, "physicalLocation": in_tree_step}},
            ]}]}],
        }]}]},
        files=files, root=".", query_identity="q-sys", result_limit=10,
    )
    assert gaps == []
    assert observations[0]["flows"][0]["location"]["path"] is None
    assert observations[0]["flows"][0]["location"]["confidence"] == 0.0
    assert observations[0]["flows"][1]["location"]["path"] == "src/request.cpp"
    assert observations[0]["flows"][1]["location"]["confidence"] == 1.0

    # Primary result in /usr/include or foreign/traversal flow step still records a gap.
    _, bad_gaps = normalize_sarif(
        {"version": "2.1.0", "runs": [{"results": [
            {"ruleId": "cpp/header-primary", "locations": [{"physicalLocation": sys_step}]},
            {"ruleId": "cpp/bad-flow", "locations": [{"physicalLocation": primary}],
             "codeFlows": [{"threadFlows": [{"locations": [
                 {"location": {"physicalLocation": {"artifactLocation": {"uri": "file://foreign/usr/include/string.h"}}}},
             ]}]}]},
        ]}]},
        files=files, root=".", query_identity="q-bad", result_limit=10,
    )
    assert "CodeQL result 0:0 had no uniquely mapped source location" in bad_gaps
    assert "CodeQL flow step for 0:1 was unmapped or ambiguous" in bad_gaps


def test_codeql_normalize_one_indexes_srcroot_locations_and_observed_at_edges(
        tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression for run 2026-11-25-0003 seq=02: native CodeQL %SRCROOT% SARIF without originalUriBaseIds."""
    import hashlib
    import json
    import sqlite3
    from dataclasses import asdict
    from pathlib import Path
    from types import SimpleNamespace
    from appsec_review.applicability import (
        FACTS_SCHEMA, ProcessingFeature, ProjectProcessingFacts,
        evaluate_applicability, finalize_processing,
    )
    from appsec_review.config.assurance import ReviewPolicy
    from appsec_review.jobs.job_codeql_analysis import job as codeql_job
    from appsec_review.jobs.job_codeql_analysis.planning import build_codeql_plan
    from appsec_review.storage import shared
    from tests.test_native_result_provenance import make_owner
    from .test_planning import IMAGE, _receipt

    run_root = Path(tmp_path)
    owner = make_owner(run_root)
    monkeypatch.setattr(shared, "current", lambda: owner)
    settings = SimpleNamespace(sarif_bytes_limit=1024 * 1024, result_limit=100, concurrency=1,
                               source_dispositions=None)
    monkeypatch.setattr(codeql_job, "_settings", lambda _unit: settings)

    target_root = run_root / "target"
    (target_root / "src").mkdir(parents=True)
    request_bytes = b"int main() {\n" + b"  return 0;\n" * 140 + b"}\n"
    request_file = target_root / "src" / "request.cpp"
    request_file.write_bytes(request_bytes)
    request_sha = hashlib.sha256(request_bytes).hexdigest()

    planned = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=({"path": "src/request.cpp", "sha256": request_sha, "size_bytes": len(request_bytes),
                "language": "cpp"},),
        receipts=(_receipt("appsec_multi_vuln", "native", root="."),),
        supported_extractors=("cpp",),
        source_image_id=IMAGE,
    )
    scope, = planned.scopes

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CodeQL", "rules": [{
                "id": "cpp/command-line-injection",
                "defaultConfiguration": {"level": "error"},
                "properties": {"security-severity": "9.8"},
            }]}},
            "columnKind": "utf16CodeUnits",
            "results": [{
                "ruleId": "cpp/command-line-injection",
                "message": {"text": "Call to system with untrusted input."},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "src/request.cpp", "uriBaseId": "%SRCROOT%", "index": 0},
                    "region": {"startLine": 137, "startColumn": 9, "endColumn": 24},
                }}],
                "partialFingerprints": {"primaryLocationLineHash": "deadbeef:1"},
                "codeFlows": [{"threadFlows": [{"locations": [
                    {"location": {
                        "message": {"text": "*call to __builtin_strchr"},
                        "physicalLocation": {
                            "artifactLocation": {"uri": "file:///usr/include/string.h", "index": 1},
                            "region": {"startLine": 235, "startColumn": 10, "endColumn": 26},
                        },
                    }},
                    {"location": {
                        "message": {"text": "source parameter"},
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/request.cpp", "uriBaseId": "%SRCROOT%", "index": 0},
                            "region": {"startLine": 42, "startColumn": 5, "endColumn": 12},
                        },
                    }},
                    {"location": {
                        "message": {"text": "sink argument"},
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/request.cpp", "uriBaseId": "%SRCROOT%", "index": 0},
                            "region": {"startLine": 137, "startColumn": 9, "endColumn": 24},
                        },
                    }},
                ]}]}],
            }],
        }],
    }
    sarif_path = run_root / "results.sarif"
    sarif_path.write_text(json.dumps(sarif_doc), encoding="utf-8")
    exec_path = run_root / "query-execution.json"
    exec_path.write_text(json.dumps({"exit_code": 0}), encoding="utf-8")

    def _ref(p: Path) -> dict[str, object]:
        raw = p.read_bytes()
        return {"path": p.name, "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}

    query = {
        "scope": asdict(scope),
        "query_profile": {"query_id": "security-extended", "kind": "additional",
                          "query_suite": "cpp-security-extended.qls"},
        "database_identity": "d" * 64,
        "query_identity": "q" * 64,
        "terminal_status": "SUCCEEDED",
        "database_reused": False,
        "query_reused": False,
        "gaps": [],
        "sarif": _ref(sarif_path),
        "query_execution": _ref(exec_path),
    }
    unit = SimpleNamespace(
        job=SimpleNamespace(
            run_root=run_root,
            target_root=target_root,
            attempt_id="attempt_0001",
            source_fingerprint="f" * 64,
            review_policy=ReviewPolicy(),
        ),
        unit_id="execution.scopes",
    )

    normalized = codeql_job._normalize_one(unit, query)
    assert normalized["gaps"] == []
    assert normalized["observation_count"] == 1
    assert normalized["support_count"] == 2

    facts = ProjectProcessingFacts(
        FACTS_SCHEMA, "appsec_multi_vuln", "cpp", "native", ".", "cmake",
        True, ("compiled-descriptor:cmake",), (), ("compile-commands",), ("codeql-build",), (),
    )
    decision = evaluate_applicability(
        feature=ProcessingFeature.CODEQL, policy="auto", facts=facts,
        configuration_sha256="c" * 64,
    )
    finalized = finalize_processing(
        decision,
        succeeded=normalized["terminal_status"] == "SUCCEEDED",
        evidence_complete=not bool(normalized["gaps"]),
        toolchain_available=True,
    ).as_dict()
    assert finalized["disposition"] == "SUCCEEDED"
    assert finalized["reason_code"] == "PROCESSING_SUCCEEDED"
    assert codeql_job.publication_status([finalized], [normalized], gaps=normalized["gaps"]) == "SUCCEEDED"

    shard_file = run_root / normalized["index"]["path"]
    with sqlite3.connect(shard_file) as conn:
        locations = conn.execute(
            "SELECT path, file_sha256, confidence FROM locations ORDER BY entity_id"
        ).fetchall()
        relations = dict(conn.execute(
            "SELECT kind, COUNT(*) FROM relations GROUP BY kind"
        ).fetchall())
        coverage = conn.execute("SELECT status, gap FROM coverage").fetchall()
    assert len(locations) == 4  # 1 tool_observation + 1 source_file + 2 in-tree source_spans
    assert all(row == ("src/request.cpp", request_sha, 1.0) for row in locations)
    assert relations["OBSERVED_AT"] == 3  # 1 observation->file + 2 flow_spans->file
    assert relations["SUPPORTS"] == 2
    assert relations["DERIVED_FROM"] == 1
    assert coverage == [("complete", None)]
