"""Game threat-model slices: operator path rules, annotation and slicing (T-070)."""
from __future__ import annotations

import copy

import pytest

from appsec_review.observability.findings import contracts as c
from appsec_review.observability.findings import slices as s
from appsec_review.observability.findings.identity import fingerprint

CODE = "void f(char *p) {\n  char b[8];\n  strcpy(b, p);\n}\n"


def located(*paths, function="parse_packet"):
    return [{"path": path, "start_line": 10, "end_line": 12, "function": function, "code": CODE} for path in paths]


def finding(finding_id="F1", **changes):
    value = {"finding_id": finding_id, "state": "confirmed", "weakness_cwe": "CWE-121", "severity": "high",
             "lane": "lead", "locations": located("src/net/parse.c")}
    value.update(changes)
    return value


def normalized(finding_id="F1", **changes):
    return c.normalize_finding(finding(finding_id, **changes))


def snapshot(findings, **changes):
    arguments = dict(run_id="run-1", target_id="game", source_revision="a" * 40, findings=findings,
                     fingerprint=fingerprint)
    arguments.update(changes)
    return c.build_snapshot(**arguments)


def rules_document(**changes):
    document = {
        "schema": s.SLICE_RULES_SCHEMA,
        "ownership": {"engine": ["engine/**"], "middleware": ["third_party/**", "engine/plugins/physx/**"],
                      "default": "first_party"},
        "build_configuration": {"editor_or_test": ["**/tests/**", "editor/**"], "development": ["**/debug/**"],
                                "default": "shipping"},
        "components": [{"name": "netcode", "paths": ["src/net/**"]}, {"name": "game", "paths": ["src/**"]}],
    }
    document.update(changes)
    return document


RULES = s.load_rules(rules_document())


# ------------------------------------------------------------------------------------- globs

GLOB_CASES = [
    ("*.c", "a.c", True),                       # * within a segment
    ("*.c", "src/a.c", False),                  # * never crosses a separator
    ("src/*.c", "src/a.c", True),
    ("src/*.c", "src/net/a.c", False),
    ("src/*", "src", False),                    # * needs a segment of its own
    ("src/*/a.c", "src/a.c", False),
    ("*/*", "a/b", True),
    ("*/*", "a", False),
    ("a*b*c", "aXbXbYc", True),                 # backtracking inside a segment
    ("*a", "aXa", True),
    ("a*", "a", True),                          # * matches the empty run
    ("**", "a", True),                          # ** alone matches every path
    ("**", "a/b/c.c", True),
    ("**/a.c", "a.c", True),                    # leading ** matches zero segments
    ("**/a.c", "x/y/a.c", True),                # and many
    ("src/**", "src", True),                    # trailing ** matches zero segments
    ("src/**", "src/a/b.c", True),
    ("src/**", "srcs/a.c", False),
    ("src/**/a.c", "src/a.c", True),            # inner ** matches zero segments
    ("src/**/a.c", "src/x/y/a.c", True),
    ("src/**/a.c", "src/x/b.c", False),
    ("**/**/x", "x", True),
    ("**/test/**", "a/test/b.c", True),
    ("**/test/**", "a/tests/b.c", False),
    ("**/*.c", "a/b/c.c", True),
    ("**/b/**/b/c", "a/b/b/c", True),           # backtracking across segments
    ("**/b/**/b/c", "a/b/c", False),
    ("a**b", "axyb", True),                     # ** inside a segment behaves as *
    ("a**b", "a/b", False),
    ("a?.c", "ab.c", True),                     # ? is exactly one character
    ("a?.c", "a.c", False),
    ("a?.c", "abc.c", False),
    ("a?c", "a/c", False),                      # ? never matches a separator
    ("src", "src/a.c", False),                  # anchored at the end
    ("src/a", "src/a.c", False),
    ("a.c", "src/a.c", False),                  # anchored at the start
    ("net/*.c", "src/net/a.c", False),
    ("Src/*.c", "src/a.c", False),              # case-sensitive
    ("src/*.C", "src/a.c", False),
    ("src/A.c", "src/A.c", True),
    ("[ab].c", "a.c", False),                   # brackets are literal
    ("[ab].c", "[ab].c", True),
    ("a.c", "abc", False),                      # a dot is literal
]


@pytest.mark.parametrize("pattern, path, expected", GLOB_CASES,
                         ids=[f"g{index:02d}" for index in range(len(GLOB_CASES))])
def test_glob_match(pattern, path, expected):
    assert s.glob_match(pattern, path) is expected


def test_glob_match_is_bounded_on_a_pathological_pattern():
    assert s.glob_match("*a" * 120 + "b", "a" * 1000) is False
    assert s.glob_match("/".join(["**", "a"] * 60 + ["b"]), "/".join(["a"] * 400)) is False


# ------------------------------------------------------------------------------------- rules

def test_load_rules_normalizes_and_identifies_the_document():
    assert RULES.engine == ("engine/**",)
    assert RULES.middleware == ("engine/plugins/physx/**", "third_party/**")
    assert RULES.components == (("netcode", ("src/net/**",)), ("game", ("src/**",)))
    assert RULES.ownership_default == "first_party" and RULES.build_configuration_default == "shipping"
    assert c.is_sha256(RULES.sha256) and c.digest(RULES.document()) == RULES.sha256
    assert s.load_rules(RULES.document()) == RULES
    with pytest.raises(AttributeError):
        RULES.engine = ()   # type: ignore[misc]


def test_rules_identity_ignores_glob_order_but_not_component_order():
    reordered = rules_document(ownership={"engine": ["engine/**", "engine/**"],
                                          "middleware": ["engine/plugins/physx/**", "third_party/**"],
                                          "default": "first_party"})
    assert s.load_rules(reordered).sha256 == RULES.sha256
    swapped = rules_document(components=list(reversed(rules_document()["components"])))
    assert s.load_rules(swapped).sha256 != RULES.sha256


def test_omitted_sections_establish_nothing():
    empty = s.load_rules({"schema": s.SLICE_RULES_SCHEMA})
    explicit = s.load_rules({"schema": s.SLICE_RULES_SCHEMA, "ownership": {"engine": [], "middleware": [],
                                                                         "default": None},
                             "build_configuration": {"editor_or_test": [], "development": [], "default": None},
                             "components": []})
    assert empty == explicit
    annotated = s.annotate(normalized(), empty)
    assert (annotated["ownership"], annotated["build_configuration"], annotated["component"]) == (None, None, None)


def test_load_rules_does_not_mutate_its_document():
    document = rules_document()
    before = copy.deepcopy(document)
    s.load_rules(document)
    assert document == before


@pytest.mark.parametrize("document", [
    None,
    {},
    {"schema": "appsec-review/finding-slice-rules/0"},
    rules_document(note="x"),
    rules_document(ownership={"engine": [], "vendor": []}),
    rules_document(ownership=["engine/**"]),
    rules_document(ownership={"default": "engine"}),
    rules_document(ownership={"engine": "engine/**"}),
    rules_document(build_configuration={"shipping": []}),
    rules_document(build_configuration={"default": "development"}),
    rules_document(components={"name": "a", "paths": []}),
    rules_document(components=[{"name": "a", "paths": [], "owner": "x"}]),
    rules_document(components=[{"name": "a"}]),
    rules_document(components=[{"name": "a", "paths": "src/**"}]),
    rules_document(components=[{"name": "a", "paths": []}, {"name": "a", "paths": []}]),
    rules_document(components=[{"name": "", "paths": []}]),
    rules_document(components=[{"name": "a\nb", "paths": []}]),
    rules_document(components=[{"name": "null", "paths": []}]),
    rules_document(components=[{"name": 7, "paths": []}]),
    rules_document(components=["netcode"]),
], ids=[f"r{index:02d}" for index in range(20)])
def test_load_rules_refuses_unknown_keys_and_invalid_shapes(document):
    with pytest.raises(ValueError):
        s.load_rules(document)


@pytest.mark.parametrize("glob", ["", "/abs/**", "a/../b", "..", "a\\b", "a//b", "a/", "./a", "a\nb", 7, None],
                         ids=[f"b{index:02d}" for index in range(11)])
def test_load_rules_refuses_globs_that_are_not_target_relative_posix(glob):
    with pytest.raises(ValueError):
        s.load_rules(rules_document(ownership={"engine": [glob]}))
    with pytest.raises(ValueError):
        s.load_rules(rules_document(components=[{"name": "a", "paths": [glob]}]))


def test_a_dotted_name_is_not_an_escaping_segment():
    assert s.load_rules(rules_document(ownership={"engine": ["a..b/**"]})).engine == ("a..b/**",)


def test_glob_length_bound_is_exact():
    assert s.load_rules(rules_document(ownership={"engine": ["a" * s.MAX_GLOB_CHARS]}))
    with pytest.raises(ValueError):
        s.load_rules(rules_document(ownership={"engine": ["a" * (s.MAX_GLOB_CHARS + 1)]}))


@pytest.mark.parametrize("where", ["build_configuration.development", "build_configuration.editor_or_test",
                                   "components", "ownership.engine", "ownership.middleware"])
def test_glob_list_bound_is_exact(where):
    def document(count):
        globs = [f"dir{index}/**" for index in range(count)]
        if where == "components":
            return rules_document(components=[{"name": "a", "paths": globs}])
        section, key = where.split(".")
        return rules_document(**{section: {key: globs}})

    assert s.load_rules(document(s.MAX_GLOBS))
    with pytest.raises(ValueError):
        s.load_rules(document(s.MAX_GLOBS + 1))


def test_component_count_and_name_bounds_are_exact():
    def components(count):
        return [{"name": f"c{index}", "paths": []} for index in range(count)]

    assert len(s.load_rules(rules_document(components=components(s.MAX_COMPONENTS))).components) == s.MAX_COMPONENTS
    with pytest.raises(ValueError):
        s.load_rules(rules_document(components=components(s.MAX_COMPONENTS + 1)))
    assert s.load_rules(rules_document(components=[{"name": "n" * s.MAX_COMPONENT_NAME_CHARS, "paths": []}]))
    with pytest.raises(ValueError):
        s.load_rules(rules_document(components=[{"name": "n" * (s.MAX_COMPONENT_NAME_CHARS + 1), "paths": []}]))


# ---------------------------------------------------------------------------------- annotate

@pytest.mark.parametrize("path, ownership, build, component", [
    ("editor/tools/bake.c", "first_party", "editor_or_test", None),
    ("engine/core/alloc.c", "engine", "shipping", None),
    ("engine/plugins/physx/solver.c", "engine", "shipping", None),          # engine wins over middleware
    ("src/game/debug/cheats.c", "first_party", "development", "game"),
    ("src/game/tests/debug/x.c", "first_party", "editor_or_test", "game"),   # editor_or_test wins over development
    ("src/net/parse.c", "first_party", "shipping", "netcode"),              # first declared component wins
    ("third_party/zlib/inflate.c", "middleware", "shipping", None),
], ids=["editor", "engine", "engine-first", "development", "test-first", "netcode", "middleware"])
def test_annotate_classifies_a_single_location(path, ownership, build, component):
    annotated = s.annotate(normalized(locations=located(path)), RULES)
    assert (annotated["ownership"], annotated["build_configuration"], annotated["component"]) == (
        ownership, build, component)


def test_annotate_needs_every_location_to_agree():
    agreeing = s.annotate(normalized(locations=located("src/net/a.c", "src/net/b.c")), RULES)
    assert (agreeing["ownership"], agreeing["build_configuration"], agreeing["component"]) == (
        "first_party", "shipping", "netcode")
    split = s.annotate(normalized(locations=located("engine/core/a.c", "src/net/tests/b.c")), RULES)
    assert (split["ownership"], split["build_configuration"], split["component"]) == (None, None, None)
    partly = s.annotate(normalized(locations=located("src/net/a.c", "src/game/b.c")), RULES)
    assert (partly["ownership"], partly["component"]) == ("first_party", None)


def test_annotate_leaves_unmatched_paths_null_when_no_default_is_stated():
    rules = s.load_rules(rules_document(ownership={"engine": ["engine/**"]},
                                        build_configuration={"development": ["**/debug/**"]}))
    unmatched = s.annotate(normalized(), rules)
    assert unmatched["ownership"] is None and unmatched["build_configuration"] is None
    assert s.annotate(normalized(locations=located("engine/a.c")), rules)["ownership"] == "engine"
    mixed = s.annotate(normalized(locations=located("engine/a.c", "src/a.c")), rules)
    assert mixed["ownership"] is None, "a matched and an unmatched location disagree"


def test_annotate_never_overrides_an_established_value():
    established = normalized(locations=located("engine/core/tests/a.c"), ownership="middleware",
                             build_configuration="development", component="renderer")
    annotated = s.annotate(established, RULES)
    assert (annotated["ownership"], annotated["build_configuration"], annotated["component"]) == (
        "middleware", "development", "renderer")


def test_annotate_never_infers_attacker_position():
    assert s.annotate(normalized(), RULES)["attacker_position"] is None
    kept = s.annotate(normalized(attacker_position="client_to_server"), RULES)
    assert kept["attacker_position"] == "client_to_server"


def test_annotate_returns_a_new_record_and_does_not_mutate_its_input():
    record = snapshot([finding()])["findings"][0]
    before = copy.deepcopy(record)
    annotated = s.annotate(record, RULES)
    assert record == before and annotated is not record
    annotated["locations"][0]["path"] = "changed.c"
    assert record == before, "the copy shares no structure with the input"
    assert {key: value for key, value in s.annotate(record, RULES).items()
            if key not in ("ownership", "build_configuration", "component")} == {
        key: value for key, value in before.items() if key not in ("ownership", "build_configuration", "component")}


@pytest.mark.parametrize("record, rules", [
    (None, RULES), ({"finding_id": "F"}, RULES), ({"finding_id": "F", "locations": []}, RULES),
    ({"finding_id": "F", "locations": [{"path": "/abs.c"}]}, RULES), ({"finding_id": "F", "locations": ["a.c"]}, RULES),
    (finding(), rules_document()),
], ids=["not-object", "no-locations", "empty-locations", "absolute-path", "bare-location", "raw-rules"])
def test_annotate_refuses_invalid_input(record, rules):
    with pytest.raises(ValueError):
        s.annotate(record, rules)


def test_annotate_snapshot_keeps_identity_and_adds_nothing():
    built = snapshot([finding("A"), finding("B", locations=located("engine/core/alloc.c", function="alloc")),
                      finding("C", locations=located("src/x.c", function="x"), ownership="engine")],
                     reviewed_units={"src/net/parse.c": None})
    before = copy.deepcopy(built)
    annotated = s.annotate_snapshot(built, RULES)
    assert built == before and annotated is not built
    assert c.check_snapshot(annotated) == annotated
    assert list(annotated) == list(built)
    assert {key: value for key, value in annotated.items() if key != "findings"} == {
        key: value for key, value in built.items() if key != "findings"}
    identities = [item["fingerprint"] for item in built["findings"]]
    assert [item["fingerprint"] for item in annotated["findings"]] == identities
    assert [fingerprint(item) for item in annotated["findings"]] == identities, "the dimensions are not identity"
    assert [(item["finding_id"], item["ownership"], item["component"]) for item in annotated["findings"]] == [
        ("A", "first_party", "netcode"), ("B", "engine", None), ("C", "engine", "game")]


def test_annotate_snapshot_refuses_a_foreign_document():
    with pytest.raises(ValueError):
        s.annotate_snapshot({"schema": "other"}, RULES)


# ----------------------------------------------------------------------------------- slicing

def sample():
    return [
        normalized("A", ownership="engine", severity="critical", lane="hunt", component="netcode",
                   attacker_position="client_to_server", build_configuration="shipping",
                   ship_block_status="ship_blocking"),
        normalized("B", ownership="first_party", severity="high", weakness_cwe="CWE-78", component="audio"),
        normalized("C", ownership=None, severity=None, weakness_cwe=None, lane=None, state="supported"),
        normalized("D", ownership="middleware", severity="high", weakness_cwe="CWE-9999", state="contradicted",
                   component="netcode"),
    ]


@pytest.mark.parametrize("dimension, expected", [
    ("attacker_position", {"client_to_server": 1, "server_to_client": 0, "peer_to_peer": 0, "hostile_content": 0,
                           "local": 0, "null": 3}),
    ("build_configuration", {"shipping": 1, "development": 0, "editor_or_test": 0, "null": 3}),
    ("component", {"audio": 1, "netcode": 2, "null": 1}),
    ("lane", {"lead": 2, "hunt": 1, "null": 1}),
    ("ownership", {"first_party": 1, "engine": 1, "middleware": 1, "null": 1}),
    ("severity", {"low": 0, "medium": 0, "high": 2, "critical": 1, "null": 1}),
    ("ship_block_status", {"ship_blocking": 1, "ship_blocking_pending_distinct_verification": 0,
                           "needs_verification": 0, "decision_pending": 0, "not_ship_blocking": 0, "null": 3}),
    ("weakness_family", {"CWE-9999": 1, "injection": 1, "memory_safety": 1, "null": 1}),
], ids=lambda value: value if isinstance(value, str) else "")
def test_slice_counts(dimension, expected):
    table = s.slice_counts(sample(), dimension)
    assert table == expected and list(table) == list(expected)
    assert sum(table.values()) == 4


@pytest.mark.parametrize("dimension", s.DIMENSIONS)
def test_slice_counts_of_nothing_keeps_the_null_row(dimension):
    table = s.slice_counts([], dimension)
    assert table["null"] == 0 and set(table.values()) == {0}
    assert set(table) == {*s.CLOSED_DIMENSIONS.get(dimension, ()), "null"}


def test_dimensions_are_the_documented_slices():
    assert s.DIMENSIONS == ("attacker_position", "build_configuration", "component", "lane", "ownership", "severity",
                            "ship_block_status", "weakness_family")


@pytest.mark.parametrize("dimension", ["", "finding_id", "lead_families", "state"])
def test_unknown_dimension_is_refused(dimension):
    with pytest.raises(ValueError):
        s.slice_counts(sample(), dimension)
    with pytest.raises(ValueError):
        s.sliced(sample(), dimension, len)


def test_slicing_refuses_values_it_cannot_place():
    with pytest.raises(ValueError):
        s.slice_counts([{"finding_id": "X", "ownership": "vendor"}], "ownership")
    with pytest.raises(ValueError):
        s.slice_counts([{"finding_id": "X", "component": "null"}], "component")
    with pytest.raises(ValueError):
        s.sliced([{"finding_id": "X", "severity": "severe"}], "severity", len)


def test_sliced_applies_the_metric_to_every_slice_including_empty_ones():
    findings = sample()
    before = copy.deepcopy(findings)
    result = s.sliced(findings, "ownership", lambda group: sorted(item["finding_id"] for item in group))
    assert result == {"engine": ["A"], "first_party": ["B"], "middleware": ["D"], "null": ["C"]}
    assert list(result) == sorted(result) and findings == before
    by_severity = s.sliced(findings, "severity", len)
    assert by_severity == {"critical": 1, "high": 2, "low": 0, "medium": 0, "null": 1}
    assert list(by_severity) == ["critical", "high", "low", "medium", "null"]
    shares = s.sliced(findings, "lane", lambda group: c.ratio(sum(map(c.is_published, group)), len(group)))
    assert shares["hunt"]["value"] == 1.0 and shares["lead"]["value"] == 0.5
    assert s.sliced([], "lane", lambda group: c.ratio(0, len(group)))["hunt"]["status"] == "empty_denominator"
    assert s.sliced(findings, "component", len) == {"audio": 1, "netcode": 2, "null": 1}


def test_sliced_accepts_an_iterator_once():
    assert s.sliced(iter(sample()), "lane", len) == {"hunt": 1, "lead": 2, "null": 1}
    assert s.slice_counts(iter(sample()), "weakness_family")["memory_safety"] == 1


def test_routing_separates_dependency_findings_and_unknown_ownership():
    findings = sample() + [normalized("E", ownership="middleware", state="supported"),
                           normalized("0", ownership="first_party")]
    before = copy.deepcopy(findings)
    assert s.routing(findings) == {
        "published": 5,
        "fixable_in_place": {"count": 2, "finding_ids": ["0", "B"]},
        "route_as_dependency": {"count": 2, "finding_ids": ["A", "E"]},
        "ownership_unknown": {"count": 1, "finding_ids": ["C"]},
    }
    assert findings == before


def test_routing_of_nothing_and_of_an_open_vocabulary():
    assert s.routing([]) == {"published": 0, "fixable_in_place": {"count": 0, "finding_ids": []},
                             "route_as_dependency": {"count": 0, "finding_ids": []},
                             "ownership_unknown": {"count": 0, "finding_ids": []}}
    with pytest.raises(ValueError):
        s.routing([{"finding_id": "X", "state": "confirmed", "ownership": "vendor"}])
