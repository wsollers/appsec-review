from __future__ import annotations

from dataclasses import replace

import pytest

from appsec_review.owasp_workbench.evidence import component_evidence
from appsec_review.owasp_workbench.obligations import PROCEDURES, instantiate, subjects
from appsec_review.owasp_workbench.subject_selection import parse_subjects, select_subjects


SQL = "def lookup(cursor, name):\n    return cursor.execute('SELECT id FROM users WHERE name = ?', (name,))\n"
AUTH = "@app.get('/records')\ndef records():\n    return service.records()\n"


def select(boundary, settings):
    return component_evidence(boundary.resolver, "api", boundary.files, settings)


@pytest.mark.parametrize("padding", [121, 5000])
def test_discovers_complete_subject_past_old_prefix_in_long_file(accepted, settings, padding):
    source = "# earlier context\n" * padding + SQL + "# later context\n" * 10
    boundary = accepted({"app.py": source})
    [item], gaps = select(boundary, settings)
    assert not gaps
    assert item["excerpt"] == SQL.rstrip("\n")
    assert item["reference"]["locator"]["lines"] == [padding + 1, padding + 2]
    assert item["source_subject"]["outside_lines"] == padding + 10
    assert item["source_subject"]["complete"] and not item["truncated"]
    assert boundary.resolver.resolve(item["reference"], component_id="api") == {
        key: value for key, value in item.items() if key != "component_id"}
    [site] = subjects(PROCEDURES[0], item)
    assert site


def test_index_locations_prioritize_files_and_sites_beyond_delivery_cap(accepted, settings):
    boundary = accepted({"a.py": SQL, "z.py": SQL + "\n" + SQL.replace("lookup", "other")},
                        hints=(("z.py", 4, 5),))
    values, gaps = select(boundary, replace(settings, max_evidence_per_component=1))
    assert len(values) == 1
    assert values[0]["reference"]["locator"]["path"] == "z.py"
    assert values[0]["reference"]["locator"]["lines"] == [4, 5]
    assert any("2 complete recognized subjects omitted" in gap for gap in gaps)


def test_new_discovery_reaches_files_beyond_sixty(accepted, settings):
    sources = {f"{number:03}.py": "x = 1\n" for number in range(65)}
    sources["065.py"] = SQL
    boundary = accepted(sources)
    [item], gaps = select(boundary, settings)
    assert item["reference"]["locator"]["path"] == "065.py"
    assert sum("no recognized subject" in gap for gap in gaps) == 65


def test_decorators_async_and_nested_context_keep_absolute_lines(accepted, settings):
    source = ("class Service:\n"
              "    def outer(self):\n"
              "        @audit(\n"
              "            'access',\n"
              "        )\n"
              "        @app.get('/records')\n"
              "        async def handler():\n"
              "            return cursor.execute('SELECT 1')\n"
              "        return handler\n")
    boundary = accepted({"nested.py": "# outside\n" * 200 + source})
    [item], gaps = select(boundary, settings)
    assert any("<module>: complete subject exceeds max_source_lines" in gap for gap in gaps)
    assert not item["truncated"]
    assert item["reference"]["locator"]["lines"] == [203, 208]
    assert item["source_subject"]["name"] == "Service.outer.handler"
    assert item["excerpt"].startswith("        @audit(")
    assert subjects(PROCEDURES[0], item)
    assert subjects(PROCEDURES[2], item) and subjects(PROCEDURES[3], item)


def test_module_level_site_requires_complete_module(accepted, settings):
    boundary = accepted({"app.py": "cursor.execute('SELECT 1')\n" + "# context\n" * 120})
    values, gaps = select(boundary, settings)
    assert not values
    assert any("<module>: complete subject exceeds max_source_lines; 1 subject omitted" in gap for gap in gaps)


def test_smaller_nested_subject_survives_oversized_parent(accepted, settings):
    source = "@app.get('/long')\ndef outer():\n" + "    pass\n" * 130
    source += "    def inner(cursor):\n        return cursor.execute('SELECT 1')\n"
    boundary = accepted({"app.py": source})
    [item], gaps = select(boundary, settings)
    assert item["source_subject"]["name"] == "outer.inner"
    assert not item["truncated"]
    assert any("outer: complete subject exceeds max_source_lines; 1 subject omitted" in gap for gap in gaps)


@pytest.mark.parametrize("source,reason", [
    ("def broken(:\n", "parse failure"),
    (b"# \xff\n", "parse failure"),
    ("print('SELECT 1')\n", "no recognized subject"),
    ("def f(cursor):\n    return cursor.execute('SELECT " + "x" * 16000 + "')\n", "character cap"),
], ids=["invalid-python", "non-utf8", "unrecognized", "character-cap"])
def test_unusable_subjects_are_named_omissions(accepted, settings, source, reason):
    values, gaps = select(accepted({"app.py": source}), settings)
    assert not values and any(reason in gap for gap in gaps)


@pytest.mark.parametrize("path,language", [("app.js", "JavaScript"), ("app.py", "Rust")])
def test_unsupported_source_is_not_parsed(accepted, settings, path, language):
    boundary = accepted({path: SQL}, languages={path: language})
    values, gaps = select(boundary, settings)
    assert not values and not boundary.reads
    assert any("unsupported source language; 1 file omitted" in gap for gap in gaps)


def test_file_cap_has_exact_known_file_and_unknown_subject_counts(accepted, settings):
    boundary = accepted({"b.py": SQL, "a.py": SQL, "c.py": SQL})
    values, gaps = select(boundary, replace(settings, max_discovery_files=1))
    assert [item["reference"]["locator"]["path"] for item in values] == ["a.py"]
    assert any("2 accepted files omitted (subject count unknown)" in gap for gap in gaps)
    assert all(path == "a.py" for path, _ in boundary.reads)


def test_byte_budget_is_cumulative_and_does_not_read_oversized_source(accepted, settings):
    boundary = accepted({"a.py": SQL, "b.py": SQL, "c.py": "x = 1\n"})
    values, gaps = select(boundary, replace(settings, max_discovery_bytes=len(SQL.encode()) + 6))
    assert len(values) == 1
    assert any("b.py: max_discovery_bytes reached; 1 file omitted" in gap for gap in gaps)
    assert ("b.py", 6) in boundary.reads and ("c.py", 6) in boundary.reads
    assert any("c.py: no recognized subject" in gap for gap in gaps)


def test_zero_remaining_bytes_names_each_unread_file(accepted, settings):
    boundary = accepted({"a.py": SQL, "b.py": SQL, "c.py": SQL})
    values, gaps = select(boundary, replace(settings, max_discovery_bytes=len(SQL.encode())))
    assert len(values) == 1 and sum("max_discovery_bytes reached" in gap for gap in gaps) == 2
    assert ("b.py", 0) in boundary.reads and ("c.py", 0) in boundary.reads


def test_source_tampering_is_integrity_failure_not_coverage_gap(accepted, settings):
    boundary = accepted({"app.py": SQL})
    boundary.data["app.py"] = SQL.replace("id FROM", "no FROM").encode()
    with pytest.raises(ValueError, match="changed after indexing"):
        select(boundary, settings)


def test_stable_order_and_exact_omissions_ignore_inventory_order(accepted, settings):
    boundary = accepted({"b.py": SQL, "a.py": SQL, "c.py": SQL})
    settings = replace(settings, max_evidence_per_component=2)
    first = select(boundary, settings)
    boundary.files.reverse()
    boundary.rows.reverse()
    assert select(boundary, settings) == first
    values, gaps = first
    assert [item["reference"]["locator"]["path"] for item in values] == ["a.py", "b.py"]
    assert any("1 complete recognized subjects omitted" in gap for gap in gaps)


def test_independent_component_discovery_budget_is_not_shared(accepted, settings):
    boundary = accepted({"app.py": SQL})
    settings = replace(settings, max_discovery_bytes=len(SQL.encode()))
    assert select(boundary, settings) == select(boundary, settings)


def test_redacted_source_never_defines_a_proof_subject(accepted, settings):
    boundary = accepted({"app.py": SQL.replace("return cursor", "password = 'secret-value'\n    return cursor")})
    [item], _ = select(boundary, settings)
    assert item["redaction"]["applied"]
    assert "secret-value" not in item["excerpt"]
    assert not subjects(PROCEDURES[0], item)


def test_subject_cap_deduplicates_sites_and_records_exact_omissions(accepted, settings):
    source = SQL.replace("return cursor", "cursor") + "    cursor.execute('SELECT 2')\n"
    [item], _ = select(accepted({"app.py": source}), settings)
    rule = PROCEDURES[0]
    control = {"family": rule.family, "version": rule.version, "id": rule.control}
    row = {"row_id": "r", "control_identity": f"{rule.family}:{rule.version}:{rule.control}",
           "component_id": "api", "run_id": "unit-run", "target_id": item["reference"]["target_snapshot"],
           "evidence_mode": "static_source"}
    supported, omitted = instantiate(control, row, [item, item], max_subjects=1)
    assert supported["supported"] and supported["evidence_ids"] == [item["evidence_id"]]
    assert omitted["omitted_subject_count"] == 1
    assert len(omitted["omitted_subject_ids"]) == 1 and not omitted["omitted_ids_truncated"]


def test_all_four_reviewed_procedures_have_complete_selected_context(accepted, settings):
    source = SQL + AUTH + "def register(password):\n    return len(password) >= 8\n"
    values, _ = select(accepted({"app.py": source}), settings)
    assert len(values) == 1 and values[0]["source_subject"]["kind"] == "module"
    for rule in PROCEDURES[:4]:
        assert any(subjects(rule, item) for item in values)


def test_complete_ast_identity_changes_with_body_but_not_line_padding():
    first = next(item for item in parse_subjects(SQL) if item.kind == "function")
    moved = next(item for item in parse_subjects("\n" * 200 + SQL) if item.kind == "function")
    changed = next(item for item in parse_subjects(SQL.replace("SELECT id", "SELECT no"))
                   if item.kind == "function")
    assert first.ast_sha256 == moved.ast_sha256 != changed.ast_sha256
    selected, gaps = select_subjects(parse_subjects(SQL), SQL, max_lines=1)
    assert not selected and len(gaps) == 1


def test_empty_source_has_no_subject_not_an_invented_empty_module():
    assert parse_subjects("") == ()
    selected, gaps = select_subjects((), "", max_lines=120)
    assert not selected and gaps == ["no recognized subject for the four reviewed Python procedures"]


def test_configured_larger_line_bound_delivers_whole_function(accepted, settings):
    source = "def lookup(cursor):\n" + "    pass\n" * 140 + "    return cursor.execute('SELECT 1')\n"
    boundary = accepted({"app.py": source})
    values, gaps = select(boundary, settings)
    assert not values and any("max_source_lines" in gap for gap in gaps)
    boundary.resolver.max_source_lines = 500
    [item], gaps = select(boundary, replace(settings, max_source_lines=500))
    assert not gaps and not item["truncated"]
    assert item["reference"]["locator"]["lines"] == [1, 142]


@pytest.mark.parametrize("bound", ["lines", "characters"])
def test_http_module_context_respects_exact_existing_bounds(accepted, settings, bound):
    source = (AUTH + "# context\n" * 117 if bound == "lines"
              else AUTH + "#" + "x" * (16000 - len(AUTH) - 1))
    [item], gaps = select(accepted({"app.py": source}), settings)
    assert not gaps and item["source_subject"]["kind"] == "module"
    assert item["source_subject"]["outside_lines"] == 0 and not item["truncated"]
    exceeded = source + ("# context\n" if bound == "lines" else "x")
    [fallback], gaps = select(accepted({"app.py": exceeded}), settings)
    assert fallback["source_subject"]["kind"] == "function" and not fallback["truncated"]
    assert fallback["excerpt"] == AUTH.rstrip("\n")
    assert any("<module>: complete subject exceeds" in gap for gap in gaps)


def test_module_context_deduplicates_indexed_routes_within_evidence_budget(accepted, settings):
    source = AUTH + "\n" + AUTH.replace("records", "other") + "\n" + SQL
    boundary = accepted({"app.py": source}, hints=(("app.py", 5, 7),))
    [item], gaps = select(boundary, replace(settings, max_evidence_per_component=1))
    assert not gaps and item["source_subject"]["kind"] == "module"
    assert len(subjects(PROCEDURES[2], item)) == len(subjects(PROCEDURES[3], item)) == 2
    assert len(subjects(PROCEDURES[0], item)) == 1


# ----------------------------------------------------------------------------------------------------
# T-5013: C and C++ subjects through the same binder, selection bounds and acceptance as Python.

C_SERVER = (
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "\n"
    "// Serves a template named by the request.\n"
    "long serve_file(const char *name, char *out, size_t cap) {\n"
    "  char path[512];\n"
    "  snprintf(path, sizeof(path), \"/var/lib/smoke/%s\", name);\n"
    "  FILE *file = fopen(path, \"rb\");\n"
    "  if (file == NULL) {\n"
    "    return -1;\n"
    "  }\n"
    "  size_t n = fread(out, 1, cap, file);\n"
    "  fclose(file);\n"
    "  return (long)n;\n"
    "}\n"
    "\n"
    "int run_tool(const char *name) {\n"
    "  char cmd[640];\n"
    "  snprintf(cmd, sizeof(cmd), \"/usr/libexec/report %s\", name);\n"
    "  FILE *pipe = popen(cmd, \"r\");\n"
    "  if (pipe == NULL) {\n"
    "    return -1;\n"
    "  }\n"
    "  return pclose(pipe);\n"
    "}\n"
    "\n"
    "static int helper(int x) {\n"
    "  return x * 2;\n"
    "}\n"
)
C_FILES = {"src/request.c": "C", "src/request.cpp": "C++", "src/cache.h": "C/C++"}


def c_rule(control: str):
    return next(rule for rule in PROCEDURES if rule.control == control and rule.language == "c-cpp")


@pytest.mark.parametrize("path", sorted(C_FILES))
def test_c_sources_are_supported_and_yield_complete_function_subjects(accepted, settings, path):
    boundary = accepted({path: C_SERVER}, languages={path: C_FILES[path]})
    values, gaps = select(boundary, settings)
    assert not gaps
    assert [(item["source_subject"]["name"], item["reference"]["locator"]["lines"]) for item in values] == [
        ("serve_file", [5, 15]), ("run_tool", [17, 25])]
    for item in values:
        assert item["source_subject"]["complete"] and item["source_subject"]["language"] == "c-cpp"
        assert item["source_subject"]["rule"] == "owasp-complete-source-subjects/2"
        assert not item["truncated"] and item["source_subject"]["kind"] == "function"
        assert boundary.resolver.resolve(item["reference"], component_id="api") == {
            key: value for key, value in item.items() if key != "component_id"}
    serve_file, run_tool = values
    assert serve_file["source_subject"]["recognisers"] == {
        "c_error_path/1": [10], "c_file_path/1": [8], "c_input_entry/1": [12]}
    assert serve_file["source_subject"]["entries"] == [12]
    assert run_tool["source_subject"]["recognisers"] == {"c_command_sink/1": [20], "c_error_path/1": [22]}
    assert any("18 file lines outside subject" in gap for gap in serve_file["limitations"])


def test_c_sites_bind_the_procedure_family_to_the_complete_function(accepted, settings):
    boundary = accepted({"src/request.c": C_SERVER}, languages=C_FILES)
    serve_file, run_tool = select(boundary, settings)[0]
    [site] = subjects(c_rule("V5.3.2"), serve_file)
    assert subjects(c_rule("V5.3.2"), run_tool) == []
    [command] = subjects(c_rule("V1.2.5"), run_tool)
    assert subjects(c_rule("V1.2.5"), serve_file) == [] and site != command
    # The same function excerpt is the subject of every family it carries; identities differ per procedure.
    assert subjects(c_rule("V16.5.1"), serve_file) and subjects(c_rule("V16.5.1"), serve_file) != [site]
    # Python procedures never read C source and C procedures never read Python source.
    assert subjects(PROCEDURES[0], serve_file) == []
    python = accepted({"app.py": SQL})
    [query] = select(python, settings)[0]
    assert subjects(c_rule("V1.2.5"), query) == []


def test_c_obligation_names_entry_and_sink_lines_in_file_coordinates(accepted, settings):
    boundary = accepted({"src/request.c": "// banner\n" * 100 + C_SERVER}, languages=C_FILES)
    serve_file, _ = select(boundary, settings)[0]
    rule = c_rule("V5.3.2")
    control = {"family": rule.family, "version": rule.version, "id": rule.control}
    row = {"row_id": "r", "control_identity": f"{rule.family}:{rule.version}:{rule.control}",
           "component_id": "api", "run_id": "unit-run", "target_id": serve_file["reference"]["target_snapshot"],
           "evidence_mode": "static_source"}
    obligation, coverage = instantiate(control, row, [serve_file], max_subjects=8)
    assert obligation["supported"] and not coverage["supported"]
    assert "118 file lines outside subject remain unassessed" in coverage["reason"]
    subject = obligation["subject"]
    assert subject["name"] == "file path in serve_file" and subject["language"] == "c-cpp"
    assert subject["locator"]["lines"] == [105, 115] and subject["locator"]["columns"][0] == 0
    assert subject["sites"] == {"recognised_lines": [108], "entry_lines": [112], "recogniser": "c_file_path/1"}
    assert obligation["procedure"]["language"] == "c-cpp"


@pytest.mark.parametrize("outcome", ["satisfied", "not_satisfied"])
def test_c_subject_acceptance_rebinds_the_complete_function(accepted, settings, outcome):
    from appsec_review.owasp_workbench.assessment import accept_obligations
    boundary = accepted({"src/request.c": C_SERVER}, languages=C_FILES)
    serve_file, run_tool = select(boundary, settings)[0]
    rule = c_rule("V1.2.5")
    control = {"family": rule.family, "version": rule.version, "id": rule.control}
    row = {"row_id": "r", "control_identity": f"{rule.family}:{rule.version}:{rule.control}",
           "component_id": "api", "run_id": "unit-run", "target_id": run_tool["reference"]["target_snapshot"],
           "evidence_mode": "static_source"}
    obligation, coverage = instantiate(control, row, [run_tool, serve_file], max_subjects=8)
    assert obligation["supported"] and not coverage["supported"]
    package = {"control": control, "component": {"component_id": "api"}, "proof_obligations": [obligation]}

    def proposal(reference):
        return {"obligations": [{
            "obligation_id": obligation["obligation_id"], "subject_id": obligation["subject_id"],
            "outcome": outcome, "rationale": "Bounded analyst assessment.",
            "supporting": [reference] if outcome == "satisfied" else [],
            "contradictory": [reference] if outcome == "not_satisfied" else [],
            "assumptions": [], "evidence_requests": [], "hypotheses": [], "limitations": []}]}

    [accepted_result] = accept_obligations(package, proposal(run_tool["reference"]), boundary.resolver)
    assert accepted_result["outcome"] == outcome and accepted_result["citation_checks"][0]["subject_binding"]
    [other] = accept_obligations(package, proposal(serve_file["reference"]), boundary.resolver)
    assert other["outcome"] == "cannot_verify" and not other["citation_checks"][0]["subject_binding"]


def test_c_subject_bounds_and_scanner_gaps_are_named(accepted, settings):
    long_function = "int f(const char *a) {\n" + "  (void)a;\n" * 130 + "  return system(a);\n}\n"
    boundary = accepted({"src/a.c": long_function, "src/b.c": "int g(void) {\n  return 0;\n", "src/c.c": "int h(void) { return 1; }\n"},
                        languages={"src/a.c": "C", "src/b.c": "C", "src/c.c": "C"})
    values, gaps = select(boundary, settings)
    assert not values
    assert any("src/a.c: f: complete subject exceeds max_source_lines; 1 subject omitted" in gap for gap in gaps)
    assert any("src/b.c: unbalanced braces after line 1; later definitions unscanned" in gap for gap in gaps)
    assert any("src/c.c: no recognized subject for the reviewed C/C++ recogniser families" in gap for gap in gaps)


def test_c_subject_cap_and_index_hints_order_functions(accepted, settings):
    source = C_SERVER + "\nint other(const char *a) {\n  return system(a);\n}\n"
    boundary = accepted({"src/request.c": source}, languages=C_FILES, hints=(("src/request.c", 31, 33),))
    [item], gaps = select(boundary, replace(settings, max_evidence_per_component=1))
    assert item["source_subject"]["name"] == "other"
    assert any("2 complete recognized subjects omitted" in gap for gap in gaps)
