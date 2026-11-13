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
    boundary = accepted({"nested.py": source})
    [item], gaps = select(boundary, settings)
    assert not gaps and not item["truncated"]
    assert item["reference"]["locator"]["lines"] == [3, 8]
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
    assert len(values) == 3
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
