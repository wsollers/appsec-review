"""Unit tests for bounded LCOV, Cobertura, JaCoCo, and LLVM coverage parsers."""

from __future__ import annotations

import json

import pytest

from appsec_review.jobs.job_test_coverage import CoverageTotals, parse_coverage
from appsec_review.jobs.job_test_coverage.parsers import _checked_int


def _totals(document, index: int = 0) -> dict[str, int | float | None]:
    return document.files[index].totals.as_dict()


def test_coverage_totals_enforce_non_negative_and_bounded_counts() -> None:
    with pytest.raises(ValueError, match="cannot be negative"):
        CoverageTotals(lines_total=-1)
    with pytest.raises(ValueError, match="exceeds total count"):
        CoverageTotals(lines_total=1, lines_covered=2)
    with pytest.raises(ValueError, match="exceeds total count"):
        CoverageTotals(branches_total=1, branches_covered=2)
    with pytest.raises(ValueError, match="exceeds total count"):
        CoverageTotals(functions_total=1, functions_covered=2)
    zero = CoverageTotals().as_dict()
    assert (zero["lines_rate"], zero["branches_rate"], zero["functions_rate"]) == (None, None, None)


@pytest.mark.parametrize(("raw", "match"), [
    (True, "not an integer"),
    ("abc", "not an integer"),
    (None, "not an integer"),
    ("-3", "cannot be negative"),
])
def test_checked_int_rejects_booleans_non_integers_and_negatives(raw: object, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        _checked_int(raw, "field")


def test_parses_lcov_line_branch_and_function_counts_and_merges_duplicate_files() -> None:
    document = parse_coverage(
        b"""TN:
SF:src/main.c
FN:1,main
FNDA:2,main
DA:1,2
DA:2,0
BRDA:2,0,0,1
BRDA:2,0,1,-
end_of_record
SF:src/main.c
DA:3,1
SF:src/other.c
DA:1,1
""",
        "lcov",
    )
    assert [item.source_path for item in document.files] == ["src/main.c", "src/other.c"]
    assert _totals(document, 0) == {
        "lines_total": 3,
        "lines_covered": 2,
        "branches_total": 2,
        "branches_covered": 1,
        "functions_total": 1,
        "functions_covered": 1,
        "lines_rate": 0.66666667,
        "branches_rate": 0.5,
        "functions_rate": 1.0,
    }


@pytest.mark.parametrize(("payload", "match"), [
    (b"\xff\xfe", "not valid UTF-8"),
    (b"SF:   \n", "empty source path"),
    (b"DA:1,1\n", "precedes SF"),
    (b"SF:a.c\nDA:1\n", "is malformed"),
    (b"BRDA:1,0,0,1\n", "precedes SF"),
    (b"SF:a.c\nBRDA:1,0,0\n", "is malformed"),
    (b"SF:a.c\nFN:1,\n", "is malformed"),
    (b"SF:a.c\nFNDA:1,\n", "is malformed"),
    (b"TN:empty\n", "no source records"),
])
def test_lcov_rejects_malformed_rows_and_empty_reports(payload: bytes, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        parse_coverage(payload, "lcov")


def test_parses_cobertura_counts_and_deduplicates_method_and_class_branch_lines() -> None:
    document = parse_coverage(
        b"""<?xml version="1.0"?>
<coverage><packages><package><classes><class name="Empty"/><class filename="pkg/a.py"><methods>
<method name="f"><lines><line number="1" hits="1"/></lines></method></methods><lines>
<line number="1" hits="1"/><line number="2" hits="0" branch="true"
condition-coverage="50% (1/2)"/><line number="3" hits="1"/></lines>
</class></classes></package></packages></coverage>""",
        "cobertura",
    )
    assert document.files[0].source_path == "pkg/a.py"
    assert _totals(document)["lines_covered"] == 2
    assert _totals(document)["branches_total"] == 2
    assert _totals(document)["functions_covered"] == 1

    line = b'<line number="5" hits="1" branch="true" condition-coverage="50% (2/4)"/>'
    deduped = parse_coverage(
        b"""<?xml version="1.0"?>
<coverage><packages><package><classes><class filename="Program.cs"><methods>
<method name="Main"><lines>"""
        + line
        + b"""</lines></method></methods><lines>"""
        + line
        + b"""</lines></class></classes></package></packages></coverage>""",
        "cobertura",
    )
    totals = _totals(deduped)
    assert (totals["lines_total"], totals["branches_total"], totals["branches_covered"]) == (1, 4, 2)


@pytest.mark.parametrize(("payload", "match"), [
    (b"<report/>", "root element is not coverage"),
    (b"<coverage><packages/></coverage>", "no class source records"),
    (b"<coverage><class filename='a.py'><line number='1' hits='1'/></class></coverage>", "node bound exceeded"),
])
def test_cobertura_rejects_wrong_root_empty_classes_and_node_bounds(payload: bytes, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        parse_coverage(payload, "cobertura", max_rows=2 if "bound" in match else 100)


def test_parses_jacoco_counts_with_and_without_package_prefix() -> None:
    document = parse_coverage(
        b"""<report name="fixture"><package name="org/acme">
<class name="Ignored"/><class name="org/acme/A" sourcefilename="A.java">
<counter type="METHOD" missed="1" covered="2"/></class>
<sourcefile name=""/><sourcefile name="A.java"><counter type="LINE" missed="2" covered="8"/>
<counter type="BRANCH" missed="1" covered="3"/></sourcefile></package>
<package name=""><sourcefile name="Root.java"><counter type="LINE" missed="0" covered="4"/></sourcefile></package>
</report>""",
        "jacoco",
    )
    by_path = {item.source_path: item.totals.as_dict() for item in document.files}
    assert by_path["org/acme/A.java"] == {
        "lines_total": 10,
        "lines_covered": 8,
        "branches_total": 4,
        "branches_covered": 3,
        "functions_total": 3,
        "functions_covered": 2,
        "lines_rate": 0.8,
        "branches_rate": 0.75,
        "functions_rate": 0.66666667,
    }
    assert by_path["Root.java"]["lines_covered"] == 4


@pytest.mark.parametrize(("payload", "match"), [
    (b"<coverage/>", "root element is not report"),
    (b"<report><package name='p'/></report>", "no sourcefile records"),
])
def test_jacoco_rejects_wrong_root_and_empty_sourcefiles(payload: bytes, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        parse_coverage(payload, "jacoco")


def test_parses_llvm_export_counts() -> None:
    document = parse_coverage(
        json.dumps(
            {
                "type": "llvm.coverage.json.export",
                "version": "2.0.1",
                "data": [
                    {
                        "files": [
                            {
                                "filename": "/checkout/src/a.cc",
                                "summary": {
                                    "lines": {"count": 7, "covered": 5},
                                    "branches": {"count": 6, "covered": 2},
                                    "functions": {"count": 2, "covered": 1},
                                },
                            }
                        ]
                    }
                ],
            }
        ).encode(),
        "llvm",
    )
    assert document.files[0].source_path == "/checkout/src/a.cc"
    assert _totals(document)["lines_rate"] == pytest.approx(5 / 7)


@pytest.mark.parametrize(("payload", "max_rows", "match"), [
    (b"x", 0, "row bound must be positive"),
    (b"x", 10, "unsupported coverage format: gcov"),
    (b"{", 10, "LLVM coverage JSON is malformed"),
    (b"[]", 10, "no data array"),
    (b'{"data": [{}]}', 10, "no files array"),
    (b'{"data": [{"files": [{"filename": "a", "summary": {}}, {"filename": "b", "summary": {}}]}]}',
     1, "file row bound exceeded"),
    (b'{"data": [{"files": [{}]}]}', 10, "file row is invalid"),
    (b'{"data": [{"files": [{"filename": "a", "summary": []}]}]}', 10, "file summary is invalid"),
    (b'{"data": [{"files": [{"filename": "a", "summary": {"lines": []}}]}]}', 10, "lines summary is invalid"),
    (b'{"data": [{"files": []}]}', 10, "contains no source records"),
    (b"SF:a.c\nDA:1,1\nend_of_record\n", 2, "LCOV row bound exceeded"),
    (b'<!DOCTYPE x [<!ENTITY y "z">]><coverage/>', 10, "declarations are not allowed"),
])
def test_parse_coverage_rejects_unsupported_malformed_and_bounded_inputs(
    payload: bytes, max_rows: int, match: str,
) -> None:
    fmt = "gcov" if "gcov" in match else "lcov" if "LCOV" in match else "cobertura" if "declarations" in match else "llvm"
    with pytest.raises(ValueError, match=match):
        parse_coverage(payload, fmt, max_rows=max_rows)



@pytest.mark.parametrize("format_name", ["lcov", "cobertura"])
def test_same_source_records_union_physical_lines(format_name: str) -> None:
    if format_name == "lcov":
        data = (
            b"TN:first\nSF:a.c\nDA:1,0\nDA:2,1\nFN:2,f\nFNDA:1,f\n"
            b"BRDA:2,0,0,1\nBRDA:2,0,1,-\nend_of_record\n"
            b"TN:second\nSF:a.c\nDA:1,1\nDA:2,0\nFN:2,f\nFNDA:0,f\n"
            b"BRDA:2,0,0,-\nBRDA:2,0,1,1\nend_of_record\n"
        )
    else:
        data = (
            b'<coverage><class name="A" filename="a.c"><line number="1" hits="0"/>'
            b'<line number="2" hits="1"/></class>'
            b'<class name="B" filename="a.c"><line number="1" hits="1"/>'
            b'<line number="2" hits="0"/></class></coverage>'
        )
    document = parse_coverage(data, format_name)
    assert len(document.files) == 1
    totals = _totals(document)
    assert (totals["lines_total"], totals["lines_covered"], totals["lines_rate"]) == (2, 2, 1.0)
    if format_name == "lcov":
        assert (totals["branches_total"], totals["branches_covered"]) == (2, 2)
        assert (totals["functions_total"], totals["functions_covered"]) == (1, 1)


def test_lcov_duplicate_hits_do_not_erase_coverage() -> None:
    document = parse_coverage(
        b"SF:a.c\nDA:1,1\nDA:1,0\nFN:1,f\nFNDA:1,f\nFNDA:0,f\n", "lcov"
    )
    assert (_totals(document)["lines_covered"], _totals(document)["functions_covered"]) == (1, 1)


@pytest.mark.parametrize("record", [b"FN:1,ghost", b"FNDA:1,ghost"])
def test_lcov_requires_source_for_function_records(record: bytes) -> None:
    with pytest.raises(ValueError, match="precedes SF"):
        parse_coverage(record + b"\nSF:a.c\nDA:1,1\n", "lcov")


@pytest.mark.parametrize("count", ["1.9", "-0.5", "1e309", "NaN", "true"])
def test_llvm_rejects_invalid_numeric_counts(count: str) -> None:
    payload = (
        '{"data":[{"files":[{"filename":"a.c","summary":{"lines":{"count":'
        + count + ',"covered":0}}}]}]}'
    ).encode()
    with pytest.raises(ValueError, match="not an integer"):
        parse_coverage(payload, "llvm")


@pytest.mark.parametrize("annotation", ["", "not-a-count", "50% (3/2)"],
                         ids=["missing", "malformed", "exceeds-total"])
def test_cobertura_rejects_unknown_or_invalid_branch_counts(annotation: str) -> None:
    payload = (
        '<coverage><class filename="a.py"><line number="1" hits="1" branch="true" '
        f'condition-coverage="{annotation}"/></class></coverage>'
    ).encode()
    with pytest.raises(ValueError, match="Cobertura.*branch"):
        parse_coverage(payload, "cobertura")


def test_cobertura_refuses_ambiguous_cross_class_branch_union() -> None:
    payload = (
        b'<coverage><class name="A" filename="a.py"><line number="1" hits="1" '
        b'branch="true" condition-coverage="50% (1/2)"/></class>'
        b'<class name="A" filename="a.py"><line number="1" hits="1" '
        b'branch="true" condition-coverage="50% (1/2)"/></class></coverage>'
    )
    with pytest.raises(ValueError, match="overlapping Cobertura branch"):
        parse_coverage(payload, "cobertura")



def test_cobertura_unions_identifiable_method_and_fully_covered_branch_records() -> None:
    first = (
        b'<class name="A" filename="a.py"><method name="f" signature="()"><line number="1" hits="0" '
        b'branch="true" condition-coverage="0% (0/2)"/></method></class>'
    )
    second = first.replace(b'hits="0"', b'hits="1"').replace(b'0% (0/2)', b'100% (2/2)')
    for records in (first + second, second + first):
        totals = _totals(parse_coverage(b"<coverage>" + records + b"</coverage>", "cobertura"))
        assert (totals["lines_total"], totals["lines_covered"]) == (1, 1)
        assert (totals["branches_total"], totals["branches_covered"]) == (2, 2)
        assert (totals["functions_total"], totals["functions_covered"]) == (1, 1)


@pytest.mark.parametrize("format_name", ["jacoco", "llvm"])
def test_duplicate_summary_only_source_records_are_not_added_as_unique_lines(format_name: str) -> None:
    if format_name == "jacoco":
        record = b'<sourcefile name="A.java"><counter type="LINE" missed="0" covered="1"/></sourcefile>'
        payload = b'<report><package name="p">' + record + record + b"</package></report>"
    else:
        record = {"filename": "a.c", "summary": {"lines": {"count": 1, "covered": 1}}}
        payload = json.dumps({"data": [{"files": [record, record]}]}).encode()
    with pytest.raises(ValueError, match="overlapping source summaries cannot be unioned"):
        parse_coverage(payload, format_name)



def test_cobertura_conflicting_method_and_class_branches_are_not_silently_maximized() -> None:
    payload = (
        b'<coverage><class filename="a.py"><method name="f"><line number="1" hits="1" '
        b'branch="true" condition-coverage="50% (1/2)"/></method><line number="1" hits="1" '
        b'branch="true" condition-coverage="50% (2/4)"/></class></coverage>'
    )
    with pytest.raises(ValueError, match="overlapping Cobertura branch annotations disagree"):
        parse_coverage(payload, "cobertura")



@pytest.mark.parametrize("header", [
    b'<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">',
    b"<!DOCTYPE report\n PUBLIC '-//JACOCO//DTD Report 1.1//EN'\n 'report.dtd'>",
    b'\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">',
], ids=["standard", "single-quotes-whitespace", "utf8-bom"])
def test_standard_jacoco_doctype_never_resolves_external_resources(header, monkeypatch):
    import builtins
    import io
    import socket
    import urllib.request

    payload = header + (
        b'<report name="fixture &amp; safe"><package name="p"><sourcefile name="A.java">'
        b'<counter type="LINE" missed="0" covered="1"/></sourcefile></package></report>')

    def no_resolution(*args, **kwargs):
        raise AssertionError("coverage XML attempted external resolution")

    with monkeypatch.context() as blocked:
        blocked.setattr(builtins, "open", no_resolution)
        blocked.setattr(io, "open", no_resolution)
        blocked.setattr(socket, "create_connection", no_resolution)
        blocked.setattr(urllib.request, "urlopen", no_resolution)
        document = parse_coverage(payload, "jacoco")
        assert document.files[0].source_path == "p/A.java"
        assert _totals(document)["lines_rate"] == 1.0
        with pytest.raises(ValueError, match="node bound exceeded"):
            parse_coverage(payload, "jacoco", max_rows=2)
        with pytest.raises(ValueError, match="declarations are not allowed"):
            parse_coverage(payload, "cobertura")


@pytest.mark.parametrize("format_name", ["jacoco", "cobertura"])
def test_utf16_cannot_hide_internal_entity_declarations(format_name):
    if format_name == "jacoco":
        text = (
            '<!DOCTYPE report [<!ENTITY count "1">]><report><package name="p">'
            '<sourcefile name="A.java"><counter type="LINE" missed="0" covered="&count;"/>'
            '</sourcefile></package></report>')
    else:
        text = (
            '<!DOCTYPE coverage [<!ENTITY count "1">]><coverage><class filename="a.c">'
            '<line number="1" hits="&count;"/></class></coverage>')
    with pytest.raises(ValueError, match="declarations are not allowed"):
        parse_coverage(text.encode("utf-16"), format_name)



@pytest.mark.parametrize("report", [b'<report name="&unresolved;"/>', b'<report>&unresolved;</report>'],
                         ids=["attribute", "text"])
def test_standard_jacoco_header_does_not_enable_unresolved_entity_expansion(report):
    payload = b'<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">' + report
    with pytest.raises(ValueError, match="coverage XML (declarations|is malformed)"):
        parse_coverage(payload, "jacoco")



@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
def test_jacoco_header_filter_preserves_utf16_and_rejects_unknown_attribute_entities(encoding):
    text = (
        '<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">'
        '<report name="fixture &amp; safe"><package name="p"><sourcefile name="A.java">'
        '<counter type="LINE" missed="0" covered="1"/></sourcefile></package></report>')
    bom = b"\xff\xfe" if encoding == "utf-16-le" else b"\xfe\xff"
    document = parse_coverage(bom + text.encode(encoding), "jacoco")
    assert _totals(document)["lines_rate"] == 1.0
    with pytest.raises(ValueError, match="coverage XML is malformed"):
        parse_coverage(bom + text.replace("&amp;", "&unresolved;").encode(encoding), "jacoco")



@pytest.mark.parametrize(("definition", "name"), [
    ("1,f", "f"),
    ("1,3,f", "f"),
    ("1,f<int,int>", "f<int,int>"),
    ("1,3,f<int,int>", "f<int,int>"),
    ("1,1,f", "f"),
    ("1,7", "7"),
    ("1,3,f", "3,f"),
], ids=["legacy", "range", "legacy-comma", "range-comma", "one-line", "numeric-name", "numeric-comma"])
def test_lcov_fn_optional_end_preserves_full_name(definition, name):
    payload = f"SF:a.c\nFN:{definition}\nFNDA:1,{name}\nDA:1,1\nend_of_record\n".encode()
    totals = _totals(parse_coverage(payload, "lcov"))
    assert (totals["functions_total"], totals["functions_covered"], totals["functions_rate"]) == (1, 1, 1.0)
    assert (totals["lines_total"], totals["lines_covered"]) == (1, 1)
    with pytest.raises(ValueError, match="LCOV row bound exceeded"):
        parse_coverage(payload, "lcov", max_rows=4)


def test_lcov_fn_versions_union_across_source_records():
    old = b"SF:a.c\nFN:1,f<int,int>\nFNDA:1,f<int,int>\nDA:1,1\nend_of_record\n"
    new = b"SF:a.c\nFN:1,3,f<int,int>\nFNDA:0,f<int,int>\nFN:4,6,g\nDA:1,0\nend_of_record\n"
    for payload in (old + new, new + old):
        totals = _totals(parse_coverage(payload, "lcov"))
        assert (totals["functions_total"], totals["functions_covered"], totals["functions_rate"]) == (2, 1, 0.5)
        assert (totals["lines_total"], totals["lines_covered"]) == (1, 1)
