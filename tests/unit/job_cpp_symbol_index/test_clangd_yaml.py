"""Unit tests for the strict clangd YAML subset parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.jobs.job_cpp_symbol_index.clangd_yaml import (
    Document,
    _block,
    _logical_lines,
    _quote_open,
    _scalar,
    iter_tagged,
    parse_documents,
)


SAMPLE_STREAM = """--- !Symbol
ID:              AAAAAAAAAAAAAAA1
Name:            main
Scope:           ''
SymInfo:
  Kind:            Function
  Lang:            C
EmptyKey:
NestedList:
- Item:          one
  Extra:         'quoted ''inner'''
- Item:          two
IndentedList:
  - Sub:         alpha
...
--- !Refs
ID:              AAAAAAAAAAAAAAA1
References:
  - Kind:        28
    Container:
      ID:        BBBBBBBBBBBBBBB2
...
--- !Empty
...
"""


def test_scalar_and_quote_open_cover_plain_single_escaped_and_invalid_forms() -> None:
    assert _scalar("  plain_value  ") == "plain_value"
    assert _scalar("''") == ""
    assert _scalar("'it''s ok'") == "it's ok"

    with pytest.raises(ValueError, match="unterminated single-quoted scalar"):
        _scalar("'")
    with pytest.raises(ValueError, match="unterminated single-quoted scalar"):
        _scalar("'unterminated")
    # Double-quoted scalars decode exactly the YAML 1.2 escape set; anything else is rejected.
    assert _scalar('"double"') == "double"
    assert _scalar('  "a\\nb \\"q\\" \\\\ \\t \\u00e9 \\x41 \\U0001F600"  ') == 'a\nb "q" \\ \t \u00e9 A \U0001F600'
    assert _scalar('""') == ""
    for bad, message in [
        ('"open', "unterminated double-quoted scalar"),
        ('"trailing backslash\\', "unterminated double-quoted scalar"),
        ('"x" y', "content after the closing double quote"),
        ('"\\q"', r"unsupported escape in double-quoted scalar: \\q"),
        ('"\\u12"', r"malformed \\u escape in double-quoted scalar"),
        ('"\\xZZ"', r"malformed \\x escape in double-quoted scalar"),
        ('"\\uD800"', "invalid code point in double-quoted scalar: U\\+D800"),
        ('"\\U00110000"', "invalid code point in double-quoted scalar: U\\+110000"),
    ]:
        with pytest.raises(ValueError, match=message):
            _scalar(bad)

    assert _quote_open("plain") is False
    assert _quote_open("'closed'") is False
    assert _quote_open("'escaped '' closed'") is False
    assert _quote_open("'still open") is True
    assert _quote_open("'escaped '' still open") is True


def test_logical_lines_folds_multiline_scalars_and_rejects_unterminated() -> None:
    folded = _logical_lines(
        [
            "",
            "  Doc: 'line one",
            "    it''s line two",
            "    end'",
            "  Plain: ok",
        ]
    )
    assert folded == [(2, "Doc: 'line one it''s line two end'"), (2, "Plain: ok")]

    # Multi-line scalar when pending line has no key-colon (exercising the else branch of joined.split)
    # cannot start via _logical_lines directly unless key had ': ', so verify '- key: value' prefix branch too:
    seq_folded = _logical_lines(["- Note: 'hello", "  world'"])
    assert seq_folded == [(0, "- Note: 'hello world'")]

    with pytest.raises(ValueError, match="unterminated multi-line scalar"):
        _logical_lines(["Doc: 'never closes", "  still open"])


def test_parse_documents_and_iter_tagged_handle_valid_cap_and_truncation() -> None:
    docs, truncated, capped = parse_documents(SAMPLE_STREAM, document_limit=10)
    assert truncated is False and capped is False
    assert [d.tag for d in docs] == ["Symbol", "Refs", "Empty"]
    assert docs[0].value["EmptyKey"] == ""
    assert docs[0].value["NestedList"] == [{"Item": "one", "Extra": "quoted 'inner'"}, {"Item": "two"}]
    assert docs[0].value["IndentedList"] == [{"Sub": "alpha"}]
    assert docs[2] == Document("Empty", {})
    assert len(list(iter_tagged(docs, "Symbol"))) == 1
    assert len(list(iter_tagged(docs, "Refs"))) == 1
    assert list(iter_tagged(docs, "Unknown")) == []

    # Blank lines outside documents are ignored; truncated tail and document_limit are reported cleanly.
    padded = "\n  \n" + SAMPLE_STREAM + "\n--- !Symbol\nID: ZZZ\n"
    docs_trunc, truncated2, capped2 = parse_documents(padded, document_limit=10)
    assert len(docs_trunc) == 3 and truncated2 is True and capped2 is False

    docs_cap, truncated3, capped3 = parse_documents(SAMPLE_STREAM, document_limit=2)
    assert len(docs_cap) == 2 and truncated3 is False and capped3 is True


@pytest.mark.parametrize(
    ("bad_yaml", "match"),
    [
        ("stray content\n", "content outside a document"),
        ("...\n", "document end without a start"),
        ("--- !Symbol\n--- !Refs\n...\n", "document started before the previous one ended"),
        ("--- NoBang\n...\n", "unexpected document tag"),
        ("--- !" + ("A" * 65) + "\n...\n", "unexpected document tag"),
        ('--- !Symbol\nName: "open\n...\n', "unterminated double-quoted scalar"),
        ('--- !Symbol\nName: "x" y\n...\n', "content after the closing double quote"),
        ('--- !Symbol\nName: "bad \\q"\n...\n', "unsupported escape in double-quoted scalar"),
        ("--- !Symbol\nID: a\nID: b\n...\n", "duplicate mapping key: ID"),
        ("--- !Symbol\nNoColonLine\n...\n", "expected a mapping key"),
        ("--- !Symbol\n: empty_key\n...\n", "expected a mapping key"),
        ("--- !Symbol\nspaced_key : val\n...\n", "expected a mapping key"),
        ("--- !Symbol\n  IndentedRoot: x\n...\n", "unexpected indentation"),
        ("--- !Symbol\n- TopSeq: x\n...\n", "malformed !Symbol document"),
        ("--- !Symbol\nKey: val\n- MixedSeq: x\n...\n", "malformed !Symbol document"),
        ("--- !Symbol\nItems:\n  - First: a\n      TooDeep: b\n...\n", "unexpected indentation"),
        (
            "--- !Symbol\nItems:\n  - First: a\n    - NestedDash: b\n...\n",
            "sequence item has inconsistent indentation",
        ),
    ],
)
def test_parse_documents_rejects_malformed_inputs(bad_yaml: str, match: str) -> None:
    assert callable(_block)
    with pytest.raises(ValueError, match=match):
        parse_documents(bad_yaml, document_limit=10)


CLANGD23_DOCUMENTATION = (
    Path(__file__).resolve().parents[2] / "fixtures" / "cpp_symbol_index" / "clangd23-documentation.yaml"
)


def test_clangd23_documentation_double_quoted_scalars_round_trip() -> None:
    """Run 2026-11-17-0003: clangd 23 writes ``Documentation`` as a double-quoted scalar with
    escapes; the parser used to reject it and the whole 6 MB index was discarded (0 symbols)."""
    text = CLANGD23_DOCUMENTATION.read_text(encoding="utf-8")
    assert text.count('Documentation:   "') == 3  # the fixture carries the real double-quoted form

    documents, truncated, capped = parse_documents(text, document_limit=10)
    assert (truncated, capped) == (False, False)
    symbols = list(iter_tagged(documents, "Symbol"))
    assert len(symbols) == 3
    assert [symbol["Name"] for symbol in symbols] == ["inflateReset2", "LZ4_compress_destSize", "cJSON_Minify"]

    zlib_doc = symbols[0]["Documentation"]
    assert zlib_doc.startswith("\n     This function is equivalent to inflateEnd followed by inflateInit,\n")
    assert "\n\n     inflateReset returns Z_OK if success" in zlib_doc
    assert zlib_doc.endswith("(such as zalloc or state being Z_NULL).")
    assert "\\" not in zlib_doc  # every ``\n`` escape became a newline

    lz4_doc = symbols[1]["Documentation"]
    assert 'note: acceleration parameter is fixed to "default".\n\n*srcSizePtr' in lz4_doc  # ``\"`` round-trips
    assert lz4_doc.count("\n") == 10

    cjson_doc = symbols[2]["Documentation"]
    # ``\\t`` in the stream is a literal backslash-t in the comment text, not a tab.
    assert "blank characters(such as ' ', '\\t', '\\r', '\\n') from strings.\nThe input pointer" in cjson_doc
    assert "\t" not in cjson_doc
    assert symbols[2]["IncludeHeaders"] == [
        {"Header": "file:///target/source/third_party/cjson/cJSON.h", "References": "1"}
    ]
    # Plain and single-quoted scalars beside the double-quoted one are unaffected.
    assert symbols[0]["Signature"] == "(z_streamp strm, int windowBits)"
    assert symbols[0]["ReturnType"] == "int"
