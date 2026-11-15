"""Unit tests for the strict clangd YAML subset parser."""

from __future__ import annotations

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
    with pytest.raises(ValueError, match="double-quoted scalars are outside the clangd subset"):
        _scalar('"double"')

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
        ('--- !Symbol\nName: "double"\n...\n', "double-quoted scalars"),
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
