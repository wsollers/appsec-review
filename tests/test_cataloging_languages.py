from __future__ import annotations

from pathlib import Path

from appsec_review.jobs.cataloging import LANGUAGES, SOURCE_ECOSYSTEMS, inventory
from appsec_review.tool_inputs import C_CPP_SOURCE


def test_every_c_and_cpp_suffix_the_scanners_read_has_a_catalog_language() -> None:
    # Catalog-driven jobs (history symbols, Tree-sitter scopes) skip a file without a language, so a
    # header the scanners read must not reach them as "Other".
    assert C_CPP_SOURCE <= set(LANGUAGES)
    assert {SOURCE_ECOSYSTEMS[suffix] for suffix in C_CPP_SOURCE} == {"native"}


def test_cpp_headers_are_catalogued_as_cpp(tmp_path: Path) -> None:
    for name in ("api.hpp", "detail.hh", "inline.hxx", "impl.cxx", "legacy.h"):
        (tmp_path / name).write_text("int value;\n", encoding="utf-8")

    languages = {item["path"]: item["language"] for item in inventory(tmp_path)["files"]}
    assert languages == {"api.hpp": "C++", "detail.hh": "C++", "inline.hxx": "C++", "impl.cxx": "C++",
                         "legacy.h": "C/C++"}
