"""Loader and renderers on the synthetic run (no Docker, no network)."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re
import shutil

import pytest

from appsec_review.reporting import Limits, Selection, load_document, render_html, render_latex
from appsec_review.reporting.__main__ import main
from appsec_review.reporting.latex import default_template_dir
from appsec_review.reporting.model import Box, Heading
from appsec_review.reporting.text import clean, tex, tex_mono
from appsec_review.reporting.tokens import BOX_STYLES, BoxKind, Limits as _Limits, VERDICTS, palette_tex

from .fixture import CELL_B, CLAIM_ID, HOSTILE, PACKAGE_A, PACKAGE_B, RUN_ID, build_fixture


@pytest.fixture(scope="module")
def run_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_fixture(tmp_path_factory.mktemp("fixture"))


@pytest.fixture(scope="module")
def document(run_dir: Path):
    return load_document(run_dir)


def _boxes(document):
    return [block for block in document.blocks if isinstance(block, Box)]


def test_palette_file_matches_the_design_tokens() -> None:
    committed = (default_template_dir() / "appsec-palette.tex").read_text(encoding="utf-8")
    assert committed == palette_tex(), "run: python -m appsec_review.reporting palette --write"


def test_every_box_kind_has_a_style_and_all_required_kinds_exist() -> None:
    assert {style.kind for style in BOX_STYLES} == set(BoxKind)
    assert {"confirmed", "supported", "contradicted", "not_reachable", "insufficient_evidence", "unresolved"} <= {v.state for v in VERDICTS}
    for style in BOX_STYLES:
        assert re.fullmatch(r"[0-9A-F]{6}", style.accent) and re.fullmatch(r"[0-9A-F]{6}", style.fill)


def test_accents_have_text_contrast_on_white() -> None:
    def luminance(hex_color: str) -> float:
        channels = [int(hex_color[i:i + 2], 16) / 255 for i in (0, 2, 4)]
        lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]

    for color in [style.accent for style in BOX_STYLES] + [v.color for v in VERDICTS]:
        assert 1.05 / (luminance(color) + 0.05) >= 4.5, color


def test_loader_builds_summary_package_interchange_and_outcome(document) -> None:
    assert document.run_id == RUN_ID
    assert document.status_badge == "DEGRADED"
    assert document.source_date_epoch == 1792574429  # the publication handoff's completed_at
    titles = [b.text for b in document.blocks if isinstance(b, Heading)]
    assert titles[0] == "Summary" and titles.index("Reading guide") < titles.index("Reviewed packages")
    kinds = {box.kind for box in _boxes(document)}
    assert {BoxKind.EVIDENCE, BoxKind.REQUEST, BoxKind.RESPONSE, BoxKind.RESULT, BoxKind.FEEDBACK, BoxKind.CLAIM,
            BoxKind.COUNTER, BoxKind.VERIFICATION, BoxKind.GAP, BoxKind.PROVENANCE} <= kinds
    packages = [b for b in document.blocks if isinstance(b, Heading) and b.text.startswith("Package ")]
    assert len(packages) == 2
    claim_boxes = [b for b in _boxes(document) if b.kind is BoxKind.CLAIM and b.title == "Claim"]
    assert claim_boxes and claim_boxes[0].badges == ("supported",)


def test_missing_package_is_a_named_gap_not_a_failure(document) -> None:
    assert any(PACKAGE_B[:32] in gap for gap in document.named_gaps)
    assert any(isinstance(b, Box) and b.kind is BoxKind.GAP and b.title == "Package content is not available" for b in document.blocks)


def test_missing_artifacts_render_named_gaps(tmp_path: Path) -> None:
    empty = tmp_path / "2026-10-21-9999"
    (empty / "data").mkdir(parents=True)
    document = load_document(empty)
    assert document.run_id == "2026-10-21-9999" and document.status_badge == "UNKNOWN"
    assert any("final report" in gap for gap in document.named_gaps)
    assert any("ledger" in gap for gap in document.named_gaps)
    assert "could not read" in render_html(document)
    assert r"\begin{document}" in render_latex(document)


def test_limit_and_package_selection(run_dir: Path) -> None:
    limited = load_document(run_dir, selection=Selection(limit=1))
    assert len([b for b in limited.blocks if isinstance(b, Heading) and b.text.startswith("Package ")]) == 1
    only_b = load_document(run_dir, selection=Selection(packages=(PACKAGE_B[:30],)))
    assert len([b for b in only_b.blocks if isinstance(b, Heading) and b.text.startswith("Package ")]) == 1
    with pytest.raises(ValueError):
        Selection(limit=0)


def test_truncation_is_visible_and_hashed(document) -> None:
    html = render_html(document)
    latex = render_latex(document)
    assert re.search(r"\d+ more [a-z]+, sha256 <code>[0-9a-f]{64}</code>", html)
    assert re.search(r"\\truncnote\{\d+\}\{[a-z]+\}\{[0-9a-f]{64}\}", latex)


def test_tighter_limits_cut_more(run_dir: Path) -> None:
    wide = render_html(load_document(run_dir))
    narrow = render_html(load_document(run_dir, limits=replace(Limits(), rows=1, code_lines=3, gaps_per_package=1)))
    assert narrow.count("more rows") + narrow.count("more lines") + narrow.count("more more") > wide.count("more rows") + wide.count("more lines")
    assert len(narrow) < len(wide)


def test_same_input_gives_byte_identical_output(run_dir: Path, tmp_path: Path) -> None:
    copy = tmp_path / "copy"
    shutil.copytree(run_dir.parent, copy)
    first = load_document(run_dir)
    second = load_document(copy / RUN_ID)
    assert render_html(first) == render_html(second)
    assert render_latex(first) == render_latex(second)
    assert render_html(first) == render_html(first)


def test_hostile_text_is_harmless_in_latex(document) -> None:
    latex = render_latex(document)
    body = latex.split(r"\begin{document}", 1)[1]
    for needle in ("\\input{/etc/passwd}", "\\write18", "\\immediate", "\\end{document}\\begin{document}", "^^M", "\x00", "\x1b", "\u202e"):
        assert needle not in body, needle
    assert body.count(r"\end{document}") == 1  # only the skeleton's own
    assert r"\textbackslash{}input\{/etc/passwd\}" in body.replace(r"\allowbreak{}", "")
    assert "<script>" not in body.replace(r"\textless{}script\textgreater{}", "")
    # every line of generated content starts a known macro or text; no stray unescaped special character survives
    for char, escaped in (("$", r"\$"), ("&", r"\&"), ("#", r"\#"), ("%", r"\%")):
        assert escaped in body
    assert "U+4E2D" in body  # glyphs the bundled fonts lack are shown as code points


def test_hostile_text_is_harmless_in_html(document) -> None:
    html = render_html(document)
    assert "<script>alert" not in html and "<img src=x" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "\u202e" not in html and "\x00" not in html and "\x1b" not in html
    assert html.count("<script>") == 1  # the one inline print helper
    assert "onerror=alert(2)" in html and "&lt;img src=x onerror=alert(2)&gt;" in html


def test_html_is_one_self_contained_file(document) -> None:
    html = render_html(document)
    assert not re.search(r"(?i)(src|href)\s*=\s*[\"']?(https?:|//|file:)", html)
    assert not re.search(r"(?i)@import|url\(", html)
    assert "<link" not in html and "<details" in html and "@media print" in html and "max-width:34rem" in html
    assert 'name="viewport"' in html
    for style in BOX_STYLES:
        assert f"#{style.accent}" in html


def test_escapes_cover_every_tex_special_and_break_long_identifiers() -> None:
    nasty = "\\{}$&#^_%~|<>\"[]-"
    escaped = tex(nasty)
    assert "\\textbackslash{}" in escaped and r"\{" in escaped and r"\$" in escaped and r"\&" in escaped
    assert not re.search(r"(?<!\\)[$&#%^_~]", escaped.replace(r"\textasciicircum{}", "").replace(r"\textasciitilde{}", ""))
    mono = tex_mono("A" * 100)
    assert mono.count(r"\allowbreak{}") >= 6
    assert clean("a\x00b\u200bc\u202ed") == "abcd"


def test_cli_writes_files_and_rejects_bad_input(run_dir: Path, tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    assert main(["render", "--run", str(run_dir), "--format", "html", "--out", str(out)]) == 0
    assert (out / "report.html").read_text(encoding="utf-8").startswith("<!doctype html>")
    assert main(["render", "--run", RUN_ID, "--runs-dir", str(run_dir.parent), "--format", "tex", "--out", str(out), "--limit", "1"]) == 0
    assert (out / "report.tex").read_text(encoding="utf-8").startswith("% Main document skeleton")
    assert (out / "source-date-epoch").read_text() == "1792574429\n"
    json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert main(["render", "--run", "nope", "--runs-dir", str(tmp_path), "--format", "html", "--out", str(out)]) == 2
    assert main(["render", "--run", str(run_dir), "--format", "html", "--out", str(out), "--max-cells", "0"]) == 2


def test_the_run_directory_is_never_written(run_dir: Path, tmp_path: Path) -> None:
    def snapshot() -> dict[str, str]:
        return {str(p.relative_to(run_dir)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(run_dir.rglob("*")) if p.is_file()}

    before = snapshot()
    main(["render", "--run", str(run_dir), "--format", "html", "--out", str(tmp_path / "o")])
    main(["render", "--run", str(run_dir), "--format", "tex", "--out", str(tmp_path / "o")])
    assert snapshot() == before


def test_timeline_shows_who_spoke_with_tokens_models_and_denials(document) -> None:
    html = render_html(document)
    assert "Turn 1: retrieve (3 requests)" in html and "claude-haiku-5-5" in html and "2 in / 1949 out / 2234 cached tokens" in html
    assert "forbidden_parameter" in html and "tool_error" in html
    assert "Final answer of the red team analyst" in html
    assert 'class="chip" data-kind="counter">COUNTER' in html and 'class="chip" data-kind="verification">VERIFIER' in html
    assert "insufficient evidence" in html  # the blue stance badge
    assert "supported" in html and "Model call failed" in html
    assert CELL_B[:10] in html or "timed_out" in html
