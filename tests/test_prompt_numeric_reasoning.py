"""Numeric-reasoning lint for review-worker prompt fragments (``numeric-reasoning-guardrail/1``).

Language models reach correct conclusions through unsound reasoning about value ranges, loop
bounds, invariants, widening and joins (Mitchell et al., arXiv:2503.12686). Those facts must come
from deterministic tools, so a prompt fragment must not model or instruct inline range, bound,
wrap, or loop reasoning unless the same unit ties it to a cited tool fact or artifact.

Every ``*.md`` under ``pipeline/prompt-fragments`` is split into units: each list item with its
continuation lines, each non-list paragraph, and each heading. YAML front matter is skipped. A unit
is flagged when ``detect`` reports a numeric category and ``cites_tool_fact`` finds no anchor in
that same unit. Reviewed exceptions live in ``ALLOWLIST`` below, never as annotations in prompt
text, because prompt text reaches the model.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import NamedTuple

from appsec_review.review import numeric_reasoning


ROOT = Path(__file__).resolve().parents[1]
FRAGMENTS = ROOT / "pipeline" / "prompt-fragments"

_LIST_ITEM = re.compile(r"^(?P<indent>\s*)(?:[-*+]|\d+[.)])\s+")
_HEADING = re.compile(r"^\s{0,3}#{1,6}(?:\s|$)")
_FENCE = re.compile(r"^\s*(?:```|~~~)")


class Unit(NamedTuple):
    path: str
    line: int
    text: str


def normalize(text: str) -> str:
    """Collapse whitespace and drop list markers so a unit's identity survives re-wrapping."""
    lines = [_LIST_ITEM.sub("", line, count=1) for line in text.splitlines()]
    return " ".join(" ".join(lines).split())


def split_units(text: str) -> list[tuple[int, str]]:
    """Split markdown into ``(first_line_number, unit_text)`` lint units.

    A list item owns its indented or lazy continuation lines until a blank line, heading, fence, or
    the next list item. Consecutive non-list lines form a paragraph. Headings and fenced blocks are
    units of their own. Leading YAML front matter (``---`` ... ``---``) is skipped.
    """
    lines = text.split("\n")
    start = 0
    if lines and lines[0].strip() == "---":
        closing = next((index for index in range(1, len(lines)) if lines[index].strip() == "---"), None)
        if closing is not None:
            start = closing + 1
    units: list[tuple[int, str]] = []
    current: list[str] = []
    current_line = 0
    in_fence = False

    def flush() -> None:
        nonlocal current
        if current:
            units.append((current_line, "\n".join(current)))
        current = []

    for index in range(start, len(lines)):
        line = lines[index]
        number = index + 1
        if in_fence:
            current.append(line)
            if _FENCE.match(line):
                in_fence = False
                flush()
            continue
        if _FENCE.match(line):
            flush()
            current_line, current, in_fence = number, [line], True
            continue
        if not line.strip():
            flush()
            continue
        if _HEADING.match(line):
            flush()
            units.append((number, line))
            continue
        if _LIST_ITEM.match(line):
            flush()
            current_line, current = number, [line]
            continue
        if not current:
            current_line = number
        current.append(line)
    flush()
    return units


def fragment_paths() -> list[Path]:
    return sorted(FRAGMENTS.rglob("*.md"))


def all_units() -> list[Unit]:
    return [Unit(path.relative_to(FRAGMENTS).as_posix(), line, unit)
            for path in fragment_paths()
            for line, unit in split_units(path.read_text(encoding="utf-8"))]


def is_unanchored_numeric(text: str) -> bool:
    return bool(numeric_reasoning.detect(text)) and not numeric_reasoning.cites_tool_fact(text)


class Allowed(NamedTuple):
    path: str
    snippet: str
    reason: str


# Reviewed exceptions: knowledge-only persona or stack bullets that name a numeric weakness
# pattern, route it to another persona, or describe what a tool result must show, rather than
# modelling or instructing inline range, bound, wrap, or loop reasoning. ``snippet`` is a substring
# of the normalized unit text. Keep entries few; prefer anchoring the prompt text to a tool fact.
ALLOWLIST: tuple[Allowed, ...] = (
    Allowed("personas/business_logic_abuse.md", "integer wrap in totals",
            "Failure-mode bullet that names integer wrap among quantity-abuse patterns; it states no bound."),
    Allowed("personas/business_logic_abuse.md", "Integer overflow in native totals goes to `memory_safety_native`",
            "Hand-off that routes the weakness to another persona; it models no reasoning."),
    Allowed("personas/cryptography_data_protection.md", "PBKDF2 with modern iteration counts",
            "Detector misfire: a KDF work-factor parameter, not loop trip-count reasoning."),
    Allowed("personas/memory_safety_native.md", "Size arithmetic that wraps before allocation:",
            "Failure-mode bullet that names allocation-size wrap idioms; it states no bound."),
    Allowed("personas/memory_safety_native.md", "Off-by-one on terminators:",
            "Failure-mode bullet that names terminator off-by-one idioms; it states no bound."),
    Allowed("stacks/android.md", "parsing app or network data without bounds checks",
            "Pitfall that names missing bounds checks in native libraries; it states no bound."),
    Allowed("stacks/cpp_native_service.md", "there is no runtime bounds checking",
            "Runtime-model fact about the language, not reasoning about a value range."),
    Allowed("stacks/rust_service.md", "`CStr::from_ptr` on non-terminated data",
            "Detector misfire: NUL termination of C strings, not loop termination."),
    Allowed("stacks/rust_service.md", "integer overflow in debug builds",
            "Pitfall that names panic sources reachable from requests; it states no bound."),
    Allowed("stacks/rust_service.md", "Release builds wrap integer overflow silently",
            "Language-semantics fact that names the wrap pattern and the checked idiom; it states no bound."),
    Allowed("stacks/wasm.md", "bounds-checked containers",
            "Names a source-language safety mechanism carried into the module; it states no bound."),
)


def allowlist_matches(entry: Allowed, unit: Unit) -> bool:
    return unit.path == entry.path and normalize(entry.snippet) in normalize(unit.text)


def _flagged() -> list[Unit]:
    return [unit for unit in all_units() if is_unanchored_numeric(unit.text)]


def test_fragments_exist() -> None:
    paths = {path.relative_to(FRAGMENTS).as_posix() for path in fragment_paths()}
    assert "governing-rules.md" in paths
    assert {path.split("/", 1)[0] for path in paths if "/" in path} >= {"roles", "personas", "stacks"}


def test_prompt_fragments_cite_a_tool_fact_for_numeric_reasoning() -> None:
    problems = []
    for unit in _flagged():
        if any(allowlist_matches(entry, unit) for entry in ALLOWLIST):
            continue
        categories = ", ".join(numeric_reasoning.detect(unit.text))
        problems.append(f"{unit.path}:{unit.line} [{categories}] {normalize(unit.text)!r}")
    assert not problems, (
        f"{numeric_reasoning.RULE}: numeric range, bound, wrap, or loop reasoning in a prompt fragment "
        "must cite a tool fact (R/G/P/M/C label) or a tool artifact in the same unit:\n" + "\n".join(problems))


def test_allowlist_entries_are_reasoned_and_unique() -> None:
    keys = [(entry.path, normalize(entry.snippet)) for entry in ALLOWLIST]
    assert len(keys) == len(set(keys)), "duplicate allowlist entries"
    for entry in ALLOWLIST:
        assert entry.reason.strip(), f"{entry.path}: allowlist entry needs a reason"
        assert normalize(entry.snippet), f"{entry.path}: allowlist entry needs a snippet"
        assert (FRAGMENTS / entry.path).is_file(), f"{entry.path}: no such fragment"


def test_allowlist_has_no_stale_entries() -> None:
    flagged = _flagged()
    stale = []
    for entry in ALLOWLIST:
        matched = [unit for unit in flagged if allowlist_matches(entry, unit)]
        if len(matched) != 1:
            stale.append(f"{entry.path}: {entry.snippet!r} matches {len(matched)} flagged units")
    assert not stale, "allowlist entries must match exactly one flagged unit:\n" + "\n".join(stale)


def test_lint_flags_unanchored_and_accepts_anchored_reasoning() -> None:
    assert is_unanchored_numeric("- the length cannot overflow because it is checked above")
    assert not is_unanchored_numeric("- G1 shows len <= 64, so the copy cannot overflow")
    assert not is_unanchored_numeric("- The handler logs the request path.")


def test_anchor_must_share_the_unit() -> None:
    text = "\n".join((
        "Rely on G1 for the header length.",
        "",
        "- The length cannot overflow because it is checked above.",
        "- R1 shows the index stays in range for the table.",
    ))
    flagged = [unit for _, unit in split_units(text) if is_unanchored_numeric(unit)]
    assert flagged == ["- The length cannot overflow because it is checked above."]


def test_splitter_skips_front_matter_and_keeps_continuations() -> None:
    text = "\n".join((
        "---",
        "id: example",
        "covers: [\"integer overflow\"]",
        "---",
        "# Title",
        "",
        "## Section",
        "Intro line one",
        "continues here.",
        "- First item",
        "  continues indented",
        "lazily continues",
        "- Second item",
        "  - Nested item",
        "",
        "Closing paragraph.",
    ))
    assert split_units(text) == [
        (5, "# Title"),
        (7, "## Section"),
        (8, "Intro line one\ncontinues here."),
        (10, "- First item\n  continues indented\nlazily continues"),
        (13, "- Second item"),
        (14, "  - Nested item"),
        (16, "Closing paragraph."),
    ]
    assert normalize("- First item\n  continues   indented") == "First item continues indented"
    fenced = "Intro.\n```json\n{\"a\": 1}\n\n{\"b\": 2}\n```\n- After."
    assert split_units(fenced) == [(1, "Intro."), (2, "```json\n{\"a\": 1}\n\n{\"b\": 2}\n```"), (7, "- After.")]


def test_allowlist_matching_is_path_and_unit_scoped() -> None:
    entry = Allowed("stacks/example.md", "integer overflow in totals", "names a pattern")
    unit = Unit("stacks/example.md", 3, "- Integer overflow in\n  totals goes elsewhere.")
    assert not allowlist_matches(entry, unit)
    entry = Allowed("stacks/example.md", "Integer overflow in totals", "names a pattern")
    assert allowlist_matches(entry, unit)
    assert not allowlist_matches(entry, unit._replace(path="stacks/other.md"))
