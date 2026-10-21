"""Design tokens shared by the LaTeX and HTML report renderers.

The palette, the kinds of box and the verdict badges are defined once, here. The HTML renderer writes
them into its stylesheet; ``palette_tex`` writes ``containers/report/latex/template/appsec-palette.tex``
from them, and ``tests/reporting`` fail when that committed file drifts. Nothing else in the package
spells a colour.

Every accent is a 700-level hue chosen for at least 4.5:1 contrast against white (chip text) and
against its own tint (the box body uses the neutral ink on the tint), so the boxes read in print,
greyscale and on screen. Colour is never the only signal: each kind also carries a text chip, and
the gap box is dashed.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class BoxKind(StrEnum):
    EVIDENCE = "evidence"          # what we pass in: lead, source, neighbourhood, build, tags
    REQUEST = "request"            # application -> model: task and tools
    RESPONSE = "response"          # model -> application: retrieve action, final answer
    RESULT = "result"              # retrieval result rows
    FEEDBACK = "feedback"          # application feedback: denials and tool errors
    CLAIM = "claim"                # red affirmation
    COUNTER = "counter"            # blue counter-claim
    VERIFICATION = "verification"  # blind verifier
    GAP = "gap"                    # gap or limitation
    PROVENANCE = "provenance"      # hashes and provenance


@dataclass(frozen=True, slots=True)
class BoxStyle:
    kind: BoxKind
    chip: str          # short label shown in the chip
    meaning: str       # one line for the legend
    accent: str        # hex without '#': bar, chip background
    fill: str          # hex without '#': box background
    dashed: bool = False


BOX_STYLES: tuple[BoxStyle, ...] = (
    BoxStyle(BoxKind.EVIDENCE, "EVIDENCE", "Package context passed to the model: lead, location, source excerpt, neighbourhood facts, build and tags.", "0F766E", "F0FDFA"),
    BoxStyle(BoxKind.REQUEST, "REQUEST", "Application to model: the task, the role and model, and the tools the model may call.", "334155", "F1F5F9"),
    BoxStyle(BoxKind.RESPONSE, "MODEL", "Model to application: a retrieve action or a final answer.", "6D28D9", "F5F3FF"),
    BoxStyle(BoxKind.RESULT, "RESULT", "Rows the application retrieved for the model, with status and counts.", "0369A1", "F0F9FF"),
    BoxStyle(BoxKind.FEEDBACK, "FEEDBACK", "Application feedback: a denied request or a tool error, returned to the model as data.", "B45309", "FFFBEB"),
    BoxStyle(BoxKind.CLAIM, "CLAIM", "Red affirmation: a proposed security claim with its evidence.", "B91C1C", "FEF2F2"),
    BoxStyle(BoxKind.COUNTER, "COUNTER", "Blue counter-claim: an attempt to falsify a claim.", "1D4ED8", "EFF6FF"),
    BoxStyle(BoxKind.VERIFICATION, "VERIFIER", "Blind verifier: an independent investigation of the claim.", "15803D", "F0FDF4"),
    BoxStyle(BoxKind.GAP, "GAP", "A named gap or limitation. A gap is never evidence that a target is clean.", "BE185D", "FDF2F8", dashed=True),
    BoxStyle(BoxKind.PROVENANCE, "PROVENANCE", "Hashes, receipts and other provenance. Neutral on purpose.", "52525B", "F4F4F5"),
)
STYLE_BY_KIND = {style.kind: style for style in BOX_STYLES}


@dataclass(frozen=True, slots=True)
class Verdict:
    state: str
    color: str         # hex without '#': badge background (white text)
    meaning: str


VERDICTS: tuple[Verdict, ...] = (
    Verdict("confirmed", "15803D", "Independently verified."),
    Verdict("supported", "4D7C0F", "Evidence supports the claim; not independently confirmed."),
    Verdict("contradicted", "B91C1C", "Evidence contradicts the claim."),
    Verdict("not_reachable", "475569", "The affected construct is not reachable."),
    Verdict("insufficient_evidence", "B45309", "Evidence does not decide the claim."),
    Verdict("unresolved", "6B7280", "No decision was reached; see the gaps."),
)
EXTRA_VERDICTS: tuple[Verdict, ...] = (
    Verdict("proposed", "6D28D9", "Proposed by red, not yet decided."),
    Verdict("not_exploitable_in_observed_configuration", "0369A1", "Not exploitable in the observed configuration."),
    Verdict("duplicate", "6B7280", "Duplicate of another claim."),
    Verdict("out_of_scope", "6B7280", "Outside the review scope."),
    Verdict("coverage_gap", "BE185D", "Blocked by a coverage gap."),
)
VERDICT_COLOR = {verdict.state: verdict.color for verdict in (*VERDICTS, *EXTRA_VERDICTS)}
UNKNOWN_VERDICT_COLOR = "6B7280"
SHORT_LABELS = {"not_exploitable_in_observed_configuration": "not exploitable", "insufficient_evidence": "insufficient evidence"}


def badge_text(state: str) -> str:
    """The words on a badge: the state, with underscores as spaces, long names shortened."""
    return SHORT_LABELS.get(state, state.replace("_", " "))
# Review and publication statuses reuse the verdict colours: complete reads as confirmed, degraded as a caution.
STATUS_TONES = {"COMPLETE": "confirmed", "DEGRADED": "insufficient_evidence", "EMPTY": "unresolved",
                "PUBLISHABLE": "confirmed", "PUBLISHABLE_WITH_LIMITATIONS": "insufficient_evidence"}

# Neutral base. Text colours are used on white and on every box tint.
NEUTRALS: tuple[tuple[str, str], ...] = (
    ("ink", "111827"),
    ("muted", "4B5563"),
    ("faint", "9CA3AF"),
    ("rule", "E5E7EB"),
    ("panel", "F9FAFB"),
    ("brand", "0F172A"),
)

FONT_SANS = "Inter"
FONT_MONO = "JetBrains Mono"


@dataclass(frozen=True, slots=True)
class Limits:
    """Display bounds. Every bounded field shows a visible 'n more, sha256 ...' note when it is cut."""

    text_chars: int = 700            # one prose field
    value_chars: int = 220           # one key/value or table cell
    code_lines: int = 28
    code_chars: int = 3000
    rows: int = 8                    # table rows or id-list entries
    ids: int = 6
    gaps_per_package: int = 8
    claims_per_package: int = 12
    cells_per_package: int = 6       # interchanges shown per package; the rest are summarised
    turns_per_cell: int = 14
    requests_per_turn: int = 5
    results_per_response: int = 4

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            if getattr(self, name) < 1:
                raise ValueError(f"limit {name} must be positive")


def palette_tex() -> str:
    """The LaTeX colour definitions, generated from the tokens above (deterministic)."""
    lines = ["% Generated by appsec_review.reporting.tokens.palette_tex; do not edit by hand.",
             "% Regenerate with: python -m appsec_review.reporting palette --write", ""]
    for name, value in NEUTRALS:
        lines.append(f"\\definecolor{{{name}}}{{HTML}}{{{value}}}")
    lines.append("")
    for style in BOX_STYLES:
        lines.append(f"\\definecolor{{{style.kind.value}-accent}}{{HTML}}{{{style.accent}}}")
        lines.append(f"\\definecolor{{{style.kind.value}-fill}}{{HTML}}{{{style.fill}}}")
    lines.append("")
    for verdict in (*VERDICTS, *EXTRA_VERDICTS):
        lines.append(f"\\definecolor{{verdict-{verdict.state.replace('_', '-')}}}{{HTML}}{{{verdict.color}}}")
    lines.append(f"\\definecolor{{verdict-unknown}}{{HTML}}{{{UNKNOWN_VERDICT_COLOR}}}")
    return "\n".join(lines) + "\n"
