"""Closed front matter, fixed sections, and content validation for guidance fragments.

Persona and stack-profile files are knowledge only. They carry no authority, tools, budgets,
severities, claim states, confirmation language, or output fields; the validator rejects any of
these before a fragment can reach a guidance bundle. Task prompts use a smaller front matter and
a lighter validator because they legitimately reference the role's tool allowlist.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from appsec_review.review import models as _models
from appsec_review.review.models import ClaimState, Predicate, Role

PERSONA_SECTIONS = (
    "Viewpoint", "Coverage", "Likely failure modes", "Effective controls", "False positives",
    "Evidence by predicate", "Hand-offs",
)
STACK_SECTIONS = (
    "Runtime and framework model", "Trust and interface layer", "Idiomatic security mechanisms",
    "Stack-specific pitfalls", "Build and deployment facts to check",
)


ROLE_SECTIONS = ("Responsibility", "Allowed outputs", "Prohibited decisions", "Independence", "Tools")
SECTIONS = {"persona": PERSONA_SECTIONS, "stack": STACK_SECTIONS}
FRONT_MATTER_KEYS = ("id", "version", "covers", "standards", "max_tokens")
TASK_FRONT_MATTER_KEYS = ("id", "version", "roles", "requests_tools", "max_tokens")
MAX_FRAGMENT_TOKENS = 4000
CHARS_PER_TOKEN = 4
COVERAGE_PLACEHOLDERS = ("", "GENERATED", "<!-- GENERATED -->")
TOOL_CATALOG = Path("docs") / "schemas" / "retrieval-mcp-tools.json"

_ID = re.compile(r"^[a-z][a-z0-9_]*$")
_COVER = re.compile(r"^[a-z][a-z0-9-]*:[a-z0-9.\-:]*\*?$")
_HEADING = re.compile(r"^##\s+(.+?)\s*$")


class GuidanceError(ValueError):
    """A guidance fragment, registry, or assembly violates the closed guidance contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GuidanceError(message)


def estimate_tokens(text: str) -> int:
    """Deterministic approximation: one token per four characters, rounded up."""
    return math.ceil(len(text) / CHARS_PER_TOKEN)


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_tool_names(repository_root: Path) -> frozenset[str]:
    """Return the closed retrieval tool names from the repository tool catalog."""
    path = Path(repository_root) / TOOL_CATALOG
    _require(path.is_file(), f"retrieval tool catalog is unavailable: {TOOL_CATALOG.as_posix()}")
    document = json.loads(path.read_text(encoding="utf-8"))
    _require(document.get("schema") == "appsec-review/mcp-tool-catalog/1", "unsupported tool catalog")
    names = frozenset(str(tool["name"]) for tool in document.get("tools", ()))
    _require(bool(names) and all(_ID.fullmatch(name) for name in names), "tool catalog names are invalid")
    return names


# ---------------------------------------------------------------------------------------------
# Front matter

def _parse_value(key: str, raw: str) -> object:
    raw = raw.strip()
    if raw.startswith("["):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GuidanceError(f"front matter list is not a single-line JSON array: {key}") from exc
        _require(isinstance(value, list) and all(isinstance(item, str) and item for item in value),
                 f"front matter list must contain non-empty strings: {key}")
        _require(len(value) == len(set(value)), f"front matter list repeats a value: {key}")
        return tuple(value)
    if re.fullmatch(r"[0-9]+", raw):
        return int(raw)
    _require(bool(raw) and not raw.startswith(("{", '"', "'")), f"front matter value is invalid: {key}")
    return raw


def split_front_matter(text: str, keys: tuple[str, ...]) -> tuple[dict[str, object], str]:
    """Parse a closed ``key: value`` front matter block; values are words, integers, or JSON lists."""
    _require(text.startswith("---\n"), "fragment must start with a front matter block")
    end = text.find("\n---\n", 3)
    _require(end != -1, "front matter block is not terminated")
    values: dict[str, object] = {}
    for line in text[4:end].split("\n"):
        if not line.strip():
            continue
        match = re.fullmatch(r"([a-z_]+):\s*(.*)", line)
        _require(match is not None, f"front matter line is not 'key: value': {line!r}")
        key, raw = match.group(1), match.group(2)
        _require(key in keys, f"front matter key is not allowed: {key}")
        _require(key not in values, f"front matter key is repeated: {key}")
        values[key] = _parse_value(key, raw)
    missing = [key for key in keys if key not in values]
    _require(not missing, f"front matter is missing keys: {', '.join(missing)}")
    _require(isinstance(values["id"], str) and bool(_ID.fullmatch(str(values["id"]))),
             "front matter id must be a lower_snake_case word")
    _require(isinstance(values["version"], int) and int(values["version"]) >= 1,
             "front matter version must be a positive integer")
    budget = values["max_tokens"]
    _require(isinstance(budget, int) and 1 <= budget <= MAX_FRAGMENT_TOKENS,
             f"front matter max_tokens must be an integer from 1 to {MAX_FRAGMENT_TOKENS}")
    return values, text[end + len("\n---\n"):]


def split_sections(body: str, expected: tuple[str, ...]) -> dict[str, str]:
    """Split ``## Heading`` sections and require exactly ``expected`` in order."""
    names: list[str] = []
    chunks: dict[str, list[str]] = {}
    preamble: list[str] = []
    for line in body.split("\n"):
        match = _HEADING.match(line)
        if match is not None:
            name = match.group(1)
            _require(name not in chunks, f"section is repeated: {name}")
            names.append(name)
            chunks[name] = []
            continue
        _require(not re.match(r"^#\s", line), "fragment may not contain a top-level heading")
        (chunks[names[-1]] if names else preamble).append(line)
    _require(not "".join(preamble).strip(), "fragment has text before its first section")
    extra = [name for name in names if name not in expected]
    missing = [name for name in expected if name not in chunks]
    _require(not extra, f"fragment has extra sections: {', '.join(extra)}")
    _require(not missing, f"fragment is missing sections: {', '.join(missing)}")
    _require(tuple(names) == expected, "fragment sections are out of order")
    return {name: "\n".join(chunks[name]).strip() for name in expected}


# ---------------------------------------------------------------------------------------------
# Content validation

_OUTPUT_FIELDS = sorted({
    name for record in (_models.Claim, _models.CellRecord, _models.EvidenceRelation, _models.Gap)
    for name in record.__dataclass_fields__  # type: ignore[attr-defined]
})
_PREDICATES = frozenset(member.value for member in Predicate)
_STATE_WORDS = sorted(member.value for member in ClaimState)
_ROLE_WORDS = sorted(member.value for member in Role)


def _word(names: Iterable[str]) -> str:
    return "|".join(re.escape(name) for name in sorted(names, key=lambda item: (-len(item), item)))


def _tool_patterns(tools: Iterable[str]) -> list[re.Pattern[str]]:
    tools = sorted(set(tools))
    underscored = [name for name in tools if "_" in name]
    patterns = [re.compile(rf"`\s*(?:{_word(tools)})\s*(?:\([^`]*\))?`"),
                re.compile(rf"\b(?:{_word(tools)})\("),
                re.compile(r"\bmcp\b", re.IGNORECASE),
                re.compile(r"\btool[- ](?:calls?|use|allowlist|access)\b", re.IGNORECASE)]
    if underscored:
        patterns.append(re.compile(rf"\b(?:{_word(underscored)})\b"))
    return patterns


_BUDGET = [
    re.compile(r"\bbudgets?\b", re.IGNORECASE),
    re.compile(r"\bmax_[a-z_]+\b", re.IGNORECASE),
    re.compile(r"\b(?:token|query|queries|turn|retrieval|model)[- ](?:budget|cap|caps|limit|limits|count)\b",
               re.IGNORECASE),
    re.compile(r"\bmodel turns?\b", re.IGNORECASE),
]
_SEVERITY = [
    re.compile(r"\bseverit(?:y|ies)\b", re.IGNORECASE),
    re.compile(r"\b(?:cvss|ssvc)\b", re.IGNORECASE),
    re.compile(r"\b(?:critical|high|medium|low|informational)[- ]"
               r"(?:severity|risk|rated|rating|impact|priority)\b", re.IGNORECASE),
    re.compile(r"\bship[- ]blocking\b", re.IGNORECASE),
]
_CLAIM_STATE = [
    re.compile(rf"`\s*(?:{_word(_STATE_WORDS)})\s*`", re.IGNORECASE),
    re.compile(rf"\b(?:{_word([name for name in _STATE_WORDS if '_' in name])})\b", re.IGNORECASE),
    re.compile(r"\bclaim[- ]states?\b", re.IGNORECASE),
    re.compile(r"\bcontradicted\b", re.IGNORECASE),
    re.compile(r"\b(?:mark|label|set|classif|report|declare)\w*\s+(?:\w+\s+){0,3}?as\s+"
               r"(?:proposed|supported|contradicted|duplicate|out of scope|not reachable)\b", re.IGNORECASE),
]
_CONFIRM = [re.compile(r"confirm", re.IGNORECASE)]
_OUTPUT = [
    re.compile(rf"\b(?:{_word([name for name in _OUTPUT_FIELDS if '_' in name])})\b"),
    re.compile(rf"`\s*(?:{_word(_OUTPUT_FIELDS)})\s*`"),
    re.compile(r"\boutput[- ]fields?\b", re.IGNORECASE),
    re.compile(r"\b(?:return|respond|emit|output)\w*\s+(?:only\s+)?(?:with\s+)?(?:an?\s+|the\s+)?"
               r"(?:json|object|field|fields|schema)\b", re.IGNORECASE),
]
_AUTHORITY = [
    re.compile(r"\bauthorit(?:y|ies)\b", re.IGNORECASE),
    re.compile(r"\bignor\w*\s+(?:\w+\s+){0,3}?(?:rules|instructions|guidance|role|policy)\b", re.IGNORECASE),
    re.compile(r"\boverrid\w*\s+(?:\w+\s+){0,2}?(?:role|rules|instructions|guidance|policy|governing)\b",
               re.IGNORECASE),
    re.compile(r"\byou\s+(?:may|must|are\s+(?:allowed|permitted|authori[sz]ed)|can\s+now)\b", re.IGNORECASE),
    re.compile(r"\bwiden\w*\b", re.IGNORECASE),
    re.compile(r"\badjudicat\w*", re.IGNORECASE),
    re.compile(r"\bverdicts?\b", re.IGNORECASE),
    re.compile(r"\breadable[- ]roots?\b", re.IGNORECASE),
    re.compile(rf"\b(?:act|acting|behave)\s+as\s+(?:an?\s+|the\s+)?(?:{_word(_ROLE_WORDS)})\b", re.IGNORECASE),
]

FRAGMENT_RULES: tuple[tuple[str, list[re.Pattern[str]]], ...] = (
    ("budget", _BUDGET),
    ("severity", _SEVERITY),
    ("claim state", _CLAIM_STATE),
    ("confirmation", _CONFIRM),
    ("output field", _OUTPUT),
    ("authority", _AUTHORITY),
)
TASK_RULES: tuple[tuple[str, list[re.Pattern[str]]], ...] = (
    ("budget", _BUDGET),
    ("authority", _AUTHORITY),
)


def _scan(label: str, text: str, rules: Iterable[tuple[str, list[re.Pattern[str]]]]) -> None:
    for name, patterns in rules:
        for pattern in patterns:
            match = pattern.search(text)
            _require(match is None, f"{label} contains forbidden {name} text: {match.group(0)!r}" if match else "")


def tool_mentions(text: str, tools: Iterable[str]) -> list[str]:
    """Return every catalog tool the text names (any form the tool validator recognizes)."""
    found: set[str] = set()
    for name in sorted(set(tools)):
        word = re.escape(name)
        forms = [rf"`\s*{word}\s*(?:\([^`]*\))?`", rf"\b{word}\("]
        if "_" in name:
            forms.append(rf"\b{word}\b")
        if any(re.search(form, text) for form in forms):
            found.add(name)
    return sorted(found)


def validate_fragment_text(label: str, text: str, tools: Iterable[str]) -> None:
    """Reject persona or stack text that names tools, budgets, severities, claim states,
    confirmation, output fields, or authority."""
    for pattern in _tool_patterns(tools):
        match = pattern.search(text)
        _require(match is None, f"{label} names a tool: {match.group(0)!r}" if match else "")
    _scan(label, text, FRAGMENT_RULES)


def validate_task_text(label: str, text: str, tools: Iterable[str], requested: Iterable[str]) -> None:
    """A task prompt may name only the tools it requests and may not set budgets or authority."""
    extra = sorted(set(tool_mentions(text, tools)) - set(requested))
    _require(not extra, f"{label} names a tool it does not request: {', '.join(extra)}")
    _require(re.search(r"\bmcp\b", text, re.IGNORECASE) is None, f"{label} names a tool transport")
    _scan(label, text, TASK_RULES)


_POLICY_LINE = re.compile(r"^\s*(?:[-*]\s+)?`?([a-z][a-z0-9]*(?:_[a-z0-9]+)+)`?\s*(?:=|:)\s*\S", re.MULTILINE)


def policy_keys(text: str) -> frozenset[str]:
    """snake_case ``key: value`` or ``key = value`` lines define policy keys; predicate names do not."""
    return frozenset(key for key in _POLICY_LINE.findall(text) if key not in _PREDICATES)


# ---------------------------------------------------------------------------------------------
# Parsed records

@dataclass(frozen=True, slots=True)
class Fragment:
    """A validated persona or stack profile."""

    kind: str
    id: str
    version: int
    covers: tuple[str, ...]
    standards: tuple[str, ...]
    max_tokens: int
    sections: Mapping[str, str]
    sha256: str


@dataclass(frozen=True, slots=True)
class TaskPrompt:
    id: str
    version: int
    roles: tuple[str, ...]
    requests_tools: tuple[str, ...]
    max_tokens: int
    text: str
    sha256: str


def parse_fragment(text: str, *, kind: str, tools: Iterable[str], expected_id: str | None = None) -> Fragment:
    """Parse and validate one persona (``kind='persona'``) or stack profile (``kind='stack'``)."""
    _require(kind in SECTIONS, f"unknown fragment kind: {kind}")
    values, body = split_front_matter(text, FRONT_MATTER_KEYS)
    fragment_id = str(values["id"])
    label = f"{kind} {fragment_id}"
    _require(expected_id is None or fragment_id == expected_id,
             f"{label} front matter id does not match its registry id {expected_id}")
    covers, standards = values["covers"], values["standards"]
    _require(isinstance(covers, tuple) and isinstance(standards, tuple),
             f"{label} covers and standards must be JSON lists")
    for pattern in covers:
        _require(bool(_COVER.fullmatch(pattern)) and "*" not in pattern[:-1],
                 f"{label} covers pattern is invalid (only a '*' suffix wildcard is allowed): {pattern}")
    for standard in standards:
        _require(bool(re.fullmatch(r"[a-z][a-z0-9-]*", standard)), f"{label} standard is invalid: {standard}")
    sections = split_sections(body, SECTIONS[kind])
    if kind == "persona":
        _require(sections["Coverage"] in COVERAGE_PLACEHOLDERS,
                 f"{label} Coverage section must be empty or the GENERATED placeholder")
    for name, content in sections.items():
        _require(bool(content) or (kind == "persona" and name == "Coverage"), f"{label} section is empty: {name}")
    _require(estimate_tokens(body) <= int(values["max_tokens"]),
             f"{label} exceeds its max_tokens ({estimate_tokens(body)} > {values['max_tokens']})")
    validate_fragment_text(label, body, tools)
    return Fragment(kind=kind, id=fragment_id, version=int(values["version"]), covers=tuple(covers),
                    standards=tuple(standards), max_tokens=int(values["max_tokens"]),
                    sections=dict(sections), sha256=text_sha256(text))


def parse_task(text: str, *, tools: Iterable[str], expected_id: str | None = None) -> TaskPrompt:
    values, body = split_front_matter(text, TASK_FRONT_MATTER_KEYS)
    task_id = str(values["id"])
    label = f"task {task_id}"
    _require(expected_id is None or task_id == expected_id,
             f"{label} front matter id does not match its registry id {expected_id}")
    roles, requested = values["roles"], values["requests_tools"]
    _require(isinstance(roles, tuple) and bool(roles) and set(roles) <= {member.value for member in Role},
             f"{label} roles must name inference roles")
    tools = frozenset(tools)
    _require(isinstance(requested, tuple) and set(requested) <= tools,
             f"{label} requests a tool outside the catalog")
    body = body.strip()
    _require(bool(body), f"{label} has no question")
    _require(estimate_tokens(body) <= int(values["max_tokens"]),
             f"{label} exceeds its max_tokens ({estimate_tokens(body)} > {values['max_tokens']})")
    validate_task_text(label, body, tools, requested)
    return TaskPrompt(id=task_id, version=int(values["version"]), roles=tuple(roles),
                      requests_tools=tuple(sorted(requested)), max_tokens=int(values["max_tokens"]),
                      text=body, sha256=text_sha256(text))


def parse_role_text(text: str, *, role_id: str, tools: Iterable[str]) -> dict[str, str]:
    """A role record file has fixed sections; its Tools section lists exactly the registry tools."""
    lines = text.strip().split("\n")
    _require(bool(lines) and lines[0].startswith("# Role: "), f"role {role_id} must start with '# Role: '")
    sections = split_sections("\n".join(lines[1:]), ROLE_SECTIONS)
    for name, content in sections.items():
        _require(bool(content), f"role {role_id} section is empty: {name}")
    listed = sorted(set(re.findall(r"`([a-z_]+)`", sections["Tools"])))
    expected = sorted(set(tools))
    if not expected:
        _require(not listed and sections["Tools"].strip().rstrip(".").lower() == "none",
                 f"role {role_id} Tools section must read 'None.' when its allowlist is empty")
    _require(listed == expected, f"role {role_id} Tools section does not match its registry allowlist")
    return sections
