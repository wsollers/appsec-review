"""Content contract for review personas and stack profiles.

The files under ``pipeline/prompt-fragments/personas`` and ``pipeline/prompt-fragments/stacks`` are
knowledge-only guidance for inference review workers. This test parses them with a small local
parser, enforces the fixed section layout and size limits, rejects authority, tool, and claim
vocabulary, and checks that the personas partition the taxonomy's routing tags.
"""

from __future__ import annotations

import json
from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[1]
FRAGMENTS = ROOT / "pipeline" / "prompt-fragments"
TAXONOMY = ROOT / "data" / "reference" / "taxonomy"
TAXONOMY_DOC = ROOT / "docs" / "architecture" / "security-tag-taxonomy.md"

PERSONAS = (
    "memory_safety_native", "injection_interpreters", "parsing_deserialization",
    "authentication_session", "authorization_access_control", "cryptography_data_protection",
    "network_api_surface", "filesystem_resources", "business_logic_abuse", "build_supply_chain",
    "ci_cd_pipeline", "cloud_container_deployment", "mobile_platform", "generalist",
)
STACKS = (
    "cpp_rpc_service", "cpp_native_service", "c_systems_embedded", "jvm_service", "dotnet_service",
    "go_service", "rust_service", "python_service", "node_web", "php_web", "android", "ios", "wasm",
    "ci_pipeline", "iac_kubernetes", "generic",
)
PERSONA_SECTIONS = (
    "Viewpoint", "Coverage", "Likely failure modes", "Effective controls", "False positives",
    "Evidence by predicate", "Hand-offs",
)
STACK_SECTIONS = (
    "Runtime and framework model", "Trust and interface layer", "Idiomatic security mechanisms",
    "Stack-specific pitfalls", "Build and deployment facts to check",
)
PREDICATES = (
    "affected_construct", "attacker_input_control", "source_to_sink_reachability",
    "missing_or_ineffective_guard", "configuration_enables", "security_impact",
)
FRONT_MATTER_KEYS = ("id", "version", "covers", "standards", "max_tokens")
PARTITIONED_NAMESPACES = ("cwe", "func", "infra", "data")

# Whole-word, case-insensitive. Retrieval tool names, severity and claim-state vocabulary,
# confirmation, budgets, output field names, and authority-granting phrases.
FORBIDDEN = (
    r"search", r"find", r"read_excerpt", r"trace", r"resolve_evidence", r"coverage", r"query_\w*",
    r"critical", r"high", r"medium", r"low", r"severity",
    r"confirm", r"confirmed", r"confirmation", r"supported", r"contradicted", r"proposed",
    r"insufficient_evidence", r"not_reachable", r"not_exploitable_in_observed_configuration",
    r"duplicate", r"out_of_scope", r"coverage_gap", r"budget",
    r"claim_id", r"affected_entities", r"weakness_cwe", r"security_predicate", r"relation_id",
    r"entity_id", r"cell_id", r"package_id",
    r"you may", r"may decide", r"decide", r"mark as", r"you are allowed",
)
_FORBIDDEN = re.compile(r"(?<!\w)(?:" + "|".join(FORBIDDEN) + r")(?!\w)", re.IGNORECASE)
_TICKED_ID = re.compile(r"`([a-z][a-z0-9_]*)`")


def parse_fragment(path: Path) -> tuple[dict[str, object], list[tuple[str, str]]]:
    """Return ``(front_matter, [(section_title, body), ...])`` for one fragment file."""
    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    assert lines[0] == "---", f"{path.name}: front matter must open the file"
    end = lines.index("---", 1)
    front: dict[str, object] = {}
    for line in lines[1:end]:
        key, sep, value = line.partition(": ")
        assert sep and key in FRONT_MATTER_KEYS and key not in front, f"{path.name}: bad front matter line {line!r}"
        if key in ("covers", "standards"):
            parsed = json.loads(value)
            assert isinstance(parsed, list) and all(isinstance(item, str) for item in parsed), path.name
            front[key] = parsed
        elif key in ("version", "max_tokens"):
            assert re.fullmatch(r"[1-9][0-9]*", value), f"{path.name}: {key} must be a positive integer"
            front[key] = int(value)
        else:
            front[key] = value
    assert tuple(sorted(front)) == tuple(sorted(FRONT_MATTER_KEYS)), f"{path.name}: front matter keys"
    sections: list[tuple[str, str]] = []
    current: str | None = None
    body: list[str] = []
    for line in lines[end + 1:]:
        if line.startswith("## "):
            if current is not None:
                sections.append((current, "\n".join(body).strip()))
            current, body = line[3:].strip(), []
        else:
            assert current is not None or not line.strip(), f"{path.name}: text before first section"
            assert not line.startswith("# "), f"{path.name}: top-level heading in body"
            body.append(line)
    if current is not None:
        sections.append((current, "\n".join(body).strip()))
    return front, sections


def _load_vocabulary() -> dict[str, dict]:
    return json.loads((TAXONOMY / "vocabulary.json").read_text(encoding="utf-8"))["namespaces"]


def _universe(vocabulary: dict[str, dict]) -> list[str]:
    """Every enumerated cwe/func/infra/data tag the taxonomy names.

    ``cwe`` is an open pattern namespace, so its universe is every CWE tag named by the pinned
    taxonomy data files or the taxonomy design document.
    """
    tags: set[str] = set()
    for name in PARTITIONED_NAMESPACES:
        tags.update(vocabulary[name].get("terms", ()))
    sources = [*sorted(TAXONOMY.glob("*.json")), TAXONOMY_DOC]
    for source in sources:
        tags.update(f"cwe:{number}" for number in
                    re.findall(r"(?<![\w-])cwe:([1-9][0-9]{0,4})(?![\w])", source.read_text(encoding="utf-8")))
    return sorted(tags)


def _matches(pattern: str, tag: str) -> bool:
    return tag.startswith(pattern[:-1]) if pattern.endswith("*") else tag == pattern


def _overlap(left: str, right: str) -> bool:
    if left.endswith("*") and right.endswith("*"):
        return left[:-1].startswith(right[:-1]) or right[:-1].startswith(left[:-1])
    if left.endswith("*"):
        return _matches(left, right)
    if right.endswith("*"):
        return _matches(right, left)
    return left == right


def _fragments(kind: str, ids: tuple[str, ...]) -> dict[str, tuple[dict[str, object], list[tuple[str, str]], str]]:
    loaded = {}
    for fragment_id in ids:
        path = FRAGMENTS / kind / f"{fragment_id}.md"
        front, sections = parse_fragment(path)
        loaded[fragment_id] = (front, sections, path.read_text(encoding="utf-8"))
    return loaded


PERSONA_FILES = _fragments("personas", PERSONAS)
STACK_FILES = _fragments("stacks", STACKS)
ALL_FILES = {**{("personas", key): value for key, value in PERSONA_FILES.items()},
             **{("stacks", key): value for key, value in STACK_FILES.items()}}


def test_fragment_directories_hold_exactly_the_expected_files() -> None:
    personas = {path.stem for path in (FRAGMENTS / "personas").glob("*.md")} - {"devops-engineer"}
    stacks = {path.stem for path in (FRAGMENTS / "stacks").glob("*.md")}
    assert personas == set(PERSONAS)
    assert stacks == set(STACKS)


@pytest.mark.parametrize("key", sorted(ALL_FILES), ids=lambda key: f"{key[0]}/{key[1]}")
def test_front_matter_and_sections(key: tuple[str, str]) -> None:
    kind, fragment_id = key
    front, sections, text = ALL_FILES[key]
    assert front["id"] == fragment_id
    assert front["version"] == 1
    for pattern in [*front["covers"], *front["standards"]]:  # type: ignore[misc]
        assert "*" not in pattern[:-1], f"{fragment_id}: wildcard only as a suffix: {pattern}"
    assert len(set(front["covers"])) == len(front["covers"])  # type: ignore[arg-type]
    assert front["standards"], f"{fragment_id}: standards must not be empty"
    expected = PERSONA_SECTIONS if kind == "personas" else STACK_SECTIONS
    assert tuple(title for title, _ in sections) == expected
    assert all(body for _, body in sections), f"{fragment_id}: empty section"
    if kind == "personas":
        assert dict(sections)["Coverage"] == "GENERATED"
    assert len(text) <= int(front["max_tokens"]) * 4, f"{fragment_id}: {len(text)} chars exceeds max_tokens"
    floor = 3500 if kind == "personas" else 2500
    assert len(text) >= floor, f"{fragment_id}: {len(text)} chars is too thin"


@pytest.mark.parametrize("key", sorted(ALL_FILES), ids=lambda key: f"{key[0]}/{key[1]}")
def test_no_forbidden_vocabulary(key: tuple[str, str]) -> None:
    _, sections, _ = ALL_FILES[key]
    hits = sorted({match.group(0).lower() for _, body in sections for match in _FORBIDDEN.finditer(body)})
    assert not hits, f"{key[1]}: forbidden terms {hits}"


@pytest.mark.parametrize("persona", PERSONAS)
def test_persona_evidence_bullets_and_hand_offs(persona: str) -> None:
    _, sections, _ = PERSONA_FILES[persona]
    evidence = dict(sections)["Evidence by predicate"]
    bullets = [line for line in evidence.splitlines() if line.startswith("- ")]
    named = [match.group(1) for line in bullets if (match := _TICKED_ID.match(line[2:]))]
    assert sorted(named) == sorted(PREDICATES), f"{persona}: one bullet per predicate, got {named}"
    assert len(bullets) == len(PREDICATES)
    hand_offs = set(_TICKED_ID.findall(dict(sections)["Hand-offs"]))
    assert hand_offs, f"{persona}: hand-offs must name adjacent personas"
    assert hand_offs <= set(PERSONAS) - {persona}, f"{persona}: unknown hand-off ids {hand_offs - set(PERSONAS)}"


def test_covers_name_real_active_tags() -> None:
    vocabulary = _load_vocabulary()
    problems = []
    for (_, fragment_id), (front, _, _) in sorted(ALL_FILES.items()):
        for pattern in front["covers"]:  # type: ignore[union-attr]
            name = pattern.split(":", 1)[0]
            namespace = vocabulary.get(name)
            if namespace is None or namespace.get("status") != "active":
                problems.append(f"{fragment_id}: inactive or unknown namespace {pattern}")
                continue
            terms = namespace.get("terms", ())
            regex = namespace.get("pattern")
            if pattern.endswith("*"):
                ok = (any(term.startswith(pattern[:-1]) for term in terms) if terms
                      else pattern == f"{name}:*" or pattern.startswith(f"{name}:"))
            else:
                ok = pattern in terms if terms else bool(regex and re.fullmatch(regex, pattern))
            if not ok:
                problems.append(f"{fragment_id}: names no taxonomy tag {pattern}")
    assert not problems, "\n".join(problems)


def test_stack_profiles_cover_no_partitioned_tags() -> None:
    for fragment_id, (front, _, _) in STACK_FILES.items():
        owned = [p for p in front["covers"] if p.split(":", 1)[0] in PARTITIONED_NAMESPACES]  # type: ignore[union-attr]
        assert not owned, f"{fragment_id}: stack profiles must not claim routing tags {owned}"


def test_personas_partition_the_taxonomy() -> None:
    universe = _universe(_load_vocabulary())
    assert len(universe) > 150
    owners = {tag: [persona for persona in PERSONAS
                    if any(_matches(pattern, tag) for pattern in PERSONA_FILES[persona][0]["covers"])]  # type: ignore[union-attr]
              for tag in universe}
    orphans = sorted(tag for tag, found in owners.items() if not found)
    doubles = {tag: found for tag, found in owners.items() if len(found) > 1}
    assert not orphans, f"orphan tags: {orphans}"
    assert not doubles, f"doubly claimed tags: {doubles}"


def test_persona_patterns_never_overlap() -> None:
    claimed = [(persona, pattern) for persona in PERSONAS
               for pattern in PERSONA_FILES[persona][0]["covers"]]  # type: ignore[union-attr]
    clashes = [(a, p, b, q) for index, (a, p) in enumerate(claimed) for b, q in claimed[index + 1:]
               if a != b and _overlap(p, q)]
    assert not clashes, f"overlapping persona patterns: {clashes}"
