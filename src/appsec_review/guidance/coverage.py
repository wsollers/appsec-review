"""Generated persona coverage: expand ``covers`` patterns through the pinned taxonomy and crosswalk.

The text produced here is never hand-written into a persona file. It is a pure function of the
persona's ``covers``/``standards`` and the pinned vocabulary and crosswalk hashes, so a taxonomy
change changes the coverage hash and therefore the guidance bundle hash.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from appsec_review.jobs.job_security_tagging.crosswalk import Crosswalk
from appsec_review.jobs.job_security_tagging.taxonomy import TaxonomyError, Vocabulary, split_tag

from .fragments import GuidanceError, text_sha256


COVERAGE_RULE = "persona-coverage/1"
STANDARD_ORDER = ("cwe", "cert-c", "cert-cpp", "misra-c2012", "misra-cpp2023", "asvs5", "masvs2",
                  "capec", "attack", "nist53r5", "ssdf", "top10-2025", "api-top10-2023")


def cover_matches(pattern: str, tag: str) -> bool:
    """A cover is an exact tag or a prefix ending in a single ``*`` suffix wildcard."""
    return tag.startswith(pattern[:-1]) if pattern.endswith("*") else tag == pattern


def cover_specificity(pattern: str) -> tuple[int, int]:
    """Exact covers beat wildcards; a longer literal prefix beats a shorter one."""
    return (0 if pattern.endswith("*") else 1, len(pattern.rstrip("*")))


def _leaf_tags(condition: Mapping[str, Any]) -> list[str]:
    if "any" in condition:
        return [tag for item in condition["any"] for tag in _leaf_tags(item)]
    return [condition["tag"]] if "tag" in condition else []


def rule_condition_tags(rule: Mapping[str, Any]) -> list[str]:
    return sorted({tag for condition in rule["when"]["all"] for tag in _leaf_tags(condition)})


def crosswalk_tags(crosswalk: Crosswalk) -> frozenset[str]:
    """Every concrete tag the crosswalk names, in a condition or an emit list."""
    return frozenset(tag for rule in crosswalk.rules
                     for tag in (*rule_condition_tags(rule), *rule["emit"]))


def taxonomy_universe(vocabulary: Vocabulary, crosswalk: Crosswalk) -> frozenset[str]:
    """Enumerable taxonomy tags: every vocabulary term plus every tag the crosswalk names."""
    terms = {term for namespace in vocabulary.namespaces.values() for term in namespace.terms}
    return frozenset(terms | crosswalk_tags(crosswalk))


def _namespace(vocabulary: Vocabulary, pattern: str) -> str:
    name = pattern.split(":", 1)[0]
    if name not in vocabulary.namespaces:
        raise GuidanceError(f"covers pattern names an unregistered namespace: {pattern}")
    return name


def expand_patterns(covers: Iterable[str], vocabulary: Vocabulary, crosswalk: Crosswalk
                    ) -> tuple[list[str], list[str]]:
    """Return ``(covered_tags, open_patterns)``.

    A pattern in a closed (term-listed) namespace must match at least one term. A pattern in an
    open catalog namespace (``cwe``, ``cert-c``, ``capec``...) keeps a concrete tag after grammar
    validation, matches known crosswalk tags when wildcarded, and is otherwise kept as an open
    pattern. A proposed namespace has no pinned catalog, so its patterns are always open.
    """
    universe = taxonomy_universe(vocabulary, crosswalk)
    covered: set[str] = set()
    open_patterns: set[str] = set()
    for pattern in sorted(set(covers)):
        namespace = vocabulary.namespaces[_namespace(vocabulary, pattern)]
        matched = {tag for tag in universe if split_tag(tag)[0] == namespace.name and cover_matches(pattern, tag)}
        if namespace.status != "active":
            open_patterns.add(pattern)
            continue
        if namespace.terms:
            if not matched:
                raise GuidanceError(f"covers pattern matches no taxonomy term: {pattern}")
            covered |= matched
            continue
        if pattern.endswith("*"):
            covered |= matched
            open_patterns.add(pattern)
            continue
        if namespace.pattern is None or not namespace.pattern.fullmatch(pattern):
            raise GuidanceError(f"covers tag is outside its catalog identifier form: {pattern}")
        covered.add(pattern)
    return sorted(covered), sorted(open_patterns)


def _standard_key(tag: str) -> tuple[int, str, str]:
    name = split_tag(tag)[0]
    rank = STANDARD_ORDER.index(name) if name in STANDARD_ORDER else len(STANDARD_ORDER)
    return rank, name, tag


def mapped_items(tag: str, crosswalk: Crosswalk) -> list[str]:
    """One-hop crosswalk neighbours: emits of rules conditioned on the tag, and co-emitted tags."""
    items: set[str] = set()
    for rule in crosswalk.rules:
        emits = set(rule["emit"])
        if tag in rule_condition_tags(rule):
            items |= emits
        if tag in emits:
            items |= emits | set(rule_condition_tags(rule))
    items.discard(tag)
    return sorted(items, key=_standard_key)


def expand_coverage(covers: Iterable[str], standards: Iterable[str], vocabulary: Vocabulary,
                    crosswalk: Crosswalk) -> dict[str, Any]:
    """Generate the deterministic, hash-pinned Coverage section for one persona."""
    standards = tuple(standards)
    for standard in standards:
        if standard not in vocabulary.namespaces:
            raise GuidanceError(f"persona standard is not a taxonomy namespace: {standard}")
    try:
        covered, open_patterns = expand_patterns(covers, vocabulary, crosswalk)
    except TaxonomyError as exc:
        raise GuidanceError(str(exc)) from exc
    mapping: dict[str, list[str]] = {}
    for tag in covered:
        items = [item for item in mapped_items(tag, crosswalk)
                 if not standards or split_tag(item)[0] in standards]
        if items:
            mapping[tag] = items
    lines = [f"{COVERAGE_RULE} vocabulary={vocabulary.sha256} crosswalk={crosswalk.sha256}",
             "Covered tags:"]
    lines += [f"- {tag}" for tag in sorted(covered, key=_standard_key)] or ["- none"]
    lines.append("Mapped standard items:")
    lines += [f"- {tag}: {', '.join(items)}" for tag, items in sorted(mapping.items(),
                                                                       key=lambda pair: _standard_key(pair[0]))]
    if not mapping:
        lines.append("- none")
    if open_patterns:
        lines.append("Open catalog patterns:")
        lines += [f"- {pattern}" for pattern in open_patterns]
    text = "\n".join(lines)
    return {"rule": COVERAGE_RULE, "covered_tags": covered, "open_patterns": open_patterns,
            "mapped": mapping, "text": text, "sha256": text_sha256(text),
            "vocabulary_sha256": vocabulary.sha256, "crosswalk_sha256": crosswalk.sha256}
