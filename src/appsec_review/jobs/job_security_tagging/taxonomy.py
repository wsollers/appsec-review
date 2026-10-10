"""Versioned security tag vocabulary, tag grammar, and basis-qualified assignment records.

The design is ``docs/architecture/security-tag-taxonomy.md``. A tag is never stored as a bare
string: every assignment names its subject, its basis, the producer, and resolving evidence.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from appsec_review.storage import canonical_json, file_sha256


VOCABULARY_SCHEMA = "appsec-review/tag-vocabulary/1"
CAPABILITY_RULES_SCHEMA = "appsec-review/tag-capability-rules/1"
ASSIGNMENT_SCHEMA = "appsec-review/tag-assignment/1"
BASES = ("derived", "declared", "invoked", "reported", "confirmed")
BASIS_RANK = {basis: rank for rank, basis in enumerate(BASES)}
FLOW_ROLES = ("source", "sink", "sanitizer", "guard", "none")
SUBJECT_KINDS = ("source_file", "source_span", "symbol", "component", "project", "package",
                 "tool_observation", "build_artifact")
_NAMESPACE = re.compile(r"^[a-z][a-z0-9-]*$")
_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9.\-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ROLLUPS = {"self", "domain", "chapter", "cert-category", "family"}
_FAMILIES = {"code_facts", "controls", "routing", "weakness", "threat", "gap"}


class TaxonomyError(ValueError):
    """The vocabulary, a rule file, or an assignment violates the pinned taxonomy contract."""


def split_tag(tag: str) -> tuple[str, tuple[str, ...]]:
    """Return ``(namespace, segments)`` for a grammatical tag, or raise."""
    if not isinstance(tag, str) or not tag or tag != tag.strip():
        raise TaxonomyError(f"tag is not a string: {tag!r}")
    parts = tag.split(":")
    namespace, segments = parts[0], tuple(parts[1:])
    if not _NAMESPACE.fullmatch(namespace) or not 1 <= len(segments) <= 3:
        raise TaxonomyError(f"tag grammar violation: {tag}")
    if any(not _SEGMENT.fullmatch(segment) for segment in segments):
        raise TaxonomyError(f"tag grammar violation: {tag}")
    return namespace, segments


def segment(value: str) -> str:
    """Normalize free producer text (a tool or shard name) into one tag segment."""
    text = re.sub(r"[^a-z0-9.]+", "-", str(value).lower()).strip("-.")
    if not text:
        raise TaxonomyError(f"value cannot form a tag segment: {value!r}")
    return text[:64].rstrip("-.")


def normalize_cwe(value: str) -> str | None:
    """``CWE-079``, ``external/cwe/cwe-079``, and ``cwe:79`` all become ``cwe:79``."""
    match = re.fullmatch(r"(?:external/cwe/)?cwe[-:_ ]?0*([1-9][0-9]{0,4})", str(value).strip(), re.I)
    return f"cwe:{match.group(1)}" if match else None


def normalize_attack(value: str) -> str | None:
    match = re.fullmatch(r"(?:attack:)?(t[0-9]{4}(?:\.[0-9]{3})?)", str(value).strip().lower())
    return f"attack:{match.group(1)}" if match else None


def normalize_cert(value: str) -> str | None:
    """``MEM30-C`` and clang-tidy ``cert-err58-cpp`` become ``cert-c:mem30-c`` / ``cert-cpp:err58-cpp``."""
    match = re.fullmatch(r"(?:cert-)?([a-z]{3})([0-9]{2})-(c|cpp)", str(value).strip().lower())
    if match is None:
        return None
    category, number, language = match.groups()
    return f"cert-{language}:{category}{number}-{language}"


@dataclass(frozen=True, slots=True)
class Namespace:
    name: str
    family: str
    status: str
    bases: frozenset[str]
    rollup: str
    terms: frozenset[str] = frozenset()
    pattern: re.Pattern[str] | None = None
    parameterized: frozenset[str] = frozenset()
    flow_role: bool = False
    derived_prefixes: tuple[str, ...] = ()
    confirmed_only: frozenset[str] = frozenset()
    proposed_terms: frozenset[str] = frozenset()
    catalog_fixture: bool = False
    rollup_gap: str | None = None


@dataclass(frozen=True, slots=True)
class Vocabulary:
    sha256: str
    version: str
    namespaces: Mapping[str, Namespace]

    def namespace(self, tag: str) -> Namespace:
        name, _ = split_tag(tag)
        try:
            return self.namespaces[name]
        except KeyError as exc:
            raise TaxonomyError(f"unregistered tag namespace: {name}") from exc

    def validate_tag(self, tag: str, basis: str) -> Namespace:
        """Reject unknown, proposed, or ungrammatical tags and namespace/basis pairs outside the table."""
        name, segments = split_tag(tag)
        namespace = self.namespace(tag)
        if namespace.status != "active":
            raise TaxonomyError(f"namespace is {namespace.status}; its catalog is not pinned: {name}")
        if tag in namespace.proposed_terms:
            raise TaxonomyError(f"tag is proposed; its catalog is not pinned: {tag}")
        if basis not in BASIS_RANK:
            raise TaxonomyError(f"unknown basis: {basis}")
        if basis not in namespace.bases:
            raise TaxonomyError(f"basis {basis} is invalid for namespace {name}")
        if basis == "derived" and namespace.derived_prefixes and not tag.startswith(namespace.derived_prefixes):
            raise TaxonomyError(f"basis derived is invalid for {tag}")
        if tag in namespace.confirmed_only and basis != "confirmed":
            raise TaxonomyError(f"{tag} requires basis confirmed")
        if namespace.pattern is not None:
            if not namespace.pattern.fullmatch(tag):
                raise TaxonomyError(f"tag is outside the {name} catalog identifier form: {tag}")
        elif segments[0] in namespace.parameterized:
            if len(segments) != 2:
                raise TaxonomyError(f"parameterized tag requires exactly one parameter: {tag}")
        elif tag not in namespace.terms:
            raise TaxonomyError(f"tag is not in the {name} vocabulary: {tag}")
        return namespace

    def rollup(self, tag: str) -> str:
        name, segments = split_tag(tag)
        method = self.namespace(tag).rollup
        if method == "domain" and len(segments) > 1:
            return f"{name}:{segments[0]}"
        if method == "chapter":
            return f"{name}:{segments[0].split('.')[0]}"
        if method == "cert-category":
            return f"{name}:{segments[0][:3]}"
        if method == "family":
            return f"{name}:{segments[0].split('-')[0]}"
        return tag


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TaxonomyError(message)


def _read_pinned(path: Path, expected_sha256: str, schema: str) -> dict[str, Any]:
    _require(isinstance(expected_sha256, str) and bool(_SHA256.fullmatch(expected_sha256)),
             f"pinned sha256 is invalid for {path.name}")
    _require(path.is_file(), f"pinned taxonomy file is unavailable: {path.name}")
    actual = file_sha256(path)
    _require(actual == expected_sha256, f"pinned taxonomy file hash mismatch: {path.name}")
    document = json.loads(path.read_text(encoding="utf-8"))
    _require(isinstance(document, dict) and document.get("schema") == schema,
             f"unsupported taxonomy schema in {path.name}")
    return document


def parse_vocabulary(document: Mapping[str, Any], sha256: str) -> Vocabulary:
    _require(document.get("schema") == VOCABULARY_SCHEMA, "unsupported vocabulary schema")
    _require(tuple(document.get("bases", ())) == BASES, "vocabulary basis order does not match the contract")
    _require(tuple(document.get("flow_roles", ())) == FLOW_ROLES, "vocabulary flow roles do not match the contract")
    raw = document.get("namespaces")
    _require(isinstance(raw, Mapping) and bool(raw), "vocabulary namespaces are required")
    namespaces: dict[str, Namespace] = {}
    for name, value in raw.items():
        _require(bool(_NAMESPACE.fullmatch(name)) and isinstance(value, Mapping), f"namespace is invalid: {name}")
        _require(value.get("family") in _FAMILIES, f"namespace family is invalid: {name}")
        _require(value.get("status") in {"active", "proposed"}, f"namespace status is invalid: {name}")
        _require(value.get("rollup") in _ROLLUPS, f"namespace rollup is invalid: {name}")
        bases = frozenset(value.get("bases", ()))
        _require(bool(bases) and bases <= set(BASES), f"namespace bases are invalid: {name}")
        terms = frozenset(value.get("terms", ()))
        for term in terms:
            _require(split_tag(term)[0] == name, f"term belongs to another namespace: {term}")
        pattern = re.compile(value["pattern"]) if isinstance(value.get("pattern"), str) else None
        if value["status"] == "active":
            _require(bool(terms) or pattern is not None, f"active namespace has no vocabulary: {name}")
        for key in ("confirmed_only", "proposed_terms"):
            _require(set(value.get(key, ())) <= terms, f"{name}.{key} names an unknown term")
        namespaces[name] = Namespace(
            name=name, family=value["family"], status=value["status"], bases=bases,
            rollup=value["rollup"], terms=terms, pattern=pattern,
            parameterized=frozenset(value.get("parameterized", ())), flow_role=bool(value.get("flow_role")),
            derived_prefixes=tuple(value.get("derived_prefixes", ())),
            confirmed_only=frozenset(value.get("confirmed_only", ())),
            proposed_terms=frozenset(value.get("proposed_terms", ())),
            catalog_fixture=bool(value.get("catalog_fixture")), rollup_gap=value.get("rollup_gap"),
        )
    _require(any(item.flow_role for item in namespaces.values()), "no namespace accepts flow roles")
    return Vocabulary(sha256=sha256, version=str(document.get("version", "")), namespaces=namespaces)


def load_vocabulary(path: Path, expected_sha256: str) -> Vocabulary:
    return parse_vocabulary(_read_pinned(path, expected_sha256, VOCABULARY_SCHEMA), expected_sha256)


@dataclass(frozen=True, slots=True)
class CapabilityRules:
    sha256: str
    languages: Mapping[str, str]
    path_rules: tuple[Mapping[str, Any], ...]
    package_rules: tuple[Mapping[str, Any], ...]
    observation_rules: tuple[Mapping[str, Any], ...]
    coverage_gaps: Mapping[str, str]


_EXTRACTORS = {"sarif-rule-cwe-tags", "cert-rule-id", "advisory-severity", "package-capability"}


def parse_capability_rules(document: Mapping[str, Any], sha256: str, vocabulary: Vocabulary) -> CapabilityRules:
    """Validate producer-to-tag rules; every fixed tag must be valid at the rule's basis."""
    _require(document.get("schema") == CAPABILITY_RULES_SCHEMA, "unsupported capability-rule schema")
    languages = dict(document.get("languages", {}))
    for tag in languages.values():
        vocabulary.validate_tag(tag, "declared")
    seen: set[str] = set()

    def rules(key: str, basis: str) -> tuple[Mapping[str, Any], ...]:
        values = tuple(document.get(key, ()))
        for rule in values:
            rule_id = rule.get("id")
            _require(isinstance(rule_id, str) and rule_id not in seen, f"duplicate or missing rule id: {rule_id}")
            seen.add(rule_id)
            extract = rule.get("extract")
            _require(extract is None or extract in _EXTRACTORS, f"unknown extractor in {rule_id}")
            _require(bool(rule.get("emit")) or extract is not None, f"rule emits nothing: {rule_id}")
            for tag in rule.get("emit", ()):
                vocabulary.validate_tag(tag, basis)
        return values

    path_rules = rules("path_rules", "declared")
    package_rules = rules("package_rules", "declared")
    observation_rules = rules("observation_rules", "reported")
    for rule in path_rules:
        _require(any(rule.get(key) for key in ("names", "suffixes", "prefixes")),
                 f"path rule has no matcher: {rule['id']}")
    for rule in package_rules:
        _require(bool(rule.get("packages")), f"package rule has no packages: {rule['id']}")
    for rule in observation_rules:
        _require(bool(rule.get("producers")), f"observation rule has no producers: {rule['id']}")
    gaps = dict(document.get("coverage_gaps", {}))
    for tag in gaps.values():
        name, segments = split_tag(tag)
        _require(name == "gap", f"coverage gap mapping must use the gap namespace: {tag}")
        if segments[0] in vocabulary.namespaces["gap"].parameterized:
            vocabulary.validate_tag(f"{tag}:probe", "reported")
        else:
            vocabulary.validate_tag(tag, "reported")
    return CapabilityRules(sha256, languages, path_rules, package_rules, observation_rules, gaps)


def load_capability_rules(path: Path, expected_sha256: str, vocabulary: Vocabulary) -> CapabilityRules:
    document = _read_pinned(path, expected_sha256, CAPABILITY_RULES_SCHEMA)
    return parse_capability_rules(document, expected_sha256, vocabulary)


def assignment(*, vocabulary: Vocabulary, tag: str, basis: str, subject: Mapping[str, Any],
               producer: Mapping[str, Any], evidence: Iterable[Mapping[str, Any]] = (),
               derived_from: Iterable[str] = (), crosswalk_rule: str | None = None,
               flow_role: str | None = None, confidence: str = "high",
               crosswalk_sha256: str | None = None) -> dict[str, Any]:
    """Build one validated assignment record with a content-derived identity."""
    namespace = vocabulary.validate_tag(tag, basis)
    if flow_role is not None:
        _require(namespace.flow_role and flow_role in FLOW_ROLES, f"flow_role is invalid for {tag}")
    _require(subject.get("kind") in SUBJECT_KINDS, f"subject kind is invalid: {subject.get('kind')}")
    _require(isinstance(subject.get("logical_id"), str) and bool(subject["logical_id"]),
             "subject logical identity is required")
    evidence_values = [dict(item) for item in evidence]
    derived_values = sorted(set(derived_from))
    if basis == "derived":
        _require(bool(crosswalk_rule) and bool(derived_values),
                 f"derived tag requires a crosswalk rule and inputs: {tag}")
    else:
        _require(crosswalk_rule is None, f"only derived tags name a crosswalk rule: {tag}")
        _require(bool(evidence_values), f"tag requires resolving evidence: {tag}")
    _require(confidence in {"high", "medium", "low"}, "confidence is invalid")
    record = {
        "schema": ASSIGNMENT_SCHEMA, "tag": tag, "namespace": namespace.name, "family": namespace.family,
        "subject": dict(subject), "basis": basis, "flow_role": flow_role, "producer": dict(producer),
        "evidence": evidence_values, "derived_from": derived_values, "crosswalk_rule": crosswalk_rule,
        "confidence": confidence, "vocabulary_sha256": vocabulary.sha256,
        "crosswalk_sha256": crosswalk_sha256,
    }
    record["assignment_id"] = "tag:" + hashlib.sha256(canonical_json(
        {key: value for key, value in record.items() if key != "crosswalk_sha256"})).hexdigest()
    return record


def validate_assignment(vocabulary: Vocabulary, record: Mapping[str, Any]) -> None:
    """Re-validate a stored record exactly as :func:`assignment` would have built it."""
    rebuilt = assignment(
        vocabulary=vocabulary, tag=record["tag"], basis=record["basis"], subject=record["subject"],
        producer=record["producer"], evidence=record["evidence"], derived_from=record["derived_from"],
        crosswalk_rule=record["crosswalk_rule"], flow_role=record["flow_role"],
        confidence=record["confidence"], crosswalk_sha256=record.get("crosswalk_sha256"))
    _require(rebuilt == dict(record), f"assignment record does not match its content identity: {record.get('tag')}")


def merge_assignments(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate by content identity and return a deterministic order."""
    merged: dict[str, dict[str, Any]] = {}
    for record in records:
        existing = merged.get(record["assignment_id"])
        if existing is not None and existing != dict(record):
            raise TaxonomyError(f"assignment identity collision: {record['assignment_id']}")
        merged[record["assignment_id"]] = dict(record)
    return [merged[key] for key in sorted(merged)]
