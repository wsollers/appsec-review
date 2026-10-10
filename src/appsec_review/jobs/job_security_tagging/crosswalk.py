"""One-hop, deterministic crosswalk from observed assignments to derived (applicable) tags."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from appsec_review.storage import canonical_json

from .taxonomy import (
    BASIS_RANK, FLOW_ROLES, TaxonomyError, Vocabulary, _read_pinned, assignment, split_tag,
)


CROSSWALK_SCHEMA = "appsec-review/tag-crosswalk/1"
SCOPES = ("same_subject", "ci_job", "component", "project")
SOURCES = ("curated", "published", "upstream")


@dataclass(frozen=True, slots=True)
class Crosswalk:
    sha256: str
    rules: tuple[Mapping[str, Any], ...]


def _condition_tags(condition: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if "any" in condition:
        values = condition["any"]
        if not isinstance(values, list) or not values:
            raise TaxonomyError("crosswalk 'any' requires a non-empty list")
        return [leaf for item in values for leaf in _condition_tags(item)]
    return [condition]


def _validate_leaf(vocabulary: Vocabulary, leaf: Mapping[str, Any], rule_id: str) -> None:
    if set(leaf) - {"tag", "namespace", "basis_at_least", "flow_role"}:
        raise TaxonomyError(f"crosswalk condition has unknown keys: {rule_id}")
    if ("tag" in leaf) == ("namespace" in leaf):
        raise TaxonomyError(f"crosswalk condition names exactly one tag or namespace: {rule_id}")
    floor = leaf.get("basis_at_least", "declared")
    if floor not in BASIS_RANK or floor == "derived":
        raise TaxonomyError(f"crosswalk conditions cannot read derived tags (one hop): {rule_id}")
    if leaf.get("flow_role") is not None and leaf["flow_role"] not in FLOW_ROLES:
        raise TaxonomyError(f"crosswalk flow role is invalid: {rule_id}")
    if "namespace" in leaf:
        namespace = vocabulary.namespaces.get(leaf["namespace"])
        if namespace is None or namespace.status != "active":
            raise TaxonomyError(f"crosswalk condition namespace is unregistered or proposed: {rule_id}")
        return
    usable = [basis for basis in vocabulary.namespace(leaf["tag"]).bases
              if basis != "derived" and BASIS_RANK[basis] >= BASIS_RANK[floor]]
    for basis in usable:
        try:
            vocabulary.validate_tag(leaf["tag"], basis)
            return
        except TaxonomyError:
            continue
    raise TaxonomyError(f"crosswalk condition can never match an observed tag: {rule_id} {leaf['tag']}")


def parse_crosswalk(document: Mapping[str, Any], sha256: str, vocabulary: Vocabulary) -> Crosswalk:
    """Validate rule data; conflicts fail assembly and rule order never resolves them."""
    if document.get("schema") != CROSSWALK_SCHEMA:
        raise TaxonomyError("unsupported crosswalk schema")
    rules = tuple(document.get("rules", ()))
    seen_ids: set[str] = set()
    seen_conditions: dict[bytes, str] = {}
    for rule in rules:
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id or rule_id in seen_ids:
            raise TaxonomyError(f"crosswalk rule id is missing or duplicated: {rule_id}")
        seen_ids.add(rule_id)
        if rule.get("scope") not in SCOPES:
            raise TaxonomyError(f"crosswalk scope is unsupported: {rule_id} {rule.get('scope')}")
        if rule.get("source") not in SOURCES:
            raise TaxonomyError(f"crosswalk source is invalid: {rule_id}")
        if rule["source"] == "upstream" or "emit_from" in rule:
            raise TaxonomyError(f"upstream crosswalk rules require a run-pinned MITRE feed: {rule_id}")
        if rule["source"] == "curated" and not (rule.get("reviewer") and rule.get("rationale")):
            raise TaxonomyError(f"curated crosswalk rule requires a reviewer and rationale: {rule_id}")
        when = rule.get("when")
        if not isinstance(when, Mapping) or set(when) != {"all"} or not when["all"]:
            raise TaxonomyError(f"crosswalk rule requires a non-empty 'all' condition: {rule_id}")
        for condition in when["all"]:
            for leaf in _condition_tags(condition):
                _validate_leaf(vocabulary, leaf, rule_id)
        emit = rule.get("emit")
        if not isinstance(emit, list) or not emit or len(emit) != len(set(emit)):
            raise TaxonomyError(f"crosswalk rule must emit distinct tags: {rule_id}")
        for tag in emit:
            vocabulary.validate_tag(tag, "derived")
        key = canonical_json({"scope": rule["scope"], "when": when})
        if key in seen_conditions:
            raise TaxonomyError(f"crosswalk rules conflict on identical conditions: "
                                f"{seen_conditions[key]} and {rule_id}")
        seen_conditions[key] = rule_id
    return Crosswalk(sha256=sha256, rules=rules)


def load_crosswalk(path: Path, expected_sha256: str, vocabulary: Vocabulary) -> Crosswalk:
    return parse_crosswalk(_read_pinned(path, expected_sha256, CROSSWALK_SCHEMA), expected_sha256, vocabulary)


def _leaf_matches(leaf: Mapping[str, Any], record: Mapping[str, Any]) -> bool:
    if record["basis"] == "derived":
        return False
    if "tag" in leaf and record["tag"] != leaf["tag"]:
        return False
    if "namespace" in leaf and split_tag(record["tag"])[0] != leaf["namespace"]:
        return False
    if BASIS_RANK[record["basis"]] < BASIS_RANK[leaf.get("basis_at_least", "declared")]:
        return False
    return leaf.get("flow_role") is None or record.get("flow_role") == leaf["flow_role"]


def _condition(condition: Mapping[str, Any], group: list[Mapping[str, Any]]) -> list[str]:
    """Return the assignment ids satisfying one condition, or an empty list when it fails."""
    leaves = _condition_tags(condition)
    return sorted({record["assignment_id"] for leaf in leaves for record in group if _leaf_matches(leaf, record)})


def scope_key(scope: str, record: Mapping[str, Any]) -> str | None:
    subject = record["subject"]
    if scope == "same_subject":
        # The whole subject is the key: per-component records of one shared logical subject stay in
        # separate groups, so no group ever has to pick one of several subjects.
        return canonical_json(dict(subject)).decode()
    if scope == "component":
        # Ambiguous or unowned evidence has no component and never joins a component group.
        return subject.get("component_id")
    if scope == "project":
        return subject.get("project_id")
    if scope == "ci_job":
        job = record["producer"].get("ci_job")
        return f"{job['path']}#{job['job']}" if isinstance(job, Mapping) and job.get("job") else None
    raise TaxonomyError(f"crosswalk scope is unsupported: {scope}")


def evaluate(crosswalk: Crosswalk, vocabulary: Vocabulary, records: Iterable[Mapping[str, Any]], *,
             scope_subject: Callable[[str, str, list[Mapping[str, Any]]], Sequence[Mapping[str, Any]]]
             ) -> list[dict[str, Any]]:
    """Apply every rule once to observed assignments; derived inputs are never read.

    ``scope_subject`` returns every subject a satisfied group resolves to (one per owning component
    when evidence is shared) and an empty sequence when the group has no resolvable subject.
    """
    observed = sorted((dict(record) for record in records if record["basis"] != "derived"),
                      key=lambda item: item["assignment_id"])
    derived: list[dict[str, Any]] = []
    for rule in sorted(crosswalk.rules, key=lambda item: item["id"]):
        groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for record in observed:
            key = scope_key(rule["scope"], record)
            if key is not None:
                groups[key].append(record)
        for key in sorted(groups):
            group = groups[key]
            matched = [_condition(condition, group) for condition in rule["when"]["all"]]
            if not all(matched):
                continue
            subjects = scope_subject(rule["scope"], key, group)
            inputs = sorted({value for values in matched for value in values})
            for subject in subjects:
                for tag in rule["emit"]:
                    derived.append(assignment(
                        vocabulary=vocabulary, tag=tag, basis="derived", subject=subject,
                        producer={"name": "tag-crosswalk", "rule_id": rule["id"], "source": rule["source"],
                                  "version": crosswalk.sha256},
                        derived_from=inputs, crosswalk_rule=rule["id"], confidence="medium",
                        crosswalk_sha256=crosswalk.sha256))
    return derived
