"""Bounded readers that turn accepted retrieval shards into observed tag assignments.

Every reader queries immutable, hash-verified index shards; none scans the target tree. Producer
text is data: it is matched against pinned rules and never interpreted as an instruction.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hmac
import json
from pathlib import Path, PurePosixPath
import sqlite3
from typing import Any

from appsec_review.retrieval import EntityKind, LogicalIdentity
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.storage import file_sha256

from .taxonomy import (
    CapabilityRules, TaxonomyError, Vocabulary, assignment, normalize_cert, normalize_cwe, segment,
)


TAG_INDEX = "tags"
REQUIRED_INDEXES = ("source", "observations", "components")
_SEVERITIES = {"critical", "high", "medium", "low"}
_NON_FINDING_CATEGORIES = {"software_inventory"}


@dataclass(frozen=True, slots=True)
class Row:
    identity: str
    kind: str
    native_id: str
    name: str
    payload: Mapping[str, Any]
    location: Mapping[str, Any] | None


class AcceptedIndexes:
    """The accepted manifest for one run, excluding any earlier tag shards."""

    def __init__(self, run_root: Path):
        self.run_root = Path(run_root)
        manifest_path, manifest_sha = resolve_accepted_manifest(self.run_root)
        self.manifest, self.manifest_sha256 = load_verified_manifest(self.run_root, manifest_path, manifest_sha)
        self.manifest_path = manifest_path
        self.target_snapshot = str(self.manifest["target_snapshot"])
        self.identities = [dict(item) for item in self.manifest["indexes"] if item["name"] != TAG_INDEX]

    def shards(self, name: str) -> list[Mapping[str, Any]]:
        return sorted((item for item in self.identities if item["name"] == name),
                      key=lambda item: str(item.get("shard_id", "default")))

    def _open(self, identity: Mapping[str, Any]) -> sqlite3.Connection:
        path = (self.run_root / str(identity["relative_path"])).resolve()
        if self.run_root.resolve() not in path.parents or not path.is_file():
            raise ValueError(f"index is unavailable: {identity['name']}/{identity.get('shard_id')}")
        if not hmac.compare_digest(file_sha256(path), str(identity["sha256"])):
            raise ValueError(f"index integrity mismatch: {identity['name']}/{identity.get('shard_id')}")
        database = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA query_only=ON")
        return database

    def rows(self, identity: Mapping[str, Any], kinds: tuple[str, ...], limit: int) -> tuple[list[Row], bool]:
        """Return at most ``limit`` entities of ``kinds`` in identity order, and whether the bound was hit."""
        placeholders = ",".join("?" for _ in kinds)
        with self._open(identity) as database:
            values = database.execute(
                "SELECT e.identity, e.kind, e.native_id, e.name, e.payload_json, l.path, l.file_sha256, "
                "l.start_byte, l.end_byte, l.start_line, l.end_line, l.start_column, l.end_column, "
                "l.target_snapshot, l.mapping_method, l.confidence "
                f"FROM entities e LEFT JOIN locations l ON l.entity_id = e.identity "
                f"WHERE e.kind IN ({placeholders}) ORDER BY e.identity LIMIT ?",
                (*kinds, limit + 1)).fetchall()
        rows = []
        for value in values[:limit]:
            location = None
            if value["path"] is not None:
                location = {key: value[key] for key in (
                    "path", "file_sha256", "start_byte", "end_byte", "start_line", "end_line",
                    "start_column", "end_column", "target_snapshot", "mapping_method", "confidence")}
            rows.append(Row(value["identity"], value["kind"], value["native_id"], value["name"],
                            json.loads(value["payload_json"]), location))
        return rows, len(values) > limit

    def coverage(self, identity: Mapping[str, Any]) -> list[dict[str, Any]]:
        with self._open(identity) as database:
            return [{"area": row["area"], "status": row["status"], "gap": row["gap"]}
                    for row in database.execute("SELECT area, status, gap FROM coverage ORDER BY area, status")]


@dataclass(frozen=True, slots=True)
class Scope:
    """Subjects that every collector shares: the project and the cataloged components."""

    target_snapshot: str
    project: Mapping[str, Any]
    components: tuple[Mapping[str, Any], ...]

    def component_for(self, path: str | None) -> str | None:
        if not path:
            return None
        best: tuple[int, str] | None = None
        for component in self.components:
            root = str(component.get("root") or ".")
            if root == "." or path == root or path.startswith(root.rstrip("/") + "/"):
                depth = 0 if root == "." else len(PurePosixPath(root).parts)
                if best is None or depth > best[0]:
                    best = (depth, str(component["component_id"]))
        return best[1] if best else None

    def subject(self, kind: str, logical_id: str, path: str | None = None, **extra: Any) -> dict[str, Any]:
        value = {"kind": kind, "logical_id": logical_id, "component_id": self.component_for(path),
                 "project_id": self.project["logical_id"]}
        if path:
            value["path"] = path
        value.update({key: item for key, item in extra.items() if item is not None})
        return value

    def component_subject(self, component_id: str) -> dict[str, Any] | None:
        for component in self.components:
            if component["component_id"] == component_id:
                return {"kind": "component", "logical_id": component["logical_id"], "component_id": component_id,
                        "project_id": self.project["logical_id"]}
        return None


def resolve_scope(indexes: AcceptedIndexes, limit: int) -> tuple[Scope, list[str]]:
    gaps: list[str] = []
    project_id = LogicalIdentity.derive(EntityKind.PROJECT, indexes.target_snapshot,
                                        {"scope": "security-tagging", "target_snapshot": indexes.target_snapshot})
    project = {"kind": "project", "logical_id": project_id.value, "component_id": None,
               "project_id": project_id.value}
    components = []
    for identity in indexes.shards("components"):
        rows, truncated = indexes.rows(identity, (EntityKind.COMPONENT.value,), limit)
        if truncated:
            gaps.append(f"components/{identity.get('shard_id')}: component bound {limit} reached")
        for row in rows:
            component_id = row.payload.get("component_id")
            if isinstance(component_id, str) and component_id:
                components.append({"component_id": component_id, "logical_id": row.identity,
                                   "root": str(row.payload.get("root") or ".")})
    components.sort(key=lambda item: (item["component_id"], item["logical_id"]))
    return Scope(indexes.target_snapshot, project, tuple(components)), gaps


def _evidence(row: Row, identity: Mapping[str, Any]) -> dict[str, Any]:
    value: dict[str, Any] = {"ref": row.identity, "index": identity["name"],
                             "shard_id": identity.get("shard_id", "default"), "index_sha256": identity["sha256"]}
    if row.location is not None:
        value.update({"path": row.location["path"], "file_sha256": row.location["file_sha256"],
                      "span": {"start_line": row.location["start_line"], "end_line": row.location["end_line"]},
                      "location": dict(row.location)})
    return value


def _path_tags(rules: CapabilityRules, path: str) -> list[tuple[str, str]]:
    name = PurePosixPath(path).name
    tags = []
    for rule in rules.path_rules:
        names = rule.get("names", ())
        suffixes = tuple(rule.get("suffixes", ()))
        prefixes = tuple(rule.get("prefixes", ()))
        if prefixes and not path.startswith(prefixes):
            continue
        if names or suffixes:
            if not (name in names or (suffixes and name.endswith(suffixes))):
                continue
        tags.extend((tag, rule["id"]) for tag in rule["emit"])
    return tags


def collect_source_facts(indexes: AcceptedIndexes, scope: Scope, vocabulary: Vocabulary,
                         rules: CapabilityRules, limit: int) -> tuple[list[dict[str, Any]], list[str]]:
    """Declared language and configuration-file facts from the cataloged source inventory."""
    records: list[dict[str, Any]] = []
    gaps: list[str] = []
    for identity in indexes.shards("source"):
        rows, truncated = indexes.rows(identity, (EntityKind.SOURCE_FILE.value,), limit)
        if truncated:
            gaps.append(f"source/{identity.get('shard_id')}: source-file bound {limit} reached")
        for row in rows:
            if row.location is None:
                continue
            path = row.location["path"]
            subject = scope.subject("source_file", row.identity, path)
            evidence = [_evidence(row, identity)]
            emitted: list[tuple[str, str]] = []
            language = row.payload.get("language")
            if isinstance(language, str) and language:
                tag = rules.languages.get(language)
                if tag is None:
                    gaps.append(f"language has no lang tag mapping: {language}")
                else:
                    emitted.append((tag, "catalog-language"))
            emitted.extend(_path_tags(rules, path))
            for tag, rule_id in emitted:
                records.append(assignment(
                    vocabulary=vocabulary, tag=tag, basis="declared", subject=subject,
                    producer={"name": "capability-rules", "rule_id": rule_id, "version": rules.sha256},
                    evidence=evidence))
    return records, sorted(set(gaps))


def producer_key(row: Row, identity: Mapping[str, Any]) -> str:
    producer = identity.get("producer") if isinstance(identity.get("producer"), Mapping) else {}
    if row.payload.get("producer") == "codeql":
        return "codeql"
    if producer.get("job") == "job_ci_configuration_analysis":
        return f"ci:{row.payload.get('tool_id') or producer.get('tool_id') or 'unknown'}"
    return str(row.payload.get("tool_id") or producer.get("producer") or producer.get("tool_id") or "unknown")


def _producer_matches(patterns: tuple[str, ...], key: str) -> bool:
    return any(pattern == "*" or pattern == key or (pattern.endswith("*") and key.startswith(pattern[:-1]))
               for pattern in patterns)


def _sarif_cwe_tags(payload: Mapping[str, Any]) -> list[str]:
    tags: list[str] = []
    for container in (payload.get("rule"), payload):
        properties = container.get("properties") if isinstance(container, Mapping) else None
        values = properties.get("tags") if isinstance(properties, Mapping) else None
        for value in values if isinstance(values, list) else ():
            tag = normalize_cwe(str(value)) if str(value).lower().startswith(("external/cwe/", "cwe")) else None
            if tag is not None:
                tags.append(tag)
    return sorted(set(tags))


def _extract(kind: str, row: Row, rule_id: str, rules: CapabilityRules) -> list[tuple[str, str, str]]:
    """Return ``(tag, basis, rule_id)`` triples produced by a named extractor."""
    if kind == "sarif-rule-cwe-tags":
        return [(tag, "reported", kind) for tag in _sarif_cwe_tags(row.payload)]
    if kind == "cert-rule-id":
        tag = normalize_cert(rule_id)
        return [(tag, "reported", kind)] if tag else []
    if kind == "advisory-severity":
        severity = str(row.payload.get("severity") or "unknown").lower()
        return [(f"vuln:severity:{severity if severity in _SEVERITIES else 'unknown'}", "reported", kind)]
    if kind == "package-capability":
        package = str(row.payload.get("package") or "").strip().lower()
        return [(tag, "declared", rule["id"]) for rule in rules.package_rules
                if package and package in {value.lower() for value in rule["packages"]} for tag in rule["emit"]]
    raise TaxonomyError(f"unknown extractor: {kind}")


def collect_observation_facts(indexes: AcceptedIndexes, scope: Scope, vocabulary: Vocabulary,
                              rules: CapabilityRules, limit: int) -> tuple[list[dict[str, Any]], list[str]]:
    """Reported weakness, advisory, and CI capability tags from normalized tool observations."""
    records: list[dict[str, Any]] = []
    gaps: list[str] = []
    for identity in indexes.shards("observations"):
        rows, truncated = indexes.rows(identity, (EntityKind.TOOL_OBSERVATION.value,), limit)
        if truncated:
            gaps.append(f"observations/{identity.get('shard_id')}: observation bound {limit} reached")
        for row in rows:
            key = producer_key(row, identity)
            rule_id = str(row.payload.get("native_rule_id") or row.payload.get("rule_id") or row.name)
            emitted: list[tuple[str, str, str]] = []
            for rule in rules.observation_rules:
                if not _producer_matches(tuple(rule["producers"]), key):
                    continue
                if rule.get("rule_ids") and rule_id not in rule["rule_ids"]:
                    continue
                if rule.get("extract"):
                    emitted.extend(_extract(rule["extract"], row, rule_id, rules))
                emitted.extend((tag, "reported", rule["id"]) for tag in rule.get("emit", ()))
            path = row.location["path"] if row.location else row.payload.get("path")
            ci_job = None
            if key.startswith("ci:") and row.payload.get("job") and row.location:
                ci_job = {"path": row.location["path"], "job": str(row.payload["job"])}
            subject = scope.subject("tool_observation", row.identity, path if isinstance(path, str) else None)
            evidence = [_evidence(row, identity)]
            category = str(row.payload.get("category") or "")
            finding_tags = [item for item in emitted if item[1] == "reported"]
            if not finding_tags and category not in _NON_FINDING_CATEGORIES:
                emitted.append(("gap:crosswalk-unmapped", "reported", "unmapped-producer-rule"))
            for tag, basis, source_rule in sorted(set(emitted)):
                producer = {"name": key, "rule_id": rule_id, "mapping_rule": source_rule,
                            "version": rules.sha256}
                if ci_job is not None:
                    producer["ci_job"] = ci_job
                records.append(assignment(vocabulary=vocabulary, tag=tag, basis=basis, subject=subject,
                                          producer=producer, evidence=evidence))
    return records, sorted(set(gaps))


def collect_coverage_gaps(indexes: AcceptedIndexes, scope: Scope, vocabulary: Vocabulary,
                          rules: CapabilityRules) -> tuple[list[dict[str, Any]], list[str]]:
    """Gap tags for every shard that reports incomplete coverage, and for absent required indexes."""
    records: list[dict[str, Any]] = []
    notes: list[str] = []
    for identity in indexes.identities:
        kind = rules.coverage_gaps.get(str(identity["name"]))
        if kind is None:
            continue
        coverage = [row for row in indexes.coverage(identity) if row["status"] != "complete"]
        declared = [str(item) for item in identity.get("gaps", ())]
        if not coverage and not declared:
            continue
        shard_id = str(identity.get("shard_id", "default"))
        parameterized = kind.split(":", 1)[1] in vocabulary.namespaces["gap"].parameterized
        tag = f"{kind}:{segment(shard_id)}" if parameterized else kind
        evidence = [{"ref": f"index:{identity['name']}/{shard_id}", "index": identity["name"],
                     "shard_id": shard_id, "index_sha256": identity["sha256"],
                     "coverage": coverage[:10], "declared_gaps": declared[:10]}]
        records.append(assignment(
            vocabulary=vocabulary, tag=tag, basis="reported", subject=dict(scope.project),
            producer={"name": "retrieval-coverage", "rule_id": f"coverage:{identity['name']}",
                      "version": rules.sha256}, evidence=evidence))
    for name in REQUIRED_INDEXES:
        if indexes.shards(name):
            continue
        kind = rules.coverage_gaps[name]
        parameterized = kind.split(":", 1)[1] in vocabulary.namespaces["gap"].parameterized
        tag = f"{kind}:index-unavailable" if parameterized else kind
        notes.append(f"required index is unavailable in the accepted manifest: {name}")
        records.append(assignment(
            vocabulary=vocabulary, tag=tag, basis="reported", subject=dict(scope.project),
            producer={"name": "retrieval-coverage", "rule_id": f"required:{name}", "version": rules.sha256},
            evidence=[{"ref": f"manifest:{indexes.manifest_sha256}", "index": name, "missing": True,
                       "manifest_sha256": indexes.manifest_sha256}]))
    return records, notes

