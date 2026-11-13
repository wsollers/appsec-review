"""Bounded readers that turn accepted retrieval shards into observed tag assignments.

Every reader queries immutable, hash-verified index shards; none scans the target tree. Producer
text is data: it is matched against pinned rules and never interpreted as an instruction.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import sqlite3
from typing import Any

from appsec_review.jobs.cataloging import (
    MANIFEST_ECOSYSTEMS, MANIFEST_SUFFIX_ECOSYSTEMS, SOURCE_ECOSYSTEMS, manifest_ecosystem,
)
from appsec_review.jobs.component_ownership import Ownership, resolve_ownership
from appsec_review.graph.catalog import LANGUAGE_ALIASES
from appsec_review.graph.contract import fact_identity, validate_payload
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.retrieval import EntityKind, LogicalIdentity, SourceLocation
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.retrieval.source_resolution import read_source_bytes, source_native
from appsec_review.storage import canonical_json, file_sha256
from appsec_review.swift_policy import SWIFT_KNOWN_GAP, is_swift_language, is_swift_path

from .taxonomy import (
    CapabilityRules, TaxonomyError, Vocabulary, assignment, merge_assignments, normalize_cert, normalize_cwe, segment,
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

    def __init__(self, run_root: Path, *, manifest_path: Path | None = None,
                 manifest_sha256: str | None = None):
        self.run_root = Path(run_root)
        if manifest_path is None or manifest_sha256 is None:
            manifest_path, manifest_sha = resolve_accepted_manifest(self.run_root)
        else:
            manifest_sha = manifest_sha256
        self.manifest, self.manifest_sha256 = load_verified_manifest(self.run_root, manifest_path, manifest_sha)
        self.manifest_path = manifest_path
        self.target_snapshot = str(self.manifest["target_snapshot"])
        self.identities = [dict(item) for item in self.manifest["indexes"] if item["name"] != TAG_INDEX]

    def shards(self, name: str) -> list[Mapping[str, Any]]:
        return sorted((item for item in self.identities if item["name"] == name),
                      key=lambda item: str(item.get("shard_id", "default")))

    def _open(self, identity: Mapping[str, Any]) -> sqlite3.Connection:
        from appsec_review.runtime.inputs import observe_shard
        observe_shard(self.run_root, identity)
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
                ", l.ambiguous, l.producer_location_json "
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
                if identity["name"] == "graph":
                    location["ambiguous"] = bool(value["ambiguous"])
                    location["producer_location"] = json.loads(value["producer_location_json"])
            rows.append(Row(value["identity"], value["kind"], value["native_id"], value["name"],
                            json.loads(value["payload_json"]), location))
        return rows, len(values) > limit

    def source_bytes(self, location: Mapping[str, Any]) -> bytes:
        """Resolve only this accepted location, through the existing bounded custody verifier."""
        return read_source_bytes(
            self.run_root, Path(str(self.manifest["target_root"])),
            target_snapshot=self.target_snapshot, path=location["path"], sha256=location["file_sha256"],
            native=source_native(location.get("producer_location", {})))

    def coverage(self, identity: Mapping[str, Any]) -> list[dict[str, Any]]:
        with self._open(identity) as database:
            return [{"area": row["area"], "status": row["status"], "gap": row["gap"]}
                    for row in database.execute("SELECT area, status, gap FROM coverage ORDER BY area, status")]


OWNERSHIP_RULES_VERSION = "appsec-review/component-ownership/1"
OWNERSHIP_STATUSES = ("owned", "shared", "ambiguous", "unowned", "not_applicable")


def ownership_rules() -> dict[str, Any]:
    """Versioned identity of the component-ownership rules, including the central ecosystem tables."""
    tables = {"manifest_names": MANIFEST_ECOSYSTEMS, "manifest_suffixes": MANIFEST_SUFFIX_ECOSYSTEMS,
              "source_suffixes": SOURCE_ECOSYSTEMS}
    return {"version": OWNERSHIP_RULES_VERSION,
            "tables_sha256": hashlib.sha256(canonical_json(tables)).hexdigest()}


def component_topology_sha256(components: Iterable[Mapping[str, Any]], rules: Mapping[str, Any]) -> str:
    """Hash the component roots, manifests, and ecosystems together with the ownership rules."""
    return hashlib.sha256(canonical_json({"components": [dict(item) for item in components],
                                          "ownership_rules": dict(rules)})).hexdigest()


@dataclass(frozen=True, slots=True)
class Scope:
    """Subjects that every collector shares: the project and the cataloged components."""

    target_snapshot: str
    project: Mapping[str, Any]
    components: tuple[Mapping[str, Any], ...]

    def ownership(self, path: str | None) -> Ownership:
        return resolve_ownership(path, self.components)

    def subjects(self, kind: str, logical_id: str, path: str | None = None, **extra: Any) -> list[dict[str, Any]]:
        """Return one subject per component the path resolves to, or one unassigned subject."""
        decision = self.ownership(path)
        base: dict[str, Any] = {"kind": kind, "logical_id": logical_id, "component_id": None,
                                "project_id": self.project["logical_id"],
                                "component_ownership": decision.status,
                                "component_ownership_basis": decision.basis}
        if decision.status in {"shared", "ambiguous"}:
            base["component_candidates"] = list(decision.candidates)
        if path:
            base["path"] = path
        base.update({key: item for key, item in extra.items() if item is not None})
        if not decision.component_ids:
            return [base]
        return [{**base, "component_id": component_id} for component_id in decision.component_ids]

    def component_subject(self, component_id: str) -> dict[str, Any] | None:
        for component in self.components:
            if component["component_id"] == component_id:
                return {"kind": "component", "logical_id": component["logical_id"], "component_id": component_id,
                        "project_id": self.project["logical_id"], "component_ownership": "owned",
                        "component_ownership_basis": "component-subject"}
        return None


def resolve_scope(indexes: AcceptedIndexes, limit: int) -> tuple[Scope, list[str]]:
    gaps: list[str] = []
    project_id = LogicalIdentity.derive(EntityKind.PROJECT, indexes.target_snapshot,
                                        {"scope": "security-tagging", "target_snapshot": indexes.target_snapshot})
    project = {"kind": "project", "logical_id": project_id.value, "component_id": None,
               "project_id": project_id.value, "component_ownership": "not_applicable",
               "component_ownership_basis": "project-subject"}
    components = []
    for identity in indexes.shards("components"):
        rows, truncated = indexes.rows(identity, (EntityKind.COMPONENT.value,), limit)
        if truncated:
            gaps.append(f"components/{identity.get('shard_id')}: component bound {limit} reached")
        for row in rows:
            component_id = row.payload.get("component_id")
            if isinstance(component_id, str) and component_id:
                manifest = row.payload.get("manifest")
                manifest = manifest if isinstance(manifest, str) and manifest else None
                components.append({"component_id": component_id, "logical_id": row.identity,
                                   "root": str(row.payload.get("root") or "."), "manifest": manifest,
                                   "ecosystem": manifest_ecosystem(manifest)})
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
                         rules: CapabilityRules, limit: int, *,
                         enable_swift: bool = False) -> tuple[list[dict[str, Any]], list[str]]:
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
            if not enable_swift and (is_swift_path(path) or is_swift_language(row.payload.get("language"))):
                gaps.append(SWIFT_KNOWN_GAP)
                continue
            subjects = scope.subjects("source_file", row.identity, path)
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
            for subject in subjects:
                for tag, rule_id in emitted:
                    records.append(assignment(
                        vocabulary=vocabulary, tag=tag, basis="declared", subject=subject,
                        producer={"name": "capability-rules", "rule_id": rule_id, "version": rules.sha256},
                        evidence=evidence))
    return records, sorted(set(gaps))


def _graph_location(row: Row, snapshot: str) -> SourceLocation:
    """Recheck the graph contract and identity, never trusting a published eligibility flag alone."""
    validate_payload(row.payload)
    if row.kind != row.payload["family"] or row.kind not in {"entry_point", "sink_site"}:
        raise ValueError("family differs from the accepted entity kind")
    if not isinstance(row.location, Mapping):
        raise ValueError("source location is missing")
    location = SourceLocation(**row.location)
    numeric = ("start_byte", "end_byte", "start_line", "end_line", "start_column", "end_column")
    if (any(type(row.location[key]) is not int for key in numeric)
            or location.target_snapshot != snapshot or location.ambiguous or location.confidence != 1.0
            or location.end_byte <= location.start_byte):
        raise ValueError("source location is not exact or belongs to another snapshot")
    result = row.payload["result"]
    scope = row.payload["scope"]
    if (not isinstance(scope["scope_id"], str) or not isinstance(scope["language"], str)
            or not scope["language"] or any(scope[key] is not None
            and (not isinstance(scope[key], str) or not scope[key]) for key in ("component_id", "build_unit_id"))):
        raise ValueError("graph scope identities are malformed")
    field = "source_class" if row.kind == "entry_point" else "sink_class"
    if not isinstance(result.get(field), str) or not result[field]:
        raise ValueError("operation class is missing")
    native = {"scope_id": row.payload["scope"]["scope_id"], "path": location.path,
              "start_byte": location.start_byte, "end_byte": location.end_byte, field: result[field]}
    if row.kind == "sink_site":
        argument = result.get("argument_index")
        if type(argument) is not int or argument < -1:
            raise ValueError("sink argument index is invalid")
        native["argument_index"] = argument
    if fact_identity(row.kind, snapshot, native).value != row.identity or row.native_id != row.identity:
        raise ValueError("graph native identity does not resolve to the accepted site")
    return location


def _resolving_span(location: SourceLocation, source: SourceFile) -> bool:
    """Check absolute lines/columns against the exact, hash-verified byte range."""
    start = source.offset(location.start_line, location.start_column)
    end = source.offset(location.end_line, location.end_column)
    return (start, end) == (location.start_byte, location.end_byte)


def collect_graph_facts(indexes: AcceptedIndexes, scope: Scope, vocabulary: Vocabulary,
                        rules: CapabilityRules, limit: int, *,
                        enable_swift: bool = False) -> tuple[list[dict[str, Any]], list[str]]:
    """Observed operations only: no vulnerability, control-satisfaction or deployment inference.

    The existing per-shard entity bound also bounds graph reads. Source verification holds only
    one bounded file at a time; immutable graph references retain their original producer/scope.
    """
    records: list[dict[str, Any]] = []
    gaps: list[str] = []
    shards = indexes.shards("graph")
    if not shards:
        return [], ["graph-capability:missing_graph: accepted graph index is unavailable"]
    pending: list[tuple[Row, Mapping[str, Any]]] = []
    contents: dict[str, bytes] = {}
    conflicts: set[str] = set()
    for identity in shards:
        gaps.extend(f"graph-capability:producer_coverage: {identity.get('shard_id', 'default')}: {note}"
                    for note in identity.get("gaps", ()))
        rows, truncated = indexes.rows(identity, ("entry_point", "sink_site"), limit)
        if truncated:
            gaps.append(f"graph-capability:entity_bound: {identity.get('shard_id', 'default')}: {limit}")
        for row in rows:
            content = hashlib.sha256(canonical_json({"kind": row.kind, "native_id": row.native_id,
                                                     "payload": row.payload, "location": row.location})).digest()
            previous = contents.setdefault(row.identity, content)
            if previous != content:
                conflicts.add(row.identity)
            pending.append((row, identity))
    if not pending:
        gaps.append("graph-capability:missing_site_facts: accepted graph contains no entry_point or sink_site facts")
    cached_key: bytes | None = None
    cached_source: SourceFile | None = None
    cached_error: str | None = None
    for row, identity in sorted(pending, key=lambda item: (
            str((item[0].location or {}).get("path", "")), item[0].identity,
            str(item[1].get("shard_id", "default")))):
        def gap(reason: str, detail: str) -> None:
            gaps.append(f"graph-capability:{reason}: {row.identity}: {detail}")

        if row.identity in conflicts:
            gap("conflicting_fact", "accepted shards disagree on the same logical fact")
            continue
        try:
            location = _graph_location(row, scope.target_snapshot)
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            gap("malformed_fact", str(exc))
            continue
        eligibility = row.payload["admissibility"]
        for note in row.payload["gaps"]:
            gap("producer_fact_gap", note)
        if eligibility["direct_eligible"] is not True:
            gap("ineligible_fact", ",".join(eligibility["ineligibility_reasons"]))
            continue
        if not enable_swift and (is_swift_path(location.path)
                                 or is_swift_language(row.payload["scope"]["language"])):
            gap("unsupported_language", SWIFT_KNOWN_GAP)
            continue
        field = "source_class" if row.kind == "entry_point" else "sink_class"
        klass = row.payload["result"][field]
        language = LANGUAGE_ALIASES.get(row.payload["scope"]["language"].strip().lower())
        matched = [rule for rule in rules.graph_rules
                   if rule["family"] == row.kind and klass in rule["classes"]
                   and ("languages" not in rule or language is not None and language in {
                       LANGUAGE_ALIASES.get(name.strip().lower()) for name in rule["languages"]})]
        if not matched:
            gap("unmapped_class", f"{row.kind}/{klass}: no semantics-preserving vocabulary mapping")
            continue
        try:
            native = source_native(location.producer_location)
        except ValueError as exc:
            gap("source_unresolved", str(exc))
            continue
        key = canonical_json({"path": location.path, "sha256": location.file_sha256, "native": native})
        if key != cached_key:
            cached_key, cached_source, cached_error = key, None, None
            try:
                cached_source = SourceFile(location.file_sha256, indexes.source_bytes(row.location))
            except (OSError, ValueError, TypeError, KeyError) as exc:
                cached_error = str(exc)
        if cached_error is not None:
            gap("source_unresolved", cached_error)
            continue
        if cached_source is None or not _resolving_span(location, cached_source):
            gap("source_span_mismatch", "accepted lines/columns do not resolve to the exact byte span")
            continue
        ownership = scope.ownership(location.path)
        component = row.payload["scope"]["component_id"]
        if component and ownership.component_ids and component not in ownership.component_ids:
            gap("component_scope_disagreement", "graph scope and source ownership disagree")
            continue
        if ownership.status in {"ambiguous", "unowned"}:
            gap("component_ownership", ownership.status)
        site = LogicalIdentity.derive(EntityKind.SOURCE_SPAN, scope.target_snapshot, {
            "path": location.path, "sha256": location.file_sha256,
            "start_byte": location.start_byte, "end_byte": location.end_byte})
        subjects = scope.subjects("source_span", site.value, location.path,
                                  native_address=f"graph-site:{location.path}:{location.start_byte}:{location.end_byte}")
        evidence = {**_evidence(row, identity), "graph_family": row.kind,
                    "graph_producer": dict(row.payload["producer"]), "graph_scope": dict(row.payload["scope"]),
                    "graph_upstream": list(row.payload["upstream"]),
                    "index_producer": dict(identity.get("producer", {}))}
        for rule in matched:
            for tag in rule["emit"]:
                records.extend(assignment(
                    vocabulary=vocabulary, tag=tag, basis="invoked", subject=subject,
                    producer={"name": row.payload["producer"]["name"], "rule_id": rule["id"],
                              "version": rules.sha256, "graph_producer": dict(row.payload["producer"])},
                    evidence=[evidence],
                    flow_role="sink" if row.kind == "sink_site" and vocabulary.namespace(tag).flow_role else None)
                    for subject in subjects)
    return merge_assignments(records), sorted(set(gaps))


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
            subjects = scope.subjects("tool_observation", row.identity, path if isinstance(path, str) else None)
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
                records.extend(assignment(vocabulary=vocabulary, tag=tag, basis=basis, subject=subject,
                                          producer=producer, evidence=evidence) for subject in subjects)
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
