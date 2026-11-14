"""The collation pass (T-5008): closed facet tags for first-party files and components.

Design: ``docs/architecture/collation-pass.md``. The pass runs as the ``collation.collate_facets``
unit of ``job_security_tagging`` after capability collection. It reads only the attempt's accepted
shards and hash-verified first-party source bytes, applies the pinned collation rules of the
capability-rules file, and publishes ``tag-assignment/1`` records in the facet namespaces
(``role``, ``exposure``, ``trust``, ``mechanism``, ``asset``, ``state``) plus one ``target:*`` class
per component. Every record names its basis, its evidence span or the assignments it derives from,
and the rule that produced it. Tags are routing data: a wrong facet can only misroute.

A missing source is a named gap, never a guessed tag. Facets are assigned only to files the T-165
dispositions keep first-party; vendored, SDK, generated and test files are counted, not tagged.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from appsec_review.config.collation import CollationSettings
from appsec_review.retrieval import EntityKind
from appsec_review.review.dispositions import FIRST_PARTY

from .producers import AcceptedIndexes, Row, Scope, _evidence
from .taxonomy import (
    COLLATION_NAMESPACES, FACET_NAMESPACES, TARGET_NAMESPACE, CapabilityRules, Vocabulary, assignment,
    merge_assignments, split_tag,
)


COLLATION_SCHEMA = "appsec-review/collation-pass/1"
PRODUCER = "collation"
RULE_PREFIX = "collation:"
# Build-point kinds that produce a library rather than a program (build_discovery build points).
LIBRARY_KINDS = frozenset({"static_library", "shared_library", "object_library", "interface_library", "module_library"})
EXECUTABLE_KINDS = frozenset({"executable"})
# Target documents that establish a component-level mechanism (indexing.target_documents.KINDS).
DOCUMENT_MECHANISMS = {"openapi": "mechanism:http", "postman": "mechanism:http", "graphql": "mechanism:http",
                       "protobuf": "mechanism:rpc", "asyncapi": "mechanism:rpc"}
MECHANISM_PREFIX = "mechanism:"
# The structural target classes the collector derives in code; the data-driven ones are target_rules.
STRUCTURAL_TARGET_RULES = {
    "target-library": "target:library", "target-build-tooling": "target:build-tooling",
    "target-test-only": "target:test-only",
}


@dataclass
class _File:
    row: Row
    path: str
    language: str | None
    component_ids: tuple[str, ...]
    subjects: list[dict[str, Any]]
    source_identity: Mapping[str, Any]
    records: list[dict[str, Any]] = field(default_factory=list)   # facet assignments on this file
    inputs: list[Mapping[str, Any]] = field(default_factory=list)  # capability assignments on this file

    def tags(self) -> set[str]:
        return {record["tag"] for record in self.records}


def _matches(pattern: str, tag: str) -> bool:
    return tag.startswith(pattern[:-1]) if pattern.endswith("*") else tag == pattern


def _any(patterns: Iterable[str], tags: Iterable[str]) -> list[str]:
    present = sorted(set(tags))
    return [tag for tag in present if any(_matches(pattern, tag) for pattern in patterns)]


def _lines(data: bytes) -> list[tuple[int, int, int, str]]:
    """``(line_number, start_byte, end_byte, text)`` per line, bytes exact, text decoded for matching."""
    result = []
    offset = 0
    for number, raw in enumerate(data.splitlines(keepends=True), 1):
        text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        result.append((number, offset, offset + len(raw.rstrip(b"\r\n")), text))
        offset += len(raw)
    return result


class _Collector:
    def __init__(self, indexes: AcceptedIndexes, scope: Scope, vocabulary: Vocabulary, rules: CapabilityRules,
                 settings: CollationSettings, limit: int) -> None:
        if rules.collation is None:
            raise ValueError("the pinned capability rules carry no collation rules")
        self.indexes, self.scope, self.vocabulary, self.rules = indexes, scope, vocabulary, rules
        self.collation = rules.collation
        self.settings, self.limit = settings, limit
        self.producer = {"name": PRODUCER, "version": rules.sha256}
        self.gaps: list[str] = []
        self.files: dict[str, _File] = {}
        self.skipped: Counter[str] = Counter()
        self.component_inputs: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        self.component_records: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.sources: dict[str, str] = {}

    # Records ------------------------------------------------------------------------------------
    def _declared(self, tag: str, subject: Mapping[str, Any], rule_id: str, evidence: list[dict[str, Any]],
                  confidence: str) -> dict[str, Any]:
        return assignment(vocabulary=self.vocabulary, tag=tag, basis="declared", subject=subject,
                          producer={**self.producer, "rule_id": rule_id}, evidence=evidence, confidence=confidence)

    def _derived(self, tag: str, subject: Mapping[str, Any], rule_id: str, derived_from: Iterable[str],
                 evidence: Iterable[Mapping[str, Any]] = (), confidence: str = "high") -> dict[str, Any]:
        return assignment(vocabulary=self.vocabulary, tag=tag, basis="derived", subject=subject,
                          producer={**self.producer, "rule_id": rule_id}, evidence=evidence,
                          derived_from=derived_from, crosswalk_rule=RULE_PREFIX + rule_id, confidence=confidence)

    # Scope --------------------------------------------------------------------------------------
    def resolve_files(self) -> None:
        shards = self.indexes.shards("source")
        if not shards:
            self.gaps.append("collation:no_source_index: accepted source index is unavailable; nothing to collate")
        per_component: Counter[str] = Counter()
        for identity in shards:
            rows, truncated = self.indexes.rows(identity, (EntityKind.SOURCE_FILE.value,), self.limit)
            if truncated:
                self.gaps.append(f"collation:source_bound: source/{identity.get('shard_id')}: {self.limit}")
            for row in sorted(rows, key=lambda item: (str((item.location or {}).get("path", "")), item.identity)):
                if row.location is None:
                    continue
                path = str(row.location["path"])
                disposition = self.settings.source_dispositions.classify(path)
                if disposition != FIRST_PARTY:
                    self.skipped[disposition] += 1
                    continue
                subjects = self.scope.subjects("source_file", row.identity, path)
                components = tuple(sorted(subject["component_id"] for subject in subjects
                                          if subject.get("component_id")))
                if components and any(per_component[cid] >= self.settings.max_files_per_component
                                      for cid in components):
                    self.gaps.append(f"collation:file_bound: {path}: max_files_per_component "
                                     f"{self.settings.max_files_per_component} reached")
                    continue
                for cid in components:
                    per_component[cid] += 1
                language = row.payload.get("language")
                self.files[path] = _File(row, path, language if isinstance(language, str) and language else None,
                                         components, subjects, identity)

    def take_inputs(self, inputs: Iterable[Mapping[str, Any]]) -> None:
        """Capability assignments of the collectors, by first-party file or by component."""
        for record in inputs:
            subject = record.get("subject") or {}
            namespace = str(record.get("namespace") or split_tag(record["tag"])[0])
            if namespace in COLLATION_NAMESPACES or namespace == "gap":
                continue
            kind = subject.get("kind")
            path = subject.get("path")
            if kind in {"source_file", "source_span"} and isinstance(path, str) and path in self.files:
                self.files[path].inputs.append(record)
            elif kind == "component" and subject.get("component_id"):
                self.component_inputs[str(subject["component_id"])].append(record)
            elif kind == "tool_observation" and record.get("basis") == "declared" and subject.get("component_id"):
                # A package capability (declared through a manifest or SBOM entry) is a component fact.
                self.component_inputs[str(subject["component_id"])].append(record)

    # Lexical and path facts -----------------------------------------------------------------------
    def _language_tag(self, file: _File) -> str | None:
        return self.rules.languages.get(file.language) if file.language else None

    def lexical_facts(self) -> None:
        for path in sorted(self.files):
            file = self.files[path]
            self._path_facts(file)
            lang = self._language_tag(file)
            applicable = [rule for rule in self.collation.lexical_rules
                          if lang is not None and ("languages" not in rule or lang in rule["languages"])]
            if lang is None:
                continue
            if not applicable:
                self.gaps.append(f"collation:no_lexical_rules:{lang}: {path}")
                continue
            size = int(file.row.payload.get("size_bytes") or (file.row.location or {}).get("end_byte") or 0)
            if size > self.settings.max_source_bytes_per_file:
                self.gaps.append(f"collation:source_unread:{path}: {size} bytes exceeds "
                                 f"max_source_bytes_per_file {self.settings.max_source_bytes_per_file}")
                continue
            try:
                data = self.indexes.source_bytes(file.row.location)
            except (OSError, ValueError, TypeError, KeyError) as exc:
                self.gaps.append(f"collation:source_unread:{path}: {exc}")
                continue
            if len(data) > self.settings.max_source_bytes_per_file:
                self.gaps.append(f"collation:source_unread:{path}: {len(data)} bytes exceeds "
                                 f"max_source_bytes_per_file {self.settings.max_source_bytes_per_file}")
                continue
            lines = _lines(data)
            for rule in applicable:
                patterns = self.collation.patterns[rule["id"]]
                hits = [line for line in lines if any(pattern.search(line[3]) for pattern in patterns)]
                if not hits:
                    continue
                number, start, end, text = hits[0]
                location = {**file.row.location, "start_byte": start, "end_byte": end, "start_line": number,
                            "end_line": number, "start_column": 1, "end_column": len(text) + 1,
                            "mapping_method": "collation-lexical", "confidence": 1.0}
                evidence = [{**_evidence(file.row, file.source_identity), "rule": rule["id"],
                             "match_count": len(hits), "span": {"start_line": number, "end_line": number},
                             "location": location}]
                confidence = rule.get("confidence", "medium" if rule["kind"] == "identifier" else "high")
                for tag in rule["emit"]:
                    for subject in file.subjects:
                        file.records.append(self._declared(tag, subject, rule["id"], evidence, confidence))

    def _path_facts(self, file: _File) -> None:
        name = PurePosixPath(file.path).name
        for rule in self.collation.path_rules:
            prefixes = tuple(rule.get("prefixes", ()))
            if prefixes and not file.path.startswith(prefixes):
                continue
            names, suffixes = rule.get("names", ()), tuple(rule.get("suffixes", ()))
            if (names or suffixes) and not (name in names or (suffixes and name.endswith(suffixes))):
                continue
            evidence = [{**_evidence(file.row, file.source_identity), "rule": rule["id"]}]
            for tag in rule["emit"]:
                for subject in file.subjects:
                    file.records.append(self._declared(tag, subject, rule["id"], evidence, "high"))

    # Derivation -----------------------------------------------------------------------------------
    def _apply_tag_rules(self, inputs: list[Mapping[str, Any]], subjects: list[Mapping[str, Any]],
                         out: list[dict[str, Any]]) -> None:
        for rule in self.collation.tag_rules:
            matched = [record for record in inputs
                       if any(_matches(pattern, record["tag"]) for pattern in rule["inputs"])]
            if not matched:
                continue
            ids = sorted({record["assignment_id"] for record in matched})
            for tag in rule["emit"]:
                for subject in subjects:
                    out.append(self._derived(tag, subject, rule["id"], ids))

    def _apply_facet_rules(self, records: list[dict[str, Any]], subjects: list[Mapping[str, Any]]) -> None:
        """Facet-to-facet rules to a fixed point; a rule resting on absence records its condition."""
        for _round in range(len(self.collation.facet_rules) + 1):
            present = {record["tag"] for record in records}
            added = False
            for rule in self.collation.facet_rules:
                hit = _any(rule["any_of"], present)
                if not hit or _any(rule.get("none_of", ()), present):
                    continue
                ids = sorted({record["assignment_id"] for record in records if record["tag"] in hit})
                evidence = ([{"ref": RULE_PREFIX + rule["id"], "condition": {"any_of": list(rule["any_of"]),
                              "none_of": list(rule["none_of"])}, "rests_on_absence": True}]
                            if rule.get("none_of") else ())
                confidence = "medium" if rule.get("none_of") else "high"
                for tag in rule["emit"]:
                    if tag in present:
                        continue
                    for subject in subjects:
                        records.append(self._derived(tag, subject, rule["id"], ids, evidence, confidence))
                    present.add(tag)
                    added = True
            if not added:
                return

    def derive_files(self) -> None:
        for path in sorted(self.files):
            file = self.files[path]
            self._apply_tag_rules([*file.inputs, *file.records], file.subjects, file.records)
            self._apply_facet_rules(file.records, file.subjects)
            file.records = merge_assignments(file.records)

    # Component roll-up and target class -----------------------------------------------------------
    def _build_points(self) -> dict[str, set[str]]:
        kinds: dict[str, set[str]] = defaultdict(set)
        shards = self.indexes.shards("build")
        self.sources["build"] = "available" if shards else "unavailable"
        if not shards:
            self.gaps.append("collation:no_build_facts: accepted build index is unavailable; "
                             "the library class rests on the absence of entry mechanisms")
        for identity in shards:
            rows, truncated = self.indexes.rows(identity, (EntityKind.BUILD_ACTION.value,), self.limit)
            if truncated:
                self.gaps.append(f"collation:build_bound: build/{identity.get('shard_id')}: {self.limit}")
            for row in rows:
                for point in row.payload.get("build_points") or ():
                    if not isinstance(point, Mapping):
                        continue
                    kind = str(point.get("kind") or "")
                    for source in point.get("sources") or ():
                        for cid in self.scope.ownership(str(source)).component_ids:
                            kinds[cid].add(kind)
        return kinds

    def _document_facts(self) -> None:
        shards = self.indexes.shards("documents")
        found = False
        for identity in shards:
            rows, truncated = self.indexes.rows(identity, (EntityKind.DOCUMENT_RECORD.value,), self.limit)
            if truncated:
                self.gaps.append(f"collation:documents_bound: documents/{identity.get('shard_id')}: {self.limit}")
            for row in sorted(rows, key=lambda item: item.identity):
                found = True
                tag = DOCUMENT_MECHANISMS.get(str(row.payload.get("kind") or ""))
                path = (row.location or {}).get("path") or row.payload.get("path")
                if tag is None or not isinstance(path, str):
                    continue
                for cid in self.scope.ownership(path).component_ids:
                    subject = self.scope.component_subject(cid)
                    if subject is not None:
                        self.component_records[cid].append(self._declared(
                            tag, subject, "document-interface", [{**_evidence(row, identity), "rule": "document-interface"}],
                            "high"))
        self.sources["documents"] = "available" if found else "unavailable"
        if not found:
            self.gaps.append("collation:no_documents: no accepted target document (OpenAPI, protobuf, AsyncAPI, "
                             "GraphQL) establishes an interface")

    def derive_components(self) -> list[dict[str, Any]]:
        kinds = self._build_points()
        self._document_facts()
        self.sources["graph"] = "available" if self.indexes.shards("graph") else "unavailable"
        if self.sources["graph"] == "unavailable":
            self.gaps.append("collation:no_graph_facts: accepted graph index is unavailable; facets rest on "
                             "lexical, path, package and document facts")
        summaries = []
        for component in self.scope.components:
            cid = component["component_id"]
            subject = self.scope.component_subject(cid)
            if subject is None:
                continue
            files = [file for file in self.files.values() if cid in file.component_ids]
            records = self.component_records[cid]
            if not files:
                self.gaps.append(f"collation:no_first_party_files:{cid}: the component has no first-party source "
                                 "file; it receives no facet or target class")
                summaries.append({"component_id": cid, "file_count": 0, "facets": [], "target_classes": [],
                                  "build_point_kinds": sorted(kinds.get(cid, ()))})
                continue
            by_tag: dict[str, set[str]] = defaultdict(set)
            for file in files:
                for record in file.records:
                    by_tag[record["tag"]].add(record["assignment_id"])
            for tag in sorted(by_tag):
                records.append(self._derived(tag, subject, "component-rollup", sorted(by_tag[tag])))
            self._apply_tag_rules(self.component_inputs.get(cid, []), [subject], records)
            self._apply_facet_rules(records, [subject])
            self._target_class(cid, subject, files, records, kinds.get(cid, set()))
            self.component_records[cid] = merge_assignments(records)
            summaries.append({
                "component_id": cid, "file_count": len(files),
                "facets": sorted({r["tag"] for r in self.component_records[cid]
                                  if r["namespace"] in FACET_NAMESPACES}),
                "target_classes": sorted({r["tag"] for r in self.component_records[cid]
                                          if r["namespace"] == TARGET_NAMESPACE}),
                "build_point_kinds": sorted(kinds.get(cid, ()))})
        return summaries

    def _target_class(self, cid: str, subject: Mapping[str, Any], files: list[_File],
                      records: list[dict[str, Any]], build_kinds: set[str]) -> None:
        present = {record["tag"] for record in records}
        classes: list[tuple[str, str, list[str], list[Mapping[str, Any]], str]] = []
        for rule in self.collation.target_rules:
            hit = _any(rule["any_of"], present)
            if hit and not _any(rule.get("none_of", ()), present):
                ids = sorted({r["assignment_id"] for r in records if r["tag"] in hit})
                evidence = ([{"ref": RULE_PREFIX + rule["id"], "condition": {"any_of": list(rule["any_of"]),
                              "none_of": list(rule["none_of"])}, "rests_on_absence": True}]
                            if rule.get("none_of") else [])
                for tag in rule["emit"]:
                    classes.append((tag, rule["id"], ids, evidence, "medium" if rule.get("none_of") else "high"))
        mechanisms = sorted(tag for tag in present if tag.startswith(MECHANISM_PREFIX))
        glue = [file for file in files if "role:build-glue" in file.tags()]
        tests = [file for file in files if "role:test" in file.tags()]
        if len(glue) == len(files):
            ids = sorted({r["assignment_id"] for file in glue for r in file.records if r["tag"] == "role:build-glue"})
            classes.append(("target:build-tooling", "target-build-tooling", ids, [], "high"))
        elif len(tests) + len(glue) == len(files) and tests:
            ids = sorted({r["assignment_id"] for file in tests for r in file.records if r["tag"] == "role:test"})
            classes.append(("target:test-only", "target-test-only", ids, [], "high"))
        elif not classes and not mechanisms:
            only_libraries = bool(build_kinds) and build_kinds <= LIBRARY_KINDS
            if only_libraries or self.sources.get("build") == "unavailable" or not build_kinds:
                evidence = [{"ref": RULE_PREFIX + "target-library",
                             "condition": {"build_point_kinds": sorted(build_kinds), "mechanisms": []},
                             "rests_on_absence": not only_libraries}]
                ids = sorted({r["assignment_id"] for r in records})
                if ids:
                    classes.append(("target:library", "target-library", ids, evidence,
                                    "high" if only_libraries else "medium"))
                else:
                    self.gaps.append(f"collation:target_class_unresolved:{cid}: no facet on any first-party file")
                    return
        if not classes:
            self.gaps.append(f"collation:target_class_unresolved:{cid}: no target rule fired "
                             f"(mechanisms={mechanisms})")
            return
        for tag, rule_id, ids, evidence, confidence in classes:
            records.append(self._derived(tag, subject, rule_id, ids, evidence, confidence))

    # Output ----------------------------------------------------------------------------------------
    def document(self, components: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "schema": COLLATION_SCHEMA, "target_snapshot": self.scope.target_snapshot,
            "vocabulary_sha256": self.vocabulary.sha256, "capability_rules_sha256": self.rules.sha256,
            "settings": self.settings.record(),
            "files": [{"path": path, "component_ids": list(file.component_ids), "language": file.language,
                       "facets": sorted({r["tag"] for r in file.records}),
                       "assignment_ids": sorted({r["assignment_id"] for r in file.records})}
                      for path, file in sorted(self.files.items())],
            "skipped_dispositions": dict(sorted(self.skipped.items())),
            "components": components, "sources": dict(sorted(self.sources.items())),
            "gaps": sorted(set(self.gaps)),
        }


def collect_facets(indexes: AcceptedIndexes, scope: Scope, vocabulary: Vocabulary, rules: CapabilityRules,
                   settings: CollationSettings, inputs: Iterable[Mapping[str, Any]], limit: int
                   ) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    """Facet and target assignments for the first-party files and components of the accepted scope.

    Returns ``(records, gaps, document)``: the validated ``tag-assignment/1`` records, the named gaps
    and the ``collation-pass/1`` summary document. Deterministic for the same accepted manifest,
    pinned taxonomy, settings and input assignments, whatever order the inputs arrive in.
    """
    collector = _Collector(indexes, scope, vocabulary, rules, settings, limit)
    collector.resolve_files()
    collector.take_inputs(sorted(inputs, key=lambda record: record["assignment_id"]))
    collector.lexical_facts()
    collector.derive_files()
    components = collector.derive_components()
    records = merge_assignments([*(record for file in collector.files.values() for record in file.records),
                                 *(record for cid in sorted(collector.component_records)
                                   for record in collector.component_records[cid])])
    gaps = sorted(set(collector.gaps))
    return records, gaps, collector.document(components)


__all__ = ["COLLATION_SCHEMA", "DOCUMENT_MECHANISMS", "LIBRARY_KINDS", "PRODUCER", "collect_facets"]
