from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import INDEX_SCHEMA, load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256

from .cloud import build_cloud
from .crosswalk import Crosswalk, evaluate, load_crosswalk
from .producers import (
    TAG_INDEX, AcceptedIndexes, Scope, collect_coverage_gaps, collect_observation_facts,
    collect_source_facts, resolve_scope,
)
from .taxonomy import (
    CapabilityRules, TaxonomyError, Vocabulary, assignment, load_capability_rules, load_vocabulary,
    merge_assignments, validate_assignment,
)


SCHEMA = "appsec-review/security-tagging-handoff/1"
TOPOLOGY = {
    "taxonomy": ("load_taxonomy",),
    "scope": ("resolve_inputs",),
    "collection": ("source_facts", "observation_facts", "coverage_gaps"),
    "crosswalk": ("apply_crosswalk",),
    "integrity": ("validate_assignments",),
    "publication": ("publish_index", "publish_tag_cloud", "publish_handoff"),
}
COLLECTORS = tuple(f"collection.{task}" for task in TOPOLOGY["collection"])
STANDING_GAPS = (
    "invoked capability detection is not implemented; func tags are declared from package inventory only",
    "upstream CWE->CAPEC->ATT&CK crosswalk is deferred until the MITRE feed is pinned into the run",
    "taint_path, iac_resource, k8s_object, and container_stage crosswalk scopes are not implemented",
)
_TAXONOMY_KEYS = ("vocabulary_path", "vocabulary_sha256", "capability_rules_path",
                  "capability_rules_sha256", "crosswalk_path", "crosswalk_sha256")


def _settings(settings: Mapping[str, Any]) -> tuple[Mapping[str, Any], int, int]:
    taxonomy = settings.get("taxonomy")
    if not isinstance(taxonomy, Mapping) or set(taxonomy) != set(_TAXONOMY_KEYS):
        raise ValueError("security tagging taxonomy settings must name exactly the pinned files and hashes")
    limits = []
    for key, maximum in (("max_entities_per_shard", 1_000_000), ("max_assignments", 2_000_000)):
        value = settings.get(key)
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"security tagging configured bound is invalid: {key}")
        limits.append(value)
    if set(settings) - {"taxonomy", "max_entities_per_shard", "max_assignments", "configuration_sha256"}:
        raise ValueError("security tagging settings contain unknown keys")
    return taxonomy, limits[0], limits[1]


def _taxonomy(root: Path, settings: Mapping[str, Any]) -> tuple[Vocabulary, CapabilityRules, Crosswalk]:
    taxonomy, _, _ = _settings(settings)
    vocabulary = load_vocabulary(root / taxonomy["vocabulary_path"], taxonomy["vocabulary_sha256"])
    rules = load_capability_rules(root / taxonomy["capability_rules_path"],
                                  taxonomy["capability_rules_sha256"], vocabulary)
    crosswalk = load_crosswalk(root / taxonomy["crosswalk_path"], taxonomy["crosswalk_sha256"], vocabulary)
    return vocabulary, rules, crosswalk


def _unit_taxonomy(unit: UnitContext) -> tuple[Vocabulary, CapabilityRules, Crosswalk]:
    values = _taxonomy(unit.job.repository_root, unit.job.config.settings)
    pinned = unit.output("taxonomy.load_taxonomy")["identities"]
    if (values[0].sha256, values[1].sha256, values[2].sha256) != (
            pinned["vocabulary_sha256"], pinned["capability_rules_sha256"], pinned["crosswalk_sha256"]):
        raise ValueError("taxonomy identity changed during the attempt")
    return values


def _rel(run_root: Path, path: Path) -> str:
    return path.resolve().relative_to(run_root.resolve()).as_posix()


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": _rel(run_root, path), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _write(unit: UnitContext, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    path = unit.job.attempt_root / "artifacts" / "security-tagging" / name
    atomic_json(path, dict(value))
    return _artifact(unit.job.run_root, path)


def _read(unit: UnitContext, artifact: Mapping[str, Any]) -> dict[str, Any]:
    path = (unit.job.run_root / str(artifact["path"])).resolve()
    if unit.job.run_root.resolve() not in path.parents or file_sha256(path) != artifact["sha256"]:
        raise ValueError(f"security tagging artifact failed integrity verification: {artifact['path']}")
    return json.loads(path.read_text(encoding="utf-8"))


def _indexes(unit: UnitContext) -> AcceptedIndexes:
    indexes = AcceptedIndexes(unit.job.run_root)
    resolved = unit.output("scope.resolve_inputs")
    if indexes.manifest_sha256 != resolved["accepted_manifest"]["sha256"]:
        raise ValueError("accepted index manifest changed during the security tagging attempt")
    return indexes


def _scope(unit: UnitContext) -> Scope:
    value = _read(unit, unit.output("scope.resolve_inputs")["artifact"])
    return Scope(value["target_snapshot"], value["project"], tuple(value["components"]))


def _assignment_set(unit: UnitContext, name: str, records: list[dict[str, Any]], gaps: list[str]) -> dict[str, Any]:
    _, _, maximum = _settings(unit.job.config.settings)
    if len(records) > maximum:
        raise ValueError(f"security tagging assignment bound {maximum} exceeded by {name}")
    records = merge_assignments(records)
    artifact = _write(unit, f"{name}.json", {"schema": "appsec-review/tag-assignment-set/1",
                                             "collector": name, "assignments": records, "gaps": gaps})
    return {"artifact": artifact, "item_count": len(records), "gaps": gaps,
            "tag_counts": dict(sorted(Counter(record["tag"] for record in records).items())),
            "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}


def _validate_config(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("security tagging topology does not match central configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"security tagging task order mismatch: {step}")
    _taxonomy(context.repository_root, context.config.settings)
    resolve_accepted_manifest(context.run_root)


def _subject_location(record: Mapping[str, Any]) -> SourceLocation | None:
    for evidence in record["evidence"]:
        location = evidence.get("location")
        if isinstance(location, Mapping):
            return SourceLocation(
                target_snapshot=location["target_snapshot"], path=location["path"],
                file_sha256=location["file_sha256"], start_byte=location["start_byte"],
                end_byte=location["end_byte"], start_line=location["start_line"], end_line=location["end_line"],
                start_column=location["start_column"], end_column=location["end_column"],
                producer_location={"assignment_evidence": evidence["ref"]},
                mapping_method="tag-subject-evidence", confidence=float(location["confidence"]))
    return None


def _publish_shards(unit: UnitContext, records: list[dict[str, Any]], indexes: AcceptedIndexes,
                    identities: Mapping[str, str]) -> list[IndexIdentity]:
    snapshot = indexes.target_snapshot
    by_id = {record["assignment_id"]: record for record in records}
    families = sorted({record["family"] for record in records})
    shards = []
    for family in families:
        members = [record for record in records if record["family"] == family]
        shard_id = family.replace("_", "-")
        fingerprint = index_fingerprint(
            name=TAG_INDEX, target_snapshot=snapshot,
            producer_artifacts=[{"assignments_sha256": hashlib.sha256(canonical_json(members)).hexdigest()}],
            tool_identity={"vocabulary": identities["vocabulary_sha256"],
                           "capability_rules": identities["capability_rules_sha256"],
                           "crosswalk": identities["crosswalk_sha256"]},
            parser_identity="tag-assignment/1", normalizer_identity="tag-vocabulary/1",
            mapping_identity="tag-crosswalk/1", upstream_manifests=[indexes.manifest_sha256])
        path = unit.job.run_root / "data" / "indices" / TAG_INDEX / shard_id / f"{fingerprint}.sqlite"
        if path.is_file():
            sha256 = file_sha256(path)
        else:
            builder = IndexBuilder(path, name=TAG_INDEX, fingerprint=fingerprint, target_snapshot=snapshot,
                                   shard_id=shard_id)
            local_subjects: dict[str, Mapping[str, Any]] = {}
            for record in members:
                identity = LogicalIdentity.derive(EntityKind.TAG_ASSIGNMENT, snapshot,
                                                  {"assignment_id": record["assignment_id"]})
                subject = record["subject"]
                text = " ".join(str(value) for value in (
                    record["tag"], record["basis"], record["producer"].get("name"),
                    record["producer"].get("rule_id"), subject.get("path"), subject.get("component_id")) if value)
                builder.add_entity(EntityRecord(identity, record["assignment_id"], record["tag"], text, record,
                                                _subject_location(record)))
                if subject["kind"] == "project" or subject.get("native_address"):
                    local_subjects[subject["logical_id"]] = subject
                builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT, identity.value,
                                                    subject["logical_id"], True, 1.0))
                for source in record["derived_from"]:
                    target = LogicalIdentity.derive(EntityKind.TAG_ASSIGNMENT, snapshot, {"assignment_id": source})
                    builder.add_relation(RelationRecord(
                        RelationKind.DERIVED_FROM, identity.value, target.value, True, 1.0,
                        payload={"crosswalk_rule": record["crosswalk_rule"],
                                 "input_tag": by_id[source]["tag"]}))
            for logical_id, subject in sorted(local_subjects.items()):
                # Subjects without an upstream entity are duplicated here so relation closure holds.
                builder.add_entity(EntityRecord(LogicalIdentity.parse(logical_id),
                                                subject.get("native_address") or logical_id,
                                                subject.get("path") or subject["kind"],
                                                f"{subject['kind']} {subject.get('path', '')}".strip(),
                                                {"subject": dict(subject)}))
            builder.add_coverage(f"tags:{family}", "complete")
            sha256 = builder.build()
        shards.append(IndexIdentity(TAG_INDEX, INDEX_SCHEMA, sha256, fingerprint, _rel(unit.job.run_root, path),
                                    {"job": "job_security_tagging", "family": family}, (), shard_id))
    return shards


def build_job() -> Job:
    def load_taxonomy(unit: UnitContext) -> Mapping[str, Any]:
        vocabulary, rules, crosswalk = _taxonomy(unit.job.repository_root, unit.job.config.settings)
        proposed = sorted(name for name, value in vocabulary.namespaces.items() if value.status != "active")
        identities = {"vocabulary_sha256": vocabulary.sha256, "capability_rules_sha256": rules.sha256,
                      "crosswalk_sha256": crosswalk.sha256}
        document = {"schema": "appsec-review/tag-taxonomy-identity/1", **identities,
                    "vocabulary_version": vocabulary.version, "namespaces": sorted(vocabulary.namespaces),
                    "proposed_namespaces": proposed, "crosswalk_rule_count": len(crosswalk.rules)}
        return {"identities": identities, "artifact": _write(unit, "taxonomy-identity.json", document),
                "proposed_namespaces": proposed}

    def resolve_inputs(unit: UnitContext) -> Mapping[str, Any]:
        _, limit, _ = _settings(unit.job.config.settings)
        indexes = AcceptedIndexes(unit.job.run_root)
        if unit.job.source_fingerprint not in {"none", indexes.target_snapshot}:
            raise ValueError("security tagging target fingerprint does not match the accepted index manifest")
        scope, gaps = resolve_scope(indexes, limit)
        manifest = {"path": _rel(unit.job.run_root, indexes.manifest_path), "sha256": indexes.manifest_sha256}
        document = {"schema": "appsec-review/tag-scope/1", "target_snapshot": scope.target_snapshot,
                    "project": dict(scope.project), "components": [dict(item) for item in scope.components],
                    "accepted_manifest": manifest, "gaps": gaps}
        return {"artifact": _write(unit, "scope.json", document), "accepted_manifest": manifest,
                "component_count": len(scope.components), "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    def source_facts(unit: UnitContext) -> Mapping[str, Any]:
        vocabulary, rules, _ = _unit_taxonomy(unit)
        _, limit, _ = _settings(unit.job.config.settings)
        records, gaps = collect_source_facts(_indexes(unit), _scope(unit), vocabulary, rules, limit)
        return _assignment_set(unit, "source-facts", records, gaps)

    def observation_facts(unit: UnitContext) -> Mapping[str, Any]:
        vocabulary, rules, _ = _unit_taxonomy(unit)
        _, limit, _ = _settings(unit.job.config.settings)
        records, gaps = collect_observation_facts(_indexes(unit), _scope(unit), vocabulary, rules, limit)
        return _assignment_set(unit, "observation-facts", records, gaps)

    def coverage_gaps(unit: UnitContext) -> Mapping[str, Any]:
        vocabulary, rules, _ = _unit_taxonomy(unit)
        records, notes = collect_coverage_gaps(_indexes(unit), _scope(unit), vocabulary, rules)
        return _assignment_set(unit, "coverage-gaps", records, notes)

    def apply_crosswalk(unit: UnitContext) -> Mapping[str, Any]:
        vocabulary, _, crosswalk = _unit_taxonomy(unit)
        scope = _scope(unit)
        observed = [record for unit_id in COLLECTORS
                    for record in _read(unit, unit.output(unit_id)["artifact"])["assignments"]]

        def scope_subject(kind: str, key: str, group: list[Mapping[str, Any]]) -> Mapping[str, Any] | None:
            if kind == "same_subject":
                return group[0]["subject"]
            if kind == "component":
                return scope.component_subject(key)
            if kind == "project":
                return scope.project
            for record in group:
                for evidence in record["evidence"]:
                    if evidence.get("path") and evidence.get("file_sha256"):
                        source = LogicalIdentity.derive(EntityKind.SOURCE_FILE, scope.target_snapshot,
                                                        {"path": evidence["path"], "sha256": evidence["file_sha256"]})
                        return scope.subject("source_file", source.value, evidence["path"],
                                             native_address=f"ci_job:{key}")
            return None

        derived = evaluate(crosswalk, vocabulary, observed, scope_subject=scope_subject)
        fixture_namespaces = sorted({record["namespace"] for record in derived
                                     if vocabulary.namespaces[record["namespace"]].catalog_fixture})
        if fixture_namespaces:
            derived.append(assignment(
                vocabulary=vocabulary, tag="gap:catalog-fixture", basis="reported", subject=dict(scope.project),
                producer={"name": "tag-crosswalk", "rule_id": "catalog-fixture", "version": crosswalk.sha256},
                evidence=[{"ref": f"vocabulary:{vocabulary.sha256}", "namespaces": fixture_namespaces}]))
        return _assignment_set(unit, "derived", derived, [])

    def validate_assignments(unit: UnitContext) -> Mapping[str, Any]:
        vocabulary, _, _ = _unit_taxonomy(unit)
        records = [record for unit_id in (*COLLECTORS, "crosswalk.apply_crosswalk")
                   for record in _read(unit, unit.output(unit_id)["artifact"])["assignments"]]
        merged = merge_assignments(records)
        known = {record["assignment_id"] for record in merged}
        for record in merged:
            validate_assignment(vocabulary, record)
            if record["basis"] == "derived":
                for source in record["derived_from"]:
                    if source not in known:
                        raise TaxonomyError(f"derived tag cites an unknown input: {source}")
            elif not record["evidence"]:
                raise TaxonomyError(f"observed tag lacks resolving evidence: {record['assignment_id']}")
        result = _assignment_set(unit, "assignments", merged, [])
        result["basis_counts"] = dict(sorted(Counter(record["basis"] for record in merged).items()))
        result["family_counts"] = dict(sorted(Counter(record["family"] for record in merged).items()))
        return result

    def publish_index(unit: UnitContext) -> Mapping[str, Any]:
        validated = unit.output("integrity.validate_assignments")
        records = _read(unit, validated["artifact"])["assignments"]
        indexes = _indexes(unit)
        identities = unit.output("taxonomy.load_taxonomy")["identities"]
        shards = _publish_shards(unit, records, indexes, identities)
        upstream = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))}) for item in indexes.identities]
        combined = unit.job.run_root / "data" / "indices" / "manifests" / f"tags-{unit.job.attempt_id}.json"
        write_manifest(combined, run_id=unit.job.run_id, target_snapshot=indexes.target_snapshot,
                       target_root=Path(str(indexes.manifest["target_root"])), indexes=[*upstream, *shards],
                       upstream_manifests=({"path": _rel(unit.job.run_root, indexes.manifest_path),
                                            "sha256": indexes.manifest_sha256},))
        load_verified_manifest(unit.job.run_root, combined, file_sha256(combined))
        return {"index_manifest": _artifact(unit.job.run_root, combined),
                "shards": [asdict(item) for item in shards], "shard_count": len(shards)}

    def publish_tag_cloud(unit: UnitContext) -> Mapping[str, Any]:
        vocabulary, _, _ = _unit_taxonomy(unit)
        records = _read(unit, unit.output("integrity.validate_assignments")["artifact"])["assignments"]
        cloud = build_cloud(vocabulary, records)
        return {"artifact": _write(unit, "tag-cloud.json", cloud), "node_count": len(cloud["nodes"]),
                "rollup_gaps": cloud["rollup_gaps"]}

    def publish_handoff(unit: UnitContext) -> Mapping[str, Any]:
        validated = unit.output("integrity.validate_assignments")
        records = _read(unit, validated["artifact"])["assignments"]
        gap_tags = sorted({record["tag"] for record in records if record["family"] == "gap"})
        collector_gaps = [gap for unit_id in ("scope.resolve_inputs", *COLLECTORS)
                          for gap in unit.output(unit_id)["gaps"]]
        gaps = list(dict.fromkeys([*STANDING_GAPS, *collector_gaps,
                                   *unit.output("publication.publish_tag_cloud")["rollup_gaps"]]))
        document = {"schema": SCHEMA, "target_snapshot": _scope(unit).target_snapshot,
                    "taxonomy": unit.output("taxonomy.load_taxonomy")["identities"],
                    "accepted_upstream_manifest": unit.output("scope.resolve_inputs")["accepted_manifest"],
                    "assignments": validated["artifact"], "assignment_count": validated["item_count"],
                    "basis_counts": validated["basis_counts"], "family_counts": validated["family_counts"],
                    "tag_cloud": unit.output("publication.publish_tag_cloud")["artifact"],
                    "index_manifest": unit.output("publication.publish_index")["index_manifest"],
                    "gap_tags": gap_tags, "gaps": gaps,
                    "claim_policy": "Tags are review routing facts. A derived tag means applicable, never present "
                                    "or satisfied; only reported or confirmed weakness tags cite findings.",
                    "security_findings": []}
        return {**document, "artifact": _write(unit, "handoff.json", document),
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps or gap_tags else "SUCCEEDED"}

    u = Unit
    units = (
        u("taxonomy.load_taxonomy", load_taxonomy),
        u("scope.resolve_inputs", resolve_inputs, ("taxonomy.load_taxonomy",)),
        *(u(unit_id, handler, ("taxonomy.load_taxonomy", "scope.resolve_inputs"))
          for unit_id, handler in zip(COLLECTORS, (source_facts, observation_facts, coverage_gaps), strict=True)),
        u("crosswalk.apply_crosswalk", apply_crosswalk, ("taxonomy.load_taxonomy", "scope.resolve_inputs",
                                                         *COLLECTORS)),
        u("integrity.validate_assignments", validate_assignments,
          ("taxonomy.load_taxonomy", *COLLECTORS, "crosswalk.apply_crosswalk")),
        u("publication.publish_index", publish_index,
          ("taxonomy.load_taxonomy", "scope.resolve_inputs", "integrity.validate_assignments")),
        u("publication.publish_tag_cloud", publish_tag_cloud,
          ("taxonomy.load_taxonomy", "integrity.validate_assignments")),
        u("publication.publish_handoff", publish_handoff,
          ("taxonomy.load_taxonomy", "scope.resolve_inputs", *COLLECTORS, "integrity.validate_assignments",
           "publication.publish_index", "publication.publish_tag_cloud")),
    )
    sources = sorted(Path(__file__).parent.glob("*.py"))
    identity = hashlib.sha256(b"".join(path.read_bytes() for path in sources)).hexdigest()
    return Job("job_security_tagging", "security_tagging", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=identity, validation_identity=identity, units=units)
