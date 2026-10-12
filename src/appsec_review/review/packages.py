"""Deterministic review-package assembly and membership audits (contract gates 3-6).

Lane A: every accepted lead of every family whose normalized reported severity is in the admitted
list (default critical, high, unknown) gets exactly one ``finding_lead`` package, including
suppressed and duplicate leads. Lane B: ranked review units above the cutoff get ``hunt``
packages whose lead menus list every lead in the unit, partitioned and never truncated.

Packages are canonical JSON. ``package_id`` is the kind plus the SHA-256 of the canonical body
without ``package_id``; arrays sort by stable identity; nothing time- or order-dependent enters a
package. Reassembly from the same accepted inputs is byte-identical. A missing producer is a
named gap; a membership or integrity failure raises :class:`IntegrityError`.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, fields
import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_review.indexing.store import ShardSet
from appsec_review.retrieval.model import LogicalIdentity
from appsec_review.retrieval.observations import REPORTED_SEVERITIES, SEVERITY_ORDER
from appsec_review.review.identity import sha256_hex
from appsec_review.review.lead_families import FAMILIES, FAMILY_RULES, Lead, LeadCollection, collect_leads
from appsec_review.review.models import IntegrityError, Predicate
from appsec_review.review.scope import AcceptedScope, ScopeGap, sorted_gaps
from appsec_review.review.units import (
    RANK_RULE, ContextEntry, RankedUnit, build_units, context_entry, rank_units, select_hunts,
)
from appsec_review.storage import atomic_bytes, file_sha256
from appsec_review.storage.atomic import canonical_json


PACKAGE_SCHEMA = "appsec-review/review-package/2"
ASSEMBLY_RULE = "appsec-review/assemble-review-packages/2"
MANIFEST_SCHEMA = "appsec-review/review-package-manifest/1"
OBLIGATION_RULE = "appsec-review/package-obligations/1"
SUPPRESSION_STATES = ("suppressed", "possibly_suppressed", "not_suppressed", "unknown")
_P = Predicate
# Deterministic obligation table keyed by lead family; every predicate starts open.
OBLIGATIONS: Mapping[str, tuple[Predicate, ...]] = {
    "source_sast": (_P.AFFECTED_CONSTRUCT, _P.ATTACKER_INPUT_CONTROL, _P.SOURCE_TO_SINK_REACHABILITY,
                    _P.MISSING_OR_INEFFECTIVE_GUARD, _P.SECURITY_IMPACT),
    "codeql": (_P.AFFECTED_CONSTRUCT, _P.ATTACKER_INPUT_CONTROL, _P.SOURCE_TO_SINK_REACHABILITY,
               _P.MISSING_OR_INEFFECTIVE_GUARD, _P.SECURITY_IMPACT),
    "dependency_advisory": (_P.AFFECTED_CONSTRUCT, _P.SOURCE_TO_SINK_REACHABILITY, _P.CONFIGURATION_ENABLES,
                            _P.SECURITY_IMPACT),
    "artifact_scanner": (_P.AFFECTED_CONSTRUCT, _P.CONFIGURATION_ENABLES, _P.SECURITY_IMPACT),
    "post_build_hardening": (_P.AFFECTED_CONSTRUCT, _P.CONFIGURATION_ENABLES, _P.SECURITY_IMPACT),
    "ci_rule": (_P.AFFECTED_CONSTRUCT, _P.ATTACKER_INPUT_CONTROL, _P.CONFIGURATION_ENABLES, _P.SECURITY_IMPACT),
    "owasp_control": (_P.AFFECTED_CONSTRUCT, _P.MISSING_OR_INEFFECTIVE_GUARD, _P.SECURITY_IMPACT),
    "hunt": tuple(Predicate),
}


@dataclass(frozen=True, slots=True)
class PackageSettings:
    admit_severities: tuple[str, ...] = ("critical", "high", "unknown")
    hunt_max_units: int = 8
    hunt_menu_partition_size: int = 25
    unit_max_files: int = 200
    max_context_entries: int = 64
    max_package_bytes: int = 64 * 1024
    max_page_size: int = 20
    max_pages: int = 5
    max_depth: int = 4

    def __post_init__(self) -> None:
        admitted = tuple(self.admit_severities)
        if not admitted or len(set(admitted)) != len(admitted) or any(
                item not in REPORTED_SEVERITIES for item in admitted):
            raise ValueError("admit_severities must be distinct normalized reported severities")
        object.__setattr__(self, "admit_severities", tuple(sorted(admitted, key=SEVERITY_ORDER.__getitem__)))
        for name in ("hunt_menu_partition_size", "unit_max_files", "max_context_entries", "max_package_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if isinstance(self.hunt_max_units, bool) or not isinstance(self.hunt_max_units, int) or self.hunt_max_units < 0:
            raise ValueError("hunt_max_units must be a non-negative integer")
        for name, bound in (("max_page_size", 100), ("max_pages", 100), ("max_depth", 8)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= bound:
                raise ValueError(f"{name} must be between 1 and {bound}")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "PackageSettings":
        value = dict(value or {})
        known = {item.name for item in fields(cls)}
        unknown = sorted(set(value) - known)
        if unknown:
            raise ValueError(f"unknown package settings: {unknown}")
        if "admit_severities" in value:
            value["admit_severities"] = tuple(value["admit_severities"])
        return cls(**value)

    def record(self) -> dict[str, Any]:
        return {**asdict(self), "admit_severities": list(self.admit_severities)}


@dataclass(frozen=True, slots=True)
class Package:
    package_id: str
    kind: str
    lane: str
    lead_family: str | None
    partition_key: str
    lead_ids: tuple[str, ...]
    unit_key: str | None
    body: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    def document(self) -> dict[str, Any]:
        return json.loads(self.body)

    def entry(self) -> dict[str, Any]:
        return {"package_id": self.package_id, "kind": self.kind, "lane": self.lane,
                "lead_family": self.lead_family, "partition_key": self.partition_key, "unit_key": self.unit_key,
                "lead_count": len(self.lead_ids), "sha256": self.sha256, "bytes": len(self.body)}


@dataclass(frozen=True, slots=True)
class Assembly:
    packages: tuple[Package, ...]
    manifest: Mapping[str, Any]
    gaps: tuple[ScopeGap, ...]

    @property
    def manifest_bytes(self) -> bytes:
        return canonical_json(self.manifest)


def lead_record(lead: Lead, component_id: str, build_unit_id: str | None) -> dict[str, Any]:
    duplicate = lead.duplicate_of
    if duplicate is not None:
        LogicalIdentity.parse(duplicate)
    return {
        "observation_id": lead.observation_id, "lead_family": lead.family, "scanner": lead.scanner,
        "rule_id": lead.rule_id, "message": lead.message, "rule_cwe": list(lead.rule_cwe),
        "native_severity": lead.native_severity, "reported_severity": lead.reported_severity,
        "severity_rule": lead.severity_rule, "severity_basis": lead.severity_basis,
        "component_id": component_id, "build_unit_id": build_unit_id,
        "suppression_status": lead.suppression_status if lead.suppression_status in SUPPRESSION_STATES else "unknown",
        "duplicate_of": duplicate, "location_exact": lead.location_exact, "flow_ids": list(lead.flow_ids),
    }


def _evidence(lead: Lead) -> dict[str, Any]:
    if lead.location_exact and lead.path is not None:
        resolution = "source_line"
    elif any(role == "artifact" for _identity, role in lead.related):
        resolution = "run_artifact"
    else:
        resolution = "unresolved"
    return {"entity_id": lead.observation_id, "relation": "nominates", "shard_id": lead.shard_label,
            "shard_sha256": lead.shard_sha256, "resolution": resolution}


class _Assembler:
    def __init__(self, scope: AcceptedScope, settings: PackageSettings, collection: LeadCollection):
        self.scope = scope
        self.settings = settings
        self.collection = collection
        self.correlation_hashes = tuple(sorted(str(item["sha256"]) for item in collection.correlation_shards))
        self.extra_gaps: list[ScopeGap] = []

    def _locate(self, lead: Lead) -> tuple[str, str | None, Any, Any]:
        component = self.scope.component_for(lead.path)
        unit = self.scope.build_unit_for(lead.path)
        return (component.component_id if component else lead.component_hint or "unassigned",
                unit.build_unit_id if unit else None, component, unit)

    def _cap(self, context: Iterable[ContextEntry], subject: str, producer: str
             ) -> tuple[list[ContextEntry], int, list[ScopeGap]]:
        unique = {(item.role, item.id): item for item in context}
        ordered = [unique[key] for key in sorted(unique)]
        bound = self.settings.max_context_entries
        if len(ordered) <= bound:
            return ordered, 0, []
        omitted = len(ordered) - bound
        return ordered[:bound], omitted, [ScopeGap(producer, subject, "truncated",
                                                   f"{omitted} context entr{'y' if omitted == 1 else 'ies'} "
                                                   f"exceeded max_context_entries={bound}")]

    def _build(self, *, kind: str, lead_family: str | None, scope_record: Mapping[str, Any],
               partition: tuple[int, int], rank: Mapping[str, Any] | None, menu: list[tuple[Lead, str, str | None]],
               context: list[ContextEntry], obligations: Iterable[Predicate], gaps: Iterable[ScopeGap],
               truncation: Mapping[str, Any]) -> tuple[str, bytes]:
        leads = sorted(menu, key=lambda item: (SEVERITY_ORDER[item[0].reported_severity], item[0].observation_id))
        lead_ids = sorted(item[0].observation_id for item in leads)
        entities = sorted({*lead_ids, *scope_record["source_ids"], *scope_record["artifact_ids"],
                           *(item.id for item in context)})
        shard_hashes = sorted({*(item[0].shard_sha256 for item in leads),
                               *(item.shard_sha256 for item in context if item.shard_sha256),
                               *(self.correlation_hashes if any(item[0].family in {"source_sast", "codeql"}
                                                                for item in leads) else ())})
        retrieval = {"indexes": list(self.scope.index_names), "query_sets": list(self.scope.query_sets),
                     "entity_ids": entities, "max_page_size": self.settings.max_page_size,
                     "max_pages": self.settings.max_pages, "max_depth": self.settings.max_depth}
        fingerprint = sha256_hex({
            "manifest_sha256": self.scope.manifest_sha256, "scope": dict(scope_record), "shards": shard_hashes,
            "lead_ids": lead_ids, "rules": {"assembly": ASSEMBLY_RULE, "obligations": OBLIGATION_RULE,
                                            "rank": RANK_RULE, "families": FAMILY_RULES},
            "caps": self.settings.record()})
        body = {
            "schema": PACKAGE_SCHEMA, "kind": kind, "lane": "lead" if kind == "finding_lead" else "hunt",
            "lead_family": lead_family, "run_id": self.scope.run_id, "manifest_sha256": self.scope.manifest_sha256,
            "target_snapshot": self.scope.target_snapshot, "input_fingerprint": fingerprint,
            "assembly_rule": ASSEMBLY_RULE, "scope": dict(scope_record),
            "partition": {"number": partition[0], "count": partition[1]}, "rank": rank,
            "persona": None, "stack_profile": None,
            "lead_menu": [lead_record(*item) for item in leads],
            "evidence": sorted((_evidence(item[0]) for item in leads), key=lambda value: value["entity_id"]),
            "context": [item.record() for item in context],
            "proof_obligations": sorted(item.value for item in obligations),
            "retrieval": retrieval, "coverage_gaps": [gap.record() for gap in sorted_gaps(gaps)],
            "truncation": dict(truncation),
        }
        package_id = f"{kind}-{sha256_hex(body)}"
        return package_id, canonical_json({**body, "package_id": package_id})

    # Lane A ---------------------------------------------------------------------------------------
    def finding_lead(self, lead: Lead) -> Package:
        component_id, unit_id, component, unit = self._locate(lead)
        source = self.scope.source_for(lead.path)
        context: list[ContextEntry] = []
        sources = {source.identity} if source else set()
        artifacts: set[str] = set()
        for identity, role in lead.related:
            if role == "source":
                sources.add(identity)
            elif role == "artifact":
                artifacts.add(identity)
            else:
                context.append(context_entry(identity, role))
        if component is not None:
            context.append(context_entry(component.identity, "component"))
        if unit is not None:
            context.append(context_entry(unit.identity, "build_unit"))
        if lead.duplicate_of:
            context.append(context_entry(lead.duplicate_of, "duplicate_of"))
        context.extend(context_entry(identity, "flow") for identity in lead.flow_ids)
        partition_key = f"lead/{lead.observation_id}"
        capped, omitted, gaps = self._cap(context, partition_key, lead.family)
        gaps.extend(gap for gap in self.collection.gaps if gap.producer == lead.family)
        if not lead.location_exact:
            gaps.append(ScopeGap(lead.family, partition_key, "ambiguous",
                                 "lead location is unresolved or ambiguous; no source line is cited"))
        scope_record = {"component_id": component_id, "trust_boundary_id": None, "build_unit_id": unit_id,
                        "partition_key": partition_key, "source_ids": sorted(sources), "artifact_ids": sorted(artifacts)}
        while True:
            package_id, body = self._build(
                kind="finding_lead", lead_family=lead.family, scope_record=scope_record, partition=(0, 1), rank=None,
                menu=[(lead, component_id, unit_id)], context=capped, obligations=OBLIGATIONS[lead.family],
                gaps=gaps, truncation={"omitted_leads": 0, "omitted_context": omitted, "next_partition": None})
            if len(body) <= self.settings.max_package_bytes:
                break
            if not capped:
                raise IntegrityError(f"finding-lead package for {lead.observation_id} exceeds max_package_bytes and "
                                     "cannot be partitioned; the membership gate is blocked")
            capped = capped[:-1]
            omitted += 1
            gaps = [gap for gap in gaps if gap.state != "truncated"] + [ScopeGap(
                lead.family, partition_key, "truncated",
                f"{omitted} context entries omitted to respect max_package_bytes")]
        self.extra_gaps.extend(gap for gap in gaps if gap.state == "truncated")
        return Package(package_id, "finding_lead", "lead", lead.family, partition_key, (lead.observation_id,),
                       None, body)

    # Lane B ---------------------------------------------------------------------------------------
    def hunts(self, ranked: RankedUnit) -> list[Package]:
        unit = ranked.unit
        menu = [(lead, *self._locate(lead)[:2]) for lead in unit.leads]
        menu.sort(key=lambda item: (SEVERITY_ORDER[item[0].reported_severity], item[0].observation_id))
        context, omitted, gaps = self._cap(unit.context, unit.key, "lane_b_hunt")
        missing = [gap for gap in (*self.scope.gaps, *self.collection.gaps) if gap.state == "missing"]
        scope_record = {"component_id": unit.component_id, "trust_boundary_id": unit.trust_boundary_id,
                        "build_unit_id": unit.build_unit_id, "source_ids": list(unit.source_ids),
                        "artifact_ids": sorted({identity for lead in unit.leads for identity, role in lead.related
                                                if role == "artifact"})}
        rank = ranked.rank_record()

        def render(chunk: list, number: int, count: int) -> tuple[str, bytes]:
            key = f"{unit.key}#{number:05d}"
            following = f"{unit.key}#{number + 1:05d}" if number + 1 < count else None
            return self._build(
                kind="hunt", lead_family=None, scope_record={**scope_record, "partition_key": key},
                partition=(number, count), rank=rank, menu=chunk, context=context, obligations=OBLIGATIONS["hunt"],
                gaps=[*gaps, *missing], truncation={"omitted_leads": 0, "omitted_context": omitted,
                                                    "next_partition": following})

        def split(chunk: list) -> list[list]:
            _identity, body = render(chunk, 99_998, 99_999)  # widest numbering bounds the final size
            if len(body) <= self.settings.max_package_bytes:
                return [chunk]
            if len(chunk) <= 1:
                raise IntegrityError(f"hunt partition of {unit.key} exceeds max_package_bytes with a single lead; "
                                     "the membership gate is blocked")
            middle = len(chunk) // 2
            return split(chunk[:middle]) + split(chunk[middle:])

        size = self.settings.hunt_menu_partition_size
        chunks = [chunk for offset in range(0, max(1, len(menu)), size)
                  for chunk in split(menu[offset:offset + size])]
        self.extra_gaps.extend(gaps)
        packages = []
        for number, chunk in enumerate(chunks):
            package_id, body = render(chunk, number, len(chunks))
            packages.append(Package(package_id, "hunt", "hunt", None, f"{unit.key}#{number:05d}",
                                    tuple(sorted(item[0].observation_id for item in chunk)), unit.key, body))
        return packages


def audit_membership(collection: LeadCollection, packages: Iterable[Package],
                     admit: Iterable[str]) -> dict[str, Any]:
    """Gate 5 for lane A: E ⊆ F per family and severity, exactly once, with no invented lead."""
    admitted = set(admit)
    expected = {lead.observation_id: lead for lead in collection.leads if lead.reported_severity in admitted}
    seen: Counter[str] = Counter()
    for package in packages:
        if package.kind == "finding_lead":
            seen.update(package.lead_ids)
    missing = sorted(set(expected) - set(seen))
    repeated = sorted(key for key, count in seen.items() if count > 1)
    invented = sorted(set(seen) - set(expected))
    if missing or repeated or invented:
        raise IntegrityError(f"lane A membership audit failed: missing={missing[:5]} repeated={repeated[:5]} "
                             f"invented={invented[:5]}")
    by_cell: dict[str, dict[str, dict[str, int]]] = {}
    for family in FAMILIES:
        by_cell[family] = {}
        for severity in sorted(admitted, key=SEVERITY_ORDER.__getitem__):
            members = [key for key, lead in expected.items() if lead.family == family and lead.reported_severity == severity]
            packaged = sum(seen[key] for key in members)
            if packaged != len(members):
                raise IntegrityError(f"lane A membership audit failed for {family}/{severity}")
            by_cell[family][severity] = len(members)
    return {"status": "passed", "expected": len(expected), "packaged": sum(seen.values()), "by_family": by_cell,
            "suppressed": sum(1 for lead in expected.values() if lead.suppression_status == "suppressed"),
            "duplicates": sum(1 for lead in expected.values() if lead.duplicate_of)}


def audit_hunts(hunted: Iterable[RankedUnit], packages: Iterable[Package]) -> dict[str, Any]:
    """Every lead of a hunted unit appears in exactly one of its menu partitions; none is invented."""
    menus: dict[str, Counter[str]] = defaultdict(Counter)
    for package in packages:
        if package.kind == "hunt":
            menus[str(package.unit_key)].update(package.lead_ids)
    listed = 0
    for item in hunted:
        expected = set(item.unit.lead_ids)
        found = menus.pop(item.unit.key, Counter())
        if set(found) != expected or any(count != 1 for count in found.values()):
            raise IntegrityError(f"lane B hunt menu membership failed for {item.unit.key}")
        listed += len(expected)
    if menus:
        raise IntegrityError(f"hunt packages exist for units that were not selected: {sorted(menus)[:5]}")
    return {"status": "passed", "listed_leads": listed}


def assemble_packages(scope: AcceptedScope, settings: PackageSettings | None = None, *,
                      collection: LeadCollection | None = None) -> Assembly:
    """Assemble both lanes and the package manifest; raises on any membership or integrity failure."""
    settings = settings or PackageSettings()
    collection = collection if collection is not None else collect_leads(scope)
    collection = LeadCollection(tuple(sorted(collection.leads, key=lambda lead: lead.observation_id)),
                                collection.gaps, collection.available, collection.correlation_audit,
                                collection.correlation_shards, collection.non_lead_counts)
    assembler = _Assembler(scope, settings, collection)
    admitted = [lead for lead in collection.leads if lead.reported_severity in settings.admit_severities]
    packages = [assembler.finding_lead(lead) for lead in admitted]
    lane_a = audit_membership(collection, packages, settings.admit_severities)

    units = build_units(scope, collection, unit_max_files=settings.unit_max_files)
    ranked = rank_units(units)
    hunted, cutoff_gaps = select_hunts(ranked, settings.hunt_max_units)
    for item in hunted:
        packages.extend(assembler.hunts(item))
    lane_b = audit_hunts(hunted, packages)
    packages.sort(key=lambda package: package.package_id)
    if len({package.package_id for package in packages}) != len(packages):
        raise IntegrityError("package identity collision")
    scope.verify()

    gaps = sorted_gaps((*scope.gaps, *collection.gaps, *cutoff_gaps, *assembler.extra_gaps))
    hunted_keys = {item.unit.key for item in hunted}
    unit_packages: dict[str, list[str]] = defaultdict(list)
    for package in packages:
        if package.unit_key is not None:
            unit_packages[package.unit_key].append(package.package_id)
    admitted_counts = {family: {severity: sum(1 for lead in admitted if lead.family == family
                                              and lead.reported_severity == severity)
                                for severity in settings.admit_severities} for family in FAMILIES}
    document: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA, "assembly_rule": ASSEMBLY_RULE, "package_schema": PACKAGE_SCHEMA,
        "run_id": scope.run_id, "manifest_sha256": scope.manifest_sha256, "target_snapshot": scope.target_snapshot,
        "settings": settings.record(), "rules": {"families": dict(FAMILY_RULES), "rank": RANK_RULE,
                                                 "obligations": OBLIGATION_RULE},
        "inputs": ShardSet.identities(scope.shards), "evidence_map_sha256": sha256_hex(scope.evidence_map()),
        "packages": [package.entry() for package in packages],
        "units": [{"unit_key": item.unit.key, **item.rank_record(), "hunted": item.unit.key in hunted_keys,
                   "lead_count": len(item.unit.leads), "package_ids": sorted(unit_packages.get(item.unit.key, ()))}
                  for item in ranked],
        "gaps": [gap.record() for gap in gaps],
        "counts": {"leads": collection.counts(), "admitted": admitted_counts,
                   "non_lead_observations": dict(collection.non_lead_counts),
                   "packages": {"finding_lead": sum(1 for item in packages if item.kind == "finding_lead"),
                                "hunt": sum(1 for item in packages if item.kind == "hunt")},
                   "units": {"total": len(ranked), "hunted": len(hunted), "below_cutoff": len(cutoff_gaps)}},
        "audit": {"lane_a": lane_a, "lane_b": lane_b,
                  "families_available": {family: bool(collection.available.get(family)) for family in FAMILIES}},
    }
    document["content_sha256"] = sha256_hex(document)
    return Assembly(tuple(packages), document, gaps)


def publish_packages(assembly: Assembly, out_dir: Path) -> Path:
    """Write package bytes and the manifest under a run-owned directory, then verify them."""
    out_dir = Path(out_dir)
    for package in assembly.packages:
        path = out_dir / "packages" / f"{package.package_id}.json"
        if path.is_file():
            if path.read_bytes() != package.body:
                raise IntegrityError(f"published package differs from its reassembly: {package.package_id}")
            continue
        atomic_bytes(path, package.body)
    manifest_path = out_dir / "package-manifest.json"
    if manifest_path.is_file() and manifest_path.read_bytes() != assembly.manifest_bytes:
        raise IntegrityError("published package manifest differs from its reassembly")
    atomic_bytes(manifest_path, assembly.manifest_bytes)
    verify_package_manifest(manifest_path)
    return manifest_path


def verify_package_manifest(manifest_path: Path) -> dict[str, Any]:
    """Verify the manifest hash and every package's bytes before a consumer reads them."""
    manifest_path = Path(manifest_path)
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    if document.get("schema") != MANIFEST_SCHEMA:
        raise IntegrityError("unsupported package manifest schema")
    claimed = document.pop("content_sha256", None)
    if claimed != sha256_hex(document):
        raise IntegrityError("package manifest content hash mismatch")
    document["content_sha256"] = claimed
    for entry in document["packages"]:
        path = manifest_path.parent / "packages" / f"{entry['package_id']}.json"
        if not path.is_file() or file_sha256(path) != entry["sha256"]:
            raise IntegrityError(f"package bytes do not match the manifest: {entry['package_id']}")
        body = json.loads(path.read_text(encoding="utf-8"))
        package_id = body.pop("package_id")
        if package_id != entry["package_id"] or package_id != f"{body['kind']}-{sha256_hex(body)}":
            raise IntegrityError(f"package identity does not match its body: {entry['package_id']}")
    return document
