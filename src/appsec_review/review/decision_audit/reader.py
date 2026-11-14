"""Bounded host-application reads of accepted protected decision products.

The accepted envelope, not a caller path or a role string, selects the publication.
This module grants no worker access and never changes the accepted review's decisions.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields, is_dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
from types import MappingProxyType
from typing import Any

from appsec_review.config.inference_review import DecisionAuditSettings
from appsec_review.indexing.inventory import compile_glob
from appsec_review.review.models import IntegrityError, Role
from appsec_review.runtime.inputs import observe_output, observe_shard, producer_contract

from . import contracts as c
from .metadata import PUBLICATION_SCHEMA, policy_document, read_publication

REVIEW_JOB = "job_inference_security_review"
_AUDIT_OUTPUTS = {
    "publication.json": ("review_audit_metadata", PUBLICATION_SCHEMA),
    "manifest.json": ("review_decision_audit", c.MANIFEST_SCHEMA),
    "decision": ("review_decisions", c.DECISION_SCHEMA),
    "verification_coverage": ("review_verification_coverage", c.VERIFICATION_SCHEMA),
    "decision_basis": ("review_decision_bases", c.BASIS_SCHEMA),
    "continuations": ("review_audit_continuations", "application/x-ndjson"),
}


class AuditBoundExceeded(IntegrityError):
    """The supplied audit cannot be completely verified within the configured bounds."""


@dataclass(frozen=True, slots=True)
class ReadReceipt:
    path: str
    sha256: str
    byte_count: int

    def reference(self) -> dict[str, str]:
        return {"path": self.path, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class AcceptedAudit:
    """Fully validated immutable products, or an explicit unavailable capability."""

    reference: c.ManifestRef | None
    manifest: c.AuditManifest | None
    records: tuple[c.Product, ...]
    continuations: tuple[tuple[str, tuple[c.SourceRef | c.RelationRef, ...]], ...]
    reads: tuple[ReadReceipt, ...]
    settings: DecisionAuditSettings
    accepted_handoff_sha256: str
    unavailable_reason: str | None = None
    lead_membership_unavailable: tuple[str, ...] = ()
    _records: Mapping[str, c.Product] = field(init=False, repr=False, compare=False)
    _bases: Mapping[str, c.DecisionBasisRecord] = field(init=False, repr=False, compare=False)
    _continued: Mapping[str, tuple[c.SourceRef | c.RelationRef, ...]] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_records", MappingProxyType({row.record_id: row for row in self.records}))
        object.__setattr__(self, "_bases", MappingProxyType({
            row.context.subject.claim_id.value: row for row in self.records if isinstance(row, c.DecisionBasisRecord)}))
        object.__setattr__(self, "_continued", MappingProxyType(dict(self.continuations)))

    @property
    def available(self) -> bool:
        return self.manifest is not None

    def relations(self, record: c.Product) -> tuple[c.RelationRef, ...]:
        if self._records.get(record.record_id) != record:
            raise IntegrityError("record is not a member of this accepted audit")
        return tuple(sorted((*record.context.relations, *(
            row for ref in record.context.continuations if ref.field == c.ReferenceField.RELATIONS
            for row in self._continued[ref.path] if isinstance(row, c.RelationRef))), key=lambda row: row.relation_id))

    def basis(self, claim_id: str) -> c.DecisionBasisRecord | None:
        return self._bases.get(claim_id)

    def origin_proposals(self, record: c.Product) -> tuple[c.SourceRef, ...]:
        if self._records.get(record.record_id) != record:
            raise IntegrityError("record is not a member of this accepted audit")
        return tuple(sorted((*record.context.origin_proposals, *(
            row for ref in record.context.continuations if ref.field == c.ReferenceField.ORIGIN_PROPOSALS
            for row in self._continued[ref.path] if isinstance(row, c.SourceRef))),
            key=lambda row: (row.path, row.sha256, row.record_id.value)))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IntegrityError(message)


def _sources(value: object) -> tuple[c.SourceRef, ...]:
    if isinstance(value, c.SourceRef):
        return (value,)
    if is_dataclass(value) and not isinstance(value, type):
        return tuple(ref for field in fields(value) for ref in _sources(getattr(value, field.name)))
    if isinstance(value, tuple):
        return tuple(ref for item in value for ref in _sources(item))
    return ()


def expected_origin(*, handoff: Mapping[str, Any], published: Mapping[str, Any],
                    review: Mapping[str, Any], scope: Mapping[str, Any],
                    policy: Mapping[str, Any]) -> c.Origin:
    """Build the origin exclusively from independently verified accepted inputs."""
    _require(handoff["run_id"] == review["run_id"] == scope["run_id"],
             "decision audit anchors belong to different runs")
    _require(handoff["target_snapshot"] == scope["target_snapshot"],
             "decision audit anchors belong to different targets")
    _require(scope["manifest_sha256"] == review["accepted_manifest_sha256"],
             "decision audit scope disagrees with the accepted review")
    lead = review.get("lead_package_manifest_sha256")
    return c.Origin(
        handoff["run_id"], handoff["attempt_id"], scope["target_snapshot"], scope["manifest_sha256"],
        published["artifact"]["sha256"], review["ledger_head_sha256"], review["projection_sha256"],
        review["package_manifest_sha256"],
        c.HashLink(lead, None if lead else c.AbsenceReason.LEGACY_UNRECORDED),
        handoff["resolved_config_sha256"], c.HashLink(None, c.AbsenceReason.NOT_PRODUCED),
        c.HashLink(None, c.AbsenceReason.NOT_PRODUCED), policy["version"], policy["sha256"])


class _BoundReader:
    def __init__(self, root: Path, handoff: Mapping[str, Any], settings: DecisionAuditSettings):
        self.root = root
        self.settings = settings
        self.pins: dict[str, str] = {}
        self.audit_root = (PurePosixPath(handoff["resolving_paths"]["attempt"]) / "artifacts/decision-audit")
        expected = PurePosixPath("data/jobs") / REVIEW_JOB / "attempts" / handoff["attempt_id"]
        _require(PurePosixPath(handoff["resolving_paths"]["attempt"]) == expected,
                 "accepted audit attempt path disagrees with its identity")
        self.attempt = expected
        for ref in handoff["artifacts"]:
            self.admit(ref)
        self.receipts: dict[str, ReadReceipt] = {}
        self.cache: dict[str, bytes] = {}
        self.documents: dict[str, Any] = {}
        self.shards: dict[str, Mapping[str, Any]] = {}
        self.independence: dict[tuple[str, str], Mapping[str, Any]] = {}
        self.proposals: dict[tuple[str, int, str], Mapping[str, Any]] = {}
        self.cell_receipts: dict[tuple[str, str], str] = {}
        self.receipts_by_cell: dict[str, set[tuple[str, str]]] = {}
        self.proposal_origins: set[tuple[str, str, str, str | None]] = set()
        self.lead_membership_unavailable: set[str] = set()
        self.declarations = {row.output_kind: row for row in producer_contract(root, handoff)}
        self.output_patterns = tuple((row.output_kind, compile_glob(pattern))
                                     for row in self.declarations.values() for pattern in row.artifacts)
        self.used_bytes = 0
        self.used_records = 0

    def admit(self, reference: Mapping[str, Any]) -> None:
        path, digest = reference["path"], reference["sha256"]
        _require(isinstance(path, str) and isinstance(digest, str), "malformed accepted audit artifact pin")
        _require(self.pins.get(path, digest) == digest, "accepted audit path has conflicting hash pins")
        self.pins[path] = digest

    def records(self, count: int) -> None:
        self.used_records += count
        if self.used_records > self.settings.max_records:
            raise AuditBoundExceeded("decision audit max_records exhausted")

    def read(self, ref: Mapping[str, Any], *, audit: bool = False, maximum: int | None = None) -> bytes:
        name, digest = ref["path"], ref["sha256"]
        path = PurePosixPath(name)
        _require(not path.is_absolute() and path.as_posix() == name
                 and all(part not in ("", ".", "..") for part in name.split("/")) and "\\" not in name,
                 "decision audit path is not a canonical run-relative path")
        _require(self.pins.get(name) == digest, "decision audit artifact is not an admitted accepted pin")
        if audit:
            _require(self.audit_root in path.parents, "decision audit artifact belongs to another attempt")
        if name in self.cache:
            data = self.cache[name]
            if maximum is not None and len(data) > maximum:
                raise AuditBoundExceeded("decision audit shard_bytes exhausted")
            return data
        cap = min(self.settings.max_input_bytes - self.used_bytes,
                  maximum if maximum is not None else self.settings.max_input_bytes)
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in path.parts[:-1]:
                following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = following
            handle = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                info = os.fstat(handle)
                _require(stat.S_ISREG(info.st_mode), "decision audit artifact is not a regular file")
                if info.st_size > cap:
                    raise AuditBoundExceeded("decision audit max_input_bytes or shard_bytes exhausted")
                with os.fdopen(handle, "rb", closefd=False) as stream:
                    data = stream.read(cap + 1)
                if len(data) > cap:
                    raise AuditBoundExceeded("decision audit max_input_bytes exhausted during read")
            finally:
                os.close(handle)
        except OSError as exc:
            raise IntegrityError("decision audit artifact custody or availability failed: " + name) from exc
        finally:
            os.close(fd)
        _require(hashlib.sha256(data).hexdigest() == digest, "decision audit artifact hash changed: " + name)
        if audit:
            suffix = path.relative_to(self.audit_root).parts
            binding = _AUDIT_OUTPUTS.get(suffix[0])
            _require(binding is not None, "decision audit path has no declared output kind")
            kind, schema = binding
            declaration = self.declarations.get(kind)
            _require(declaration is not None and declaration.schema == schema
                     and declaration.disposition == "protected" and declaration.authority == "operational"
                     and any(owner == kind and pattern.fullmatch(name) for owner, pattern in self.output_patterns),
                     "decision audit path or schema disagrees with its protected output declaration")
            observe_output(self.root, REVIEW_JOB, kind, ref)
        elif name in self.shards:
            observe_shard(self.root, self.shards[name])
        else:
            kinds = {kind for kind, pattern in self.output_patterns if pattern.fullmatch(name)}
            _require(len(kinds) <= 1, "audit source belongs to ambiguous output declarations")
            if kinds:
                observe_output(self.root, REVIEW_JOB, next(iter(kinds)), ref)
        self.used_bytes += len(data)
        self.receipts[name] = ReadReceipt(name, digest, len(data))
        self.cache[name] = data
        return data

    def document(self, ref: Mapping[str, Any], **kwargs: Any) -> Any:
        data = self.read(ref, **kwargs)
        if ref["path"] in self.documents:
            return self.documents[ref["path"]]
        try:
            document = json.loads(data)
        except (ValueError, UnicodeDecodeError) as exc:
            raise IntegrityError("decision audit artifact is not JSON: " + ref["path"]) from exc
        self.documents[ref["path"]] = document
        return document


def _authority_sources(store: _BoundReader, outputs: Mapping[str, Any], scope: Mapping[str, Any],
                       projection: Mapping[str, Any]) -> None:
    # Shared receipts are selected by the accepted projection, not by an audit-provided path.
    for cell_id, cells in projection.get("cells", {}).items():
        for cell in cells:
            if cell.get("receipt_sha256") is not None:
                path = f"data/jobs/{REVIEW_JOB}/cells/{cell_id}/attempt-{cell['attempts']}.json"
                store.admit({"path": path, "sha256": cell["receipt_sha256"]})
                store.cell_receipts[(path, cell["receipt_sha256"])] = cell_id
                store.receipts_by_cell.setdefault(cell_id, set()).add((path, cell["receipt_sha256"]))
    for lane in ("lead", "hunt"):
        output = outputs.get(f"{lane}_review.teams")
        if output is None:
            continue
        document = store.document(output["artifact"])
        _require(isinstance(document, Mapping), "accepted audit lane is not an object")
        capture = document.get("proposal_audit")
        if capture is not None:
            _require(isinstance(capture, Mapping) and set(capture) == {"schema", "items"}
                     and capture["schema"] == "appsec-review/proposal-membership-capture/1"
                     and isinstance(capture["items"], list), "audit proposal capture has an unsupported schema")
            for entry in capture["items"]:
                _require(isinstance(entry, Mapping) and set(entry) == {
                    "package_id", "cell_id", "round", "proposal_ref", "claim_id", "decision", "reason", "receipt_sha256"}
                    and type(entry["round"]) is int and entry["round"] >= 0
                    and all(isinstance(entry[key], str) and 0 < len(entry[key]) <= 200
                            for key in ("package_id", "cell_id", "proposal_ref", "receipt_sha256"))
                    and (entry["claim_id"] is None or isinstance(entry["claim_id"], str))
                    and entry["decision"] in ("admitted", "rejected", "over_cap"),
                    "audit proposal capture has invalid fields")
                key = (entry["cell_id"], entry["round"], entry["proposal_ref"])
                _require(key not in store.proposals, "audit proposal capture repeats an original membership")
                store.proposals[key] = entry
                store.proposal_origins.add((entry["cell_id"], entry["receipt_sha256"],
                                            entry["proposal_ref"], entry["claim_id"]))
        independence = document.get("independence", {})
        _require(isinstance(independence, Mapping), "accepted audit independence is not an object")
        for claim_id, entries in independence.items():
            _require(isinstance(entries, list), "accepted audit independence entries are not an array")
            for entry in entries:
                _require(isinstance(entry, Mapping), "accepted audit independence entry is not an object")
                cell_id = entry.get("verifier_cell_id")
                _require(cell_id is None or isinstance(cell_id, str), "accepted audit verifier cell is invalid")
                if cell_id is not None:
                    key = (claim_id, cell_id)
                    _require(store.independence.get(key, entry) == entry,
                             "accepted verifier independence records conflict")
                    store.independence[key] = entry
                structure = entry.get("audit")
                _require(structure is None or isinstance(structure, Mapping), "accepted audit structure is invalid")
                check = (structure or {}).get("request_check")
                if check is not None:
                    _require(isinstance(check, Mapping) and set(check) == {"path", "sha256"}
                             and all(isinstance(value, str) for value in check.values()),
                             "accepted audit request check reference is malformed")
                    paths = {f"data/jobs/{REVIEW_JOB}/cells/{cell_id}/independence-attempt-{cell['attempts']}.json"
                             for cell in projection["cells"].get(cell_id, ())}
                    _require(check["path"] in paths, "audit request check belongs to another cell")
                    store.admit(check)
    manifest_ref = {"path": scope["manifest_path"], "sha256": scope["manifest_sha256"]}
    store.admit(manifest_ref)
    manifest = store.document(manifest_ref)
    _require(isinstance(manifest, Mapping) and manifest.get("run_id") == store.root.name and
             manifest.get("target_snapshot") == scope["target_snapshot"],
             "audit source manifest belongs to another run or target")
    selected = {(row["name"], row.get("shard_id", "default"), row["sha256"]) for row in scope["shards"]}
    for shard in manifest.get("indexes", ()):
        if (shard["name"], shard.get("shard_id", "default"), shard["sha256"]) in selected:
            ref = {"path": shard["relative_path"], "sha256": shard["sha256"]}
            store.admit(ref)
            store.shards[ref["path"]] = shard


def _membership(records: Sequence[c.Product], continued: Mapping[str, Sequence[c.SourceRef | c.RelationRef]], *,
                projection: Mapping[str, Any], projection_ref: Mapping[str, str],
                findings: Sequence[tuple[Mapping[str, str], Mapping[str, Any]]],
                adjudications: Mapping[str, Any], adjudication_ref: Mapping[str, str]) -> None:
    claims = {row["claim_id"]: row for row in projection["claims"]}
    finding_map = {row["claim_id"]: (ref, row) for ref, row in findings}
    decisions: dict[str, set[str]] = {claim_id: set() for claim_id in claims}
    for row in records:
        if isinstance(row, c.DecisionRecord) and row.context.subject.claim_id.value in decisions:
            decisions[row.context.subject.claim_id.value].add(row.record_id)
    judges = projection.get("judge_verdicts", {})
    adjudicated = {row["adjudication_id"]: row for row in adjudications["adjudications"]}
    adjudication_ids = {claim_id: {row.get("adjudication_id") for row in claim.get("state_history", ())
                                  if row.get("adjudication_id") is not None}
                       for claim_id, claim in claims.items()}
    for row in adjudicated.values():
        adjudication_ids.setdefault(row["claim_id"], set()).add(row["adjudication_id"])
    original_relations = {claim_id: {row["relation_id"]: row for row in rows}
                          for claim_id, rows in projection["relations"].items()}
    bases: set[str] = set()
    for record in records:
        subject = record.context.subject
        claim_id, cell_id = subject.claim_id.value, subject.cell_id.value
        cells = projection["cells"].get(cell_id, ())
        _require(claim_id is None or claim_id in claims, "audit record names a claim absent from the accepted ledger")
        if cell_id is not None:
            _require(bool(cells), "audit record names a cell absent from the accepted ledger")
            _require(claim_id is None or all(row["claim_id"] in (None, claim_id) for row in cells),
                     "audit record cell belongs to another claim")
            if isinstance(record, c.DecisionRecord) and record.actor_role is not None:
                _require({row["role"] for row in cells} == {record.actor_role},
                         "audit producing role disagrees with the accepted cell")
                if record.stage == c.Stage.CELL_EXECUTION:
                    _require(record.outcome in {row["status"] for row in cells},
                             "audit execution outcome disagrees with the accepted cell")
        if claim_id is not None and subject.package_id.value is not None:
            packages = {claims[claim_id]["package_id"], *(row["package_id"] for row in cells)}
            _require(subject.package_id.value in packages, "audit package belongs to another claim or cell")
        if subject.adjudication_id.value is not None:
            _require(subject.adjudication_id.value in adjudication_ids.get(claim_id, ()),
                     "audit record names a foreign adjudication")
        if subject.finding_package_id.value is not None:
            _require(claim_id in finding_map and finding_map[claim_id][1]["finding_package_id"] ==
                     subject.finding_package_id.value, "audit record names a foreign finding")
        relations = (*record.context.relations, *(row for ref in record.context.continuations
                     if ref.field == c.ReferenceField.RELATIONS for row in continued[ref.path]))
        originals = original_relations.get(claim_id, {})
        for relation in relations:
            original = originals.get(relation.relation_id)
            _require(original is not None, "audit relation is absent from the accepted claim")
            _require(all(getattr(relation, key) == original[key] for key in
                         ("claim_id", "predicate", "kind", "admissibility", "producing_cell_id")),
                     "audit relation disagrees with the accepted ledger")
            roles = {row["role"] for row in projection["cells"].get(relation.producing_cell_id, ())}
            _require(roles == {relation.actor_role}, "audit relation actor role disagrees with the accepted cell")
            _require((relation.source.path, relation.source.sha256) ==
                     (projection_ref["path"], projection_ref["sha256"]),
                     "audit relation does not bind the accepted projection")
        if isinstance(record, c.DecisionRecord) and record.stage == c.Stage.ADJUDICATION:
            original = adjudicated.get(subject.adjudication_id.value)
            _require(original is not None and record.deciding_row == original["deciding_row"]
                     and record.outcome == original["state"],
                     "audit deciding row or outcome disagrees with the accepted adjudication")
            required = {row["predicate"] for row in original["predicates"] if row["required"]}
            counted = set(original["counted_relation_ids"])
            _require(set(record.required_predicates) == required
                     and {row.relation_id for row in relations} == set(originals)
                     and all(row.counted == (row.relation_id in counted) for row in relations),
                     "audit deciding attribution changes accepted predicate accounting")
            _require(record.deciding_actor_roles == c.deciding_roles(record.deciding_row, required, relations),
                     "audit deciding actors disagree with the accepted chosen row")
        if not isinstance(record, c.DecisionBasisRecord):
            continue
        _require(claim_id not in bases, "audit repeats a claim decision basis")
        bases.add(claim_id)
        _require(claim_id in finding_map, "audit basis has no accepted finding")
        finding_ref, finding = finding_map[claim_id]
        _require((record.finding.path, record.finding.sha256, subject.finding_package_id.value,
                  subject.adjudication_id.value) == (finding_ref["path"], finding_ref["sha256"],
                  finding["finding_package_id"], finding["adjudication_id"]),
                 "audit basis disagrees with the accepted finding")
        _require((record.claim.path, record.claim.sha256) == (projection_ref["path"], projection_ref["sha256"]),
                 "audit basis does not bind the accepted claim projection")
        _require((record.adjudication.path, record.adjudication.sha256) ==
                 (adjudication_ref["path"], adjudication_ref["sha256"]),
                 "audit basis does not bind the accepted adjudication artifact")
        adjudication = adjudicated.get(subject.adjudication_id.value)
        _require(adjudication is not None and adjudication["claim_id"] == claim_id
                 and adjudication["state"] == finding["state"], "audit basis names a foreign adjudication")
        _require({row.record_id for row in record.decisions} == decisions[claim_id],
                 "audit basis omits or adds claim decision membership")
        _require({row.relation_id for row in relations} == set(originals),
                 "audit basis omits or adds accepted claim relations")
        counted = set(adjudication["counted_relation_ids"])
        _require(all(row.counted == (row.relation_id in counted) for row in relations),
                 "audit basis changes existing counted evidence")
        required = {row["predicate"] for row in adjudication["predicates"] if row["required"]}
        _require(set(record.required_predicates) == required
                 and set(record.missing_predicates) == set(finding["missing_predicates"]),
                 "audit basis changes accepted predicate coverage")
        _require({row.record_id.value for row in record.judge_verdicts} ==
                 {row["verdict_id"] for row in judges.get(claim_id, ())},
                 "audit basis omits or adds judge verdicts")
        _require(all((row.path, row.sha256) == (projection_ref["path"], projection_ref["sha256"])
                     for row in record.judge_verdicts), "audit judge verdict does not bind the accepted projection")
        _require({row.record_id.value for row in record.score_refs} == set(finding["scores"]),
                 "audit basis omits or adds accepted scores")


def _cell_receipt(store: _BoundReader, source: c.SourceRef, cell_id: str,
                  projection: Mapping[str, Any], *, record_id: str | None = None) -> Mapping[str, Any]:
    candidates = {(f"data/jobs/{REVIEW_JOB}/cells/{cell_id}/attempt-{row['attempts']}.json",
                   row["receipt_sha256"]): row for row in projection["cells"].get(cell_id, ())}
    cell = candidates.get((source.path, source.sha256))
    _require(cell is not None and source.record_id.value == (cell_id if record_id is None else record_id),
             "audit receipt is not the accepted subject cell's receipt")
    receipt = store.document(source.to_dict())
    _require(isinstance(receipt, Mapping) and receipt.get("schema") == "appsec-review/cell-attempt-receipt/1"
             and receipt.get("cell_id") == cell_id and receipt.get("attempt") == cell["attempts"]
             and receipt.get("status") == cell["status"], "audit receipt identity disagrees with the accepted cell")
    return receipt


def _proposal_source(store: _BoundReader, source: c.SourceRef, projection: Mapping[str, Any]) -> str:
    cell_id = store.cell_receipts.get((source.path, source.sha256))
    _require(cell_id is not None and source.record_id.value is not None,
             "audit original proposal does not identify an accepted cell receipt")
    roles = {row["role"] for row in projection["cells"][cell_id]}
    _require(bool(roles) and roles <= {Role.RED_TEAM_ANALYST, Role.HYPOTHESIS_HUNTER},
             "audit original proposal is not from an accepted discovery cell")
    receipt = _cell_receipt(store, source, cell_id, projection, record_id=source.record_id.value)
    result = receipt.get("result")
    proposals = result.get("proposals", ()) if isinstance(result, Mapping) else ()
    _require(isinstance(proposals, list) and sum(isinstance(row, Mapping) and
             row.get("local_id") == source.record_id.value for row in proposals) == 1,
             "audit proposal identity is absent or ambiguous in its original receipt")
    return cell_id


def _accounted_proposals(receipt: Mapping[str, Any], lead_id: str) -> tuple[str, ...] | None:
    result = receipt.get("result")
    if result is None:
        return None
    _require(isinstance(result, Mapping), "audit lead discovery result is malformed")
    if "lead_accounting" not in result:
        return None
    entries = result["lead_accounting"]
    _require(isinstance(entries, list) and all(isinstance(row, Mapping) for row in entries),
             "audit lead accounting is malformed")
    matches = [row for row in entries if row.get("observation_id") == lead_id]
    _require(len(matches) == 1, "audit lead is absent or ambiguous in its original receipt")
    if "proposal_ids" not in matches[0]:
        return None
    ids = matches[0]["proposal_ids"]
    _require(isinstance(ids, list) and all(isinstance(value, str) and value for value in ids)
             and len(ids) == len(set(ids)), "audit lead proposal membership is malformed")
    proposals = result.get("proposals")
    _require(isinstance(proposals, list) and all(isinstance(row, Mapping)
             and isinstance(row.get("local_id"), str) for row in proposals), "audit original proposals are malformed")
    by_id = {row["local_id"]: row for row in proposals}
    _require(len(by_id) == len(proposals) and set(ids) <= set(by_id),
             "audit lead accounting names absent or ambiguous original proposals")
    for local_id, proposal in by_id.items():
        if "source_lead_ids" not in proposal:
            continue
        leads = proposal["source_lead_ids"]
        _require(isinstance(leads, list) and all(isinstance(value, str) and value for value in leads)
                 and len(leads) == len(set(leads)), "audit proposal source leads are malformed")
        _require((lead_id in leads) == (local_id in ids),
                 "audit lead accounting disagrees with original proposal source_lead_ids")
    return tuple(sorted(ids))


def _lead_membership(store: _BoundReader, record: c.Product, projection: Mapping[str, Any],
                      origins: Sequence[c.SourceRef],
                      continued: Mapping[str, Sequence[c.SourceRef | c.RelationRef]]) -> None:
    subject = record.context.subject
    lead_id = subject.lead_id.value
    if lead_id is None:
        return
    is_lead_semantic = (isinstance(record, c.DecisionRecord) and record.stage == c.Stage.RED_DISCOVERY
                        and subject.proposal_ref.value is None)
    if is_lead_semantic:
        if subject.cell_id.value is not None:
            roles = {row["role"] for row in projection["cells"][subject.cell_id.value]}
            _require(roles <= {Role.RED_TEAM_ANALYST, Role.HYPOTHESIS_HUNTER},
                     "audit lead semantic row does not name a discovery cell")
        receipt_ref = record.cell_receipt.value
        if receipt_ref is not None:
            _cell_receipt(store, receipt_ref, subject.cell_id.value, projection)
        sources = (*record.context.sources, *(row for ref in record.context.continuations
                   if ref.field == c.ReferenceField.SOURCES for row in continued[ref.path]))
        refs = set()
        for source in sources:
            identity = (source.path, source.sha256)
            cell_id = store.cell_receipts.get(identity)
            if cell_id is None:
                continue
            _require(subject.cell_id.value in (None, cell_id),
                     "audit lead source receipt belongs to a different known cell")
            _require(source.record_id.value in (cell_id, lead_id),
                     "audit lead receipt locator is not its accepted cell or requested lead")
            roles = {row["role"] for row in projection["cells"][cell_id]}
            _require(roles <= {Role.RED_TEAM_ANALYST, Role.HYPOTHESIS_HUNTER},
                     "audit lead receipt source is not a discovery cell")
            refs.add(identity)
        if receipt_ref is not None:
            refs.add((receipt_ref.path, receipt_ref.sha256))
        subject_refs = store.receipts_by_cell.get(subject.cell_id.value, set())
        if len(subject_refs) == 1:
            refs.update(subject_refs)
        expected = set()
        unavailable = not refs
        for path, sha in sorted(refs):
            cell_id = store.cell_receipts[(path, sha)]
            source = c.SourceRef(store.root.name, path, sha, c.Link(cell_id, None), (c.EvidenceUse.READ,))
            receipt = _cell_receipt(store, source, cell_id, projection)
            ids = _accounted_proposals(receipt, lead_id)
            if ids is None:
                unavailable = True
            else:
                expected.update((path, sha, identity) for identity in ids)
        _require({(row.path, row.sha256, row.record_id.value) for row in origins} == expected,
                 "audit lead origin set omits or substitutes original lead-accounted proposals; "
                 "unrecorded memberships permit no inferred origins")
        if unavailable:
            _require(bool(record.context.gap_ids), "unrecorded lead proposal membership needs an explicit omission")
            store.lead_membership_unavailable.add(record.record_id)
        return
    for source in origins:
        cell_id = store.cell_receipts[(source.path, source.sha256)]
        receipt = _cell_receipt(store, source, cell_id, projection, record_id=source.record_id.value)
        ids = _accounted_proposals(receipt, lead_id)
        _require(ids is not None and source.record_id.value in ids,
                 "audit proposal origin does not belong to its declared lead")


def _proposal_membership(store: _BoundReader, record: c.Product, projection: Mapping[str, Any],
                         continued: Mapping[str, Sequence[c.SourceRef | c.RelationRef]]) -> None:
    subject = record.context.subject
    proposal_id = subject.proposal_ref.value
    if proposal_id is not None:
        key = (subject.cell_id.value, subject.round.value, proposal_id)
        capture = store.proposals.get(key)
        if capture is None:
            _require(isinstance(record, c.DecisionRecord) and record.stage == c.Stage.RED_DISCOVERY
                     and subject.claim_id.value is None
                     and subject.claim_id.absence_reason == c.AbsenceReason.LEGACY_UNRECORDED
                     and bool(record.context.gap_ids), "audit proposal has no exact original claim membership")
        else:
            _require((capture["package_id"], capture["claim_id"]) ==
                     (subject.package_id.value, subject.claim_id.value),
                     "audit proposal disagrees with its accepted normalization membership")
        receipts = [(path, sha) for path, sha in store.receipts_by_cell.get(subject.cell_id.value, ())
                    if capture is None or sha == capture["receipt_sha256"]]
        _require(len(receipts) == 1, "audit proposal does not select exactly one accepted terminal receipt")
        path, sha = receipts[0]
        _proposal_source(store, c.SourceRef(store.root.name, path, sha, c.Link(proposal_id, None),
                                           (c.EvidenceUse.READ,)), projection)
    origins = (*record.context.origin_proposals, *(row for ref in record.context.continuations
               if ref.field == c.ReferenceField.ORIGIN_PROPOSALS for row in continued[ref.path]))
    for source in origins:
        cell_id = _proposal_source(store, source, projection)
        _require(subject.claim_id.value is None or (cell_id, source.sha256, source.record_id.value,
                 subject.claim_id.value) in store.proposal_origins,
                 "audit origin proposal is not an accepted member of this claim")
    _lead_membership(store, record, projection, origins, continued)


def _verification_facts(store: _BoundReader, record: c.VerificationRecord) -> None:
    subject = record.context.subject
    entry = store.independence.get((subject.claim_id.value, subject.cell_id.value), {})
    for observed, key in ((record.existing_r6_passed, "independent"),
                          (record.diversity.provider_distinct, "provider_distinct"),
                          (record.diversity.model_profile_distinct, "verifier_model_distinct")):
        _require(observed.value is None or type(entry.get(key)) is bool and entry[key] == observed.value,
                 "audit verifier facts disagree with accepted independence provenance")
    structural = entry.get("audit") or {}
    _require(not structural or structural.get("schema") == "appsec-review/verifier-structure-capture/1",
             "audit structural check capture has an unsupported schema")
    for name in ("actor_distinct", "conversation_fresh", "prior_response_absent", "shared_actor_cache_absent"):
        observed = getattr(record.blindness, name)
        _require(observed.value is None or type(structural.get(name)) is bool and structural[name] == observed.value,
                 "audit blindness differs from observed structural checks")
    source = record.blindness.request_check.value
    if source is not None:
        _require(structural.get("request_check") == {"path": source.path, "sha256": source.sha256}
                 and source.record_id.value == subject.cell_id.value,
                 "audit blindness request check is not the accepted cell check")
        document = store.document(source.to_dict())
        _require(isinstance(document, Mapping) and document.get("schema") == "appsec-review/verifier-request-check/1"
                 and document.get("cell_id") == subject.cell_id.value,
                 "audit blindness request check belongs to another cell")
        if record.blindness.passed.value is True:
            _require(document.get("contains_forbidden_marker") is False
                     and structural.get("request_markers_absent") is True,
                     "audit blindness passed despite an unverified or forbidden request")


def _observed_sources(store: _BoundReader, records: Sequence[c.Product], projection: Mapping[str, Any],
                      outputs: Mapping[str, Any], continued: Mapping[str, Sequence[c.SourceRef | c.RelationRef]]) -> None:
    original_relations = {claim_id: {row["relation_id"]: row for row in rows}
                          for claim_id, rows in projection["relations"].items()}
    for record in records:
        _proposal_membership(store, record, projection, continued)
        if isinstance(record, c.DecisionBasisRecord):
            if record.score_refs:
                score_ref = outputs["scoring.score_claims"]["artifact"]
                _require(all((row.path, row.sha256) == (score_ref["path"], score_ref["sha256"])
                             for row in record.score_refs), "audit scores do not bind the accepted scoring artifact")
            continue
        cell_id = record.context.subject.cell_id.value
        source = record.cell_receipt if isinstance(record, c.DecisionRecord) else record.receipt
        if source.value is not None:
            _cell_receipt(store, source.value, cell_id, projection)
        if not isinstance(record, c.VerificationRecord):
            continue
        _verification_facts(store, record)
        _require(record.status in {row["status"] for row in projection["cells"].get(cell_id, ())},
                 "audit verifier status disagrees with the accepted cell")
        originals = original_relations.get(record.context.subject.claim_id.value, {})
        for predicate in record.predicates:
            for own_read in predicate.own_read_refs:
                receipt = _cell_receipt(store, own_read, cell_id, projection)
                seen = receipt.get("seen_identities")
                _require("reused_from" not in receipt and isinstance(seen, list) and bool(seen)
                         and all(isinstance(item, str) for item in seen),
                         "audit verifier own reads require original observed retrieval, not memo reuse or supply")
                ids = (*predicate.supporting_relation_ids, *predicate.contradicting_relation_ids)
                _require(all(originals[identity]["retrieval_receipt_sha256"] == own_read.sha256
                             and originals[identity]["entity_id"] in seen for identity in ids),
                         "audit verifier relation is not among its own observed reads")


def verify_decision_audit(run_root: Path, *, accepted: Any, published: Mapping[str, Any],
                          review: Mapping[str, Any], scope: Mapping[str, Any],
                          projection: Mapping[str, Any], projection_ref: Mapping[str, str],
                          findings: Sequence[tuple[Mapping[str, str], Mapping[str, Any]]]) -> AcceptedAudit:
    """Join a verified review to its optional sidecar without modifying public state."""
    declarations = producer_contract(Path(run_root), accepted.handoff)
    declared = next((row for row in declarations if row.output_kind == "review_audit_metadata"), None)
    if "metadata_path" not in published:
        _require(declared is None, "accepted review declares decision audit metadata but omitted its publication")
        return AcceptedAudit(None, None, (), (), (), DecisionAuditSettings(), accepted.sha256, "legacy_unrecorded")
    _require(declared is not None and declared.schema == PUBLICATION_SCHEMA and
             declared.disposition == "protected" and declared.authority == "operational",
             "decision audit publication lacks its protected operational dataset declaration")
    root = Path(run_root)
    _require(not root.is_symlink(), "decision audit run root is symbolic")
    root = root.resolve()
    handoff = accepted.handoff
    _require(handoff["run_id"] == root.name and handoff["job_id"] == REVIEW_JOB,
             "decision audit accepted handoff belongs to another run or producer")
    store = _BoundReader(root, handoff, DecisionAuditSettings())
    _require(PurePosixPath(accepted.path).parent == store.attempt, "accepted handoff is in another attempt")
    metadata_path = published["metadata_path"]
    _require(metadata_path == (store.audit_root / "publication.json").as_posix(),
             "audit publication descriptor is outside the accepted audit directory")
    metadata = store.document({"path": metadata_path, "sha256": store.pins.get(metadata_path)}, audit=True)
    config_ref = {"path": "data/configuration/resolved.json", "sha256": handoff["resolved_config_sha256"]}
    store.admit(config_ref)
    frozen = store.document(config_ref)
    settings = DecisionAuditSettings.from_mapping(
        frozen["jobs"][REVIEW_JOB]["settings"].get("decision_audit"), "frozen.decision_audit")
    store.settings = settings
    if store.used_bytes > settings.max_input_bytes:
        raise AuditBoundExceeded("decision audit max_input_bytes exhausted by metadata and configuration")
    origin = expected_origin(handoff=handoff, published=published, review=review, scope=scope,
                             policy=policy_document(settings))
    publication = read_publication(metadata, expected_origin=origin, settings=settings)
    for ref, document in ((published["artifact"], review), (projection_ref, projection),
                          (handoff["outputs"]["scope.accept_manifest"]["artifact"], scope)):
        _require(store.attempt in PurePosixPath(ref["path"]).parents,
                 "decision audit anchor is outside the accepted attempt")
        _require(store.document(ref) == document, "audit anchor differs from its accepted bytes")
    if publication.manifest is None:
        return AcceptedAudit(None, None, (), (), tuple(store.receipts[key] for key in sorted(store.receipts)),
                             settings, accepted.sha256, publication.unavailable_reason)
    reference = publication.manifest
    _require(reference.path == (store.audit_root / "manifest.json").as_posix(),
             "audit manifest is outside its declared manifest location")
    manifest = c.from_document(store.document(reference.to_dict(), audit=True), expected_origin=origin)
    _require(isinstance(manifest, c.AuditManifest), "accepted audit reference is not a manifest")
    _require(store.cache[reference.path] == c.canonical_bytes(manifest), "audit manifest bytes are not canonical")
    reference.verify(manifest, expected_origin=origin)
    shards: dict[str, tuple[c.Product, ...]] = {}
    continued: dict[str, tuple[c.SourceRef | c.RelationRef, ...]] = {}
    for shard in manifest.shards:
        _require(PurePosixPath(shard.path).parent == store.audit_root / shard.kind.value
                 and shard.path.endswith(".jsonl"), "audit product shard is in the wrong declared family")
        if shard.record_count > settings.shard_records:
            raise AuditBoundExceeded("decision audit shard_records exhausted")
        store.records(shard.record_count)
        data = store.read(shard.to_dict(), audit=True, maximum=settings.shard_bytes)
        _require(len(data) == shard.byte_count, "audit shard byte count changed")
        lines = data.splitlines()
        _require(len(lines) == shard.record_count, "audit shard record count changed")
        try:
            rows = tuple(c.from_document(json.loads(line), expected_origin=origin) for line in lines)
        except (ValueError, UnicodeDecodeError) as exc:
            raise IntegrityError("audit shard contains invalid JSON") from exc
        _require(all(not isinstance(row, c.AuditManifest) for row in rows), "audit shard contains a manifest")
        _require(b"".join(c.canonical_bytes(row) for row in rows) == data, "audit shard bytes are not canonical")
        shards[shard.path] = rows
        for row in rows:
            for ref in row.context.continuations:
                _require(store.audit_root / "continuations" in PurePosixPath(ref.path).parents
                         and ref.path.endswith(".jsonl"), "audit continuation is outside its declared family")
                if ref.path in continued:
                    continue
                if ref.record_count > settings.shard_records:
                    raise AuditBoundExceeded("decision audit continuation shard_records exhausted")
                store.records(ref.record_count)
                payload = store.read(ref.to_dict(), audit=True, maximum=settings.shard_bytes)
                _require(len(payload) == ref.byte_count and len(payload.splitlines()) == ref.record_count,
                         "audit continuation counts changed")
                try:
                    continued[ref.path] = tuple(c.reference_from_document(
                        json.loads(line), field=ref.field, origin=origin, claim_id=row.context.subject.claim_id)
                        for line in payload.splitlines())
                except (ValueError, UnicodeDecodeError) as exc:
                    raise IntegrityError("audit continuation contains invalid JSON") from exc
                _require(c.reference_bytes(ref.field, continued[ref.path], origin=origin,
                         claim_id=row.context.subject.claim_id) == payload, "audit continuation bytes are not canonical")
    c.validate_bundle(manifest, shards, expected_origin=origin, manifest_reference=reference, continuations=continued)
    records = tuple(sorted((row for rows in shards.values() for row in rows), key=lambda row: row.record_id))
    _authority_sources(store, handoff["outputs"], scope, projection)
    adjudication_ref = handoff["outputs"]["adjudicate.apply_policy"]["artifact"]
    adjudications = store.document(adjudication_ref)
    _membership(records, continued, projection=projection, projection_ref=projection_ref,
                findings=findings, adjudications=adjudications, adjudication_ref=adjudication_ref)
    for source in (*_sources(records), *_sources(tuple(row for rows in continued.values() for row in rows))):
        _require(source.path in store.shards or any(pattern.fullmatch(source.path)
                 for _, pattern in store.output_patterns), "audit source is not a declared accepted output")
        store.read(source.to_dict())
    _observed_sources(store, records, projection, handoff["outputs"], continued)
    return AcceptedAudit(reference, manifest, records, tuple(sorted(continued.items())),
                         tuple(store.receipts[key] for key in sorted(store.receipts)), settings, accepted.sha256,
                         lead_membership_unavailable=tuple(sorted(store.lead_membership_unavailable)))


def load_decision_audit(run_root: Path, *, max_packages: int = 10000) -> AcceptedAudit:
    """Operator/application adapter; uses existing admitted upstream loading and read receipts."""
    from appsec_review.application_paths import application_asset
    from appsec_review.jobs.accepted_review import load_accepted_review
    from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
    schemas = SchemaSet(application_asset(SCHEMA_DIRECTORY / "handoff.schema.json").parent)
    audit = load_accepted_review(run_root, schemas, max_packages=max_packages, include_decision_audit=True).decision_audit
    _require(audit is not None, "accepted review loader did not verify decision audit capability")
    return audit


__all__ = ["AcceptedAudit", "AuditBoundExceeded", "ReadReceipt", "expected_origin",
           "load_decision_audit", "verify_decision_audit"]
