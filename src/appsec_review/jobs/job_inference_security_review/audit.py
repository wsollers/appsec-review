"""Publication-only adapter from the review's already accepted, hash-pinned inputs."""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from appsec_review.config.inference_review import DecisionAuditSettings, semantic_settings_sha256
from appsec_review.review.cells import RECEIPT_SCHEMA, _RECEIPT_KEYS, _valid_reused_from
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.metadata import policy_document
from appsec_review.review.decision_audit.projection import (
    Document, ProjectionInputs, link, project,
)
from appsec_review.review.decision_audit.publication import (
    AuditUnavailable, BoundReader, PublishedAudit, audit_directory, publish_bundle, publish_descriptor,
)
from appsec_review.review.identity import sha256_hex
from appsec_review.review.lead_families import LeadCollection
from appsec_review.review.ledger import project as ledger_project, verify_events
from appsec_review.review.models import CellStatus, IntegrityError
from appsec_review.review.models import Role
from appsec_review.review.scope import AcceptedScope
from appsec_review.runtime.release import read_document
from appsec_review.runtime.units import UnitContext
from appsec_review.storage import canonical_json
from appsec_review.storage.shared import safe_path


@dataclass(frozen=True)
class AuditInputs:
    """Original unit-output pins, not mutable latest pointers or newly computed evidence."""
    handoff: Mapping[str, Any]
    ledger: Mapping[str, Any]
    projection: Mapping[str, Any]
    lanes: tuple[Mapping[str, Any], ...]
    package_sets: tuple[Mapping[str, Any], ...]
    adjudications: Mapping[str, Any]
    scores: Mapping[str, Any]
    triage: Mapping[str, Any]
    additional_expected_cells: Mapping[str, str]
    verification_inputs: tuple[Mapping[str, Any], ...] = ()


def trusted_origin(unit: UnitContext, scope: AcceptedScope, handoff: Mapping[str, Any],
                   settings: DecisionAuditSettings) -> tuple[c.Origin, Mapping[str, Any]]:
    """Bind the sidecar to the executing attempt, never to self-declared audit metadata.

    The runner already admits this claim; compare its persisted identity to the live context
    and frozen configuration before deriving an origin. Control reads use the existing bounded
    readers independently of the optional projection's capacity.
    """
    job = unit.job
    root = Path(job.run_root).absolute()
    attempt = f"data/jobs/job_inference_security_review/attempts/{job.attempt_id}"
    try:
        if (root != root.resolve() or root.name != job.run_id or scope.run_root != root
                or Path(job.attempt_root).absolute() != root / attempt
                or job.config.job_id != "job_inference_security_review"):
            raise IntegrityError("audit context has a foreign run or attempt")
        claim_path = safe_path(root, attempt + "/claim.json")
        manifest_path = safe_path(root, "data/configuration/manifest.json")
        if not claim_path.is_file() or not manifest_path.is_file():
            raise IntegrityError("audit control anchor is not a regular file")
        claim = read_document(claim_path)
        manifest = read_document(manifest_path)
        expected = {
            "schema": "appsec-review/attempt-claim/1", "run_id": job.run_id,
            "job_id": job.config.job_id, "attempt_id": job.attempt_id, "attempt_path": attempt,
            "repository_root": str(job.repository_root), "source_fingerprint": job.source_fingerprint,
            "upstream_handoffs": dict(job.upstream_handoffs),
        }
        if any(claim.get(key) != value for key, value in expected.items()):
            raise IntegrityError("audit attempt claim differs from executing context")
        target = job.evidence_target_snapshot or job.source_fingerprint
        if (claim.get("evidence_target_snapshot", claim["source_fingerprint"]) != target
                or (scope.run_id, scope.target_snapshot) != (job.run_id, target)):
            raise IntegrityError("audit scope differs from the claimed target")
        manifest_path = scope.manifest_path.relative_to(root).as_posix()
        if (job.input_manifest_path != scope.manifest_path
                or job.input_manifest_sha256 != scope.manifest_sha256
                or claim.get("input_manifest_path") != manifest_path
                or claim.get("input_manifest_sha256") != scope.manifest_sha256):
            raise IntegrityError("audit scope differs from the attempt's admitted manifest")
        config_ref = {"path": "data/configuration/resolved.json", "sha256": claim["resolved_config_sha256"]}
        if manifest.get("resolved_sha256") != config_ref["sha256"]:
            raise IntegrityError("audit claim differs from frozen configuration identity")
        reader = BoundReader(root, DecisionAuditSettings())
        frozen = reader.json(config_ref)
        frozen_settings = frozen["jobs"][job.config.job_id]["settings"]
        if (frozen_settings != job.config.settings or
                DecisionAuditSettings.from_mapping(frozen_settings.get("decision_audit"), "frozen.decision_audit")
                != settings):
            raise IntegrityError("audit settings differ from frozen configuration")
        scope_ref = unit.output("scope.accept_manifest")["artifact"]
        ledger = unit.output("publication.publish_claim_ledger")
        package_refs = tuple(unit.output(f"packages.assemble_{lane}_packages")["artifact"] for lane in ("lead", "hunt"))
        for ref in (scope_ref, handoff, ledger["ledger"], ledger["projection"], *package_refs):
            if not ref["path"].startswith(attempt + "/"):
                raise IntegrityError("audit anchor belongs to a foreign attempt")
            safe_path(root, ref["path"])
        accepted = reader.json(scope_ref)
        if (accepted["schema"] != "appsec-review/inference-review-accepted-scope/1"
                or (accepted["run_id"], accepted["target_snapshot"], accepted["manifest_sha256"],
                    accepted["manifest_path"]) != (job.run_id, target, scope.manifest_sha256, manifest_path)):
            raise IntegrityError("audit scope artifact differs from accepted scope")
        body = reader.json(handoff)
        if (body["schema"] != "appsec-review/inference-review-handoff/3"
                or (body["run_id"], body["accepted_manifest_sha256"], body["configuration_sha256"],
                    body["ledger_head_sha256"], body["projection_sha256"]) !=
                (job.run_id, scope.manifest_sha256, semantic_settings_sha256(job.config.typed_settings),
                 ledger["ledger_head_sha256"], ledger["projection"]["sha256"])):
            raise IntegrityError("audit handoff differs from original review anchors")
        for lane, ref in zip(("lead", "hunt"), package_refs):
            packages = reader.json(ref)
            key = "lead_package_manifest_sha256" if lane == "lead" else "package_manifest_sha256"
            if (packages["schema"] != "appsec-review/inference-review-lane-packages/1"
                    or packages["lane"] != lane or packages["package_manifest_content_sha256"] != body[key]):
                raise IntegrityError("audit handoff differs from original package set")
        policy = policy_document(settings)
        origin = c.Origin(
            job.run_id, job.attempt_id, target, scope.manifest_sha256, handoff["sha256"],
            body["ledger_head_sha256"], body["projection_sha256"], body["package_manifest_sha256"],
            c.HashLink(body["lead_package_manifest_sha256"], None), config_ref["sha256"],
            c.HashLink(None, c.AbsenceReason.NOT_PRODUCED), c.HashLink(None, c.AbsenceReason.NOT_PRODUCED),
            policy["version"], policy["sha256"])
        audit_directory(root, job.attempt_root, origin)
        return origin, config_ref
    except (OSError, KeyError, TypeError, ValueError, AuditUnavailable) as exc:
        raise IntegrityError("cannot verify decision audit publication identity") from exc


def publish_decision_audit(*, run_root: Path, attempt_root: Path, origin: c.Origin,
                           scope: AcceptedScope, collection: LeadCollection | None,
                           inputs: AuditInputs, settings: DecisionAuditSettings) -> PublishedAudit:
    """Return existing-control metadata and exact artifact pins after full bundle validation.

    The caller supplies the full resolved configuration hash in ``origin``; it is not the
    semantic model-settings hash inside the inner handoff. ``collection`` must be the existing
    accepted collector's result, with its observed shard reads retained by the job context.
    Historical callers may pass None, producing explicit provenance limitations.
    """
    if not settings.enabled:
        raise AuditUnavailable("disabled")
    try:
        return _publish(run_root=run_root, attempt_root=attempt_root, origin=origin, scope=scope,
                        collection=collection, inputs=inputs, settings=settings)
    except (KeyError, TypeError, ValueError) as exc:
        raise IntegrityError("malformed or unsupported decision audit source input") from exc


def _publish(*, run_root, attempt_root, origin, scope, collection, inputs, settings):
    directory = audit_directory(run_root, attempt_root, origin)
    if (scope.run_id, scope.target_snapshot, scope.manifest_sha256) != (
            origin.run_id, origin.target_snapshot, origin.accepted_manifest_sha256):
        raise IntegrityError("audit accepted scope differs from origin")
    reader = BoundReader(run_root, settings)
    for reference in inputs.verification_inputs:
        reader.read(reference)
    attempt = Path(attempt_root).absolute().relative_to(Path(run_root).absolute()).as_posix()

    def document(reference, schema=None, *, namespace=None, owned=True):
        if owned and not reference["path"].startswith(attempt + "/"):
            raise IntegrityError("audit source belongs to a foreign review attempt")
        value = reader.json(reference, namespace=namespace)
        if schema is not None and value.get("schema") != schema:
            raise IntegrityError("unsupported audit source schema")
        source = c.SourceRef(origin.run_id, reference["path"], reference["sha256"],
                             link(), (c.EvidenceUse.READ,))
        return Document(source, value)

    manifest_ref = {"path": Path(scope.manifest_path).relative_to(run_root).as_posix(),
                    "sha256": scope.manifest_sha256}
    reader.read(manifest_ref)
    handoff = document(inputs.handoff, "appsec-review/inference-review-handoff/3")
    body = handoff.value
    if (inputs.handoff["sha256"], body["run_id"], body["accepted_manifest_sha256"],
        body["ledger_head_sha256"], body["projection_sha256"], body["package_manifest_sha256"],
        body["lead_package_manifest_sha256"]) != (
            origin.review_handoff_sha256, origin.run_id, origin.accepted_manifest_sha256,
            origin.ledger_head_sha256, origin.projection_sha256, origin.package_manifest_sha256,
            origin.lead_package_manifest_sha256.value):
        raise IntegrityError("inner review handoff differs from audit origin")
    if not inputs.ledger["path"].startswith(attempt + "/"):
        raise IntegrityError("audit ledger belongs to a foreign review attempt")
    raw_ledger = reader.read(inputs.ledger)
    events = tuple(json.loads(line) for line in raw_ledger.splitlines())
    if b"".join(canonical_json(event) for event in events) != raw_ledger:
        raise IntegrityError("audit ledger is not canonical")
    streams = {event["stream"] for event in events}
    for stream in streams:
        verify_events(sorted((event for event in events if event["stream"] == stream),
                             key=lambda event: event["sequence"]))
    projection = ledger_project(events)
    projected = document(inputs.projection, "appsec-review/claim-projection/1")
    lanes = tuple(document(ref, "appsec-review/inference-review-lane/1") for ref in inputs.lanes)
    sets = tuple(document(ref, "appsec-review/inference-review-lane-packages/1") for ref in inputs.package_sets)
    packages = {}
    for package_set in sets:
        value = package_set.value
        manifest = document(value["package_manifest"], "appsec-review/review-package-manifest/1")
        expected = origin.lead_package_manifest_sha256.value if value["lane"] == "lead" else origin.package_manifest_sha256
        manifest_body = {key: val for key, val in manifest.value.items() if key != "content_sha256"}
        if (manifest.value["content_sha256"] != expected or sha256_hex(manifest_body) != expected
                or value["package_manifest_content_sha256"] != expected
                or manifest.value["run_id"] != origin.run_id
                or manifest.value["manifest_sha256"] != origin.accepted_manifest_sha256):
            raise IntegrityError("audit package manifest differs from accepted review")
        for ref in value["packages"]:
            package = document(ref, "appsec-review/review-package/6")
            identity = ref["package_id"]
            if package.value["package_id"] != identity:
                raise IntegrityError("audit package identity changed")
            if identity in packages and packages[identity] != package:
                raise IntegrityError("conflicting package inputs")
            packages[identity] = package
    receipts = {}
    for cell_id, records in projection.cells.items():
        if len(records) != 1:
            raise IntegrityError("ambiguous terminal cell receipts")
        record = records[0]
        if record.receipt_sha256 is None:
            if record.attempts != 0:
                raise IntegrityError("attempted cell lacks an original receipt")
            continue
        path = f"data/jobs/job_inference_security_review/cells/{cell_id}/attempt-{record.attempts}.json"
        receipt = document({"path": path, "sha256": record.receipt_sha256}, RECEIPT_SCHEMA,
                           namespace="review-cell", owned=False)
        value = receipt.value
        if (set(value) - {"reused_from"} != _RECEIPT_KEYS or value["cell_id"] != cell_id
                or type(value["attempt"]) is not int or value["attempt"] != record.attempts or value["status"] != record.status
                or value["attempt_id"] != f"{cell_id}/attempt-{record.attempts}"):
            raise IntegrityError("cell receipt does not match accepted terminal record")
        if not isinstance(value["seen_identities"], list) or any(
                not isinstance(identity, str) for identity in value["seen_identities"]):
            raise IntegrityError("malformed original receipt read identities")
        if "reused_from" in value and not _valid_reused_from(value["reused_from"], cell_id):
            raise IntegrityError("cell receipt has an invalid reuse pin")
        if record.status == CellStatus.SUCCEEDED and (
                not isinstance(value["result"], dict) or value["result_sha256"] != sha256_hex(value["result"])):
            raise IntegrityError("cell receipt result hash changed")
        if (record.status == CellStatus.SUCCEEDED
                and record.role in (Role.RED_TEAM_ANALYST, Role.HYPOTHESIS_HUNTER)
                and value["result"].get("schema") != "appsec-review/red-discovery-result/1"):
            raise IntegrityError("unsupported red result schema")
        receipts[cell_id] = receipt
    checks = {}
    for lane in lanes:
        for rows in lane.value["independence"].values():
            for row in rows:
                ref = (row.get("audit") or {}).get("request_check")
                if ref is None:
                    continue
                cell_id = row["verifier_cell_id"]
                cell = projection.cells[cell_id][0]
                expected = f"data/jobs/job_inference_security_review/cells/{cell_id}/independence-attempt-{cell.attempts}.json"
                if ref["path"] != expected:
                    raise IntegrityError("request check belongs to another cell or attempt")
                found = document(ref, "appsec-review/verifier-request-check/1", namespace="cell-check", owned=False)
                if found.value["cell_id"] != cell_id or found.value["attempt"] != cell.attempts:
                    raise IntegrityError("request check identity differs from original verifier")
                if (set(found.value) != {"schema", "cell_id", "attempt", "markers_sha256",
                                         "request_sha256s", "contains_forbidden_marker"}
                        or type(found.value["contains_forbidden_marker"]) is not bool):
                    raise IntegrityError("malformed verifier request check")
                if found.value["contains_forbidden_marker"] and row["audit"]["request_markers_absent"]:
                    raise IntegrityError("verifier structure contradicts its original request check")
                checks[cell_id] = found
    findings = tuple(document({"path": (PurePosixPath(inputs.handoff["path"]).parent / "findings" /
                                        f"{ref['finding_package_id']}.json").as_posix(), "sha256": ref["sha256"]},
                              "appsec-review/finding-package/2")
                     for ref in body["finding_packages"])
    if any(finding.value["finding_package_id"] != ref["finding_package_id"]
           for finding, ref in zip(findings, body["finding_packages"])):
        raise IntegrityError("finding identity differs from original handoff membership")
    lead_sources = {}
    shards = {(row["name"], row.get("shard_id", "default"), row["sha256"]): row for row in scope.shards}
    if collection is not None:
        for lead in collection.leads:
            shard = shards.get((lead.shard_name, lead.shard_id, lead.shard_sha256))
            if shard is None:
                raise IntegrityError("lead provenance names an unaccepted shard")
            reader.read({"path": shard["relative_path"], "sha256": shard["sha256"]})
            from appsec_review.runtime.inputs import observe_shard
            observe_shard(run_root, shard)
            lead_sources[lead.observation_id] = c.SourceRef(origin.run_id, shard["relative_path"], shard["sha256"],
                                                            link(lead.observation_id), (c.EvidenceUse.READ,))
    result = project(ProjectionInputs(
        origin, projection, projected, lanes, sets, tuple(packages.values()),
        document(inputs.adjudications, "appsec-review/inference-review-adjudications/1"),
        document(inputs.scores, "appsec-review/inference-review-scores/3"), findings,
        document(inputs.triage, "appsec-review/lead-triage/1"), receipts, checks, collection,
        lead_sources, inputs.additional_expected_cells), settings=settings, directory=directory)
    artifacts = []
    manifest = publish_bundle(run_root=run_root, attempt_root=attempt_root, origin=origin, settings=settings,
                              records=result.records, coverage=result.coverage, continuations=result.continuations,
                              artifact_sink=artifacts, byte_budget=reader.remaining)
    published = publish_descriptor(run_root=run_root, attempt_root=attempt_root, origin=origin, settings=settings,
                                   manifest=manifest, artifacts=tuple(artifacts))
    sources = tuple({"path": path, "sha256": digest, "size_bytes": len(data)}
                    for path, (digest, data) in sorted(reader.cache.items()) if path.startswith(attempt + "/"))
    return replace(published, source_artifacts=sources)
