"""Bounded custody checks around the authoritative accepted-review and gate projection."""
from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time
from typing import Any, Iterator

from appsec_review.applicability import resolved_configuration_identity
from appsec_review.config.inference_review import parse_inference_review_settings, semantic_settings_sha256
from appsec_review.indexing.store import AcceptedHandoff, accepted_handoff
from appsec_review.jobs.engineering_contracts import (
    FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, FINAL_PUBLICATION_GATE_SCHEMA,
)
from appsec_review.jobs.job_final_publication_gate import classify as classifier
from appsec_review.jobs.job_final_publication_gate.verify import REVIEW_JOB, load_accepted_review, project_score
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.retrieval.index import MANIFEST_SCHEMA, load_verified_manifest
from appsec_review.review.models import IntegrityError
from appsec_review.review.ship_block import policy_sha256
from appsec_review.storage.shared import safe_path

from .contracts import (
    ArtifactRef, ExportError, ExportFailureReason as Reason, ExportPhase, ExportProvenance,
    RepositoryIdentityBasis, SizedArtifactRef, SourceIdentity, VerifiedFinding, VerifiedInputs,
    canonical_bytes, json_sha256, parse_json_bytes, require_run_path,
    require_sha256, validate_repository_iri,
)
from .settings import OpenVexExportSettings

GATE_JOB = "job_final_publication_gate"
INTAKE_JOB = "job_review_intake"
_SCOPE_SCHEMA = "appsec-review/inference-review-accepted-scope/1"


def _require(condition: bool, message: str, reason: Reason = Reason.SEMANTIC_INVALID,
             *, phase: ExportPhase = ExportPhase.LOAD) -> None:
    if not condition:
        raise ExportError(message, reason=reason, phase=phase)


@contextmanager
def _errors(phase: ExportPhase, reason: Reason = Reason.SEMANTIC_INVALID) -> Iterator[None]:
    try:
        yield
    except ExportError:
        raise
    except FileNotFoundError as exc:
        raise ExportError("required run-owned input is missing", reason=Reason.INPUT_MISSING, phase=phase) from exc
    except OSError as exc:
        raise ExportError("run-owned input I/O failed", reason=Reason.IO_ERROR, phase=phase) from exc
    except (ValueError, KeyError, TypeError, IntegrityError) as exc:
        raise ExportError("run-owned input verification failed", reason=reason, phase=phase) from exc
    except Exception as exc:
        raise ExportError("unexpected input verification failure", reason=Reason.INTERNAL_ERROR, phase=phase) from exc


def _ref(value: Mapping[str, Any]) -> ArtifactRef:
    return ArtifactRef(value["path"], value["sha256"])


def _durable_inventory(inventory: tuple[SizedArtifactRef, ...]) -> tuple[SizedArtifactRef, ...]:
    """Admission pointers are bounded/reproved internally, not durable evidence bindings."""
    return tuple(reference for reference in inventory
                 if reference.path != "data/indices/accepted.json"
                 and re.fullmatch(r"data/jobs/[^/]+/latest\.json", reference.path) is None)


class BoundedInputReader:
    """Hash exact run-owned bytes; count unique paths, not repeated verification work.

    ``deadline`` is an absolute monotonic time. The reader never treats a constructor,
    a cached digest, or an upstream validation admission as proof of the current bytes.
    """

    def __init__(self, run_root: Path, settings: OpenVexExportSettings, *,
                 deadline: float | None = None, phase: ExportPhase = ExportPhase.LOAD) -> None:
        self.root = Path(run_root).absolute()
        self.settings = settings
        self.phase = ExportPhase(phase)
        self.deadline = time.monotonic() + settings.timeout_seconds if deadline is None else deadline
        self._inventory: dict[str, SizedArtifactRef] = {}
        self._total = 0

    def check_deadline(self) -> None:
        _require(time.monotonic() < self.deadline, "OpenVEX input verification timed out",
                 Reason.TIMED_OUT, phase=self.phase)

    def path(self, relative: str) -> Path:
        with _errors(self.phase, Reason.INPUT_TAMPERED):
            self.check_deadline()
            require_run_path(relative)
            # Windows junctions are reparse points, but need not report is_symlink().
            for parent in (*reversed(self.root.parents), self.root):
                attributes = parent.lstat()
                _require(not stat.S_ISLNK(attributes.st_mode)
                         and not getattr(attributes, "st_file_attributes", 0) & 0x400,
                         "run-root ancestry contains a link", Reason.INPUT_TAMPERED, phase=self.phase)
            candidate = safe_path(self.root, relative)
            current = self.root
            for part in PurePosixPath(relative).parts:
                current /= part
                attributes = current.lstat()
                _require(not stat.S_ISLNK(attributes.st_mode)
                         and not getattr(attributes, "st_file_attributes", 0) & 0x400,
                         "run-owned path contains a link", Reason.INPUT_TAMPERED, phase=self.phase)
            return candidate

    def _read(self, relative: str, digest: str | None) -> tuple[bytes, SizedArtifactRef]:
        with _errors(self.phase, Reason.INPUT_TAMPERED):
            path = self.path(relative)
            before = path.stat()
            _require(stat.S_ISREG(before.st_mode), "input is not a regular file",
                     Reason.INPUT_TAMPERED, phase=self.phase)
            old = self._inventory.get(relative)
            if old is not None and digest is not None:
                _require(old.sha256 == digest, "one input path has conflicting identities",
                         Reason.IDENTITY_CONFLICT, phase=self.phase)
            _require(old is not None or len(self._inventory) < self.settings.max_bindings,
                     "unique input binding bound exceeded", Reason.BOUND_EXCEEDED, phase=self.phase)
            remaining = self.settings.max_total_input_bytes - self._total + (old.size_bytes if old else 0)
            limit = min(self.settings.max_artifact_bytes, remaining)
            _require(before.st_size <= limit, "input byte bound exceeded",
                     Reason.BOUND_EXCEEDED, phase=self.phase)
            chunks: list[bytes] = []
            size = 0
            with path.open("rb") as stream:
                opened = os.fstat(stream.fileno())
                _require(stat.S_ISREG(opened.st_mode) and self._stamp(opened) == self._stamp(before),
                         "input changed while opening", Reason.INPUT_TAMPERED, phase=self.phase)
                while True:
                    self.check_deadline()
                    chunk = stream.read(min(65536, limit - size + 1))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    _require(size <= limit, "input byte bound exceeded",
                             Reason.BOUND_EXCEEDED, phase=self.phase)
                after = os.fstat(stream.fileno())
            _require(self._stamp(before) == self._stamp(after)
                     == self._stamp(self.path(relative).stat()) and size == after.st_size,
                     "input changed while reading", Reason.INPUT_TAMPERED, phase=self.phase)
            payload = b"".join(chunks)
            actual = hashlib.sha256(payload).hexdigest()
            _require(digest is None or actual == digest, "input digest does not match accepted bytes",
                     Reason.INPUT_TAMPERED, phase=self.phase)
            measured = SizedArtifactRef(relative, actual, size)
            _require(old is None or old == measured, "input changed during verification",
                     Reason.INPUT_TAMPERED, phase=self.phase)
            if old is None:
                self._inventory[relative] = measured
                self._total += size
            self.check_deadline()
            return payload, measured

    @staticmethod
    def _stamp(value: os.stat_result) -> tuple[int, int, int, int]:
        # Windows path-stat and descriptor-stat disagree about legacy st_ctime.
        return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns

    def pin(self, relative: str) -> SizedArtifactRef:
        return self._read(relative, None)[1]

    def read(self, reference: ArtifactRef) -> bytes:
        payload, measured = self._read(reference.path, reference.sha256)
        if isinstance(reference, SizedArtifactRef):
            _require(reference.size_bytes == measured.size_bytes, "declared input size disagrees with bytes",
                     Reason.INPUT_TAMPERED, phase=self.phase)
        return payload

    def json(self, reference: ArtifactRef) -> dict[str, Any]:
        payload = self.read(reference)
        with _errors(self.phase, Reason.SCHEMA_INVALID):
            return parse_json_bytes(payload, max_bytes=self.settings.max_artifact_bytes)

    @property
    def inventory(self) -> tuple[SizedArtifactRef, ...]:
        return tuple(self._inventory[key] for key in sorted(self._inventory))

    def reprove(self) -> None:
        for reference in self.inventory:
            self.read(reference)


def _published(handoff: Mapping[str, Any], unit: str) -> Mapping[str, Any]:
    result = handoff["outputs"][unit]
    _require(isinstance(result, Mapping), "accepted job output is not an object")
    return result


def _accepted(reader: BoundedInputReader, job: str, *, optional: bool = False) -> AcceptedHandoff | None:
    relative = f"data/jobs/{job}/latest.json"
    # lstat custody precedes accepted_handoff: its symlink-as-absent behavior is not safe here.
    try:
        reader.path(relative)
    except ExportError as exc:
        if optional and exc.reason == Reason.INPUT_MISSING:
            return None
        raise
    pointer = reader.json(reader.pin(relative).reference)
    reference = ArtifactRef(pointer["handoff_path"], pointer["handoff_sha256"])
    _require(reference.path.startswith(f"data/jobs/{job}/attempts/"),
             "accepted pointer belongs to another job", Reason.IDENTITY_CONFLICT)
    handoff = reader.json(reference)
    _require(handoff.get("schema") == "appsec-review/job-handoff/1"
             and handoff.get("status") == "ACCEPTED" and handoff.get("job_id") == job,
             "job handoff is not accepted for the required job", Reason.IDENTITY_CONFLICT)
    _require(handoff.get("run_id", reader.root.name) == reader.root.name,
             "job handoff belongs to another run", Reason.IDENTITY_CONFLICT)
    reader.check_deadline()
    with _errors(reader.phase, Reason.INPUT_TAMPERED):
        accepted = accepted_handoff(reader.root, job)
    reader.check_deadline()
    _require(accepted is not None, "accepted job handoff disappeared", Reason.INPUT_STALE)
    assert accepted is not None
    _require((accepted.path, accepted.sha256) == (reference.path, reference.sha256)
             and canonical_bytes(accepted.handoff) == canonical_bytes(handoff),
             "accepted job changed during verification", Reason.INPUT_STALE)
    reader.read(reference)
    return accepted


def _configuration(reader: BoundedInputReader, settings: OpenVexExportSettings
                   ) -> tuple[ArtifactRef, ArtifactRef, dict[str, Any], str, str]:
    manifest_ref = reader.pin("data/configuration/manifest.json").reference
    manifest = reader.json(manifest_ref)
    resolved_ref = ArtifactRef("data/configuration/resolved.json", manifest["resolved_sha256"])
    resolved = reader.json(resolved_ref)
    reader.check_deadline()
    with _errors(reader.phase, Reason.INPUT_TAMPERED):
        _require(resolved_configuration_identity(reader.root) == resolved_ref.sha256,
                 "resolved configuration identity changed", Reason.INPUT_TAMPERED)
    jobs = resolved["jobs"]
    with _errors(reader.phase, Reason.CONFIGURATION_INVALID):
        frozen = OpenVexExportSettings.from_mapping(jobs["job_openvex_export"]["settings"])
        frozen.require_enabled()
        frozen.validate_prerequisites(gate_enabled=jobs[GATE_JOB]["settings"]["enabled"],
                                      review_enabled=REVIEW_JOB in jobs)
    _require(frozen == settings, "export settings differ from immutable run configuration",
             Reason.CONFIGURATION_INVALID)
    with _errors(reader.phase, Reason.CONFIGURATION_INVALID):
        review_settings = parse_inference_review_settings(jobs[REVIEW_JOB]["settings"])
    semantic = semantic_settings_sha256(review_settings)
    policy = policy_sha256(review_settings.ship_block,
                          review_settings.verification.require_distinct_model_for_ship_blocking)
    reader.check_deadline()
    return manifest_ref, resolved_ref, resolved, semantic, policy


def _preflight_review(reader: BoundedInputReader, handoff: Mapping[str, Any]
                      ) -> tuple[ArtifactRef, dict[str, Any], ArtifactRef, dict[str, Any]]:
    review_ref = _ref(_published(handoff, "publication.publish_handoff")["artifact"])
    review = reader.json(review_ref)
    _require(review["run_id"] == reader.root.name, "review belongs to another run", Reason.IDENTITY_CONFLICT)
    _require(len(review["finding_packages"]) <= reader.settings.max_packages,
             "finding package bound exceeded", Reason.BOUND_EXCEEDED)
    scope_ref = _ref(_published(handoff, "scope.accept_manifest")["artifact"])
    scope = reader.json(scope_ref)
    for lane in ("lead", "hunt"):
        lane_ref = _ref(_published(handoff, f"packages.assemble_{lane}_packages")["artifact"])
        lane_doc = reader.json(lane_ref)
        manifest_ref = _ref(lane_doc["package_manifest"])
        package_manifest = reader.json(manifest_ref)
        for entry in package_manifest["packages"]:
            package_id = entry["package_id"]
            _require(isinstance(package_id, str) and re.fullmatch(r"[a-z][a-z0-9_-]*-[0-9a-f]{64}", package_id)
                     is not None, "unsafe review-package identity", Reason.IDENTITY_CONFLICT)
            name = (PurePosixPath(manifest_ref.path).parent / "packages" / f"{package_id}.json").as_posix()
            reader.json(ArtifactRef(name, entry["sha256"]))
    receipt_ref = _ref(_published(handoff, "publication.publish_claim_ledger")["artifact"])
    receipt = reader.json(receipt_ref)
    directory = PurePosixPath(receipt_ref.path).parent
    reader.read(ArtifactRef((directory / "claim-ledger.jsonl").as_posix(), receipt["ledger_sha256"]))
    reader.json(ArtifactRef((directory / "projection.json").as_posix(), receipt["projection_file_sha256"]))
    reader.json(_ref(review["coverage_matrix"]))
    for shard in review["shards"]:
        reader.read(_ref(shard))
    finding_root = PurePosixPath(review_ref.path).parent / "findings"
    score_root = PurePosixPath(_ref(_published(handoff, "scoring.score_claims")["artifact"]).path).parent / "scores"
    for entries, key, prefix, directory in (
        (review["finding_packages"], "finding_package_id", "finding", finding_root),
        (review["score_packages"], "score_id", "score", score_root),
    ):
        identities: set[str] = set()
        for entry in entries:
            identity = entry[key]
            _require(isinstance(identity, str) and re.fullmatch(rf"{prefix}-[0-9a-f]{{64}}", identity) is not None
                     and identity not in identities, "duplicate or invalid review package identity",
                     Reason.IDENTITY_CONFLICT)
            identities.add(identity)
            reader.json(ArtifactRef((directory / f"{identity}.json").as_posix(), entry["sha256"]))
    return review_ref, review, scope_ref, scope


def _manifest(reader: BoundedInputReader, reference: ArtifactRef, run_id: str, snapshot: str
              ) -> dict[str, Any]:
    pending = [reference]
    seen: set[ArtifactRef] = set()
    root_document: dict[str, Any] | None = None
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        document = reader.json(current)
        _require(document.get("schema") == MANIFEST_SCHEMA and document.get("run_id") == run_id
                 and document.get("target_snapshot") == snapshot,
                 "accepted manifest scope identity disagrees", Reason.IDENTITY_CONFLICT)
        if current == reference:
            root_document = document
        for raw in document["indexes"]:
            reader.read(ArtifactRef(raw["relative_path"], raw["sha256"]))
        pending.extend(_ref(raw) for raw in document.get("upstream_manifests", ()))
    reader.check_deadline()
    verified, digest = load_verified_manifest(reader.root, reader.path(reference.path), reference.sha256)
    reader.check_deadline()
    _require(digest == reference.sha256 and canonical_bytes(verified) == canonical_bytes(root_document),
             "accepted manifest changed during verification", Reason.INPUT_TAMPERED)
    assert root_document is not None
    return root_document


def _scope(reader: BoundedInputReader, scope: Mapping[str, Any], review: Mapping[str, Any]
           ) -> tuple[ArtifactRef, dict[str, Any]]:
    _require(scope.get("schema") == _SCOPE_SCHEMA and scope.get("run_id") == reader.root.name,
             "accepted scope schema/run identity disagrees", Reason.IDENTITY_CONFLICT)
    require_sha256(scope["target_snapshot"])
    reference = ArtifactRef(scope["manifest_path"], scope["manifest_sha256"])
    _require(reference.sha256 == review["accepted_manifest_sha256"],
             "accepted scope manifest differs from review", Reason.IDENTITY_CONFLICT)
    manifest = _manifest(reader, reference, reader.root.name, scope["target_snapshot"])
    actual = [(raw["name"], raw.get("shard_id", "default"), raw["sha256"]) for raw in manifest["indexes"]]
    declared = [(raw["name"], raw["shard_id"], raw["sha256"]) for raw in scope["shards"]]
    _require(len(set(actual)) == len(actual) and len(set(declared)) == len(declared)
             and set(actual) == set(declared), "accepted scope shard sets disagree", Reason.IDENTITY_CONFLICT)
    return reference, manifest


def _source(reader: BoundedInputReader, settings: OpenVexExportSettings, snapshot: str,
            config_ref: ArtifactRef, resolved: Mapping[str, Any], manifest: Mapping[str, Any]) -> SourceIdentity:
    qualifications = [
        "Identity is the accepted reviewed source snapshot and frozen configuration, not a released artifact.",
        "Configuration SHA-256: " + config_ref.sha256,
    ]
    profile = resolved.get("configuration_profile")
    if isinstance(profile, Mapping):
        qualifications.append("Observed configuration profile SHA-256: " + json_sha256(profile))
    if any(raw["name"] == "build" for raw in manifest["indexes"]):
        qualifications.append("Accepted metadata includes build index shards; this does not assert build success.")
    intake = _accepted(reader, INTAKE_JOB, optional=True)
    acquisition_ref = None
    basis = RepositoryIdentityBasis.OPERATOR_DECLARED
    if intake is not None:
        _require(intake.handoff.get("resolved_config_sha256") == config_ref.sha256,
                 "accepted intake configuration is stale", Reason.INPUT_STALE)
        intake_ref = _ref(_published(intake.handoff, "publish_intake.publish_handoff")["artifact"])
        document = reader.json(intake_ref)
        fingerprint = document["fingerprint"]
        _require(document.get("schema") == "appsec-review/review-intake/1"
                 and fingerprint.get("sha256") == snapshot,
                 "accepted intake snapshot disagrees", Reason.IDENTITY_CONFLICT)
        record = fingerprint["acquisition"]
        if record is not None:
            acquisition_ref = ArtifactRef(record["manifest"], record["manifest_sha256"])
            acquisition = reader.json(acquisition_ref)
            _require(acquisition.get("schema") in {
                "appsec-review/target-acquisition/1", "appsec-review/target-system-acquisition/1"},
                "unsupported accepted acquisition schema", Reason.SCHEMA_INVALID)
            _require(acquisition["identity_sha256"] == json_sha256(acquisition["identity"])
                     and acquisition["status"] in {"COMPLETE", "PARTIAL"}
                     and all(record[key] == acquisition[key] for key in (
                         "schema", "identity", "identity_sha256", "acquisition_id", "status")),
                     "accepted acquisition identity disagrees", Reason.IDENTITY_CONFLICT)
            matches = require_sha256(acquisition["tree"]["sha256"]) == snapshot
            _require(type(record["tree_matches"]) is bool and record["tree_matches"] == matches,
                     "acquisition snapshot qualification disagrees", Reason.IDENTITY_CONFLICT)
            spec = acquisition["spec"]
            if acquisition["schema"] == "appsec-review/target-acquisition/1":
                identity = acquisition["identity"]
                _require(spec["kind"] in {"git", "perforce", "review_export"}
                         and identity["kind"] == spec["kind"],
                         "acquisition source kinds disagree", Reason.IDENTITY_CONFLICT)
                if spec["kind"] in {"git", "review_export"}:
                    revision_key = "commit" if spec["kind"] == "git" else "revision"
                    _require(spec[revision_key] == identity[revision_key],
                             "acquisition source revisions disagree", Reason.IDENTITY_CONFLICT)
            repository = spec.get("url") if spec.get("kind") == "git" else spec.get("clone_url")
            if repository is not None:
                with _errors(reader.phase, Reason.IDENTITY_CONFLICT):
                    validate_repository_iri(repository)
                _require(repository == settings.repository_iri,
                         "operator repository identity conflicts with accepted acquisition", Reason.IDENTITY_CONFLICT)
            else:
                qualifications.append("Acquisition establishes no single repository IRI; repository identity is operator asserted.")
            qualifications.extend((
                "Accepted acquisition status: " + acquisition["status"],
                "Acquired tree matches the reviewed snapshot." if matches
                else "Acquired tree differs from the reviewed snapshot; no acquired revision is asserted as the reviewed tree.",
                "Accepted acquisition gaps SHA-256: " + json_sha256(record["gaps"]),
            ))
            basis = RepositoryIdentityBasis.ACCEPTED_ACQUISITION
    if acquisition_ref is None:
        qualifications.append("No accepted acquisition provenance supplies a repository or commit; repository identity is operator asserted.")
    return SourceIdentity(settings.repository_iri, basis, snapshot, acquisition_ref, tuple(qualifications))


def _findings(reader: BoundedInputReader, gate: Mapping[str, Any], review: Mapping[str, Any],
              review_handoff: Mapping[str, Any]) -> tuple[VerifiedFinding, ...]:
    projection_ref = _ref(gate["inputs"]["projection"])
    ledger_ref = _ref(gate["inputs"]["claim_ledger"])
    projection = reader.json(projection_ref)
    _require(projection.get("schema") == "appsec-review/claim-projection/1"
             and projection.get("ledger_head_sha256") == gate["review"]["ledger_head_sha256"]
             and json_sha256(projection) == gate["review"]["projection_sha256"],
             "claim projection identity disagrees", Reason.IDENTITY_CONFLICT)
    score_root = PurePosixPath(_ref(_published(review_handoff, "scoring.score_claims")["artifact"]).path).parent / "scores"
    scores = {raw["score_id"]: ArtifactRef((score_root / f"{raw['score_id']}.json").as_posix(), raw["sha256"])
              for raw in review["score_packages"]}
    findings = []
    for row in gate["packages"]:
        reader.check_deadline()
        relations = projection["relations"].get(row["claim_id"], ())
        by_id = {relation["relation_id"]: relation for relation in relations}
        _require(len(by_id) == len(relations), "duplicate resolving evidence relation", Reason.IDENTITY_CONFLICT)
        ids = [*row["direct_evidence"], *row["analyst_assessed_evidence"]]
        _require(len(ids) == len(set(ids)) and set(ids) <= set(by_id)
                 and all(by_id[identity]["claim_id"] == row["claim_id"] for identity in ids),
                 "finding evidence does not resolve through the accepted projection", Reason.IDENTITY_CONFLICT)
        refs = tuple(scores[score["score_id"]] for score in row["scores"])
        _require(all(ref.sha256 == score["sha256"] for ref, score in zip(refs, row["scores"])),
                 "finding score identity disagrees", Reason.IDENTITY_CONFLICT)
        for reference, score in zip(refs, row["scores"]):
            package = reader.json(reference)
            _require(package["claim_id"] == row["claim_id"] and package["score_id"] == score["score_id"]
                     and project_score(reference.to_json(), package) == score,
                     "score package claim/projection disagrees", Reason.IDENTITY_CONFLICT)
        findings.append(VerifiedFinding(row, refs, (ledger_ref, projection_ref)))
    return tuple(findings)


def verify_inputs(run_root: Path, settings: OpenVexExportSettings, repository_root: Path) -> VerifiedInputs:
    """Re-prove accepted gate/review/scope/configuration without accessing a target checkout."""
    with _errors(ExportPhase.LOAD):
        with _errors(ExportPhase.LOAD, Reason.CONFIGURATION_INVALID):
            settings = OpenVexExportSettings.from_mapping(settings.to_mapping())
            settings.require_enabled()
        reader = BoundedInputReader(run_root, settings)
        config_manifest_ref, config_ref, resolved, semantic, policy = _configuration(reader, settings)
        gate_job = _accepted(reader, GATE_JOB)
        review_job = _accepted(reader, REVIEW_JOB)
        assert gate_job is not None and review_job is not None
        _require(gate_job.handoff.get("upstream_handoff_sha256", {}).get(REVIEW_JOB) == review_job.sha256,
                 "gate was accepted against another review handoff", Reason.INPUT_STALE)
        for accepted in (gate_job, review_job):
            _require(accepted.handoff.get("resolved_config_sha256") == config_ref.sha256,
                     "accepted handoff uses another frozen configuration", Reason.INPUT_STALE)
        published = _published(gate_job.handoff, "acceptance.publish_handoff")
        _require(published.get("schema") == FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA,
                 "unsupported gate handoff schema", Reason.SCHEMA_INVALID)
        gate_ref = _ref(published["artifact"])
        gate = reader.json(gate_ref)
        _require(gate.get("run_id") == reader.root.name, "gate belongs to another run", Reason.IDENTITY_CONFLICT)
        _require(len(gate["packages"]) <= settings.max_packages, "gate package bound exceeded", Reason.BOUND_EXCEEDED)
        _require(len(gate["bindings"]) <= settings.max_bindings, "gate binding bound exceeded", Reason.BOUND_EXCEEDED)
        for raw in gate["bindings"]:
            reader.read(_ref(raw))
        review_ref, review, scope_ref, scope = _preflight_review(reader, review_job.handoff)
        with _errors(ExportPhase.LOAD, Reason.SCHEMA_INVALID):
            schemas = SchemaSet(Path(repository_root) / "docs" / "schemas" / "final-report")
            schemas.validate("final-publication-gate", gate)
        reader.check_deadline()
        authoritative = load_accepted_review(reader.root, SchemaSet(Path(repository_root) / SCHEMA_DIRECTORY),
                                             max_packages=settings.max_packages)
        reader.check_deadline()
        expected = classifier.gate_document(FINAL_PUBLICATION_GATE_SCHEMA, authoritative.document,
                                             classifier.classify(authoritative.document))
        _require(canonical_bytes(gate) == canonical_bytes(expected),
                 "accepted gate does not exactly equal its authoritative classifier projection", Reason.INPUT_STALE)
        _require(type(published["item_count"]) is int and published["item_count"] == gate["package_counts"]["total"]
                 == len(gate["packages"]), "published gate item count disagrees")
        _require(gate["review"]["configuration_sha256"] == semantic
                 and gate["review"]["ship_block_policy_sha256"] == policy,
                 "accepted review settings/policy differ from frozen configuration", Reason.IDENTITY_CONFLICT)
        manifest_ref, manifest = _scope(reader, scope, review)
        for accepted in (gate_job, review_job):
            declared_snapshot = accepted.handoff.get("evidence_target_snapshot",
                                                      accepted.handoff.get("source_fingerprint", "none"))
            _require(declared_snapshot in {"none", scope["target_snapshot"]},
                     "accepted job snapshot qualification disagrees", Reason.IDENTITY_CONFLICT)
        source = _source(reader, settings, scope["target_snapshot"], config_ref, resolved, manifest)
        findings = _findings(reader, gate, review, review_job.handoff)
        provenance = ExportProvenance(
            ArtifactRef(gate_job.path, gate_job.sha256), gate_ref,
            ArtifactRef(review_job.path, review_job.sha256), review_ref, scope_ref, manifest_ref,
            config_manifest_ref, config_ref, semantic, gate["review"]["lead_package_manifest_sha256"],
            gate["review"]["package_manifest_sha256"], gate["review"]["ledger_head_sha256"],
            gate["review"]["projection_sha256"], policy,
        )
        # Upstream authorities may use validation admissions. Re-read bounded bytes, not their cache.
        reader.reprove()
        reader.check_deadline()
        result = VerifiedInputs(reader.root.name, provenance, source, gate_job.handoff["completed_at"],
                                settings.settings_sha256(), gate, findings, _durable_inventory(reader.inventory))
        reader.check_deadline()
        return result


def reprove_inputs(run_root: Path, verified: VerifiedInputs, settings: OpenVexExportSettings,
                   repository_root: Path) -> None:
    """Re-run acceptance/custody and require the complete original input pin set."""
    with _errors(ExportPhase.ACCEPT):
        try:
            current = verify_inputs(run_root, settings, repository_root)
        except ExportError as exc:
            raise ExportError("OpenVEX inputs no longer verify at acceptance",
                              reason=exc.reason, phase=ExportPhase.ACCEPT) from exc
        _require(canonical_bytes(current.to_json()) == canonical_bytes(verified.to_json()),
                 "OpenVEX accepted inputs changed after load", Reason.INPUT_STALE, phase=ExportPhase.ACCEPT)


__all__ = ["BoundedInputReader", "reprove_inputs", "verify_inputs"]
