"""Tiny original producer publications; no review job, model, target or container execution."""
from dataclasses import asdict
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
import tomllib

from appsec_review.config.inference_review import DecisionAuditSettings
from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.jobs.decision_audit_inputs import ORIGINAL_AUDIT_SOURCES
from appsec_review.retrieval import EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, write_manifest
from appsec_review.review.decision_audit import contracts as audit_contracts
from appsec_review.review.decision_audit.reader import REVIEW_JOB, _authority_sources, _BoundReader
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff

ROOT = Path(__file__).resolve().parents[3]
GATE = "job_final_publication_gate"
DOSSIER = "job_dossier_publication"
SCANNER = ("job_evidence_collection", "static_tool_observations", "observations", "scanner-fixture")
POST_BUILD = ("job_post_build_security_assessment", "build_security", "build_security", "hardening-fixture")
HISTORY = ("job_source_history_analysis", "history_signals", "history", "history-fixture")


class SourceRun:
    def __init__(self, base: Path, *, run_id="audit-source-run"):
        self.root = base / run_id
        self.target = "fixture-target"
        jobs = sorted({REVIEW_JOB, GATE, DOSSIER, HISTORY[0], *(producer for producer, _ in ORIGINAL_AUDIT_SOURCES)})
        config = {"build_capture": tomllib.loads((ROOT / "appsec-review.toml").read_text())["build_capture"],
                  "jobs": {name: {"name": name, "settings": {}, "workers": 1, "steps": {}} for name in jobs}}
        atomic_json(self.root / "data/configuration/resolved.json", config)
        atomic_json(self.root / "data/configuration/manifest.json", {
            "resolved_sha256": file_sha256(self.root / "data/configuration/resolved.json")})

    def publish(self, producer, outputs, *, attempt="attempt_0001", upstream=None, artifacts=(), target=None):
        declarations = import_module(f"appsec_review.jobs.{producer}.datasets").DATASETS
        directory = self.root / f"data/jobs/{producer}/attempts/{attempt}"
        atomic_json(directory / "claim.json", {
            "dataset_contract": dataset_contract(producer, sorted(
                {row.step for row in declarations} | {key.split(".")[0] for key in outputs}), declarations)})
        path = write_fixture_handoff(self.root, directory / "handoff.json", {
            "job_id": producer, "target_snapshot": target or self.target,
            "source_fingerprint": target or self.target,
            "outputs": outputs, "artifacts": list(artifacts),
            "upstream_handoff_sha256": dict(upstream or {})})
        atomic_json(directory.parent.parent / "latest.json", {
            "handoff_path": path.relative_to(self.root).as_posix(), "handoff_sha256": file_sha256(path)})
        return accepted_handoff(self.root, producer)

    def source(self, specification, *, attempt="attempt_0001", target=None, upstream=None):
        producer, kind, index, shard_id = specification
        target = target or self.target
        declarations = import_module(f"appsec_review.jobs.{producer}.datasets").DATASETS
        declaration = next(row for row in declarations if row.output_kind == kind)
        path = self.root / f"data/indices/audit-source-fixture/{producer}/{attempt}.sqlite"
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, target, {"producer": producer, "attempt": attempt})
        payload = ({"producer": "deterministic-build-security-rules", "check_id": "fixture",
                    "status": "FAIL"} if producer == POST_BUILD[0] else
                   {"tool_id": "tool-semgrep", "category": "source_sast", "native_severity": "HIGH"})
        builder = IndexBuilder(path, name=index, fingerprint="a" * 64, target_snapshot=target, shard_id=shard_id)
        builder.add_entity(EntityRecord(identity, "fixture", "fixture", "Synthetic original observation", payload))
        builder.add_coverage("fixture", "complete", None)
        shard = IndexIdentity(index, "appsec-review/retrieval-index/2", builder.build(), "a" * 64,
                              path.relative_to(self.root).as_posix(),
                              {"job": producer, "unit": declaration.step + ".fixture"}, (), shard_id)
        manifest_path = path.with_suffix(".manifest.json")
        write_manifest(manifest_path, run_id=self.root.name, target_snapshot=target,
                       target_root=self.root / "unavailable-checkout", indexes=(shard,))
        accepted = self.publish(producer, {declaration.step + ".fixture": {
            "index_manifest": artifact_ref(self.root, manifest_path), "index_identity": asdict(shard)}},
            attempt=attempt, upstream=upstream, target=target, artifacts=(artifact_ref(self.root, path),))
        return SimpleNamespace(accepted=accepted, shard=shard, source=audit_contracts.SourceRef(
            self.root.name, shard.relative_path, shard.sha256, audit_contracts.Link(identity.value, None),
            (audit_contracts.EvidenceUse.READ,)))

    def review(self, sources, *, upstream=None):
        manifest_path = self.root / "data/indices/manifests/audit-scope.json"
        write_manifest(manifest_path, run_id=self.root.name, target_snapshot=self.target,
                       target_root=self.root / "unavailable-checkout", indexes=tuple(row.shard for row in sources))
        scope_path = self.root / f"data/jobs/{REVIEW_JOB}/attempts/attempt_0001/steps/scope/tasks/accept_manifest/accepted-scope.json"
        atomic_json(scope_path, {"run_id": self.root.name, "target_snapshot": self.target,
                                "manifest_path": manifest_path.relative_to(self.root).as_posix(),
                                "manifest_sha256": file_sha256(manifest_path),
                                "shards": [{"name": row.shard.name, "shard_id": row.shard.shard_id,
                                            "sha256": row.shard.sha256} for row in sources]})
        pins = {row.accepted.job_id: row.accepted.sha256 for row in sources} if upstream is None else upstream
        return self.publish(REVIEW_JOB, {"scope.accept_manifest": {"artifact": artifact_ref(self.root, scope_path)}},
                            upstream=pins)

    def read_original(self, source):
        accepted = accepted_handoff(self.root, REVIEW_JOB)
        reader = _BoundReader(self.root, accepted.handoff, DecisionAuditSettings())
        scope = reader.document(accepted.handoff["outputs"]["scope.accept_manifest"]["artifact"])
        _authority_sources(reader, accepted.handoff["outputs"], scope, {"cells": {}})
        data = reader.read(source.source.to_dict())
        return data, reader.receipts[source.source.path]
