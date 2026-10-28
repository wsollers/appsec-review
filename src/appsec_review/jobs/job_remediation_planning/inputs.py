"""Confirmed-only accepted intake and bounded index-to-run-workspace source resolution."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable, Mapping

from appsec_review.config.remediation import RemediationBounds
from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.jobs.completion_contracts import FindingBinding
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds
from appsec_review.review.models import IntegrityError
from .patches import safe_file


def load_review(run_root: Path, repository_root: Path, bounds: RemediationBounds) -> dict[str, Any]:
    from appsec_review.jobs.accepted_review import load_accepted_review
    verified = load_accepted_review(run_root, SchemaSet(repository_root / SCHEMA_DIRECTORY),
                                    max_packages=bounds.max_packages).document
    if verified["run_id"] != run_root.name:
        raise IntegrityError("remediation review run identity mismatch")
    return verified


def confirmed_findings(review: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    confirmed = set(review["partition"]["confirmed"])
    findings = [item for item in review["packages"] if item["finding_package_id"] in confirmed]
    if len(findings) != len(confirmed) or any(item["state"] != "confirmed" for item in findings):
        raise IntegrityError("remediation intake is not exactly the verified confirmed partition")
    return sorted(findings, key=lambda row: (row["claim_id"], row["finding_package_id"]))


def binding(finding: Mapping[str, Any]) -> dict[str, str]:
    return FindingBinding(finding["claim_id"], finding["finding_package_id"], finding["sha256"]).as_dict()


def evidence_relations(run_root: Path, review: Mapping[str, Any], finding: Mapping[str, Any]) -> list[dict[str, Any]]:
    projection = read_bound_json(run_root, review["inputs"]["projection"])
    wanted = set(finding["direct_evidence"])
    rows = [row for row in projection["relations"].get(finding["claim_id"], ())
            if row["relation_id"] in wanted]
    if {row["relation_id"] for row in rows} != wanted:
        raise IntegrityError("confirmed finding evidence is absent from the accepted projection")
    return rows


def retrieval_core(run_root: Path, review: Mapping[str, Any]) -> Any:
    from appsec_review.retrieval.core import RetrievalCore
    handoff = read_bound_json(run_root, review["inputs"]["job_handoff"])
    scope = read_bound_json(run_root, handoff["outputs"]["scope.accept_manifest"]["artifact"])
    return RetrievalCore(run_root.parent, review["run_id"], manifest_sha256=scope["manifest_sha256"],
                         manifest_path=run_root / scope["manifest_path"])


class SourceReader:
    """Only indexed, evidence-related paths are readable; never reads a user target checkout."""

    def __init__(self, builds: AcceptedBuilds, core: Any, relations: list[dict[str, Any]],
                 bounds: RemediationBounds) -> None:
        self.builds, self.core, self.relations, self.bounds = builds, core, relations, bounds
        self.files: dict[str, dict[str, Any]] = {}
        self.gaps: list[str] = []
        self.total_bytes = 0

    def resolve(self) -> None:
        for relation in self.relations[:self.bounds.max_list_items]:
            result = self.core.find(identity=relation["entity_id"], limit=1)
            rows = result["results"]
            if not rows or not isinstance(rows[0].get("location"), Mapping):
                self.gaps.append(f"source_location_unavailable:{relation['relation_id']}")
                continue
            location = rows[0]["location"]
            name = location.get("path")
            if not isinstance(name, str) or name in self.files:
                continue
            if len(self.files) >= self.bounds.max_source_files:
                self.gaps.append("source_file_bound_reached")
                break
            located = self.builds.locate(name)
            if located.unit is None:
                self.gaps.append(f"run_owned_source_unavailable:{name}:{located.code}")
                continue
            build = located.unit
            digest = build.workspace_manifest.get(name)
            if digest != location.get("file_sha256"):
                raise IntegrityError(f"accepted index and build baseline disagree: {name}")
            path = safe_file(build.workspace, name)
            if path.stat().st_size > min(self.bounds.max_file_bytes, self.bounds.max_source_bytes):
                self.gaps.append(f"source_byte_bound_reached:{name}")
                continue
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                raise IntegrityError(f"accepted source bytes changed: {name}")
            if self.total_bytes + len(data) > self.bounds.max_source_bytes:
                self.gaps.append("source_byte_bound_reached")
                break
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                self.gaps.append(f"source_encoding_unsupported:{name}")
                continue
            self.total_bytes += len(data)
            self.files[name] = {"path": name, "sha256": digest, "text": text,
                                "entity_id": relation["entity_id"], "relation_id": relation["relation_id"],
                                "build": build.identity()}
        if len(self.relations) > self.bounds.max_list_items:
            self.gaps.append("evidence_relation_bound_reached")
        self.gaps = list(dict.fromkeys(self.gaps))

    def retrieve(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if set(request) != {"path", "start_line", "end_line"}:
            raise ValueError("retrieve requires exactly path, start_line and end_line")
        name, start, end = request["path"], request["start_line"], request["end_line"]
        if (not isinstance(name, str) or name not in self.files or type(start) is not int
                or type(end) is not int or start < 1 or end < start or end - start >= 120):
            raise ValueError("retrieve must name an admitted source file and at most 120 lines")
        row = self.files[name]
        return {"path": name, "sha256": row["sha256"], "start_line": start,
                "lines": row["text"].splitlines()[start - 1:end]}


CoreFactory = Callable[[Path, Mapping[str, Any]], Any]
