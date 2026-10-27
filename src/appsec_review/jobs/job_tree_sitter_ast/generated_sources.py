"""Select accepted source artifacts, not filesystem trees, for the generated AST lane."""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
from pathlib import Path, PurePosixPath
from typing import Any

from appsec_review.jobs.cataloging import LANGUAGES
from appsec_review.jobs.delivery_scope import delivery_gap, scope_fields, source_in_scope
from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.jobs.job_artifact_indexing.job import _validate_receipts
from appsec_review.retrieval.source_resolution import generated_path, publish_source
from appsec_review.storage.shared import safe_path
from appsec_review.runtime.scope import supplied_run_path


_SOURCE_KINDS = frozenset({"generated-source", "generated-code", "generated-java-source",
                          "generated-kotlin-source", "generated-autoload", "generated-declaration"})
_LANGUAGES = {**LANGUAGES, ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
              ".mts": "TypeScript", ".cts": "TypeScript", ".kts": "Kotlin"}


def load_generated_sources(run_root: Path, *, target_snapshot: str, relevant: bool,
                           max_files: int, max_file_bytes: int,
                           max_total_bytes: int) -> tuple[list[dict[str, Any]], list[dict[str, str]], str | None]:
    if min(max_files, max_file_bytes, max_total_bytes) < 1:
        raise ValueError("generated source bounds must be positive")
    max_file_bytes = min(max_file_bytes, 16 * 1024 * 1024)
    pointer = run_root / "data/jobs/job_language_build/latest.json"
    if not pointer.is_file():
        return [], ([{"path": "@generated", "reason": "generated_source_producer_unavailable"}]
                    if relevant else []), None
    accepted = load_accepted_language_build(run_root)
    if accepted.get("source_fingerprint") != target_snapshot:
        raise ValueError("generated source producer target snapshot differs")
    rows: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = [
        {"path": "@generated", "reason": f"generated_source_producer_gap: {gap}"}
        for gap in list(accepted.get("gaps", ()))[:1000]]
    selected_count = total = examined = 0
    max_files, max_total_bytes = min(max_files, 10000), min(max_total_bytes, 128 * 1024 * 1024)
    for receipt in accepted.get("receipts", ()):
        examined += 1
        if examined > 100000:
            gaps.append({"path": "@generated", "reason": "generated_source_metadata_bound"})
            break
        if not isinstance(receipt, Mapping):
            raise ValueError("generated source receipt is invalid")
        selected = []
        exhausted = False
        for raw in receipt.get("artifacts", ()):
            examined += 1
            if examined > 100000:
                gaps.append({"path": "@generated", "reason": "generated_source_metadata_bound"})
                exhausted = True
                break
            if not isinstance(raw, Mapping):
                raise ValueError("generated source artifact is invalid")
            if not source_in_scope(raw):
                continue
            if supplied_run_path(str(raw.get("path", ""))):
                raise ValueError("supplied platform path entered generated source intake")
            original = str(raw.get("workspace_path", ""))
            language = _LANGUAGES.get(PurePosixPath(original).suffix.lower())
            if language is None or (raw.get("kind") not in _SOURCE_KINDS and
                    raw.get("scope_role") not in {"deliverable", "shipped_dependency"}):
                continue
            if raw.get("artifact_origin") not in {"accepted-input", "build-output"}:
                raise ValueError("generated source artifact has unaccepted origin")
            size = raw.get("size_bytes")
            if type(size) is not int or size < 0:
                raise ValueError("generated source byte size is invalid")
            if size > max_file_bytes:
                gaps.append({"path": original, "reason": "generated_source_file_byte_bound"})
                continue
            if selected_count >= max_files or total + size > max_total_bytes:
                gaps.append({"path": "@generated", "reason": "generated_source_lane_bound"})
                exhausted = True
                break
            selected_count += 1
            total += size
            selected.append(dict(raw))
        if not selected:
            if receipt.get("terminal_status") != "SUCCEEDED":
                gaps.append({"path": str(receipt.get("build_unit_id", "@generated")),
                             "reason": "generated_source_build_unsuccessful"})
            if exhausted:
                break
            continue
        manifest = receipt.get("workspace_manifest")
        if (not isinstance(manifest, Mapping) or supplied_run_path(str(manifest.get("path", "")))
                or safe_path(run_root, str(manifest.get("path", ""))).stat().st_size > 16 * 1024 * 1024):
            raise ValueError("generated source workspace manifest unavailable or exceeds bound")
        verified, _ = _validate_receipts(run_root, target_snapshot, [{**receipt, "artifacts": selected}])
        for artifact in verified[0]["validated_artifacts"]:
            fields = scope_fields(artifact)
            artifact.update(fields)
            source = safe_path(run_root, artifact["path"])
            with source.open("rb") as stream:
                data = stream.read(max_file_bytes + 1)
            if len(data) != artifact["size_bytes"] or hashlib.sha256(data).hexdigest() != artifact["sha256"]:
                raise ValueError("generated source changed before detached publication")
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                gaps.append({"path": artifact["workspace_path"], "reason": "generated_source_not_utf8"})
                continue
            logical = generated_path(artifact["canonical_identity"], artifact["workspace_path"])
            backing = publish_source(run_root, target_snapshot=target_snapshot, logical_path=logical,
                                     artifact=artifact, build_unit_id=str(receipt["build_unit_id"]),
                                     handoff_sha256=accepted["language_build_handoff_sha256"], data=data)
            row = {
                "path": logical, "sha256": artifact["sha256"], "size_bytes": len(data),
                "language": _LANGUAGES[PurePosixPath(artifact["workspace_path"]).suffix.lower()],
                "generated": True, **fields, "source_domain": "generated", "source_backing": backing,
                "build_unit_id": receipt["build_unit_id"], "build_root": receipt.get("root", "."),
                "workspace_path": artifact["workspace_path"],
                "canonical_artifact_identity": artifact["canonical_identity"],
            }
            rows.append(row)
            if gap := delivery_gap(artifact):
                gaps.append({"path": logical, "reason": gap})
        if exhausted:
            break
    return rows, gaps, str(accepted["language_build_handoff_sha256"])
