"""The evidence header/body partition of a job handoff and its body content identity.

``docs/architecture/job-interchange.md`` ("Evidence header, evidence body and the content identity")
is the definition; this module implements it. A field moving between header and body is a
content-identity change and must come with a note there and a new ``CONTENT_SCHEMA``.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping

from appsec_review.storage import canonical_json
import hashlib

CONTENT_SCHEMA = "appsec-review/handoff-content/1"
NORMALISED_ATTEMPT = "attempts/@/"
HEADER_FIELDS = frozenset({
    "schema", "run_id", "job_id", "attempt_id", "status", "started_at", "completed_at",
    "implementation_identity", "schema_identity", "validation_identity", "tool_identity",
    "resolving_paths", "artifacts", "outcomes", "input_manifest", "input_identity", "input_set_sha256",
    "upstream_handoff_sha256", "resolved_config_sha256", "job_config_sha256", "source_fingerprint",
    "target_snapshot", "content_sha256",
})
BODY_FIELDS = ("outputs", "artifact_content", "coverage", "completion_status", "execution_status", "gaps",
               "dataset_contract_sha256", "evidence_target_snapshot", "upstream_content_sha256")
EXCLUDED_FILES = frozenset({"claim.json", "status.json", "published.json", "outcomes.json", "result.json",
                            "revalidation.json"})
EXCLUDED_DIRECTORIES = frozenset({"logs", "events", "steps", "shared"})
_SHA = re.compile(r"[0-9a-f]{64}")


def normalise_attempt_paths(value: Any, attempt_id: str) -> Any:
    """Replace this attempt's ``attempts/<attempt_id>/`` in every string with ``attempts/@/``."""
    marker = f"attempts/{attempt_id}/"
    if isinstance(value, str):
        return value.replace(marker, NORMALISED_ATTEMPT)
    if isinstance(value, Mapping):
        return {str(key): normalise_attempt_paths(item, attempt_id) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalise_attempt_paths(item, attempt_id) for item in value]
    return value


def artifact_content(artifacts: list[Mapping[str, Any]], attempt_path: str) -> list[list[Any]]:
    """Sorted ``[sha256, size_bytes]`` of the attempt-root artifacts that are evidence, not bookkeeping."""
    prefix = attempt_path.rstrip("/") + "/"
    pairs = set()
    for artifact in artifacts:
        path = str(artifact["path"])
        if not path.startswith(prefix):
            continue
        relative = PurePosixPath(path[len(prefix):])
        if relative.name in EXCLUDED_FILES or (relative.parts and relative.parts[0] in EXCLUDED_DIRECTORIES):
            continue
        pairs.add((str(artifact["sha256"]), int(artifact["size_bytes"])))
    return [list(pair) for pair in sorted(pairs)]


def handoff_body(handoff: Mapping[str, Any], *, gaps: list[Any],
                 upstream_content_sha256: Mapping[str, str]) -> dict[str, Any]:
    attempt_id = str(handoff["attempt_id"])
    attempt_path = str(handoff["resolving_paths"]["attempt"])
    return {
        "outputs": normalise_attempt_paths(handoff["outputs"], attempt_id),
        "artifact_content": artifact_content(handoff["artifacts"], attempt_path),
        "coverage": dict(handoff["coverage"]),
        "completion_status": str(handoff["completion_status"]),
        "execution_status": str(handoff["execution_status"]),
        "gaps": normalise_attempt_paths(list(gaps), attempt_id),
        "dataset_contract_sha256": str(handoff["dataset_contract_sha256"]),
        "evidence_target_snapshot": str(handoff.get("evidence_target_snapshot", handoff["target_snapshot"])),
        "upstream_content_sha256": dict(sorted(upstream_content_sha256.items())),
    }


def content_sha256(body: Mapping[str, Any]) -> str:
    if set(body) != set(BODY_FIELDS):
        raise ValueError("handoff body does not match the documented partition")
    return hashlib.sha256(canonical_json({"schema": CONTENT_SCHEMA, "body": body})).hexdigest()


def pinned_upstream_content(run_root: Path, pins: Mapping[str, str]) -> dict[str, str] | None:
    """``{producer: content_sha256}`` of the pinned upstream handoffs; ``None`` when any lacks one."""
    from appsec_review.retrieval.core import _accepted_handoff
    result = {}
    for producer, digest in sorted(pins.items()):
        handoff, _ = _accepted_handoff(run_root, producer, str(digest))
        identity = handoff.get("content_sha256")
        if not isinstance(identity, str) or not _SHA.fullmatch(identity):
            return None
        result[producer] = identity
    return result


REVALIDATION_SCHEMA = "appsec-review/attempt-revalidation/1"


def equivalent_upstreams(run_root: Path, pinned: Mapping[str, str],
                         current: Mapping[str, str]) -> dict[str, dict[str, Any]] | None:
    """Per producer, whether the handoff a consumer pinned is equivalent to the one accepted now.

    Equal whole-file hashes are trivially equivalent. Otherwise both handoffs must carry a
    ``content_sha256`` and the two must be equal; a handoff without one, a producer pinned but no
    longer supplied (or supplied but not pinned) or any differing identity means ``None``: not
    equivalent, the consumer runs. Same run root only; the pins are resolved inside it.
    """
    from appsec_review.retrieval.core import RetrievalIntegrityError, _accepted_handoff
    if set(pinned) != set(current):
        return None
    record: dict[str, dict[str, Any]] = {}
    for producer in sorted(pinned):
        pinned_sha, current_sha = str(pinned[producer]), str(current[producer])
        entry: dict[str, Any] = {"pinned_handoff_sha256": pinned_sha, "current_handoff_sha256": current_sha}
        if pinned_sha == current_sha:
            entry["content_sha256"] = None
            entry["equivalence"] = "identical_handoff"
        else:
            try:
                old_handoff, _ = _accepted_handoff(run_root, producer, pinned_sha)
                new_handoff, _ = _accepted_handoff(run_root, producer, current_sha)
            except RetrievalIntegrityError:
                return None  # a pin that does not resolve to exactly one accepted handoff is not equivalent
            old_identity, new_identity = old_handoff.get("content_sha256"), new_handoff.get("content_sha256")
            if (not isinstance(old_identity, str) or not _SHA.fullmatch(old_identity)
                    or old_identity != new_identity):
                return None
            entry["content_sha256"] = old_identity
            entry["equivalence"] = "equivalent_content"
        record[producer] = entry
    return record


def handoff_content_sha256(run_root: Path, handoff: Mapping[str, Any], *, gaps: list[Any]) -> str | None:
    """The identity the runner records on an accepted handoff, or ``None`` when it cannot be transitive."""
    upstream = pinned_upstream_content(run_root, handoff.get("upstream_handoff_sha256", {}))
    if upstream is None:
        return None
    return content_sha256(handoff_body(handoff, gaps=gaps, upstream_content_sha256=upstream))
