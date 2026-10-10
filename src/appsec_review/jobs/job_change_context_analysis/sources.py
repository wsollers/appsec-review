"""Bounded loading and normalization of review, deployment, and organization data.

All three sources are untrusted external metadata.  Operator exports are read only from a path
relative to the repository root, only when their bytes match the SHA-256 pinned in central
configuration, and only into closed schemas.  Any failure yields a named gap and an unavailable
source, never an empty-but-trusted dataset.  Free text (titles, names, emails, notes) is rejected or
discarded; only identifiers, enumerations, and timestamps survive normalization.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .settings import ExportSource


MAX_EXPORT_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 200_000
REVIEW_EXPORT_SCHEMA = "appsec-review/review-records/1"
DEPLOYMENT_EXPORT_SCHEMA = "appsec-review/deployment-events/1"
ORGANIZATION_EXPORT_SCHEMA = "appsec-review/organization-membership/1"
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})")
_OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TOKEN = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")


def parse_timestamp(value: Any) -> int | None:
    """Return epoch seconds for an RFC 3339 timestamp with an explicit offset, else ``None``."""
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    if "." in text:
        head, _, tail = text.partition(".")
        digits = re.match(r"\d+", tail).group(0)  # type: ignore[union-attr]
        text = head + "." + digits[:6].ljust(6, "0") + tail[len(digits):]
    try:
        return int(datetime.fromisoformat(text).timestamp())
    except ValueError:
        return None


def identity_hash(email: str) -> str:
    """Pseudonymous identity key shared with organization exports: SHA-256 of the lowercased email."""
    return hashlib.sha256(email.strip().lower().encode("utf-8", "surrogateescape")).hexdigest()


def load_export(repository_root: Path, target_root: Path | None, source: ExportSource,
                name: str) -> tuple[Any | None, bytes | None, list[str]]:
    """Return ``(document, raw_bytes, gaps)``; the document is ``None`` whenever a gap applies."""
    if not source.enabled:
        return None, None, [f"{name}_disabled"]
    if not source.export_sha256:
        return None, None, [f"{name}_export_unpinned"]
    root = repository_root.resolve()
    candidate = (root / source.export_path).resolve()
    if Path(source.export_path).is_absolute() or root not in candidate.parents:
        return None, None, [f"{name}_export_outside_repository"]
    if target_root is not None and (candidate == target_root.resolve() or target_root.resolve() in candidate.parents):
        return None, None, [f"{name}_export_inside_target"]
    if not candidate.is_file() or candidate.is_symlink():
        return None, None, [f"{name}_export_missing"]
    if candidate.stat().st_size > MAX_EXPORT_BYTES:
        return None, None, [f"{name}_export_too_large"]
    data = candidate.read_bytes()
    if hashlib.sha256(data).hexdigest() != source.export_sha256:
        return None, None, [f"{name}_export_hash_mismatch"]
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None, None, [f"{name}_export_invalid"]
    return document, data, []


def normalize_review_record(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize one per-commit review record from GitHub enrichment or an export.

    Approvals are other-reviewer approvals only.  ``complete`` is false when a timeline field the
    review-speed metrics need is missing, so consumers can report partial coverage.
    """
    pull = raw.get("pull_request")
    pull = pull if type(pull) is int and pull > 0 else None
    direct = raw.get("direct_push") is True and pull is None
    approvals_raw = raw.get("approvals")
    approvals = None
    if isinstance(approvals_raw, list):
        approvals = sorted(({"submitted_at": parse_timestamp(item.get("submitted_at")),
                             "commit_id": item.get("commit_id") if isinstance(item.get("commit_id"), str) and
                             _OBJECT_ID.fullmatch(item["commit_id"]) else None}
                            for item in approvals_raw[:1000] if isinstance(item, Mapping)),
                           key=lambda item: (item["submitted_at"] is None, item["submitted_at"] or 0,
                                             item["commit_id"] or ""))
    approved = raw.get("approved_by_other")
    if approved not in (True, False):
        approved = bool(approvals) if approvals is not None else None
    head = raw.get("head_sha") if isinstance(raw.get("head_sha"), str) and _OBJECT_ID.fullmatch(raw["head_sha"]) else None
    record = {
        "pull_request": pull, "direct_push": direct, "approved_by_other": None if direct else approved,
        "created_at": parse_timestamp(raw.get("created_at")), "merged_at": parse_timestamp(raw.get("merged_at")),
        "head_sha": head, "head_committed_at": parse_timestamp(raw.get("head_committed_at")),
        "approvals": approvals, "self_merged": raw.get("self_merged") if raw.get("self_merged") in (True, False) else None,
    }
    record["complete"] = direct or (pull is not None and approvals is not None and record["created_at"] is not None
                                    and record["merged_at"] is not None and head is not None)
    return record


def review_records_from_export(document: Any) -> tuple[dict[str, dict[str, Any]], list[str]]:
    if (not isinstance(document, Mapping) or document.get("schema") != REVIEW_EXPORT_SCHEMA or
            not isinstance(document.get("records"), Mapping) or len(document["records"]) > MAX_RECORDS):
        return {}, ["review_export_invalid"]
    records = {}
    for commit, value in document["records"].items():
        if isinstance(commit, str) and _OBJECT_ID.fullmatch(commit) and isinstance(value, Mapping):
            records[commit] = normalize_review_record(value)
    return dict(sorted(records.items())), []


def deployments_from_export(document: Any, environments: tuple[str, ...]) -> tuple[dict[str, Any] | None, list[str]]:
    if (not isinstance(document, Mapping) or document.get("schema") != DEPLOYMENT_EXPORT_SCHEMA or
            not isinstance(document.get("events"), list) or len(document["events"]) > MAX_RECORDS or
            not isinstance(document.get("coverage"), Mapping)):
        return None, ["deployment_export_invalid"]
    start = parse_timestamp(document["coverage"].get("start"))
    end = parse_timestamp(document["coverage"].get("end"))
    if start is None or end is None or end < start:
        return None, ["deployment_export_invalid"]
    events, rejected = [], 0
    allowed = set(environments)
    for item in document["events"]:
        if not isinstance(item, Mapping):
            rejected += 1
            continue
        deployed_at = parse_timestamp(item.get("deployed_at"))
        identifier, environment, status, commit = (item.get("deployment_id"), item.get("environment"),
                                                   item.get("status"), item.get("commit"))
        if (deployed_at is None or not isinstance(identifier, str) or not _TOKEN.fullmatch(identifier) or
                not isinstance(environment, str) or not _TOKEN.fullmatch(environment) or
                status not in {"success", "failure", "cancelled"} or
                not isinstance(commit, str) or not _OBJECT_ID.fullmatch(commit) or not start <= deployed_at <= end):
            rejected += 1
            continue
        if environment in allowed and status == "success":
            events.append({"deployment_id": identifier, "environment": environment, "deployed_at": deployed_at,
                           "commit": commit})
    events.sort(key=lambda item: (item["deployed_at"], item["deployment_id"]))
    gaps = ["deployment_events_rejected"] if rejected else []
    return {"coverage": {"start": start, "end": end}, "events": events, "rejected_count": rejected}, gaps


def organization_from_export(document: Any) -> tuple[dict[str, Any] | None, list[str]]:
    if (not isinstance(document, Mapping) or document.get("schema") != ORGANIZATION_EXPORT_SCHEMA or
            not isinstance(document.get("members"), list) or len(document["members"]) > MAX_RECORDS or
            parse_timestamp(document.get("as_of")) is None):
        return None, ["organization_export_invalid"]
    members: dict[str, dict[str, Any]] = {}
    rejected = 0
    for item in document["members"]:
        key = item.get("identity_sha256") if isinstance(item, Mapping) else None
        status = item.get("status") if isinstance(item, Mapping) else None
        if not isinstance(key, str) or not _SHA256.fullmatch(key) or status not in {"active", "departed"} or key in members:
            rejected += 1
            continue
        members[key] = {"status": status, "departed_at": parse_timestamp(item.get("departed_at"))}
    gaps = ["organization_members_rejected"] if rejected else []
    return {"as_of": parse_timestamp(document["as_of"]), "members": dict(sorted(members.items())),
            "rejected_count": rejected}, gaps
