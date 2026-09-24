#!/usr/bin/env python3
"""Validate a common worker envelope and its run-owned attempt artifacts without publishing."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import re
from types import MappingProxyType
from typing import Any, Mapping
import urllib.parse

import container_mobile_binary_contracts as _v07
from evidence_redaction import DEFAULT_LIMITS
from execution_state import ROOT, beneath, file_hash, identifier, read_json, tree_hashes
import sbom_family_contracts as _v05
from sca_nvd_snapshot import NO_AGE_LIMIT
from schema_validate import SchemaStore, validate_document
import secrets_iac_contracts as _v04
from tool_instance_shapes import HEADER_FIELDS, NODE_STATUSES
from worker_result import validate_immutable_reuse, validate_worker_result

REGISTRY = ROOT / "registry"
GRAPH = ROOT / "job-graph.json"
SCHEMAS = ROOT.parent / "schemas"
MAX_RESULT_BYTES = 8 * 1024 * 1024
MAX_CITATIONS = 4096
MAX_REPOSITORY_PATH = 1024
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SECRET_PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")),
)
SECRET_FIELD_RE = re.compile(r"(?i)(?:^|[_-])(api[_-]?key|access[_-]?token|password|secret)(?:$|[_-])")
HIGH_ENTROPY_VALUE_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{16,}$")
CLAIM_CLASS_POLICIES = {
    "ossf-scorecard-results": {
        "claim_class_id": "supply_chain_posture_evidence",
        "allowed_assertions": {
            "published-scorecard-posture", "published-check-evidence",
            "publication-coverage-gap",
        },
    },
    "repository-partition-map": {
        "claim_class_id": "supplied_partition_map",
        "allowed_assertions": {
            "declared-repository-structure", "statically-inferred-partition-relationship",
            "review-routing", "coverage-gap",
        },
    },
    "project-discovery": {
        "claim_class_id": "supplied_project_discovery",
        "allowed_assertions": {
            "declared-project-structure", "statically-inferred-build-plan", "coverage-gap",
        },
    },
}
PROMOTION_FIELDS = {
    "finding": {
        "finding", "findings", "verified_finding", "verified_findings",
        "vulnerability", "vulnerabilities",
    },
    "severity": {"severity", "cvss", "cvss_score", "exploitability"},
    "runtime-state": {
        "runtime_state", "runtime_observation", "observed_runtime", "live_scan",
        "live_scan_result", "production_state",
    },
}
PROMOTION_TEXT = {
    "finding": (
        re.compile(r"(?i)(?<!not a )(?<!no )\bverified[- ]finding\b"),
        re.compile(r"(?i)(?<!not a )(?<!no )\bconfirmed[- ]vulnerabilit(?:y|ies)\b"),
    ),
    "severity": (
        re.compile(r"(?i)\bseverity\s*[:=]\s*(?:critical|high|medium|low)\b"),
        re.compile(r"(?i)\bcvss\s*[:=]\s*[0-9]"),
    ),
    "runtime-state": (
        re.compile(r"(?i)\bruntime[- ]verified\b"),
        re.compile(r"(?i)\blive[- ]scan\s+(?:found|detected|confirmed|verified)\b"),
        re.compile(r"(?i)(?<!not )(?<!no )\bobserved[- ]runtime\s+(?:state|behavior|exposure)\b"),
    ),
}


def _relative_artifact_path(value: Any) -> tuple[Path | None, str | None]:
    if not isinstance(value, str) or not value or "\\" in value:
        return None, "artifact path must be a non-empty normalized POSIX relative path"
    pure = PurePosixPath(value)
    if pure.is_absolute() or re.match(r"^[A-Za-z]:", value) or ".." in pure.parts or "." in pure.parts:
        return None, f"artifact path escapes or is not normalized: {value!r}"
    normalized = pure.as_posix()
    if normalized != value:
        return None, f"artifact path is not canonical: {value!r}"
    return Path(*pure.parts), None


def _skip_reasons(graph: dict[str, Any], producer: str,
                  consumer: str | None) -> tuple[set[str], list[str]]:
    if consumer is None:
        return set(), ["SKIPPED validation requires a named consumer dependency edge"]
    node = graph.get("jobs", {}).get(consumer)
    if not node:
        return set(), [f"unknown consumer job: {consumer}"]
    matches = [dependency for dependency in node.get("dependencies", [])
               if dependency.get("job") == producer]
    if len(matches) != 1:
        return set(), [f"{consumer} does not have exactly one dependency edge from {producer}"]
    return set(matches[0].get("allowed_skip_reasons", [])), []


def _repository_relative(value: Any, *, allow_dot: bool = False,
                         exact: bool = False) -> str | None:
    if not isinstance(value, str) or not value or len(value) > MAX_REPOSITORY_PATH:
        return "must be a non-empty bounded repository-relative path"
    if value == "." and allow_dot:
        return None
    if "\\" in value or "\x00" in value or re.match(r"^[A-Za-z]:", value):
        return "must use normalized repository-relative POSIX syntax"
    pure = PurePosixPath(value)
    if (pure.is_absolute() or "." in pure.parts or ".." in pure.parts or
            pure.as_posix() != value):
        return "must be a normalized repository-relative path without traversal"
    if exact and any(marker in value for marker in "*?[]{}"):
        return "citation paths must name an exact repository file, not a pattern"
    return None


def _owning_run_root(attempt_root: Path, run_id: str) -> Path | None:
    for candidate in (attempt_root, *attempt_root.parents):
        if candidate.name == run_id and (candidate / "inputs" / "artifact-manifest.json").is_file():
            return candidate
    return None


def _source_root(attempt_root: Path, run_id: str) -> tuple[Path | None, list[str]]:
    owner = _owning_run_root(attempt_root, run_id)
    if owner is None:
        return None, ["cannot locate the owning run manifest for citation freshness"]
    try:
        manifest = read_json(owner / "inputs" / "artifact-manifest.json")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return None, [f"cannot read the owning run manifest: {type(exc).__name__}"]
    target = manifest.get("target")
    value = target.get("repo_path") if isinstance(target, dict) else None
    if not isinstance(value, str) or not value:
        value = manifest.get("intake_config", {}).get("target") if isinstance(
            manifest.get("intake_config"), dict) else None
    if not isinstance(value, str) or not value:
        return None, ["owning run manifest does not declare target.repo_path"]
    root = Path(value).absolute()
    if not root.is_dir():
        return None, ["owning run target repository is unavailable for citation freshness"]
    return root, []


def _walk_citations(value: Any, path: str = "$") -> list[tuple[str, dict[str, Any]]]:
    found: list[tuple[str, dict[str, Any]]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}"
            if key == "evidence_citations" and isinstance(item, list):
                found.extend((f"{child}[{index}]", citation)
                             for index, citation in enumerate(item)
                             if isinstance(citation, dict))
            else:
                found.extend(_walk_citations(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_walk_citations(item, f"{path}[{index}]"))
    return found


def _citation_errors(value: Any, source_root: Path | None) -> list[str]:
    citations = _walk_citations(value)
    errors: list[str] = []
    if len(citations) > MAX_CITATIONS:
        return [f"result has more than {MAX_CITATIONS} evidence citations"]
    if citations and source_root is None:
        errors.append("source repository is required to validate evidence citation freshness")
        return errors
    for location, citation in citations:
        if citation.get("source_type") != "source_file":
            errors.append(f"{location}: repository discovery citations must use source_type source_file")
            continue
        relative = citation.get("path")
        path_error = _repository_relative(relative, exact=True)
        if path_error:
            errors.append(f"{location}.path: {path_error}")
            continue
        digest_value = citation.get("content_hash")
        if not isinstance(digest_value, str) or not re.fullmatch(r"[0-9a-f]{64}", digest_value):
            errors.append(f"{location}.content_hash: a lowercase SHA-256 is required for freshness")
            continue
        try:
            cited = beneath(source_root, source_root / Path(*PurePosixPath(relative).parts))
        except ValueError:
            errors.append(f"{location}.path: citation escapes the target repository")
            continue
        if not cited.is_file() or cited.is_symlink():
            errors.append(f"{location}.path: cited repository file is missing or linked")
        elif file_hash(cited) != digest_value:
            errors.append(f"{location}.content_hash: cited repository file is stale")
    return errors


def _secret_errors(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}"
            if (isinstance(item, str) and SECRET_FIELD_RE.search(key) and
                    HIGH_ENTROPY_VALUE_RE.fullmatch(item)):
                errors.append(f"{child}: secret-like value is forbidden in a published result")
            errors.extend(_secret_errors(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_secret_errors(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(value):
                errors.append(f"{path}: {label} material is forbidden in a published result")
    return errors


def _claim_promotion_errors(value: Any, forbidden: set[str], path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}"
            normalized = key.lower().replace("-", "_")
            for category in forbidden:
                if normalized in PROMOTION_FIELDS[category]:
                    errors.append(
                        f"{child}: {category} promotion is forbidden by the declared claim class")
            errors.extend(_claim_promotion_errors(item, forbidden, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_claim_promotion_errors(item, forbidden, f"{path}[{index}]"))
    elif isinstance(value, str):
        for category in forbidden:
            if any(pattern.search(value) for pattern in PROMOTION_TEXT[category]):
                errors.append(
                    f"{path}: {category} promotion is forbidden by the declared claim class")
    return errors


def _claim_class_errors(contract: dict[str, Any], value: Any) -> list[str]:
    """Enforce opted-in claim identity; contracts without it remain historically readable."""
    declaration = contract.get("claim_class")
    if declaration is None:
        return []
    if not isinstance(declaration, dict):
        return ["output contract claim_class declaration must be an object"]
    contract_id = contract.get("contract_id")
    policy = CLAIM_CLASS_POLICIES.get(contract_id)
    if policy is None:
        return [f"output contract has no trusted claim-class policy: {contract_id}"]
    errors: list[str] = []
    if declaration.get("claim_class_id") != policy["claim_class_id"]:
        errors.append("output contract claim-class identity does not match its trusted policy")
    allowed = declaration.get("allowed_assertions")
    if not isinstance(allowed, list) or set(allowed) != policy["allowed_assertions"]:
        errors.append("output contract allowed assertions do not match its trusted claim surface")
    forbidden_value = declaration.get("forbidden_promotions")
    if not isinstance(forbidden_value, list):
        errors.append("output contract forbidden promotions must be an array")
        return errors
    forbidden = set(forbidden_value)
    required = set(PROMOTION_FIELDS)
    if forbidden != required:
        errors.append("output contract must forbid finding, severity, and runtime-state promotion")
        return errors
    errors.extend(_claim_promotion_errors(value, forbidden))
    return errors


def _status_errors(attempt_root: Path, contract: dict[str, Any], envelope: dict[str, Any]) -> list[str]:
    required = contract.get("required_status_fields", [])
    if not required:
        return []
    try:
        status = read_json(attempt_root / "status.json")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"status.json cannot be read: {type(exc).__name__}"]
    if not isinstance(status, dict):
        return ["status.json must contain an object"]
    errors = []
    for field in required:
        if field not in status:
            errors.append(f"status.json is missing required field: {field}")
        elif status[field] is None or (isinstance(status[field], str) and not status[field]):
            errors.append(f"status.json required field is empty: {field}")
    if status.get("status") != envelope.get("execution_status"):
        errors.append("status.json status does not match the worker envelope")
    if "attempt_id" in status and status.get("attempt_id") != envelope.get("attempt_id"):
        errors.append("status.json attempt_id does not match the worker envelope")
    if "run_id" in status and status.get("run_id") != envelope.get("run_id"):
        errors.append("status.json run_id does not match the worker envelope")
    if "job" in status and status.get("job") != envelope.get("job_id"):
        errors.append("status.json job does not match the worker envelope")
    return errors


def _scorecard_payload_errors(attempt_root: Path, value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["Scorecard result must be an object"]
    try:
        inputs = read_json(attempt_root / "inputs.json")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"Scorecard inputs.json cannot be read: {type(exc).__name__}"]
    requested = inputs.get("source", {}).get("projects", []) if inputs.get("applicable") else []
    projects = value.get("projects", [])
    if not isinstance(projects, list) or len(projects) != len(requested):
        errors.append("OpenSSF Scorecard result count does not match requested projects")
        return errors
    published = 0
    missing = 0
    for index, (request, result) in enumerate(zip(requested, projects)):
        location = f"$.projects[{index}]"
        if not isinstance(result, dict) or result.get("repository") != request.get("repository"):
            errors.append(f"{location}: repository or result ordering mismatch")
            continue
        expected_url = "https://api.scorecard.dev/projects/" + request["repository"]
        if request.get("commit"):
            expected_url += "?" + urllib.parse.urlencode({"commit": request["commit"]})
        if result.get("request_url") != expected_url:
            errors.append(f"{location}.request_url: endpoint or requested commit mismatch")
        if result.get("requested_commit") != request.get("commit"):
            errors.append(f"{location}.requested_commit: does not match the staged request")
        if result.get("status") == "published":
            published += 1
            payload = result.get("result")
            repo = payload.get("repo") if isinstance(payload, dict) else None
            tool = payload.get("scorecard") if isinstance(payload, dict) else None
            checks = payload.get("checks") if isinstance(payload, dict) else None
            score = payload.get("score") if isinstance(payload, dict) else None
            if not isinstance(repo, dict) or repo.get("name") != request["repository"]:
                errors.append(f"{location}.result.repo: repository does not match request")
            commit = repo.get("commit") if isinstance(repo, dict) else None
            if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
                errors.append(f"{location}.result.repo.commit: invalid repository commit")
            elif request.get("commit") and commit.lower() != request["commit"]:
                errors.append(f"{location}.result.repo.commit: does not match pinned request")
            if not isinstance(tool, dict) or not isinstance(tool.get("version"), str):
                errors.append(f"{location}.result.scorecard: tool version provenance is missing")
            if (isinstance(score, bool) or not isinstance(score, (int, float)) or
                    not 0 <= score <= 10):
                errors.append(f"{location}.result.score: must be between 0 and 10")
            names: set[str] = set()
            if not isinstance(checks, list) or not checks:
                errors.append(f"{location}.result.checks: at least one check is required")
            else:
                for check_index, check in enumerate(checks):
                    name = check.get("name") if isinstance(check, dict) else None
                    check_score = check.get("score") if isinstance(check, dict) else None
                    if not isinstance(name, str) or not name:
                        errors.append(f"{location}.result.checks[{check_index}]: check name is missing")
                    elif name in names:
                        errors.append(f"{location}.result.checks[{check_index}]: duplicate check name")
                    else:
                        names.add(name)
                    if (isinstance(check_score, bool) or not isinstance(check_score, (int, float)) or
                            not -1 <= check_score <= 10):
                        errors.append(f"{location}.result.checks[{check_index}].score: invalid score")
            raw_name = result.get("raw_path")
            if not isinstance(raw_name, str) or not re.fullmatch(r"response-[0-9]{3}\.json", raw_name):
                errors.append(f"{location}.raw_path: invalid raw response path")
            else:
                raw = attempt_root / "outputs" / raw_name
                if not raw.is_file() or raw.is_symlink():
                    errors.append(f"{location}.raw_path: raw response is missing or linked")
                elif file_hash(raw) != result.get("raw_sha256"):
                    errors.append(f"{location}.raw_sha256: raw response hash mismatch")
            if result.get("http_status") != 200:
                errors.append(f"{location}.http_status: published result must be HTTP 200")
        elif result.get("status") == "not-published":
            missing += 1
            if result.get("http_status") != 404 or not isinstance(result.get("coverage_gap"), str):
                errors.append(f"{location}: not-published result must record HTTP 404 and a gap")
        else:
            errors.append(f"{location}.status: unsupported Scorecard result status")
    if value.get("published_count") != published or value.get("not_published_count") != missing:
        errors.append("OpenSSF Scorecard aggregate counts do not match project records")
    try:
        manifest = read_json(attempt_root / "manifest.json")
        if manifest.get("results_sha256") != file_hash(attempt_root / "outputs" / "scorecard-results.json"):
            errors.append("OpenSSF Scorecard manifest result hash mismatch")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"OpenSSF Scorecard manifest cannot be read: {type(exc).__name__}")
    return errors


def _partition_errors(value: Any, registry_root: Path, source_root: Path | None) -> list[str]:
    errors: list[str] = []
    partitions = value.get("partitions", []) if isinstance(value, dict) else []
    ids = [item.get("partition_id") for item in partitions if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        errors.append("repository partition IDs must be unique")
    known = set(ids)
    for index, partition in enumerate(partitions):
        if not isinstance(partition, dict):
            continue
        for field in ("include_paths", "exclude_paths"):
            for path_index, relative in enumerate(partition.get(field, [])):
                path_error = _repository_relative(relative)
                if path_error:
                    errors.append(f"$.partitions[{index}].{field}[{path_index}]: {path_error}")
        personas = [partition.get("primary_persona_id"), *partition.get("supporting_persona_ids", [])]
        if len(personas) != len(set(personas)):
            errors.append(f"$.partitions[{index}]: primary/supporting persona IDs must be unique")
        for persona in personas:
            if (not isinstance(persona, str) or
                    not (registry_root / "personas" / f"{persona}.json").is_file()):
                errors.append(f"$.partitions[{index}]: unknown registry persona ID")
        for relation_index, relationship in enumerate(partition.get("relationships", [])):
            if relationship.get("target_partition_id") not in known:
                errors.append(f"$.partitions[{index}].relationships[{relation_index}]: target ID does not resolve")
    coverage = value.get("coverage", {}) if isinstance(value, dict) else {}
    for field in ("inventory_scope", "unassigned_paths", "uninspected_scope"):
        for index, relative in enumerate(coverage.get(field, [])):
            path_error = _repository_relative(relative)
            if path_error:
                errors.append(f"$.coverage.{field}[{index}]: {path_error}")
    for check_index, check in enumerate(coverage.get("category_checks", [])):
        for path_index, relative in enumerate(check.get("search_scope", [])):
            path_error = _repository_relative(relative)
            if path_error:
                errors.append(f"$.coverage.category_checks[{check_index}].search_scope[{path_index}]: {path_error}")
    errors.extend(_citation_errors(value, source_root))
    return errors


def _project_discovery_errors(value: Any, source_root: Path | None) -> list[str]:
    errors: list[str] = []
    projects = value.get("projects", []) if isinstance(value, dict) else []
    ids = [item.get("project_id") for item in projects if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        errors.append("project discovery project IDs must be unique")
    known = set(ids)
    for index, project in enumerate(projects):
        if not isinstance(project, dict):
            continue
        root_error = _repository_relative(project.get("root"), allow_dot=True)
        if root_error:
            errors.append(f"$.projects[{index}].root: {root_error}")
        for field in ("manifests", "lockfiles"):
            for path_index, relative in enumerate(project.get(field, [])):
                path_error = _repository_relative(relative, exact=True)
                if path_error:
                    errors.append(f"$.projects[{index}].{field}[{path_index}]: {path_error}")
    for index, command in enumerate(value.get("safe_command_plan", []) if isinstance(value, dict) else []):
        if isinstance(command, dict) and command.get("project_id") not in known:
            errors.append(f"$.safe_command_plan[{index}].project_id: does not resolve to a project")
    errors.extend(_citation_errors(value, source_root))
    return errors


def _operations_topology_errors(value: Any, source_root: Path | None) -> list[str]:
    errors: list[str] = []
    services = value.get("services", []) if isinstance(value, dict) else []
    ids = [item.get("service_id") for item in services if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        errors.append("operations topology service IDs must be unique")
    known = set(ids)
    for index, service in enumerate(services):
        if not isinstance(service, dict):
            continue
        for dep_index, dependency in enumerate(service.get("dependencies", [])):
            if isinstance(dependency, dict) and dependency.get("target_service_id") not in known:
                errors.append(f"$.services[{index}].dependencies[{dep_index}].target_service_id: "
                               "does not resolve to a service")
    errors.extend(_citation_errors(value, source_root))
    return errors


# ---- ADR-0010 vendor-prepass contracts (V04, V07, V05) -----------------------------------------
#
# The nine family contracts have their own verifiers, and those verifiers deliberately take no
# optional safety input: every fact that decides the answer is a required argument that must come
# from OUTSIDE the attempt under validation. This section is the one place that says where each
# fact comes from (docs/contracts/validator-vendor-prepass-dispatch.md has the table). A fact with no
# authoritative source fails closed with a named error; it is never read from the attempt, an
# environment variable or a default, and the verifier is never skipped in favour of the generic
# schema check.

# publish_job_output.ACCEPTED_SCHEMA. That module imports this one, so the value is repeated here
# and tied to it by a test.
ACCEPTED_POINTER_SCHEMA = "appsec-review/accepted-worker-result/1.0"
# The validator is the CONSUMER of the redaction receipt, so the policy and bounds are its own.
REDACTION_POLICY = "refuse"
REDACTION_LIMITS = DEFAULT_LIMITS
_RUNTIME_ID_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,127}\Z")
_SNAPSHOT_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UPSTREAM_STATUSES = ("OK", "OK_WITH_GAPS")  # the SBOM and licence nodes are never SKIPPED


class _NoOrchestrationFacts:
    """The explicit "this caller has no orchestration facts" value. It is never a default of
    `validate_job_output`; with it every vendor-prepass contract fails closed."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "NO_ORCHESTRATION_FACTS"


NO_ORCHESTRATION_FACTS = _NoOrchestrationFacts()


@dataclass(frozen=True)
class OrchestrationFacts:
    """What only the publication boundary knows and the worker envelope does not carry.

    `dagster_run_id` is the orchestrator run that PRODUCED the attempt (on reuse: the producing
    run, not the run that is reusing it). `source_snapshot_sha256` is the intake source-snapshot
    identity the node ran against. `now` is the caller's clock: nothing below reads the wall
    clock. Every field is required."""

    dagster_run_id: str
    source_snapshot_sha256: str
    now: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.dagster_run_id, str) or not _RUNTIME_ID_RE.match(self.dagster_run_id):
            raise TypeError("dagster_run_id must be the orchestrator run id that produced the attempt")
        if (not isinstance(self.source_snapshot_sha256, str) or
                not _SNAPSHOT_RE.match(self.source_snapshot_sha256)):
            raise TypeError("source_snapshot_sha256 must be 'sha256:<64 lowercase hex>'")
        if not isinstance(self.now, datetime) or self.now.tzinfo is None:
            raise TypeError("now must be a timezone-aware datetime")


class BindingUnavailable(Exception):
    """A caller fact has no authoritative source yet. The message names what is missing."""


def vulnerability_database_bindings(run_root: Path) -> Mapping[str, Mapping[str, str]]:
    """The Grype DB and OSV snapshot identities `verify_sca_attempt` must be given.

    THE V18 SEAM. Task V18 (`BLOCKED(V16,V17)`) delivers the consumer bindings that resolve and
    re-verify both databases offline. Until it lands there is no authoritative identity, so this
    blocks; V18 replaces this body and nothing else. Never return an identity read from the
    attempt, the environment or a constant."""
    raise BindingUnavailable("no Grype DB / OSV consumer binding exists (V18)")


def lifecycle_reference_table_binding(run_root: Path) -> tuple[Path, Mapping[str, str]]:
    """(reference_table_path, expected_reference_table) for `verify_lifecycle_attempt`.

    No task has published the curated end-of-life table or a consumer binding for it, so this
    blocks. Whoever publishes the table replaces this body and nothing else."""
    raise BindingUnavailable("no dependency-lifecycle reference-table publisher or consumer binding exists")


def job_max_age(contract_id: str) -> Any:
    """ADR-0010 M4: no age limit by default; a JOB may set a tighter `max_age`, and exceeding it is
    FAILED. Nothing in the run inputs, the launch request or the registry carries a job-set limit
    today, so "no limit" is stated here explicitly. When such a setting exists it is read here."""
    return NO_AGE_LIMIT


def _node(**fields: Any) -> MappingProxyType:
    return MappingProxyType(fields)


def _vendor_prepass_nodes() -> MappingProxyType:
    v04, v05, v07 = _v04.CONTRACT_POLICIES, _v05.CONTRACT_POLICIES, _v07.CONTRACTS
    # `declared_tool_ids`: no job template or tooling profile registers these nodes' tools yet
    # (V10-V12 add them). Until then the ids are pinned here from the adopted ADR-0010 fixture
    # (docs/proposals/vendor-prepass/job-nodes.proposal.json); a test fails on any drift.
    tools = {
        "secrets-inventory": ("gitleaks", "key-material-file-inventory"),
        "iac-config-evidence": ("checkov", "trivy-config", "tfsec", "kube-linter", "hadolint",
                                "dockerfile-base-image-inventory"),
        "container-image-inventory": ("oci-archive-inventory", "image-package-and-config-inspection"),
        "mobile-sast": ("mobsfscan-android", "mobsfscan-ios"),
        "binary-hardening": ("binskim",),
        "sbom-inventory": ("syft-directory",),
        "sca-vulnerability-match": ("grype",),
        "license-inventory": ("scancode-toolkit",),
        "dependency-lifecycle": ("dependency-lifecycle-transform",),
    }
    nodes: dict[str, MappingProxyType] = {}
    for contract_id, policy in v04.items():
        nodes[contract_id] = _node(family="V04", job_id=policy["job_id"], result=policy["result_schema"][0],
                                   permitted_node_statuses=tuple(policy["permitted_node_statuses"]))
    for contract_id, policy in v07.items():
        # V07 exports no permitted-status table; ADR-0010 lets all three nodes skip, so the set is
        # every status a family node may have (V03). SKIPPED is still edge-authorized below.
        nodes[contract_id] = _node(family="V07", job_id=policy["job_id"], result=policy["result"],
                                   permitted_node_statuses=tuple(NODE_STATUSES))
    for contract_id, policy in v05.items():
        nodes[contract_id] = _node(family="V05", job_id=policy["job_id"], result=policy["result_schema"][0],
                                   permitted_node_statuses=tuple(_v05.NEVER_SKIPS))
    if set(nodes) != set(tools):
        raise RuntimeError("vendor-prepass node table and verifier policy tables disagree")
    return MappingProxyType({contract_id: _node(**node, declared_tool_ids=tools[contract_id])
                             for contract_id, node in nodes.items()})


VENDOR_PREPASS_NODES = _vendor_prepass_nodes()


def _vendor_prepass_claim_policies() -> dict[str, dict[str, Any]]:
    """Built from each module's exported policy table, never retyped -- except V07, whose module
    exports no claim-class table: its three entries are pinned here and a test ties them to the
    ADR fixture and the contract records."""
    policies = {contract_id: {"claim_class_id": policy["claim_class_id"],
                              "allowed_assertions": set(policy["allowed_assertions"])}
                for table in (_v04.CONTRACT_POLICIES, _v05.CONTRACT_POLICIES)
                for contract_id, policy in table.items()}
    policies.update({
        "container-image-inventory": {
            "claim_class_id": "supplied_image_static_evidence",
            "allowed_assertions": {"image-layer-package-inventory", "image-configuration-property",
                                   "image-hardening-rule-hit", "scan-coverage-gap"}},
        "mobile-sast": {
            "claim_class_id": "mobile_static_lead",
            "allowed_assertions": {"mobile-platform-marker-present", "mobile-rule-hit", "scan-coverage-gap"}},
        "binary-hardening": {
            "claim_class_id": "binary_hardening_property_evidence",
            "allowed_assertions": {"static-hardening-property-observed", "static-hardening-rule-hit",
                                   "binary-format-unsupported", "scan-coverage-gap"}},
    })
    return policies


CLAIM_CLASS_POLICIES.update(_vendor_prepass_claim_policies())


def _attempt_layout(attempt_root: Path, run_id: str, job_id: str) -> tuple[Path | None, Path | None, str | None]:
    """(run root, data/jobs/<job_id>, error). The attempt must sit at
    `<run>/data/jobs/<job_id>/<scope>/attempts/<attempt_id>` inside the run named `run_id`."""
    owner = _owning_run_root(attempt_root, run_id)
    if owner is None:
        return None, None, "cannot locate the owning run manifest"
    parents = attempt_root.parents
    if (len(parents) < 4 or attempt_root.parent.name != "attempts" or parents[2].name != job_id or
            parents[3] != owner / "data" / "jobs"):
        return None, None, (f"the attempt is not at data/jobs/{job_id}/<scope>/attempts/<attempt_id> "
                            "inside its run, so its tool outputs and upstream jobs cannot be located")
    try:
        beneath(owner, attempt_root)
    except ValueError:
        return None, None, "the attempt is reached through a linked directory of its run"
    return owner, parents[2], None


# THE ATTEMPT TREE IS CLOSED for the nine contracts. The publisher pins EVERY regular file of the
# attempt into accepted.json (`tree_hashes`), while the verifiers close the file set of `outputs/`
# only (manifest.json + the redaction receipt). So what may sit beside `outputs/` is stated here,
# and it is everything: a name that is not in this table is refused whatever the envelope lists.
#   entry          kind        who checks its content
#   status.json    file        the verifier (exact registered fields, each bound)
#   manifest.json  file        the verifier (names exactly the files beneath outputs/)
#   result.json    file        the envelope under validation (absent until the worker persists it)
#   outputs        directory   the verifier: manifest.json and the receipt close its file set,
#                              including the raw tool outputs a V07 contract retains there
# Nothing else: no `inputs.json`, no logs, no heartbeat or temporary file. The goldens of all three
# families hold exactly this; docs/contracts/validator-vendor-prepass-dispatch.md has the consequence for the
# common runtime's `allocate_attempt`.
ATTEMPT_ROOT_FILES = ("status.json", "manifest.json", "result.json")
ATTEMPT_ROOT_DIRECTORIES = ("outputs",)


def _entry_kind(entry: os.DirEntry) -> str:
    """"file", "directory" or "other" (a link, junction, reparse point, device, socket, fifo).
    No link is followed."""
    if entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction()):
        return "other"
    if getattr(entry.stat(follow_symlinks=False), "st_reparse_tag", 0):
        return "other"
    if entry.is_dir(follow_symlinks=False):
        return "directory"
    return "file" if entry.is_file(follow_symlinks=False) else "other"


def attempt_closure_errors(attempt_root: Path) -> list[str]:
    """Enumerate the attempt's directory entries (names and kinds only: no file is opened, no link
    followed) and refuse anything the table above does not allow. A name comes from the attempt,
    so messages carry counts, never names."""
    allowed = {**{name: "file" for name in ATTEMPT_ROOT_FILES},
               **{name: "directory" for name in ATTEMPT_ROOT_DIRECTORIES}}
    unlisted = other = empty = 0
    try:
        with os.scandir(attempt_root) as entries:
            pending = []
            for entry in entries:
                kind = _entry_kind(entry)
                if kind == "other":
                    other += 1
                elif allowed.get(entry.name) != kind:
                    unlisted += 1
                elif kind == "directory":
                    pending.append(entry.path)
        while pending:
            with os.scandir(pending.pop()) as entries:
                count = 0
                for entry in entries:
                    count += 1
                    kind = _entry_kind(entry)
                    if kind == "other":
                        other += 1
                    elif kind == "directory":
                        pending.append(entry.path)
                empty += count == 0
    except OSError as exc:
        return [f"attempt-not-closed: the attempt cannot be enumerated ({type(exc).__name__})"]
    expected = ", ".join(ATTEMPT_ROOT_FILES) + " and " + ", ".join(f"{name}/" for name in ATTEMPT_ROOT_DIRECTORIES)
    errors = []
    if unlisted:
        errors.append(f"attempt-not-closed: the attempt holds {unlisted} entr{'y' if unlisted == 1 else 'ies'} "
                      f"other than {expected}; every file of an accepted attempt is published, so none may "
                      "be unverified")
    if other:
        errors.append(f"attempt-not-closed: {other} entr{'y' if other == 1 else 'ies'} of the attempt "
                      "are links or special files")
    if empty:
        errors.append(f"attempt-not-closed: {empty} director{'y' if empty == 1 else 'ies'} of the attempt "
                      "hold nothing")
    return errors


def _accepted_upstream(attempt_root: Path, run_root: Path, run_id: str,
                       upstream_contract: str) -> tuple[Path | None, dict[str, str] | None, list[str]]:
    """The SAME run's accepted attempt of an upstream node: (attempt root, {attempt_id, sha256}).

    Both values come from the upstream job's `accepted.json`, which the publisher wrote outside the
    attempt after validating it -- never from the document under validation. The pointer is checked
    the way `publish_job_output.validate_published` checks one, minus what needs the upstream
    job's own staged inputs (its input fingerprint). Every path is contained in the RUN root, so a
    linked job, scope or attempt directory is refused: one spelling per file."""
    node = VENDOR_PREPASS_NODES[upstream_contract]
    job_id, artifact = node["job_id"], node["result"]
    base = attempt_root.parents[3] / job_id / attempt_root.parents[1].name

    def blocked(reason: str) -> tuple[None, None, list[str]]:
        return None, None, [f"upstream job {job_id} {reason}"]

    try:
        if not (base / "accepted.json").is_file():
            return blocked("has no accepted pointer in this run")
        pointer = read_json(beneath(run_root, base / "accepted.json"))
        latest = read_json(beneath(run_root, base / "latest.json"))
    except (OSError, ValueError, json.JSONDecodeError):
        return blocked("has no readable accepted pointer in this run")
    if not isinstance(pointer, dict) or pointer.get("schema") != ACCEPTED_POINTER_SCHEMA:
        return blocked("has no CURRENT accepted result (its newest attempt is pending, failed or legacy)")
    hashes = pointer.get("hashes")
    if (pointer.get("run_id") != run_id or pointer.get("job") != job_id or
            pointer.get("status") not in _UPSTREAM_STATUSES or not isinstance(hashes, dict)):
        return blocked(f"accepted pointer is not an {' or '.join(_UPSTREAM_STATUSES)} result of this run and job")
    try:
        attempt_id = identifier(pointer.get("attempt_id"))
        upstream = beneath(run_root, base / "attempts" / attempt_id)
        if not isinstance(latest, dict) or latest.get("attempt_id") != attempt_id:
            return blocked("accepted attempt is not its newest attempt")
        if not upstream.is_dir() or tree_hashes(upstream) != hashes:
            return blocked("accepted attempt changed after it was accepted")
        envelope_path = beneath(upstream, upstream / str(pointer.get("envelope_path", "")))
        if not envelope_path.is_file() or file_hash(envelope_path) != pointer.get("envelope_sha256"):
            return blocked("accepted worker-result envelope changed")
    except (OSError, ValueError):
        return blocked("accepted pointer does not resolve to an unlinked attempt of this run")
    digest_value = hashes.get(artifact)
    if not isinstance(digest_value, str) or not re.fullmatch(r"[0-9a-f]{64}", digest_value):
        return blocked(f"accepted pointer does not record {artifact}")
    return upstream, {"attempt_id": attempt_id, "sha256": "sha256:" + digest_value}, []


def validate_vendor_prepass_attempt(attempt_root: Path, contract: dict[str, Any], *, run_id: Any,
                                    job_id: Any, attempt_id: Any, node_status: Any,
                                    orchestration: Any) -> list[str]:
    """Assemble every caller fact from outside the attempt and run the contract's own verifier.

    Every argument is required. `run_id` and `job_id` are the caller's EXPECTED run and job,
    `attempt_id` the attempt directory's name (`validate_job_output` requires the worker envelope to
    restate all three and passes its own, never the envelope's); `node_status` is the envelope's
    `execution_status`, passed only when it is one of the closed `NODE_STATUSES`. The verifiers
    quote these as "what the caller expected", so none may be a free value of the attempt.
    `orchestration` is `OrchestrationFacts` or the explicit `NO_ORCHESTRATION_FACTS`.
    An empty list means the verifier ran and accepted the attempt. Anything that prevents the
    verifier from running is an error: there is no schema-only fallback. Messages quote only
    values the caller expected."""
    contract_id = contract.get("contract_id")
    node = VENDOR_PREPASS_NODES[contract_id]
    prefix = f"{contract_id} cannot be validated: "
    if orchestration is NO_ORCHESTRATION_FACTS:
        return [prefix + "the caller supplied NO_ORCHESTRATION_FACTS; the orchestrator run id and the "
                "source snapshot identity are never read from the attempt"]
    if not isinstance(orchestration, OrchestrationFacts):
        raise TypeError("orchestration must be OrchestrationFacts or NO_ORCHESTRATION_FACTS")
    for name, value in (("run_id", run_id), ("job_id", job_id), ("attempt_id", attempt_id),
                        ("execution_status", node_status)):
        if not isinstance(value, str) or not value:
            return [prefix + f"the caller and the worker envelope supply no usable {name}"]
    if job_id != node["job_id"]:
        return [prefix + f"the contract belongs to job {node['job_id']!r} and the envelope names another job"]
    attempt_root = Path(attempt_root).absolute()
    closure = attempt_closure_errors(attempt_root)
    if closure:
        return [f"{contract_id} {error}" for error in closure]
    declaration = _v04.contract_declaration_errors if node["family"] == "V04" else (
        _v05.contract_declaration_errors if node["family"] == "V05" else None)
    if declaration is not None:
        declared = declaration(contract)
        if declared:
            return [f"output contract record: {error}" for error in declared]
    owner, tool_outputs_root, layout_error = _attempt_layout(attempt_root, run_id, node["job_id"])
    if layout_error:
        return [prefix + layout_error]

    # Facts. Every problem is collected, so a caller sees all that is missing at once.
    problems: list[str] = []
    header = {"run_id": run_id, "job_id": node["job_id"], "attempt_id": attempt_id,
              "source_snapshot_sha256": orchestration.source_snapshot_sha256}
    common = {"node_status": node_status, "declared_tool_ids": list(node["declared_tool_ids"]),
              "permitted_node_statuses": list(node["permitted_node_statuses"]),
              "on_unhandled": REDACTION_POLICY, "limits": REDACTION_LIMITS,
              "expected_dagster_run_id": orchestration.dagster_run_id}
    source_root = None
    if contract_id in {"sbom-inventory", "license-inventory", "mobile-sast", "binary-hardening"}:
        source_root, source_errors = _source_root(attempt_root, run_id)
        problems += source_errors
    upstream: dict[str, tuple[Path | None, dict[str, str] | None]] = {}
    wanted = {"sca-vulnerability-match": ("sbom-inventory",), "license-inventory": ("sbom-inventory",),
              "dependency-lifecycle": ("sbom-inventory", "license-inventory")}.get(contract_id, ())
    for upstream_contract in wanted:
        root, expected, upstream_errors = _accepted_upstream(attempt_root, owner, run_id, upstream_contract)
        upstream[upstream_contract] = (root, expected)
        problems += upstream_errors
    databases = table = None
    try:
        if contract_id == "sca-vulnerability-match":
            databases = vulnerability_database_bindings(owner)
        elif contract_id == "dependency-lifecycle":
            table = lifecycle_reference_table_binding(owner)
    except BindingUnavailable as unavailable:
        problems.append(str(unavailable))
    if problems:
        return [prefix + problem for problem in problems]

    family = node["family"]
    try:
        if family == "V04":
            verifier = (_v04.validate_secrets_attempt if contract_id == _v04.SECRETS_CONTRACT_ID
                        else _v04.validate_iac_attempt)
            errors = verifier(attempt_root, tool_outputs_root=tool_outputs_root, **common)
        elif family == "V07":
            inputs_root = owner / "inputs" if contract_id == "container-image-inventory" else source_root
            errors = _v07.verify_attempt(contract_id, attempt_root, inputs_root, expected_header=header, **common)
        else:
            common.update(tool_outputs_root=tool_outputs_root, expected_header=header)
            sbom_root, expected_sbom = upstream.get("sbom-inventory", (None, None))
            if contract_id == _v05.SBOM_CONTRACT_ID:
                errors = _v05.verify_sbom_attempt(attempt_root, source_root=source_root, **common)
            elif contract_id == _v05.SCA_CONTRACT_ID:
                errors = _v05.verify_sca_attempt(
                    attempt_root, sbom_attempt_root=sbom_root, expected_sbom=expected_sbom,
                    expected_databases=databases, max_age=job_max_age(contract_id),
                    now=orchestration.now, **common)
            elif contract_id == _v05.LICENSE_CONTRACT_ID:
                errors = _v05.verify_license_attempt(
                    attempt_root, source_root=source_root, sbom_attempt_root=sbom_root,
                    expected_sbom=expected_sbom, **common)
            else:
                license_root, expected_license = upstream["license-inventory"]
                errors = _v05.verify_lifecycle_attempt(
                    attempt_root, sbom_attempt_root=sbom_root, expected_sbom=expected_sbom,
                    license_attempt_root=license_root, expected_license=expected_license,
                    reference_table_path=table[0], expected_reference_table=table[1],
                    max_age=job_max_age(contract_id), now=orchestration.now, **common)
    except (TypeError, ValueError) as refused:
        # A verifier raises when a CALLER fact is malformed. That is this module's problem, not the
        # attempt's, and it must not become an accepted attempt or an unhandled crash.
        return [prefix + f"the verifier refused its caller facts ({type(refused).__name__})"]
    if errors:
        return [f"{contract_id} verifier: {error}" for error in errors]

    # The verifier accepted the attempt, so the receipt holds and the result may be parsed. V04's
    # verifier takes no expected header: it proves the documents agree with EACH OTHER. Binding the
    # result's header to the caller's facts here closes that for all nine alike.
    try:
        value = read_json(beneath(attempt_root, attempt_root / Path(*PurePosixPath(node["result"]).parts)))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [prefix + f"the verified result cannot be read ({type(exc).__name__})"]
    return [f"{contract_id} result {field} is not the caller's expected {header[field]!r}"
            for field in HEADER_FIELDS if not isinstance(value, dict) or value.get(field) != header[field]]


def validate_contract_result(attempt_root: Path, contract: dict[str, Any], *,
                             run_id: str, registry_root: Path = REGISTRY,
                             schemas_root: Path = SCHEMAS) -> list[str]:
    """Validate only the one result artifact explicitly selected by an opted-in contract.

    For an ADR-0010 vendor-prepass contract this is the GENERIC layer only (schema, secret and
    claim-class checks over the result artifact). It parses that artifact without looking at the
    redaction receipt and knows none of the caller facts, so on its own it is not acceptance:
    `validate_job_output` runs `validate_vendor_prepass_attempt` first and reaches this function
    only when that verifier accepted the attempt."""
    declaration = contract.get("result_schema")
    if declaration is None:
        return []
    if not isinstance(declaration, dict):
        return ["output contract result_schema declaration must be an object"]
    artifact = declaration.get("artifact")
    relative, path_error = _relative_artifact_path(artifact)
    if path_error:
        return [f"output contract result artifact: {path_error}"]
    if artifact not in contract.get("required_files", []):
        return ["output contract result artifact must also be a required file"]
    schema_name = declaration.get("schema_file")
    if (not isinstance(schema_name, str) or PurePosixPath(schema_name).name != schema_name or
            "\\" in schema_name or not schema_name.endswith(".schema.json")):
        return ["output contract result schema must name one schemas/ file"]
    path = attempt_root / relative
    if not path.is_file() or path.is_symlink():
        return [f"declared result artifact is missing or linked: {artifact}"]
    if path.stat().st_size > MAX_RESULT_BYTES:
        return [f"declared result artifact exceeds {MAX_RESULT_BYTES} bytes"]
    try:
        value = read_json(path)
        schema_errors = validate_document(value, schema_name, SchemaStore(Path(schemas_root)))
    except (OSError, ValueError, json.JSONDecodeError, FileNotFoundError) as exc:
        return [f"declared result artifact/schema cannot be read: {type(exc).__name__}"]
    errors = [f"declared result schema: {error}" for error in schema_errors]
    errors.extend(_secret_errors(value))
    errors.extend(_claim_class_errors(contract, value))
    source_root = None
    if contract.get("contract_id") in {"repository-partition-map", "project-discovery"}:
        source_root, source_errors = _source_root(attempt_root, run_id)
        errors.extend(source_errors)
    dispatch = {
        "ossf-scorecard-results": lambda: _scorecard_payload_errors(attempt_root, value),
        "repository-partition-map": lambda: _partition_errors(value, Path(registry_root), source_root),
        "project-discovery": lambda: _project_discovery_errors(value, source_root),
    }
    validator = dispatch.get(contract.get("contract_id"))
    if validator is not None:
        errors.extend(validator())
    return errors


def _job_contract_errors(job_id: Any, contract_id: Any, graph: dict[str, Any], registry_root: Path) -> list[str]:
    """The envelope states both the job and the output contract, and the contract selects every
    check below -- so a producer that may choose it freely chooses its own validator. A
    `02-secrets-inventory` attempt publishing `verified_findings` was ACCEPTED by claiming
    `evidence-index` (no result schema, two dummy files). The contract a job publishes is therefore
    taken from what registers the job, never from the envelope: its job template's composition, its
    graph node, and the vendor-prepass node table. Every source that knows the job must name the
    claimed contract. A job no source knows (a synthetic or standalone preparation job) is left as
    it was. Only the expected value is quoted."""
    if not isinstance(job_id, str) or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]*", job_id):
        return []  # reported as a job identity error elsewhere
    expected: set[str] = set()
    template = Path(registry_root) / "job-templates" / f"{job_id}.json"
    if template.is_file():
        try:
            declared = read_json(template).get("composition", {}).get("output_contract_id")
        except (OSError, ValueError, AttributeError):
            return ["job template cannot be read to determine the job's output contract"]
        if isinstance(declared, str):
            expected.add(declared)
    node = graph.get("jobs", {}).get(job_id) if isinstance(graph, dict) else None
    if isinstance(node, dict) and isinstance(node.get("contract"), str):
        expected.add(node["contract"])
    expected.update(contract for contract, vendor in VENDOR_PREPASS_NODES.items() if vendor["job_id"] == job_id)
    if len(expected) > 1:
        return ["the registry, the graph and the vendor-prepass table disagree about this job's output contract"]
    if expected and contract_id not in expected:
        return [f"output contract is not the one this job publishes; expected {sorted(expected)[0]!r}"]
    return []


# The envelope IS the attempt's result.json: every value in it is the producer's. For a
# vendor-prepass job or contract no envelope value reaches a message; a location (the envelope
# schema is closed, so a location holds only its own property names and indexes) and the rule do.
_ENVELOPE_SCHEMA_RULES = (("missing required property", "required"), ("unexpected property", "additionalProperties"),
                          ("expected const", "const"), ("expected type", "type"), ("not in enum", "enum"),
                          ("does not match pattern", "pattern"))
_ENVELOPE_LOCATION_RE = re.compile(r"\$(?:\.[a-z_]{1,40}|\[[0-9]{1,9}\])*\Z")
# The cross-field messages of `worker_result.validate_worker_result` that interpolate nothing, or
# only a status the message's own condition drew from a closed set. A test derives this set from
# that function, so a new or reworded message cannot silently become the generic one.
_VALUE_FREE_ENVELOPE_DETAILS = frozenset({
    "SKIPPED requires an explicit edge-authorized reason", "only SKIPPED may declare a skip reason",
    *(f"{status} requires at least one explicit gap" for status in ("OK_WITH_GAPS", "UNRESOLVED")),
    *(f"{status} requires an explicit cause" for status in ("BLOCKED", "FAILED", "CANCELED", "UNRESOLVED")),
    *(f"{status} cannot declare a failure cause" for status in ("OK", "OK_WITH_GAPS")),
    *(f"{status} cannot be CURRENT" for status in ("BLOCKED", "FAILED", "CANCELED", "UNRESOLVED")),
    "SUPERSEDED requires the replacement attempt", "an attempt cannot supersede itself",
    "only SUPERSEDED may name a replacement attempt", "retryable results require a resume command",
    "non-retryable results cannot declare a resume command"})


def _envelope_errors_without_values(messages: list[str]) -> list[str]:
    quiet: list[str] = []
    for message in messages:
        location, _, detail = message.partition(": ")
        if not _ENVELOPE_LOCATION_RE.match(location):
            location = "$"
        rule = next((name for marker, name in _ENVELOPE_SCHEMA_RULES if marker in detail), None)
        if detail in _VALUE_FREE_ENVELOPE_DETAILS:
            text = detail
        elif rule is not None:
            text = f"violates worker-result-envelope.schema.json ({rule})"
        elif detail.endswith(" is not authorized for this dependency edge"):
            text = "the skip reason is not authorized for this dependency edge"
        else:
            text = "violates the worker-result state rules"
        if f"{location}: {text}" not in quiet:
            quiet.append(f"{location}: {text}")
    return quiet


def validate_job_output(attempt_root: Path, envelope: dict[str, Any],
                        expected_input_fingerprint: str,
                        expected_run_id: str | None = None,
                        expected_job_id: str | None = None,
                        registry_root: Path = REGISTRY, graph_path: Path = GRAPH,
                        consumer_job_id: str | None = None,
                        accepted_envelope: dict[str, Any] | None = None,
                        reuse: bool = False, schemas_root: Path = SCHEMAS, *,
                        orchestration: Any) -> list[str]:
    """`orchestration` is required and has no default: `OrchestrationFacts` when the caller knows
    the producing orchestrator run and source snapshot, else the explicit
    `NO_ORCHESTRATION_FACTS`, with which every vendor-prepass contract fails closed."""
    if orchestration is not NO_ORCHESTRATION_FACTS and not isinstance(orchestration, OrchestrationFacts):
        raise TypeError("orchestration must be OrchestrationFacts or NO_ORCHESTRATION_FACTS")
    errors: list[str] = []
    attempt_root = Path(attempt_root).absolute()
    if not attempt_root.is_dir():
        return [f"attempt root is not a directory: {attempt_root}"]
    try:
        beneath(attempt_root, attempt_root)
    except ValueError as exc:
        return [str(exc)]
    if expected_run_id is None or envelope.get("run_id") != expected_run_id:
        errors.append("run_id does not match the owning run")
    if expected_job_id is None or envelope.get("job_id") != expected_job_id:
        errors.append("job_id does not match the owning job")
    contract_id = envelope.get("output_contract")
    # `quiet`: the attempt belongs to a vendor-prepass job (the CALLER's expected job) or claims a
    # vendor-prepass contract. Then no value of the envelope is quoted below.
    quiet = (isinstance(contract_id, str) and contract_id in VENDOR_PREPASS_NODES) or any(
        node["job_id"] == expected_job_id for node in VENDOR_PREPASS_NODES.values())
    if not isinstance(contract_id, str) or not re.fullmatch(r"[0-9a-z][0-9a-z-]*", contract_id):
        errors.append("invalid output contract identity")
        contract = None
    else:
        contract_path = Path(registry_root) / "output-contracts" / f"{contract_id}.json"
        if not contract_path.is_file():
            errors.append("registry output contract does not exist" + ("" if quiet else f": {contract_id}"))
            contract = None
        else:
            contract = read_json(contract_path)
            errors.extend(f"output contract: {error}" for error in
                          validate_document(contract, "output-contract.schema.json"))
            if contract.get("contract_id") != contract_id:
                errors.append("registry output contract identity mismatch")
    graph = read_json(graph_path)
    errors.extend(_job_contract_errors(envelope.get("job_id"), contract_id, graph, Path(registry_root)))
    allowed_skips: set[str] | None = None
    if envelope.get("execution_status") == "SKIPPED":
        # A mismatch with the expected job is already an error above; the edge is the caller's.
        allowed_skips, edge_errors = _skip_reasons(
            graph, expected_job_id if quiet else envelope.get("job_id"), consumer_job_id)
        errors.extend(edge_errors)
    envelope_errors = validate_worker_result(envelope, allowed_skip_reasons=allowed_skips)
    errors.extend(_envelope_errors_without_values(envelope_errors) if quiet else envelope_errors)
    if envelope.get("input_fingerprint") != expected_input_fingerprint:
        errors.append("stale input fingerprint: envelope does not match the staged input fingerprint")
    if envelope.get("attempt_id") != attempt_root.name:
        errors.append("attempt_id does not match the owning attempt directory")
    artifacts = envelope.get("artifacts")
    artifact_paths: dict[str, dict[str, Any]] = {}
    if isinstance(artifacts, list):
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                continue
            value = artifact.get("path")
            relative, path_error = _relative_artifact_path(value)
            where = f"$.artifacts[{index}]"  # `quiet`: the index, never the path
            if path_error:
                errors.append(f"{where}.path: " + ("is not a normalized POSIX relative path" if quiet else path_error))
                continue
            if value in artifact_paths:
                errors.append(f"{where}.path: repeats an earlier artifact" if quiet else
                              f"duplicate artifact path: {value}")
                continue
            artifact_paths[value] = artifact
            try:
                path = beneath(attempt_root, attempt_root / relative)
            except ValueError as exc:
                errors.append(f"{where}.path: escapes the attempt or is reached through a link" if quiet else
                              f"artifact {value}: {exc}")
                continue
            if not path.is_file():
                errors.append(f"{where}.path: is missing or not a regular file" if quiet else
                              f"artifact is missing or not a regular file: {value}")
                continue
            actual = file_hash(path)
            if artifact.get("sha256") != actual:
                errors.append(f"{where}.sha256: is not the sha256 of the file" if quiet else
                              f"artifact hash mismatch: {value}")
            if not artifact.get("media_type"):
                errors.append(f"{where}.media_type: is empty" if quiet else
                              f"artifact media_type is empty: {value}")
    if contract:
        for required in contract.get("required_files", []):
            _, path_error = _relative_artifact_path(required)
            if path_error:
                errors.append(f"output contract has unsafe required file {required!r}")
            elif required not in artifact_paths:
                errors.append(f"required output is absent from the artifact manifest: {required}")
        # ORDER IS A SAFETY PROPERTY for the vendor-prepass contracts. Their verifier checks the
        # redaction receipt against the published bytes before it parses anything, so it runs
        # FIRST (after the attempt's entries were enumerated and found closed); if it (or the
        # assembly of its caller facts) reports anything, no file of the attempt is parsed here
        # at all: status.json and the result artifact stay unread. What is returned then is the
        # verifier's non-echoing errors plus the envelope errors above, which for these contracts
        # quote a location or an artifact index and never an envelope value (`quiet`).
        verifier_errors: list[str] = []
        if contract.get("contract_id") in VENDOR_PREPASS_NODES:
            # The verifiers quote what THE CALLER expected, so what they are given must be the
            # caller's: the expected run and job and the attempt directory's name, never the
            # envelope's restatement of them (a disagreement is already an error above). The
            # node status has no source but the envelope, so it is passed only when it is one of
            # the closed set of node statuses.
            status = envelope.get("execution_status")
            verifier_errors = validate_vendor_prepass_attempt(
                attempt_root, contract, run_id=expected_run_id, job_id=expected_job_id,
                attempt_id=attempt_root.name,
                node_status=status if isinstance(status, str) and status in NODE_STATUSES else None,
                orchestration=orchestration)
            errors.extend(verifier_errors)
        if not verifier_errors:
            errors.extend(_status_errors(attempt_root, contract, envelope))
            errors.extend(validate_contract_result(
                attempt_root, contract, run_id=envelope.get("run_id", ""),
                registry_root=Path(registry_root), schemas_root=Path(schemas_root)))
    if reuse:
        if accepted_envelope is None:
            errors.append("reuse validation requires the accepted envelope")
        else:
            errors.extend(validate_immutable_reuse(accepted_envelope, envelope))
    elif accepted_envelope is not None and accepted_envelope.get("attempt_id") == envelope.get("attempt_id"):
        errors.append("an existing attempt cannot be republished without explicit immutable-reuse validation")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempt-root", type=Path, required=True)
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--expected-input-fingerprint", required=True)
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--expected-job-id", required=True)
    parser.add_argument("--consumer-job")
    parser.add_argument("--accepted-envelope", type=Path)
    parser.add_argument("--reuse", action="store_true")
    parser.add_argument("--dagster-run-id",
                        help="orchestrator run that produced the attempt (vendor-prepass contracts)")
    parser.add_argument("--source-snapshot-sha256",
                        help="intake source snapshot identity, sha256:<hex> (vendor-prepass contracts)")
    args = parser.parse_args(argv)
    if (args.dagster_run_id is None) != (args.source_snapshot_sha256 is None):
        parser.error("--dagster-run-id and --source-snapshot-sha256 go together")
    # The command line is the edge where the wall clock is read; nothing below reads it.
    orchestration = NO_ORCHESTRATION_FACTS if args.dagster_run_id is None else OrchestrationFacts(
        dagster_run_id=args.dagster_run_id, source_snapshot_sha256=args.source_snapshot_sha256,
        now=datetime.now(timezone.utc))
    envelope = read_json(args.envelope)
    accepted = read_json(args.accepted_envelope) if args.accepted_envelope else None
    errors = validate_job_output(
        args.attempt_root, envelope, args.expected_input_fingerprint,
        expected_run_id=args.expected_run_id, expected_job_id=args.expected_job_id,
        consumer_job_id=args.consumer_job, accepted_envelope=accepted, reuse=args.reuse,
        orchestration=orchestration)
    print(json.dumps({"status": "PASS" if not errors else "FAIL", "errors": errors}, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
