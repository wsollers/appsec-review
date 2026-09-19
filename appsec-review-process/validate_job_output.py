#!/usr/bin/env python3
"""Validate a common worker envelope and its run-owned attempt artifacts without publishing."""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any
import urllib.parse

from execution_state import ROOT, beneath, file_hash, read_json
from schema_validate import SchemaStore, validate_document
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


def validate_contract_result(attempt_root: Path, contract: dict[str, Any], *,
                             run_id: str, registry_root: Path = REGISTRY,
                             schemas_root: Path = SCHEMAS) -> list[str]:
    """Validate only the one result artifact explicitly selected by an opted-in contract."""
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


def validate_job_output(attempt_root: Path, envelope: dict[str, Any],
                        expected_input_fingerprint: str,
                        expected_run_id: str | None = None,
                        expected_job_id: str | None = None,
                        registry_root: Path = REGISTRY, graph_path: Path = GRAPH,
                        consumer_job_id: str | None = None,
                        accepted_envelope: dict[str, Any] | None = None,
                        reuse: bool = False, schemas_root: Path = SCHEMAS) -> list[str]:
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
    if not isinstance(contract_id, str) or not re.fullmatch(r"[0-9a-z][0-9a-z-]*", contract_id):
        errors.append("invalid output contract identity")
        contract = None
    else:
        contract_path = Path(registry_root) / "output-contracts" / f"{contract_id}.json"
        if not contract_path.is_file():
            errors.append(f"registry output contract does not exist: {contract_id}")
            contract = None
        else:
            contract = read_json(contract_path)
            errors.extend(f"output contract: {error}" for error in
                          validate_document(contract, "output-contract.schema.json"))
            if contract.get("contract_id") != contract_id:
                errors.append("registry output contract identity mismatch")
    graph = read_json(graph_path)
    allowed_skips: set[str] | None = None
    if envelope.get("execution_status") == "SKIPPED":
        allowed_skips, edge_errors = _skip_reasons(
            graph, envelope.get("job_id"), consumer_job_id)
        errors.extend(edge_errors)
    errors.extend(validate_worker_result(envelope, allowed_skip_reasons=allowed_skips))
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
            if path_error:
                errors.append(f"$.artifacts[{index}].path: {path_error}")
                continue
            if value in artifact_paths:
                errors.append(f"duplicate artifact path: {value}")
                continue
            artifact_paths[value] = artifact
            try:
                path = beneath(attempt_root, attempt_root / relative)
            except ValueError as exc:
                errors.append(f"artifact {value}: {exc}")
                continue
            if not path.is_file():
                errors.append(f"artifact is missing or not a regular file: {value}")
                continue
            actual = file_hash(path)
            if artifact.get("sha256") != actual:
                errors.append(f"artifact hash mismatch: {value}")
            if not artifact.get("media_type"):
                errors.append(f"artifact media_type is empty: {value}")
    if contract:
        for required in contract.get("required_files", []):
            _, path_error = _relative_artifact_path(required)
            if path_error:
                errors.append(f"output contract has unsafe required file {required!r}")
            elif required not in artifact_paths:
                errors.append(f"required output is absent from the artifact manifest: {required}")
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
    args = parser.parse_args(argv)
    envelope = read_json(args.envelope)
    accepted = read_json(args.accepted_envelope) if args.accepted_envelope else None
    errors = validate_job_output(
        args.attempt_root, envelope, args.expected_input_fingerprint,
        expected_run_id=args.expected_run_id, expected_job_id=args.expected_job_id,
        consumer_job_id=args.consumer_job, accepted_envelope=accepted, reuse=args.reuse)
    print(json.dumps({"status": "PASS" if not errors else "FAIL", "errors": errors}, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
