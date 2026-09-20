#!/usr/bin/env python3
"""Cross-record rules for the `secrets-inventory` and `iac-config-evidence` contracts (ADR-0010, V04).

The two result schemas fix the shapes. What ties a result to the node's tool instances, to the
redaction receipt and to the bytes on disk cannot be written in the JSON-Schema subset
`schema_validate.py` supports, so it lives here as pure, read-only functions:

    contract_declaration_errors(contract) -> list[str]
    validate_secrets_attempt(attempt_root, *, tool_outputs_root, node_status, declared_tool_ids,
                             permitted_node_statuses, on_unhandled, limits) -> list[str]
    validate_iac_attempt(attempt_root, *, <the same keywords>) -> list[str]

Every argument is required and none has a default. `declared_tool_ids` and
`permitted_node_statuses` come from the node's registered template and graph edge,
`node_status` from the worker envelope, `on_unhandled` and `limits` are the redaction policy and
bounds the CONSUMER demands, and `tool_outputs_root` is the directory the `outputs[].path` values of
`tool-results.json` are relative to (`data/jobs/<node>/`). None of them is read from the documents
under validation: a document cannot vouch for itself.

This module composes and does not re-implement `tool_instance_shapes.validate_node_aggregate`,
`tool_instance_shapes.verify_outputs_on_disk` (V03) and `evidence_redaction.verify_receipt` (V06).

Order is part of the contract. The receipt is verified FIRST, and nothing else is looked at unless
it verifies: `verify_receipt` re-runs the redactor over every file in `outputs/` and demands a fixed
point, so from that step on every published document is known to hold nothing the redactor detects.
Only then are documents parsed and compared, and only then may a V03 message quote a value from
them. Messages written here name record ids, tool ids and field names; they never quote a path, an
address or any other document string, and never anything from `status.json`, which lies outside the
receipt.

The functions return error strings and nothing else. Each string starts with a stable error name
followed by `: `; an empty list means the attempt is consistent. There is deliberately no returned
summary, verdict record or parsed document: a caller that needs a fact re-derives it from the bytes.
Nothing here publishes, redacts, repairs or writes. Adoption by the workers and by
`validate_job_output.py` dispatch belongs to V10 and the integration owner.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from types import MappingProxyType
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from evidence_redaction import RECEIPT_FILENAME, Limits, POLICIES, ReceiptVerificationError, verify_receipt  # noqa: E402
from execution_state import beneath  # noqa: E402
from schema_validate import SchemaStore, validate_document  # noqa: E402
from tool_instance_shapes import (  # noqa: E402
    HEADER_FIELDS, RESULT_ROLES, VALIDATED, has_validated_output, output_path_errors,
    validate_node_aggregate, verify_outputs_on_disk,
)

SECRETS_CONTRACT_ID = "secrets-inventory"
IAC_CONTRACT_ID = "iac-config-evidence"

OUTPUTS_DIR = "outputs"
RECEIPT_FILE = f"{OUTPUTS_DIR}/{RECEIPT_FILENAME}"
TOOL_RESULTS_FILE = f"{OUTPUTS_DIR}/tool-results.json"
COVERAGE_FILE = f"{OUTPUTS_DIR}/coverage.json"
PROBE_RECEIPT_FILE = f"{OUTPUTS_DIR}/applicability-probe-receipt.json"
SECRETS_RESULT_FILE = f"{OUTPUTS_DIR}/secrets-inventory.redacted.json"
IAC_RESULT_FILE = f"{OUTPUTS_DIR}/iac-config-evidence.json"
BASE_IMAGE_FILE = f"{OUTPUTS_DIR}/base-image-inventory.json"

FORBIDDEN_PROMOTIONS = ("finding", "severity", "runtime-state")
NEVER_SKIPS = ("OK", "OK_WITH_GAPS", "BLOCKED", "FAILED", "CANCELED")
CAN_SKIP = ("OK", "OK_WITH_GAPS", "SKIPPED", "BLOCKED", "FAILED", "CANCELED")
EXPOSURE_CATEGORIES = ("network-exposure", "public-access-grant")
PUBLISHED_DISPOSITIONS = ("unchanged", "redacted")
STATUS_FIELDS = ("status", "run_id", "attempt_id")


def _policy(**fields: Any) -> MappingProxyType:
    return MappingProxyType(fields)


# What each contract file in the registry must declare. Pinned here because a contract file is
# data: a copy that dropped the receipt or a forbidden promotion must not weaken validation.
CONTRACT_POLICIES = MappingProxyType({
    SECRETS_CONTRACT_ID: _policy(
        job_id="02-secrets-inventory",
        required_files=("manifest.json", "status.json", SECRETS_RESULT_FILE, RECEIPT_FILE, TOOL_RESULTS_FILE,
                        COVERAGE_FILE),
        result_schema=(SECRETS_RESULT_FILE, "secrets-inventory.schema.json"),
        claim_class_id="secret_exposure_lead",
        allowed_assertions=("candidate-secret-location", "credential-store-file-present",
                            "private-key-header-present", "redaction-applied", "scan-coverage-gap"),
        permitted_node_statuses=NEVER_SKIPS,
        probe_receipt=False,
    ),
    IAC_CONTRACT_ID: _policy(
        job_id="02-iac-config-scan",
        required_files=("manifest.json", "status.json", IAC_RESULT_FILE, BASE_IMAGE_FILE, RECEIPT_FILE,
                        TOOL_RESULTS_FILE, COVERAGE_FILE, PROBE_RECEIPT_FILE),
        result_schema=(IAC_RESULT_FILE, "iac-config-evidence.schema.json"),
        claim_class_id="declared_configuration_evidence",
        allowed_assertions=("declared-configuration-rule-hit", "declared-base-image-reference",
                            "declared-exposure-lead", "scan-coverage-gap"),
        permitted_node_statuses=CAN_SKIP,
        probe_receipt=True,
    ),
})
BASE_IMAGE_SCHEMA = "iac-config-base-image-inventory.schema.json"

_SCHEMA_RULES = ("missing required property", "unexpected property", "expected type", "not in enum",
                 "does not match pattern", "expected const", "minItems")
_LOCATION_RE = re.compile(r"\$[A-Za-z0-9_.\[\]\-]*\Z")
_PROPERTY_RE = re.compile(r"(?:missing required|unexpected) property '([A-Za-z0-9_-]{1,64})'")


def contract_declaration_errors(contract: Any) -> list[str]:
    """The registry contract must declare exactly the pinned files, result schema and claim class."""
    if not isinstance(contract, dict):
        raise TypeError("contract must be the parsed output-contract object")
    errors = [f"contract-schema: {error}" for error in validate_document(contract, "output-contract.schema.json")]
    if errors:
        return errors
    policy = CONTRACT_POLICIES.get(contract["contract_id"])
    if policy is None:
        return [f"contract-unknown: {contract['contract_id']!r} is not a contract this module pins"]
    files = contract["required_files"]
    if len(files) != len(set(files)) or set(files) != set(policy["required_files"]):
        errors.append("contract-required-files: required_files must be exactly "
                      f"{sorted(policy['required_files'])}, each listed once")
    declared = contract.get("result_schema")
    if declared != {"artifact": policy["result_schema"][0], "schema_file": policy["result_schema"][1]}:
        errors.append("contract-result-schema: result_schema must name artifact "
                      f"{policy['result_schema'][0]!r} and schema_file {policy['result_schema'][1]!r}")
    if any(field not in contract["required_status_fields"] for field in STATUS_FIELDS):
        errors.append(f"contract-status-fields: required_status_fields must include {list(STATUS_FIELDS)}")
    claim = contract.get("claim_class")
    if not isinstance(claim, dict):
        return errors + ["contract-claim-class: claim_class must be declared"]
    if claim["claim_class_id"] != policy["claim_class_id"]:
        errors.append(f"contract-claim-class: claim_class_id must be {policy['claim_class_id']!r}")
    allowed = claim["allowed_assertions"]
    if len(allowed) != len(set(allowed)) or set(allowed) != set(policy["allowed_assertions"]):
        errors.append("contract-claim-class: allowed_assertions must be exactly "
                      f"{sorted(policy['allowed_assertions'])}, each listed once")
    forbidden = claim["forbidden_promotions"]
    if len(forbidden) != len(set(forbidden)) or set(forbidden) != set(FORBIDDEN_PROMOTIONS):
        errors.append(f"contract-forbidden-promotions: forbidden_promotions must be exactly {list(FORBIDDEN_PROMOTIONS)}, "
                      "each listed once")
    return errors


# ---- reading -----------------------------------------------------------------------------------

def _reject_constant(_name: str) -> Any:
    raise ValueError("non-standard JSON constant")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate object key")  # two parsers must never see two documents
    return result


def _read_bytes(attempt: Path, relative: str, limits: Limits) -> bytes | None:
    """The regular, non-linked file `relative` inside the attempt, or None."""
    try:
        path = beneath(attempt, attempt.joinpath(*relative.split("/")))
        if not path.is_file():
            return None
        with path.open("rb") as stream:
            data = stream.read(limits.max_file_bytes + 1)
    except (OSError, ValueError):
        return None
    return None if len(data) > limits.max_file_bytes else data


def _parse(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"), parse_constant=_reject_constant, object_pairs_hook=_unique_pairs)


def _schema_errors(label: str, document: Any, schema_name: str, store: SchemaStore) -> list[str]:
    """`schema_validate` echoes the offending value; keep only the location, the rule and, for a
    missing or unexpected property, its (bounded, identifier-shaped) name."""
    errors = []
    for message in validate_document(document, schema_name, store):
        location, _, detail = message.partition(": ")
        rule = next((rule for rule in _SCHEMA_RULES if rule in detail), "schema rule")
        named = _PROPERTY_RE.search(detail)
        if named:
            rule = f"{rule} '{named.group(1)}'"
        if not _LOCATION_RE.match(location):
            location = "$"
        errors.append(f"schema:{label}: {location}: violates {schema_name} ({rule})")
    return sorted(set(errors))


# ---- record rules --------------------------------------------------------------------------------

def _is_line(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _location_errors(record_id: str, location: dict, whole_file: bool) -> list[str]:
    errors = []
    path, start, end = location["path"], location["start_line"], location["end_line"]
    if (location["path_disposition"] == "published") != (path is not None):
        errors.append(f"location-path: {record_id}: path must be set exactly when path_disposition is 'published'")
    if path is not None and output_path_errors(path):
        errors.append(f"location-path: {record_id}: path is not a normalized repository-relative path "
                      "(no '.', '..', empty or leading-slash segments)")
    if whole_file:
        if start is not None or end is not None:
            errors.append(f"location-lines: {record_id}: a whole-file fact must have null start_line and end_line")
    elif not (_is_line(start) and _is_line(end) and start <= end):
        errors.append(f"location-lines: {record_id}: start_line and end_line must be integers with 1 <= start_line <= end_line")
    return errors


def _citation_errors(record_id: str, record: dict, job_id: str, instances: dict[str, dict]) -> list[str]:
    tool_id, citation = record["tool_id"], record["citation"]
    errors = []
    if citation["producer"] != job_id:
        errors.append(f"citation-producer: {record_id}: citation.producer must equal the document's job_id")
    instance = instances.get(tool_id)
    if instance is None:
        return errors + [f"tool-unresolved: {record_id}: tool {tool_id!r} has no tool instance in tool-results.json"]
    if not has_validated_output(instance):
        return errors + [f"tool-without-validated-output: {record_id}: tool {tool_id!r} ended "
                         f"{instance['terminal_status']} with no validated output, so it supports no record"]
    if citation["attempt_id"] != instance["attempt_id"]:
        errors.append(f"citation-attempt-mismatch: {record_id}: citation.attempt_id is not the attempt id of tool {tool_id!r}")
    listed = [output for output in instance["outputs"] if output["path"] == citation["path"]]
    if not listed:
        return errors + [f"citation-unresolved: {record_id}: citation.path is not an output listed for tool {tool_id!r}"]
    output = listed[0]
    if output["role"] not in RESULT_ROLES or output["validation"] not in VALIDATED:
        errors.append(f"citation-not-validated-output: {record_id}: the cited output of tool {tool_id!r} is not a validated result file")
    if "sha256:" + citation["sha256"] != output["sha256"]:
        errors.append(f"citation-hash-mismatch: {record_id}: citation.sha256 is not the sha256 tool-results.json lists for that output")
    return errors


def _ordinal_errors(label: str, prefix: str, ids: list[str]) -> list[str]:
    expected = [f"{prefix}-{index:06d}" for index in range(1, len(ids) + 1)]
    if ids != expected:
        return [f"record-id-order: {label} ids must be {prefix}-000001..{prefix}-{len(ids):06d} in document order"]
    return []


def _shared_record_errors(records: list[tuple[str, dict]], job_id: str, instances: dict[str, dict],
                          coverage: dict) -> list[str]:
    errors = []
    excluded: dict[str, set[str]] = {}
    for tool in coverage["tools"]:
        paths = excluded.setdefault(tool["tool_id"], set())
        for field in ("not_analyzed_inputs", "unsupported_inputs"):
            paths.update(entry["path"] for entry in tool[field])
    per_tool: dict[str, int] = {}
    for record_id, record in records:
        errors += _citation_errors(record_id, record, job_id, instances)
        per_tool[record["tool_id"]] = per_tool.get(record["tool_id"], 0) + 1
        path = record["location"]["path"]
        if path is not None and path in excluded.get(record["tool_id"], ()):
            errors.append(f"record-path-not-analyzed: {record_id}: coverage.json lists this path as not analyzed or "
                          f"unsupported for tool {record['tool_id']!r}")
    for tool_id, count in sorted(per_tool.items()):
        instance = instances.get(tool_id)
        reported = instance["result_record_count"] if instance is not None else None
        if isinstance(reported, int) and count > reported:
            errors.append(f"record-count-exceeds-tool: {count} records cite tool {tool_id!r}, whose result_record_count is {reported}")
    return errors


def _secrets_record_errors(result: dict) -> list[str]:
    errors = _ordinal_errors("entries", "SI", [entry["entry_id"] for entry in result["entries"]])
    seen = set()
    for entry in result["entries"]:
        entry_id, assertion, data_class = entry["entry_id"], entry["assertion"], entry["data_class"]
        whole_file = assertion == "credential-store-file-present"
        errors += _location_errors(entry_id, entry["location"], whole_file)
        if whole_file != (data_class == "key-store-file"):
            errors.append(f"entry-data-class: {entry_id}: data_class 'key-store-file' goes exactly with assertion "
                          "'credential-store-file-present'")
        if assertion == "private-key-header-present" and data_class != "private-key":
            errors.append(f"entry-data-class: {entry_id}: assertion 'private-key-header-present' requires data_class 'private-key'")
        location = entry["location"]
        key = (entry["tool_id"], entry["rule_id"], location["path"], location["start_line"], location["end_line"])
        if location["path"] is not None:
            if key in seen:
                errors.append(f"duplicate-record: {entry_id}: repeats the tool, rule, path and line span of an earlier entry")
            seen.add(key)
    return errors


def _address_ok(address: str) -> bool:
    return all(re.split(r"[./]", address))


def _iac_record_errors(result: dict, base: dict, instances: dict[str, dict], node_status: str) -> list[str]:
    hits, images = result["rule_hits"], base["base_images"]
    errors = _ordinal_errors("rule_hits", "IC", [hit["hit_id"] for hit in hits])
    errors += _ordinal_errors("base_images", "BI", [image["reference_id"] for image in images])
    if node_status == "SKIPPED" and (hits or images):
        errors.append("skipped-node-with-records: a SKIPPED node analyzed nothing and cannot publish rule hits or base images")
    seen = set()
    for hit in hits:
        hit_id, exposure, resource = hit["hit_id"], hit["exposure"], hit["resource"]
        errors += _location_errors(hit_id, hit["location"], whole_file=False)
        if exposure == "OBSERVED_EXPOSURE":
            errors.append(f"observed-exposure-forbidden: {hit_id}: static configuration supports DECLARED_EXPOSURE only; "
                          "OBSERVED_EXPOSURE is never producible by this node")
        lead = hit["assertion"] == "declared-exposure-lead"
        if lead != (exposure is not None):
            errors.append(f"exposure-assertion-mismatch: {hit_id}: exposure must be non-null exactly when the assertion is "
                          "'declared-exposure-lead'")
        if lead and hit["category"] not in EXPOSURE_CATEGORIES:
            errors.append(f"exposure-category: {hit_id}: a declared-exposure-lead needs category {list(EXPOSURE_CATEGORIES)}")
        instance = instances.get(hit["tool_id"])
        if instance is not None:
            packs = [{"kind": item["kind"], "identity_id": item["identity_id"], "sha256": item["sha256"]}
                     for item in instance["identity"]["data_identities"]]
            if hit["rule"]["rule_pack"] not in packs:
                errors.append(f"rule-pack-unresolved: {hit_id}: rule_pack is not a (kind, identity_id, sha256) data identity "
                              f"of tool {hit['tool_id']!r} in tool-results.json")
        disposition, address = resource["address_disposition"], resource["address"]
        if (disposition == "published") != (address is not None):
            errors.append(f"resource-address: {hit_id}: address must be set exactly when address_disposition is 'published'")
        if (disposition == "not-applicable") != (resource["iac_kind"] == "dockerfile"):
            errors.append(f"resource-address: {hit_id}: address_disposition 'not-applicable' goes exactly with iac_kind 'dockerfile'")
        if address is not None and not _address_ok(address):
            errors.append(f"resource-address: {hit_id}: address has an empty segment")
        location = hit["location"]
        key = (hit["tool_id"], hit["rule"]["rule_id"], address, location["path"], location["start_line"], location["end_line"])
        if location["path"] is not None and disposition != "withheld-unsafe-address":
            if key in seen:
                errors.append(f"duplicate-record: {hit_id}: repeats the tool, rule, address, path and line span of an earlier hit")
            seen.add(key)
    for image in images:
        reference_id = image["reference_id"]
        errors += _location_errors(reference_id, image["location"], whole_file=False)
        parts = (image["repository"], image["tag"], image["digest"])
        if image["reference_form"] == "literal":
            if image["repository"] is None:
                errors.append(f"base-image-form: {reference_id}: a literal reference needs its repository")
        elif any(part is not None for part in parts):
            errors.append(f"base-image-form: {reference_id}: only a literal reference may carry repository, tag or digest")
    return errors


# ---- the attempt ---------------------------------------------------------------------------------

def _check_arguments(attempt_root: Any, tool_outputs_root: Any, node_status: Any, declared_tool_ids: Any,
                     permitted_node_statuses: Any, on_unhandled: Any, limits: Any) -> None:
    for name, value in (("attempt_root", attempt_root), ("tool_outputs_root", tool_outputs_root)):
        if value is None or isinstance(value, (bytes, bool)) or not str(value):
            raise TypeError(f"{name} must be a directory path")
    if not isinstance(node_status, str):
        raise TypeError("node_status must be the worker envelope's terminal status string")
    for name, value in (("declared_tool_ids", declared_tool_ids), ("permitted_node_statuses", permitted_node_statuses)):
        if value is None or isinstance(value, (str, bytes)):
            raise TypeError(f"{name} must be a collection of strings, not a string or None")
    if on_unhandled not in POLICIES:
        raise TypeError("on_unhandled must be exactly 'refuse' or 'withhold'")
    if not isinstance(limits, Limits):
        raise TypeError("limits must be an evidence_redaction.Limits instance")


def _validate_attempt(contract_id: str, attempt_root: Any, tool_outputs_root: Any, node_status: str,
                      declared_tool_ids: Iterable[str], permitted_node_statuses: Iterable[str],
                      on_unhandled: str, limits: Limits) -> list[str]:
    _check_arguments(attempt_root, tool_outputs_root, node_status, declared_tool_ids, permitted_node_statuses,
                     on_unhandled, limits)
    policy = CONTRACT_POLICIES[contract_id]
    declared, permitted = list(declared_tool_ids), list(permitted_node_statuses)
    attempt = Path(attempt_root).absolute()
    if not attempt.is_dir():
        return ["attempt-root: attempt_root is not a directory"]
    store = SchemaStore()

    # 1. Every contract file is a regular, non-linked file. The receipt is named on its own.
    raw: dict[str, bytes] = {}
    errors = []
    for relative in policy["required_files"]:
        data = _read_bytes(attempt, relative, limits)
        if data is not None:
            raw[relative] = data
        elif relative == RECEIPT_FILE:
            errors.append(f"receipt-missing: {RECEIPT_FILE} is absent, linked, not a regular file or over max_file_bytes; "
                          "without a receipt the whole output is absent")
        else:
            errors.append(f"required-file-missing: {relative} is absent, linked, not a regular file or over max_file_bytes")
    if errors:
        return errors

    # 2. The receipt, verified against outputs/ BEFORE any other document is parsed.
    try:
        receipt = _parse(raw[RECEIPT_FILE])
    except (ValueError, RecursionError):
        return [f"receipt-invalid: {RECEIPT_FILE} is not strict UTF-8 JSON with unique keys"]
    try:
        verify_receipt(receipt, attempt / OUTPUTS_DIR, on_unhandled=on_unhandled, limits=limits)
    except ReceiptVerificationError as failure:
        return [f"receipt-invalid: {error}" for error in failure.errors]

    # 3. Each outputs/ contract file is published by that receipt, and the bytes read here are the
    #    bytes it verified.
    records = {record["path"]: record for record in receipt["files"]}
    documents: dict[str, Any] = {}
    for relative in policy["required_files"]:
        if not relative.startswith(OUTPUTS_DIR + "/") or relative == RECEIPT_FILE:
            continue
        record = records.get(relative[len(OUTPUTS_DIR) + 1:])
        if record is None or record["disposition"] not in PUBLISHED_DISPOSITIONS:
            errors.append(f"receipt-does-not-publish: the receipt does not list {relative} as unchanged or redacted")
            continue
        if hashlib.sha256(raw[relative]).hexdigest() != record["published_sha256"]:
            errors.append(f"receipt-hash-mismatch: {relative} does not have the receipt's published_sha256")
            continue
        try:
            documents[relative] = _parse(raw[relative])
        except (ValueError, RecursionError):
            errors.append(f"document-unreadable: {relative} is not strict UTF-8 JSON with unique keys")
    if errors:
        return errors

    # 4. Shapes. Structural failures are returned alone.
    result_file, result_schema = policy["result_schema"]
    errors += _schema_errors("result", documents[result_file], result_schema, store)
    if contract_id == IAC_CONTRACT_ID:
        errors += _schema_errors("base-image-inventory", documents[BASE_IMAGE_FILE], BASE_IMAGE_SCHEMA, store)
    if errors:
        return errors
    tool_results, coverage = documents[TOOL_RESULTS_FILE], documents[COVERAGE_FILE]
    probe = documents[PROBE_RECEIPT_FILE] if policy["probe_receipt"] else None
    aggregate = validate_node_aggregate(node_status, tool_results, coverage, probe, declared, permitted, store=store)
    errors += [f"aggregate: {error}" for error in aggregate]
    if any(error.startswith("schema:") for error in aggregate):
        return errors
    errors += [f"tool-outputs: {error}" for error in verify_outputs_on_disk(tool_results, tool_outputs_root)]

    # 5. What this contract adds.
    for status in sorted(set(permitted) - set(policy["permitted_node_statuses"])):
        errors.append(f"status-not-permitted-by-contract: contract {contract_id} never permits node status {status!r}")
    if tool_results["job_id"] != policy["job_id"]:
        errors.append(f"header-mismatch: tool-results.job_id must be {policy['job_id']!r} for contract {contract_id}")
    results = [(result_file, documents[result_file])]
    if contract_id == IAC_CONTRACT_ID:
        results.append((BASE_IMAGE_FILE, documents[BASE_IMAGE_FILE]))
    for relative, document in results:
        for field in HEADER_FIELDS:
            if document[field] != tool_results[field]:
                errors.append(f"header-mismatch: {relative} {field} differs from tool-results.json")
        if document["redactor"] != receipt["redactor"]:
            errors.append(f"redactor-mismatch: {relative} redactor block differs from the receipt's redactor identity")
    try:
        status = _parse(raw["status.json"])
    except (ValueError, RecursionError):
        status = None
    if not isinstance(status, dict):
        errors.append("status-mismatch: status.json is not a strict JSON object")
    else:
        expected = {"status": node_status, "run_id": tool_results["run_id"], "attempt_id": tool_results["attempt_id"]}
        for field in STATUS_FIELDS:
            if field not in status or status[field] != expected[field]:
                source = "the node_status argument" if field == "status" else "tool-results.json"
                errors.append(f"status-mismatch: status.json {field} must equal {source}")

    instances: dict[str, dict] = {}
    for instance in tool_results["tool_instances"]:
        instances.setdefault(instance["tool_id"], instance)
    for tool_id, instance in sorted(instances.items()):
        if not instance["outputs"]:
            continue
        redactor = instance["identity"]["redactor"]
        if (redactor is None or redactor["redactor_version"] != receipt["redactor"]["module_version"]
                or redactor["ruleset_sha256"] != "sha256:" + receipt["redactor"]["ruleset_sha256"]):
            errors.append(f"instance-redactor-mismatch: tool {tool_id!r} lists outputs, so its identity.redactor must carry "
                          "the receipt's module_version and ruleset_sha256")

    if contract_id == SECRETS_CONTRACT_ID:
        result = documents[result_file]
        errors += _secrets_record_errors(result)
        listed = [(entry["entry_id"], entry) for entry in result["entries"]]
    else:
        result, base = documents[result_file], documents[BASE_IMAGE_FILE]
        errors += _iac_record_errors(result, base, instances, node_status)
        listed = ([(hit["hit_id"], hit) for hit in result["rule_hits"]]
                  + [(image["reference_id"], image) for image in base["base_images"]])
    errors += _shared_record_errors(listed, policy["job_id"], instances, coverage)
    return errors


def validate_secrets_attempt(attempt_root: Any, *, tool_outputs_root: Any, node_status: str,
                             declared_tool_ids: Iterable[str], permitted_node_statuses: Iterable[str],
                             on_unhandled: str, limits: Limits) -> list[str]:
    """Validate one `02-secrets-inventory` attempt directory against contract `secrets-inventory`."""
    return _validate_attempt(SECRETS_CONTRACT_ID, attempt_root, tool_outputs_root, node_status, declared_tool_ids,
                             permitted_node_statuses, on_unhandled, limits)


def validate_iac_attempt(attempt_root: Any, *, tool_outputs_root: Any, node_status: str,
                         declared_tool_ids: Iterable[str], permitted_node_statuses: Iterable[str],
                         on_unhandled: str, limits: Limits) -> list[str]:
    """Validate one `02-iac-config-scan` attempt directory against contract `iac-config-evidence`."""
    return _validate_attempt(IAC_CONTRACT_ID, attempt_root, tool_outputs_root, node_status, declared_tool_ids,
                             permitted_node_statuses, on_unhandled, limits)
