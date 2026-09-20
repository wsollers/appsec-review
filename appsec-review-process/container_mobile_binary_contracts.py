#!/usr/bin/env python3
"""Cross-record rules for the container-image-inventory, mobile-sast and binary-hardening output
contracts (ADR-0010 decisions G6 = A, G7 = A, G8 = A, G9; task V07).

The three result schemas fix shapes. What ties a result to `tool-results.json`, `coverage.json`, the
applicability probe receipt, the redaction receipt and the bytes it cites cannot be written in the
JSON-Schema subset `schema_validate.py` supports, so it lives here, as two read-only functions:

    validate_result(contract_id, node_status, result, tool_results, coverage, probe_receipt,
                    declared_tool_ids, permitted_node_statuses) -> list[str]

    verify_attempt(contract_id, attempt_root, inputs_root, *, expected_header, node_status,
                   declared_tool_ids, permitted_node_statuses, on_unhandled, limits) -> list[str]

Every argument of both is required; none has a default. `declared_tool_ids`,
`permitted_node_statuses`, `node_status` and `expected_header` come from the node's registered
template, graph edge and worker envelope, never from the documents under validation: a document
cannot vouch for itself.

`validate_result` is pure. It COMPOSES V03's `tool_instance_shapes.validate_node_aggregate` (its
errors are returned unchanged) and adds the rules of this family. `verify_attempt` trusts no parsed
document: it re-reads every required file from the attempt's bytes, calls `validate_result`, V03's
`verify_outputs_on_disk` and V06's `evidence_redaction.verify_receipt`, and then re-derives the hash
and size of every image archive, supplied binary and cited source file from `inputs_root`.
`inputs_root` is the run's staged inputs root for container-image-inventory and the source snapshot
root for mobile-sast and binary-hardening.

Each returned string starts with a stable error name followed by `: `. An empty list means the
attempt satisfies the contract. Both functions return a fresh list and keep no state; a caller that
needs the answer again calls again. Nothing here publishes, redacts, repairs, pulls an image or
starts anything.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
import sys
from types import MappingProxyType
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from schema_validate import SchemaStore, validate_document  # noqa: E402
import tool_instance_shapes as shapes  # noqa: E402

REGISTRY_CONTRACTS = ROOT / "registry" / "output-contracts"
REDACTION_RECEIPT = "outputs/redaction-receipt.json"
TOOL_RESULTS = "outputs/tool-results.json"
COVERAGE = "outputs/coverage.json"
PUBLISHED_DIR = "outputs"
HEADER_FIELDS = shapes.HEADER_FIELDS
UNSUPPORTED_FORMAT_REASON = "unsupported-format"
BINSKIM_SARIF = "outputs/binskim.sarif"

# contract_id -> the facts this module needs. Read-only: a caller cannot widen a contract.
CONTRACTS: Mapping[str, Mapping[str, str]] = MappingProxyType({
    "container-image-inventory": MappingProxyType({
        "job_id": "02-container-image-inventory",
        "result": "outputs/container-image-inventory.json",
        "schema": "container-image-inventory.schema.json",
        "probe_receipt": "outputs/container-image-applicability.json",
        "records": "images",
    }),
    "mobile-sast": MappingProxyType({
        "job_id": "02-mobile-sast",
        "result": "outputs/mobile-sast.json",
        "schema": "mobile-sast.schema.json",
        "probe_receipt": "outputs/mobile-applicability.json",
        "records": "rule_hits",
    }),
    "binary-hardening": MappingProxyType({
        "job_id": "02-binary-hardening",
        "result": "outputs/binary-hardening.json",
        "schema": "binary-hardening.schema.json",
        "probe_receipt": "outputs/binary-hardening-applicability.json",
        "records": "binaries",
    }),
})

PLATFORMS = ("android", "ios")
ASSESSED_VERDICTS = ("present", "absent")
NOT_ASSESSED = "not-assessed"
NOT_APPLICABLE = "not-applicable-for-format"
# Which hardening checks exist for which binary format. A check outside its formats can only be
# not-applicable-for-format (or not-assessed); `unsupported` has no checks at all.
CHECK_FORMATS: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "position_independent": ("pe", "elf", "macho"),
    "non_executable_data": ("pe", "elf", "macho"),
    "stack_protector": ("pe", "elf", "macho"),
    "relro": ("elf",),
    "fortify_source": ("elf",),
    "control_flow_guard": ("pe",),
    "safe_seh": ("pe",),
    "high_entropy_aslr": ("pe",),
})


# Leading bytes that decide a binary's format. The listed `format` is re-derived from these.
FORMAT_MAGIC: Mapping[str, tuple[bytes, ...]] = MappingProxyType({
    "pe": (b"MZ",),
    "elf": (b"\x7fELF",),
    "macho": (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
              b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"),
})
_SAFE_NAME = re.compile(r"[A-Za-z0-9_.$-]{1,64}\Z")
_SCHEMA_RULES = (("missing required property", "required"), ("unexpected property", "additionalProperties"),
                 ("expected const", "const"), ("expected type", "type"), ("not in enum", "enum"),
                 ("does not match pattern", "pattern"), ("minItems", "minItems"))


def detect_format(data: bytes) -> str:
    """pe | elf | macho | unsupported, from the file's leading bytes."""
    for name, magics in FORMAT_MAGIC.items():
        if data.startswith(magics):
            return name
    return "unsupported"


def _safe_schema_errors(document: Any, schema_name: str, store: SchemaStore) -> list[str]:
    """Schema errors as location + violated keyword (+ the property name when it is a plain
    identifier). `schema_validate` echoes the offending VALUE, which for a rejected document may be
    exactly the matched line or environment value this contract exists to keep out of evidence."""
    errors = []
    for message in validate_document(document, schema_name, store):
        location, _, detail = message.partition(": ")
        rule = next((name for marker, name in _SCHEMA_RULES if marker in detail), "schema rule")
        if not re.fullmatch(r"\$[A-Za-z0-9_.\[\]-]*", location):
            location = "$"
        named = re.search(r"property '([^']*)'", detail) if rule in ("required", "additionalProperties") else None
        suffix = f" {named.group(1)!r}" if named and _SAFE_NAME.match(named.group(1)) else ""
        errors.append(f"schema:result: {location}: violates {schema_name} ({rule}{suffix})")
    return sorted(set(errors))


def _contract(contract_id: Any) -> Mapping[str, str]:
    if not isinstance(contract_id, str) or contract_id not in CONTRACTS:
        raise ValueError(f"contract_id must be one of {sorted(CONTRACTS)}, got {contract_id!r}")
    return CONTRACTS[contract_id]


def _nonneg(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _path_errors(name: str, label: str, path: str) -> list[str]:
    return [f"{name}: {label}: {error.replace('output path', 'path')}" for error in shapes.output_path_errors(path)]


def _duplicates(values: Iterable[Any]) -> list[Any]:
    seen, repeated = set(), []
    for value in values:
        if value in seen and value not in repeated:
            repeated.append(value)
        seen.add(value)
    return repeated


class _Aggregate:
    """Read-only views over the already-validated V03 documents."""

    def __init__(self, tool_results: dict, coverage: dict, probe_receipt: dict, declared: set[str]):
        self.declared = declared
        self.instances: dict[str, dict] = {}
        for instance in tool_results["tool_instances"]:
            self.instances.setdefault(instance["tool_id"], instance)
        self.coverage: dict[str, dict] = {}
        for tool in coverage["tools"]:
            self.coverage.setdefault(tool["tool_id"], tool)
        self.probe: dict[str, dict] = {}
        for tool in probe_receipt["tools"]:
            self.probe.setdefault(tool["tool_id"], tool)

    def tool_errors(self, tool_id: str, where: str) -> list[str]:
        if tool_id not in self.declared or tool_id not in self.instances:
            return [f"unknown-tool: {where} names tool {tool_id!r}, which is not a declared tool instance in tool-results.json"]
        return []

    def has_output(self, tool_id: str) -> bool:
        instance = self.instances.get(tool_id)
        return instance is not None and shapes.has_validated_output(instance)

    def listed(self, tool_id: str, field: str) -> dict[str, str]:
        tool = self.coverage.get(tool_id)
        return {} if tool is None else {entry["path"]: entry["reason_code"] for entry in tool[field]}

    def not_covered(self, tool_id: str) -> dict[str, str]:
        return {**self.listed(tool_id, "not_analyzed_inputs"), **self.listed(tool_id, "unsupported_inputs")}


def _complete_coverage_errors(agg: _Aggregate, record_paths: list[str], label: str) -> list[str]:
    """Container and binary results are per-input, so coverage must be the same set seen from the
    other side: every tool's candidates are exactly the records, and no list is truncated."""
    errors = []
    known = set(record_paths)
    for tool_id, tool in agg.coverage.items():
        if tool["input_lists_truncated"]:
            errors.append(
                f"coverage-list-truncated: tool {tool_id!r}: this contract needs every unsupported and "
                "not-analyzed input listed, so input_lists_truncated must be false"
            )
        if tool["candidate_input_count"] != len(record_paths):
            errors.append(
                f"coverage-record-mismatch: tool {tool_id!r} has candidate_input_count "
                f"{tool['candidate_input_count']} but the result lists {len(record_paths)} {label}"
            )
        for path in sorted(set(agg.not_covered(tool_id)) - known):
            errors.append(f"coverage-record-mismatch: tool {tool_id!r} lists {path!r}, which is not one of the result's {label}")
    return errors


# ---- container-image-inventory ---------------------------------------------------------------

def env_value_errors(result: Any) -> list[str]:
    """Named rejection of an environment VALUE, run on the raw document before (and regardless of)
    schema validation. A name holding '=', or any environment-shaped key other than
    `declared_env_names`, is a value trying to get published."""
    errors = []
    images = result.get("images") if isinstance(result, dict) else None
    for index, image in enumerate(images if isinstance(images, list) else []):
        config = image.get("config") if isinstance(image, dict) else None
        if not isinstance(config, dict):
            continue
        where = f"images[{index}].config"
        for key, value in config.items():
            lowered = key.lower()
            if key != "declared_env_names" and ("env" in lowered.split("_") or "environment" in lowered):
                errors.append(f"env-value-present: {where}.{key}: only declared_env_names may describe the environment")
        names = config.get("declared_env_names")
        for position, name in enumerate(names if isinstance(names, list) else []):
            if not isinstance(name, str) or "=" in name:
                errors.append(
                    f"env-value-present: {where}.declared_env_names[{position}] is not a bare variable name "
                    "(environment values are never recorded)"
                )
    return errors


def _container_errors(result: dict, agg: _Aggregate) -> list[str]:
    errors = []
    images = result["images"]
    for repeated in _duplicates(image["image_id"] for image in images):
        errors.append(f"duplicate-record: image_id {repeated!r} is used more than once")
    for repeated in _duplicates(image["source"]["archive_path"] for image in images):
        errors.append(f"duplicate-record: archive {repeated!r} is listed more than once")
    errors += _complete_coverage_errors(agg, [image["source"]["archive_path"] for image in images], "image archives")

    for image in images:
        where = f"image {image['image_id']!r}"
        path = image["source"]["archive_path"]
        errors += _path_errors("input-path", where, path)
        if not _nonneg(image["source"]["archive_bytes"]):
            errors.append(f"input-size: {where}: archive_bytes is negative")
        tool_errors = agg.tool_errors(image["tool_id"], where)
        errors += tool_errors
        if tool_errors:
            continue
        gap_reason = agg.not_covered(image["tool_id"]).get(path)
        unsupported_reason = agg.listed(image["tool_id"], "unsupported_inputs").get(path)
        inspected = image["inspection"] == "inspected"
        if image["archive_format"] == "unsupported" and unsupported_reason != UNSUPPORTED_FORMAT_REASON:
            errors.append(
                f"unsupported-format-not-in-coverage: {where}: archive_format is 'unsupported' but coverage.json "
                f"does not list {path!r} under unsupported_inputs with reason {UNSUPPORTED_FORMAT_REASON!r}"
            )
        if image["archive_format"] != "unsupported" and unsupported_reason == UNSUPPORTED_FORMAT_REASON:
            errors.append(
                f"unsupported-format-not-in-coverage: {where}: coverage.json lists {path!r} as "
                f"{UNSUPPORTED_FORMAT_REASON!r} but archive_format is {image['archive_format']!r}"
            )
        if inspected == (gap_reason is not None):
            errors.append(
                f"inspection-coverage-mismatch: {where}: inspection must be 'not-inspected' exactly when "
                f"coverage.json lists {path!r} as unsupported or not analyzed"
            )
        if image["archive_format"] == "unsupported" and inspected:
            errors.append(f"unsupported-format-inspected: {where}: an archive of an unsupported format cannot be 'inspected'")
        facts = (image["image_manifest_digest"], image["config"])
        if inspected:
            if None in facts or not image["layers"]:
                errors.append(f"inspected-image-incomplete: {where}: an inspected image needs its manifest digest, config and at least one layer")
            if not agg.has_output(image["tool_id"]):
                errors.append(f"result-from-tool-without-output: {where}: tool {image['tool_id']!r} has no validated, hashed output")
        elif facts != (None, None) or image["layers"] or image["packages"] or image["hardening_rule_hits"]:
            errors.append(
                f"not-inspected-image-with-facts: {where}: a not-inspected archive cannot carry a digest, "
                "config, layer, package or rule hit"
            )
        indexes = [layer["layer_index"] for layer in image["layers"]]
        if indexes != list(range(len(indexes))):
            errors.append(f"layer-index: {where}: layer_index values must be 0..n-1 in order")
        if any(not _nonneg(layer["layer_bytes"]) for layer in image["layers"]):
            errors.append(f"layer-index: {where}: a layer_bytes is negative")
        for kind, records in (("package", image["packages"]), ("hardening rule hit", image["hardening_rule_hits"])):
            for record in records:
                inner = f"{where} {kind} {record.get('name', record.get('rule_id'))!r}"
                found = agg.tool_errors(record["tool_id"], inner)
                errors += found
                if found:
                    continue
                if not agg.has_output(record["tool_id"]):
                    errors.append(f"result-from-tool-without-output: {inner}: tool {record['tool_id']!r} has no validated, hashed output")
                if path in agg.not_covered(record["tool_id"]):
                    errors.append(f"result-from-uncovered-input: {inner}: coverage.json says tool {record['tool_id']!r} did not analyze {path!r}")
        for package in image["packages"]:
            if package["layer_index"] not in indexes:
                errors.append(f"layer-index: {where}: package {package['name']!r} names layer {package['layer_index']}, which is not listed")
        config = image["config"]
        if config is None:
            continue
        for field in ("declared_entrypoint_argument_count", "declared_command_argument_count"):
            if not _nonneg(config[field]):
                errors.append(f"config-count: {where}: {field} is negative")
        for prefix in ("declared_entrypoint", "declared_command"):
            if config[f"{prefix}_executable"] is None and config[f"{prefix}_argument_count"] != 0:
                errors.append(f"config-count: {where}: {prefix}_argument_count must be 0 when {prefix}_executable is null")
        for repeated in _duplicates(config["declared_env_names"]):
            errors.append(f"duplicate-record: {where}: environment name {repeated!r} is listed more than once")
        for repeated in _duplicates((port["port"], port["protocol"]) for port in config["declared_ports"]):
            errors.append(f"duplicate-record: {where}: port {repeated[0]}/{repeated[1]} is listed more than once")
        for port in config["declared_ports"]:
            if not (_nonneg(port["port"]) and 1 <= port["port"] <= 65535):
                errors.append(f"port-range: {where}: declared port {port['port']!r} is not in 1..65535")
            if port["exposure_label"] != "DECLARED_EXPOSURE":
                errors.append(
                    f"observed-exposure: {where}: port {port['port']}/{port['protocol']} is labelled "
                    f"{port['exposure_label']!r}; an image archive can only show DECLARED_EXPOSURE"
                )
    return errors


# ---- mobile-sast -----------------------------------------------------------------------------

def _mobile_errors(result: dict, agg: _Aggregate, tool_results: dict) -> list[str]:
    errors = []
    platforms: dict[str, dict] = {}
    for entry in result["platforms"]:
        if entry["platform"] in platforms:
            errors.append(f"duplicate-record: platform {entry['platform']!r} is listed more than once")
        platforms.setdefault(entry["platform"], entry)
    for platform in PLATFORMS:
        if platform not in platforms:
            errors.append(f"platform-missing: the result has no entry for platform {platform!r}")
    for repeated in _duplicates(entry["tool_id"] for entry in platforms.values()):
        errors.append(f"duplicate-record: tool {repeated!r} is named by more than one platform")
    for platform, entry in platforms.items():
        found = agg.tool_errors(entry["tool_id"], f"platform {platform!r}")
        errors += found
        if found:
            continue
        probed = agg.probe.get(entry["tool_id"])
        if probed is None or probed["applicable"] != entry["marker_present"]:
            errors.append(
                f"marker-probe-mismatch: platform {platform!r}: marker_present {entry['marker_present']!r} differs "
                f"from the probe receipt's applicable flag for tool {entry['tool_id']!r} "
                f"({None if probed is None else probed['applicable']!r})"
            )

    hits = result["rule_hits"]
    for repeated in _duplicates(hit["hit_id"] for hit in hits):
        errors.append(f"duplicate-record: hit_id {repeated!r} is used more than once")
    counts: dict[str, int] = {}
    for hit in hits:
        where = f"rule hit {hit['hit_id']!r}"
        counts[hit["tool_id"]] = counts.get(hit["tool_id"], 0) + 1
        errors += _path_errors("input-path", where, hit["file_path"])
        if not (_nonneg(hit["line"]) and hit["line"] >= 1):
            errors.append(f"hit-line: {where}: line {hit['line']!r} is not a 1-based line number")
        found = agg.tool_errors(hit["tool_id"], where)
        errors += found
        if found:
            continue
        entry = platforms.get(hit["platform"])
        if entry is None or entry["tool_id"] != hit["tool_id"]:
            errors.append(f"hit-platform-mismatch: {where}: tool {hit['tool_id']!r} is not the tool of platform {hit['platform']!r}")
        elif not entry["marker_present"]:
            errors.append(f"hit-without-marker: {where}: platform {hit['platform']!r} has no platform marker, so its tool cannot have run")
        if not agg.has_output(hit["tool_id"]):
            errors.append(f"result-from-tool-without-output: {where}: tool {hit['tool_id']!r} has no validated, hashed output")
        if hit["file_path"] in agg.not_covered(hit["tool_id"]):
            errors.append(f"result-from-uncovered-input: {where}: coverage.json says tool {hit['tool_id']!r} did not analyze {hit['file_path']!r}")
    for instance in tool_results["tool_instances"]:
        tool_id = instance["tool_id"]
        if shapes.has_validated_output(instance) and instance["result_record_count"] != counts.get(tool_id, 0):
            errors.append(
                f"record-count-mismatch: tool {tool_id!r} reports result_record_count "
                f"{instance['result_record_count']} but the result attributes {counts.get(tool_id, 0)} rule hit(s) to it"
            )
    return errors


# ---- binary-hardening ------------------------------------------------------------------------

def _binary_errors(result: dict, agg: _Aggregate, tool_results: dict) -> list[str]:
    errors = []
    binaries = result["binaries"]
    for repeated in _duplicates(binary["binary_id"] for binary in binaries):
        errors.append(f"duplicate-record: binary_id {repeated!r} is used more than once")
    for repeated in _duplicates(binary["path"] for binary in binaries):
        errors.append(f"duplicate-record: binary {repeated!r} is listed more than once")
    errors += _complete_coverage_errors(agg, [binary["path"] for binary in binaries], "binaries")

    counts: dict[str, int] = {}
    for binary in binaries:
        where = f"binary {binary['binary_id']!r}"
        path, fmt, checks = binary["path"], binary["format"], binary["checks"]
        counts[binary["tool_id"]] = counts.get(binary["tool_id"], 0) + 1
        errors += _path_errors("input-path", where, path)
        if not _nonneg(binary["bytes"]):
            errors.append(f"input-size: {where}: bytes is negative")
        found = agg.tool_errors(binary["tool_id"], where)
        errors += found
        if found:
            continue
        assessed = sorted(name for name, verdict in checks.items() if verdict in ASSESSED_VERDICTS)
        all_not_assessed = all(verdict == NOT_ASSESSED for verdict in checks.values())
        gap_reason = agg.not_covered(binary["tool_id"]).get(path)
        unsupported_reason = agg.listed(binary["tool_id"], "unsupported_inputs").get(path)

        if fmt == "unsupported":
            if not all_not_assessed:
                errors.append(
                    f"unsupported-format-assessed: {where}: format is 'unsupported', so every check must be "
                    f"{NOT_ASSESSED!r}; got " + ", ".join(f"{name}={checks[name]}" for name in sorted(checks) if checks[name] != NOT_ASSESSED)
                )
            if unsupported_reason != UNSUPPORTED_FORMAT_REASON:
                errors.append(
                    f"unsupported-format-not-in-coverage: {where}: format is 'unsupported' but coverage.json does not "
                    f"list {path!r} under unsupported_inputs with reason {UNSUPPORTED_FORMAT_REASON!r}"
                )
        elif unsupported_reason == UNSUPPORTED_FORMAT_REASON and assessed:
            errors.append(
                f"unsupported-format-assessed: {where}: coverage.json says tool {binary['tool_id']!r} does not support "
                f"{path!r}, so no check can be present or absent; got {', '.join(assessed)}"
            )
        if all_not_assessed != (gap_reason is not None):
            errors.append(
                f"assessment-coverage-mismatch: {where}: every check must be {NOT_ASSESSED!r} exactly when "
                f"coverage.json lists {path!r} as unsupported or not analyzed"
            )
        if assessed and not agg.has_output(binary["tool_id"]):
            errors.append(f"result-from-tool-without-output: {where}: tool {binary['tool_id']!r} has no validated, hashed output")
        for name, verdict in sorted(checks.items()):
            exists = fmt in CHECK_FORMATS[name]
            if verdict in ASSESSED_VERDICTS and not exists:
                errors.append(f"check-format-mismatch: {where}: check {name!r} does not exist for format {fmt!r} and cannot be {verdict!r}")
            if verdict == NOT_APPLICABLE and (exists or fmt == "unsupported"):
                errors.append(f"check-format-mismatch: {where}: check {name!r} cannot be {NOT_APPLICABLE!r} for format {fmt!r}")
        if binary["rule_hits"] and all_not_assessed:
            errors.append(f"rule-hit-on-unassessed-binary: {where}: a binary with no assessed check cannot carry a rule hit")
        for hit in binary["rule_hits"]:
            if hit["check"] != "other" and checks[hit["check"]] not in ASSESSED_VERDICTS:
                errors.append(
                    f"rule-hit-on-unassessed-binary: {where}: rule {hit['rule_id']!r} names check {hit['check']!r}, "
                    f"which is {checks[hit['check']]!r}"
                )
    for instance in tool_results["tool_instances"]:
        tool_id = instance["tool_id"]
        if not shapes.has_validated_output(instance):
            continue
        if instance["result_record_count"] != counts.get(tool_id, 0):
            errors.append(
                f"record-count-mismatch: tool {tool_id!r} reports result_record_count "
                f"{instance['result_record_count']} but the result attributes {counts.get(tool_id, 0)} binaries to it"
            )
        sarif = [output for output in instance["outputs"] if output["path"] == BINSKIM_SARIF]
        if len(sarif) != 1 or sarif[0]["role"] != "raw-tool-output" or sarif[0]["validation"] != "format-validated":
            errors.append(
                f"raw-output-missing: tool {tool_id!r} produced output, so it must list {BINSKIM_SARIF!r} once as a "
                "format-validated raw-tool-output"
            )
    return errors


# ---- the pure entry point --------------------------------------------------------------------

def validate_result(
    contract_id: str,
    node_status: str,
    result: Any,
    tool_results: Any,
    coverage: Any,
    probe_receipt: Any,
    declared_tool_ids: Iterable[str],
    permitted_node_statuses: Iterable[str],
) -> list[str]:
    """Validate one node's result against its aggregate documents. See the module docstring.

    `probe_receipt=None` is a rejection, not a relaxation: all three nodes may be SKIPPED, so all
    three always publish a receipt. Structural failures are returned without cross-record rules,
    which only run over well-formed input."""
    contract = _contract(contract_id)
    if probe_receipt is None:
        return [
            f"probe-receipt-missing: contract {contract_id!r} requires the applicability probe receipt "
            f"{contract['probe_receipt']!r} for every node status, and none was supplied"
        ]
    declared_list = list(declared_tool_ids) if not isinstance(declared_tool_ids, (str, bytes)) else declared_tool_ids
    store = SchemaStore()
    if contract_id == "container-image-inventory":
        env_errors = env_value_errors(result)
        if env_errors:
            return env_errors  # named, and reported alone: no other message may describe the value
    errors = _safe_schema_errors(result, contract["schema"], store)
    aggregate_errors = shapes.validate_node_aggregate(
        node_status, tool_results, coverage, probe_receipt, declared_list, permitted_node_statuses, store=store
    )
    errors += aggregate_errors
    if any(error.startswith("schema:") for error in errors):
        return errors

    for field in HEADER_FIELDS:
        if result[field] != tool_results[field]:
            errors.append(f"header-mismatch: result.{field} {result[field]!r} differs from tool-results {tool_results[field]!r}")
    records = result[contract["records"]]
    if node_status == "SKIPPED" and records:
        errors.append(f"skipped-node-with-records: node is SKIPPED but the result lists {len(records)} {contract['records']}")

    agg = _Aggregate(tool_results, coverage, probe_receipt, set(declared_list))
    if contract_id == "container-image-inventory":
        errors += _container_errors(result, agg)
    elif contract_id == "mobile-sast":
        errors += _mobile_errors(result, agg, tool_results)
    else:
        errors += _binary_errors(result, agg, tool_results)
    return errors


# ---- the on-disk entry point -----------------------------------------------------------------

def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate object key")
    return dict(pairs)


def _read_document(attempt_root: Path, relative: str, max_bytes: int) -> tuple[Any, list[str]]:
    from execution_state import beneath  # local: keeps the pure validator import-light

    try:
        path = beneath(attempt_root, attempt_root / relative)
    except ValueError:
        return None, [f"required-file-missing: {relative!r} leaves the attempt or is a linked path"]
    if not path.is_file():
        return None, [f"required-file-missing: {relative!r} is not a regular file in the attempt"]
    if path.stat().st_size > max_bytes:
        return None, [f"required-file-unreadable: {relative!r} exceeds max_file_bytes {max_bytes}"]
    try:
        return json.loads(path.read_bytes().decode("utf-8"), object_pairs_hook=_reject_duplicate_keys), []
    except (OSError, ValueError):
        return None, [f"required-file-unreadable: {relative!r} is not UTF-8 JSON with unique object keys"]


def _cited_inputs(contract_id: str, result: dict) -> list[tuple]:
    """(label, path, sha256, bytes or None, line or None, format or None) for every cited input file."""
    if contract_id == "container-image-inventory":
        return [(f"image {image['image_id']!r}", image["source"]["archive_path"], image["source"]["archive_sha256"],
                 image["source"]["archive_bytes"], None, None) for image in result["images"]]
    if contract_id == "binary-hardening":
        return [(f"binary {binary['binary_id']!r}", binary["path"], binary["sha256"], binary["bytes"], None, binary["format"])
                for binary in result["binaries"]]
    return [(f"rule hit {hit['hit_id']!r}", hit["file_path"], hit["file_sha256"], None, hit["line"], None)
            for hit in result["rule_hits"]]


def _input_errors(contract_id: str, result: dict, inputs_root: Path) -> list[str]:
    import hashlib
    from execution_state import beneath

    if not inputs_root.is_dir():
        return [f"input-missing: inputs root {str(inputs_root)!r} is not a directory"]
    errors = []
    owners: dict[Any, str] = {}
    measured: dict[str, tuple[int, str, int, str]] = {}
    for label, relative, listed_hash, listed_bytes, line, listed_format in _cited_inputs(contract_id, result):
        if shapes.output_path_errors(relative):
            continue  # already reported by validate_result as input-path
        if relative not in measured:
            try:
                path = beneath(inputs_root, inputs_root / relative)
            except ValueError:
                errors.append(f"input-missing: {label}: {relative!r} leaves the inputs root or is a linked path")
                continue
            if not path.is_file():
                errors.append(f"input-missing: {label}: {relative!r} is not a regular file under the inputs root")
                continue
            # "The same file" is decided by the file, not the string (hard link, case-insensitive name).
            status = path.stat()
            identity = (status.st_dev, status.st_ino) if status.st_ino else os.path.normcase(str(path.resolve()))
            other = owners.setdefault(identity, relative)
            if other != relative:
                errors.append(f"input-alias: {label}: {relative!r} and {other!r} are the same file under two names")
                continue
            data = path.read_bytes()
            line_count = data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)
            measured[relative] = (len(data), "sha256:" + hashlib.sha256(data).hexdigest(), line_count,
                                  detect_format(data[:8]))
        size, actual_hash, line_count, actual_format = measured[relative]
        if listed_bytes is not None and size != listed_bytes:
            errors.append(f"input-size: {label}: {relative!r} is {size} bytes, listed as {listed_bytes}")
        if actual_hash != listed_hash:
            errors.append(f"input-hash-mismatch: {label}: {relative!r} does not have the listed sha256")
        elif listed_format is not None and listed_format != actual_format:
            errors.append(
                f"input-format-mismatch: {label}: {relative!r} is listed as format {listed_format!r} but its leading "
                f"bytes are {actual_format!r}"
            )
        elif line is not None and line > line_count:
            errors.append(f"hit-line: {label}: line {line} is beyond the {line_count} line(s) of {relative!r}")
    return errors


def verify_attempt(
    contract_id: str,
    attempt_root: Any,
    inputs_root: Any,
    *,
    expected_header: Mapping[str, str],
    node_status: str,
    declared_tool_ids: Iterable[str],
    permitted_node_statuses: Iterable[str],
    on_unhandled: str,
    limits: Any,
) -> list[str]:
    """Bind one published attempt to its contract, its own bytes and the inputs it cites.

    Every argument is required. Nothing parsed earlier is trusted: each required file of the
    registered contract is re-read from `attempt_root`. `expected_header` is the run_id, job_id,
    attempt_id and source_snapshot_sha256 from the worker envelope; every document must equal it.
    `on_unhandled` and `limits` are the redaction policy and bounds the CONSUMER demands and are
    passed straight to `evidence_redaction.verify_receipt`.
    """
    import evidence_redaction  # local: keeps validate_result import-light

    contract = _contract(contract_id)
    for name, root in (("attempt_root", attempt_root), ("inputs_root", inputs_root)):
        if root is None or isinstance(root, (bytes, bool)) or not str(root):
            raise TypeError(f"{name} must be a directory path")
    if not isinstance(expected_header, Mapping) or set(expected_header) != set(HEADER_FIELDS):
        raise TypeError(f"expected_header must map exactly {list(HEADER_FIELDS)}")
    if not isinstance(limits, evidence_redaction.Limits):
        raise TypeError("limits must be an evidence_redaction.Limits")
    attempt, inputs = Path(attempt_root).absolute(), Path(inputs_root).absolute()
    if not attempt.is_dir():
        return [f"required-file-missing: attempt root {str(attempt)!r} is not a directory"]
    if expected_header["job_id"] != contract["job_id"]:
        return [f"header-mismatch: expected job_id {expected_header['job_id']!r} is not {contract['job_id']!r}, the node of contract {contract_id!r}"]

    registered = json.loads((REGISTRY_CONTRACTS / f"{contract_id}.json").read_text(encoding="utf-8"))
    required = registered["required_files"]
    for relative in (contract["result"], contract["probe_receipt"], REDACTION_RECEIPT, TOOL_RESULTS, COVERAGE):
        if relative not in required:
            raise ValueError(f"registered contract {contract_id!r} does not require {relative!r}")

    errors: list[str] = []
    documents: dict[str, Any] = {}
    for relative in required:
        document, found = _read_document(attempt, relative, limits.max_file_bytes)
        if found and relative == contract["probe_receipt"]:
            found = [f"probe-receipt-missing: {found[0].split(': ', 1)[1]} (required for every node status, including SKIPPED)"]
        errors += found
        documents[relative] = document
    if errors:
        return errors

    result, tool_results = documents[contract["result"]], documents[TOOL_RESULTS]
    errors += validate_result(contract_id, node_status, result, tool_results, documents[COVERAGE],
                              documents[contract["probe_receipt"]], declared_tool_ids, permitted_node_statuses)
    if any(error.startswith(("schema:", "env-value-present", "probe-receipt-missing")) for error in errors):
        return errors
    for field in HEADER_FIELDS:
        if tool_results[field] != expected_header[field]:
            errors.append(
                f"header-mismatch: tool-results.{field} {tool_results[field]!r} differs from the worker envelope's "
                f"{expected_header[field]!r}"
            )
    errors += shapes.verify_outputs_on_disk(tool_results, attempt)
    try:
        evidence_redaction.verify_receipt(documents[REDACTION_RECEIPT], attempt / PUBLISHED_DIR,
                                          on_unhandled=on_unhandled, limits=limits)
    except evidence_redaction.ReceiptVerificationError as failure:
        errors += [f"redaction-receipt: {error}" for error in failure.errors]
    errors += _input_errors(contract_id, result, inputs)
    return errors
