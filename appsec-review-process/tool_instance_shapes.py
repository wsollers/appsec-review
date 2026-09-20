#!/usr/bin/env python3
"""Cross-record rules for a family node's tool-instance aggregate (ADR-0010, task V03).

`schemas/tool-results.schema.json`, `schemas/scan-coverage.schema.json` and
`schemas/applicability-probe-receipt.schema.json` fix the three shapes. The rules that tie them to
each other and to the node's terminal status cannot be written in the JSON-Schema subset
`schema_validate.py` supports, so they live here as one pure, read-only function.

    validate_node_aggregate(node_status, tool_results, coverage, probe_receipt,
                            declared_tool_ids, permitted_node_statuses) -> list[str]

Every argument is required. `declared_tool_ids` and `permitted_node_statuses` come from the node's
registered template and graph edge, never from the documents under validation: a document cannot
vouch for its own completeness, and a failed tool that was simply left out of `tool-results.json`
must still be noticed. `probe_receipt` may be passed as an explicit `None` only for a node that
cannot skip; `None` never relaxes a rule, it forbids every SKIPPED node and tool instance.

Each returned string starts with a stable error name followed by `: `. An empty list means the
aggregate is consistent. Nothing here publishes, redacts, repairs or reads the filesystem beyond
loading the schemas; adoption by workers and by `validate_job_output.py` belongs to V10-V13.
"""
from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from schema_validate import SchemaStore, validate_document  # noqa: E402

TOOL_RESULTS_SCHEMA = "tool-results.schema.json"
COVERAGE_SCHEMA = "scan-coverage.schema.json"
PROBE_RECEIPT_SCHEMA = "applicability-probe-receipt.schema.json"

SKIP_REASON = "not-applicable-no-matching-inputs"

# ADR-0010: "UNRESOLVED is not used: these nodes answer no contracted question."
NODE_STATUSES = ("OK", "OK_WITH_GAPS", "SKIPPED", "BLOCKED", "FAILED", "CANCELED")
NODE_SUCCESS_STATUSES = ("OK", "OK_WITH_GAPS", "SKIPPED")
INSTANCE_OUTPUT_STATUSES = ("OK", "OK_WITH_GAPS")

# A non-OK tool instance that ran (or should have run) is reported under exactly this gap kind.
INSTANCE_GAP_KIND = {
    "FAILED": "tool-instance-failed",
    "BLOCKED": "tool-instance-blocked",
    "CANCELED": "tool-instance-canceled",
    "UNRESOLVED": "tool-instance-unresolved",
    "OK_WITH_GAPS": "tool-instance-partial",
}
GAP_KIND_INSTANCE = {kind: status for status, kind in INSTANCE_GAP_KIND.items()}

RESULT_ROLES = ("normalized-result", "raw-tool-output", "analysis-substrate")
VALIDATED = ("schema-validated", "format-validated")
HEADER_FIELDS = ("run_id", "job_id", "attempt_id", "source_snapshot_sha256")

# exit_meaning values each instance terminal status may carry.
STATUS_EXIT_MEANINGS = {
    "OK": ("clean", "findings-present"),
    "OK_WITH_GAPS": ("clean", "findings-present"),
    "SKIPPED": ("not-started",),
    "BLOCKED": ("not-started",),
    "FAILED": ("tool-error", "timeout", "killed", "clean", "findings-present"),
    "CANCELED": ("canceled", "not-started"),
    "UNRESOLVED": ("clean", "findings-present", "tool-error"),
}

# cause_code values each instance terminal status may carry (None = must be null).
STATUS_CAUSES = {
    "OK": (None,),
    "SKIPPED": (None,),
    "OK_WITH_GAPS": ("partial-input-coverage",),
    "BLOCKED": ("image-unavailable", "identity-unverified", "offline-operation-unavailable", "required-input-missing"),
    "FAILED": ("tool-error", "timeout", "killed", "output-invalid"),
    "CANCELED": ("canceled",),
    "UNRESOLVED": ("tool-error", "output-invalid"),
}
# A cause that restates the exit must agree with it.
CAUSE_EXIT_MEANING = {"tool-error": "tool-error", "timeout": "timeout", "killed": "killed"}


def has_validated_output(instance: dict) -> bool:
    """True when the instance ended OK/OK_WITH_GAPS and carries a hashed, validated result file."""
    if instance.get("terminal_status") not in INSTANCE_OUTPUT_STATUSES:
        return False
    return any(
        output.get("role") in RESULT_ROLES and output.get("validation") in VALIDATED
        for output in instance.get("outputs", [])
    )


def supportable_success_status(tool_results: dict, coverage: dict) -> str | None:
    """The one success status the documents can support, or None when only BLOCKED / FAILED /
    CANCELED are honest. `validate_node_aggregate` accepts a success status if and only if it
    equals this value (pinned by a test over every status combination)."""
    instances = tool_results["tool_instances"]
    ran = [inst for inst in instances if inst["terminal_status"] != "SKIPPED"]
    if not ran:
        return "SKIPPED"
    if all(inst["terminal_status"] == "OK" for inst in ran) and not coverage["gaps"]:
        return "OK"
    if any(has_validated_output(inst) for inst in ran) and coverage["gaps"]:
        return "OK_WITH_GAPS"
    return None


def _nonneg(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _id_set_errors(label: str, ids: list[str], declared: set[str]) -> list[str]:
    errors = []
    seen: set[str] = set()
    for tool_id in ids:
        if tool_id in seen:
            errors.append(f"duplicate-tool: {label} lists tool {tool_id!r} more than once")
        seen.add(tool_id)
    for tool_id in sorted(declared - seen):
        errors.append(f"declared-tool-missing: {label} has no entry for declared tool {tool_id!r}")
    for tool_id in sorted(seen - declared):
        errors.append(f"undeclared-tool: {label} names tool {tool_id!r}, which the node does not declare")
    return errors


def _identity_errors(tool_id: str, instance: dict) -> list[str]:
    errors = []
    identity = instance["identity"]
    image = (identity["image_repository"], identity["image_digest"])
    if identity["executor_kind"] == "pinned_container":
        if None in image or identity["executable_sha256"] is not None:
            errors.append(
                f"instance-identity: {tool_id}: a pinned_container instance needs image_repository and "
                "image_digest, and a null executable_sha256"
            )
    else:
        if image != (None, None) or identity["executable_sha256"] is None:
            errors.append(
                f"instance-identity: {tool_id}: a deterministic_python instance needs executable_sha256, "
                "and null image_repository and image_digest"
            )
    if instance["terminal_status"] in INSTANCE_OUTPUT_STATUSES and identity["tool_version"] is None:
        errors.append(
            f"instance-identity: {tool_id}: status {instance['terminal_status']} needs the tool-reported version"
        )
    keys = [(item["kind"], item["identity_id"]) for item in identity["data_identities"]]
    if len(keys) != len(set(keys)):
        errors.append(f"instance-identity: {tool_id}: data_identities repeats a (kind, identity_id) pair")
    return errors


def _exit_errors(tool_id: str, instance: dict) -> list[str]:
    errors = []
    status = instance["terminal_status"]
    exit_block = instance["exit"]
    code = exit_block["exit_code"]
    meaning = exit_block["exit_meaning"]
    findings_codes = exit_block["findings_exit_codes"]

    if meaning not in STATUS_EXIT_MEANINGS[status]:
        errors.append(f"instance-exit: {tool_id}: status {status} cannot carry exit_meaning {meaning!r}")
    if exit_block["timed_out"] != (meaning == "timeout"):
        errors.append(f"instance-exit: {tool_id}: timed_out must be true exactly when exit_meaning is 'timeout'")
    if exit_block["nonzero_exit_on_findings"] != bool(findings_codes):
        errors.append(
            f"instance-exit: {tool_id}: nonzero_exit_on_findings must be true exactly when "
            "findings_exit_codes is non-empty"
        )
    if 0 in findings_codes or len(findings_codes) != len(set(findings_codes)):
        errors.append(f"instance-exit: {tool_id}: findings_exit_codes must be distinct non-zero codes")

    if meaning == "not-started":
        if code is not None:
            errors.append(f"instance-exit: {tool_id}: a process that never started has no exit_code")
    elif meaning == "clean":
        if code != 0:
            errors.append(f"instance-exit: {tool_id}: exit_meaning 'clean' requires exit_code 0, got {code!r}")
    elif meaning == "findings-present":
        expected = code in findings_codes if findings_codes else code == 0
        if not expected:
            errors.append(
                f"instance-exit: {tool_id}: exit_code {code!r} does not mean 'findings-present' for this tool "
                f"(findings_exit_codes {findings_codes})"
            )
    elif meaning == "tool-error":
        if code is None or code == 0 or code in findings_codes:
            errors.append(
                f"instance-exit: {tool_id}: exit_meaning 'tool-error' requires a non-zero exit_code outside "
                f"findings_exit_codes, got {code!r}"
            )
    return errors


def output_path_errors(path: str) -> list[str]:
    """An output path is ONE spelling of one file: relative, '/'-separated, with no '.', '..' or
    empty segment. Aliases such as `a/./b`, `a//b`, `a/x/../b` and `./a/b` all reach the same file
    as `a/b`; allowing them would let two records name one file without looking alike."""
    segments = path.split("/")
    if ".." in segments:
        return [f"output path {path!r} leaves the attempt"]
    if path.startswith("/") or any(segment in ("", ".") for segment in segments):
        return [f"output path {path!r} is not normalized (no '.', empty or leading-slash segments)"]
    return []


def _output_errors(tool_id: str, instance: dict) -> list[str]:
    errors = []
    status = instance["terminal_status"]
    outputs = instance["outputs"]
    paths = [output["path"] for output in outputs]
    if len(paths) != len(set(paths)):
        errors.append(f"instance-output: {tool_id}: two outputs share one path")
    for output in outputs:
        errors.extend(f"instance-output: {tool_id}: {error}" for error in output_path_errors(output["path"]))
        if not _nonneg(output["bytes"]):
            errors.append(f"instance-output: {tool_id}: output {output['path']!r} has a negative byte count")
        if (output["validation"] in VALIDATED) != (output["validated_against"] is not None):
            errors.append(
                f"instance-output: {tool_id}: output {output['path']!r} must name validated_against exactly "
                "when its validation is schema-validated or format-validated"
            )
    if status in INSTANCE_OUTPUT_STATUSES and not has_validated_output(instance):
        errors.append(f"instance-output: {tool_id}: status {status} needs at least one validated, hashed result output")
    if status in INSTANCE_OUTPUT_STATUSES:
        if not _nonneg(instance["result_record_count"]):
            errors.append(f"instance-count: {tool_id}: status {status} needs a non-negative result_record_count")
    elif instance["result_record_count"] is not None:
        errors.append(f"instance-count: {tool_id}: status {status} cannot carry a result_record_count")
    if status in ("SKIPPED", "BLOCKED") and outputs:
        errors.append(f"instance-output: {tool_id}: a {status} instance never ran and cannot list outputs")
    return errors


def _instance_errors(tool_id: str, instance: dict, probe_counts: dict[str, int] | None) -> list[str]:
    errors = []
    status = instance["terminal_status"]
    if (status == "SKIPPED") != (instance["skip_reason"] is not None):
        errors.append(f"instance-skip: {tool_id}: skip_reason must be set exactly when the instance is SKIPPED")
    cause = instance["cause_code"]
    if cause not in STATUS_CAUSES[status]:
        errors.append(
            f"instance-cause: {tool_id}: status {status} cannot carry cause_code {cause!r} "
            f"(allowed: {list(STATUS_CAUSES[status])})"
        )
    for restating_cause, meaning in CAUSE_EXIT_MEANING.items():
        if status in ("FAILED", "UNRESOLVED") and (cause == restating_cause) != (instance["exit"]["exit_meaning"] == meaning):
            errors.append(
                f"instance-cause: {tool_id}: cause_code {restating_cause!r} must be set exactly when "
                f"exit_meaning is {meaning!r}"
            )
    if status == "SKIPPED":
        if probe_counts is None:
            errors.append(f"instance-skip: {tool_id}: a SKIPPED instance needs a probe receipt and none was supplied")
        elif probe_counts.get(tool_id) != 0:
            errors.append(
                f"instance-skip: {tool_id}: SKIPPED, but the probe receipt does not show zero matching inputs "
                f"(found {probe_counts.get(tool_id)!r})"
            )
    elif probe_counts is not None and probe_counts.get(tool_id) == 0:
        errors.append(
            f"instance-skip: {tool_id}: the probe receipt shows zero matching inputs, so the instance must be "
            f"SKIPPED, not {status}"
        )
    errors.extend(_identity_errors(tool_id, instance))
    errors.extend(_exit_errors(tool_id, instance))
    errors.extend(_output_errors(tool_id, instance))
    return errors


def _probe_errors(receipt: dict) -> list[str]:
    errors = []
    examined = receipt["files_examined_count"]
    if not _nonneg(examined):
        errors.append("probe-count: files_examined_count is negative")
    any_applicable = False
    for tool in receipt["tools"]:
        tool_id = tool["tool_id"]
        counts = [detector["matching_input_count"] for detector in tool["detectors"]]
        total = tool["matching_input_count"]
        detector_ids = [detector["detector_id"] for detector in tool["detectors"]]
        if len(detector_ids) != len(set(detector_ids)):
            errors.append(f"probe-count: {tool_id}: a detector_id is repeated")
        if not all(_nonneg(count) for count in [*counts, total]):
            errors.append(f"probe-count: {tool_id}: a matching_input_count is negative")
            continue
        # One input may match several detectors, so the tool count is between the largest detector
        # count and their sum; in particular it is zero exactly when every detector found nothing.
        if not max(counts) <= total <= sum(counts):
            errors.append(
                f"probe-count: {tool_id}: matching_input_count {total} is not between the largest detector "
                f"count {max(counts)} and the detector sum {sum(counts)}"
            )
        if _nonneg(examined) and total > examined:
            errors.append(f"probe-count: {tool_id}: {total} matching inputs out of {examined} files examined")
        if tool["applicable"] != (total > 0):
            errors.append(f"probe-applicable: {tool_id}: applicable must be true exactly when matching_input_count > 0")
        any_applicable = any_applicable or total > 0
    if receipt["node_applicable"] != any_applicable:
        errors.append("probe-applicable: node_applicable must be true exactly when some tool has matching inputs")
    if (receipt["skip_reason"] is None) != any_applicable:
        errors.append(
            f"probe-skip-reason: skip_reason must be {SKIP_REASON!r} exactly when no tool has matching inputs"
        )
    return errors


def _coverage_errors(coverage: dict, instances: dict[str, dict], probe_counts: dict[str, int] | None) -> list[str]:
    errors = []
    tools = {}
    for tool in coverage["tools"]:
        tools.setdefault(tool["tool_id"], tool)
    for tool_id, tool in tools.items():
        instance = instances.get(tool_id)
        candidate = tool["candidate_input_count"]
        analyzed = tool["analyzed_input_count"]
        not_analyzed = tool["not_analyzed_input_count"]
        unsupported = tool["unsupported_input_count"]
        if not all(_nonneg(value) for value in (candidate, analyzed, not_analyzed, unsupported)):
            errors.append(f"coverage-count: {tool_id}: an input count is negative")
            continue
        if candidate != analyzed + not_analyzed + unsupported:
            errors.append(
                f"coverage-count: {tool_id}: candidate_input_count {candidate} is not analyzed {analyzed} + "
                f"not-analyzed {not_analyzed} + unsupported {unsupported}"
            )
        listed_ok = True
        for field, count in (("not_analyzed_inputs", not_analyzed), ("unsupported_inputs", unsupported)):
            listed = tool[field]
            paths = [entry["path"] for entry in listed]
            if len(paths) != len(set(paths)) or any(".." in path.split("/") for path in paths):
                errors.append(f"coverage-count: {tool_id}: {field} repeats a path or leaves the repository")
            if len(listed) > count:
                errors.append(f"coverage-count: {tool_id}: {field} lists {len(listed)} inputs but the count is {count}")
            listed_ok = listed_ok and len(listed) == count
        if tool["input_lists_truncated"] == listed_ok:
            errors.append(
                f"coverage-count: {tool_id}: input_lists_truncated must be true exactly when a list is shorter "
                "than its count"
            )
        if probe_counts is not None and tool_id in probe_counts and probe_counts[tool_id] != candidate:
            errors.append(
                f"coverage-probe-mismatch: {tool_id}: candidate_input_count {candidate} differs from the probe "
                f"receipt's matching_input_count {probe_counts[tool_id]}"
            )
        if instance is None:
            continue
        skipped = instance["terminal_status"] == "SKIPPED"
        if (tool["applicability"] == SKIP_REASON) != skipped:
            errors.append(
                f"coverage-applicability: {tool_id}: applicability must be {SKIP_REASON!r} exactly when the "
                "tool instance is SKIPPED"
            )
        if tool["applicability"] == SKIP_REASON and candidate != 0:
            errors.append(f"coverage-applicability: {tool_id}: a not-applicable tool cannot have candidate inputs")
        if analyzed and not has_validated_output(instance):
            errors.append(
                f"coverage-analyzed-without-output: {tool_id}: {analyzed} inputs claimed analyzed, but the tool "
                "instance has no validated output"
            )

    gaps = coverage["gaps"]
    gap_ids = [gap["gap_id"] for gap in gaps]
    if len(gap_ids) != len(set(gap_ids)):
        errors.append("gap-duplicate-id: two gaps share one gap_id")
    kinds_by_tool: dict[str, set[str]] = {}
    for gap in gaps:
        tool_id, kind, affected = gap["tool_id"], gap["kind"], gap["affected_input_count"]
        kinds_by_tool.setdefault(tool_id, set()).add(kind)
        instance, tool = instances.get(tool_id), tools.get(tool_id)
        if instance is None or tool is None:
            errors.append(f"gap-unknown-tool: gap {gap['gap_id']!r} names tool {tool_id!r}, which has no tool instance")
            continue
        if affected is not None and not _nonneg(affected):
            errors.append(f"gap-unfounded: gap {gap['gap_id']!r} has a negative affected_input_count")
        if kind in GAP_KIND_INSTANCE:
            if instance["terminal_status"] != GAP_KIND_INSTANCE[kind]:
                errors.append(
                    f"gap-unfounded: gap {gap['gap_id']!r} is {kind!r} but tool {tool_id!r} ended "
                    f"{instance['terminal_status']}"
                )
            if affected is not None:
                errors.append(f"gap-unfounded: gap {gap['gap_id']!r}: a {kind!r} gap carries no affected_input_count")
        elif kind == "inputs-not-analyzed":
            if affected != tool["not_analyzed_input_count"] or not affected:
                errors.append(
                    f"gap-unfounded: gap {gap['gap_id']!r}: affected_input_count {affected!r} must equal the "
                    f"tool's non-zero not_analyzed_input_count {tool['not_analyzed_input_count']!r}"
                )
        elif kind == "inputs-unsupported":
            if affected != tool["unsupported_input_count"] or not affected:
                errors.append(
                    f"gap-unfounded: gap {gap['gap_id']!r}: affected_input_count {affected!r} must equal the "
                    f"tool's non-zero unsupported_input_count {tool['unsupported_input_count']!r}"
                )
        elif kind == "zero-analyzed-inputs":
            if affected is not None or tool["analyzed_input_count"] != 0 or instance["terminal_status"] == "SKIPPED":
                errors.append(
                    f"gap-unfounded: gap {gap['gap_id']!r} is 'zero-analyzed-inputs' but tool {tool_id!r} is "
                    "SKIPPED or analyzed inputs, or the gap carries a count"
                )
        elif instance["terminal_status"] == "SKIPPED":
            errors.append(f"gap-unfounded: gap {gap['gap_id']!r} is {kind!r} on tool {tool_id!r}, which never ran")

    for tool_id, instance in instances.items():
        tool = tools.get(tool_id)
        have = kinds_by_tool.get(tool_id, set())
        status = instance["terminal_status"]
        needed = []
        if status in INSTANCE_GAP_KIND:
            needed.append(INSTANCE_GAP_KIND[status])
        if tool is not None and _nonneg(tool["not_analyzed_input_count"]) and tool["not_analyzed_input_count"]:
            needed.append("inputs-not-analyzed")
        if tool is not None and _nonneg(tool["unsupported_input_count"]) and tool["unsupported_input_count"]:
            needed.append("inputs-unsupported")
        if tool is not None and status in INSTANCE_OUTPUT_STATUSES and tool["analyzed_input_count"] == 0:
            needed.append("zero-analyzed-inputs")
        for kind in needed:
            if kind not in have:
                errors.append(
                    f"gap-missing: tool {tool_id!r} ({status}) is not reported as a named {kind!r} coverage gap"
                )
    return errors


def validate_node_aggregate(
    node_status: str,
    tool_results: dict,
    coverage: dict,
    probe_receipt: dict | None,
    declared_tool_ids: Iterable[str],
    permitted_node_statuses: Iterable[str],
    *,
    store: SchemaStore | None = None,
) -> list[str]:
    """Validate one node's `tool-results.json` + `coverage.json` (+ probe receipt) against the
    node terminal status the worker envelope reports. See the module docstring for the contract.
    Structural failures are returned alone: cross-record rules only run over well-formed input."""
    store = store or SchemaStore()
    if isinstance(declared_tool_ids, (str, bytes)) or isinstance(permitted_node_statuses, (str, bytes)):
        raise TypeError("declared_tool_ids and permitted_node_statuses must be collections, not strings")
    declared_list = list(declared_tool_ids)
    declared = set(declared_list)
    if len(declared) != len(declared_list):
        raise ValueError("declared_tool_ids names a tool more than once")
    permitted = set(permitted_node_statuses)
    if not declared:
        raise ValueError("declared_tool_ids must name at least one tool")
    if not permitted:
        raise ValueError("permitted_node_statuses must name at least one status")

    errors = [f"schema:tool-results: {e}" for e in validate_document(tool_results, TOOL_RESULTS_SCHEMA, store)]
    errors += [f"schema:coverage: {e}" for e in validate_document(coverage, COVERAGE_SCHEMA, store)]
    if probe_receipt is not None:
        errors += [f"schema:probe-receipt: {e}" for e in validate_document(probe_receipt, PROBE_RECEIPT_SCHEMA, store)]
    if errors:
        return errors

    for status in sorted(permitted - set(NODE_STATUSES)):
        errors.append(f"status-not-permitted: {status!r} is not a status a family node may be permitted")
    if node_status not in NODE_STATUSES:
        errors.append(f"status-not-permitted: node status {node_status!r} is not one of {list(NODE_STATUSES)}")
    elif node_status not in permitted:
        errors.append(f"status-not-permitted: node status {node_status!r} is not permitted for this node")
    if "SKIPPED" in permitted and probe_receipt is None:
        errors.append("probe-receipt-required: a node that may be SKIPPED must publish a probe receipt")

    documents = [("coverage", coverage)] + ([("probe-receipt", probe_receipt)] if probe_receipt is not None else [])
    for label, document in documents:
        for field in HEADER_FIELDS:
            if document[field] != tool_results[field]:
                errors.append(
                    f"header-mismatch: {label}.{field} {document[field]!r} differs from tool-results "
                    f"{tool_results[field]!r}"
                )

    instance_list = tool_results["tool_instances"]
    errors += _id_set_errors("tool-results", [inst["tool_id"] for inst in instance_list], declared)
    errors += _id_set_errors("coverage", [tool["tool_id"] for tool in coverage["tools"]], declared)
    probe_counts: dict[str, int] | None = None
    if probe_receipt is not None:
        errors += _id_set_errors("probe-receipt", [tool["tool_id"] for tool in probe_receipt["tools"]], declared)
        errors += _probe_errors(probe_receipt)
        probe_counts = {}
        for tool in probe_receipt["tools"]:
            probe_counts.setdefault(tool["tool_id"], tool["matching_input_count"])

    attempt_ids = [inst["attempt_id"] for inst in instance_list]
    if len(attempt_ids) != len(set(attempt_ids)) or tool_results["attempt_id"] in attempt_ids:
        errors.append("duplicate-attempt: tool instances and the node must each have their own attempt_id")

    instances: dict[str, dict] = {}
    for instance in instance_list:
        instances.setdefault(instance["tool_id"], instance)
    for tool_id, instance in instances.items():
        errors += _instance_errors(tool_id, instance, probe_counts)
    errors += _coverage_errors(coverage, instances, probe_counts)

    # ---- node status against its instances (the three V03 acceptance rules) ----------------
    ran = [inst for inst in instance_list if inst["terminal_status"] != "SKIPPED"]
    if node_status == "OK":
        for instance in ran:
            if instance["terminal_status"] != "OK":
                errors.append(
                    f"node-ok-with-non-ok-instance: node is OK but tool {instance['tool_id']!r} ended "
                    f"{instance['terminal_status']}"
                )
        if coverage["gaps"]:
            errors.append(f"node-ok-with-gaps: node is OK but coverage names {len(coverage['gaps'])} gap(s)")
        if not ran:
            errors.append("node-not-skipped-with-zero-inputs: node is OK but every tool instance is SKIPPED")
    elif node_status == "OK_WITH_GAPS":
        if not any(has_validated_output(instance) for instance in ran):
            errors.append(
                "node-ok-with-gaps-without-validated-output: node is OK_WITH_GAPS but no tool instance has a "
                "validated, hashed output"
            )
        if not coverage["gaps"]:
            errors.append("node-ok-with-gaps-without-gap: node is OK_WITH_GAPS but coverage names no gap")
    elif node_status == "SKIPPED":
        if probe_receipt is None:
            errors.append("node-skipped-without-receipt: node is SKIPPED but no probe receipt was supplied")
        else:
            for tool_id in sorted(declared):
                if tool_id not in probe_counts:
                    errors.append(f"node-skipped-tool-not-probed: node is SKIPPED but the receipt omits tool {tool_id!r}")
                elif probe_counts[tool_id] != 0:
                    errors.append(
                        f"node-skipped-with-inputs: node is SKIPPED but the receipt shows "
                        f"{probe_counts[tool_id]} matching input(s) for tool {tool_id!r}"
                    )
            if probe_receipt["skip_reason"] != SKIP_REASON or probe_receipt["node_applicable"]:
                errors.append(f"node-skipped-wrong-reason: a SKIPPED node's receipt must carry {SKIP_REASON!r}")
            if not probe_receipt["files_examined_count"] > 0:
                errors.append("node-skipped-nothing-examined: a probe that examined no files cannot show absence")
            if not probe_receipt["tools"] or any(
                not detector["patterns_searched"] for tool in probe_receipt["tools"] for detector in tool["detectors"]
            ):
                errors.append("node-skipped-nothing-searched: the receipt names no searched pattern")
        for instance in ran:
            errors.append(
                f"node-skipped-instance-not-skipped: node is SKIPPED but tool {instance['tool_id']!r} ended "
                f"{instance['terminal_status']}"
            )
        if coverage["gaps"]:
            errors.append("node-skipped-with-gaps: a SKIPPED node analyzed nothing and cannot name coverage gaps")
    return errors


def verify_outputs_on_disk(tool_results: dict, attempt_root) -> list[str]:
    """Bind every listed output to the bytes in the attempt.

    `validate_node_aggregate` checks that the three documents agree with each other. It cannot know
    whether an output's `sha256`, `bytes` or even its existence is true: those are statements about
    files. A worker (V10-V13) therefore calls this too, before publication, with the attempt root it
    owns. `attempt_root` is required; there is no mode that skips the files.

    Every output path must be normalized, stay inside the attempt, be a regular non-linked file,
    have exactly the listed size and hash, and name a file that is listed exactly once. "The same
    file" is decided by the file, not by the string: ownership is keyed on the file's identity
    (device and inode, falling back to the resolved path), so an alias, a hard link, or a
    different-case name on a case-insensitive filesystem cannot give one file two owners.
    """
    import os
    from execution_state import beneath, file_hash  # local: keeps the pure validator import-light

    if attempt_root is None or isinstance(attempt_root, (bytes, bool)) or not str(attempt_root):
        raise TypeError("attempt_root must be the attempt directory that owns these outputs")
    errors = [f"schema:tool-results: {e}" for e in validate_document(tool_results, TOOL_RESULTS_SCHEMA, SchemaStore())]
    if errors:
        return errors
    root = Path(attempt_root)
    if not root.is_dir():
        return [f"outputs-on-disk: attempt root {str(root)!r} is not a directory"]
    owners: dict[Any, tuple[str, str]] = {}
    for instance in tool_results["tool_instances"]:
        tool_id = instance["tool_id"]
        for output in instance["outputs"]:
            relative = output["path"]
            malformed = output_path_errors(relative)
            if malformed:
                errors.extend(f"outputs-on-disk: {tool_id}: {error}" for error in malformed)
                continue
            try:
                path = beneath(root, root / relative)
            except ValueError:
                errors.append(f"outputs-on-disk: {tool_id}: {relative!r} leaves the attempt or is a linked path")
                continue
            if not path.is_file():
                errors.append(f"outputs-on-disk: {tool_id}: {relative!r} is listed but is not a regular file in the attempt")
                continue
            status = path.stat()
            identity = (status.st_dev, status.st_ino) if status.st_ino else os.path.normcase(str(path.resolve()))
            if identity in owners:
                other_tool, other_path = owners[identity]
                if other_tool != tool_id:
                    errors.append(f"outputs-on-disk: {relative!r} is listed by both {other_tool!r} and {tool_id!r}"
                                  + ("" if other_path == relative else f" (as {other_path!r})"))
                else:
                    errors.append(f"outputs-on-disk: {tool_id}: {relative!r} and {other_path!r} are the same file listed twice")
                continue
            owners[identity] = (tool_id, relative)
            size = status.st_size
            if size != output["bytes"]:
                errors.append(f"outputs-on-disk: {tool_id}: {relative!r} is {size} bytes, listed as {output['bytes']}")
            actual = "sha256:" + file_hash(path)
            if actual != output["sha256"]:
                errors.append(f"outputs-on-disk: {tool_id}: {relative!r} does not have the listed sha256")
    return errors
