"""Golden, mutation and invariant tests for the container-image-inventory, mobile-sast and
binary-hardening output contracts (ADR-0010 G6 = A, G7 = A, G8 = A, G9; task V07).

`build_case` produces an internally consistent result + tool-results + coverage + probe receipt for
any input mix; the tracked goldens are exactly what it produces (pinned), so every golden is a
producible state. Every mutation edits only the field under test. Image archives, binaries and
source files are GENERATED at test time, never tracked, and tracked JSON is parsed, never compared
as bytes, so nothing here depends on Git newline conversion.

    python3 -B appsec-review-process/tests/test_container_mobile_binary_contracts.py
    python3 -B appsec-review-process/tests/test_container_mobile_binary_contracts.py --regenerate-goldens
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import inspect
import itertools
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))

from schema_validate import SchemaStore, validate_document
import container_mobile_binary_contracts as contracts
from container_mobile_binary_contracts import validate_result, verify_attempt
import evidence_redaction
import tool_instance_shapes as shapes

FIXTURES = ROOT / "tests" / "fixtures" / "container-mobile-binary-contracts"
REGISTRY = ROOT / "registry" / "output-contracts"
PROPOSAL = REPO / "docs" / "proposals" / "vendor-prepass" / "job-nodes.proposal.json"

CONTAINER, MOBILE, BINARY = "container-image-inventory", "mobile-sast", "binary-hardening"
CONTRACT_IDS = (CONTAINER, MOBILE, BINARY)
SCHEMAS = {
    CONTAINER: ["container-image-inventory.schema.json", "container-image-inventory-image.schema.json",
                "container-image-inventory-config.schema.json"],
    MOBILE: ["mobile-sast.schema.json", "mobile-sast-rule-hit.schema.json"],
    BINARY: ["binary-hardening.schema.json", "binary-hardening-binary.schema.json"],
}
ALL_SCHEMAS = [name for names in SCHEMAS.values() for name in names]
DOCUMENTS = ("result", "tool-results", "coverage", "probe-receipt", "declared-tools")
SKIP_REASON = shapes.SKIP_REASON
LIMITS = evidence_redaction.DEFAULT_LIMITS
POLICY = "refuse"

# No field may give a registry pull, a container start, a runtime observation, a roll-up verdict, a
# severity, free text or an environment value a home.
FORBIDDEN_PROPERTY_NAMES = {
    "registry", "registry_url", "pull", "pulled", "pulled_at", "pull_policy", "repo_digest", "repo_digests",
    "repo_digest_resolved_at", "repo_tags", "image_ref", "image_reference", "image_tag", "tag", "tags",
    "container_id", "container_name", "started_at", "start_time", "exec", "exec_result", "runtime", "pid",
    "running", "is_running", "listening", "listening_ports", "reachable", "reachability", "deployed",
    "deployment_state", "exploited", "exploitable", "exploitability", "observed", "observed_at",
    "runtime_state", "runtime_observation", "observed_runtime", "live_scan", "live_scan_result",
    "production_state", "state", "status", "health", "uptime",
    "pass", "passed", "secure", "is_secure", "hardened", "overall", "overall_verdict", "verdict", "score",
    "grade", "rating", "result", "compliant", "severity", "level", "cvss", "cvss_score", "risk", "priority",
    "finding", "findings", "vulnerability", "vulnerabilities", "verified_finding", "verified_findings",
    "message", "messages", "snippet", "snippets", "match", "matches", "matched_text", "line_text", "lines",
    "text", "content", "excerpt", "context", "raw", "description", "detail", "details", "note", "notes",
    "summary", "title", "env", "environment", "env_values", "declared_env", "value", "values", "secret",
    "entrypoint", "cmd", "command", "args", "arguments", "argv",
}
RUNTIME_WORDS = ("running", "listening", "reachable", "deployed", "exploited", "observed", "runtime", "live")
DELIBERATE_RUNTIME_ENUM = {"OBSERVED_EXPOSURE"}
RAW_LINES = [
    "pass" + 'word = "example"  # do not commit',
    "    api_key: " + "EXAMPLE" * 3,
    "line one\nline two",
    "sha256:" + "0" * 64 + "\n",
    "name\n",
]


def sha_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha(label: str) -> str:
    return sha_bytes(label.encode("utf-8"))


def dump(document) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def names(errors) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def proposal_node(contract_id: str) -> dict:
    proposal = json.loads(PROPOSAL.read_text(encoding="utf-8"))
    (node,) = [n for n in proposal["proposed_nodes"] if n["proposed_output_contract_id"] == contract_id]
    return node


PROPOSED = {contract_id: proposal_node(contract_id) for contract_id in CONTRACT_IDS}
PERMITTED = {contract_id: PROPOSED[contract_id]["permitted_terminal_statuses"] for contract_id in CONTRACT_IDS}
TOOLS = {contract_id: [t["tool_id"] for t in PROPOSED[contract_id]["tool_instances"]] for contract_id in CONTRACT_IDS}


# ---- generated inputs (never tracked) ---------------------------------------------------------

def input_bytes(path: str, fmt: str | None = None) -> bytes:
    """Deterministic fake content for an input path: a fake archive, binary or source file. A binary
    starts with the real magic of `fmt`, because the listed format is re-derived from the bytes."""
    if path.endswith((".kt", ".swift", ".xml", ".plist")):
        return "".join(f"// {path} line {n}\n" for n in range(1, 21)).encode("utf-8")
    magic = contracts.FORMAT_MAGIC[fmt][0] if fmt in contracts.FORMAT_MAGIC else b"\x00FAKE"
    return magic + b"\x00" + hashlib.sha256(path.encode("utf-8")).digest() * 4


# ---- consistent-document builder -------------------------------------------------------------

def header(contract_id: str) -> dict:
    return {"run_id": "20260920T120000Z-v07abc", "job_id": contracts.CONTRACTS[contract_id]["job_id"],
            "attempt_id": "node-attempt-0001", "source_snapshot_sha256": sha("snapshot")}


def build_instance(tool_id: str, status: str, outputs: list[dict], record_count) -> dict:
    exit_code, meaning = {"OK": (0, "clean"), "OK_WITH_GAPS": (0, "clean"), "SKIPPED": (None, "not-started"),
                          "BLOCKED": (None, "not-started"), "FAILED": (2, "tool-error"),
                          "CANCELED": (None, "canceled")}[status]
    cause = {"OK": None, "SKIPPED": None, "OK_WITH_GAPS": "partial-input-coverage", "BLOCKED": "image-unavailable",
             "FAILED": "tool-error", "CANCELED": "canceled"}[status]
    has_output = status in ("OK", "OK_WITH_GAPS")
    return {
        "tool_id": tool_id, "attempt_id": f"{tool_id}-attempt-0001", "terminal_status": status,
        "skip_reason": SKIP_REASON if status == "SKIPPED" else None, "cause_code": cause,
        "identity": {"executor_kind": "pinned_container",
                     "image_repository": "registry.internal.example:5000/appsec/audit-static",
                     "image_digest": sha("analysis-image" + tool_id), "executable_sha256": None,
                     "tool_name": tool_id, "tool_version": "1.2.3" if has_output or status == "FAILED" else None,
                     "data_identities": [], "redactor": None},
        "argv": [tool_id, "--offline", "/in"],
        "exit": {"exit_code": exit_code, "exit_meaning": meaning, "timed_out": False,
                 "nonzero_exit_on_findings": False, "findings_exit_codes": []},
        "outputs": outputs if has_output else [],
        "result_record_count": record_count if has_output else None,
    }


def raw_output(path: str, document: dict, validated_against: str) -> tuple[dict, bytes]:
    data = dump(document)
    return ({"path": path, "sha256": sha_bytes(data), "bytes": len(data),
             "media_type": "application/json", "role": "raw-tool-output", "validation": "format-validated",
             "validated_against": validated_against}, data)


def build_aggregate(contract_id: str, tools: dict[str, dict]) -> tuple[dict, dict[str, bytes]]:
    """`tools`: tool_id -> {candidates: [paths], gaps: {path: (list_field, reason)}, failed: bool,
    raw: (path, document, validated_against), records: int}."""
    instances, coverage_tools, gaps, probed, raw_files = [], [], [], [], {}
    for tool_id, spec in tools.items():
        candidates, listed = spec["candidates"], spec["gaps"]
        if not candidates:
            status = "SKIPPED"
        elif spec.get("failed"):
            status = "FAILED"
            listed = {path: listed[path] if listed.get(path, ("", ""))[1] == "unsupported-format"
                      else ("not_analyzed_inputs", "tool-instance-did-not-complete") for path in candidates}
        else:
            status = "OK_WITH_GAPS" if listed else "OK"
        entry, data = raw_output(*spec["raw"])
        if status in ("OK", "OK_WITH_GAPS"):
            raw_files[entry["path"]] = data
        instances.append(build_instance(tool_id, status, [entry], spec["records"]))
        not_analyzed = [{"path": p, "reason_code": r} for p, (f, r) in sorted(listed.items()) if f == "not_analyzed_inputs"]
        unsupported = [{"path": p, "reason_code": r} for p, (f, r) in sorted(listed.items()) if f == "unsupported_inputs"]
        analyzed = len(candidates) - len(listed)
        coverage_tools.append({
            "tool_id": tool_id, "applicability": SKIP_REASON if status == "SKIPPED" else "applicable",
            "candidate_input_count": len(candidates), "analyzed_input_count": analyzed,
            "not_analyzed_input_count": len(not_analyzed), "unsupported_input_count": len(unsupported),
            "not_analyzed_inputs": not_analyzed, "unsupported_inputs": unsupported, "input_lists_truncated": False,
        })
        if status in shapes.INSTANCE_GAP_KIND:
            gaps.append({"gap_id": f"gap-{tool_id}-instance", "kind": shapes.INSTANCE_GAP_KIND[status],
                         "tool_id": tool_id, "affected_input_count": None})
        if not_analyzed:
            gaps.append({"gap_id": f"gap-{tool_id}-not-analyzed", "kind": "inputs-not-analyzed",
                         "tool_id": tool_id, "affected_input_count": len(not_analyzed)})
        if unsupported:
            gaps.append({"gap_id": f"gap-{tool_id}-unsupported", "kind": "inputs-unsupported",
                         "tool_id": tool_id, "affected_input_count": len(unsupported)})
        if status in ("OK", "OK_WITH_GAPS") and analyzed == 0:
            gaps.append({"gap_id": f"gap-{tool_id}-zero-analyzed", "kind": "zero-analyzed-inputs",
                         "tool_id": tool_id, "affected_input_count": None})
        probed.append({"tool_id": tool_id,
                       "detectors": [{"detector_id": f"{tool_id}-detector", "patterns_searched": spec["patterns"],
                                      "matching_input_count": len(candidates)}],
                       "matching_input_count": len(candidates), "applicable": bool(candidates)})
    applicable = any(tool["applicable"] for tool in probed)
    head = header(contract_id)
    documents = {
        "tool-results": {"schema": "appsec-review/tool-results/1.0", **head, "tool_instances": instances},
        "coverage": {"schema": "appsec-review/scan-coverage/1.0", **head, "tools": coverage_tools, "gaps": gaps},
        "probe-receipt": {"schema": "appsec-review/applicability-probe-receipt/1.0", **head,
                          "probe": {"probe_id": f"{contract_id}-probe", "probe_version": "1.0.0",
                                    "probe_sha256": sha("probe" + contract_id)},
                          "files_examined_count": 40 + sum(len(spec["candidates"]) for spec in tools.values()),
                          "tools": probed, "node_applicable": applicable,
                          "skip_reason": None if applicable else SKIP_REASON},
        "declared-tools": list(tools),
    }
    return documents, raw_files


def finish(contract_id: str, result_body: dict, tools: dict, inputs: dict[str, bytes]) -> dict:
    documents, raw_files = build_aggregate(contract_id, tools)
    documents["result"] = {"schema": f"appsec-review/{contract_id}/1.0", **header(contract_id), **result_body}
    status = shapes.supportable_success_status(documents["tool-results"], documents["coverage"])
    return {"contract_id": contract_id, "status": status or "FAILED", "documents": documents,
            "raw_files": raw_files, "inputs": dict(inputs)}


def binary_checks(fmt: str, assessed: bool) -> dict:
    checks = {}
    for index, (name, formats) in enumerate(sorted(contracts.CHECK_FORMATS.items())):
        if not assessed:
            checks[name] = "not-assessed"
        elif fmt in formats:
            checks[name] = "present" if index % 2 == 0 else "absent"
        else:
            checks[name] = "not-applicable-for-format"
    return checks


def binary_case(binaries: list[tuple[str, str, str]], failed: bool = False) -> dict:
    """binaries: (path, format, state); state is assessed | unsupported-format | parse-failed."""
    (tool_id,) = TOOLS[BINARY]
    gaps, records = {}, []
    for path, fmt, state in binaries:
        if state == "unsupported-format":
            gaps[path] = ("unsupported_inputs", "unsupported-format")
        elif state == "parse-failed":
            gaps[path] = ("not_analyzed_inputs", "parse-failed")
        assessed = state == "assessed" and not failed
        data = input_bytes(path, fmt)
        records.append({
            "binary_id": "bin-" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:12], "tool_id": tool_id,
            "path": path, "sha256": sha_bytes(data), "bytes": len(data), "format": fmt,
            "checks": binary_checks(fmt, assessed),
            "rule_hits": [{"rule_id": "BA2008", "check": "control_flow_guard"}] if assessed and fmt == "pe" else [],
        })
    tools = {tool_id: {"candidates": [b[0] for b in binaries], "gaps": gaps, "failed": failed,
                       "raw": ("outputs/binskim.sarif", {"version": "2.1.0", "runs": []}, "sarif-2.1.0"),
                       "records": len(binaries), "patterns": ["**/*.dll", "**/*.exe", "**/*.so", "**/*.dylib"]}}
    return finish(BINARY, {"binaries": records}, tools, {b[0]: input_bytes(b[0], b[1]) for b in binaries})


def container_case(archives: list[tuple[str, str, str]]) -> dict:
    """archives: (path, archive_format, state); state is inspected | unsupported-format | parse-failed."""
    inventory_tool, package_tool = TOOLS[CONTAINER]
    gaps, images, package_total = {}, [], 0
    for path, fmt, state in archives:
        if state == "unsupported-format":
            gaps[path] = ("unsupported_inputs", "unsupported-format")
        elif state == "parse-failed":
            gaps[path] = ("not_analyzed_inputs", "parse-failed")
        inspected = state == "inspected"
        data = input_bytes(path)
        packages = [{"tool_id": package_tool, "layer_index": 1, "ecosystem": "deb", "name": "openssl", "version": "3.0.13-1"},
                    {"tool_id": package_tool, "layer_index": 0, "ecosystem": "deb", "name": "libc6", "version": None}]
        package_total += len(packages) if inspected else 0
        images.append({
            "image_id": "img-" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:12], "tool_id": inventory_tool,
            "source": {"kind": "supplied-archive", "archive_path": path, "archive_sha256": sha_bytes(data),
                       "archive_bytes": len(data)},
            "archive_format": fmt, "inspection": "inspected" if inspected else "not-inspected",
            "image_manifest_digest": sha("manifest" + path) if inspected else None,
            "layers": [{"layer_index": n, "layer_digest": sha(f"layer{n}{path}"), "layer_bytes": 1000 + n}
                       for n in range(2)] if inspected else [],
            "config": {
                "config_digest": sha("config" + path), "architecture": "amd64", "os": "linux",
                "declared_user": None, "declared_entrypoint_executable": "/usr/local/bin/entry",
                "declared_entrypoint_argument_count": 2, "declared_command_executable": None,
                "declared_command_argument_count": 0,
                "declared_ports": [{"port": 8443, "protocol": "tcp", "exposure_label": "DECLARED_EXPOSURE"}],
                "declared_env_names": ["PATH", "APP_MODE"],
            } if inspected else None,
            "packages": packages if inspected else [],
            "hardening_rule_hits": [{"tool_id": package_tool, "rule_id": "IMG-0001", "category": "no-user-declared"}]
            if inspected else [],
        })
    paths = [a[0] for a in archives]
    inspected_count = sum(1 for a in archives if a[2] == "inspected")
    tools = {
        inventory_tool: {"candidates": paths, "gaps": dict(gaps), "records": inspected_count,
                         "raw": (f"outputs/{inventory_tool}.json", {"archives_read": inspected_count}, "oci-image-layout-1.0"),
                         "patterns": ["images/*.tar", "images/*.oci.tar"]},
        package_tool: {"candidates": paths, "gaps": dict(gaps), "records": package_total,
                       "raw": (f"outputs/{package_tool}.json", {"packages_read": package_total}, "package-listing-1.0"),
                       "patterns": ["images/*.tar", "images/*.oci.tar"]},
    }
    return finish(CONTAINER, {"images": images}, tools, {path: input_bytes(path) for path in paths})


def mobile_case(android_files: list[str], ios_files: list[str], hits: list[tuple[str, str, int]]) -> dict:
    """hits: (platform, file_path, line)."""
    tool_of = dict(zip(contracts.PLATFORMS, TOOLS[MOBILE]))
    files = {"android": android_files, "ios": ios_files}
    rule_hits = [{"hit_id": f"hit-{n:04d}", "tool_id": tool_of[platform], "platform": platform,
                  "rule_id": "android_logging" if platform == "android" else "ios_keychain_access",
                  "category": "insecure-data-storage", "file_path": path,
                  "file_sha256": sha_bytes(input_bytes(path)), "line": line}
                 for n, (platform, path, line) in enumerate(hits, 1)]
    markers = {"android": ["**/AndroidManifest.xml", "**/build.gradle*"], "ios": ["**/Info.plist", "**/*.xcodeproj/*"]}
    tools = {tool_of[p]: {"candidates": files[p], "gaps": {}, "records": sum(1 for h in hits if h[0] == p),
                          "raw": (f"outputs/{tool_of[p]}.sarif", {"version": "2.1.0", "runs": []}, "sarif-2.1.0"),
                          "patterns": markers[p]} for p in contracts.PLATFORMS}
    body = {"platforms": [{"platform": p, "tool_id": tool_of[p], "marker_present": bool(files[p])}
                          for p in contracts.PLATFORMS], "rule_hits": rule_hits}
    return finish(MOBILE, body, tools, {path: input_bytes(path) for path in android_files + ios_files})


ANDROID = ["app/src/main/AndroidManifest.xml", "app/src/main/kotlin/Login.kt", "app/src/main/kotlin/Store.kt"]
IOS = ["ios/App/Info.plist", "ios/App/Keychain.swift"]
GOLDENS = {
    "container-ok-with-gaps": lambda: container_case([("images/api.oci.tar", "oci-layout", "inspected"),
                                                      ("images/worker.tar", "docker-save", "inspected"),
                                                      ("images/legacy.aci", "unsupported", "unsupported-format")]),
    "container-skipped": lambda: container_case([]),
    "mobile-ok-android-only": lambda: mobile_case(ANDROID, [], [("android", ANDROID[1], 7), ("android", ANDROID[1], 12),
                                                                ("android", ANDROID[2], 3)]),
    "mobile-skipped": lambda: mobile_case([], [], []),
    "binary-ok-with-gaps": lambda: binary_case([("vendor/win/agent.dll", "pe", "assessed"),
                                                ("vendor/linux/libcodec.so", "elf", "assessed"),
                                                ("vendor/mac/libui.dylib", "macho", "assessed"),
                                                ("vendor/fw/boot.bin", "unsupported", "unsupported-format"),
                                                ("vendor/linux/packed.so", "elf", "parse-failed")]),
    "binary-skipped": lambda: binary_case([]),
}
GOLDEN_STATUS = {"container-ok-with-gaps": "OK_WITH_GAPS", "container-skipped": "SKIPPED",
                 "mobile-ok-android-only": "OK", "mobile-skipped": "SKIPPED",
                 "binary-ok-with-gaps": "OK_WITH_GAPS", "binary-skipped": "SKIPPED"}


def check(case: dict, status: str | None = None, **override) -> list[str]:
    docs = case["documents"]
    args = {"result": docs["result"], "tool_results": docs["tool-results"], "coverage": docs["coverage"],
            "probe_receipt": docs["probe-receipt"], "declared_tool_ids": docs["declared-tools"],
            "permitted_node_statuses": PERMITTED[case["contract_id"]]}
    args.update(override)
    return validate_result(case["contract_id"], status or case["status"], args["result"], args["tool_results"],
                           args["coverage"], args["probe_receipt"], args["declared_tool_ids"],
                           args["permitted_node_statuses"])


def materialize(case: dict, root: Path) -> tuple[Path, Path]:
    """Write the inputs and a published attempt for `case` beneath `root`, the way a worker would:
    stage, then publish `outputs/` through the V06 redactor so the receipt is real."""
    spec = contracts.CONTRACTS[case["contract_id"]]
    inputs, staging, attempt = root / "inputs", root / "staging", root / "attempt"
    for relative, data in case["inputs"].items():
        (inputs / relative).parent.mkdir(parents=True, exist_ok=True)
        (inputs / relative).write_bytes(data)
    inputs.mkdir(exist_ok=True)
    staging.mkdir()
    docs = case["documents"]
    staged = {spec["result"]: dump(docs["result"]), spec["probe_receipt"]: dump(docs["probe-receipt"]),
              contracts.TOOL_RESULTS: dump(docs["tool-results"]), contracts.COVERAGE: dump(docs["coverage"]),
              **case["raw_files"]}
    for relative, data in staged.items():
        (staging / Path(relative).name).write_bytes(data)
    attempt.mkdir()
    (attempt / "status.json").write_bytes(dump(status_document(case)))
    receipt = evidence_redaction.redact_tree(staging, attempt / "outputs", on_unhandled=POLICY, limits=LIMITS)
    assert receipt["totals"]["files_redacted"] == 0, "a consistent case must be a fixed point of the redactor"
    (attempt / "manifest.json").write_bytes(dump(manifest_document(case["contract_id"], attempt)))
    return attempt, inputs


def manifest_document(contract_id: str, attempt: Path) -> dict:
    """What a worker writes last: the hashes of exactly what it published under outputs/."""
    outputs = [{"path": path.relative_to(attempt).as_posix(), "sha256": sha_bytes(path.read_bytes())}
               for path in sorted((attempt / "outputs").rglob("*")) if path.is_file()]
    return {"schema": contracts.MANIFEST_SCHEMA, "contract_id": contract_id, "outputs": outputs}


DAGSTER_RUN_ID = "0f4c2b7e-dagster-run-v07"


def status_document(case: dict) -> dict:
    """Exactly the registered contract's required_status_fields, bound to the envelope."""
    return {"status": case["status"], "attempt_id": header(case["contract_id"])["attempt_id"],
            "dagster_run_id": DAGSTER_RUN_ID}


def verify(case: dict, attempt: Path, inputs: Path, **override) -> list[str]:
    kwargs = {"expected_header": header(case["contract_id"]), "expected_dagster_run_id": DAGSTER_RUN_ID,
              "node_status": case["status"],
              "declared_tool_ids": case["documents"]["declared-tools"],
              "permitted_node_statuses": PERMITTED[case["contract_id"]], "on_unhandled": POLICY, "limits": LIMITS}
    kwargs.update(override)
    return verify_attempt(case["contract_id"], attempt, inputs, **kwargs)


def walk_schema(node, path="$"):
    if isinstance(node, dict):
        if "properties" in node:
            yield path, node
        for key, value in node.items():
            yield from walk_schema(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk_schema(value, f"{path}[{index}]")


def walk_leaves(node, path="$"):
    if isinstance(node, dict):
        if ("type" in node or "const" in node or "enum" in node) and "properties" not in node and "items" not in node:
            yield path, node
        for key in ("properties", "items"):
            value = node.get(key)
            if key == "properties" and isinstance(value, dict):
                for name, child in value.items():
                    yield from walk_leaves(child, f"{path}.{name}")
            elif key == "items" and isinstance(value, dict):
                yield from walk_leaves(value, f"{path}[]")


def _link_capability(make) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "target"
        target.write_bytes(b"x")
        try:
            make(target, Path(tmp) / "link")
            return True
        except (OSError, NotImplementedError, AttributeError):
            return False


# ---- known V03 x V06 conflict on main ---------------------------------------------------------
# V06's entropy pass also redacts JSON object KEYS, and it classifies the V03 header key
# `source_snapshot_sha256` as high-entropy. tool-results.json, coverage.json and the probe receipt
# therefore cannot pass through `redact_tree` unchanged, although ADR-0010 publishes them beside
# `outputs/redaction-receipt.json`. Neither module is in V07's paths. Until the integrator fixes V06,
# the on-disk tests model the smallest fix (exempt exactly that key). The shim is applied ONLY while
# the conflict exists (probed through the public API) and is removed again in tearDownModule.
V03_HEADER_KEY = "source_snapshot_sha256"
_SHIM = {}


def redactor_rewrites(document) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "source"
        source.mkdir()
        (source / "probe.json").write_bytes(dump(document))
        receipt = evidence_redaction.redact_tree(source, Path(tmp) / "published", on_unhandled="withhold", limits=LIMITS)
        return receipt["totals"]["files_unchanged"] != 1


def setUpModule():
    if redactor_rewrites({V03_HEADER_KEY: 1}):
        original = evidence_redaction._exempt
        _SHIM["original"] = original
        evidence_redaction._exempt = lambda run: run == V03_HEADER_KEY or original(run)


def tearDownModule():
    if "original" in _SHIM:
        evidence_redaction._exempt = _SHIM.pop("original")


CAN_SYMLINK = _link_capability(lambda target, link: os.symlink(target, link))
CAN_HARDLINK = _link_capability(lambda target, link: os.link(target, link))


# =============================================================================================

class SchemaHygieneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = SchemaStore()

    def test_every_object_is_closed_and_every_declared_property_is_required(self):
        for name in ALL_SCHEMAS:
            schema = self.store.load(name)
            self.assertEqual(schema["$id"], name)
            nodes = list(walk_schema(schema))
            self.assertTrue(nodes)
            for path, node in nodes:
                self.assertIs(node.get("additionalProperties"), False, f"{name} {path} is not closed")
                self.assertEqual(set(node["required"]), set(node["properties"]), f"{name} {path}")

    def test_only_validator_subset_keywords_are_used(self):
        allowed = {"$schema", "$id", "title", "description", "type", "required", "properties",
                   "additionalProperties", "enum", "const", "pattern", "items", "minItems", "$ref"}

        def keywords(node, inside_properties=False):
            if isinstance(node, dict):
                for key, value in node.items():
                    if not inside_properties:
                        yield key
                    yield from keywords(value, key == "properties" and not inside_properties)
            elif isinstance(node, list):
                for value in node:
                    yield from keywords(value)

        for name in ALL_SCHEMAS:
            self.assertLessEqual(set(keywords(self.store.load(name))), allowed, name)

    def test_no_schema_offers_a_runtime_pull_rollup_severity_free_text_or_env_value_field(self):
        for name in ALL_SCHEMAS:
            for path, node in walk_schema(self.store.load(name)):
                offenders = FORBIDDEN_PROPERTY_NAMES & {key.lower() for key in node["properties"]}
                self.assertFalse(offenders, f"{name} {path} declares forbidden fields {sorted(offenders)}")
                for key in node["properties"]:
                    tokens = set(key.lower().split("_"))
                    self.assertFalse(tokens & set(RUNTIME_WORDS), f"{name} {path}.{key} names runtime state")

    def test_no_enum_value_asserts_runtime_state_except_the_one_the_validator_rejects_by_name(self):
        found = set()
        for name in ALL_SCHEMAS:
            for path, leaf in walk_leaves(self.store.load(name)):
                for value in leaf.get("enum", []):
                    if isinstance(value, str) and any(word in re.split(r"[-_]", value.lower()) for word in RUNTIME_WORDS):
                        found.add(value)
        self.assertEqual(found, DELIBERATE_RUNTIME_ENUM)

    def test_every_string_is_a_const_an_enum_or_a_fully_anchored_pattern_that_rejects_a_raw_line(self):
        seen = 0
        for name in ALL_SCHEMAS:
            for path, leaf in walk_leaves(self.store.load(name)):
                if "const" in leaf or "enum" in leaf:
                    continue
                types = leaf["type"] if isinstance(leaf["type"], list) else [leaf["type"]]
                self.assertLessEqual(set(types), {"string", "integer", "boolean", "null"}, f"{name} {path}")
                if "string" not in types:
                    continue
                seen += 1
                pattern = leaf.get("pattern")
                self.assertIsNotNone(pattern, f"{name} {path} is a free-text string")
                self.assertTrue(pattern.startswith("^") and pattern.endswith("\\Z"), f"{name} {path} must end with \\Z")
                for line in RAW_LINES:
                    self.assertIsNone(re.match(pattern, line), f"{name} {path} accepts raw line {line!r}")
        self.assertGreater(seen, 20)

    def test_every_property_name_and_enum_value_survives_the_v06_redactor(self):
        # A key the redactor rewrites makes the published document schema-invalid. The only tolerated
        # name is the header key inherited from V03 (see the conflict note above setUpModule).
        keys, values = set(), set()
        for name in ALL_SCHEMAS:
            schema = self.store.load(name)
            for _, node in walk_schema(schema):
                keys |= set(node["properties"])
            for _, leaf in walk_leaves(schema):
                values |= {value for value in leaf.get("enum", []) if isinstance(value, str)}
        keys.discard(V03_HEADER_KEY)
        self.assertGreater(len(keys) + len(values), 60)
        # a key is probed WITH a value: a credential-named key would get its value redacted wholesale
        self.assertEqual({key for key in sorted(keys) if redactor_rewrites({key: "plain-value"})}, set())
        self.assertEqual({value for value in sorted(values) if redactor_rewrites({"k": [value]})}, set())

    def test_the_conflict_shim_is_active_only_while_v06_rewrites_the_v03_header_key(self):
        if "original" in _SHIM:
            self.assertFalse(_SHIM["original"](V03_HEADER_KEY), "the shim must only cover a real conflict")
        self.assertFalse(redactor_rewrites({V03_HEADER_KEY: "sha256:" + "0" * 64}))

    def test_image_source_kind_is_a_closed_enum_with_the_supplied_archive_as_its_only_value(self):
        image = self.store.load("container-image-inventory-image.schema.json")
        source = image["properties"]["source"]
        self.assertEqual(source["properties"]["kind"]["enum"], ["supplied-archive"])
        self.assertEqual(set(source["properties"]), {"kind", "archive_path", "archive_sha256", "archive_bytes"})

    def test_binary_format_and_verdict_enums_are_closed_and_match_the_module(self):
        binary = self.store.load("binary-hardening-binary.schema.json")["properties"]
        self.assertEqual(binary["format"]["enum"], ["pe", "elf", "macho", "unsupported"])
        self.assertEqual(set(binary["checks"]["properties"]), set(contracts.CHECK_FORMATS))
        for name, leaf in binary["checks"]["properties"].items():
            self.assertEqual(leaf["enum"], ["present", "absent", "not-applicable-for-format", "not-assessed"], name)
        hit_checks = binary["rule_hits"]["items"]["properties"]["check"]["enum"]
        self.assertEqual(set(hit_checks), set(contracts.CHECK_FORMATS) | {"other"})
        for formats in contracts.CHECK_FORMATS.values():
            self.assertLessEqual(set(formats), {"pe", "elf", "macho"})


class ContractDeclarationTests(unittest.TestCase):
    def load(self, contract_id):
        return json.loads((REGISTRY / f"{contract_id}.json").read_text(encoding="utf-8"))

    def test_contracts_validate_and_match_the_accepted_adr_fixture(self):
        for contract_id in CONTRACT_IDS:
            contract, node = self.load(contract_id), PROPOSED[contract_id]
            self.assertEqual(validate_document(contract, "output-contract.schema.json"), [])
            self.assertEqual(contract["contract_id"], contract_id)
            self.assertTrue(node["adopted"])
            self.assertEqual(contract["claim_class"], node["proposed_claim_class"])
            self.assertIn("runtime-state", contract["claim_class"]["forbidden_promotions"])
            self.assertEqual(set(contract["claim_class"]["forbidden_promotions"]), {"finding", "severity", "runtime-state"})
            self.assertIn("SKIPPED", node["permitted_terminal_statuses"])
            self.assertEqual(contracts.CONTRACTS[contract_id]["job_id"], node["proposed_job_id"])

    def test_required_files_are_the_fixture_artifacts_plus_the_probe_receipt_and_the_redaction_receipt(self):
        # Pinned differences from job-nodes.proposal.json: every node gains the probe receipt it needs to be
        # SKIPPED; binary-hardening gains the redaction receipt (it publishes scanner output) and makes
        # binskim.sarif conditional, because a SKIPPED node never ran BinSkim and has no SARIF to publish.
        expected_extra = {
            CONTAINER: ({"outputs/container-image-applicability.json"}, set()),
            MOBILE: (set(), set()),
            BINARY: ({"outputs/binary-hardening-applicability.json", "outputs/redaction-receipt.json"},
                     {"outputs/binskim.sarif"}),
        }
        for contract_id in CONTRACT_IDS:
            contract = self.load(contract_id)
            required, proposed = set(contract["required_files"]), set(PROPOSED[contract_id]["required_artifacts"])
            self.assertEqual(len(required), len(contract["required_files"]))
            added, dropped = expected_extra[contract_id]
            self.assertEqual(required - proposed, added, contract_id)
            self.assertEqual(proposed - required, dropped, contract_id)
            spec = contracts.CONTRACTS[contract_id]
            for relative in ("manifest.json", "status.json", spec["result"], spec["probe_receipt"],
                             contracts.TOOL_RESULTS, contracts.COVERAGE, contracts.REDACTION_RECEIPT):
                self.assertIn(relative, required, contract_id)
                self.assertEqual(shapes.output_path_errors(relative), [])
            self.assertEqual(contract["result_schema"], {"artifact": spec["result"], "schema_file": spec["schema"]})
            self.assertEqual(Path(contracts.REDACTION_RECEIPT).name, evidence_redaction.RECEIPT_FILENAME)

    def test_mobile_contract_requires_the_in_worker_probe_receipt_and_adopts_no_applicability_node(self):
        contract = self.load(MOBILE)
        self.assertIn("outputs/mobile-applicability.json", contract["required_files"])
        self.assertEqual(contracts.CONTRACTS[MOBILE]["probe_receipt"], "outputs/mobile-applicability.json")
        proposal = json.loads(PROPOSAL.read_text(encoding="utf-8"))
        (gate,) = [n for n in proposal["proposed_nodes"] if n["proposed_job_id"] == "02-mobile-applicability"]
        self.assertFalse(gate["adopted"])
        self.assertEqual(proposal["gate_decisions"]["G6"], "A")

    def test_no_contract_or_schema_text_contradicts_the_accepted_adr_or_implies_a_pull_or_a_start(self):
        texts = {f"{c}.json": (REGISTRY / f"{c}.json").read_text(encoding="utf-8") for c in CONTRACT_IDS}
        texts.update({name: (ROOT.parent / "schemas" / name).read_text(encoding="utf-8") for name in ALL_SCHEMAS})
        for name, text in texts.items():
            lowered = text.lower()
            for word in ("recommended", "recommendation", "proposed", "proposal_only", "02-mobile-applicability", "todo"):
                self.assertNotIn(word, lowered, f"{name} says {word!r} about a decided thing")
        for contract_id in CONTRACT_IDS:
            for rule in self.load(contract_id)["validation_rules"]:
                lowered = rule.lower()
                if any(word in lowered for word in ("registry", "pull", "fetch", "started", "built", "execution", "ptrace")):
                    self.assertRegex(lowered, r"\b(no|not|never|nothing)\b", f"{contract_id}: not negated: {rule}")
        container_rules = " ".join(self.load(CONTAINER)["validation_rules"]).lower()
        self.assertIn("no image is fetched from a registry", container_rules)
        self.assertIn("no container is created or started", container_rules)


class GoldenTests(unittest.TestCase):
    def test_every_tracked_golden_is_exactly_what_the_builder_produces(self):
        for name, build in GOLDENS.items():
            case = build()
            for part in DOCUMENTS:
                tracked = json.loads((FIXTURES / name / f"{part}.json").read_text(encoding="utf-8"))
                self.assertEqual(tracked, case["documents"][part], f"{name}/{part}.json is stale")
        self.assertEqual({p.name for p in FIXTURES.iterdir()}, set(GOLDENS))

    def test_goldens_are_valid_for_their_status_and_for_no_other_success_status(self):
        for name, build in GOLDENS.items():
            case = build()
            self.assertEqual(case["status"], GOLDEN_STATUS[name])
            self.assertEqual(check(case), [], name)
            for other in set(shapes.NODE_SUCCESS_STATUSES) - {case["status"]}:
                self.assertTrue(check(case, status=other), f"{name} also accepted as {other}")

    def test_goldens_verify_on_disk_with_generated_inputs(self):
        for name, build in GOLDENS.items():
            case = build()
            with tempfile.TemporaryDirectory() as tmp:
                attempt, inputs = materialize(case, Path(tmp))
                self.assertEqual(verify(case, attempt, inputs), [], name)
                contract = json.loads((REGISTRY / f"{case['contract_id']}.json").read_text(encoding="utf-8"))
                for relative in contract["required_files"]:
                    self.assertTrue((attempt / relative).is_file(), f"{name}: {relative}")

    def test_ids_are_consistent_within_and_across_goldens_and_with_the_adr_fixture(self):
        run_ids = set()
        for name, build in GOLDENS.items():
            case = build()
            docs, contract_id = case["documents"], case["contract_id"]
            self.assertEqual(docs["declared-tools"], TOOLS[contract_id], name)
            self.assertEqual(docs["result"]["job_id"], PROPOSED[contract_id]["proposed_job_id"])
            for part in ("result", "tool-results", "coverage", "probe-receipt"):
                self.assertEqual({f: docs[part][f] for f in shapes.HEADER_FIELDS}, header(contract_id), f"{name}/{part}")
                run_ids.add(docs[part]["run_id"])
            for part, key in (("tool-results", "tool_instances"), ("coverage", "tools"), ("probe-receipt", "tools")):
                self.assertEqual([t["tool_id"] for t in docs[part][key]], TOOLS[contract_id], f"{name}/{part}")
            self.assertLessEqual({g["tool_id"] for g in docs["coverage"]["gaps"]}, set(TOOLS[contract_id]))
        self.assertEqual(len(run_ids), 1)

    def test_skipped_goldens_publish_the_receipt_and_no_raw_tool_output(self):
        for name in ("container-skipped", "mobile-skipped", "binary-skipped"):
            case = GOLDENS[name]()
            self.assertEqual(case["raw_files"], {})
            self.assertEqual(case["documents"]["probe-receipt"]["skip_reason"], SKIP_REASON)
            self.assertEqual(case["documents"]["result"][contracts.CONTRACTS[case["contract_id"]]["records"]], [])


class RequiredInputTests(unittest.TestCase):
    def test_no_argument_of_either_entry_point_has_a_default(self):
        for function in (validate_result, verify_attempt):
            for parameter in inspect.signature(function).parameters.values():
                self.assertIs(parameter.default, inspect.Parameter.empty, f"{function.__name__}.{parameter.name}")

    def test_omitting_any_validate_result_argument_is_a_type_error(self):
        case = GOLDENS["binary-ok-with-gaps"]()
        docs = case["documents"]
        full = {"contract_id": BINARY, "node_status": case["status"], "result": docs["result"],
                "tool_results": docs["tool-results"], "coverage": docs["coverage"],
                "probe_receipt": docs["probe-receipt"], "declared_tool_ids": docs["declared-tools"],
                "permitted_node_statuses": PERMITTED[BINARY]}
        self.assertEqual(validate_result(**full), [])
        for name in full:
            with self.assertRaises(TypeError, msg=name):
                validate_result(**{k: v for k, v in full.items() if k != name})

    def test_omitting_any_verify_attempt_argument_is_a_type_error(self):
        case = GOLDENS["binary-ok-with-gaps"]()
        with tempfile.TemporaryDirectory() as tmp:
            attempt, inputs = materialize(case, Path(tmp))
            full = {"contract_id": BINARY, "attempt_root": attempt, "inputs_root": inputs,
                    "expected_header": header(BINARY), "expected_dagster_run_id": DAGSTER_RUN_ID,
                    "node_status": case["status"],
                    "declared_tool_ids": TOOLS[BINARY], "permitted_node_statuses": PERMITTED[BINARY],
                    "on_unhandled": POLICY, "limits": LIMITS}
            self.assertEqual(verify_attempt(**full), [])
            for name in full:
                with self.assertRaises(TypeError, msg=name):
                    verify_attempt(**{k: v for k, v in full.items() if k != name})
            for name, bad in (("attempt_root", None), ("inputs_root", ""), ("limits", None),
                              ("expected_header", {"run_id": "x"}), ("expected_dagster_run_id", None),
                              ("expected_dagster_run_id", ""), ("expected_dagster_run_id", "has space")):
                with self.assertRaises(TypeError, msg=name):
                    verify_attempt(**{**full, name: bad})

    def test_unknown_contract_and_string_tool_ids_are_refused(self):
        case = GOLDENS["mobile-skipped"]()
        docs = case["documents"]
        with self.assertRaises(ValueError):
            validate_result("binary-intelligence", "SKIPPED", docs["result"], docs["tool-results"], docs["coverage"],
                            docs["probe-receipt"], docs["declared-tools"], PERMITTED[MOBILE])
        with self.assertRaises(TypeError):
            check(case, declared_tool_ids="mobsfscan-android")
        with self.assertRaises(ValueError):
            check(case, declared_tool_ids=[])

    def test_the_module_keeps_no_mutable_authority_and_never_mutates_its_input(self):
        with self.assertRaises(TypeError):
            contracts.CONTRACTS["mobile-sast"]["probe_receipt"] = "outputs/other.json"
        with self.assertRaises(TypeError):
            contracts.CONTRACTS["extra"] = {}
        with self.assertRaises(TypeError):
            contracts.CHECK_FORMATS["relro"] = ("pe",)
        case = GOLDENS["container-ok-with-gaps"]()
        before = deepcopy(case["documents"])
        first = check(case)
        first.append("caller-edit")
        self.assertEqual(check(case), [])
        self.assertEqual(case["documents"], before)


class ProbeReceiptTests(unittest.TestCase):
    """Acceptance: a mobile result without mobile-applicability.json is rejected (G6 = A reconciliation)."""

    def test_a_result_without_a_probe_receipt_is_rejected_for_every_contract_and_status(self):
        for name, build in GOLDENS.items():
            case = build()
            errors = check(case, probe_receipt=None)
            self.assertEqual(names(errors), {"probe-receipt-missing"}, name)
            self.assertIn(contracts.CONTRACTS[case["contract_id"]]["probe_receipt"], errors[0])

    def test_a_published_mobile_attempt_without_mobile_applicability_json_is_rejected(self):
        for name in ("mobile-ok-android-only", "mobile-skipped"):
            case = GOLDENS[name]()
            with tempfile.TemporaryDirectory() as tmp:
                attempt, inputs = materialize(case, Path(tmp))
                (attempt / "outputs" / "mobile-applicability.json").unlink()
                errors = verify(case, attempt, inputs)
                self.assertEqual(names(errors), {"probe-receipt-missing"}, name)
                self.assertIn("mobile-applicability.json", errors[0])

    def test_a_receipt_under_another_name_does_not_satisfy_the_contract(self):
        case = GOLDENS["mobile-ok-android-only"]()
        with tempfile.TemporaryDirectory() as tmp:
            attempt, inputs = materialize(case, Path(tmp))
            outputs = attempt / "outputs"
            (outputs / "mobile-applicability.json").rename(outputs / "applicability.json")
            self.assertEqual(names(verify(case, attempt, inputs)), {"probe-receipt-missing"})

    def test_the_receipt_is_bound_to_the_node_status_and_to_the_platform_markers(self):
        case = GOLDENS["mobile-ok-android-only"]()
        self.assertIn("node-skipped-with-inputs", names(check(case, status="SKIPPED")))
        skipped = GOLDENS["mobile-skipped"]()
        self.assertIn("node-not-skipped-with-zero-inputs", names(check(skipped, status="OK")))
        flipped = deepcopy(case)
        flipped["documents"]["result"]["platforms"][1]["marker_present"] = True
        self.assertEqual(names(check(flipped)), {"marker-probe-mismatch"})
        # the wrong party: a receipt for another node
        other = deepcopy(case)
        other["documents"]["probe-receipt"]["job_id"] = "02-binary-hardening"
        self.assertIn("header-mismatch", names(check(other)))

    def test_a_skipped_node_cannot_carry_records(self):
        ok = GOLDENS["mobile-ok-android-only"]()
        skipped = GOLDENS["mobile-skipped"]()
        skipped["documents"]["result"]["rule_hits"] = deepcopy(ok["documents"]["result"]["rule_hits"][:1])
        found = names(check(skipped))
        self.assertIn("skipped-node-with-records", found)
        self.assertIn("hit-without-marker", found)


class RuntimeStateTests(unittest.TestCase):
    """Acceptance: mutations asserting runtime state are rejected."""

    RUNTIME_FIELDS = {"running": True, "listening_ports": [8443], "reachable": True, "deployed": True,
                      "exploited": False, "observed_at": "2026-09-20T12:00:00Z", "runtime_state": "up",
                      "container_id": "abc123", "started_at": "2026-09-20T12:00:00Z", "registry": "docker.io",
                      "pulled_at": "2026-09-20T12:00:00Z", "repo_digest_resolved_at": "2026-09-20T12:00:00Z",
                      "exec": ["id"], "runtime": "runc", "overall": "pass", "secure": True, "severity": "high"}

    def targets(self, case):
        result = case["documents"]["result"]
        yield result
        if case["contract_id"] == CONTAINER:
            image = result["images"][0]
            yield from (image, image["source"], image["config"], image["config"]["declared_ports"][0], image["layers"][0])
        elif case["contract_id"] == MOBILE:
            yield from (result["platforms"][0], result["rule_hits"][0])
        else:
            binary = result["binaries"][0]
            yield from (binary, binary["checks"], binary["rule_hits"][0])

    def test_no_object_anywhere_accepts_a_runtime_pull_start_or_rollup_field(self):
        for name in ("container-ok-with-gaps", "mobile-ok-android-only", "binary-ok-with-gaps"):
            baseline = GOLDENS[name]()
            for index, _ in enumerate(self.targets(baseline)):
                for field, value in self.RUNTIME_FIELDS.items():
                    case = deepcopy(baseline)
                    list(self.targets(case))[index][field] = value
                    errors = check(case)
                    self.assertEqual(names(errors), {"schema"}, f"{name} target {index} accepted {field}")
                    self.assertTrue(any(field in error for error in errors))

    def test_no_enum_accepts_a_runtime_value(self):
        mutations = [
            ("container-ok-with-gaps", lambda r: r["images"][0]["source"].__setitem__("kind", "registry-pull")),
            ("container-ok-with-gaps", lambda r: r["images"][0]["source"].__setitem__("kind", "running-container")),
            ("container-ok-with-gaps", lambda r: r["images"][0].__setitem__("inspection", "started")),
            ("container-ok-with-gaps", lambda r: r["images"][0]["config"]["declared_ports"][0].__setitem__("exposure_label", "LISTENING")),
            ("binary-ok-with-gaps", lambda r: r["binaries"][0]["checks"].__setitem__("relro", "enforced-at-runtime")),
            ("binary-ok-with-gaps", lambda r: r["binaries"][0]["checks"].__setitem__("relro", "pass")),
            ("mobile-ok-android-only", lambda r: r["rule_hits"][0].__setitem__("category", "exploited-in-production")),
        ]
        for name, mutate in mutations:
            case = GOLDENS[name]()
            mutate(case["documents"]["result"])
            self.assertEqual(names(check(case)), {"schema"}, name)

    def test_observed_exposure_is_schema_valid_and_rejected_by_name(self):
        case = GOLDENS["container-ok-with-gaps"]()
        case["documents"]["result"]["images"][0]["config"]["declared_ports"][0]["exposure_label"] = "OBSERVED_EXPOSURE"
        self.assertEqual(validate_document(case["documents"]["result"], "container-image-inventory.schema.json"), [])
        errors = check(case)
        self.assertEqual(names(errors), {"observed-exposure"})
        self.assertIn("DECLARED_EXPOSURE", errors[0])

    def test_an_image_reference_or_registry_path_cannot_stand_in_for_a_supplied_archive(self):
        for bad in ("docker.io/library/nginx:latest", "registry.example/app@sha256:" + "0" * 64, "https://r.example/v2/app"):
            case = GOLDENS["container-ok-with-gaps"]()
            case["documents"]["result"]["images"][0]["source"]["archive_path"] = bad
            self.assertEqual(names(check(case)), {"schema"}, bad)

    def test_the_claim_class_forbids_runtime_state_promotion(self):
        for contract_id in CONTRACT_IDS:
            contract = json.loads((REGISTRY / f"{contract_id}.json").read_text(encoding="utf-8"))
            self.assertIn("runtime-state", contract["claim_class"]["forbidden_promotions"])
            self.assertTrue(any("runtime" in rule for rule in contract["validation_rules"]))


class ContainerRuleTests(unittest.TestCase):
    def case(self):
        return GOLDENS["container-ok-with-gaps"]()

    def expect(self, mutate, expected, exact=True):
        case = self.case()
        mutate(case["documents"])
        found = names(check(case))
        if exact:
            self.assertEqual(found, {expected})
        else:
            self.assertIn(expected, found)

    def test_environment_values_are_rejected_by_name(self):
        generated = hashlib.sha256(os.urandom(16)).hexdigest()[:24]

        def with_value(docs):
            docs["result"]["images"][0]["config"]["declared_env_names"].append("API_TOKEN=" + generated)

        def with_map(docs):
            docs["result"]["images"][0]["config"]["declared_env"] = {"API_TOKEN": generated}

        for mutate in (with_value, with_map):
            case = self.case()
            mutate(case["documents"])
            errors = check(case)
            self.assertIn("env-value-present", names(errors))
            self.assertFalse(any(generated in error for error in errors), "an error message echoed the value")

    def test_entrypoint_arguments_have_no_field(self):
        self.expect(lambda d: d["result"]["images"][0]["config"].__setitem__("declared_entrypoint", ["/bin/app", "--flag"]), "schema")

    def test_unsupported_archive_rules_are_bound_both_ways(self):
        self.expect(lambda d: d["result"]["images"][2].__setitem__("inspection", "inspected"), "inspection-coverage-mismatch", exact=False)
        self.expect(lambda d: d["result"]["images"][2].__setitem__("inspection", "inspected"), "unsupported-format-inspected", exact=False)
        self.expect(lambda d: d["result"]["images"][2].__setitem__("image_manifest_digest", sha("x")), "not-inspected-image-with-facts")
        self.expect(lambda d: d["result"]["images"][2].__setitem__("archive_format", "docker-save"), "unsupported-format-not-in-coverage")
        self.expect(lambda d: d["result"]["images"][0].__setitem__("archive_format", "unsupported"), "unsupported-format-not-in-coverage", exact=False)
        self.expect(lambda d: d["result"]["images"][0].__setitem__("inspection", "not-inspected"), "inspection-coverage-mismatch", exact=False)
        self.expect(lambda d: d["result"]["images"][0].__setitem__("config", None), "inspected-image-incomplete")

    def test_records_and_coverage_describe_the_same_archives(self):
        self.expect(lambda d: d["result"]["images"].pop(1), "coverage-record-mismatch")
        self.expect(lambda d: d["coverage"]["tools"][0]["unsupported_inputs"][0].__setitem__("path", "images/other.aci"),
                    "coverage-record-mismatch", exact=False)

        def truncate(docs):
            for tool in docs["coverage"]["tools"]:
                tool["unsupported_inputs"] = []
                tool["input_lists_truncated"] = True

        self.expect(truncate, "coverage-list-truncated", exact=False)

    def test_ids_layers_ports_and_tools_are_bound(self):
        self.expect(lambda d: d["result"]["images"][1].__setitem__("image_id", d["result"]["images"][0]["image_id"]), "duplicate-record")
        self.expect(lambda d: d["result"]["images"][0].__setitem__("tool_id", "trivy"), "unknown-tool")
        self.expect(lambda d: d["result"]["images"][0]["packages"][0].__setitem__("tool_id", "trivy"), "unknown-tool")
        self.expect(lambda d: d["result"]["images"][0]["packages"][0].__setitem__("layer_index", 9), "layer-index")
        self.expect(lambda d: d["result"]["images"][0]["layers"][1].__setitem__("layer_index", 5), "layer-index", exact=False)
        self.expect(lambda d: d["result"]["images"][0]["config"]["declared_ports"][0].__setitem__("port", 70000), "port-range")
        self.expect(lambda d: d["result"]["images"][0]["config"]["declared_ports"][0].__setitem__("port", 0), "port-range")
        self.expect(lambda d: d["result"]["images"][0]["config"]["declared_ports"].append(
            deepcopy(d["result"]["images"][0]["config"]["declared_ports"][0])), "duplicate-record")
        self.expect(lambda d: d["result"]["images"][0]["config"]["declared_env_names"].append("PATH"), "duplicate-record")
        self.expect(lambda d: d["result"]["images"][0]["config"].__setitem__("declared_command_argument_count", 3), "config-count")
        self.expect(lambda d: d["result"]["images"][0]["source"].__setitem__("archive_bytes", -1), "input-size")

    def test_header_fields_are_each_bound(self):
        for field, value in (("run_id", "another-run"), ("attempt_id", "node-attempt-0002"),
                             ("source_snapshot_sha256", sha("other"))):
            self.expect(lambda d, f=field, v=value: d["result"].__setitem__(f, v), "header-mismatch")
        self.expect(lambda d: d["result"].__setitem__("job_id", "02-binary-hardening"), "schema")

    def test_packages_need_a_tool_with_output(self):
        package_tool = TOOLS[CONTAINER][1]
        case = container_case([("images/api.oci.tar", "oci-layout", "inspected")])
        other = build_instance(package_tool, "BLOCKED", [], None)
        docs = case["documents"]
        docs["tool-results"]["tool_instances"][1] = other
        tool = docs["coverage"]["tools"][1]
        tool.update({"analyzed_input_count": 0, "not_analyzed_input_count": 1,
                     "not_analyzed_inputs": [{"path": "images/api.oci.tar", "reason_code": "tool-instance-did-not-complete"}]})
        docs["coverage"]["gaps"] += [
            {"gap_id": "gap-blocked", "kind": "tool-instance-blocked", "tool_id": package_tool, "affected_input_count": None},
            {"gap_id": "gap-na", "kind": "inputs-not-analyzed", "tool_id": package_tool, "affected_input_count": 1}]
        found = names(check(case, status="OK_WITH_GAPS"))
        self.assertEqual(found, {"result-from-tool-without-output", "result-from-uncovered-input"})
        image = docs["result"]["images"][0]
        image["packages"], image["hardening_rule_hits"] = [], []
        self.assertEqual(check(case, status="OK_WITH_GAPS"), [])


class MobileRuleTests(unittest.TestCase):
    def expect(self, mutate, expected, exact=True):
        case = GOLDENS["mobile-ok-android-only"]()
        mutate(case["documents"])
        found = names(check(case))
        self.assertEqual(found, {expected}) if exact else self.assertIn(expected, found)

    def test_a_hit_has_no_home_for_a_message_or_a_snippet(self):
        matched_line = "val pass" + "word = \"" + hashlib.sha256(os.urandom(8)).hexdigest()[:20] + "\""
        for field in ("message", "snippet", "matched_text", "description", "severity", "level"):
            self.expect(lambda d, f=field: d["result"]["rule_hits"][0].__setitem__(f, matched_line), "schema")
        for field in ("rule_id", "file_path", "hit_id"):
            self.expect(lambda d, f=field: d["result"]["rule_hits"][0].__setitem__(f, matched_line), "schema")

    def test_platform_tool_and_count_bindings(self):
        ios_tool = TOOLS[MOBILE][1]
        self.expect(lambda d: d["result"]["rule_hits"][0].__setitem__("platform", "ios"), "hit-platform-mismatch")
        self.expect(lambda d: d["result"]["rule_hits"][0].update({"platform": "ios", "tool_id": ios_tool}), "hit-without-marker", exact=False)
        self.expect(lambda d: d["result"]["rule_hits"][0].__setitem__("tool_id", "semgrep"), "unknown-tool", exact=False)
        self.expect(lambda d: d["result"]["rule_hits"].pop(), "record-count-mismatch")
        self.expect(lambda d: d["tool-results"]["tool_instances"][0].__setitem__("result_record_count", 9), "record-count-mismatch")
        self.expect(lambda d: d["result"]["rule_hits"][1].__setitem__("hit_id", "hit-0001"), "duplicate-record")
        self.expect(lambda d: d["result"]["platforms"].pop(1), "platform-missing")
        self.expect(lambda d: d["result"]["platforms"][1].__setitem__("platform", "android"), "duplicate-record", exact=False)
        self.expect(lambda d: d["result"]["platforms"][1].__setitem__("tool_id", TOOLS[MOBILE][0]), "duplicate-record", exact=False)
        self.expect(lambda d: d["result"]["rule_hits"][0].__setitem__("line", 0), "hit-line")

    def test_server_side_source_counts_are_not_a_marker(self):
        # bare *.kt files without a platform marker: the probe reports zero, so the node is SKIPPED and a
        # result claiming a marker disagrees with the receipt.
        case = GOLDENS["mobile-skipped"]()
        case["documents"]["result"]["platforms"][0]["marker_present"] = True
        self.assertEqual(names(check(case)), {"marker-probe-mismatch"})

    def test_cited_source_is_bound_to_the_snapshot_bytes(self):
        base = GOLDENS["mobile-ok-android-only"]()
        with tempfile.TemporaryDirectory() as tmp:
            attempt, inputs = materialize(base, Path(tmp))
            (inputs / ANDROID[1]).write_bytes(input_bytes(ANDROID[1]) + b"// edited\n")
            self.assertEqual(names(verify(base, attempt, inputs)), {"input-hash-mismatch"})
            (inputs / ANDROID[1]).unlink()
            self.assertEqual(names(verify(base, attempt, inputs)), {"input-missing"})
        beyond = GOLDENS["mobile-ok-android-only"]()
        beyond["documents"]["result"]["rule_hits"][0]["line"] = 21
        with tempfile.TemporaryDirectory() as tmp:
            attempt, inputs = materialize(beyond, Path(tmp))
            self.assertEqual(names(verify(beyond, attempt, inputs)), {"hit-line"})


class BinaryRuleTests(unittest.TestCase):
    """Acceptance: a hardening 'pass' for an unsupported format is rejected."""

    UNSUPPORTED, PARSE_FAILED, PE, ELF = 3, 4, 0, 1

    def expect(self, mutate, expected, exact=True):
        case = GOLDENS["binary-ok-with-gaps"]()
        mutate(case["documents"])
        found = names(check(case))
        self.assertEqual(found, {expected}) if exact else self.assertIn(expected, found)

    def test_an_unsupported_format_can_never_carry_present_or_absent(self):
        for check_name in contracts.CHECK_FORMATS:
            for verdict in ("present", "absent"):
                case = GOLDENS["binary-ok-with-gaps"]()
                case["documents"]["result"]["binaries"][self.UNSUPPORTED]["checks"][check_name] = verdict
                errors = check(case)
                self.assertIn("unsupported-format-assessed", names(errors), f"{check_name}={verdict}")
                self.assertTrue(any(f"{check_name}={verdict}" in error for error in errors))
        self.expect(lambda d: d["result"]["binaries"][self.UNSUPPORTED]["checks"].__setitem__("relro", "not-applicable-for-format"),
                    "unsupported-format-assessed", exact=False)

    def test_there_is_no_pass_value_and_no_rollup_field(self):
        for value in ("pass", "passed", "secure", "ok", "fail"):
            self.expect(lambda d, v=value: d["result"]["binaries"][self.UNSUPPORTED]["checks"].__setitem__("relro", v), "schema")
        for field in ("overall", "verdict", "pass", "secure", "score", "hardened", "grade"):
            self.expect(lambda d, f=field: d["result"]["binaries"][self.PE].__setitem__(f, "pass"), "schema")
            self.expect(lambda d, f=field: d["result"].__setitem__(f, "pass"), "schema")

    def test_a_format_the_tool_does_not_support_per_coverage_cannot_be_assessed(self):
        # The ELF binary is relabelled in coverage as unsupported by this tool instance (e.g. a PE-only build).
        def tool_does_not_support_elf(docs):
            tool = docs["coverage"]["tools"][0]
            path = docs["result"]["binaries"][self.ELF]["path"]
            tool["unsupported_inputs"].append({"path": path, "reason_code": "unsupported-format"})
            tool["unsupported_inputs"].sort(key=lambda entry: entry["path"])
            tool["unsupported_input_count"] += 1
            tool["analyzed_input_count"] -= 1
            for gap in docs["coverage"]["gaps"]:
                if gap["kind"] == "inputs-unsupported":
                    gap["affected_input_count"] += 1

        case = GOLDENS["binary-ok-with-gaps"]()
        tool_does_not_support_elf(case["documents"])
        self.assertEqual(names(check(case)), {"unsupported-format-assessed", "assessment-coverage-mismatch"})
        binary = case["documents"]["result"]["binaries"][self.ELF]
        binary["checks"] = binary_checks("elf", assessed=False)
        self.assertEqual(check(case), [])

    def test_unsupported_in_the_result_must_be_unsupported_in_coverage_and_vice_versa(self):
        def drop_from_coverage(docs):
            tool = docs["coverage"]["tools"][0]
            tool["unsupported_inputs"], tool["unsupported_input_count"] = [], 0
            tool["analyzed_input_count"] += 1
            docs["coverage"]["gaps"] = [g for g in docs["coverage"]["gaps"] if g["kind"] != "inputs-unsupported"]

        case = GOLDENS["binary-ok-with-gaps"]()
        drop_from_coverage(case["documents"])
        self.assertEqual(names(check(case)), {"unsupported-format-not-in-coverage", "assessment-coverage-mismatch"})
        # wrong reason code: listed, but not as an unsupported FORMAT
        self.expect(lambda d: d["coverage"]["tools"][0]["unsupported_inputs"][0].__setitem__("reason_code", "encrypted-or-packed"),
                    "unsupported-format-not-in-coverage")
        # an assessed binary relabelled unsupported
        self.expect(lambda d: d["result"]["binaries"][self.PE].__setitem__("format", "unsupported"), "unsupported-format-assessed", exact=False)
        # a parse-failed binary given a verdict
        self.expect(lambda d: d["result"]["binaries"][self.PARSE_FAILED]["checks"].__setitem__("relro", "present"),
                    "assessment-coverage-mismatch")
        # an assessed binary blanked without a coverage entry
        self.expect(lambda d: d["result"]["binaries"][self.PE].update({"checks": binary_checks("pe", False), "rule_hits": []}),
                    "assessment-coverage-mismatch")

    def test_invariant_a_binary_is_in_coverage_gaps_iff_all_its_checks_are_not_assessed(self):
        paths = ["bin/a.dll", "bin/b.so", "bin/c.dylib"]
        options = [("pe", "assessed"), ("elf", "assessed"), ("macho", "assessed"), ("unsupported", "unsupported-format"),
                   ("elf", "unsupported-format"), ("pe", "parse-failed")]
        cases = 0
        for combo in itertools.product(options, repeat=len(paths)):
            for failed in (False, True):
                case = binary_case([(p, f, s) for p, (f, s) in zip(paths, combo)], failed=failed)
                status = case["status"] if not failed else "FAILED"
                self.assertEqual(check(case, status=status), [], f"{combo} failed={failed}")
                tool = case["documents"]["coverage"]["tools"][0]
                gap_paths = {e["path"] for e in tool["unsupported_inputs"] + tool["not_analyzed_inputs"]}
                for binary in case["documents"]["result"]["binaries"]:
                    blank = all(v == "not-assessed" for v in binary["checks"].values())
                    self.assertEqual(blank, binary["path"] in gap_paths)
                    if binary["format"] == "unsupported":
                        self.assertTrue(blank)
                        self.assertIn({"path": binary["path"], "reason_code": "unsupported-format"}, tool["unsupported_inputs"])
                # flipping any one blank check to a verdict always breaks the invariant and is rejected
                for index, binary in enumerate(case["documents"]["result"]["binaries"]):
                    if all(v == "not-assessed" for v in binary["checks"].values()):
                        mutated = deepcopy(case)
                        mutated["documents"]["result"]["binaries"][index]["checks"]["position_independent"] = "present"
                        self.assertTrue(check(mutated, status=status), f"{combo} accepted a verdict on a blank binary")
                cases += 1
        self.assertEqual(cases, 2 * len(options) ** len(paths))

    def test_check_applicability_per_format_is_bound_both_ways(self):
        self.expect(lambda d: d["result"]["binaries"][self.PE]["checks"].__setitem__("relro", "present"), "check-format-mismatch")
        self.expect(lambda d: d["result"]["binaries"][self.ELF]["checks"].__setitem__("safe_seh", "absent"), "check-format-mismatch")
        self.expect(lambda d: d["result"]["binaries"][self.ELF]["checks"].__setitem__("relro", "not-applicable-for-format"), "check-format-mismatch")
        partial = GOLDENS["binary-ok-with-gaps"]()
        partial["documents"]["result"]["binaries"][self.ELF]["checks"]["relro"] = "not-assessed"
        self.assertEqual(check(partial), [], "a partially assessed binary is a valid state")

    def test_rule_hits_records_and_raw_output_are_bound(self):
        self.expect(lambda d: d["result"]["binaries"][self.UNSUPPORTED]["rule_hits"].append({"rule_id": "BA2001", "check": "other"}),
                    "rule-hit-on-unassessed-binary")
        self.expect(lambda d: d["result"]["binaries"][self.ELF]["rule_hits"].append({"rule_id": "BA2008", "check": "control_flow_guard"}),
                    "rule-hit-on-unassessed-binary")
        self.expect(lambda d: d["tool-results"]["tool_instances"][0].__setitem__("result_record_count", 4), "record-count-mismatch")
        self.expect(lambda d: d["result"]["binaries"][self.PE].__setitem__("tool_id", "checksec"), "unknown-tool", exact=False)
        self.expect(lambda d: d["tool-results"]["tool_instances"][0]["outputs"][0].__setitem__("path", "outputs/other.sarif"), "raw-output-missing")
        self.expect(lambda d: d["tool-results"]["tool_instances"][0]["outputs"][0].__setitem__("role", "normalized-result"), "raw-output-missing")
        self.expect(lambda d: d["result"]["binaries"][1].__setitem__("path", d["result"]["binaries"][0]["path"]), "duplicate-record", exact=False)

    def test_the_listed_format_is_rederived_from_the_leading_bytes(self):
        for data, expected in ((b"MZ\x90\x00", "pe"), (b"\x7fELF\x02", "elf"), (b"\xcf\xfa\xed\xfe", "macho"),
                               (b"\xca\xfe\xba\xbe", "macho"), (b"#!/bin/sh\n", "unsupported"), (b"", "unsupported")):
            self.assertEqual(contracts.detect_format(data), expected)
        # an unsupported blob relabelled as a supported format, consistently in result AND coverage, so
        # that only the bytes can contradict it
        honest = binary_case([("bin/blob.bin", "unsupported", "unsupported-format")])
        forged = binary_case([("bin/blob.bin", "elf", "assessed")])
        forged["inputs"] = honest["inputs"]
        record = forged["documents"]["result"]["binaries"][0]
        record["sha256"], record["bytes"] = sha_bytes(honest["inputs"]["bin/blob.bin"]), len(honest["inputs"]["bin/blob.bin"])
        self.assertEqual(check(forged), [])
        with tempfile.TemporaryDirectory() as tmp:
            attempt, inputs = materialize(forged, Path(tmp))
            errors = verify(forged, attempt, inputs)
            self.assertEqual(names(errors), {"input-format-mismatch"})
            self.assertIn("'unsupported'", errors[0])
        # and the other direction: a real ELF hidden as unsupported
        hidden = binary_case([("bin/real.so", "unsupported", "unsupported-format")])
        hidden["inputs"]["bin/real.so"] = input_bytes("bin/real.so", "elf")
        record = hidden["documents"]["result"]["binaries"][0]
        record["sha256"], record["bytes"] = sha_bytes(hidden["inputs"]["bin/real.so"]), len(hidden["inputs"]["bin/real.so"])
        with tempfile.TemporaryDirectory() as tmp:
            attempt, inputs = materialize(hidden, Path(tmp))
            self.assertEqual(names(verify(hidden, attempt, inputs)), {"input-format-mismatch"})

    def test_a_failed_tool_supports_no_verdict(self):
        case = binary_case([("bin/a.dll", "pe", "assessed")], failed=True)
        self.assertEqual(check(case, status="FAILED"), [])
        case["documents"]["result"]["binaries"][0]["checks"] = binary_checks("pe", True)
        self.assertEqual(names(check(case, status="FAILED")), {"assessment-coverage-mismatch", "result-from-tool-without-output"})


class PathAndBytesTests(unittest.TestCase):
    def test_non_normalized_and_escaping_paths_are_rejected(self):
        for bad, expected in (("vendor/./win/agent.dll", "input-path"), ("vendor//win/agent.dll", "input-path"),
                              ("vendor/x/../win/agent.dll", "input-path"), ("../outside.dll", "input-path"),
                              ("./vendor/win/agent.dll", "input-path"), ("vendor/win/agent.dll/", "input-path"),
                              ("/etc/passwd", "schema"), ("C:\\vendor\\agent.dll", "schema"), ("", "schema")):
            case = GOLDENS["binary-ok-with-gaps"]()
            case["documents"]["result"]["binaries"][0]["path"] = bad
            self.assertIn(expected, names(check(case)), bad)
            container = GOLDENS["container-ok-with-gaps"]()
            container["documents"]["result"]["images"][0]["source"]["archive_path"] = bad
            self.assertIn(expected, names(check(container)), bad)
            mobile = GOLDENS["mobile-ok-android-only"]()
            mobile["documents"]["result"]["rule_hits"][0]["file_path"] = bad
            self.assertIn(expected, names(check(mobile)), bad)

    def test_each_listed_hash_and_size_is_bound_to_the_input_bytes(self):
        for name, path in (("container-ok-with-gaps", "images/api.oci.tar"), ("binary-ok-with-gaps", "vendor/win/agent.dll")):
            case = GOLDENS[name]()
            with tempfile.TemporaryDirectory() as tmp:
                attempt, inputs = materialize(case, Path(tmp))
                original = (inputs / path).read_bytes()
                (inputs / path).write_bytes(original[:-1] + b"\x01")
                self.assertEqual(names(verify(case, attempt, inputs)), {"input-hash-mismatch"}, name)
                (inputs / path).write_bytes(original + b"\x00")
                self.assertEqual(names(verify(case, attempt, inputs)), {"input-hash-mismatch", "input-size"}, name)
                (inputs / path).unlink()
                self.assertEqual(names(verify(case, attempt, inputs)), {"input-missing"}, name)
                # the wrong root: the attempt is not the inputs root
                self.assertIn("input-missing", names(verify(case, attempt, attempt)), name)
        # editing ONLY the listed value, with the bytes untouched
        for name, edit in (
            ("container-ok-with-gaps", lambda r: r["images"][0]["source"].__setitem__("archive_sha256", sha("forged"))),
            ("binary-ok-with-gaps", lambda r: r["binaries"][0].__setitem__("sha256", sha("forged"))),
            ("mobile-ok-android-only", lambda r: r["rule_hits"][0].__setitem__("file_sha256", sha("forged"))),
        ):
            case = GOLDENS[name]()
            edit(case["documents"]["result"])
            with tempfile.TemporaryDirectory() as tmp:
                attempt, inputs = materialize(case, Path(tmp))
                self.assertEqual(names(verify(case, attempt, inputs)), {"input-hash-mismatch"}, name)
        for name, edit in (
            ("container-ok-with-gaps", lambda r: r["images"][0]["source"].__setitem__("archive_bytes", 1)),
            ("binary-ok-with-gaps", lambda r: r["binaries"][0].__setitem__("bytes", 1)),
        ):
            case = GOLDENS[name]()
            edit(case["documents"]["result"])
            with tempfile.TemporaryDirectory() as tmp:
                attempt, inputs = materialize(case, Path(tmp))
                self.assertEqual(names(verify(case, attempt, inputs)), {"input-size"}, name)

    def test_published_documents_are_reread_from_bytes_and_bound_to_the_receipt_and_the_envelope(self):
        case = GOLDENS["binary-ok-with-gaps"]()
        with tempfile.TemporaryDirectory() as tmp:
            attempt, inputs = materialize(case, Path(tmp))
            for field, value in (("run_id", "another-run"), ("attempt_id", "node-attempt-0009"),
                                 ("source_snapshot_sha256", sha("other-snapshot"))):
                errors = verify(case, attempt, inputs, expected_header={**header(BINARY), field: value})
                # status.json is bound to the envelope too, so a different attempt_id shows up twice
                expected = {"header-mismatch", "status-mismatch"} if field == "attempt_id" else {"header-mismatch"}
                self.assertEqual(names(errors), expected, field)
            self.assertEqual(names(verify(case, attempt, inputs, expected_header={**header(BINARY), "job_id": "02-mobile-sast"})),
                             {"header-mismatch"})
            # the wrong policy and the wrong limits are the consumer's to demand
            self.assertEqual(names(verify(case, attempt, inputs, on_unhandled="withhold")), {"redaction-receipt"})
            tighter = evidence_redaction.Limits(**{**LIMITS.__dict__, "max_files": LIMITS.max_files - 1})
            self.assertEqual(names(verify(case, attempt, inputs, limits=tighter)), {"redaction-receipt"})
            # the wrong state: the in-memory case says OK_WITH_GAPS; the caller's envelope says OK
            self.assertIn("node-ok-with-gaps", names(verify(case, attempt, inputs, node_status="OK")))
            # a published result edited after the receipt was sealed
            result_path = attempt / contracts.CONTRACTS[BINARY]["result"]
            document = json.loads(result_path.read_text(encoding="utf-8"))
            document["binaries"][3]["checks"]["relro"] = "present"
            result_path.write_bytes(dump(document))
            # The receipt is verified FIRST. Once it fails nothing else is parsed, so the edited
            # document's content is never inspected or reported (PR 19 review).
            self.assertEqual(names(verify(case, attempt, inputs)), {"redaction-receipt"})

    def test_raw_tool_output_is_bound_to_the_attempt_bytes(self):
        case = GOLDENS["binary-ok-with-gaps"]()
        with tempfile.TemporaryDirectory() as tmp:
            attempt, inputs = materialize(case, Path(tmp))
            (attempt / contracts.BINSKIM_SARIF).write_bytes(dump({"version": "2.1.0", "runs": [], "extra": 1}))
            self.assertEqual(names(verify(case, attempt, inputs)), {"redaction-receipt"})
            (attempt / "outputs" / "unlisted.json").write_bytes(dump({}))
            self.assertIn("redaction-receipt", names(verify(case, attempt, inputs)))

    def test_required_files_missing_unreadable_or_with_duplicate_keys_are_rejected(self):
        case = GOLDENS["container-ok-with-gaps"]()
        for relative, expected in (("manifest.json", "required-file-missing"), ("status.json", "required-file-missing"),
                                   (contracts.COVERAGE, "required-file-missing"),
                                   (contracts.CONTRACTS[CONTAINER]["probe_receipt"], "probe-receipt-missing")):
            with tempfile.TemporaryDirectory() as tmp:
                attempt, inputs = materialize(case, Path(tmp))
                (attempt / relative).unlink()
                self.assertEqual(names(verify(case, attempt, inputs)), {expected}, relative)
        with tempfile.TemporaryDirectory() as tmp:
            attempt, inputs = materialize(case, Path(tmp))
            # a published document edited after sealing fails the receipt before it is ever parsed
            (attempt / contracts.CONTRACTS[CONTAINER]["result"]).write_bytes(b'{"schema": 1, "schema": 2}')
            self.assertEqual(names(verify(case, attempt, inputs)), {"redaction-receipt"})
        for relative in ("status.json", "manifest.json"):   # outside outputs/: parsed strictly on their own
            with tempfile.TemporaryDirectory() as tmp:
                attempt, inputs = materialize(case, Path(tmp))
                (attempt / relative).write_bytes(b'{"status": "OK", "status": "FAILED"}')
                self.assertEqual(names(verify(case, attempt, inputs)), {"required-file-unreadable"}, relative)
        with tempfile.TemporaryDirectory() as tmp:
            attempt, inputs = materialize(case, Path(tmp))
            self.assertEqual(names(verify(case, Path(tmp) / "absent", inputs)), {"required-file-missing"})

    def test_a_symlinked_input_is_rejected(self):
        if not CAN_SYMLINK:
            self.assertNotEqual(os.name, "posix", "a POSIX host must be able to create a symlink")
            self.skipTest("symlinks are not available on this host")
        case = GOLDENS["binary-ok-with-gaps"]()
        with tempfile.TemporaryDirectory() as tmp:
            attempt, inputs = materialize(case, Path(tmp))
            target = inputs / "vendor/win/agent.dll"
            outside = Path(tmp) / "outside.dll"
            outside.write_bytes(target.read_bytes())
            target.unlink()
            os.symlink(outside, target)
            self.assertEqual(names(verify(case, attempt, inputs)), {"input-missing"})

    def test_one_file_under_two_names_is_decided_by_the_file_not_the_string(self):
        if not CAN_HARDLINK:
            self.assertNotEqual(os.name, "posix", "a POSIX host must be able to create a hard link")
            self.skipTest("hard links are not available on this host")
        case = binary_case([("bin/a.dll", "pe", "assessed"), ("bin/b.dll", "pe", "assessed")])
        first, second = case["documents"]["result"]["binaries"]
        second["sha256"], second["bytes"] = first["sha256"], first["bytes"]
        with tempfile.TemporaryDirectory() as tmp:
            attempt, inputs = materialize(case, Path(tmp))
            (inputs / "bin/b.dll").unlink()
            os.link(inputs / "bin/a.dll", inputs / "bin/b.dll")
            self.assertEqual(names(verify(case, attempt, inputs)), {"input-alias"})


class ErrorMessageTests(unittest.TestCase):
    def test_no_error_message_echoes_a_rejected_value(self):
        planted = "pl4nted" + hashlib.sha256(os.urandom(8)).hexdigest()[:16]
        edits = [
            ("mobile-ok-android-only", lambda r: r["rule_hits"][0].__setitem__("rule_id", "x = " + planted)),
            ("mobile-ok-android-only", lambda r: r["rule_hits"][0].__setitem__("message", planted)),
            ("mobile-ok-android-only", lambda r: r["rule_hits"][0].__setitem__(planted + " key", 1)),
            ("mobile-ok-android-only", lambda r: r["rule_hits"][0].__setitem__("category", planted)),
            ("container-ok-with-gaps", lambda r: r["images"][0]["config"]["declared_env_names"].append("A=" + planted)),
            ("container-ok-with-gaps", lambda r: r["images"][0]["config"].__setitem__("env", {"A": planted})),
            ("container-ok-with-gaps", lambda r: r["images"][0]["config"].__setitem__("declared_user", planted + " x")),
            ("binary-ok-with-gaps", lambda r: r.__setitem__("schema", planted)),
        ]
        for name, edit in edits:
            case = GOLDENS[name]()
            edit(case["documents"]["result"])
            errors = check(case)
            self.assertTrue(errors, name)
            self.assertFalse([error for error in errors if planted in error], name)

    def test_every_error_starts_with_a_stable_name(self):
        case = GOLDENS["binary-ok-with-gaps"]()
        docs = case["documents"]["result"]
        docs["binaries"][3]["checks"]["relro"] = "present"
        docs["binaries"][0]["path"] = "a/../b"
        docs["run_id"] = "zzz"
        errors = check(case)
        self.assertTrue(errors)
        for error in errors:
            self.assertRegex(error, r"^[a-z][a-z:-]*[a-z]: \S")


def regenerate_goldens() -> None:
    for name, build in GOLDENS.items():
        case = build()
        (FIXTURES / name).mkdir(parents=True, exist_ok=True)
        for part in DOCUMENTS:
            (FIXTURES / name / f"{part}.json").write_text(
                json.dumps(case["documents"][part], indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")



class ReceiptFirstAndStatusTests(unittest.TestCase):
    """PR 19 review. (1) The redaction receipt is the proof that the published documents are safe
    to read, so it is verified before any of them is parsed, and no value read from the attempt is
    ever echoed. (2) status.json is validated against the registered contract and bound to the
    node status and the worker envelope."""

    PLANT = "gh" + "p_" + "".join("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"[b % 57]
                                  for b in hashlib.sha256(b"pr19-plant").digest() * 2)[:36]
    QUIET = "hunter2-run-id"          # low entropy: the redactor does not see it, so the receipt stays valid

    def fresh(self, case_name="binary-ok-with-gaps", mutate=None):
        case = GOLDENS[case_name]()
        if mutate:
            mutate(case)
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        attempt, inputs = materialize(case, tmp)
        return case, attempt, inputs

    def published_documents(self, case, attempt):
        spec = contracts.CONTRACTS[case["contract_id"]]
        return [attempt / spec["result"], attempt / spec["probe_receipt"], attempt / contracts.TOOL_RESULTS,
                attempt / contracts.COVERAGE]

    def test_a_value_planted_after_sealing_is_never_echoed_and_only_the_receipt_is_reported(self):
        # The reviewer's case, for every published document and every header field.
        for index in range(4):
            for field in contracts.HEADER_FIELDS:
                case, attempt, inputs = self.fresh()
                path = self.published_documents(case, attempt)[index]
                document = json.loads(path.read_text(encoding="utf-8"))
                document[field] = self.PLANT
                path.write_bytes(dump(document))
                errors = verify(case, attempt, inputs)
                with self.subTest(document=path.name, field=field):
                    self.assertEqual(names(errors), {"redaction-receipt"})
                    self.assertFalse([e for e in errors if self.PLANT in e], "a planted value reached an error message")

    def test_nothing_is_parsed_once_the_receipt_fails(self):
        # Make a published document unparseable AND break the receipt: only the receipt is reported.
        case, attempt, inputs = self.fresh()
        self.published_documents(case, attempt)[0].write_bytes(b"{ this is not json " + self.PLANT.encode())
        errors = verify(case, attempt, inputs)
        self.assertEqual(names(errors), {"redaction-receipt"})
        self.assertFalse([e for e in errors if self.PLANT in e])

    def test_a_sealed_but_wrong_header_is_reported_without_quoting_the_document(self):
        # A worker that published the wrong run id and sealed it honestly: the receipt is VALID, so
        # the comparison does run. It may quote what the caller expected, never what the file said.
        def wrong_run(case):
            for name in ("result", "tool-results", "coverage", "probe-receipt"):
                case["documents"][name]["run_id"] = self.QUIET
        case, attempt, inputs = self.fresh(mutate=wrong_run)
        errors = verify(case, attempt, inputs)
        self.assertIn("header-mismatch", names(errors))
        self.assertFalse([e for e in errors if self.QUIET in e], errors)
        self.assertTrue(any(header(BINARY)["run_id"] in e for e in errors), "the expected value may be quoted")

    def test_in_memory_header_mismatch_does_not_quote_either_document(self):
        case = GOLDENS["binary-ok-with-gaps"]()
        case["documents"]["result"]["run_id"] = self.QUIET
        errors = check(case)
        self.assertIn("header-mismatch", names(errors))
        self.assertFalse([e for e in errors if e.startswith("header-mismatch: result.") and self.QUIET in e], errors)

    def test_the_reviewers_status_json_is_rejected(self):
        case, attempt, inputs = self.fresh()
        (attempt / "status.json").write_bytes(dump({"status": "FAILED", "attacker": self.PLANT}))
        errors = verify(case, attempt, inputs)
        self.assertEqual(names(errors), {"status-invalid", "status-mismatch"})
        self.assertFalse([e for e in errors if self.PLANT in e or "attacker" in e or "FAILED" in e], errors)

    def test_each_status_field_is_required_bound_and_never_quoted(self):
        good = status_document(GOLDENS["binary-ok-with-gaps"]())
        self.assertEqual(sorted(good), sorted(json.loads(
            (contracts.REGISTRY_CONTRACTS / f"{BINARY}.json").read_text(encoding="utf-8"))["required_status_fields"]))
        cases = {
            "status missing": ({k: v for k, v in good.items() if k != "status"}, {"status-invalid"}),
            "attempt_id missing": ({k: v for k, v in good.items() if k != "attempt_id"}, {"status-invalid"}),
            "dagster_run_id missing": ({k: v for k, v in good.items() if k != "dagster_run_id"}, {"status-invalid"}),
            "status edited alone": ({**good, "status": "OK"}, {"status-mismatch"}),
            "attempt_id edited alone": ({**good, "attempt_id": self.QUIET}, {"status-mismatch"}),
            "dagster_run_id edited alone": ({**good, "dagster_run_id": self.QUIET}, {"status-mismatch"}),
            "status not a string": ({**good, "status": ["OK_WITH_GAPS"]}, {"status-mismatch"}),
            "unregistered extra field": ({**good, "note": self.QUIET}, {"status-invalid"}),
            "empty object": ({}, {"status-invalid"}),
        }
        for label, (document, expected) in cases.items():
            case, attempt, inputs = self.fresh()
            (attempt / "status.json").write_bytes(dump(document))
            errors = verify(case, attempt, inputs)
            with self.subTest(case=label):
                self.assertEqual(names(errors), expected, errors)
                self.assertFalse([e for e in errors if self.QUIET in e], errors)
        for label, raw in (("a list", b"[]"), ("a string", b'"OK_WITH_GAPS"'), ("null", b"null")):
            case, attempt, inputs = self.fresh()
            (attempt / "status.json").write_bytes(raw)
            self.assertEqual(names(verify(case, attempt, inputs)), {"status-invalid"}, label)

    def test_status_is_bound_to_the_callers_facts_not_to_the_file(self):
        case, attempt, inputs = self.fresh()
        self.assertEqual(verify(case, attempt, inputs), [])
        self.assertIn("status-mismatch", names(verify(case, attempt, inputs, expected_dagster_run_id="another-dagster-run")))
        self.assertIn("status-mismatch", names(verify(case, attempt, inputs, node_status="OK")))

    def test_status_holds_for_every_contract_and_status(self):
        for name in GOLDENS:
            case, attempt, inputs = self.fresh(name)
            self.assertEqual(verify(case, attempt, inputs), [], name)
            (attempt / "status.json").write_bytes(dump({"status": case["status"]}))   # the pre-review golden
            self.assertEqual(names(verify(case, attempt, inputs)), {"status-invalid"}, name)

    def test_manifest_binds_exactly_what_was_published(self):
        for raw in (b"[]", b'"x"', b"null", b"{}"):
            case, attempt, inputs = self.fresh()
            (attempt / "manifest.json").write_bytes(raw)
            self.assertEqual(names(verify(case, attempt, inputs)), {"manifest-invalid"})
        good = None
        mutations = {
            "wrong schema": lambda d: d.update(schema="appsec-review/attempt-manifest/0"),
            "another contract": lambda d: d.update(contract_id=MOBILE),
            "extra key": lambda d: d.update(note=self.QUIET),
            "one hash edited": lambda d: d["outputs"][0].update(sha256="sha256:" + "0" * 64),
            "one entry dropped": lambda d: d["outputs"].pop(),
            "an unpublished file listed": lambda d: d["outputs"].append({"path": "outputs/zz-ghost.json", "sha256": "sha256:" + "1" * 64}),
            "alias path": lambda d: d["outputs"][0].update(path=d["outputs"][0]["path"].replace("outputs/", "outputs/./")),
            "unsorted": lambda d: d["outputs"].reverse(),
            "entry with an extra field": lambda d: d["outputs"][0].update(size=1),
        }
        for label, mutate in mutations.items():
            case, attempt, inputs = self.fresh()
            document = json.loads((attempt / "manifest.json").read_text(encoding="utf-8"))
            mutate(document)
            (attempt / "manifest.json").write_bytes(dump(document))
            errors = verify(case, attempt, inputs)
            with self.subTest(case=label):
                self.assertTrue(names(errors) <= {"manifest-invalid", "manifest-mismatch"} and errors, errors)
                self.assertFalse([e for e in errors if self.QUIET in e], errors)

    def test_invariant_no_value_written_into_the_attempt_after_sealing_reaches_an_error(self):
        """Every file of the attempt, tampered one at a time with a planted value in every position
        a JSON document offers at its top level: no error message may contain it."""
        case, attempt, inputs = self.fresh()
        files = sorted(path for path in attempt.rglob("*") if path.is_file())
        self.assertGreaterEqual(len(files), 7)
        for path in files:
            original = path.read_bytes()
            try:
                document = json.loads(original.decode("utf-8"))
            except ValueError:
                document = None
            variants = [self.PLANT.encode(), dump({"x": self.PLANT}), dump([self.PLANT])]
            if isinstance(document, dict):
                variants += [dump({**document, key: self.PLANT}) for key in document]
                variants.append(dump({**document, self.PLANT: 1}))
            for variant in variants:
                path.write_bytes(variant)
                errors = verify(case, attempt, inputs)
                self.assertTrue(errors, f"{path.name}: tampering was accepted")
                self.assertFalse([e for e in errors if self.PLANT in e], f"{path.name}: {errors}")
            path.write_bytes(original)
        self.assertEqual(verify(case, attempt, inputs), [])


if __name__ == "__main__":
    unittest.main()
