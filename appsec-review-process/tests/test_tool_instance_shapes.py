"""Golden and mutation tests for the shared tool-instance aggregate shapes (ADR-0010, task V03).

Covers the three schemas (`tool-results`, `scan-coverage`, `applicability-probe-receipt`), their two
sibling sub-shapes, and the cross-record rules in `tool_instance_shapes.validate_node_aggregate`.

Every rule has the mutation that violates it, and the mutation edits only the field under test so
a rejection proves that field is bound. `build_aggregate` produces internally consistent documents
for any per-tool status assignment; the invariant tests sweep it.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import itertools
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from schema_validate import SchemaStore, validate_document
import tool_instance_shapes as shapes
from tool_instance_shapes import supportable_success_status, validate_node_aggregate

FIXTURES = ROOT / "tests" / "fixtures" / "tool-instance-shapes"

RESULTS = "tool-results.schema.json"
COVERAGE = "scan-coverage.schema.json"
RECEIPT = "applicability-probe-receipt.schema.json"
INSTANCE = "tool-instance-result.schema.json"
IDENTITY = "tool-instance-identity.schema.json"
ALL_SCHEMAS = [RESULTS, COVERAGE, RECEIPT, INSTANCE, IDENTITY]

TERMINAL = ["OK", "OK_WITH_GAPS", "SKIPPED", "BLOCKED", "FAILED", "CANCELED", "UNRESOLVED"]
SKIP_REASON = "not-applicable-no-matching-inputs"
CAN_SKIP = ["OK", "OK_WITH_GAPS", "SKIPPED", "BLOCKED", "FAILED", "CANCELED"]
NEVER_SKIPS = ["OK", "OK_WITH_GAPS", "BLOCKED", "FAILED", "CANCELED"]

# Names that could give a raw matched line, a tool message, a shell string or a mutable image tag a
# home. ADR-0010: tool-results and coverage "carry counts and identities, never matches".
FORBIDDEN_PROPERTY_NAMES = {
    "snippet", "snippets", "match", "matches", "matched_text", "match_text", "line_text", "lines",
    "evidence_text", "message", "messages", "text", "content", "excerpt", "context", "raw", "raw_output",
    "stdout", "stderr", "output_text", "description", "detail", "details", "note", "notes", "summary",
    "secret", "value", "finding", "findings", "severity",
    "command", "command_line", "cmd", "shell", "shell_command", "script",
    "image", "image_tag", "tag", "image_ref", "image_reference",
}
RAW_LINES = [
    'password = "hunter2"  # do not commit',
    "    api_key: AKIAIOSFODNN7EXAMPLE",
    "const token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';\treturn token;",
    "line one\nline two",
]

GOLDENS = {
    "iac-ok-with-gaps": ("OK_WITH_GAPS", CAN_SKIP),
    "mobile-skipped": ("SKIPPED", CAN_SKIP),
    "source-sast-ok": ("OK", NEVER_SKIPS),
}


def sha(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def load_golden(name: str) -> dict:
    out = {}
    for part in ("tool-results", "coverage", "probe-receipt", "declared-tools"):
        out[part] = json.loads((FIXTURES / name / f"{part}.json").read_text(encoding="utf-8"))
    return out


def walk_schema(node, path="$"):
    """Yields (path, subschema) for every subschema that declares properties, nullable or not."""
    if isinstance(node, dict):
        if "properties" in node:
            yield path, node
        for key, value in node.items():
            yield from walk_schema(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk_schema(value, f"{path}[{index}]")


def walk_leaves(node, path="$"):
    """Yields (path, subschema) for every subschema with a `type` that is not an object/array."""
    if isinstance(node, dict):
        types = node.get("type")
        if types is not None and not isinstance(node.get("properties"), dict) and "items" not in node:
            yield path, node
        for key, value in node.items():
            if key in ("properties", "items") or isinstance(value, dict) and key not in ("description",):
                yield from walk_leaves(value, f"{path}.{key}")


# ---- consistent-document builder -------------------------------------------------------------

HEADER = {
    "run_id": "20260920T120000Z-v03abc",
    "job_id": "02-iac-config-scan",
    "attempt_id": "node-attempt-0001",
    "source_snapshot_sha256": sha("snapshot"),
}


def build_instance(tool_id: str, status: str, executor: str = "pinned_container") -> dict:
    container = executor == "pinned_container"
    started = status not in ("SKIPPED", "BLOCKED")
    exit_block = {
        "OK": (1, "findings-present"), "OK_WITH_GAPS": (0, "clean"), "SKIPPED": (None, "not-started"),
        "BLOCKED": (None, "not-started"), "FAILED": (2, "tool-error"), "CANCELED": (None, "canceled"),
        "UNRESOLVED": (0, "clean"),
    }[status]
    cause = {"OK": None, "SKIPPED": None, "OK_WITH_GAPS": "partial-input-coverage",
             "BLOCKED": "image-unavailable", "FAILED": "tool-error", "CANCELED": "canceled",
             "UNRESOLVED": "output-invalid"}[status]
    if status in ("OK", "OK_WITH_GAPS"):
        outputs = [{"path": f"{tool_id}/outputs/result.json", "sha256": sha(tool_id + "result"), "bytes": 2048,
                    "media_type": "application/json", "role": "normalized-result",
                    "validation": "schema-validated", "validated_against": "tool-normalized-result.schema.json"}]
    elif status in ("FAILED", "UNRESOLVED"):
        outputs = [{"path": f"{tool_id}/logs/stderr.redacted.log", "sha256": sha(tool_id + "stderr"), "bytes": 310,
                    "media_type": "text/plain", "role": "retained-stderr",
                    "validation": "not-validated", "validated_against": None}]
    else:
        outputs = []
    return {
        "tool_id": tool_id,
        "attempt_id": f"{tool_id}-attempt-0001",
        "terminal_status": status,
        "skip_reason": SKIP_REASON if status == "SKIPPED" else None,
        "cause_code": cause,
        "identity": {
            "executor_kind": executor,
            "image_repository": "registry.internal.example:5000/appsec/audit-iac" if container else None,
            "image_digest": sha("image" + tool_id) if container else None,
            "executable_sha256": None if container else sha("module" + tool_id),
            "tool_name": tool_id,
            "tool_version": "3.2.1" if started else None,
            "data_identities": [{"kind": "policy-bundle", "identity_id": f"{tool_id}-bundle",
                                 "version": "2026.09.01", "sha256": sha("bundle" + tool_id)}],
            "redactor": None,
        },
        "argv": [tool_id, "--offline", "--output", "/out/result.json", "/src"],
        "exit": {"exit_code": exit_block[0], "exit_meaning": exit_block[1], "timed_out": False,
                 "nonzero_exit_on_findings": True, "findings_exit_codes": [1]},
        "outputs": outputs,
        "result_record_count": 7 if status in ("OK", "OK_WITH_GAPS") else None,
    }


def build_aggregate(statuses: dict[str, str], inputs: int = 5) -> dict:
    """Consistent tool-results / coverage / receipt for one status per tool. `inputs` >= 2."""
    instances, tools, gaps, probed = [], [], [], []
    for tool_id, status in statuses.items():
        instances.append(build_instance(tool_id, status))
        count = 0 if status == "SKIPPED" else inputs
        not_analyzed = {"OK": 0, "SKIPPED": 0, "OK_WITH_GAPS": 1}.get(status, count)
        reason = "parse-failed" if status == "OK_WITH_GAPS" else "tool-instance-did-not-complete"
        listed = [{"path": f"deploy/{tool_id}/input-{n}.tf", "reason_code": reason} for n in range(min(not_analyzed, 2))]
        tools.append({
            "tool_id": tool_id,
            "applicability": SKIP_REASON if status == "SKIPPED" else "applicable",
            "candidate_input_count": count,
            "analyzed_input_count": count - not_analyzed,
            "not_analyzed_input_count": not_analyzed,
            "unsupported_input_count": 0,
            "not_analyzed_inputs": listed,
            "unsupported_inputs": [],
            "input_lists_truncated": len(listed) < not_analyzed,
        })
        if status in shapes.INSTANCE_GAP_KIND:
            gaps.append({"gap_id": f"gap-{tool_id}-instance", "kind": shapes.INSTANCE_GAP_KIND[status],
                         "tool_id": tool_id, "affected_input_count": None})
        if not_analyzed:
            gaps.append({"gap_id": f"gap-{tool_id}-not-analyzed", "kind": "inputs-not-analyzed",
                         "tool_id": tool_id, "affected_input_count": not_analyzed})
        probed.append({
            "tool_id": tool_id,
            "detectors": [{"detector_id": f"{tool_id}-glob", "patterns_searched": ["**/*.tf", "**/Dockerfile*"],
                           "matching_input_count": count}],
            "matching_input_count": count,
            "applicable": count > 0,
        })
    applicable = any(tool["applicable"] for tool in probed)
    return {
        "tool-results": {"schema": "appsec-review/tool-results/1.0", **HEADER, "tool_instances": instances},
        "coverage": {"schema": "appsec-review/scan-coverage/1.0", **HEADER, "tools": tools, "gaps": gaps},
        "probe-receipt": {
            "schema": "appsec-review/applicability-probe-receipt/1.0", **HEADER,
            "probe": {"probe_id": "iac-detector-probe", "probe_version": "1.0.0", "probe_sha256": sha("probe")},
            "files_examined_count": 412, "tools": probed, "node_applicable": applicable,
            "skip_reason": None if applicable else SKIP_REASON,
        },
        "declared-tools": list(statuses),
    }


def check(status, agg, permitted=CAN_SKIP, **override):
    args = {"tool_results": agg["tool-results"], "coverage": agg["coverage"],
            "probe_receipt": agg["probe-receipt"], "declared_tool_ids": agg["declared-tools"],
            "permitted_node_statuses": permitted}
    args.update(override)
    return validate_node_aggregate(status, args["tool_results"], args["coverage"], args["probe_receipt"],
                                   args["declared_tool_ids"], args["permitted_node_statuses"])


def names(errors):
    return {error.split(":", 1)[0] for error in errors}


class SchemaHygieneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = SchemaStore()

    def test_every_schema_loads_and_every_object_is_closed_and_fully_required(self):
        for name in ALL_SCHEMAS:
            schema = self.store.load(name)
            self.assertEqual(schema.get("$id"), name)
            nodes = list(walk_schema(schema))
            self.assertTrue(nodes)
            for path, node in nodes:
                self.assertIs(node.get("additionalProperties"), False, f"{name} {path} is not closed")
                self.assertEqual(set(node.get("required", [])), set(node["properties"]),
                                 f"{name} {path}: every declared property must be required")

    def test_no_schema_offers_a_field_that_could_hold_a_match_a_shell_string_or_an_image_tag(self):
        for name in ALL_SCHEMAS:
            for path, node in walk_schema(self.store.load(name)):
                offenders = FORBIDDEN_PROPERTY_NAMES & set(node["properties"])
                self.assertFalse(offenders, f"{name} {path} declares forbidden fields {sorted(offenders)}")

    def test_every_string_is_a_const_an_enum_or_an_anchored_pattern_that_rejects_a_raw_line(self):
        seen = 0
        for name in ALL_SCHEMAS:
            for path, leaf in walk_leaves(self.store.load(name)):
                types = leaf["type"] if isinstance(leaf["type"], list) else [leaf["type"]]
                self.assertTrue(set(types) <= {"string", "integer", "boolean", "null"}, f"{name} {path}: {types}")
                if "string" not in types or "enum" in leaf:
                    continue
                seen += 1
                pattern = leaf.get("pattern")
                self.assertIsNotNone(pattern, f"{name} {path} is a free-text string")
                self.assertTrue(pattern.startswith("^") and pattern.endswith("$"), f"{name} {path} is unanchored")
                for line in RAW_LINES:
                    self.assertIsNone(re.match(pattern, line), f"{name} {path} accepts raw line {line!r}")
        self.assertGreater(seen, 20)

    def test_tool_instance_terminal_status_is_exactly_the_envelope_terminal_set(self):
        envelope = self.store.load("worker-result-envelope.schema.json")
        expected = envelope["properties"]["execution_status"]["enum"]
        self.assertEqual(expected, TERMINAL)
        self.assertEqual(self.store.load(INSTANCE)["properties"]["terminal_status"]["enum"], expected)
        self.assertEqual(set(shapes.STATUS_EXIT_MEANINGS), set(expected))
        self.assertEqual(set(shapes.STATUS_CAUSES), set(expected))
        # the node may use every envelope status except UNRESOLVED (ADR-0010)
        self.assertEqual(set(shapes.NODE_STATUSES), set(expected) - {"UNRESOLVED"})

    def test_module_tables_stay_inside_the_schema_enums(self):
        instance = self.store.load(INSTANCE)["properties"]
        meanings = set(instance["exit"]["properties"]["exit_meaning"]["enum"])
        causes = set(instance["cause_code"]["enum"])
        for allowed in shapes.STATUS_EXIT_MEANINGS.values():
            self.assertTrue(set(allowed) <= meanings)
        used = set()
        for allowed in shapes.STATUS_CAUSES.values():
            self.assertTrue(set(allowed) <= causes)
            used |= set(allowed)
        self.assertEqual(used, causes, "every cause_code must belong to some status")
        kinds = set(self.store.load(COVERAGE)["properties"]["gaps"]["items"]["properties"]["kind"]["enum"])
        self.assertTrue(set(shapes.INSTANCE_GAP_KIND.values()) <= kinds)
        outputs = instance["outputs"]["items"]["properties"]
        self.assertTrue(set(shapes.RESULT_ROLES) <= set(outputs["role"]["enum"]))
        self.assertTrue(set(shapes.VALIDATED) <= set(outputs["validation"]["enum"]))
        self.assertEqual(instance["skip_reason"]["enum"], [SKIP_REASON, None])
        self.assertEqual(self.store.load(RECEIPT)["properties"]["skip_reason"]["enum"], [SKIP_REASON, None])

    def test_job_id_is_not_pinned_so_02_source_sast_reuses_the_shapes_unchanged(self):
        for name in (RESULTS, COVERAGE, RECEIPT):
            job_id = self.store.load(name)["properties"]["job_id"]
            self.assertNotIn("const", job_id)
            self.assertNotIn("enum", job_id)
            self.assertIsNotNone(re.match(job_id["pattern"], "02-source-sast"))


class GoldenTests(unittest.TestCase):
    def test_goldens_validate_structurally_and_as_aggregates(self):
        store = SchemaStore()
        for name, (status, permitted) in GOLDENS.items():
            golden = load_golden(name)
            self.assertEqual(validate_document(golden["tool-results"], RESULTS, store), [], name)
            self.assertEqual(validate_document(golden["coverage"], COVERAGE, store), [], name)
            self.assertEqual(validate_document(golden["probe-receipt"], RECEIPT, store), [], name)
            self.assertEqual(check(status, golden, permitted), [], name)
            self.assertEqual(supportable_success_status(golden["tool-results"], golden["coverage"]), status)

    def test_golden_ids_are_internally_consistent(self):
        for name in GOLDENS:
            golden = load_golden(name)
            declared = golden["declared-tools"]
            self.assertEqual(len(declared), len(set(declared)))
            results, coverage, receipt = golden["tool-results"], golden["coverage"], golden["probe-receipt"]
            self.assertEqual([i["tool_id"] for i in results["tool_instances"]], declared, name)
            self.assertEqual([t["tool_id"] for t in coverage["tools"]], declared, name)
            self.assertEqual([t["tool_id"] for t in receipt["tools"]], declared, name)
            for field in shapes.HEADER_FIELDS:
                self.assertEqual({results[field], coverage[field], receipt[field]}, {results[field]}, f"{name} {field}")
            for gap in coverage["gaps"]:
                self.assertIn(gap["tool_id"], declared)
            attempts = [i["attempt_id"] for i in results["tool_instances"]] + [results["attempt_id"]]
            self.assertEqual(len(attempts), len(set(attempts)))
            for instance in results["tool_instances"]:
                for output in instance["outputs"]:
                    self.assertTrue(output["path"].startswith(instance["tool_id"] + "/"), output["path"])

    def test_goldens_agree_with_the_accepted_adr_node_declarations(self):
        proposal = json.loads((ROOT.parent / "docs" / "proposals" / "vendor-prepass" /
                               "job-nodes.proposal.json").read_text(encoding="utf-8"))
        nodes = {n["proposed_job_id"]: n for n in proposal["proposed_nodes"]}
        for name in ("iac-ok-with-gaps", "mobile-skipped"):
            golden = load_golden(name)
            node = nodes[golden["tool-results"]["job_id"]]
            self.assertEqual(golden["declared-tools"], [t["tool_id"] for t in node["tool_instances"]])
            self.assertEqual(GOLDENS[name][1], node["permitted_terminal_statuses"])
            kinds = {t["tool_id"]: t.get("worker_kind", node["worker_kind"]) for t in node["tool_instances"]}
            for instance in golden["tool-results"]["tool_instances"]:
                self.assertEqual(instance["identity"]["executor_kind"], kinds[instance["tool_id"]])
        self.assertEqual(proposal["proposed_new_skip_reason"]["id"], SKIP_REASON)

    def test_source_sast_golden_has_one_instance_per_legacy_step_including_eight_semgrep_packs(self):
        proposal = json.loads((ROOT.parent / "docs" / "proposals" / "vendor-prepass" /
                               "job-nodes.proposal.json").read_text(encoding="utf-8"))
        legacy = proposal["existing_nodes_receiving_legacy_steps"][0]
        self.assertEqual(legacy["existing_job_id"], "02-source-sast")
        golden = load_golden("source-sast-ok")
        self.assertEqual(golden["tool-results"]["job_id"], "02-source-sast")
        self.assertEqual(len(golden["declared-tools"]), len(legacy["legacy_steps"]))
        self.assertEqual(len(golden["declared-tools"]), 15)
        semgrep = [i for i in golden["tool-results"]["tool_instances"] if i["identity"]["tool_name"] == "semgrep"]
        self.assertEqual(len(semgrep), 8)
        packs = {i["identity"]["data_identities"][0]["identity_id"] for i in semgrep}
        self.assertEqual(len(packs), 8, "each Semgrep rule pack is its own instance with its own hashed pack")
        self.assertEqual(len({i["identity"]["image_digest"] for i in semgrep}), 1)
        self.assertTrue(any(i["terminal_status"] == "SKIPPED" for i in golden["tool-results"]["tool_instances"]))


class AcceptanceRuleTests(unittest.TestCase):
    """The three V03 acceptance rules, each with wrong-state mutations."""

    def test_ok_node_cannot_hide_a_failed_instance_by_status(self):
        for bad in ("FAILED", "BLOCKED", "CANCELED", "UNRESOLVED", "OK_WITH_GAPS"):
            agg = build_aggregate({"checkov": "OK", "tfsec": bad})
            self.assertIn("node-ok-with-non-ok-instance", names(check("OK", agg)), bad)
            self.assertIn("node-ok-with-gaps", names(check("OK", agg)), bad)

    def test_ok_node_cannot_hide_a_failed_instance_by_not_reporting_the_gap(self):
        agg = build_aggregate({"checkov": "OK", "tfsec": "FAILED"})
        self.assertEqual(check("OK_WITH_GAPS", agg), [])
        agg["coverage"]["gaps"] = [g for g in agg["coverage"]["gaps"] if g["kind"] != "tool-instance-failed"]
        self.assertIn("gap-missing", names(check("OK_WITH_GAPS", agg)))
        agg["coverage"]["gaps"] = []
        for status in ("OK", "OK_WITH_GAPS"):
            self.assertIn("gap-missing", names(check(status, agg)), status)

    def test_ok_node_cannot_hide_a_failed_instance_by_dropping_it_from_tool_results(self):
        agg = build_aggregate({"checkov": "OK", "tfsec": "FAILED"})
        clean = build_aggregate({"checkov": "OK"})
        clean["declared-tools"] = agg["declared-tools"]
        errors = check("OK", clean)
        self.assertEqual(names(errors), {"declared-tool-missing"})
        self.assertEqual(len(errors), 3, "missing from tool-results, coverage and the receipt")

    def test_ok_node_cannot_relabel_a_failed_instance_as_ok(self):
        agg = build_aggregate({"checkov": "OK", "tfsec": "FAILED"})
        agg["tool-results"]["tool_instances"][1]["terminal_status"] = "OK"
        found = names(check("OK", agg))
        self.assertTrue({"instance-exit", "instance-output", "instance-cause"} <= found, found)

    def test_ok_with_gaps_needs_a_validated_hashed_output(self):
        for statuses in ({"checkov": "FAILED", "tfsec": "BLOCKED"}, {"checkov": "FAILED", "tfsec": "SKIPPED"},
                         {"checkov": "CANCELED", "tfsec": "UNRESOLVED"}):
            agg = build_aggregate(statuses)
            self.assertEqual(names(check("OK_WITH_GAPS", agg)), {"node-ok-with-gaps-without-validated-output"})
            self.assertEqual(check("FAILED", agg), [])

    def test_an_unvalidated_or_log_only_output_does_not_count_as_validated(self):
        base = build_aggregate({"checkov": "OK", "tfsec": "FAILED"})
        for field, value in (("validation", "not-validated"), ("validation", "invalid"), ("role", "retained-stdout")):
            agg = deepcopy(base)
            output = agg["tool-results"]["tool_instances"][0]["outputs"][0]
            output[field] = value
            if field == "validation":
                output["validated_against"] = None
            found = names(check("OK_WITH_GAPS", agg))
            self.assertIn("node-ok-with-gaps-without-validated-output", found, value)
            self.assertIn("instance-output", found, value)

    def test_ok_with_gaps_needs_a_named_gap(self):
        agg = build_aggregate({"checkov": "OK", "tfsec": "OK"})
        self.assertEqual(check("OK", agg), [])
        self.assertEqual(names(check("OK_WITH_GAPS", agg)), {"node-ok-with-gaps-without-gap"})

    def test_skipped_needs_a_receipt(self):
        agg = build_aggregate({"mobsfscan-android": "SKIPPED", "mobsfscan-ios": "SKIPPED"})
        self.assertEqual(check("SKIPPED", agg), [])
        found = names(check("SKIPPED", agg, probe_receipt=None))
        self.assertTrue({"node-skipped-without-receipt", "probe-receipt-required", "instance-skip"} <= found, found)

    def test_skipped_needs_every_declared_tool_in_the_receipt(self):
        agg = build_aggregate({"mobsfscan-android": "SKIPPED", "mobsfscan-ios": "SKIPPED"})
        del agg["probe-receipt"]["tools"][1]
        found = names(check("SKIPPED", agg))
        self.assertTrue({"node-skipped-tool-not-probed", "declared-tool-missing"} <= found, found)

    def test_skipped_is_forbidden_by_any_non_zero_count(self):
        agg = build_aggregate({"mobsfscan-android": "SKIPPED", "mobsfscan-ios": "SKIPPED"})
        tool = agg["probe-receipt"]["tools"][1]
        tool["matching_input_count"] = 1
        tool["detectors"][0]["matching_input_count"] = 1
        tool["applicable"] = True
        agg["probe-receipt"]["node_applicable"] = True
        agg["probe-receipt"]["skip_reason"] = None
        found = names(check("SKIPPED", agg))
        self.assertTrue({"node-skipped-with-inputs", "node-skipped-wrong-reason", "instance-skip"} <= found, found)

    def test_skipped_cannot_edit_only_the_tool_count_or_only_a_detector_count(self):
        agg = build_aggregate({"mobsfscan-android": "SKIPPED", "mobsfscan-ios": "SKIPPED"})
        only_detector = deepcopy(agg)
        only_detector["probe-receipt"]["tools"][0]["detectors"][0]["matching_input_count"] = 3
        self.assertIn("probe-count", names(check("SKIPPED", only_detector)))
        only_total = deepcopy(agg)
        only_total["probe-receipt"]["tools"][0]["matching_input_count"] = 3
        self.assertIn("probe-count", names(check("SKIPPED", only_total)))

    def test_skipped_needs_search_evidence(self):
        agg = build_aggregate({"mobsfscan-android": "SKIPPED", "mobsfscan-ios": "SKIPPED"})
        nothing_examined = deepcopy(agg)
        nothing_examined["probe-receipt"]["files_examined_count"] = 0
        self.assertEqual(names(check("SKIPPED", nothing_examined)), {"node-skipped-nothing-examined"})
        no_patterns = deepcopy(agg)
        no_patterns["probe-receipt"]["tools"][0]["detectors"][0]["patterns_searched"] = []
        self.assertIn("minItems is 1", "\n".join(check("SKIPPED", no_patterns)))
        no_detectors = deepcopy(agg)
        no_detectors["probe-receipt"]["tools"][0]["detectors"] = []
        self.assertIn("minItems is 1", "\n".join(check("SKIPPED", no_detectors)))
        for field in ("source_snapshot_sha256", "files_examined_count", "probe"):
            missing = deepcopy(agg)
            del missing["probe-receipt"][field]
            self.assertIn(f"missing required property '{field}'", "\n".join(check("SKIPPED", missing)))

    def test_skipped_receipt_must_be_for_this_snapshot_run_job_and_attempt(self):
        agg = build_aggregate({"mobsfscan-android": "SKIPPED", "mobsfscan-ios": "SKIPPED"})
        for field, value in (("source_snapshot_sha256", sha("another snapshot")), ("run_id", "another-run"),
                             ("job_id", "02-mobile-sast"), ("attempt_id", "node-attempt-0000")):
            for part in ("probe-receipt", "coverage"):
                other = deepcopy(agg)
                other[part][field] = value
                self.assertEqual(names(check("SKIPPED", other)), {"header-mismatch"}, f"{part}.{field}")

    def test_skipped_reason_is_the_adr_reason_only(self):
        agg = build_aggregate({"mobsfscan-android": "SKIPPED", "mobsfscan-ios": "SKIPPED"})
        wrong = deepcopy(agg)
        wrong["probe-receipt"]["skip_reason"] = "not-requested"
        self.assertIn("not in enum", "\n".join(check("SKIPPED", wrong)))
        wrong = deepcopy(agg)
        wrong["probe-receipt"]["skip_reason"] = None
        self.assertTrue({"probe-skip-reason", "node-skipped-wrong-reason"} <= names(check("SKIPPED", wrong)))
        wrong = deepcopy(agg)
        wrong["tool-results"]["tool_instances"][0]["skip_reason"] = "not-applicable-non-native"
        self.assertIn("not in enum", "\n".join(check("SKIPPED", wrong)))

    def test_skipped_node_with_an_instance_that_ran_is_rejected_and_so_is_the_reverse(self):
        agg = build_aggregate({"mobsfscan-android": "OK", "mobsfscan-ios": "SKIPPED"})
        self.assertIn("node-skipped-instance-not-skipped", names(check("SKIPPED", agg)))
        all_skipped = build_aggregate({"mobsfscan-android": "SKIPPED", "mobsfscan-ios": "SKIPPED"})
        self.assertEqual(names(check("OK", all_skipped)), {"node-not-skipped-with-zero-inputs"})
        self.assertEqual(names(check("OK_WITH_GAPS", all_skipped)),
                         {"node-ok-with-gaps-without-validated-output", "node-ok-with-gaps-without-gap"})

    def test_failure_is_not_a_skip(self):
        agg = build_aggregate({"mobsfscan-android": "FAILED", "mobsfscan-ios": "BLOCKED"})
        found = names(check("SKIPPED", agg))
        self.assertTrue({"node-skipped-instance-not-skipped", "node-skipped-with-inputs", "node-skipped-with-gaps"} <= found)
        relabeled = deepcopy(agg)
        instance = relabeled["tool-results"]["tool_instances"][0]
        instance["terminal_status"], instance["skip_reason"] = "SKIPPED", SKIP_REASON
        self.assertIn("instance-skip", names(check("OK_WITH_GAPS", relabeled)))


class RequiredInputTests(unittest.TestCase):
    """Lesson 1: no optional safety input."""

    def test_every_safety_input_is_a_required_argument(self):
        agg = build_aggregate({"checkov": "OK"})
        full = ["OK", agg["tool-results"], agg["coverage"], agg["probe-receipt"], agg["declared-tools"], CAN_SKIP]
        self.assertEqual(validate_node_aggregate(*full), [])
        for length in range(len(full)):
            with self.assertRaises(TypeError):
                validate_node_aggregate(*full[:length])
        with self.assertRaises(TypeError):
            validate_node_aggregate("OK", agg["tool-results"], agg["coverage"],
                                    declared_tool_ids=agg["declared-tools"], permitted_node_statuses=CAN_SKIP)

    def test_empty_or_string_safety_inputs_are_refused_not_treated_as_no_constraint(self):
        agg = build_aggregate({"checkov": "OK"})
        with self.assertRaises(ValueError):
            check("OK", agg, declared_tool_ids=[])
        with self.assertRaises(ValueError):
            check("OK", agg, permitted_node_statuses=[])
        with self.assertRaises(TypeError):
            check("OK", agg, declared_tool_ids="checkov")
        with self.assertRaises(TypeError):
            check("OK", agg, permitted_node_statuses="OK")

    def test_an_explicit_none_receipt_only_ever_tightens(self):
        agg = build_aggregate({"syft-directory": "OK"})
        self.assertEqual(check("OK", agg, NEVER_SKIPS, probe_receipt=None), [])
        self.assertEqual(names(check("OK", agg, CAN_SKIP, probe_receipt=None)), {"probe-receipt-required"})
        skipping = build_aggregate({"syft-directory": "OK", "other": "SKIPPED"})
        self.assertIn("instance-skip", names(check("OK", skipping, NEVER_SKIPS, probe_receipt=None)))

    def test_node_status_must_be_permitted_and_is_never_unresolved(self):
        agg = build_aggregate({"syft-directory": "SKIPPED"})
        self.assertEqual(names(check("SKIPPED", agg, NEVER_SKIPS)), {"status-not-permitted"})
        self.assertEqual(names(check("UNRESOLVED", agg, CAN_SKIP)), {"status-not-permitted"})
        self.assertEqual(names(check("FAILED", agg, CAN_SKIP + ["UNRESOLVED"])), {"status-not-permitted"})
        self.assertEqual(names(check("RUNNING", agg, CAN_SKIP)), {"status-not-permitted"})


class ToolIdResolutionTests(unittest.TestCase):
    """Rule (d): tool ids resolve both ways across all three documents and the declaration."""

    def setUp(self):
        self.agg = build_aggregate({"checkov": "OK", "tfsec": "FAILED", "hadolint": "SKIPPED"})
        self.assertEqual(check("OK_WITH_GAPS", self.agg), [])

    def test_a_tool_missing_from_any_one_document_is_named(self):
        for part, key in (("tool-results", "tool_instances"), ("coverage", "tools"), ("probe-receipt", "tools")):
            agg = deepcopy(self.agg)
            agg[part][key] = [entry for entry in agg[part][key] if entry["tool_id"] != "hadolint"]
            errors = [e for e in check("OK_WITH_GAPS", agg) if e.startswith("declared-tool-missing")]
            self.assertEqual(len(errors), 1, part)
            self.assertIn(part, errors[0])

    def test_an_extra_tool_in_any_one_document_is_named(self):
        for part, key in (("tool-results", "tool_instances"), ("coverage", "tools"), ("probe-receipt", "tools")):
            agg = deepcopy(self.agg)
            extra = deepcopy(agg[part][key][0])
            extra["tool_id"] = "ghost"
            if part == "tool-results":
                extra["attempt_id"] = "ghost-attempt-0001"
            agg[part][key].append(extra)
            errors = [e for e in check("OK_WITH_GAPS", agg) if e.startswith("undeclared-tool")]
            self.assertEqual(len(errors), 1, part)
            self.assertIn(part, errors[0])

    def test_a_duplicated_tool_is_named(self):
        for part, key in (("tool-results", "tool_instances"), ("coverage", "tools"), ("probe-receipt", "tools")):
            agg = deepcopy(self.agg)
            agg[part][key].append(deepcopy(agg[part][key][0]))
            self.assertIn("duplicate-tool", names(check("OK_WITH_GAPS", agg)), part)

    def test_a_gap_must_name_a_known_tool(self):
        agg = deepcopy(self.agg)
        agg["coverage"]["gaps"][0]["tool_id"] = "ghost"
        found = names(check("OK_WITH_GAPS", agg))
        self.assertTrue({"gap-unknown-tool", "gap-missing"} <= found, found)

    def test_attempt_ids_are_distinct_and_never_the_node_attempt(self):
        agg = deepcopy(self.agg)
        agg["tool-results"]["tool_instances"][1]["attempt_id"] = agg["tool-results"]["tool_instances"][0]["attempt_id"]
        self.assertEqual(names(check("OK_WITH_GAPS", agg)), {"duplicate-attempt"})
        agg = deepcopy(self.agg)
        agg["tool-results"]["tool_instances"][0]["attempt_id"] = agg["tool-results"]["attempt_id"]
        self.assertEqual(names(check("OK_WITH_GAPS", agg)), {"duplicate-attempt"})


class FieldBindingTests(unittest.TestCase):
    """Lesson 2: every trusted field is bound; each test edits only the named field."""

    def setUp(self):
        self.agg = build_aggregate({"checkov": "OK", "tfsec": "FAILED", "hadolint": "SKIPPED",
                                    "trivy-config": "OK_WITH_GAPS"})
        self.assertEqual(check("OK_WITH_GAPS", self.agg), [])

    def edit(self, part, path, value):
        agg = deepcopy(self.agg)
        node = agg[part]
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
        return names(check("OK_WITH_GAPS", agg))

    def test_instance_status_fields(self):
        inst = ("tool-results", "tool_instances")
        self.assertIn("instance-skip", self.edit(*inst[:1], [inst[1], 0, "skip_reason"], SKIP_REASON))
        self.assertIn("instance-skip", self.edit(*inst[:1], [inst[1], 2, "skip_reason"], None))
        self.assertIn("instance-cause", self.edit(*inst[:1], [inst[1], 0, "cause_code"], "tool-error"))
        self.assertIn("instance-cause", self.edit(*inst[:1], [inst[1], 1, "cause_code"], None))
        self.assertIn("instance-cause", self.edit(*inst[:1], [inst[1], 1, "cause_code"], "timeout"))
        self.assertIn("instance-cause", self.edit(*inst[:1], [inst[1], 1, "cause_code"], "image-unavailable"))
        self.assertIn("instance-count", self.edit(*inst[:1], [inst[1], 0, "result_record_count"], None))
        self.assertIn("instance-count", self.edit(*inst[:1], [inst[1], 0, "result_record_count"], -1))
        self.assertIn("instance-count", self.edit(*inst[:1], [inst[1], 1, "result_record_count"], 4))

    def test_instance_status_edited_alone_is_always_rejected(self):
        for index, instance in enumerate(self.agg["tool-results"]["tool_instances"]):
            for status in TERMINAL:
                if status == instance["terminal_status"]:
                    continue
                for node_status in shapes.NODE_STATUSES:
                    agg = deepcopy(self.agg)
                    agg["tool-results"]["tool_instances"][index]["terminal_status"] = status
                    self.assertTrue(check(node_status, agg), f"{instance['tool_id']} -> {status} under {node_status}")

    def test_exit_semantics(self):
        path = ["tool_instances", 0, "exit"]
        self.assertIn("instance-exit", self.edit("tool-results", path + ["exit_code"], 2))
        self.assertIn("instance-exit", self.edit("tool-results", path + ["exit_code"], 0))
        self.assertIn("instance-exit", self.edit("tool-results", path + ["exit_code"], None))
        self.assertIn("instance-exit", self.edit("tool-results", path + ["exit_meaning"], "clean"))
        self.assertIn("instance-exit", self.edit("tool-results", path + ["exit_meaning"], "tool-error"))
        self.assertIn("instance-exit", self.edit("tool-results", path + ["exit_meaning"], "timeout"))
        self.assertIn("instance-exit", self.edit("tool-results", path + ["timed_out"], True))
        self.assertIn("instance-exit", self.edit("tool-results", path + ["nonzero_exit_on_findings"], False))
        self.assertIn("instance-exit", self.edit("tool-results", path + ["findings_exit_codes"], []))
        self.assertIn("instance-exit", self.edit("tool-results", path + ["findings_exit_codes"], [0, 1]))
        self.assertIn("instance-exit", self.edit("tool-results", path + ["findings_exit_codes"], [1, 1]))
        failed = ["tool_instances", 1, "exit"]
        self.assertIn("instance-exit", self.edit("tool-results", failed + ["exit_code"], 1))
        self.assertIn("instance-exit", self.edit("tool-results", failed + ["exit_code"], 0))
        skipped = ["tool_instances", 2, "exit"]
        self.assertIn("instance-exit", self.edit("tool-results", skipped + ["exit_code"], 0))
        self.assertIn("instance-exit", self.edit("tool-results", skipped + ["exit_meaning"], "clean"))

    def test_a_tool_that_exits_zero_on_findings_is_representable_and_bound(self):
        agg = deepcopy(self.agg)
        exit_block = agg["tool-results"]["tool_instances"][0]["exit"]
        exit_block.update({"exit_code": 0, "nonzero_exit_on_findings": False, "findings_exit_codes": []})
        self.assertEqual(check("OK_WITH_GAPS", agg), [])
        exit_block["exit_code"] = 1
        self.assertIn("instance-exit", names(check("OK_WITH_GAPS", agg)))

    def test_timeout_is_a_failed_instance_with_matching_cause(self):
        agg = deepcopy(self.agg)
        failed = agg["tool-results"]["tool_instances"][1]
        failed["exit"].update({"exit_code": None, "exit_meaning": "timeout", "timed_out": True})
        failed["cause_code"] = "timeout"
        self.assertEqual(check("OK_WITH_GAPS", agg), [])
        failed["cause_code"] = "tool-error"
        self.assertIn("instance-cause", names(check("OK_WITH_GAPS", agg)))

    def test_identity_block(self):
        path = ["tool_instances", 0, "identity"]
        self.assertIn("instance-identity", self.edit("tool-results", path + ["image_digest"], None))
        self.assertIn("instance-identity", self.edit("tool-results", path + ["image_repository"], None))
        self.assertIn("instance-identity", self.edit("tool-results", path + ["executable_sha256"], sha("x")))
        self.assertIn("instance-identity", self.edit("tool-results", path + ["executor_kind"], "deterministic_python"))
        self.assertIn("instance-identity", self.edit("tool-results", path + ["tool_version"], None))
        item = self.agg["tool-results"]["tool_instances"][0]["identity"]["data_identities"][0]
        self.assertIn("instance-identity", self.edit("tool-results", path + ["data_identities"], [item, item]))

    def test_deterministic_python_instance_is_valid_without_an_image_and_bound(self):
        agg = deepcopy(self.agg)
        agg["tool-results"]["tool_instances"][0] = build_instance("checkov", "OK", "deterministic_python")
        self.assertEqual(check("OK_WITH_GAPS", agg), [])
        agg["tool-results"]["tool_instances"][0]["identity"]["executable_sha256"] = None
        self.assertIn("instance-identity", names(check("OK_WITH_GAPS", agg)))

    def test_outputs(self):
        path = ["tool_instances", 0, "outputs"]
        output = self.agg["tool-results"]["tool_instances"][0]["outputs"][0]
        self.assertIn("instance-output", self.edit("tool-results", path, []))
        self.assertIn("instance-output", self.edit("tool-results", path, [output, output]))
        self.assertIn("instance-output", self.edit("tool-results", path + [0, "validated_against"], None))
        self.assertIn("instance-output", self.edit("tool-results", path + [0, "bytes"], -1))
        self.assertIn("instance-output", self.edit("tool-results", path + [0, "path"], "checkov/../../etc/result.json"))
        log = self.agg["tool-results"]["tool_instances"][1]["outputs"][0]
        self.assertIn("instance-output", self.edit("tool-results", ["tool_instances", 2, "outputs"], [log]))
        self.assertIn("instance-output",
                      self.edit("tool-results", ["tool_instances", 1, "outputs", 0, "validated_against"], "sarif-2.1.0"))

    def test_coverage_counts(self):
        path = ["tools", 3]
        self.assertIn("coverage-count", self.edit("coverage", path + ["analyzed_input_count"], 5))
        self.assertIn("coverage-count", self.edit("coverage", path + ["candidate_input_count"], 6))
        self.assertIn("coverage-count", self.edit("coverage", path + ["not_analyzed_input_count"], 0))
        self.assertIn("coverage-count", self.edit("coverage", path + ["unsupported_input_count"], -1))
        self.assertIn("coverage-count", self.edit("coverage", path + ["not_analyzed_inputs"], []))
        self.assertIn("coverage-count", self.edit("coverage", path + ["input_lists_truncated"], True))
        entry = self.agg["coverage"]["tools"][1]["not_analyzed_inputs"][0]
        self.assertIn("coverage-count", self.edit("coverage", ["tools", 1, "not_analyzed_inputs"], [entry, entry]))
        self.assertIn("coverage-count", self.edit("coverage", ["tools", 1, "input_lists_truncated"], False))

    def test_coverage_is_bound_to_the_probe_and_to_the_instance(self):
        agg = deepcopy(self.agg)
        probed = agg["probe-receipt"]["tools"][0]
        probed["matching_input_count"] = probed["detectors"][0]["matching_input_count"] = 4
        self.assertEqual(names(check("OK_WITH_GAPS", agg)), {"coverage-probe-mismatch"})
        agg = deepcopy(self.agg)
        tool = agg["coverage"]["tools"][0]
        tool["candidate_input_count"], tool["analyzed_input_count"] = 6, 6
        self.assertEqual(names(check("OK_WITH_GAPS", agg)), {"coverage-probe-mismatch"})
        self.assertIn("coverage-applicability", self.edit("coverage", ["tools", 0, "applicability"], SKIP_REASON))
        self.assertIn("coverage-applicability", self.edit("coverage", ["tools", 2, "applicability"], "applicable"))
        failed = deepcopy(self.agg)
        tool = failed["coverage"]["tools"][1]
        tool.update({"analyzed_input_count": 5, "not_analyzed_input_count": 0, "not_analyzed_inputs": [],
                     "input_lists_truncated": False})
        failed["coverage"]["gaps"] = [g for g in failed["coverage"]["gaps"]
                                      if not (g["tool_id"] == "tfsec" and g["kind"] == "inputs-not-analyzed")]
        self.assertEqual(names(check("OK_WITH_GAPS", failed)), {"coverage-analyzed-without-output"})

    def test_probe_receipt_fields(self):
        path = ["tools", 0]
        self.assertIn("probe-applicable", self.edit("probe-receipt", path + ["applicable"], False))
        self.assertIn("probe-applicable", self.edit("probe-receipt", ["tools", 2, "applicable"], True))
        self.assertIn("probe-applicable", self.edit("probe-receipt", ["node_applicable"], False))
        self.assertIn("probe-skip-reason", self.edit("probe-receipt", ["skip_reason"], SKIP_REASON))
        self.assertIn("probe-count", self.edit("probe-receipt", ["files_examined_count"], 4))
        self.assertIn("probe-count", self.edit("probe-receipt", ["files_examined_count"], -1))
        self.assertIn("probe-count", self.edit("probe-receipt", path + ["matching_input_count"], -1))
        detector = self.agg["probe-receipt"]["tools"][0]["detectors"][0]
        self.assertIn("probe-count", self.edit("probe-receipt", path + ["detectors"], [detector, detector]))

    def test_overlapping_detectors_are_representable(self):
        agg = deepcopy(self.agg)
        tool = agg["probe-receipt"]["tools"][0]
        tool["detectors"] = [{"detector_id": "terraform", "patterns_searched": ["**/*.tf"], "matching_input_count": 4},
                             {"detector_id": "cloudformation", "patterns_searched": ["**/*.template.json"],
                              "matching_input_count": 3}]
        self.assertEqual(check("OK_WITH_GAPS", agg), [])  # 5 is between max 4 and sum 7
        tool["detectors"][1]["matching_input_count"] = 0
        self.assertIn("probe-count", names(check("OK_WITH_GAPS", agg)))  # 5 > sum 4

    def test_gaps(self):
        gaps = self.agg["coverage"]["gaps"]
        kinds = [(g["tool_id"], g["kind"]) for g in gaps]
        failed = kinds.index(("tfsec", "tool-instance-failed"))
        not_analyzed = kinds.index(("tfsec", "inputs-not-analyzed"))
        self.assertIn("gap-unfounded", self.edit("coverage", ["gaps", failed, "kind"], "tool-instance-blocked"))
        self.assertIn("gap-unfounded", self.edit("coverage", ["gaps", failed, "tool_id"], "checkov"))
        self.assertIn("gap-unfounded", self.edit("coverage", ["gaps", failed, "affected_input_count"], 5))
        self.assertIn("gap-unfounded", self.edit("coverage", ["gaps", not_analyzed, "affected_input_count"], 4))
        self.assertIn("gap-unfounded", self.edit("coverage", ["gaps", not_analyzed, "affected_input_count"], None))
        self.assertIn("gap-unfounded", self.edit("coverage", ["gaps", not_analyzed, "kind"], "inputs-unsupported"))
        self.assertIn("gap-duplicate-id", self.edit("coverage", ["gaps", failed, "gap_id"], gaps[not_analyzed]["gap_id"]))
        for kind in ("stale-reference-data", "zero-analyzed-inputs", "inputs-not-analyzed", "tool-instance-failed"):
            extra = gaps + [{"gap_id": "gap-on-skipped", "kind": kind, "tool_id": "hadolint",
                             "affected_input_count": None}]
            self.assertIn("gap-unfounded", self.edit("coverage", ["gaps"], extra), kind)

    def test_every_non_ok_instance_status_needs_its_own_named_gap(self):
        for status, kind in shapes.INSTANCE_GAP_KIND.items():
            agg = build_aggregate({"checkov": "OK", "tfsec": status})
            self.assertEqual(check("OK_WITH_GAPS", agg), [], status)
            agg["coverage"]["gaps"] = [g for g in agg["coverage"]["gaps"] if g["kind"] != kind]
            errors = [e for e in check("OK_WITH_GAPS", agg) if e.startswith("gap-missing")]
            self.assertEqual(len(errors), 1, status)
            self.assertIn(kind, errors[0])

    def test_zero_analyzed_and_unsupported_inputs_are_named_gaps_not_a_clean_pass(self):
        agg = build_aggregate({"binskim": "OK"})
        tool = agg["coverage"]["tools"][0]
        tool.update({"analyzed_input_count": 0, "unsupported_input_count": 5, "input_lists_truncated": True})
        found = [e for e in check("OK", agg) if e.startswith("gap-missing")]
        self.assertEqual(len(found), 2, found)
        agg["coverage"]["gaps"] = [
            {"gap_id": "gap-unsupported", "kind": "inputs-unsupported", "tool_id": "binskim", "affected_input_count": 5},
            {"gap_id": "gap-zero", "kind": "zero-analyzed-inputs", "tool_id": "binskim", "affected_input_count": None},
        ]
        self.assertEqual(names(check("OK", agg)), {"node-ok-with-gaps"})
        self.assertEqual(check("OK_WITH_GAPS", agg), [])


class ProjectionInvariantTests(unittest.TestCase):
    """Lesson 4: `supportable_success_status` and `validate_node_aggregate` always agree."""

    def test_a_success_status_is_accepted_if_and_only_if_it_is_the_supportable_one(self):
        cases = 0
        tool_ids = ("tool-a", "tool-b", "tool-c")
        for width in (1, 2, 3):
            for combo in itertools.product(TERMINAL, repeat=width):
                agg = build_aggregate(dict(zip(tool_ids, combo)))
                supportable = supportable_success_status(agg["tool-results"], agg["coverage"])
                for node_status in shapes.NODE_STATUSES:
                    errors = check(node_status, agg)
                    if node_status in shapes.NODE_SUCCESS_STATUSES:
                        self.assertEqual(errors == [], node_status == supportable, f"{combo} as {node_status}: {errors}")
                    else:
                        self.assertEqual(errors, [], f"{combo} as {node_status}")
                    cases += 1
        self.assertEqual(cases, (7 + 49 + 343) * 6)

    def test_supportable_status_follows_the_adr_sentences(self):
        def supportable(*statuses):
            agg = build_aggregate({f"tool-{n}": s for n, s in enumerate(statuses)})
            return supportable_success_status(agg["tool-results"], agg["coverage"])
        self.assertEqual(supportable("OK", "OK"), "OK")
        self.assertEqual(supportable("OK", "SKIPPED"), "OK")
        self.assertEqual(supportable("SKIPPED", "SKIPPED"), "SKIPPED")
        self.assertEqual(supportable("OK", "FAILED"), "OK_WITH_GAPS")
        self.assertEqual(supportable("OK_WITH_GAPS", "BLOCKED"), "OK_WITH_GAPS")
        # "A node whose every tool instance failed is FAILED, not OK_WITH_GAPS"
        self.assertIsNone(supportable("FAILED", "FAILED"))
        self.assertIsNone(supportable("BLOCKED", "CANCELED", "SKIPPED"))
        self.assertIsNone(supportable("UNRESOLVED"))

    def test_instance_gap_kinds_cover_exactly_the_statuses_that_force_a_node_below_ok(self):
        self.assertEqual(set(shapes.INSTANCE_GAP_KIND), set(TERMINAL) - {"OK", "SKIPPED"})


class StructuralMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = SchemaStore()

    def setUp(self):
        self.agg = build_aggregate({"checkov": "OK", "tfsec": "FAILED"})

    def rejected(self, document, schema, *needles):
        joined = "\n".join(validate_document(document, schema, self.store))
        self.assertTrue(joined, f"expected {schema} to reject the mutation")
        for needle in needles:
            self.assertIn(needle, joined)

    def test_structural_errors_are_returned_by_the_aggregate_validator_under_a_schema_name(self):
        self.agg["tool-results"]["tool_instances"][0]["snippet"] = RAW_LINES[0]
        errors = check("OK_WITH_GAPS", self.agg)
        self.assertEqual(names(errors), {"schema"})
        self.assertIn("unexpected property 'snippet'", errors[0])

    def test_no_raw_match_line_fits_anywhere_in_tool_results(self):
        instance = self.agg["tool-results"]["tool_instances"][0]
        for name in ("snippet", "match", "line_text", "evidence_text", "message"):
            mutated = deepcopy(self.agg["tool-results"])
            mutated["tool_instances"][0][name] = RAW_LINES[0]
            self.rejected(mutated, RESULTS, f"unexpected property '{name}'")
            mutated = deepcopy(self.agg["tool-results"])
            mutated["tool_instances"][0]["outputs"][0][name] = RAW_LINES[0]
            self.rejected(mutated, RESULTS, f"unexpected property '{name}'")

        def strings(node, path=()):
            if isinstance(node, dict):
                for key, value in node.items():
                    yield from strings(value, path + (key,))
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    yield from strings(value, path + (index,))
            elif isinstance(node, str):
                yield path

        paths = list(strings(instance))
        self.assertGreater(len(paths), 15)
        for path in paths:
            for line in RAW_LINES:
                mutated = deepcopy(self.agg["tool-results"])
                node = mutated["tool_instances"][0]
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = line
                self.assertTrue(validate_document(mutated, RESULTS, self.store), f"{path} accepted {line!r}")

    def test_no_raw_match_line_fits_in_coverage_or_the_receipt(self):
        for line in RAW_LINES:
            coverage = deepcopy(self.agg["coverage"])
            coverage["tools"][1]["not_analyzed_inputs"][0]["path"] = line
            self.rejected(coverage, COVERAGE, "does not match pattern")
            coverage = deepcopy(self.agg["coverage"])
            coverage["gaps"][0]["gap_id"] = line
            self.rejected(coverage, COVERAGE, "does not match pattern")
            receipt = deepcopy(self.agg["probe-receipt"])
            receipt["tools"][0]["detectors"][0]["patterns_searched"][0] = line
            self.rejected(receipt, RECEIPT, "does not match pattern")
        coverage = deepcopy(self.agg["coverage"])
        coverage["gaps"][0]["detail"] = "free text"
        self.rejected(coverage, COVERAGE, "unexpected property 'detail'")

    def test_a_mutable_image_tag_is_unrepresentable(self):
        for field, value in (("image_digest", ":local"), ("image_digest", "latest"), ("image_digest", "sha256:abc"),
                             ("image_repository", "audit-iac:local"), ("image_repository", "ghcr.io/org/audit-iac:latest"),
                             ("image_repository", "ghcr.io/org/audit-iac:1.2.3"),
                             ("image_repository", "ghcr.io/org/audit-iac@sha256:" + "0" * 64)):
            mutated = deepcopy(self.agg["tool-results"])
            mutated["tool_instances"][0]["identity"][field] = value
            self.rejected(mutated, RESULTS, field, "does not match pattern")
        for name in ("image_tag", "tag", "image"):
            mutated = deepcopy(self.agg["tool-results"])
            mutated["tool_instances"][0]["identity"][name] = "audit-iac:local"
            self.rejected(mutated, RESULTS, f"unexpected property '{name}'")

    def test_argv_is_an_array_and_there_is_no_shell_field(self):
        mutated = deepcopy(self.agg["tool-results"])
        mutated["tool_instances"][0]["argv"] = "checkov -d /src || true"
        self.rejected(mutated, RESULTS, "argv", "expected type 'array'")
        mutated["tool_instances"][0]["argv"] = ["sh", "-c", "checkov -d /src || true"]
        self.rejected(mutated, RESULTS, "argv[2]", "does not match pattern")
        mutated["tool_instances"][0]["argv"] = []
        self.rejected(mutated, RESULTS, "minItems is 1")
        for name in ("command", "shell"):
            mutated = deepcopy(self.agg["tool-results"])
            mutated["tool_instances"][0][name] = "checkov"
            self.rejected(mutated, RESULTS, f"unexpected property '{name}'")

    def test_identity_block_fields_are_all_required(self):
        for field in ("image_digest", "tool_name", "tool_version", "data_identities", "redactor", "executor_kind"):
            mutated = deepcopy(self.agg["tool-results"])
            del mutated["tool_instances"][0]["identity"][field]
            self.rejected(mutated, RESULTS, f"missing required property '{field}'")
        mutated = deepcopy(self.agg["tool-results"])
        del mutated["tool_instances"][0]["identity"]["data_identities"][0]["sha256"]
        self.rejected(mutated, RESULTS, "missing required property 'sha256'")

    def test_redactor_identity_is_nullable_but_closed_when_present(self):
        mutated = deepcopy(self.agg["tool-results"])
        mutated["tool_instances"][0]["identity"]["redactor"] = {
            "redactor_id": "evidence-redaction", "redactor_version": "1.0.0", "ruleset_sha256": sha("ruleset")}
        self.assertEqual(validate_document(mutated, RESULTS, self.store), [])
        del mutated["tool_instances"][0]["identity"]["redactor"]["ruleset_sha256"]
        self.rejected(mutated, RESULTS, "missing required property 'ruleset_sha256'")

    def test_closed_enums_and_types(self):
        for path, value in ((["terminal_status"], "COMPLETE"), (["terminal_status"], "RUNNING"),
                            (["exit", "exit_meaning"], "success"), (["exit", "exit_code"], "1"),
                            (["exit", "exit_code"], True), (["exit", "timed_out"], "no"),
                            (["outputs", 0, "sha256"], "0" * 64), (["outputs", 0, "role"], "findings"),
                            (["outputs", 0, "validation"], "ok"), (["identity", "executor_kind"], "shell"),
                            (["cause_code"], "it broke"), (["result_record_count"], 1.5)):
            mutated = deepcopy(self.agg["tool-results"])
            node = mutated["tool_instances"][0]
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
            self.assertTrue(validate_document(mutated, RESULTS, self.store), path)
        for schema, part in ((RESULTS, "tool-results"), (COVERAGE, "coverage"), (RECEIPT, "probe-receipt")):
            mutated = deepcopy(self.agg[part])
            mutated["schema"] = "appsec-review/other/1.0"
            self.rejected(mutated, schema, "expected const")
        mutated = deepcopy(self.agg["tool-results"])
        mutated["tool_instances"] = []
        self.rejected(mutated, RESULTS, "minItems is 1")
        coverage = deepcopy(self.agg["coverage"])
        coverage["gaps"][0]["kind"] = "todo"
        self.rejected(coverage, COVERAGE, "not in enum")
        coverage = deepcopy(self.agg["coverage"])
        coverage["tools"][0]["applicability"] = "skipped"
        self.rejected(coverage, COVERAGE, "not in enum")



class OutputsOnDiskTests(unittest.TestCase):
    """The aggregate validator proves the documents agree with each other; this proves the listed
    hashes and sizes are true of the files. Both are needed before a worker publishes."""

    def setUp(self):
        import copy, hashlib, tempfile
        self.copy, self.hashlib = copy, hashlib
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "attempt"
        self.root.mkdir()
        golden = Path(__file__).resolve().parent / "fixtures" / "tool-instance-shapes" / "iac-ok-with-gaps" / "tool-results.json"
        self.results = json.loads(golden.read_text(encoding="utf-8"))
        for index, instance in enumerate(self.results["tool_instances"]):
            for number, output in enumerate(instance["outputs"]):
                data = f"synthetic output {index}.{number}\n".encode()
                target = self.root / output["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                output["bytes"] = len(data)
                output["sha256"] = "sha256:" + hashlib.sha256(data).hexdigest()
        self.first = next(o for i in self.results["tool_instances"] for o in i["outputs"])

    def tearDown(self):
        self.temporary.cleanup()

    def check(self, results=None, root=None):
        return shapes.verify_outputs_on_disk(results or self.results, self.root if root is None else root)

    def test_true_statements_about_the_files_verify(self):
        self.assertEqual(self.check(), [])

    def test_attempt_root_is_required(self):
        with self.assertRaises(TypeError):
            shapes.verify_outputs_on_disk(self.results)
        for bad in (None, "", b"x"):
            with self.assertRaises(TypeError):
                shapes.verify_outputs_on_disk(self.results, bad)
        self.assertIn("is not a directory", self.check(root=self.root / "missing")[0])

    def test_listed_hash_edited_alone_is_rejected(self):
        self.first["sha256"] = "sha256:" + "0" * 64
        self.assertTrue(any("does not have the listed sha256" in e for e in self.check()))

    def test_listed_size_edited_alone_is_rejected(self):
        self.first["bytes"] += 1
        self.assertTrue(any("bytes, listed as" in e for e in self.check()))

    def test_file_changed_after_listing_is_rejected(self):
        (self.root / self.first["path"]).write_bytes(b"replaced after the hash was recorded\n")
        self.assertTrue(any("listed sha256" in e or "listed as" in e for e in self.check()))

    def test_listed_but_missing_file_is_rejected(self):
        (self.root / self.first["path"]).unlink()
        self.assertTrue(any("is not a regular file in the attempt" in e for e in self.check()))

    def test_linked_output_is_rejected(self):
        target = self.root / self.first["path"]
        outside = Path(self.temporary.name) / "outside.json"
        outside.write_bytes(target.read_bytes())
        target.unlink()
        try:
            target.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable on this platform")
        self.assertTrue(any("leaves the attempt or is a linked path" in e for e in self.check()))

    def test_one_file_cannot_be_claimed_by_two_tools(self):
        instances = [i for i in self.results["tool_instances"] if i["outputs"]]
        if len(instances) < 2:
            self.skipTest("golden has fewer than two instances with outputs")
        instances[1]["outputs"][0] = self.copy.deepcopy(instances[0]["outputs"][0])
        self.assertTrue(any("is listed by both" in e for e in self.check()))

    def test_malformed_tool_results_are_reported_not_walked(self):
        del self.results["tool_instances"][0]["outputs"]
        self.assertTrue(self.check()[0].startswith("schema:tool-results:"))


class DeclaredToolsTests(unittest.TestCase):
    def test_a_tool_declared_twice_is_refused(self):
        with self.assertRaisesRegex(ValueError, "more than once"):
            shapes.validate_node_aggregate("OK", {}, {}, None, ["bandit", "bandit"], ["OK"])


if __name__ == "__main__":
    unittest.main()
