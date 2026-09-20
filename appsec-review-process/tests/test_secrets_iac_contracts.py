"""Golden and mutation tests for the `secrets-inventory` and `iac-config-evidence` contracts
(ADR-0010, task V04): the two registry contracts, their five schemas and the cross-record rules in
`secrets_iac_contracts.py`.

Goldens are BUILT, not tracked: each is written to a temporary attempt by running the real V06
redactor (`redact_tree`) over a private directory, so every golden is a state a worker can actually
produce, its receipt is real, and no assertion depends on how Git converted a text fixture. A
mutation edits only the field under test, either before publication (an honest receipt over a wrong
document: proves the cross-record rule) or after it (proves the binding to the receipt and bytes).

Secret-shaped values are assembled at run time; `run` asserts after EVERY validation that no planted
value reached an error message.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))

import evidence_redaction as redaction
from schema_validate import SchemaStore, validate_document
import secrets_iac_contracts as contracts
import tool_instance_shapes as shapes
import validate_job_output

SECRETS_SCHEMA = "secrets-inventory.schema.json"
ENTRY_SCHEMA = "secrets-inventory-entry.schema.json"
IAC_SCHEMA = "iac-config-evidence.schema.json"
HIT_SCHEMA = "iac-config-rule-hit.schema.json"
BASE_SCHEMA = "iac-config-base-image-inventory.schema.json"
ALL_SCHEMAS = [SECRETS_SCHEMA, ENTRY_SCHEMA, IAC_SCHEMA, HIT_SCHEMA, BASE_SCHEMA]
CONTRACT_DIR = ROOT / "registry" / "output-contracts"
PROPOSAL = REPO / "docs" / "proposals" / "vendor-prepass" / "job-nodes.proposal.json"
SKIP_REASON = "not-applicable-no-matching-inputs"
POLICY = "refuse"
LIMITS = redaction.DEFAULT_LIMITS
REDACTOR = {"name": redaction.REDACTOR_NAME, "module_version": redaction.MODULE_VERSION,
            "ruleset_sha256": redaction.RULESET_SHA256}

# Assembled here so that no scannable literal exists in the repository. All obviously synthetic.
SECRETS = {
    "AWS_KEY": "AK" + "IA" + "SYNTHETIC0KEY0V4",
    "GITHUB_TOKEN": "gh" + "p_" + "SyntheticV04" * 3,
    "PEM_HEADER": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "NAMED": "pass" + "word = \"v04-synthetic-hunter\"",
    "HIGH_ENTROPY": "q7Zx2" + "Lm9Pw4Rt6Yv8Bn1Cd3Fg5Hj0Ks",
}
PLANTED = [*SECRETS.values(), "v04-synthetic-hunter"]

# Names that could give a match, a fragment, a per-value hash, a length, a tool message or a
# promoted claim a home. None may be a property of any V04 schema.
FORBIDDEN_PROPERTY_NAMES = {
    "value", "values", "secret", "secret_value", "match", "matches", "matched_text", "match_text", "snippet",
    "snippets", "line_text", "lines", "context", "preview", "excerpt", "raw", "raw_output", "entropy", "entropy_sample",
    "sample", "text", "content", "message", "messages", "title", "description", "detail", "details", "note", "notes",
    "summary", "remediation", "guideline", "evidence_text", "stdout", "stderr", "code", "code_block",
    "value_sha256", "value_hash", "secret_sha256", "secret_hash", "fingerprint", "fingerprints", "hash", "digest_of_value",
    "hmac", "checksum", "md5", "sha1", "length", "value_length", "size", "prefix", "suffix", "first_chars", "last_chars",
    "masked", "masked_value", "redacted_value", "column", "start_column", "end_column", "offset", "start_offset",
    "end_offset", "span", "author", "email", "commit", "commit_message", "url", "uri", "link",
    "finding", "findings", "verified_finding", "vulnerability", "vulnerabilities", "severity", "cvss", "cvss_score",
    "exploitability", "runtime_state", "runtime_observation", "observed_runtime", "live_scan", "production_state",
    "valid", "is_valid", "verified", "is_live", "active", "attribute_value", "resource_value", "image", "image_ref",
}


# ---- known cross-task blocker (V03 x V06), reported to the integration owner -------------------
# `tool-results.json`, `coverage.json` and the probe receipt (V03) REQUIRE the key
# `source_snapshot_sha256`. The V06 redactor's entropy rule reads that key as a high-entropy token
# (20+ characters, letters and digits, and `_wordy` refuses the piece `sha256`) and rewrites it to a
# marker, so today NO V03 aggregate can pass through `redact_tree` and stay schema-valid, and no
# attempt of any ADR-0010 node is producible. Neither file is V04's to edit. While the collision
# exists, this suite exempts exactly that one string from the entropy rule so that everything else
# about the contracts is exercised against the real redactor; `KnownBlockerTests` reports the state.
# The shim switches itself off as soon as the redactor stops flagging the key.
V03_HEADER_KEY = "source_snapshot_sha256"
V06_FLAGS_V03_HEADER_KEY = bool(redaction._merged_spans(V03_HEADER_KEY))
_PATCHES = []


def setUpModule():
    if V06_FLAGS_V03_HEADER_KEY:
        original = redaction._exempt
        patch = mock.patch.object(redaction, "_exempt", lambda run: run == V03_HEADER_KEY or original(run))
        patch.start()
        _PATCHES.append(patch)


def tearDownModule():
    while _PATCHES:
        _PATCHES.pop().stop()


def sha_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def label_sha(label: str) -> str:
    return "sha256:" + sha_hex(label.encode("utf-8"))


def dump(document) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def walk_schema(node, path="$"):
    if isinstance(node, dict):
        if "properties" in node:
            yield path, node
        for key, value in node.items():
            yield from walk_schema(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk_schema(value, f"{path}[{index}]")


def string_leaves(node, path="$"):
    """(path, subschema) for every subschema that can accept a string."""
    if isinstance(node, dict):
        types = node.get("type")
        types = types if isinstance(types, list) else [types]
        if "string" in types:
            yield path, node
        for key in ("properties", "items"):
            child = node.get(key)
            if key == "properties" and isinstance(child, dict):
                for name, value in child.items():
                    yield from string_leaves(value, f"{path}.{name}")
            elif isinstance(child, dict):
                yield from string_leaves(child, f"{path}[]")


def names(errors):
    return {error.split(": ", 1)[0] for error in errors}


# ---- golden builder ----------------------------------------------------------------------------

def tool_output_bytes(tool_id: str) -> bytes:
    return dump({"normalized_by": tool_id, "records": "held in the tool instance's own attempt"})


def build_instance(job_id: str, tool_id: str, status: str, records: int | None, executor: str) -> dict:
    container = executor == "pinned_container"
    started = status not in ("SKIPPED", "BLOCKED")
    exit_block = {"OK": (1, "findings-present") if records else (0, "clean"), "OK_WITH_GAPS": (0, "clean"),
                  "SKIPPED": (None, "not-started"), "BLOCKED": (None, "not-started"), "FAILED": (2, "tool-error")}[status]
    cause = {"OK": None, "SKIPPED": None, "OK_WITH_GAPS": "partial-input-coverage",
             "BLOCKED": "offline-operation-unavailable", "FAILED": "tool-error"}[status]
    outputs = []
    if status in ("OK", "OK_WITH_GAPS"):
        data = tool_output_bytes(tool_id)
        outputs = [{"path": f"{tool_id}/outputs/result.json", "sha256": "sha256:" + sha_hex(data), "bytes": len(data),
                    "media_type": "application/json", "role": "normalized-result", "validation": "schema-validated",
                    "validated_against": "tool-normalized-result.schema.json"}]
    return {
        "tool_id": tool_id, "attempt_id": f"{tool_id}-attempt-0001", "terminal_status": status,
        "skip_reason": SKIP_REASON if status == "SKIPPED" else None, "cause_code": cause,
        "identity": {
            "executor_kind": executor,
            "image_repository": "registry.internal.example:5000/appsec/audit-tools" if container else None,
            "image_digest": label_sha("image" + tool_id) if container else None,
            "executable_sha256": None if container else label_sha("module" + tool_id),
            "tool_name": tool_id, "tool_version": "3.2.1" if started else None,
            "data_identities": [{"kind": "policy-bundle" if job_id == "02-iac-config-scan" else "rule-pack",
                                 "identity_id": f"{tool_id}-rules", "version": "2026.09.01",
                                 "sha256": label_sha("rules" + tool_id)}],
            "redactor": {"redactor_id": "evidence-redaction", "redactor_version": redaction.MODULE_VERSION,
                         "ruleset_sha256": "sha256:" + redaction.RULESET_SHA256},
        },
        "argv": [tool_id, "--offline", "--report", "/out/result.json", "/src"],
        "exit": {"exit_code": exit_block[0], "exit_meaning": exit_block[1], "timed_out": False,
                 "nonzero_exit_on_findings": True, "findings_exit_codes": [1]},
        "outputs": outputs, "result_record_count": records if status in ("OK", "OK_WITH_GAPS") else None,
    }


def build_aggregate(header: dict, tools: list[tuple], with_probe: bool) -> dict:
    """tools: (tool_id, status, record count, executor). Consistent tool-results/coverage/probe."""
    instances, covered, gaps, probed = [], [], [], []
    for tool_id, status, records, executor in tools:
        instances.append(build_instance(header["job_id"], tool_id, status, records, executor))
        count = 0 if status == "SKIPPED" else 4
        not_analyzed = {"OK": 0, "SKIPPED": 0, "OK_WITH_GAPS": 1}.get(status, count)
        reason = "parse-failed" if status == "OK_WITH_GAPS" else "tool-instance-did-not-complete"
        listed = [{"path": f"deploy/{tool_id}/input-{n}.tf", "reason_code": reason} for n in range(not_analyzed)]
        covered.append({"tool_id": tool_id, "applicability": SKIP_REASON if status == "SKIPPED" else "applicable",
                        "candidate_input_count": count, "analyzed_input_count": count - not_analyzed,
                        "not_analyzed_input_count": not_analyzed, "unsupported_input_count": 0,
                        "not_analyzed_inputs": listed, "unsupported_inputs": [], "input_lists_truncated": False})
        if status in shapes.INSTANCE_GAP_KIND:
            gaps.append({"gap_id": f"gap-{tool_id}-instance", "kind": shapes.INSTANCE_GAP_KIND[status],
                         "tool_id": tool_id, "affected_input_count": None})
        if not_analyzed:
            gaps.append({"gap_id": f"gap-{tool_id}-not-analyzed", "kind": "inputs-not-analyzed", "tool_id": tool_id,
                         "affected_input_count": not_analyzed})
        probed.append({"tool_id": tool_id, "matching_input_count": count, "applicable": count > 0,
                       "detectors": [{"detector_id": f"{tool_id}-glob", "patterns_searched": ["**/*.tf", "**/Dockerfile*"],
                                      "matching_input_count": count}]})
    documents = {
        contracts.TOOL_RESULTS_FILE: {"schema": "appsec-review/tool-results/1.0", **header, "tool_instances": instances},
        contracts.COVERAGE_FILE: {"schema": "appsec-review/scan-coverage/1.0", **header, "tools": covered, "gaps": gaps},
    }
    if with_probe:
        applicable = any(tool["applicable"] for tool in probed)
        documents[contracts.PROBE_RECEIPT_FILE] = {
            "schema": "appsec-review/applicability-probe-receipt/1.0", **header,
            "probe": {"probe_id": "iac-detector-probe", "probe_version": "1.0.0", "probe_sha256": label_sha("probe")},
            "files_examined_count": 412, "tools": probed, "node_applicable": applicable,
            "skip_reason": None if applicable else SKIP_REASON}
    return documents


def location(path, start=None, end=None):
    return {"path": path, "path_disposition": "published" if path is not None else "withheld-unsafe-path",
            "start_line": start, "end_line": end}


def citation(job_id: str, tool_id: str) -> dict:
    return {"source_class": "raw", "producer": job_id, "attempt_id": f"{tool_id}-attempt-0001",
            "path": f"{tool_id}/outputs/result.json", "sha256": sha_hex(tool_output_bytes(tool_id))}


class Golden:
    def __init__(self, name, contract_id, node_status, permitted, tools, results, with_probe):
        self.name, self.contract_id, self.node_status, self.permitted = name, contract_id, node_status, list(permitted)
        self.declared = [tool[0] for tool in tools]
        job_id = contracts.CONTRACT_POLICIES[contract_id]["job_id"]
        self.header = {"run_id": "20260920T120000Z-v04abc", "job_id": job_id, "attempt_id": "node-attempt-0001",
                       "source_snapshot_sha256": label_sha("snapshot")}
        self.documents = build_aggregate(self.header, tools, with_probe)
        for relative, (schema_id, body) in results.items():
            self.documents[relative] = {"schema": schema_id, **self.header, "redactor": dict(REDACTOR), **body}
        self.tool_files = {f"{tool[0]}/outputs/result.json": tool_output_bytes(tool[0])
                           for tool in tools if tool[1] in ("OK", "OK_WITH_GAPS")}
        self.status = {"status": node_status, "run_id": self.header["run_id"], "attempt_id": self.header["attempt_id"],
                       "dagster_run_id": "dagster-run-v04"}

    @property
    def validate(self):
        return (contracts.validate_secrets_attempt if self.contract_id == contracts.SECRETS_CONTRACT_ID
                else contracts.validate_iac_attempt)

    @property
    def result_file(self):
        return contracts.CONTRACT_POLICIES[self.contract_id]["result_schema"][0]


SECRETS_JOB, IAC_JOB = "02-secrets-inventory", "02-iac-config-scan"


def secrets_entry(number, assertion, tool_id, rule_id, data_class, where):
    return {"entry_id": f"SI-{number:06d}", "assertion": assertion, "tool_id": tool_id, "rule_id": rule_id,
            "data_class": data_class, "confidence": "high", "location": where, "citation": citation(SECRETS_JOB, tool_id)}


def iac_hit(number, tool_id, rule_id, category, kind, address, where, lead=False):
    return {"hit_id": f"IC-{number:06d}", "assertion": "declared-exposure-lead" if lead else "declared-configuration-rule-hit",
            "tool_id": tool_id,
            "rule": {"rule_id": rule_id, "rule_pack": {"kind": "policy-bundle", "identity_id": f"{tool_id}-rules",
                                                       "sha256": label_sha("rules" + tool_id)}},
            "category": category, "exposure": "DECLARED_EXPOSURE" if lead else None,
            "resource": {"iac_kind": kind, "address": address,
                         "address_disposition": "not-applicable" if kind == "dockerfile" else "published"},
            "location": where, "citation": citation(IAC_JOB, tool_id)}


def base_image(number, form, repository, tag, digest, where):
    tool_id = "dockerfile-base-image-inventory"
    return {"reference_id": f"BI-{number:06d}", "assertion": "declared-base-image-reference", "tool_id": tool_id,
            "reference_form": form, "repository": repository, "tag": tag, "digest": digest, "location": where,
            "citation": citation(IAC_JOB, tool_id)}


def goldens() -> dict[str, Golden]:
    secrets_schema, iac_schema = "appsec-review/secrets-inventory/1.0", "appsec-review/iac-config-evidence/1.0"
    base_schema = "appsec-review/iac-config-base-image-inventory/1.0"
    hit_entries = [
        secrets_entry(1, "candidate-secret-location", "gitleaks", "aws-access-token", "cloud-provider-credential",
                      location("services/billing/config/settings.py", 41, 41)),
        secrets_entry(2, "candidate-secret-location", "gitleaks", "generic-api-key", "api-key", location(None, 7, 7)),
        secrets_entry(3, "credential-store-file-present", "key-material-file-inventory", "key-store-extension",
                      "key-store-file", location("deploy/certs/service.p12")),
        secrets_entry(4, "private-key-header-present", "key-material-file-inventory", "pem-private-key-header",
                      "private-key", location("deploy/certs/service.pem", 1, 28)),
    ]
    iac_tools = [("checkov", "OK", 2, "pinned_container"), ("trivy-config", "BLOCKED", None, "pinned_container"),
                 ("tfsec", "OK_WITH_GAPS", 1, "pinned_container"), ("kube-linter", "SKIPPED", None, "pinned_container"),
                 ("hadolint", "OK", 1, "pinned_container"),
                 ("dockerfile-base-image-inventory", "OK", 3, "deterministic_python")]
    hits = [
        iac_hit(1, "checkov", "CKV_AWS_24", "network-exposure", "terraform", "module.net.aws_security_group.web",
                location("deploy/terraform/network.tf", 12, 30), lead=True),
        iac_hit(2, "checkov", "CKV_AWS_19", "encryption-at-rest", "terraform", "aws_s3_bucket.logs",
                location("deploy/terraform/storage.tf", 3, 9)),
        iac_hit(3, "tfsec", "aws-s3-no-public-access", "public-access-grant", "terraform", "aws_s3_bucket.assets",
                location("deploy/terraform/storage.tf", 14, 22), lead=True),
        iac_hit(4, "hadolint", "DL3002", "privilege-escalation", "dockerfile", None, location("docker/Dockerfile", 9, 9)),
    ]
    images = [
        base_image(1, "literal", "registry.internal.example:5000/base/python", "3.12-slim", label_sha("base"),
                   location("docker/Dockerfile", 1, 1)),
        base_image(2, "build-arg-parameterized", None, None, None, location("docker/Dockerfile.worker", 2, 2)),
        base_image(3, "scratch", None, None, None, location("docker/Dockerfile.worker", 11, 11)),
    ]
    return {golden.name: golden for golden in (
        Golden("secrets-hits", contracts.SECRETS_CONTRACT_ID, "OK", contracts.NEVER_SKIPS,
               [("gitleaks", "OK", 2, "pinned_container"), ("key-material-file-inventory", "OK", 2, "deterministic_python")],
               {contracts.SECRETS_RESULT_FILE: (secrets_schema, {"entries": hit_entries})}, with_probe=False),
        Golden("secrets-tool-failed", contracts.SECRETS_CONTRACT_ID, "OK_WITH_GAPS", contracts.NEVER_SKIPS,
               [("gitleaks", "FAILED", None, "pinned_container"), ("key-material-file-inventory", "OK", 0, "deterministic_python")],
               {contracts.SECRETS_RESULT_FILE: (secrets_schema, {"entries": []})}, with_probe=False),
        Golden("iac-ok-with-gaps", contracts.IAC_CONTRACT_ID, "OK_WITH_GAPS", contracts.CAN_SKIP, iac_tools,
               {contracts.IAC_RESULT_FILE: (iac_schema, {"rule_hits": hits}),
                contracts.BASE_IMAGE_FILE: (base_schema, {"base_images": images})}, with_probe=True),
        Golden("iac-skipped", contracts.IAC_CONTRACT_ID, "SKIPPED", contracts.CAN_SKIP,
               [(tool[0], "SKIPPED", None, tool[3]) for tool in iac_tools],
               {contracts.IAC_RESULT_FILE: (iac_schema, {"rule_hits": []}),
                contracts.BASE_IMAGE_FILE: (base_schema, {"base_images": []})}, with_probe=True),
    )}


class Attempt:
    """One golden published into a temporary directory by the real redactor."""

    def __init__(self, test: unittest.TestCase, golden: Golden, mutate=None, extra_private=None):
        self.golden = deepcopy(golden)
        if mutate:
            mutate(self.golden)
        directory = tempfile.TemporaryDirectory()
        test.addCleanup(directory.cleanup)
        base = Path(directory.name)
        self.tool_root, self.root = base / "job", base / "job" / "attempts" / self.golden.header["attempt_id"]
        private = base / "private"
        for relative, document in self.golden.documents.items():
            target = private / Path(relative).name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(dump(document))
        for name, data in (extra_private or {}).items():
            (private / name).write_bytes(data)
        self.root.mkdir(parents=True)
        self.receipt = redaction.redact_tree(private, self.root / "outputs", on_unhandled=POLICY, limits=LIMITS)
        (self.root / "status.json").write_bytes(dump(self.golden.status))
        (self.root / "manifest.json").write_bytes(dump({"schema": "appsec-review/v04-test-manifest/1",
                                                        "run_id": self.golden.header["run_id"]}))
        for relative, data in self.golden.tool_files.items():
            target = self.tool_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)

    def arguments(self, **override):
        values = {"tool_outputs_root": self.tool_root, "node_status": self.golden.node_status,
                  "declared_tool_ids": self.golden.declared, "permitted_node_statuses": self.golden.permitted,
                  "on_unhandled": POLICY, "limits": LIMITS}
        values.update(override)
        return values

    def run(self, **override):
        errors = self.golden.validate(self.root, **self.arguments(**override))
        assert isinstance(errors, list) and all(isinstance(error, str) for error in errors)
        for error in errors:  # the invariant, checked on every validation this suite performs
            for planted in PLANTED:
                assert planted not in error, "a planted secret value reached an error message"
            assert re.match(r"[a-z][a-z0-9:-]*: ", error), f"unnamed error: {error!r}"
        return errors


GOLDENS = goldens()


def edit(relative, function):
    def mutate(golden):
        function(golden.documents[relative])
    return mutate


# ---- contracts and schemas ---------------------------------------------------------------------

class ContractDeclarationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proposal = {node["proposed_output_contract_id"]: node
                        for node in json.loads(PROPOSAL.read_text(encoding="utf-8"))["proposed_nodes"]}

    def contract(self, contract_id):
        return json.loads((CONTRACT_DIR / f"{contract_id}.json").read_text(encoding="utf-8"))

    def test_registry_contracts_are_schema_valid_and_match_the_pinned_policy(self):
        for contract_id in contracts.CONTRACT_POLICIES:
            record = self.contract(contract_id)
            self.assertEqual(validate_document(record, "output-contract.schema.json"), [])
            self.assertEqual(record["contract_id"], contract_id)
            self.assertEqual(contracts.contract_declaration_errors(record), [])

    def test_contract_policy_and_proposal_are_three_projections_of_one_decision(self):
        """ADR-0010's fixture is the source of truth; the single, deliberate addition is the probe
        receipt file on the contract whose node may be SKIPPED (no ADR contract listed one)."""
        for contract_id, policy in contracts.CONTRACT_POLICIES.items():
            node, record = self.proposal[contract_id], self.contract(contract_id)
            self.assertTrue(node["adopted"])
            self.assertEqual(node["proposed_job_id"], policy["job_id"])
            added = {contracts.PROBE_RECEIPT_FILE} if "SKIPPED" in node["permitted_terminal_statuses"] else set()
            self.assertEqual(set(record["required_files"]), set(node["required_artifacts"]) | added)
            self.assertEqual(set(policy["required_files"]), set(record["required_files"]))
            self.assertEqual(record["claim_class"], node["proposed_claim_class"])
            self.assertEqual(list(policy["allowed_assertions"]), node["proposed_claim_class"]["allowed_assertions"])
            self.assertEqual(list(policy["permitted_node_statuses"]), node["permitted_terminal_statuses"])
            self.assertEqual(policy["probe_receipt"], bool(added))
            self.assertEqual(record["result_schema"]["artifact"], node["required_artifacts"][2])  # first outputs/ file
            self.assertTrue((REPO / "schemas" / record["result_schema"]["schema_file"]).is_file())

    def test_goldens_use_the_tools_and_ids_the_proposal_names(self):
        for golden in GOLDENS.values():
            node = self.proposal[golden.contract_id]
            self.assertEqual(golden.declared, [tool["tool_id"] for tool in node["tool_instances"]])
            self.assertEqual(golden.header["job_id"], node["proposed_job_id"])
            self.assertIn(golden.node_status, node["permitted_terminal_statuses"])
            executors = {tool["tool_id"]: tool.get("worker_kind", node["worker_kind"]) for tool in node["tool_instances"]}
            for instance in golden.documents[contracts.TOOL_RESULTS_FILE]["tool_instances"]:
                self.assertEqual(instance["identity"]["executor_kind"], executors[instance["tool_id"]])

    def test_every_allowed_assertion_has_exactly_one_home(self):
        store = SchemaStore()
        homes = {
            contracts.SECRETS_CONTRACT_ID: set(store.load(ENTRY_SCHEMA)["properties"]["assertion"]["enum"]),
            contracts.IAC_CONTRACT_ID: set(store.load(HIT_SCHEMA)["properties"]["assertion"]["enum"])
            | {store.load(BASE_SCHEMA)["properties"]["base_images"]["items"]["properties"]["assertion"]["const"]},
        }
        elsewhere = {contracts.SECRETS_CONTRACT_ID: {"redaction-applied", "scan-coverage-gap"},
                     contracts.IAC_CONTRACT_ID: {"scan-coverage-gap"}}  # the receipt and coverage.json
        for contract_id, policy in contracts.CONTRACT_POLICIES.items():
            self.assertEqual(homes[contract_id] | elsewhere[contract_id], set(policy["allowed_assertions"]))
            self.assertFalse(homes[contract_id] & elsewhere[contract_id])

    def test_a_weakened_contract_declaration_is_rejected(self):
        def drop(field, value):
            def mutate(record):
                record[field].remove(value)
            return mutate

        def promotion(record):
            record["claim_class"]["forbidden_promotions"].remove("runtime-state")

        def assertion(record):
            record["claim_class"]["allowed_assertions"].append("verified-live-credential")

        def class_id(record):
            record["claim_class"]["claim_class_id"] = "supplied_partition_map"

        def schema_file(record):
            record["result_schema"]["schema_file"] = "tool-results.schema.json"

        def no_claim(record):
            del record["claim_class"]

        cases = [(drop("required_files", contracts.RECEIPT_FILE), "contract-required-files"),
                 (drop("required_files", contracts.COVERAGE_FILE), "contract-required-files"),
                 (drop("required_status_fields", "attempt_id"), "contract-status-fields"),
                 (promotion, "contract-forbidden-promotions"), (assertion, "contract-claim-class"),
                 (class_id, "contract-claim-class"), (schema_file, "contract-result-schema"), (no_claim, "contract-claim-class")]
        for contract_id in contracts.CONTRACT_POLICIES:
            for mutate, expected in cases:
                record = self.contract(contract_id)
                mutate(record)
                with self.subTest(contract=contract_id, case=expected, mutate=mutate.__name__):
                    self.assertEqual(names(contracts.contract_declaration_errors(record)), {expected})
        record = self.contract(contracts.IAC_CONTRACT_ID)
        record["required_files"].remove(contracts.PROBE_RECEIPT_FILE)
        self.assertEqual(names(contracts.contract_declaration_errors(record)), {"contract-required-files"})
        record = self.contract(contracts.SECRETS_CONTRACT_ID)
        record["claim_class"]["forbidden_promotions"].append("exploitability")  # outside the closed enum
        self.assertEqual(names(contracts.contract_declaration_errors(record)), {"contract-schema"})
        record["contract_id"] = "license-inventory"
        record["claim_class"]["forbidden_promotions"].pop()
        self.assertEqual(names(contracts.contract_declaration_errors(record)), {"contract-unknown"})
        with self.assertRaises(TypeError):
            contracts.contract_declaration_errors(None)

    def test_the_pinned_policy_cannot_be_edited_in_place(self):
        with self.assertRaises(TypeError):
            contracts.CONTRACT_POLICIES[contracts.SECRETS_CONTRACT_ID]["required_files"] = ()
        with self.assertRaises(TypeError):
            contracts.CONTRACT_POLICIES["extra"] = {}
        self.assertIsInstance(contracts.CONTRACT_POLICIES[contracts.IAC_CONTRACT_ID]["required_files"], tuple)

    def test_validation_rules_name_the_receipt_and_the_declared_only_rule(self):
        secrets_rules = " ".join(self.contract(contracts.SECRETS_CONTRACT_ID)["validation_rules"])
        iac_rules = " ".join(self.contract(contracts.IAC_CONTRACT_ID)["validation_rules"])
        for rules in (secrets_rules, iac_rules):
            self.assertIn("outputs/redaction-receipt.json is required", rules)
            self.assertIn("cannot promote", rules)
            for undecided in ("recommended", "proposed", "should consider", "TBD"):
                self.assertNotIn(undecided, rules)
        self.assertIn("hash, HMAC or digest of an individual value", secrets_rules)
        self.assertIn("OBSERVED_EXPOSURE", iac_rules)
        self.assertIn(SKIP_REASON, iac_rules)


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
                self.assertEqual(set(node.get("required", [])), set(node["properties"]), f"{name} {path}")

    def test_only_subset_keywords_and_sibling_refs_are_used(self):
        supported = {"$schema", "$id", "title", "description", "type", "required", "properties", "additionalProperties",
                     "enum", "const", "pattern", "items", "minItems", "$ref"}

        def keywords(node, inside_properties=False):
            if isinstance(node, dict):
                for key, value in node.items():
                    if not inside_properties:
                        yield key
                    yield from keywords(value, inside_properties=(key == "properties" and not inside_properties))
            elif isinstance(node, list):
                for value in node:
                    yield from keywords(value)

        for name in ALL_SCHEMAS:
            schema = self.store.load(name)
            self.assertLessEqual(set(keywords(schema)), supported, name)
            for reference in re.findall(r'"\$ref": "([^"]+)"', json.dumps(schema)):
                self.assertTrue((REPO / "schemas" / reference).is_file(), reference)

    def test_no_property_name_can_hold_a_match_a_per_value_hash_or_a_promoted_claim(self):
        hashish = re.compile(r"(?i)(hash|hmac|digest|checksum|md5|sha1|sha256|sha512|fingerprint|entropy|length|prefix|suffix)")
        # The only hash-bearing names allowed, each a FILE, snapshot, rule-pack or ruleset identity.
        allowed_hash_names = {"source_snapshot_sha256", "ruleset_sha256", "sha256", "digest"}
        for name in ALL_SCHEMAS:
            for path, node in walk_schema(self.store.load(name)):
                for property_name in node["properties"]:
                    self.assertNotIn(property_name.lower(), FORBIDDEN_PROPERTY_NAMES, f"{name} {path}")
                    if hashish.search(property_name):
                        self.assertIn(property_name, allowed_hash_names, f"{name} {path}.{property_name}")
        entry = self.store.load(ENTRY_SCHEMA)["properties"]
        self.assertEqual([key for key in entry if hashish.search(key)], [])  # an entry itself holds no hash at all
        self.assertEqual(set(entry["citation"]["properties"]), {"source_class", "producer", "attempt_id", "path", "sha256"})

    def test_no_property_name_would_be_wholesale_redacted_by_the_v06_redactor(self):
        """A key holding one of the redactor's keywords has its VALUE replaced by a marker, which
        would make the published document unproducible."""
        for name in ALL_SCHEMAS:
            for path, node in walk_schema(self.store.load(name)):
                for property_name in node["properties"]:
                    self.assertIsNone(redaction._KEYWORD_RE.search(property_name), f"{name} {path}.{property_name}")

    # Strings that are not free: each must equal a value in another document (or the caller's
    # argument), so it cannot be chosen to carry anything. BindingTests edits each one alone.
    BOUND = ("$.run_id", "$.attempt_id", ".citation.attempt_id", ".citation.producer", ".citation.path", ".tool_id",
             ".rule_pack.identity_id", ".module_version")
    FILE_IDENTITIES = ("source_snapshot_sha256", "ruleset_sha256", ".sha256", ".digest")

    def test_every_string_is_a_const_an_enum_or_an_anchored_pattern_with_no_room_for_text(self):
        texts = ("two words", "line one\nline two", "tab\there", "a=b", "a:b c", "quote\"d", "paren(x)", "x" * 2000,
                 "trailing\n", "", SECRETS["NAMED"], SECRETS["PEM_HEADER"], "https://user:pw@host/x")
        for name in ALL_SCHEMAS:
            leaves = list(string_leaves(self.store.load(name)))
            self.assertTrue(leaves)
            for path, leaf in leaves:
                if "enum" in leaf:
                    continue
                pattern = leaf.get("pattern")
                self.assertIsNotNone(pattern, f"{name} {path} is free text")
                self.assertTrue(pattern.startswith("^") and pattern.endswith("\\Z"), f"{name} {path}: {pattern}")
                self.assertNotIn("$", pattern, f"{name} {path}")
                for text in texts:
                    self.assertIsNone(re.match(pattern, text), f"{name} {path} accepts {text[:12]!r}")

    def test_no_free_string_field_can_carry_a_digest(self):
        """Token-shaped values are the redactor's job (AcceptanceMutationTests); a hex digest is
        exempt from its entropy rule, so the schemas themselves refuse a 32+ hex run in every string
        that is not bound to another document and is not a named file, snapshot or ruleset identity."""
        digests = ["a3" * 16, "0F" * 20, "b7" * 32, "sha256:" + "c1" * 32, "dir/" + "d4" * 32 + ".js", "x-" + "e5" * 16]
        free = []
        for name in ALL_SCHEMAS:
            for path, leaf in string_leaves(self.store.load(name)):
                if "enum" in leaf or path.endswith(self.BOUND) or path.endswith(self.FILE_IDENTITIES):
                    continue
                free.append(path.rsplit(".", 1)[-1])
                for value in digests:
                    self.assertIsNone(re.match(leaf["pattern"], value), f"{name} {path} accepts a digest")
        self.assertEqual(set(free), {"entry_id", "rule_id", "path", "hit_id", "address", "reference_id", "repository", "tag"})

    def test_observed_exposure_is_schema_valid_on_purpose(self):
        exposure = self.store.load(HIT_SCHEMA)["properties"]["exposure"]
        self.assertEqual(exposure["enum"], ["DECLARED_EXPOSURE", "OBSERVED_EXPOSURE", None])
        hit = deepcopy(GOLDENS["iac-ok-with-gaps"].documents[contracts.IAC_RESULT_FILE]["rule_hits"][0])
        hit["exposure"] = "OBSERVED_EXPOSURE"
        self.assertEqual(validate_document(hit, HIT_SCHEMA, self.store), [])  # the validator rejects it by name instead
        hit["exposure"] = "RUNTIME_EXPOSURE"
        self.assertTrue(validate_document(hit, HIT_SCHEMA, self.store))

    def test_goldens_are_schema_valid_and_mutations_of_the_shape_are_not(self):
        documents = GOLDENS["secrets-hits"].documents
        inventory = documents[contracts.SECRETS_RESULT_FILE]
        self.assertEqual(validate_document(inventory, SECRETS_SCHEMA, self.store), [])
        iac = GOLDENS["iac-ok-with-gaps"].documents
        self.assertEqual(validate_document(iac[contracts.IAC_RESULT_FILE], IAC_SCHEMA, self.store), [])
        self.assertEqual(validate_document(iac[contracts.BASE_IMAGE_FILE], BASE_SCHEMA, self.store), [])

        def entry_with(**fields):
            document = deepcopy(inventory)
            document["entries"][0].update(fields)
            return validate_document(document, SECRETS_SCHEMA, self.store)

        for forbidden in ("value", "match", "snippet", "line_text", "context", "preview", "excerpt", "raw",
                          "entropy_sample", "value_sha256", "fingerprint", "hash", "digest", "hmac", "length", "prefix",
                          "suffix", "severity", "finding", "runtime_state"):
            with self.subTest(property=forbidden):
                self.assertTrue(entry_with(**{forbidden: SECRETS["AWS_KEY"]}))
                self.assertTrue(entry_with(**{forbidden: 12}))
        for field, value in (("rule_id", SECRETS["NAMED"]), ("rule_id", "b7" * 20), ("data_class", SECRETS["AWS_KEY"]),
                             ("confidence", "critical"), ("assertion", "verified-live-credential"),
                             ("entry_id", "SI-" + SECRETS["AWS_KEY"]), ("tool_id", SECRETS["PEM_HEADER"])):
            with self.subTest(field=field):
                self.assertTrue(entry_with(**{field: value}))
        for path in (SECRETS["NAMED"], "config/" + "e9" * 32, "a b", "/etc/passwd", "C:\\keys", "x\n"):
            document = deepcopy(inventory)
            document["entries"][0]["location"]["path"] = path
            self.assertTrue(validate_document(document, SECRETS_SCHEMA, self.store), path[:6])
        for field in ("message", "title", "description", "remediation", "attribute_value", "severity"):
            document = deepcopy(iac[contracts.IAC_RESULT_FILE])
            document["rule_hits"][0][field] = "ingress 0.0.0.0/0 on " + SECRETS["NAMED"]
            self.assertTrue(validate_document(document, IAC_SCHEMA, self.store), field)
        for address in ('aws_s3_bucket.logs["' + SECRETS["AWS_KEY"] + '"]', "a b", "user:pw@host", "x" * 129):
            document = deepcopy(iac[contracts.IAC_RESULT_FILE])
            document["rule_hits"][0]["resource"]["address"] = address
            self.assertTrue(validate_document(document, IAC_SCHEMA, self.store))
        for repository in ("https://user:pw@registry.example/base", "registry.example/base:latest", "Registry/Base"):
            document = deepcopy(iac[contracts.BASE_IMAGE_FILE])
            document["base_images"][0]["repository"] = repository
            self.assertTrue(validate_document(document, BASE_SCHEMA, self.store), repository)


# ---- goldens -----------------------------------------------------------------------------------

class GoldenTests(unittest.TestCase):
    def test_every_golden_is_producible_and_validates(self):
        for name, golden in GOLDENS.items():
            with self.subTest(golden=name):
                attempt = Attempt(self, golden)
                self.assertEqual(attempt.receipt["totals"]["redactions_total"], 0)  # nothing had to be redacted
                self.assertEqual(attempt.receipt["totals"]["files_withheld"], 0)
                self.assertEqual(attempt.run(), [])

    def test_golden_ids_resolve_within_and_across_documents(self):
        for name, golden in GOLDENS.items():
            documents = golden.documents
            instances = {inst["tool_id"]: inst for inst in documents[contracts.TOOL_RESULTS_FILE]["tool_instances"]}
            self.assertEqual(list(instances), golden.declared, name)
            self.assertEqual([tool["tool_id"] for tool in documents[contracts.COVERAGE_FILE]["tools"]], golden.declared)
            records = []
            for relative, key in ((contracts.SECRETS_RESULT_FILE, "entries"), (contracts.IAC_RESULT_FILE, "rule_hits"),
                                  (contracts.BASE_IMAGE_FILE, "base_images")):
                records += documents.get(relative, {}).get(key, [])
            for record in records:
                instance = instances[record["tool_id"]]
                self.assertEqual(record["citation"]["attempt_id"], instance["attempt_id"])
                self.assertIn(record["citation"]["path"], golden.tool_files)
            for tool_id, instance in instances.items():
                cited = sum(record["tool_id"] == tool_id for record in records)
                self.assertEqual(cited, instance["result_record_count"] or 0, f"{name} {tool_id}")

    def test_the_shared_validator_accepts_the_golden_result_and_rejects_a_promotion(self):
        """`validate_job_output.validate_contract_result` is the shared runtime path. Its trusted
        claim-class table is integration-owned, so it is patched here exactly as the integrator
        will extend it; nothing else about that validator is changed."""
        trusted = {contract_id: {"claim_class_id": policy["claim_class_id"],
                                 "allowed_assertions": set(policy["allowed_assertions"])}
                   for contract_id, policy in contracts.CONTRACT_POLICIES.items()}
        for name, golden in GOLDENS.items():
            record = json.loads((CONTRACT_DIR / f"{golden.contract_id}.json").read_text(encoding="utf-8"))
            attempt = Attempt(self, golden)
            unpatched = validate_job_output.validate_contract_result(attempt.root, record, run_id=golden.header["run_id"])
            self.assertEqual([error for error in unpatched if "no trusted claim-class policy" not in error], [], name)
            with mock.patch.dict(validate_job_output.CLAIM_CLASS_POLICIES, trusted):
                self.assertEqual(validate_job_output.validate_contract_result(
                    attempt.root, record, run_id=golden.header["run_id"]), [], name)
                for key in ("severity", "findings", "runtime_state"):
                    promoted = Attempt(self, golden, edit(golden.result_file, lambda doc, key=key: doc.update({key: "high"})))
                    errors = validate_job_output.validate_contract_result(promoted.root, record, run_id=golden.header["run_id"])
                    self.assertTrue(any("promotion is forbidden" in error for error in errors), (name, key))
                    self.assertTrue(any("unexpected property" in error for error in errors), (name, key))
                    self.assertIn("schema:result", names(promoted.run()))


# ---- required inputs ---------------------------------------------------------------------------

class RequiredInputTests(unittest.TestCase):
    KEYWORDS = ("tool_outputs_root", "node_status", "declared_tool_ids", "permitted_node_statuses", "on_unhandled", "limits")

    def test_no_safety_input_has_a_default(self):
        for function in (contracts.validate_secrets_attempt, contracts.validate_iac_attempt):
            parameters = inspect.signature(function).parameters
            self.assertEqual(tuple(parameters), ("attempt_root", *self.KEYWORDS))
            for parameter in parameters.values():
                self.assertIs(parameter.default, inspect.Parameter.empty, parameter.name)

    def test_omitting_or_nulling_any_input_is_a_type_error(self):
        for name in ("secrets-hits", "iac-ok-with-gaps"):
            attempt = Attempt(self, GOLDENS[name])
            for keyword in self.KEYWORDS:
                arguments = attempt.arguments()
                del arguments[keyword]
                with self.subTest(golden=name, omitted=keyword), self.assertRaises(TypeError):
                    attempt.golden.validate(attempt.root, **arguments)
                with self.subTest(golden=name, none=keyword), self.assertRaises(TypeError):
                    attempt.golden.validate(attempt.root, **attempt.arguments(**{keyword: None}))
            with self.assertRaises(TypeError):
                attempt.golden.validate(**attempt.arguments())
            for bad in (None, "", b"x"):
                with self.assertRaises(TypeError):
                    attempt.golden.validate(bad, **attempt.arguments())
            for keyword, bad in (("declared_tool_ids", "gitleaks"), ("permitted_node_statuses", "OK"),
                                 ("on_unhandled", "copy"), ("limits", {"max_file_bytes": 1}), ("node_status", 0)):
                with self.subTest(golden=name, bad=keyword), self.assertRaises(TypeError):
                    attempt.run(**{keyword: bad})
            self.assertEqual(names(attempt.golden.validate(attempt.root / "missing", **attempt.arguments())), {"attempt-root"})

    def test_the_callers_facts_are_not_taken_from_the_documents(self):
        secrets, iac = Attempt(self, GOLDENS["secrets-hits"]), Attempt(self, GOLDENS["iac-ok-with-gaps"])
        self.assertIn("aggregate", names(secrets.run(declared_tool_ids=["gitleaks"])))
        self.assertIn("aggregate", names(secrets.run(declared_tool_ids=[*secrets.golden.declared, "trufflehog"])))
        self.assertIn("aggregate", names(secrets.run(node_status="OK_WITH_GAPS")))
        self.assertIn("aggregate", names(iac.run(node_status="OK")))
        self.assertIn("aggregate", names(iac.run(permitted_node_statuses=["OK"])))
        self.assertIn("status-mismatch", names(iac.run(node_status="OK")))
        self.assertEqual(names(secrets.run(on_unhandled="withhold")), {"receipt-invalid"})
        tighter = redaction.Limits(**{**redaction.asdict(LIMITS), "max_files": 10})
        self.assertEqual(names(secrets.run(limits=tighter)), {"receipt-invalid"})

    def test_the_wrong_contract_for_the_attempt_is_rejected(self):
        secrets, iac = Attempt(self, GOLDENS["secrets-hits"]), Attempt(self, GOLDENS["iac-ok-with-gaps"])
        self.assertIn("required-file-missing", names(contracts.validate_iac_attempt(secrets.root, **secrets.arguments())))
        self.assertIn("required-file-missing", names(contracts.validate_secrets_attempt(iac.root, **iac.arguments())))
        errors = secrets.run(permitted_node_statuses=contracts.CAN_SKIP)  # a secrets node can never be permitted to skip
        self.assertIn("status-not-permitted-by-contract", names(errors))


# ---- acceptance mutations ----------------------------------------------------------------------

class AcceptanceMutationTests(unittest.TestCase):
    def test_a_secret_value_is_rejected_at_every_layer(self):
        golden = GOLDENS["secrets-hits"]
        for label, value in SECRETS.items():
            with self.subTest(secret=label):
                # 1. smuggled into a new property before publication: the redactor marks it, the closed schema refuses it
                def add(document, value=value):
                    document["entries"][0]["value"] = value
                self.assertEqual(names(Attempt(self, golden, edit(golden.result_file, add)).run()), {"schema:result"})

                # 2. smuggled into an existing field before publication
                def path(document, value=value):
                    document["entries"][0]["location"]["path"] = "config/" + value
                self.assertEqual(names(Attempt(self, golden, edit(golden.result_file, path)).run()), {"schema:result"})

                # 3. written into the published inventory after the receipt was sealed
                attempt = Attempt(self, golden)
                target = attempt.root / contracts.SECRETS_RESULT_FILE
                document = json.loads(target.read_bytes().decode("utf-8"))
                document["entries"][0]["rule_id"] = value
                target.write_bytes(dump(document))
                self.assertEqual(names(attempt.run()), {"receipt-invalid"})

    def test_secret_material_in_any_published_file_fails_the_receipt_even_when_the_receipt_is_rewritten(self):
        """The forger rehashes the receipt so it describes the planted bytes exactly. Only the
        fixed-point re-run of the redactor can notice, and it does."""
        for name in ("secrets-hits", "iac-ok-with-gaps"):
            golden = GOLDENS[name]
            for relative in (golden.result_file, contracts.TOOL_RESULTS_FILE, contracts.COVERAGE_FILE):
                attempt = Attempt(self, golden)
                target = attempt.root / relative
                document = json.loads(target.read_bytes().decode("utf-8"))
                document["run_id"] = SECRETS["AWS_KEY"]
                target.write_bytes(dump(document))
                receipt = deepcopy(attempt.receipt)
                for record in receipt["files"]:
                    if record["path"] == Path(relative).name:
                        record["published_sha256"] = record["source_sha256"] = sha_hex(target.read_bytes())
                        record["published_bytes"] = len(target.read_bytes())
                receipt["totals"] = redaction._totals(receipt["files"])
                receipt = redaction._seal(receipt)
                (attempt.root / contracts.RECEIPT_FILE).write_bytes(redaction.receipt_bytes(receipt))
                with self.subTest(golden=name, file=relative):
                    errors = attempt.run()
                    self.assertEqual(names(errors), {"receipt-invalid"})
                    self.assertTrue(any("not a fixed point" in error for error in errors))

    def test_a_secret_shaped_path_never_survives(self):
        golden = GOLDENS["secrets-hits"]
        for value in ("keys/" + SECRETS["HIGH_ENTROPY"] + ".txt", "keys/" + SECRETS["AWS_KEY"]):
            self.assertEqual(validate_document({"entries": []}, SECRETS_SCHEMA)[:0], [])
            self.assertIsNotNone(re.match(SchemaStore().load(ENTRY_SCHEMA)["properties"]["location"]["properties"]["path"]["pattern"], value),
                                 "the schema alone cannot tell; the redactor must")

            def path(document, value=value):
                document["entries"][0]["location"]["path"] = value
            # before publication: the redactor replaces the path with a marker, which the pattern refuses
            self.assertEqual(names(Attempt(self, golden, edit(golden.result_file, path)).run()), {"schema:result"})
        # the producible state for such a location is a withheld path, which the golden already carries
        withheld = [entry for entry in golden.documents[golden.result_file]["entries"] if entry["location"]["path"] is None]
        self.assertEqual(len(withheld), 1)

    def test_a_per_value_hash_is_rejected(self):
        golden = GOLDENS["secrets-hits"]
        digest_value = sha_hex(SECRETS["AWS_KEY"].encode("utf-8"))
        for field in ("value_sha256", "fingerprint", "hash", "digest", "hmac", "value_length"):
            def add(document, field=field):
                document["entries"][0][field] = digest_value
            with self.subTest(field=field):
                errors = Attempt(self, golden, edit(golden.result_file, add)).run()
                self.assertEqual(names(errors), {"schema:result"})
                self.assertTrue(any(f"unexpected property '{field}'" in error for error in errors))
                self.assertFalse(any(digest_value in error for error in errors))
        for setter in (lambda entry: entry.update(rule_id=digest_value[:40]),
                       lambda entry: entry["location"].update(path="keys/" + digest_value),
                       lambda entry: entry.update(entry_id="SI-" + digest_value[:6])):
            def smuggle(document, setter=setter):
                setter(document["entries"][0])
            self.assertEqual(names(Attempt(self, golden, edit(golden.result_file, smuggle)).run()), {"schema:result"})

    def test_a_missing_receipt_is_rejected(self):
        for name, golden in GOLDENS.items():
            attempt = Attempt(self, golden)
            (attempt.root / contracts.RECEIPT_FILE).unlink()
            with self.subTest(golden=name):
                errors = attempt.run()
                self.assertEqual(names(errors), {"receipt-missing"})
                self.assertEqual(len(errors), 1)

    def test_an_unverifiable_receipt_is_rejected(self):
        golden = GOLDENS["secrets-hits"]

        def rewrite(attempt, mutate):
            receipt = deepcopy(attempt.receipt)
            mutate(receipt)
            (attempt.root / contracts.RECEIPT_FILE).write_bytes(redaction.receipt_bytes(receipt))

        def foreign_ruleset(receipt):
            receipt["redactor"]["ruleset_sha256"] = "0" * 64

        def unsealed(receipt):
            receipt["totals"]["redactions_total"] = 3

        for mutate in (foreign_ruleset, unsealed):
            attempt = Attempt(self, golden)
            rewrite(attempt, mutate)
            self.assertEqual(names(attempt.run()), {"receipt-invalid"}, mutate.__name__)
        attempt = Attempt(self, golden)
        (attempt.root / contracts.RECEIPT_FILE).write_bytes(b'{"schema_version": "1.0", "schema_version": "1.0"}')
        self.assertEqual(names(attempt.run()), {"receipt-invalid"})
        other = Attempt(self, GOLDENS["secrets-tool-failed"])  # a real receipt, but from a different attempt
        (attempt.root / contracts.RECEIPT_FILE).write_bytes((other.root / contracts.RECEIPT_FILE).read_bytes())
        self.assertEqual(names(attempt.run()), {"receipt-invalid"})
        attempt = Attempt(self, golden)  # a file the receipt never listed appears in outputs/
        (attempt.root / "outputs" / "gitleaks-raw.json").write_bytes(b"{}\n")
        self.assertEqual(names(attempt.run()), {"receipt-invalid"})

    def test_a_receipt_that_does_not_publish_the_contract_files_is_rejected(self):
        """A verifiable receipt over a directory in which the inventory was withheld is still not a
        receipt FOR the inventory."""
        golden = GOLDENS["secrets-hits"]
        attempt = Attempt(self, golden)
        private = attempt.root.parent / "private-again"
        private.mkdir()
        for relative, document in golden.documents.items():
            (private / Path(relative).name).write_bytes(dump(document))
        (private / Path(contracts.SECRETS_RESULT_FILE).name).write_bytes(b"\xff\xfe not utf-8")
        published = attempt.root.parent / "republished"
        receipt = redaction.redact_tree(private, published, on_unhandled="withhold", limits=LIMITS)
        self.assertEqual(receipt["totals"]["files_withheld"], 1)
        for path in (attempt.root / "outputs").iterdir():
            if path.name != Path(contracts.SECRETS_RESULT_FILE).name:
                path.write_bytes((published / path.name).read_bytes())
        # the old inventory is still on disk, so the receipt (which withheld it) no longer describes outputs/
        self.assertEqual(names(attempt.run(on_unhandled="withhold")), {"receipt-invalid"})
        (attempt.root / contracts.SECRETS_RESULT_FILE).unlink()
        self.assertEqual(names(attempt.run(on_unhandled="withhold")), {"required-file-missing"})

    def test_an_observed_exposure_assertion_is_rejected_by_name(self):
        golden = GOLDENS["iac-ok-with-gaps"]

        def observed(document):
            document["rule_hits"][0]["exposure"] = "OBSERVED_EXPOSURE"
        errors = Attempt(self, golden, edit(golden.result_file, observed)).run()
        self.assertEqual(names(errors), {"observed-exposure-forbidden"})
        self.assertIn("IC-000001", errors[0])

        def observed_on_plain_hit(document):
            document["rule_hits"][1]["exposure"] = "OBSERVED_EXPOSURE"
        self.assertEqual(names(Attempt(self, golden, edit(golden.result_file, observed_on_plain_hit)).run()),
                         {"observed-exposure-forbidden", "exposure-assertion-mismatch"})

    def test_any_forbidden_promotion_is_rejected(self):
        for name in ("secrets-hits", "iac-ok-with-gaps"):
            golden = GOLDENS[name]
            key = "entries" if name == "secrets-hits" else "rule_hits"
            for field, value in (("finding", True), ("findings", []), ("verified_finding", "yes"), ("severity", "critical"),
                                 ("cvss", 9.8), ("exploitability", "high"), ("runtime_state", "exposed"),
                                 ("observed_runtime", True), ("live_scan_result", "open"), ("is_live", True),
                                 ("valid", True)):
                for top_level in (True, False):
                    def promote(document, field=field, value=value, top_level=top_level):
                        (document if top_level else document[key][0])[field] = value
                    with self.subTest(golden=name, field=field, top_level=top_level):
                        errors = Attempt(self, golden, edit(golden.result_file, promote)).run()
                        self.assertEqual(names(errors), {"schema:result"})
                        self.assertTrue(any(f"unexpected property '{field}'" in error for error in errors))
        for assertion in ("verified-secret", "live-credential", "observed-exposure", "confirmed-vulnerability"):
            def assert_more(document, assertion=assertion):
                document["rule_hits"][0]["assertion"] = assertion
            golden = GOLDENS["iac-ok-with-gaps"]
            self.assertEqual(names(Attempt(self, golden, edit(golden.result_file, assert_more)).run()), {"schema:result"})


# ---- every trusted field is bound ---------------------------------------------------------------

def set_in(relative, path, value):
    """Edit exactly one field, addressed by a key/index path, in one document."""
    def mutate(golden):
        node = golden.documents[relative]
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = value
    return mutate


def status_field(field, value):
    def mutate(golden):
        golden.status[field] = value
    return mutate


class BindingTests(unittest.TestCase):
    def expect(self, golden_name, mutate, expected, exact=True):
        errors = Attempt(self, GOLDENS[golden_name], mutate).run()
        if exact:
            self.assertEqual(names(errors), {expected}, errors)
        else:
            self.assertIn(expected, names(errors), errors)
        return errors

    def test_each_secrets_field_edited_alone_is_rejected(self):
        inventory, first = contracts.SECRETS_RESULT_FILE, ["entries", 0]
        cases = [
            (set_in(inventory, ["run_id"], "another-run"), "header-mismatch"),
            (set_in(inventory, ["attempt_id"], "node-attempt-0002"), "header-mismatch"),
            (set_in(inventory, ["source_snapshot_sha256"], label_sha("other snapshot")), "header-mismatch"),
            (set_in(inventory, ["job_id"], "02-iac-config-scan"), "schema:result"),
            (set_in(inventory, ["redactor", "module_version"], "9.9.9"), "redactor-mismatch"),
            (set_in(inventory, ["redactor", "ruleset_sha256"], "1" * 64), "redactor-mismatch"),
            (set_in(inventory, [*first, "tool_id"], "trufflehog"), "tool-unresolved"),
            (set_in(inventory, [*first, "citation", "producer"], "02-source-sast"), "citation-producer"),
            (set_in(inventory, [*first, "citation", "attempt_id"], "gitleaks-attempt-0002"), "citation-attempt-mismatch"),
            (set_in(inventory, [*first, "citation", "path"], "gitleaks/outputs/other.json"), "citation-unresolved"),
            (set_in(inventory, [*first, "citation", "sha256"], "2" * 64), "citation-hash-mismatch"),
            (set_in(inventory, [*first, "entry_id"], "SI-000009"), "record-id-order"),
            (set_in(inventory, [*first, "location", "path_disposition"], "withheld-unsafe-path"), "location-path"),
            (set_in(inventory, ["entries", 1, "location", "path_disposition"], "published"), "location-path"),
            (set_in(inventory, [*first, "location", "start_line"], 42), "location-lines"),
            (set_in(inventory, [*first, "location", "start_line"], 0), "location-lines"),
            (set_in(inventory, [*first, "location", "end_line"], None), "location-lines"),
            (set_in(inventory, ["entries", 2, "location", "start_line"], 1), "location-lines"),
            (set_in(inventory, ["entries", 2, "data_class"], "password"), "entry-data-class"),
            (set_in(inventory, [*first, "data_class"], "key-store-file"), "entry-data-class"),
            (set_in(inventory, ["entries", 3, "data_class"], "api-key"), "entry-data-class"),
            (set_in(contracts.TOOL_RESULTS_FILE, ["tool_instances", 0, "identity", "redactor"], None), "instance-redactor-mismatch"),
            (set_in(contracts.TOOL_RESULTS_FILE, ["tool_instances", 0, "identity", "redactor", "ruleset_sha256"],
                    label_sha("old ruleset")), "instance-redactor-mismatch"),
            (set_in(contracts.TOOL_RESULTS_FILE, ["tool_instances", 0, "identity", "redactor", "redactor_version"], "0.9.0"),
             "instance-redactor-mismatch"),
            (set_in(contracts.TOOL_RESULTS_FILE, ["tool_instances", 0, "result_record_count"], 1), "record-count-exceeds-tool"),
            (set_in(contracts.TOOL_RESULTS_FILE, ["tool_instances", 0, "outputs", 0, "sha256"], label_sha("x")), "tool-outputs"),
            (set_in(contracts.TOOL_RESULTS_FILE, ["tool_instances", 0, "outputs", 0, "bytes"], 1), "tool-outputs"),
            (status_field("status", "OK_WITH_GAPS"), "status-mismatch"),
            (status_field("run_id", "another-run"), "status-mismatch"),
            (status_field("attempt_id", "node-attempt-0002"), "status-mismatch"),
        ]
        for index, (mutate, expected) in enumerate(cases):
            with self.subTest(case=index, expected=expected):
                self.expect("secrets-hits", mutate, expected, exact=expected != "tool-outputs")

    def test_secrets_cross_document_contradictions_are_rejected(self):
        def not_normalized(golden):
            golden.documents[contracts.SECRETS_RESULT_FILE]["entries"][0]["location"]["path"] = "services/./billing/settings.py"
        errors = self.expect("secrets-hits", not_normalized, "location-path")
        self.assertNotIn("billing", errors[0])  # messages name the record, never the path
        for bad in ("services/../../etc/shadow", "services//settings.py"):
            self.expect("secrets-hits", set_in(contracts.SECRETS_RESULT_FILE, ["entries", 0, "location", "path"], bad), "location-path")

        def duplicate(golden):
            entries = golden.documents[contracts.SECRETS_RESULT_FILE]["entries"]
            entries[3] = {**deepcopy(entries[2]), "entry_id": "SI-000004"}
        self.expect("secrets-hits", duplicate, "duplicate-record")

        def cites_the_failed_tool(golden):
            golden.documents[contracts.SECRETS_RESULT_FILE]["entries"].append(secrets_entry(
                1, "candidate-secret-location", "gitleaks", "generic-api-key", "api-key", location("src/app.py", 3, 3)))
        self.expect("secrets-tool-failed", cites_the_failed_tool, "tool-without-validated-output")

        def cites_an_unanalyzed_path(golden):
            coverage = golden.documents[contracts.COVERAGE_FILE]
            golden.documents[contracts.SECRETS_RESULT_FILE]["entries"].append(secrets_entry(
                1, "credential-store-file-present", "key-material-file-inventory", "key-store-extension", "key-store-file",
                location("deploy/store.jks")))
            tool = coverage["tools"][1]
            tool.update(candidate_input_count=5, unsupported_input_count=1,
                        unsupported_inputs=[{"path": "deploy/store.jks", "reason_code": "encrypted-or-packed"}])
            coverage["gaps"].append({"gap_id": "gap-unsupported", "kind": "inputs-unsupported",
                                     "tool_id": tool["tool_id"], "affected_input_count": 1})
            golden.documents[contracts.TOOL_RESULTS_FILE]["tool_instances"][1]["result_record_count"] = 1
            golden.documents[contracts.TOOL_RESULTS_FILE]["tool_instances"][1]["exit"].update(exit_code=1, exit_meaning="findings-present")
        self.expect("secrets-tool-failed", cites_an_unanalyzed_path, "record-path-not-analyzed")

        def citation_of_a_log(golden):
            instance = golden.documents[contracts.TOOL_RESULTS_FILE]["tool_instances"][0]
            data = b"retained\n"
            instance["outputs"].append({"path": "gitleaks/logs/stderr.log", "sha256": "sha256:" + sha_hex(data), "bytes": len(data),
                                        "media_type": "text/plain", "role": "retained-stderr", "validation": "not-validated",
                                        "validated_against": None})
            golden.tool_files["gitleaks/logs/stderr.log"] = data
            golden.documents[contracts.SECRETS_RESULT_FILE]["entries"][0]["citation"].update(
                path="gitleaks/logs/stderr.log", sha256=sha_hex(data))
        self.expect("secrets-hits", citation_of_a_log, "citation-not-validated-output")

    def test_each_iac_field_edited_alone_is_rejected(self):
        evidence, base, first = contracts.IAC_RESULT_FILE, contracts.BASE_IMAGE_FILE, ["rule_hits", 0]
        cases = [
            (set_in(evidence, ["source_snapshot_sha256"], label_sha("other snapshot")), "header-mismatch"),
            (set_in(base, ["attempt_id"], "node-attempt-0002"), "header-mismatch"),
            (set_in(base, ["redactor", "ruleset_sha256"], "1" * 64), "redactor-mismatch"),
            (set_in(base, ["job_id"], "02-secrets-inventory"), "schema:base-image-inventory"),
            (set_in(evidence, [*first, "rule", "rule_pack", "sha256"], label_sha("another bundle")), "rule-pack-unresolved"),
            (set_in(evidence, [*first, "rule", "rule_pack", "identity_id"], "tfsec-rules"), "rule-pack-unresolved"),
            (set_in(evidence, [*first, "rule", "rule_pack", "kind"], "rule-pack"), "rule-pack-unresolved"),
            (set_in(evidence, [*first, "exposure"], None), "exposure-assertion-mismatch"),
            (set_in(evidence, ["rule_hits", 1, "exposure"], "DECLARED_EXPOSURE"), "exposure-assertion-mismatch"),
            (set_in(evidence, [*first, "category"], "encryption-at-rest"), "exposure-category"),
            (set_in(evidence, [*first, "resource", "address"], None), "resource-address"),
            (set_in(evidence, [*first, "resource", "address_disposition"], "withheld-unsafe-address"), "resource-address"),
            (set_in(evidence, [*first, "resource", "iac_kind"], "dockerfile"), "resource-address"),
            (set_in(evidence, [*first, "resource", "address"], "module..aws_security_group.web"), "resource-address"),
            (set_in(evidence, ["rule_hits", 3, "resource", "iac_kind"], "kubernetes"), "resource-address"),
            (set_in(evidence, [*first, "tool_id"], "trivy-config"), "tool-without-validated-output"),
            (set_in(evidence, [*first, "tool_id"], "kube-linter"), "tool-without-validated-output"),
            (set_in(evidence, [*first, "citation", "sha256"], "2" * 64), "citation-hash-mismatch"),
            (set_in(evidence, [*first, "hit_id"], "IC-000002"), "record-id-order"),
            (set_in(evidence, [*first, "location", "end_line"], 2), "location-lines"),
            (set_in(base, ["base_images", 0, "repository"], None), "base-image-form"),
            (set_in(base, ["base_images", 1, "tag"], "latest"), "base-image-form"),
            (set_in(base, ["base_images", 2, "digest"], label_sha("scratch")), "base-image-form"),
            (set_in(base, ["base_images", 0, "reference_id"], "BI-000007"), "record-id-order"),
            (set_in(base, ["base_images", 0, "location", "start_line"], None), "location-lines"),
            (set_in(base, ["base_images", 0, "citation", "attempt_id"], "checkov-attempt-0001"), "citation-attempt-mismatch"),
            (set_in(contracts.TOOL_RESULTS_FILE, ["tool_instances", 5, "result_record_count"], 2), "record-count-exceeds-tool"),
            (set_in(contracts.PROBE_RECEIPT_FILE, ["run_id"], "another-run"), "aggregate"),
            (set_in(contracts.COVERAGE_FILE, ["attempt_id"], "node-attempt-0002"), "aggregate"),
            (status_field("status", "OK"), "status-mismatch"),
        ]
        for index, (mutate, expected) in enumerate(cases):
            with self.subTest(case=index, expected=expected):
                errors = self.expect("iac-ok-with-gaps", mutate, expected, exact=False)
                if expected in ("rule-pack-unresolved", "exposure-category", "base-image-form", "header-mismatch"):
                    self.assertEqual(names(errors), {expected})

    def test_a_tfsec_hit_on_a_path_tfsec_did_not_analyze_is_rejected(self):
        self.expect("iac-ok-with-gaps",
                    set_in(contracts.IAC_RESULT_FILE, ["rule_hits", 2, "location", "path"], "deploy/tfsec/input-0.tf"),
                    "record-path-not-analyzed")

    def test_a_skipped_node_publishes_no_records_and_needs_its_probe_receipt(self):
        def records(golden):
            source = GOLDENS["iac-ok-with-gaps"].documents
            golden.documents[contracts.IAC_RESULT_FILE]["rule_hits"] = deepcopy(source[contracts.IAC_RESULT_FILE]["rule_hits"][:1])
        errors = self.expect("iac-skipped", records, "skipped-node-with-records", exact=False)
        self.assertIn("tool-without-validated-output", names(errors))

        def inputs_were_found(golden):
            tool = golden.documents[contracts.PROBE_RECEIPT_FILE]["tools"][0]
            tool.update(matching_input_count=2, applicable=True)
            tool["detectors"][0]["matching_input_count"] = 2
            golden.documents[contracts.PROBE_RECEIPT_FILE].update(node_applicable=True, skip_reason=None)
        self.expect("iac-skipped", inputs_were_found, "aggregate")
        attempt = Attempt(self, GOLDENS["iac-skipped"])
        (attempt.root / contracts.PROBE_RECEIPT_FILE).unlink()
        self.assertEqual(names(attempt.run()), {"required-file-missing"})
        # and the secrets node, which can never skip, is rejected as SKIPPED whatever it publishes
        secrets = Attempt(self, GOLDENS["secrets-tool-failed"], status_field("status", "SKIPPED"))
        self.assertIn("aggregate", names(secrets.run(node_status="SKIPPED")))


# ---- files, not strings -------------------------------------------------------------------------

def symlinks_work() -> bool:
    with tempfile.TemporaryDirectory() as directory:
        try:
            (Path(directory) / "link").symlink_to(Path(directory) / "target")
        except (OSError, NotImplementedError):
            return False
    return True


SYMLINKS = symlinks_work()


class FileBindingTests(unittest.TestCase):
    def test_each_required_file_missing_alone_is_rejected(self):
        for name in ("secrets-hits", "iac-ok-with-gaps"):
            golden = GOLDENS[name]
            for relative in contracts.CONTRACT_POLICIES[golden.contract_id]["required_files"]:
                attempt = Attempt(self, golden)
                (attempt.root / relative).unlink()
                expected = "receipt-missing" if relative == contracts.RECEIPT_FILE else "required-file-missing"
                with self.subTest(golden=name, file=relative):
                    self.assertEqual(names(attempt.run()), {expected})

    def test_a_published_document_changed_after_sealing_is_rejected(self):
        for name in ("secrets-hits", "iac-ok-with-gaps"):
            golden = GOLDENS[name]
            for relative in contracts.CONTRACT_POLICIES[golden.contract_id]["required_files"]:
                if not relative.startswith("outputs/") or relative == contracts.RECEIPT_FILE:
                    continue
                attempt = Attempt(self, golden)
                target = attempt.root / relative
                document = json.loads(target.read_bytes().decode("utf-8"))
                document["run_id"] = "edited-after-sealing"
                target.write_bytes(dump(document))
                with self.subTest(golden=name, file=relative):
                    self.assertEqual(names(attempt.run()), {"receipt-invalid"})

    def test_a_tool_output_changed_or_missing_is_rejected(self):
        attempt = Attempt(self, GOLDENS["secrets-hits"])
        (attempt.tool_root / "gitleaks/outputs/result.json").write_bytes(b"{}\n")
        self.assertEqual(names(attempt.run()), {"tool-outputs"})
        (attempt.tool_root / "gitleaks/outputs/result.json").unlink()
        self.assertEqual(names(attempt.run()), {"tool-outputs"})
        self.assertEqual(names(attempt.run(tool_outputs_root=attempt.root)), {"tool-outputs"})  # the wrong root

    def test_duplicate_keys_and_non_json_are_rejected(self):
        attempt = Attempt(self, GOLDENS["secrets-hits"])
        (attempt.root / "status.json").write_bytes(b'{"status": "FAILED", "status": "OK", "run_id": "x", "attempt_id": "y"}')
        self.assertEqual(names(attempt.run()), {"status-mismatch"})
        (attempt.root / "status.json").write_bytes(b"[]")
        self.assertEqual(names(attempt.run()), {"status-mismatch"})

    def test_the_receipt_binding_holds_even_if_the_directory_changes_after_verification(self):
        """`verify_receipt` reads the directory itself. These rules bind the bytes THIS module parsed
        to the receipt it verified, so a change between the two reads cannot slip a document past
        it. The race is simulated by stubbing the verifier to accept."""
        golden = GOLDENS["secrets-hits"]
        with mock.patch.object(contracts, "verify_receipt", lambda *args, **kwargs: None):
            attempt = Attempt(self, golden)
            self.assertEqual(attempt.run(), [])
            target = attempt.root / contracts.COVERAGE_FILE
            target.write_bytes(target.read_bytes() + b"\n")
            errors = attempt.run()
            self.assertEqual(names(errors), {"receipt-hash-mismatch"})
            self.assertIn(contracts.COVERAGE_FILE, errors[0])

            def rewrite(attempt, mutate):
                receipt = deepcopy(attempt.receipt)
                mutate(next(record for record in receipt["files"] if record["path"] == Path(golden.result_file).name))
                (attempt.root / contracts.RECEIPT_FILE).write_bytes(redaction.receipt_bytes(receipt))

            attempt = Attempt(self, golden)
            rewrite(attempt, lambda record: record.update(disposition="withheld"))
            self.assertEqual(names(attempt.run()), {"receipt-does-not-publish"})
            attempt = Attempt(self, golden)
            rewrite(attempt, lambda record: record.update(path="another-inventory.json"))
            self.assertEqual(names(attempt.run()), {"receipt-does-not-publish"})
            attempt = Attempt(self, golden)
            data = b'{"entries": [], "entries": []}'
            (attempt.root / golden.result_file).write_bytes(data)
            rewrite(attempt, lambda record: record.update(published_sha256=sha_hex(data)))
            self.assertEqual(names(attempt.run()), {"document-unreadable"})

    @unittest.skipUnless(SYMLINKS or os.name != "nt", "this Windows host cannot create symbolic links")
    def test_a_linked_required_file_is_rejected(self):
        self.assertTrue(SYMLINKS, "a POSIX host must always be able to run the symbolic-link case")
        for relative, expected in (("status.json", "required-file-missing"), (contracts.COVERAGE_FILE, "required-file-missing"),
                                   (contracts.RECEIPT_FILE, "receipt-missing")):
            attempt = Attempt(self, GOLDENS["secrets-hits"])
            target = attempt.root / relative
            outside = attempt.root.parent / ("outside-" + target.name)
            outside.write_bytes(target.read_bytes())
            target.unlink()
            target.symlink_to(outside)
            with self.subTest(file=relative):
                self.assertEqual(names(attempt.run()), {expected})


class KnownBlockerTests(unittest.TestCase):
    def test_v06_redactor_against_the_v03_header_key(self):
        """See the note at the top of this file. Not a V04 defect and not V04's to fix; reported."""
        if V06_FLAGS_V03_HEADER_KEY:
            self.skipTest(f"BLOCKER for V10: evidence_redaction redacts the V03-required key {V03_HEADER_KEY!r}; "
                          "this suite ran with that one string exempted")
        self.assertEqual(_PATCHES, [])

    def test_v06_redactor_against_run_ids_of_the_repos_own_format(self):
        """`run_process.new_run_id` yields `<UTC stamp>-<6 hex>`. The header of every published
        document carries it, so a run id the redactor reads as high-entropy makes that run's
        attempts unproducible. Deterministic sample; reported, not V04's to fix."""
        sample = [f"20260920T12{minute:02d}{second:02d}Z-{(minute * 7919 + second * 104729) % 0xFFFFFF:06x}"
                  for minute in range(0, 60, 3) for second in range(0, 60, 7)]
        flagged = [run_id for run_id in sample if redaction._merged_spans(run_id)]
        if flagged:
            self.skipTest(f"BLOCKER for V10: evidence_redaction flags {len(flagged)} of {len(sample)} sampled run ids "
                          "of the repository's own format as high-entropy")

    def test_every_synthetic_secret_is_detected_whatever_the_shim_state(self):
        for value in SECRETS.values():
            self.assertTrue(redaction._merged_spans(value), value[:6])

    def test_the_shim_exempts_exactly_one_string(self):
        if not V06_FLAGS_V03_HEADER_KEY:
            # evidence_redaction >= 1.1.0 treats the key as an identifier itself; no shim is
            # installed, so there is nothing for it to be exact about.
            self.assertEqual(_PATCHES, [])
            return
        for value in (V03_HEADER_KEY + "x", "x" + V03_HEADER_KEY):
            self.assertTrue(redaction._merged_spans(value), value[:6])


# ---- invariants ----------------------------------------------------------------------------------

class InvariantTests(unittest.TestCase):
    def test_validation_is_read_only_and_returns_nothing_but_strings(self):
        for name, golden in GOLDENS.items():
            attempt = Attempt(self, golden)
            before = {path.relative_to(attempt.tool_root).as_posix(): path.read_bytes()
                      for path in sorted(attempt.tool_root.rglob("*")) if path.is_file()}
            first, second = attempt.run(), attempt.run()
            after = {path.relative_to(attempt.tool_root).as_posix(): path.read_bytes()
                     for path in sorted(attempt.tool_root.rglob("*")) if path.is_file()}
            self.assertEqual(before, after, name)
            self.assertEqual(first, second)
            self.assertIsNot(first, second)  # no shared, mutable result a caller could poison

    def test_the_decision_is_re_derived_from_bytes_every_time(self):
        """A verdict is a cache. After a clean run, change one byte on disk: the next run must notice,
        with no way to hand the earlier result back in."""
        attempt = Attempt(self, GOLDENS["iac-ok-with-gaps"])
        self.assertEqual(attempt.run(), [])
        target = attempt.root / contracts.IAC_RESULT_FILE
        target.write_bytes(target.read_bytes().replace(b"DECLARED_EXPOSURE", b"OBSERVED_EXPOSURE", 1))
        self.assertEqual(names(attempt.run()), {"receipt-invalid"})
        for function in (contracts.validate_secrets_attempt, contracts.validate_iac_attempt):
            self.assertFalse({"receipt", "verified", "trusted", "cache", "skip_receipt", "store"} & set(inspect.signature(function).parameters))

    def test_no_planted_value_appears_in_any_error_for_any_golden_and_any_location(self):
        """Plant every synthetic secret into every string of every published document, before
        publication and after it. `Attempt.run` asserts the invariant; here we drive the sweep."""
        def strings(node, path=()):
            if isinstance(node, dict):
                for key, value in node.items():
                    yield from strings(value, (*path, key))
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    yield from strings(value, (*path, index))
            elif isinstance(node, str):
                yield path

        planted = SECRETS["NAMED"] + " " + SECRETS["AWS_KEY"]
        for name in ("secrets-hits", "iac-ok-with-gaps"):
            golden = GOLDENS[name]
            for relative in (golden.result_file, contracts.TOOL_RESULTS_FILE):
                paths = list(strings(golden.documents[relative]))[::7]  # a spread of fields keeps the sweep quick
                self.assertGreaterEqual(len(paths), 5)
                for path in paths:
                    before = Attempt(self, golden, set_in(relative, list(path), planted))
                    self.assertTrue(before.run(), (name, relative, path))
                    after = Attempt(self, golden)
                    document = json.loads((after.root / relative).read_bytes().decode("utf-8"))
                    node = document
                    for step in path[:-1]:
                        node = node[step]
                    node[path[-1]] = planted
                    (after.root / relative).write_bytes(dump(document))
                    self.assertEqual(names(after.run()), {"receipt-invalid"})
            status = Attempt(self, golden, status_field("run_id", planted))  # status.json lies outside the receipt
            self.assertEqual(names(status.run()), {"status-mismatch"})

    def test_this_work_contains_no_scannable_secret_literal(self):
        scanners = [re.compile("AK" + r"IA[0-9A-Z]{16}"), re.compile("gh" + r"p_[A-Za-z0-9]{36}"),
                    re.compile("-----BEGIN " + r"(RSA |EC |OPENSSH )?PRIVATE KEY-----"),
                    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.")]
        paths = [ROOT / "secrets_iac_contracts.py", Path(__file__), *[REPO / "schemas" / name for name in ALL_SCHEMAS],
                 *[CONTRACT_DIR / f"{contract_id}.json" for contract_id in contracts.CONTRACT_POLICIES]]
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for scanner in scanners:
                with self.subTest(path=path.name, scanner=scanner.pattern[:8]):
                    self.assertIsNone(scanner.search(text))
            self.assertNotIn("\r", text.replace("\r\n", "\n"))
        for label in ("AWS_KEY", "GITHUB_TOKEN", "PEM_HEADER"):  # and the synthetic values really are scanner-shaped
            self.assertTrue(any(scanner.search(SECRETS[label]) for scanner in scanners), label)
        for label, value in SECRETS.items():  # and the V06 redactor really does detect each one
            self.assertTrue(redaction._merged_spans(value), label)


if __name__ == "__main__":
    unittest.main()
