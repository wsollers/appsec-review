"""Golden and mutation tests for the four SBOM-family contracts (ADR-0010 G2/G4/M1-M5, task V05):
`sbom-inventory`, `sca-vulnerability-match`, `license-inventory` and `dependency-lifecycle`, their
schemas and the cross-record rules and on-disk bindings in `sbom_family_contracts.py`.

Goldens are BUILT, not tracked: a `World` writes a source snapshot, a reference table and up to four
attempts into a temporary directory, publishing every attempt with the real V06 redactor
(`redact_tree`). So every golden is a state a worker can actually produce, its receipt is real, the
downstream attempts are bound to the bytes the upstream attempt really published, and no assertion
depends on how Git converted a text fixture. A mutation edits only the field under test, either
before publication (an honest receipt over a wrong document: proves the rule) or after it (proves
the binding to the receipt and the bytes).

`run` asserts after EVERY verification that no planted value reached an error message. Secret-shaped
values are assembled at run time.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
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
import sbom_family_contracts as contracts
import sca_nvd_snapshot
from schema_validate import SchemaStore, validate_document
import tool_instance_shapes as shapes

CONTRACT_DIR = ROOT / "registry" / "output-contracts"
PROPOSAL = REPO / "docs" / "proposals" / "vendor-prepass" / "job-nodes.proposal.json"
PRODUCERS = REPO / "docs" / "proposals" / "vendor-prepass" / "threat-workbench-producers.proposal.yaml"
ALL_SCHEMAS = sorted(path.name for prefix in ("sbom-inventory", "sca-vulnerability-match", "license-inventory",
                                              "dependency-lifecycle") for path in (REPO / "schemas").glob(f"{prefix}*.schema.json"))
POLICY = "refuse"
LIMITS = redaction.DEFAULT_LIMITS
REDACTOR = {"name": redaction.REDACTOR_NAME, "module_version": redaction.MODULE_VERSION,
            "ruleset_sha256": redaction.RULESET_SHA256}
DAGSTER_RUN = "dagster-run-v05"
RUN_ID = "20260920T120000Z-05abc0"
NOW = datetime(2026, 9, 20, 12, 30, 0, tzinfo=timezone.utc)
EVALUATED_AT = "2026-09-20T12:10:00Z"
SBOM, SCA, LICENSE, LIFECYCLE = (contracts.SBOM_CONTRACT_ID, contracts.SCA_CONTRACT_ID, contracts.LICENSE_CONTRACT_ID,
                                 contracts.LIFECYCLE_CONTRACT_ID)
TOOLS = {SBOM: "syft-directory", SCA: "grype", LICENSE: "scancode-toolkit", LIFECYCLE: "dependency-lifecycle-transform"}
EXECUTORS = {SBOM: "pinned_container", SCA: "pinned_container", LICENSE: "pinned_container", LIFECYCLE: "deterministic_python"}

# Assembled here so that no scannable literal exists in the repository. All obviously synthetic.
CANARY = "v05-canary-" + "zq9x7"
SECRETS = {
    "AWS_KEY": "AK" + "IA" + "SYNTHETIC0KEY0V5",
    "GITHUB_TOKEN": "gh" + "p_" + "SyntheticV05" * 3,
    "PEM_HEADER": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "HIGH_ENTROPY": "q7Zx2" + "Lm9Pw4Rt6Yv8Bn1Cd3Fg5Hj0Ks",
}
PLANTED = [CANARY, *SECRETS.values()]

# ---- known cross-task state (V03 x V06) ----------------------------------------------------------
# V03's documents REQUIRE the key `source_snapshot_sha256`. V06 1.0.0 reads that key as a
# high-entropy token and rewrites it, so no ADR-0010 attempt is producible with it; V06 1.1.0 (PR 17,
# on main, not on this slice's base branch) fixes that. While the redactor in the tree still flags the
# key, this suite exempts exactly that one string so everything else is exercised against the real
# redactor. The shim switches itself off as soon as the redactor stops flagging the key.
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


def _probe_links() -> tuple[bool, bool]:
    """(symlinks, hardlinks) this host can create. Probed once; a POSIX host must support both."""
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "target"
        target.write_bytes(b"x")
        results = []
        for make in (os.symlink, os.link):
            try:
                make(target, Path(directory) / f"link-{make.__name__}")
                results.append(True)
            except (OSError, NotImplementedError, AttributeError):
                results.append(False)
    if os.name == "posix":
        assert all(results), "a POSIX host must be able to create symlinks and hard links; nothing may be skipped here"
    return results[0], results[1]


CAN_SYMLINK, CAN_HARDLINK = _probe_links()


def sha_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha(data: bytes) -> str:
    return "sha256:" + sha_hex(data)


def label_sha(label: str) -> str:
    return sha(label.encode("utf-8"))


def dump(document) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def names(errors):
    return {error.split(": ", 1)[0] for error in errors}


# ---- the source snapshot, the reference table and the database identities ---------------------------

def _lines(*lines: str) -> bytes:
    return ("\n".join(lines) + "\n").encode("utf-8")


SOURCE_FILES = {
    "web/package.json": _lines("{", '  "name": "storefront",', '  "license": "MIT",', '  "dependencies": {"lodash": "4.17.20", "left-pad": "*"}', "}"),
    "web/package-lock.json": _lines("{", '  "lockfileVersion": 3', "}"),
    "services/api/requirements.txt": _lines("jinja2==3.1.2"),
    "services/batch/pom.xml": _lines("<project>", "  <artifactId>batch</artifactId>", "</project>"),
    "native/conanfile.txt": _lines("[requires]", "openssl/1.1.1k"),
    "tools/widget/go.mod": _lines("module example.test/tools", "require github.com/example/widget master-snapshot"),
    "third_party/zlib/zlib.h": _lines("/* zlib.h -- interface of the compression library */", "#define ZLIB_VERSION x"),
    "third_party/zlib/LICENSE": _lines("zlib License", "", "This software is provided 'as-is'", "Copyright (C) the zlib authors"),
    "LICENSE": _lines("Apache License", "Version 2.0, January 2004"),
}
CLEAN_SOURCE = ("web/package-lock.json", "services/api/requirements.txt", "services/batch/pom.xml", "LICENSE", "web/package.json")

TABLE = {
    "schema": "appsec-review/dependency-lifecycle-reference-table/1.0", "table_id": "curated-eol-table", "version": "2026.09.01",
    "as_of": "2026-09-01",
    "rows": [
        {"row_id": "jinja2-3.1", "ecosystem": "pypi", "name": "jinja2", "cycle": "3.1", "status": "supported", "eol_date": None},
        {"row_id": "log4j-core-2", "ecosystem": "maven", "name": "log4j-core", "cycle": "2", "status": "supported", "eol_date": None},
        {"row_id": "log4j-core-2.14", "ecosystem": "maven", "name": "log4j-core", "cycle": "2.14", "status": "end-of-life",
         "eol_date": "2021-12-14"},
        {"row_id": "lodash-3", "ecosystem": "npm", "name": "lodash", "cycle": "3", "status": "end-of-life", "eol_date": "2016-01-12"},
    ],
}
DATABASES = {
    "grype-db": {"vendor_build": "2026-09-18T01-31-42Z", "schema_version": "6.0.2", "snapshot_id": "grype-db-20260918",
                 "sha256": label_sha("grype-db"), "data_timestamp": "2026-09-18T01:31:42Z"},
    "osv": {"vendor_build": "osv-export-20260919", "schema_version": "1.6.7", "snapshot_id": "osv-20260919",
            "sha256": label_sha("osv"), "data_timestamp": "2026-09-19T04:00:00Z"},
}


def database_block(kind: str) -> dict:
    return {"database_kind": kind, **{field: DATABASES[kind][field] for field in contracts.DATABASE_BLOCK_FIELDS}}


# ---- V03 aggregate builder -------------------------------------------------------------------------

def tool_output_bytes(tool_id: str) -> bytes:
    return dump({"normalized_by": tool_id, "records": "held in the tool instance's own attempt"})


def build_aggregate(header: dict, tool_id: str, executor: str, records: int, data_identities: list, candidates: int,
                    extra_gaps: list) -> dict:
    container = executor == "pinned_container"
    data = tool_output_bytes(tool_id)
    instance = {
        "tool_id": tool_id, "attempt_id": f"{tool_id}-attempt-0001", "terminal_status": "OK", "skip_reason": None,
        "cause_code": None,
        "identity": {
            "executor_kind": executor,
            "image_repository": "registry.internal.example:5000/appsec/sbom-tools" if container else None,
            "image_digest": label_sha("image" + tool_id) if container else None,
            "executable_sha256": None if container else label_sha("module" + tool_id),
            "tool_name": tool_id, "tool_version": "1.2.3", "data_identities": data_identities,
            "redactor": {"redactor_id": "evidence-redaction", "redactor_version": redaction.MODULE_VERSION,
                         "ruleset_sha256": "sha256:" + redaction.RULESET_SHA256}},
        "argv": [tool_id, "--offline", "--output", "/out/result.json", "/src"],
        "exit": {"exit_code": 0, "exit_meaning": "clean", "timed_out": False, "nonzero_exit_on_findings": False,
                 "findings_exit_codes": []},
        "outputs": [{"path": f"{tool_id}/outputs/result.json", "sha256": sha(data), "bytes": len(data),
                     "media_type": "application/json", "role": "normalized-result", "validation": "schema-validated",
                     "validated_against": "tool-normalized-result.schema.json"}],
        "result_record_count": records}
    coverage = {"tool_id": tool_id, "applicability": "applicable", "candidate_input_count": candidates,
                "analyzed_input_count": candidates, "not_analyzed_input_count": 0, "unsupported_input_count": 0,
                "not_analyzed_inputs": [], "unsupported_inputs": [], "input_lists_truncated": False}
    return {contracts.TOOL_RESULTS_FILE: {"schema": "appsec-review/tool-results/1.0", **header, "tool_instances": [instance]},
            contracts.COVERAGE_FILE: {"schema": "appsec-review/scan-coverage/1.0", **header, "tools": [coverage],
                                      "gaps": extra_gaps}}


def citation(job_id: str, tool_id: str) -> dict:
    return {"source_class": "raw", "producer": job_id, "attempt_id": f"{tool_id}-attempt-0001",
            "path": f"{tool_id}/outputs/result.json", "sha256": sha_hex(tool_output_bytes(tool_id))}


def unmapped_gap(tool_id: str, count: int) -> list:
    return [{"gap_id": f"gap-{tool_id}-unmapped", "kind": "unmapped-components", "tool_id": tool_id,
             "affected_input_count": count}] if count else []


# ---- specs: one producible attempt each ----------------------------------------------------------------

class Spec:
    def __init__(self, contract_id: str, documents: dict, raw_files: dict | None = None):
        self.contract_id = contract_id
        self.job_id = contracts.CONTRACT_POLICIES[contract_id]["job_id"]
        self.header = header_for(contract_id)
        self.documents = documents
        self.raw_files = dict(raw_files or {})  # outputs/ files that are not built from `documents`
        self.tool_id = TOOLS[contract_id]
        self.declared = [self.tool_id]
        self.permitted = list(contracts.NEVER_SKIPS)
        self.node_status = "OK_WITH_GAPS" if documents[contracts.COVERAGE_FILE]["gaps"] else "OK"
        self.status = {"status": self.node_status, "run_id": self.header["run_id"], "attempt_id": self.header["attempt_id"],
                       "job_id": self.job_id, "dagster_run_id": DAGSTER_RUN}
        self.tool_files = {f"{self.tool_id}/outputs/result.json": tool_output_bytes(self.tool_id)}

    def reseal(self):
        """Recompute the hashes one published document holds of another, after an honest edit."""
        if self.contract_id == SBOM:
            data = dump(self.documents[contracts.SBOM_CDX_FILE])
            self.documents[contracts.SBOM_MANIFEST_FILE]["sbom_document"].update(sha256=sha(data), bytes=len(data))
        if self.contract_id == SCA:
            self.documents[contracts.SCA_SUMMARY_FILE]["gap_list"]["sha256"] = sha(dump(self.documents[contracts.SCA_GAPS_FILE]))
        return self


def header_for(contract_id: str) -> dict:
    job_id = contracts.CONTRACT_POLICIES[contract_id]["job_id"]
    return {"run_id": RUN_ID, "job_id": job_id, "attempt_id": f"{contract_id.split('-')[0]}-node-attempt-0001",
            "source_snapshot_sha256": label_sha("snapshot")}


def component(number, ecosystem, name, version, purl, cpe, path, declaration="declared"):
    kind = contracts.declaration_kind(ecosystem, path)
    assertion = ("inventory-coverage-gap" if declaration != "declared" else
                 "component-version-unknown" if version is None else "declared-component-present")
    return {"component_id": f"SC-{number:06d}", "assertion": assertion, "declaration": declaration, "name": name,
            "version": version, "purl": purl, "cpe": cpe, "ecosystem": ecosystem,
            "source": {"evidence_kind": kind, "path": path, "sha256": sha(SOURCE_FILES[path])},
            "tool_id": TOOLS[SBOM], "citation": citation("02-sbom-inventory", TOOLS[SBOM])}


def sbom_components(variant: str) -> list:
    evaluable = [
        ("npm", "lodash", "4.17.20", "pkg:npm/lodash@4.17.20", None, "web/package-lock.json"),
        ("pypi", "jinja2", "3.1.2", "pkg:pypi/jinja2@3.1.2", None, "services/api/requirements.txt"),
        ("maven", "log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
         "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", "services/batch/pom.xml"),
    ]
    gaps = [
        ("npm", "left-pad", None, "pkg:npm/left-pad", None, "web/package.json", "declared"),
        ("generic", "zlib", "1.2.11", None, None, "third_party/zlib/zlib.h", "inferred-vendored"),
        ("conan", "openssl", "1.1.1k", "pkg:conan/openssl@1.1.1k", None, "native/conanfile.txt", "declared"),
        ("golang", "github.com/example/widget", "master-snapshot", "pkg:golang/github.com/example/widget@master-snapshot", None,
         "tools/widget/go.mod", "declared"),
    ]
    rows = [(*row, "declared") for row in evaluable] + (gaps if variant == "full" else [])
    return [component(number, *row) for number, row in enumerate(rows, 1)]


def sbom_spec(variant: str) -> Spec:
    header, components = header_for(SBOM), sbom_components(variant)
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
           "components": [{"type": "library", "bom-ref": item["component_id"], "name": item["name"],
                           **({"version": item["version"]} if item["version"] is not None else {}),
                           **({"purl": item["purl"]} if item["purl"] is not None else {})} for item in components]}
    manifest = {"schema": "appsec-review/sbom-inventory/1.0", **header, "redactor": dict(REDACTOR),
                "generated_at": "2026-09-20T12:01:00Z",
                "sbom_document": {"path": contracts.SBOM_CDX_FILE, "sha256": "", "bytes": 0, "bom_format": "CycloneDX",
                                  "spec_version": "1.6"},
                "components": components}
    documents = {contracts.SBOM_CDX_FILE: cdx, contracts.SBOM_MANIFEST_FILE: manifest,
                 **build_aggregate(header, TOOLS[SBOM], EXECUTORS[SBOM], len(components), [], 6, [])}
    return Spec(SBOM, documents).reseal()


def sbom_binding(expected: dict) -> dict:
    return {"job_id": "02-sbom-inventory", "attempt_id": expected["attempt_id"], "path": contracts.SBOM_MANIFEST_FILE,
            "sha256": expected["sha256"]}


def age_block(data_timestamp: str, max_age) -> dict:
    stamp = datetime.strptime(data_timestamp, "%Y-%m-%dT%H:%M:%SZ")
    evaluated = datetime.strptime(EVALUATED_AT, "%Y-%m-%dT%H:%M:%SZ")
    limit = None if max_age is contracts.NO_AGE_LIMIT else int(max_age.total_seconds())
    return {"evaluated_at": EVALUATED_AT, "age_seconds": int((evaluated - stamp).total_seconds()), "max_age_seconds": limit,
            "age_policy": "no-limit" if limit is None else "within-limit"}


def sca_spec(sbom: dict, expected_sbom: dict, max_age) -> Spec:
    header, binding, tool_id = header_for(SCA), sbom_binding(expected_sbom), TOOLS[SCA]
    by_name = {item["name"]: item for item in sbom["components"]}
    evaluated, gaps = [], []
    for item in sbom["components"]:
        reason = contracts.required_gap_reason(item)
        if reason is None:
            evaluated.append({"component_ref": item["component_id"],
                              "outcome": "no-advisory-matched" if item["name"] == "jinja2" else "advisory-matched",
                              "version_scheme": contracts.version_scheme_for(item), "evaluated_by": ["grype-db", "osv"]})
        else:
            gaps.append({"gap_id": f"VG-{len(gaps) + 1:06d}", "assertion": "match-coverage-gap",
                         "component_ref": item["component_id"], "ecosystem": item["ecosystem"], "reason": reason})

    def match(number, name, aliases, citations):
        return {"match_id": f"VM-{number:06d}", "assertion": "advisory-matches-declared-version",
                "component_ref": by_name[name]["component_id"], "advisory_id": contracts.canonical_advisory_id(aliases),
                "aliases": sorted(aliases), "version_scheme": contracts.version_scheme_for(by_name[name]),
                "citations": [{"database": database_block(kind), "advisory_id": advisory, "match_basis": basis}
                              for kind, advisory, basis in citations],
                "tool_id": tool_id, "citation": citation("02-sca-vulnerability-match", tool_id)}

    matches = [
        match(1, "lodash", ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"], [("grype-db", "GHSA-35jh-r3h4-6jhm", "purl")]),
        # One advisory reported by BOTH sources under two ids: one match, two citations.
        match(2, "log4j-core", ["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"],
              [("grype-db", "CVE-2021-44228", "cpe"), ("osv", "GHSA-jfh8-c2jp-5v3q", "purl")]),
    ]
    digest = contracts.databases_digest(DATABASES)
    result = {"schema": "appsec-review/sca-vulnerability-match/1.0", **header, "redactor": dict(REDACTOR),
              "sbom_binding": dict(binding), "databases_digest": digest, "evaluated": evaluated, "matches": matches}
    identities = {"schema": "appsec-review/sca-vulnerability-match-database-identities/1.0", **header,
                  "databases_digest": digest,
                  "databases": [{"assertion": "database-snapshot-identity", "database": database_block(kind),
                                 "data_timestamp": DATABASES[kind]["data_timestamp"],
                                 **age_block(DATABASES[kind]["data_timestamp"], max_age)} for kind in contracts.DATABASE_KINDS]}
    gap_document = {"schema": "appsec-review/sca-vulnerability-match-coverage-gaps/1.0", **header, "redactor": dict(REDACTOR),
                    "sbom_binding": dict(binding), "gaps": gaps}
    summary = {"schema": "appsec-review/sca-vulnerability-match-gap-summary/1.0", **header, "sbom_binding": dict(binding),
               "component_count": len(sbom["components"]), "evaluated_count": len(evaluated), "gap_count": len(gaps),
               "counts": [{"ecosystem": e, "reason": r, "count": c} for e, r, c in contracts.gap_summary_counts(gaps)],
               "gap_list": {"path": contracts.SCA_GAPS_FILE, "sha256": ""}}
    identities_listed = [{"kind": "vulnerability-database", "identity_id": kind, "version": DATABASES[kind]["schema_version"],
                          "sha256": DATABASES[kind]["sha256"]} for kind in contracts.DATABASE_KINDS]
    documents = {contracts.SCA_RESULT_FILE: result, contracts.SCA_IDENTITIES_FILE: identities,
                 contracts.SCA_GAPS_FILE: gap_document, contracts.SCA_SUMMARY_FILE: summary,
                 **build_aggregate(header, tool_id, EXECUTORS[SCA], len(matches), identities_listed, 1,
                                   unmapped_gap(tool_id, len(gaps)))}
    return Spec(SCA, documents).reseal()


def license_spec(sbom: dict, expected_sbom: dict) -> Spec:
    header, tool_id = header_for(LICENSE), TOOLS[LICENSE]
    by_name = {item["name"]: item["component_id"] for item in sbom["components"]}

    def record(number, assertion, reference, expression, state, kind, path, start, end):
        return {"record_id": f"LI-{number:06d}", "assertion": assertion, "component_ref": reference,
                "license_expression": expression, "expression_state": state,
                "claim_source": {"kind": kind, "path": path, "sha256": sha(SOURCE_FILES[path]), "start_line": start, "end_line": end},
                "tool_id": tool_id, "citation": citation("02-license-scan", tool_id)}

    records = [record(1, "license-text-detected", None, "Apache-2.0", "spdx-expression", "found-in-file", "LICENSE", 1, 2),
               record(2, "license-text-detected", by_name["lodash"], "MIT", "spdx-expression", "found-in-file",
                      "web/package-lock.json", 1, 3),
               record(3, "license-text-detected", by_name["jinja2"], None, "unknown", "found-in-file",
                      "services/api/requirements.txt", 1, 1)]
    if "zlib" in by_name:
        records += [record(4, "license-text-detected", by_name["left-pad"], "MIT", "spdx-expression", "declared-in-manifest",
                           "web/package.json", 3, 3),
                    record(5, "vendored-component-inferred", by_name["zlib"], "Zlib", "spdx-expression", "found-in-file",
                           "third_party/zlib/LICENSE", 1, 3),
                    record(6, "copyright-statement-detected", None, None, "no-assertion", "found-in-file",
                           "third_party/zlib/LICENSE", 4, 4)]
    result = {"schema": "appsec-review/license-inventory/1.0", **header, "redactor": dict(REDACTOR),
              "sbom_binding": sbom_binding(expected_sbom), "records": records}
    documents = {contracts.LICENSE_RESULT_FILE: result,
                 **build_aggregate(header, tool_id, EXECUTORS[LICENSE], len(records), [], 9, [])}
    return Spec(LICENSE, documents)


def lifecycle_spec(sbom: dict, expected_sbom: dict, inventory: dict, expected_license: dict, table_identity: dict, max_age) -> Spec:
    header, tool_id = header_for(LIFECYCLE), TOOLS[LIFECYCLE]
    entries = []
    for number, item in enumerate(sbom["components"], 1):
        row = contracts.lifecycle_row_for(item, TABLE["rows"])
        entries.append({
            "entry_id": f"DL-{number:06d}", "component_ref": item["component_id"],
            "assertion": "lifecycle-unknown" if row is None else "reference-table-eol-match",
            "status": "unknown" if row is None else row["status"],
            "table_row": None if row is None else {field: row[field] for field in ("row_id", "cycle", "status", "eol_date")},
            "resurfaced_licenses": [{"assertion": "license-field-resurfaced", "record_ref": record["record_id"],
                                     "license_expression": record["license_expression"]} for record in inventory["records"]
                                    if record["component_ref"] == item["component_id"]
                                    and record["assertion"] == "license-text-detected"]})
    result = {"schema": "appsec-review/dependency-lifecycle/1.0", **header, "redactor": dict(REDACTOR),
              "sbom_binding": sbom_binding(expected_sbom),
              "license_binding": {"job_id": "02-license-scan", "attempt_id": expected_license["attempt_id"],
                                  "path": contracts.LICENSE_RESULT_FILE, "sha256": expected_license["sha256"]},
              "reference_table": dict(table_identity), "entries": entries}
    identity = {"schema": "appsec-review/dependency-lifecycle-reference-table-identity/1.0", **header, **table_identity,
                "row_count": len(TABLE["rows"]), **age_block(TABLE["as_of"] + "T00:00:00Z", max_age)}
    listed = [{"kind": "reference-table", "identity_id": table_identity["table_id"], "version": table_identity["version"],
               "sha256": table_identity["sha256"]}]
    unknown = sum(1 for entry in entries if entry["status"] == "unknown")
    documents = {contracts.LIFECYCLE_RESULT_FILE: result, contracts.TABLE_IDENTITY_FILE: identity,
                 **build_aggregate(header, tool_id, EXECUTORS[LIFECYCLE], len(entries), listed, 2, unmapped_gap(tool_id, unknown))}
    return Spec(LIFECYCLE, documents)


def manifest_document(contract_id: str, attempt: Path) -> dict:
    outputs = [{"path": path.relative_to(attempt).as_posix(), "sha256": sha(path.read_bytes())}
               for path in sorted((attempt / "outputs").rglob("*")) if path.is_file()]
    return {"schema": contracts.MANIFEST_SCHEMA, "contract_id": contract_id, "outputs": outputs}


class Published:
    """One spec published into the world by the real redactor."""

    def __init__(self, world: "World", spec: Spec, extra_private: dict | None = None):
        self.world, self.spec = world, spec
        self.tool_root = world.base / "jobs" / spec.job_id
        self.root = self.tool_root / "attempts" / spec.header["attempt_id"]
        private = world.base / "private" / spec.job_id
        private.mkdir(parents=True)
        self.private_bytes = {}
        for relative, document in spec.documents.items():
            self.private_bytes[relative] = dump(document)
        self.private_bytes.update(spec.raw_files)
        for relative, data in {**self.private_bytes, **(extra_private or {})}.items():
            (private / Path(relative).name).write_bytes(data)
        self.root.mkdir(parents=True)
        self.receipt = redaction.redact_tree(private, self.root / "outputs", on_unhandled=POLICY, limits=LIMITS)
        (self.root / "status.json").write_bytes(dump(spec.status))
        (self.root / "manifest.json").write_bytes(dump(manifest_document(spec.contract_id, self.root)))
        for relative, data in spec.tool_files.items():
            target = self.tool_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)

        # What acceptance recorded, once. A downstream caller reads THIS, never the attempt's current bytes.
        self.accepted = {relative: sha((self.root / relative).read_bytes()) for relative in self.private_bytes}

    def expected(self, relative: str) -> dict:
        return {"attempt_id": self.spec.header["attempt_id"], "sha256": self.accepted[relative]}


class World:
    def __init__(self, test: unittest.TestCase, variant: str = "full", max_age=contracts.NO_AGE_LIMIT, source_edit=None):
        self.test, self.variant, self.max_age = test, variant, max_age
        directory = tempfile.TemporaryDirectory()
        test.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.source = self.base / "source"
        for relative, data in SOURCE_FILES.items():
            if variant == "full" or relative in CLEAN_SOURCE:
                target = self.source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        if source_edit:
            source_edit(self.source)
        self.table_path = self.base / "data" / "reference" / "curated-eol-table.json"
        self.table_path.parent.mkdir(parents=True)
        self.table_path.write_bytes(dump(TABLE))
        self.table_identity = {"table_id": TABLE["table_id"], "version": TABLE["version"], "sha256": sha(dump(TABLE)),
                               "as_of": TABLE["as_of"]}
        self.published: dict[str, Published] = {}

    def publish(self, contract_id: str, mutate=None, extra_private=None) -> Published:
        if contract_id != SBOM and SBOM not in self.published:
            self.publish(SBOM)
        if contract_id == LIFECYCLE and LICENSE not in self.published:
            self.publish(LICENSE)
        if contract_id == SBOM:
            spec = sbom_spec(self.variant)
        else:
            sbom = self.published[SBOM].spec.documents[contracts.SBOM_MANIFEST_FILE]
            expected_sbom = self.published[SBOM].expected(contracts.SBOM_MANIFEST_FILE)
            if contract_id == SCA:
                spec = sca_spec(sbom, expected_sbom, self.max_age)
            elif contract_id == LICENSE:
                spec = license_spec(sbom, expected_sbom)
            else:
                spec = lifecycle_spec(sbom, expected_sbom, self.published[LICENSE].spec.documents[contracts.LICENSE_RESULT_FILE],
                                      self.published[LICENSE].expected(contracts.LICENSE_RESULT_FILE), self.table_identity,
                                      self.max_age)
        if mutate:
            mutate(spec)
        self.published[contract_id] = Published(self, spec, extra_private)
        return self.published[contract_id]

    def arguments(self, contract_id: str, **override) -> dict:
        item = self.published[contract_id]
        values = {"tool_outputs_root": item.tool_root, "expected_header": dict(item.spec.header),
                  "expected_dagster_run_id": DAGSTER_RUN, "node_status": item.spec.node_status,
                  "declared_tool_ids": list(item.spec.declared), "permitted_node_statuses": list(item.spec.permitted),
                  "on_unhandled": POLICY, "limits": LIMITS}
        if contract_id in (SBOM, LICENSE):
            values["source_root"] = self.source
        if contract_id != SBOM:
            values["sbom_attempt_root"] = self.published[SBOM].root
            values["expected_sbom"] = self.published[SBOM].expected(contracts.SBOM_MANIFEST_FILE)
        if contract_id == SCA:
            values.update(expected_databases=deepcopy(DATABASES), max_age=self.max_age, now=NOW)
        if contract_id == LIFECYCLE:
            values.update(license_attempt_root=self.published[LICENSE].root,
                          expected_license=self.published[LICENSE].expected(contracts.LICENSE_RESULT_FILE),
                          reference_table_path=self.table_path, expected_reference_table=dict(self.table_identity),
                          max_age=self.max_age, now=NOW)
        values.update(override)
        return values

    def run(self, contract_id: str, **override) -> list[str]:
        errors = VERIFIERS[contract_id](self.published[contract_id].root, **self.arguments(contract_id, **override))
        assert isinstance(errors, list) and all(isinstance(error, str) for error in errors)
        for error in errors:  # the invariant, checked on every verification this suite performs
            for planted in PLANTED:
                assert planted not in error, f"a planted value reached an error message: {error!r}"
            assert re.match(r"[a-z][A-Za-z0-9:./_-]*: ", error), f"unnamed error: {error!r}"
        return errors


VERIFIERS = {SBOM: contracts.verify_sbom_attempt, SCA: contracts.verify_sca_attempt,
             LICENSE: contracts.verify_license_attempt, LIFECYCLE: contracts.verify_lifecycle_attempt}
RESULT_FILES = {contract_id: policy["result_schema"][0] for contract_id, policy in contracts.CONTRACT_POLICIES.items()}


def edit(relative, function, reseal=True):
    def mutate(spec):
        function(spec.documents[relative])
        if reseal:
            spec.reseal()
    return mutate


def mutated(test, contract_id, mutate, **world_arguments) -> list[str]:
    world = World(test, **world_arguments)
    world.publish(contract_id, mutate)
    return world.run(contract_id)


def walk_schema(node, path="$"):
    if isinstance(node, dict):
        if "properties" in node:
            yield path, node
        for key, value in node.items():
            yield from walk_schema(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk_schema(value, f"{path}[{index}]")


def schema_strings(node):
    """Every property name, const and enum string a schema can put into a published document."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "properties" and isinstance(value, dict):
                yield from value
            if key == "const" and isinstance(value, str):
                yield value
            if key == "enum":
                yield from (item for item in value if isinstance(item, str))
            yield from schema_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from schema_strings(value)


# ---- contracts and schemas ---------------------------------------------------------------------------

class ContractDeclarationTests(unittest.TestCase):
    # Nothing: the PR 23 review reconciled the fixture and the ADR with the registry records, so a
    # contract's required_files ARE the fixture's required_artifacts. Kept as an explicit empty pin so
    # that a future divergence has to be written down here rather than appear silently.
    ADDED_FILES = {SBOM: set(), SCA: set(), LICENSE: set(), LIFECYCLE: set()}

    @classmethod
    def setUpClass(cls):
        cls.proposal = {node["proposed_output_contract_id"]: node
                        for node in json.loads(PROPOSAL.read_text(encoding="utf-8"))["proposed_nodes"]}

    def contract(self, contract_id):
        return json.loads((CONTRACT_DIR / f"{contract_id}.json").read_text(encoding="utf-8"))

    def test_registry_contracts_are_schema_valid_and_match_the_pinned_policy(self):
        self.assertEqual(set(contracts.CONTRACT_POLICIES), {SBOM, SCA, LICENSE, LIFECYCLE})
        for contract_id in contracts.CONTRACT_POLICIES:
            record = self.contract(contract_id)
            self.assertEqual(validate_document(record, "output-contract.schema.json"), [])
            self.assertEqual(record["contract_id"], contract_id)
            self.assertEqual(contracts.contract_declaration_errors(record), [])

    def test_contract_policy_and_adr_fixture_are_projections_of_one_decision(self):
        for contract_id, policy in contracts.CONTRACT_POLICIES.items():
            node, record = self.proposal[contract_id], self.contract(contract_id)
            with self.subTest(contract=contract_id):
                self.assertTrue(node["adopted"])
                self.assertEqual(node["proposed_job_id"], policy["job_id"])
                self.assertEqual(set(record["required_files"]), set(node["required_artifacts"]) | self.ADDED_FILES[contract_id])
                self.assertFalse(set(node["required_artifacts"]) & self.ADDED_FILES[contract_id])
                self.assertEqual(set(policy["required_files"]), set(record["required_files"]))
                self.assertEqual(record["claim_class"], node["proposed_claim_class"])
                self.assertEqual(list(policy["allowed_assertions"]), node["proposed_claim_class"]["allowed_assertions"])
                self.assertEqual(list(contracts.NEVER_SKIPS), node["permitted_terminal_statuses"])
                self.assertEqual(node["evidence_assembly_edge"]["allowed_skip_reasons"], [])
                self.assertIn(record["result_schema"]["artifact"], node["required_artifacts"])
                self.assertTrue((REPO / "schemas" / record["result_schema"]["schema_file"]).is_file())
                self.assertEqual([tool["tool_id"] for tool in node["tool_instances"]], [TOOLS[contract_id]])
                self.assertEqual(node["worker_kind"], EXECUTORS[contract_id])

    def test_the_accepted_adr_names_the_same_files_edges_and_data_sources_as_the_contracts(self):
        """PR 23 review [P1]: the accepted ADR said one thing and the registry another. The ADR's
        contract table, node table and permission table are read here, not trusted."""
        adr = (REPO / "docs" / "decisions" / "ADR-0010-vendor-prepass-decomposition.md").read_text(encoding="utf-8")
        rows = [[cell.strip() for cell in line.strip().strip("|").split("|")]
                for line in adr.replace("\r\n", "\n").split("\n") if line.startswith("| `")]
        for contract_id in contracts.CONTRACT_POLICIES:
            with self.subTest(contract=contract_id):
                listed = [row for row in rows if row[0] == f"`{contract_id}`" and "json" in row[1]]
                self.assertEqual(len(listed), 1)
                named = {f"{contracts.OUTPUTS_DIR}/{name}" for name in re.findall(r"`([^`]+)`", listed[0][1])}
                required = set(self.contract(contract_id)["required_files"]) - {"manifest.json", "status.json"}
                self.assertEqual(named, required)
        nodes = {row[0].strip("`"): row for row in rows if len(row) == 6 and row[1] in ("producer", "deterministic transform")}
        by_job = {node["proposed_job_id"]: node for node in self.proposal.values()}
        step_map = json.loads((PROPOSAL.parent / "legacy-step-map.proposal.json").read_text(encoding="utf-8"))

        def step_dependencies(node, found):
            if isinstance(node, dict):
                if "legacy_step" in node and isinstance(node.get("dependencies"), list):
                    found.setdefault(node.get("proposed_job_id"), []).append(sorted(node["dependencies"]))
                for value in node.values():
                    step_dependencies(value, found)
            elif isinstance(node, list):
                for value in node:
                    step_dependencies(value, found)
            return found
        from_steps = step_dependencies(step_map, {})
        for policy in contracts.CONTRACT_POLICIES.values():
            job = policy["job_id"]
            with self.subTest(job=job):
                in_adr = sorted(re.findall(r"`([^`]+)`", nodes[job][2]))
                self.assertEqual(in_adr, sorted(edge["job"] for edge in by_job[job]["dependencies"]))
                for listed in from_steps.get(job, []):
                    self.assertEqual(listed, in_adr)
        self.assertEqual(sorted(re.findall(r"`([^`]+)`", nodes["02-license-scan"][2])), ["00-intake", "02-sbom-inventory"])
        permission = [row for row in rows if row[0] == "`02-sca-vulnerability-match`" and len(row) == 8]
        self.assertEqual(len(permission), 1)
        self.assertIn("Grype", permission[0][2])
        self.assertIn("OSV", permission[0][2])
        self.assertNotIn("reads the published NVD", permission[0][2])

    def test_every_artifact_the_threat_workbench_is_promised_is_a_required_file(self):
        text = PRODUCERS.read_text(encoding="utf-8").replace("\r\n", "\n")
        family = text.split("- id: sbom-sca-license-lifecycle", 1)[1].split("rejected_alternatives", 1)[0]
        blocks = family.split("- job: ")[1:]
        self.assertEqual(len(blocks), 4)
        for block in blocks:
            contract_id = re.search(r"contract: ([a-z-]+)", block).group(1)
            promised = set(re.findall(r"outputs/[A-Za-z0-9._-]+", block.split("artifacts:", 1)[1]))
            with self.subTest(contract=contract_id):
                self.assertTrue(promised)
                self.assertLessEqual(promised, set(self.contract(contract_id)["required_files"]))
        self.assertIn(contracts.SCA_SUMMARY_FILE, family)  # M5's aggregated summary is what the workbench gets

    def test_every_allowed_assertion_has_exactly_one_home(self):
        store = SchemaStore()

        def enum_of(schema, *path):
            node = store.load(schema)
            for key in path:
                node = node[key]
            return set(node["enum"]) if "enum" in node else {node["const"]}

        homes = {
            SBOM: enum_of("sbom-inventory-component.schema.json", "properties", "assertion"),
            SCA: enum_of("sca-vulnerability-match-record.schema.json", "properties", "assertion")
            | enum_of("sca-vulnerability-match-database-identities.schema.json", "properties", "databases", "items", "properties", "assertion")
            | enum_of("sca-vulnerability-match-coverage-gaps.schema.json", "properties", "gaps", "items", "properties", "assertion"),
            LICENSE: enum_of("license-inventory-record.schema.json", "properties", "assertion") | {"scan-coverage-gap"},
            LIFECYCLE: enum_of("dependency-lifecycle-entry.schema.json", "properties", "assertion")
            | enum_of("dependency-lifecycle-entry.schema.json", "properties", "resurfaced_licenses", "items", "properties", "assertion"),
        }
        for contract_id, policy in contracts.CONTRACT_POLICIES.items():
            self.assertEqual(homes[contract_id], set(policy["allowed_assertions"]), contract_id)

    def test_a_weakened_contract_declaration_is_rejected(self):
        def drop(field, value):
            def mutate(record):
                record[field].remove(value)
            return mutate

        def promotion(record):
            record["claim_class"]["forbidden_promotions"].remove("runtime-state")

        def assertion(record):
            record["claim_class"]["allowed_assertions"].append("component-is-reachable")

        def class_id(record):
            record["claim_class"]["claim_class_id"] = "supplied_partition_map"

        def schema_file(record):
            record["result_schema"]["schema_file"] = "tool-results.schema.json"

        def no_claim(record):
            del record["claim_class"]

        def extra_status(record):
            record["required_status_fields"].append("reviewer")

        cases = [(drop("required_files", contracts.RECEIPT_FILE), "contract-required-files"),
                 (drop("required_files", contracts.COVERAGE_FILE), "contract-required-files"),
                 (drop("required_status_fields", "attempt_id"), "contract-status-fields"), (extra_status, "contract-status-fields"),
                 (promotion, "contract-forbidden-promotions"), (assertion, "contract-claim-class"),
                 (class_id, "contract-claim-class"), (schema_file, "contract-result-schema"), (no_claim, "contract-claim-class")]
        for contract_id in contracts.CONTRACT_POLICIES:
            for mutate, expected in cases:
                record = self.contract(contract_id)
                mutate(record)
                with self.subTest(contract=contract_id, case=expected, mutate=mutate.__name__):
                    self.assertEqual(names(contracts.contract_declaration_errors(record)), {expected})
        for contract_id, dropped in ((SCA, contracts.SCA_IDENTITIES_FILE), (SCA, contracts.SCA_SUMMARY_FILE),
                                     (SCA, contracts.SCA_GAPS_FILE), (LIFECYCLE, contracts.TABLE_IDENTITY_FILE),
                                     (SBOM, contracts.SBOM_CDX_FILE)):
            record = self.contract(contract_id)
            record["required_files"].remove(dropped)
            self.assertEqual(names(contracts.contract_declaration_errors(record)), {"contract-required-files"}, dropped)
        record = self.contract(SCA)
        record["claim_class"]["forbidden_promotions"].append("exploitability")  # outside the closed enum
        self.assertEqual(names(contracts.contract_declaration_errors(record)), {"contract-schema"})
        record = self.contract(SCA)
        record["contract_id"] = "secrets-inventory"
        self.assertEqual(names(contracts.contract_declaration_errors(record)), {"contract-unknown"})
        with self.assertRaises(TypeError):
            contracts.contract_declaration_errors(None)

    def test_the_pinned_policy_cannot_be_edited_in_place(self):
        with self.assertRaises(TypeError):
            contracts.CONTRACT_POLICIES[SCA]["required_files"] = ()
        with self.assertRaises(TypeError):
            contracts.CONTRACT_POLICIES["extra"] = {}
        with self.assertRaises(TypeError):
            contracts.CONTRACT_POLICIES[SCA]["document_schemas"]["outputs/x.json"] = "x"
        with self.assertRaises(TypeError):
            contracts.ECOSYSTEM_VERSION_SCHEME["conan"] = "semver"
        self.assertIsInstance(contracts.CONTRACT_POLICIES[SBOM]["required_files"], tuple)
        self.assertIsInstance(contracts.FORBIDDEN_CLAIM_WORDS, frozenset)

    def test_validation_rules_state_the_decisions_and_nothing_undecided(self):
        rules = {contract_id: " ".join(self.contract(contract_id)["validation_rules"]) for contract_id in contracts.CONTRACT_POLICIES}
        for text in rules.values():
            self.assertIn("outputs/redaction-receipt.json is required", text)
            self.assertIn("BEFORE any published document is parsed", text)
            self.assertIn("cannot promote", text)
            for undecided in ("recommended", "proposed", "should consider", "TBD"):
                self.assertNotIn(undecided, text)
        for phrase in ("grype-db or osv", "closed enum (purl, cpe)", "never the constant cpe", "ONE match with two citations",
                       "version scheme", "partitioned", "M5", "FAILED, never OK_WITH_GAPS", "06-cve-reachability", "NO_AGE_LIMIT"):
            self.assertIn(phrase, rules[SCA], phrase)
        self.assertIn("never be promoted to a declared one", rules[SBOM])
        self.assertIn("no legal conclusion", rules[LICENSE])
        self.assertIn("Absence from the table is never supported", rules[LIFECYCLE])


class SchemaHygieneTests(unittest.TestCase):
    SUPPORTED = {"$schema", "$id", "title", "description", "type", "required", "properties", "additionalProperties", "enum",
                 "const", "pattern", "items", "minItems", "$ref"}

    @classmethod
    def setUpClass(cls):
        cls.schemas = {name: json.loads((REPO / "schemas" / name).read_text(encoding="utf-8")) for name in ALL_SCHEMAS}

    def test_the_slice_owns_the_expected_schema_files(self):
        self.assertEqual(len(ALL_SCHEMAS), 16)
        for policy in contracts.CONTRACT_POLICIES.values():
            for schema_name in policy["document_schemas"].values():
                self.assertIn(schema_name, ALL_SCHEMAS)
        self.assertIn(contracts.REFERENCE_TABLE_SCHEMA, ALL_SCHEMAS)

    def test_every_object_is_closed_and_every_declared_property_is_required(self):
        for name, schema in self.schemas.items():
            for path, node in walk_schema(schema):
                with self.subTest(schema=name, path=path):
                    self.assertIs(node.get("additionalProperties"), False)
                    self.assertEqual(sorted(node["required"]), sorted(node["properties"]))

    def test_only_subset_keywords_sibling_refs_and_end_anchored_patterns_are_used(self):
        def visit(node, name, inside_properties=False):
            if isinstance(node, dict):
                if not inside_properties:
                    self.assertLessEqual(set(node), self.SUPPORTED, name)
                    if "$ref" in node:
                        self.assertTrue((REPO / "schemas" / node["$ref"]).is_file(), node["$ref"])
                        self.assertNotIn("/", node["$ref"])
                        self.assertNotIn("#", node["$ref"])
                    if "pattern" in node:
                        self.assertTrue(node["pattern"].startswith("^") and node["pattern"].endswith(r"\Z"), node["pattern"])
                    if node.get("type") == "string" or node.get("type") == ["string", "null"]:
                        self.assertTrue("pattern" in node or "enum" in node, f"{name}: a free string has room for text")
                for key, value in node.items():
                    visit(value, name, inside_properties=(key == "properties" and not inside_properties))
            elif isinstance(node, list):
                for value in node:
                    visit(value, name)

        for name, schema in self.schemas.items():
            visit(schema, name)

    def test_no_property_names_a_claim_this_family_may_not_make(self):
        taxonomy = json.loads((REPO / "schemas" / "verdict-taxonomies.json").read_text(encoding="utf-8"))
        owned_by_06 = set(taxonomy["taxonomies"]["cve-reachability"]["values"])
        self.assertIn("reachable", owned_by_06)
        for name, schema in self.schemas.items():
            strings = set(schema_strings(schema))
            with self.subTest(schema=name):
                self.assertFalse(strings & owned_by_06, "a value of 06-cve-reachability's verdict taxonomy")
                for text in strings:
                    self.assertFalse(set(re.split(r"[_\-\s./]+", text.lower())) & contracts.FORBIDDEN_CLAIM_WORDS, text)
                for free_text in ("description", "note", "notes", "message", "summary", "title", "text", "comment", "url",
                                  "supplier", "author", "holder", "range", "fixed_in"):
                    self.assertNotIn(free_text, strings)

    def test_no_schema_string_is_rewritten_or_wholesale_redacted_by_the_v06_redactor(self):
        for name, schema in self.schemas.items():
            for text in set(schema_strings(schema)):
                with self.subTest(schema=name, text=text):
                    self.assertIsNone(redaction._KEYWORD_RE.search(text), "the redactor redacts the VALUE under a secret-ish key")
                    if text != V03_HEADER_KEY:
                        self.assertEqual(redaction._merged_spans(text), [])

    def test_match_basis_is_a_closed_enum_and_never_the_constant_cpe(self):
        record = self.schemas["sca-vulnerability-match-record.schema.json"]
        basis = record["properties"]["citations"]["items"]["properties"]["match_basis"]
        self.assertEqual(basis, {"type": "string", "enum": ["purl", "cpe"]})
        self.assertEqual(tuple(basis["enum"]), contracts.MATCH_BASES)
        self.assertEqual(record["properties"]["citations"]["minItems"], 1)
        database = self.schemas["sca-vulnerability-match-database.schema.json"]
        self.assertEqual(tuple(database["properties"]["database_kind"]["enum"]), contracts.DATABASE_KINDS)
        self.assertEqual(set(database["required"]), {"database_kind", *contracts.DATABASE_BLOCK_FIELDS})
        gaps = self.schemas["sca-vulnerability-match-coverage-gaps.schema.json"]["properties"]["gaps"]["items"]["properties"]
        self.assertEqual(tuple(gaps["reason"]["enum"]), contracts.GAP_REASONS)

    def test_age_fields_mirror_the_v09_identity_schema(self):
        v09 = json.loads((REPO / "schemas" / "vulnerability-database-identity.schema.json").read_text(encoding="utf-8"))["properties"]
        mine = self.schemas["sca-vulnerability-match-database-identities.schema.json"]["properties"]["databases"]["items"]["properties"]
        table = self.schemas["dependency-lifecycle-reference-table-identity.schema.json"]["properties"]
        for properties in (mine, table):
            self.assertEqual(properties["age_policy"]["enum"], v09["age_policy"]["enum"])
            self.assertEqual(properties["max_age_seconds"]["type"], v09["max_age_seconds"]["type"])
            self.assertEqual(properties["age_seconds"]["type"], v09["age_seconds"]["type"])
        self.assertIs(contracts.NO_AGE_LIMIT, sca_nvd_snapshot.NO_AGE_LIMIT)


# ---- goldens --------------------------------------------------------------------------------------------

class GoldenTests(unittest.TestCase):
    def worlds(self):
        for variant in ("full", "clean"):
            for max_age in (contracts.NO_AGE_LIMIT, timedelta(days=30)):
                world = World(self, variant, max_age)
                for contract_id in (SBOM, SCA, LICENSE, LIFECYCLE):
                    world.publish(contract_id)
                yield variant, world

    def test_every_golden_is_producible_verifies_and_survives_the_redactor_unchanged(self):
        for variant, world in self.worlds():
            for contract_id, item in world.published.items():
                with self.subTest(variant=variant, contract=contract_id, max_age=repr(world.max_age)):
                    self.assertEqual(world.run(contract_id), [])
                    # purls, CPEs, hashes, CVE/GHSA ids, licence expressions and run ids all survive V06.
                    self.assertTrue(all(record["disposition"] == "unchanged" for record in item.receipt["files"]))
                    totals = item.receipt["totals"]
                    self.assertEqual((totals["redactions_total"], totals["files_redacted"], totals["files_withheld"]), (0, 0, 0))
                    for relative, data in item.private_bytes.items():
                        self.assertEqual((item.root / relative).read_bytes(), data, relative)
                    for relative, schema_name in contracts.CONTRACT_POLICIES[contract_id]["document_schemas"].items():
                        self.assertEqual(validate_document(item.spec.documents[relative], schema_name), [])

    def test_golden_statuses_are_the_only_ones_the_documents_support(self):
        for variant, expected in (("full", {SBOM: "OK", SCA: "OK_WITH_GAPS", LICENSE: "OK", LIFECYCLE: "OK_WITH_GAPS"}),
                                  ("clean", {SBOM: "OK", SCA: "OK", LICENSE: "OK", LIFECYCLE: "OK_WITH_GAPS"})):
            world = World(self, variant)
            for contract_id, status in expected.items():
                item = world.publish(contract_id)
                documents = item.spec.documents
                self.assertEqual(item.spec.node_status, status)
                self.assertEqual(shapes.supportable_success_status(documents[contracts.TOOL_RESULTS_FILE],
                                                                   documents[contracts.COVERAGE_FILE]), status)
                other = "OK" if status == "OK_WITH_GAPS" else "OK_WITH_GAPS"
                self.assertTrue(world.run(contract_id, node_status=other))

    def test_invariant_evaluated_and_gap_sets_partition_the_sbom(self):
        for variant in ("full", "clean"):
            world = World(self, variant)
            documents = world.publish(SCA).spec.documents
            sbom_ids = [item["component_id"] for item in world.published[SBOM].spec.documents[contracts.SBOM_MANIFEST_FILE]["components"]]
            evaluated = [entry["component_ref"] for entry in documents[contracts.SCA_RESULT_FILE]["evaluated"]]
            gaps = [gap["component_ref"] for gap in documents[contracts.SCA_GAPS_FILE]["gaps"]]
            self.assertEqual(sorted(evaluated + gaps), sorted(sbom_ids))
            self.assertFalse(set(evaluated) & set(gaps))
            self.assertEqual(len(gaps), 4 if variant == "full" else 0)

    def test_invariant_the_m5_summary_is_a_projection_of_the_gap_records(self):
        world = World(self)
        documents = world.publish(SCA).spec.documents
        gaps, summary = documents[contracts.SCA_GAPS_FILE]["gaps"], documents[contracts.SCA_SUMMARY_FILE]
        derived = contracts.gap_summary_counts(gaps)
        self.assertIsInstance(derived, tuple)
        self.assertEqual([(row["ecosystem"], row["reason"], row["count"]) for row in summary["counts"]], list(derived))
        self.assertEqual(sum(count for _, _, count in derived), summary["gap_count"])
        self.assertEqual(summary["component_count"], summary["evaluated_count"] + summary["gap_count"])
        self.assertEqual({reason for _, reason, _ in derived},
                         {"version-unknown", "no-package-identifier", "ecosystem-not-covered", "version-unparseable"})
        self.assertEqual(summary["gap_list"], {"path": contracts.SCA_GAPS_FILE,
                                               "sha256": sha((world.published[SCA].root / contracts.SCA_GAPS_FILE).read_bytes())})

    def test_one_advisory_from_both_sources_is_one_match_with_two_citations(self):
        world = World(self)
        matches = world.publish(SCA).spec.documents[contracts.SCA_RESULT_FILE]["matches"]
        log4j = matches[1]
        self.assertEqual([c["database"]["database_kind"] for c in log4j["citations"]], ["grype-db", "osv"])
        self.assertEqual({c["match_basis"] for c in log4j["citations"]}, {"purl", "cpe"})
        self.assertEqual(log4j["advisory_id"], "CVE-2021-44228")
        self.assertEqual(contracts.canonical_advisory_id(["GHSA-jfh8-c2jp-5v3q", "PYSEC-2021-1"]), "GHSA-jfh8-c2jp-5v3q")
        self.assertEqual(contracts.canonical_advisory_id(["PYSEC-2021-9", "GO-2021-0001"]), "GO-2021-0001")

    def test_pure_helpers(self):
        def item(ecosystem, version, purl="pkg:x/y", cpe=None):
            return {"ecosystem": ecosystem, "version": version, "purl": purl, "cpe": cpe, "name": "y"}

        self.assertIsNone(contracts.required_gap_reason(item("npm", "1.2.3")))
        self.assertIsNone(contracts.required_gap_reason(item("golang", "v1.2.3+incompatible")))
        self.assertIsNone(contracts.required_gap_reason(item("pypi", "1!2.0rc1.post2")))
        self.assertIsNone(contracts.required_gap_reason(item("conan", "1.1.1k", cpe="cpe:2.3:a:o:o:1:*:*:*:*:*:*:*")))
        self.assertEqual(contracts.required_gap_reason(item("npm", None)), "version-unknown")
        self.assertEqual(contracts.required_gap_reason(item("npm", "1.2.3", purl=None)), "no-package-identifier")
        self.assertEqual(contracts.required_gap_reason(item("conan", "1.1.1k")), "ecosystem-not-covered")
        for ecosystem, version in (("npm", "latest"), ("npm", "1.2"), ("golang", "1.2.3"), ("pypi", "1.0-SNAPSHOT"),
                                   ("maven", "RELEASE"), ("deb", "~1")):
            self.assertEqual(contracts.required_gap_reason(item(ecosystem, version)), "version-unparseable", (ecosystem, version))
        for ecosystem, path, kind in (("npm", "a/package.json", "manifest"), ("npm", "yarn.lock", "lockfile"),
                                      ("pypi", "requirements-dev.txt", "manifest"), ("nuget", "src/App.csproj", "manifest"),
                                      ("pypi", "a/package.json", "vendored-file-evidence"), ("generic", "go.mod", "vendored-file-evidence"),
                                      ("npm", "third_party/x/LICENSE", "vendored-file-evidence")):
            self.assertEqual(contracts.declaration_kind(ecosystem, path), kind, (ecosystem, path))
        rows = TABLE["rows"]
        self.assertEqual(contracts.lifecycle_row_for({"ecosystem": "maven", "name": "log4j-core", "version": "2.14.1"}, rows)["row_id"],
                         "log4j-core-2.14")  # the longest cycle wins
        self.assertEqual(contracts.lifecycle_row_for({"ecosystem": "maven", "name": "log4j-core", "version": "2.17.0"}, rows)["row_id"],
                         "log4j-core-2")
        self.assertIsNone(contracts.lifecycle_row_for({"ecosystem": "maven", "name": "log4j-core", "version": "21.0"}, rows))
        self.assertIsNone(contracts.lifecycle_row_for({"ecosystem": "maven", "name": "log4j-core", "version": None}, rows))
        self.assertIsNone(contracts.lifecycle_row_for({"ecosystem": "npm", "name": "log4j-core", "version": "2.14.1"}, rows))

    def test_both_database_identities_enter_the_fingerprint_and_the_clock_does_not(self):
        component = contracts.fingerprint_component(DATABASES)
        self.assertEqual([entry["database_kind"] for entry in component["databases"]], list(contracts.DATABASE_KINDS))
        text = json.dumps(component)
        for forbidden in ("age_seconds", "evaluated_at", "max_age", "age_policy"):
            self.assertNotIn(forbidden, text)
        base = contracts.databases_digest(DATABASES)
        for kind in contracts.DATABASE_KINDS:
            for field in contracts.DATABASE_FIELDS:
                changed = deepcopy(DATABASES)
                changed[kind][field] = label_sha("other") if field == "sha256" else (
                    "2026-01-01T00:00:00Z" if field == "data_timestamp" else changed[kind][field] + "x")
                self.assertNotEqual(contracts.databases_digest(changed), base, (kind, field))
        with self.assertRaises(TypeError):
            contracts.databases_digest({"grype-db": DATABASES["grype-db"]})


# ---- arguments ------------------------------------------------------------------------------------------

class ArgumentTests(unittest.TestCase):
    def test_no_safety_input_has_a_default(self):
        for contract_id, verifier in VERIFIERS.items():
            parameters = inspect.signature(verifier).parameters
            for name, parameter in parameters.items():
                with self.subTest(contract=contract_id, parameter=name):
                    self.assertIs(parameter.default, inspect.Parameter.empty)
                    if name != "attempt_root":
                        self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        for name in ("max_age", "now", "expected_databases", "expected_sbom", "sbom_attempt_root"):
            self.assertIn(name, inspect.signature(contracts.verify_sca_attempt).parameters)
        for name in ("max_age", "now", "expected_reference_table", "reference_table_path", "expected_license",
                     "license_attempt_root", "expected_sbom"):
            self.assertIn(name, inspect.signature(contracts.verify_lifecycle_attempt).parameters)

    def test_omitting_or_nulling_any_input_is_a_type_error(self):
        world = World(self, "clean")
        for contract_id in VERIFIERS:
            world.publish(contract_id)
        for contract_id, verifier in VERIFIERS.items():
            arguments = world.arguments(contract_id)
            root = world.published[contract_id].root
            for name in arguments:
                with self.subTest(contract=contract_id, omitted=name):
                    with self.assertRaises(TypeError):
                        verifier(root, **{key: value for key, value in arguments.items() if key != name})
                with self.subTest(contract=contract_id, nulled=name):
                    with self.assertRaises(TypeError):
                        verifier(root, **{**arguments, name: None})
            with self.assertRaises(TypeError):
                verifier(None, **arguments)

    def test_malformed_caller_facts_are_type_or_value_errors(self):
        world = World(self, "clean")
        world.publish(LIFECYCLE)
        world.publish(SCA)
        root = world.published[SCA].root
        bad = {
            "expected_header": [{"run_id": RUN_ID}, {**header_for(SCA), "extra": "x"}, {**header_for(SCA), "run_id": 5}],
            "expected_sbom": [{"sha256": "x"}, {"attempt_id": "a", "sha256": "b", "path": "c"}],
            "expected_databases": [{"grype-db": DATABASES["grype-db"]}, {**DATABASES, "nvd": DATABASES["osv"]},
                                   {**DATABASES, "osv": {**DATABASES["osv"], "sha256": "abc"}},
                                   {**DATABASES, "osv": {key: value for key, value in DATABASES["osv"].items() if key != "snapshot_id"}}],
            "max_age": [30, "NO_AGE_LIMIT", False], "now": [datetime(2026, 9, 20), "2026-09-20T12:30:00Z"],
            "declared_tool_ids": ["grype", {"grype": True}], "permitted_node_statuses": ["OK"],
            "on_unhandled": ["ignore", ""], "limits": [{}, 5], "expected_dagster_run_id": ["", "has space", 7],
            "node_status": [5], "tool_outputs_root": ["", b"x", True], "sbom_attempt_root": ["", False],
        }
        for name, values in bad.items():
            for value in values:
                with self.subTest(argument=name, value=repr(value)[:40]):
                    with self.assertRaises(TypeError):
                        contracts.verify_sca_attempt(root, **world.arguments(SCA, **{name: value}))
        with self.assertRaises(ValueError):
            contracts.verify_sca_attempt(root, **world.arguments(SCA, max_age=timedelta(0)))
        with self.assertRaises(TypeError):
            contracts.verify_lifecycle_attempt(world.published[LIFECYCLE].root, **world.arguments(
                LIFECYCLE, expected_reference_table={"table_id": "x"}))

    def test_the_callers_facts_are_not_taken_from_the_documents(self):
        world = World(self)
        for contract_id in VERIFIERS:
            world.publish(contract_id)
        cases = [
            (SCA, {"declared_tool_ids": ["grype", "osv-scanner"]}, "aggregate:declared-tool-missing"),
            (SCA, {"declared_tool_ids": ["osv-scanner"]}, "aggregate:undeclared-tool"),
            (SCA, {"node_status": "OK"}, "aggregate:node-ok-with-gaps"),
            (SCA, {"node_status": "FAILED"}, "status-mismatch"),
            (SCA, {"permitted_node_statuses": ["OK"]}, "aggregate:status-not-permitted"),
            (SCA, {"permitted_node_statuses": [*contracts.NEVER_SKIPS, "SKIPPED"]}, "status-not-permitted-by-contract"),
            (SCA, {"expected_dagster_run_id": "dagster-run-other"}, "status-mismatch"),
            (SBOM, {"expected_header": {**header_for(SBOM), "run_id": "20260101T000000Z-aaaaaa"}}, "header-mismatch"),
            (SBOM, {"expected_header": {**header_for(SBOM), "attempt_id": "another-attempt"}}, "header-mismatch"),
            (SBOM, {"expected_header": {**header_for(SBOM), "source_snapshot_sha256": label_sha("another")}}, "header-mismatch"),
            (LICENSE, {"limits": redaction.Limits(**{**redaction.asdict(LIMITS), "max_files": 1999})}, "receipt-invalid"),
            (LICENSE, {"on_unhandled": "withhold"}, "receipt-invalid"),
        ]
        for contract_id, override, expected in cases:
            with self.subTest(contract=contract_id, override=list(override)):
                self.assertIn(expected, names(world.run(contract_id, **override)))

    def test_the_wrong_verifier_or_the_wrong_attempt_is_rejected(self):
        world = World(self, "clean")
        for contract_id in VERIFIERS:
            world.publish(contract_id)
        with self.assertRaises(ValueError):  # the SCA verifier told it is validating the SBOM node
            contracts.verify_sca_attempt(world.published[SBOM].root, **world.arguments(SCA, expected_header=header_for(SBOM)))
        # the SCA verifier pointed at the SBOM attempt: the SCA files are simply not there
        errors = VERIFIERS[SCA](world.published[SBOM].root, **world.arguments(SCA))
        self.assertEqual(names(errors), {"required-file-missing"})
        # the licence attempt offered as the SBOM upstream, and an SBOM from another attempt
        self.assertEqual(names(world.run(SCA, sbom_attempt_root=world.published[LICENSE].root)), {"upstream-missing"})
        other = {**world.published[SBOM].expected(contracts.SBOM_MANIFEST_FILE), "attempt_id": "sbom-node-attempt-0002"}
        found = names(world.run(SCA, expected_sbom=other))
        self.assertEqual(found, {"upstream-binding-mismatch", "upstream-mismatch"})
        self.assertEqual(names(VERIFIERS[SBOM](world.base / "absent", **world.arguments(SBOM))), {"attempt-root"})


# ---- the six acceptance mutations of the task text ------------------------------------------------------------

class AcceptanceMutationTests(unittest.TestCase):
    def test_1_a_reachability_or_exploitability_assertion_is_rejected_by_name(self):
        planted = [("reachable", True), ("reachability", "reachable"), ("exploitability", CANARY), ("is_exploitable", True),
                   ("known_exploited", True), ("epss", 0.97), ("affected_in_deployment", True), ("severity", "critical"),
                   ("cvss_score", 9.8), ("fixed_in", CANARY), ("call-path-reachable", [CANARY])]
        for key, value in planted:
            for place in ("match", "evaluated", "top", "citation"):
                def mutate(document, key=key, value=value, place=place):
                    target = {"match": document["matches"][0], "evaluated": document["evaluated"][0], "top": document,
                              "citation": document["matches"][0]["citations"][0]}[place]
                    target[key] = value
                with self.subTest(key=key, place=place):
                    errors = mutated(self, SCA, edit(contracts.SCA_RESULT_FILE, mutate))
                    self.assertEqual(names(errors), {"forbidden-claim"})
                    self.assertTrue(all("06-cve-reachability" in error for error in errors))
        # as a VALUE of an existing field it is a schema violation, and is not echoed
        for value in ("reachable", "exploitable", "not-vulnerable", "affected"):
            def outcome(document, value=value):
                document["evaluated"][0]["outcome"] = value
            self.assertEqual(names(mutated(self, SCA, edit(contracts.SCA_RESULT_FILE, outcome))),
                             {f"schema:{contracts.SCA_RESULT_FILE}"})

        def assertion(document):
            document["matches"][0]["assertion"] = "advisory-is-reachable"
        self.assertEqual(names(mutated(self, SCA, edit(contracts.SCA_RESULT_FILE, assertion))), {f"schema:{contracts.SCA_RESULT_FILE}"})
        # the same guard protects the other three contracts, including legal conclusions
        for contract_id, relative, key in ((LICENSE, contracts.LICENSE_RESULT_FILE, "license_compatible"),
                                           (LICENSE, contracts.LICENSE_RESULT_FILE, "policy_violation"),
                                           (LIFECYCLE, contracts.LIFECYCLE_RESULT_FILE, "upgrade_recommendation"),
                                           (SBOM, contracts.SBOM_MANIFEST_FILE, "used_at_runtime")):
            def plant(document, key=key):
                document[key] = CANARY
            self.assertEqual(names(mutated(self, contract_id, edit(relative, plant))), {"forbidden-claim"}, key)

    def test_2_a_match_without_database_identity_is_rejected(self):
        def no_block(document):
            del document["matches"][0]["citations"][0]["database"]

        def no_citations(document):
            document["matches"][0]["citations"] = []

        def null_block(document):
            document["matches"][0]["citations"][0]["database"] = None

        for mutate in (no_block, no_citations, null_block):
            with self.subTest(mutate=mutate.__name__):
                self.assertEqual(names(mutated(self, SCA, edit(contracts.SCA_RESULT_FILE, mutate))), {f"schema:{contracts.SCA_RESULT_FILE}"})
        for field in contracts.DATABASE_BLOCK_FIELDS:
            def drop(document, field=field):
                del document["matches"][1]["citations"][1]["database"][field]

            def wrong(document, field=field):
                block = document["matches"][1]["citations"][1]["database"]
                block[field] = label_sha(CANARY) if field == "sha256" else "v05-canary-build"
            with self.subTest(field=field):
                self.assertEqual(names(mutated(self, SCA, edit(contracts.SCA_RESULT_FILE, drop))), {f"schema:{contracts.SCA_RESULT_FILE}"})
                self.assertEqual(names(mutated(self, SCA, edit(contracts.SCA_RESULT_FILE, wrong))), {"database-identity-mismatch"})

        def nvd(document):
            document["matches"][0]["citations"][0]["database"]["database_kind"] = "nvd"
        self.assertEqual(names(mutated(self, SCA, edit(contracts.SCA_RESULT_FILE, nvd))), {f"schema:{contracts.SCA_RESULT_FILE}"})

        def swapped(document):  # a grype-db citation relabelled osv: every identity field now disagrees
            document["matches"][0]["citations"][0]["database"]["database_kind"] = "osv"
        self.assertEqual(names(mutated(self, SCA, edit(contracts.SCA_RESULT_FILE, swapped))), {"database-identity-mismatch"})

        def one_database(document):
            document["databases"].pop()
        self.assertEqual(names(mutated(self, SCA, edit(contracts.SCA_IDENTITIES_FILE, one_database))),
                         {f"schema:{contracts.SCA_IDENTITIES_FILE}"})

        def same_database_twice(document):
            document["databases"][1] = deepcopy(document["databases"][0])
        self.assertEqual(names(mutated(self, SCA, edit(contracts.SCA_IDENTITIES_FILE, same_database_twice))),
                         {"database-identity-missing"})

    def test_3_a_match_basis_outside_the_enum_is_rejected(self):
        for value in ("name", "CPE", "purl-or-cpe", "", None, ["purl"], CANARY):
            def mutate(document, value=value):
                document["matches"][0]["citations"][0]["match_basis"] = value
            with self.subTest(value=repr(value)):
                self.assertEqual(names(mutated(self, SCA, edit(contracts.SCA_RESULT_FILE, mutate))), {f"schema:{contracts.SCA_RESULT_FILE}"})

        def cpe_without_a_cpe(document):  # lodash has no cpe in the bound SBOM
            document["matches"][0]["citations"][0]["match_basis"] = "cpe"

        def osv_by_cpe(document):
            document["matches"][1]["citations"][1]["match_basis"] = "cpe"
        for mutate in (cpe_without_a_cpe, osv_by_cpe):
            self.assertEqual(names(mutated(self, SCA, edit(contracts.SCA_RESULT_FILE, mutate))), {"match-basis-unsupported"})

    def test_4_an_uncovered_component_with_no_gap_record_is_rejected(self):
        def drop_gap_consistently(spec):
            """Remove the zlib gap and keep every OTHER projection honest, so only the partition can object."""
            gaps = spec.documents[contracts.SCA_GAPS_FILE]["gaps"]
            del gaps[1]
            for number, gap in enumerate(gaps, 1):
                gap["gap_id"] = f"VG-{number:06d}"
            summary = spec.documents[contracts.SCA_SUMMARY_FILE]
            summary["gap_count"] = len(gaps)
            summary["counts"] = [{"ecosystem": e, "reason": r, "count": c} for e, r, c in contracts.gap_summary_counts(gaps)]
            spec.documents[contracts.COVERAGE_FILE]["gaps"][0]["affected_input_count"] = len(gaps)
            spec.reseal()

        errors = mutated(self, SCA, drop_gap_consistently)
        self.assertEqual(names(errors), {"component-unaccounted"})
        self.assertIn("explicit gap record", " ".join(errors))

        def hide_as_clean(spec):
            """Move the gap into `evaluated` as 'no-advisory-matched': absence passed off as a clean result."""
            gaps = spec.documents[contracts.SCA_GAPS_FILE]["gaps"]
            for index, reason in enumerate(["version-unknown", "no-package-identifier", "ecosystem-not-covered", "version-unparseable"]):
                self.assertEqual(gaps[index]["reason"], reason)
            moved = gaps.pop(3)  # the unparseable version
            spec.documents[contracts.SCA_RESULT_FILE]["evaluated"].append(
                {"component_ref": moved["component_ref"], "outcome": "no-advisory-matched", "version_scheme": "go-module",
                 "evaluated_by": ["grype-db", "osv"]})
            summary = spec.documents[contracts.SCA_SUMMARY_FILE]
            summary.update(gap_count=3, evaluated_count=summary["evaluated_count"] + 1,
                           counts=[{"ecosystem": e, "reason": r, "count": c} for e, r, c in contracts.gap_summary_counts(gaps)])
            spec.documents[contracts.COVERAGE_FILE]["gaps"][0]["affected_input_count"] = 3
            spec.reseal()

        errors = mutated(self, SCA, hide_as_clean)
        self.assertEqual(names(errors), {"gap-hidden-as-evaluated"})
        self.assertIn("'version-unparseable'", errors[0])
        self.assertIn("never 'no-advisory-matched'", errors[0])

        def both(document):
            document["evaluated"].append({"component_ref": "SC-000005", "outcome": "no-advisory-matched",
                                          "version_scheme": "generic", "evaluated_by": ["grype-db"]})
        found = names(mutated(self, SCA, edit(contracts.SCA_RESULT_FILE, both)))
        self.assertLessEqual({"component-in-two-sets", "gap-hidden-as-evaluated"}, found)

    def test_5_supported_inferred_from_table_absence_is_rejected(self):
        def supported_without_row(document):  # lodash 4.17.20 has no row: only the status changes
            document["entries"][0]["status"] = "supported"

        def supported_with_an_invented_row(document):
            document["entries"][0].update(status="supported", assertion="reference-table-eol-match",
                                          table_row={"row_id": "lodash-4", "cycle": "4", "status": "supported", "eol_date": None})

        def supported_citing_another_components_row(document):
            document["entries"][0].update(status="supported", assertion="reference-table-eol-match",
                                          table_row=deepcopy(document["entries"][1]["table_row"]))
        for mutate in (supported_without_row, supported_with_an_invented_row, supported_citing_another_components_row):
            with self.subTest(mutate=mutate.__name__):
                errors = mutated(self, LIFECYCLE, edit(contracts.LIFECYCLE_RESULT_FILE, mutate))
                self.assertEqual(names(errors), {"status-without-table-row"})
                self.assertIn("absence from the table is never 'supported'", errors[0])

        def eol_relabelled_supported(document):  # log4j-core 2.14.1: the longest-cycle row says end-of-life
            document["entries"][2]["status"] = "supported"

        def eol_citing_the_shorter_supported_row(document):
            document["entries"][2].update(status="supported", table_row={"row_id": "log4j-core-2", "cycle": "2",
                                                                         "status": "supported", "eol_date": None})

        def eol_hidden_as_unknown(spec):
            spec.documents[contracts.LIFECYCLE_RESULT_FILE]["entries"][2].update(status="unknown", assertion="lifecycle-unknown",
                                                                                 table_row=None)
            spec.documents[contracts.COVERAGE_FILE]["gaps"][0]["affected_input_count"] += 1
        self.assertEqual(names(mutated(self, LIFECYCLE, edit(contracts.LIFECYCLE_RESULT_FILE, eol_relabelled_supported))),
                         {"status-table-row-mismatch"})
        self.assertEqual(names(mutated(self, LIFECYCLE, edit(contracts.LIFECYCLE_RESULT_FILE, eol_citing_the_shorter_supported_row))),
                         {"status-table-row-mismatch"})
        self.assertEqual(names(mutated(self, LIFECYCLE, eol_hidden_as_unknown)), {"status-table-row-mismatch", "coverage-gap-mismatch"})

    def test_6_an_inferred_vendored_component_promoted_to_declared_is_rejected(self):
        def declaration_only(document):
            document["components"][4]["declaration"] = "declared"

        def declaration_and_assertion(document):
            document["components"][4].update(declaration="declared", assertion="declared-component-present")

        def all_three_labels(document):
            document["components"][4].update(declaration="declared", assertion="declared-component-present")
            document["components"][4]["source"]["evidence_kind"] = "manifest"
        self.assertEqual(names(mutated(self, SBOM, edit(contracts.SBOM_MANIFEST_FILE, declaration_only))),
                         {"inferred-promoted-to-declared", "assertion-mismatch"})
        self.assertEqual(names(mutated(self, SBOM, edit(contracts.SBOM_MANIFEST_FILE, declaration_and_assertion))),
                         {"inferred-promoted-to-declared"})
        errors = mutated(self, SBOM, edit(contracts.SBOM_MANIFEST_FILE, all_three_labels))
        self.assertEqual(names(errors), {"inferred-promoted-to-declared", "evidence-kind-mismatch"})
        self.assertIn("'vendored-file-evidence'", " ".join(errors))

        def cite_a_manifest_of_another_ecosystem(document):  # zlib is `generic`; package.json declares npm only
            document["components"][4].update(declaration="declared", assertion="declared-component-present")
            document["components"][4]["source"] = {"evidence_kind": "manifest", "path": "web/package.json",
                                                   "sha256": sha(SOURCE_FILES["web/package.json"])}
        self.assertEqual(names(mutated(self, SBOM, edit(contracts.SBOM_MANIFEST_FILE, cite_a_manifest_of_another_ecosystem))),
                         {"inferred-promoted-to-declared", "evidence-kind-mismatch"})

        def demoted(document):  # and the reverse: a declared component cannot be hidden as an inventory gap
            document["components"][0].update(declaration="inferred-vendored", assertion="inventory-coverage-gap")
        self.assertEqual(names(mutated(self, SBOM, edit(contracts.SBOM_MANIFEST_FILE, demoted))), {"inferred-promoted-to-declared"})

        # licence inventory: `vendored-component-inferred` may never point at a declared component
        def vendored_points_at_declared(document):
            document["records"][4]["component_ref"] = "SC-000001"

        def vendored_declared_in_manifest(document):
            document["records"][4]["claim_source"]["kind"] = "declared-in-manifest"
        self.assertEqual(names(mutated(self, LICENSE, edit(contracts.LICENSE_RESULT_FILE, vendored_points_at_declared))),
                         {"inferred-promoted-to-declared"})
        self.assertEqual(names(mutated(self, LICENSE, edit(contracts.LICENSE_RESULT_FILE, vendored_declared_in_manifest))),
                         {"claim-source-mismatch"})


# ---- every trusted field, edited alone -------------------------------------------------------------------------

class FieldBindingTests(unittest.TestCase):
    def check(self, contract_id, cases):
        for relative, mutate, expected in cases:
            with self.subTest(contract=contract_id, case=mutate.__name__):
                self.assertEqual(names(mutated(self, contract_id, edit(relative, mutate, reseal=False))), set(expected))

    def test_each_sbom_field_edited_alone_is_rejected(self):
        manifest, cdx = contracts.SBOM_MANIFEST_FILE, contracts.SBOM_CDX_FILE
        schema = f"schema:{manifest}"

        def first(document):
            return document["components"][0]

        def run_id(d): d["run_id"] = "20260101T000000Z-aaaaaa"
        def job_id(d): d["job_id"] = "02-license-scan"
        def attempt_id(d): d["attempt_id"] = "another-attempt"
        def snapshot(d): d["source_snapshot_sha256"] = label_sha(CANARY)
        def redactor_version(d): d["redactor"]["module_version"] = "9.9.9"
        def redactor_ruleset(d): d["redactor"]["ruleset_sha256"] = sha_hex(b"other")
        def document_sha(d): d["sbom_document"]["sha256"] = label_sha(CANARY)
        def document_bytes(d): d["sbom_document"]["bytes"] += 1
        def spec_version(d): d["sbom_document"]["spec_version"] = "1.5"
        def component_id(d): first(d)["component_id"] = "SC-000009"
        def name(d): first(d)["name"] = "lodash-es"
        def version(d): first(d)["version"] = "4.17.21"
        def version_null(d): first(d)["version"] = None
        def purl(d): first(d)["purl"] = "pkg:npm/lodash@4.17.21"
        def purl_type(d): first(d)["purl"] = "pkg:pypi/lodash@4.17.20"
        def ecosystem(d): first(d)["ecosystem"] = "pypi"
        def evidence_kind(d): first(d)["source"]["evidence_kind"] = "manifest"
        def source_path(d): first(d)["source"]["path"] = "web/package.json"
        def source_sha(d): first(d)["source"]["sha256"] = label_sha(CANARY)
        def tool_id(d): first(d)["tool_id"] = "v05-canary-tool"
        def citation_attempt(d): first(d)["citation"]["attempt_id"] = "v05-canary-attempt"
        def citation_path(d): first(d)["citation"]["path"] = "syft-directory/outputs/other.json"
        def citation_sha(d): first(d)["citation"]["sha256"] = sha_hex(b"other")
        def citation_producer(d): first(d)["citation"]["producer"] = "02-license-scan"
        def duplicate(d): d["components"].append({**deepcopy(first(d)), "component_id": "SC-000008"})
        def cdx_component(d): d["components"][0]["version"] = "4.17.21"
        def cdx_extra(d): d["components"].append({"type": "library", "name": "v05-canary-extra", "version": "1.0.0"})
        def cdx_format(d): d["bomFormat"] = "SPDX"
        def cdx_spec(d): d["specVersion"] = "1.5"

        self.check(SBOM, [
            (manifest, run_id, ["header-mismatch"]), (manifest, job_id, [schema]), (manifest, attempt_id, ["header-mismatch"]),
            (manifest, snapshot, ["header-mismatch"]), (manifest, redactor_version, ["redactor-mismatch"]),
            (manifest, redactor_ruleset, ["redactor-mismatch"]), (manifest, document_sha, ["sbom-document-mismatch"]),
            (manifest, document_bytes, ["sbom-document-mismatch"]), (manifest, spec_version, ["sbom-document-invalid"]),
            (manifest, component_id, ["record-id-order"]), (manifest, name, ["purl-mismatch", "sbom-projection-mismatch"]),
            (manifest, version, ["purl-mismatch", "sbom-projection-mismatch"]),
            (manifest, version_null, ["purl-mismatch", "sbom-projection-mismatch", "assertion-mismatch"]),
            (manifest, purl, ["purl-mismatch", "sbom-projection-mismatch"]),
            (manifest, purl_type, ["purl-mismatch", "sbom-projection-mismatch"]),
            (manifest, ecosystem, ["purl-mismatch", "evidence-kind-mismatch", "inferred-promoted-to-declared"]),
            (manifest, evidence_kind, ["evidence-kind-mismatch"]), (manifest, source_path, ["evidence-kind-mismatch", "source-hash-mismatch"]),
            (manifest, source_sha, ["source-hash-mismatch"]), (manifest, tool_id, ["tool-unresolved"]),
            (manifest, citation_attempt, ["citation-attempt-mismatch"]), (manifest, citation_path, ["citation-unresolved"]),
            (manifest, citation_sha, ["citation-hash-mismatch"]), (manifest, citation_producer, ["citation-producer"]),
            (manifest, duplicate, ["duplicate-record", "sbom-projection-mismatch", "record-count-exceeds-tool"]),
            (cdx, cdx_component, ["sbom-document-mismatch", "sbom-projection-mismatch"]),
            (cdx, cdx_extra, ["sbom-document-mismatch", "sbom-projection-mismatch"]),
            (cdx, cdx_format, ["sbom-document-mismatch", "sbom-document-invalid"]),
            (cdx, cdx_spec, ["sbom-document-mismatch", "sbom-document-invalid"]),
        ])
        # an honest reseal of a changed CycloneDX document leaves only the projection rule to object
        self.assertEqual(names(mutated(self, SBOM, edit(cdx, cdx_extra))), {"sbom-projection-mismatch"})

    def test_each_sca_field_edited_alone_is_rejected(self):
        result, identities, gap_file, summary = (contracts.SCA_RESULT_FILE, contracts.SCA_IDENTITIES_FILE,
                                                 contracts.SCA_GAPS_FILE, contracts.SCA_SUMMARY_FILE)

        def binding_attempt(d): d["sbom_binding"]["attempt_id"] = "sbom-node-attempt-0002"
        def binding_sha(d): d["sbom_binding"]["sha256"] = label_sha(CANARY)
        def binding_job(d): d["sbom_binding"]["job_id"] = "02-license-scan"
        def binding_path(d): d["sbom_binding"]["path"] = "outputs/license-inventory.json"
        def digest(d): d["databases_digest"] = label_sha(CANARY)
        def run_id(d): d["run_id"] = "20260101T000000Z-aaaaaa"
        def evaluated_ref(d): d["evaluated"][1]["component_ref"] = "SC-000099"
        def evaluated_duplicate(d): d["evaluated"].append(deepcopy(d["evaluated"][1]))
        def outcome_clean(d): d["evaluated"][0]["outcome"] = "no-advisory-matched"
        def outcome_matched(d): d["evaluated"][1]["outcome"] = "advisory-matched"
        def scheme_evaluated(d): d["evaluated"][1]["version_scheme"] = "semver"
        def scheme_match(d): d["matches"][0]["version_scheme"] = "pep440"
        def evaluated_by(d): d["evaluated"][0]["evaluated_by"] = ["osv"]
        def evaluated_by_twice(d): d["evaluated"][1]["evaluated_by"] = ["osv", "osv"]
        def match_id(d): d["matches"][1]["match_id"] = "VM-000007"
        def match_component(d): d["matches"][0]["component_ref"] = "SC-000004"
        def advisory_id(d): d["matches"][0]["advisory_id"] = "GHSA-35jh-r3h4-6jhm"
        def advisory_outside(d): d["matches"][0]["advisory_id"] = "CVE-2020-8203"
        def aliases_unsorted(d): d["matches"][0]["aliases"].reverse()
        def citation_advisory(d): d["matches"][0]["citations"][0]["advisory_id"] = "CVE-2020-8203"
        def citation_twice(d): d["matches"][0]["citations"].append(deepcopy(d["matches"][0]["citations"][0]))
        def tool_id(d): d["matches"][0]["tool_id"] = "v05-canary-tool"
        def citation_sha(d): d["matches"][0]["citation"]["sha256"] = sha_hex(b"other")

        def split_by_source(d):
            """The defect alias collapsing exists to stop: the osv report of log4shell as a second match."""
            extra = deepcopy(d["matches"][1])
            extra.update(match_id="VM-000003", advisory_id="GHSA-jfh8-c2jp-5v3q", aliases=["GHSA-jfh8-c2jp-5v3q"],
                         citations=[extra["citations"][1]])
            d["matches"][1]["citations"].pop()
            d["matches"].append(extra)

        def identity_timestamp(d): d["databases"][0]["data_timestamp"] = "2026-09-19T01:31:42Z"
        def identity_block(d): d["databases"][1]["database"]["snapshot_id"] = "osv-20260101"
        def evaluated_at(d): d["databases"][0]["evaluated_at"] = "2026-09-20T12:11:00Z"
        def evaluated_in_future(d): d["databases"][0]["evaluated_at"] = "2026-09-21T00:00:00Z"
        def age_seconds(d): d["databases"][0]["age_seconds"] -= 1
        def max_age_seconds(d): d["databases"][0]["max_age_seconds"] = 999999999
        def age_policy(d): d["databases"][0]["age_policy"] = "within-limit"
        def impossible_stamp(d): d["databases"][0]["evaluated_at"] = "2026-13-45T25:61:61Z"

        def gap_id(d): d["gaps"][0]["gap_id"] = "VG-000009"
        def gap_ref(d): d["gaps"][0]["component_ref"] = "SC-000099"
        def gap_ref_evaluated(d): d["gaps"][0]["component_ref"] = "SC-000001"
        def gap_ecosystem(d): d["gaps"][0]["ecosystem"] = "pypi"
        def gap_reason(d): d["gaps"][0]["reason"] = "ecosystem-not-covered"
        def gap_matcher(d): d["gaps"][0]["reason"] = "matcher-did-not-complete"
        def gap_twice(d): d["gaps"][1]["component_ref"] = d["gaps"][0]["component_ref"]

        def component_count(d): d["component_count"] += 1
        def evaluated_count(d): d["evaluated_count"] -= 1
        def gap_count(d): d["gap_count"] += 1
        def counts_value(d): d["counts"][0]["count"] += 1
        def counts_reason(d): d["counts"][0]["reason"] = "matcher-did-not-complete"
        def counts_dropped(d): d["counts"].pop()
        def counts_order(d): d["counts"].reverse()
        def gap_list_sha(d): d["gap_list"]["sha256"] = label_sha(CANARY)

        stale = "gap-summary-mismatch"
        self.check(SCA, [
            (result, binding_attempt, ["upstream-binding-mismatch"]), (result, binding_sha, ["upstream-binding-mismatch"]),
            (result, binding_job, ["upstream-binding-mismatch"]), (result, binding_path, ["upstream-binding-mismatch"]),
            (gap_file, binding_sha, ["upstream-binding-mismatch", stale]), (summary, binding_sha, ["upstream-binding-mismatch"]),
            (result, digest, ["database-digest-mismatch"]), (identities, digest, ["database-digest-mismatch"]),
            (result, run_id, ["header-mismatch"]), (identities, run_id, ["header-mismatch"]), (summary, run_id, ["header-mismatch"]),
            (gap_file, run_id, ["header-mismatch", stale]),
            (result, evaluated_ref, ["component-unresolved", "component-unaccounted"]),
            (result, evaluated_duplicate, ["duplicate-record", stale]),
            (result, outcome_clean, ["outcome-mismatch"]), (result, outcome_matched, ["outcome-mismatch"]),
            (result, scheme_evaluated, ["version-scheme-mismatch"]), (result, scheme_match, ["version-scheme-mismatch"]),
            (result, evaluated_by, ["citation-database-not-evaluated"]), (result, evaluated_by_twice, ["duplicate-record"]),
            (result, match_id, ["record-id-order"]), (result, match_component, ["match-on-unevaluated-component", "outcome-mismatch"]),
            (result, advisory_id, ["alias-set-invalid"]), (result, advisory_outside, ["alias-set-invalid"]),
            (result, aliases_unsorted, ["alias-set-invalid"]), (result, citation_advisory, ["alias-set-invalid"]),
            (result, citation_twice, ["duplicate-record"]), (result, split_by_source, ["alias-not-collapsed", "record-count-exceeds-tool"]),
            (result, tool_id, ["tool-unresolved"]), (result, citation_sha, ["citation-hash-mismatch"]),
            (identities, identity_timestamp, ["database-identity-mismatch"]), (identities, identity_block, ["database-identity-mismatch"]),
            (identities, evaluated_at, ["age-invalid"]), (identities, evaluated_in_future, ["age-invalid"]),
            (identities, age_seconds, ["age-invalid"]), (identities, max_age_seconds, ["age-policy-mismatch"]),
            (identities, age_policy, ["age-policy-mismatch"]), (identities, impossible_stamp, ["age-invalid"]),
            (gap_file, gap_id, ["record-id-order", stale]), (gap_file, gap_ref, ["component-unresolved", "component-unaccounted", stale]),
            (gap_file, gap_ref_evaluated, ["gap-reason-mismatch", "component-in-two-sets", "component-unaccounted", stale]),
            (gap_file, gap_ecosystem, ["gap-ecosystem-mismatch", stale]), (gap_file, gap_reason, ["gap-reason-mismatch", stale]),
            (gap_file, gap_matcher, ["gap-reason-mismatch", stale]),
            (gap_file, gap_twice, ["duplicate-record", "gap-reason-mismatch", "gap-ecosystem-mismatch", "component-unaccounted", stale]),
            (summary, component_count, [stale]), (summary, evaluated_count, [stale]), (summary, gap_count, [stale]),
            (summary, counts_value, [stale]), (summary, counts_reason, [stale]), (summary, counts_dropped, [stale]),
            (summary, counts_order, [stale]), (summary, gap_list_sha, [stale]),
        ])

    def test_the_sca_aggregate_is_bound_to_the_databases_and_the_gap_count(self):
        tool_results, coverage = contracts.TOOL_RESULTS_FILE, contracts.COVERAGE_FILE

        def identities(d): return d["tool_instances"][0]["identity"]["data_identities"]
        def database_sha(d): identities(d)[0]["sha256"] = label_sha(CANARY)
        def database_version(d): identities(d)[1]["version"] = "0.0.1"
        def database_dropped(d): identities(d).pop()
        def database_kind(d): identities(d)[0]["kind"] = "rule-pack"
        def instance_redactor(d): d["tool_instances"][0]["identity"]["redactor"]["redactor_version"] = "9.9.9"
        def output_sha(d): d["tool_instances"][0]["outputs"][0]["sha256"] = label_sha(CANARY)
        def record_count(d): d["tool_instances"][0]["result_record_count"] = 1
        def gap_count(d): d["gaps"][0]["affected_input_count"] = 3
        def gap_dropped(d): d["gaps"].clear()
        def gap_twice(d): d["gaps"].append({**d["gaps"][0], "gap_id": "gap-grype-unmapped-2"})

        self.check(SCA, [
            (tool_results, database_sha, ["instance-database-mismatch"]), (tool_results, database_version, ["instance-database-mismatch"]),
            (tool_results, database_dropped, ["instance-database-mismatch"]), (tool_results, database_kind, ["instance-database-mismatch"]),
            (tool_results, instance_redactor, ["instance-redactor-mismatch"]),
            (tool_results, output_sha, ["aggregate:tool-outputs-on-disk", "citation-hash-mismatch"]),
            (tool_results, record_count, ["record-count-exceeds-tool"]), (coverage, gap_count, ["coverage-gap-mismatch"]),
            (coverage, gap_dropped, ["coverage-gap-mismatch", "aggregate:node-ok-with-gaps-without-gap"]),
            (coverage, gap_twice, ["coverage-gap-mismatch"]),
        ])
        # matcher-did-not-complete is honest only while a tool instance did not end OK
        world = World(self, "clean")

        def partial(spec):
            result, gaps = spec.documents[contracts.SCA_RESULT_FILE], spec.documents[contracts.SCA_GAPS_FILE]["gaps"]
            moved = result["evaluated"].pop(1)  # jinja2: evaluable, but the matcher stopped early
            gaps.append({"gap_id": "VG-000001", "assertion": "match-coverage-gap", "component_ref": moved["component_ref"],
                         "ecosystem": "pypi", "reason": "matcher-did-not-complete"})
            summary = spec.documents[contracts.SCA_SUMMARY_FILE]
            summary.update(evaluated_count=2, gap_count=1, counts=[{"ecosystem": "pypi", "reason": "matcher-did-not-complete", "count": 1}])
            instance = spec.documents[tool_results]["tool_instances"][0]
            instance.update(terminal_status="OK_WITH_GAPS", cause_code="partial-input-coverage")
            spec.documents[coverage]["gaps"] = [{"gap_id": "gap-grype-partial", "kind": "tool-instance-partial", "tool_id": "grype",
                                                 "affected_input_count": None}, *unmapped_gap("grype", 1)]
            spec.node_status = spec.status["status"] = "OK_WITH_GAPS"
            spec.reseal()
        world.publish(SCA, partial)
        self.assertEqual(world.run(SCA), [])

    def test_each_license_field_edited_alone_is_rejected(self):
        result = contracts.LICENSE_RESULT_FILE

        def binding_sha(d): d["sbom_binding"]["sha256"] = label_sha(CANARY)
        def record_id(d): d["records"][0]["record_id"] = "LI-000009"
        def component_ref(d): d["records"][1]["component_ref"] = "SC-000099"
        def expression_without_state(d): d["records"][1]["expression_state"] = "unknown"
        def state_without_expression(d): d["records"][2]["expression_state"] = "spdx-expression"
        def copyright_with_license(d): d["records"][5].update(license_expression="Zlib", expression_state="spdx-expression")
        def manifest_claim_in_other_file(d): d["records"][3]["claim_source"].update(path="LICENSE", sha256=sha(SOURCE_FILES["LICENSE"]), start_line=1, end_line=1)
        def manifest_claim_without_component(d): d["records"][3]["component_ref"] = None
        def manifest_claim_on_inferred(d): d["records"][3]["component_ref"] = "SC-000005"
        def source_sha(d): d["records"][0]["claim_source"]["sha256"] = label_sha(CANARY)
        def source_path(d): d["records"][0]["claim_source"]["path"] = "third_party/zlib/LICENSE"
        def line_beyond_file(d): d["records"][0]["claim_source"]["end_line"] = 400
        def line_order(d): d["records"][0]["claim_source"].update(start_line=2, end_line=1)
        def line_zero(d): d["records"][0]["claim_source"].update(start_line=0, end_line=1)
        def line_half(d): d["records"][0]["claim_source"]["end_line"] = None
        def duplicate(d): d["records"].append({**deepcopy(d["records"][0]), "record_id": "LI-000007"})
        def citation_attempt(d): d["records"][0]["citation"]["attempt_id"] = "v05-canary-attempt"
        def legal_value(d): d["records"][0]["expression_state"] = "incompatible"
        def free_text(d): d["records"][0]["license_expression"] = "MIT; see NOTICE for " + CANARY

        schema = f"schema:{result}"
        self.check(LICENSE, [
            (result, binding_sha, ["upstream-binding-mismatch"]), (result, record_id, ["record-id-order"]),
            (result, component_ref, ["component-unresolved"]), (result, expression_without_state, ["expression-state-mismatch"]),
            (result, state_without_expression, ["expression-state-mismatch"]), (result, copyright_with_license, ["expression-state-mismatch"]),
            (result, manifest_claim_in_other_file, ["claim-source-mismatch"]), (result, manifest_claim_without_component, ["claim-source-mismatch"]),
            (result, manifest_claim_on_inferred, ["claim-source-mismatch"]), (result, source_sha, ["source-hash-mismatch"]),
            (result, source_path, ["source-hash-mismatch"]), (result, line_beyond_file, ["source-line-range"]),
            (result, line_order, ["claim-source-lines"]), (result, line_zero, ["claim-source-lines"]), (result, line_half, ["claim-source-lines"]),
            (result, duplicate, ["duplicate-record", "record-count-exceeds-tool"]), (result, citation_attempt, ["citation-attempt-mismatch"]),
            (result, legal_value, [schema]), (result, free_text, [schema]),
        ])

    def test_each_lifecycle_field_edited_alone_is_rejected(self):
        result, identity, tool_results, coverage = (contracts.LIFECYCLE_RESULT_FILE, contracts.TABLE_IDENTITY_FILE,
                                                    contracts.TOOL_RESULTS_FILE, contracts.COVERAGE_FILE)

        def sbom_sha(d): d["sbom_binding"]["sha256"] = label_sha(CANARY)
        def license_sha(d): d["license_binding"]["sha256"] = label_sha(CANARY)
        def license_attempt(d): d["license_binding"]["attempt_id"] = "license-node-attempt-0002"
        def license_job(d): d["license_binding"]["job_id"] = "02-sbom-inventory"
        def entry_ref(d): d["entries"][0]["component_ref"] = "SC-000002"
        def entry_dropped(d): d["entries"].pop()
        def entry_id(d): d["entries"][0]["entry_id"] = "DL-000009"
        def assertion(d): d["entries"][0]["assertion"] = "reference-table-eol-match"
        def row_status(d): d["entries"][1]["table_row"]["status"] = "end-of-life"
        def row_cycle(d): d["entries"][1]["table_row"]["cycle"] = "3"
        def row_eol(d): d["entries"][2]["table_row"]["eol_date"] = "2031-01-01"
        def row_id(d): d["entries"][1]["table_row"]["row_id"] = "jinja2-3.0"
        def resurfaced_expression(d): d["entries"][0]["resurfaced_licenses"][0]["license_expression"] = "GPL-3.0-only"
        def resurfaced_ref(d): d["entries"][0]["resurfaced_licenses"][0]["record_ref"] = "LI-000001"
        def resurfaced_dropped(d): d["entries"][0]["resurfaced_licenses"].clear()
        def resurfaced_invented(d): d["entries"][2]["resurfaced_licenses"].append(
            {"assertion": "license-field-resurfaced", "record_ref": "LI-000002", "license_expression": "MIT"})
        def table_field(field, value):
            def mutate(d):
                (d["reference_table"] if "reference_table" in d else d)[field] = value
            mutate.__name__ = f"table_{field}"
            return mutate
        def row_count(d): d["row_count"] += 1
        def age_seconds(d): d["age_seconds"] += 1
        def max_age_seconds(d): d["max_age_seconds"] = 86400
        def table_identity_sha(d): d["tool_instances"][0]["identity"]["data_identities"][0]["sha256"] = label_sha(CANARY)
        def table_identity_dropped(d): d["tool_instances"][0]["identity"]["data_identities"].clear()
        def unknown_count(d): d["gaps"][0]["affected_input_count"] -= 1

        mismatch = "reference-table-identity-mismatch"
        cases = [
            (result, sbom_sha, ["upstream-binding-mismatch"]), (result, license_sha, ["upstream-binding-mismatch"]),
            (result, license_attempt, ["upstream-binding-mismatch"]), (result, license_job, ["upstream-binding-mismatch"]),
            (result, entry_ref, ["component-unaccounted"]), (result, entry_dropped, ["component-unaccounted"]),
            (result, entry_id, ["record-id-order"]), (result, assertion, ["status-without-table-row"]),
            (result, row_status, ["status-table-row-mismatch"]), (result, row_cycle, ["status-table-row-mismatch"]),
            (result, row_eol, ["status-table-row-mismatch"]), (result, row_id, ["status-table-row-mismatch"]),
            (result, resurfaced_expression, ["resurfaced-license-mismatch"]), (result, resurfaced_ref, ["resurfaced-license-mismatch"]),
            (result, resurfaced_dropped, ["resurfaced-license-mismatch"]), (result, resurfaced_invented, ["resurfaced-license-mismatch"]),
            (identity, row_count, [mismatch]), (identity, age_seconds, ["age-invalid"]), (identity, max_age_seconds, ["age-policy-mismatch"]),
            (tool_results, table_identity_sha, ["instance-reference-table-mismatch"]),
            (tool_results, table_identity_dropped, ["instance-reference-table-mismatch"]), (coverage, unknown_count, ["coverage-gap-mismatch"]),
        ]
        for field, value in (("table_id", "another-table"), ("version", "2020.01.01"), ("sha256", label_sha(CANARY)), ("as_of", "2026-08-01")):
            cases += [(result, table_field(field, value), [mismatch]), (identity, table_field(field, value), [mismatch])]
        self.check(LIFECYCLE, cases)

    def test_the_reference_table_is_bound_to_its_bytes_and_to_the_callers_identity(self):
        world = World(self)
        world.publish(LIFECYCLE)
        self.assertEqual(world.run(LIFECYCLE), [])
        good = world.table_path.read_bytes()
        for field, value in (("table_id", "another-table"), ("version", "2020.01.01"), ("sha256", label_sha("x")), ("as_of", "2026-08-01")):
            expected = {**world.table_identity, field: value}
            with self.subTest(expected=field):
                found = names(world.run(LIFECYCLE, expected_reference_table=expected))
                self.assertIn("reference-table-hash-mismatch" if field == "sha256" else "reference-table-identity-mismatch", found)
        # a row edited in the table: the bytes no longer hash to what the caller expects, and are NOT parsed
        edited = deepcopy(TABLE)
        edited["rows"].append({"row_id": "lodash-4", "ecosystem": "npm", "name": "lodash", "cycle": "4", "status": "supported", "eol_date": None})
        world.table_path.write_bytes(dump(edited))
        with mock.patch.object(contracts, "_parse", wraps=contracts._parse) as parse:
            self.assertEqual(names(world.run(LIFECYCLE)), {"reference-table-hash-mismatch"})
            self.assertNotIn(dump(edited), [call.args[0] for call in parse.call_args_list])
        # even when the caller is told the new hash, the published entries no longer follow from the table
        identity = {**world.table_identity, "sha256": sha(dump(edited))}
        found = names(world.run(LIFECYCLE, expected_reference_table=identity))
        self.assertLessEqual({"reference-table-identity-mismatch", "status-table-row-mismatch"}, found)
        for broken in ({**TABLE, "rows": [*TABLE["rows"], deepcopy(TABLE["rows"][0])]},
                       {**TABLE, "rows": [{**TABLE["rows"][0], "status": "end-of-life"}]},
                       {**TABLE, "rows": [{**TABLE["rows"][0], "eol_date": "2020-01-01"}]},
                       {**TABLE, "rows": [{**TABLE["rows"][3], "eol_date": "2026-13-45"}]}, {**TABLE, "note": CANARY}):
            world.table_path.write_bytes(dump(broken))
            found = names(world.run(LIFECYCLE, expected_reference_table={**world.table_identity, "sha256": sha(dump(broken))}))
            self.assertTrue(found & {"reference-table-invalid", "schema:reference-table"}, found)
        world.table_path.unlink()
        self.assertEqual(names(world.run(LIFECYCLE)), {"reference-table-missing"})
        world.table_path.write_bytes(good)
        self.assertEqual(world.run(LIFECYCLE), [])

    def test_upstream_documents_are_bound_to_bytes_run_snapshot_and_each_other(self):
        world = World(self)
        for contract_id in VERIFIERS:
            world.publish(contract_id)
        sbom_file = world.published[SBOM].root / contracts.SBOM_MANIFEST_FILE
        original = sbom_file.read_bytes()
        document = json.loads(original)
        document["components"][0]["version"] = "4.17.21"  # the SBOM edited after the downstream attempts were computed
        sbom_file.write_bytes(dump(document))
        for contract_id in (SCA, LICENSE, LIFECYCLE):
            with mock.patch.object(contracts, "_parse", wraps=contracts._parse) as parse:
                self.assertEqual(names(world.run(contract_id)), {"upstream-hash-mismatch"}, contract_id)
                self.assertNotIn(dump(document), [call.args[0] for call in parse.call_args_list])
            # a caller who re-reads the hash from the edited bytes is told the documents are bound to another SBOM
            self.assertIn("upstream-binding-mismatch", names(world.run(
                contract_id, expected_sbom={"attempt_id": header_for(SBOM)["attempt_id"], "sha256": sha(dump(document))})))
        sbom_file.write_bytes(original)
        # an SBOM of another run or another source snapshot
        for field, value in (("run_id", "20260101T000000Z-aaaaaa"), ("source_snapshot_sha256", label_sha("other"))):
            foreign = {**json.loads(original), field: value}
            sbom_file.write_bytes(dump(foreign))
            expected = {"attempt_id": header_for(SBOM)["attempt_id"], "sha256": sha(dump(foreign))}
            self.assertLessEqual({"upstream-mismatch"}, names(world.run(SCA, expected_sbom=expected)))
        sbom_file.write_bytes(original)
        # the licence inventory the lifecycle consumed must itself be bound to the SAME SBOM
        other = World(self)

        def another_sbom(spec):
            spec.documents[contracts.LICENSE_RESULT_FILE]["sbom_binding"]["sha256"] = label_sha("another sbom")
        other.publish(LICENSE, another_sbom)
        other.publish(LIFECYCLE)
        self.assertEqual(names(other.run(LIFECYCLE)), {"upstream-sbom-mismatch"})


# ---- ADR-0010 M4 ------------------------------------------------------------------------------------------------

class AgePolicyTests(unittest.TestCase):
    def test_no_limit_is_explicit_and_a_job_limit_exceeded_is_failed(self):
        for contract_id, too_old in ((SCA, "database-too-old"), (LIFECYCLE, "reference-table-too-old")):
            world = World(self, "clean", timedelta(days=30))
            world.publish(contract_id)
            self.assertEqual(world.run(contract_id), [])
            # the caller demands a tighter limit than the one the attempt recorded
            errors = world.run(contract_id, max_age=timedelta(hours=1))
            self.assertEqual(names(errors), {"age-policy-mismatch", too_old})
            self.assertTrue(all("FAILED, never OK_WITH_GAPS" in error for error in errors if error.startswith(too_old)))
            # the caller says no limit but the attempt recorded one (and the reverse)
            self.assertEqual(names(world.run(contract_id, max_age=contracts.NO_AGE_LIMIT)), {"age-policy-mismatch"})
            # age is re-derived at the caller's clock: the same attempt, verified 60 days later
            self.assertEqual(names(world.run(contract_id, now=NOW + timedelta(days=60))), {too_old})
            # the clock may not run backwards past the attempt's own evaluation
            self.assertEqual(names(world.run(contract_id, now=NOW - timedelta(days=1))), {"age-invalid"})
            unlimited = World(self, "clean")
            unlimited.publish(contract_id)
            self.assertEqual(unlimited.run(contract_id, now=NOW + timedelta(days=3650)), [])
            self.assertEqual(names(unlimited.run(contract_id, max_age=timedelta(days=30))), {"age-policy-mismatch"})

    def test_a_document_cannot_record_an_age_over_its_own_limit(self):
        def over(spec):
            for entry in spec.documents[contracts.SCA_IDENTITIES_FILE]["databases"]:
                entry.update(max_age_seconds=3600, age_policy="within-limit")
        world = World(self, "clean")
        world.publish(SCA, over)
        self.assertEqual(names(world.run(SCA, max_age=timedelta(hours=1))), {"database-too-old"})


# ---- the attempt on disk -------------------------------------------------------------------------------------------

class OnDiskTests(unittest.TestCase):
    def full_world(self) -> World:
        world = World(self)
        for contract_id in VERIFIERS:
            world.publish(contract_id)
        return world

    def test_each_required_file_missing_alone_is_rejected(self):
        world = self.full_world()
        for contract_id, policy in contracts.CONTRACT_POLICIES.items():
            for relative in policy["required_files"]:
                path = world.published[contract_id].root / relative
                data = path.read_bytes()
                path.unlink()
                with self.subTest(contract=contract_id, missing=relative):
                    expected = "receipt-missing" if relative == contracts.RECEIPT_FILE else "required-file-missing"
                    self.assertEqual(names(world.run(contract_id)), {expected})
                path.write_bytes(data)
            self.assertEqual(world.run(contract_id), [])

    def test_order_the_receipt_is_verified_before_any_published_document_is_parsed(self):
        world = self.full_world()
        for contract_id in VERIFIERS:
            root = world.published[contract_id].root
            target = root / RESULT_FILES[contract_id]
            original = target.read_bytes()
            target.write_bytes(b'{"planted": "' + SECRETS["GITHUB_TOKEN"].encode() + b'", "also": "' + CANARY.encode() + b'"}')
            with mock.patch.object(contracts, "_parse", wraps=contracts._parse) as parse:
                errors = world.run(contract_id)
            with self.subTest(contract=contract_id):
                self.assertTrue(errors)
                self.assertEqual(names(errors), {"receipt-invalid"})  # nothing but the receipt's own errors
                self.assertEqual([call.args[0] for call in parse.call_args_list], [(root / contracts.RECEIPT_FILE).read_bytes()])
            target.write_bytes(original)

    def test_invariant_every_file_tampered_in_every_top_level_position_is_rejected_and_nothing_is_echoed(self):
        world = self.full_world()
        checked = 0
        for contract_id, policy in contracts.CONTRACT_POLICIES.items():
            self.assertEqual(world.run(contract_id), [])
            for relative in policy["required_files"]:
                path = world.published[contract_id].root / relative
                original = path.read_bytes()
                document = json.loads(original)
                variants = [("added", {**document, "v05_added": CANARY})]
                for key in document:
                    variants.append((f"replaced:{key}", {**document, key: CANARY}))
                    variants.append((f"removed:{key}", {name: value for name, value in document.items() if name != key}))
                # The one permitted edit: a known runtime identifier is optional in status.json (bound when present).
                optional = {f"removed:{field}" for field in contracts.STATUS_OPTIONAL_FIELDS} if relative == "status.json" else set()
                for label, tampered in variants:
                    path.write_bytes(dump(tampered))
                    with self.subTest(contract=contract_id, file=relative, tamper=label):
                        errors = world.run(contract_id)  # run() asserts no echo
                        self.assertEqual(errors == [], label in optional, "a tampered attempt verified")
                    checked += 1
                path.write_bytes(original)
            self.assertEqual(world.run(contract_id), [])
        self.assertGreater(checked, 300)

    def test_status_json_is_exactly_the_registered_fields_plus_bound_runtime_identifiers(self):
        world = self.full_world()
        for contract_id in VERIFIERS:
            path = world.published[contract_id].root / "status.json"
            good = json.loads(path.read_bytes())
            cases = [({key: value for key, value in good.items() if key not in ("job_id", "dagster_run_id")}, set()),
                     ({**good, "reviewer": CANARY}, {"status-invalid"}), ({**good, "dagster_run_id": "dagster-" + CANARY}, {"status-mismatch"}),
                     ({**good, "job_id": "02-secrets-inventory"}, {"status-mismatch"}), ({**good, "status": "OK" if good["status"] != "OK" else "FAILED"}, {"status-mismatch"}),
                     ({**good, "run_id": CANARY}, {"status-mismatch"}), ({**good, "attempt_id": ["x"]}, {"status-mismatch"}),
                     ({key: value for key, value in good.items() if key != "attempt_id"}, {"status-invalid"}), ([good], {"status-invalid"})]
            for document, expected in cases:
                path.write_bytes(dump(document))
                with self.subTest(contract=contract_id, expected=sorted(expected)):
                    self.assertEqual(names(world.run(contract_id)), expected)
            path.write_bytes(b'{"status": "OK", "status": "OK"}')
            self.assertEqual(names(world.run(contract_id)), {"status-invalid"})
            path.write_bytes(dump(good))

    def test_manifest_json_binds_exactly_what_was_published(self):
        world = self.full_world()
        for contract_id in VERIFIERS:
            root = world.published[contract_id].root
            path = root / "manifest.json"
            good = json.loads(path.read_bytes())
            first = good["outputs"][0]
            cases = [({**good, "schema": "appsec-review/attempt-manifest/2"}, "manifest-invalid"),
                     ({**good, "contract_id": "secrets-inventory"}, "manifest-invalid"), ({**good, "generated_by": CANARY}, "manifest-invalid"),
                     ({**good, "outputs": good["outputs"][1:]}, "manifest-mismatch"),
                     ({**good, "outputs": [{**first, "sha256": label_sha(CANARY)}, *good["outputs"][1:]]}, "manifest-mismatch"),
                     ({**good, "outputs": list(reversed(good["outputs"]))}, "manifest-invalid"),
                     ({**good, "outputs": [{**first, "path": "outputs/./" + first["path"].split("/", 1)[1]}, *good["outputs"][1:]]}, "manifest-invalid"),
                     ({**good, "outputs": [{**first, "bytes": 1}, *good["outputs"][1:]]}, "manifest-invalid")]
            for document, expected in cases:
                path.write_bytes(dump(document))
                with self.subTest(contract=contract_id, expected=expected):
                    self.assertIn(expected, names(world.run(contract_id)))
            path.write_bytes(dump(good))
            # a file the worker published but no contract names: the receipt no longer describes outputs/
            (root / "outputs" / "unlisted.json").write_bytes(b"{}\n")
            self.assertEqual(names(world.run(contract_id)), {"receipt-invalid"})
            (root / "outputs" / "unlisted.json").unlink()
            self.assertEqual(world.run(contract_id), [])

    def test_duplicate_keys_non_json_and_oversized_files_are_rejected(self):
        world = World(self, "clean")
        world.publish(SBOM)
        path = world.published[SBOM].root / contracts.SBOM_MANIFEST_FILE
        for data in (b"not json", b'{"a": NaN}', b"\xff\xfe"):
            original = path.read_bytes()
            path.write_bytes(data)
            self.assertEqual(names(world.run(SBOM)), {"receipt-invalid"})
            path.write_bytes(original)
        for data in (b'{"a": 1, "a": 2}', b'{"a": NaN}', b'{"a": Infinity}', b"\xff\xfe", b"[1,]"):
            with self.assertRaises(ValueError):
                contracts._parse(data)
        tiny = redaction.Limits(**{**redaction.asdict(LIMITS), "max_file_bytes": 64})
        self.assertEqual(names(world.run(SBOM, limits=tiny)), {"required-file-missing", "receipt-missing"})

        def duplicate_key(spec):  # published honestly through the redactor, so only this module's parser can object
            data = dump(spec.documents[contracts.SBOM_MANIFEST_FILE])
            spec.raw_files[contracts.SBOM_MANIFEST_FILE] = data.replace(b'{\n', b'{\n  "generated_at": "2026-09-20T12:01:00Z",\n', 1)
        other = World(self, "clean")
        try:
            other.publish(SBOM, duplicate_key)
        except redaction.RedactionError:
            return  # the redactor itself refuses a duplicate key: equally closed
        self.assertTrue(other.run(SBOM))

    def test_a_tool_output_changed_or_missing_is_rejected(self):
        world = World(self, "clean")
        world.publish(SCA)
        target = world.published[SCA].tool_root / "grype" / "outputs" / "result.json"
        original = target.read_bytes()
        target.write_bytes(original + b" ")
        self.assertEqual(names(world.run(SCA)), {"aggregate:tool-outputs-on-disk"})
        target.unlink()
        self.assertEqual(names(world.run(SCA)), {"aggregate:tool-outputs-on-disk"})
        target.write_bytes(original)
        self.assertEqual(names(world.run(SCA, tool_outputs_root=world.base / "elsewhere")), {"aggregate:tool-outputs-on-disk"})

    def test_paths_have_one_spelling_and_identity_is_the_file_not_the_string(self):
        for spelling in ("web/./package-lock.json", "web//package-lock.json", "web/x/../package-lock.json", "../source/web/package-lock.json"):
            def mutate(document, spelling=spelling):
                document["components"][0]["source"]["path"] = spelling
            with self.subTest(spelling=spelling):
                found = names(mutated(self, SBOM, edit(contracts.SBOM_MANIFEST_FILE, mutate)))
                self.assertEqual(found, {"source-path"})
        def leading_slash(document):
            document["components"][0]["source"]["path"] = "/web/package-lock.json"
        self.assertEqual(names(mutated(self, SBOM, edit(contracts.SBOM_MANIFEST_FILE, leading_slash))), {f"schema:{contracts.SBOM_MANIFEST_FILE}"})

        def missing(document):
            document["components"][0]["source"]["path"] = "web/absent/package-lock.json"
        self.assertEqual(names(mutated(self, SBOM, edit(contracts.SBOM_MANIFEST_FILE, missing))), {"source-file-missing"})

    @unittest.skipUnless(CAN_HARDLINK, "this host cannot create hard links (never skipped on POSIX)")
    def test_one_file_under_two_names_is_an_alias(self):
        def link(source):
            (source / "web" / "alias").mkdir()
            os.link(source / "web" / "package-lock.json", source / "web" / "alias" / "package-lock.json")

        def cite_both(document):
            extra = deepcopy(document["components"][0])
            extra.update(component_id="SC-000008", name="lodash.merge", purl="pkg:npm/lodash.merge@4.17.20")
            extra["source"]["path"] = "web/alias/package-lock.json"
            document["components"].append(extra)

        def cdx_too(spec):
            cite_both(spec.documents[contracts.SBOM_MANIFEST_FILE])
            spec.documents[contracts.SBOM_CDX_FILE]["components"].append(
                {"type": "library", "bom-ref": "SC-000008", "name": "lodash.merge", "version": "4.17.20", "purl": "pkg:npm/lodash.merge@4.17.20"})
            spec.documents[contracts.TOOL_RESULTS_FILE]["tool_instances"][0]["result_record_count"] = 8
            spec.reseal()
        world = World(self, source_edit=link)
        world.publish(SBOM, cdx_too)
        self.assertEqual(names(world.run(SBOM)), {"source-alias"})

    @unittest.skipUnless(CAN_SYMLINK, "this host cannot create symlinks (never skipped on POSIX)")
    def test_linked_files_are_never_followed(self):
        def link(source):
            (source / "web" / "package-lock.json").unlink()
            os.symlink(source / "web" / "package.json", source / "web" / "package-lock.json")
        world = World(self, source_edit=link)
        world.publish(SBOM)
        self.assertIn("source-file-missing", names(world.run(SBOM)))
        world = World(self, "clean")
        world.publish(SCA)
        for relative in ("status.json", contracts.SCA_RESULT_FILE):
            path = world.published[SCA].root / relative
            data = path.read_bytes()
            path.unlink()
            (world.base / "elsewhere.json").write_bytes(data)
            os.symlink(world.base / "elsewhere.json", path)
            self.assertEqual(names(world.run(SCA)), {"required-file-missing"}, relative)
            path.unlink()
            path.write_bytes(data)
        self.assertEqual(world.run(SCA), [])
        upstream = world.published[SBOM].root / contracts.SBOM_MANIFEST_FILE
        data = upstream.read_bytes()
        upstream.unlink()
        (world.base / "sbom-copy.json").write_bytes(data)
        os.symlink(world.base / "sbom-copy.json", upstream)
        self.assertEqual(names(world.run(SCA)), {"upstream-missing"})

    def test_verification_is_read_only_returns_a_fresh_list_and_keeps_no_state(self):
        world = self.full_world()

        def snapshot():
            return {path.relative_to(world.base).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
                    for path in sorted(world.base.rglob("*")) if path.is_file()}

        before = snapshot()
        for contract_id in VERIFIERS:
            first, second = world.run(contract_id), world.run(contract_id)
            self.assertEqual(first, [])
            self.assertIsNot(first, second)
            first.append("caller-edit: not an error")
            self.assertEqual(world.run(contract_id), [])
        self.assertEqual(snapshot(), before)
        # the decision is re-derived from bytes every time: a change after a clean verification is seen
        path = world.published[SCA].root / contracts.SCA_SUMMARY_FILE
        path.write_bytes(path.read_bytes().replace(b'"gap_count": 4', b'"gap_count": 0'))
        self.assertTrue(world.run(SCA))
        for name in dir(contracts):  # no module-level cache a second call could read
            value = getattr(contracts, name)
            if not name.startswith("__") and isinstance(value, (dict, list, set)):
                self.fail(f"mutable module state: {name}")


# ---- cross-slice ---------------------------------------------------------------------------------------------------

class CrossSliceTests(unittest.TestCase):
    def v04_shaped_document(self) -> dict:
        """The shape of V04's `secrets-inventory.redacted.json` (not importable on this base branch)."""
        return {"schema": "appsec-review/secrets-inventory/1.0", **header_for(SBOM), "redactor": dict(REDACTOR),
                "entries": [{"entry_id": "SI-000001", "assertion": "candidate-secret-location", "tool_id": "gitleaks",
                             "rule_id": CANARY, "data_class": "api-key", "confidence": "high",
                             "location": {"path": "src/" + CANARY + ".py", "path_disposition": "published", "start_line": 1, "end_line": 1},
                             "citation": citation("02-secrets-inventory", "gitleaks")}]}

    def test_documents_of_other_slices_are_rejected_without_echo(self):
        for contract_id in VERIFIERS:
            def v04(spec):
                spec.documents[RESULT_FILES[spec.contract_id]] = self.v04_shaped_document()

            def v03(spec):
                spec.documents[RESULT_FILES[spec.contract_id]] = deepcopy(spec.documents[contracts.TOOL_RESULTS_FILE])

            def v09(spec):
                spec.documents[RESULT_FILES[spec.contract_id]] = {
                    "schema": sca_nvd_snapshot.IDENTITY_SCHEMA, "database_kind": "nvd", "match_basis": "cpe", "snapshot_id": CANARY}
            for mutate in (v04, v03, v09):
                with self.subTest(contract=contract_id, document=mutate.__name__):
                    world = World(self, "clean")
                    world.publish(contract_id, mutate)
                    found = names(world.run(contract_id))  # run() asserts the canary is not echoed
                    self.assertTrue(found)
                    # V04's `path_disposition` and V03's `findings_exit_codes` are rejected by name first
                    self.assertLessEqual(found, {f"schema:{RESULT_FILES[contract_id]}", "forbidden-claim"})

    def test_the_v09_nvd_identity_is_not_a_database_this_contract_accepts(self):
        def nvd_only(document):
            document["databases"][0]["database"]["database_kind"] = "nvd"
        self.assertEqual(names(mutated(self, SCA, edit(contracts.SCA_IDENTITIES_FILE, nvd_only))), {f"schema:{contracts.SCA_IDENTITIES_FILE}"})

    def test_a_secret_in_any_published_file_never_verifies_and_is_never_echoed(self):
        world = World(self, "clean")
        world.publish(SCA)
        root = world.published[SCA].root
        for relative in (contracts.SCA_RESULT_FILE, contracts.COVERAGE_FILE, contracts.SCA_SUMMARY_FILE):
            path = root / relative
            original = path.read_bytes()
            for label, value in SECRETS.items():
                document = json.loads(original)
                document["run_id"] = value
                path.write_bytes(dump(document))
                (root / "manifest.json").write_bytes(dump(manifest_document(SCA, root)))  # a worker that re-sealed the manifest
                with self.subTest(file=relative, planted=label):
                    self.assertEqual(names(world.run(SCA)), {"receipt-invalid"})
            path.write_bytes(original)
        (root / "manifest.json").write_bytes(dump(manifest_document(SCA, root)))
        self.assertEqual(world.run(SCA), [])

    def test_the_redactor_publishes_a_planted_secret_redacted_and_the_contract_then_rejects_the_document(self):
        def plant(document):
            document["matches"][0]["advisory_id"] = SECRETS["AWS_KEY"]
        world = World(self, "clean")
        item = world.publish(SCA, edit(contracts.SCA_RESULT_FILE, plant))
        self.assertNotIn(SECRETS["AWS_KEY"].encode(), (item.root / contracts.SCA_RESULT_FILE).read_bytes())
        self.assertEqual(names(world.run(SCA)), {f"schema:{contracts.SCA_RESULT_FILE}"})

    def test_v06_state_and_shim(self):
        self.assertEqual(V06_FLAGS_V03_HEADER_KEY, redaction.MODULE_VERSION == "1.0.0",
                         "the shim must be off for any redactor that no longer flags the V03 header key")
        self.assertTrue(redaction._exempt(V03_HEADER_KEY))
        if V06_FLAGS_V03_HEADER_KEY:
            self.assertFalse(redaction._exempt(V03_HEADER_KEY + "x") and not _PATCHES)
        for label, value in SECRETS.items():  # every synthetic secret is detected whatever the shim state
            self.assertTrue(redaction._merged_spans(value), label)
        self.assertEqual(redaction._merged_spans(RUN_ID), [])

    def test_this_work_contains_no_scannable_secret_literal(self):
        scanners = [re.compile("AK" + r"IA[0-9A-Z]{16}"), re.compile("gh" + r"p_[A-Za-z0-9]{36}"),
                    re.compile("-----BEGIN " + r"(RSA |EC |OPENSSH )?PRIVATE KEY-----"),
                    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.")]
        paths = [ROOT / "sbom_family_contracts.py", Path(__file__), *[REPO / "schemas" / name for name in ALL_SCHEMAS],
                 *[CONTRACT_DIR / f"{contract_id}.json" for contract_id in contracts.CONTRACT_POLICIES]]
        doc = REPO / "docs" / "sbom-family-contracts.md"
        for path in [*paths, *([doc] if doc.is_file() else [])]:
            text = path.read_text(encoding="utf-8")
            for scanner in scanners:
                with self.subTest(path=path.name, scanner=scanner.pattern[:8]):
                    self.assertIsNone(scanner.search(text))
        for label in ("AWS_KEY", "GITHUB_TOKEN", "PEM_HEADER"):  # and the synthetic values really are scanner-shaped
            self.assertTrue(any(scanner.search(SECRETS[label]) for scanner in scanners), label)

    def test_the_module_stays_off_the_shared_surfaces_and_the_network(self):
        source = (ROOT / "sbom_family_contracts.py").read_text(encoding="utf-8")
        imported = set(re.findall(r"^(?:from|import) ([A-Za-z_][A-Za-z0-9_]*)", source, flags=re.MULTILINE))
        self.assertLessEqual(imported, {"__future__", "datetime", "hashlib", "json", "os", "pathlib", "re", "sys", "types", "typing",
                                        "urllib", "evidence_redaction", "execution_state", "sca_nvd_snapshot", "schema_validate",
                                        "tool_instance_shapes"})
        for forbidden in ("subprocess", "socket", "urlopen", "requests", "os.system", ".write_bytes", ".write_text", ".unlink",
                          ".mkdir", "shell=", "import validate_job_output", "import publish_job_output", "import worker_result"):
            self.assertNotIn(forbidden, source, forbidden)
        self.assertEqual(source.count(".open("), 1)  # the one bounded binary read


class CoordinatorProbeRegressionTests(unittest.TestCase):
    """Holes the coordinator's resealed-mutation probes found after the slice was green. Each mutation
    is a well-formed, correctly sealed attempt from a dishonest producer, so only the semantic layer
    can refuse it. The suite missed them because it treated sbom.cdx.json as bytes to bind, not as a
    published claim surface, and tested license_expression only for its state, never its content."""

    def test_the_cyclonedx_file_cannot_carry_vex_or_any_section_outside_the_inventory(self):
        def vex(cdx):
            cdx["vulnerabilities"] = [{"id": "CVE-2021-44228", "analysis": {"state": "not_affected"}}]
        self.assertEqual(names(mutated(self, SBOM, edit(contracts.SBOM_CDX_FILE, vex))), {"sbom-document-surface"})

        def rated_vex(cdx):
            cdx["vulnerabilities"] = [{"id": "CVE-2021-44228", "ratings": [{"severity": "low"}], "affects": []}]
        self.assertEqual(names(mutated(self, SBOM, edit(contracts.SBOM_CDX_FILE, rated_vex))),
                         {"sbom-document-surface", "forbidden-claim"})
        for section in ("annotations", "services", "formulation"):
            with self.subTest(section=section):
                errors = mutated(self, SBOM, edit(contracts.SBOM_CDX_FILE, lambda cdx, s=section: cdx.__setitem__(s, [])))
                self.assertEqual(names(errors), {"sbom-document-surface"})

    def test_a_component_nested_inside_a_cyclonedx_component_is_refused(self):
        def nest(cdx):
            cdx["components"][0]["components"] = [{"type": "library", "name": "hidden", "version": "1"}]
        self.assertEqual(names(mutated(self, SBOM, edit(contracts.SBOM_CDX_FILE, nest))), {"sbom-document-surface"})

        def nest_deeper(cdx):
            cdx["components"][0]["pedigree"] = {"ancestors": [{"components": []}]}
        self.assertEqual(names(mutated(self, SBOM, edit(contracts.SBOM_CDX_FILE, nest_deeper))), {"sbom-document-surface"})

    def test_a_rating_inside_a_cyclonedx_component_is_a_forbidden_claim(self):
        def rate(cdx):
            cdx["components"][0]["properties"] = [{"name": "x", "severity": "high"}]
        self.assertEqual(names(mutated(self, SBOM, edit(contracts.SBOM_CDX_FILE, rate))), {"forbidden-claim"})

    def test_a_license_expression_is_identifiers_and_operators_never_prose(self):
        for expression in ("Apache-2.0 compliant", "MIT approved for use", "MIT OR", "(MIT", "MIT)", "MIT and BSD-3-Clause"):
            with self.subTest(expression=expression):
                errors = mutated(self, LICENSE, edit(contracts.LICENSE_RESULT_FILE,
                                                     lambda doc, e=expression: doc["records"][0].__setitem__("license_expression", e)))
                self.assertEqual(names(errors), {"license-expression-shape"})
        for expression in ("MIT", "MIT OR Apache-2.0", "(MIT OR Apache-2.0) AND BSD-3-Clause",
                           "GPL-2.0-only WITH Classpath-exception-2.0"):
            with self.subTest(expression=expression):
                self.assertTrue(contracts.spdx_expression_shape_ok(expression))
                errors = mutated(self, LICENSE, edit(contracts.LICENSE_RESULT_FILE,
                                                     lambda doc, e=expression: doc["records"][0].__setitem__("license_expression", e)))
                self.assertEqual(errors, [])

    def test_an_end_of_life_row_cannot_be_republished_as_supported(self):
        def flip(doc):
            entry = next(item for item in doc["entries"] if item["table_row"] and item["table_row"]["status"] == "end-of-life")
            entry["table_row"]["status"] = entry["status"] = "supported"
        self.assertTrue(mutated(self, LIFECYCLE, edit(contracts.LIFECYCLE_RESULT_FILE, flip)))


if __name__ == "__main__":
    unittest.main()
