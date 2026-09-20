#!/usr/bin/env python3
"""Cross-record rules and on-disk bindings for the four SBOM-family output contracts (ADR-0010
G2 = A, G4 = A, M1-M5; task V05): `sbom-inventory`, `sca-vulnerability-match`,
`license-inventory` and `dependency-lifecycle`.

The schemas fix shapes. What ties a result to the node's tool instances, to the redaction receipt,
to the SBOM it was computed from, to the vulnerability databases or the reference table, and to the
bytes on disk cannot be written in the JSON-Schema subset `schema_validate.py` supports, so it lives
here as read-only functions:

    contract_declaration_errors(contract) -> list[str]
    verify_sbom_attempt(attempt_root, *, source_root, <common>) -> list[str]
    verify_sca_attempt(attempt_root, *, sbom_attempt_root, expected_sbom, expected_databases,
                       max_age, now, <common>) -> list[str]
    verify_license_attempt(attempt_root, *, source_root, sbom_attempt_root, expected_sbom,
                           <common>) -> list[str]
    verify_lifecycle_attempt(attempt_root, *, sbom_attempt_root, expected_sbom,
                             license_attempt_root, expected_license, reference_table_path,
                             expected_reference_table, max_age, now, <common>) -> list[str]

    <common> = tool_outputs_root, expected_header, expected_dagster_run_id, node_status,
               declared_tool_ids, permitted_node_statuses, on_unhandled, limits

EVERY argument is required and none has a default. They come from the worker envelope, the node's
registered template and graph edge, the upstream `accepted.json` records and the V18 database
bindings -- never from the documents under validation: a document cannot vouch for itself.
`max_age` follows ADR-0010 M4 exactly as `sca_nvd_snapshot.py` expresses it: "no limit" is the
explicit value `NO_AGE_LIMIT` (re-exported from that module), never a default; a database or table
older than a limit the job set is an error that says FAILED.

This module composes and does not re-implement `tool_instance_shapes.validate_node_aggregate`,
`tool_instance_shapes.verify_outputs_on_disk`, `tool_instance_shapes.output_path_errors` (V03) and
`evidence_redaction.verify_receipt` (V06).

ORDER IS A SAFETY PROPERTY. The redaction receipt is verified FIRST, against the published bytes,
and if it fails nothing else is parsed and only the receipt's errors are returned. An upstream
document (the SBOM, the licence inventory, the reference table) is parsed only after its bytes hash
to what the caller expects.

NO VALUE READ FROM AN ATTEMPT IS EVER ECHOED. Messages name files, fields, ordinal record ids (which
are re-derived from position), tool ids the CALLER declared, this module's own closed vocabulary
and what the caller expected. V03's aggregate messages quote document values, so they are reduced to
their stable error name plus caller-declared tool ids.

The functions return a fresh list of error strings and nothing else; each starts with a stable
error name followed by `: `, and an empty list means the attempt satisfies the contract. There is
deliberately no returned summary, verdict or parsed document: a record is a cache, never an
authority, and a caller that needs a fact re-derives it from the bytes. The pure helpers a consumer
needs for that (`databases_digest`, `fingerprint_component`, `gap_summary_counts`,
`required_gap_reason`, `lifecycle_row_for`, `declaration_kind`, `canonical_advisory_id`) keep no
state: each call derives its answer from its arguments and returns a string, a tuple or a fresh
structure nothing else holds. Nothing here publishes, redacts, repairs, writes, runs syft or Grype,
or touches the network. Adoption by the workers and by
`validate_job_output.py` dispatch belongs to V11 and the integration owner.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from types import MappingProxyType
from typing import Any, Iterable, Mapping
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from evidence_redaction import RECEIPT_FILENAME, Limits, POLICIES, ReceiptVerificationError, verify_receipt  # noqa: E402
from execution_state import beneath  # noqa: E402
from sca_nvd_snapshot import NO_AGE_LIMIT  # noqa: E402  (ADR-0010 M4: one spelling of "no limit")
from schema_validate import SchemaStore, validate_document  # noqa: E402
from tool_instance_shapes import (  # noqa: E402
    HEADER_FIELDS, RESULT_ROLES, VALIDATED, has_validated_output, output_path_errors,
    validate_node_aggregate, verify_outputs_on_disk,
)

SBOM_CONTRACT_ID = "sbom-inventory"
SCA_CONTRACT_ID = "sca-vulnerability-match"
LICENSE_CONTRACT_ID = "license-inventory"
LIFECYCLE_CONTRACT_ID = "dependency-lifecycle"

OUTPUTS_DIR = "outputs"
STATUS_FILE, MANIFEST_FILE = "status.json", "manifest.json"
RECEIPT_FILE = f"{OUTPUTS_DIR}/{RECEIPT_FILENAME}"
TOOL_RESULTS_FILE = f"{OUTPUTS_DIR}/tool-results.json"
COVERAGE_FILE = f"{OUTPUTS_DIR}/coverage.json"
SBOM_CDX_FILE = f"{OUTPUTS_DIR}/sbom.cdx.json"
SBOM_MANIFEST_FILE = f"{OUTPUTS_DIR}/sbom-manifest.json"
SCA_RESULT_FILE = f"{OUTPUTS_DIR}/sca-vulnerability-match.json"
SCA_IDENTITIES_FILE = f"{OUTPUTS_DIR}/vulnerability-database-identities.json"
SCA_GAPS_FILE = f"{OUTPUTS_DIR}/sca-coverage-gaps.json"
SCA_SUMMARY_FILE = f"{OUTPUTS_DIR}/coverage-gap-summary.json"
LICENSE_RESULT_FILE = f"{OUTPUTS_DIR}/license-inventory.json"
LIFECYCLE_RESULT_FILE = f"{OUTPUTS_DIR}/dependency-lifecycle.json"
TABLE_IDENTITY_FILE = f"{OUTPUTS_DIR}/reference-table-identity.json"
REFERENCE_TABLE_SCHEMA = "dependency-lifecycle-reference-table.schema.json"

FORBIDDEN_PROMOTIONS = ("finding", "severity", "runtime-state")
NEVER_SKIPS = ("OK", "OK_WITH_GAPS", "BLOCKED", "FAILED", "CANCELED")
PUBLISHED_DISPOSITIONS = ("unchanged", "redacted")
STATUS_FIELDS = ("status", "run_id", "attempt_id")
STATUS_OPTIONAL_FIELDS = ("dagster_run_id", "job_id")
MANIFEST_SCHEMA = "appsec-review/attempt-manifest/1"
DATABASE_KINDS = ("grype-db", "osv")
DATABASE_FIELDS = ("vendor_build", "schema_version", "snapshot_id", "sha256", "data_timestamp")
DATABASE_BLOCK_FIELDS = ("vendor_build", "schema_version", "snapshot_id", "sha256")
UPSTREAM_FIELDS = ("attempt_id", "sha256")
TABLE_FIELDS = ("table_id", "version", "sha256", "as_of")
MATCH_BASES = ("purl", "cpe")
CDX_TOP_LEVEL_KEYS = frozenset({"$schema", "bomFormat", "specVersion", "serialNumber", "version", "metadata", "components",
                                "dependencies"})
_SPDX_OPERATORS = frozenset({"AND", "OR", "WITH"})
GAP_REASONS = ("version-unknown", "no-package-identifier", "ecosystem-not-covered", "version-unparseable",
               "matcher-did-not-complete")
UNMAPPED_GAP_KIND = "unmapped-components"
_RUNTIME_ID_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,127}\Z")
_SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_STAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}\Z")
_GHSA_RE = re.compile(r"GHSA(-[0-9a-z]{4}){3}\Z")


def _frozen(**fields: Any) -> MappingProxyType:
    return MappingProxyType(fields)


# What each contract file in the registry must declare, and which schema each published document
# answers to. Pinned here because a contract file is data: a copy that dropped the receipt, a
# database identity file or a forbidden promotion must not weaken validation.
CONTRACT_POLICIES = MappingProxyType({
    SBOM_CONTRACT_ID: _frozen(
        job_id="02-sbom-inventory",
        required_files=(MANIFEST_FILE, STATUS_FILE, SBOM_CDX_FILE, SBOM_MANIFEST_FILE, RECEIPT_FILE, TOOL_RESULTS_FILE,
                        COVERAGE_FILE),
        result_schema=(SBOM_MANIFEST_FILE, "sbom-inventory.schema.json"),
        document_schemas=MappingProxyType({SBOM_MANIFEST_FILE: "sbom-inventory.schema.json"}),
        claim_class_id="dependency_inventory_evidence",
        allowed_assertions=("declared-component-present", "component-version-unknown", "inventory-coverage-gap"),
    ),
    SCA_CONTRACT_ID: _frozen(
        job_id="02-sca-vulnerability-match",
        required_files=(MANIFEST_FILE, STATUS_FILE, SCA_RESULT_FILE, SCA_IDENTITIES_FILE, SCA_GAPS_FILE, SCA_SUMMARY_FILE,
                        RECEIPT_FILE, TOOL_RESULTS_FILE, COVERAGE_FILE),
        result_schema=(SCA_RESULT_FILE, "sca-vulnerability-match.schema.json"),
        document_schemas=MappingProxyType({
            SCA_RESULT_FILE: "sca-vulnerability-match.schema.json",
            SCA_IDENTITIES_FILE: "sca-vulnerability-match-database-identities.schema.json",
            SCA_GAPS_FILE: "sca-vulnerability-match-coverage-gaps.schema.json",
            SCA_SUMMARY_FILE: "sca-vulnerability-match-gap-summary.schema.json"}),
        claim_class_id="known_vulnerability_match_lead",
        allowed_assertions=("advisory-matches-declared-version", "database-snapshot-identity", "match-coverage-gap"),
    ),
    LICENSE_CONTRACT_ID: _frozen(
        job_id="02-license-scan",
        required_files=(MANIFEST_FILE, STATUS_FILE, LICENSE_RESULT_FILE, RECEIPT_FILE, TOOL_RESULTS_FILE, COVERAGE_FILE),
        result_schema=(LICENSE_RESULT_FILE, "license-inventory.schema.json"),
        document_schemas=MappingProxyType({LICENSE_RESULT_FILE: "license-inventory.schema.json"}),
        claim_class_id="license_detection_evidence",
        allowed_assertions=("license-text-detected", "copyright-statement-detected", "vendored-component-inferred",
                            "scan-coverage-gap"),
    ),
    LIFECYCLE_CONTRACT_ID: _frozen(
        job_id="02-dependency-lifecycle",
        required_files=(MANIFEST_FILE, STATUS_FILE, LIFECYCLE_RESULT_FILE, TABLE_IDENTITY_FILE, RECEIPT_FILE,
                        TOOL_RESULTS_FILE, COVERAGE_FILE),
        result_schema=(LIFECYCLE_RESULT_FILE, "dependency-lifecycle.schema.json"),
        document_schemas=MappingProxyType({
            LIFECYCLE_RESULT_FILE: "dependency-lifecycle.schema.json",
            TABLE_IDENTITY_FILE: "dependency-lifecycle-reference-table-identity.schema.json"}),
        claim_class_id="dependency_lifecycle_evidence",
        allowed_assertions=("reference-table-eol-match", "lifecycle-unknown", "license-field-resurfaced"),
    ),
})

# Words that name a claim this family may not make. A property whose name contains one (split on
# '_' and '-', case-folded) is rejected BY NAME before anything else is reported. Reachability,
# exploitability and "affected in this deployment" are 06-cve-reachability's; severity is 12's;
# a licence verdict is a legal conclusion nobody here may draw.
FORBIDDEN_CLAIM_WORDS = frozenset({
    "reachable", "reachability", "unreachable", "reached", "callable", "called", "used", "unused", "usage", "imported",
    "exploit", "exploitable", "exploitability", "exploited", "exploitation", "kev", "epss", "weaponized",
    "affected", "affects", "impact", "impacted", "deployment", "deployed", "production", "runtime", "exposed", "exposure",
    "severity", "cvss", "score", "critical", "priority", "risk", "finding", "findings", "vulnerable", "verdict",
    "triage", "disposition", "fix", "fixed", "remediation", "recommendation",
    "compatible", "compatibility", "compliant", "compliance", "violation", "obligation", "obligations", "legal",
    "approved", "allowed", "denied", "copyleft", "permissive", "category",
})

# ---- ecosystems: declaration files and version schemes ------------------------------------------

_DECLARATION_FILES = MappingProxyType({
    "npm": MappingProxyType({"package.json": "manifest", "package-lock.json": "lockfile", "npm-shrinkwrap.json": "lockfile",
                             "yarn.lock": "lockfile", "pnpm-lock.yaml": "lockfile"}),
    "pypi": MappingProxyType({"pyproject.toml": "manifest", "setup.py": "manifest", "setup.cfg": "manifest",
                              "requirements.txt": "manifest", "Pipfile": "manifest", "poetry.lock": "lockfile",
                              "Pipfile.lock": "lockfile", "uv.lock": "lockfile"}),
    "maven": MappingProxyType({"pom.xml": "manifest", "build.gradle": "manifest", "build.gradle.kts": "manifest",
                               "gradle.lockfile": "lockfile"}),
    "golang": MappingProxyType({"go.mod": "manifest", "go.sum": "lockfile"}),
    "nuget": MappingProxyType({"packages.config": "manifest", "Directory.Packages.props": "manifest",
                               "packages.lock.json": "lockfile"}),
    "cargo": MappingProxyType({"Cargo.toml": "manifest", "Cargo.lock": "lockfile"}),
    "gem": MappingProxyType({"Gemfile": "manifest", "Gemfile.lock": "lockfile"}),
    "composer": MappingProxyType({"composer.json": "manifest", "composer.lock": "lockfile"}),
    "conan": MappingProxyType({"conanfile.txt": "manifest", "conanfile.py": "manifest", "conan.lock": "lockfile"}),
})
_DECLARATION_SUFFIXES = MappingProxyType({"nuget": (".csproj", ".fsproj", ".vbproj"), "gem": (".gemspec",)})
_PURL_TYPES = frozenset({"npm", "pypi", "maven", "golang", "nuget", "cargo", "gem", "composer", "conan", "deb", "rpm",
                         "apk", "generic"})

# The version scheme range evaluation uses is fixed by the ecosystem. An ecosystem outside this
# table has no purl-keyed source; it can be evaluated only by CPE, under the `generic` scheme.
ECOSYSTEM_VERSION_SCHEME = MappingProxyType({
    "npm": "semver", "cargo": "semver", "composer": "semver", "pypi": "pep440", "golang": "go-module", "maven": "maven",
    "nuget": "nuget", "gem": "gem", "deb": "deb", "rpm": "rpm", "apk": "apk"})
_SEMVER = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?\Z"
_LOOSE = re.compile(r"([0-9]+:)?[0-9][0-9A-Za-z.+~_-]*\Z")
_VERSION_PARSERS = MappingProxyType({
    "semver": re.compile(r"v?" + _SEMVER), "go-module": re.compile(r"v" + _SEMVER),
    "pep440": re.compile(r"([0-9]+!)?[0-9]+(\.[0-9]+)*((a|b|rc)[0-9]+)?(\.post[0-9]+)?(\.dev[0-9]+)?(\+[a-z0-9.]+)?\Z"),
    "maven": _LOOSE, "nuget": _LOOSE, "gem": _LOOSE, "deb": _LOOSE, "rpm": _LOOSE, "apk": _LOOSE, "generic": _LOOSE})


def declaration_kind(ecosystem: str, path: str) -> str:
    """manifest | lockfile | vendored-file-evidence, decided by the file NAME and the ecosystem.
    This is what stops an inferred vendored component being relabelled declared: `declared` needs a
    file that really is a manifest or lockfile of that ecosystem."""
    name = PurePosixPath(path).name
    kind = _DECLARATION_FILES.get(ecosystem, {}).get(name)
    if kind is None and ecosystem == "pypi" and re.match(r"requirements[A-Za-z0-9._-]{0,64}\.txt\Z", name):
        kind = "manifest"
    if kind is None and ecosystem in _DECLARATION_SUFFIXES and name.endswith(_DECLARATION_SUFFIXES[ecosystem]):
        kind = "manifest"
    return kind or "vendored-file-evidence"


def version_scheme_for(component: Mapping[str, Any]) -> str:
    return ECOSYSTEM_VERSION_SCHEME.get(component["ecosystem"], "generic")


def required_gap_reason(component: Mapping[str, Any]) -> str | None:
    """The closed reason this SBOM component MUST be a coverage gap for, or None when it can be
    range-evaluated. A null version, a component nothing can key on, an ecosystem no source covers
    and a version the scheme cannot parse are gaps; none of them is ever "no advisory matched"."""
    if component["version"] is None:
        return "version-unknown"
    if component["purl"] is None and component["cpe"] is None:
        return "no-package-identifier"
    if component["ecosystem"] not in ECOSYSTEM_VERSION_SCHEME and component["cpe"] is None:
        return "ecosystem-not-covered"
    if not _VERSION_PARSERS[version_scheme_for(component)].match(component["version"]):
        return "version-unparseable"
    return None


def gap_summary_counts(gaps: Iterable[Mapping[str, Any]]) -> tuple[tuple[str, str, int], ...]:
    """(ecosystem, reason, count), sorted: the M5 aggregate, derived from the gap records alone."""
    counts: dict[tuple[str, str], int] = {}
    for gap in gaps:
        key = (gap["ecosystem"], gap["reason"])
        counts[key] = counts.get(key, 0) + 1
    return tuple((ecosystem, reason, count) for (ecosystem, reason), count in sorted(counts.items()))


def _check_expected(name: str, value: Any, fields: tuple[str, ...]) -> None:
    if not isinstance(value, Mapping) or set(value) != set(fields) or not all(isinstance(value[f], str) for f in fields):
        raise TypeError(f"{name} must map exactly {list(fields)} to strings")


def _check_databases(expected_databases: Any) -> None:
    if not isinstance(expected_databases, Mapping) or set(expected_databases) != set(DATABASE_KINDS):
        raise TypeError(f"expected_databases must map exactly {list(DATABASE_KINDS)}")
    for kind in DATABASE_KINDS:
        _check_expected(f"expected_databases[{kind!r}]", expected_databases[kind], DATABASE_FIELDS)
        if not _SHA_RE.match(expected_databases[kind]["sha256"]) or not _STAMP_RE.match(expected_databases[kind]["data_timestamp"]):
            raise TypeError(f"expected_databases[{kind!r}] needs sha256 'sha256:<64 hex>' and data_timestamp 'YYYY-MM-DDTHH:MM:SSZ'")


def fingerprint_component(expected_databases: Mapping[str, Mapping[str, str]]) -> dict:
    """What the two database identities contribute to the `02-sca-vulnerability-match` input
    fingerprint. Like `sca_nvd_snapshot.fingerprint_component` it holds identity only -- never age,
    `evaluated_at` or the age policy, which the clock would otherwise turn into cache misses."""
    _check_databases(expected_databases)
    return {"schema": "appsec-review/sca-database-fingerprint/1",
            "databases": [{"database_kind": kind, **{field: expected_databases[kind][field] for field in DATABASE_FIELDS}}
                          for kind in DATABASE_KINDS]}


def databases_digest(expected_databases: Mapping[str, Mapping[str, str]]) -> str:
    canonical = json.dumps(fingerprint_component(expected_databases), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def lifecycle_row_for(component: Mapping[str, Any], rows: Iterable[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """The one reference-table row that speaks for this component: same ecosystem and name, and the
    LONGEST cycle that equals the version or is a dotted prefix of it. None means the table says
    nothing, which is `unknown` -- never `supported`."""
    version = component["version"]
    if version is None:
        return None
    best = None
    for row in rows:
        if row["ecosystem"] != component["ecosystem"] or row["name"] != component["name"]:
            continue
        if version == row["cycle"] or version.startswith(row["cycle"] + "."):
            if best is None or len(row["cycle"]) > len(best["cycle"]):
                best = row
    return best


def spdx_expression_shape_ok(expression: str) -> bool:
    """Shape of an SPDX licence expression: identifiers joined by AND / OR / WITH, with balanced
    parentheses. It does not know the SPDX licence list, so it cannot say an identifier is real; it
    does refuse two identifiers side by side, which is how prose ('Apache-2.0 compliant', 'MIT
    approved for use') gets into a field whose character class has to allow spaces."""
    tokens = re.findall(r"[()]|[^\s()]+", expression)
    depth, want_operand = 0, True
    for token in tokens:
        if token == "(":
            if not want_operand:
                return False
            depth += 1
        elif token == ")":
            if want_operand or depth == 0:
                return False
            depth -= 1
        elif token.upper() in _SPDX_OPERATORS:
            if want_operand or token not in _SPDX_OPERATORS:
                return False
            want_operand = True
        else:
            if not want_operand:
                return False
            want_operand = False
    return bool(tokens) and depth == 0 and not want_operand


def canonical_advisory_id(aliases: Iterable[str]) -> str:
    ordered = sorted(aliases)
    for pattern in (_CVE_RE, _GHSA_RE):
        preferred = [alias for alias in ordered if pattern.match(alias)]
        if preferred:
            return preferred[0]
    return ordered[0]


# ---- contract declaration --------------------------------------------------------------------------

def contract_declaration_errors(contract: Any) -> list[str]:
    """The registry contract must declare exactly the pinned files, result schema and claim class."""
    if not isinstance(contract, dict):
        raise TypeError("contract must be the parsed output-contract object")
    errors = [f"contract-schema: violates output-contract.schema.json at {_safe_location(error)}"
              for error in validate_document(contract, "output-contract.schema.json")]
    if errors:
        return sorted(set(errors))
    policy = CONTRACT_POLICIES.get(contract["contract_id"])
    if policy is None:
        return [f"contract-unknown: not one of the contracts this module pins {sorted(CONTRACT_POLICIES)}"]
    files = contract["required_files"]
    if len(files) != len(set(files)) or set(files) != set(policy["required_files"]):
        errors.append(f"contract-required-files: required_files must be exactly {sorted(policy['required_files'])}, each listed once")
    if contract.get("result_schema") != {"artifact": policy["result_schema"][0], "schema_file": policy["result_schema"][1]}:
        errors.append(f"contract-result-schema: result_schema must name artifact {policy['result_schema'][0]!r} and "
                      f"schema_file {policy['result_schema'][1]!r}")
    if sorted(contract["required_status_fields"]) != sorted(STATUS_FIELDS):
        errors.append(f"contract-status-fields: required_status_fields must be exactly {list(STATUS_FIELDS)}")
    claim = contract.get("claim_class")
    if not isinstance(claim, dict):
        return errors + ["contract-claim-class: claim_class must be declared"]
    if claim["claim_class_id"] != policy["claim_class_id"]:
        errors.append(f"contract-claim-class: claim_class_id must be {policy['claim_class_id']!r}")
    allowed = claim["allowed_assertions"]
    if len(allowed) != len(set(allowed)) or set(allowed) != set(policy["allowed_assertions"]):
        errors.append(f"contract-claim-class: allowed_assertions must be exactly {sorted(policy['allowed_assertions'])}, each listed once")
    forbidden = claim["forbidden_promotions"]
    if len(forbidden) != len(set(forbidden)) or set(forbidden) != set(FORBIDDEN_PROMOTIONS):
        errors.append(f"contract-forbidden-promotions: forbidden_promotions must be exactly {list(FORBIDDEN_PROMOTIONS)}, each listed once")
    return errors


# ---- reading ---------------------------------------------------------------------------------------

def _reject_constant(_name: str) -> Any:
    raise ValueError("non-standard JSON constant")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate object key")  # two parsers must never see two documents
    return result


def _parse(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"), parse_constant=_reject_constant, object_pairs_hook=_unique_pairs)


def _read_bytes(root: Path, relative: str, limits: Limits) -> bytes | None:
    """The regular, non-linked file `relative` inside `root`, or None."""
    try:
        path = beneath(root, root.joinpath(*relative.split("/")))
        if not path.is_file():
            return None
        with path.open("rb") as stream:
            data = stream.read(limits.max_file_bytes + 1)
    except (OSError, ValueError):
        return None
    return None if len(data) > limits.max_file_bytes else data


_SCHEMA_RULES = (("missing required property", "required"), ("unexpected property", "additionalProperties"),
                 ("expected const", "const"), ("expected type", "type"), ("not in enum", "enum"),
                 ("does not match pattern", "pattern"), ("minItems", "minItems"))
_LOCATION_RE = re.compile(r"\$[A-Za-z0-9_.\[\]\-]*\Z")


def _safe_location(message: str) -> str:
    location = message.partition(": ")[0]
    return location if _LOCATION_RE.match(location) else "$"


def _schema_errors(label: str, document: Any, schema_name: str, store: SchemaStore) -> list[str]:
    """`schema_validate` echoes the offending value and any unexpected property NAME, both of which
    come from the attempt. Keep only the location (schema-known property names and indexes) and the
    violated keyword."""
    errors = []
    for message in validate_document(document, schema_name, store):
        detail = message.partition(": ")[2]
        rule = next((name for marker, name in _SCHEMA_RULES if marker in detail), "schema rule")
        errors.append(f"schema:{label}: {_safe_location(message)}: violates {schema_name} ({rule})")
    return sorted(set(errors))


def forbidden_claim_errors(label: str, document: Any) -> list[str]:
    """Named rejection of a reachability / exploitability / affected-deployment / severity / legal
    property, run on the raw document before (and regardless of) schema validation. Only the word
    from this module's own closed list is quoted, never the property name or its value."""
    found: set[str] = set()
    stack = [document]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                found.update(set(re.split(r"[_\-\s.]+", key.lower())) & FORBIDDEN_CLAIM_WORDS)
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)
    return [f"forbidden-claim: {label}: a property name contains {word!r}; this contract may not assert reachability, "
            "exploitability, affected-deployment, severity, a recommendation or a legal conclusion "
            "(06-cve-reachability and 12 own those)" for word in sorted(found)]


def _safe_aggregate(errors: list[str], declared: list[str]) -> list[str]:
    """V03 messages quote document values. Keep the stable name and caller-declared tool ids only."""
    safe = []
    for error in errors:
        name = error.partition(": ")[0]
        if not re.match(r"[a-z][a-z0-9:-]*\Z", name):
            name = "aggregate-error"
        tools = [tool for tool in declared if f"{tool!r}" in error or f" {tool}:" in error]
        safe.append(f"aggregate:{name}: tool-results.json / coverage.json violate this V03 rule"
                    + (f" (declared tool {', '.join(repr(tool) for tool in tools)})" if tools else ""))
    return sorted(set(safe))


def _utc(stamp: str) -> datetime:
    return datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _ordinal_errors(label: str, prefix: str, ids: list[str]) -> list[str]:
    if ids != [f"{prefix}-{index:06d}" for index in range(1, len(ids) + 1)]:
        return [f"record-id-order: {label} ids must be {prefix}-000001..{prefix}-{len(ids):06d} in document order"]
    return []


# ---- the common attempt ------------------------------------------------------------------------------

class _Attempt:
    """What the common stage established. Private, short-lived and never returned to a caller."""

    def __init__(self) -> None:
        self.raw: dict[str, bytes] = {}
        self.documents: dict[str, Any] = {}
        self.receipt: dict = {}
        self.instances: dict[str, dict] = {}
        self.coverage: dict = {}
        self.all_instances_ok = False


def _check_common(attempt_root: Any, tool_outputs_root: Any, expected_header: Any, expected_dagster_run_id: Any,
                  node_status: Any, declared_tool_ids: Any, permitted_node_statuses: Any, on_unhandled: Any,
                  limits: Any) -> None:
    for name, value in (("attempt_root", attempt_root), ("tool_outputs_root", tool_outputs_root)):
        _check_root(name, value)
    _check_expected("expected_header", expected_header, HEADER_FIELDS)
    if not isinstance(expected_dagster_run_id, str) or not _RUNTIME_ID_RE.match(expected_dagster_run_id):
        raise TypeError("expected_dagster_run_id must be the orchestrator run id the caller is validating for")
    if not isinstance(node_status, str):
        raise TypeError("node_status must be the worker envelope's terminal status string")
    for name, value in (("declared_tool_ids", declared_tool_ids), ("permitted_node_statuses", permitted_node_statuses)):
        if value is None or isinstance(value, (str, bytes, Mapping)):
            raise TypeError(f"{name} must be a collection of strings, not a string, a mapping or None")
    if on_unhandled not in POLICIES:
        raise TypeError("on_unhandled must be exactly 'refuse' or 'withhold'")
    if not isinstance(limits, Limits):
        raise TypeError("limits must be an evidence_redaction.Limits instance")


def _check_root(name: str, value: Any) -> None:
    if value is None or isinstance(value, (bytes, bool)) or not str(value):
        raise TypeError(f"{name} must be a filesystem path")


def _check_age_arguments(max_age: Any, now: Any) -> None:
    if max_age is not NO_AGE_LIMIT:
        if not isinstance(max_age, timedelta):
            raise TypeError("max_age must be NO_AGE_LIMIT or a datetime.timedelta; it has no default")
        if max_age <= timedelta(0):
            raise ValueError("max_age must be greater than zero")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise TypeError("now must be a timezone-aware datetime; the wall clock is never read here")


def _status_errors(data: bytes, node_status: str, expected_header: Mapping[str, str], job_id: str,
                   expected_dagster_run_id: str) -> list[str]:
    """`status.json` is outside `outputs/`, so the receipt says nothing about it: it may carry only
    the registered fields plus the closed set of runtime identifiers, every one BOUND, and nothing
    from it is ever named or quoted."""
    try:
        status = _parse(data)
    except (ValueError, RecursionError):
        status = None
    if not isinstance(status, dict):
        return ["status-invalid: status.json is not a strict UTF-8 JSON object with unique keys"]
    errors = []
    bound = {"status": (node_status, "the node_status argument"), "run_id": (expected_header["run_id"], "expected_header"),
             "attempt_id": (expected_header["attempt_id"], "expected_header"), "job_id": (job_id, "the contract's job id"),
             "dagster_run_id": (expected_dagster_run_id, "expected_dagster_run_id")}
    for field in STATUS_FIELDS:
        if field not in status:
            errors.append(f"status-invalid: status.json lacks the registered field {field!r}")
    for field, (value, source) in bound.items():
        if field in status and (not isinstance(status[field], str) or status[field] != value):
            errors.append(f"status-mismatch: status.json {field} must equal {source} ({value!r})")
    unknown = sum(1 for key in status if key not in bound)
    if unknown:
        errors.append(f"status-invalid: status.json carries {unknown} field(s) that are neither registered nor a known runtime identifier")
    return errors


def _manifest_errors(data: bytes, contract_id: str, attempt: Path) -> list[str]:
    """`manifest.json` is exactly `{"schema", "contract_id", "outputs": [{"path", "sha256"}, ...]}`;
    `outputs` is sorted and names EXACTLY the regular files beneath `outputs/`, each with the
    sha256 of its bytes. Outside `outputs/`, so nothing from it is ever quoted."""
    try:
        document = _parse(data)
    except (ValueError, RecursionError):
        return ["manifest-invalid: manifest.json is not strict UTF-8 JSON with unique keys"]
    if not isinstance(document, dict) or set(document) != {"schema", "contract_id", "outputs"}:
        return ["manifest-invalid: manifest.json must be an object with exactly schema, contract_id and outputs"]
    if document["schema"] != MANIFEST_SCHEMA or document["contract_id"] != contract_id:
        return [f"manifest-invalid: manifest.json must carry schema {MANIFEST_SCHEMA!r} and contract_id {contract_id!r}"]
    listed = document["outputs"]
    if not isinstance(listed, list) or not all(
            isinstance(entry, dict) and set(entry) == {"path", "sha256"}
            and isinstance(entry["path"], str) and isinstance(entry["sha256"], str) for entry in listed):
        return ["manifest-invalid: manifest.json outputs must be a list of {path, sha256} records"]
    actual = {path.relative_to(attempt).as_posix(): path for path in sorted((attempt / OUTPUTS_DIR).rglob("*"))
              if path.is_file() and not path.is_symlink()}
    paths = [entry["path"] for entry in listed]
    errors = []
    if any(output_path_errors(path) for path in paths) or paths != sorted(set(paths)):
        errors.append("manifest-invalid: manifest.json outputs paths must be normalized, unique and sorted")
    if set(paths) != set(actual):
        errors.append(f"manifest-mismatch: manifest.json outputs does not name exactly the {len(actual)} file(s) beneath {OUTPUTS_DIR}/")
    wrong = sum(1 for entry in listed if entry["path"] in actual
                and entry["sha256"] != "sha256:" + hashlib.sha256(actual[entry["path"]].read_bytes()).hexdigest())
    if wrong:
        errors.append(f"manifest-mismatch: {wrong} manifest.json outputs entr{'y' if wrong == 1 else 'ies'} do not carry the sha256 of the published bytes")
    return errors


def _open_attempt(contract_id: str, attempt_root: Any, *, tool_outputs_root: Any, expected_header: Mapping[str, str],
                  expected_dagster_run_id: str, node_status: str, declared_tool_ids: Iterable[str],
                  permitted_node_statuses: Iterable[str], on_unhandled: str, limits: Limits,
                  store: SchemaStore) -> tuple[list[str], _Attempt | None]:
    """Everything the four contracts share. Returns (errors, attempt); `attempt` is None when the
    contract-specific rules must not run (they only run over verified, well-formed documents)."""
    policy = CONTRACT_POLICIES[contract_id]
    declared, permitted = list(declared_tool_ids), list(permitted_node_statuses)
    if expected_header["job_id"] != policy["job_id"]:
        raise ValueError(f"expected_header job_id must be {policy['job_id']!r}, the node of contract {contract_id!r}")
    attempt = Path(attempt_root).absolute()
    if not attempt.is_dir():
        return ["attempt-root: attempt_root is not a directory"], None

    # 1. Every contract file is a regular, non-linked, bounded file. Nothing is parsed yet.
    state, errors = _Attempt(), []
    for relative in policy["required_files"]:
        data = _read_bytes(attempt, relative, limits)
        if data is not None:
            state.raw[relative] = data
        elif relative == RECEIPT_FILE:
            errors.append(f"receipt-missing: {RECEIPT_FILE} is absent, linked, not a regular file or over max_file_bytes; "
                          "without a receipt the whole output is absent")
        else:
            errors.append(f"required-file-missing: {relative} is absent, linked, not a regular file or over max_file_bytes")
    if errors:
        return errors, None

    # 2. The receipt, verified against outputs/ BEFORE any other document is parsed.
    try:
        receipt = _parse(state.raw[RECEIPT_FILE])
    except (ValueError, RecursionError):
        return [f"receipt-invalid: {RECEIPT_FILE} is not strict UTF-8 JSON with unique keys"], None
    try:
        verify_receipt(receipt, attempt / OUTPUTS_DIR, on_unhandled=on_unhandled, limits=limits)
    except ReceiptVerificationError as failure:
        return [f"receipt-invalid: {error}" for error in failure.errors], None
    state.receipt = receipt

    # 3. status.json and manifest.json: outside outputs/, bound to caller facts, never quoted.
    outside = _status_errors(state.raw[STATUS_FILE], node_status, expected_header, policy["job_id"], expected_dagster_run_id)
    outside += _manifest_errors(state.raw[MANIFEST_FILE], contract_id, attempt)

    # 4. Each outputs/ contract file is published by that receipt, and the bytes read here are the
    #    bytes it verified. Only then is it parsed.
    records = {record["path"]: record for record in receipt["files"]}
    for relative in policy["required_files"]:
        if not relative.startswith(OUTPUTS_DIR + "/") or relative == RECEIPT_FILE:
            continue
        record = records.get(relative[len(OUTPUTS_DIR) + 1:])
        if record is None or record["disposition"] not in PUBLISHED_DISPOSITIONS:
            errors.append(f"receipt-does-not-publish: the receipt does not list {relative} as unchanged or redacted")
            continue
        if hashlib.sha256(state.raw[relative]).hexdigest() != record["published_sha256"]:
            errors.append(f"receipt-hash-mismatch: {relative} does not have the receipt's published_sha256")
            continue
        try:
            state.documents[relative] = _parse(state.raw[relative])
        except (ValueError, RecursionError):
            errors.append(f"document-unreadable: {relative} is not strict UTF-8 JSON with unique keys")
    if errors:
        return outside + errors, None

    # 5. Claims this family may not make are rejected by name, alone.
    for relative in policy["document_schemas"]:
        errors += forbidden_claim_errors(relative, state.documents[relative])
    if errors:
        return outside + errors, None

    # 6. Shapes. Structural failures are returned alone.
    for relative, schema_name in policy["document_schemas"].items():
        errors += _schema_errors(relative, state.documents[relative], schema_name, store)
    tool_results, coverage = state.documents[TOOL_RESULTS_FILE], state.documents[COVERAGE_FILE]
    aggregate = validate_node_aggregate(node_status, tool_results, coverage, None, declared, permitted, store=store)
    errors += _safe_aggregate(aggregate, declared)
    if any(error.startswith("schema:") for error in errors + aggregate):
        return outside + errors, None
    errors = outside + errors

    # 7. Bindings every contract has.
    if set(permitted) - set(NEVER_SKIPS):
        errors.append(f"status-not-permitted-by-contract: contract {contract_id} permits only {list(NEVER_SKIPS)}; this node "
                      "is always applicable and is never SKIPPED")
    for relative in (TOOL_RESULTS_FILE, *policy["document_schemas"]):
        for field in HEADER_FIELDS:
            if state.documents[relative][field] != expected_header[field]:
                errors.append(f"header-mismatch: {relative} {field} must equal expected_header ({expected_header[field]!r})")
        if "redactor" in state.documents[relative] and state.documents[relative]["redactor"] != receipt["redactor"]:
            errors.append(f"redactor-mismatch: {relative} redactor block differs from the receipt's redactor identity")
    errors += _safe_aggregate([f"tool-outputs-on-disk: {error}" for error in
                               verify_outputs_on_disk(tool_results, tool_outputs_root)], declared)
    for instance in tool_results["tool_instances"]:
        state.instances.setdefault(instance["tool_id"], instance)
    for tool_id, instance in sorted(state.instances.items()):
        if not instance["outputs"] or tool_id not in declared:
            continue
        redactor = instance["identity"]["redactor"]
        if (redactor is None or redactor["redactor_version"] != receipt["redactor"]["module_version"]
                or redactor["ruleset_sha256"] != "sha256:" + receipt["redactor"]["ruleset_sha256"]):
            errors.append(f"instance-redactor-mismatch: declared tool {tool_id!r} lists outputs, so its identity.redactor must "
                          "carry the receipt's module_version and ruleset_sha256")
    state.coverage = coverage
    state.all_instances_ok = all(instance["terminal_status"] == "OK" for instance in tool_results["tool_instances"])
    return errors, state


def _citation_errors(records: list[tuple[str, dict]], job_id: str, state: _Attempt, declared: list[str]) -> list[str]:
    errors, per_tool = [], {}
    for label, record in records:
        tool_id, citation = record["tool_id"], record["citation"]
        if citation["producer"] != job_id:
            errors.append(f"citation-producer: {label}: citation.producer must be {job_id!r}")
        instance = state.instances.get(tool_id)
        if instance is None or tool_id not in declared:
            errors.append(f"tool-unresolved: {label}: tool_id is not a declared tool instance in tool-results.json")
            continue
        per_tool[tool_id] = per_tool.get(tool_id, 0) + 1
        if not has_validated_output(instance):
            errors.append(f"tool-without-validated-output: {label}: declared tool {tool_id!r} has no validated output, so it supports no record")
            continue
        if citation["attempt_id"] != instance["attempt_id"]:
            errors.append(f"citation-attempt-mismatch: {label}: citation.attempt_id is not the attempt id of declared tool {tool_id!r}")
        listed = [output for output in instance["outputs"] if output["path"] == citation["path"]]
        if not listed:
            errors.append(f"citation-unresolved: {label}: citation.path is not an output listed for declared tool {tool_id!r}")
            continue
        if listed[0]["role"] not in RESULT_ROLES or listed[0]["validation"] not in VALIDATED:
            errors.append(f"citation-not-validated-output: {label}: the cited output of declared tool {tool_id!r} is not a validated result file")
        if "sha256:" + citation["sha256"] != listed[0]["sha256"]:
            errors.append(f"citation-hash-mismatch: {label}: citation.sha256 is not the sha256 tool-results.json lists for that output")
    for tool_id, count in sorted(per_tool.items()):
        reported = state.instances[tool_id]["result_record_count"]
        if isinstance(reported, int) and count > reported:
            errors.append(f"record-count-exceeds-tool: {count} records cite declared tool {tool_id!r}, more than its result_record_count")
    return errors


def _source_file_errors(source_root: Path, cites: list[tuple[str, str, str, int | None]], limits: Limits) -> list[str]:
    """Bind every cited source file to the bytes in the source snapshot. One file has one spelling:
    identity is the device and inode (falling back to the resolved path), not the string."""
    if not source_root.is_dir():
        return ["source-root: source_root is not a directory"]
    errors, owners, measured = [], {}, {}
    for label, relative, listed_hash, last_line in cites:
        if output_path_errors(relative):
            errors.append(f"source-path: {label}: path is not a normalized snapshot-relative path "
                          "(no '.', '..', empty or leading-slash segments)")
            continue
        if relative not in measured:
            try:
                path = beneath(source_root, source_root.joinpath(*relative.split("/")))
                if not path.is_file():
                    raise ValueError("not a regular file")
                status = path.stat()
                identity = (status.st_dev, status.st_ino) if status.st_ino else os.path.normcase(str(path.resolve()))
                data = _read_bytes(source_root, relative, limits)
            except (OSError, ValueError):
                data = None
            if data is None:
                errors.append(f"source-file-missing: {label}: the cited file is absent, linked, not a regular file or over "
                              "max_file_bytes in the source snapshot")
                continue
            if owners.setdefault(identity, relative) != relative:
                errors.append(f"source-alias: {label}: the cited file is the same file as another cited path under a second name")
                continue
            lines = data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)
            measured[relative] = ("sha256:" + hashlib.sha256(data).hexdigest(), lines)
        actual_hash, lines = measured[relative]
        if actual_hash != listed_hash:
            errors.append(f"source-hash-mismatch: {label}: the cited file does not have the listed sha256")
        elif last_line is not None and last_line > lines:
            errors.append(f"source-line-range: {label}: the line span ends beyond the cited file's {lines} line(s)")
    return errors


# ---- upstream documents --------------------------------------------------------------------------------

_UPSTREAM = MappingProxyType({
    "sbom": _frozen(job_id="02-sbom-inventory", path=SBOM_MANIFEST_FILE, schema="sbom-inventory.schema.json",
                    root_name="sbom_attempt_root", expected_name="expected_sbom"),
    "license": _frozen(job_id="02-license-scan", path=LICENSE_RESULT_FILE, schema="license-inventory.schema.json",
                       root_name="license_attempt_root", expected_name="expected_license"),
})


def _load_upstream(kind: str, root: Any, expected: Mapping[str, str], expected_header: Mapping[str, str], limits: Limits,
                   store: SchemaStore) -> tuple[list[str], Any]:
    """An upstream document is parsed only after its bytes hash to what the CALLER expects (the
    sha256 recorded when that attempt was accepted). It must belong to the same run and source
    snapshot and to the attempt the caller names."""
    spec = _UPSTREAM[kind]
    data = _read_bytes(Path(root).absolute(), spec["path"], limits)
    if data is None:
        return [f"upstream-missing: {spec['path']} is absent, linked, not a regular file or over max_file_bytes under "
                f"{spec['root_name']}"], None
    if "sha256:" + hashlib.sha256(data).hexdigest() != expected["sha256"]:
        return [f"upstream-hash-mismatch: {spec['path']} under {spec['root_name']} does not have the sha256 in "
                f"{spec['expected_name']} ({expected['sha256']!r}); it was not parsed"], None
    try:
        document = _parse(data)
    except (ValueError, RecursionError):
        return [f"upstream-invalid: {spec['path']} under {spec['root_name']} is not strict UTF-8 JSON with unique keys"], None
    errors = _schema_errors(f"upstream:{spec['path']}", document, spec["schema"], store)
    if errors:
        return errors, None
    wanted = {"run_id": expected_header["run_id"], "source_snapshot_sha256": expected_header["source_snapshot_sha256"],
              "attempt_id": expected["attempt_id"]}
    for field, value in wanted.items():
        if document[field] != value:
            errors.append(f"upstream-mismatch: {spec['path']} under {spec['root_name']} {field} must be {value!r}")
    if kind == "sbom":
        errors += _ordinal_errors("upstream SBOM components", "SC", [item["component_id"] for item in document["components"]])
    else:
        errors += _ordinal_errors("upstream licence records", "LI", [item["record_id"] for item in document["records"]])
    return errors, (None if errors else document)


def _binding_errors(relative: str, field: str, block: Mapping[str, Any], kind: str, expected: Mapping[str, str]) -> list[str]:
    spec = _UPSTREAM[kind]
    wanted = {"job_id": spec["job_id"], "path": spec["path"], "attempt_id": expected["attempt_id"], "sha256": expected["sha256"]}
    return [f"upstream-binding-mismatch: {relative} {field}.{name} must be {value!r} ({spec['expected_name']} / pinned)"
            for name, value in wanted.items() if block[name] != value]


def _age_errors(label: str, block: Mapping[str, Any], data_time: datetime, max_age: Any, now: datetime, what: str) -> list[str]:
    """ADR-0010 M4, mirroring `sca_nvd_snapshot.identity_consistency_errors`: the label restates the
    limit, the age is a function of two stamps, the limit is the CALLER's, and over the limit is
    FAILED. The age is also re-derived at the caller's `now`."""
    errors = []
    limit = None if max_age is NO_AGE_LIMIT else int(max_age.total_seconds())
    try:
        evaluated = _utc(block["evaluated_at"])
    except ValueError:
        return [f"age-invalid: {label}: evaluated_at is not a real UTC timestamp"]
    if evaluated < data_time or evaluated > now:
        errors.append(f"age-invalid: {label}: evaluated_at must not precede the {what}'s timestamp or follow the caller's now")
    if block["age_seconds"] != int((evaluated - data_time).total_seconds()):
        errors.append(f"age-invalid: {label}: age_seconds must equal evaluated_at minus the {what}'s timestamp")
    if block["max_age_seconds"] != limit:
        errors.append(f"age-policy-mismatch: {label}: max_age_seconds must be the limit the caller set ({limit!r})")
    if (block["age_policy"] == "no-limit") != (limit is None):
        errors.append(f"age-policy-mismatch: {label}: age_policy must be 'no-limit' exactly when the caller passed NO_AGE_LIMIT")
    if limit is not None and max(block["age_seconds"], int((now - data_time).total_seconds())) > limit:
        errors.append(f"{what}-too-old: {label}: older than the max_age of {limit} seconds this job set; that is FAILED, "
                      "never OK_WITH_GAPS, and no accepted result may rest on it")
    return errors


def _unmapped_gap_errors(state: _Attempt, count: int, what: str) -> list[str]:
    gaps = [gap for gap in state.coverage["gaps"] if gap["kind"] == UNMAPPED_GAP_KIND]
    if bool(gaps) != bool(count) or len(gaps) > 1 or (gaps and gaps[0]["affected_input_count"] != count):
        return [f"coverage-gap-mismatch: coverage.json must name exactly one {UNMAPPED_GAP_KIND!r} gap with "
                f"affected_input_count {count} when {what} exist, and none otherwise"]
    return []


# ---- sbom-inventory ---------------------------------------------------------------------------------------

def _purl_parts(purl: str) -> tuple[str, str, str | None]:
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    purl_type, _, rest = body.partition("/")
    path, at, version = rest.rpartition("@")
    if not at:
        path, version = rest, None
    return purl_type, unquote(path.rsplit("/", 1)[-1]), (unquote(version) if version is not None else None)


def _component_errors(components: list[dict]) -> list[str]:
    errors = _ordinal_errors("components", "SC", [component["component_id"] for component in components])
    seen = set()
    for index, component in enumerate(components, 1):
        label = f"SC-{index:06d}"
        source, declaration = component["source"], component["declaration"]
        derived = declaration_kind(component["ecosystem"], source["path"])
        if source["evidence_kind"] != derived:
            errors.append(f"evidence-kind-mismatch: {label}: source.evidence_kind must be {derived!r}, which is what the name "
                          "of source.path is for this ecosystem")
        if (declaration == "declared") != (derived in ("manifest", "lockfile")):
            errors.append(f"inferred-promoted-to-declared: {label}: declaration must be 'declared' exactly when source.path is "
                          "a manifest or lockfile of the component's ecosystem; an inferred vendored component is never declared")
        wanted = ("inventory-coverage-gap" if declaration != "declared" else
                  "component-version-unknown" if component["version"] is None else "declared-component-present")
        if component["assertion"] != wanted:
            errors.append(f"assertion-mismatch: {label}: assertion must be {wanted!r} for this declaration and version")
        if component["purl"] is not None:
            purl_type, purl_name, purl_version = _purl_parts(component["purl"])
            if purl_type not in _PURL_TYPES or purl_type != component["ecosystem"]:
                errors.append(f"purl-mismatch: {label}: the purl type must equal the component's ecosystem")
            if purl_name != component["name"].rsplit("/", 1)[-1] or purl_version != component["version"]:
                errors.append(f"purl-mismatch: {label}: the purl's name and version must agree with the component's")
        key = (component["ecosystem"], component["name"], component["version"], component["purl"], source["path"])
        if key in seen:
            errors.append(f"duplicate-record: {label}: repeats the ecosystem, name, version, purl and source of an earlier component")
        seen.add(key)
    return errors


def _cdx_errors(raw: bytes, manifest: dict) -> list[str]:
    described = manifest["sbom_document"]
    errors = []
    if "sha256:" + hashlib.sha256(raw).hexdigest() != described["sha256"] or len(raw) != described["bytes"]:
        errors.append(f"sbom-document-mismatch: sbom_document sha256 and bytes must be those of {SBOM_CDX_FILE}")
    try:
        cdx = _parse(raw)
    except (ValueError, RecursionError):
        return errors + [f"sbom-document-invalid: {SBOM_CDX_FILE} is not strict UTF-8 JSON with unique keys"]
    listed = cdx.get("components", []) if isinstance(cdx, dict) else None
    if (not isinstance(cdx, dict) or cdx.get("bomFormat") != "CycloneDX" or cdx.get("specVersion") != described["spec_version"]
            or not isinstance(listed, list) or not all(isinstance(item, dict) for item in listed)):
        return errors + [f"sbom-document-invalid: {SBOM_CDX_FILE} must be a CycloneDX object whose specVersion is the manifest's "
                         "spec_version and whose components is a list of objects"]

    # The CycloneDX file is published, so it is a claim surface too. CycloneDX can carry VEX
    # (vulnerabilities[].analysis.state = not_affected), ratings and nested components; none of those
    # is visible to the projection below, so they are refused here rather than left to a consumer.
    if set(cdx) - CDX_TOP_LEVEL_KEYS:
        errors.append(f"sbom-document-surface: {SBOM_CDX_FILE} may carry only these top-level members: "
                      f"{', '.join(sorted(CDX_TOP_LEVEL_KEYS))}; a vulnerabilities, annotations or any other section is "
                      "not an inventory and is not checked against the manifest")
    stack = list(listed)
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if "components" in node:
                errors.append(f"sbom-document-surface: {SBOM_CDX_FILE} components must be flat; a nested components list "
                              "is outside the (name, version, purl) projection")
                break
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    errors += forbidden_claim_errors(SBOM_CDX_FILE, cdx)

    def projection(items, keys):
        return sorted(json.dumps([item.get(key) for key in keys]) for item in items)

    if projection(listed, ("name", "version", "purl")) != projection(manifest["components"], ("name", "version", "purl")):
        errors.append(f"sbom-projection-mismatch: the (name, version, purl) multiset of {SBOM_CDX_FILE} components differs "
                      f"from {SBOM_MANIFEST_FILE}; two projections of one inventory must agree")
    return errors


def verify_sbom_attempt(attempt_root: Any, *, source_root: Any, tool_outputs_root: Any, expected_header: Mapping[str, str],
                        expected_dagster_run_id: str, node_status: str, declared_tool_ids: Iterable[str],
                        permitted_node_statuses: Iterable[str], on_unhandled: str, limits: Limits) -> list[str]:
    """Verify one `02-sbom-inventory` attempt directory against contract `sbom-inventory`."""
    _check_common(attempt_root, tool_outputs_root, expected_header, expected_dagster_run_id, node_status, declared_tool_ids,
                  permitted_node_statuses, on_unhandled, limits)
    _check_root("source_root", source_root)
    declared, store = list(declared_tool_ids), SchemaStore()
    errors, state = _open_attempt(
        SBOM_CONTRACT_ID, attempt_root, tool_outputs_root=tool_outputs_root, expected_header=expected_header,
        expected_dagster_run_id=expected_dagster_run_id, node_status=node_status, declared_tool_ids=declared,
        permitted_node_statuses=permitted_node_statuses, on_unhandled=on_unhandled, limits=limits, store=store)
    if state is None:
        return errors
    manifest = state.documents[SBOM_MANIFEST_FILE]
    components = manifest["components"]
    errors += _component_errors(components)
    errors += _cdx_errors(state.raw[SBOM_CDX_FILE], manifest)
    labelled = [(f"SC-{index:06d}", component) for index, component in enumerate(components, 1)]
    errors += _citation_errors(labelled, CONTRACT_POLICIES[SBOM_CONTRACT_ID]["job_id"], state, declared)
    errors += _source_file_errors(Path(source_root).absolute(),
                                  [(label, item["source"]["path"], item["source"]["sha256"], None) for label, item in labelled],
                                  limits)
    return errors


# ---- sca-vulnerability-match ---------------------------------------------------------------------------------

def _database_errors(state: _Attempt, expected_databases: Mapping[str, Mapping[str, str]], max_age: Any, now: datetime,
                     declared: list[str]) -> list[str]:
    errors = []
    identities = state.documents[SCA_IDENTITIES_FILE]
    digest = databases_digest(expected_databases)
    for relative in (SCA_RESULT_FILE, SCA_IDENTITIES_FILE):
        if state.documents[relative]["databases_digest"] != digest:
            errors.append(f"database-digest-mismatch: {relative} databases_digest must be the digest of the caller's expected "
                          f"database identities ({digest!r})")
    kinds = [entry["database"]["database_kind"] for entry in identities["databases"]]
    if sorted(kinds) != sorted(DATABASE_KINDS):
        errors.append(f"database-identity-missing: {SCA_IDENTITIES_FILE} must list exactly {list(DATABASE_KINDS)}, once each")
    for entry in identities["databases"]:
        kind = entry["database"]["database_kind"]
        expected = expected_databases[kind]
        errors += _database_block_errors(f"{SCA_IDENTITIES_FILE} database {kind!r}", entry["database"], expected_databases)
        if entry["data_timestamp"] != expected["data_timestamp"]:
            errors.append(f"database-identity-mismatch: {SCA_IDENTITIES_FILE} database {kind!r} data_timestamp must be "
                          f"{expected['data_timestamp']!r} (expected_databases)")
        errors += _age_errors(f"{SCA_IDENTITIES_FILE} database {kind!r}", entry, _utc(expected["data_timestamp"]), max_age,
                              now, "database")
    for tool_id, instance in sorted(state.instances.items()):
        if tool_id not in declared or not has_validated_output(instance):
            continue
        listed = [(item["kind"], item["identity_id"], item["version"], item["sha256"])
                  for item in instance["identity"]["data_identities"]]
        for kind in DATABASE_KINDS:
            wanted = ("vulnerability-database", kind, expected_databases[kind]["schema_version"], expected_databases[kind]["sha256"])
            if wanted not in listed:
                errors.append(f"instance-database-mismatch: declared tool {tool_id!r} must list data identity "
                              f"{wanted!r} (expected_databases)")
    return errors


def _database_block_errors(label: str, block: Mapping[str, Any], expected_databases: Mapping[str, Mapping[str, str]]) -> list[str]:
    expected = expected_databases[block["database_kind"]]
    return [f"database-identity-mismatch: {label} {field} must be {expected[field]!r} (expected_databases)"
            for field in DATABASE_BLOCK_FIELDS if block[field] != expected[field]]


def _sca_errors(state: _Attempt, sbom: dict, expected_databases: Mapping[str, Mapping[str, str]]) -> list[str]:
    result, gap_document, summary = (state.documents[name] for name in (SCA_RESULT_FILE, SCA_GAPS_FILE, SCA_SUMMARY_FILE))
    components = {component["component_id"]: component for component in sbom["components"]}
    errors = []

    evaluated: dict[str, dict] = {}
    for position, entry in enumerate(result["evaluated"], 1):
        label = f"evaluated[{position}]"
        component = components.get(entry["component_ref"])
        if component is None:
            errors.append(f"component-unresolved: {label}: component_ref is not a component of the bound SBOM")
            continue
        if entry["component_ref"] in evaluated:
            errors.append(f"duplicate-record: {label}: repeats the component_ref of an earlier evaluated entry")
            continue
        evaluated[entry["component_ref"]] = entry
        reason = required_gap_reason(component)
        if reason is not None:
            errors.append(f"gap-hidden-as-evaluated: {label}: the bound SBOM makes this component a {reason!r} coverage gap; "
                          "it cannot be evaluated and is never 'no-advisory-matched'")
        if entry["version_scheme"] != version_scheme_for(component):
            errors.append(f"version-scheme-mismatch: {label}: version_scheme must be {version_scheme_for(component)!r} for "
                          "this component's ecosystem")
        if len(entry["evaluated_by"]) != len(set(entry["evaluated_by"])):
            errors.append(f"duplicate-record: {label}: evaluated_by repeats a database")
        if "osv" in entry["evaluated_by"] and component["purl"] is None:
            errors.append(f"match-basis-unsupported: {label}: osv evaluates by purl and this component has none")

    errors += _ordinal_errors("matches", "VM", [match["match_id"] for match in result["matches"]])
    alias_owner: dict[tuple[str, str], str] = {}
    matched: set[str] = set()
    for position, match in enumerate(result["matches"], 1):
        label = f"VM-{position:06d}"
        entry, component = evaluated.get(match["component_ref"]), components.get(match["component_ref"])
        if entry is None or component is None:
            errors.append(f"match-on-unevaluated-component: {label}: component_ref is not an evaluated component of the bound SBOM")
            continue
        matched.add(match["component_ref"])
        if match["version_scheme"] != entry["version_scheme"]:
            errors.append(f"version-scheme-mismatch: {label}: version_scheme must be the scheme its component was evaluated under")
        aliases = match["aliases"]
        if aliases != sorted(set(aliases)) or match["advisory_id"] not in aliases:
            errors.append(f"alias-set-invalid: {label}: aliases must be sorted, unique and contain advisory_id")
        elif match["advisory_id"] != canonical_advisory_id(aliases):
            errors.append(f"alias-set-invalid: {label}: advisory_id must be the canonical alias (smallest CVE, else smallest "
                          "GHSA, else smallest)")
        for alias in set(aliases) | {match["advisory_id"]}:
            if alias_owner.setdefault((match["component_ref"], alias), label) != label:
                errors.append(f"alias-not-collapsed: {label}: shares an advisory alias with "
                              f"{alias_owner[(match['component_ref'], alias)]} for the same component; one advisory is ONE "
                              "match with one citation per source")
        cited = set()
        for number, citation in enumerate(match["citations"], 1):
            where = f"{label} citations[{number}]"
            kind = citation["database"]["database_kind"]
            errors += _database_block_errors(where, citation["database"], expected_databases)
            if citation["advisory_id"] not in aliases:
                errors.append(f"alias-set-invalid: {where}: advisory_id is not one of the match's aliases")
            if (kind, citation["advisory_id"]) in cited:
                errors.append(f"duplicate-record: {where}: repeats a (database, advisory) pair of this match")
            cited.add((kind, citation["advisory_id"]))
            if kind not in entry["evaluated_by"]:
                errors.append(f"citation-database-not-evaluated: {where}: database {kind!r} is not in the component's evaluated_by")
            basis = citation["match_basis"]
            if component[basis] is None or (kind == "osv" and basis != "purl"):
                errors.append(f"match-basis-unsupported: {where}: match_basis {basis!r} needs that identifier on the SBOM "
                              "component, and an osv citation is always 'purl'")
    for position, entry in enumerate(result["evaluated"], 1):
        if entry["component_ref"] in evaluated and (entry["outcome"] == "advisory-matched") != (entry["component_ref"] in matched):
            errors.append(f"outcome-mismatch: evaluated[{position}]: outcome must be 'advisory-matched' exactly when a match "
                          "names the component")

    gaps = gap_document["gaps"]
    errors += _ordinal_errors("gaps", "VG", [gap["gap_id"] for gap in gaps])
    gap_refs: set[str] = set()
    for position, gap in enumerate(gaps, 1):
        label = f"VG-{position:06d}"
        component = components.get(gap["component_ref"])
        if component is None:
            errors.append(f"component-unresolved: {label}: component_ref is not a component of the bound SBOM")
            continue
        if gap["component_ref"] in gap_refs:
            errors.append(f"duplicate-record: {label}: repeats the component_ref of an earlier gap")
        gap_refs.add(gap["component_ref"])
        if gap["ecosystem"] != component["ecosystem"]:
            errors.append(f"gap-ecosystem-mismatch: {label}: ecosystem must be the bound SBOM component's")
        reason = required_gap_reason(component)
        if reason is not None and gap["reason"] != reason:
            errors.append(f"gap-reason-mismatch: {label}: the bound SBOM makes the reason {reason!r}")
        if reason is None and (gap["reason"] != "matcher-did-not-complete" or state.all_instances_ok):
            errors.append(f"gap-reason-mismatch: {label}: an evaluable component is a gap only as 'matcher-did-not-complete', "
                          "and only while a tool instance did not end OK")

    both = sorted(set(evaluated) & gap_refs)
    if both:
        errors.append(f"component-in-two-sets: {len(both)} component(s) are both evaluated and a coverage gap "
                      f"(first {both[0]}); the two sets partition the SBOM")
    missing = [component_id for component_id in components if component_id not in evaluated and component_id not in gap_refs]
    if missing:
        errors.append(f"component-unaccounted: {len(missing)} component(s) of the bound SBOM are neither evaluated nor a "
                      f"coverage-gap record (first {missing[0]}); an uncovered component needs an explicit gap record")

    derived = [{"ecosystem": ecosystem, "reason": reason, "count": count} for ecosystem, reason, count in gap_summary_counts(gaps)]
    wanted = {"component_count": len(components), "evaluated_count": len(result["evaluated"]), "gap_count": len(gaps),
              "counts": derived}
    for field, value in wanted.items():
        if summary[field] != value:
            errors.append(f"gap-summary-mismatch: {SCA_SUMMARY_FILE} {field} is not what the gap records and the bound SBOM derive")
    if summary["gap_list"]["sha256"] != "sha256:" + hashlib.sha256(state.raw[SCA_GAPS_FILE]).hexdigest():
        errors.append(f"gap-summary-mismatch: {SCA_SUMMARY_FILE} gap_list.sha256 must be the sha256 of {SCA_GAPS_FILE}")
    errors += _unmapped_gap_errors(state, len(gaps), "coverage-gap records")
    return errors


def verify_sca_attempt(attempt_root: Any, *, sbom_attempt_root: Any, expected_sbom: Mapping[str, str],
                       expected_databases: Mapping[str, Mapping[str, str]], max_age: Any, now: datetime,
                       tool_outputs_root: Any, expected_header: Mapping[str, str], expected_dagster_run_id: str,
                       node_status: str, declared_tool_ids: Iterable[str], permitted_node_statuses: Iterable[str],
                       on_unhandled: str, limits: Limits) -> list[str]:
    """Verify one `02-sca-vulnerability-match` attempt against contract `sca-vulnerability-match`."""
    _check_common(attempt_root, tool_outputs_root, expected_header, expected_dagster_run_id, node_status, declared_tool_ids,
                  permitted_node_statuses, on_unhandled, limits)
    _check_root("sbom_attempt_root", sbom_attempt_root)
    _check_expected("expected_sbom", expected_sbom, UPSTREAM_FIELDS)
    _check_databases(expected_databases)
    _check_age_arguments(max_age, now)
    declared, store = list(declared_tool_ids), SchemaStore()
    errors, state = _open_attempt(
        SCA_CONTRACT_ID, attempt_root, tool_outputs_root=tool_outputs_root, expected_header=expected_header,
        expected_dagster_run_id=expected_dagster_run_id, node_status=node_status, declared_tool_ids=declared,
        permitted_node_statuses=permitted_node_statuses, on_unhandled=on_unhandled, limits=limits, store=store)
    if state is None:
        return errors
    for relative in (SCA_RESULT_FILE, SCA_GAPS_FILE, SCA_SUMMARY_FILE):
        errors += _binding_errors(relative, "sbom_binding", state.documents[relative]["sbom_binding"], "sbom", expected_sbom)
    errors += _database_errors(state, expected_databases, max_age, now, declared)
    found, sbom = _load_upstream("sbom", sbom_attempt_root, expected_sbom, expected_header, limits, store)
    errors += found
    if sbom is None:
        return errors
    errors += _sca_errors(state, sbom, expected_databases)
    labelled = [(f"VM-{index:06d}", match) for index, match in enumerate(state.documents[SCA_RESULT_FILE]["matches"], 1)]
    errors += _citation_errors(labelled, CONTRACT_POLICIES[SCA_CONTRACT_ID]["job_id"], state, declared)
    return errors


# ---- license-inventory -----------------------------------------------------------------------------------------

def _license_errors(records: list[dict], sbom: dict) -> list[str]:
    components = {component["component_id"]: component for component in sbom["components"]}
    errors = _ordinal_errors("records", "LI", [record["record_id"] for record in records])
    seen = set()
    for position, record in enumerate(records, 1):
        label = f"LI-{position:06d}"
        source, assertion, reference = record["claim_source"], record["assertion"], record["component_ref"]
        component = components.get(reference) if reference is not None else None
        if reference is not None and component is None:
            errors.append(f"component-unresolved: {label}: component_ref is not a component of the bound SBOM")
            continue
        if (record["expression_state"] == "spdx-expression") != (record["license_expression"] is not None):
            errors.append(f"expression-state-mismatch: {label}: license_expression must be set exactly when expression_state "
                          "is 'spdx-expression'")
        if record["license_expression"] is not None and not spdx_expression_shape_ok(record["license_expression"]):
            errors.append(f"license-expression-shape: {label}: license_expression must be licence identifiers joined by "
                          "AND, OR or WITH with balanced parentheses; two identifiers side by side is prose, and this "
                          "contract records no legal conclusion")
        if assertion == "copyright-statement-detected" and record["expression_state"] != "no-assertion":
            errors.append(f"expression-state-mismatch: {label}: a copyright statement asserts no licence; expression_state must "
                          "be 'no-assertion'")
        if assertion == "vendored-component-inferred":
            if source["kind"] != "found-in-file":
                errors.append(f"claim-source-mismatch: {label}: a vendored component is inferred from a file, never declared in a manifest")
            if component is not None and component["declaration"] == "declared":
                errors.append(f"inferred-promoted-to-declared: {label}: vendored-component-inferred may reference only an "
                              "inferred-vendored SBOM component (or none), never a declared one")
        if source["kind"] == "declared-in-manifest":
            if component is None or component["declaration"] != "declared":
                errors.append(f"claim-source-mismatch: {label}: declared-in-manifest needs a declared SBOM component")
            elif declaration_kind(component["ecosystem"], source["path"]) != "manifest":
                errors.append(f"claim-source-mismatch: {label}: declared-in-manifest needs a manifest file of the component's ecosystem")
        start, end = source["start_line"], source["end_line"]
        if (start is None) != (end is None) or (start is not None and not (
                isinstance(start, int) and isinstance(end, int) and not isinstance(start, bool) and 1 <= start <= end)):
            errors.append(f"claim-source-lines: {label}: start_line and end_line are both null or integers with 1 <= start_line <= end_line")
        key = (assertion, reference, record["license_expression"], source["path"], start, end)
        if key in seen:
            errors.append(f"duplicate-record: {label}: repeats the assertion, component, expression, path and line span of an earlier record")
        seen.add(key)
    return errors


def verify_license_attempt(attempt_root: Any, *, source_root: Any, sbom_attempt_root: Any, expected_sbom: Mapping[str, str],
                           tool_outputs_root: Any, expected_header: Mapping[str, str], expected_dagster_run_id: str,
                           node_status: str, declared_tool_ids: Iterable[str], permitted_node_statuses: Iterable[str],
                           on_unhandled: str, limits: Limits) -> list[str]:
    """Verify one `02-license-scan` attempt directory against contract `license-inventory`."""
    _check_common(attempt_root, tool_outputs_root, expected_header, expected_dagster_run_id, node_status, declared_tool_ids,
                  permitted_node_statuses, on_unhandled, limits)
    for name, value in (("source_root", source_root), ("sbom_attempt_root", sbom_attempt_root)):
        _check_root(name, value)
    _check_expected("expected_sbom", expected_sbom, UPSTREAM_FIELDS)
    declared, store = list(declared_tool_ids), SchemaStore()
    errors, state = _open_attempt(
        LICENSE_CONTRACT_ID, attempt_root, tool_outputs_root=tool_outputs_root, expected_header=expected_header,
        expected_dagster_run_id=expected_dagster_run_id, node_status=node_status, declared_tool_ids=declared,
        permitted_node_statuses=permitted_node_statuses, on_unhandled=on_unhandled, limits=limits, store=store)
    if state is None:
        return errors
    result = state.documents[LICENSE_RESULT_FILE]
    errors += _binding_errors(LICENSE_RESULT_FILE, "sbom_binding", result["sbom_binding"], "sbom", expected_sbom)
    found, sbom = _load_upstream("sbom", sbom_attempt_root, expected_sbom, expected_header, limits, store)
    errors += found
    if sbom is None:
        return errors
    errors += _license_errors(result["records"], sbom)
    labelled = [(f"LI-{index:06d}", record) for index, record in enumerate(result["records"], 1)]
    errors += _citation_errors(labelled, CONTRACT_POLICIES[LICENSE_CONTRACT_ID]["job_id"], state, declared)
    cites = [(label, record["claim_source"]["path"], record["claim_source"]["sha256"],
              record["claim_source"]["end_line"] if isinstance(record["claim_source"]["end_line"], int) else None)
             for label, record in labelled]
    errors += _source_file_errors(Path(source_root).absolute(), cites, limits)
    return errors


# ---- dependency-lifecycle --------------------------------------------------------------------------------------

def _load_table(reference_table_path: Any, expected: Mapping[str, str], limits: Limits, store: SchemaStore) -> tuple[list[str], Any]:
    path = Path(reference_table_path).absolute()
    data = _read_bytes(path.parent, path.name, limits)
    if data is None:
        return ["reference-table-missing: reference_table_path is absent, linked, not a regular file or over max_file_bytes"], None
    if "sha256:" + hashlib.sha256(data).hexdigest() != expected["sha256"]:
        return [f"reference-table-hash-mismatch: the file at reference_table_path does not have the sha256 in "
                f"expected_reference_table ({expected['sha256']!r}); it was not parsed"], None
    try:
        table = _parse(data)
    except (ValueError, RecursionError):
        return ["reference-table-invalid: the reference table is not strict UTF-8 JSON with unique keys"], None
    errors = _schema_errors("reference-table", table, REFERENCE_TABLE_SCHEMA, store)
    if errors:
        return errors, None
    for field in ("table_id", "version", "as_of"):
        if table[field] != expected[field]:
            errors.append(f"reference-table-identity-mismatch: the reference table's {field} must be {expected[field]!r} "
                          "(expected_reference_table)")
    try:
        as_of = date.fromisoformat(table["as_of"])
        keys = set()
        for row in table["rows"]:
            eol = date.fromisoformat(row["eol_date"]) if row["eol_date"] is not None else None
            key = (row["ecosystem"], row["name"], row["cycle"])
            if key in keys or (row["status"] == "end-of-life") != (eol is not None and eol <= as_of):
                raise ValueError("inconsistent row")
            keys.add(key)
        if len({row["row_id"] for row in table["rows"]}) != len(table["rows"]):
            raise ValueError("duplicate row id")
    except ValueError:
        errors.append("reference-table-invalid: rows need unique ids and (ecosystem, name, cycle) keys, real dates, and status "
                      "'end-of-life' exactly when eol_date is on or before as_of")
    return errors, (None if errors else table)


def _lifecycle_errors(state: _Attempt, sbom: dict, inventory: dict, table: dict, expected_table: Mapping[str, str],
                      max_age: Any, now: datetime, declared: list[str]) -> list[str]:
    result, identity = state.documents[LIFECYCLE_RESULT_FILE], state.documents[TABLE_IDENTITY_FILE]
    errors = []
    for relative, block in ((LIFECYCLE_RESULT_FILE + " reference_table", result["reference_table"]), (TABLE_IDENTITY_FILE, identity)):
        for field in TABLE_FIELDS:
            if block[field] != expected_table[field]:
                errors.append(f"reference-table-identity-mismatch: {relative} {field} must be {expected_table[field]!r} "
                              "(expected_reference_table)")
    if identity["row_count"] != len(table["rows"]):
        errors.append(f"reference-table-identity-mismatch: {TABLE_IDENTITY_FILE} row_count is not the table's row count")
    as_of = datetime.combine(date.fromisoformat(table["as_of"]), datetime.min.time(), tzinfo=timezone.utc)
    errors += _age_errors(TABLE_IDENTITY_FILE, identity, as_of, max_age, now, "reference-table")
    wanted = ("reference-table", expected_table["table_id"], expected_table["version"], expected_table["sha256"])
    for tool_id, instance in sorted(state.instances.items()):
        if tool_id in declared and has_validated_output(instance) and wanted not in [
                (item["kind"], item["identity_id"], item["version"], item["sha256"]) for item in instance["identity"]["data_identities"]]:
            errors.append(f"instance-reference-table-mismatch: declared tool {tool_id!r} must list data identity {wanted!r} "
                          "(expected_reference_table)")

    components, entries = sbom["components"], result["entries"]
    errors += _ordinal_errors("entries", "DL", [entry["entry_id"] for entry in entries])
    if [entry["component_ref"] for entry in entries] != [component["component_id"] for component in components]:
        errors.append(f"component-unaccounted: entries must name each of the bound SBOM's {len(components)} component(s) exactly "
                      "once, in SBOM order")
        return errors
    licences: dict[str, list[dict]] = {}
    for record in inventory["records"]:
        if record["component_ref"] is not None and record["assertion"] == "license-text-detected":
            licences.setdefault(record["component_ref"], []).append(
                {"assertion": "license-field-resurfaced", "record_ref": record["record_id"],
                 "license_expression": record["license_expression"]})
    unknown = 0
    for position, (entry, component) in enumerate(zip(entries, components), 1):
        label = f"DL-{position:06d}"
        row = lifecycle_row_for(component, table["rows"])
        cited = entry["table_row"]
        if row is None:
            unknown += 1
            if entry["status"] != "unknown" or cited is not None or entry["assertion"] != "lifecycle-unknown":
                errors.append(f"status-without-table-row: {label}: no row of the reference table matches this component, so "
                              "status must be 'unknown' with table_row null and assertion 'lifecycle-unknown'; absence from the "
                              "table is never 'supported'")
        else:
            wanted_row = {field: row[field] for field in ("row_id", "cycle", "status", "eol_date")}
            if cited != wanted_row or entry["status"] != row["status"] or entry["assertion"] != "reference-table-eol-match":
                errors.append(f"status-table-row-mismatch: {label}: the reference table has a matching row, so table_row must "
                              "cite it exactly, status must be that row's and assertion 'reference-table-eol-match'")
        if entry["resurfaced_licenses"] != licences.get(component["component_id"], []):
            errors.append(f"resurfaced-license-mismatch: {label}: resurfaced_licenses must repeat exactly the licence-text "
                          "records the bound licence inventory holds for this component")
    errors += _unmapped_gap_errors(state, unknown, "'unknown' entries")
    return errors


def verify_lifecycle_attempt(attempt_root: Any, *, sbom_attempt_root: Any, expected_sbom: Mapping[str, str],
                             license_attempt_root: Any, expected_license: Mapping[str, str], reference_table_path: Any,
                             expected_reference_table: Mapping[str, str], max_age: Any, now: datetime,
                             tool_outputs_root: Any, expected_header: Mapping[str, str], expected_dagster_run_id: str,
                             node_status: str, declared_tool_ids: Iterable[str], permitted_node_statuses: Iterable[str],
                             on_unhandled: str, limits: Limits) -> list[str]:
    """Verify one `02-dependency-lifecycle` attempt against contract `dependency-lifecycle`."""
    _check_common(attempt_root, tool_outputs_root, expected_header, expected_dagster_run_id, node_status, declared_tool_ids,
                  permitted_node_statuses, on_unhandled, limits)
    for name, value in (("sbom_attempt_root", sbom_attempt_root), ("license_attempt_root", license_attempt_root),
                        ("reference_table_path", reference_table_path)):
        _check_root(name, value)
    _check_expected("expected_sbom", expected_sbom, UPSTREAM_FIELDS)
    _check_expected("expected_license", expected_license, UPSTREAM_FIELDS)
    _check_expected("expected_reference_table", expected_reference_table, TABLE_FIELDS)
    _check_age_arguments(max_age, now)
    declared, store = list(declared_tool_ids), SchemaStore()
    errors, state = _open_attempt(
        LIFECYCLE_CONTRACT_ID, attempt_root, tool_outputs_root=tool_outputs_root, expected_header=expected_header,
        expected_dagster_run_id=expected_dagster_run_id, node_status=node_status, declared_tool_ids=declared,
        permitted_node_statuses=permitted_node_statuses, on_unhandled=on_unhandled, limits=limits, store=store)
    if state is None:
        return errors
    result = state.documents[LIFECYCLE_RESULT_FILE]
    errors += _binding_errors(LIFECYCLE_RESULT_FILE, "sbom_binding", result["sbom_binding"], "sbom", expected_sbom)
    errors += _binding_errors(LIFECYCLE_RESULT_FILE, "license_binding", result["license_binding"], "license", expected_license)
    loaded = []
    for kind, root, expected in (("sbom", sbom_attempt_root, expected_sbom), ("license", license_attempt_root, expected_license)):
        found, document = _load_upstream(kind, root, expected, expected_header, limits, store)
        errors += found
        loaded.append(document)
    found, table = _load_table(reference_table_path, expected_reference_table, limits, store)
    errors += found
    sbom, inventory = loaded
    if sbom is None or inventory is None or table is None:
        return errors
    errors += [error.replace("upstream-binding-mismatch", "upstream-sbom-mismatch") for error in _binding_errors(
        "the bound licence inventory", "sbom_binding", inventory["sbom_binding"], "sbom", expected_sbom)]
    errors += _lifecycle_errors(state, sbom, inventory, table, expected_reference_table, max_age, now, declared)
    return errors
