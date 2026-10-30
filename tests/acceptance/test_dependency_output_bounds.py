"""Acceptance: npm dependency output stays bounded in a completed review run.

Point ``APPSEC_ACCEPTANCE_RUN_ROOT`` at a completed run root (``runs/<run-id>``) and select this file
explicitly; it skips when the variable is unset. It only reads accepted handoffs and the accepted
artifact-security observations shard. Installer-record scan checks skip a run whose artifact-security
publication predates ``installer_records``.

    APPSEC_ACCEPTANCE_RUN_ROOT=runs/<run-id> python -m pytest \
        tests/acceptance/test_dependency_output_bounds.py --basetemp=test/tmp/dof-acceptance
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from contextlib import closing
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
from typing import Any

import pytest

from appsec_review.jobs.delivery_scope import scope_fields
from appsec_review.jobs.job_artifact_indexing.job import load_accepted_artifact_index
from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.retrieval import EntityKind, LogicalIdentity, RelationKind
from appsec_review.retrieval.index import load_verified_manifest


RUN_ROOT_ENV = "APPSEC_ACCEPTANCE_RUN_ROOT"
DISPOSITIONS_SCHEMA = "appsec-review/build-output-dispositions/1"
PACKAGE_ROLE = "installed-dependency-package"
RECORD_ROLE = "installed-dependency-record"
RECORD_METADATA = {"format": ".package-lock.json", "manager": "npm", "role": RECORD_ROLE}
RECORD_PRESENTATION = "appsec-review/npm-installed-record-as-package-lock/1"
COVERED = "INSTALLER_RECORD_COVERED"
RECORD_SCANNERS = ("syft", "grype", "osv")
ATTRIBUTIONS = {"verified-anchor", "unverified-record-entry"}
_INSTALLED_ROLES = {"build_dependency", "runtime_dependency", "shipped_dependency", "deliverable"}
_NATIVE_KINDS = {"executable", "shared-library", "native-addon", "native-extension"}


@pytest.fixture(scope="module")
def run_root() -> Path:
    value = os.environ.get(RUN_ROOT_ENV)
    if not value:
        pytest.skip(f"{RUN_ROOT_ENV} is unset; this acceptance check needs a completed run root")
    root = Path(value).resolve()
    assert root.is_dir(), f"{RUN_ROOT_ENV} is not a run directory: {root}"
    return root


@pytest.fixture(scope="module")
def receipts(run_root: Path) -> list[Mapping[str, Any]]:
    accepted = load_accepted_language_build(run_root)
    return [receipt for receipt in accepted.get("receipts", ())
            if receipt.get("terminal_status") in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}]


def _under(path: str, root: str) -> bool:
    return root in {"", "."} or PurePosixPath(path).is_relative_to(PurePosixPath(root))


def _roots(receipt: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    document = receipt.get("build_output_dispositions")
    if document is None:
        return []
    assert document.get("schema") == DISPOSITIONS_SCHEMA, document.get("schema")
    return list(document.get("roots", ()))


def _deepest(path: str, roots: Iterable[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """The deepest registered root decides a path's disposition, as the recorder does."""
    covering = [root for root in roots if _under(path, str(root["root"]))]
    return max(covering, key=lambda root: len(PurePosixPath(str(root["root"])).parts), default=None)


def _installer_tree(path: str, roots: list[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    root = _deepest(path, roots)
    if root and root.get("basis") == "installer-record" and root.get("disposition") == "supply_chain":
        return root
    return None


def _role(row: Mapping[str, Any], field: str) -> str | None:
    metadata = row.get(field)
    return metadata.get("role") if isinstance(metadata, Mapping) else None


def test_no_unknown_row_lies_inside_an_installer_record_tree(receipts) -> None:
    leaked = []
    for receipt in receipts:
        roots = _roots(receipt)
        packages = [row for row in receipt.get("artifacts", ())
                    if _role(row, "package_metadata") == PACKAGE_ROLE]
        assert roots or not packages, (
            f"{receipt.get('build_unit_id')}: package rows without build_output_dispositions")
        for row in receipt.get("artifacts", ()):
            path = str(row["workspace_path"])
            if scope_fields(row)["scope_role"] == "unknown" and _installer_tree(path, roots):
                leaked.append(f"{receipt.get('build_unit_id')}: {path}")
    assert not leaked, leaked[:50]


def test_installer_record_trees_publish_only_anchors_and_retained_rows(receipts) -> None:
    summarized = []
    for receipt in receipts:
        roots = _roots(receipt)
        for row in receipt.get("artifacts", ()):
            path = str(row["workspace_path"])
            tree = _installer_tree(path, roots)
            if tree is None:
                continue
            # Accepted npm-pack members keep their delivery upgrade (pack precedence).
            assert scope_fields(row)["scope_role"] in _INSTALLED_ROLES, (path, row.get("scope_role"))
            if path not in set(tree.get("kept", ())):
                summarized.append(f"{receipt.get('build_unit_id')}: {path}")
        for tree in roots:
            if tree.get("basis") == "installer-record" and tree.get("disposition") == "supply_chain":
                anchor = f"{tree['root']}/package.json"
                assert anchor in set(tree.get("kept", ())), (tree["root"], "manifest anchor not kept")
    assert not summarized, summarized[:50]


def test_artifact_index_count_is_bounded_by_the_classified_catalog(run_root: Path, receipts) -> None:
    index = load_accepted_artifact_index(run_root)
    classified = {"target": 0, "package": 0, "record": 0, "retained": 0, "other": 0}
    for receipt in receipts:
        roots = _roots(receipt)
        for row in receipt.get("artifacts", ()):
            path = str(row["workspace_path"])
            if _role(row, "package_metadata") == PACKAGE_ROLE:
                classified["package"] += 1
            elif _role(row, "dependency_metadata") == RECORD_ROLE:
                classified["record"] += 1
            elif _installer_tree(path, roots):
                classified["retained"] += 1
            elif scope_fields(row)["analysis_lane"] == "target":
                classified["target"] += 1
            else:
                classified["other"] += 1
    bound = sum(classified.values()) + len(index.get("target_artifacts", ()))
    assert index["artifact_count"] <= bound, (index["artifact_count"], classified)


def test_blint_reviews_production_dependency_binaries_but_not_build_only_ones(run_root: Path) -> None:
    """Production dependency machine code reaches blint; build-only dependency rows never do."""
    from appsec_review.jobs.job_artifact_security_analysis import job as security

    analysis = security.load_accepted_artifact_security_analysis(run_root)
    dispositions = analysis["capabilities"]["blint"].get("scope_dispositions")
    if dispositions is None:
        pytest.skip("this run's artifact-security publication predates blint scope dispositions")
    artifacts = {row["artifact_id"]: row for row in security._accepted_artifacts(run_root)["artifacts"]}
    wrong = []
    for disposition in dispositions:
        artifact = artifacts[disposition["artifact_id"]]
        role, lane = disposition["scope_role"], disposition["analysis_lane"]
        expected = lane == "target" or (role == "runtime_dependency" and artifact.get("kind") in _NATIVE_KINDS)
        if disposition["selected"] is not expected:
            wrong.append((artifact.get("workspace_path"), role, artifact.get("kind"), disposition["selected"]))
    assert not wrong, wrong[:50]


@pytest.fixture(scope="module")
def record_scans(run_root: Path) -> Mapping[str, Any]:
    """Installer records, their D2-matched anchors, and the artifact-security observations."""
    from appsec_review.jobs.job_artifact_security_analysis import job as security

    analysis = security.load_accepted_artifact_security_analysis(run_root)
    capabilities = {capability: analysis["capabilities"][capability] for capability in RECORD_SCANNERS
                    if (analysis["capabilities"].get(capability) or {}).get("installer_records") is not None}
    if not capabilities:
        pytest.skip("this run's artifact-security publication predates installer_records")
    artifacts = {row["artifact_id"]: row for row in security._accepted_artifacts(run_root)["artifacts"]}
    records = {(_build_unit(row), row["workspace_path"], row["sha256"]): row for row in artifacts.values()
               if row.get("dependency_metadata") == RECORD_METADATA}
    anchors: dict[str, tuple[Mapping[str, Any], Mapping[str, Any]]] = {}
    for row in artifacts.values():
        evidence = row.get("delivery_evidence")
        if _role(row, "package_metadata") != PACKAGE_ROLE or not isinstance(evidence, Mapping):
            continue
        if evidence.get("kind") != "npm-installed-record":
            continue
        record = records.get((_build_unit(row), evidence.get("workspace_path"), evidence.get("sha256")))
        if record is not None:
            anchors[row["artifact_id"]] = (row, record)
    return {"capabilities": capabilities, "artifacts": artifacts,
            "records": {row["artifact_id"]: row for row in records.values()}, "anchors": anchors,
            "observations": _observations(run_root, analysis)}


def _build_unit(row: Mapping[str, Any]) -> str:
    return str(row.get("build_unit_id") or (row.get("producer") or {}).get("build_unit_id") or "")


def _observations(run_root: Path, analysis: Mapping[str, Any]) -> list[tuple[Mapping[str, Any], set[str]]]:
    """(payload, OBSERVED_AT targets) for every tool observation in the artifact-security shard."""
    raw = analysis["index_manifest"]
    manifest, _ = load_verified_manifest(run_root, run_root / raw["path"], raw["sha256"])
    [shard] = [item for item in manifest["indexes"]
               if item["name"] == "observations" and item.get("shard_id") == "artifact-security"]
    path = run_root / shard["relative_path"]
    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True)) as database:
        payloads = {identity: json.loads(payload) for identity, payload in database.execute(
            "SELECT identity, payload_json FROM entities WHERE kind = ?", (EntityKind.TOOL_OBSERVATION.value,))}
        targets: dict[str, set[str]] = {}
        for source, target in database.execute(
                "SELECT source_id, target_id FROM relations WHERE kind = ?", (RelationKind.OBSERVED_AT.value,)):
            targets.setdefault(source, set()).add(target)
    return [(payload, targets.get(identity, set())) for identity, payload in payloads.items()]


def _scanned(record_scans: Mapping[str, Any], capability: str) -> list[str]:
    """Canonical identities of the artifacts ``capability`` produced a scan summary for."""
    return [str((payload.get("artifact") or {}).get("canonical_identity"))
            for payload, _ in record_scans["observations"]
            if payload.get("record_kind") == "scan_summary" and payload.get("capability") == capability]


def _dispositions(summary: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {item["artifact_id"]: item for item in summary.get("scope_dispositions") or ()}


def _covering(summary: Mapping[str, Any], record_id: str) -> bool:
    """The record passed the capability's lane gate and format partition (design D2)."""
    item = _dispositions(summary).get(record_id)
    return bool(item and item.get("selected") and item.get("input_disposition") is None)


def test_syft_and_grype_never_launch_on_an_anchor_whose_record_is_scanned(record_scans) -> None:
    wrong, launched = [], []
    for capability in ("syft", "grype"):
        summary = record_scans["capabilities"].get(capability)
        if summary is None:
            continue
        dispositions = _dispositions(summary)
        scanned = set(_scanned(record_scans, capability))
        for anchor_id, (anchor, record) in record_scans["anchors"].items():
            if not _covering(summary, record["artifact_id"]):
                continue  # Fail-open: an uncovered anchor is scanned as itself.
            item = dispositions.get(anchor_id)
            if item is None or not item.get("selected"):
                continue  # The lane gate excluded it before the installer-record rule.
            if (item.get("input_reason_code") != COVERED or item.get("input_disposition") != "SKIPPED_NA"
                    or item.get("input_covered_by") != record["artifact_id"]
                    or item.get("input_evidence_ref") !=
                    f"{record['workspace_path']}#{anchor['delivery_evidence'].get('entry')}"):
                wrong.append((capability, anchor["workspace_path"], item.get("input_reason_code")))
            if anchor["canonical_identity"] in scanned:
                launched.append((capability, anchor["workspace_path"]))
    assert not wrong, wrong[:50]
    assert not launched, launched[:50]


def test_each_installer_record_is_scanned_at_most_once_and_summarized(record_scans) -> None:
    problems = []
    for capability, summary in record_scans["capabilities"].items():
        entries = [entry for entry in summary["installer_records"]]
        ids = [entry["artifact_id"] for entry in entries]
        assert ids == sorted(set(ids)), (capability, ids)
        by_id = dict(zip(ids, entries))
        assert set(by_id) <= set(record_scans["records"]), (capability, sorted(set(by_id) - set(record_scans["records"])))
        dispositions = _dispositions(summary)
        scanned = _scanned(record_scans, capability)
        for record_id, record in record_scans["records"].items():
            launches = scanned.count(str(record["canonical_identity"]))
            if launches > 1:
                problems.append((capability, record["workspace_path"], f"{launches} scans"))
            if not _covering(summary, record_id):
                continue
            entry = by_id.get(record_id)
            if entry is None:
                problems.append((capability, record["workspace_path"], "no installer_records entry"))
                continue
            if (entry["workspace_path"], entry["sha256"], entry["presentation"]) != (
                    record["workspace_path"], record["sha256"], RECORD_PRESENTATION):
                problems.append((capability, record["workspace_path"], "entry identity differs"))
            covered = sum(1 for item in dispositions.values()
                          if item.get("input_reason_code") == COVERED and item.get("input_covered_by") == record_id)
            if entry["anchors_covered"] != (0 if capability == "osv" else covered):
                problems.append((capability, record["workspace_path"], "anchors_covered", entry["anchors_covered"]))
            if ("anchors_reported" in entry) is not (capability == "syft"):
                problems.append((capability, record["workspace_path"], "anchors_reported presence"))
            matched = sum(1 for _, owner in record_scans["anchors"].values() if owner["artifact_id"] == record_id)
            if entry["scan_outcome"] == "not_completed":
                gap = (f"{record_id}: {capability}: installer record scan of {record['workspace_path']} did not "
                       f"complete; {matched} verified packages recorded there have no {capability} coverage")
                if gap not in summary["gaps"]:
                    problems.append((capability, record["workspace_path"], "missing did-not-complete gap"))
            elif entry["scan_outcome"] not in {"completed", "completed_with_gaps"}:
                problems.append((capability, record["workspace_path"], entry["scan_outcome"]))
            if capability == "grype" and entry["dev_anchors"]:
                gap = (f"{record_id}: grype: {entry['dev_anchors']} dev-only packages recorded by "
                       f"{record['workspace_path']} are not vulnerability-matched by the pinned grype "
                       "(npm dev entries excluded); osv-scanner scans the same record")
                if gap not in summary["gaps"]:
                    problems.append((capability, record["workspace_path"], "missing dev-only gap"))
    assert not problems, problems[:50]


def test_vulnerability_findings_at_an_installer_record_carry_attribution(record_scans) -> None:
    by_canonical = {str(row["canonical_identity"]): row for row in record_scans["records"].values()}
    anchor_entities = {row["artifact_id"]: LogicalIdentity.parse(str(row["canonical_identity"])).value
                       for row, _ in record_scans["anchors"].values()}
    wrong = []
    for payload, targets in record_scans["observations"]:
        if payload.get("record_kind") != "finding" or payload.get("capability") not in {"grype", "osv"}:
            continue
        record = by_canonical.get(str((payload.get("artifact") or {}).get("canonical_identity")))
        if record is None:
            continue
        subject = (payload["capability"], record["workspace_path"], payload.get("subject"))
        attribution = payload.get("installed_package_attribution")
        if attribution not in ATTRIBUTIONS:
            wrong.append((*subject, attribution))
            continue
        own = {anchor_id for anchor_id, (_, owner) in record_scans["anchors"].items()
               if owner["artifact_id"] == record["artifact_id"]}
        if attribution == "unverified-record-entry":
            if "installed_packages" in payload or targets & {anchor_entities[item] for item in own}:
                wrong.append((*subject, "unverified entry attributed to an anchor"))
            continue
        described = [item.get("artifact_id") for item in payload.get("installed_packages") or ()]
        if not described or not set(described) <= own:
            wrong.append((*subject, "verified attribution names no anchor of this record"))
        elif not {anchor_entities[item] for item in described} <= targets:
            wrong.append((*subject, "verified anchor lacks an OBSERVED_AT relation"))
    assert not wrong, wrong[:50]


def test_syft_launches_are_bounded_by_uncovered_rows_and_records(record_scans) -> None:
    for capability in ("syft", "grype"):
        summary = record_scans["capabilities"].get(capability)
        if summary is None:
            continue
        covered = sum(1 for _, record in record_scans["anchors"].values()
                      if _covering(summary, record["artifact_id"]))
        # Uncovered rows (records included) are the only rows left for a per-artifact launch.
        bound = len(record_scans["artifacts"]) - covered
        assert summary["observation_count"] <= bound, (capability, summary["observation_count"], bound, covered)
