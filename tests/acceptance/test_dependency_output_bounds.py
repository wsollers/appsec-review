"""Acceptance: npm dependency output stays bounded in a completed review run.

Point ``APPSEC_ACCEPTANCE_RUN_ROOT`` at a completed run root (``runs/<run-id>``) and select this file
explicitly; it skips when the variable is unset. It only reads accepted handoffs.

    APPSEC_ACCEPTANCE_RUN_ROOT=runs/<run-id> python -m pytest \
        tests/acceptance/test_dependency_output_bounds.py --basetemp=test/tmp/dof-acceptance
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import os
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from appsec_review.jobs.delivery_scope import scope_fields
from appsec_review.jobs.job_artifact_indexing.job import load_accepted_artifact_index
from appsec_review.jobs.job_language_build import load_accepted_language_build


RUN_ROOT_ENV = "APPSEC_ACCEPTANCE_RUN_ROOT"
DISPOSITIONS_SCHEMA = "appsec-review/build-output-dispositions/1"
PACKAGE_ROLE = "installed-dependency-package"
RECORD_ROLE = "installed-dependency-record"
_INSTALLED_ROLES = {"build_dependency", "runtime_dependency", "shipped_dependency", "deliverable"}


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
