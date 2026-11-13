from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tomllib

import pytest

from appsec_review.config.inference_review import DecisionAuditSettings
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.review.decision_audit.contracts import (
    AbsenceReason, AuditManifest, CoverageCount, HashLink, ManifestRef, Origin, Population,
)
from appsec_review.review.decision_audit.metadata import (
    POLICY_VERSION, build_publication, policy_document, read_publication,
)
from appsec_review.review.models import IntegrityError
from appsec_review.runtime.handoff import collect_artifacts
from appsec_review.interchange import UNIT_OUTPUT_KEYS
from appsec_review.storage import canonical_json

ROOT = Path(__file__).resolve().parents[3]
HASH = "a" * 64


def _origin(settings):
    absent = HashLink(None, AbsenceReason.NOT_PRODUCED)
    return Origin("run-1", "attempt-1", HASH, HASH, HASH, HASH, HASH, HASH,
                  HashLink(HASH, None), HASH, absent, absent, POLICY_VERSION,
                  policy_document(settings)["sha256"])


def _available():
    settings = DecisionAuditSettings(enabled=True)
    origin = _origin(settings)
    coverage = tuple(CoverageCount(population, 0, 0, 0, 0, None) for population in Population)
    manifest = AuditManifest(origin, (), coverage)
    reference = ManifestRef.of(
        "data/jobs/job_inference_security_review/attempts/attempt-1/artifacts/decision-audit/manifest.json",
        manifest,
    )
    return settings, origin, reference


@pytest.fixture
def schemas():
    result = SchemaSet(ROOT / SCHEMA_DIRECTORY)
    for name in ("review-decision-audit", "review-audit-publication"):
        result.documents[f"{name}.schema.json"] = json.loads(
            (ROOT / "docs/schemas" / f"{name}.schema.json").read_text())
    return result


def test_available_publication_is_policy_bound_and_schema_valid(schemas):
    settings, origin, reference = _available()
    document = build_publication(origin, settings=settings, manifest=reference)
    schemas.validate("review-audit-publication", document)
    loaded = read_publication(document, expected_origin=origin, settings=settings)
    assert loaded.origin == origin
    assert loaded.manifest == reference
    assert loaded.settings == settings
    assert loaded.unavailable_reason is None


@pytest.mark.parametrize("reason", ["disabled", "capacity_exceeded", "input_unavailable"])
def test_unavailable_is_explicit_and_never_an_empty_complete_audit(reason, schemas):
    settings = DecisionAuditSettings(enabled=reason != "disabled")
    origin = _origin(settings)
    document = build_publication(origin, settings=settings, unavailable_reason=reason)
    schemas.validate("review-audit-publication", document)
    loaded = read_publication(document, expected_origin=origin, settings=settings)
    assert loaded.manifest is None
    assert loaded.unavailable_reason == reason


@pytest.mark.parametrize("mutation", [
    "extra", "missing", "schema", "origin", "policy-extra", "policy-missing",
    "policy-hash", "policy-version", "policy-setting", "policy-bool-int",
    "status", "available-reason", "available-no-manifest", "unavailable-manifest",
    "unavailable-reason", "wrong-origin-policy", "wrong-origin-version", "manifest-origin",
], ids=str)
def test_malformed_or_foreign_metadata_fails(mutation):
    settings, origin, reference = _available()
    document = deepcopy(build_publication(origin, settings=settings, manifest=reference))
    expected = origin
    if mutation == "extra":
        document["raw_prompt"] = "not accepted"
    elif mutation == "missing":
        del document["policy"]
    elif mutation == "schema":
        document["schema"] = "other/1"
    elif mutation == "origin":
        document["origin"]["run_id"] = "foreign"
    elif mutation == "policy-extra":
        document["policy"]["unused"] = True
    elif mutation == "policy-missing":
        del document["policy"]["settings"]
    elif mutation == "policy-hash":
        document["policy"]["sha256"] = "b" * 64
    elif mutation == "policy-version":
        document["policy"]["version"] = "future/1"
    elif mutation == "policy-setting":
        document["policy"]["settings"]["max_records"] -= 1
    elif mutation == "policy-bool-int":
        document["policy"]["settings"]["enabled"] = 1
    elif mutation == "status":
        document["status"] = "success"
    elif mutation == "available-reason":
        document["unavailable_reason"] = "input_unavailable"
    elif mutation == "available-no-manifest":
        document["manifest"] = None
    elif mutation == "unavailable-manifest":
        document["status"] = "unavailable"
        document["unavailable_reason"] = "input_unavailable"
    elif mutation == "unavailable-reason":
        document["status"] = "unavailable"
        document["manifest"] = None
        document["unavailable_reason"] = "clean"
    elif mutation == "wrong-origin-policy":
        expected = replace(origin, projection_policy_sha256="b" * 64)
    elif mutation == "wrong-origin-version":
        expected = replace(origin, projection_policy_version="future/1")
    else:
        document["manifest"]["origin"]["run_id"] = "foreign"
    with pytest.raises(IntegrityError):
        read_publication(document, expected_origin=expected, settings=settings)


@pytest.mark.parametrize("value", [None, [], "metadata", 1])
def test_non_mapping_metadata_fails(value):
    settings = DecisionAuditSettings()
    with pytest.raises(IntegrityError, match="invalid fields"):
        read_publication(value, expected_origin=_origin(settings), settings=settings)


@pytest.mark.parametrize("value", [None, [], "policy"])
def test_non_mapping_policy_fails(value):
    settings, origin, reference = _available()
    document = build_publication(origin, settings=settings, manifest=reference)
    document["policy"] = value
    with pytest.raises(IntegrityError, match="policy disagrees"):
        read_publication(document, expected_origin=origin, settings=settings)


def test_policy_hash_covers_version_and_exact_audit_settings():
    settings = DecisionAuditSettings(enabled=True)
    policy = policy_document(settings)
    assert policy["sha256"] == hashlib.sha256(
        canonical_json({"version": policy["version"], "settings": policy["settings"]})).hexdigest()
    assert policy_document(replace(settings, max_records=99999))["sha256"] != policy["sha256"]
    assert policy_document(replace(settings, page_size=49))["sha256"] != policy["sha256"]


def test_published_schema_assets_are_in_the_distribution_manifest():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assets = project["tool"]["setuptools"]["data-files"]["share/appsec-review/schemas"]
    for path in ("docs/schemas/review-decision-audit.schema.json",
                 "docs/schemas/review-audit-publication.schema.json"):
        assert path in assets
        assert (ROOT / path).is_file()


def test_missing_policy_settings_are_not_legacy_defaults():
    settings = DecisionAuditSettings()
    origin = _origin(settings)
    document = build_publication(origin, settings=settings, unavailable_reason="disabled")
    document["policy"]["settings"] = None
    with pytest.raises(IntegrityError, match="policy disagrees"):
        read_publication(document, expected_origin=origin, settings=settings)


def test_disabled_and_enabled_unavailability_cannot_be_confused():
    disabled = DecisionAuditSettings()
    enabled = replace(disabled, enabled=True)
    with pytest.raises(IntegrityError):
        build_publication(_origin(disabled), settings=disabled, unavailable_reason="input_unavailable")
    with pytest.raises(IntegrityError):
        build_publication(_origin(enabled), settings=enabled, unavailable_reason="disabled")
    with pytest.raises(IntegrityError):
        build_publication(_origin(enabled), settings=enabled)


def test_existing_control_projection_and_artifact_collection_preserve_metadata(tmp_path):
    settings, origin, reference = _available()
    document = build_publication(origin, settings=settings, manifest=reference)
    relative = (
        "data/jobs/job_inference_security_review/attempts/attempt-1/artifacts/"
        "decision-audit/publication.json"
    )
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    data = canonical_json(document)
    path.write_bytes(data)
    artifact = {"path": relative, "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data)}
    output = {"metadata_path": relative, "audit_metadata_artifact": artifact}
    control = {key: output[key] for key in UNIT_OUTPUT_KEYS if key in output}
    assert control == {"metadata_path": relative}
    assert collect_artifacts(tmp_path, control) == []
    assert collect_artifacts(tmp_path, output) == [artifact]
    path.write_bytes(b"{}")
    with pytest.raises(ValueError):
        collect_artifacts(tmp_path, output)
