"""T-5013: the ingested catalogs name no component roles; the workbench derives them per ASVS chapter.

The upstream ASVS 5.0 JSON and MASVS Markdown carry no role metadata, so ``acquisition.normalize`` stores
``component_roles: []`` and the pinned normalized-records hash forbids editing the catalog. ``control_records``
derives the roles from ``standards.ASVS_CHAPTER_ROLES`` and records the basis; a control no map covers is
``unsupported_missing_evidence``, never hidden as ``not_applicable``.
"""
from __future__ import annotations

from pathlib import Path
import tomllib

import pytest

from appsec_review.owasp_workbench import build_applicability, classify_components, control_records, load_catalogs, select_profiles
from appsec_review.owasp_workbench import engine, standards
from tests.unit.job_owasp_control_assessment.test_network_service_class import NETWORK_SERVICE, component, routing

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def catalogs():
    document = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    return load_catalogs(ROOT, document["jobs"]["job_owasp_control_assessment"]["settings"]["standards"])


def test_pinned_catalogs_carry_no_roles_and_every_control_gets_derived_ones(catalogs) -> None:
    assert all(not record.get("component_roles") for record in catalogs["ASVS"].records)
    assert all(not record.get("component_roles") for record in catalogs["MASVS"].records)
    controls = control_records(catalogs, asvs_level=3, masvs_profile="L2")
    assert controls and all(control["component_roles"] for control in controls)
    for control in controls:
        if control["family"] == "ASVS":
            chapter = engine.chapter_of(control["id"])
            assert control["component_roles"] == list(standards.ASVS_CHAPTER_ROLES[chapter])
            assert control["component_roles_basis"] == "derived:asvs-chapter-roles/1"
        else:
            assert control["component_roles"] == ["android_mobile", "ios_mobile"]
            assert control["component_roles_basis"] == "derived:masvs-roles/1"
    assert set(standards.ASVS_CHAPTER_ROLES) == {engine.chapter_of(c["id"]) for c in catalogs["ASVS"].records}
    assert {role for roles in standards.ASVS_CHAPTER_ROLES.values() for role in roles} <= engine.COMPONENT_ROLES
    for chapter in engine.FAMILY_PARTIAL_TARGET_CLASSES["ASVS"]["target:network-service"]:
        assert "network" in standards.ASVS_CHAPTER_ROLES[chapter]


def test_catalog_roles_are_kept_when_present() -> None:
    assert standards.derived_roles("ASVS", "V99.1.1") == ([], "none")
    assert standards.derived_roles("ASVS", "V1.4.1") == (list(standards.ASVS_CHAPTER_ROLES["V1"]), "derived:asvs-chapter-roles/1")
    assert standards.derived_roles("MASVS", "MASVS-NETWORK-1") == (["android_mobile", "ios_mobile"], "derived:masvs-roles/1")


def test_qualification_routes_real_catalog_controls_by_derived_roles(catalogs) -> None:
    web = [routing("mechanism:http", "declared"), routing("target:web-api")]
    [classification] = classify_components([component("api", web)])
    rows = build_applicability(catalogs, [classification], select_profiles(catalogs, asvs_level=2, masvs_profile="L2"))
    asvs = [row for row in rows if row["standard"] == "ASVS"]
    assert asvs and all(row["rule_version"] == "applicability-rules/4" for row in rows)
    served = {"application_api_server", "network"}
    for row in asvs:
        routed = served & set(standards.ASVS_CHAPTER_ROLES[engine.chapter_of(row["control_id"])])
        # Routed chapters are applicable; a chapter routed only to other roles is positively not applicable.
        assert row["outcome"] == ("applicable" if routed else "not_applicable"), (row["control_id"], row["reason"])
    assert {row["outcome"] for row in asvs if engine.chapter_of(row["control_id"]) == "V1"} == {"applicable"}
    assert {row["outcome"] for row in asvs if engine.chapter_of(row["control_id"]) == "V11"} == {"not_applicable"}


def test_network_service_roles_intersect_every_admitted_chapter(catalogs) -> None:
    [classification] = classify_components([component("srv", NETWORK_SERVICE)])
    rows = build_applicability(catalogs, [classification], select_profiles(catalogs, asvs_level=2, masvs_profile="L2"))
    admitted = [row for row in rows if row["standard"] == "ASVS"
                and engine.chapter_of(row["control_id"]) in {"V1", "V2", "V5", "V7", "V16"}]
    assert admitted and {row["outcome"] for row in admitted} == {"applicable"}


def test_a_control_without_derivable_role_is_unresolved_not_hidden(catalogs, monkeypatch) -> None:
    original = engine.control_records

    def roleless(*args, **kwargs):
        return tuple({**control, "component_roles": [], "component_roles_basis": "none"} for control in original(*args, **kwargs))

    monkeypatch.setattr(engine, "control_records", roleless)
    web = [routing("mechanism:http", "declared"), routing("target:web-api")]
    [classification] = classify_components([component("api", web)])
    rows = build_applicability(catalogs, [classification], select_profiles(catalogs, asvs_level=2, masvs_profile="L2"))
    asvs = [row for row in rows if row["standard"] == "ASVS"]
    assert {row["outcome"] for row in asvs} == {"unsupported_missing_evidence"}
    assert all(row["reason"].startswith("no control role is derivable for this control") and row["gaps"] for row in asvs)
