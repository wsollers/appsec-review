"""First-party review scope (T-150) and the stylistic lead filter (T-152).

The fixture's opt-in ``third_party`` trees carry a high Semgrep lead and a high cppcheck lead; first-party
``native/src/parse.c`` carries a cppcheck ``style`` row and a cppcheck ``warning``. With the repository's
default dispositions and lead filters, no lead, unit or hunt package reaches ``third_party/``, every excluded
lead is listed as ``not_admitted`` with its disposition or ``stylistic`` reason (never a gap), the dependency
inventory is untouched, and the manifest counts show what was left out. Without a policy every file is
first-party, so the same fixture proves the contrast.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.review.dispositions import DISPOSITIONS, FIRST_PARTY, SourceDispositions
from appsec_review.review.lead_families import EXCLUSION_REASONS, ExcludedLead, LeadCollection, collect_leads
from appsec_review.review.lead_filters import LeadFilters
from appsec_review.review.models import IntegrityError
from appsec_review.review.packages import PackageSettings, _Assembler, assemble_packages, publish_packages
from appsec_review.review.scope import accept_manifest
from appsec_review.review.units import build_units, rank_units
from tests.fixtures.inference_review.builder import THIRD_PARTY_FILES, build_accepted_index_set

ROOT = Path(__file__).resolve().parents[2]
VENDORED = tuple(sorted(THIRD_PARTY_FILES))
VENDORED_LEADS = ("sast_vendored_high", "cppcheck_vendored_high", "cppcheck_vendored_style")
STYLISTIC_LEADS = ("cppcheck_style",)
SETTINGS = PackageSettings(hunt_max_units=8)


@pytest.fixture(scope="module")
def review_settings():
    return load_config(ROOT / "appsec-review.toml").job("job_inference_security_review").typed_settings


@pytest.fixture(scope="module")
def fixture(tmp_path_factory):
    return build_accepted_index_set(tmp_path_factory.mktemp("first-party"), third_party=True)


@pytest.fixture(scope="module")
def scoped(fixture, review_settings):
    """The scope under the repository's default dispositions and its lead collection under the default filters."""
    scope = accept_manifest(fixture.run_root, dispositions=review_settings.source_dispositions)
    return scope, collect_leads(scope, filters=review_settings.lead_filters)


@pytest.fixture(scope="module")
def unscoped(fixture):
    scope = accept_manifest(fixture.run_root)
    return scope, collect_leads(scope)


def _ids(fixture, keys) -> set[str]:
    return {fixture.ids[key] for key in keys}


def _hunt_menu_ids(assembly) -> set[str]:
    return {entry["observation_id"] for item in assembly.packages if item.kind == "hunt"
            for entry in item.document()["lead_menu"]}


# --------------------------------------------------------------------------------------------- dispositions


def test_every_accepted_source_file_carries_exactly_one_disposition(scoped, unscoped) -> None:
    scope, _ = scoped
    by_path = {item.path: item.disposition for item in scope.source_files}
    assert {by_path[path] for path in VENDORED} == {"vendored"}
    assert by_path["native/src/parse.c"] == FIRST_PARTY and by_path[".github/workflows/ci.yml"] == FIRST_PARTY
    assert set(by_path.values()) <= set(DISPOSITIONS)
    assert scope.disposition_for("native/third_party/lz4/lz4.c") == "vendored"
    assert scope.disposition_for("docs/vendor/x.c") == "vendored"          # outside the catalog: the globs decide
    assert scope.disposition_for(None) == FIRST_PARTY
    assert scope.disposition_counts() == {"first_party": 5, "vendored": 2, "sdk": 0, "generated": 0, "test": 0}
    assert scope.evidence_map()["source_dispositions"]["files"] == scope.disposition_counts()
    plain, _ = unscoped
    assert {item.disposition for item in plain.source_files} == {FIRST_PARTY}
    assert plain.disposition_counts()["vendored"] == 0


def test_dispositions_classify_in_fixed_order_and_reject_bad_patterns() -> None:
    policy = SourceDispositions(vendored=("**/third_party/**",), test=("**/tests/**", "test_*"), generated=("*.pb.go",))
    assert policy.classify("native/third_party/lz4/tests/t.c") == "vendored"
    assert policy.classify("a/tests/x.py") == "test" and policy.classify("a/test_x.py") == "test"
    assert policy.classify("api/v1.pb.go") == "generated" and policy.classify("api/v1.go") == FIRST_PARTY
    assert policy.matched_pattern("third_party/a.c") == ("vendored", "**/third_party/**")
    assert policy.record()["rule"] == "appsec-review/source-disposition/1"
    assert not SourceDispositions().configured and policy.configured
    with pytest.raises(ValueError, match="source_dispositions.vendored must be a list"):
        SourceDispositions(vendored=("/abs/**",))
    with pytest.raises(ValueError, match="source_dispositions.test must be a list"):
        SourceDispositions(test=("a/../b",))
    with pytest.raises(ValueError, match="has unknown settings: first_party"):
        SourceDispositions.from_mapping({"first_party": ["src/**"]})


# -------------------------------------------------------------------------------------------- lead collection


def test_vendored_and_stylistic_leads_leave_the_collection_with_their_reason_not_a_gap(fixture, scoped, unscoped) -> None:
    scope, collection = scoped
    kept = {lead.observation_id for lead in collection.leads}
    excluded = {item.lead.observation_id: item for item in collection.excluded}
    assert not kept & _ids(fixture, VENDORED_LEADS + STYLISTIC_LEADS)
    assert set(excluded) == _ids(fixture, VENDORED_LEADS + STYLISTIC_LEADS)
    assert all(item.lead.path is not None and item.lead.path.split("/")[-3] == "third_party"
               for key, item in excluded.items() if key in _ids(fixture, VENDORED_LEADS))
    assert {excluded[key].reason for key in _ids(fixture, VENDORED_LEADS)} == {"vendored"}
    assert "**/third_party/**" in excluded[fixture.ids["cppcheck_vendored_high"]].detail
    style = excluded[fixture.ids["cppcheck_style"]]
    assert (style.reason, style.lead.native_severity, style.lead.rule_id) == ("stylistic", "style", "unusedStructMember")
    assert "lead_filters.stylistic scanner tool-cppcheck" in style.detail
    # The vendored style row is excluded for its disposition first, not as stylistic.
    assert excluded[fixture.ids["cppcheck_vendored_style"]].reason == "vendored"
    # The first-party cppcheck warning is still a lead, as medium; every other first-party lead is unchanged.
    [medium] = [lead for lead in collection.leads if lead.observation_id == fixture.ids["cppcheck_medium"]]
    assert (medium.reported_severity, medium.native_severity) == ("medium", "warning")
    _, plain = unscoped
    assert kept == {lead.observation_id for lead in plain.leads} - set(excluded)
    assert not plain.excluded and len(plain.leads) == len(collection.leads) + len(collection.excluded)
    # A scope decision is not a coverage gap: the gap set is identical with and without the policy.
    assert [gap.record() for gap in collection.gaps] == [gap.record() for gap in plain.gaps]
    assert collection.exclusion_counts() == {"vendored": 3, "sdk": 0, "generated": 0, "test": 0, "stylistic": 1}
    # The observations stay in scanner coverage: the correlation audit still counts every source-SAST row.
    assert collection.correlation_audit["counts"]["source_sast_observations"] == \
        plain.correlation_audit["counts"]["source_sast_observations"]
    assert collection.available["source_sast"] is True


def test_excluded_lead_records_are_typed_and_the_reason_is_closed(fixture, scoped) -> None:
    _, collection = scoped
    record = collection.excluded[0].record()
    assert set(record) == {"lead_id", "reason", "detail", "path", "scanner", "rule_id"}
    assert record["reason"] in EXCLUSION_REASONS
    with pytest.raises(ValueError, match="unknown lead exclusion reason"):
        ExcludedLead(collection.excluded[0].lead, "unwanted", "x")


def test_triage_is_only_asked_about_leads_in_scope(fixture, scoped) -> None:
    scope, _ = scoped
    from appsec_review.review.lead_families import LeadTriage
    triaged = collect_leads(scope, {fixture.ids["sast_unknown"]: LeadTriage("unresolved", gap="triage_skipped:test")},
                            filters=LeadFilters())
    assert {lead.triage_state for lead in triaged.leads} <= {"not_needed", "unresolved"}
    assert all(item.lead.triage_state is None for item in triaged.excluded)


# ------------------------------------------------------------------------------------------- units and hunts


def test_units_and_hunt_packages_hold_first_party_files_and_leads_only(fixture, scoped, unscoped) -> None:
    scope, collection = scoped
    units = build_units(scope, collection, unit_max_files=SETTINGS.unit_max_files)
    vendored_ids = {scope.source_for(path).identity for path in VENDORED}
    assert all(not set(unit.paths) & set(VENDORED) and not set(unit.source_ids) & vendored_ids for unit in units)
    assert not {lead.observation_id for unit in units for lead in unit.leads} & _ids(fixture, VENDORED_LEADS + STYLISTIC_LEADS)
    [native] = [unit for unit in units if unit.build_unit_id == "native-main"]
    assert "native/third_party/lz4/lz4.c" not in native.paths and "native/src/parse.c" in native.paths
    assert fixture.ids["cppcheck_medium"] in native.lead_ids
    plain_scope, plain = unscoped
    plain_units = build_units(plain_scope, plain, unit_max_files=SETTINGS.unit_max_files)
    [plain_native] = [unit for unit in plain_units if unit.build_unit_id == "native-main"]
    assert "native/third_party/lz4/lz4.c" in plain_native.paths and fixture.ids["cppcheck_vendored_high"] in plain_native.lead_ids
    assert any("third_party/zlib/inflate.c" in unit.paths for unit in plain_units)


def test_assembly_names_no_vendored_file_and_records_every_exclusion_in_the_manifest(tmp_path, fixture, scoped) -> None:
    scope, collection = scoped
    assembly = assemble_packages(scope, SETTINGS, collection=collection)
    outside = _ids(fixture, VENDORED_LEADS + STYLISTIC_LEADS)
    vendored_ids = {scope.source_for(path).identity for path in VENDORED}
    for package in assembly.packages:
        document = package.document()
        assert not set(package.lead_ids) & outside
        assert not set(document["scope"]["source_ids"]) & vendored_ids
        assert not set(document["retrieval"]["entity_ids"]) & (vendored_ids | outside)
        assert not {entry["observation_id"] for entry in document["lead_menu"]} & outside
    assert not _hunt_menu_ids(assembly) & outside
    assert fixture.ids["cppcheck_medium"] in _hunt_menu_ids(assembly)
    manifest = assembly.manifest
    admission = {entry["lead_id"]: entry for entry in manifest["admission"]}
    assert set(admission) == {lead.observation_id for lead in collection.leads} | outside
    for key in VENDORED_LEADS:
        entry = admission[fixture.ids[key]]
        assert (entry["status"], entry["reasons"], entry["residual_coverage"], entry["exclusion"]) == (
            "not_admitted", [], "outside_review_scope", "vendored")
        assert "third_party" in entry["exclusion_detail"]
    entry = admission[fixture.ids["cppcheck_style"]]
    assert (entry["status"], entry["residual_coverage"], entry["exclusion"]) == ("not_admitted", "outside_review_scope", "stylistic")
    assert "exclusion" not in admission[fixture.ids["sast_high"]]
    counts = manifest["counts"]["dispositions"]
    assert counts == {"rule": "appsec-review/source-disposition/1",
                      "files": {"first_party": 5, "vendored": 2, "sdk": 0, "generated": 0, "test": 0},
                      "leads": {"first_party": len(collection.leads), "vendored": 3, "sdk": 0, "generated": 0,
                                "test": 0, "stylistic": 1}}
    assert manifest["source_dispositions"]["vendored"] == list(scope.dispositions.vendored)
    assert not any("vendored" in gap["reason"] or "stylistic" in gap["reason"] for gap in manifest["gaps"])
    # The excluded high-severity leads would have been lane A packages: they are not.
    assert not {entry["lead_id"] for entry in manifest["admission"] if entry["status"] == "admitted"} & outside
    publish_packages(assembly, tmp_path / "out")      # the manifest validates against the published schema


def test_without_a_policy_the_vendored_leads_are_reviewed_and_the_dependency_inventory_is_the_same(fixture, scoped, unscoped) -> None:
    scope, collection = scoped
    plain_scope, plain = unscoped
    plain_assembly = assemble_packages(plain_scope, SETTINGS, collection=plain)
    admitted = {entry["lead_id"] for entry in plain_assembly.manifest["admission"] if entry["status"] == "admitted"}
    assert _ids(fixture, ("sast_vendored_high", "cppcheck_vendored_high")) <= admitted
    assert fixture.ids["cppcheck_style"] in _hunt_menu_ids(plain_assembly)
    assert plain_assembly.manifest["counts"]["dispositions"]["leads"]["vendored"] == 0
    # Dispositions narrow the lanes, not the evidence: the accepted shards, the dependency inventory producer
    # and the dependency advisory leads are identical under both scopes.
    assert scope.shards == plain_scope.shards
    assert scope.producer("dependency_intelligence").record() == plain_scope.producer("dependency_intelligence").record()
    assert scope.producer("dependency_scanner").record() == plain_scope.producer("dependency_scanner").record()
    dependency = lambda leads: sorted(lead.observation_id for lead in leads if lead.family == "dependency_advisory")
    assert dependency(collection.leads) == dependency(plain.leads) == sorted(_ids(fixture, ("dep_high", "dep_low")))
    assembly = assemble_packages(scope, SETTINGS, collection=collection)
    dependency_context = lambda item: sorted(
        entry["id"] for package in item.packages if package.kind == "hunt"
        for entry in package.document()["context"] if entry["role"] == "dependency")
    assert dependency_context(assembly) == dependency_context(plain_assembly)


def test_a_hunt_menu_reaching_outside_first_party_scope_fails_the_membership_gate(fixture, scoped, unscoped) -> None:
    scope, collection = scoped
    _, plain = unscoped
    # Units built from an unscoped collection carry vendored leads; assembling them under the scoped policy
    # must fail rather than publish a vendored lead in a hunt menu.
    units = build_units(scope, LeadCollection(plain.leads, plain.gaps, plain.available, plain.correlation_audit,
                                              plain.correlation_shards, plain.non_lead_counts),
                        unit_max_files=SETTINGS.unit_max_files)
    [native] = [item for item in rank_units(units) if item.unit.build_unit_id == "native-main"]
    assert fixture.ids["cppcheck_vendored_high"] in native.unit.lead_ids
    assembler = _Assembler(scope, SETTINGS, collection)
    with pytest.raises(IntegrityError, match="outside the first-party scope"):
        assembler.hunts(native)


def test_reassembly_under_the_policy_is_deterministic(fixture, scoped) -> None:
    scope, collection = scoped
    first = assemble_packages(scope, SETTINGS, collection=collection)
    second = assemble_packages(accept_manifest(fixture.run_root, dispositions=scope.dispositions), SETTINGS,
                               collection=collect_leads(accept_manifest(fixture.run_root, dispositions=scope.dispositions),
                                                        filters=LeadFilters.from_mapping({"stylistic": [
                                                            {"scanner": "tool-cppcheck",
                                                             "native_severities": ["style", "performance",
                                                                                   "portability", "information"]}]})))
    assert first.manifest_bytes == second.manifest_bytes
    assert [item.body for item in first.packages] == [item.body for item in second.packages]
    assert json.loads(first.manifest_bytes)["counts"]["dispositions"]["leads"]["stylistic"] == 1
