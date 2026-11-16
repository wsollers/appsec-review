from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import random

import jsonschema
import pytest

from appsec_review.review.lead_families import FAMILIES, collect_leads
from appsec_review.review.models import IntegrityError
from appsec_review.review.packages import (
    PackageSettings, assemble_packages, audit_membership, publish_packages, verify_package_manifest,
)
from appsec_review.review.scope import accept_manifest
from tests.fixtures.inference_review.builder import build_accepted_index_set


SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "docs" / "schemas" /
                     "review-packages.schema.json").read_text(encoding="utf-8"))
ADMITTED = {"sast_high", "sast_critical", "sast_unknown", "sast_suppressed", "sast_duplicate", "sast_unlocated",
            "codeql_high", "dep_high", "ci_high"}
NOT_ADMITTED = {"sast_medium", "sast_low", "dep_low", "ci_medium"}


@pytest.fixture(scope="module")
def fixture(tmp_path_factory):
    return build_accepted_index_set(tmp_path_factory.mktemp("pkg"), publish_v1_packages=False)


@pytest.fixture(scope="module")
def scope(fixture):
    return accept_manifest(fixture.run_root)


@pytest.fixture(scope="module")
def assembly(scope):
    return assemble_packages(scope)


def _finding(assembly, fixture, key: str) -> dict:
    """The finding-lead package that lists the lead ``key`` (leads of one defect site share a package)."""
    [document] = [item.document() for item in assembly.packages
                  if item.kind == "finding_lead" and fixture.ids[key] in item.lead_ids]
    return document


def _menu(document: dict, lead_id: str) -> dict:
    [entry] = [item for item in document["lead_menu"] if item["observation_id"] == lead_id]
    return entry


# sast_critical and its opengrep duplicate sit on native/src/parse.c:3 and codeql_high on line 5 of the same
# file: one defect site, one package, three menu entries. sast_unknown (io.c:1) and sast_suppressed (io.c:3)
# form the fixture's second cluster.
CLUSTER = ("sast_critical", "sast_duplicate", "codeql_high")
CLUSTERS = (CLUSTER, ("sast_unknown", "sast_suppressed"))
CLUSTERED_PACKAGES = len(ADMITTED) - sum(len(group) for group in CLUSTERS) + len(CLUSTERS)


def test_lane_a_admits_exactly_critical_high_and_unknown_across_families(fixture, assembly) -> None:
    findings = [item for item in assembly.packages if item.kind == "finding_lead"]
    packaged = [lead for item in findings for lead in item.lead_ids]
    assert sorted(packaged) == sorted(fixture.ids[key] for key in ADMITTED)
    assert not {fixture.ids[key] for key in NOT_ADMITTED} & set(packaged)
    assert {item.lead_family for item in findings} == {"source_sast", "dependency_advisory", "ci_rule"}
    for item in findings:   # a package takes the family of its highest-severity lead, the first menu entry
        assert item.lead_family == item.document()["lead_menu"][0]["lead_family"]
    audit = assembly.manifest["audit"]["lane_a"]
    assert audit["status"] == "passed" and audit["expected"] == audit["packaged"] == len(ADMITTED)
    assert audit["by_family"]["source_sast"] == {"critical": 1, "high": 4, "unknown": 1}
    assert audit["suppressed"] == 1 and audit["duplicates"] == 1

    unknown = _menu(_finding(assembly, fixture, "sast_unknown"), fixture.ids["sast_unknown"])
    assert (unknown["reported_severity"], unknown["native_severity"]) == ("unknown", "SEVERE-ISH")
    dependency = _menu(_finding(assembly, fixture, "dep_high"), fixture.ids["dep_high"])
    assert (dependency["reported_severity"], dependency["severity_basis"]) == ("high", "advisory-cvss-band")
    assert dependency["rule_cwe"] == ["CWE-400"] and dependency["severity_rule"].endswith("/dependency_advisory/2")
    codeql = _menu(_finding(assembly, fixture, "codeql_high"), fixture.ids["codeql_high"])
    assert codeql["reported_severity"] == "high" and codeql["lead_family"] == "codeql"


def test_suppressed_and_duplicate_leads_keep_their_packages_and_identity(fixture, assembly) -> None:
    suppressed = _menu(_finding(assembly, fixture, "sast_suppressed"), fixture.ids["sast_suppressed"])
    assert suppressed["suppression_status"] == "suppressed"
    assert suppressed["observation_id"] == fixture.ids["sast_suppressed"]
    assert suppressed["rule_cwe"] == ["CWE-78"]
    duplicate = _finding(assembly, fixture, "sast_duplicate")
    assert _menu(duplicate, fixture.ids["sast_duplicate"])["duplicate_of"] == fixture.ids["sast_critical"]
    assert {"id": fixture.ids["sast_critical"], "kind": "tool_observation", "role": "duplicate_of"} in \
        duplicate["context"]
    assert duplicate["scope"]["component_id"] == "component:0002"
    assert duplicate["scope"]["build_unit_id"] == "native-main"
    assert duplicate["scope"]["source_ids"] == [fixture.ids["native/src/parse.c"]]
    assert duplicate["evidence"][0]["resolution"] == "source_line"
    unlocated = _finding(assembly, fixture, "sast_unlocated")
    assert unlocated["evidence"][0]["resolution"] == "unresolved"
    assert unlocated["lead_menu"][0]["location_exact"] is False
    assert any(gap["state"] == "ambiguous" for gap in unlocated["coverage_gaps"])


def test_absent_families_and_stale_feeds_are_named_gaps(fixture, assembly) -> None:
    manifest = assembly.manifest
    available = manifest["audit"]["families_available"]
    assert {family for family in FAMILIES if not available[family]} == {
        "artifact_scanner", "post_build_hardening", "owasp_control", "secret", "config_scanner"}
    missing = {gap["producer"] for gap in manifest["gaps"] if gap["state"] == "missing"}
    assert {"artifact_scanner", "post_build_hardening", "owasp_control", "secret", "config_scanner"} <= missing
    dependency = _finding(assembly, fixture, "dep_high")
    assert any(gap["state"] == "stale" for gap in dependency["coverage_gaps"])
    hunts = [item.document() for item in assembly.packages if item.kind == "hunt"]
    assert all({"artifact_scanner", "owasp_control"} <= {gap["producer"] for gap in item["coverage_gaps"]
                                                         if gap["state"] == "missing"} for item in hunts)


def test_every_package_validates_against_the_v2_schema_and_extra_fields_are_rejected(assembly) -> None:
    validator = jsonschema.Draft202012Validator(SCHEMA)
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    for package in assembly.packages:
        document = package.document()
        validator.validate(document)
        assert document["package_id"] == package.package_id
        assert document["persona"] is None and document["stack_profile"] is None
    # Choose by content, not by hash order: the mutations need a lead with context entries.
    finding = next(item.document() for item in assembly.packages
                   if item.kind == "finding_lead" and item.document()["context"])
    hunt = next(item.document() for item in assembly.packages if item.kind == "hunt")
    mutations = [
        lambda value: value.update(extra=1),
        lambda value: value["lead_menu"][0].update(extra=1),
        lambda value: value["scope"].update(extra=1),
        lambda value: value["context"][0].update(extra=1),
        lambda value: value["truncation"].update(extra=1),
        lambda value: value.update(lane="hunt"),
        lambda value: value.update(schema="appsec-review/review-package/1"),
        lambda value: value["context"].append("asr:component:" + "0" * 64),
    ]
    for mutate in mutations:
        changed = copy.deepcopy(finding)
        mutate(changed)
        assert not validator.is_valid(changed)
    changed = copy.deepcopy(hunt)
    changed["rank"]["basis"][0]["extra"] = 1
    assert not validator.is_valid(changed)
    changed = copy.deepcopy(hunt)
    changed["rank"] = None
    assert not validator.is_valid(changed)


def test_reassembly_and_shuffled_inputs_are_byte_identical(fixture, assembly) -> None:
    scope = accept_manifest(fixture.run_root)
    collection = collect_leads(scope)
    generator = random.Random(7)

    def shuffled(values):
        values = list(values)
        generator.shuffle(values)
        return tuple(values)
    scrambled = replace(scope, shards=shuffled(scope.shards), components=shuffled(scope.components),
                        build_units=shuffled(scope.build_units), source_files=shuffled(scope.source_files))
    again = assemble_packages(scrambled, collection=replace(collection, leads=shuffled(collection.leads)))
    assert [item.body for item in again.packages] == [item.body for item in assembly.packages]
    assert again.manifest_bytes == assembly.manifest_bytes
    rebuilt = assemble_packages(accept_manifest(fixture.run_root))
    assert rebuilt.manifest_bytes == assembly.manifest_bytes


def test_package_identity_and_fingerprint_contract(assembly) -> None:
    from appsec_review.review.identity import sha256_hex
    for package in assembly.packages:
        document = package.document()
        package_id = document.pop("package_id")
        assert package_id == f"{document['kind']}-{sha256_hex(document)}"
        assert document["retrieval"]["entity_ids"] == sorted(set(document["retrieval"]["entity_ids"]))
        assert [gap["gap_id"] for gap in document["coverage_gaps"]] == sorted(
            gap["gap_id"] for gap in document["coverage_gaps"])
    fingerprints = [item.document()["input_fingerprint"] for item in assembly.packages]
    assert len(set(fingerprints)) == len(fingerprints)


def test_membership_audit_rejects_missing_repeated_or_invented_leads(fixture, assembly) -> None:
    collection = collect_leads(accept_manifest(fixture.run_root))
    findings = [item for item in assembly.packages if item.kind == "finding_lead"]
    admit = ("critical", "high", "unknown")
    assert audit_membership(collection, findings, admit)["status"] == "passed"
    with pytest.raises(IntegrityError, match="missing"):
        audit_membership(collection, findings[1:], admit)
    with pytest.raises(IntegrityError, match="repeated"):
        audit_membership(collection, [*findings, findings[0]], admit)
    with pytest.raises(IntegrityError, match="invented"):
        audit_membership(collection, findings, ("critical",))


def test_manifest_lists_every_package_hash_input_gap_and_count(tmp_path: Path, fixture, assembly) -> None:
    manifest = assembly.manifest
    assert [item["package_id"] for item in manifest["packages"]] == [item.package_id for item in assembly.packages]
    assert {item["sha256"] for item in manifest["packages"]} == {item.sha256 for item in assembly.packages}
    assert len(manifest["inputs"]) == len(accept_manifest(fixture.run_root).shards)
    assert manifest["counts"]["packages"]["finding_lead"] == CLUSTERED_PACKAGES
    assert manifest["counts"]["leads"]["dependency_advisory"]["low"] == 1
    out = tmp_path / "review"
    path = publish_packages(assembly, out)
    assert verify_package_manifest(path)["content_sha256"] == manifest["content_sha256"]
    assert publish_packages(assembly, out) == path
    victim = out / "packages" / f"{assembly.packages[0].package_id}.json"
    victim.write_bytes(victim.read_bytes().replace(b'"schema"', b'"schemA"', 1))
    with pytest.raises(IntegrityError):
        verify_package_manifest(path)
    with pytest.raises(IntegrityError, match="differs from its reassembly"):
        publish_packages(assembly, out)


def test_partitioned_hunt_menus_cover_every_lead_exactly_once(fixture) -> None:
    scope = accept_manifest(fixture.run_root)
    assembly = assemble_packages(scope, PackageSettings(hunt_menu_partition_size=2))
    native = [item.document() for item in assembly.packages
              if item.kind == "hunt" and item.unit_key == "unit:component:0002:-:native-main:r0000"]
    native.sort(key=lambda item: item["partition"]["number"])
    assert [item["partition"] for item in native] == [{"number": number, "count": 3} for number in range(3)]
    keys = [item["scope"]["partition_key"] for item in native]
    assert [item["truncation"]["next_partition"] for item in native] == [*keys[1:], None]
    listed = [lead["observation_id"] for item in native for lead in item["lead_menu"]]
    expected = {fixture.ids[key] for key in ("sast_critical", "sast_duplicate", "sast_unknown", "sast_suppressed",
                                             "codeql_high")}
    assert sorted(listed) == sorted(expected) and len(listed) == len(set(listed))
    assert all(item["truncation"]["omitted_leads"] == 0 for item in native)
    severities = [lead["reported_severity"] for item in native for lead in item["lead_menu"]]
    assert severities[0] == "critical" and severities[-1] == "unknown"


def test_context_and_byte_bounds_create_truncation_gaps_or_split_partitions(scope, assembly) -> None:
    capped = assemble_packages(scope, PackageSettings(max_context_entries=1))
    truncated = [item.resolved() for item in capped.packages if item.document()["truncation"]["omitted_context"]]
    assert truncated
    for document in truncated:
        # Neighborhood rows are bounded by the code-graph settings, not by ``max_context_entries``.
        neighborhood = document["neighborhood"]
        refs = {row["ref"] for name in ("sinks", "ranges", "guards", "callers", "callees", "flows", "entries",
                                        "corroboration") for row in neighborhood[name]}
        refs |= {item["ref"] for item in (neighborhood["build"],) if item} | (
            {neighborhood["function"]["symbol"]} if neighborhood["function"] else set())
        assert len([item for item in document["context"] if item["id"] not in refs]) == 1
        assert any(gap["state"] == "truncated" for gap in document["coverage_gaps"])
    assert any(gap["state"] == "truncated" for gap in capped.manifest["gaps"])
    assert capped.manifest["audit"]["lane_a"]["status"] == "passed"

    largest = max(len(item.body) for item in assembly.packages if item.kind == "hunt")
    split = assemble_packages(scope, PackageSettings(max_package_bytes=largest - 1))
    assert all(len(item.body) < largest for item in split.packages)
    assert split.manifest["counts"]["packages"]["hunt"] > 4
    assert split.manifest["audit"]["lane_b"]["status"] == "passed"
    with pytest.raises(IntegrityError, match="cannot be partitioned"):
        assemble_packages(scope, PackageSettings(max_package_bytes=600))


def test_missing_scanner_correlation_recomputes_duplicates_and_marks_suppression_unknown(tmp_path: Path) -> None:
    fixture = build_accepted_index_set(tmp_path, omit=("scanner_correlation",), publish_v1_packages=False)
    assembly = assemble_packages(accept_manifest(fixture.run_root))
    suppressed = _menu(_finding(assembly, fixture, "sast_suppressed"), fixture.ids["sast_suppressed"])
    assert suppressed["suppression_status"] == "unknown"
    duplicate = _menu(_finding(assembly, fixture, "sast_duplicate"), fixture.ids["sast_duplicate"])
    assert duplicate["duplicate_of"] == fixture.ids["sast_critical"]
    assert any(gap["producer"] == "scanner_correlation" and gap["state"] == "partial"
               for gap in assembly.manifest["gaps"])
    assert assembly.manifest["audit"]["lane_a"]["expected"] == len(ADMITTED)


def test_leads_of_one_defect_site_share_one_package_and_the_window_is_typed(fixture, scope, assembly) -> None:
    """T-5025: run 2026-11-15-0005 reviewed one use-after-free as four lead packages, one per tool observation."""
    ids = sorted(fixture.ids[key] for key in CLUSTER)
    [package] = [item for item in assembly.packages
                 if item.kind == "finding_lead" and fixture.ids["codeql_high"] in item.lead_ids]
    document = package.document()
    assert list(package.lead_ids) == ids and len(document["lead_menu"]) == 3
    assert package.partition_key.startswith("lead-group/")
    assert document["scope"]["partition_key"] == package.partition_key
    assert document["lead_menu"][0]["observation_id"] == fixture.ids["sast_critical"]
    assert package.lead_family == "source_sast" and document["lead_family"] == "source_sast"
    assert {entry["lead_family"] for entry in document["lead_menu"]} == {"source_sast", "codeql"}
    assert sorted(item["entity_id"] for item in document["evidence"]) == ids
    assert document["proof_obligations"] == sorted({"affected_construct", "attacker_input_control",
                                                    "source_to_sink_reachability", "missing_or_ineffective_guard",
                                                    "security_impact"})
    entry = next(item for item in assembly.manifest["packages"] if item["package_id"] == package.package_id)
    assert entry["lead_count"] == 3 and entry["partition_key"] == package.partition_key
    assert assembly.manifest["audit"]["lane_a"]["status"] == "passed"
    assert assembly.manifest["settings"]["lead_cluster_lines"] == 8
    # Advisory leads share svc/api/handler.py:1 and never cluster: distinct advisories are distinct defects.
    assert all(len(item.lead_ids) == 1 for item in assembly.packages
               if item.kind == "finding_lead" and item.lead_family == "dependency_advisory")

    def grouped(result):
        return sorted(item.lead_ids for item in result.packages
                      if item.kind == "finding_lead" and set(item.lead_ids) & set(ids))

    alone = assemble_packages(scope, PackageSettings(lead_cluster_lines=0))
    assert grouped(alone) == [(lead_id,) for lead_id in ids]
    assert alone.manifest["audit"]["lane_a"]["status"] == "passed"
    narrow = assemble_packages(scope, PackageSettings(lead_cluster_lines=1))
    assert grouped(narrow) == sorted([(fixture.ids["codeql_high"],),
                                      tuple(sorted((fixture.ids["sast_critical"], fixture.ids["sast_duplicate"])))])
    with pytest.raises(ValueError, match="lead_cluster_lines"):
        PackageSettings(lead_cluster_lines=-1)
    with pytest.raises(ValueError, match="lead_cluster_lines"):
        PackageSettings(lead_cluster_lines=True)


def test_an_unassessed_unknown_lead_is_a_named_gap_under_the_critical_high_policy(fixture, scope) -> None:
    """T-5029: lanes.lead_admission is critical and high; an unknown lead enters only through an assessed severity.
    The fixture runs no triage, so sast_unknown stays unassessed: not a lane A package, a skipped gap on the
    manifest, and still on its unit's hunt menu."""
    strict = assemble_packages(scope, PackageSettings(admit_severities=("critical", "high")))
    unknown = fixture.ids["sast_unknown"]
    assert unknown not in {lead for item in strict.packages if item.kind == "finding_lead" for lead in item.lead_ids}
    entry = next(item for item in strict.manifest["admission"] if item["lead_id"] == unknown)
    assert (entry["status"], entry["reasons"], entry["residual_coverage"]) == ("not_admitted", [], "unassessed_unknown")
    gap = next(item for item in strict.manifest["gaps"] if item["producer"] == "lead_admission" and item["scope"] == unknown)
    assert gap["state"] == "skipped" and "assessed severity" in gap["reason"]
    assert strict.manifest["audit"]["lane_a"]["status"] == "passed"
    assert any(unknown in item.lead_ids for item in strict.packages if item.kind == "hunt")
    # Admitting unknown as well packages the lead and records no such gap.
    loose = assemble_packages(scope, PackageSettings(admit_severities=("critical", "high", "unknown")))
    assert any(unknown in item.lead_ids for item in loose.packages if item.kind == "finding_lead")
    assert not [item for item in loose.manifest["gaps"] if item["producer"] == "lead_admission"]


def test_settings_are_typed_and_reject_unknown_keys() -> None:
    assert PackageSettings.from_mapping({"admit_severities": ["unknown", "critical"]}).admit_severities == (
        "critical", "unknown")
    with pytest.raises(ValueError, match="unknown package settings"):
        PackageSettings.from_mapping({"max_cost_usd": 3})
    with pytest.raises(ValueError):
        PackageSettings(admit_severities=("severe",))
    with pytest.raises(ValueError):
        PackageSettings(max_depth=9)


def test_schema_role_enum_covers_every_context_role_the_assembler_emits() -> None:
    from appsec_review.review.packages import GRAPH_ROLES
    from appsec_review.review.units import SIGNAL_CONTEXT_ROLES

    allowed = set(SCHEMA["$defs"]["inference_context"]["properties"]["role"]["enum"])
    assert SIGNAL_CONTEXT_ROLES | set(GRAPH_ROLES.values()) <= allowed
    identity = "asr:coverage_cell:" + "a" * 64
    validator = jsonschema.Draft202012Validator({**SCHEMA["$defs"]["inference_context"],
                                                 "$defs": SCHEMA["$defs"]})
    for role in sorted(SIGNAL_CONTEXT_ROLES):
        assert not list(validator.iter_errors({"id": identity, "kind": "coverage_cell", "role": role}))
