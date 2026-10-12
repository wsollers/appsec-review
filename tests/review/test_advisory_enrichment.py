"""Pinned-feed reference context: CWE validation, advisory joins, lane A admission, packages, scoring."""
from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path

import jsonschema
import pytest

from appsec_review.indexing import products
from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.job_inference_security_review import stages
from appsec_review.review.claims import normalize_claim
from appsec_review.review.lead_families import collect_leads
from appsec_review.review.models import ClaimState, GapClass, Lane
from appsec_review.review.packages import PackageSettings, assemble_packages
from appsec_review.review.references import load_cwe_reference
from appsec_review.review.scope import accept_manifest
from appsec_review.review.scoring import ApplicationRiskMatrixProvider, ScoreRequest
from tests.fixtures import reference_feeds as feeds
from tests.fixtures.inference_review.builder import V31, V40, build_accepted_index_set

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "docs" / "schemas" / "review-packages.schema.json").read_text(encoding="utf-8"))
SCORE_SCHEMA_DIR = ROOT / "docs" / "schemas" / "inference-security-review"
FILE = "svc/api/handler.py"
V98 = {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8,
       "baseSeverity": "CRITICAL"}
V2 = {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "baseScore": 7.5}


@pytest.fixture(scope="module")
def fixture(tmp_path_factory):
    return build_accepted_index_set(tmp_path_factory.mktemp("enrich"))


@pytest.fixture(scope="module")
def scope(fixture):
    return accept_manifest(fixture.run_root)


def _lead(collection, fixture, key: str):
    return next(lead for lead in collection.leads if lead.observation_id == fixture.ids[key])


def _facts(fixture, pins_override=None):
    """Rebuild dependency_advisories over the fixture's accepted shards with the given pins."""
    scope = accept_manifest(fixture.run_root)
    rule = products.product_rule("dependency_advisories")
    store = ShardSet(fixture.run_root, list(scope.shards))
    pins = {feed: (pins_override or {}).get(feed, fixture.feed_pins[feed]) for feed in rule.feeds}
    context = products.ProductContext(fixture.run_root, fixture.snapshot, store, {}, pins, {}, 1000, rule.version)
    derived = rule.build(context, rule.select(store))
    return {item.payload["result"]["advisory"]: item.payload for item in derived.entities}, derived


# --- CWE validation from the pinned MITRE catalog -------------------------------------------------


def test_claim_cwes_validate_against_the_pinned_mitre_catalog(fixture) -> None:
    reference = load_cwe_reference(fixture.run_root).with_fallback(frozenset({"CWE-89"}))
    assert reference.source == "mitre_catalog" and reference.gap is None
    assert reference.snapshot_id == fixture.feed_pins["mitre"]["snapshot_id"] and reference.version == "4.20"
    assert reference.lookup("CWE-400").abstraction == "Class"
    # CWE-787 is a real catalog weakness that no accepted rule names: accepted.
    assert "CWE-787" in reference.accepted_ids and "CWE-787" not in reference.fallback_ids
    entity = fixture.ids[FILE]
    accepted = normalize_claim(lane=Lane.LEAD, package_id="finding_lead-x", affected_entities=[entity],
                               weakness_cwe="CWE-787", security_predicate="memory_corruption", preconditions=[],
                               statement="s", accepted_cwe_ids=reference.accepted_ids)
    assert accepted.claim.weakness_cwe == "CWE-787" and not accepted.gaps
    # An identifier the catalog does not contain is dropped from identity and becomes an evidence gap.
    rejected = normalize_claim(lane=Lane.LEAD, package_id="finding_lead-x", affected_entities=[entity],
                               weakness_cwe="CWE-99999", security_predicate="memory_corruption", preconditions=[],
                               statement="s", accepted_cwe_ids=reference.accepted_ids)
    assert rejected.claim.weakness_cwe is None
    assert [gap.gap_class for gap in rejected.gaps] == [GapClass.EVIDENCE_GAP]


@pytest.mark.parametrize("variant, reason", [
    ({"omit_feeds": ("mitre",)}, "mitre_feed_unavailable"),
    ({"stale_feeds": ("mitre",)}, "mitre_stale_feed"),
])
def test_missing_or_stale_catalog_falls_back_with_a_recorded_gap(tmp_path: Path, variant, reason) -> None:
    fixture = build_accepted_index_set(tmp_path, **variant)
    reference = load_cwe_reference(fixture.run_root).with_fallback(frozenset({"CWE-89", "CWE-120"}))
    assert reference.source == "fallback" and reference.gap.startswith(reason)
    assert reference.accepted_ids == {"CWE-89", "CWE-120"} and "CWE-787" not in reference.accepted_ids
    record = reference.record()
    assert record["gap"] == reference.gap and record["accepted_count"] == 2
    gaps = stages.completeness_gaps([], [], record)
    assert len(gaps) == 1 and gaps[0].gap_class is GapClass.COVERAGE_GAP
    assert gaps[0].subject_id == "reference:mitre_cwe" and "fell back to 2 rule/crosswalk" in gaps[0].reason
    assert stages.completeness_gaps([], [], load_cwe_reference(tmp_path / "nowhere").record())


def test_tampered_catalog_is_an_identity_mismatch(tmp_path: Path) -> None:
    fixture = build_accepted_index_set(tmp_path)
    path = Path(fixture.feed_pins["mitre"]["directory"]) / "index" / "mitre.sqlite"
    with path.open("ab") as handle:
        handle.write(b"tamper")
    reference = load_cwe_reference(fixture.run_root)
    assert reference.source == "fallback" and reference.gap.startswith("mitre_identity_mismatch")


# --- advisory product joins -------------------------------------------------------------------------


def test_dependency_advisories_join_nvd_kev_and_epss_with_per_join_gaps(fixture) -> None:
    facts, derived = _facts(fixture)
    high = facts["GHSA-aaaa-bbbb-cccc"]["result"]
    assert high["cve_ids"] == ["CVE-2026-0001"] and high["join_status"] == {"nvd": "joined", "kev": "joined",
                                                                              "epss": "joined"}
    assert [item["version"] for item in high["nvd"][0]["cvss"]] == ["3.1", "4.0"] and high["nvd"][0]["cwes"] == [
        "CWE-400"]
    assert high["kev"][0]["listed"] is True and high["kev"][0]["known_ransomware_use"] == "Known"
    assert high["epss"][0]["percentile"] == 0.97
    assert high["reference_summary"]["preferred_cvss"]["version"] == "4.0"
    assert high["reference_summary"]["kev_listed"] is True
    assert {feed: ref["snapshot_id"] for feed, ref in high["feeds"].items()} == {
        feed: fixture.feed_pins[feed]["snapshot_id"] for feed in ("osv", "nvd", "kev", "epss")}
    assert facts["GHSA-aaaa-bbbb-cccc"]["gaps"] == [
        "missing_version: the scanner reported a package name only",
        "stale_feed: the pinned OSV snapshot is older than the configured freshness bound"]
    low = facts["GHSA-dddd-eeee-ffff"]
    assert low["result"]["kev"] == [{"cve_id": "CVE-2026-0002", "listed": False}]
    assert "nvd_rejected_cve: CVE-2026-0002 is Rejected in the pinned NVD snapshot" in low["gaps"]
    assert derived.coverage[-1][1] == "stale"


def test_unavailable_feeds_are_per_join_gaps_and_never_complete_empty(fixture) -> None:
    missing = {feed: {"feed_id": feed, "status": "unavailable", "reason": "fixture outage"}
               for feed in ("nvd", "kev", "epss")}
    facts, derived = _facts(fixture, missing)
    high = facts["GHSA-aaaa-bbbb-cccc"]
    intelligence = high["result"]
    assert intelligence["join_status"] == {"nvd": "unavailable", "kev": "unavailable", "epss": "unavailable"}
    assert intelligence["reference_summary"]["kev_listed"] is None and intelligence["nvd"] == []
    assert {"nvd_feed_unavailable: nvd feed is unavailable: fixture outage",
            "kev_feed_unavailable: kev feed is unavailable: fixture outage"} <= set(high["gaps"])
    assert high["coverage_status"] == "partial"
    assert any(gap.startswith("kev_feed_unavailable") for gap in derived.gaps)
    mismatched = dict(fixture.feed_pins["kev"], files={"index/kev.sqlite": "0" * 64})
    facts, _derived = _facts(fixture, {"kev": mismatched})
    assert "kev_feed_unavailable: kev feed identity mismatch for index/kev.sqlite" in facts[
        "GHSA-aaaa-bbbb-cccc"]["gaps"]
    stale = dict(fixture.feed_pins["epss"], stale=True)
    facts, _derived = _facts(fixture, {"epss": stale})
    assert any(gap.startswith("epss_stale_feed") for gap in facts["GHSA-aaaa-bbbb-cccc"]["gaps"])
    assert facts["GHSA-aaaa-bbbb-cccc"]["result"]["join_status"]["epss"] == "stale"


def test_cve_identity_comes_from_the_advisory_id_or_osv_aliases() -> None:
    assert products.advisory_cve_ids("CVE-2026-1234", []) == ["CVE-2026-1234"]
    assert products.advisory_cve_ids("GHSA-x", ["PYSEC-1", "CVE-2026-0002", "CVE-2026-0001"]) == [
        "CVE-2026-0001", "CVE-2026-0002"]
    assert products.advisory_cve_ids("GHSA-x", ["PYSEC-1"]) == []
    metrics = [{"version": "2.0", "base_score": 9.0, "family": "cvssMetricV2"},
               {"version": "3.0", "base_score": 5.0, "family": "cvssMetricV30"},
               {"version": "3.1", "base_score": 6.0, "family": "cvssMetricV31"}]
    assert products.preferred_cvss(metrics)["version"] == "3.1"
    assert products.preferred_cvss(metrics + [{"version": "4.0", "base_score": 1.0}])["version"] == "4.0"
    assert products.preferred_cvss([]) is None


# --- lane A admission and severity ---------------------------------------------------------------------


def test_nvd_cvss_band_sets_reported_severity_only_without_scanner_cvss(tmp_path: Path) -> None:
    records = [feeds.nvd_vulnerability("CVE-2026-0001", metrics={"cvssMetricV31": [V31]}),
               feeds.nvd_vulnerability("CVE-2026-0002", metrics={"cvssMetricV2": [V2], "cvssMetricV31": [V98]})]
    fixture = build_accepted_index_set(tmp_path, nvd_records=records, kev_cves=())
    scope = accept_manifest(fixture.run_root)
    collection = collect_leads(scope)
    low = _lead(collection, fixture, "dep_low")
    assert (low.reported_severity, low.severity_basis) == ("critical", "nvd-cvss-band")
    assert low.native_severity == "NVD CVSS 3.1 9.8"         # v3.1 preferred over v2
    high = _lead(collection, fixture, "dep_high")
    assert (high.reported_severity, high.severity_basis) == ("high", "advisory-cvss-band")
    assembly = assemble_packages(scope)
    [package] = [item.document() for item in assembly.packages if item.lead_ids == (fixture.ids["dep_low"],)]
    lead = package["lead_menu"][0]
    assert lead["admission_reasons"] == ["reported_severity"] and lead["severity_basis"] == "nvd-cvss-band"


def test_kev_listing_admits_a_low_severity_lead_to_lane_a_and_is_configurable(tmp_path: Path) -> None:
    fixture = build_accepted_index_set(tmp_path, kev_cves=("CVE-2026-0001", "CVE-2026-0002"))
    scope = accept_manifest(fixture.run_root)
    low_id = fixture.ids["dep_low"]
    assembly = assemble_packages(scope)
    [package] = [item.document() for item in assembly.packages if item.lead_ids == (low_id,)]
    lead = package["lead_menu"][0]
    assert lead["reported_severity"] == "low" and lead["admission_reasons"] == ["kev_listed"]
    assert assembly.manifest["audit"]["lane_a"]["kev_admitted"] == 1
    assert assembly.manifest["counts"]["kev_admitted"]["dependency_advisory"] == 1
    assert assembly.manifest["audit"]["lane_a"]["by_family"]["dependency_advisory"]["low"] == 1
    high = next(item.document() for item in assembly.packages if item.lead_ids == (fixture.ids["dep_high"],))
    assert high["lead_menu"][0]["admission_reasons"] == ["reported_severity", "kev_listed"]
    disabled = assemble_packages(scope, PackageSettings(admit_kev=False))
    assert not [item for item in disabled.packages if item.lead_ids == (low_id,)]
    assert disabled.manifest["audit"]["lane_a"]["kev_admitted"] == 0


def test_epss_has_no_admission_effect(tmp_path: Path) -> None:
    fixture = build_accepted_index_set(tmp_path, kev_cves=())
    assembly = assemble_packages(accept_manifest(fixture.run_root))
    assert not [item for item in assembly.packages
                if item.kind == "finding_lead" and item.lead_ids == (fixture.ids["dep_low"],)]


# --- packages /3 ---------------------------------------------------------------------------------------


def test_packages_carry_bounded_advisory_context_and_weaknesses_under_schema_3(fixture, scope) -> None:
    reference = load_cwe_reference(fixture.run_root)
    assembly = assemble_packages(scope, cwe_reference=reference)
    validator = jsonschema.Draft202012Validator(SCHEMA)
    for package in assembly.packages:
        validator.validate(package.document())
    assert assembly.manifest["cwe_reference"]["source"] == "mitre_catalog"
    finding = next(item.document() for item in assembly.packages if item.lead_ids == (fixture.ids["dep_high"],))
    lead = finding["lead_menu"][0]
    context = lead["advisory_context"]
    advisory = context["advisories"][0]
    assert advisory["advisory_id"] == "GHSA-aaaa-bbbb-cccc" and advisory["osv"]["fixed_versions"] == ["2.31.0"]
    assert advisory["kev"][0]["date_added"] == "2026-09-01" and advisory["epss"][0]["epss"] == 0.42
    assert advisory["feeds"]["osv"]["stale"] is True and advisory["feeds"]["kev"]["stale"] is False
    assert context["summary"]["preferred_cvss"]["vector"] == V40["vectorString"]
    assert lead["advisory_summary"] == {"cve_ids": ["CVE-2026-0001"], "kev_listed": True, "epss_percentile": 0.97,
                                        "max_cvss": 8.7}
    assert lead["weaknesses"] == [{"cwe_id": "CWE-400", "name": "Uncontrolled Resource Consumption",
                                   "abstraction": "Class", "source": "mitre_catalog", "origin": "rule"}]
    sast = next(item.document() for item in assembly.packages if item.lead_ids == (fixture.ids["sast_critical"],))
    assert sast["lead_menu"][0]["advisory_context"] is None
    assert sast["lead_menu"][0]["weaknesses"][0]["cwe_id"] == "CWE-120"
    hunt = next(item.document() for item in assembly.packages if item.kind == "hunt")
    assert all("advisory_context" not in item and "admission_reasons" not in item for item in hunt["lead_menu"])
    # Without the catalog the weakness names come from accepted reference_intelligence facts.
    fallback = assemble_packages(scope)
    sast = next(item.document() for item in fallback.packages if item.lead_ids == (fixture.ids["sast_critical"],))
    assert sast["lead_menu"][0]["weaknesses"][0]["source"] == "reference_intelligence"
    for mutate in (lambda value: value["advisory_context"]["advisories"][0].update(extra=1),
                   lambda value: value["advisory_context"]["summary"].update(kev_listed="yes"),
                   lambda value: value["weaknesses"][0].update(source="model"),
                   lambda value: value.update(admission_reasons=["epss"])):
        changed = copy.deepcopy(finding)
        mutate(changed["lead_menu"][0])
        assert not validator.is_valid(changed)
    changed = copy.deepcopy(hunt)
    changed["lead_menu"][0]["advisory_context"] = None
    assert not validator.is_valid(changed)


def test_reference_shards_and_lead_context_are_stable_across_rebuilds_and_seeds(tmp_path: Path) -> None:
    first = build_accepted_index_set(tmp_path / "a")
    second = build_accepted_index_set(tmp_path / "b", seed=7)
    assert {key: value["snapshot_id"] for key, value in first.feed_pins.items() if value["status"] == "pinned"} == {
        key: value["snapshot_id"] for key, value in second.feed_pins.items() if value["status"] == "pinned"}
    scopes = [accept_manifest(item.run_root) for item in (first, second)]
    for name in ("dependency_advisories", "reference_intelligence"):
        assert [shard["sha256"] for shard in scopes[0].producer(name).shards] == [
            shard["sha256"] for shard in scopes[1].producer(name).shards]
    menus = []
    for item, scope in zip((first, second), scopes):
        assembly = assemble_packages(scope, cwe_reference=load_cwe_reference(item.run_root))
        menus.append(next(package.document()["lead_menu"] for package in assembly.packages
                          if package.lead_ids == (item.ids["dep_high"],)))
    assert menus[0] == menus[1]


# --- scoring ---------------------------------------------------------------------------------------------

REQUEST = ScoreRequest(claim_id="claim-" + "1" * 64, adjudication_id="adjudication-" + "2" * 64,
                       claim_state=ClaimState.SUPPORTED, weakness_cwe="CWE-400", evidence_relation_ids=("evrel-" + "5" * 64,),
                       environment_sha256=None, policy_sha256="3" * 64,
                       scorer_actor_id="actor-" + "4" * 64)
TABLE = {"CWE-400": "high"}


def test_kev_raises_exploitability_one_band_only_for_scoreable_claims() -> None:
    provider = ApplicationRiskMatrixProvider(TABLE)
    plain = provider.score(REQUEST)
    raised = provider.score(replace(REQUEST, kev_listed=True))
    assert plain.exploitability_confidence.rating == "medium" and plain.technical_severity.rating == "medium"
    assert raised.exploitability_confidence.rating == "high" and raised.technical_severity.rating == "high"
    assert raised.native["kev_adjusted"] is True and any("KEV" in item for item in raised.assumptions)
    confirmed = provider.score(replace(REQUEST, claim_state=ClaimState.CONFIRMED, kev_listed=True))
    assert confirmed.exploitability_confidence.rating == "high" and "kev_adjusted" not in confirmed.native
    assert not provider.validate_inputs(replace(REQUEST, claim_state=ClaimState.INSUFFICIENT_EVIDENCE,
                                                kev_listed=True)).valid
    assert provider.score(replace(REQUEST, kev_listed=False)).exploitability_confidence.rating == "medium"


def test_reference_inputs_pass_through_and_leave_absent_fingerprints_unchanged() -> None:
    provider = ApplicationRiskMatrixProvider(TABLE)
    cvss = ({"cve_id": "CVE-2026-0001", "version": "4.0", "vector": V40["vectorString"], "base_score": 8.7},)
    epss = {"cve_id": "CVE-2026-0001", "epss": 0.42, "percentile": 0.97, "score_date": "2026-10-11"}
    result = provider.score(replace(REQUEST, reference_cvss=cvss, epss=epss))
    assert result.reference_inputs == {"label": "reference_context", "reference_cvss": [dict(cvss[0])],
                                       "kev_listed": None, "epss": epss}
    assert result.technical_severity == provider.score(REQUEST).technical_severity
    assert result.input_fingerprint != provider.score(REQUEST).input_fingerprint
    assert "reference_cvss" not in REQUEST.canonical() and provider.score(REQUEST).reference_inputs == {}
    package = stages.score_package_json(result)
    schema = json.loads((SCORE_SCHEMA_DIR / "score-package.schema.json").read_text())
    from referencing import Registry, Resource
    documents = [json.loads(path.read_text()) for path in SCORE_SCHEMA_DIR.glob("*.schema.json")]
    registry = Registry().with_resources((item["$id"], Resource.from_contents(item)) for item in documents)
    jsonschema.Draft202012Validator(schema, registry=registry).validate(package)
    assert package["reference_inputs"]["reference_cvss"][0]["vector"].startswith("CVSS:4.0")
    assert "reference_inputs" not in stages.score_package_json(provider.score(REQUEST))


def test_claim_references_come_only_from_proposing_lead_packages(fixture, scope) -> None:
    assembly = assemble_packages(scope)
    documents = {item.package_id: item.document() for item in assembly.packages}
    lead = next(item.package_id for item in assembly.packages if item.lead_ids == (fixture.ids["dep_high"],))
    hunt = next(item.package_id for item in assembly.packages if item.kind == "hunt")
    merged = {"proposal_packages": {"claim-a": [lead, hunt], "claim-b": [hunt]}}
    references = stages.claim_references(merged, documents)
    assert set(references) == {"claim-a"}
    assert references["claim-a"]["kev_listed"] is True and references["claim-a"]["epss"]["percentile"] == 0.97
    assert {item["version"] for item in references["claim-a"]["reference_cvss"]} == {"3.1", "4.0"}
