"""Decision 11: impact_class derived from the pinned MITRE CWE catalog (cwe-impact-derivation/1)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.review.references import CweConsequence, CweEntry, CweReference, load_cwe_reference
from appsec_review.review.scoring import (
    LEGACY_CWE_IMPACT_CLASSES, ApplicationRiskMatrixV2Provider, build_provider, default_factor_registry,
    default_registry,
)
from appsec_review.review.scoring.cwe_impact import (
    DERIVATION_RULE, IMPACT_CLASSES, IMPACT_RULES, UNAVAILABLE_CATALOG, ImpactCatalog, ImpactOverride, derive,
)
from appsec_review.review.scoring.factors import Citation, CitationKind, FactorId, FactorValue, MissingFactor
from appsec_review.review.scoring.risk_model import DEFAULT_RISK_MODEL
from tests.fixtures.inference_review.builder import build_accepted_index_set
from tests.review.test_scoring_factors import SCHEMAS, data, request, run_stage, strong_relations

SNAPSHOT = "sha256-" + "a" * 24
CIA = ("Confidentiality", "Integrity", "Availability")


def consequences(*entries: tuple[tuple[str, ...], tuple[str, ...]]) -> tuple[CweConsequence, ...]:
    return tuple(CweConsequence(index, tuple(scopes), tuple(impacts)) for index, (scopes, impacts) in enumerate(entries))


CATALOG_ROWS = {
    "CWE-120": consequences((("Integrity", "Confidentiality", "Availability"),
                             ("Modify Memory", "Execute Unauthorized Code or Commands")),
                            (("Availability",), ("DoS: Crash, Exit, or Restart",))),
    "CWE-200": consequences((("Confidentiality",), ("Read Application Data",))),
    "CWE-400": consequences((("Availability",), ("DoS: Resource Consumption (CPU)",))),
    "CWE-79": consequences((("Access Control", "Confidentiality"), ("Bypass Protection Mechanism",)),
                           (CIA, ("Execute Unauthorized Code or Commands",))),
    "CWE-1007": (),
    "CWE-1059": consequences((("Other",), ("Varies by Context", "Other"))),
}


def catalog(status: str = "current", rows=None, snapshot: str = SNAPSHOT, gap: str | None = None) -> ImpactCatalog:
    return ImpactCatalog(status, CATALOG_ROWS if rows is None else rows, snapshot_id=snapshot,
                         manifest_sha256="b" * 64, version="4.20",
                         gap=gap or ("mitre_stale_feed: fixture" if status == "stale" else None))


def impact(cwe: str, overrides=None, source: ImpactCatalog | None = None) -> FactorValue | MissingFactor:
    values = default_factor_registry(overrides or {}, source if source is not None else catalog()).extract(
        data(cwe=cwe), [FactorId.IMPACT_CLASS])
    return values.get(FactorId.IMPACT_CLASS) or values.missing[0]


# ------------------------------------------------------------------------------------------- the rule


@pytest.mark.parametrize("entries, expected", [
    ([(CIA, ["Execute Unauthorized Code or Commands"])], "critical"),
    ([(["Integrity"], ["Modify Memory"])], "high"),
    ([(["Access Control"], ["Gain Privileges or Assume Identity"])], "high"),
    ([(["Access Control"], ["Bypass Protection Mechanism"])], "high"),
    ([(["Integrity"], ["Modify Application Data"])], "high"),
    ([(["Confidentiality"], ["Read Memory"])], "medium"),
    ([(["Confidentiality"], ["Read Application Data", "Read Files or Directories"])], "medium"),
    # A read is raised to high when the weakness also has a non-trivial integrity-scoped consequence,
    # but not when every integrity impact is rated low (e.g. only Unexpected State).
    ([(["Confidentiality"], ["Read Memory"]), (["Integrity"], ["Other"])], "high"),
    ([(["Confidentiality"], ["Read Memory"]), (["Integrity"], ["Varies by Context"])], "high"),
    ([(["Confidentiality"], ["Read Memory"]), (["Integrity"], ["Unexpected State"])], "medium"),
    ([(["Confidentiality"], ["Read Memory"]), (["Integrity"], ["Unexpected State", "Quality Degradation"])],
     "medium"),
    ([(["Confidentiality", "Integrity"], ["Read Application Data"])], "high"),
    ([(["Availability"], ["DoS: Crash, Exit, or Restart"])], "medium"),
    ([(["Availability"], ["DoS: Resource Consumption (Memory)", "DoS: Amplification"])], "medium"),
    ([(["Availability"], ["Reduce Performance"])], "low"),
    ([(["Non-Repudiation"], ["Hide Activities"])], "low"),
    # The highest applicable class wins, wherever it appears.
    ([(["Availability"], ["DoS: Crash, Exit, or Restart"]), (["Confidentiality"], ["Read Memory"]),
      (CIA, ["Execute Unauthorized Code or Commands"])], "critical"),
    ([(["Other"], ["Varies by Context", "Other"]), (["Availability"], ["Reduce Reliability"])], "low"),
    # Matching ignores case and runs of whitespace; unknown impacts contribute nothing.
    ([(["Integrity"], ["execute  unauthorized code or COMMANDS"])], "critical"),
    ([(["Other"], ["Varies by Context", "Other", "Summon Dragons"])], None),
    ([(["Integrity"], [])], None),
    ([], None),
])
def test_derivation_truth_table(entries, expected) -> None:
    derived = derive(consequences(*((tuple(scopes), tuple(impacts)) for scopes, impacts in entries)))
    assert (derived.impact_class if derived else None) == expected


def test_rule_table_is_closed_on_the_factor_scale() -> None:
    assert DERIVATION_RULE == "cwe-impact-derivation/1"
    assert set(IMPACT_RULES.values()) <= set(IMPACT_CLASSES)
    assert all(key == key.casefold() and key == " ".join(key.split()) for key in IMPACT_RULES)
    assert IMPACT_CLASSES == ("low", "medium", "high", "critical")


def test_derived_factor_cites_the_catalog_snapshot_and_consequence_entries() -> None:
    value = impact("CWE-120")
    assert value.value == "critical"
    assert value.citations == (Citation(CitationKind.REFERENCE_INPUT, f"mitre-cwe:{SNAPSHOT}:CWE-120:consequence/0"),)
    assert value.detail["basis"] == ("derived",) and value.detail["rule"] == (DERIVATION_RULE,)
    assert value.detail["catalog_snapshot"] == (SNAPSHOT,) and value.detail["catalog_status"] == ("current",)
    assert value.detail["technical_impacts"] == ("Execute Unauthorized Code or Commands",)
    assert "catalog_gap" not in value.detail
    assert impact("CWE-400").value == "medium" and impact("CWE-200").value == "medium"


def test_an_integrity_raise_cites_the_integrity_scoped_entry() -> None:
    rows = {"CWE-1": consequences((("Confidentiality",), ("Read Memory",)), (("Availability",), ("Reduce Performance",)),
                                  (("Integrity",), ("Other",)))}
    value = impact("CWE-1", source=catalog(rows=rows))
    assert value.value == "high" and "integrity_raised" in value.detail
    assert [item.id.rsplit("/", 1)[1] for item in value.citations] == ["0", "2"]


@pytest.mark.parametrize("cwe, reason", [
    ("CWE-787", "CWE-787 is not a weakness in the pinned MITRE CWE catalog " + SNAPSHOT),
    ("CWE-1007", "CWE-1007 has no Common_Consequences in the pinned MITRE CWE catalog"),
    ("CWE-1059", "no technical impact of CWE-1059 (Other, Varies by Context) is mapped by cwe-impact-derivation/1"),
])
def test_underivable_cwes_are_missing_with_a_reason_never_low(cwe, reason) -> None:
    outcome = impact(cwe)
    assert isinstance(outcome, MissingFactor) and outcome.reason.startswith(reason)


def test_a_claim_without_a_cwe_is_missing() -> None:
    values = default_factor_registry({}, catalog()).extract(data(cwe=None), [FactorId.IMPACT_CLASS])
    assert values.missing[0].reason == "claim has no weakness CWE"


# ------------------------------------------------------------------------------------------- precedence


def test_override_beats_derivation_and_records_the_derived_class() -> None:
    override = {"CWE-79": ImpactOverride("medium", "script runs in the victim's browser")}
    value = impact("CWE-79", override)
    assert impact("CWE-79").value == "critical"
    assert value.value == "medium"
    assert value.citations == (Citation(CitationKind.CONFIGURATION, "cwe_impact_overrides.CWE-79"),)
    assert value.detail["basis"] == ("override",) and value.detail["derived_class"] == ("critical",)
    assert value.detail["override_reason"] == ("script runs in the victim's browser",)


def test_override_applies_without_a_catalog_and_fills_an_underivable_cwe() -> None:
    assert impact("CWE-1059", {"CWE-1059": "low"}).value == "low"
    unpinned = impact("CWE-89", {"CWE-89": ImpactOverride("critical", "r")}, UNAVAILABLE_CATALOG)
    assert unpinned.value == "critical" and "derived_class" not in unpinned.detail
    assert "catalog_snapshot" not in unpinned.detail


def test_overrides_are_validated() -> None:
    with pytest.raises(ValueError, match="impact class must be one of"):
        ImpactOverride("catastrophic", "r")
    with pytest.raises(ValueError, match="invalid CWE impact override"):
        default_factor_registry({"SQLi": "high"})
    with pytest.raises(ValueError, match="conflicting"):
        default_factor_registry({"CWE-120": "high", "cwe-0120": "low"})


# ------------------------------------------------------------------------------------------- catalog states


def test_unpinned_catalog_derives_nothing() -> None:
    outcome = impact("CWE-120", source=UNAVAILABLE_CATALOG)
    assert isinstance(outcome, MissingFactor)
    assert outcome.reason.startswith("impact_class not derived: mitre_feed_unavailable")


def test_catalog_view_follows_the_reference_pin_state() -> None:
    entries = {cwe: CweEntry(cwe, None, None, rows) for cwe, rows in CATALOG_ROWS.items()}
    identity = {"snapshot_id": SNAPSHOT, "manifest_sha256": "b" * 64, "version": "4.20"}
    current = ImpactCatalog.from_reference(CweReference("mitre_catalog", entries, consequences_indexed=True,
                                                        **identity))
    assert current.status == "current" and current.gap is None and current.consequences["CWE-120"]
    stale = ImpactCatalog.from_reference(CweReference("fallback", entries, gap="mitre_stale_feed: old", stale=True,
                                                      consequences_indexed=True, **identity))
    assert stale.status == "stale" and stale.gap == "mitre_stale_feed: old"
    mismatch = ImpactCatalog.from_reference(CweReference("fallback", {}, gap="mitre_identity_mismatch: x", **identity))
    assert mismatch.status == "unavailable" and mismatch.gap == "mitre_identity_mismatch: x"
    old_index = ImpactCatalog.from_reference(CweReference("mitre_catalog", entries, **identity))
    assert old_index.status == "unavailable" and old_index.gap.startswith("mitre_consequences_unavailable")
    assert isinstance(impact("CWE-120", source=old_index), MissingFactor)


def test_a_stale_catalog_still_derives_and_records_the_stale_gap() -> None:
    value = impact("CWE-120", source=catalog("stale"))
    assert value.value == "critical"
    assert value.detail["catalog_status"] == ("stale",) and value.detail["catalog_gap"] == ("mitre_stale_feed: fixture",)
    scorer = ApplicationRiskMatrixV2Provider({}, DEFAULT_RISK_MODEL, catalog("stale"))
    factors = default_factor_registry({}, catalog("stale")).extract(data(strong_relations()), scorer.consumed_factors)
    result = scorer.score(request(factors))
    assert result.technical_severity.rating == "critical"
    assert any("stale pinned MITRE CWE catalog" in item for item in result.assumptions)


def test_catalog_states_are_validated() -> None:
    with pytest.raises(ValueError, match="unknown impact catalog status"):
        ImpactCatalog("fresh", snapshot_id=SNAPSHOT)
    with pytest.raises(ValueError, match="needs its snapshot id"):
        ImpactCatalog("current")
    with pytest.raises(ValueError, match="needs its gap"):
        ImpactCatalog("stale", snapshot_id=SNAPSHOT)


# ------------------------------------------------------------------------------------------- fingerprints


def _score(overrides=None, source=None):
    source = source if source is not None else catalog()
    scorer = ApplicationRiskMatrixV2Provider(overrides or {}, DEFAULT_RISK_MODEL, source)
    factors = default_factor_registry(overrides or {}, source).extract(data(strong_relations()),
                                                                      scorer.consumed_factors)
    return scorer.score(request(factors))


def test_fingerprint_binds_the_rule_the_catalog_snapshot_and_the_overrides() -> None:
    base = _score()
    assert base == _score()
    other_snapshot = _score(source=catalog(snapshot="sha256-" + "c" * 24))
    stale = _score(source=catalog("stale"))
    override = _score({"CWE-200": ImpactOverride("low", "r")})
    reason = _score({"CWE-200": ImpactOverride("low", "another reason")})
    configs = {item.provider_config_sha256 for item in (base, other_snapshot, stale, override, reason)}
    assert len(configs) == 5
    assert len({item.score_id for item in (base, other_snapshot, stale, override, reason)}) == 5
    assert len({item.input_fingerprint for item in (base, other_snapshot, stale, override, reason)}) == 5
    scorer = ApplicationRiskMatrixV2Provider({}, DEFAULT_RISK_MODEL, catalog())
    assert scorer.impact_catalog.snapshot_id == SNAPSHOT


def test_provider_rejects_an_impact_factor_from_another_catalog() -> None:
    scorer = ApplicationRiskMatrixV2Provider({}, DEFAULT_RISK_MODEL, catalog())
    foreign = default_factor_registry({}, catalog(snapshot="sha256-" + "d" * 24)).extract(
        data(strong_relations()), scorer.consumed_factors)
    errors = scorer.validate_inputs(request(foreign)).errors
    assert any("disagrees with this provider's overrides and pinned CWE catalog" in item for item in errors)


def test_matrix_1_keeps_its_frozen_table() -> None:
    legacy = build_provider("application_risk_matrix/1", {"CWE-120": "low"}, None, catalog())
    assert dict(legacy._table) == dict(LEGACY_CWE_IMPACT_CLASSES)
    registry = default_registry({}, implementation="application_risk_matrix/1", catalog=catalog())
    result = registry.score("application_risk_matrix", request(None))
    assert result.native["cell"] == ["high", "high"]                       # CWE-120 is high in the frozen table


# ------------------------------------------------------------------------------------------- stage and feed


def test_stage_records_the_catalog_and_writes_a_valid_cited_package(tmp_path: Path) -> None:
    document, packages = run_stage(tmp_path, strong_relations(), overrides={}, cwe_catalog=catalog())
    package = json.loads(next(iter(packages.values())))
    SCHEMAS.validate("score-package", package)
    assert document["impact_class"] == {"rule": DERIVATION_RULE, "catalog": catalog().identity()}
    citations = {item["factor"]: item for item in package["factor_citations"]}
    assert citations["impact_class"]["references"] == [f"mitre-cwe:{SNAPSHOT}:CWE-120:consequence/0"]
    factors = {item["factor"]: item for item in package["factors"]}
    assert factors["impact_class"]["value"] == "critical"
    assert factors["impact_class"]["detail"]["catalog_snapshot"] == [SNAPSHOT]
    assert package["native"]["matrix_cell"] == ["critical", "high"]
    _, unpinned = run_stage(tmp_path, strong_relations(), name="unpinned", overrides={})
    package = json.loads(next(iter(unpinned.values())))
    reasons = {item["factor"]: item["reason"] for item in package["missing_factor_reasons"]}
    assert package["technical_severity"]["rating"] is None
    assert reasons["impact_class"].startswith("impact_class not derived: mitre_feed_unavailable")


@pytest.mark.parametrize("variant, status", [({}, "current"), ({"stale_feeds": ("mitre",)}, "stale"),
                                             ({"omit_feeds": ("mitre",)}, "unavailable")])
def test_pinned_fixture_catalog_derives_impact_classes(tmp_path: Path, variant, status) -> None:
    fixture = build_accepted_index_set(tmp_path, **variant)
    source = ImpactCatalog.from_reference(load_cwe_reference(fixture.run_root))
    assert source.status == status
    if status == "unavailable":
        assert source.gap.startswith("mitre_feed_unavailable") and isinstance(impact("CWE-120", source=source),
                                                                               MissingFactor)
        return
    assert source.snapshot_id == fixture.feed_pins["mitre"]["snapshot_id"]
    derived = {cwe: impact(cwe, source=source).value for cwe in ("CWE-78", "CWE-89", "CWE-120", "CWE-190",
                                                                  "CWE-400", "CWE-416", "CWE-787")}
    assert derived == {"CWE-78": "critical", "CWE-89": "critical", "CWE-120": "critical", "CWE-190": "critical",
                       "CWE-400": "medium", "CWE-416": "critical", "CWE-787": "critical"}
    assert (status == "stale") == ("catalog_gap" in impact("CWE-400", source=source).detail)
