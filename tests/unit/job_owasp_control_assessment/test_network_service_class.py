"""D2/D3/D4 (run 2026-11-16-0005): a raw-socket listener admits the transport-agnostic ASVS chapters.

The smoke-cpp request server is ``target:cli`` plus ``target:network-service``. ASVS admits that class
for V1, V2, V5, V7 and V16 only (ASVS 5.0 chapter ids; V1.4 holds the memory-safety controls), the
web-only chapters stay ``not_applicable`` citing the class, and MASVS is a not-applicable ledger line.
With no supported source language the admitted rows are ``unsupported_missing_evidence`` naming that
cause (T-5011/T-5013), never ``cannot_determine``.
"""
from __future__ import annotations

from collections import Counter
import hashlib
from pathlib import Path
import tomllib

import pytest

from appsec_review.owasp_workbench import (
    build_applicability, classify_components, control_records, load_catalogs, partition_work, select_profiles,
    target_class_ledger,
)
from appsec_review.owasp_workbench import engine

ROOT = Path(__file__).resolve().parents[3]
ADMITTED = ["V1", "V2", "V5", "V7", "V16"]


@pytest.fixture(scope="module")
def catalogs():
    document = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    return load_catalogs(ROOT, document["jobs"]["job_owasp_control_assessment"]["settings"]["standards"])


def citation(name: str) -> dict:
    return {"source_identity": name, "artifact_sha256": hashlib.sha256(name.encode()).hexdigest(), "lines": [1, 2]}


def routing(tag: str, basis: str = "derived") -> dict:
    return {"identity": f"asr:tag_assignment:{hashlib.sha256(tag.encode()).hexdigest()}", "kind": "tag_assignment",
            "index": "tags", "name": tag, "tag": tag, "basis": basis,
            "subject": {"kind": "component", "logical_id": "c", "assignment_id": f"tag:{tag}"}, "usage": "routing_only"}


NETWORK_SERVICE = [routing("lang:cpp", "declared"), routing("mechanism:cli", "declared"),
                   routing("mechanism:networked-listener", "declared"), routing("trust:user-tainted"),
                   routing("exposure:client-facing"), routing("role:session"), routing("state:session"),
                   routing("target:cli"), routing("target:network-service")]
NO_SUPPORTED_SOURCE = {"supported_files": 0, "unsupported_files": 134, "evidence_count": 0,
                       "recognisers": "python-only (T-5011/T-5013)"}


def component(component_id: str, records: list[dict], **extra) -> dict:
    return {"target_id": "target-1", "project_id": "project-1", "component_id": component_id,
            "paths": [f"{component_id}/main.cpp"], "languages": ["C++"], "frameworks": [], "tags": [],
            "evidence": [citation(f"component:{component_id}")], "routing_context": records, **extra}


def test_network_service_admits_the_transport_agnostic_chapters_and_names_the_missing_language(catalogs) -> None:
    [classification] = classify_components([component("srv", NETWORK_SERVICE, source_support=NO_SUPPORTED_SOURCE)])
    assert classification["target_classes"] == ["target:cli", "target:network-service"]
    assert "network" in classification["roles"] and classification["confidence"] == "high"
    selection = select_profiles(catalogs, asvs_level=2, masvs_profile="L2")
    rows = build_applicability(catalogs, [classification], selection)
    asvs = [row for row in rows if row["standard"] == "ASVS"]
    masvs = [row for row in rows if row["standard"] == "MASVS"]
    controls = control_records(catalogs, asvs_level=2, masvs_profile="L2")
    expected_admitted = sum(1 for item in controls if item["family"] == "ASVS" and engine.chapter_of(item["id"]) in ADMITTED)
    by_outcome = Counter(row["outcome"] for row in asvs)
    # Pinned ASVS 5.0.0 at L2: 253 controls, 81 in the admitted chapters (27+11+9+18+16), 172 web-only.
    assert by_outcome == {"unsupported_missing_evidence": expected_admitted, "not_applicable": 253 - expected_admitted}
    assert expected_admitted == 81
    for row in asvs:
        assert row["target_classes"] == ["target:cli", "target:network-service"]
        assert row["basis_class"] == "target:network-service" and row["admitted_chapters"] == ADMITTED
        assert row["rule_version"] == engine.APPLICABILITY_RULE
        if engine.chapter_of(row["control_id"]) in ADMITTED:
            assert row["outcome"] == "unsupported_missing_evidence"
            assert row["reason"] == "no supported source language for this component"
            assert row["gaps"] and "T-5011/T-5013" in row["gaps"][0]
        else:
            assert row["outcome"] == "not_applicable" and row["gaps"] == []
            assert "target:network-service admits ASVS only for the transport-agnostic chapters V1, V2, V5, V7, V16" in row["reason"]
            assert f"{engine.chapter_of(row['control_id'])} is web-only" in row["reason"]
            assert "basis tag:target:cli, tag:target:network-service" in row["reason"]
    assert len(masvs) == 24 and {row["outcome"] for row in masvs} == {"not_applicable"}
    assert all("target:mobile is required" in row["reason"] and row["admitted_chapters"] is None for row in masvs)
    ledger = {entry["family"]: entry for entry in target_class_ledger([classification], rows)["entries"]}
    assert ledger["ASVS"]["verdict"] == "partially_applicable"
    assert ledger["ASVS"]["basis_class"] == "target:network-service" and ledger["ASVS"]["admitted_chapters"] == ADMITTED
    assert ledger["ASVS"]["outcomes"] == {"not_applicable": 253 - expected_admitted, "unsupported_missing_evidence": expected_admitted}
    assert ledger["MASVS"]["verdict"] == "not_applicable" and ledger["MASVS"]["basis_class"] is None
    assert all(entry["citations"] for entry in ledger.values())
    assert partition_work(rows, ROOT)["batches"] == []


def test_admitted_chapters_are_not_class_gated_when_sources_are_supported(catalogs) -> None:
    [classification] = classify_components([component("srv", NETWORK_SERVICE)])
    assert classification["source_support"] is None
    rows = build_applicability(catalogs, [classification], select_profiles(catalogs, asvs_level=2, masvs_profile="L2"))
    admitted = [row for row in rows if row["standard"] == "ASVS" and engine.chapter_of(row["control_id"]) in ADMITTED]
    assert admitted and all("web-only" not in row["reason"] and "no supported source language" not in row["reason"]
                            for row in admitted)
    assert not any(row["outcome"] == "cannot_determine" for row in rows)


def test_web_api_class_still_admits_every_chapter_and_a_cli_alone_admits_none(catalogs) -> None:
    web = [routing("mechanism:http", "declared"), routing("target:web-api")]
    cli = [routing("mechanism:cli", "declared"), routing("target:cli")]
    classifications = classify_components([component("api", web), component("tool", cli)])
    rows = build_applicability(catalogs, classifications, select_profiles(catalogs, asvs_level=2, masvs_profile="L2"))
    for row in rows:
        if row["standard"] != "ASVS":
            continue
        if row["component_id"] == "api":
            assert row["basis_class"] == "target:web-api" and row["admitted_chapters"] is None
            assert "excludes" not in row["reason"] and "web-only" not in row["reason"]
        else:
            assert row["outcome"] == "not_applicable" and "target:cli excludes ASVS" in row["reason"]
    ledger = {(entry["component_id"], entry["family"]): entry["verdict"]
              for entry in target_class_ledger(classifications, rows)["entries"]}
    assert ledger == {("api", "ASVS"): "applicable", ("api", "MASVS"): "not_applicable",
                      ("tool", "ASVS"): "not_applicable", ("tool", "MASVS"): "not_applicable"}


def test_class_admission_rule() -> None:
    assert engine.class_admission("ASVS", "V1.4.2", {"target:web-api"}) == (True, "target:web-api", None)
    assert engine.class_admission("ASVS", "V1.4.2", {"target:network-service", "target:cli"}) == (
        True, "target:network-service", engine.FAMILY_PARTIAL_TARGET_CLASSES["ASVS"]["target:network-service"])
    assert engine.class_admission("ASVS", "V6.2.1", {"target:network-service"})[0] is False
    assert engine.class_admission("ASVS", "V6.2.1", {"target:cli"}) == (False, None, None)
    assert engine.class_admission("MASVS", "MASVS-STORAGE-1", {"target:network-service"}) == (False, None, None)
    assert engine.class_admission("MASVS", "MASVS-STORAGE-1", {"target:mobile"}) == (True, "target:mobile", None)
    assert engine.chapter_of("V16.3.1") == "V16" and engine.chapter_of("MASVS-STORAGE-1") == "MASVS-STORAGE-1"


def test_selection_records_a_reason_per_family(catalogs) -> None:
    selection = select_profiles(catalogs, asvs_level=2, masvs_profile="L2")
    by_family = {item["family"]: item for item in selection["selections"]}
    assert set(by_family) == {"ASVS", "MASVS", "MASTG", "OWASP_API_TOP_10", "OWASP_TOP_10"}
    assert all(item["reasons"] for item in by_family.values())
    assert by_family["ASVS"]["reasons"][0].startswith("selected by configuration policy asvs_level=2: 253 controls")
    assert by_family["ASVS"]["selected_controls"] == 253 and by_family["MASVS"]["selected_controls"] == 24
    assert any("MASVS/MASTG retained pending the target-class gate" in reason for reason in by_family["MASVS"]["reasons"])
    assert any("MASVS/MASTG retained pending the target-class gate" in reason for reason in by_family["MASTG"]["reasons"])
    for family in ("OWASP_API_TOP_10", "OWASP_TOP_10"):
        assert by_family[family]["selected_controls"] == 0
        assert any("routing context; no controls are selected" in reason for reason in by_family[family]["reasons"])
    assert selection["control_count"] == 277
    # The reasons are part of the recorded selection and therefore of its fingerprint.
    assert select_profiles(catalogs, asvs_level=1, masvs_profile="L2")["selection_fingerprint"] != selection["selection_fingerprint"]
