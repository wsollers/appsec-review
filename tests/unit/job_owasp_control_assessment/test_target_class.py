"""T-5008 Done-when (c): the OWASP workbench reads target classes and facets from the accepted tags.

A ``lang:cpp`` + ``mechanism:cli`` component is not applicable to ASVS and MASVS with the target-class
citation, dispatches nothing and produces no control fact; an HTTP component is ``target:web-api`` and
keeps its ASVS matrix. The workbench keeps no keyword classifier.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review import owasp_workbench
from appsec_review.owasp_workbench import (
    build_applicability, classify_components, load_catalogs, partition_work, select_profiles, target_class_ledger,
)
from appsec_review.owasp_workbench import engine

ROOT = Path(__file__).resolve().parents[3]
CATALOG_FILES = {
    "ASVS": "asvs-5.0.0.json", "MASVS": "masvs-2.1.0.json", "MASTG": "mastg-2.0.0.json",
    "OWASP_API_TOP_10": "api-top10-2023.json", "OWASP_TOP_10": "top10-2025.json",
}


def sources() -> dict:
    from appsec_review.owasp_workbench.standards import digest
    result = {}
    for family, name in CATALOG_FILES.items():
        path = ROOT / "data" / "reference" / "owasp" / "fixtures" / name
        document = json.loads(path.read_text(encoding="utf-8"))
        result[family] = {"catalog_path": path.relative_to(ROOT).as_posix(), "catalog_sha256": digest(document),
                          "version": document["version"], **document["upstream"]}
    return result


def citation(name: str) -> dict:
    import hashlib
    return {"source_identity": name, "artifact_sha256": hashlib.sha256(name.encode()).hexdigest(), "lines": [1, 2]}


def routing(tag: str, basis: str = "derived", *, redacted: bool = False, name: bool = True) -> dict:
    """One accepted tags-index record as ``accepted_inputs`` projects it (the name carries the tag)."""
    return {"identity": f"asr:tag_assignment:{abs(hash(tag)):064x}"[:84], "kind": "tag_assignment", "index": "tags",
            "name": tag if name else None, "tag": "<redacted>" if redacted else tag, "basis": basis,
            "subject": {"kind": "component", "logical_id": "c", "assignment_id": f"tag:{tag}"}, "usage": "routing_only"}


def component(component_id: str, records: list[dict]) -> dict:
    return {"target_id": "target-1", "project_id": "project-1", "component_id": component_id,
            "paths": [f"{component_id}/main.txt"], "languages": [], "frameworks": [], "tags": [],
            "evidence": [citation(f"component:{component_id}")], "routing_context": records}


CLI = [routing("lang:cpp", "declared"), routing("mechanism:cli", "declared"), routing("trust:user-tainted"),
       routing("exposure:operator-only"), routing("target:cli")]
WEB = [routing("lang:python", "declared"), routing("mechanism:http", "declared"), routing("role:auth", "declared"),
       routing("asset:credentials", redacted=True), routing("role:storage"), routing("target:web-api")]


def prepared(components):
    catalogs = load_catalogs(ROOT, sources())
    classifications = classify_components(components)
    selection = select_profiles(catalogs, asvs_level=2, masvs_profile="L2")
    return catalogs, classifications, selection, build_applicability(catalogs, classifications, selection)


def test_cpp_cli_component_is_not_applicable_to_both_families_with_the_class_citation() -> None:
    _, classifications, _, rows = prepared([component("tool", CLI)])
    [classification] = classifications
    assert classification["target_classes"] == ["target:cli"] and classification["confidence"] == "high"
    assert "mechanism:cli" in classification["facets"] and classification["roles"] == []
    assert not classification["gaps"]
    assert rows and {row["outcome"] for row in rows} == {"not_applicable"}
    assert {row["standard"] for row in rows} == {"ASVS", "MASVS"}
    for row in rows:
        assert row["target_classes"] == ["target:cli"] and row["gaps"] == []
        assert [item["tag"] for item in row["target_class_citations"]] == ["target:cli"]
        assert "target:cli is required" not in row["reason"] and "target:cli excludes" in row["reason"]
        assert row["rule_version"] == engine.APPLICABILITY_RULE == "applicability-rules/4"
    work = partition_work(rows, ROOT)
    assert work["batches"] == [] and work["accounting"]["dispatched_rows"] == 0
    assert len(work["non_dispatch_dispositions"]) == len(rows)
    ledger = target_class_ledger(classifications, rows)
    assert {(entry["family"], entry["verdict"]) for entry in ledger["entries"]} == {
        ("ASVS", "not_applicable"), ("MASVS", "not_applicable")}
    assert all(entry["citations"] and entry["outcomes"] == {"not_applicable": entry["selected_controls"]}
               for entry in ledger["entries"])


def test_http_component_is_web_api_and_keeps_its_asvs_matrix_while_masvs_is_gated() -> None:
    _, classifications, _, rows = prepared([component("api", WEB)])
    [classification] = classifications
    assert classification["target_classes"] == ["target:web-api"]
    assert {"application_api_server", "network", "authentication_identity", "storage",
            "cryptography_data_protection"} <= set(classification["roles"])
    # The redacted payload copy of asset:credentials did not hide the tag: the entity name carried it.
    assert "asset:credentials" in classification["facets"]
    asvs = [row for row in rows if row["standard"] == "ASVS"]
    masvs = [row for row in rows if row["standard"] == "MASVS"]
    assert any(row["outcome"] == "applicable" for row in asvs)
    assert masvs and {row["outcome"] for row in masvs} == {"not_applicable"}
    assert all("target:mobile is required" in row["reason"] for row in masvs)
    assert any(row["outcome"] in {"applicable", "not_applicable"} for row in asvs)
    ledger = target_class_ledger(classifications, rows)
    assert {(entry["family"], entry["verdict"]) for entry in ledger["entries"]} == {
        ("ASVS", "applicable"), ("MASVS", "not_applicable")}


def test_mixed_target_routes_each_family_to_the_component_whose_class_admits_it() -> None:
    mobile = [routing("lang:kotlin", "declared"), routing("component:android-mobile", "declared"), routing("target:mobile")]
    _, classifications, _, rows = prepared([component("api", WEB), component("app", mobile)])
    applicable = {(row["standard"], row["component_id"]) for row in rows
                  if row["outcome"] in {"applicable", "unsupported_missing_evidence"}}
    assert ("ASVS", "api") in applicable and ("MASVS", "app") in applicable
    assert all(row["outcome"] == "not_applicable" for row in rows
               if (row["standard"], row["component_id"]) in {("MASVS", "api"), ("ASVS", "app")})
    app = next(item for item in classifications if item["component_id"] == "app")
    assert app["roles"] == ["android_mobile"]


def test_component_without_a_class_is_cannot_determine_never_guessed() -> None:
    _, classifications, _, rows = prepared([component("mystery", [routing("lang:python", "declared")])])
    [classification] = classifications
    assert classification["target_classes"] == [] and classification["confidence"] == "low"
    assert classification["gaps"] == ["collation assigned no target class to this component; applicability cannot be determined"]
    assert {row["outcome"] for row in rows} == {"cannot_determine"}
    assert all("unresolved" in row["reason"] and row["gaps"] for row in rows)
    assert partition_work(rows, ROOT)["batches"] == []


@pytest.mark.parametrize("record", [
    routing("target:web-api", "declared"),          # a class is only ever derived
    routing("target:web-api", "confirmed"),
    routing("func:authn:jwt", "invoked"),           # a capability tag is not a class or a facet
    {"tag": "target:web-api"},                      # no basis
    {"name": "target:web-api", "basis": "derived"},  # grammatical but malformed subject is fine; checked below
    "target:web-api", None, {"name": ["target:web-api"], "basis": "derived"},
])
def test_only_derived_grammatical_target_tags_establish_a_class(record) -> None:
    [classification] = classify_components([component("c", [record])])
    if isinstance(record, dict) and record.get("name") == "target:web-api" and record.get("basis") == "derived" \
            and isinstance(record["name"], str):
        assert classification["target_classes"] == ["target:web-api"]
    else:
        assert classification["target_classes"] == [] and classification["roles"] == []


def test_the_keyword_classifier_is_gone() -> None:
    assert not hasattr(engine, "_deterministic_roles") and not hasattr(engine, "_CAPABILITY_TAG_ROLES")
    assert not hasattr(engine, "characterize_components") and "characterize_components" not in owasp_workbench.__all__
    # Metadata keywords that used to classify ("server", "api", frameworks) establish nothing now.
    raw = {**component("kw", []), "tags": ["server", "api", "auth"], "frameworks": ["flask"],
           "paths": ["tests/test_x.py"]}
    [classification] = classify_components([raw])
    assert classification["roles"] == [] and classification["target_classes"] == []
    assert classification["schema"] == "appsec-review/component-classification/2"
