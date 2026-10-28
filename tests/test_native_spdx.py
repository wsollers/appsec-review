from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
from importlib import resources
from itertools import permutations
import json
from typing import Any

from jsonschema import Draft7Validator
import pytest

from appsec_review.jobs.job_dependency_intelligence.native_sbom_contracts import (
    DISCOVERY_SCHEMA, PROVENANCE_SCHEMA, SBOM_COUNTERS, NativeInputIntegrityError,
    SbomBounds, SpdxValidationError, candidate_identity, evidence_identity,
)
from appsec_review.jobs.job_dependency_intelligence.sbom import (
    build_spdx, schema_sha256, validate_spdx,
)
from appsec_review.storage import canonical_json


CREATED = "2026-10-28T15:22:43Z"
SOURCE = "a" * 64
BOUNDS = SbomBounds(input_bytes=1_000_000, element_limit=1000,
                    output_bytes=2_000_000, field_bytes=100_000)
PURL = "pkg:generic/Example/Zlib@1.3.1?arch=X86_64&repository_url=https%3A%2F%2FExample.org"


def artifact(path: str, payload: Any = None) -> dict[str, Any]:
    data = canonical_json(payload if payload is not None else path)
    return {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}


def package(identifier: str = "SPDXRef-zlib", **changes: Any) -> dict[str, Any]:
    result = {
        "SPDXID": identifier, "name": "zlib", "versionInfo": "1.3.1",
        "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                          "referenceLocator": PURL}],
    }
    result.update(changes)
    return result


def document(*packages: dict[str, Any], **changes: Any) -> dict[str, Any]:
    result = {
        "SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "name": "accepted source inventory", "documentNamespace": "https://example.test/spdx/source",
        "creationInfo": {"created": CREATED, "creators": ["Tool: syft-1.52.0"]},
        "packages": list(packages), "relationships": [],
    }
    result.update(changes)
    return result


def baseline(doc: dict[str, Any], label: str = "source") -> dict[str, Any]:
    return {
        "document": doc, "artifact": artifact(f"{label}.spdx.json", doc),
        "source_artifact": artifact(f"{label}.syft.json"),
        "tool_identity": {"name": "syft", "version": "1.52.0", "image_id": "sha256:" + "b" * 64},
    }


def candidate(
    name: str = "zlib", root: str = "vendor/zlib", *,
    identity: str = "inferred", release: str = "inferred", upstream: str = "unknown",
    version: str | None = "1.3.1", purl: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    evidence = {
        "kind": "header_version", "value": name + " " + str(version), "source_fingerprint": SOURCE,
        "domain": "target", "root_id": "target", "path": root + "/version.h",
        "sha256": "c" * 64, "upstream": artifact("catalog.json"), "backing": None,
        "selector": {"start_byte": 0, "end_byte": 20, "start_line": 1, "end_line": 1},
    }
    evidence["evidence_id"] = evidence_identity(evidence)
    refs = [evidence["evidence_id"]]

    def claim(value: str | None, status: str) -> dict[str, Any]:
        return {"value": value, "status": status, "evidence_ids": refs if value else [],
                "alternatives": []}

    native = {
        "candidate_id": candidate_identity(SOURCE, "target", root, name), "native_name": name,
        "observations": [{"kind": "header", "path": root + "/version.h"}],
        "metadata": {}, "repository": None, "package_root": root, "root_id": "target",
        "identity": claim(name, identity), "release": claim(version, release),
        "upstream": claim("https://example.org/zlib" if upstream != "unknown" else None, upstream),
        "evidence_ids": refs,
    }
    if purl is not None:
        native["purl"] = purl
    return native, evidence


def discovery(*rows: tuple[dict[str, Any], dict[str, Any]], **changes: Any) -> dict[str, Any]:
    result = {
        "schema": DISCOVERY_SCHEMA, "candidates": [item[0] for item in rows],
        "evidence": [item[1] for item in rows], "gaps": [],
        "coverage": {"eligible_files": len(rows), "read_files": len(rows)},
        "metrics": {"candidates_total": len(rows)},
    }
    result.update(changes)
    return result


def build(
    *docs: dict[str, Any], native: dict[str, Any] | None = None,
    bounds: SbomBounds = BOUNDS, **changes: Any,
) -> dict[str, Any]:
    arguments = {
        "source_fingerprint": SOURCE, "created": CREATED,
        "baselines": [baseline(doc, f"source-{index}") for index, doc in enumerate(docs)],
        "discovery": native if native is not None else discovery(),
        "input_identities": [artifact("catalog.json")], "bounds": bounds,
    }
    arguments.update(changes)
    return build_spdx(**arguments)


def file_record(identifier: str, name: str, **changes: Any) -> dict[str, Any]:
    result = {
        "SPDXID": identifier, "fileName": name,
        "checksums": [{"algorithm": "SHA256", "checksumValue": "d" * 64}],
        "licenseConcluded": "NOASSERTION", "licenseInfoInFiles": ["NOASSERTION"],
        "copyrightText": "NOASSERTION",
    }
    result.update(changes)
    return result


def test_official_schema_is_release_resource_with_recorded_license_and_no_refs() -> None:
    root = resources.files("appsec_review.jobs.job_dependency_intelligence").joinpath("schemas")
    data = root.joinpath("spdx-2.3.schema.json").read_bytes()
    assert schema_sha256() == hashlib.sha256(data).hexdigest()
    assert schema_sha256() == "239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b"
    schema = json.loads(data)
    assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
    assert schema["$id"] == "http://spdx.org/rdf/terms/2.3"
    assert '"$ref"' not in data.decode()
    assert "Creative Commons Attribution 3.0 Unported" in root.joinpath(
        "SPDX-LICENSE.txt").read_text(encoding="utf-8")
    Draft7Validator.check_schema(schema)
    Draft7Validator(schema).validate(document(package()))


@pytest.mark.parametrize("change", [
    lambda doc: doc["packages"][0].update(filesAnalyzed="false"),
    lambda doc: doc["packages"][0].update(primaryPackagePurpose="MADE_UP_PURPOSE"),
    lambda doc: doc["packages"][0].update(externalRefs=[{
        "referenceCategory": "INVENTED", "referenceType": "purl", "referenceLocator": PURL}]),
    lambda doc: doc["packages"][0].update(checksums=[
        {"algorithm": "NOT-A-HASH", "checksumValue": "abc"}]),
    lambda doc: doc["packages"][0].update(unrecognizedExtension="forbidden"),
    lambda doc: doc["creationInfo"].update(creators=23),
    lambda doc: doc.update(spdxVersion="SPDX-3.0"),
    lambda doc: doc["packages"][0].pop("downloadLocation"),
])
def test_official_schema_rejects_nontrivial_invalid_fields(change: Any) -> None:
    doc = document(package())
    change(doc)
    with pytest.raises(SpdxValidationError, match="schema|Expected SPDX"):
        validate_spdx(doc, bounds=BOUNDS)


@pytest.mark.parametrize("identifier", ["SPDXRef-DOCUMENT", "SPDXRef-bad_id", "not-an-spdx-id"])
def test_duplicate_or_invalid_element_identifiers_rejected(identifier: str) -> None:
    with pytest.raises(SpdxValidationError, match="SPDXID"):
        validate_spdx(document(package(identifier)), bounds=BOUNDS)


def test_duplicate_identical_ids_are_not_hidden_by_canonicalization() -> None:
    with pytest.raises(SpdxValidationError, match="duplicate"):
        build(document(package(), package()))


@pytest.mark.parametrize("field,value", [
    ("documentDescribes", ["SPDXRef-absent"]),
    ("relationships", [{"spdxElementId": "SPDXRef-zlib", "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": "SPDXRef-absent"}]),
    ("relationships", [{"spdxElementId": "SPDXRef-absent", "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": "SPDXRef-zlib"}]),
])
def test_schema_valid_but_dangling_document_references_fail(field: str, value: Any) -> None:
    doc = document(package(), **{field: value})
    with pytest.raises(SpdxValidationError, match="reference"):
        validate_spdx(doc, bounds=BOUNDS)


@pytest.mark.parametrize("field", ["hasFiles", "fileDependencies", "snippetFromFile",
                                  "startPointer", "endPointer"])
def test_every_file_and_snippet_reference_is_checked(field: str) -> None:
    doc = rich_document()
    if field == "hasFiles":
        doc["packages"][0][field] = ["SPDXRef-no-file"]
    elif field == "fileDependencies":
        doc["files"][0][field] = ["SPDXRef-no-file"]
    elif field == "snippetFromFile":
        doc["snippets"][0][field] = "SPDXRef-no-file"
    else:
        doc["snippets"][0]["ranges"][0][field]["reference"] = "SPDXRef-no-file"
    with pytest.raises(SpdxValidationError, match="reference"):
        validate_spdx(doc, bounds=BOUNDS)


def rich_document() -> dict[str, Any]:
    annotation = {
        "annotationDate": CREATED, "annotationType": "OTHER",
        "annotator": "Tool: source-scanner", "comment": "baseline annotation",
    }
    return document(
        package(hasFiles=["SPDXRef-header"], filesAnalyzed=True,
                licenseDeclared="LicenseRef-Custom AND MIT", licenseConcluded="LicenseRef-Custom",
                annotations=[annotation], attributionTexts=["original attribution"],
                summary="summary retained", description="description retained"),
        files=[
            file_record("SPDXRef-header", "./vendor/zlib/version.h",
                        fileDependencies=["SPDXRef-helper"], licenseConcluded="LicenseRef-Custom"),
            file_record("SPDXRef-helper", "./vendor/zlib/helper.h"),
        ],
        snippets=[{
            "SPDXID": "SPDXRef-snippet", "name": "snippet", "snippetFromFile": "SPDXRef-header",
            "ranges": [{
                "startPointer": {"reference": "SPDXRef-header", "offset": 0},
                "endPointer": {"reference": "SPDXRef-header", "offset": 19},
            }],
            "licenseConcluded": "LicenseRef-Custom",
        }],
        hasExtractedLicensingInfos=[{
            "licenseId": "LicenseRef-Custom", "extractedText": "Custom license exact text",
            "name": "Custom", "seeAlsos": ["https://example.org/license"],
        }],
        externalDocumentRefs=[{
            "externalDocumentId": "DocumentRef-upstream", "spdxDocument": "https://example.org/spdx/upstream",
            "checksum": {"algorithm": "SHA1", "checksumValue": "e" * 40},
        }],
        documentDescribes=["SPDXRef-zlib"], annotations=[annotation], comment="source comment",
        relationships=[
            {"spdxElementId": "SPDXRef-zlib", "relationshipType": "CONTAINS",
             "relatedSpdxElement": "SPDXRef-header"},
            {"spdxElementId": "SPDXRef-header", "relationshipType": "GENERATED_FROM",
             "relatedSpdxElement": "DocumentRef-upstream:SPDXRef-file"},
        ],
    )


def test_preserves_baseline_fields_and_remaps_complete_reference_graph() -> None:
    doc = rich_document()
    before = deepcopy(doc)
    result = build(doc)
    assert doc == before
    output = result["document"]
    validate_spdx(output, bounds=BOUNDS)
    package_out = output["packages"][0]
    ids = result["provenance"]["baselines"][0]["spdx_id_map"]
    assert ids["SPDXRef-zlib"] == package_out["SPDXID"]
    for field, value in doc["packages"][0].items():
        if field not in {"SPDXID", "hasFiles"}:
            assert package_out[field] == value
    assert package_out["hasFiles"] == [ids["SPDXRef-header"]]
    by_id = {record["SPDXID"]: record for record in output["files"]}
    assert by_id[ids["SPDXRef-header"]]["fileDependencies"] == [ids["SPDXRef-helper"]]
    snippet = output["snippets"][0]
    assert snippet["snippetFromFile"] == ids["SPDXRef-header"]
    assert all(pointer["reference"] == ids["SPDXRef-header"]
               for pointer in snippet["ranges"][0].values())
    assert output["hasExtractedLicensingInfos"] == doc["hasExtractedLicensingInfos"]
    assert output["externalDocumentRefs"] == doc["externalDocumentRefs"]
    assert output["documentDescribes"] == [ids["SPDXRef-zlib"]]
    assert output["comment"] == "source comment"
    assert output["annotations"] == doc["annotations"]
    assert "Tool: syft-1.52.0" in output["creationInfo"]["creators"]
    assert len(output["relationships"]) == 3


@pytest.mark.parametrize("field", ["licenseDeclared", "licenseConcluded", "licenseInfoFromFiles"])
def test_missing_license_ref_is_rejected(field: str) -> None:
    value: Any = "LicenseRef-Missing AND MIT"
    if field == "licenseInfoFromFiles":
        value = [value]
    with pytest.raises(SpdxValidationError, match="LicenseRef"):
        validate_spdx(document(package(**{field: value})), bounds=BOUNDS)


def test_license_refs_in_files_and_snippets_are_checked() -> None:
    for collection in ("files", "snippets"):
        doc = rich_document()
        doc[collection][0]["licenseConcluded"] = "LicenseRef-Missing"
        with pytest.raises(SpdxValidationError, match="LicenseRef"):
            validate_spdx(doc, bounds=BOUNDS)


def test_external_bindings_are_local_and_never_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.request

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Validation must never retrieve a network resource")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    doc = rich_document()
    doc["packages"][0]["licenseDeclared"] = "DocumentRef-upstream:LicenseRef-Upstream"
    validate_spdx(doc, bounds=BOUNDS)
    doc["externalDocumentRefs"] = []
    with pytest.raises(SpdxValidationError, match="external SPDX|LicenseRef"):
        validate_spdx(doc, bounds=BOUNDS)


def test_conflicting_license_and_external_ids_are_remapped_without_field_loss() -> None:
    first, second = rich_document(), rich_document()
    second["hasExtractedLicensingInfos"][0]["extractedText"] = "A different exact license"
    second["externalDocumentRefs"][0]["spdxDocument"] = "https://example.org/different-document"
    second["packages"][0]["licenseDeclared"] = "DocumentRef-upstream:LicenseRef-Elsewhere AND LicenseRef-Custom"
    result = build(first, second)
    output = result["document"]
    validate_spdx(output, bounds=BOUNDS)
    assert len(output["packages"]) == 2
    assert len(output["hasExtractedLicensingInfos"]) == 2
    assert len(output["externalDocumentRefs"]) == 2
    assert {item["extractedText"] for item in output["hasExtractedLicensingInfos"]} == {
        "Custom license exact text", "A different exact license"}
    for record in result["provenance"]["baselines"]:
        assert record["license_ref_map"]["LicenseRef-Custom"] != "LicenseRef-Custom"
        assert record["external_document_ref_map"]["DocumentRef-upstream"] != "DocumentRef-upstream"


def test_exact_baseline_packages_merge_and_remap_relationships() -> None:
    first = document(package("SPDXRef-original"))
    second = document(package("SPDXRef-alias"), relationships=[{
        "spdxElementId": "SPDXRef-alias", "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-alias",
    }])
    result = build(first, second)
    assert len(result["document"]["packages"]) == 1
    identifier = result["document"]["packages"][0]["SPDXID"]
    assert result["document"]["relationships"] == sorted([
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
         "relatedSpdxElement": identifier},
        {"spdxElementId": identifier, "relationshipType": "DESCRIBES",
         "relatedSpdxElement": identifier},
    ], key=canonical_json)
    assert len(result["provenance"]["packages"][identifier]["baseline_packages"]) == 2


def test_safe_baseline_field_union_preserves_every_original_value() -> None:
    left = package("SPDXRef-left", annotations=[{
        "annotationDate": CREATED, "annotationType": "OTHER",
        "annotator": "Tool: first", "comment": "first"}])
    right = package("SPDXRef-right", homepage="https://example.org/zlib", annotations=[{
        "annotationDate": CREATED, "annotationType": "OTHER",
        "annotator": "Tool: second", "comment": "second"}])
    result = build(document(left), document(right))
    assert len(result["document"]["packages"]) == 1
    merged = result["document"]["packages"][0]
    assert merged["homepage"] == right["homepage"]
    assert {record["comment"] for record in merged["annotations"]} == {"first", "second"}


def test_baseline_scalar_conflicts_remain_separate() -> None:
    result = build(document(package(description="first")),
                   document(package(description="second")))
    assert {item["description"] for item in result["document"]["packages"]} == {"first", "second"}
    assert len(result["provenance"]["packages"]) == 2
    assert result["metrics"]["conflicts"] == 1
    assert all(entry["conflicts"] for entry in result["provenance"]["packages"].values())


def test_native_exact_purl_merge_preserves_observed_case_and_qualifiers() -> None:
    result = build(document(package()), native=discovery(candidate(purl=PURL)))
    assert len(result["document"]["packages"]) == 1
    assert result["metrics"]["exact_merges"] == 1
    assert result["document"]["packages"][0]["externalRefs"][0]["referenceLocator"] == PURL
    entry = next(iter(result["provenance"]["packages"].values()))
    assert entry["baseline_packages"] and entry["native_candidate_ids"] and entry["evidence_ids"]
    assert entry["merge_decisions"] == ["baseline_retained", "exact_purl"]


@pytest.mark.parametrize("purl", [PURL.lower(), PURL + "&distro=ubuntu",
                                PURL.replace("@1.3.1", "@1.3.2")])
def test_purl_case_qualifier_and_release_differences_never_name_merge(purl: str) -> None:
    result = build(document(package()), native=discovery(candidate(purl=purl)))
    assert len(result["document"]["packages"]) == 2
    assert result["metrics"]["exact_merges"] == 0


def test_corroborated_identity_release_and_upstream_allow_safe_merge() -> None:
    row = candidate(identity="corroborated", release="corroborated", upstream="corroborated")
    result = build(document(package(homepage="https://example.org/zlib")), native=discovery(row))
    assert len(result["document"]["packages"]) == 1
    assert result["provenance"]["decisions"][0]["decision"] == "corroborated_identity"


def test_corroborated_identity_release_with_root_file_association_allows_merge() -> None:
    row = candidate(identity="corroborated", release="corroborated")
    result = build(rich_document(), native=discovery(row))
    assert len(result["document"]["packages"]) == 1


def test_name_and_release_without_association_are_not_enough_to_merge() -> None:
    row = candidate(identity="corroborated", release="corroborated")
    result = build(document(package()), native=discovery(row))
    assert len(result["document"]["packages"]) == 2
    assert result["metrics"]["unresolved_matches"] == 1


@pytest.mark.parametrize("status", ["unknown", "inferred", "conflicted", "corroborated"])
def test_only_corroborated_native_releases_become_version_info(status: str) -> None:
    result = build(native=discovery(candidate(release=status)))
    emitted = result["document"]["packages"][0]
    assert ("versionInfo" in emitted) == (status == "corroborated")
    assert emitted["downloadLocation"] == emitted["licenseConcluded"] == "NOASSERTION"
    assert emitted["licenseDeclared"] == emitted["copyrightText"] == "NOASSERTION"
    assert emitted["filesAnalyzed"] is False
    assert not ({"checksums", "packageVerificationCode", "externalRefs"} & emitted.keys())
    assert result["document"]["relationships"][0]["relationshipType"] == "DESCRIBES"
    assert not any(row["relationshipType"] == "DEPENDS_ON" for row in result["document"]["relationships"])
    assert json.loads(emitted["sourceInfo"])["release"] == status


def test_native_observed_purl_is_preserved_without_fabrication() -> None:
    result = build(native=discovery(candidate(purl=PURL)))
    assert result["document"]["packages"][0]["externalRefs"] == [{
        "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": PURL}]
    assert "versionInfo" not in result["document"]["packages"][0]


@pytest.mark.parametrize("purl", ["zlib", "https://example.org/zlib", "pkg:generic/",
                                "pkg:generic/zlib@1?arch=x&arch=y", "pkg:generic/zlib%ZZ",
                                "pkg:generic/@1.0", "pkg:generic//zlib", "pkg:generic/zlib@"])
def test_invalid_observed_purl_is_not_emitted(purl: str) -> None:
    result = build(native=discovery(candidate(purl=purl)))
    assert "externalRefs" not in result["document"]["packages"][0]
    assert any(gap["kind"] == "unsupported_metadata" for gap in result["gaps"])


def test_conflicting_native_release_retains_baseline_and_separate_root_candidate() -> None:
    row = candidate(release="corroborated", version="9.9", purl=PURL)
    result = build(document(package()), native=discovery(row))
    assert {item.get("versionInfo") for item in result["document"]["packages"]} == {"1.3.1", "9.9"}
    assert any(gap["kind"] == "version_conflict" for gap in result["gaps"])
    assert result["metrics"]["conflicts"] == 1
    assert result["metrics"]["exact_merges"] == 0


def test_conflicted_claim_never_overwrites_baseline() -> None:
    result = build(document(package()), native=discovery(candidate(release="conflicted", purl=PURL)))
    assert len(result["document"]["packages"]) == 2
    assert result["metrics"]["conflicts"] == 1
    assert result["metrics"]["native_additions"] == 1


def test_ambiguous_purl_match_is_not_arbitrarily_assigned() -> None:
    result = build(document(package("SPDXRef-first", description="first"),
                            package("SPDXRef-second", description="second")),
                   native=discovery(candidate(purl=PURL)))
    assert len(result["document"]["packages"]) == 3
    assert result["metrics"]["exact_merges"] == 0
    assert any(gap["kind"] == "identity_conflict" for gap in result["gaps"])


def test_same_name_in_two_roots_remains_two_native_packages() -> None:
    result = build(native=discovery(candidate(root="vendor/one"), candidate(root="vendor/two")))
    assert len(result["document"]["packages"]) == 2
    assert len({item["SPDXID"] for item in result["document"]["packages"]}) == 2


def test_genuinely_empty_baseline_produces_valid_zero_package_spdx() -> None:
    result = build(document())
    assert result["document"]["packages"] == []
    assert result["gaps"] == []
    assert result["metrics"]["output_packages"] == 0
    validate_spdx(result["document"], bounds=BOUNDS)


def test_missing_baseline_and_native_source_cannot_claim_clean_empty_coverage() -> None:
    result = build()
    assert result["document"]["packages"] == []
    assert result["gaps"] == [{
        "kind": "input_missing", "scope": "source-syft-baseline",
        "detail": "No accepted source SPDX baseline was supplied", "evidence_ids": []}]


def test_native_only_fallback_retains_conversion_gap_and_coverage() -> None:
    native = discovery(candidate(), gaps=[{
        "kind": "sbom_conversion_failed", "scope": "source-syft-baseline",
        "detail": "Converter failed", "evidence_ids": []}])
    result = build(native=native)
    assert len(result["document"]["packages"]) == 1
    assert result["gaps"] == native["gaps"]
    assert result["provenance"]["discovery"]["coverage"] == native["coverage"]


def test_permutations_preserve_document_provenance_and_metrics_bytes() -> None:
    rows = [candidate(name=name, root=f"vendor/{name}") for name in ("alpha", "beta", "gamma")]
    baselines = [baseline(document(package()), "one"),
                 baseline(document(package("SPDXRef-other", name="other", externalRefs=[])), "two")]
    refs = [artifact("catalog.json"), artifact("language.json")]
    expected = build(baselines=baselines, native=discovery(*rows), input_identities=refs)
    for order in permutations(rows):
        native = discovery(*order)
        native["evidence"].reverse()
        actual = build(baselines=baselines[::-1], native=native, input_identities=refs[::-1])
        assert canonical_json(actual) == canonical_json(expected)


def test_baseline_collection_permutations_keep_semantic_document_and_provenance() -> None:
    original = rich_document()
    reordered = deepcopy(original)
    reordered["files"].reverse()
    reordered["relationships"].reverse()
    fixed_ref = baseline(original)
    changed = {**fixed_ref, "document": reordered}
    assert canonical_json(build(baselines=[fixed_ref])) == canonical_json(build(baselines=[changed]))


def test_converter_timestamp_namespace_and_raw_artifact_do_not_change_enriched_bytes() -> None:
    original = rich_document()
    converted_again = deepcopy(original)
    converted_again["documentNamespace"] = "https://example.org/spdx/a-new-random-id"
    converted_again["creationInfo"]["created"] = "2026-10-29T01:00:00Z"
    first, second = baseline(original), baseline(converted_again)
    result = build(baselines=[first], input_identities=[artifact("catalog.json"), first["artifact"]])
    changed = build(baselines=[second], input_identities=[artifact("catalog.json"), second["artifact"]])
    assert canonical_json(result["document"]) == canonical_json(changed["document"])
    assert result["provenance"]["input_fingerprint"] == changed["provenance"]["input_fingerprint"]
    assert result["provenance"]["baselines"][0]["artifact"] != changed["provenance"]["baselines"][0]["artifact"]


@pytest.mark.parametrize("created", [
    "2026-10-28", "2026-10-28T15:22:43", "2026-10-28T15:22:43-04:00",
    "2026-02-30T00:00:00Z", "2026-10-28T25:22:43Z", "",
])
def test_non_utc_or_invalid_creation_time_rejected(created: str) -> None:
    with pytest.raises(SpdxValidationError, match="UTC"):
        build(created=created)


def test_exact_byte_and_element_bounds_are_enforced_without_truncating_baseline() -> None:
    doc = rich_document()
    size = len(canonical_json(doc))
    count = sum(len(doc.get(field, [])) for field in (
        "packages", "files", "snippets", "relationships", "hasExtractedLicensingInfos"))
    with pytest.raises(SpdxValidationError, match="bytes"):
        build(doc, bounds=replace(BOUNDS, input_bytes=size - 1))
    with pytest.raises(SpdxValidationError, match="elements"):
        build(doc, bounds=replace(BOUNDS, element_limit=count - 1))
    result = build(doc, bounds=replace(BOUNDS, input_bytes=size, element_limit=count + 1))
    assert len(result["document"]["files"]) == 2
    assert len(result["document"]["snippets"]) == 1
    with pytest.raises(SpdxValidationError, match="bytes"):
        validate_spdx(result["document"], bounds=replace(
            BOUNDS, output_bytes=len(canonical_json(result["document"])) - 1))
    validate_spdx(result["document"], bounds=replace(
        BOUNDS, output_bytes=len(canonical_json(result["document"]))))


def test_bounds_omit_only_native_contributions_with_deterministic_gap() -> None:
    native = discovery(*(candidate(name=f"lib{index}", root=f"vendor/lib{index}") for index in range(5)))
    bounded = replace(BOUNDS, element_limit=4)
    first = build(document(package()), native=native, bounds=bounded)
    native["candidates"].reverse()
    native["evidence"].reverse()
    second = build(document(package()), native=native, bounds=bounded)
    assert canonical_json(first) == canonical_json(second)
    assert len(first["document"]["packages"]) == 2
    assert first["metrics"]["native_additions"] == 1
    assert first["provenance"]["native_omitted"] == 4
    assert any(gap["kind"] == "bounds" for gap in first["gaps"])
    assert any(item["name"] == "zlib" for item in first["document"]["packages"])


def test_sidecar_and_standard_output_independently_fit_json_byte_bound() -> None:
    native = discovery(*(candidate(name=f"lib{index}", root=f"vendor/lib{index}") for index in range(12)))
    limit = 6000
    result = build(native=native, bounds=replace(BOUNDS, output_bytes=limit))
    assert len(canonical_json(result["document"])) <= limit
    assert len(canonical_json(result["provenance"])) <= limit
    assert result["provenance"]["native_omitted"] > 0
    assert result["metrics"]["output_bytes"] == len(canonical_json(result["document"]))


def test_oversized_baseline_fields_reject_instead_of_truncating() -> None:
    with pytest.raises(SpdxValidationError, match="field"):
        build(document(package(description="x" * 1001)), bounds=replace(BOUNDS, field_bytes=1000))


def test_native_oversized_field_is_explicitly_omitted_not_truncated() -> None:
    result = build(native=discovery(candidate(name="x" * 1001)),
                   bounds=replace(BOUNDS, field_bytes=1000))
    assert result["document"]["packages"] == []
    assert result["provenance"]["native_omitted"] == 1
    assert any(gap["kind"] == "bounds" for gap in result["gaps"])


def test_metrics_have_exact_counter_shape_and_provenance_is_independently_serializable() -> None:
    result = build(document(package()), native=discovery(candidate(purl=PURL)))
    assert set(result["metrics"]) == set(SBOM_COUNTERS)
    assert all(type(value) is int and value >= 0 for value in result["metrics"].values())
    assert result["provenance"]["schema"] == PROVENANCE_SCHEMA
    assert set(result["provenance"]["packages"]) == {item["SPDXID"] for item in result["document"]["packages"]}
    assert result["provenance"]["input_fingerprint"] in result["document"]["documentNamespace"]
    assert "sbom_sha256" not in result["provenance"]
    assert "provenance_sha256" not in result["document"]
    assert json.loads(canonical_json(result["provenance"])) == result["provenance"]


@pytest.mark.parametrize("tamper", ["unknown-evidence", "unbound-corroboration",
                                   "different-source", "missing-selector"])
def test_discovery_evidence_integrity_is_not_silently_downgraded(tamper: str) -> None:
    native = discovery(candidate())
    if tamper == "unknown-evidence":
        native["candidates"][0]["evidence_ids"].append("missing")
    elif tamper == "unbound-corroboration":
        native["candidates"][0]["release"].update(status="corroborated", evidence_ids=[])
    elif tamper == "different-source":
        native["evidence"][0]["source_fingerprint"] = "b" * 64
    else:
        native["evidence"][0]["selector"] = {}
    with pytest.raises(NativeInputIntegrityError):
        build(native=native)


def test_conflicting_repeated_candidate_identity_fails_admission() -> None:
    first, second = candidate(root="vendor/first"), candidate(root="vendor/second")
    second[0]["candidate_id"] = first[0]["candidate_id"]
    with pytest.raises(NativeInputIntegrityError, match="Conflicting"):
        build(native=discovery(first, second))


@pytest.mark.parametrize("mutation", [
    lambda doc: doc["files"].append(deepcopy(doc["files"][0])),
    lambda doc: doc["externalDocumentRefs"].append(deepcopy(doc["externalDocumentRefs"][0])),
    lambda doc: doc["hasExtractedLicensingInfos"].append(deepcopy(doc["hasExtractedLicensingInfos"][0])),
    lambda doc: doc["packages"][0].update(hasFiles=["SPDXRef-zlib"]),
    lambda doc: doc["files"][0].update(fileDependencies=["SPDXRef-zlib"]),
    lambda doc: doc["snippets"][0]["ranges"][0]["endPointer"].update(reference="SPDXRef-helper"),
    lambda doc: doc["snippets"][0]["ranges"][0]["startPointer"].update(offset=-1),
    lambda doc: doc["snippets"][0]["ranges"][0]["endPointer"].update(offset=-1),
    lambda doc: doc["packages"][0].update(filesAnalyzed=False, packageVerificationCode={"packageVerificationCodeValue": "a" * 40}),
])
def test_additional_schema_valid_semantic_violations(mutation: Any) -> None:
    doc = rich_document()
    mutation(doc)
    with pytest.raises(SpdxValidationError):
        validate_spdx(doc, bounds=BOUNDS)


def test_both_relationship_absence_sentinels_are_valid_only_as_related_element() -> None:
    doc = document(package(), relationships=[{
        "spdxElementId": "SPDXRef-zlib", "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": sentinel,
    } for sentinel in ("NONE", "NOASSERTION")])
    validate_spdx(doc, bounds=BOUNDS)
    doc["relationships"][0]["spdxElementId"] = "NOASSERTION"
    with pytest.raises(SpdxValidationError, match="reference"):
        validate_spdx(doc, bounds=BOUNDS)


@pytest.mark.parametrize("namespace", ["https://[bad", "relative/path", "https://example.org/a#fragment"])
def test_invalid_namespace_is_a_validation_error(namespace: str) -> None:
    with pytest.raises(SpdxValidationError, match="documentNamespace"):
        build(document(documentNamespace=namespace))


def test_complete_document_is_not_omitted_due_to_temporary_gap_overhead() -> None:
    native = discovery(candidate())
    unconstrained = build(native=native)
    size = len(canonical_json(unconstrained["provenance"]))
    result = build(native=native, bounds=replace(BOUNDS, output_bytes=size))
    assert result["provenance"]["native_omitted"] == 0
    assert result["metrics"]["native_additions"] == 1


def test_corrupt_schema_resource_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from appsec_review.jobs.job_dependency_intelligence import sbom

    sbom._validator.cache_clear()
    monkeypatch.setattr(sbom, "_SCHEMA_SHA256", "0" * 64)
    with pytest.raises(SpdxValidationError, match="digest mismatch"):
        sbom.schema_sha256()
    sbom._validator.cache_clear()


def test_fingerprint_changes_with_accepted_sources_bounds_created_and_discovery() -> None:
    original = build(document())
    changes = [
        {"input_identities": [artifact("changed-catalog.json")]},
        {"created": "2026-10-28T15:22:44Z"},
        {"bounds": replace(BOUNDS, output_bytes=BOUNDS.output_bytes + 1)},
        {"native": discovery(candidate())},
        {"source_fingerprint": "b" * 64},
    ]
    for changed in changes:
        result = build(document(), **changed)
        assert result["provenance"]["input_fingerprint"] != original["provenance"]["input_fingerprint"]


def test_graph_ids_do_not_conflate_same_original_file_ids_with_distinct_content() -> None:
    first, second = rich_document(), rich_document()
    second["files"][1]["copyrightText"] = "different owner"
    result = build(first, second)
    assert len(result["document"]["packages"]) == 1
    assert len(result["document"]["packages"][0]["hasFiles"]) == 2
    assert len(result["document"]["files"]) == 4
    assert len(result["document"]["snippets"]) == 2
    validate_spdx(result["document"], bounds=BOUNDS)


@pytest.mark.parametrize("field,value", [
    ("checksums", [{"algorithm": "SHA256", "checksumValue": "1" * 64}]),
    ("externalRefs", [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                       "referenceLocator": PURL}, {
                           "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                           "referenceLocator": "pkg:generic/zlib@different"}]),
])
def test_baseline_identity_collection_conflicts_are_not_unioned(field: str, value: Any) -> None:
    first = package("SPDXRef-one")
    if field == "checksums":
        first[field] = [{"algorithm": "SHA256", "checksumValue": "2" * 64}]
    result = build(document(first), document(package("SPDXRef-two", **{field: value})))
    assert len(result["document"]["packages"]) == 2
    assert result["metrics"]["conflicts"] == 1
    assert result["metrics"]["exact_merges"] == 0


def test_original_spdx_array_order_is_semantically_irrelevant() -> None:
    doc = rich_document()
    doc["creationInfo"]["creators"].append("Organization: Example")
    doc["packages"][0]["externalRefs"].append({
        "referenceCategory": "SECURITY", "referenceType": "cpe23Type",
        "referenceLocator": "cpe:2.3:a:example:zlib:1.3.1:*:*:*:*:*:*:*"})
    doc["hasExtractedLicensingInfos"][0]["seeAlsos"].append("https://example.org/another-license")
    changed = deepcopy(doc)
    changed["creationInfo"]["creators"].reverse()
    changed["packages"][0]["externalRefs"].reverse()
    changed["hasExtractedLicensingInfos"][0]["seeAlsos"].reverse()
    fixed = baseline(doc)
    original_result = build(baselines=[fixed])
    changed_result = build(baselines=[{**fixed, "document": changed}])
    assert canonical_json(original_result) == canonical_json(changed_result)
    combined = build(baselines=[fixed, {**fixed, "artifact": artifact("another-baseline"),
                                       "document": changed}])
    assert len(combined["document"]["hasExtractedLicensingInfos"]) == 1
    assert not combined["gaps"]


def test_accepted_raw_baseline_or_syft_size_cannot_bypass_input_bound() -> None:
    for field in ("artifact", "source_artifact"):
        accepted = baseline(document())
        accepted[field]["size_bytes"] = BOUNDS.input_bytes + 1
        with pytest.raises(SpdxValidationError, match="input bound"):
            build(baselines=[accepted])


@pytest.mark.parametrize("expression", ["LicenseRef-Custom_broken", "LicenseRef-Custom+",
                                      "bogus:LicenseRef-Custom", "LicenseRef-"])
def test_malformed_license_ref_does_not_match_a_valid_prefix(expression: str) -> None:
    doc = rich_document()
    doc["packages"][0]["licenseDeclared"] = expression
    with pytest.raises(SpdxValidationError, match="LicenseRef"):
        validate_spdx(doc, bounds=BOUNDS)


def test_snippet_pointer_without_coordinate_is_rejected() -> None:
    doc = rich_document()
    doc["snippets"][0]["ranges"][0]["startPointer"].pop("offset")
    with pytest.raises(SpdxValidationError, match="offset"):
        validate_spdx(doc, bounds=BOUNDS)


def test_empty_creator_list_is_not_a_valid_spdx_document() -> None:
    doc = document()
    doc["creationInfo"]["creators"] = []
    with pytest.raises(SpdxValidationError, match="creator"):
        validate_spdx(doc, bounds=BOUNDS)


def test_baseline_name_and_version_without_purl_are_not_a_deduplication_identity() -> None:
    result = build(document(
        package("SPDXRef-one", externalRefs=[]), package("SPDXRef-two", externalRefs=[])))
    assert len(result["document"]["packages"]) == 2
    assert result["metrics"]["exact_merges"] == 0
    assert len(result["provenance"]["packages"]) == 2


def test_truly_identical_baseline_elements_keep_all_original_selectors() -> None:
    result = build(document(package(externalRefs=[])), document(package(externalRefs=[])))
    assert len(result["document"]["packages"]) == 1
    entry = next(iter(result["provenance"]["packages"].values()))
    assert len(entry["baseline_packages"]) == 2
    assert result["metrics"]["exact_merges"] == 1


def test_malformed_baseline_purl_cannot_be_used_as_a_merge_identity() -> None:
    ref = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
            "referenceLocator": "not-a-package-url"}]
    result = build(document(package("SPDXRef-one", externalRefs=ref),
                            package("SPDXRef-two", externalRefs=ref)))
    assert len(result["document"]["packages"]) == 2
