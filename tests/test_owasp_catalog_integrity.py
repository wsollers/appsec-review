from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.owasp_workbench.acquisition import (
    INVENTORY_PINS, PINS, _blob, acquire, normalize,
)
from appsec_review.owasp_workbench.standards import (
    SUPPORTED_FAMILIES, control_records, digest, load_catalog, load_catalogs, standards_manifest,
)
from appsec_review.storage import canonical_json


ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "ASVS": "asvs-5.0.0.json", "MASVS": "masvs-2.1.0.json", "MASTG": "mastg-2.0.0.json",
    "OWASP_API_TOP_10": "api-top10-2023.json", "OWASP_TOP_10": "top10-2025.json",
}


def snapshot(family: str) -> dict:
    return json.loads((ROOT / "data" / "reference" / "owasp" / "catalogs" / FILES[family])
                      .read_text(encoding="utf-8"))


def reseal(document: dict) -> None:
    """Simulate an accidentally repinned/truncated acquisition, including every self-hash."""
    records = document["records"]
    acquisition = document["acquisition"]
    acquisition["declared_ids"] = sorted(row["id"] for row in records)
    acquisition["declared_ids_sha256"] = digest(acquisition["declared_ids"])
    acquisition["normalized_records_sha256"] = digest(records)
    used = {row["source"]["path"] for row in records}
    acquisition["sources"] = {path: value for path, value in acquisition["sources"].items()
                              if path in used}


def load_resealed(tmp_path: Path, document: dict):
    family = document["family"]
    path = tmp_path / "catalog.json"
    path.write_bytes(canonical_json(document))
    settings = {"catalog_path": path.name, "catalog_sha256": digest(document),
                "version": document["version"], **document["upstream"]}
    return load_catalog(tmp_path, family, settings)


@pytest.mark.parametrize("family,count", [
    ("ASVS", 345), ("MASVS", 24), ("MASTG", 292), ("OWASP_API_TOP_10", 10), ("OWASP_TOP_10", 10),
])
def test_complete_snapshots_match_independent_reviewed_locks(
    tmp_path: Path, family: str, count: int,
) -> None:
    document = snapshot(family)
    catalog = load_resealed(tmp_path, document)
    pin = INVENTORY_PINS[family]
    assert not catalog.fixture and catalog.coverage["completeness"] == "complete"
    assert len(catalog.records) == pin.record_count == count
    assert catalog.authority == SUPPORTED_FAMILIES[family]
    assert digest(document["acquisition"]["sources"]) == pin.sources_sha256
    assert digest(document["records"]) == pin.records_sha256
    assert _blob(document["distribution"]["license_text"].encode()) == pin.license_blob
    assert catalog.distribution["license_source"]["git_blob"] == pin.license_blob


@pytest.mark.parametrize("family", FILES)
def test_resealed_missing_record_is_not_complete(tmp_path: Path, family: str) -> None:
    document = snapshot(family)
    document["records"].pop()
    reseal(document)
    with pytest.raises(ValueError, match="pinned upstream ID inventory"):
        load_resealed(tmp_path, document)


@pytest.mark.parametrize("family", FILES)
def test_same_count_replacement_id_is_not_complete(tmp_path: Path, family: str) -> None:
    document = snapshot(family)
    document["records"][-1]["id"] = "invented-replacement"
    reseal(document)
    with pytest.raises(ValueError, match="pinned upstream ID inventory"):
        load_resealed(tmp_path, document)


def test_beta_mastg_tests_are_not_silently_excluded(tmp_path: Path) -> None:
    document = snapshot("MASTG")
    beta = [row for row in document["records"] if row["source"]["path"].startswith("tests-beta/")]
    assert beta
    document["records"] = [row for row in document["records"] if row not in beta]
    reseal(document)
    with pytest.raises(ValueError, match="pinned upstream ID inventory"):
        load_resealed(tmp_path, document)


@pytest.mark.parametrize("family", FILES)
def test_resealed_altered_text_is_not_upstream_content(tmp_path: Path, family: str) -> None:
    document = snapshot(family)
    document["records"][0]["text"] += "\nInvented control content."
    reseal(document)
    with pytest.raises(ValueError, match="pinned normalized records"):
        load_resealed(tmp_path, document)


@pytest.mark.parametrize("field,value", [
    ("tree_id", "0" * 40), ("tree_commit", "0" * 40), ("tree_sha256", "not-a-hash"),
    ("language", "unspecified"), ("exclusions", ["dropped tests"]), ("normalizer", "invented"),
    ("completeness", "partial"), ("path_pattern", ".*"),
])
def test_resealed_provenance_change_is_rejected(
    tmp_path: Path, field: str, value: object,
) -> None:
    document = snapshot("MASVS")
    document["acquisition"][field] = value
    with pytest.raises(ValueError, match="supported pinned acquisition"):
        load_resealed(tmp_path, document)


@pytest.mark.parametrize("field,value", [
    ("repository", "https://github.com/example/not-owasp"), ("ref", "unreviewed-tag"),
    ("license", "MIT"),
])
def test_outer_configuration_cannot_relabel_upstream(
    tmp_path: Path, field: str, value: str,
) -> None:
    document = snapshot("MASVS")
    document["upstream"][field] = value
    with pytest.raises(ValueError, match="supported upstream identity"):
        load_resealed(tmp_path, document)


def test_outer_configuration_cannot_relabel_version(tmp_path: Path) -> None:
    document = snapshot("ASVS")
    document["version"] = "invented-version"
    with pytest.raises(ValueError, match="supported upstream identity"):
        load_resealed(tmp_path, document)


@pytest.mark.parametrize("field", ["git_blob", "sha256"])
def test_source_inventory_is_not_self_authenticating(tmp_path: Path, field: str) -> None:
    document = snapshot("ASVS")
    source = next(iter(document["acquisition"]["sources"].values()))
    source[field] = "0" * len(source[field])
    with pytest.raises(ValueError, match="pinned source inventory"):
        load_resealed(tmp_path, document)


@pytest.mark.parametrize("family,field,value", [
    ("ASVS", "levels", [1, 2, 3]),
    ("MASVS", "profiles", ["L2"]),
    ("MASVS", "profile_basis", "upstream L2 certification"),
    ("MASTG", "supports", ["MASVS-STORAGE-2"]),
])
def test_routing_or_profile_metadata_changes_require_review(
    tmp_path: Path, family: str, field: str, value: object,
) -> None:
    document = snapshot(family)
    assert document["records"][0][field] != value
    document["records"][0][field] = value
    reseal(document)
    with pytest.raises(ValueError, match="pinned normalized records"):
        load_resealed(tmp_path, document)


@pytest.mark.parametrize("field", [
    "attribution", "changes", "license_url", "license_source", "license_text",
])
def test_cc_by_sa_distribution_fields_cannot_be_dropped(tmp_path: Path, field: str) -> None:
    document = snapshot("MASVS")
    del document["distribution"][field]
    with pytest.raises(ValueError, match="distribution attribution or pinned license"):
        load_resealed(tmp_path, document)


def test_license_mention_is_not_the_pinned_license(tmp_path: Path) -> None:
    document = snapshot("MASVS")
    document["distribution"]["license_text"] = "Attribution-ShareAlike 4.0; invented terms."
    with pytest.raises(ValueError, match="distribution attribution or pinned license"):
        load_resealed(tmp_path, document)


@pytest.mark.parametrize("field,value", [
    ("attribution", "unattributed third party"),
    ("changes", "No changes were made."),
    ("license_url", "https://example.invalid/license"),
    ("license_source", {"path": "License.md", "git_blob": "0" * 40}),
])
def test_distribution_claims_are_bound_to_actual_upstream(
    tmp_path: Path, field: str, value: object,
) -> None:
    document = snapshot("MASVS")
    document["distribution"][field] = value
    with pytest.raises(ValueError, match="distribution attribution or pinned license"):
        load_resealed(tmp_path, document)


@pytest.mark.parametrize("marker", [None, "false", 0, 1, []])
def test_fixture_marker_cannot_bypass_complete_validation(tmp_path: Path, marker: object) -> None:
    document = snapshot("ASVS")
    document["fixture"] = marker
    with pytest.raises(ValueError, match="fixture marker"):
        load_resealed(tmp_path, document)


def test_fixture_cannot_claim_complete_acquisition(tmp_path: Path) -> None:
    document = snapshot("ASVS")
    document["fixture"] = True
    with pytest.raises(ValueError, match="qualification fixture"):
        load_resealed(tmp_path, document)


def test_qualification_catalogs_remain_explicitly_abridged(tmp_path: Path) -> None:
    document = json.loads((ROOT / "data" / "reference" / "owasp" / "fixtures" /
                           FILES["MASVS"]).read_text(encoding="utf-8"))
    catalog = load_resealed(tmp_path, document)
    source = standards_manifest({"MASVS": catalog})
    assert catalog.fixture and catalog.coverage["completeness"] == "abridged_fixture"
    assert catalog.coverage["exclusions"]
    assert source["sources"][0]["completeness"] == "abridged_fixture"
    assert "fixture profile labels" in source["sources"][0]["profile_basis"]
    assert source["gaps"] and "fixture" in source["gaps"][0]


def test_authorities_profiles_and_attribution_survive_manifest() -> None:
    settings = load_config(ROOT / "appsec-review.toml").job("job_owasp_control_assessment").settings
    catalogs = load_catalogs(ROOT, settings["standards"])
    sources = {row["family"]: row for row in standards_manifest(catalogs)["sources"]}
    assert {family for family, row in sources.items() if row["authority"] == "control"} == {
        "ASVS", "MASVS",
    }
    assert sources["MASTG"]["authority"] == "supporting_test"
    assert sources["OWASP_TOP_10"]["authority"] == "routing_context"
    assert sources["OWASP_API_TOP_10"]["authority"] == "routing_context"
    assert "no upstream levels" in sources["MASVS"]["profile_basis"]
    for family, row in sources.items():
        distribution = row["distribution"]
        assert distribution["attribution"] == snapshot(family)["distribution"]["attribution"]
        assert distribution["license_url"] == "https://creativecommons.org/licenses/by-sa/4.0/"
        assert distribution["changes"]
        assert distribution["license_text_sha256"] == hashlib.sha256(
            snapshot(family)["distribution"]["license_text"].encode()).hexdigest()
        assert row["normalized_records_sha256"] == INVENTORY_PINS[family].records_sha256
    l1 = control_records(catalogs, asvs_level=1, masvs_profile="L1")
    l2 = control_records(catalogs, asvs_level=2, masvs_profile="L2")
    assert {row["id"] for row in l1 if row["family"] == "MASVS"} == {
        row["id"] for row in l2 if row["family"] == "MASVS"
    }
    assert len([row for row in l1 if row["family"] == "MASVS"]) == 24
    assert all("MASVS 2 has no levels" in row["profile_basis"]
               for row in l1 if row["family"] == "MASVS")
    assert {row["family"] for row in l2} == {"ASVS", "MASVS"}


@pytest.mark.parametrize("family", ["MASVS", "MASTG", "OWASP_API_TOP_10", "OWASP_TOP_10"])
def test_normalization_is_lossless_and_independent_of_source_order(family: str) -> None:
    document = snapshot(family)
    files = {row["source"]["path"]: row.get("description", row["text"]).encode()
             for row in document["records"]}
    assert normalize(family, files) == document["records"]
    assert normalize(family, dict(reversed(list(files.items())))) == document["records"]


def test_asvs_normalization_preserves_text_and_upstream_level() -> None:
    path = next(iter(snapshot("ASVS")["acquisition"]["sources"]))
    document = {"Version": "5.0.0", "Requirements": [{
        "Shortcode": "V6", "Items": [{"Name": "Authentication", "Items": [
            {"Shortcode": "V6.1.1", "Description": "Exact upstream requirement.", "L": 2},
        ]}],
    }]}
    payload = canonical_json(document)
    records = normalize("ASVS", {path: payload})
    assert len(records) == 1
    assert records[0]["text"] == "Exact upstream requirement."
    assert records[0]["levels"] == [2, 3]
    assert records[0]["source"] == {
        "path": path, "git_blob": _blob(payload), "sha256": hashlib.sha256(payload).hexdigest(),
    }


def test_normalizer_does_not_accept_undeclared_paths() -> None:
    with pytest.raises(ValueError, match="outside the pinned inventory"):
        normalize("MASVS", {"unreviewed.md": b"## Control\ninvented"})


def offline_upstream(family: str = "OWASP_API_TOP_10"):
    document = snapshot(family)
    repo, commit, _, _, license_path, _ = PINS[family]
    files = {row["source"]["path"]: row.get("description", row["text"]).encode()
             for row in document["records"]}
    files[license_path] = document["distribution"]["license_text"].encode()
    tree_id = INVENTORY_PINS[family].tree_id
    revision = {"sha": commit, "tree": {"sha": tree_id}}
    tree = {"sha": tree_id, "truncated": False, "tree": [
        {"path": path, "sha": _blob(payload), "type": "blob"}
        for path, payload in sorted(files.items())
    ]}
    calls = []

    def read(url: str) -> bytes:
        calls.append(url)
        if url == f"https://api.github.com/repos/{repo}/git/commits/{commit}":
            return canonical_json(revision)
        if url == f"https://api.github.com/repos/{repo}/git/trees/{tree_id}?recursive=1":
            return canonical_json(tree)
        prefix = f"https://raw.githubusercontent.com/{repo}/{commit}/"
        assert url.startswith(prefix), "acquisition requested an unpinned endpoint"
        return files[url.removeprefix(prefix)]

    return document, revision, tree, files, read, calls


@pytest.mark.parametrize("family", ["MASVS", "MASTG", "OWASP_API_TOP_10", "OWASP_TOP_10"])
def test_offline_acquisition_is_reproducible_and_validated_before_publication(
    tmp_path: Path, family: str,
) -> None:
    document, _, _, _, read, calls = offline_upstream(family)
    one = acquire(family, tmp_path / "one.json", read=read)
    two = acquire(family, tmp_path / "two.json", read=read)
    assert (tmp_path / "one.json").read_bytes() == (tmp_path / "two.json").read_bytes()
    acquired = json.loads((tmp_path / "one.json").read_bytes())
    assert acquired["records"] == document["records"]
    assert acquired["distribution"] == document["distribution"]
    assert load_catalog(tmp_path, family, {
        **one, "catalog_path": "one.json",
    }).coverage["completeness"] == "complete"
    assert one["catalog_sha256"] == two["catalog_sha256"]
    assert calls and all(PINS[family][1] in url or "/git/trees/" in url for url in calls)


@pytest.mark.parametrize("defect", [
    "wrong_commit", "wrong_tree", "truncated", "missing_truncation_marker", "dropped",
    "duplicate", "changed_blob", "rewritten_record", "changed_license", "missing_license",
])
def test_invalid_upstream_never_replaces_existing_snapshot(tmp_path: Path, defect: str) -> None:
    _, revision, tree, files, read, _ = offline_upstream()
    if defect == "wrong_commit":
        revision["sha"] = "0" * 40
    elif defect == "wrong_tree":
        revision["tree"]["sha"] = "0" * 40
    elif defect == "truncated":
        tree["truncated"] = True
    elif defect == "missing_truncation_marker":
        del tree["truncated"]
    elif defect == "dropped":
        tree["tree"].pop()
    elif defect == "duplicate":
        tree["tree"].append(deepcopy(tree["tree"][0]))
    elif defect == "changed_blob":
        path = next(path for path in files if path != "LICENSE")
        files[path] += b"\nChanged after tree fetch."
    elif defect == "rewritten_record":
        path = next(path for path in files if path != "LICENSE")
        files[path] += b"\nInvented text with a matching upstream blob declaration."
        next(row for row in tree["tree"] if row["path"] == path)["sha"] = _blob(files[path])
    elif defect == "changed_license":
        next(row for row in tree["tree"] if row["path"] == "LICENSE")["sha"] = "0" * 40
    elif defect == "missing_license":
        tree["tree"] = [row for row in tree["tree"] if row["path"] != "LICENSE"]
    destination = tmp_path / "catalog.json"
    destination.write_bytes(b"previous valid snapshot")
    with pytest.raises(ValueError, match="OWASP"):
        acquire("OWASP_API_TOP_10", destination, read=read)
    assert destination.read_bytes() == b"previous valid snapshot"
