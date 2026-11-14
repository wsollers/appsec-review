"""T-5008: the unit context carries the unit's collation facets and its component's target class."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from appsec_review.review.packages import UNIT_CONTEXT_SCHEMA, UNIT_FACETS_RULE, assemble_packages, resolve_package_document, publish_packages
from appsec_review.review.scope import accept_manifest
from tests.fixtures.inference_review.builder import build_accepted_index_set

ROOT = Path(__file__).resolve().parents[2]
UNIT_CONTEXT_SCHEMA_DOCUMENT = json.loads(
    (ROOT / "docs" / "schemas" / "review-package-unit-context.schema.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def faceted(tmp_path_factory):
    fixture = build_accepted_index_set(tmp_path_factory.mktemp("facets"), facets=True)
    return fixture, assemble_packages(accept_manifest(fixture.run_root))


def _context(assembly, component_id: str):
    [found] = [item for item in assembly.unit_contexts if item.document["scope"]["component_id"] == component_id]
    return found


def test_unit_context_carries_the_facets_and_target_class_with_traceable_ids(faceted) -> None:
    fixture, assembly = faceted
    svc = _context(assembly, "component:0001").document
    jsonschema.validate(svc, UNIT_CONTEXT_SCHEMA_DOCUMENT)
    assert svc["schema"] == UNIT_CONTEXT_SCHEMA == "appsec-review/package-unit-context/2"
    facets = svc["facets"]
    assert facets["rule"] == UNIT_FACETS_RULE and facets["target_classes"] == ["target:web-api"]
    tags = {row["tag"]: row for row in facets["tags"]}
    assert {"role:auth", "mechanism:http", "trust:user-tainted", "exposure:client-facing", "state:session"} <= set(tags)
    assert tags["role:auth"]["basis"] == "declared" and tags["trust:user-tainted"]["basis"] == "derived"
    assert tags["role:auth"]["subjects"] == 1 and len(tags["role:auth"]["assignment_ids"]) == 1
    # Every facet row is reachable through the unit-wide retrieval grant, so a worker can trace it.
    assert all(set(row["entity_ids"]) <= set(svc["entity_ids"]) for row in facets["tags"])
    assert fixture.ids["facet:role:auth:svc/api/handler.py"] in svc["entity_ids"]
    # Target classes never appear among the facet tags; the native unit is a CLI.
    assert not any(row["namespace"] == "target" for row in facets["tags"])
    native = _context(assembly, "component:0002").document
    assert native["facets"]["target_classes"] == ["target:cli"]
    assert {row["tag"] for row in native["facets"]["tags"]} == {"mechanism:cli", "trust:user-tainted",
                                                                "exposure:operator-only"}


def test_without_facet_records_the_unit_context_says_so_and_still_validates(tmp_path: Path) -> None:
    fixture = build_accepted_index_set(tmp_path)
    assembly = assemble_packages(accept_manifest(fixture.run_root))
    for context in assembly.unit_contexts:
        jsonschema.validate(context.document, UNIT_CONTEXT_SCHEMA_DOCUMENT)
        assert context.document["facets"] == {"rule": UNIT_FACETS_RULE, "tags": [], "target_classes": []}


def test_resolved_hunt_package_exposes_the_facets_through_its_reference(faceted, tmp_path: Path) -> None:
    fixture, assembly = faceted
    out = tmp_path / "assembly"
    publish_packages(assembly, out)
    hunt = next(item for item in assembly.packages if item.kind == "hunt"
                and item.document()["scope"]["component_id"] == "component:0001")
    package_path = out / "packages" / f"{hunt.package_id}.json"
    stored = json.loads(package_path.read_text(encoding="utf-8"))
    assert "facets" not in stored, "the body references the unit context; it does not embed the facets"
    assert stored["unit_context"]["schema"] == UNIT_CONTEXT_SCHEMA
    document = json.loads((out / stored["unit_context"]["path"]).read_text(encoding="utf-8"))
    assert document["facets"]["target_classes"] == ["target:web-api"]
    resolved = resolve_package_document(package_path)
    assert resolved["unit_context"]["sha256"] == stored["unit_context"]["sha256"]
    assert set(document["entity_ids"]) <= set(resolved["retrieval"]["entity_ids"])
