from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import json

from jsonschema import Draft202012Validator
import pytest

from appsec_review.deployment import (
    Limits, Selection, catalog, catalog_schema, extract_inventory, inventory_schema,
    observations_schema, validate_inventory,
)
from tests.deployment_support import SNAPSHOT, document, fixture


def test_closed_versioned_schemas_validate_the_catalog_and_inventory():
    for schema in (inventory_schema(), catalog_schema(), observations_schema()):
        Draft202012Validator.check_schema(schema)
    Draft202012Validator(catalog_schema()).validate(catalog())
    data = catalog()
    assert {item["product"] for item in data["signatures"]} == {"nginx", "redis", "postgresql"}
    assert "helm_templates" in data["unsupported"]["formats"]
    assert "garnet" in data["unsupported"]["cache_search"]
    assert all(item["rule"] and item["limitations"] for item in data["signatures"])
    rules = {item["id"] for item in data["evidence_rules"]}
    assert len(rules) == len(data["evidence_rules"])
    assert all(item["rule"] in rules for item in data["signatures"])
    data["signatures"][0]["product"] = "mutated"
    assert catalog()["signatures"][0]["product"] == "nginx"
    graph = extract_inventory([fixture("compose.yaml", "compose")], target_snapshot=SNAPSHOT)
    validate_inventory(graph.to_dict())
    assert {item.rule for item in graph.evidence} <= rules
    assert graph.schema.endswith("/1") and len(graph.catalog_sha256) == 64


@pytest.mark.parametrize("group", ["root", "services", "listeners", "evidence", "sources", "coverage"])
def test_inventory_schema_rejects_unknown_fields_at_every_record_boundary(group):
    value = extract_inventory([fixture("compose.yaml", "compose")], target_snapshot=SNAPSHOT).to_dict()
    target = value if group == "root" else value[group][0]
    target["trust_me"] = True
    with pytest.raises(ValueError, match="invalid deployment inventory"):
        validate_inventory(value)


def test_inventory_contract_rejects_foreign_or_dangling_evidence_and_runtime_claims():
    original = extract_inventory([fixture("compose.yaml", "compose")], target_snapshot=SNAPSHOT).to_dict()
    altered = deepcopy(original)
    altered["sources"][0]["scope"] = "analysis_platform"
    with pytest.raises(ValueError, match="source identity|out-of-scope"):
        validate_inventory(altered)
    altered = deepcopy(original)
    altered["listeners"][0]["evidence"] = ["missing"]
    with pytest.raises(ValueError, match="evidence reference"):
        validate_inventory(altered)
    altered = deepcopy(original)
    altered["facts"][0]["evidence_class"] = "proven_reachability"
    with pytest.raises(ValueError, match="static inventory"):
        validate_inventory(altered)
    altered = deepcopy(original)
    altered["evidence"][0]["end_byte"] = 9999999
    with pytest.raises(ValueError, match="unresolved"):
        validate_inventory(altered)


@pytest.mark.parametrize("path", ["../outside", "/absolute", "C:/absolute", "a/../b", "a//b", "a\\b"])
def test_sources_require_canonical_logical_paths(path):
    with pytest.raises(ValueError):
        document("services: {}", path=path)


@pytest.mark.parametrize(("name", "value"), [("max_depth", 0), ("max_nodes", True), ("max_documents", 999)])
def test_limits_are_typed_and_cannot_disable_bounds(name, value):
    with pytest.raises(ValueError, match="bounded integers"):
        Limits(**{name: value})


def test_content_variant_scope_and_target_bind_stable_ids():
    source = fixture("compose.yaml", "compose")
    first = extract_inventory([source], target_snapshot=SNAPSHOT)
    again = extract_inventory([source], target_snapshot=SNAPSHOT)
    assert first.to_dict() == again.to_dict()
    changed_snapshot = extract_inventory([source], target_snapshot="different")
    changed_variant = extract_inventory([replace(source, variant="alternative")], target_snapshot=SNAPSHOT)
    assert {item.id for item in first.services}.isdisjoint(item.id for item in changed_snapshot.services)
    assert {item.id for item in first.services}.isdisjoint(item.id for item in changed_variant.services)
    changed_source = document(source.data + b"\n", path=source.path)
    changed_bytes = extract_inventory([changed_source], target_snapshot=SNAPSHOT)
    assert first.sources[0].id != changed_bytes.sources[0].id
    assert json.loads(json.dumps(first.to_dict())) == first.to_dict()
    assert asdict(source)["data"] == source.data


def test_selection_cannot_hide_missing_paths_or_unrendered_profile():
    source = document("services:\n  api:\n    image: nginx\n    profiles: [disabled]\n", variant="prod")
    missing = extract_inventory([source], target_snapshot=SNAPSHOT,
                                selections=[Selection("customer", "prod", ("absent.yaml",))])
    assert missing.services[0].selection == "unknown"
    assert "selection_unresolved" in {item.code for item in missing.gaps}
    partial = extract_inventory([source], target_snapshot=SNAPSHOT,
                                selections=[Selection("customer", "prod", ("compose.yaml",))])
    assert partial.services[0].selection == "unknown"
    with pytest.raises(ValueError):
        extract_inventory([source], target_snapshot=SNAPSHOT, selections=[
            Selection("customer", "prod", ("compose.yaml",)), Selection("customer", "dev", ("dev.yaml",)),
        ])


def test_wire_contract_cannot_upgrade_scope_or_listener_authority():
    original = extract_inventory([fixture("compose.yaml", "compose")], target_snapshot=SNAPSHOT).to_dict()
    value = deepcopy(original)
    value["coverage"][0]["disposition"] = "excluded"
    with pytest.raises(ValueError, match="exclusion"):
        validate_inventory(value)
    value = deepcopy(original)
    value["listeners"][0]["evidence_class"] = "observed_listener"
    with pytest.raises(ValueError, match="static listeners"):
        validate_inventory(value)
    value = deepcopy(original)
    value["services"][0]["selection"] = "selected"
    with pytest.raises(ValueError, match="selection"):
        validate_inventory(value)
    value = deepcopy(original)
    value["services"][0]["key"] = "compose:altered"
    with pytest.raises(ValueError, match="service identity"):
        validate_inventory(value)
    value = deepcopy(original)
    value["evidence"][0]["rule"] = "made-up-rule.v1"
    with pytest.raises(ValueError, match="invalid deployment inventory"):
        validate_inventory(value)
