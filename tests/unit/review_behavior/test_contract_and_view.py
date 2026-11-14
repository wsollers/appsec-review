from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import json
import tomllib

import jsonschema
import pytest

from appsec_review.config.inference_review import parse_inference_review_settings
from appsec_review.jobs.job_inference_security_review.datasets import CONTRACT
from appsec_review.review.behavior import MODEL_JOB, graph_operations
from appsec_review.review.package_view import ViewLimits, build_view
from appsec_review.review.packages import ASSEMBLY_RULE, PackageSettings
from appsec_review.review.units import RANK_RULE
from appsec_review.runtime.contracts import Availability, MissingPolicy

from .support import PATH, SHA, SOURCE, Scope, graph_row

ROOT = Path(__file__).resolve().parents[3]


def settings():
    with (ROOT / "appsec-review.toml").open("rb") as stream:
        return tomllib.load(stream)["jobs"]["job_inference_security_review"]["settings"]


def package_and_core():
    operations, _ = graph_operations(Scope(graph=[graph_row()]), limit=8)
    operation = operations[0].record()
    package = {"kind": "hunt", "lane": "hunt", "lead_menu": [], "context": [], "neighborhood": {},
               "scope": {"component_id": "api", "build_unit_id": "app", "partition_key": "unit:operation",
                         "operation": operation},
               "coverage_gaps": [], "retrieval": {"entity_ids": [SOURCE]}}
    location = {"path": PATH, "file_sha256": SHA, "start_line": 1, "end_line": 200}
    core = SimpleNamespace(
        read_source_lines=lambda **_: ({"location": location, "lines": [f"line {n}" for n in range(1, 201)]}, None),
        find=lambda **_: {"results": []})
    return package, core


def test_generated_input_contract_is_explicit_optional_and_routing_only():
    rows = [item for item in CONTRACT.inputs if item.producer == MODEL_JOB]
    assert {item.output_kind for item in rows} == {
        "handoff", "generated_dfd", "generated_threat_model", "generated_model_evidence", "threat_model_documents"}
    assert all(item.availability is Availability.OPTIONAL and item.missing is MissingPolicy.GAP for item in rows)
    assert all(item.authority.value == "routing_context" for item in rows)
    assert MODEL_JOB in CONTRACT.consumes


def test_central_bounds_reach_the_real_package_settings():
    parsed = parse_inference_review_settings(settings())
    assert PackageSettings.from_review_settings(parsed).max_operation_records == 2000
    assert PackageSettings.from_review_settings(parsed).max_behavior_artifact_bytes == 8388608
    assert RANK_RULE.endswith("/3") and ASSEMBLY_RULE.endswith("/13")


@pytest.mark.parametrize("key,value", [
    ("max_operation_records", 0), ("max_operation_records", True), ("max_operation_records", 100001),
    ("max_behavior_artifact_bytes", 0), ("max_behavior_artifact_bytes", 67108865),
])
def test_configuration_rejects_invalid_discovery_bounds(key, value):
    value_settings = settings()
    value_settings["packages"][key] = value
    with pytest.raises(ValueError, match=key):
        parse_inference_review_settings(value_settings)


def test_older_frozen_settings_get_bounded_defaults_without_mutation():
    value = settings()
    value["packages"].pop("max_operation_records")
    value["packages"].pop("max_behavior_artifact_bytes")
    before = deepcopy(value)
    parsed = parse_inference_review_settings(value)
    assert parsed.packages.max_operation_records == 2000 and value == before


def test_operation_view_shows_real_anchor_and_marks_scope_limit():
    package, core = package_and_core()
    view = build_view(package, core, ViewLimits(max_source_lines=20))
    operation = view.document["scope"]["operation"]
    assert operation["authority"] == "routing_context" and operation["lines"] == [20, 20]
    assert operation["questions"]
    assert view.document["source"] and "20| line 20" in view.document["source"][0]["text"]
    assert len(view.document["source"][0]["text"]) <= 20
    assert any("not complete control or whole-file proof" in item["text"] for item in view.document["material_gaps"])
    assert PATH in view.locator_paths


def test_operation_view_does_not_show_changed_source():
    package, core = package_and_core()
    package["scope"]["operation"]["file_sha256"] = "e" * 64
    view = build_view(package, core, ViewLimits())
    assert not view.document["source"]
    assert any("differs from accepted source" in item["text"] for item in view.document["material_gaps"])


def test_operation_view_preserves_missing_source_gap():
    package, core = package_and_core()
    core.read_source_lines = lambda **_: (None, "source unavailable")
    view = build_view(package, core, ViewLimits())
    assert not view.document["source"]
    assert any("source unavailable" in item["text"] for item in view.document["material_gaps"])


def test_generated_context_is_visible_but_never_an_evidence_label():
    package, core = package_and_core()
    package["scope"]["operation"]["model_context"] = [{
        "flow_id": "flow:1", "interaction": "network_receive", "basis": "derived",
        "boundary_ids": ["tb:1"], "threat_ids": ["threat:1"], "authority": "routing_context"}]
    view = build_view(package, core, ViewLimits())
    assert view.document["scope"]["operation"]["model_context"][0]["boundary_ids"] == ["tb:1"]
    assert "flow:1" not in view.labels.values() and "threat:1" not in view.packaged_refs


def test_operation_schema_rejects_authority_promotion_and_unknown_fields():
    package, _ = package_and_core()
    schema = json.loads((ROOT / "docs/schemas/review-packages.schema.json").read_text())
    validator = jsonschema.Draft202012Validator({"$defs": schema["$defs"], "$ref": "#/$defs/behavior_operation"})
    operation = package["scope"]["operation"]
    assert not list(validator.iter_errors(operation))
    assert list(validator.iter_errors({**operation, "authority": "confirmed"}))
    assert list(validator.iter_errors({**operation, "safe": True}))
