from __future__ import annotations

from copy import deepcopy
import json

import pytest

from appsec_review.jobs.job_security_tagging.taxonomy import TaxonomyError, parse_capability_rules
from appsec_review.owasp_workbench.engine import classify_components

from .helpers import ROOT, taxonomy


def rule_document():
    return json.loads((ROOT / "data/reference/taxonomy/capability-rules.json").read_text())


@pytest.mark.parametrize("case", [
    "unknown-key", "unknown-family", "unknown-class", "unclassified", "duplicate-class", "missing-class",
    "empty-languages", "bad-languages", "missing-rationale", "blank-rationale", "finding", "control",
    "public-http", "remote-http-route", "remote-rpc", "sink-entry", "duplicate-id", "not-object",
])
def test_pinned_graph_rules_reject_unknown_or_promoting_rules(case):
    vocabulary, _, _ = taxonomy()
    document = rule_document()
    rule = document["graph_rules"][0]
    if case == "unknown-key":
        rule["regex"] = ".*"
    elif case == "unknown-family":
        rule["family"] = "call_site"
    elif case in {"unknown-class", "unclassified", "duplicate-class", "missing-class"}:
        rule["classes"] = {"unknown-class": ["new"], "unclassified": ["unclassified"],
                           "duplicate-class": ["remote", "remote"], "missing-class": []}[case]
    elif case in {"empty-languages", "bad-languages"}:
        rule["languages"] = [] if case == "empty-languages" else [1]
    elif case == "missing-rationale":
        rule.pop("rationale")
    elif case == "blank-rationale":
        rule["rationale"] = " "
    elif case in {"finding", "control", "public-http", "remote-http-route", "remote-rpc", "sink-entry"}:
        rule["emit"] = [{"finding": "cwe:89", "control": "asvs5:v1",
                         "public-http": "surface:entry:http-public", "remote-http-route": "func:net:http-route",
                         "remote-rpc": "surface:entry:rpc", "sink-entry": "surface:entry:file-input"}[case]]
        if case == "sink-entry":
            rule["family"], rule["classes"] = "sink_site", ["sql_query"]
    elif case == "duplicate-id":
        document["graph_rules"].append(deepcopy(rule))
    else:
        document["graph_rules"][0] = "not-a-rule"
    with pytest.raises(TaxonomyError):
        parse_capability_rules(document, "0" * 64, vocabulary)


def test_legacy_rules_remain_declared_and_pinned_rules_cover_only_supported_classes():
    vocabulary, current, _ = taxonomy()
    document = rule_document()
    document.pop("graph_rules")
    previous = parse_capability_rules(document, "0" * 64, vocabulary)
    for field in ("path_rules", "package_rules", "observation_rules", "languages", "coverage_gaps"):
        assert getattr(previous, field) == getattr(current, field)
    assert previous.graph_rules == ()
    for rule in current.package_rules:
        for tag in rule["emit"]:
            vocabulary.validate_tag(tag, "declared")


def classify(tag, basis):
    return classify_components([{
        "component_id": "component:app", "project_id": "project:app",
        "evidence": [{"source_identity": "accepted-component", "artifact_sha256": "a" * 64, "lines": [1, 1]}],
        "routing_context": [{"identity": "asr:tag_assignment:" + "0" * 64, "name": tag, "tag": tag, "basis": basis,
                             "subject": {"kind": "component", "logical_id": "c"}}],
    }])[0]


@pytest.mark.parametrize("tag,role", [
    ("role:auth", "authentication_identity"), ("role:session", "authentication_identity"),
    ("role:authorization", "authentication_identity"),
    ("role:crypto", "cryptography_data_protection"), ("asset:keys", "cryptography_data_protection"),
    ("role:storage", "storage"), ("state:persistent-store", "storage"),
    ("mechanism:networked-listener", "network"), ("role:build-glue", "build_supply_chain"),
    ("role:test", "test_development_only"),
])
def test_collation_facets_route_component_roles_with_their_recorded_basis(tag, role):
    """T-5008: the workbench reads roles from facets; the keyword classifier is gone."""
    for basis in ("declared", "invoked", "derived"):
        result = classify(tag, basis)
        assert role in result["roles"]
        assert any(basis in reason and "not control proof" in reason for reason in result["reasons"])
        assert result["target_classes"] == [] and result["confidence"] == "low"


def test_target_class_comes_only_from_a_derived_target_tag():
    assert classify("target:cli", "derived")["target_classes"] == ["target:cli"]
    assert classify("target:web-api", "derived")["roles"] == ["application_api_server"]
    assert classify("target:cli", "declared")["target_classes"] == []
    assert classify("target:cli", "derived")["confidence"] == "high"


@pytest.mark.parametrize("tag,basis", [
    ("func:authn:jwt", "declared"), ("func:authn:jwt", "invoked"),      # capabilities route through facets now
    ("func:crypto:symmetric", "invoked"), ("func:data:sql-query", "invoked"),
    ("role:auth", "confirmed"), ("role:auth", None), ("surface:entry:remote-input", "invoked"),
    ("cwe:89", "reported"), ("asvs5:v1", "derived"), ("role:invented", "declared"),
])
def test_noncanonical_or_wrong_basis_tags_never_establish_component_role(tag, basis):
    result = classify(tag, basis)
    if tag == "role:invented":
        # Grammatical but not a facet the workbench maps: nothing is routed, nothing is invented.
        assert result["roles"] == []
    else:
        assert result["roles"] == []
    assert result["ambiguity"]


def test_malformed_routing_context_cannot_establish_a_role():
    result = classify_components([{
        "component_id": "component:app", "project_id": "project:app",
        "evidence": [{"source_identity": "accepted-component", "artifact_sha256": "a" * 64, "lines": [1, 1]}],
        "routing_context": [None, "role:auth", {"tag": [], "basis": "declared"},
                            {"name": "role:auth", "basis": ["declared"]}, {"name": "ROLE:AUTH", "basis": "declared"}],
    }])[0]
    assert not result["roles"] and not result["target_classes"] and result["ambiguity"]
