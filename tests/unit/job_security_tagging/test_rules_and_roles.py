from __future__ import annotations

from copy import deepcopy
import json

import pytest

from appsec_review.jobs.job_security_tagging.taxonomy import TaxonomyError, parse_capability_rules
from appsec_review.owasp_workbench.engine import characterize_components

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
    return characterize_components([{
        "component_id": "component:app", "project_id": "project:app",
        "evidence": [{"source_identity": "accepted-component", "artifact_sha256": "a" * 64, "lines": [1, 1]}],
        "routing_context": [{"tag": tag, "basis": basis}],
    }])[0]


@pytest.mark.parametrize("tag,role", [
    ("func:authn:jwt", "authentication_identity"), ("func:authn:oauth2-client", "authentication_identity"),
    ("func:session:cookie", "authentication_identity"),
    ("func:crypto:password-hash", "cryptography_data_protection"),
    ("func:crypto:symmetric", "cryptography_data_protection"),
    ("func:crypto:cert-validation", "cryptography_data_protection"),
    ("func:data:sql-query", "storage"), ("func:data:nosql-query", "storage"), ("func:data:orm", "storage"),
    ("func:data:ldap-query", "storage"), ("func:net:http-client", "network"),
    ("func:net:redirect", "network"),
])
def test_canonical_capabilities_route_with_their_original_basis(tag, role):
    for basis in ("declared", "invoked"):
        result = classify(tag, basis)
        assert result["roles"] == [role]
        assert any(basis in reason and "not control proof" in reason for reason in result["reasons"])


@pytest.mark.parametrize("tag,basis", [
    ("func:auth:authentication", "invoked"), ("func:crypto:encryption", "invoked"),
    ("func:authn:invented", "invoked"), ("func:crypto:invented", "invoked"),
    ("func:authn:jwt", "derived"), ("func:authn:jwt", "reported"), ("func:authn:jwt", None),
    ("func:crypto:symmetric", "confirmed"), ("surface:entry:remote-input", "invoked"),
    ("cwe:89", "reported"), ("asvs5:v1", "derived"),
])
def test_noncanonical_or_wrong_basis_tags_never_establish_component_role(tag, basis):
    result = classify(tag, basis)
    assert result["roles"] == []
    assert result["ambiguity"]


def test_malformed_routing_context_cannot_establish_a_role():
    result = characterize_components([{
        "component_id": "component:app", "project_id": "project:app",
        "evidence": [{"source_identity": "accepted-component", "artifact_sha256": "a" * 64, "lines": [1, 1]}],
        "routing_context": [None, "func:authn:jwt", {"tag": [], "basis": "invoked"},
                            {"tag": "func:authn:jwt", "basis": ["invoked"]}],
    }])[0]
    assert not result["roles"] and result["ambiguity"]
