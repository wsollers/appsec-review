"""Lead coverage: every observation producer is a lead family or a documented non-lead; secrets never leak.

The ``secret`` family (gitleaks) was missing, so a seeded hard-coded key stopped at ``observed``. These tests pin
the family, the explicit producer decision table, the unmapped-scanner gap, and the rule that no credential
literal reaches a lead menu, a package, a view or a published file.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

import jsonschema
import pytest

from appsec_review.jobs.job_evidence_collection.adapters import adapter_registry
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.review import lead_families
from appsec_review.review.lead_families import (
    CLASS_FAMILY, FAMILIES, FAMILY_PRODUCERS, FAMILY_RULES, NOT_A_LEAD_CLASSES, OBSERVATION_PRODUCERS,
    collect_leads, non_lead_key, observation_family, producer_decision,
)
from appsec_review.review.package_view import ViewLimits, build_view
from appsec_review.review.packages import OBLIGATIONS, PackageSettings, assemble_packages, publish_packages
from appsec_review.review.scope import PRODUCERS, accept_manifest
from appsec_review.review.secret_redaction import redact_message, redact_source_line
from tests.fixtures.inference_review.builder import FIXTURE_SECRET, build_accepted_index_set

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "docs" / "schemas" / "review-packages.schema.json").read_text(encoding="utf-8"))
LIMITS = ViewLimits(48 * 1024, 160, 6)


@pytest.fixture(scope="module")
def secret_run(tmp_path_factory):
    return build_accepted_index_set(tmp_path_factory.mktemp("lead-coverage-secret"), secrets=True)


@pytest.fixture(scope="module")
def leaky_run(tmp_path_factory):
    """A gitleaks row that wrongly carries the raw match in several fields (a producer fault)."""
    extra = {"message": f"Detected a key {FIXTURE_SECRET} in config", "Match": f"kApiKey = {FIXTURE_SECRET}",
             "raw": {"secret": FIXTURE_SECRET}, "native_rule_id": f"rule-{FIXTURE_SECRET}"}
    return build_accepted_index_set(tmp_path_factory.mktemp("lead-coverage-leaky"), secrets=True, secret_extra=extra)


def _secret_package(assembly, fixture) -> dict:
    [document] = [item.document() for item in assembly.packages
                  if item.kind == "finding_lead" and item.lead_ids == (fixture.ids["secret_key"],)]
    return document


# --------------------------------------------------------------------------------------------- the secret family


def test_gitleaks_observation_becomes_a_secret_lead_with_the_menu_entry(secret_run) -> None:
    collection = collect_leads(accept_manifest(secret_run.run_root))
    [lead] = [item for item in collection.leads if item.family == "secret"]
    assert lead.observation_id == secret_run.ids["secret_key"]
    assert (lead.scanner, lead.rule_id) == ("tool-gitleaks", "generic-api-key")    # the entity name restores the id
    assert (lead.path, lead.start_line, lead.location_exact) == ("native/src/config.cpp", 2, True)
    assert (lead.reported_severity, lead.severity_basis, lead.native_severity) == ("unknown", "no-native-severity", None)
    assert lead.rule_cwe == ("CWE-798",) and lead.severity_rule == "appsec-review/lead-family/secret/1"
    assert collection.available["secret"] is True
    assert not [gap for gap in collection.gaps if gap.producer == "unmapped_observations"]


def test_secret_lead_is_admitted_by_default_and_packaged_with_its_obligations(secret_run) -> None:
    assembly = assemble_packages(accept_manifest(secret_run.run_root))
    package = _secret_package(assembly, secret_run)
    jsonschema.Draft202012Validator(SCHEMA).validate(package)
    entry = package["lead_menu"][0]
    assert entry["lead_family"] == "secret" and entry["reported_severity"] == "unknown"
    assert entry["admission_reasons"] == ["reported_severity"] and entry["location_exact"] is True
    assert (entry["scanner"], entry["rule_id"]) == ("tool-gitleaks", "generic-api-key")
    assert package["evidence"][0]["resolution"] == "source_line"
    assert package["scope"]["component_id"] == "component:0002"
    assert package["proof_obligations"] == sorted(item.value for item in OBLIGATIONS["secret"])
    audit = assembly.manifest["audit"]["lane_a"]
    assert audit["status"] == "passed" and audit["by_family"]["secret"] == {"critical": 0, "high": 0, "unknown": 1}
    assert assembly.manifest["audit"]["families_available"]["secret"] is True


def test_secret_lead_is_admitted_under_the_repository_lane_settings() -> None:
    from appsec_review.config import load_config
    settings = load_config(ROOT / "appsec-review.toml").job("job_inference_security_review").typed_settings
    assert PackageSettings.from_review_settings(settings).admit_severities == ("critical", "high", "unknown")
    assert settings.lanes.lead_admission_kev is True and 0.0 < settings.lanes.lead_budget_share < 1.0


def test_absent_secret_producer_is_a_named_gap_not_an_empty_family(tmp_path) -> None:
    fixture = build_accepted_index_set(tmp_path, secrets=True, omit=("gitleaks",))
    assembly = assemble_packages(accept_manifest(fixture.run_root))
    assert assembly.manifest["audit"]["families_available"]["secret"] is False
    gap = next(item for item in assembly.manifest["gaps"] if item["producer"] == "secret")
    assert gap["state"] == "missing" and "secret_scanner" in gap["reason"] and "not absent" in gap["reason"]


def test_default_fixture_has_no_secret_or_config_producer_and_says_so(tmp_path) -> None:
    fixture = build_accepted_index_set(tmp_path)
    audit = assemble_packages(accept_manifest(fixture.run_root)).manifest["audit"]
    assert audit["families_available"]["secret"] is False and audit["families_available"]["config_scanner"] is False


# ----------------------------------------------------------------------------------- the producer decision table


def _evidence_tools() -> set[str]:
    return set(adapter_registry())


def test_every_evidence_collection_tool_has_an_explicit_decision() -> None:
    undecided = sorted(tool for tool in _evidence_tools()
                       if producer_decision("job_evidence_collection", tool) is None)
    assert not undecided, f"new evidence-collection tools need a family or a not-a-lead reason: {undecided}"


def test_every_job_that_publishes_tool_observations_is_decided() -> None:
    """A new job deriving ``tool_observation`` entities must be mapped to a family or listed with a reason."""
    pattern = re.compile(r"derive\(\s*EntityKind\.TOOL_OBSERVATION")
    publishers = {path.parent.name for path in (ROOT / "src" / "appsec_review" / "jobs").glob("job_*/*.py")
                  if pattern.search(path.read_text(encoding="utf-8"))}
    decided = {item.job for item in OBSERVATION_PRODUCERS}
    assert publishers, "the producer scan found nothing; the pattern is stale"
    assert not publishers - decided, f"observation producers without a lead decision: {sorted(publishers - decided)}"


def test_decisions_are_well_formed_and_every_family_has_a_producer_selector() -> None:
    assert set(FAMILY_PRODUCERS) == set(FAMILIES) == set(FAMILY_RULES)
    assert all(name in PRODUCERS for names in FAMILY_PRODUCERS.values() for name in names)
    assert all(item.reason for item in OBSERVATION_PRODUCERS)
    keys = [(item.job, item.scanner) for item in OBSERVATION_PRODUCERS]
    assert len(keys) == len(set(keys)), "a producer has two decisions"
    assert set(CLASS_FAMILY.values()) <= set(FAMILIES)
    assert {item.family for item in OBSERVATION_PRODUCERS if item.family} <= set(FAMILIES)
    with pytest.raises(ValueError):
        lead_families.ProducerDecision("job_evidence_collection", "tool-x", "no_such_family", "reason")
    with pytest.raises(ValueError):
        lead_families.ProducerDecision("job_evidence_collection", "tool-x", None, "")


def test_deliberate_non_leads_are_listed_with_reasons() -> None:
    not_leads = {item.scanner for item in OBSERVATION_PRODUCERS if item.family is None}
    assert {"tool-syft", "tool-blint", "tool-zizmor"} <= not_leads
    assert set(NOT_A_LEAD_CLASSES) == {"diagnostic", "inventory", "binary"}


def _row(tool: str, **payload) -> dict:
    return {"identity": "asr:tool_observation:" + "0" * 64, "name": "rule", "payload": {"tool_id": tool, **payload}}


def _shard(job: str, tool: str | None = None) -> dict:
    return {"name": "observations", "shard_id": "s", "producer": {"job": job, **({"producer": tool} if tool else {})}}


@pytest.mark.parametrize(("tool", "category", "family"), [
    ("tool-gitleaks", "static_analysis", "secret"),
    ("tool-shellcheck", "static_analysis", "source_sast"),       # generic category used to be dropped
    ("tool-psalm", "static_analysis", "source_sast"),
    ("tool-semgrep", "source_sast", "source_sast"),
    ("tool-hadolint", "static_analysis", "config_scanner"),
    ("tool-checkov", "configuration", "config_scanner"),
    ("tool-trivy", "configuration", "config_scanner"),
    ("tool-zizmor", "static_analysis", None),
    ("tool-syft", "software_inventory", None),
    ("tool-blint", "binary_hardening", None),
    ("tool-pmd", "tool_diagnostic", None),
    ("tool-osv-scanner", "vulnerability_matching", "dependency_advisory"),
])
def test_evidence_collection_rows_map_to_their_decided_family(tool, category, family) -> None:
    row, shard = _row(tool, category=category), _shard("job_evidence_collection", tool)
    assert observation_family(row, shard) == family
    if family is None:
        assert non_lead_key(row, shard) is not None, "a deliberate non-lead is accounted, not silent"


def test_infer_rows_are_source_sast_leads_and_their_shard_counts_as_source_sast_coverage() -> None:
    row = {"identity": "asr:tool_observation:" + "1" * 64, "name": "NULL_DEREFERENCE",
           "payload": {"tool": "infer", "rule_id": "NULL_DEREFERENCE", "severity": "ERROR", "category": ""}}
    shard = {"name": "observations", "shard_id": "cpp-x-infer",
             "producer": {"job": "job_cpp_compiled_analysis", "branch": "infer"}}
    assert observation_family(row, shard) == "source_sast" and PRODUCERS["source_sast"](shard)
    assert not PRODUCERS["source_sast"]({**shard, "producer": {"job": "job_cpp_compiled_analysis", "branch": "ast"}})


def test_non_sast_evidence_tools_do_not_count_as_source_sast_coverage() -> None:
    for tool, producer in (("tool-gitleaks", "secret_scanner"), ("tool-hadolint", "config_scanner")):
        shard = _shard("job_evidence_collection", tool)
        assert PRODUCERS[producer](shard) and not PRODUCERS["source_sast"](shard)
    for tool in ("tool-syft", "tool-blint", "tool-zizmor"):
        assert not PRODUCERS["source_sast"](_shard("job_evidence_collection", tool))
    assert PRODUCERS["source_sast"](_shard("job_evidence_collection", "tool-semgrep"))


def test_an_unmapped_scanner_is_a_named_gap_never_a_silent_drop(secret_run, monkeypatch) -> None:
    decisions = tuple(item for item in OBSERVATION_PRODUCERS if item.scanner != "tool-gitleaks")
    monkeypatch.setattr(lead_families, "OBSERVATION_PRODUCERS", decisions)
    monkeypatch.setattr(lead_families, "CLASS_FAMILY", {"source_sast": "source_sast"})
    collection = collect_leads(accept_manifest(secret_run.run_root))
    assert not [item for item in collection.leads if item.family == "secret"]
    [gap] = [item for item in collection.gaps if item.producer == "unmapped_observations"]
    assert gap.state == "partial" and gap.scope == "observations/gitleaks:tool-gitleaks" and "1 observation" in gap.reason


def test_deliberate_non_leads_are_counted_in_the_manifest_not_in_gaps() -> None:
    row, shard = _row("tool-syft", category="software_inventory"), _shard("job_evidence_collection", "tool-syft")
    assert non_lead_key(row, shard) == "class:inventory"
    row = _row("tool-zizmor", category="static_analysis")
    assert non_lead_key(row, _shard("job_evidence_collection", "tool-zizmor")) == "scanner:tool-zizmor"


# ------------------------------------------------------------------------------------------- secret redaction


def test_redaction_replaces_the_literal_and_keeps_the_line_structure() -> None:
    assert redact_source_line(f'static const char *kApiKey = "{FIXTURE_SECRET}";') == \
        f'static const char *kApiKey = "<redacted:{len(FIXTURE_SECRET)} chars>";'
    assert redact_source_line(f"  API_KEY={FIXTURE_SECRET}") == f"  API_KEY=<redacted:{len(FIXTURE_SECRET)} chars>"
    assert FIXTURE_SECRET not in redact_source_line(f"  token: {FIXTURE_SECRET}  # prod")
    assert FIXTURE_SECRET not in redact_source_line(f"send({FIXTURE_SECRET});")          # a bare, mixed-class token
    assert redact_source_line("int send_key() { return post(kApiKey); }") == "int send_key() { return post(kApiKey); }"
    assert redact_source_line("    AKIAIOSFODNN7EXAMPLE", whole_line=True) == "    <redacted:20 chars>"
    assert FIXTURE_SECRET not in (redact_message(f"found {FIXTURE_SECRET} here") or "")


def test_no_secret_value_reaches_any_artifact_the_intake_produces(secret_run, leaky_run, tmp_path) -> None:
    for fixture in (secret_run, leaky_run):
        scope = accept_manifest(fixture.run_root)
        collection = collect_leads(scope)
        assembly = assemble_packages(scope)
        out = tmp_path / fixture.run_root.parent.parent.name
        manifest = publish_packages(assembly, out)
        serialized = [repr(collection.leads), json.dumps(assembly.manifest, sort_keys=True),
                      manifest.read_text(encoding="utf-8")]
        serialized += [package.body.decode("utf-8") for package in assembly.packages]
        serialized += [path.read_text(encoding="utf-8") for path in sorted(out.rglob("*.json"))]
        core = RetrievalCore(fixture.runs_dir, fixture.run_id)
        for package in assembly.packages:
            view = build_view(package.document(), core, LIMITS)
            serialized.append(json.dumps(view.document, sort_keys=True))
            serialized += [json.dumps(list(rows), sort_keys=True) for rows in view.files.values()]
        text = "\n".join(serialized)
        assert "tool-gitleaks" in text                       # the artifacts were not simply empty
        assert FIXTURE_SECRET not in text and "sk_live_" not in text
        assert "kApiKey = " not in text.replace('kApiKey = \\"<redacted', "")


def test_the_model_facing_excerpt_redacts_the_literal_but_shows_where_it_is_used(secret_run) -> None:
    assembly = assemble_packages(accept_manifest(secret_run.run_root))
    package = _secret_package(assembly, secret_run)
    core = RetrievalCore(secret_run.runs_dir, secret_run.run_id)
    view = build_view(package, core, LIMITS)
    [span] = [item for item in view.document["source"] if item["role"] == "function"]
    lines = "\n".join(span["text"])
    assert FIXTURE_SECRET not in lines and f"<redacted:{len(FIXTURE_SECRET)} chars>" in lines
    assert "2| static const char *kApiKey = " in lines and "post(kApiKey)" in lines
    assert view.document["leads"][0]["family"] == "secret"
    assert FIXTURE_SECRET not in json.dumps(view.document)


def test_a_multi_line_secret_span_is_redacted_line_by_line() -> None:
    from appsec_review.review.package_view import _Builder
    builder = _Builder({}, None, LIMITS)
    builder.secret_lines["k.pem"] = [(2, 4)]
    lines = ["key = (", "-----BEGIN PRIVATE KEY-----", "MIIEvQIBADANBgkqhkiG9w0B", "-----END PRIVATE KEY-----", ")"]
    span = builder._span("ref", "k.pem", "sha", lines, 1, 5, "function", False)
    assert span["text"][0] == "1| key = (" and span["text"][4] == "5| )"
    assert all("<redacted:" in line for line in span["text"][1:4])
    assert "MIIEvQ" not in "\n".join(span["text"]) and "BEGIN PRIVATE" not in "\n".join(span["text"])
