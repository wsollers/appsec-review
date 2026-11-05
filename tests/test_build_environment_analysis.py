from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import (
    BuildEnvironmentSettings, PlanningFeedbackSettings, load_config, parse_bounded_settings,
)
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_build_environment_analysis.job import (
    JOB_ID, analyze_environment, build_job, environment_contract, load_environment, redact, validate_environment,
)
from appsec_review.jobs.job_review_intake import build_job as intake_job
from appsec_review.jobs.job_target_catalog import build_job as catalog_job
from appsec_review.runtime import GraphRunner

ROOT = Path(__file__).parents[1]


def _static(files, **limits):
    payloads = {path: text.encode() for path, text in files.items()}
    catalog = {"source_fingerprint": "synthetic-source", "catalog_handoff_sha256": "c" * 64,
               "files": [{"path": path, "sha256": hashlib.sha256(data).hexdigest(),
                          "size_bytes": len(data)} for path, data in payloads.items()]}
    return analyze_environment(catalog, lambda item, bound: payloads[item["path"]][:bound + 1],
                               replace(BuildEnvironmentSettings(), **limits))


def test_static_literals_are_advisory_redacted_and_source_resolving():
    value = _static({"setup.sh": "SDK_ROOT=tools/sdk\nAPI_TOKEN=do-not-retain\nURL=https://u:p@host/a\n"})
    assert value["availability"] == "AVAILABLE"
    assert value["declarations"][0]["value"] == "tools/sdk"
    assert value["declarations"][0]["reason"] == "static_literal_advisory_only"
    assert [item["status"] for item in value["declarations"]] == ["declared", "redacted", "redacted"]
    assert all(item["sha256"] == hashlib.sha256(
        b"SDK_ROOT=tools/sdk\nAPI_TOKEN=do-not-retain\nURL=https://u:p@host/a\n").hexdigest()
               for item in value["declarations"])
    assert "do-not-retain" not in json.dumps(value)
    assert "u:p@" not in json.dumps(value)


@pytest.mark.parametrize("text", [
    "if test -f flag; then\nCC=clang\nfi\n", "source other.sh\nCC=clang\n",
    "SDK=$(dirname \"$0\")\nCC=clang\n", "call other.cmd\nCC=clang\n",
    "cd child\nCC=clang\n", "CC=clang;make\n", "CC=clang args\n",
    "pushd child\nCC=clang\n", "function setup {\nCC=clang\n}\n", "setup() {\nCC=clang\n}\n",
])
def test_uncertain_script_context_never_becomes_a_known_value(text):
    value = _static({"setup.sh": text})
    assert value["declarations"]
    assert all(item["value"] is None and item["status"] == "unknown" for item in value["declarations"])


def test_literal_sourced_inventory_is_bounded_and_context_tainted():
    value = _static({"setup.sh": "source child.sh\n", "child.sh": "CC=clang\n",
                     "unselected.sh": "UNRELATED=1\n"})
    assert value["bounds"]["inspected_scripts"] == 2
    assert value["declarations"][0]["path"] == "child.sh"
    assert value["declarations"][0]["status"] == "unknown"
    assert all(item["name"] != "UNRELATED" for item in value["declarations"])


@pytest.mark.parametrize("child", ["env-child.sh", "z-env.sh"])
def test_sourced_context_taints_an_already_selected_script_in_either_discovery_order(child):
    value = _static({"setup.sh": "source " + child + "\n", child: "CC=clang\n"})
    assert value["bounds"]["inspected_scripts"] == 2
    declarations = [item for item in value["declarations"] if item["path"] == child]
    assert len(declarations) == 1 and declarations[0]["status"] == "unknown"
    assert declarations[0]["value"] is None and value["coverage"] == "partial"


@pytest.mark.parametrize("limit,files,expected", [
    ({"max_scripts": 1}, {"env-a.sh": "A=1", "env-b.sh": "B=2"}, "script_count_exhausted"),
    ({"max_script_bytes": 1}, {"setup.sh": "A=1"}, "script_byte_bound"),
    ({"max_assignments": 1}, {"setup.sh": "A=1\nB=2\n"}, "assignment_count_exhausted"),
    ({"max_depth": 1}, {"setup.sh": "source a.sh", "a.sh": "source b.sh",
                       "b.sh": "B=2"}, "source_depth_or_script_bound"),
])
def test_static_exhaustion_publishes_partial_coverage(limit, files, expected):
    value = _static(files, **limit)
    assert value["coverage"] == "partial"
    assert any(expected in gap for gap in value["gaps"])


def test_powershell_and_empty_inventory_have_distinct_honest_coverage():
    unsupported = _static({"setup.ps1": "$env:CC='cl'"})
    assert unsupported["availability"] == "UNAVAILABLE" and unsupported["coverage"] == "partial"
    assert _static({})["coverage"] == "not_applicable"
    assert "inspected scope" not in unsupported["gaps"]


def test_internal_deadline_is_a_named_gap_not_an_unexpected_failure():
    catalog = {"source_fingerprint": "s", "catalog_handoff_sha256": "c" * 64, "files": []}
    # A finite empty scope is not a timeout; a pending script is.
    catalog["files"] = [{"path": "setup.sh", "sha256": "a" * 64, "size_bytes": 1}]
    times = iter((0, 31))
    result = analyze_environment(catalog, lambda *_: pytest.fail("deadline must prevent the read"),
                                 BuildEnvironmentSettings(), clock=lambda: next(times))
    assert result["availability"] == "UNAVAILABLE"
    assert result["gaps"] == ["internal_environment_deadline"]


def test_source_corruption_and_unexpected_reader_bugs_propagate():
    catalog = {"source_fingerprint": "s", "catalog_handoff_sha256": "c" * 64,
               "files": [{"path": "setup.sh", "sha256": "a" * 64, "size_bytes": 3}]}
    with pytest.raises(ValueError, match="source bytes changed"):
        analyze_environment(catalog, lambda *_: b"A=1", BuildEnvironmentSettings())
    def broken(*_):
        raise RuntimeError("synthetic unexpected bug")
    with pytest.raises(RuntimeError, match="synthetic unexpected bug"):
        analyze_environment(catalog, broken, BuildEnvironmentSettings())


@pytest.mark.parametrize("kind,key,value", [
    ("environment", "max_scripts", 65), ("environment", "max_script_bytes", 262145),
    ("environment", "max_assignments", 4097), ("environment", "max_depth", 5),
    ("environment", "enabled", "true"), ("feedback", "max_calls", 5),
    ("feedback", "max_evidence_rounds", 4), ("feedback", "max_documents", 9),
    ("feedback", "max_request_bytes", 131073), ("feedback", "max_response_bytes", 65537),
    ("feedback", "units_per_scope", 0), ("feedback", "max_scopes", True),
])
def test_typed_bounds_reject_loosening_and_nonintegers(kind, key, value):
    with pytest.raises(ValueError):
        parse_bounded_settings({key: value}, BuildEnvironmentSettings if kind == "environment"
                               else PlanningFeedbackSettings)


def _published(tmp_path):
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_bytes((ROOT / "appsec-review.toml").read_bytes())
    config = load_config(config_path)
    target = tmp_path / "target"
    target.mkdir()
    (target / "setup.sh").write_bytes(b"SDK_ROOT=tools/sdk\n")
    fingerprint = source_fingerprint(target)
    result = GraphRunner(config, [intake_job(), catalog_job(), build_job()]).run(
        target_root=target, source_fingerprint=fingerprint)
    run_root = config.runtime.runs_dir / result["run_id"]
    pointer = json.loads((run_root / "data/jobs" / JOB_ID / "latest.json").read_bytes())
    contract = environment_contract(config, {"workflow": "wave1_review"},
                                    {JOB_ID: pointer["handoff_sha256"]})
    return config, run_root, fingerprint, contract


def test_real_static_producer_publication_and_strict_current_reader(tmp_path):
    config, root, fingerprint, contract = _published(tmp_path)
    value = load_environment(root, fingerprint, contract)
    assert config.job(JOB_ID).settings["enabled"] is True
    assert value["availability"] == "AVAILABLE"
    assert value["evidence"]["declarations"][0]["name"] == "SDK_ROOT"
    assert value["expected_producer"] == JOB_ID
    assert value["artifact"]["sha256"] == hashlib.sha256(
        (root / value["artifact"]["path"]).read_bytes()).hexdigest()


def test_optional_prior_stale_is_unavailable_but_expected_current_blocks(tmp_path):
    _, root, _, contract = _published(tmp_path)
    optional = {**contract, "mode": "OPTIONAL_PRIOR", "expected_producer": None,
                "workflow": "standalone"}
    value = load_environment(root, "other-source", optional)
    assert value["availability"] == "UNAVAILABLE"
    assert value["evidence"] is None and value["artifact"] is None
    assert value["reason"] == "STALE optional prior source"
    with pytest.raises(ValueError, match="wrong source"):
        load_environment(root, "other-source", contract)


@pytest.mark.parametrize("mode,availability", [("NOT_RUN", "ABSENT"), ("DISABLED", "DISABLED")])
def test_explicit_absent_or_disabled_needs_no_producer(tmp_path, mode, availability):
    config = load_config(ROOT / "appsec-review.toml")
    orchestration = {}
    if mode == "DISABLED":
        jobs = dict(config.jobs)
        jobs[JOB_ID] = replace(jobs[JOB_ID], settings={**jobs[JOB_ID].settings, "enabled": False})
        config = replace(config, jobs=jobs)
    contract = environment_contract(config, orchestration, {})
    assert contract["mode"] == mode and contract["reason"]
    assert load_environment(tmp_path, "s", contract)["availability"] == availability


def test_expected_current_missing_and_changed_bytes_block(tmp_path):
    config = load_config(ROOT / "appsec-review.toml")
    contract = environment_contract(config, {"workflow": "wave1_review"}, {})
    with pytest.raises(ValueError, match="no accepted handoff"):
        load_environment(tmp_path, "s", contract)
    _, root, source, contract = _published(tmp_path)
    value = load_environment(root, source, contract)
    (root / value["artifact"]["path"]).write_bytes(b"{}")
    with pytest.raises(ValueError, match="identity mismatch"):
        load_environment(root, source, contract)


def test_redaction_precedes_model_context():
    assert redact("TOKEN=abc\nURL=https://name:password@host/x\n") == (
        "[REDACTED assignment]\nURL=https://[REDACTED]@host/x\n")


@pytest.mark.parametrize("mutation", ["unknown_field", "unknown_bound", "loosen_bound", "bad_path",
                                   "unavailable_facts", "false_complete", "false_not_applicable"])
def test_environment_reader_rejects_schema_and_coverage_corruption(mutation):
    value = _static({"setup.sh": "SDK=tools/sdk\n"})
    if mutation == "unknown_field":
        value["extra"] = True
    elif mutation == "unknown_bound":
        value["bounds"]["extra"] = True
    elif mutation == "loosen_bound":
        value["bounds"]["max_scripts"] = 65
    elif mutation == "bad_path":
        value["declarations"][0]["path"] = "dir\\setup.sh"
    elif mutation == "unavailable_facts":
        value["availability"] = "UNAVAILABLE"
    elif mutation == "false_complete":
        value["gaps"] = ["unsupported"]
    else:
        value["coverage"] = "not_applicable"
    with pytest.raises(ValueError):
        validate_environment(value)


def test_redaction_preserves_unmodified_raw_line_endings_and_withholds_container_secrets():
    text = "FROM pinned-base\r\nENV SDK=tools/sdk\r\n"
    assert redact(text) == text
    assert redact("ENV API_TOKEN=value\r\n") == "[REDACTED assignment]\r\n"


def test_environment_publication_matches_the_checked_in_offline_schema():
    from jsonschema import Draft202012Validator
    schema = json.loads((ROOT / "docs/schemas/build-environment-analysis.schema.json").read_bytes())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for files in ({}, {"setup.ps1": "unsupported"}, {"setup.sh": "SDK=tools/sdk\n"},
                  {"setup.sh": "source missing.sh\nSDK=tools/sdk\n"}):
        validator.validate(_static(files))


@pytest.mark.parametrize("handoff", [False, True])
def test_environment_handoff_bound_does_not_relax_the_environment_artifact_bound(tmp_path, handoff):
    from appsec_review.jobs.job_build_environment_analysis.job import _read
    data = b'{"padding":"' + b"x" * 16777216 + b'"}'
    path = tmp_path / "bounded-environment.json"
    path.write_bytes(data)
    identity = {"path": path.name, "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}
    if handoff:
        assert len(_read(tmp_path, identity, byte_limit=33554432)["padding"]) == 16777216
        with pytest.raises(ValueError, match="identity mismatch"):
            _read(tmp_path, {**identity, "sha256": "f" * 64}, byte_limit=33554432)
    else:
        with pytest.raises(ValueError, match="exceeds its bound"):
            _read(tmp_path, identity)
    with pytest.raises(ValueError, match="unsupported.*byte limit"):
        _read(tmp_path, identity, byte_limit=33554433)
