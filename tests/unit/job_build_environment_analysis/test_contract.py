"""Code-level environment contracts, launch modes, and Wave 4 read-scope pins."""
from __future__ import annotations

from dataclasses import asdict, replace
from fnmatch import fnmatch
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from jsonschema import Draft202012Validator
import pytest

from appsec_review.config import BuildEnvironmentSettings, load_config
from appsec_review.interchange import decode_handoff, validate_unit_output
from appsec_review.jobs.job_build_environment_analysis import build_job as package_build_job, load_environment as package_load_environment
from appsec_review.jobs.job_build_environment_analysis.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_build_environment_analysis.job import (
    JOB_ID,
    SCHEMA,
    analyze_environment,
    build_job,
    environment_contract,
    load_environment,
    optional_prior_environment_handoffs,
    planning_environment_inputs,
)
from appsec_review.jobs.job_target_analysis_plan.datasets import CONTRACT as PLANNER_CONTRACT
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff

ROOT = Path(__file__).resolve().parents[3]
PUBLISH = "environment_analysis.publish_handoff"
SOURCE = "synthetic-environment-source"
CATALOG_SHA = "c" * 64


def _catalog(root, attempt_id="attempt_0001", source=SOURCE):
    path = write_fixture_handoff(
        root, root / "data/jobs/job_target_catalog/attempts" / attempt_id / "handoff.json",
        {"job_id": "job_target_catalog", "source_fingerprint": source},
    )
    digest = file_sha256(path)
    atomic_json(root / "data/jobs/job_target_catalog/latest.json", {
        "handoff_path": path.relative_to(root).as_posix(), "handoff_sha256": digest,
    })
    return digest


def test_every_input_requirement_field_and_package_exports_are_pinned():
    assert package_build_job is build_job
    assert package_load_environment is load_environment
    schemas = (
        ("handoff", "appsec-review/job-handoff/2", "required", "reject"),
        ("target_artifact_inputs", "appsec-review/target-artifact-intake/1", "optional", "gap"),
        ("source_files", "appsec-review/retrieval-index/2", "optional", "gap"),
        ("declaration_symbols", "appsec-review/retrieval-index/2", "optional", "gap"),
        ("components", "appsec-review/retrieval-index/2", "optional", "gap"),
        ("target_documents", "appsec-review/retrieval-index/2", "optional", "gap"),
        ("build_units", "appsec-review/retrieval-index/2", "optional", "gap"),
        ("catalog_documents", "appsec-review/target-catalog/1", "optional", "gap"),
    )
    assert tuple(asdict(item) for item in CONTRACT.inputs) == tuple(
        {
            "producer": "job_target_catalog",
            "output_kind": kind,
            "schema": schema,
            "authority": "producer_evidence",
            "availability": availability,
            "missing": missing,
            "coverage": "allow_partial",
            "channel": "handoff",
        }
        for kind, schema, availability, missing in schemas
    )
    assert CONTRACT.schedule_after == ("job_target_catalog",)
    assert CONTRACT.consumes == CONSUMES == ("job_target_catalog",)
    assert CONTRACT.dispatch == "review_graph" and CONTRACT.target_access == "checkout"
    assert CONTRACT.always_execute is False and CONTRACT.propagate_handoff is True
    job = build_job()
    assert job.contract is CONTRACT and job.datasets is DATASETS
    assert job.consumes == CONTRACT.consumes and job.strict_gaps is True


def test_every_dataset_field_is_pinned():
    assert tuple(asdict(item) for item in DATASETS) == (
        {
            "output_kind": "build_environment",
            "step": "environment_analysis",
            "family": "build",
            "schema": "appsec-review/build-environment-analysis/1",
            "sensitivity": "sensitive",
            "disposition": "artifact_only",
            "description": "Redacted bounded static declarations and explicit environment coverage.",
            "indexes": (),
            "shard_prefixes": (),
            "shard_suffixes": (),
            "artifacts": (
                "data/jobs/job_build_environment_analysis/attempts/*/steps/"
                "environment_analysis/tasks/publish_handoff/build-environment.json",
            ),
            "query_route": "query_dataset_inventory (sanitized identity, hash, status and coverage only)",
            "reason": "advisory source declarations; never recipe-enforced target proof",
            "required": False,
            "store": "retrieval",
            "authority": "operational",
        },
    )


def _write_published_environment(
    root: Path,
    *,
    handoff_source: str = SOURCE,
    artifact_source: str = SOURCE,
    handoff_catalog_sha: str = CATALOG_SHA,
    artifact_catalog_sha: str = CATALOG_SHA,
    catalog_pointer_sha: str | None = CATALOG_SHA,
):
    actual_catalog_sha = _catalog(root)
    if handoff_catalog_sha == CATALOG_SHA:
        handoff_catalog_sha = actual_catalog_sha
    if artifact_catalog_sha == CATALOG_SHA:
        artifact_catalog_sha = actual_catalog_sha
    if catalog_pointer_sha == CATALOG_SHA:
        catalog_pointer_sha = actual_catalog_sha
    attempt = root / "data/jobs" / JOB_ID / "attempts/attempt_0001"
    payload = b"SDK_ROOT=tools/sdk\n"
    value = analyze_environment(
        {
            "source_fingerprint": artifact_source,
            "catalog_handoff_sha256": artifact_catalog_sha,
            "files": [
                {
                    "path": "setup.sh",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload),
                }
            ],
        },
        lambda item, bound: payload,
        BuildEnvironmentSettings(),
    )
    events = []
    context = SimpleNamespace(
        job=SimpleNamespace(
            run_root=root,
            events=SimpleNamespace(write=lambda event, **details: events.append((event, details))),
        ),
        unit_id=PUBLISH,
        unit_root=attempt / "steps/environment_analysis/tasks/publish_handoff",
        output=lambda unit_id: {"environment": value},
    )
    output = build_job().units[1].handler(context)
    validate_unit_output(output, unit_id=PUBLISH, strict_gaps=True)
    atomic_json(
        attempt / "claim.json",
        {
            "dataset_contract": dataset_contract(
                JOB_ID, ("environment_analysis",), DATASETS, job_contract=CONTRACT.document()
            ),
        },
    )
    handoff_path = write_fixture_handoff(
        root,
        attempt / "handoff.json",
        {
            "job_id": JOB_ID,
            "outputs": {PUBLISH: output},
            "schema_identity": SCHEMA,
            "source_fingerprint": handoff_source,
            "upstream_handoff_sha256": {"job_target_catalog": handoff_catalog_sha},
        },
    )
    handoff = decode_handoff(json.loads(handoff_path.read_bytes()), run_id=root.name, job_id=JOB_ID)
    assert handoff["outputs"][PUBLISH] == output
    digest = file_sha256(handoff_path)
    atomic_json(
        attempt.parent.parent / "latest.json",
        {
            "schema": "appsec-review/latest-handoff/1",
            "attempt_id": "attempt_0001",
            "handoff_path": handoff_path.relative_to(root).as_posix(),
            "handoff_sha256": digest,
        },
    )
    if catalog_pointer_sha is not None:
        atomic_json(
            root / "data/jobs/job_target_catalog/latest.json",
            {
                "schema": "appsec-review/latest-handoff/1",
                "attempt_id": "attempt_0001",
                "handoff_path": "data/jobs/job_target_catalog/attempts/attempt_0001/handoff.json",
                "handoff_sha256": catalog_pointer_sha,
            },
        )
    config = SimpleNamespace(jobs={JOB_ID: SimpleNamespace(settings={"enabled": True})})
    return root, config, digest, output, value, events


@pytest.fixture
def published_environment(tmp_path):
    return _write_published_environment(tmp_path / "synthetic-run")


def test_publication_matches_declared_glob_schema_and_bytes(published_environment):
    root, _, _, output, value, events = published_environment
    identity = output["artifact"]
    path = root / identity["path"]
    assert fnmatch(identity["path"], DATASETS[0].artifacts[0])
    assert identity["path"].endswith("/steps/environment_analysis/tasks/publish_handoff/build-environment.json")
    assert output == {"schema": SCHEMA, "artifact": identity, "gaps": [], "terminal_status": "SUCCEEDED"}
    assert identity["size_bytes"] == len(path.read_bytes())
    assert identity["sha256"] == file_sha256(path)
    assert json.loads(path.read_bytes()) == value
    assert value["schema"] == DATASETS[0].schema
    schema_path = ROOT / "docs/schemas/build-environment-analysis.schema.json"
    Draft202012Validator(json.loads(schema_path.read_bytes())).validate(value)
    assert value["declarations"][0]["value"] == "tools/sdk"
    assert events == [
        (
            "BUILD_ENVIRONMENT_PUBLISHED",
            {
                "unit_id": PUBLISH,
                "availability": "AVAILABLE",
                "coverage": "complete",
                "gap_count": 0,
                "artifact": identity,
            },
        )
    ]


def _read_context(root: Path, upstream: dict[str, str], optional_prior: dict[str, str] | None = None):
    return SimpleNamespace(
        run_root=root,
        config=SimpleNamespace(job_id="job_target_analysis_plan"),
        upstream_handoffs=upstream,
        optional_prior_handoffs=optional_prior or {},
        contract=PLANNER_CONTRACT,
    )


def test_optional_prior_and_expected_current_record_handoff_and_output_reads(published_environment):
    root, config, digest, output, value, _ = published_environment
    opt_contract = environment_contract(config, {"environment_mode": "OPTIONAL_PRIOR"}, {JOB_ID: digest})
    assert optional_prior_environment_handoffs(opt_contract) == {JOB_ID: digest}
    with input_read_scope(_read_context(root, {}, optional_prior_environment_handoffs(opt_contract))) as reads:
        loaded = load_environment(root, SOURCE, opt_contract)
        assert loaded["artifact"] == output["artifact"] and loaded["evidence"] == value
        assert loaded["availability"] == "AVAILABLE"
        observed = {(item["output_kind"], item["handoff_sha256"]) for item in reads.document()["reads"]}
        assert observed == {("handoff", digest), ("build_environment", digest)}

    cur_contract = environment_contract(config, {"workflow": "wave1_review"}, {JOB_ID: digest})
    assert optional_prior_environment_handoffs(cur_contract) == {}
    catalog_sha = value["catalog_handoff_sha256"]
    with input_read_scope(_read_context(root, {JOB_ID: digest, "job_target_catalog": catalog_sha})) as cur_reads:
        cur_loaded = load_environment(root, SOURCE, cur_contract)
        assert cur_loaded["availability"] == "AVAILABLE" and cur_loaded["expected_producer"] == JOB_ID
        cur_observed = {(item["output_kind"], item["handoff_sha256"]) for item in cur_reads.document()["reads"]}
        assert cur_observed == {("handoff", digest), ("build_environment", digest), ("handoff", catalog_sha)}


@pytest.mark.parametrize("stale", [False, True], ids=["current-source", "stale-source"])
def test_optional_prior_is_readable_under_the_inputs_selected_for_its_claim(published_environment, stale):
    root, config, digest, output, value, _ = published_environment
    source = "later-synthetic-source" if stale else SOURCE
    orchestration = {"environment_mode": "OPTIONAL_PRIOR", "environment_reference": digest}
    contract, upstream = planning_environment_inputs(config, root, source, orchestration, {JOB_ID: digest})
    assert contract["reference"] == digest and contract["mode"] == "OPTIONAL_PRIOR"
    assert JOB_ID not in upstream
    prior_pins = optional_prior_environment_handoffs(contract)
    with input_read_scope(_read_context(root, upstream, prior_pins)):
        loaded = load_environment(root, source, contract)
    assert loaded["reference"] == digest
    assert loaded["availability"] == ("UNAVAILABLE" if stale else "AVAILABLE")
    assert loaded["artifact"] == (None if stale else output["artifact"])
    assert loaded["evidence"] == (None if stale else value)


def test_planning_environment_inputs_preserves_non_optional_upstream(tmp_path):
    config = SimpleNamespace(jobs={JOB_ID: SimpleNamespace(settings={"enabled": True})})
    contract, required = planning_environment_inputs(
        config, tmp_path, SOURCE, {"workflow": "wave1_review"}, {JOB_ID: "a" * 64}
    )
    assert contract["mode"] == "EXPECTED_CURRENT"
    assert required == {JOB_ID: "a" * 64}


@pytest.mark.parametrize(
    "enabled,orchestration,upstream,match",
    [
        (True, {"environment_mode": "INVALID"}, {}, "unsupported explicit environment mode"),
        (True, {"environment_reference": "a" * 64}, {}, "requires optional prior mode"),
        (True, {"environment_mode": "OPTIONAL_PRIOR", "environment_reference": "not-a-hash"}, {}, "exact hash"),
        (True, {"environment_mode": "OPTIONAL_PRIOR", "environment_reference": 123}, {}, "exact hash"),
        (False, {"environment_mode": "OPTIONAL_PRIOR"}, {JOB_ID: "a" * 64}, "disabled environment producer"),
        (True, {"workflow": "wave1_review", "environment_mode": "OPTIONAL_PRIOR"}, {JOB_ID: "a" * 64}, "scheduled environment"),
        (True, {"workflow": "project_build_review", "environment_mode": "OPTIONAL_PRIOR"}, {JOB_ID: "a" * 64}, "scheduled environment"),
        (True, {"environment_mode": "OPTIONAL_PRIOR", "environment_reference": "a" * 64}, {JOB_ID: "b" * 64}, "conflicting optional"),
        (True, {"environment_mode": "OPTIONAL_PRIOR"}, {}, "explicitly supplied exact reference"),
        (True, {"environment_mode": "OPTIONAL_PRIOR"}, {JOB_ID: "bad"}, "explicitly supplied exact reference"),
    ],
    ids=[
        "bad-mode",
        "ref-without-opt",
        "bad-ref-str",
        "bad-ref-int",
        "disabled-opt",
        "wave1-opt",
        "proj-build-opt",
        "conflicting-ref",
        "missing-opt-ref",
        "invalid-upstream-ref",
    ],
)
def test_environment_contract_rejects_invalid_and_contradictory_modes(enabled, orchestration, upstream, match):
    config = SimpleNamespace(jobs={JOB_ID: SimpleNamespace(settings={"enabled": enabled})})
    with pytest.raises(ValueError, match=match):
        environment_contract(config, orchestration, upstream)


def test_environment_contract_and_load_environment_absent_and_disabled_modes(tmp_path):
    config = load_config(ROOT / "appsec-review.toml")
    not_run = environment_contract(config, {}, {})
    assert not_run["mode"] == "NOT_RUN" and not_run["expected_producer"] is None
    assert load_environment(tmp_path, "s", not_run)["availability"] == "ABSENT"

    unconfigured = SimpleNamespace(jobs={})
    assert environment_contract(unconfigured, {}, {})["mode"] == "NOT_RUN"

    jobs = dict(config.jobs)
    jobs[JOB_ID] = replace(jobs[JOB_ID], settings={**jobs[JOB_ID].settings, "enabled": False})
    disabled_cfg = replace(config, jobs=jobs)
    disabled = environment_contract(disabled_cfg, {}, {JOB_ID: "a" * 64})
    assert disabled["mode"] == "DISABLED" and disabled["expected_producer"] is None
    assert load_environment(tmp_path, "s", disabled)["availability"] == "DISABLED"


def test_load_environment_validates_contract_pointers_lineage_and_source(tmp_path):
    valid = {
        "schema": "appsec-review/build-environment-availability/1",
        "workflow": "wave1_review",
        "expected_producer": JOB_ID,
        "mode": "EXPECTED_CURRENT",
        "reference": "a" * 64,
        "reason": "workflow requires the current accepted producer",
    }
    for bad in (
        {"schema": "bad"},
        {**valid, "schema": "other/1"},
        {**valid, "mode": "OTHER"},
        {**valid, "workflow": ""},
        {**valid, "reason": ""},
        {**valid, "expected_producer": None},
        {**valid, "mode": "NOT_RUN", "expected_producer": JOB_ID, "workflow": "standalone"},
        {**valid, "mode": "NOT_RUN", "expected_producer": None, "workflow": "wave1_review"},
    ):
        with pytest.raises(ValueError, match="invalid authoritative environment launch contract"):
            load_environment(tmp_path, SOURCE, bad)

    missing_root = tmp_path / "missing-run"
    missing_root.mkdir()
    with pytest.raises(ValueError, match="handoff is required"):
        load_environment(missing_root, SOURCE, valid)

    oversize_root = tmp_path / "oversize-pointer"
    pointer_file = oversize_root / "data/jobs" / JOB_ID / "latest.json"
    pointer_file.parent.mkdir(parents=True)
    pointer_file.write_bytes(b"x" * 65537)
    with pytest.raises(ValueError, match="pointer is not JSON"):
        load_environment(oversize_root, SOURCE, valid)

    root, _, digest, _, _, _ = _write_published_environment(tmp_path / "mismatch-ref")
    with pytest.raises(ValueError, match="environment reference is not the accepted producer"):
        load_environment(root, SOURCE, {**valid, "reference": "f" * 64})

    with pytest.raises(ValueError, match="expected current environment producer has the wrong source"):
        load_environment(root, "wrong-source", {**valid, "reference": digest})

    cat_pointer = root / "data/jobs/job_target_catalog/latest.json"
    _catalog(root, "attempt_0002", "new-source")
    with pytest.raises(ValueError, match="does not consume the current catalog"):
        load_environment(root, SOURCE, {**valid, "reference": digest})

    cat_pointer.write_bytes(b"x" * 65537)
    with pytest.raises(ValueError, match="pointer is not JSON"):
        load_environment(root, SOURCE, {**valid, "reference": digest})

    src_diff_root, _, src_diff_digest, _, _, _ = _write_published_environment(
        tmp_path / "handoff-src-diff", handoff_source="other-handoff-source", artifact_source=SOURCE
    )
    with pytest.raises(ValueError, match="environment handoff and artifact source differ"):
        load_environment(src_diff_root, SOURCE, {**valid, "reference": src_diff_digest})

    cat_diff_root, _, cat_diff_digest, _, _, _ = _write_published_environment(
        tmp_path / "handoff-cat-diff", handoff_catalog_sha="e" * 64, artifact_catalog_sha=CATALOG_SHA
    )
    with pytest.raises(ValueError, match="environment catalog reference differs"):
        load_environment(cat_diff_root, SOURCE, {**valid, "reference": cat_diff_digest})


def test_current_environment_uses_admitted_catalog_when_latest_moves(published_environment):
    root, config, digest, _, value, _ = published_environment
    pinned_catalog = value["catalog_handoff_sha256"]
    _catalog(root, "attempt_0002", "different-source")
    contract = environment_contract(config, {"workflow": "wave1_review"}, {JOB_ID: digest})
    with input_read_scope(_read_context(root, {
        JOB_ID: digest, "job_target_catalog": pinned_catalog,
    })) as reads:
        assert load_environment(root, SOURCE, contract)["availability"] == "AVAILABLE"
        assert any(row["producer"] == "job_target_catalog" and row["handoff_sha256"] == pinned_catalog
                   for row in reads.document()["reads"])
    with pytest.raises(ValueError, match="not supplied"), input_read_scope(_read_context(root, {JOB_ID: digest})):
        load_environment(root, SOURCE, contract)


def test_optional_environment_pin_survives_latest_pointer_change(published_environment):
    root, config, digest, _, _, _ = published_environment
    contract = environment_contract(config, {"environment_mode": "OPTIONAL_PRIOR"}, {JOB_ID: digest})
    atomic_json(root / "data/jobs" / JOB_ID / "latest.json", {"handoff_sha256": "d" * 64})
    with input_read_scope(_read_context(root, {}, {JOB_ID: digest})):
        assert load_environment(root, SOURCE, contract)["availability"] == "AVAILABLE"
