"""Real publication, ownership and admission for the Wave 1a declaration repairs."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.indexing.inventory import InventoryInputs, build_inventory, compile_glob
from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.job_artifact_indexing.datasets import DATASETS as ARTIFACT_DATASETS
from appsec_review.jobs.job_debug_symbol_indexing.job import build_job as debug_job, load_accepted_debug_symbols
from appsec_review.jobs.job_review_data_indexing.datasets import CONTRACT as INDEXING_CONTRACT
from appsec_review.jobs.job_target_acquisition.job import build_job as acquisition_job
from appsec_review.runtime import Job, JobRunner, Unit, UnitExecutor
from appsec_review.runtime.contracts import (
    Availability, CoveragePolicy, EvidenceAuthority, InputChannel, JobContract, MissingPolicy, TargetAccess,
)
from appsec_review.runtime.datasets import METADATA_ROUTE, dataset_contract, read_dataset_contract
from appsec_review.runtime.inputs import input_read_scope, observe_output, read_input_observations
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.storage import atomic_json, file_sha256
from tests.capture_fakes import build_capture_toml
from tests.release_support import write_release
from tests.unit.job_debug_symbol_indexing.support import ELF, artifact, catalog_shard, extractor, manifest


SNAPSHOT = "target-sha256:" + "7" * 64
ACQUISITION = "job_target_acquisition"
DEBUG = "job_debug_symbol_indexing"
JOB_SCHEMA = "appsec-review/target-acquisition-job/2"
DECISION_SCHEMA = "appsec-review/debug-symbol-decision/2"
MANIFEST_BYTES = b'{ "schema": "appsec-review/target-system-acquisition/1", "system_id": "sys" }\n'
CONSUMERS = (
    "job_codeql_analysis", "job_document_issue_analysis", "job_inference_security_review",
    "job_review_data_indexing", "job_review_package_assembly", "job_security_tagging",
)
ACQUISITION_OUTPUTS = {
    "target_acquisition": ("publication.publish_handoff", "target-acquisition-handoff.json", JOB_SCHEMA),
    "target_acquisition_plan": ("selection.resolve_system", "target-acquisition-plan.json", JOB_SCHEMA),
    "target_acquisition_result": ("acquisition.acquire_components", "target-acquisition-result.json", JOB_SCHEMA),
    "target_acquisition_system_manifest": (
        "acquisition.acquire_components", "system-manifest.json", "appsec-review/target-system-acquisition/1"),
}
SYSTEM_CONFIG = """
[target_acquisition]
targets_dir = "checkouts"
records_dir = "acquisition-records"
[[target_acquisition.systems]]
id = "sys"
[[target_acquisition.systems.components]]
id = "service"
url = "https://example.invalid/service.git"
commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"""


def runner_for(root, *jobs):
    root.mkdir(parents=True, exist_ok=True)
    text = ('[runtime]\nruns_dir="runs"\ndata_dir="data"\n'
            '[review_policy.releases]\nplatform="fixture/1"\nvalidation="fixture/1"\n'
            + build_capture_toml() + SYSTEM_CONFIG)
    for job in jobs:
        text += f'\n[jobs.{job.job_id}]\nname="{job.name}"\nworkers=1\n'
        if job.job_id == "job_review_data_indexing":
            text += f'[jobs.{job.job_id}.settings]\nfeed_max_age_days=14\n'
        for unit in job.units:
            step, task = unit.unit_id.split(".")
            text += f'[jobs.{job.job_id}.steps.{step}.tasks.{task}]\nworkers=1\n'
    path = root / "appsec-review.toml"
    path.write_text(text, encoding="utf-8")
    write_release(root, [job.job_id for job in jobs])
    target = root / "fixture-source"
    target.mkdir()
    return JobRunner(load_config(path)), target


def run(runner, job, target, run_id=None, **kwargs):
    independent = job.contract.target_access is TargetAccess.NONE
    return runner.run(job, run_id=run_id, target_root=None if independent else target,
                      source_fingerprint="none" if independent else SNAPSHOT, **kwargs)


def requirements(consumer, producer, kind):
    return tuple(item for item in builtin_registry().build(consumer).contract.inputs
                 if item.producer == producer and item.output_kind in {"handoff", kind})


def reader(inputs, *, read=False):
    def consume(unit):
        if read:
            value = accepted_handoff(unit.job.run_root, inputs[0].producer)
            assert value is not None
        return {"terminal_status": "SUCCEEDED"}

    units = (Unit("work.read", consume),)
    return Job("job_fixture_reader", "fixture_reader", UnitExecutor(units).execute,
               units=units, contract=JobContract(inputs=inputs), strict_gaps=True)


def acquisition_fixture(tmp_path, monkeypatch, state="COMPLETE", *, consumer=None, tamper=False, extra_jobs=()):
    from appsec_review.target_acquisition import acquire

    job = acquisition_job(environ={} if state == "NOT_REQUESTED" else {"APPSEC_REVIEW_SYSTEM": "sys"})
    runner, target = runner_for(tmp_path, job, *extra_jobs, *((consumer,) if consumer else ()))
    records = tmp_path / "acquisition-records" / "sys"
    records.mkdir(parents=True)
    (records / "manifest.json").write_bytes(MANIFEST_BYTES)
    calls = []

    def acquire_system(**kwargs):
        calls.append(kwargs)
        return {
            "status": state, "acquisition_id": "sys@fixture", "target_path": "checkouts/sys",
            "manifest": "acquisition-records/sys/manifest.json",
            "manifest_sha256": "0" * 64 if tamper else hashlib.sha256(MANIFEST_BYTES).hexdigest(),
            "tree_sha256": "2" * 64, "components": {"service": {"status": state, "action": "acquired"}},
            "gaps": [{"path": "service", "reason": "component_not_acquired"}] if state == "PARTIAL" else [],
        }

    monkeypatch.setattr(acquire, "acquire_system", acquire_system)
    monkeypatch.setattr(acquire, "system_paths", lambda *_: (tmp_path / "checkouts" / "sys", records))
    return runner, job, target, calls


def artifact_producer():
    def index(unit):
        root = unit.job.run_root
        binary = artifact(root, "bin/program", ELF, snapshot=SNAPSHOT)
        index = catalog_shard(root, [binary], snapshot=SNAPSHOT)
        index = replace(index, producer={"job": "job_artifact_indexing", "unit": unit.unit_id})
        upstream = manifest(root, [index], snapshot=SNAPSHOT, run_id=root.name)
        return {"index_manifest": upstream, "target_artifacts": [binary["reference"]]}

    def publish(unit):
        root = unit.job.run_root
        indexed = unit.output("index.catalog")
        path = unit.job.attempt_root / "artifacts/artifact-indexing/accepted-index.json"
        atomic_json(path, {
            "schema": "appsec-review/artifact-indexing/1", "source_fingerprint": SNAPSHOT,
            **indexed, "gaps": [],
        })
        return {"artifact": {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path)},
                "index_manifest": indexed["index_manifest"]}

    units = (Unit("index.catalog", index),
             Unit("acceptance.publish_handoff", publish, ("index.catalog",)))
    return Job("job_artifact_indexing", "artifact_indexing", UnitExecutor(units).execute,
               units=units, datasets=ARTIFACT_DATASETS, contract=JobContract())


def debug_fixture(tmp_path, *, consumer=None, old=False):
    upstream = artifact_producer()
    job = debug_job(extractor=extractor())
    if old:
        job = replace(job, datasets=tuple(
            replace(item, schema="appsec-review/debug-symbol-decision/1")
            if item.output_kind == "target_decision" else item for item in job.datasets))
    runner, target = runner_for(tmp_path, upstream, job, *((consumer,) if consumer else ()))
    first = run(runner, upstream, target)
    output = run(runner, job, target, first["status"]["run_id"],
                 upstream_handoffs={upstream.job_id: first["handoff_sha256"]})
    return runner, job, target, output


def artifact_document(root, reference):
    path = root / reference["path"]
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == reference["sha256"]
    if "size_bytes" in reference:
        assert len(data) == reference["size_bytes"]
    return json.loads(data)


def owners(job, relative):
    return [item for item in job.datasets
            if any(compile_glob(pattern).fullmatch(relative) for pattern in item.artifacts)]


@pytest.mark.parametrize("state", ("COMPLETE", "NOT_REQUESTED", "PARTIAL"))
def test_real_acquisition_files_have_exact_schema_step_and_unique_owner(tmp_path, monkeypatch, state):
    runner, job, target, calls = acquisition_fixture(tmp_path, monkeypatch, state)
    output = run(runner, job, target)
    root = runner.runs.resolve(output["status"]["run_id"])
    declared = {item.output_kind: item for item in job.datasets}
    assert set(declared) == set(ACQUISITION_OUTPUTS)
    for kind, (unit_id, name, schema) in ACQUISITION_OUTPUTS.items():
        declaration = declared[kind]
        step, task = unit_id.split(".")
        path = Path(output["attempt_root"]) / "steps" / step / "tasks" / task / name
        relative = path.relative_to(root).as_posix()
        assert owners(job, relative) == [declaration]
        assert declaration.step == step and declaration.schema == schema
        assert declaration.artifacts == (f"data/jobs/{ACQUISITION}/attempts/*/steps/{step}/tasks/{task}/{name}",)
        assert (declaration.disposition, declaration.family, declaration.sensitivity, declaration.store,
                declaration.required, declaration.authority, declaration.query_route) == (
                    "artifact_only", "configuration", "internal", "retrieval", False,
                    EvidenceAuthority.OPERATIONAL, METADATA_ROUTE)
        assert declaration.reason and not declaration.indexes
        if kind == "target_acquisition_system_manifest" and state == "NOT_REQUESTED":
            assert not path.exists()
            continue
        reference = next(item for item in output["handoff"]["artifacts"] if item["path"] == relative)
        assert artifact_document(root, reference)["schema"] == schema
        if kind == "target_acquisition_system_manifest":
            assert path.read_bytes() == MANIFEST_BYTES
    assert bool(calls) is (state != "NOT_REQUESTED")
    assert not (tmp_path / "checkouts").exists()
    acquired = output["result"]["outputs"]["acquisition.acquire_components"]
    published = output["result"]["outputs"]["publication.publish_handoff"]
    assert artifact_document(root, published["artifact"])["artifact"] == acquired["artifact"]
    assert published["result"] == acquired["artifact"]
    assert acquired["terminal_status"] == {
        "COMPLETE": "SUCCEEDED", "NOT_REQUESTED": "NOT_APPLICABLE", "PARTIAL": "COMPLETED_WITH_GAPS",
    }[state]
    assert published["terminal_status"] == "SUCCEEDED" and published["gaps"] == []
    if state == "PARTIAL":
        [gap] = acquired["gaps"]
        assert (gap["code"], gap["scope_id"], gap["retryable"]) == ("producer_reported_gap", "service", True)
        assert output["handoff"]["coverage"]["disposition"] == "partial"
        assert artifact_document(root, published["artifact"])["gaps"] == [gap]
    statuses = {key: value.get("terminal_status", "SUCCEEDED")
                for key, value in output["result"]["outputs"].items()}
    inventory = build_inventory(InventoryInputs(
        root, root.name, "none", {job.job_id: tuple(runner.config.job(job.job_id).steps)},
        {job.job_id: job.datasets}, {}, {job.job_id: accepted_handoff(root, job.job_id)},
        {job.job_id: statuses}, ()))
    assert inventory["audit"]["status"] == "PASSED", inventory["audit"]["violations"]
    rows = {row["output_kind"]: row for row in inventory["rows"] if row["job_id"] == job.job_id}
    assert set(ACQUISITION_OUTPUTS) <= rows.keys()
    if state == "NOT_REQUESTED":
        missing = rows["target_acquisition_system_manifest"]
        assert missing["disposition"] == "unavailable"
        assert missing["coverage"]["status_class"] == "skipped"


@pytest.mark.parametrize("failure", ("manifest-tamper", "unavailable"))
def test_failed_acquisition_retains_result_without_accepted_publication(tmp_path, monkeypatch, failure):
    runner, job, target, _ = acquisition_fixture(
        tmp_path, monkeypatch, "FAILED" if failure == "unavailable" else "COMPLETE",
        tamper=failure == "manifest-tamper")
    with pytest.raises(RuntimeError, match="system manifest changed|target acquisition of system"):
        run(runner, job, target)
    attempts = sorted((tmp_path / "runs").glob(f"*/data/jobs/{ACQUISITION}/attempts/*"))
    assert len(attempts) == 1
    attempt = attempts[0]
    document = json.loads((attempt / "steps/acquisition/tasks/acquire_components/target-acquisition-result.json").read_bytes())
    assert document["schema"] == JOB_SCHEMA
    assert not (attempt / "steps/publication/tasks/publish_handoff/target-acquisition-handoff.json").exists()
    assert not (attempt.parent.parent / "latest.json").exists()
    assert (attempt / "rejected-handoff.json").is_file()
    if failure == "manifest-tamper":
        assert not (attempt / "steps/acquisition/tasks/acquire_components/system-manifest.json").exists()


def test_debug_real_publication_and_loader_agree_on_decision_contract(tmp_path):
    runner, job, _target, output = debug_fixture(tmp_path)
    root = runner.runs.resolve(output["status"]["run_id"])
    reference = output["result"]["outputs"]["decide.target"]["artifact"]
    [owner] = owners(job, reference["path"])
    decision = artifact_document(root, reference)
    assert (owner.output_kind, owner.step, owner.schema) == ("target_decision", "decide", DECISION_SCHEMA)
    assert decision["schema"] == owner.schema
    assert len(decision["artifacts"]) == 1
    assert decision["artifact_handoff_sha256"] == output["handoff"]["upstream_handoff_sha256"]["job_artifact_indexing"]
    assert load_accepted_debug_symbols(root)["decision"] == reference
    claim = json.loads((Path(output["attempt_root"]) / "claim.json").read_bytes())
    assert read_dataset_contract(claim["dataset_contract"], DEBUG)[1] == job.datasets
    assert file_sha256(Path(output["attempt_root"]) / "handoff.json") == output["handoff_sha256"]


@pytest.mark.parametrize("consumer_id", CONSUMERS)
def test_optional_unread_decision_still_has_exact_admitted_schema(tmp_path, consumer_id):
    inputs = requirements(consumer_id, DEBUG, "target_decision")
    assert len(inputs) == 2
    decision = next(item for item in inputs if item.output_kind == "target_decision")
    assert (decision.schema, decision.authority, decision.availability, decision.missing,
            decision.coverage, decision.channel) == (
                DECISION_SCHEMA, EvidenceAuthority.PRODUCER_EVIDENCE, Availability.OPTIONAL,
                MissingPolicy.GAP, CoveragePolicy.ALLOW_PARTIAL, InputChannel.HANDOFF)
    consumer = reader(inputs)
    runner, _job, target, publication = debug_fixture(tmp_path, consumer=consumer)
    output = run(runner, consumer, target, publication["status"]["run_id"],
                 upstream_handoffs={DEBUG: publication["handoff_sha256"]})
    root = runner.runs.resolve(output["status"]["run_id"])
    claim = json.loads((Path(output["attempt_root"]) / "claim.json").read_bytes())
    assert all(row["supplied"] and row["available"] and not row["read"]
               for row in claim["input_admission"]["requirements"])
    assert read_input_observations(root, output["handoff"])["reads"] == []


@pytest.mark.parametrize("producer", (ACQUISITION, DEBUG), ids=("acquisition", "debug"))
@pytest.mark.parametrize("change", ("schema", "authority", "tamper"))
def test_incompatible_optional_unread_input_is_rejected_before_consumer(tmp_path, monkeypatch, producer, change):
    kind = "target_acquisition" if producer == ACQUISITION else "target_decision"
    inputs = requirements("job_review_data_indexing", producer, kind)
    consumer = reader(inputs)
    if producer == ACQUISITION:
        runner, job, target, _ = acquisition_fixture(tmp_path, monkeypatch, consumer=consumer)
        publication = run(runner, job, target)
        reference = publication["result"]["outputs"]["publication.publish_handoff"]["artifact"]
    else:
        runner, job, target, publication = debug_fixture(tmp_path, consumer=consumer)
        reference = publication["result"]["outputs"]["decide.target"]["artifact"]
    root = runner.runs.resolve(publication["status"]["run_id"])
    if change == "tamper":
        (root / reference["path"]).write_text("{}")
    else:
        replacement = {"schema": "appsec-review/target-acquisition-job/1" if producer == ACQUISITION
                       else "appsec-review/debug-symbol-decision/1"} if change == "schema" else {
                           "authority": EvidenceAuthority.REFERENCE}
        consumer = replace(consumer, contract=replace(consumer.contract, inputs=tuple(
            replace(item, **replacement) if item.output_kind == kind else item for item in inputs)))
    with pytest.raises(ValueError, match="contract mismatch|authority mismatch|changed|mismatch|integrity"):
        run(runner, consumer, target, root.name, upstream_handoffs={producer: publication["handoff_sha256"]})
    assert not list((root / "data/jobs/job_fixture_reader").glob("attempts/*/steps/work/tasks/read/result.json"))


@pytest.mark.parametrize("state", ("NOT_REQUESTED", "PARTIAL"))
def test_indexing_permission_and_reads_do_not_expand_to_split_payloads(tmp_path, monkeypatch, state):
    inputs = tuple(item for item in INDEXING_CONTRACT.inputs if item.producer == ACQUISITION)
    assert [(item.output_kind, item.schema) for item in inputs] == [
        ("handoff", "appsec-review/job-handoff/2"), ("target_acquisition", JOB_SCHEMA)]
    consumer = reader(inputs, read=True)
    runner, job, target, _ = acquisition_fixture(tmp_path, monkeypatch, state, consumer=consumer)
    publication = run(runner, job, target)
    output = run(runner, consumer, target, publication["status"]["run_id"],
                 upstream_handoffs={ACQUISITION: publication["handoff_sha256"]})
    root = runner.runs.resolve(output["status"]["run_id"])
    reads = read_input_observations(root, output["handoff"])["reads"]
    assert {row["output_kind"] for row in reads} == {"handoff"}
    assert all(row["authority"] == "operational" and row["cited"] is None for row in reads)
    if state == "PARTIAL":
        assert reads[0]["coverage"]["disposition"] == "partial"
    claim = json.loads((Path(output["attempt_root"]) / "claim.json").read_bytes())
    context = runner._context_from_claim(consumer, claim)
    reference = publication["result"]["outputs"]["selection.resolve_system"]["artifact"]
    with pytest.raises(ValueError, match="undeclared consumption"), input_read_scope(context):
        observe_output(root, ACQUISITION, "target_acquisition_plan", reference)


@pytest.mark.parametrize("state", ("NOT_REQUESTED", "PARTIAL"))
def test_real_indexing_loader_observes_acquisition_envelope_not_split_payloads(tmp_path, monkeypatch, state):
    from appsec_review.jobs.job_review_data_indexing.job import build_job as indexing_job

    indexing = indexing_job()
    artifacts = artifact_producer()
    runner, acquisition, target, _ = acquisition_fixture(
        tmp_path, monkeypatch, state, consumer=indexing, extra_jobs=(artifacts,))
    published_artifacts = run(runner, artifacts, target)
    run_id = published_artifacts["status"]["run_id"]
    published_acquisition = run(runner, acquisition, target, run_id)
    claim = runner.begin_attempt(
        indexing, run_id=run_id, source_fingerprint=SNAPSHOT, target_root=target,
        upstream_handoffs={artifacts.job_id: published_artifacts["handoff_sha256"],
                           acquisition.job_id: published_acquisition["handoff_sha256"]})
    result = runner.execute_or_reuse_unit(indexing, claim, "load.accepted_inputs")
    root = runner.runs.resolve(run_id)
    document = artifact_document(root, result["artifact"])
    assert set(document["declarations"][ACQUISITION]) == set(ACQUISITION_OUTPUTS)
    assert document["handoffs"][ACQUISITION]["sha256"] == published_acquisition["handoff_sha256"]
    attempt = root / claim["attempt_path"]
    status = json.loads((attempt / "steps/load/tasks/accepted_inputs/status.json").read_bytes())
    reads = [row for row in status["input_consumption"]["reads"] if row["producer"] == ACQUISITION]
    assert len(reads) == 1 and reads[0]["output_kind"] == "handoff"
    assert reads[0]["authority"] == "operational" and reads[0]["cited"] is None
    assert not (attempt / "handoff.json").exists(), "one unit is not accepted indexing publication"


def test_intake_external_records_keep_their_own_schema_and_channel():
    contract = builtin_registry().build("job_review_intake").contract
    inputs = [item for item in contract.inputs if item.producer == ACQUISITION]
    assert [(item.output_kind, item.schema, item.channel, item.authority) for item in inputs] == [
        ("target_acquisition", "appsec-review/target-acquisition/1", InputChannel.EXTERNAL,
         EvidenceAuthority.OPERATIONAL),
        ("system_acquisition", "appsec-review/target-system-acquisition/1", InputChannel.EXTERNAL,
         EvidenceAuthority.OPERATIONAL),
    ]


def test_old_debug_output_contract_cannot_be_reused_or_silently_rewritten(tmp_path):
    runner, old, target, output = debug_fixture(tmp_path, old=True)
    root = runner.runs.resolve(output["status"]["run_id"])
    before = {item["path"]: (root / item["path"]).read_bytes() for item in output["handoff"]["artifacts"]}
    current = debug_job(extractor=extractor())
    planner = ResumePlanner(runner.config, root, (current,), SNAPSHOT, target_root=target)
    reasons, _ = planner.accepted(current, output["handoff"]["upstream_handoff_sha256"])
    assert "dataset contract identity changed" in reasons
    assert old.datasets != current.datasets
    assert all((root / path).read_bytes() == data for path, data in before.items())
    assert load_accepted_debug_symbols(root)["decision"]["path"].endswith("decision.json")


def test_consumer_schema_rebinding_invalidates_reuse(tmp_path):
    current_inputs = requirements("job_review_data_indexing", DEBUG, "target_decision")
    old_inputs = tuple(replace(item, schema="appsec-review/debug-symbol-decision/1")
                       if item.output_kind == "target_decision" else item for item in current_inputs)
    old_consumer = reader(old_inputs)
    runner, _job, target, publication = debug_fixture(tmp_path, consumer=old_consumer, old=True)
    supplied = {DEBUG: publication["handoff_sha256"]}
    output = run(runner, old_consumer, target, publication["status"]["run_id"], upstream_handoffs=supplied)
    root = runner.runs.resolve(output["status"]["run_id"])
    path = Path(output["attempt_root"]) / "handoff.json"
    before = path.read_bytes()
    current = reader(current_inputs)
    reasons, _ = ResumePlanner(runner.config, root, (current,), SNAPSHOT, target_root=target).accepted(current, supplied)
    assert "dataset contract identity changed" in reasons
    assert path.read_bytes() == before


def test_acquisition_contract_split_changes_identity_without_enabling_reuse(tmp_path, monkeypatch):
    runner, job, target, _ = acquisition_fixture(tmp_path, monkeypatch, "NOT_REQUESTED")
    publication = run(runner, job, target)
    root = runner.runs.resolve(publication["status"]["run_id"])
    declaration = next(item for item in job.datasets if item.output_kind == "target_acquisition")
    old = (replace(declaration, schema="appsec-review/target-acquisition-job/1",
                   artifacts=tuple(f"data/jobs/{ACQUISITION}/attempts/*/steps/{unit.split('.')[0]}/tasks/"
                                   f"{unit.split('.')[1]}/{name}"
                                   for kind in ("target_acquisition_plan", "target_acquisition_result",
                                                "target_acquisition_system_manifest", "target_acquisition")
                                   for unit, name, _ in (ACQUISITION_OUTPUTS[kind],))),)
    current = dataset_contract(job.job_id, runner.config.job(job.job_id).steps, job.datasets,
                               job_contract=job.contract.document())
    historical = dataset_contract(job.job_id, runner.config.job(job.job_id).steps, old,
                                  job_contract=job.contract.document())
    assert historical["sha256"] != current["sha256"]
    assert job.always_execute and not job.propagate_handoff and job.strict_gaps
    assert job.contract.target_access is TargetAccess.NONE and job.contract.inputs == ()
    assert ResumePlanner(runner.config, root, (job,), "none").accepted(job, {})[0] == (
        "job requires a fresh execution for every graph dispatch",)
