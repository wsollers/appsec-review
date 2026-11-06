"""Runner publication and inventory contracts, without model or container execution."""

from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.indexing import input_matrix
from appsec_review.indexing.inventory import FileClaims, InventoryInputs, build_inventory, runtime_claims
from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.job_build_iteration import build_job as build_iteration_job
from appsec_review.jobs.job_review_data_indexing.job import build_job, registry_providers
from appsec_review.retrieval.index import write_manifest
from appsec_review.runtime import Job, JobRunner, Unit, UnitContext
from appsec_review.runtime.datasets import artifact_only, read_dataset_contract
from appsec_review.runtime.repair import admit_repair, plan_repair
from appsec_review.storage import atomic_json, file_sha256
from tests.release_support import write_release
from tests.test_job_runtime import write_config


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = "target-sha256:" + "7" * 64


def _fixture(tmp_path, mode, *, internal=False):
    path = write_config(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    with path.open("a", encoding="utf-8") as stream:
        stream.write(
            f'\n[review_policy]\nmode = "{mode}"\nproject_id = "fixture"\n'
            'approved_first_party_projects = ["fixture"]\ncustody = "application_private_v1"\n'
            f'target_root = {json.dumps(str(target))}\n')
        if internal:
            stream.write('\n[jobs.job_build_iteration]\nname = "build_iteration"\nworkers = 1\n'
                         '[jobs.job_build_iteration.steps.execute.tasks.node]\nworkers = 1\n')
    write_release(tmp_path, ("job_fixture", "job_build_iteration") if internal else ("job_fixture",))
    declaration = artifact_only(
        "fixture_output", "work", "inventory", "application/json", "Inert fixture output.",
        artifacts=("data/jobs/job_fixture/attempts/*/steps/work/tasks/publish/output.json",),
        reason="fixture metadata")

    def publish(unit):
        path = unit.unit_root / "output.json"
        atomic_json(path, {"value": 7})
        return {"artifact": {"path": path.relative_to(unit.job.run_root).as_posix(),
                             "sha256": file_sha256(path)}}

    units = (Unit("work.only", lambda _: {"value": 7}),
             Unit("work.publish", publish, ("work.only",)))
    return JobRunner(load_config(path)), Job(
        "job_fixture", "fixture", publish, units=units, datasets=(declaration,)), target


def _inventory(root, job, *, managed=False):
    return build_inventory(InventoryInputs(
        root, root.name, SNAPSHOT, {job.job_id: ("work",)}, {job.job_id: job.datasets}, {},
        {job.job_id: accepted_handoff(root, job.job_id)}, {}, (), managed_publications=managed))


@pytest.mark.parametrize("mode", ("strict", "first_party_managed"))
def test_real_publication_failure_and_repair_are_owned(tmp_path, mode):
    runner, job, target = _fixture(tmp_path, mode)
    first = runner.run(job, target_root=target, source_fingerprint=SNAPSHOT)
    root = runner.runs.resolve(first["status"]["run_id"])
    first_attempt = Path(first["attempt_root"])
    accepted_bytes = (first_attempt / "handoff.json").read_bytes()

    def fail(_):
        raise RuntimeError("inert fixture failure")

    broken = replace(job, units=(job.units[0], replace(job.units[1], handler=fail)))
    with pytest.raises(RuntimeError, match="inert fixture failure"):
        runner.run(broken, run_id=root.name, target_root=target, source_fingerprint=SNAPSHOT)
    failed = first_attempt.parent / "attempt_0002"
    assert (first_attempt / "published.json").is_file()
    assert (failed / "steps/work/tasks/only/checkpoint.json").is_file()
    assert (failed / "rejected-handoff.json").is_file()
    assert not (failed / "published.json").exists()
    assert json.loads((failed / "status.json").read_bytes())["status"] == "FAILED"

    report = _inventory(root, job, managed=mode == "first_party_managed")
    assert report["audit"]["status"] == "PASSED", report["audit"]["violations"]
    assert report["run_tree"]["scratch_audited"] is (mode == "strict")
    assert report["run_tree"]["audit_scope"] == (
        "full_customer_evidence" if mode == "strict" else "accepted_publications")
    assert not any(row["producer"].get("attempt_id") == failed.name for row in report["rows"])
    if mode == "strict":
        owned = report["file_ownership"]
        assert {first_attempt.name, failed.name} <= {
            row["attempt_id"] for row in owned if row["job_id"] == job.job_id}
        recovery = next(row for row in report["rows"] if row["output_kind"] == "recovery_records")
        assert recovery["disposition"] == "protected" and recovery["index"] is None
        assert recovery["artifacts"]["file_count"] >= 4
    else:
        assert all(row.get("attempt_id") != failed.name for row in report["file_ownership"])

    plan = plan_repair(runner.config, root, (job,), SNAPSHOT, target_root=target)
    assert plan["admissible"], plan["refusals"]
    assert plan["unit_decisions"][job.job_id]["work.only"]["action"] == "REUSE"
    admit_repair(runner.config, root, (job,), plan, target_root=target)
    repaired = runner.run(job, run_id=root.name, target_root=target, source_fingerprint=SNAPSHOT)
    assert repaired["status"]["attempt_id"] == "attempt_0003"
    assert (first_attempt / "handoff.json").read_bytes() == accepted_bytes
    report = _inventory(root, job, managed=mode == "first_party_managed")
    assert report["audit"]["status"] == "PASSED", report["audit"]["violations"]

    stray = root / "data/recovery/undeclared.json"
    atomic_json(stray, {})
    report = _inventory(root, job, managed=mode == "first_party_managed")
    if mode == "strict":
        assert report["audit"]["status"] == "FAILED"
        assert {row["subject"] for row in report["audit"]["violations"]} == {
            stray.relative_to(root).as_posix()}
    else:
        assert report["audit"]["status"] == "PASSED"
        assert report["run_tree"]["scratch_audited"] is False


@pytest.mark.parametrize("internal_attempt", (False, True), ids=("absent", "rejected"))
def test_default_registry_contract_and_internal_eligibility(tmp_path, internal_attempt):
    config = load_config(ROOT / "appsec-review.toml")
    config = replace(config, runtime=replace(
        config.runtime, repository_root=tmp_path, runs_dir=tmp_path / "runs",
        data_dir=tmp_path / "data", metadata_dir=tmp_path / "runs/metadata"))
    runner = JobRunner(config)
    indexing = build_job()
    claim = runner.begin_attempt(indexing, source_fingerprint=SNAPSHOT)
    context = runner._context_from_claim(indexing, claim)
    if internal_attempt:
        with pytest.raises(RuntimeError, match="requires an immutable iteration_request"):
            runner.run(build_iteration_job(), run_id=context.run_id, source_fingerprint=SNAPSHOT)
    manifest = context.run_root / "data/indices/manifests/fixture.json"
    write_manifest(manifest, run_id=context.run_id, target_snapshot=SNAPSHOT,
                   target_root=tmp_path, indexes=[])
    context = replace(context, input_manifest_path=manifest, input_manifest_sha256=file_sha256(manifest))
    unit = next(unit for unit in indexing.units if unit.unit_id == "load.accepted_inputs")
    unit_root = context.attempt_root / "steps/load/tasks/accepted_inputs"
    unit_root.mkdir(parents=True)
    result = unit.handler(UnitContext(context, unit.unit_id, "load", "accepted_inputs", unit_root, {}))
    document = json.loads((context.run_root / result["artifact"]["path"]).read_bytes())

    assert "job_build_iteration" not in document["registry_jobs"]
    assert "job_build_iteration" not in document["job_steps"]
    assert "job_build_iteration" not in document["handoffs"]
    assert "job_third_party_data_sync" not in document["registry_jobs"]
    assert document["dispatch_classes"]["job_third_party_data_sync"] == "maintenance"
    assert document["dispatch_classes"]["job_build_iteration"] == "internal_transaction"
    assert len(document["registered_jobs"]) == 46
    assert document["file_job_steps"]["job_build_iteration"] == ["execute"]
    assert document["registry_configuration_mismatch"] == []
    assert "job_build_environment_analysis" in document["registry_jobs"]
    assert "job_model_connectivity" in document["registry_jobs"]
    assert "job_image_pin_verification" in document["registry_jobs"]
    registered, declarations, _ = registry_providers()
    assert all(declarations.get(job_id) for job_id in registered)
    internal = build_iteration_job()
    assert internal.always_execute and not internal.propagate_handoff
    assert internal.datasets == declarations[internal.job_id]
    assert internal.datasets
    audit_unit = next(unit for unit in indexing.units if unit.unit_id == "audit.inventory")
    audit_root = context.attempt_root / "steps/audit/tasks/inventory"
    audit_result = audit_unit.handler(UnitContext(
        context, audit_unit.unit_id, "audit", "inventory", audit_root, {"load.accepted_inputs": result}))
    report = json.loads((context.run_root / audit_result["artifact"]["path"]).read_bytes())
    assert report["audit"]["status"] == "PASSED", report["audit"]["violations"]
    assert not any(row["job_id"] == internal.job_id for row in report["rows"])
    owned = [row for row in report["file_ownership"] if row["job_id"] == internal.job_id]
    assert bool(owned) is internal_attempt
    assert all(row["accounting_only"] and not row["in_publication_stage"] for row in owned)
    atomic_json(context.run_root / "data/recovery/unknown.json", {})
    with pytest.raises(ValueError, match="dataset publication audit failed"):
        audit_unit.handler(UnitContext(
            context, audit_unit.unit_id, "audit", "inventory", audit_root,
            {"load.accepted_inputs": result}))
    rejected = json.loads((audit_root / "inventory.json").read_bytes())
    assert rejected["audit"]["status"] == "FAILED"
    assert {row["subject"] for row in rejected["audit"]["violations"]} == {"data/recovery/unknown.json"}


def test_default_matrix_names_build_environment():
    row = next(row for row in input_matrix.INPUT_SOURCES if row[0] == "build_environment_analysis")
    assert row[1] == ("job_build_environment_analysis",)
    assert row[2] == "artifact_only"
    assert row[3] == ()
    assert row[4] == ("coverage",)
    registered, _, _ = registry_providers()
    _, discrepancies = input_matrix.reconcile(registered, (), (), {}, "job_review_data_indexing")
    assert discrepancies == []


@pytest.mark.parametrize("mode", ("strict", "first_party_managed"))
@pytest.mark.parametrize("state", ("absent", "accepted", "rejected"))
def test_internal_attempts_are_accounting_only(tmp_path, mode, state):
    from appsec_review.jobs.build_iterations import retain
    from appsec_review.jobs.build_topology import VARIANT_FIELDS
    from appsec_review.jobs.build_workspace import BuildWorkspace, NodeBinding, ProductSpec

    runner, parent, target = _fixture(tmp_path, mode, internal=True)
    internal = build_iteration_job()
    initial = runner.run(parent, target_root=target, source_fingerprint=SNAPSHOT)
    root = runner.runs.resolve(initial["status"]["run_id"])
    completion = None

    def produce(unit):
        nonlocal completion
        from appsec_review.jobs.build_iterations import REQUEST_SCHEMA, read_reference
        from appsec_review.runtime.contracts import InputChannel
        from appsec_review.runtime.inputs import observe_external
        request = retain(root, "requests", {"schema": REQUEST_SCHEMA, "fixture": "inventory-only"})
        assert read_reference(root, request)["schema"] == REQUEST_SCHEMA
        observe_external(root, "build_controller", "iteration_request", REQUEST_SCHEMA, request,
                         channel=InputChannel.TRANSACTION)
        workspace = BuildWorkspace(unit.job.run_root)
        generation = workspace.materialize(target, SNAPSHOT)
        binding = NodeBinding("fixture", SNAPSHOT, "graph/1", "config/1", "recipe/1",
                              "sha256:" + "a" * 64, "toolchain/1", (), "execution/1", "outputs/1")
        with workspace.writer() as writer:
            writer.begin_attempt(binding, unit.job.attempt_id, generation)
            (workspace.paths.target / "fixture.h").write_bytes(b"int fixture(void);\n")
            product = writer.commit((ProductSpec(
                "target/fixture.h", "headers", "fixture-header", "include:fixture",
                dict.fromkeys(VARIANT_FIELDS)),))
        completion = retain(root, "completed", {"workspace_product": product.reference})
        if state == "rejected":
            raise RuntimeError("internal fixture failure")
        return {"completion": completion, "terminal_status": "SUCCEEDED"}

    # Substitute only the producer work; retain the real internal metadata, runner and inventory.
    minimal = replace(internal, units=(replace(internal.units[0], handler=produce),))
    if state == "accepted":
        outcome = runner.run(minimal, run_id=root.name, target_root=target, source_fingerprint=SNAPSHOT)
        claim = json.loads((Path(outcome["attempt_root"]) / "claim.json").read_bytes())
        assert read_dataset_contract(claim["dataset_contract"], internal.job_id)[1] == internal.datasets
        def publish(unit):
            return {"artifact": completion}

        parent = replace(parent, units=(parent.units[0], replace(parent.units[1], handler=publish)))
        runner.run(parent, run_id=root.name, target_root=target, source_fingerprint=SNAPSHOT)
    elif state == "rejected":
        with pytest.raises(RuntimeError, match="internal fixture failure"):
            runner.run(minimal, run_id=root.name, target_root=target, source_fingerprint=SNAPSHOT)

    inputs = InventoryInputs(
        root, root.name, SNAPSHOT, {parent.job_id: ("work",)}, {parent.job_id: parent.datasets}, {},
        {parent.job_id: accepted_handoff(root, parent.job_id)}, {}, (),
        file_job_steps={parent.job_id: ("work",), internal.job_id: ("execute",)},
        file_declarations={parent.job_id: parent.datasets, internal.job_id: internal.datasets},
        managed_publications=mode == "first_party_managed")
    report = build_inventory(inputs)
    assert report["audit"]["status"] == "PASSED", report["audit"]["violations"]
    assert not any(row["job_id"] == internal.job_id for row in report["rows"])
    owned = [row for row in report["file_ownership"] if row["job_id"] == internal.job_id]
    assert bool(owned) is (state != "absent" if mode == "strict" else state == "accepted")
    assert all(row["accounting_only"] and not row["in_publication_stage"] for row in owned)
    if state != "absent" and mode == "strict":
        attempts = [row for row in owned if row["attempt_id"]]
        assert attempts and all(row["contract_basis"] == "pinned_attempt_contract" for row in attempts)
        stray = root / f"data/jobs/{internal.job_id}/attempts/attempt_0001/steps/execute/tasks/node/unknown.json"
        atomic_json(stray, {})
        atomic_json(root / "data/build/iterations/unknown.json", {})
        rejected = build_inventory(inputs)
        assert rejected["run_tree"]["unaccounted_count"] == 2


@pytest.mark.parametrize("mode", ("strict", "first_party_managed"))
def test_undeclared_accepted_artifact_still_fails(tmp_path, mode):
    runner, job, target = _fixture(tmp_path, mode)
    outcome = runner.run(job, target_root=target, source_fingerprint=SNAPSHOT)
    root = runner.runs.resolve(outcome["status"]["run_id"])
    changed = replace(job.datasets[0], artifacts=("data/other/output.json",))
    report = _inventory(root, replace(job, datasets=(changed,)), managed=mode == "first_party_managed")
    assert report["audit"]["status"] == "FAILED"
    assert any(row["code"] == "unaccounted_handoff_artifact" and row["subject"].endswith("/output.json")
               for row in report["audit"]["violations"])


@pytest.mark.parametrize("path", (
    "data/recovery/current.json.bak",
    "data/recovery/releases/nested/unknown.json",
    "data/recovery/workers/record.txt",
    "data/jobs/job_unknown/attempts/attempt_0001/published.json",
    "data/jobs/job_fixture/attempts/attempt_0001/published.json.bak",
    "data/jobs/job_fixture/attempts/attempt_0001/steps/unknown/tasks/only/checkpoint.json",
    "data/jobs/job_fixture/attempts/attempt_0001/steps/work/tasks/only/checkpoint.json.bak",
))
def test_runtime_claims_do_not_expand_to_unknown_paths(path):
    claims = FileClaims(runtime_claims({"job_fixture": ("work",)}))
    assert claims.file(path) is None


@pytest.mark.parametrize("path", (
    "data/recovery/current.json", "data/recovery/admission.lock", "data/recovery/successor.json",
    "data/recovery/releases/release.json", "data/recovery/workers/worker.json",
    "data/recovery/dispatches/dispatch.json", "data/recovery/repairs/repair.json",
    "data/jobs/job_fixture/attempts/attempt_0001/published.json",
    "data/jobs/job_fixture/attempts/attempt_0001/steps/work/tasks/only/checkpoint.json",
))
def test_runtime_lifecycle_records_have_protected_ownership(path):
    claims = FileClaims(runtime_claims({"job_fixture": ("work",)}))
    claim = claims.file(path)
    assert claim is not None
    assert claim.declaration.disposition == "protected"
    assert claim.declaration.sensitivity == "sensitive"
    assert claim.declaration.reason
