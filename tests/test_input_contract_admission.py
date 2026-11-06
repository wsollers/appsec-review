from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.indexing.input_matrix import job_contract_matrix
from appsec_review.indexing.store import accepted_handoff
from appsec_review.runtime import Job, JobRunner, Unit, UnitExecutor
from appsec_review.runtime.contracts import (
    Availability, CoveragePolicy, DispatchClass, InputRequirement, JobContract, MissingPolicy,
    TargetAccess, EvidenceAuthority, InputChannel, accepted_inputs,
)
from appsec_review.runtime.dependencies import graph_dependencies, input_projection, semantic_dependencies
from appsec_review.runtime.inputs import input_read_scope, read_input_observations
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.storage import file_sha256
from tests.release_support import write_release
from tests.test_inventory_publication import SNAPSHOT, _fixture

ROOT = Path(__file__).resolve().parents[1]


def setup(tmp_path, *, read=True, availability=Availability.REQUIRED, missing=MissingPolicy.REJECT, mode="strict"):
    _runner, producer, target = _fixture(tmp_path, mode)
    config_path = tmp_path / "appsec-review.toml"
    with config_path.open("a") as stream:
        stream.write('\n[jobs.job_reader]\nname="reader"\nworkers=1\n'
                     '[jobs.job_reader.steps.work.tasks.read]\nworkers=1\n')
    write_release(tmp_path, ("job_fixture", "job_reader"))
    runner = JobRunner(load_config(config_path))
    producer = replace(producer, contract=JobContract())
    contract = JobContract(inputs=accepted_inputs(
        producer.job_id, producer.datasets, availability=availability, missing=missing))

    def handler(unit):
        if read:
            value = accepted_handoff(unit.job.run_root, "job_fixture")
            assert value is not None
        return {"value": 7}

    units = (Unit("work.read", handler),)
    consumer = Job("job_reader", "reader", UnitExecutor(units).execute, units=units, contract=contract)
    return runner, producer, consumer, target


def run(runner, job, target, run_id=None, **kwargs):
    return runner.run(job, run_id=run_id, source_fingerprint=SNAPSHOT, target_root=target, **kwargs)


def test_real_admission_and_reader_observation_are_separate(tmp_path):
    runner, producer, consumer, target = setup(tmp_path)
    first = run(runner, producer, target)
    root = runner.runs.resolve(first["status"]["run_id"])
    output = run(runner, consumer, target, root.name)
    claim = json.loads((Path(output["attempt_root"]) / "claim.json").read_bytes())
    admission = claim["input_admission"]["requirements"]
    assert all(row["available"] and row["supplied"] for row in admission)
    assert all(row["read"] is False and row["cited"] is None for row in admission)
    result = read_input_observations(root, output["handoff"])
    assert result["citation_observation"] == "not_observed"
    assert result["reads"][0]["handoff_sha256"] == first["handoff_sha256"]
    assert result["reads"][0]["output_kind"] == "handoff"
    assert result["reads"][0]["read"] is True and result["reads"][0]["cited"] is None
    assert claim["dataset_contract"]["schema"] == "appsec-review/attempt-datasets/3"


def test_supplied_but_unread_is_not_consumed(tmp_path):
    runner, producer, consumer, target = setup(tmp_path, read=False)
    first = run(runner, producer, target)
    output = run(runner, consumer, target, first["status"]["run_id"])
    root = runner.runs.resolve(first["status"]["run_id"])
    assert read_input_observations(root, output["handoff"])["reads"] == []


@pytest.mark.parametrize("availability,missing,accept", [
    (Availability.REQUIRED, MissingPolicy.REJECT, False),
    (Availability.OPTIONAL, MissingPolicy.GAP, True),
    (Availability.WHEN_ENABLED, MissingPolicy.REJECT, False),
])
def test_missing_input_policy_at_real_admission(tmp_path, availability, missing, accept):
    runner, _producer, consumer, target = setup(tmp_path, read=False, availability=availability, missing=missing)
    if not accept:
        with pytest.raises(ValueError, match="required input unavailable"):
            run(runner, consumer, target)
    else:
        output = run(runner, consumer, target)
        claim = json.loads((Path(output["attempt_root"]) / "claim.json").read_bytes())
        assert all(row["status"] == "gap" for row in claim["input_admission"]["requirements"])


def test_reader_rejects_undeclared_actual_consumption(tmp_path):
    runner, producer, consumer, target = setup(tmp_path)
    first = run(runner, producer, target)
    consumer = replace(consumer, consumes=(), contract=JobContract())
    with pytest.raises(RuntimeError, match="undeclared consumption") as error:
        run(runner, consumer, target, first["status"]["run_id"])
    assert isinstance(error.value.__cause__, ValueError)


@pytest.mark.parametrize("change", ("schema", "output", "authority", "tamper", "stale"))
def test_foreign_output_schema_bytes_and_stale_handoffs(tmp_path, change):
    runner, producer, consumer, target = setup(tmp_path)
    first = run(runner, producer, target)
    root = runner.runs.resolve(first["status"]["run_id"])
    supplied = {producer.job_id: first["handoff_sha256"]}
    if change in {"schema", "output", "authority"}:
        inputs = list(consumer.contract.inputs)
        replacement = {"schema": "appsec-review/facts/999"} if change == "schema" else (
            {"authority": EvidenceAuthority.OPERATIONAL} if change == "authority" else {"output_kind": "unknown"})
        inputs[1] = replace(inputs[1], **replacement)
        consumer = replace(consumer, contract=replace(consumer.contract, inputs=tuple(inputs)))
        message = "authority mismatch" if change == "authority" else "output contract mismatch"
    elif change == "tamper":
        path = Path(first["attempt_root"]) / "steps/work/tasks/publish/output.json"
        path.write_text('{"tampered":true}')
        message = "changed|mismatch|integrity"
    else:
        run(runner, producer, target, root.name)
        message = "stale"
    with pytest.raises(ValueError, match=message):
        run(runner, consumer, target, root.name, upstream_handoffs=supplied)


def test_contract_change_refuses_reuse_but_historical_bytes_remain(tmp_path):
    runner, producer, consumer, target = setup(tmp_path)
    first = run(runner, producer, target)
    run_id = first["status"]["run_id"]
    output = run(runner, consumer, target, run_id)
    path = Path(output["attempt_root"]) / "handoff.json"
    digest = file_sha256(path)
    contract = replace(consumer.contract, schedule_after=("job_fixture",))
    changed = replace(consumer, contract=contract)
    reasons, _ = ResumePlanner(runner.config, runner.runs.resolve(run_id), (changed,), SNAPSHOT,
                               target_root=target).accepted(changed, {producer.job_id: first["handoff_sha256"]})
    assert "dataset contract identity changed" in reasons
    assert file_sha256(path) == digest


def test_all_46_contract_config_output_and_dispatch_invariants():
    registry = builtin_registry()
    config = load_config(ROOT / "appsec-review.toml")
    rows = job_contract_matrix(config, registry)
    assert len(rows) == 46
    classes = {row["job_id"]: row["contract"]["dispatch"] for row in rows}
    assert classes["job_build_iteration"] == "internal_transaction"
    assert classes["job_third_party_data_sync"] == "maintenance"
    assert sum(value == "review_graph" for value in classes.values()) == 44
    from appsec_review.orchestration.topology import wave1_dependencies, enabled_wave1_dependencies
    enabled = {row["job_id"] for row in rows if row["enabled"]}
    graph = enabled_wave1_dependencies(enabled, set(registry.job_ids()))
    assert set(graph) == {name for name in enabled if classes[name] == "review_graph"}
    jobs = tuple(registry.build(name) for name in graph)
    assert graph_dependencies(jobs) == graph
    assert set(wave1_dependencies(set(classes))) == {name for name, value in classes.items()
                                                     if value == "review_graph"}


def test_scheduling_does_not_supply_or_invalidate_independent_branch():
    a = Job("a", "a", lambda _: {}, contract=JobContract())
    b = Job("b", "b", lambda _: {}, contract=JobContract(schedule_after=("a",)))
    c = Job("c", "c", lambda _: {}, contract=JobContract(inputs=(
        InputRequirement("a", "handoff", "appsec-review/job-handoff/2"),)))
    jobs = (a, b, c)
    scheduling = {"a": (), "b": ("a",), "c": ("a",)}
    assert graph_dependencies(jobs) == scheduling
    assert semantic_dependencies(jobs, scheduling) == {"a": (), "b": (), "c": ("a",)}
    assert input_projection(b, {"a": "changed"}, scheduling, {"a"}) == {}
    assert input_projection(c, {"a": "changed"}, scheduling, {"a"}) == {"a": "changed"}


@pytest.mark.parametrize("terminal,policy,accept", [
    ("COMPLETED_WITH_GAPS", CoveragePolicy.ALLOW_PARTIAL, True),
    ("COMPLETED_WITH_GAPS", CoveragePolicy.REQUIRE_COMPLETE, False),
    ("FAILED", CoveragePolicy.REQUIRE_NONRETRIABLE, False),
])
def test_partial_and_retriable_inputs_are_not_clean(tmp_path, terminal, policy, accept):
    runner, producer, consumer, target = setup(tmp_path, read=False)
    producer = replace(producer, units=(replace(producer.units[0], handler=lambda _: {
        "terminal_status": terminal, "gaps": ["bounded producer omitted scope"]}), producer.units[1]))
    first = run(runner, producer, target)
    inputs = (replace(consumer.contract.inputs[0], coverage=policy), *consumer.contract.inputs[1:])
    consumer = replace(consumer, contract=replace(consumer.contract, inputs=inputs))
    if accept:
        output = run(runner, consumer, target, first["status"]["run_id"])
        claim = json.loads((Path(output["attempt_root"]) / "claim.json").read_bytes())
        assert claim["input_admission"]["requirements"][0]["coverage"]["disposition"] == "partial"
    else:
        with pytest.raises(ValueError, match="input coverage"):
            run(runner, consumer, target, first["status"]["run_id"])


def test_foreign_target_is_rejected_before_consumer(tmp_path):
    runner, producer, consumer, target = setup(tmp_path)
    first = run(runner, producer, target)
    with pytest.raises(ValueError, match="different target"):
        runner.run(consumer, run_id=first["status"]["run_id"], target_root=target,
                   source_fingerprint="target-sha256:" + "8" * 64)


def test_conditional_disabled_input_is_an_explicit_gap(tmp_path):
    runner, _producer, consumer, target = setup(
        tmp_path, read=False, availability=Availability.WHEN_ENABLED, missing=MissingPolicy.REJECT)
    path = tmp_path / "appsec-review.toml"
    with path.open("a") as stream:
        stream.write("\n[jobs.job_fixture.settings]\nenabled=false\n")
    runner = JobRunner(load_config(path))
    output = run(runner, consumer, target)
    claim = json.loads((Path(output["attempt_root"]) / "claim.json").read_bytes())
    assert claim["input_admission"]["requirements"][0]["status"] == "gap"
    assert claim["input_admission"]["requirements"][0]["supplied"] is False


@pytest.mark.parametrize("change", ("none", "undeclared", "unbound", "tampered"))
def test_real_shard_reader_binds_exact_output_owner(tmp_path, change):
    from appsec_review.runtime.datasets import indexed
    from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
    from appsec_review.indexing.store import open_shard

    runner, producer, consumer, target = setup(tmp_path, read=False)
    declaration = indexed("observations", "work", "catalog", "appsec-review/retrieval-index/2",
                          "Fixture observations.", indexes=("analysis",), route="find", required=True)

    def publish(unit):
        root = unit.job.run_root
        path = root / "data/indices/analysis/fixture.sqlite"
        builder = IndexBuilder(path, name="analysis", fingerprint="a" * 64,
                               target_snapshot=SNAPSHOT, shard_id="fixture")
        builder.add_coverage("fixture", "complete")
        identity = IndexIdentity("analysis", declaration.schema, builder.build(), "a" * 64,
                                 path.relative_to(root).as_posix(), {"job": producer.job_id,
                                                                   "unit": unit.unit_id}, (), "fixture")
        manifest_path = unit.unit_root / "manifest.json"
        write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=SNAPSHOT,
                       target_root=target, indexes=(identity,))
        from dataclasses import asdict
        return {"index_identity": asdict(identity),
                "index_manifest": {"path": manifest_path.relative_to(root).as_posix(),
                                   "sha256": file_sha256(manifest_path)},
                "artifacts": [{"path": identity.relative_path, "sha256": identity.sha256}]}

    producer = replace(producer, units=(Unit("work.publish", publish),), datasets=(declaration,))
    first = run(runner, producer, target)
    root = runner.runs.resolve(first["status"]["run_id"])
    shard = first["result"]["outputs"]["work.publish"]["index_identity"]
    inputs = accepted_inputs(producer.job_id, (declaration,))
    if change == "undeclared":
        inputs = inputs[:1]
    consumer = replace(consumer, contract=JobContract(inputs=inputs))
    claim = runner.begin_attempt(consumer, run_id=root.name, target_root=target, source_fingerprint=SNAPSHOT)
    context = runner._context_from_claim(consumer, claim)
    if change == "unbound":
        shard = {**shard, "sha256": "b" * 64}
    elif change == "tampered":
        (root / shard["relative_path"]).write_bytes(b"changed")
    if change == "none":
        with input_read_scope(context) as reads:
            with open_shard(root, shard) as database:
                assert database.execute("SELECT COUNT(*) FROM entities").fetchone()[0] == 0
        assert reads.document()["reads"][0]["output_kind"] == "observations"
        assert reads.document()["reads"][0]["sha256"] == shard["sha256"]
    else:
        with input_read_scope(context), pytest.raises(ValueError, match="undeclared|bound|changed"):
            open_shard(root, shard)


@pytest.mark.parametrize("mode", ("strict", "first_party_managed"))
def test_typed_target_independent_consumer_preserves_origin_without_checkout_access(tmp_path, mode):
    runner, producer, consumer, target = setup(tmp_path, mode=mode)
    first = run(runner, producer, target)
    consumer = replace(consumer, contract=replace(consumer.contract, target_access=TargetAccess.ACCEPTED_EVIDENCE))
    output = runner.run(consumer, run_id=first["status"]["run_id"],
                        upstream_handoffs={producer.job_id: first["handoff_sha256"]})
    claim = json.loads((Path(output["attempt_root"]) / "claim.json").read_bytes())
    assert claim["source_fingerprint"] == "none" and claim["target_root"] is None
    assert claim["evidence_target_snapshot"] == SNAPSHOT
    with pytest.raises(ValueError, match="cannot grant"):
        run(runner, consumer, target, first["status"]["run_id"])


def test_maintenance_metadata_needs_no_graph_handoff_or_target(tmp_path):
    runner, _producer, consumer, _target = setup(tmp_path, read=False)
    consumer = replace(consumer, consumes=(), contract=JobContract(
        dispatch=DispatchClass.MAINTENANCE, target_access=TargetAccess.NONE))
    output = runner.run(consumer)
    claim = json.loads((Path(output["attempt_root"]) / "claim.json").read_bytes())
    assert claim["upstream_handoffs"] == {}
    assert claim["evidence_target_snapshot"] == "none" and claim["target_root"] is None


def test_dagster_definition_edges_match_direct_contract_without_execution():
    from appsec_review.orchestration.dagster.adapter import build_definitions
    from appsec_review.orchestration.topology import describe_wave1
    registry = builtin_registry()
    config = load_config(ROOT / "appsec-review.toml")
    description = describe_wave1(config, registry)
    graph = build_definitions(ROOT / "appsec-review.toml").get_job_def("wave1_review").graph
    dependencies = {node.name: values for node, values in graph.dependencies.items()}
    for row in description["jobs"]:
        name = row["job_id"].removeprefix("job_") + "__begin"
        actual = {value.node for value in dependencies.get(name, {}).values()}
        expected = {value.removeprefix("job_") + "__finalize" for value in row["dependencies"]}
        assert actual == expected
        assert set(row["upstream_handoffs"]) == set(registry.build(row["job_id"]).consumes) & {
            entry["job_id"] for entry in description["jobs"]}
    assert not any(name.startswith(("build_iteration__", "third_party_data_sync__")) for name in dependencies)


def test_real_resume_keeps_schedule_only_branch_identity(tmp_path):
    runner, producer, consumer, target = setup(tmp_path, read=False)
    consumer = replace(consumer, consumes=(), contract=JobContract(schedule_after=(producer.job_id,)))
    first = run(runner, producer, target)
    output = run(runner, consumer, target, first["status"]["run_id"])
    root = runner.runs.resolve(first["status"]["run_id"])
    accepted_bytes = (Path(output["attempt_root"]) / "handoff.json").read_bytes()
    decisions = ResumePlanner(runner.config, root, (producer, consumer), SNAPSHOT,
                              target_root=target).plan(force_from=producer.job_id, emit_event=False)
    assert [row.action for row in decisions] == ["RUN", "REUSE"]
    assert decisions[1].handoff_sha256 == output["handoff_sha256"]
    assert (Path(output["attempt_root"]) / "handoff.json").read_bytes() == accepted_bytes


@pytest.mark.parametrize("omitted", (False, True), ids=("complete-root", "omitted-inherited-shard"))
def test_input_manifest_preserves_a_dominating_accepted_manifest(tmp_path, omitted):
    from appsec_review.retrieval.core import materialize_attempt_input_manifest, resolve_context_manifest
    from appsec_review.retrieval.index import IndexBuilder, IndexIdentity, write_manifest, load_verified_manifest
    from appsec_review.runtime.datasets import indexed
    from appsec_review.storage.shared import reference

    runner, producer, consumer, target = setup(tmp_path, read=False)

    def publish(unit):
        path = unit.unit_root / "manifest.json"
        parents = ()
        indexes = ()
        result = {}
        if unit.job.upstream_handoffs:
            upstream, digest = resolve_context_manifest(unit.job)
            parents = (reference(unit.job.run_root, upstream, expected_sha256=digest),)
        elif omitted:
            from dataclasses import asdict
            database = unit.job.run_root / "data/indices/analysis/inherited.sqlite"
            builder = IndexBuilder(database, name="analysis", fingerprint="a" * 64,
                                   target_snapshot=SNAPSHOT, shard_id="inherited")
            builder.add_coverage("inherited", "complete")
            identity = IndexIdentity("analysis", "appsec-review/retrieval-index/2",
                                     builder.build(), "a" * 64,
                                     database.relative_to(unit.job.run_root).as_posix(),
                                     {"job": producer.job_id, "unit": unit.unit_id}, (), "inherited")
            indexes = (identity,)
            result = {"index_identity": asdict(identity), "artifacts": [reference(unit.job.run_root, database)]}
        write_manifest(path, run_id=unit.job.run_id, target_snapshot=SNAPSHOT,
                       target_root=target, indexes=indexes, upstream_manifests=parents)
        return {**result, "index_manifest": reference(unit.job.run_root, path)}

    datasets = (indexed("analysis", "work", "catalog", "appsec-review/retrieval-index/2",
                        "Inherited fixture analysis.", indexes=("analysis",), route="find"),) if omitted else ()
    producer = replace(producer, datasets=datasets, units=(Unit("work.publish", publish),))
    consumer = replace(consumer, units=(Unit("work.read", publish),),
                       contract=JobContract(inputs=accepted_inputs(producer.job_id, datasets)))
    first = run(runner, producer, target)
    second = run(runner, consumer, target, first["status"]["run_id"])
    root = runner.runs.resolve(first["status"]["run_id"])
    projection = root / "data/inputs/manifest-projection"
    path, digest = materialize_attempt_input_manifest(
        run_root=root, attempt_root=projection, run_id=root.name,
        target_snapshot=SNAPSHOT, target_root=target, upstream_handoffs={
            producer.job_id: first["handoff_sha256"], consumer.job_id: second["handoff_sha256"]})
    expected = second["result"]["outputs"]["work.read"]["index_manifest"]
    if omitted:
        assert path != root / expected["path"]
        manifest, _ = load_verified_manifest(root, path, digest)
        assert [item["shard_id"] for item in manifest["indexes"]] == ["inherited"]
    else:
        assert path == root / expected["path"] and digest == expected["sha256"]
    assert not (Path(second["attempt_root"]) / "inputs/retrieval-manifest.json").exists()


def test_external_feed_selection_invalidates_reuse_without_scheduling_maintenance(tmp_path):
    import re
    from appsec_review.runtime.inputs import feed_input_identity
    from appsec_review.jobs.job_third_party_data_sync.publication import publish_snapshot
    runner, _producer, consumer, target = setup(tmp_path, read=False)
    path = tmp_path / "appsec-review.toml"
    selected = False
    with path.open("a") as stream:
        for line in (ROOT / "appsec-review.toml").read_text().splitlines():
            header = re.fullmatch(r"\[{1,2}([A-Za-z0-9_.]+)\]{1,2}\s*(?:#.*)?", line.strip())
            if header:
                selected = header[1] == "jobs.job_third_party_data_sync" or header[1].startswith(
                    "jobs.job_third_party_data_sync.")
            if selected:
                stream.write(line + "\n")
    runner = JobRunner(load_config(path))
    consumer = replace(consumer, consumes=(), contract=JobContract(inputs=(
        InputRequirement("job_third_party_data_sync", "feed_snapshot", "appsec-review/public-feed-use/1",
                         authority=EvidenceAuthority.REFERENCE, channel=InputChannel.EXTERNAL),)),
                       external_input_identity=feed_input_identity)
    first = run(runner, consumer, target)
    root = runner.runs.resolve(first["status"]["run_id"])
    planner = ResumePlanner(runner.config, root, (consumer,), SNAPSHOT, target_root=target)
    assert planner.accepted(consumer, {})[0] == ()
    records = tmp_path / "records.json"
    records.write_text("[]")
    configured = runner.config.job("job_third_party_data_sync").step("osv_sync").settings["feed_root"]
    feed_root = tmp_path / configured
    publish_snapshot(feed_root, feed_id="osv", schema="appsec-review/osv-snapshot/1",
                     files={"records.json": records}, manifest_fields={})
    reasons, _ = planner.accepted(consumer, {})
    assert "input identity changed" in reasons
    assert not (root / "data/jobs/job_third_party_data_sync/latest.json").exists()
    assert builtin_registry().build("job_third_party_data_sync").always_execute


@pytest.mark.parametrize("supplied", (False, True))
def test_required_transaction_needs_verified_reader_receipt(tmp_path, supplied):
    from appsec_review.jobs.build_iterations import retain, read_reference, REQUEST_SCHEMA
    from appsec_review.runtime.inputs import observe_external
    runner, _producer, consumer, target = setup(tmp_path, read=False)
    contract = JobContract(inputs=(
        InputRequirement("controller", "request", REQUEST_SCHEMA, channel=InputChannel.TRANSACTION,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),),
                           always_execute=True)

    def handle(unit):
        if supplied:
            request = retain(unit.job.run_root, "requests", {"schema": REQUEST_SCHEMA, "fixture": "bounded"})
            assert read_reference(unit.job.run_root, request)["schema"] == REQUEST_SCHEMA
            observe_external(unit.job.run_root, "controller", "request", REQUEST_SCHEMA, request,
                             channel=InputChannel.TRANSACTION)
        return {"value": 7}

    consumer = replace(consumer, consumes=(), contract=contract, units=(Unit("work.read", handle),))
    if supplied:
        output = run(runner, consumer, target)
        assert output["handoff"]["status"] == "ACCEPTED"
        root = runner.runs.resolve(output["status"]["run_id"])
        assert read_input_observations(root, output["handoff"])["reads"][0]["channel"] == "transaction"
    else:
        with pytest.raises(ValueError, match="required external input was not validated"):
            run(runner, consumer, target)
