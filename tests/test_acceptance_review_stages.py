from __future__ import annotations

from dataclasses import asdict, replace
import json
import shutil
import tomllib

import pytest

from appsec_review.acceptance.lanes import LaneWorkspace
from appsec_review.acceptance.staging import (
    CUSTODY_INPUT_FILE, STAGE_ENVIRONMENT, SeedInputs, StageContext, StageKind,
)
from appsec_review.config import load_config
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.storage import file_sha256
from appsec_review.storage.validation import current_validation, validation_scope
from tests import acceptance_review_stages as support
from tests.fixtures.inference_review.acceptance import JOB, ROOT


@pytest.fixture(scope="module", params=["native-positive", "ci-positive"])
def prepared(request, tmp_path_factory):
    root = tmp_path_factory.mktemp(request.param).resolve()
    lane = LaneWorkspace(ROOT, root, request.param, "acceptance-unit")
    lane.runs_dir.mkdir()
    lane.driver_root.mkdir()
    chain = support.prepare_chain(lane, **asdict(support.VARIANTS[request.param]))
    support.write_state(chain, request.param)
    return request.param, lane, chain


def test_real_bounded_fixture_preserves_identity_and_immutable_configuration(prepared):
    variant, lane, chain = prepared
    with support.environment(chain.env):
        config = load_config(chain.config)
    manifest = json.loads((chain.run_root / "data" / "configuration" / "manifest.json").read_text())
    assert manifest["resolved_sha256"] == config.resolved_sha256
    assert manifest["selection"]["overlay"] == chain.env["APPSEC_REVIEW_CONFIG_OVERLAY"]
    assert config.runtime.runs_dir == lane.runs_dir
    settings = tomllib.loads(chain.config.read_text())["jobs"][JOB]["settings"]
    assert settings["budgets"]["budget_team_packages"] == 1
    assert settings["rounds"]["max_rounds"] == 1
    assert settings["lanes"]["hunt_max_units"] == 0
    assert all(settings["teams"][key] == 1 for key in ("red_per_team", "blue_per_team", "verifier_per_team"))
    core = RetrievalCore(chain.fixture.runs_dir, chain.fixture.run_id)
    pointer = json.loads((chain.run_root / "data" / "indices" / "accepted.json").read_text())
    handoff = json.loads((chain.run_root / pointer["handoff_path"]).read_text())
    assert handoff["schema"] == "appsec-review/job-handoff/2"
    assert handoff["resolved_config_sha256"] == config.resolved_sha256
    assert chain.fixture.target.is_relative_to(lane.root)
    names = set(core.indexes)
    if variant == "ci-positive":
        assert "reference_intelligence" not in names and "graph" not in names
        assert set(chain.fixture.feed_pins) == {"osv", "nvd", "kev", "epss", "mitre", "cve-bin-tool"}
        assert all(pin["status"] == "unavailable" for pin in chain.fixture.feed_pins.values())
    else:
        assert {"graph", "tags", "observations"} <= names
    inputs = SeedInputs.from_mapping(json.loads((lane.root / CUSTODY_INPUT_FILE).read_text()))
    assert inputs.variant == variant
    assert set(inputs.read_only_paths) == {
        "data/target", "appsec-review.toml", "capacity-overlay.toml", support.STATE_FILE,
        f"runs/{chain.fixture.run_id}/data/configuration"}
    assert support.read_state(lane.root, variant=variant).fixture == chain.fixture


def test_relocation_changes_reader_loci_not_authenticated_bytes_or_source_paths(prepared, tmp_path):
    variant, lane, chain = prepared
    destination = tmp_path / "private"
    shutil.copytree(lane.root, destination)
    before = {path.relative_to(lane.root): file_sha256(path)
              for path in lane.root.rglob("*") if path.is_file()}
    relocated = support.read_state(destination, source_root=lane.root, variant=variant)
    expected = replace(chain.fixture, runs_dir=destination / "runs",
                       run_root=destination / "runs" / chain.fixture.run_id)
    assert relocated.fixture == expected
    assert relocated.config == chain.config and relocated.env == chain.env
    assert relocated.run_root.name == chain.run_root.name
    assert before == {path.relative_to(destination): file_sha256(path)
                      for path in destination.rglob("*") if path.is_file()}
    with validation_scope(relocated.run_root):
        copied = RetrievalCore(relocated.fixture.runs_dir, relocated.fixture.run_id)
        original = RetrievalCore(chain.fixture.runs_dir, chain.fixture.run_id)
        assert copied.manifest_sha256 == original.manifest_sha256
        assert copied.target_root == original.target_root == chain.fixture.target
    assert current_validation(relocated.run_root) is None


def test_configuration_is_bound_before_upstream_publication(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    lane = LaneWorkspace(ROOT, root, "ci-positive", "acceptance-order")
    lane.runs_dir.mkdir()
    lane.driver_root.mkdir()
    original = support.build_accepted_index_set
    checked = []

    def build(base, **kwargs):
        frozen = lane.runs_dir / support.RUN_ID / "data" / "configuration"
        assert (frozen / "manifest.json").is_file()
        assert (root / "capacity-overlay.toml").is_file()
        frozen_bytes = {path.name: path.read_bytes() for path in frozen.iterdir()}
        fixture = original(base, **kwargs)
        assert frozen_bytes == {path.name: path.read_bytes() for path in frozen.iterdir()}
        checked.append(fixture.run_root)
        return fixture

    monkeypatch.setattr(support, "build_accepted_index_set", build)
    chain = support.prepare_chain(lane, ci_only=True)
    assert checked == [chain.run_root]


@pytest.mark.parametrize("part", ["config", "overlay", "target", "run_root", "feed-directory"])
def test_serialized_paths_cannot_escape_owned_source(prepared, tmp_path, part):
    variant, lane, _chain = prepared
    destination = tmp_path / "copy"
    destination.mkdir()
    state = json.loads((lane.root / support.STATE_FILE).read_text())
    outside = str(tmp_path.resolve() / "outside")
    if part == "config":
        state["config"] = outside
    elif part == "overlay":
        state["env"]["APPSEC_REVIEW_CONFIG_OVERLAY"] = outside
    elif part == "feed-directory":
        state["fixture"]["feed_pins"]["outside"] = {"directory": outside}
    else:
        state["fixture"][part] = outside
    (destination / support.STATE_FILE).write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(ValueError, match="owned descendant"):
        support.read_state(destination, source_root=lane.root, variant=variant)


def test_bad_present_stage_context_never_falls_back_to_direct_fixture(monkeypatch):
    monkeypatch.setenv(STAGE_ENVIRONMENT, "{invalid")
    with pytest.raises(ValueError):
        support.consumer_chain("ci-positive")
    monkeypatch.setenv(STAGE_ENVIRONMENT, "{}")
    with pytest.raises(ValueError, match="fields"):
        support.consumer_chain("ci-positive")


def test_producer_root_is_exact_context_work_root(tmp_path, monkeypatch):
    workspace = tmp_path.resolve()
    context = StageContext(
        StageKind.PRODUCER, "ci-positive", "ci-positive-prepare", "acceptance-staged", "1" * 40,
        {"tests/fixture.py": "2" * 64}, workspace, workspace / "variant")
    for key, value in {
        STAGE_ENVIRONMENT: json.dumps(context.record()), "APPSEC_ACCEPTANCE_ROOT": str(workspace),
        "APPSEC_ACCEPTANCE_INVOCATION": context.invocation_id,
        "APPSEC_ACCEPTANCE_TESTED_COMMIT": context.tested_commit,
    }.items():
        monkeypatch.setenv(key, value)
    lane = support.stage_lane(support.context_for(StageKind.PRODUCER, "ci-positive"))
    assert lane.root == context.work_root
    assert lane.runs_dir == context.work_root / "runs"
    with pytest.raises(ValueError, match="kind or variant"):
        support.consumer_chain("ci-positive")
    with pytest.raises(ValueError, match="exact declared variant"):
        support.context_for(StageKind.PRODUCER, "native-positive")


def test_consumer_telemetry_is_fresh_and_copied_producer_logs_are_not_execution_evidence(prepared, tmp_path):
    variant, producer, chain = prepared
    producer.emit("PRODUCER_HISTORY", obligation_id=f"{variant}-prepare")
    destination = tmp_path.resolve() / "consumer"
    shutil.copytree(producer.root, destination)
    copied_driver = destination / "driver"
    retained = {path.relative_to(copied_driver): path.read_bytes()
                for path in copied_driver.rglob("*") if path.is_file()}
    context = StageContext(
        StageKind.CONSUMER, variant, "consumer-oracle", "acceptance-staged", "1" * 40,
        {"tests/fixture.py": "2" * 64}, producer.root.parent, destination,
        producer.root, producer.root.parent / "sealed.json", "3" * 64)
    lanes = [support.stage_lane(context), support.stage_lane(context)]
    assert lanes[0].root != lanes[1].root
    for lane in lanes:
        assert lane.root.is_relative_to(destination / "consumer-telemetry")
        assert lane.driver_root != copied_driver
        path = lane.root / support.TELEMETRY_IDENTITY_FILE
        identity = json.loads(path.read_text())
        assert identity["reader_root"] == str(destination)
        assert identity["obligation_id"] == context.obligation_id
        assert identity["seed_manifest_sha256"] == context.manifest_sha256
        assert identity["retained_producer_telemetry"] == {
            "root": str(copied_driver), "execution_evidence": False}
        assert identity["metric_paths"] == {
            "events": str(lane.driver_root / "events.jsonl"), "pipeline": str(lane.pipeline.path)}
        events = [json.loads(line) for line in (lane.driver_root / "events.jsonl").read_text().splitlines()]
        assert [event["event"] for event in events] == ["ACCEPTANCE_CONSUMER_TELEMETRY_STARTED"]
        assert events[0]["metric_identity_path"] == str(path)
        assert events[0]["metric_identity_sha256"] == file_sha256(path)
        records, torn = lane.pipeline.read()
        assert not torn and len(records) == 1 and records[0]["sequence"] == 1
        lane.emit("CONSUMER_EXECUTION", obligation_id=context.obligation_id)
    assert retained == {path.relative_to(copied_driver): path.read_bytes()
                        for path in copied_driver.rglob("*") if path.is_file()}
    relocated = support.read_state(destination, source_root=producer.root, variant=variant)
    assert relocated.run_root == destination / "runs" / chain.fixture.run_id
    assert relocated.config == chain.config


def test_direct_negative_copies_are_independent_and_each_validation_is_fresh(prepared):
    _variant, _lane, chain = prepared
    pointer = json.loads((chain.run_root / "data" / "indices" / "accepted.json").read_text())
    original = chain.run_root / pointer["manifest_path"]
    initial = original.read_bytes()
    scopes = []
    for _ in range(2):
        private = support.fresh_chain(chain, "same-size-unit")
        with validation_scope(private.run_root):
            RetrievalCore(private.fixture.runs_dir, private.fixture.run_id)
        path = private.run_root / pointer["manifest_path"]
        path.write_bytes(b"[" + initial[1:])
        with validation_scope(private.run_root) as validation:
            scopes.append(validation)
            assert current_validation(private.run_root) is validation
            with pytest.raises(ValueError, match="integrity mismatch"):
                RetrievalCore(private.fixture.runs_dir, private.fixture.run_id)
        assert current_validation(private.run_root) is None
    assert scopes[0] is not scopes[1]
    assert original.read_bytes() == initial


@pytest.mark.parametrize("failure", [
    "missing-plugin", "missing-preflight", "unfinished-preflight", "foreign-workspace", "foreign-invocation",
])
def test_exhaustive_preflight_reuse_refuses_absent_or_foreign_guard(tmp_path, monkeypatch, failure):
    from types import SimpleNamespace

    from tests.integration import test_current_report_integrity_cases as vectors

    workspace = tmp_path.resolve()
    context = StageContext(
        StageKind.CONSUMER, "ci-positive", "current-report-integrity", "acceptance-staged", "1" * 40,
        {"tests/fixture.py": "2" * 64}, workspace, workspace / "consumer",
        workspace / "producer", workspace / "sealed.json", "3" * 64)
    owner = SimpleNamespace(root=workspace, invocation_id=context.invocation_id)
    preflight = {"span_id": "completed", "duration_seconds": 1.0}
    if failure == "foreign-workspace":
        owner.root = workspace / "other"
    elif failure == "foreign-invocation":
        owner.invocation_id = "another-invocation"
    elif failure == "missing-preflight":
        preflight = None
    elif failure == "unfinished-preflight":
        preflight = {}
    plugin = None if failure == "missing-plugin" else SimpleNamespace(_workspace=owner, _preflight=preflight)
    manager = SimpleNamespace(get_plugin=lambda name: plugin if name == "tests.acceptance_plugin" else None)
    request = SimpleNamespace(config=SimpleNamespace(pluginmanager=manager))
    monkeypatch.setattr(vectors, "context_for", lambda *_args: context)
    with pytest.raises(ValueError, match="completed guarded consumer preflight"):
        vectors._reuse_guarded_consumer(request)
