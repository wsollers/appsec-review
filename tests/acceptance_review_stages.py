"""Rehydratable authentic fixtures; only producer phases may run application jobs."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path
import shutil
from uuid import uuid4

from appsec_review.acceptance.lanes import LaneWorkspace
from appsec_review.acceptance.staging import (
    CUSTODY_INPUT_FILE, SeedInputs, StageContext, StageKind, stage_context,
)
from tests.final_report_support import (
    GATE, REPORT, Chain, environment, gate_job, job_tables, report_job, run_job,
)
from tests.fixtures.inference_review.acceptance import JOB, ROOT, write_config, write_overlay
from tests.fixtures.inference_review.builder import RUN_ID, FixtureRun, build_accepted_index_set
from tests.poc_chain import poc_tables


STATE_FILE = "fixture-state.json"
STATE_SCHEMA = "appsec-review/acceptance-review-fixture/1"


@dataclass(frozen=True)
class Variant:
    ci_only: bool = False
    basis: bool = True
    benign: bool = False
    blocked: bool = False


VARIANTS = {
    "native-positive": Variant(),
    "native-empty": Variant(basis=False),
    "ci-positive": Variant(ci_only=True),
    "ci-benign": Variant(ci_only=True, benign=True),
    "ci-blocked": Variant(ci_only=True, blocked=True),
}


def context_for(kind: StageKind, variant: str | None = None) -> StageContext | None:
    context = stage_context()
    if context is not None:
        if context.kind is not kind or context.variant not in VARIANTS:
            raise ValueError("review fixture stage kind or variant is incompatible")
        if variant is not None and context.variant != variant:
            raise ValueError("review fixture requires its exact declared variant")
    return context


def stage_lane(context: StageContext) -> LaneWorkspace:
    lane = LaneWorkspace(ROOT, context.work_root, context.variant, context.invocation_id)
    lane.root.mkdir(parents=True, exist_ok=True)
    lane.runs_dir.mkdir(exist_ok=True)
    lane.driver_root.mkdir(exist_ok=True)
    return lane


def prepare_chain(lane: LaneWorkspace, *, basis=True, benign=False, blocked=False, ci_only=False) -> Chain:
    """Freeze the tiny configuration before publishing any framework /2 upstream."""
    from appsec_review.config import load_config
    from appsec_review.runtime import JobRunner
    from tests.integration.test_authentic_poc_contract import attach_call_chain

    config = write_config(
        lane.root, lane.runs_dir,
        overrides={"budget_team_packages": 1, "hunt_max_units": 0, "max_rounds": 1,
                   "red_per_team": 1, "blue_per_team": 1, "verifier_per_team": 1},
        extra=job_tables("job_review_data_indexing") + job_tables("job_third_party_data_sync")
              + job_tables(GATE) + job_tables(REPORT) + poc_tables(max_candidates=2))
    env = {"APPSEC_REVIEW_CONFIG_OVERLAY": str(write_overlay(lane.root, 1))}
    with environment(env):
        JobRunner(load_config(config))._bind_configuration(lane.runs_dir / RUN_ID)
    omit = ("semgrep", "opengrep", "codeql", "osv", "priority", "history", "tags", "scanner_correlation",
            "dependency_advisories", "gitleaks")
    fixture = build_accepted_index_set(
        lane.root / "data", runs_dir=lane.runs_dir,
        omit=omit + (("components", "build", "reference_intelligence") if ci_only else ("ci",)),
        omit_feeds=("osv", "nvd", "kev", "epss") + (("mitre",) if ci_only else ()))
    assert fixture.runs_dir == lane.runs_dir
    if not ci_only:
        attach_call_chain(fixture)
    (fixture.run_root / "data" / "jobs" / JOB / "cells").mkdir(parents=True, exist_ok=True)
    return Chain(lane.root, fixture, config, env)


def run_review(lane: LaneWorkspace, chain: Chain, *, basis=True, benign=False, blocked=False,
               ci_only=False) -> None:
    from appsec_review.jobs.job_inference_security_review import build_job
    from tests.integration.test_authentic_poc_contract import BasisInfer

    infer = BasisInfer({
        "ids": chain.fixture.ids, "basis": basis, "benign": benign,
        "trace": str(lane.root / "scripted-turns.jsonl"),
        **({"fail_roles": ["red_team_analyst", "hypothesis_hunter"]} if blocked else {})})
    pointer = json.loads((chain.run_root / "data" / "indices" / "accepted.json").read_text(encoding="utf-8"))
    with lane.span("review"):
        outcome = run_job(chain.config, build_job(infer=infer, repository_root=ROOT), chain.fixture.run_id,
                          {"job_review_data_indexing": pointer["handoff_sha256"]}, chain.env)
    assert outcome["handoff"]["completion_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    assert chain.handoff(JOB)["upstream_handoff_sha256"]["job_review_data_indexing"] == pointer["handoff_sha256"]


def run_gate(lane: LaneWorkspace, chain: Chain) -> None:
    with lane.span("gate"):
        outcome = run_job(chain.config, gate_job(), chain.fixture.run_id, chain.upstream(JOB), chain.env)
    assert outcome["handoff"]["completion_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    assert chain.handoff(GATE)["upstream_handoff_sha256"][JOB] == chain.pointer_sha(JOB)


def run_report(lane: LaneWorkspace, chain: Chain) -> None:
    with lane.span("report"):
        outcome = run_job(chain.config, report_job(), chain.fixture.run_id, chain.upstream(GATE), chain.env)
    assert outcome["handoff"]["completion_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    assert chain.handoff(REPORT)["upstream_handoff_sha256"][GATE] == chain.pointer_sha(GATE)


def _owned(path: Path, root: Path) -> Path:
    if not path.is_absolute() or path.resolve() != path or path == root or not path.is_relative_to(root):
        raise ValueError("fixture metadata path must be a canonical owned descendant")
    return path


def _owned_metadata(value, root: Path) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _owned_metadata(item, root)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _owned_metadata(item, root)
    elif isinstance(value, str) and Path(value).is_absolute():
        _owned(Path(value), root)


def write_state(chain: Chain, variant: str) -> None:
    if variant not in VARIANTS:
        raise ValueError("fixture metadata requires its exact declared variant")
    root = chain.base.resolve()
    fixture = chain.fixture
    for path in (fixture.runs_dir, fixture.run_root, fixture.target, chain.config,
                 Path(chain.env["APPSEC_REVIEW_CONFIG_OVERLAY"])):
        _owned(path, root)
    if fixture.run_root != fixture.runs_dir / fixture.run_id:
        raise ValueError("fixture run identity does not match its reader locus")
    state = {
        "schema": STATE_SCHEMA, "variant": variant, "base": str(root),
        "config": str(chain.config), "env": dict(chain.env),
        "fixture": {**asdict(fixture), "runs_dir": str(fixture.runs_dir),
                    "run_root": str(fixture.run_root), "target": str(fixture.target)},
    }
    _owned_metadata(state["fixture"], root)
    (root / STATE_FILE).write_text(json.dumps(state, sort_keys=True) + "\n", encoding="utf-8")
    paths = (fixture.target, chain.config, Path(chain.env["APPSEC_REVIEW_CONFIG_OVERLAY"]),
             fixture.run_root / "data" / "configuration", root / STATE_FILE)
    inputs = SeedInputs(variant, tuple(path.relative_to(root).as_posix() for path in paths))
    (root / CUSTODY_INPUT_FILE).write_text(json.dumps(inputs.record(), sort_keys=True) + "\n",
                                         encoding="utf-8")


def read_state(root: Path, *, source_root: Path | None = None, variant: str) -> Chain:
    """Relocate reader loci only; every authenticated absolute source/config path stays frozen."""
    root = root.resolve()
    source = (source_root or root).resolve()
    state = json.loads((root / STATE_FILE).read_text(encoding="utf-8"))
    if (set(state) != {"schema", "variant", "base", "config", "env", "fixture"}
            or state["schema"] != STATE_SCHEMA or state["variant"] != variant
            or state["base"] != str(source) or variant not in VARIANTS):
        raise ValueError("fixture metadata identity changed")
    value = state["fixture"]
    if set(value) != {"runs_dir", "run_root", "run_id", "target", "snapshot", "ids", "shards", "feed_pins"}:
        raise ValueError("fixture metadata fields changed")
    if set(state["env"]) != {"APPSEC_REVIEW_CONFIG_OVERLAY"}:
        raise ValueError("fixture environment fields changed")
    _owned_metadata(value, source)
    config = _owned(Path(state["config"]), source)
    overlay = _owned(Path(state["env"]["APPSEC_REVIEW_CONFIG_OVERLAY"]), source)
    runs = _owned(Path(value["runs_dir"]), source)
    run = _owned(Path(value["run_root"]), source)
    target = _owned(Path(value["target"]), source)
    if run != runs / value["run_id"] or run.name != value["run_id"]:
        raise ValueError("fixture run identity changed")
    fixture = FixtureRun(
        root / runs.relative_to(source), root / run.relative_to(source), value["run_id"], target,
        value["snapshot"], value["ids"], tuple(value["shards"]), value["feed_pins"])
    return Chain(root, fixture, config, {"APPSEC_REVIEW_CONFIG_OVERLAY": str(overlay)})


def consumer_chain(variant: str) -> tuple[LaneWorkspace, Chain] | None:
    context = context_for(StageKind.CONSUMER, variant)
    if context is None:
        return None
    from appsec_review.acceptance.custody import verify_seed

    verify_seed(context)
    return stage_lane(context), read_state(context.work_root, source_root=context.seed_root, variant=variant)


def fresh_chain(chain: Chain, name: str) -> Chain:
    """One new materialization per mutation; callers open validation only after mutation."""
    if not name or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in name):
        raise ValueError("private fixture copy requires a bounded logical name")
    name = f"{name}-{uuid4().hex}"
    context = context_for(StageKind.CONSUMER)
    if context is not None:
        from appsec_review.acceptance.custody import materialize_seed

        destination = materialize_seed(context, context.work_root / name)
        return read_state(destination, source_root=context.seed_root, variant=context.variant)
    destination = chain.base / "private-copies" / name
    shutil.copytree(chain.fixture.runs_dir, destination / "runs")
    fixture = replace(chain.fixture, runs_dir=destination / "runs",
                      run_root=destination / "runs" / chain.fixture.run_id)
    return Chain(destination, fixture, chain.config, chain.env)


def run_poc_planning(lane: LaneWorkspace, chain: Chain) -> int:
    from appsec_review.jobs.job_poc_generation import build_job
    from tests.integration.test_authentic_poc_contract import assert_poc_candidates, assert_poc_output

    inputs = assert_poc_candidates(lane, chain)

    def forbidden(*args, **kwargs):
        raise AssertionError("no model or compiler may be dispatched by the planning lane")

    with lane.span("poc-planning"):
        outcome = run_job(chain.config, build_job(
            infer=forbidden, executor_factory=forbidden, repository_root=ROOT),
            chain.fixture.run_id, chain.upstream(JOB), chain.env)
    assert outcome["handoff"]["completion_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    assert_poc_output(chain, len(inputs.candidates))
    return len(inputs.candidates)


def produce(phase: str, variant: str) -> Chain:
    context = context_for(StageKind.PRODUCER, variant)
    if context is None:
        raise ValueError("producer phases require the supervisor's stage context")
    lane = stage_lane(context)
    options = asdict(VARIANTS[variant])
    if phase == "prepare":
        with lane.span("prepare"):
            chain = prepare_chain(lane, **options)
            write_state(chain, variant)
    else:
        chain = read_state(lane.root, variant=variant)
        if phase == "review":
            run_review(lane, chain, **options)
        elif phase == "gate" and VARIANTS[variant].ci_only:
            run_gate(lane, chain)
        elif phase == "report" and VARIANTS[variant].ci_only:
            run_report(lane, chain)
        elif phase == "poc" and variant == "native-positive":
            run_poc_planning(lane, chain)
        else:
            raise ValueError("phase is incompatible with its fixture variant")
    lane.emit("ACCEPTANCE_CASE_FINISHED", case=f"{variant}-{phase}")
    return chain
