"""Resource pools (B15) against a real Dagster instance: limits, fairness, release, restart.

Runs in the code-server (Dagster 1.13.21). On a host without Dagster the module is skipped; it is
skipped for that reason only. The instance is a temporary SQLite one built from the repository's
own dagster.yaml (run coordinator, concurrency and run-monitoring sections), because 1.13.21's
SQLite event log supports pool slots; the Postgres path is covered by live qualification.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

try:
    import dagster  # noqa: F401
except ModuleNotFoundError as exc:  # pragma: no cover - host without Dagster
    if exc.name != "dagster":
        raise
    raise unittest.SkipTest("dagster is not importable here; these tests run in the code-server")

import yaml  # noqa: E402  (a Dagster dependency)
from dagster import DagsterInstance, DagsterRun, build_sensor_context  # noqa: E402
from dagster._utils.tags import TagConcurrencyLimitsCounter  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(TESTS))

import resource_pools as rp  # noqa: E402
import resource_pools_support as support  # noqa: E402
from schema_validate import validate_document  # noqa: E402
from test_resource_pools import state_fixture  # noqa: E402  (the host suite's Dagster-free document)

UNREADABLE = "state document is not readable JSON with unique keys and finite numbers"


def shape(node):
    """Keys of a document, with every list reduced to the shape of its first item."""
    if isinstance(node, dict):
        return {key: shape(value) for key, value in node.items()}
    if isinstance(node, list):
        return [shape(node[0])] if node else []
    return "value"

ORCHESTRATION = Path(os.environ.get("APPSEC_ORCHESTRATOR_ROOT", ROOT.parent / "orchestrator" / "dagster"))
INSTANCE_SECTIONS = ("run_coordinator", "concurrency", "run_monitoring")


def make_home(directory: Path, free_slots_seconds: int | None = None) -> Path:
    """A DAGSTER_HOME whose queue, pool and monitoring settings are the repository's own."""
    config = yaml.safe_load((ORCHESTRATION / "dagster.yaml").read_text(encoding="utf-8"))
    config = {name: config[name] for name in INSTANCE_SECTIONS}
    if free_slots_seconds is not None:
        config["run_monitoring"]["free_slots_after_run_end_seconds"] = free_slots_seconds
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "dagster.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    return directory


def intervals(records, predicate):
    opened, result = {}, []
    for record in records:
        key = (record["run_id"], record["op"])
        if not predicate(record):
            continue
        if record["what"] == "start":
            opened[key] = record["time"]
        else:
            result.append((opened.pop(key), record["time"]))
    result.extend((start, None) for start in opened.values())
    return result


class Case(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = make_home(self.root / "home")
        self.log = self.root / "pool-log.jsonl"
        self.log.write_text("", encoding="utf-8")
        previous = os.environ.get(support.LOG_ENV)
        os.environ[support.LOG_ENV] = str(self.log)
        self.addCleanup(lambda: os.environ.pop(support.LOG_ENV) if previous is None
                        else os.environ.__setitem__(support.LOG_ENV, previous))

    def instance(self, home=None):
        instance = DagsterInstance.from_config(str(home or self.home))
        self.addCleanup(instance.dispose)
        return instance

    def claimed(self, instance, pool_id):
        return len(instance.event_log_storage.get_concurrency_info(pool_id).claimed_slots)


class InstanceState(Case):
    def test_repository_yaml_loads_with_unchanged_outer_limits(self):
        settings = rp.instance_settings(self.instance())
        self.assertEqual(settings, {"default_pool_limit": rp.DEFAULT_POOL_LIMIT, "granularity": "op",
                                    "free_slots_after_run_end_seconds": rp.FREE_SLOTS_AFTER_RUN_END_SECONDS,
                                    "outer_limits": {"max_concurrent_runs": 2, "per_engagement_limit": 1,
                                                     "nvd_feed_limit": 1}})

    def test_engagement_and_nvd_serialization_are_what_the_queue_enforces(self):
        limits = self.instance().get_concurrency_config().run_queue_config.tag_concurrency_limits
        running = [DagsterRun(job_name="evidence_index", tags={"engagement_run_id": "eng-a"}),
                   DagsterRun(job_name="nvd_reference_sync", tags={"nvd_feed_id": "nvd"})]
        counter = TagConcurrencyLimitsCounter(limits, running)
        self.assertTrue(counter.is_blocked(DagsterRun(job_name="full_review", tags={"engagement_run_id": "eng-a"})))
        self.assertFalse(counter.is_blocked(DagsterRun(job_name="full_review", tags={"engagement_run_id": "eng-b"})))
        self.assertTrue(counter.is_blocked(DagsterRun(job_name="nvd_reference_sync", tags={"nvd_feed_id": "nvd"})))

    def test_apply_is_idempotent_and_verify_is_read_only(self):
        instance = self.instance()
        before = rp.verify_instance(instance)
        self.assertEqual(len([e for e in before if "MISSING" in e]), len(rp.POOLS))
        self.assertEqual(rp.observed_limits(instance), {})  # verify wrote nothing
        self.assertEqual({item["pool_id"] for item in rp.apply_limits(instance)}, set(rp.POOL_IDS))
        self.assertEqual(rp.apply_limits(instance), [])
        self.assertEqual(rp.verify_instance(instance), [])
        self.assertEqual({name: value["limit"] for name, value in rp.observed_limits(instance).items()}, rp.LIMITS)

    def test_limits_survive_an_instance_restart(self):
        first = DagsterInstance.from_config(str(self.home))
        rp.apply_limits(first)
        first.dispose()
        reopened = self.instance()
        self.assertEqual(rp.verify_instance(reopened), [])
        self.assertEqual(rp.apply_limits(reopened), [])

    def test_drift_is_visible_and_corrected_down_as_well_as_up(self):
        instance = self.instance()
        rp.apply_limits(instance)
        storage = instance.event_log_storage
        storage.set_concurrency_slots(rp.DOCKER, 5)   # someone raised a limit in the UI
        storage.set_concurrency_slots(rp.CPU, 1)      # someone lowered one
        storage.delete_concurrency_limit(rp.NETWORK)  # someone deleted one
        errors = rp.verify_instance(instance)
        self.assertEqual(sorted(errors), ["pool cpu: DRIFT expected=3 observed=1",
                                          "pool docker: DRIFT expected=1 observed=5",
                                          "pool network: MISSING expected=1 observed=None"])
        self.assertEqual({item["pool_id"] for item in rp.apply_limits(instance)}, {rp.DOCKER, rp.CPU, rp.NETWORK})
        self.assertEqual(rp.verify_instance(instance), [])

    def test_an_undeclared_pool_is_reported_not_deleted(self):
        instance = self.instance()
        rp.apply_limits(instance)
        instance.event_log_storage.set_concurrency_slots("gpu", 4)
        self.assertEqual(rp.verify_instance(instance), ["pool gpu: not a declared pool"])
        self.assertEqual(rp.apply_limits(instance), [])
        self.assertIn("gpu", rp.observed_limits(instance))

    def test_wrong_instance_settings_are_reported(self):
        for mutate, expected in [
            (lambda c: c.pop("concurrency"), "default pool limit: expected=1 observed=None"),
            (lambda c: c["concurrency"].__setitem__("default_op_concurrency_limit", 4),
             "default pool limit: expected=1 observed=4"),
            (lambda c: c["run_monitoring"].pop("free_slots_after_run_end_seconds"),
             "free_slots_after_run_end_seconds: expected=120 observed=None"),
            (lambda c: c["run_monitoring"].__setitem__("enabled", False),
             "free_slots_after_run_end_seconds: expected=120 observed=None"),
            (lambda c: c["run_coordinator"]["config"].__setitem__("max_concurrent_runs", 3),
             "outer limit max_concurrent_runs: expected=2 observed=3"),
            (lambda c: c["run_coordinator"]["config"]["tag_concurrency_limits"].pop(0),
             "outer limit per_engagement_limit: expected=1 observed=None"),
            (lambda c: c["run_coordinator"]["config"]["tag_concurrency_limits"][0].__setitem__("value", "eng-a"),
             "outer limit per_engagement_limit: expected=1 observed=None"),
            (lambda c: c["run_coordinator"]["config"]["tag_concurrency_limits"].pop(1),
             "outer limit nvd_feed_limit: expected=1 observed=None"),
            # Without the section Dagster falls back to its own queue default of ten runs.
            (lambda c: c.pop("run_coordinator"), "outer limit max_concurrent_runs: expected=2 observed=10"),
        ]:
            home = make_home(self.root / f"home-{len(list(self.root.iterdir()))}")
            config = yaml.safe_load((home / "dagster.yaml").read_text(encoding="utf-8"))
            mutate(config)
            (home / "dagster.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
            instance = self.instance(home)
            rp.apply_limits(instance)
            self.assertIn(expected, rp.verify_instance(instance))

    def test_storage_without_pool_support_fails_closed(self):
        with DagsterInstance.ephemeral() as instance:
            for call in (rp.apply_limits, rp.verify_instance, rp.observed_limits):
                with self.assertRaises(rp.PoolStateError):
                    call(instance)

    def test_guard_sensor_applies_verifies_and_fails_visibly(self):
        instance = self.instance()
        guard = rp.build_guard_sensor()
        self.assertEqual(guard.name, rp.GUARD_SENSOR_NAME)
        self.assertEqual(guard.minimum_interval_seconds, rp.GUARD_INTERVAL_SECONDS)
        self.assertEqual(guard.default_status.value, "RUNNING")
        result = guard(build_sensor_context(instance=instance))
        self.assertIn("corrected=6", result.skip_message)
        instance.event_log_storage.set_concurrency_slots(rp.PERSONA_LLM, 9)
        self.assertIn("corrected=1", guard(build_sensor_context(instance=instance)).skip_message)
        self.assertEqual(rp.verify_instance(instance), [])
        self.assertIn("corrected=0", guard(build_sensor_context(instance=instance)).skip_message)
        instance.event_log_storage.set_concurrency_slots("gpu", 1)
        with self.assertRaisesRegex(rp.PoolStateError, "pool gpu: not a declared pool"):
            guard(build_sensor_context(instance=instance))


class Assignments(unittest.TestCase):
    def test_every_registered_op_has_an_explicit_state(self):
        sys.path.insert(0, os.environ.get("APPSEC_DEFINITIONS_DIR", "/opt/app"))
        from definitions import defs
        report = rp.require_explicit_assignments(defs)
        self.assertEqual(report["errors"], [])
        pooled = {(item["job"], item["op"]): item["pool_id"] for item in report["pooled"]}
        for key, pool in {("evidence_index", "evidence_index_work"): rp.MEMORY,
                          ("full_review", "evidence_index_work"): rp.MEMORY,
                          ("build_execution", "build_execution_work"): rp.DOCKER,
                          ("full_review", "job_02_build_configure"): rp.DOCKER,
                          ("ossf_scorecard", "ossf_scorecard_work"): rp.NETWORK,
                          ("full_review", "job_02_ossf_scorecard"): rp.NETWORK,
                          ("nvd_reference_sync", "nvd_sync_work"): rp.NETWORK,
                          ("engagement_workflow", "scope_check"): rp.CPU,
                          ("engagement_workflow", "workflow_intake"): rp.CPU,
                          ("phase1_intake", "intake_work"): rp.CPU,
                          ("full_review", "job_02_dev_project_discovery"): rp.CPU}.items():
            self.assertEqual(pooled[key], pool, key)
        reasons = {(item["job"], item["op"]): item["reason"] for item in report["unassigned"]}
        self.assertEqual(reasons[("engagement_workflow", "workflow_config")], "coordination_only")
        self.assertEqual(reasons[("engagement_workflow", "workflow_publish")], "coordination_only")
        self.assertEqual(reasons[("full_review", "job_07_red_team_adversarial")], "worker_not_implemented")
        self.assertEqual(reasons[("orchestration_smoke", "smoke_work")], "bootstrap_diagnostic")
        # A root op in a pool would let the run coordinator hold the whole run in the queue.
        from dagster_workflow import full_review
        self.assertNotIn(("full_review", "workflow_config"), pooled)
        self.assertEqual(len(report["pooled"]) + len(report["unassigned"]),
                         sum(len([n for n in job.all_node_defs if isinstance(n, dagster.OpDefinition)])
                             for job in defs.get_repository_def().get_all_jobs()))
        self.assertIsNotNone(full_review)
        self.assertIn(rp.GUARD_SENSOR_NAME, {s.name for s in defs.get_repository_def().sensor_defs})

    def test_silent_and_malformed_states_are_errors(self):
        report = rp.inspect_assignments([support.undeclared])
        self.assertEqual(sorted(report["errors"]), [
            "undeclared.bad_reason: invalid unassigned record",
            "undeclared.pooled_and_unassigned: has a pool and an unassigned record",
            "undeclared.reason_without_state: invalid unassigned record",
            "undeclared.silent_default: no pool and no explicit unassigned record",
            "undeclared.unknown_pool: unknown pool"])
        self.assertEqual(report["unassigned"], [{"job": "undeclared", "op": "recorded_unassigned",
                                                 "reason": "coordination_only"}])
        with self.assertRaisesRegex(rp.PoolAssignmentError, "silent_default"):
            rp.require_explicit_assignments([support.undeclared])


class Contention(Case):
    def test_each_pool_admits_its_limit_and_no_more_and_state_document_verifies(self):
        instance = self.instance()
        rp.apply_limits(instance)
        result = support.run("contention", instance)
        self.assertTrue(result.success)
        records = support.read_log(self.log)
        for pool in rp.POOLS:
            mine = intervals(records, lambda r, p=pool: r["op"].startswith(p.pool_id + "_"))
            self.assertEqual(len(mine), pool.limit + 1, pool.pool_id)
            self.assertLessEqual(rp.max_overlap(mine), pool.limit, pool.pool_id)
            if pool.limit > 1:  # a limit above one is not silently serialized either
                self.assertGreaterEqual(rp.max_overlap(mine), 2, pool.pool_id)
            self.assertEqual(self.claimed(instance, pool.pool_id), 0, pool.pool_id)

        sys.path.insert(0, os.environ.get("APPSEC_DEFINITIONS_DIR", "/opt/app"))
        from definitions import defs
        document = rp.build_state(instance, defs, [result.run_id], "2026-09-21T00:00:00+00:00")
        self.assertEqual(document["errors"], [])
        self.assertEqual(document["result"], "PASS")
        self.assertEqual(validate_document(document, rp.STATE_SCHEMA_FILE), [])
        self.assertEqual(len(document["runs"][0]["steps"]), sum(rp.LIMITS.values()) + len(rp.POOLS))
        for item in document["observed_overlap"]:
            self.assertLessEqual(item["max_concurrent_steps"], item["limit"])
        self.assertIs(document["pooled_steps_recorded"], True)
        self.assertEqual(document["dagster_version"], rp.DAGSTER_VERSION)
        self.assertEqual(shape(document), shape(state_fixture()))  # the host tamper tests use a real shape
        path = self.root / "state.json"
        path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        self.assertEqual(rp.verify_state_file(path), [])
        with self.assertRaisesRegex(rp.PoolStateError, "given twice"):
            rp.build_state(instance, defs, [result.run_id, result.run_id], "2026-09-21T00:00:00+00:00")
        empty = rp.build_state(instance, defs, [], "2026-09-21T00:00:00+00:00")
        self.assertEqual((empty["result"], empty["pooled_steps_recorded"]), ("PASS", False))
        self.assertEqual(rp.build_state(instance, [], [], "2026-09-21T00:00:00+00:00")["errors"],
                         ["assignments: no op was inspected"])

        def tampered(change, rehash):
            value = deepcopy(document)
            change(value)
            if rehash:
                value["state_sha256"] = rp._state_digest(value)
            target = self.root / "tampered.json"
            target.write_text(json.dumps(value), encoding="utf-8")
            return rp.verify_state_file(target)

        self.assertEqual(tampered(lambda v: v.__setitem__("result", "FAIL"), False),
                         ["state_sha256 does not match the document", "result does not follow from the errors"])
        for change in (
            lambda v: v.__setitem__("result", "FAIL"),
            lambda v: v["observed_overlap"][0].__setitem__("max_concurrent_steps", 0),
            lambda v: v["pools"][0].__setitem__("expected_limit", 6),
            lambda v: v["pools"][1].__setitem__("observed_limit", 2),
            lambda v: v["pools"].reverse(),
            lambda v: v["outer_limits"]["expected"].__setitem__("max_concurrent_runs", 4),
            lambda v: v["errors"].append("x"),
            lambda v: v["assignments"]["errors"].append("full_review.x: no pool and no explicit unassigned record"),
            lambda v: [s.__setitem__("pool_id", rp.DOCKER) for s in v["runs"][0]["steps"]],
            lambda v: v["runs"][0]["steps"][0].__setitem__("ended", v["runs"][0]["steps"][0]["started"] - 1),
            lambda v: v["runs"].append(deepcopy(v["runs"][0])),
        ):
            self.assertTrue(tampered(change, True))
        self.assertTrue(tampered(lambda v: v.__setitem__("note", "extra"), True))
        self.assertTrue(tampered(lambda v: v.pop("foreign_pools"), True))
        (self.root / "infinite.json").write_text(
            json.dumps(document).replace(json.dumps(document["runs"][0]["steps"][0]["started"]), "-Infinity", 1),
            encoding="utf-8")
        self.assertEqual(rp.verify_state_file(self.root / "infinite.json"), [UNREADABLE])
        (self.root / "junk.json").write_text("{", encoding="utf-8")
        self.assertEqual(rp.verify_state_file(self.root / "junk.json"), [UNREADABLE])
        self.assertEqual(rp.verify_state_file(self.root / "absent.json"), [UNREADABLE])

    def test_a_saturated_pool_does_not_starve_another_pool(self):
        instance = self.instance()
        rp.apply_limits(instance)
        self.assertTrue(support.run("two_pools", instance).success)
        records = support.read_log(self.log)
        docker = sorted(intervals(records, lambda r: r["op"].startswith("docker_queue_")))
        network = intervals(records, lambda r: r["op"] == "network_quick")
        self.assertEqual(rp.max_overlap(docker), 1)
        self.assertLess(network[0][1], docker[-1][0])  # done before the docker queue drained

    def test_the_executor_cap_still_binds_below_the_pool_limit(self):
        instance = self.instance()
        rp.apply_limits(instance)
        self.assertTrue(support.run("executor_cap", instance).success)
        capped = intervals(support.read_log(self.log), lambda r: r["op"].startswith("cpu_capped_"))
        self.assertEqual(len(capped), 3)
        self.assertLessEqual(rp.max_overlap(capped), 2)

    def test_an_unapplied_pool_gets_the_floor_not_unlimited(self):
        instance = self.instance()  # limits deliberately not applied: fresh or wiped storage
        self.assertTrue(support.run("executor_cap", instance).success)
        capped = intervals(support.read_log(self.log), lambda r: r["op"].startswith("cpu_capped_"))
        self.assertEqual(rp.max_overlap(capped), rp.DEFAULT_POOL_LIMIT)
        self.assertEqual(rp.observed_limits(instance)[rp.CPU], {"limit": rp.DEFAULT_POOL_LIMIT, "from_default": True})
        self.assertIn("pool cpu: DEFAULTED expected=3 observed=1", rp.verify_instance(instance))
        rp.apply_limits(instance)
        self.assertEqual(rp.observed_limits(instance)[rp.CPU], {"limit": 3, "from_default": False})

    def test_two_engagements_take_turns_on_one_pool(self):
        rp.apply_limits(self.instance())
        results = {}

        def engagement(name, delay):
            time.sleep(delay)
            with DagsterInstance.from_config(str(self.home)) as instance:
                results[name] = support.run("engagement_chain", instance, tags={"engagement_run_id": name})

        threads = [threading.Thread(target=engagement, args=("eng-a", 0)),
                   threading.Thread(target=engagement, args=("eng-b", 1.0))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=180)
        self.assertTrue(results["eng-a"].success and results["eng-b"].success)
        records = support.read_log(self.log)
        self.assertEqual(rp.max_overlap(intervals(records, lambda r: True)), 1)
        owner = {results[name].run_id: name for name in results}
        grants = [owner[record["run_id"]] for record in records if record["what"] == "start"]
        self.assertEqual(sorted(grants), ["eng-a", "eng-a", "eng-b", "eng-b"])
        # FIFO by request: neither engagement gets its second slot before the other got its first.
        self.assertNotEqual(grants[0], grants[1])
        sys.path.insert(0, os.environ.get("APPSEC_DEFINITIONS_DIR", "/opt/app"))
        from definitions import defs
        document = rp.build_state(self.instance(), defs, [r.run_id for r in results.values()],
                                  "2026-09-21T00:00:00+00:00")
        self.assertEqual([run["engagement_run_id"] for run in document["runs"]], ["eng-a", "eng-b"])
        self.assertEqual(document["errors"], [])
        # Wrong party: the same two runs claiming to be one engagement is a serialization breach.
        for run in document["runs"]:
            run["engagement_run_id"] = "eng-a"
        self.assertIn("engagement serialization: pooled steps of two runs of one engagement overlap",
                      rp._state_errors(document))


class Release(Case):
    def test_a_failed_step_and_a_killed_step_release_their_slot(self):
        instance = self.instance()
        rp.apply_limits(instance)
        for name in ("failing", "crashing"):
            self.assertFalse(support.run(name, instance).success)
            self.assertEqual(self.claimed(instance, rp.DOCKER), 0, name)
        started = time.monotonic()
        self.assertTrue(support.run("next_in_line", instance).success)
        self.assertLess(time.monotonic() - started, 30)

    def worker(self, home):
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import resource_pools_support as s; "
                "s.worker_main(sys.argv[2], 'long_running')")
        process = subprocess.Popen([sys.executable, "-B", "-c", code, str(TESTS), str(home)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.addCleanup(lambda: (os.killpg(process.pid, signal.SIGKILL) if process.poll() is None else None,
                                 process.wait()))
        deadline = time.monotonic() + 90
        while not support.read_log(self.log):
            self.assertIsNone(process.poll(), "run worker ended before its step started")
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.2)
        return process, support.read_log(self.log)[0]

    def test_a_canceled_run_releases_its_slot(self):
        instance = self.instance()
        rp.apply_limits(instance)
        process, record = self.worker(self.home)
        self.assertEqual(self.claimed(instance, rp.DOCKER), 1)
        os.kill(process.pid, signal.SIGINT)  # what run termination delivers to the run worker
        process.wait(timeout=90)
        self.assertTrue(instance.get_run_by_id(record["run_id"]).is_finished)
        self.assertEqual(self.claimed(instance, rp.DOCKER), 0)
        self.assertTrue(support.run("next_in_line", instance).success)

    def test_a_killed_run_worker_leaks_its_slot_until_run_monitoring_frees_it(self):
        from dagster._daemon.monitoring.concurrency import execute_concurrency_slots_iteration
        import logging
        home = make_home(self.root / "home-fast-release", free_slots_seconds=1)
        instance = self.instance(home)
        rp.apply_limits(instance)
        process, record = self.worker(home)
        os.killpg(process.pid, signal.SIGKILL)  # run worker and step process lost without cleanup
        process.wait(timeout=30)
        self.assertEqual(self.claimed(instance, rp.DOCKER), 1)  # nothing in the run could free it
        run = instance.get_run_by_id(record["run_id"])
        self.assertFalse(run.is_finished)
        instance.report_run_failed(run)  # what run monitoring does for a lost run worker
        time.sleep(2.5)

        class Workspace:  # the daemon passes its workspace context; only `.instance` is read
            pass
        Workspace.instance = instance
        list(execute_concurrency_slots_iteration(Workspace, logging.getLogger("b15")))
        self.assertEqual(self.claimed(instance, rp.DOCKER), 0)
        self.assertTrue(support.run("next_in_line", instance).success)


if __name__ == "__main__":
    unittest.main()
