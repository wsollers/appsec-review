"""Entrypoints run only inside the acceptance supervisor's owned process tree."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from urllib.request import Request, urlopen
from uuid import uuid4

from appsec_review.observability import write_run_metrics
from appsec_review.runtime import GraphRunner
from appsec_review.runtime.resources import ResourceAdmission
from appsec_review.storage import atomic_json

from . import jobs
from .support import CHECKOUT, MODULE, read, wait_for, working_directory


def dagster_run(kind):
    from dagster import DagsterInstance, reconstructable
    from dagster._core.execution.api import execute_run
    from dagster._serdes import serialize_value

    root = jobs.root()
    definitions = {"propagation": jobs.define_propagation, "recording": jobs.define_recording,
                   "fail_fast": jobs.define_fail_fast, "sensor": jobs.define_sensor}
    definition = definitions[kind]
    reconstructed = reconstructable(definition)
    dagster_root = root / "dagster"
    dagster_root.mkdir()
    tags, run_config = {}, {}
    run_id = str(uuid4())
    if kind == "propagation":
        tags = {"appsec/profile": os.environ.get("APPSEC_PROCESS_PROFILE", "prod"),
                "appsec/overlay": str(root / "test" / "acceptance" / "capacity.toml")}
    if kind == "fail_fast":
        from appsec_review.config import load_config
        from appsec_review.runtime import execution_safety as safety

        config = load_config(root / "appsec-review.toml", profile="dev",
                             overlay=str(root / "test" / "acceptance" / "capacity.toml"))
        resolved = json.loads(config.resolved_json)
        envelope = safety.policy(run_id, {
            "source_commit": "a" * 40, "target_commit": "b" * 40,
            "configuration": {"base_sha256": config.source_sha256, "profile": "dev",
                              "profile_sha256": resolved["configuration_profile"].get("sha256"),
                              "overlay_sha256": resolved["configuration_overlay"]["sha256"]}})
        run_config = {"execution": {"config": {"safety": envelope}}}
        tags = {"appsec/safety_identity": safety.identity(envelope), "dagster/max_retries": "0"}
    with DagsterInstance.local_temp(tempdir=str(dagster_root)) as instance:
        atomic_json(root / "instance.json", {"ref": serialize_value(instance.get_ref())})
        run = instance.create_run_for_job(
            reconstructed.get_definition(), run_id=run_id, tags=tags, run_config=run_config)
        jobs.marker("dagster-started", run_id=run.run_id)
        result = execute_run(reconstructed, run, instance, raise_on_error=False)
        current = instance.get_run_by_id(run_id)
        atomic_json(root / f"{kind}.json", {
            "success": result.success, "run_id": run_id, "tags": dict(current.tags),
            "queue_timestamp_available": isinstance(getattr(current, "create_timestamp", None), (int, float)),
            "events": [{"type": event.event_type_value, "step": event.step_key}
                       for event in result.all_events],
        })


def local_run(action, arguments):
    from appsec_review.jobs.cataloging import source_fingerprint
    from appsec_review.jobs.job_review_intake import build_job as intake

    root, config = jobs.root(), jobs.config()
    if action == "resume-selection":
        from appsec_review.config.run_selection import RunConfigurations
        run_id = arguments[0]
        manifest = read(config.runtime.runs_dir / run_id / "data/configuration/manifest.json")
        config = RunConfigurations(config).for_tags({
            "appsec/profile": manifest["selection"]["profile"],
            "appsec/overlay": manifest["selection"]["overlay"]})
        from appsec_review.runtime.launch import begin, launch_inputs
        from appsec_review.runtime.runner import JobRunner
        job = jobs.fixture_job((("first", jobs.propagation), ("second", jobs.propagation)))
        claim = begin(JobRunner(config), job, launch_inputs(
            job, target=root / "target", upstream_handoffs={}), run_id=run_id,
            trigger="manual", orchestration={"system": "local"})
        atomic_json(root / f"{action}.json", {
            **dict(claim), "observed_configuration": {
                "resolved_sha256": config.resolved_sha256, "profile": config.profile}})
        return
    if action in {"replay-local", "replay-exhaust"}:
        units = [jobs.fixture_job((("first", jobs.model_unit),))]
    else:
        units = [intake(), jobs.recovery_job(action == "interrupt-worker")]
    admission = ResourceAdmission(config.runtime.metadata_dir, config.review_policy.resources)
    removed = admission.reconcile(lambda _: False)
    kwargs = {}
    if action == "resume-worker":
        kwargs["run_id"] = read(root / "worker-ready.json")["run_id"]
    try:
        if action in {"replay-local", "replay-exhaust"}:
            from appsec_review.runtime.launch import launch, launch_inputs
            from appsec_review.runtime.runner import JobRunner
            outcome_job = launch(JobRunner(config), units[0], launch_inputs(
                units[0], target=root / "target", upstream_handoffs={}), run_id=None)
            outcome = {"run_id": outcome_job["status"]["run_id"], "job": outcome_job}
        else:
            outcome = GraphRunner(config, units).run(
                target_root=root / "target", source_fingerprint=source_fingerprint(root / "target"),
                **kwargs)
    except RuntimeError as error:
        if action != "replay-exhaust":
            raise
        atomic_json(root / f"{action}.json", {"error": str(error)})
        return
    write_run_metrics(config.runtime.runs_dir / outcome["run_id"])
    atomic_json(root / f"{action}.json", {**dict(outcome), "reconciled": removed})


def submission(action, arguments):
    sys.path.insert(0, str(CHECKOUT / "deploy" / "dagster" / "bin"))
    import review_run

    root = jobs.root()
    review_run.ROOT = root
    url, run_id = arguments
    identity = {"url": url, "fixture": "owned-loopback-submission"}
    with review_run.submission_lock(root):
        if action == "refuse-submission":
            try:
                review_run.begin_submission(root, identity, run_id)
            except ValueError as error:
                atomic_json(root / f"{action}.json", {"refused": str(error)})
                return
            raise AssertionError("an unresolved submission was admitted")
        if action == "begin-next":
            record = review_run.begin_submission(root, identity, run_id)
            atomic_json(root / f"{action}.json", record)
            return
        record = review_run.begin_submission(root, identity, run_id)
        jobs.marker("intent-persisted")
        if action == "submit-intent":
            wait_for(lambda: (root / "release-intent").exists(), timeout=30)
        payload = {"query": "mutation FixtureLaunch { launchRun }", "run_id": run_id,
                   "identity_sha256": record["identity_sha256"]}
        with urlopen(Request(url, data=json.dumps(payload).encode(),
                             headers={"Content-Type": "application/json"}), timeout=15) as response:
            response.read()
        jobs.marker("ack-received")
        if action == "submit-ack":
            wait_for(lambda: (root / "release-ack").exists(), timeout=30)
        record["state"] = "SUBMITTED"
        review_run.write_submission(root, record)


def main():
    action, *arguments = sys.argv[1:]
    if action not in {"tree", "grandchild"} and sys.stdin.readline().strip() != "start":
        raise RuntimeError("fixture supervisor did not open the startup gate")
    if action in {"propagation", "recording", "fail_fast", "sensor"}:
        dagster_run(action)
    elif action in {"interrupt-worker", "resume-worker", "replay-local", "replay-exhaust", "resume-selection"}:
        local_run(action, arguments)
    elif action == "tree":
        child = subprocess.Popen([sys.executable, "-m", MODULE, "grandchild"],
                                 stdin=subprocess.DEVNULL)
        jobs.marker("child-ready", child_pid=child.pid)
        try:
            child.wait(timeout=35)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
    elif action == "grandchild":
        jobs.marker("grandchild-ready")
        wait_for(lambda: (jobs.root() / "release-grandchild").exists(), timeout=35)
    elif action in {"submit-intent", "submit-ack", "refuse-submission", "begin-next"}:
        submission(action, arguments)
    elif action == "reconcile-submission":
        sys.path.insert(0, str(CHECKOUT / "deploy" / "dagster" / "bin"))
        import review_run
        review_run.ROOT = jobs.root()
        url, run_id = arguments
        review_run.reconcile_submission(run_id, url)
        atomic_json(jobs.root() / f"{action}.json", review_run.read_submission(jobs.root()))
    elif action == "storage-failure":
        from unittest.mock import patch
        sys.path.insert(0, str(CHECKOUT / "deploy" / "dagster" / "bin"))
        import review_run
        url, run_id, fault = arguments
        try:
            with patch(f"appsec_review.storage.atomic.os.{fault}",
                       side_effect=OSError(f"fixture {fault} unavailable")):
                with review_run.submission_lock(jobs.root()):
                    review_run.begin_submission(jobs.root(), {"url": url}, run_id)
                    with urlopen(Request(url, data=b'{"unexpected":"dispatch"}'), timeout=2):
                        raise AssertionError("unjournaled dispatch succeeded")
        except OSError as error:
            atomic_json(jobs.root() / f"{action}.json", {"error": str(error)})
        else:
            raise AssertionError("submission durability failure was ignored")
    elif action == "mcp":
        from appsec_review.mcp.stdio import main as stdio
        raise SystemExit(stdio(arguments))
    elif action == "unix-listener":
        import socket
        from appsec_review.runtime import execution_safety as safety

        envelope = safety.policy(str(uuid4()), {
            "source_commit": "a" * 40, "target_commit": "b" * 40, "configuration": {}})
        with safety.AdmissionGuardian(envelope, jobs.root() / "first",
                                      resolved_config_sha256="c" * 64) as guardian:
            with safety.safety_scope(envelope), safety.operation("fixture.peer"):
                pass
            try:
                with safety.AdmissionGuardian(envelope, jobs.root() / "replacement",
                                              resolved_config_sha256="c" * 64):
                    raise AssertionError("second real listener replaced the first")
            except OSError:
                pass
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(2)
                peer.connect(safety._address(envelope))
            if not guardian.stopped.wait(5):
                raise AssertionError("peer disconnect did not close admission")
            try:
                safety.SafetyClient(envelope).request("admit", action="after-disconnect")
            except safety.ReviewStopped:
                pass
            else:
                raise AssertionError("disconnect allowed subsequent admission")
        atomic_json(jobs.root() / f"{action}.json", guardian.state)
    elif action == "powershell-dispatch":
        import shutil
        import tempfile
        from pathlib import Path

        executable = shutil.which("powershell.exe")
        if not executable:
            raise RuntimeError("required Windows PowerShell executable is unavailable")
        native_root = Path(tempfile.mkdtemp(prefix="ps-", dir=working_directory(jobs.root())))
        output = native_root / "wsl-arguments.txt"
        result = subprocess.run([
            executable, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(CHECKOUT / "tests/fixtures/process_lifecycle/powershell_dispatch.ps1"),
            "-Common", str(CHECKOUT / "scripts/lib/common.ps1"), "-Output", str(output)],
            cwd=working_directory(jobs.root()), capture_output=True, text=True, timeout=15,
            env={**os.environ, "APPSEC_REPO_ROOT": str(CHECKOUT),
                 "TEMP": str(native_root), "TMP": str(native_root)})
        if output.exists():
            shutil.copyfile(output, jobs.root() / output.name)
        atomic_json(jobs.root() / f"{action}.json", {
            "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
            "native_root": str(native_root)})
    else:
        raise ValueError(f"unknown fixture action: {action}")


if __name__ == "__main__":
    main()
