"""One explicit native operator path; no Compose fallback or privileged provisioning."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import json
import logging
import os
from pathlib import Path
import subprocess
import time
from urllib.request import Request, urlopen
from urllib.error import URLError
from uuid import UUID

from appsec_review.config import load_config
from appsec_review.config.native_dagster import load_native_dagster_config
from appsec_review.container_runtime.buildkit_worker import private_path, process_token
from appsec_review.container_runtime.native_client import NativeClient, NativeClientContract
from appsec_review.observability import EventLog
from appsec_review.orchestration.dagster.native import child_environment, prepare_instance
from appsec_review.orchestration.dagster.native_lifecycle import (
    NativeSupervisor, active_runs, bounded_postgres, database_deadline,
)
from appsec_review.runtime.resources import ResourceAdmission, Reservation


def verify_application_cgroup(contract: NativeClientContract) -> None:
    if contract.host_cgroup is None:
        raise RuntimeError("native application lacks its persistent host cgroup contract")
    root = Path(contract.host_cgroup)
    private_path(root, uid=0)
    membership = Path("/proc/self/cgroup").read_text().splitlines()
    if len(membership) != 1 or not membership[0].startswith("0::/"):
        raise RuntimeError("native application requires unified cgroup-v2 accounting")
    group = Path("/sys/fs/cgroup") / membership[0][4:]
    quota, period = (root / "cpu.max").read_text().split()
    memory = (root / "memory.max").read_text().strip()
    if (not group.is_relative_to(root)
            or not quota.isdecimal() or not period.isdecimal() or int(period) <= 0
            or not 0 < int(quota) <= contract.host_cpu * int(period)
            or not memory.isdecimal() or not 0 < int(memory) <= contract.host_memory_mb * 1024**2
            or (root / "memory.swap.max").read_text().strip() != "0"):
        raise RuntimeError("native app/controller overhead is outside its persistent capped reservation")


def verify_owned_listener(owner: dict, port: int) -> bool:
    pid = owner["pid"]
    if process_token(pid) != owner["start_token"]:
        raise RuntimeError("native endpoint process generation changed")
    if os.readlink(f"/proc/{pid}/ns/net") != os.readlink("/proc/self/ns/net"):
        raise RuntimeError("native endpoint changed its network namespace")
    descriptors = set()
    for index, path in enumerate(Path(f"/proc/{pid}/fd").iterdir()):
        if index >= 4096:
            raise RuntimeError("native endpoint descriptor proof exceeds its bound")
        try:
            descriptors.add(os.readlink(path))
        except FileNotFoundError:
            continue
    with Path(f"/proc/{pid}/net/tcp").open("rb") as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise RuntimeError("native endpoint socket table exceeds its proof bound")
    listeners = []
    for line in data.decode("ascii").splitlines()[1:]:
        fields = line.split()
        address, number = fields[1].split(":")
        if fields[3] == "0A" and int(number, 16) == port:
            if address != "0100007F":
                raise RuntimeError("native endpoint is not restricted to IPv4 loopback")
            listeners.append("socket:[" + fields[9] + "]")
    if process_token(pid) != owner["start_token"]:
        raise RuntimeError("native endpoint process changed during proof")
    if not listeners:
        return False
    if len(listeners) != 1 or listeners[0] not in descriptors:
        raise RuntimeError("native endpoint belongs to a foreign process")
    return True


class NativeReadiness:
    def __init__(self, config, instance):
        self.config, self.instance = config, instance
        self.contract = NativeClientContract.load(Path(config.engine_contract))
        application = load_config(config.review_config)
        if (self.contract.uid != config.client_uid
                or self.contract.resources != application.review_policy.resources
                or self.contract.binding["project_id"] != application.review_policy.project_id
                or Path(self.contract.run_root).parent != application.runtime.runs_dir.resolve()
                or not self.contract.image_ids):
            raise ValueError("native operator contract differs from the configured review")
        self.client = NativeClient(self.contract)
        self.server_id = None

    def before_start(self):
        verify_application_cgroup(self.contract)
        self.before_stop()
        # Inspect through the same lease-checked broker as later tools, never ambient Docker.
        admission = ResourceAdmission(Path(self.contract.metadata_root), self.contract.resources,
                                      require_container_removal=True)
        events = EventLog(Path(self.config.dagster_home) / "native-preflight.jsonl")
        with admission.reserve(Reservation(1, 1 + self.contract.resources.staging_memory_mb),
                               events=events, action="native.operator.preflight", timeout_seconds=60):
            for image_id in self.contract.image_ids:
                self.client.run(("docker", "image", "inspect", image_id, "--format", "{{.Id}}"), 60)

    def connected(self):
        from dagster._grpc.client import DagsterGrpcClient
        from dagster._core.errors import DagsterUserCodeUnreachableError

        with database_deadline():
            self.instance.get_runs(limit=1)
        state = json.loads((Path(self.config.dagster_home) / "native-processes.json").read_bytes())
        endpoints = [(state["processes"]["code-location"], self.config.grpc_port),
                     (state["processes"]["webserver"], self.config.webserver_port)]
        if not all(verify_owned_listener(owner, port) for owner, port in endpoints):
            return False
        client = DagsterGrpcClient(port=self.config.grpc_port, host="127.0.0.1")
        try:
            server_id = client.get_server_id(timeout=5)
            if not server_id or self.server_id not in {None, server_id}:
                raise RuntimeError("native gRPC server identity is unavailable")
            request = Request(f"http://127.0.0.1:{self.config.webserver_port}/graphql",
                              data=b'{"query":"{ version }"}', headers={"Content-Type": "application/json"})
            with urlopen(request, timeout=5) as response:
                data = response.read(65537)
                if response.status != 200 or len(data) > 65536:
                    raise RuntimeError("native webserver readiness response is invalid")
        except (DagsterUserCodeUnreachableError, URLError) as error:
            logging.getLogger(__name__).warning("NATIVE_READINESS_UNAVAILABLE type=%s", type(error).__name__)
            return False
        if not isinstance(json.loads(data).get("data", {}).get("version"), str):
            raise RuntimeError("native webserver did not return its GraphQL readiness result")
        if not all(verify_owned_listener(owner, port) for owner, port in endpoints):
            raise RuntimeError("native endpoint disappeared during readiness")
        self.server_id = server_id
        return True

    def before_stop(self):
        if active_runs(self.instance):
            raise RuntimeError("native stop/start refused while a review or sync is active")

    def shutdown_complete(self):
        self.before_stop()
        # All app descendants inherit this host subtree. Broker/daemon baseline is not released here.
        root = Path(self.contract.host_cgroup)
        own = os.getpid()
        for path in root.rglob("cgroup.procs"):
            for text in path.read_text().splitlines():
                pid = int(text)
                if pid == own or pid == self.contract.broker_pid:
                    continue
                # Root-owned engine helpers remain accounted in the persistent lifetime.
                if Path(f"/proc/{pid}").stat().st_uid == self.contract.uid:
                    return False
        return True


def launch_command(config, contract, run_id: str) -> tuple[str, ...]:
    if str(UUID(run_id)) != run_id:
        raise ValueError("native launch requires a canonical Dagster UUID")
    tags = json.dumps({"appsec/application_run_id": contract.binding["run_id"]}, separators=(",", ":"))
    return (config.python_executable, "-m", "dagster", "job", "launch",
            "-w", str(Path(config.dagster_home) / "workspace.yaml"),
            "-l", config.location_name, "-j", "wave1_review", "--run-id", run_id, "--tags", tags)


def execute(config_path: Path, run_id: str, *, instance, readiness=None, supervisor=None,
            launch=subprocess.run, sleep=time.sleep) -> int:
    config = load_native_dagster_config(config_path)
    readiness = readiness or NativeReadiness(config, instance)
    supervisor = supervisor or NativeSupervisor(config_path, readiness)
    with database_deadline():
        existing = instance.get_run_by_id(run_id)
    if existing is not None:
        raise RuntimeError("native Dagster run ID already exists; refusing duplicate submission")
    command = launch_command(config, readiness.contract, run_id)
    environment = child_environment(config_path, os.environ)
    environment["APPSEC_REVIEW_TARGET"] = readiness.contract.target_root
    # Persist submission intent before the CLI can create or launch a Dagster run.
    from appsec_review.storage import atomic_json
    from appsec_review.orchestration.dagster.native import _sync_directory

    intent = Path(config.dagster_home) / "native-submission.json"
    if intent.exists() or intent.is_symlink():
        raise RuntimeError("native submission intent requires explicit reconciliation")
    supervisor.start()
    atomic_json(intent, {"run_id": run_id, "state": "SUBMITTING", "command": list(command)})
    _sync_directory(intent.parent)
    try:
        supervisor.heartbeat()
        readiness.before_stop()
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="native-submit") as pool:
            future = pool.submit(launch, command, cwd=config.repository_root, env=environment,
                                 stdin=subprocess.DEVNULL, timeout=60, check=True)
            while True:
                try:
                    future.result(timeout=1)
                    break
                except FutureTimeout:
                    if future.done():
                        raise
                    supervisor.heartbeat()
        atomic_json(intent, {"run_id": run_id, "state": "SUBMITTED", "command": list(command)})
        _sync_directory(intent.parent)
        while True:
            supervisor.heartbeat()
            with database_deadline():
                run = instance.get_run_by_id(run_id)
            if run is None:
                raise RuntimeError("native submitted run identity is unavailable")
            if run.is_finished:
                result = 0 if run.status.value == "SUCCESS" else 1
                break
            sleep(1)
        supervisor.stop()
        return result
    except BaseException:
        # No automatic stop of code-location/run children or release of persistent reservations.
        atomic_json(intent, {"run_id": run_id, "state": "UNKNOWN", "command": list(command)})
        _sync_directory(intent.parent)
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "run", "status", "stop"))
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--run-id")
    args = parser.parse_args(argv)
    if args.action == "prepare":
        print(json.dumps(prepare_instance(args.config)))
        return 0
    config = load_native_dagster_config(args.config)
    if args.action == "status":
        print(json.dumps(NativeSupervisor(args.config, None).status()))
        return 0
    if args.action == "run" and not args.run_id:
        parser.error("run requires --run-id")
    # Native instance selection is explicit; never borrow ambient DAGSTER_HOME.
    from dagster import DagsterInstance
    with ExitStack() as stack:
        stack.enter_context(bounded_postgres())
        with database_deadline():
            instance = stack.enter_context(DagsterInstance.from_config(config.dagster_home))
        if args.action == "stop":
            readiness = NativeReadiness(config, instance)
            print(json.dumps(NativeSupervisor(args.config, readiness).stop()))
            return 0
        return execute(args.config, args.run_id, instance=instance)


if __name__ == "__main__":
    raise SystemExit(main())
