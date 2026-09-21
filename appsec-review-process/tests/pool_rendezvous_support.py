"""Shared builders, hostile invokers and a killable coordinator for the rendezvous tests (C02).

Not a test module. Every pool is a real C01 expansion of real B13/B14 request templates, every
instance is launched through the real adapters, and a hostile case is the honest path plus exactly
one departure. Nothing here sleeps to synchronize: invokers signal and block on events.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import container_execution as ce  # noqa: E402
import container_execution_support as b13  # noqa: E402
import persona_invocation as pi  # noqa: E402
import persona_invocation_support as b14  # noqa: E402
import pool_rendezvous as pr  # noqa: E402
import pool_specification as ps  # noqa: E402
import pool_specification_support as c01  # noqa: E402

MARKER = c01.MARKER
HANG_SECONDS = 60          # a blocked test invoker gives up after this long: a hang fails, it never wedges


class RendezvousWorkspace(c01.PoolWorkspace):
    """C01's workspace plus a rendezvous parent that is a sibling of everything a worker can reach."""

    def __init__(self, base: Path) -> None:
        super().__init__(base)
        self.rendezvous_parent = base / "rendezvous"
        self.rendezvous_parent.mkdir()
        self.cancel = pr.PoolCancel()

    def persona_runtime(self, invoker=None, **over) -> pi.PersonaRuntime:
        fields = self.persona.runtime_fields(invoker=invoker or pi.FixtureInvoker(), cancel=self.cancel)
        fields.update(over)
        return pi.PersonaRuntime(**fields)

    def container_runtime(self, **over) -> ce.ContainerRuntime:
        return b13.runtime(**{"cancel": self.cancel, **over})

    def runtime_fields(self, invoker=None, **over) -> dict:
        fields = {"rendezvous_parent": self.rendezvous_parent, "container_runtime": self.container_runtime(),
                  "persona_runtime": self.persona_runtime(invoker), "cancel": self.cancel,
                  "max_parallel": pr.MAX_PARALLEL, "wait_limit_seconds": HANG_SECONDS, "drain_seconds": 5}
        fields.update(over)
        return fields

    def runtime(self, invoker=None, **over) -> pr.RendezvousRuntime:
        return pr.RendezvousRuntime(**self.runtime_fields(invoker, **over))

    def expand(self, spec: dict) -> ps.ExpansionPlan:
        return ps.expand_pool(spec, context=self.context())

    def arguments(self, spec: dict) -> dict:
        return {"expected_spec": spec, "context": self.context()}

    def run(self, spec: dict, plan: ps.ExpansionPlan, invoker=None, **over):
        return pr.run_rendezvous(self.root(plan), **self.arguments(spec), runtime=self.runtime(invoker, **over))

    def host_facts(self) -> pr.ContainerHostFacts:
        """What every launch in these tests uses: the facts of ``container_runtime()``."""
        return pr.host_facts_of(self.container_runtime())

    def reader_arguments(self, spec: dict, **over) -> dict:
        return {**self.arguments(spec), "rendezvous_parent": self.rendezvous_parent,
                "host_facts": self.host_facts(), **over}

    def classifier_arguments(self, plan: ps.ExpansionPlan) -> dict:
        return {"pool_root": self.root(plan), "context": self.context(), "host_facts": self.host_facts()}

    def verify(self, spec: dict, plan: ps.ExpansionPlan, **over) -> list:
        return pr.verify_manifest(self.root(plan), **self.reader_arguments(spec, **over))

    def load(self, spec: dict, plan: ps.ExpansionPlan, **over):
        return pr.load_verified_manifest(self.root(plan), **self.reader_arguments(spec, **over))

    def manifest_path(self, plan: ps.ExpansionPlan) -> Path:
        return pr.rendezvous_root(plan, self.rendezvous_parent) / pr.MANIFEST_FILE

    def result_path(self, plan: ps.ExpansionPlan, index: int) -> Path:
        entry = plan.manifest["instances"][index]
        name = pi.RESULT_FILE if entry["worker_kind"] == ps.PERSONA else ce.RESULT_FILE
        return self.instance_root(plan, index).joinpath(*entry["log_path"].split("/"), name)


def ids(plan: ps.ExpansionPlan) -> list:
    return [entry["instance_id"] for entry in plan.manifest["instances"]]


def states(manifest) -> list:
    return [record["state"] for record in manifest["instances"]]


# ---- invokers: the honest fixture, routed per instance, then exactly one departure ----------------

class Routed:
    """One runtime has one invoker; this one picks a behaviour by the instance's attempt id and
    records, in order, every instance it was invoked for."""
    invoker_id = pi.FixtureInvoker.invoker_id

    def __init__(self, routes: dict | None = None, default=None) -> None:
        self.routes, self.default = dict(routes or {}), default or pi.FixtureInvoker()
        self.invoked: list = []
        self._guard = threading.Lock()

    def invoke(self, package, *, output_root, cancel):
        attempt = package.request["attempt_id"]
        with self._guard:
            self.invoked.append(attempt)
        self.routes.get(attempt, self.default).invoke(package, output_root=output_root, cancel=cancel)


class Gated(pi.FixtureInvoker):
    """Signals ``started``, blocks until ``release`` (or, when it honours cancel, until the adapter
    cancels it), then behaves as the honest fixture."""

    def __init__(self, honor_cancel: bool = True, before=None) -> None:
        self.started, self.release, self.finished = threading.Event(), threading.Event(), threading.Event()
        self.honor_cancel, self.before = honor_cancel, before

    def invoke(self, package, *, output_root, cancel):
        if self.before is not None:
            self.before()
        self.started.set()
        waited = 0.0
        while not self.release.is_set() and not (self.honor_cancel and cancel.is_set()) and waited < HANG_SECONDS:
            self.release.wait(0.01)
            waited += 0.01
        try:
            if self.release.is_set():
                super().invoke(package, output_root=output_root, cancel=cancel)
        finally:
            self.finished.set()


def pool_threads() -> list:
    return [thread for thread in threading.enumerate() if thread.name.startswith("pool-instance-")]


def join_pool_threads(timeout: float = HANG_SECONDS) -> None:
    for thread in pool_threads():
        thread.join(timeout)
        if thread.is_alive():
            raise AssertionError("a pool worker thread is still alive")


# ---- scripted docker routed per instance ----------------------------------------------------------

class RoutedDocker:
    """B13's ScriptedDocker (test_container_execution), one per container name, so several tool
    instances of one pool can end differently. Anything unrouted is the honest default."""

    def __init__(self, scripted_class, routes: dict | None = None, default=None) -> None:
        self.routes = dict(routes or {})
        self.default = default or scripted_class()
        self.started: list = []

    def _for(self, texts) -> object:
        for text in texts:
            for name, scripted in self.routes.items():
                if name in text:
                    return scripted
        return self.default

    def docker(self, runtime, arguments):
        return self._for(arguments).docker(runtime, arguments)

    def child(self, spec, *, cancel=None, observer=None):
        scripted = self._for(spec.argv)
        self.started.append(spec.argv[3])
        hook = getattr(scripted, "before_child", None)
        if hook is not None:
            hook(cancel)
        return scripted.child(spec, cancel=cancel, observer=observer)

    def patches(self):
        from unittest import mock
        return (mock.patch.object(ce, "_docker", side_effect=self.docker),
                mock.patch.object(ce.deterministic_child, "execute_child", side_effect=self.child))


def container_name(plan: ps.ExpansionPlan, index: int) -> str:
    entry = plan.manifest["instances"][index]
    return ce.container_name(entry["run_id"], entry["job_id"], entry["attempt_id"])


# ---- a coordinator in its own process, so that it can really die ----------------------------------

def coordinator_command(ws: RendezvousWorkspace, spec: dict, block_at: str) -> list:
    """argv of a real coordinator over this workspace that blocks forever inside the instance
    ``block_at`` (a persona invoker, or the docker client of a tool instance) after printing one
    line. The parent reads that line and kills the process."""
    arguments = {"base": str(ws.base), "spec": spec, "block_at": block_at}
    return [sys.executable, "-B", str(Path(__file__).resolve()), json.dumps(arguments)]


class _BlockForever(pi.FixtureInvoker):
    def invoke(self, package, *, output_root, cancel):
        print("BLOCKED", flush=True)
        threading.Event().wait()


def _coordinator(arguments: dict) -> None:
    """Rebuilds the parent's context from its paths (nothing is created) and runs a real,
    sequential rendezvous."""
    ws = RendezvousWorkspace.__new__(RendezvousWorkspace)
    ws.base = Path(arguments["base"])
    ws.persona = b14.Workspace.__new__(b14.Workspace)
    ws.persona.base = ws.base / "persona"
    ws.persona.prompts, ws.persona.data = ws.persona.base / "process", ws.persona.base / "data"
    ws.data, ws.targets = ws.persona.data, ws.base / "targets"
    ws.pool_parent, ws.rendezvous_parent = ws.data / "pools" / "wave-1", ws.base / "rendezvous"
    ws.cancel = pr.PoolCancel()
    spec = arguments["spec"]
    plan = ps.plan_expansion(spec, context=ws.context())
    real = ce.deterministic_child.execute_child

    def child(spec_, *, cancel=None, observer=None):
        if ce.container_name(spec["run_id"], spec["job_id"], arguments["block_at"]) in spec_.argv:
            print("BLOCKED", flush=True)
        return real(spec_, cancel=cancel, observer=observer)

    ce.deterministic_child.execute_child = child
    ws.run(spec, plan, Routed({arguments["block_at"]: _BlockForever()}), max_parallel=1)


if __name__ == "__main__":
    _coordinator(json.loads(sys.argv[1]))
