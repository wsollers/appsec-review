"""Shared builders and invokers for the OWASP dispatch tests (T10). Not a test module.

Every fixture is a producible state. The upstream chain is the one T06-T09 tests build: T03 and T04
publications written the way ``test_owasp_validator_handoff`` writes them, then the REAL T05
(``owasp_batching.build``) and the REAL T06 (``owasp_validator_handoff.build``). Cells run through the
real C01 expansion, the real C02 rendezvous and the real B14 adapter; nothing of those layers is
mocked. The honest invoker writes a candidate T07 really accepts, built with T07's own test
helpers from NOTHING but the bytes B14 handed it. A hostile invoker is the honest one plus exactly
one departure.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

PROCESS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROCESS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import execution_state  # noqa: E402
import owasp_applicability  # noqa: E402
import owasp_batching  # noqa: E402
import owasp_dispatch as od  # noqa: E402
import owasp_validator_handoff  # noqa: E402
import owasp_validator_result  # noqa: E402
import persona_invocation as pi  # noqa: E402
import persona_invocation_support as b14  # noqa: E402
import pool_rendezvous as pr  # noqa: E402
import test_owasp_validator_handoff as t06  # noqa: E402
import test_owasp_validator_result as t07  # noqa: E402

write_json, sha = t06.write_json, t06.sha
MARKER = b14.MARKER
INJECTION = b14.INJECTION
NOW = b14.NOW
MODEL = b14.MODEL
SNAPSHOT = b14.SNAPSHOT
HANG_SECONDS = 60
VALIDATOR_PROFILE = "owasp-worklist-builder"
STATIC = {"primary_evidence_mode": "static_source", "authorization_boundary": "static_offline",
          "tooling_profile_id": "read-only-source", "validator_role": "owasp-validator"}
DYNAMIC = {"primary_evidence_mode": "dynamic_runtime", "authorization_boundary": "dynamic_request_only",
           "tooling_profile_id": "request-drafting-only", "validator_role": "dynamic-test-request-author"}


def validator_registry(target: Path) -> Path:
    """The tracked registry with ONE departure: the tooling profile of the only composition that
    names the ``owasp-validator`` persona allows ``control_verdict``. The tracked profile forbids it
    (it is the worklist builder's), so the tracked registry cannot run a validator cell at all;
    ``test_owasp_dispatch`` proves that too. Registering a validator composition is T14."""
    b14.copy_registry(target)
    path = target / "tooling-profiles" / (VALIDATOR_PROFILE + ".json")
    profile = json.loads(path.read_text(encoding="utf-8"))
    profile["claim_limits"]["control_verdict"] = "allowed"
    path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    return target


# ---- the honest validator invoker and its departures ----------------------------------------------

class _CandidateBuilder:
    """T07's own test helpers, pointed at a directory that holds only what B14 handed the cell."""
    make_candidate = t07.OwaspValidatorResultTests.make_candidate
    citation = t07.OwaspValidatorResultTests.citation
    refresh_id = t07.OwaspValidatorResultTests.refresh_id


def candidate_from_package(package, scratch: Path) -> dict:
    """The candidate a cell can produce from its package: the handoff, the T06 pointer and the
    handoff set arrive as pinned bytes with their run-data paths; nothing else is read."""
    builder = _CandidateBuilder()
    builder.data = scratch
    for item in package.inputs:
        path = scratch.joinpath(*item.path.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(item.data)
        if item.role == "handoff":
            builder.handoff_path, builder.handoff = path, json.loads(item.data.decode("utf-8"))
        elif item.role == "reference" and path.name == "accepted.json":
            builder.t06_pointer = path
        elif item.role == "reference":
            builder.handoff_set_path = path
    builder.run_id = builder.handoff["run_identity"]["run_id"]
    candidate = builder.make_candidate()
    candidate["producer"]["producer_id"] = package.request["attempt_id"]
    builder.refresh_id(candidate)
    return candidate


def refresh(candidate: dict) -> dict:
    _CandidateBuilder().refresh_id(candidate)
    return candidate


class ValidatorInvoker(pi.FixtureInvoker):
    """Deterministic and model-free. Writes one T07 candidate and the canonical invoker manifest.
    ``edit(candidate, package)`` is the one departure a hostile variant makes; ``extra`` adds files."""

    def __init__(self, edit=None, claim_class: str = "control_verdict", statement: str | None = None) -> None:
        self.edit, self.claim_class, self.statement = edit, claim_class, statement
        self.packages: list = []
        self._guard = threading.Lock()

    def invoke(self, package, *, output_root, cancel):
        with self._guard:
            self.packages.append(package)
        with tempfile.TemporaryDirectory() as scratch:
            candidate = candidate_from_package(package, Path(scratch))
        if self.edit is not None:
            replaced = self.edit(candidate, package)
            candidate = candidate if replaced is None else replaced
        data = candidate if isinstance(candidate, bytes) else pi.canonical_bytes(candidate)
        pi.atomic_bytes(Path(output_root) / od.CANDIDATE_FILE, data)
        handoff = next(item for item in package.inputs if item.role == "handoff")
        read = len(package.prompt) + sum(len(item.data) for item in package.inputs)
        pi.write_invoker_output(
            package, output_root, files=[od.CANDIDATE_FILE],
            claims=[{"claim_id": "cell-claim-1", "claim_class": self.claim_class,
                     "statement": self.statement or "The assigned fragments were assessed from the pinned inputs.",
                     "file": od.CANDIDATE_FILE,
                     "citations": [{"root": handoff.root, "path": handoff.path, "sha256": handoff.sha256,
                                    "locator": "whole file"}]}],
            usage={"input_bytes": read, "input_units": (read + 3) // 4, "output_units": (len(data) + 3) // 4,
                   "tool_calls": 0},
            tool_calls=[], verified_invocations=[], injection_suspected=[],
            limitations=["No model was called; this is a protocol fixture."])


class NoCandidate(pi.FixtureInvoker):
    """B14's own honest fixture: a verified ``OK`` result that holds no candidate file."""


class Routed:
    """One runtime has one invoker; this one picks a behaviour by the cell's handoff ordinal (read
    from the pinned handoff it was handed) and records every ordinal it was invoked for."""
    invoker_id = pi.FixtureInvoker.invoker_id

    def __init__(self, routes: dict | None = None, default=None) -> None:
        self.routes, self.default = dict(routes or {}), default or ValidatorInvoker()
        self.invoked: list = []
        self._guard = threading.Lock()

    def invoke(self, package, *, output_root, cancel):
        handoff = next(item for item in package.inputs if item.role == "handoff")
        ordinal = json.loads(handoff.data.decode("utf-8"))["batch_identity"]["ordinal"]
        with self._guard:
            self.invoked.append(ordinal)
        self.routes.get(ordinal, self.default).invoke(package, output_root=output_root, cancel=cancel)


class Gated(ValidatorInvoker):
    """Signals ``started``, blocks until ``release`` (or, when it honours cancel, until the adapter
    cancels it), then behaves as the honest validator. Never sleeps to synchronize."""

    def __init__(self, honor_cancel: bool = True, on_start=None) -> None:
        super().__init__()
        self.started, self.release, self.finished = threading.Event(), threading.Event(), threading.Event()
        self.honor_cancel, self.on_start = honor_cancel, on_start

    def invoke(self, package, *, output_root, cancel):
        self.started.set()
        if self.on_start is not None:
            self.on_start()
        waited = 0.0
        while not self.release.is_set() and not (self.honor_cancel and cancel.is_set()) and waited < HANG_SECONDS:
            self.release.wait(0.01)
            waited += 0.01
        try:
            if self.release.is_set():
                super().invoke(package, output_root=output_root, cancel=cancel)
        finally:
            self.finished.set()


# ---- the workspace --------------------------------------------------------------------------------

class DispatchCase(unittest.TestCase):
    """A run with a real T05 and T06 publication, a validator registry and dispatch facts."""
    input_manifest = t06.OwaspValidatorHandoffTests.input_manifest
    row = t06.OwaspValidatorHandoffTests.row
    chapters = ("V1", "V2", "V3")       # one static batch per chapter (T05 never mixes domains)
    dynamic_chapters: tuple = ()        # chapters whose controls T05 routes to the request-only boundary
    caveats: list | None = None
    max_cells_per_pool: int | None = None
    max_timeout_seconds: int | None = None

    def setUp(self):
        t06.OwaspValidatorHandoffTests.setUp(self)
        self.base = Path(self.temporary.name).resolve()
        self.run_id = "dispatch-fixture"
        self.run = execution_state.RUNS / self.run_id
        self.data = self.run / "data"
        write_json(self.run / "run-status.json", {"run_id": self.run_id, "status": "READY"})
        self.raw = self.data / "imports" / "import-1" / "component.json"
        write_json(self.raw, {"component": "server", "kind": "web application", "comment": INJECTION})
        self.registry = validator_registry(self.base / "registry")
        self.cancel = pr.PoolCancel()
        self.config_reference = self.dispatch_config()
        self.publish_handoffs()
        self.addCleanup(self.join_threads)

    # -- upstream: T03/T04 as the T06 tests write them, then the real T05 and T06 -------------------

    def selected_controls(self) -> list:
        chosen = []
        for chapter in (*self.chapters, *self.dynamic_chapters):
            chosen.append(next(c for c in self.controls if c["group"]["chapter_id"] == chapter))
        return chosen

    def routing_rules(self) -> list:
        def rule(route_id, domains, fields):
            return {"route_id": route_id, "selector": {
                "standard_family": "owasp_asvs", "obligation_ids": [], "control_ids": [],
                "domain_ids": list(domains), "all_controls": not domains, "component_ids": [],
                "all_components": True}, **fields, "linked_test_ids": []}
        rules = [rule("static-route", (), STATIC)]
        if self.dynamic_chapters:
            rules.append(rule("dynamic-route", self.dynamic_chapters, DYNAMIC))
        return rules

    def publish_handoffs(self, *, rows=None, force: bool = False) -> dict:
        t03_root = self.data / "jobs" / owasp_applicability.UPSTREAM_JOB / "whole"
        t03_manifest = t03_root / "attempts" / self.t03_attempt / "outputs" / "owasp-input-manifest.json"
        write_json(t03_manifest, self.input_manifest(self.caveats))
        write_json(t03_root / "accepted.json", {
            "status": "OK", "run_id": self.run_id, "job_id": owasp_applicability.UPSTREAM_JOB,
            "attempt_id": self.t03_attempt, "input_fingerprint": "b" * 64, "selection_id": "selection-1",
            "artifacts": {"outputs/owasp-input-manifest.json": sha(t03_manifest)}})
        write_json(t03_root / "latest.json", {"attempt_id": self.t03_attempt})
        rows = rows if rows is not None else [self.row(control) for control in self.selected_controls()]
        applicable = sum(row["applicability_status"] == "applicable" for row in rows)
        model = {
            "schema": "appsec-review/owasp-applicability-model/1.0", "run_id": self.run_id,
            "selection_id": "selection-1", "input_fingerprint": "f" * 64,
            "generated_at": "2026-09-20T00:00:00+00:00",
            "assigned_reviewer": {"reviewer_id": "reviewer-1", "role": "owasp-applicability-reviewer"},
            "reference_snapshots": [{"family": "owasp_asvs", "edition": "5.0.0", "profile_or_level": "L2",
                                     "snapshot_id": self.snapshot_root.name,
                                     "manifest_sha256": sha(self.snapshot_manifest_path)}],
            "counts": {"selected_controls": len(rows), "components": 1, "control_targets": len(rows),
                       "applicable": applicable, "conditional": 0, "not_applicable": len(rows) - applicable,
                       "cannot_determine": 0, "out_of_scope": 0},
            "rows": rows, "claim_limits": ["Applicability only."]}
        t04_root = self.data / "jobs" / owasp_batching.UPSTREAM_JOB / "whole"
        t04_attempt = t04_root / "attempts" / self.t04_attempt
        outputs = t04_attempt / "outputs"
        paths = {name: outputs / name for name in ("owasp-applicability-model.json", "applicable-controls.json",
                                                   "applicability-gaps.json", "applicability-overrides.jsonl")}
        write_json(paths["owasp-applicability-model.json"], model)
        write_json(paths["applicable-controls.json"], {
            "schema": "appsec-review/owasp-applicable-controls/1.0", "run_id": self.run_id,
            "selection_id": "selection-1",
            "rows": [row for row in rows if row["applicability_status"] == "applicable"]})
        write_json(paths["applicability-gaps.json"], {"schema": "appsec-review/owasp-applicability-gaps/1.0",
                                                      "run_id": self.run_id, "selection_id": "selection-1", "gaps": []})
        paths["applicability-overrides.jsonl"].write_bytes(b"")
        write_json(t04_root / "accepted.json", {
            "status": "OK", "run_id": self.run_id, "job_id": owasp_batching.UPSTREAM_JOB,
            "attempt_id": self.t04_attempt, "input_fingerprint": "f" * 64, "selection_id": "selection-1",
            "artifacts": {path.relative_to(t04_attempt).as_posix(): sha(path) for path in paths.values()}})
        write_json(t04_root / "latest.json", {"attempt_id": self.t04_attempt})
        write_json(t04_attempt / "inputs.json", {
            "schema": "appsec-review/owasp-applicability-request/1.0", "run_id": self.run_id,
            "input_manifest": {"attempt_id": self.t03_attempt,
                               "accepted_pointer_path": f"jobs/{owasp_applicability.UPSTREAM_JOB}/whole/accepted.json",
                               "accepted_pointer_sha256": sha(t03_root / "accepted.json"),
                               "manifest_path": t03_manifest.relative_to(self.data).as_posix(),
                               "manifest_sha256": sha(t03_manifest)},
            "assigned_reviewer": model["assigned_reviewer"],
            "components": [{"component_id": "server", "name": "Server", "classification_hash": "a" * 64,
                            "input_ids": ["component-map"], "scope_status": "in_scope", "scope_authority": None}],
            "rules": [], "overrides": []})
        batch_config = json.loads((PROCESS / "config" / "owasp-batching" / "default-v1.json").read_text(encoding="utf-8"))
        model_path = paths["owasp-applicability-model.json"]
        batch_request_path = self.run / "inputs" / "owasp-batch-request.json"
        write_json(batch_request_path, {
            "schema": "appsec-review/owasp-batch-request/1.0", "run_id": self.run_id,
            "applicability": {"attempt_id": self.t04_attempt,
                              "accepted_pointer_path": f"jobs/{owasp_batching.UPSTREAM_JOB}/whole/accepted.json",
                              "accepted_pointer_sha256": sha(t04_root / "accepted.json"),
                              "model_path": model_path.relative_to(self.data).as_posix(),
                              "model_sha256": sha(model_path)},
            "batch_config": {"path": "appsec-review-process/config/owasp-batching/default-v1.json",
                             "config_digest": execution_state.digest(batch_config)},
            "component_contexts": [{"component_id": "server", "component_group_id": "application",
                                    "trust_role": "application-tier", "evidence_root_input_ids": ["component-map"]}],
            "routing_rules": self.routing_rules()})
        t05 = owasp_batching.build(self.run_id, batch_request_path, force=force)
        t05_root = self.data / "jobs" / owasp_batching.JOB_ID / "whole"
        t05_outputs = t05_root / "attempts" / t05["attempt_id"] / "outputs"
        names = {"worklist": "owasp-validation-worklist.json", "batch_manifest": "owasp-batch-manifest.json",
                 "summary": "batch-summary.md"}
        batching = {"attempt_id": t05["attempt_id"],
                    "accepted_pointer_path": f"jobs/{owasp_batching.JOB_ID}/whole/accepted.json",
                    "accepted_pointer_sha256": sha(t05_root / "accepted.json")}
        for key, name in names.items():
            batching[key + "_path"] = (t05_outputs / name).relative_to(self.data).as_posix()
            batching[key + "_sha256"] = sha(t05_outputs / name)
        handoff_request_path = self.run / "inputs" / "owasp-validator-handoff-request.json"
        write_json(handoff_request_path, {
            "schema": "appsec-review/owasp-validator-handoff-request/1.0", "run_id": self.run_id,
            "batching": batching,
            "handoff_config": {"path": "appsec-review-process/config/owasp-validator-handoff/default-v1.json",
                               "config_digest": execution_state.digest(self.handoff_config)},
            "budget": "standard", "operation": "build", "batch_id": None})
        t06_result = owasp_validator_handoff.build(self.run_id, handoff_request_path, force=force)
        self.t06_root = self.data / "jobs" / owasp_validator_handoff.JOB_ID / "whole"
        self.t06_attempt = self.t06_root / "attempts" / t06_result["attempt_id"]
        self.handoff_set_path = self.t06_attempt / "outputs" / "owasp-validator-handoff-set.json"
        self.handoff_set = json.loads(self.handoff_set_path.read_text(encoding="utf-8"))
        self.worklist = json.loads((t05_outputs / names["worklist"]).read_text(encoding="utf-8"))
        self.request_path = self.write_request()
        return t06_result

    def handoff(self, ordinal: int) -> dict:
        entry = self.handoff_set["handoffs"][ordinal - 1]
        return json.loads((self.t06_attempt / entry["path"]).read_text(encoding="utf-8"))

    # -- T10 inputs --------------------------------------------------------------------------------

    def dispatch_config(self) -> dict:
        """The tracked default configuration, or (when a test narrows a limit) a copy of it in a
        relocated tracked tree, exactly the way the T06 tests relocate theirs."""
        tracked = od.CONFIG_ROOT / "default-v1.json"
        config = json.loads(tracked.read_text(encoding="utf-8"))
        reference = "appsec-review-process/config/owasp-dispatch/default-v1.json"
        if self.max_cells_per_pool is None and self.max_timeout_seconds is None:
            return {"path": reference, "config_digest": execution_state.digest(config)}
        return self.relocate_config(config)

    def relocate_config(self, config: dict) -> dict:
        if self.max_cells_per_pool is not None:
            config["pool"]["max_cells_per_pool"] = self.max_cells_per_pool
        if self.max_timeout_seconds is not None:
            for budget in config["cell_budgets"].values():
                budget["max_timeout_seconds"] = self.max_timeout_seconds
        repo = self.base / "config-repo"
        root = repo / "appsec-review-process" / "config" / "owasp-dispatch"
        write_json(root / "default-v1.json", config)
        for name, value in (("REPO_ROOT", repo), ("CONFIG_ROOT", root)):
            patcher = mock.patch.object(od, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        return {"path": "appsec-review-process/config/owasp-dispatch/default-v1.json",
                "config_digest": execution_state.digest(config)}

    def write_request(self, **over) -> Path:
        pointer = self.t06_root / "accepted.json"
        request = {"schema": od.REQUEST_ID, "run_id": self.run_id,
                   "handoffs": {"attempt_id": self.t06_attempt.name,
                                "accepted_pointer_path": pointer.relative_to(self.data).as_posix(),
                                "accepted_pointer_sha256": sha(pointer),
                                "handoff_set_path": self.handoff_set_path.relative_to(self.data).as_posix(),
                                "handoff_set_sha256": sha(self.handoff_set_path)},
                   "dispatch_config": self.config_reference, "model": deepcopy(MODEL)}
        request.update(deepcopy(over))
        path = self.run / "inputs" / "owasp-dispatch-request.json"
        write_json(path, request)
        self.request = request
        return path

    def facts(self, **over) -> od.DispatchFacts:
        fields = {"registry_dir": self.registry, "allowed_models": (b14.MODEL, b14.OTHER_MODEL),
                  "invoker_id": pi.FixtureInvoker.invoker_id, "source_snapshot_sha256": SNAPSHOT,
                  "registry_ceiling": None}
        fields.update(over)
        return od.DispatchFacts(**fields)

    def runtime_fields(self, invoker=None, **over) -> dict:
        fields = {"facts": self.facts(), "invoker": invoker or ValidatorInvoker(), "clock": lambda: NOW,
                  "cancel": self.cancel, "stop_grace_seconds": 2, "max_parallel": pr.MAX_PARALLEL,
                  "wait_limit_seconds": HANG_SECONDS, "drain_seconds": 5}
        fields.update(over)
        return fields

    def runtime(self, invoker=None, **over) -> od.DispatchRuntime:
        return od.DispatchRuntime(**self.runtime_fields(invoker, **over))

    def dispatch(self, invoker=None, *, force: bool = False, **over) -> dict:
        return od.dispatch(self.run_id, self.request_path, runtime=self.runtime(invoker, **over), force=force)

    # -- reading what was published ----------------------------------------------------------------

    @property
    def job_root(self) -> Path:
        return self.data / "jobs" / od.JOB_ID / "whole"

    def attempt(self, pointer: dict) -> Path:
        return self.job_root / "attempts" / pointer["attempt_id"]

    def accounting_path(self, pointer: dict) -> Path:
        return self.attempt(pointer) / od.OUTPUTS_DIR / od.ACCOUNTING_FILE

    def accounting(self, pointer: dict) -> dict:
        return json.loads(self.accounting_path(pointer).read_text(encoding="utf-8"))

    def verify(self, pointer: dict, **facts) -> list:
        return od.verify_publication(self.run_id, attempt_id=pointer["attempt_id"], facts=self.facts(**facts))

    def load(self, **facts):
        return od.load_verified_accounting(self.run_id, facts=self.facts(**facts))

    def cell(self, accounting: dict, ordinal: int) -> dict:
        return next(cell for cell in accounting["cells"] if cell["cell_ordinal"] == ordinal)

    def result_pointer(self, ordinal: int) -> dict:
        batch = self.handoff_set["handoffs"][ordinal - 1]["batch_id"]
        return json.loads((self.data / "jobs" / owasp_validator_result.JOB_ID / batch / "accepted.json")
                          .read_text(encoding="utf-8"))

    def join_threads(self) -> None:
        for thread in [t for t in threading.enumerate() if t.name.startswith("pool-instance-")]:
            thread.join(HANG_SECONDS)
            if thread.is_alive():
                raise AssertionError("a pool worker thread is still alive")


def every_text(node) -> list:
    """Every string, key and scalar of a JSON-like structure, for marker searches."""
    if isinstance(node, dict):
        return [text for key, value in node.items() for text in (str(key), *every_text(value))]
    if isinstance(node, (list, tuple)):
        return [text for value in node for text in every_text(value)]
    return [str(node)]


def tree_bytes(root: Path) -> dict:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}
