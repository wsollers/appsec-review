"""Durable global build scheduling; each writer transaction is a separate invocation."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import copy
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any
import uuid

from appsec_review.jobs.build_topology import (
    VARIANT_FIELDS, compile_build_topology, ready_build_units, topological_order,
    validate_build_topology,
)
from appsec_review.jobs.build_workspace import (
    BuildWorkspace, NodeBinding, ProductSpec, ReconstructionMiss, WorkspaceError, sweep_workspaces,
)
from appsec_review.config.build_workspaces import BuildWorkspacePolicy
from appsec_review.jobs.build_recipe_commands import normalize_recipe_command, prepare_recipe_command
from appsec_review.storage import FileLock, atomic_json, canonical_json
from appsec_review.storage.shared import immutable_bytes, put_file, reference, verify_reference


SCHEMA = "appsec-review/build-iterations/1"
REQUEST_SCHEMA = "appsec-review/build-iteration-request/1"
LANGUAGE_RECEIPT_SCHEMA = "appsec-review/language-build-receipt/1"


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def retain(run_root: Path, category: str, value: Mapping[str, Any]) -> dict[str, Any]:
    return immutable_bytes(run_root, f"artifacts/build/iterations/{category}/{digest(value)}.json",
                           canonical_json(value))


def read_reference(run_root: Path, reference: Mapping[str, Any]) -> dict[str, Any]:
    value = json.loads(verify_reference(run_root, reference).read_bytes())
    if not isinstance(value, dict):
        raise ValueError("iteration reference must resolve an object")
    return value


def selected_graph(actions: Sequence[Mapping[str, Any]], *, source_fingerprint: str,
                   relationships: Sequence[Mapping[str, Any]],
                   variants: Mapping[str, Mapping[str, str]],
                   accepted_graph: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Selection is a sidecar; it cannot rewrite observed facts or a complete source graph."""
    if accepted_graph is not None:
        validate_build_topology(accepted_graph)
        if accepted_graph["source_fingerprint"] != source_fingerprint:
            raise ValueError("selected graph has a different accepted source identity")
        return copy.deepcopy(dict(accepted_graph))
    return compile_build_topology(actions, source_fingerprint=source_fingerprint)


@dataclass(frozen=True, slots=True)
class IterationOutcome:
    receipt: Mapping[str, Any]
    products: tuple[ProductSpec, ...]
    cleanup_complete: bool


Worker = Callable[[Mapping[str, Any], str], IterationOutcome]
Invoker = Callable[[Mapping[str, Any], str, Callable[[Mapping[str, Any], str], Mapping[str, Any]]],
                   Mapping[str, Any]]


class BuildIterations:
    """The controller never holds a workspace writer while waiting for a worker.

    Requests and completion envelopes are immutable. The small ledger is a recoverable index,
    not success authority: only B's verified committed product generation permits reuse.
    """

    def __init__(self, run_root: Path, target: Path, graph: Mapping[str, Any],
                 dispatches: Sequence[Mapping[str, Any]], *, configuration: Mapping[str, Any],
                 releases: Mapping[str, str], execution_identity: str, output_policy_identity: str,
                 validate_receipt: Callable[[Mapping[str, Any]], None] | None = None,
                 product_overrides: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
                 omitted_receipts: Mapping[str, Mapping[str, Any]] | None = None):
        self.run_root = run_root.resolve(strict=True)
        self.target = target.resolve(strict=True)
        self.graph = copy.deepcopy(dict(graph))
        validate_build_topology(self.graph)
        self.dispatches = {str(item["build_unit_id"]): copy.deepcopy(dict(item)) for item in dispatches}
        if len(self.dispatches) != len(dispatches):
            raise ValueError("iteration dispatches repeat a build unit")
        self.configuration = dict(configuration)
        self.releases = dict(releases)
        self.execution_identity = execution_identity
        self.output_policy_identity = output_policy_identity
        self.validate_receipt = validate_receipt
        self.product_overrides = copy.deepcopy(dict(product_overrides or {}))
        self.omitted_receipts = copy.deepcopy(dict(omitted_receipts or {}))
        self.workspace = BuildWorkspace(self.run_root)
        self.ledger_path = self.run_root / "data/build/iterations/ledger.json"
        self.graph_ref = retain(self.run_root, "graphs", self.graph)
        self.configuration_ref = retain(self.run_root, "configurations", {
            "configuration_identity": digest(self.configuration), "releases": self.releases,
            "execution": self.configuration,
        })

    def _ledger(self) -> dict[str, Any]:
        if not self.ledger_path.exists():
            return {"schema": SCHEMA, "nodes": {}, "order": []}
        value = json.loads(self.ledger_path.read_bytes())
        if value.get("schema") != SCHEMA or not isinstance(value.get("nodes"), dict):
            raise ValueError("iteration ledger is malformed; refusing to invent accepted state")
        return value

    def _binding(self, uid: str, upstreams: Sequence[str]) -> NodeBinding:
        dispatch = self.dispatches[uid]
        from appsec_review.jobs.build_topology_artifacts import guard_cache_action as guard_action
        try:
            selected_proof = guard_action(self.run_root, dispatch, graph=self.graph,
                                          configuration=self.configuration, releases=self.releases)
        except ValueError as error:
            raise ReconstructionMiss(str(error)) from error
        missing = {"platform", "build_toolchain", "validation"} - self.releases.keys()
        missing.update(key for key in ("platform", "build_toolchain", "validation")
                       if self.releases.get(key) in {"", "undeclared"})
        if missing:
            raise ReconstructionMiss("missing release evidence: " + ", ".join(sorted(missing)))
        node = next(item for item in self.graph["nodes"] if item["build_unit_id"] == uid)
        if node["variant"]["toolchain"] not in {None, self.releases["build_toolchain"]}:
            raise ReconstructionMiss("variant toolchain does not resolve its declared release")
        image = dispatch.get("image")
        if (not isinstance(image, Mapping) or not isinstance(image.get("image_id"), str)
                or not image["image_id"].startswith("sha256:") or len(image["image_id"]) != 71):
            raise ReconstructionMiss(f"missing immutable build image: {uid}")
        return NodeBinding(
            uid, str(self.graph["source_fingerprint"]), str(self.graph["topology_id"]),
            digest(self.configuration), digest(dispatch["recipe"]), str(image["image_id"]),
            self.releases["build_toolchain"], tuple(sorted(upstreams)),
            self.execution_identity, digest({"policy": self.output_policy_identity,
                                             "products": self.product_overrides.get(uid),
                                             "selected_proof": selected_proof}),
        )

    def _refinement(self, uid: str) -> Mapping[str, Any]:
        from appsec_review.jobs.build_topology_artifacts import load_refinement
        return load_refinement(self.run_root, self.dispatches[uid]["topology_refinement"], graph=self.graph)

    @staticmethod
    def _decode_binding(value: Mapping[str, Any]) -> NodeBinding:
        fields = dict(value)
        fields["upstream_products"] = tuple(fields["upstream_products"])
        return NodeBinding(**fields)

    def _request(self, uid: str, binding: NodeBinding, generation: str,
                 interfaces: Sequence[Mapping[str, Any]], label: str,
                 producers: Mapping[str, NodeBinding]) -> dict[str, Any]:
        attempt = "iteration-" + uuid.uuid4().hex
        value = {
            "schema": REQUEST_SCHEMA, "run_id": self.run_root.name, "node_id": uid,
            "attempt_id": attempt, "controller_id": self.controller_id,
            "binding": binding.view(), "generation": generation, "display_label": label,
            "target": str(self.target),
            "graph": self.graph_ref, "configuration": self.configuration_ref,
            "dispatch": self.dispatches[uid], "interfaces": list(interfaces),
            "products": self.product_overrides.get(uid),
            "producers": {key: value.view() for key, value in producers.items()},
        }
        return {**retain(self.run_root, "requests", value), "run_id": self.run_root.name}

    def _execute(self, request_ref: Mapping[str, Any], dagster_run_id: str, worker: Worker) -> Mapping[str, Any]:
        request = read_reference(self.run_root, request_ref)
        if request.get("schema") != REQUEST_SCHEMA or request["run_id"] != self.run_root.name:
            raise ValueError("iteration request run/schema mismatch")
        binding = self._decode_binding(request["binding"])
        if (binding.node_id != request["node_id"] or digest(request["dispatch"]) != digest(self.dispatches[binding.node_id])
                or request["graph"] != self.graph_ref or request["configuration"] != self.configuration_ref
                or request["target"] != str(self.target)
                or digest(request.get("products")) != digest(self.product_overrides.get(binding.node_id))):
            raise ValueError("immutable iteration request differs from selected execution inputs")
        if binding.view() != self._binding(binding.node_id, binding.upstream_products).view():
            raise WorkspaceError("iteration target admission changed before workspace recovery")
        with self.workspace.writer() as writer:
            products = []
            producer_bindings = {key: self._decode_binding(value)
                                 for key, value in request["producers"].items()}
            accepted = writer.committed_generation()["accepted"]
            for uid, producer in producer_bindings.items():
                if producer.view() != self._binding(uid, producer.upstream_products).view():
                    raise WorkspaceError("iteration producer binding differs from selected inputs")
                products.extend(writer.product_interfaces(accepted[uid], producer))
            dependencies = {edge["producer_build_unit_id"] for edge in self.graph["edges"]
                            if edge["consumer_build_unit_id"] == binding.node_id}
            expected = self._binding(binding.node_id, [
                accepted[uid]["sha256"] for uid in dependencies if uid in producer_bindings])
            if binding.view() != expected.view():
                raise WorkspaceError("iteration binding differs from verified prerequisite products")
            readiness = ready_build_units(
                self.graph, {uid: "SUCCEEDED" for uid in producer_bindings},
                products=products, verify_product=lambda record: bool(writer.verify_product(
                    record["workspace_product"], producer_bindings[record["producer_build_unit_id"]])),
                refinement=self._refinement(binding.node_id))
            if binding.node_id not in readiness["ready"]:
                raise WorkspaceError("iteration prerequisites changed before writer acquisition")
            if list(request["interfaces"]) != [value for value in products
                    if value["producer_build_unit_id"] in {
                        edge["producer_build_unit_id"] for edge in self.graph["edges"]
                        if edge["consumer_build_unit_id"] == binding.node_id}]:
                raise WorkspaceError("iteration product interfaces changed before writer acquisition")
            writer.begin_attempt(binding, request["attempt_id"], request["generation"])
            try:
                outcome = worker(request, dagster_run_id)
                receipt = {**outcome.receipt, "attempt_id": request["attempt_id"],
                           "dagster_run_id": dagster_run_id}
                receipt_ref = retain(self.run_root, "receipts", receipt)
                prepared = retain(self.run_root, "prepared", {
                    "request": dict(request_ref), "receipt": receipt_ref,
                    "dagster_run_id": dagster_run_id, "cleanup_complete": outcome.cleanup_complete,
                    "products": [asdict(spec) for spec in outcome.products],
                })
                atomic_json(self.run_root / "data/build/iterations/prepared" / f"{request['attempt_id']}.json",
                            {"prepared": prepared})
                if receipt.get("terminal_status") != "SUCCEEDED":
                    from appsec_review.jobs.job_project_build.repair import diagnose_failure
                    from appsec_review.jobs.job_project_build.enforcement import gap_text
                    evidence = [reference(
                        self.run_root, self.run_root / value["path"], expected_sha256=value["sha256"])
                        for command in receipt.get("commands", ())
                        for key in ("stdout", "stderr", "execution_capture")
                        if isinstance((value := command.get(key)), Mapping)]
                    commands = receipt.get("commands", ())
                    last = commands[-1] if commands else {}
                    stderr_ref = last.get("stderr")
                    stderr = (verify_reference(self.run_root, reference(
                        self.run_root, self.run_root / stderr_ref["path"],
                        expected_sha256=stderr_ref["sha256"])).read_text(errors="replace")[-32768:]
                        if isinstance(stderr_ref, Mapping) else "")
                    messages = [gap_text(gap) for gap in receipt.get("gaps", ())]
                    diagnosis = diagnose_failure(
                        exit_code=last.get("exit_code"), timed_out=last.get("timed_out", False),
                        stderr=stderr, gaps=messages,
                        capture_gaps=tuple(value for value in messages
                                           if "capture" in value.lower()))
                    failure = retain(self.run_root, "failures", {
                        "attempt_id": request["attempt_id"], "binding": binding.view(),
                        "terminal_status": "FAILED", "evidence": evidence, "receipt": receipt_ref,
                        "request": dict(request_ref),
                        "diagnosis": {"kind": diagnosis.kind.value, "reason": diagnosis.reason,
                                      "evidence": list(diagnosis.evidence)},
                    })
                    atomic_json(self.run_root / "data/build/iterations/failures" / f"{binding.node_id}.json",
                                {"failure": failure, "request": dict(request_ref)})
                if outcome.cleanup_complete is not True:
                    raise WorkspaceError("iteration worker/container cleanup is unconfirmed")
                if receipt.get("terminal_status") != "SUCCEEDED":
                    raise WorkspaceError("iteration build did not succeed")
                from appsec_review.jobs.build_topology import refinement_unit, verify_product_contract
                verify_product_contract(
                    refinement_unit(self.graph, self._refinement(binding.node_id), binding.node_id),
                    outcome.products)
                product = writer.commit(outcome.products)
                completed = retain(self.run_root, "completed", {
                    "request": dict(request_ref), "receipt": receipt_ref, "prepared": prepared,
                    "workspace_product": dict(product.reference), "binding": binding.view(),
                    "dagster_run_id": dagster_run_id, "generation": writer.state()["generation"],
                })
                return {"completion": completed, "terminal_status": "SUCCEEDED"}
            except BaseException as error:
                state = writer.state()
                if state["attempt"] is not None:
                    writer.fail_attempt(f"{type(error).__name__}: {error}")
                raise

    def run(self, worker: Worker, *, invoke: Invoker | None = None) -> dict[str, Any]:
        refusals = {}
        for uid in self.dispatches:
            try:
                self._binding(uid, ())
            except ReconstructionMiss as error:
                refusals[uid] = str(error)
        if not refusals and self.dispatches:
            for uid, entry in self._ledger()["nodes"].items():
                if uid not in self.dispatches:
                    refusals[uid] = "retained producer has no selected recipe admission for workspace reconstruction"
                    continue
                try:
                    from appsec_review.jobs.build_topology_artifacts import guard_cache_action
                    from appsec_review.jobs.build_topology import verify_product_contract
                    completion = read_reference(self.run_root, entry["completion"])
                    request = read_reference(self.run_root, completion["request"])
                    bound = guard_cache_action(
                        self.run_root, request["dispatch"], graph=self.graph,
                        configuration=self.configuration, releases=self.releases)
                    binding = self._decode_binding(entry["binding"])
                    if self._binding(uid, binding.upstream_products).view() != binding.view():
                        raise ReconstructionMiss("retained producer differs from the selected recipe binding")
                    from appsec_review.jobs.build_workspace import verify_retained_product
                    product = verify_retained_product(
                        self.run_root, entry["generation"], entry["product"], binding)
                    if product["binding"] != entry["binding"]:
                        raise ReconstructionMiss("retained product differs from its admitted producer")
                    verify_product_contract(bound, product["products"])
                    if self.validate_receipt is not None:
                        self.validate_receipt(read_reference(self.run_root, entry["receipt"]))
                except (ValueError, WorkspaceError, OSError, KeyError, TypeError) as error:
                    refusals[uid] = str(error)
        if not self.dispatches:
            receipts = [copy.deepcopy(self.omitted_receipts.get(
                node["build_unit_id"], self._gap(node["build_unit_id"], "no admitted build dispatch")))
                for node in self.graph["nodes"] if node["disposition"] != "contained"]
            return {"schema": SCHEMA, "graph": self.graph_ref,
                    "states": {receipt["build_unit_id"]: receipt["terminal_status"] for receipt in receipts},
                    "receipts": receipts, "gaps": [gap for receipt in receipts for gap in receipt.get("gaps", ())],
                    "terminal_status": ("COMPLETED_WITH_GAPS" if any(item.get("gaps") for item in receipts)
                                        else "SUCCEEDED" if receipts else "NOT_APPLICABLE")}
        if refusals:
            receipts = [self._gap(node["build_unit_id"], refusals.get(
                node["build_unit_id"], "shared workspace recovery withheld until selected inputs are admitted"))
                for node in self.graph["nodes"] if node["disposition"] != "contained"]
            return {"schema": SCHEMA, "graph": self.graph_ref,
                    "states": {receipt["build_unit_id"]: receipt["terminal_status"] for receipt in receipts},
                    "receipts": receipts,
                    "gaps": [f"{uid}: {reason}" for uid, reason in sorted(refusals.items())],
                    "terminal_status": "BLOCKED_BY_DEPENDENCY"}
        if invoke is None:
            from appsec_review.jobs.job_build_iteration.job import invoke_iteration
            invoke = invoke_iteration
        self.controller_id = uuid.uuid4().hex
        with FileLock(self.run_root / "data/build/iterations/controller.lock"):
            owner = self.run_root / self.workspace.owner_relative
            if not owner.exists():
                self.workspace.materialize(self.target, str(self.graph["source_fingerprint"]))
            self.workspace.set_hold("production-controller", held=True)
            self.workspace.set_hold("review-consumers", held=True)
            try:
                self._recover_invalidation()
                self._recover()
                with self.workspace.writer() as writer:
                    writer.resume()
                return self._run(worker, invoke)
            finally:
                self.workspace.set_hold("production-controller", held=False)

    def _recover_invalidation(self) -> None:
        pointer = self.run_root / "data/build/iterations/pending-invalidation.json"
        if not pointer.exists():
            return
        intent = read_reference(self.run_root, json.loads(pointer.read_bytes())["intent"])
        for uid, state in intent["after_ledger"]["nodes"].items():
            binding = self._decode_binding(state["binding"])
            if self._binding(uid, binding.upstream_products).view() != binding.view():
                raise WorkspaceError("invalidation recovery has no matching accepted refinement")
        ledger = self._ledger()
        if digest(ledger) not in {intent["before_ledger"], digest(intent["after_ledger"])}:
            raise WorkspaceError("invalidation ledger changed outside its pinned transaction")
        with self.workspace.writer() as writer:
            result = writer.invalidate_nodes(
                intent["invalid_nodes"], [tuple(item) for item in intent["checkpoints"]],
                operation_id=intent["operation_id"], expected_generation=intent["expected_generation"])
            if writer.state()["generation"] != result["after_generation"]:
                raise WorkspaceError("invalidation receipt differs from committed workspace generation")
        wanted = {uid: item["product"] for uid, item in intent["after_ledger"]["nodes"].items()}
        if dict(result["retained"]) != wanted:
            raise WorkspaceError("invalidation receipt differs from retained ledger products")
        checkpoints = [list(item) for item in intent["checkpoints"] if item[0] in wanted]
        if result["retained_checkpoints"] != checkpoints:
            raise WorkspaceError("invalidation receipt changed surviving checkpoint provenance")
        atomic_json(self.run_root / "data/build/iterations/recompositions" /
                    f"{intent['operation_id']}.json", result)
        after = copy.deepcopy(intent["after_ledger"])
        for uid, before_generation, after_generation in result["retained_checkpoints"]:
            after["nodes"][uid].update(before_generation=before_generation, generation=after_generation)
        atomic_json(self.ledger_path, after)
        pointer.unlink()

    def _invalidate(self, uid: str, ledger: Mapping[str, Any]) -> dict[str, Any]:
        invalid = {uid}
        while True:
            expanded = invalid | {edge["consumer_build_unit_id"] for edge in self.graph["edges"]
                                  if edge["producer_build_unit_id"] in invalid}
            if expanded == invalid:
                break
            invalid = expanded
        invalid.intersection_update(ledger["nodes"])
        after = copy.deepcopy(dict(ledger))
        after["nodes"] = {key: value for key, value in after["nodes"].items() if key not in invalid}
        after["order"] = [key for key in after["order"] if key not in invalid]
        with self.workspace.writer() as writer:
            generation = writer.state()["generation"]
        intent = retain(self.run_root, "invalidations", {
            "operation_id": "invalidate-" + uuid.uuid4().hex,
            "expected_generation": generation, "invalid_nodes": sorted(invalid),
            "checkpoints": [(key, ledger["nodes"][key]["before_generation"], ledger["nodes"][key]["generation"])
                            for key in ledger["order"]],
            "before_ledger": digest(ledger), "after_ledger": after,
        })
        atomic_json(self.run_root / "data/build/iterations/pending-invalidation.json", {"intent": intent})
        self._recover_invalidation()
        return self._ledger()

    def _recover(self) -> None:
        pending_path = self.run_root / "data/build/iterations/pending.json"
        if not pending_path.exists():
            return
        pending = json.loads(pending_path.read_bytes())
        request = read_reference(self.run_root, pending["request"])
        selected_binding = self._decode_binding(request["binding"])
        if self._binding(selected_binding.node_id, selected_binding.upstream_products).view() != selected_binding.view():
            raise WorkspaceError("worker recovery has no matching accepted recipe refinement")
        attempt = request["attempt_id"]
        prepared_path = self.run_root / "data/build/iterations/prepared" / f"{attempt}.json"
        if not prepared_path.exists():
            with self.workspace.writer() as writer:
                if writer.state()["attempt"] is not None:
                    from appsec_review.container_runtime.build_executor import reconcile_build_leases
                    reconcile_build_leases(
                        self.run_root / "data/build/iterations/leases" / attempt,
                        workspace=self.workspace.paths.target, install=self.workspace.paths.install)
                    writer.restore(pending["before_generation"])
            self.workspace.set_hold("worker-" + attempt, held=False)
            pending_path.unlink()
            return
        prepared_ref = json.loads(prepared_path.read_bytes())["prepared"]
        prepared = read_reference(self.run_root, prepared_ref)
        if prepared["request"] != pending["request"]:
            raise WorkspaceError("interrupted worker request differs from its immutable preparation")
        if prepared["cleanup_complete"] is not True:
            from appsec_review.container_runtime.build_executor import reconcile_build_leases
            leases = self.run_root / "data/build/iterations/leases" / attempt
            if not leases.is_dir() or not any(leases.glob("*.json")):
                raise WorkspaceError("interrupted worker has no registered cleanup proof")
            with self.workspace.writer() as writer:
                reconcile_build_leases(
                    leases,
                    workspace=self.workspace.paths.target, install=self.workspace.paths.install)
                writer.restore(pending["before_generation"])
            self.workspace.set_hold("worker-" + attempt, held=False)
            pending_path.unlink()
            return
        binding = self._decode_binding(request["binding"])
        ledger = self._ledger()
        with self.workspace.writer() as writer:
            generation = writer.committed_generation()
            ref = generation["accepted"].get(binding.node_id)
            if ref is None:
                writer.restore(pending["before_generation"])
            elif binding.node_id not in ledger["nodes"]:
                writer.verify_product(ref, binding)
                receipt = read_reference(self.run_root, prepared["receipt"])
                if receipt.get("terminal_status") != "SUCCEEDED":
                    raise WorkspaceError("committed product has no successful immutable receipt")
                completed = retain(self.run_root, "completed", {
                    "request": pending["request"], "receipt": prepared["receipt"], "prepared": prepared_ref,
                    "workspace_product": ref, "binding": binding.view(),
                    "dagster_run_id": prepared["dagster_run_id"], "generation": writer.state()["generation"],
                })
                ledger["nodes"][binding.node_id] = {
                    "binding": binding.view(), "product": ref, "receipt": prepared["receipt"],
                    "completion": completed, "before_generation": pending["before_generation"],
                    "generation": writer.state()["generation"],
                }
                ledger["order"].append(binding.node_id)
                atomic_json(self.ledger_path, ledger)
        self.workspace.set_hold("worker-" + attempt, held=False)
        pending_path.unlink()

    def _run(self, worker: Worker, invoke: Invoker) -> dict[str, Any]:
        ledger = self._ledger()
        states: dict[str, str] = {}
        receipts: dict[str, Any] = {}
        bindings: dict[str, NodeBinding] = {}
        interfaces: list[dict[str, Any]] = []
        order = topological_order(self.graph)
        nodes = {item["build_unit_id"]: item for item in self.graph["nodes"]}
        for uid in order:
            if uid not in self.dispatches:
                if uid in ledger["nodes"]:
                    ledger = self._invalidate(uid, ledger)
                receipts[uid] = copy.deepcopy(self.omitted_receipts.get(
                    uid, self._gap(uid, "immutable image/build dispatch is unavailable")))
                states[uid] = receipts[uid]["terminal_status"]
                continue
            dependencies = sorted({edge["producer_build_unit_id"] for edge in self.graph["edges"]
                                   if edge["consumer_build_unit_id"] == uid})
            upstreams = [ledger["nodes"][key]["product"]["sha256"]
                         for key in dependencies if states.get(key) == "SUCCEEDED"]
            try:
                binding = self._binding(uid, upstreams)
            except ReconstructionMiss as error:
                states[uid] = "BLOCKED_BY_DEPENDENCY"
                receipts[uid] = self._gap(uid, str(error))
                continue
            prior = ledger["nodes"].get(uid)
            if prior is not None:
                try:
                    if prior["binding"] != binding.view():
                        raise ReconstructionMiss("selected node inputs changed")
                    if self.graph["schema"] == "appsec-review/build-topology/1" and any(
                            value is None for value in nodes[uid]["variant"].values()):
                        raise ReconstructionMiss("missing ABI/variant evidence forbids reuse")
                    with self.workspace.writer() as writer:
                        product = writer.verify_product(prior["product"], binding)
                        from appsec_review.jobs.build_topology import refinement_unit, verify_product_contract
                        verify_product_contract(refinement_unit(
                            self.graph, self._refinement(uid), uid), product.products)
                        found = writer.product_interfaces(prior["product"], binding)
                    receipt = read_reference(self.run_root, prior["receipt"])
                    if self.validate_receipt is not None:
                        self.validate_receipt(receipt)
                    receipt["checkpoint_reused"] = True
                    states[uid], receipts[uid], bindings[uid] = "SUCCEEDED", receipt, binding
                    interfaces.extend(found)
                    continue
                except (ReconstructionMiss, OSError, ValueError, KeyError) as error:
                    ledger = self._invalidate(uid, ledger)
                    receipts.pop(uid, None)
                    self._miss(uid, str(error))
            states[uid] = "PENDING"

            def verify(record: Mapping[str, Any]) -> bool:
                producer = str(record["producer_build_unit_id"])
                with self.workspace.writer() as writer:
                    writer.verify_product(record["workspace_product"], bindings[producer])
                return True

            readiness = ready_build_units(self.graph, states, products=interfaces, verify_product=verify,
                                          refinement=self._refinement(uid))
            if uid not in readiness["ready"]:
                reasons = next((item["reasons"] for item in readiness["blocked"]
                                if item["build_unit_id"] == uid), ["prerequisites unavailable"])
                states[uid] = "BLOCKED_BY_DEPENDENCY"
                receipts[uid] = self._gap(uid, "; ".join(reasons))
                continue
            with self.workspace.writer() as writer:
                before = writer.state()["generation"]
            family = "cpp" if nodes[uid]["family"] == "native" else nodes[uid]["family"]
            ordinal = sum(1 for key in states if key != uid and nodes[key]["family"] == nodes[uid]["family"])
            label = f"build_{family}{ordinal or ''}"
            relevant = [value for value in interfaces if value["producer_build_unit_id"] in dependencies]
            request_ref = self._request(uid, binding, before, relevant, label, bindings)
            request = read_reference(self.run_root, request_ref)
            hold = "worker-" + request["attempt_id"]
            self.workspace.set_hold(hold, held=True)
            atomic_json(self.run_root / "data/build/iterations/pending.json", {
                "request": request_ref, "before_generation": before,
            })
            try:
                result = invoke(request_ref, label, lambda ref, run_id: self._execute(ref, run_id, worker))
                completed = read_reference(self.run_root, result["completion"])
                with self.workspace.writer() as writer:
                    writer.verify_product(completed["workspace_product"], binding)
                    found = writer.product_interfaces(completed["workspace_product"], binding)
                receipt = read_reference(self.run_root, completed["receipt"])
                ledger["nodes"][uid] = {
                    "binding": binding.view(), "product": completed["workspace_product"],
                    "receipt": completed["receipt"], "completion": result["completion"],
                    "before_generation": before, "generation": completed["generation"],
                }
                ledger["order"].append(uid)
                atomic_json(self.ledger_path, ledger)
                self.workspace.set_hold(hold, held=False)
                (self.run_root / "data/build/iterations/pending.json").unlink()
                states[uid], receipts[uid], bindings[uid] = "SUCCEEDED", receipt, binding
                interfaces.extend(found)
            except (WorkspaceError, RuntimeError, ValueError, OSError) as error:
                prepared_path = self.run_root / "data/build/iterations/prepared" / f"{request['attempt_id']}.json"
                if not prepared_path.exists():
                    from appsec_review.container_runtime.build_executor import reconcile_build_leases
                    with self.workspace.writer() as writer:
                        reconcile_build_leases(
                            self.run_root / "data/build/iterations/leases" / request["attempt_id"],
                            workspace=self.workspace.paths.target, install=self.workspace.paths.install)
                        writer.restore(before)
                    self.workspace.set_hold(hold, held=False)
                    (self.run_root / "data/build/iterations/pending.json").unlink()
                    raise
                prepared = read_reference(self.run_root, json.loads(prepared_path.read_bytes())["prepared"])
                if prepared["cleanup_complete"] is not True:
                    raise WorkspaceError("worker cleanup is unconfirmed; workspace retained") from error
                with self.workspace.writer() as writer:
                    writer.restore(before)
                self.workspace.set_hold(hold, held=False)
                states[uid] = "FAILED"
                (self.run_root / "data/build/iterations/pending.json").unlink()
                failed_receipt = read_reference(self.run_root, prepared["receipt"])
                from appsec_review.jobs.job_project_build.enforcement import unique_gaps
                receipts[uid] = {
                    **failed_receipt, "terminal_status": "FAILED", "artifacts": [],
                    "gaps": unique_gaps([*failed_receipt.get("gaps", ()),
                                        f"{type(error).__name__}: {error}"]),
                }
        for uid, node in nodes.items():
            if uid not in receipts and node["disposition"] != "contained":
                receipts[uid] = self._gap(uid, node["disposition"])
        gaps = [gap if isinstance(gap, Mapping) else f"{uid}: {gap}"
                for uid, receipt in receipts.items() for gap in receipt.get("gaps", ())]
        gaps.extend(f"topology:{item['code']}: {item['reason']}" for item in self.graph["coverage_gaps"])
        return {"schema": SCHEMA, "graph": self.graph_ref, "states": states,
                "receipts": [receipts[key] for key in sorted(receipts)], "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    def _gap(self, uid: str, reason: str, *, failed: bool = False) -> dict[str, Any]:
        dispatch = self.dispatches.get(uid, next(
            (node for node in self.graph["nodes"] if node["build_unit_id"] == uid), {}))
        return {"schema": LANGUAGE_RECEIPT_SCHEMA, "source_fingerprint": self.graph["source_fingerprint"],
                "build_unit_id": uid, "family": dispatch.get("family"), "root": dispatch.get("root"),
                "terminal_status": "FAILED" if failed else "BLOCKED",
                "artifacts": [], "commands": [], "gaps": [reason]}

    def _miss(self, uid: str, reason: str) -> None:
        from appsec_review.observability import PipelineLog
        PipelineLog(self.run_root).write("BUILD_ITERATION_REUSE_MISSED", run_id=self.run_root.name,
                                         details={"build_unit_id": uid, "reason": reason})


def resume_build_workspace(run_root: Path) -> None:
    workspace = BuildWorkspace(run_root)
    if not (run_root / workspace.owner_relative).exists():
        return
    from appsec_review.config.build_selection import parse_build_selection
    from appsec_review.jobs.build_topology_artifacts import (
        _read, guard_cache_action, selected_cache_actions,
    )
    manifest_path = run_root / "data/configuration/manifest.json"
    if not manifest_path.is_file() or manifest_path.stat().st_size > 16 * 1024 * 1024:
        raise WorkspaceError("workspace reconstruction has no bounded frozen configuration")
    manifest = json.loads(manifest_path.read_bytes())
    resolved_path = run_root / "data/configuration/resolved.json"
    resolved = _read(run_root, {"path": resolved_path.relative_to(run_root).as_posix(),
                               "sha256": manifest["resolved_sha256"],
                               "size_bytes": resolved_path.stat().st_size})
    settings = resolved["jobs"]["job_project_build"]["settings"]
    bindings = {"configuration": {"build_selection": parse_build_selection(
        settings.get("build_selection")).view()}, "releases": resolved["review_policy"]["releases"]}
    for action in selected_cache_actions(run_root).values():
        guard_cache_action(run_root, action, **bindings)
    ledger_path = run_root / "data/build/iterations/ledger.json"
    pending_path = run_root / "data/build/iterations/pending.json"
    if not ledger_path.exists() and not pending_path.exists():
        # A run whose every iteration failed restored its materialized generation and admitted
        # nothing. Only that pristine state has no products to reconstruct from a ledger.
        with workspace.writer() as writer:
            pristine = writer.state()["attempt"] is None and not writer.committed_generation()["accepted"]
        if not pristine:
            raise WorkspaceError("workspace reconstruction lacks accepted or pending recipe admission")
    if ledger_path.exists():
        ledger = json.loads(ledger_path.read_bytes())
        if ledger.get("schema") != SCHEMA:
            raise WorkspaceError("workspace reconstruction ledger has changed schema")
        for entry in ledger["nodes"].values():
            completion = read_reference(run_root, entry["completion"])
            request = read_reference(run_root, completion["request"])
            bound = guard_cache_action(run_root, request["dispatch"], **bindings)
            if request["binding"] != entry["binding"]:
                raise WorkspaceError("workspace ledger differs from its admitted request binding")
            from appsec_review.jobs.build_topology import verify_product_contract
            from appsec_review.jobs.build_workspace import verify_retained_product
            product = verify_retained_product(
                run_root, entry["generation"], entry["product"],
                BuildIterations._decode_binding(entry["binding"]))
            if product["binding"] != entry["binding"]:
                raise WorkspaceError("workspace product differs from its admitted producer binding")
            verify_product_contract(bound, product["products"])
            receipt = read_reference(run_root, entry["receipt"])
            guard_cache_action(run_root, receipt, **bindings)
    if pending_path.exists():
        request = read_reference(run_root, json.loads(pending_path.read_bytes())["request"])
        guard_cache_action(run_root, request["dispatch"], **bindings)
    workspace.set_hold("resume", held=True)
    with workspace.writer() as writer:
        if writer.state()["attempt"] is None:
            writer.resume()


def finish_build_workspaces(run_root: Path, policy: BuildWorkspacePolicy) -> None:
    workspace = BuildWorkspace(run_root)
    owner_path = run_root / workspace.owner_relative
    if not owner_path.exists():
        return
    with FileLock(run_root / "data/resume.lock"):
        owner = json.loads(owner_path.read_bytes())
        if any(name.startswith("worker-") for name in owner["holds"]):
            raise WorkspaceError("terminal build workspace still has an unresolved worker lease")
        workspace.set_hold("resume", held=False)
        workspace.set_hold("review-consumers", held=False)
        with workspace.writer() as writer:
            if writer.state()["attempt"] is not None:
                raise WorkspaceError("terminal build workspace has an unfinished writer")
        workspace.mark_terminal(workers_stopped=True)
        report = sweep_workspaces(run_root.parent, policy)
        atomic_json(run_root / "data/build/iterations/retention.json", {
            "deleted": report.deleted, "retained": report.retained, "failures": report.failures,
        })
        if report.failures:
            raise WorkspaceError("build workspace retention failed: " + repr(report.failures))


def durable_artifacts(run_root: Path, receipt: Mapping[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(dict(receipt))
    retained = {}

    def retain_identity(identity):
        original = str(identity["path"])
        if original not in retained:
            retained[original] = put_file(run_root, run_root / original)
        reference = retained[original]
        identity.update(path=reference["path"], sha256=reference["sha256"])

    for key in ("artifacts", "rejected_artifacts"):
        for artifact in value.get(key, ()):
            retain_identity(artifact)
    if isinstance(value.get("declared_compile_database"), Mapping):
        retain_identity(value["declared_compile_database"])
    for proof in value.get("enforcement", ()):
        for artifact in proof["closure_manifest"].get("native_artifacts", ()):
            retain_identity(artifact)
        proof["enforcement_id"] = digest({key: item for key, item in proof.items() if key != "enforcement_id"})
    if value.get("family") == "native" and value.get("terminal_status") != "SUCCEEDED":
        value["workspace"] = None  # The uncommitted tree will be rolled back; evidence above survives.
    return value


def install_inventory(root: Path) -> dict[str, tuple[str, int]]:
    result = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if not path.resolve(strict=True).is_relative_to(root.resolve(strict=True)):
            raise WorkspaceError("installed product symlink escapes the shared prefix")
        result[path.relative_to(root).as_posix()] = (
            hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mode & 0o7777)
    return result


def product_specs(graph_node: Mapping[str, Any], receipt: Mapping[str, Any],
                  workspace: BuildWorkspace, *,
                  install_before: Mapping[str, tuple[str, int]] | None = None,
                  bound: Mapping[str, Any] | None = None,
                  declarations: Sequence[Mapping[str, Any]] = ()) -> tuple[ProductSpec, ...]:
    """Resolve descriptor interfaces to actual retained outputs, never a successful attempt ID."""
    variant = dict(graph_node["variant"])
    candidates = list(receipt.get("artifacts", ()))
    installed = [relative for relative, identity in install_inventory(workspace.paths.install).items()
                 if install_before is None or install_before.get(relative) != identity]
    result: list[ProductSpec] = []
    from appsec_review.jobs.artifact_kinds import binary_role
    from appsec_review.jobs.build_workspace import native_product_axes, verify_native_product
    from appsec_review.jobs.build_topology import proven_product_axes
    axes = proven_product_axes(bound) if bound is not None else None
    native_roles = {"static-library": ("library", "static_archive"),
                    "shared-library": ("library", "runtime_shared"),
                    "executable": ("executable", "executable"),
                    "object": ("generated_source", "native_object")}

    def physical_role(path: str) -> tuple[str, str] | None:
        root, _, relative = path.partition("/")
        base = workspace.paths.target if root == "target" else workspace.paths.install
        candidate = base / relative
        if candidate.is_file() and not candidate.resolve(strict=True).is_relative_to(base.resolve(strict=True)):
            raise WorkspaceError("retained product escapes its admitted workspace")
        kind, _ = binary_role(candidate) if candidate.is_file() else (None, None)
        if kind == "static-library" and native_product_axes(candidate)["import_library"]:
            return ("library", "import_library")
        return native_roles.get(kind)

    for product in graph_node["products"]:
        interface = str(product["interface"]).removeprefix("cmake-target:")
        names = {interface, f"lib{interface}.a", f"lib{interface}.so", f"{interface}.dll",
                 f"{interface}.lib", f"lib{interface}.dylib", f"{interface}.exe"}
        choices = [("install/" + relative) for relative in installed if PurePosixPath(relative).name in names]
        if not choices:
            choices = [("target/" + str(item["workspace_path"])) for item in candidates
                       if PurePosixPath(str(item.get("workspace_path", ""))).name in names]
        declaration = next((value for value in declarations if
                            value["owner_build_unit_id"] == graph_node["build_unit_id"]
                            and value["product_id"] == product["product_id"]), None)
        role = declaration["role"] if declaration is not None else None
        if role == "runtime_shared" and axes is not None and axes["os"] == "windows":
            role = "import_library"
        if bound is not None:
            choices = [path for path in choices if physical_role(path) == (product["kind"], role)]
        if len(choices) != 1:
            raise WorkspaceError(f"product interface does not resolve one captured output: {interface}")
        result.append(ProductSpec(choices[0], product["kind"], product["product_id"],
                                  product["interface"], product["variant"], role, axes))
    used = {spec.path for spec in result}
    for item in candidates:
        path = str(item.get("workspace_path", ""))
        if not path or "target/" + path in used:
            continue
        kind = str(item.get("kind", ""))
        product_kind = ("library" if kind in {"shared-library", "static-library", "rust-library"} else
                        "executable" if kind == "executable" else "generated_source")
        result.append(ProductSpec("target/" + path, product_kind, "output-" + digest(path)[:20],
                                  path, variant))
        used.add("target/" + path)
    source_dir = PurePosixPath(str(receipt.get("recipe", {}).get("source_dir", ".")))
    headers = workspace.paths.target / Path(*source_dir.parts) / "include"
    if headers.is_dir() and any(path.is_file() for path in headers.rglob("*")):
        path = headers.relative_to(workspace.paths.target).as_posix()
        if "target/" + path not in used:
            result.append(ProductSpec("target/" + path, "headers", "headers-" + digest(path)[:20],
                                      path, variant))
    for relative in sorted(installed):
        if "install/" + relative in used:
            continue
        path = workspace.paths.install / relative
        kind = ("library" if path.suffix in {".a", ".so", ".lib", ".dylib", ".dll"} else
                "headers" if path.suffix in {".h", ".hpp", ".hh"} else
                "package_metadata" if path.suffix in {".pc", ".cmake"} else
                "executable" if path.stat().st_mode & 0o111 else "generated_source")
        result.append(ProductSpec("install/" + relative, kind, "install-" + digest(relative)[:20],
                                  relative, variant))
    if not result:
        raise WorkspaceError("build produced no verifiable product bytes")
    if bound is None:
        return tuple(result)
    typed = []
    for spec in result:
        if spec.role is not None:
            typed.append(spec)
            continue
        physical = physical_role(spec.path)
        artifact = next((value for value in candidates if
                         "target/" + str(value.get("workspace_path", "")) == spec.path), {})
        kind = artifact.get("kind")
        if physical is not None and kind != "managed-assembly":
            product_kind, role = physical
        elif kind == "managed-assembly":
            product_kind, role = "package_metadata", "managed_assembly"
        elif kind == "object":
            product_kind, role = "generated_source", "native_object"
        elif kind in {"jar", "aar", "apk", "package", "python-wheel"}:
            product_kind, role = "package_metadata", "package"
        elif spec.kind == "headers":
            product_kind, role = "headers", "headers"
        elif kind in {"generated-source", "generated-java-source", "generated-kotlin-source", "generated-code"}:
            product_kind, role = "generated_source", "generated_source"
        elif spec.kind == "library":
            raise WorkspaceError("native library role is unresolved; suffixes cannot authorize a product")
        elif spec.kind == "executable":
            raise WorkspaceError("native executable role is unresolved; capture labels cannot authorize a product")
        else:
            product_kind, role = "package_metadata", "metadata"
        typed.append(ProductSpec(spec.path, product_kind, spec.product_id, spec.interface,
                                 spec.variant, role, axes))
    for spec in typed:
        root, _, relative = spec.path.partition("/")
        base = workspace.paths.target if root == "target" else workspace.paths.install
        verify_native_product(base / relative, spec)
    return tuple(typed)


def decode_replay_context(value: Mapping[str, Any]):
    from appsec_review.jobs.build_recipe_replay import ProducerProduct, ReplayContext
    fields = dict(value)
    fields["binding"] = BuildIterations._decode_binding(fields["binding"])
    fields["products"] = tuple(ProductSpec(**item) for item in fields["products"])
    fields["upstreams"] = tuple(ProducerProduct(
        BuildIterations._decode_binding(item["binding"]), item["reference"])
        for item in fields.get("upstreams", ()))
    return ReplayContext(**fields)


def failure_context(run_root: Path, node_id: str, products: Sequence[Mapping[str, Any]]):
    from appsec_review.jobs.build_recipe_replay import ProducerProduct, ReplayContext
    from appsec_review.jobs.job_target_analysis_plan import load_accepted_plan
    from appsec_review.storage.shared import reference
    validation = next(item for item in load_accepted_plan(run_root)["build_topology"]["build_actions"]
                      if item["build_unit_id"] == node_id)
    pointer = json.loads((run_root / "data/build/iterations/failures" / f"{node_id}.json").read_bytes())
    failure = read_reference(run_root, pointer["failure"])
    request = read_reference(run_root, pointer["request"])
    graph = read_reference(run_root, request["graph"])
    configuration = read_reference(run_root, request["configuration"])
    workspace = BuildWorkspace(run_root)
    with workspace.writer() as writer:
        original = writer.committed_generation(request["generation"])
        generation_identity = writer.state()["generation"]
        generation = writer.committed_generation(generation_identity)
        if (generation["input_identity"] != original["input_identity"]
                or any(generation["accepted"].get(uid) != product
                       for uid, product in original["accepted"].items())):
            raise WorkspaceError("failure prerequisites changed before context selection")
        for product in generation["accepted"].values():
            binding = BuildIterations._decode_binding(read_reference(run_root, product)["binding"])
            if (binding.source_identity != request["binding"]["source_identity"]
                    or binding.graph_identity != request["binding"]["graph_identity"]
                    or binding.configuration_identity != request["binding"]["configuration_identity"]):
                raise WorkspaceError("failure context has incompatible retained production inputs")
        upstreams = tuple(ProducerProduct(
            BuildIterations._decode_binding(binding), generation["accepted"][uid])
            for uid, binding in request["producers"].items()
            if generation["accepted"][uid]["sha256"] in request["binding"]["upstream_products"])
    context = ReplayContext(
        run_root.name, request["attempt_id"], BuildIterations._decode_binding(request["binding"]),
        generation_identity, validation, request["dispatch"]["recipe"],
        next(item["variant"] for item in graph["nodes"] if item["build_unit_id"] == node_id),
        tuple(ProductSpec(**item) for item in products), configuration["releases"],
        {"failure": pointer["failure"], "graph": request["graph"], "configuration": request["configuration"],
         "source": reference(run_root, run_root / "artifacts/build/workspace/input.json"),
         "production_generation": retain(run_root, "failure-generation-selections", {
             "failure_generation": request["generation"], "selected_generation": generation_identity,
             "original_products": original["accepted"], "retained_products": generation["accepted"],
         })}, upstreams)
    if failure["attempt_id"] != context.failed_attempt_id:
        raise ValueError("failure and pending request identities disagree")
    return retain(run_root, "contexts", context.view())


def captured_replay(config, context, invocation):
    """Only captured configure/build commands; no image preparation or host bootstrap path."""
    from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile, CaptureScope
    from appsec_review.container_runtime.project_images import derived_base_image_id
    from appsec_review.jobs.build_recipe_replay import TrialExecution
    from appsec_review.jobs.job_language_build.job import _interface_environment
    run_root = config.runtime.runs_dir / context.run_id
    failure = read_reference(run_root, context.inputs["failure"])
    request = read_reference(run_root, failure["request"])
    image = request["dispatch"]["image"]
    profile = invocation.profile
    if profile is None:
        profile = (BuildProfile(**request["dispatch"]["promoted_profile"])
                   if request["dispatch"].get("promoted_profile") is not None else BuildProfile(
                       str(image["family"]), str(image["image_tag"]), str(image["image_id"]), str(image["user"]),
                       derived_from_image_id=derived_base_image_id(image)))
    if profile.image_id != invocation.image_identity:
        raise ValueError("replay image differs from its approved pinned profile")
    from appsec_review.jobs.build_topology_artifacts import guard_action
    guard_action(run_root, {
        **request["dispatch"], "recipe": dict(invocation.candidate.recipe),
        "image": {**image, "image_id": profile.image_id},
        "topology_refinement": invocation.topology_refinement,
    }, releases=context.releases, image_identity=profile.image_id)
    settings = config.job("job_language_build")
    executor = BuildContainerExecutor(
        profile, timeout_seconds=int(settings.settings["command_timeout_seconds"]),
        output_bytes=int(settings.settings["output_bytes"]), network=invocation.network,
        lease_directory=invocation.capture_directory / "leases",
        network_offline=invocation.network == "none")
    executor.resolve()
    environment = dict(invocation.candidate.recipe["environment"])
    environment.update(_interface_environment(invocation.interfaces, environment))
    environment.setdefault("CMAKE_INSTALL_PREFIX", "/install")
    environment.setdefault("PREFIX", "/install")
    results = []
    for ordinal in range(len(invocation.commands)):
        argv, cwd = invocation.prepare_command(ordinal)
        phase = "configure" if ordinal < len(invocation.candidate.recipe["configure_commands"]) else "build"
        argv, checked_cwd = prepare_recipe_command(
            invocation.paths.target, context.validation_unit, invocation.candidate.recipe, phase, argv,
            normalized=True)
        if checked_cwd != cwd:
            raise ValueError("replay phase cwd differs from its immutable command plan")
        result = executor.execute_captured(
            argv, workspace=invocation.paths.target, install_dir=invocation.paths.install,
            working_directory=cwd, environment=environment,
            capture_directory=invocation.capture_directory / f"command-{ordinal + 1:03d}",
            capture_config=settings.build_capture,
            scope=CaptureScope(context.run_id, "job_project_build", invocation.attempt_id,
                               context.binding.node_id, context.validation_unit["family"]))
        results.append(result)
        if result.timed_out or result.exit_code != 0:
            break
    return TrialExecution(tuple(results), bool(results) and all(item.cleanup_complete for item in results))


def select_promotion(run_root: Path, context_document: Mapping[str, Any], trial: Mapping[str, Any]):
    from appsec_review.jobs.build_recipe_replay import load_promoted_revision, promote_recipe
    context = decode_replay_context(context_document)
    if context.run_id != run_root.name:
        raise ValueError("recipe context belongs to another application run")
    workspace = BuildWorkspace(run_root)
    with FileLock(run_root / "data/resume.lock"), FileLock(
            run_root / "data/build/iterations/controller.lock"):
        promotion = promote_recipe(workspace, context, trial)
        load_promoted_revision(workspace, context, promotion)
        pointer = run_root / "data/build/iterations/selection.json"
        selections = (read_reference(run_root, json.loads(pointer.read_bytes())["selection"])
                      if pointer.exists() else {})
        selections[context.binding.node_id] = {
            "context": retain(run_root, "contexts", context_document), "promotion": dict(promotion)}
        selected = retain(run_root, "selections", selections)
        atomic_json(pointer, {"selection": selected})
    return promotion


def selected_revisions(run_root: Path, accepted: Mapping[str, Any],
                       dispatches: Sequence[Mapping[str, Any]]):
    pointer = run_root / "data/build/iterations/selection.json"
    if not pointer.exists():
        return dict(accepted["execution_graph"]), list(dispatches), {}
    from appsec_review.jobs.build_recipe_replay import load_promoted_revision
    from appsec_review.container_runtime import BuildProfile
    from appsec_review.container_runtime.project_images import derived_base_image_id, project_recipe_identity
    from appsec_review.config.assurance import ComponentReleases
    selections = read_reference(run_root, json.loads(pointer.read_bytes())["selection"])
    graph = accepted["execution_graph"]
    selected = copy.deepcopy(graph)
    copied = {item["build_unit_id"]: copy.deepcopy(dict(item)) for item in dispatches}
    overrides = {}
    for uid, selection in selections.items():
        if uid not in copied:
            raise ValueError("selected promotion has no accepted image/build dispatch")
        context = decode_replay_context(read_reference(run_root, selection["context"]))
        if (context.binding.graph_identity != graph["topology_id"]
                or context.binding.source_identity != graph["source_fingerprint"]):
            raise ValueError("selected promotion belongs to a different source/topology")
        revision = load_promoted_revision(BuildWorkspace(run_root), context, selection["promotion"])
        copied[uid]["recipe"] = dict(revision.recipe)
        failure = read_reference(run_root, context.inputs["failure"])
        failed_dispatch = read_reference(run_root, failure["request"])["dispatch"]
        image = copy.deepcopy(failed_dispatch["image"])
        copied[uid]["image"] = image
        if revision.profile is not None:
            profile = revision.profile
            image = {
                "schema": "appsec-review/promoted-build-image/1", "family": profile.name,
                "image_id": profile.image_id, "image_tag": profile.tag, "user": profile.user,
                "dependency_hashes": image["dependency_hashes"], "promotion": dict(revision.reference),
            }
            copied[uid]["image"] = image
            copied[uid]["promoted_profile"] = asdict(profile)
        elif image["image_id"] != revision.image_identity:
            raise ValueError("promoted image lacks approved production profile metadata")
        elif failed_dispatch.get("promoted_profile") is not None:
            profile = BuildProfile(**failed_dispatch["promoted_profile"])
            copied[uid]["promoted_profile"] = asdict(profile)
        else:
            profile = BuildProfile(str(image["family"]), str(image["image_tag"]), str(image["image_id"]),
                                   str(image["user"]), derived_from_image_id=derived_base_image_id(image))
        copied[uid]["recipe_identity"] = project_recipe_identity(
            revision.recipe, profile, image["dependency_hashes"], releases=ComponentReleases(context.releases))
        copied[uid]["recipe_promotion"] = dict(revision.reference)
        overrides[uid] = [asdict(spec) for spec in revision.products]
    from appsec_review.jobs.build_topology_artifacts import bind_actions, guard_action, load_refinement
    base_dispatch = next(iter(copied.values()), None)
    if base_dispatch is not None:
        base = load_refinement(run_root, base_dispatch["topology_refinement"], graph=graph)
        refined = bind_actions(run_root, list(copied.values()), policy=base["policy"],
                               profiles=base["profiles"], environment=base["environment"],
                               releases=base["releases"])
        copied = {item["build_unit_id"]: item for item in refined}
        for action in copied.values():
            guard_action(run_root, action, graph=graph, releases=base["releases"])
    validate_build_topology(selected)
    if selected["topology_id"] != graph["topology_id"]:
        raise ValueError("recipe promotion changed structural build topology")
    return selected, list(copied.values()), overrides
