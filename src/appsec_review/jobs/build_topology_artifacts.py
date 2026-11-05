"""Run-owned immutable acceptance and execution checks for recipe-bound refinements."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from appsec_review.jobs.build_topology import (
    BUILD_TOPOLOGY_SCHEMA, compile_build_topology, refine_build_topology,
    refinement_unit, validate_refinement, _SOURCE_KEYS,
)
from appsec_review.storage import FileLock, atomic_json, canonical_json
from appsec_review.storage.shared import immutable_bytes, safe_path, verify_reference

INDEX_SCHEMA = "appsec-review/accepted-topology-refinements/1"
INDEX_BYTE_LIMIT = 32 * 1024 * 1024


def _read_refinement_index(pointer: Path) -> dict[str, Any]:
    size = pointer.stat().st_size
    if size > INDEX_BYTE_LIMIT:
        raise ValueError("accepted refinement index exceeds its byte bound")
    data = pointer.read_bytes()
    if len(data) != size or len(data) > INDEX_BYTE_LIMIT:
        raise ValueError("accepted refinement index changed during its bounded read")
    index = json.loads(data)
    if (not isinstance(index, dict) or set(index) != {"schema", "entries"}
            or index["schema"] != INDEX_SCHEMA or not isinstance(index["entries"], list)):
        raise ValueError("accepted refinement index is malformed")
    return index


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _read(root: Path, ref: Mapping[str, Any]) -> dict[str, Any]:
    path = safe_path(root, ref["path"])
    # Whole plans, recipe inputs and sidecars may repeat bounded source evidence.
    # Graph documents retain their separate 16 MiB limit.
    byte_limit = 16 * 1024 * 1024 if "/graphs/" in ref["path"] else 32 * 1024 * 1024
    if path.stat().st_size > byte_limit:
        raise ValueError("accepted topology artifact exceeds its byte bound")
    path = verify_reference(root, ref)
    data = path.read_bytes()
    if len(data) > byte_limit or hashlib.sha256(data).hexdigest() != ref["sha256"]:
        raise ValueError("accepted topology artifact changed during its bounded read")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("accepted topology artifact must be an object")
    return value


def _retain(root: Path, category: str, value: Mapping[str, Any]) -> dict[str, Any]:
    data = canonical_json(value)
    if len(data) > (16 if category == "graphs" else 32) * 1024 * 1024:
        raise ValueError("topology publication exceeds its category byte bound")
    return immutable_bytes(root, f"artifacts/build/topology/{category}/{_digest(value)}.json", data)


def publish_refinement(run_root: Path, actions: Sequence[Mapping[str, Any]], *,
                       policy=None, profiles=None, environment=None, releases=None) -> dict[str, Any]:
    from appsec_review.jobs.job_target_analysis_plan.job import load_accepted_plan
    root = Path(run_root)
    plan = load_accepted_plan(root)
    graph = plan["build_topology"]["executable_graph"]
    if graph["schema"] != BUILD_TOPOLOGY_SCHEMA:
        raise ValueError("graph/1 requires accepted replanning, not synthetic graph/2 authority")
    source_bundle = plan["build_topology"]["evidence_bundle"]
    if environment is None:
        environment = source_bundle["environment"]
    if profiles is None:
        profiles = source_bundle["profiles"]
    accepted = {unit["build_unit_id"]: copy.deepcopy(unit)
                for unit in plan["build_topology"]["build_actions"]}
    changed = {action["build_unit_id"] for action in actions}
    carried = {}
    if set(accepted) - changed:
        for action in actions:
            prior = action.get("topology_refinement")
            if prior is None:
                continue
            load_refinement(root, prior, graph=graph, plan=plan)
            previous = _read(root, _read(root, prior)["inputs"])["actions"]
            for unit in previous:
                uid = unit["build_unit_id"]
                if uid in changed:
                    continue
                recipe = unit.get("recipe")
                if uid in carried and carried[uid] != recipe:
                    raise ValueError("refinement requires one explicit complete accepted recipe snapshot")
                carried[uid] = copy.deepcopy(recipe)
        for uid, recipe in carried.items():
            accepted[uid]["recipe"] = recipe
    seen = set()
    for action in actions:
        uid = action["build_unit_id"]
        if uid not in accepted or uid in seen:
            raise ValueError("refinement names an unknown or duplicated accepted action")
        seen.add(uid)
        accepted[uid] = {**accepted[uid], **copy.deepcopy(dict(action))}
    complete = list(accepted.values())
    refinement = refine_build_topology(
        graph, complete, policy=policy, profiles=profiles,
        environment=environment, releases=releases)
    graph_ref = _retain(root, "graphs", graph)
    plan_ref = _retain(root, "plans", plan)
    actions_ref = _retain(root, "inputs", {"actions": complete})
    refinement_ref = _retain(root, "refinements", refinement)
    acceptance = {"schema": "appsec-review/accepted-topology-refinement/1",
                  "plan": plan_ref, "graph": graph_ref, "inputs": actions_ref,
                  "refinement": refinement_ref, "plan_identity": _digest(plan),
                  "graph_identity": graph["topology_id"],
                  "refinement_id": refinement["refinement_id"]}
    receipt = _retain(root, "acceptances", acceptance)
    pointer = root / "data/build/topology/accepted-refinements.json"
    with FileLock(pointer.with_suffix(".lock")):
        index = (_read_refinement_index(pointer) if pointer.exists() else
                 {"schema": INDEX_SCHEMA, "entries": []})
        if receipt not in index["entries"]:
            index["entries"].append(receipt)
            if len(canonical_json(index)) > INDEX_BYTE_LIMIT:
                raise ValueError("accepted refinement index publication exceeds its byte bound")
            atomic_json(pointer, index)
    return receipt


@lru_cache(maxsize=2)
def _verify_derivation(graph_bytes: bytes, input_bytes: bytes, refinement_bytes: bytes) -> None:
    graph, inputs, refinement = map(json.loads, (graph_bytes, input_bytes, refinement_bytes))
    validate_refinement(graph, refinement)
    expected = refine_build_topology(
        graph, inputs["actions"], policy=refinement["policy"],
        profiles=refinement["profiles"], environment=refinement["environment"],
        releases=refinement["releases"])
    if expected != refinement:
        raise ValueError("accepted refinement does not reproduce from its complete immutable inputs")


def load_refinement(run_root: Path, receipt: Mapping[str, Any], *, graph=None, plan=None):
    from appsec_review.jobs.job_target_analysis_plan.job import load_accepted_plan
    root = Path(run_root)
    pointer = root / "data/build/topology/accepted-refinements.json"
    if not pointer.is_file():
        raise ValueError("accepted refinement publication is missing")
    index = _read_refinement_index(pointer)
    if receipt not in index["entries"]:
        raise ValueError("refinement has no accepted index entry")
    acceptance = _read(root, receipt)
    if acceptance.get("schema") != "appsec-review/accepted-topology-refinement/1":
        raise ValueError("unsupported refinement acceptance")
    stored_plan, stored_graph = _read(root, acceptance["plan"]), _read(root, acceptance["graph"])
    live_plan = load_accepted_plan(root) if plan is None else plan
    if (_digest(stored_plan) != acceptance["plan_identity"]
            or stored_plan != live_plan or graph is not None and stored_graph != graph
            or stored_graph != stored_plan["build_topology"]["executable_graph"]):
        raise ValueError("refinement acceptance belongs to a different immutable plan")
    inputs = _read(root, acceptance["inputs"])
    refinement = _read(root, acceptance["refinement"])
    _verify_derivation(canonical_json(stored_graph), canonical_json(inputs), canonical_json(refinement))
    if (acceptance["refinement_id"] != refinement["refinement_id"]
            or acceptance["graph_identity"] != stored_graph["topology_id"]):
        raise ValueError("accepted refinement does not reproduce from its immutable complete inputs")
    return refinement


def guard_action(run_root: Path, action: Mapping[str, Any], *, graph=None,
                 configuration=None, releases=None, image_identity=None) -> Mapping[str, Any]:
    from appsec_review.jobs.job_target_analysis_plan.job import load_accepted_plan
    plan = load_accepted_plan(Path(run_root))
    accepted_graph = plan["build_topology"]["executable_graph"]
    if accepted_graph["schema"] != BUILD_TOPOLOGY_SCHEMA:
        raise ValueError("graph/1 remains audit-only and requires accepted replanning before execution or reuse")
    if not isinstance(action.get("recipe"), Mapping):
        raise ValueError("execution requires the exact selected non-null recipe")
    if graph is not None and graph != accepted_graph:
        raise ValueError("execution graph differs from the complete immutable accepted graph")
    receipt = action.get("topology_refinement")
    if not isinstance(receipt, Mapping):
        raise ValueError("execution requires an accepted recipe-bound refinement")
    refinement = load_refinement(run_root, receipt, graph=accepted_graph, plan=plan)
    if releases is not None and refinement["releases"] != dict(releases):
        raise ValueError("execution releases differ from the accepted refinement")
    if configuration is not None:
        settings = configuration.get("build_selection")
        if settings is None:
            settings = configuration.get("settings", {}).get("build_selection")
        if settings is not None and refinement["policy"] != settings:
            raise ValueError("execution selection differs from the accepted refinement")
    bound = refinement_unit(accepted_graph, refinement, action["build_unit_id"], action.get("recipe"))
    source = next(item for item in plan["build_topology"]["build_actions"]
                  if item["build_unit_id"] == action["build_unit_id"])
    for key in _SOURCE_KEYS:
        if key in action and action[key] != source.get(key):
            raise ValueError("dispatch source fact differs from the accepted plan: " + key)
    if "descriptor_package" in action and action["descriptor_package"] != source.get("descriptor_package"):
        raise ValueError("dispatch declaring documents differ from the accepted whole bundle")
    if action.get("source_fingerprint", accepted_graph["source_fingerprint"]) != accepted_graph["source_fingerprint"]:
        raise ValueError("dispatch source identity differs from the accepted plan")
    if bound["recipe_digest"] is None or bound["blockers"]:
        raise ValueError("build execution blocked: " + "; ".join(bound["blockers"]))
    image_value = action.get("image")
    if image_value is not None and not isinstance(image_value, Mapping):
        raise ValueError("dispatch image must be an immutable image record")
    recorded_image = image_value.get("image_id") if image_value is not None else None
    if image_identity is not None and recorded_image is not None and image_identity != recorded_image:
        raise ValueError("prospective and recorded native image identities disagree")
    image = image_identity or recorded_image
    if image is not None and (not isinstance(image, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image)):
        raise ValueError("native image admission requires an immutable image identity")
    if bound["enforcement"] and image is None:
        raise ValueError("native admission requires a bound prospective or recorded immutable image")
    for proof in bound["enforcement"]:
        if proof["proof_kind"] in {"compiler_explicit_target", "compiler_pinned_default",
                                  "msbuild_selected_mapping"}:
            metadata = refinement["profiles"]
            if image is not None and (not isinstance(metadata, Mapping) or metadata.get("image_digest") != image):
                raise ValueError("native compiler metadata is bound to a different immutable image")
            if (image_identity is not None and any(action["recipe"].get(field) for field in (
                    "system_packages", "image_repairs", "environment"))
                    and metadata.get("image_recipe_digest") != _digest(action["recipe"])):
                raise ValueError("native image derivation has no prebound compiler/recipe metadata")
    return bound


def bind_actions(run_root: Path, actions: Sequence[Mapping[str, Any]], *, policy=None,
                 profiles=None, environment=None, releases=None) -> list[dict[str, Any]]:
    receipt = publish_refinement(run_root, actions, policy=policy, profiles=profiles,
                                 environment=environment, releases=releases)
    return [{**copy.deepcopy(dict(action)), "topology_refinement": receipt} for action in actions]


def selected_cache_actions(run_root: Path) -> dict[str, Mapping[str, Any]]:
    """Read selected revisions without reconstructing a workspace or replaying a trial."""
    root = Path(run_root)
    pointer = root / "data/build/iterations/selection.json"
    if not pointer.is_file():
        return {}
    if pointer.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("selected revision pointer exceeds its byte bound")
    selections = _read(root, json.loads(pointer.read_bytes())["selection"])
    actions = {}
    for uid, selected in selections.items():
        context = _read(root, selected["context"])
        promotion = _read(root, selected["promotion"])
        trial = _read(root, promotion["trial"])
        if (promotion.get("schema") != "appsec-review/build-recipe-promotion/1"
                or promotion.get("production_reexecution_required") is not True
                or promotion.get("trial_products_reusable_in_production") is not False
                or context != _read(root, promotion["context"])
                or context["binding"]["node_id"] != uid
                or _digest(promotion["recipe"]) != promotion["recipe_identity"]):
            raise ValueError("selected revision has no matching immutable recipe-only promotion")
        failure = _read(root, context["inputs"]["failure"])
        original = _read(root, failure["request"])["dispatch"]
        image = {**original["image"], "image_id": promotion["image_identity"]}
        action = {**original, "recipe": promotion["recipe"], "image": image,
                  "topology_refinement": trial["topology_refinement"]}
        guard_action(root, action, releases=context["releases"])
        from appsec_review.jobs.build_iterations import decode_replay_context
        from appsec_review.jobs.build_recipe_replay import verify_selected_trial
        verify_selected_trial(root, decode_replay_context(context), promotion, trial)
        actions[uid] = action
    return actions


def guard_cache_action(run_root: Path, action: Mapping[str, Any], *, interfaces=None, **bindings):
    bound = guard_action(run_root, action, **bindings)
    selected = selected_cache_actions(run_root).get(action["build_unit_id"])
    if selected is not None and (action.get("recipe") != selected["recipe"]
                                or action.get("image", {}).get("image_id") != selected["image"]["image_id"]):
        raise ValueError("cached execution differs from the selected immutable recipe revision")
    if action.get("family") == "go":
        from appsec_review.jobs.job_language_build.go import build_facts, verify_target_facts
        for artifact in action.get("artifacts", ()):
            if artifact.get("kind") == "executable":
                path = safe_path(Path(run_root), artifact["path"])
                verify_target_facts(build_facts(path), bound, action["recipe"])
    if interfaces is not None:
        from appsec_review.jobs.job_target_analysis_plan.job import load_accepted_plan
        from appsec_review.jobs.build_iterations import BuildIterations, read_reference
        from appsec_review.jobs.build_workspace import ProductSpec, verify_retained_product
        from appsec_review.jobs.build_topology import ready_build_units, verify_product_contract
        root = Path(run_root)
        graph = load_accepted_plan(root)["build_topology"]["executable_graph"]
        needed = {edge["producer_build_unit_id"] for edge in graph["edges"]
                  if edge["consumer_build_unit_id"] == action["build_unit_id"]}
        if needed:
            pointer = root / "data/build/iterations/ledger.json"
            if not pointer.is_file() or pointer.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("direct execution lacks bounded accepted producer admission")
            ledger = json.loads(pointer.read_bytes())
            if ledger.get("schema") != "appsec-review/build-iterations/1":
                raise ValueError("direct execution producer ledger has changed schema")
            products = {}
            for uid in needed:
                entry = ledger["nodes"].get(uid)
                if entry is None:
                    raise ValueError("direct execution required producer has not succeeded: " + uid)
                completion = read_reference(root, entry["completion"])
                request = read_reference(root, completion["request"])
                producer = guard_cache_action(root, request["dispatch"], **bindings)
                binding = BuildIterations._decode_binding(entry["binding"])
                if request["binding"] != entry["binding"]:
                    raise ValueError("direct execution producer differs from its accepted request binding")
                product = verify_retained_product(root, entry["generation"], entry["product"], binding)
                verify_product_contract(producer, product["products"])
                relative = f"artifacts/build/workspace/generations/{entry['generation']}.json"
                generation = _read(root, {"path": relative, "sha256": entry["generation"],
                                          "size_bytes": safe_path(root, relative).stat().st_size})
                products[uid] = (entry, product, binding, generation)

            def verified(row):
                uid = row.get("producer_build_unit_id")
                if uid not in products:
                    return False
                entry, product, binding, generation = products[uid]
                spec = next((ProductSpec(**item) for item in product["products"]
                             if item["product_id"] == row.get("product_id")), None)
                if spec is None:
                    return False
                from appsec_review.jobs.build_workspace import WorkspaceWriter
                resolved = WorkspaceWriter._link_target(spec.path, generation["entries"])
                physical = generation["entries"][resolved]
                footprint = {path: item for path, item in product["entries"].items()
                             if path == spec.path or path.startswith(spec.path + "/")}
                identity = physical["sha256"] if physical["kind"] == "file" else _digest(footprint)
                return all(row.get(key) == value for key, value in {
                    "workspace_product": entry["product"], "kind": spec.kind,
                    "interface": spec.interface, "variant": dict(spec.variant),
                    "role": spec.role, "axes": spec.axes, "path": spec.container_path,
                    "topology_id": binding.graph_identity, "recipe_revision": binding.recipe_identity,
                    "sha256": identity,
                }.items())

            refinement = load_refinement(root, action["topology_refinement"], graph=graph)
            readiness = ready_build_units(graph, {uid: "SUCCEEDED" for uid in needed},
                                          products=interfaces, verify_product=verified, refinement=refinement)
            if action["build_unit_id"] not in readiness["ready"]:
                raise ValueError("direct execution required interfaces are unresolved or incompatible")
    return bound


def guard_build_cache(run_root: Path, job_id: str, output: Mapping[str, Any], *,
                      configuration=None, releases=None, source_fingerprint=None, unit_id=None) -> None:
    if job_id not in {"job_project_build", "job_language_build", "job_build_iteration"}:
        return
    if job_id == "job_project_build" and unit_id and unit_id.startswith("static_dispatch."):
        return
    from appsec_review.jobs.job_target_analysis_plan.job import load_accepted_plan
    if (source_fingerprint is not None and load_accepted_plan(Path(run_root))[
            "build_topology"]["executable_graph"]["source_fingerprint"] != source_fingerprint):
        raise ValueError("build cache has no accepted plan for the current source snapshot")
    pending = [output]
    admitted, count = 0, 0
    while pending:
        value = pending.pop()
        count += 1
        if count > 100000:
            raise ValueError("build cache output exceeds its structural bound")
        if isinstance(value, Mapping):
            action = value.get("action")
            if isinstance(action, Mapping):
                action = {**action, **({"image": value["image"]} if value.get("image") is not None else {})}
                pending.append(action)
            if "build_unit_id" in value and (
                    isinstance(value.get("recipe"), Mapping) or value.get("terminal_status") == "SUCCEEDED"):
                if source_fingerprint is not None and value.get(
                        "source_fingerprint", source_fingerprint) != source_fingerprint:
                    raise ValueError("cached build belongs to a different source snapshot")
                if not isinstance(value.get("recipe"), Mapping):
                    raise ValueError("cached build lacks a positive descriptor and recipe basis")
                guard_cache_action(run_root, value, configuration=configuration, releases=releases)
                admitted += 1
            for key, nested in value.items():
                if key == "action":
                    continue
                if key == "completion" and isinstance(nested, Mapping):
                    completed = _read(Path(run_root), nested)
                    request = _read(Path(run_root), completed["request"])
                    execution = guard_cache_action(run_root, request["dispatch"],
                                                   configuration=configuration, releases=releases)
                    from appsec_review.jobs.build_iterations import BuildIterations
                    from appsec_review.jobs.build_workspace import verify_retained_product
                    from appsec_review.jobs.build_topology import verify_product_contract
                    product = verify_retained_product(
                        Path(run_root), completed["generation"], completed["workspace_product"],
                        BuildIterations._decode_binding(completed["binding"]))
                    verify_product_contract(execution, product["products"])
                    pending.extend([request["dispatch"], _read(Path(run_root), completed["receipt"])])
                elif key in {"artifact", "iteration"} and isinstance(nested, Mapping) and {
                        "path", "sha256", "size_bytes"} <= nested.keys():
                    pending.append(_read(Path(run_root), nested))
                elif isinstance(nested, (Mapping, list, tuple)):
                    pending.append(nested)
        elif isinstance(value, (list, tuple)):
            pending.extend(value)
    if not admitted:
        raise ValueError("build cache has no positively admitted execution inputs")
