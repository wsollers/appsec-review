"""Detached, full-context trials and immutable recipe-only promotion.

The production controller supplies accepted identities and the existing captured
executor boundary. This module never executes host commands, builds images itself,
edits frozen inputs, or copies trial mutations into the production workspace.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Literal

from appsec_review.config.assurance import ComponentReleases
from appsec_review.container_runtime.build_capture import CaptureScope, verify_capture_record
from appsec_review.container_runtime.build_executor import BuildCommandResult, BuildProfile
from appsec_review.jobs.build_discovery import ensure_declared_build_dir, validate_build_recipe
from appsec_review.jobs.build_recipe_commands import (
    normalize_recipe_command, prepare_recipe_command,
)
from appsec_review.jobs.build_topology import ready_build_units, validate_build_topology
from appsec_review.jobs.build_workspace import (
    BuildWorkspace, NodeBinding, ProductSpec, WorkspaceError, WorkspacePaths, WorkspaceWriter,
)
from appsec_review.storage.atomic import canonical_json, canonical_json_sha256
from appsec_review.storage.lock import FileLock
from appsec_review.storage.shared import immutable_bytes, reference, safe_path, verify_reference


CANDIDATE_SCHEMA = "appsec-review/build-recipe-candidate/1"
REPLAY_SCHEMA = "appsec-review/build-recipe-replay/1"
PROMOTION_SCHEMA = "appsec-review/build-recipe-promotion/1"
_ROOT = "artifacts/build/recipe-replay"
_VARIANT = {"configuration", "target_arch", "execution_role", "linkage", "toolchain", "abi"}
_IMAGE_FIELDS = ("system_packages", "image_repairs", "environment")
_MUTABLE = {"configure_commands", "build_commands", "build_dir", "expected_outputs",
            "system_packages", "image_repairs", "environment", "reason", "execution_cwd"}


class ReplayRefused(ValueError):
    def __init__(self, reason_code: str, reason: str):
        super().__init__(f"{reason_code}: {reason}")
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class ProducerProduct:
    binding: NodeBinding
    reference: Mapping[str, Any]

    def view(self) -> dict[str, Any]:
        return {"binding": self.binding.view(), "reference": dict(self.reference)}


@dataclass(frozen=True, slots=True)
class ReplayContext:
    run_id: str
    failed_attempt_id: str
    binding: NodeBinding
    generation_identity: str
    validation_unit: Mapping[str, Any]
    accepted_recipe: Mapping[str, Any]
    variant: Mapping[str, str | None]
    products: tuple[ProductSpec, ...]
    releases: Mapping[str, str]
    inputs: Mapping[str, Mapping[str, Any]]
    upstreams: tuple[ProducerProduct, ...] = ()

    def view(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "failed_attempt_id": self.failed_attempt_id,
                "binding": self.binding.view(), "generation_identity": self.generation_identity,
                "validation_unit": deepcopy(dict(self.validation_unit)),
                "accepted_recipe": deepcopy(dict(self.accepted_recipe)),
                "variant": dict(self.variant), "products": [asdict(spec) for spec in self.products],
                "releases": dict(self.releases),
                "inputs": {name: dict(ref) for name, ref in self.inputs.items()},
                "upstreams": [item.view() for item in self.upstreams]}


@dataclass(frozen=True, slots=True)
class RecipeCandidate:
    recipe: Mapping[str, Any]
    evidence: tuple[Mapping[str, Any], ...]
    reason: str
    products: tuple[ProductSpec, ...] | None = None

    def view(self) -> dict[str, Any]:
        return {"schema": CANDIDATE_SCHEMA, "recipe": deepcopy(dict(self.recipe)),
                "evidence": [dict(ref) for ref in self.evidence], "reason": self.reason,
                "products": None if self.products is None else [asdict(spec) for spec in self.products]}


@dataclass(frozen=True, slots=True)
class ReplayInvocation:
    context: ReplayContext
    candidate: RecipeCandidate
    paths: WorkspacePaths
    capture_directory: Path
    attempt_id: str
    network: str
    image_identity: str
    profile: BuildProfile | None = None
    interfaces: tuple[Mapping[str, Any], ...] = ()

    @property
    def commands(self) -> tuple[tuple[str, ...], ...]:
        return _command_plan(self.candidate.recipe)

    @property
    def working_directories(self) -> tuple[str, ...]:
        return _working_directories(self.candidate.recipe)

    def prepare_command(self, ordinal: int) -> tuple[tuple[str, ...], str]:
        """C calls this immediately before each captured container launch."""
        if type(ordinal) is not int or not 0 <= ordinal < len(self.commands):
            raise ReplayRefused("invalid_command_ordinal", "command ordinal is outside the validated sequence")
        cwd = self.working_directories[ordinal]
        recipe = self.candidate.recipe
        build_dir = recipe["build_dir"]
        build_cwd = cwd == build_dir or build_dir != "." and cwd.startswith(build_dir + "/")
        if cwd != recipe["source_dir"] and not build_cwd:
            documents = self.context.validation_unit.get("descriptor_package", {}).get("documents", ())
            if not any(PurePosixPath(item["path"]).parent.as_posix() == cwd for item in documents):
                raise ReplayRefused("unproven_execution_cwd", "source cwd needs accepted descriptor evidence")
        try:
            ensure_declared_build_dir(self.paths.target, recipe)
            path = self.paths.target if cwd == "." else safe_path(self.paths.target, cwd)
        except ValueError as error:
            raise ReplayRefused("unsafe_execution_cwd", str(error)) from error
        if not path.is_dir() or path.is_symlink() or path.absolute() != path.resolve():
            raise ReplayRefused("unsafe_execution_cwd", "effective cwd must be an existing nonsymlink workspace directory")
        configure_count = len(recipe["configure_commands"])
        phase: Literal["configure", "build"] = "configure" if ordinal < configure_count else "build"
        index = ordinal if phase == "configure" else ordinal - configure_count
        return prepare_recipe_command(
            self.paths.target, self.context.validation_unit, recipe, phase, recipe[f"{phase}_commands"][index])


@dataclass(frozen=True, slots=True)
class TrialExecution:
    commands: tuple[BuildCommandResult, ...]
    cleanup_complete: bool


@dataclass(frozen=True, slots=True)
class ImageResolution:
    profile: BuildProfile
    evidence: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class PromotedRecipe:
    recipe: Mapping[str, Any]
    products: tuple[ProductSpec, ...]
    image_identity: str
    recipe_identity: str
    reference: Mapping[str, Any]
    profile: BuildProfile | None = None


ReplayExecutor = Callable[[ReplayInvocation], TrialExecution]
ApprovedImageBuilder = Callable[[ReplayContext, RecipeCandidate, bool], ImageResolution]


def _read(run: Path, ref: Mapping[str, Any]) -> dict[str, Any]:
    path = verify_reference(run, ref)
    if not str(ref["path"]).startswith(("artifacts/", "data/")):
        raise ReplayRefused("disposable_evidence", "evidence must outlive the disposable tree")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ReplayRefused("invalid_evidence", "expected an evidence object")
    return value


def _verify_evidence(run: Path, ref: Mapping[str, Any]) -> Path:
    if not isinstance(ref, Mapping) or not str(ref.get("path", "")).startswith(("artifacts/", "data/")):
        raise ReplayRefused("disposable_evidence", "evidence must be a durable run-owned reference")
    return verify_reference(run, ref)


def _publish(run: Path, kind: str, value: Mapping[str, Any]) -> dict[str, Any]:
    identity = canonical_json_sha256(value)
    return immutable_bytes(run, f"{_ROOT}/{kind}/{identity}.json", canonical_json(value))


def _load(run: Path, kind: str, ref: Mapping[str, Any]) -> dict[str, Any]:
    if ref.get("path") != f"{_ROOT}/{kind}/{ref.get('sha256')}.json":
        raise ReplayRefused("foreign_receipt", f"not an immutable {kind} receipt")
    return _read(run, ref)


def _recipe_key(recipe: Mapping[str, Any]) -> str:
    value = deepcopy(dict(recipe))
    value.pop("reason", None)
    if isinstance(value.get("execution_cwd"), Mapping):
        explicit = {phase: cwd for phase, cwd in value["execution_cwd"].items()
                    if cwd != value.get("source_dir")}
        if explicit:
            value["execution_cwd"] = explicit
        else:
            value.pop("execution_cwd")
    value["system_packages"] = sorted(value.get("system_packages", ()))
    value["expected_outputs"] = sorted(value.get("expected_outputs", ()))
    if isinstance(value.get("image_repairs"), dict):
        repairs = value["image_repairs"]
        repairs["dependency_restores"] = sorted(repairs.get("dependency_restores", ()),
                                                key=lambda item: item["manifest"])
        if not any((repairs.get("environment"), repairs.get("package_manager"), repairs["dependency_restores"])):
            value.pop("image_repairs")
    return canonical_json_sha256(value)


def _product_views(products: tuple[ProductSpec, ...]) -> list[dict[str, Any]]:
    return sorted((asdict(spec) for spec in products), key=lambda spec: spec["product_id"])


def _validate_context(workspace: BuildWorkspace, context: ReplayContext,
                      writer: WorkspaceWriter) -> dict[str, Any]:
    if workspace.replay_id is not None or not context.run_id or not context.failed_attempt_id:
        raise ReplayRefused("invalid_context", "a named production run and failed attempt are required")
    if context.run_id != workspace.run_dir.name:
        raise ReplayRefused("foreign_run", "context must name this exact run")
    if (not context.releases or any(not isinstance(value, str) or not value.strip()
                                   for value in context.releases.values())):
        raise ReplayRefused("missing_release_identity", "accepted release identities are required")
    try:
        releases = ComponentReleases(context.releases)
    except ValueError as error:
        raise ReplayRefused("invalid_release_identity", str(error)) from error
    implementation = "job_project_build" if "job_project_build" in releases.values else "platform"
    reusable, reason = releases.require(implementation, "validation")
    if not reusable or any(releases.values.get(key) == "undeclared" for key in (implementation, "validation")):
        raise ReplayRefused(reason or "missing_release_identity",
                            "declared implementation and validation releases are required")
    if (set(context.variant) != _VARIANT or any(not isinstance(value, str) or not value.strip()
                                             for value in context.variant.values())
            or context.variant.get("execution_role") not in {"host", "target"}):
        raise ReplayRefused("missing_variant_identity", "all six resolved variant values are required")
    if context.variant["toolchain"] != context.binding.toolchain_identity:
        raise ReplayRefused("toolchain_mismatch", "variant does not name the bound toolchain")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", context.binding.image_identity):
        raise ReplayRefused("missing_image_identity", "an immutable image identity is required")
    if not {"failure", "graph", "configuration", "source"} <= context.inputs.keys():
        raise ReplayRefused("missing_inputs", "failure, graph, configuration and source references are required")
    documents = {name: _read(workspace.run_dir, ref) for name, ref in context.inputs.items()}
    failure = documents["failure"]
    if (failure.get("attempt_id") != context.failed_attempt_id
            or failure.get("binding") != context.binding.view()
            or failure.get("terminal_status") != "FAILED"
            or not isinstance(failure.get("evidence"), list) or not failure["evidence"]):
        raise ReplayRefused("foreign_failure", "failed node/attempt and original evidence must match")
    for ref in failure["evidence"]:
        _verify_evidence(workspace.run_dir, ref)
    configuration = documents["configuration"]
    if (configuration.get("configuration_identity") != context.binding.configuration_identity
            or configuration.get("releases") != dict(context.releases)):
        raise ReplayRefused("configuration_mismatch", "frozen configuration or releases changed")
    source = documents["source"]
    if source.get("source_identity") != context.binding.source_identity:
        raise ReplayRefused("source_mismatch", "source evidence names another snapshot")
    graph = documents["graph"]
    validate_build_topology(graph)
    if (graph["topology_id"] != context.binding.graph_identity
            or graph["source_fingerprint"] != context.binding.source_identity):
        raise ReplayRefused("graph_mismatch", "structural graph or source changed")
    node = next((node for node in graph["nodes"] if node["build_unit_id"] == context.binding.node_id), None)
    if (node is None or node["variant"] != dict(context.variant)
            or node["recipe_revision"] != context.binding.recipe_identity
            or canonical_json_sha256(context.accepted_recipe) != context.binding.recipe_identity
            or context.validation_unit.get("build_unit_id") != context.binding.node_id
            or context.validation_unit.get("root") != node["root"]
            or context.validation_unit.get("family") != node["family"]
            or context.validation_unit.get("build_system") != node["build_system"]):
        raise ReplayRefused("node_mismatch", "accepted node, recipe, unit or variant changed")
    markers = context.validation_unit.get("markers", ())
    if {(marker["path"], marker["sha256"]) for marker in markers} != {
            (item["path"], item["sha256"]) for item in node["evidence"]
            if item["relationship"] == "build_descriptor"}:
        raise ReplayRefused("descriptor_identity_mismatch", "validation markers differ from the accepted execution graph")
    for marker in markers:
        if source.get("entries", {}).get(f"target/{marker['path']}", {}).get("sha256") != marker.get("sha256"):
            raise ReplayRefused("descriptor_identity_mismatch", "validation marker is not in the accepted source snapshot")
    for document in context.validation_unit.get("descriptor_package", {}).get("documents", ()):
        if (source.get("entries", {}).get(f"target/{document['path']}", {}).get("sha256") != document.get("sha256")
                or "content" in document and hashlib.sha256(document["content"].encode()).hexdigest() != document.get("sha256")):
            raise ReplayRefused("descriptor_identity_mismatch", "validation descriptor differs from the accepted source bytes")
    errors = validate_build_recipe(context.accepted_recipe, context.validation_unit)
    if errors:
        raise ReplayRefused("invalid_accepted_recipe", "; ".join(errors))
    # B verifies all retained CAS bytes and accepted producer records, even if a
    # failed command has left the production mount dirty. Never scan/restore it here.
    generation = writer.committed_generation(context.generation_identity)
    state = writer.state()
    if state["generation"] != context.generation_identity:
        raise ReplayRefused("stale_generation", "production advanced since the selected failure")
    if state["condition"] == "running":
        raise ReplayRefused("active_production_attempt", "production has an unfinished active command")
    if state["attempt"] is not None and state["attempt"]["attempt_id"] != context.failed_attempt_id:
        raise ReplayRefused("stale_failure", "production now names a different failed attempt")
    if generation["input_identity"] != context.inputs["source"]["sha256"]:
        raise ReplayRefused("source_mismatch", "workspace input differs from the frozen source evidence")
    if context.binding.node_id in generation["accepted"]:
        raise ReplayRefused("node_already_accepted", "the failed node has since succeeded")
    identities: list[str] = []
    for upstream in context.upstreams:
        ref = dict(upstream.reference)
        if generation["accepted"].get(upstream.binding.node_id) != ref:
            raise ReplayRefused("upstream_mismatch", "producer is not accepted in this generation")
        record = _read(workspace.run_dir, ref)
        if record.get("binding") != upstream.binding.view():
            raise ReplayRefused("upstream_mismatch", "producer binding changed")
        if (upstream.binding.source_identity != context.binding.source_identity
                or upstream.binding.graph_identity != context.binding.graph_identity
                or upstream.binding.configuration_identity != context.binding.configuration_identity):
            raise ReplayRefused("upstream_mismatch", "producer has incompatible frozen inputs")
        identities.append(ref["sha256"])
    if tuple(sorted(identities)) != tuple(sorted(context.binding.upstream_products)):
        raise ReplayRefused("upstream_mismatch", "exact upstream product identities are required")
    _validate_products(context.products, context, node)
    return graph


def _validate_products(products: tuple[ProductSpec, ...], context: ReplayContext,
                       node: Mapping[str, Any]) -> None:
    if (not 1 <= len(products) <= 64
            or len({spec.product_id for spec in products}) != len(products)
            or len({spec.path for spec in products}) != len(products)):
        raise ReplayRefused("missing_product_contract", "unique verified product declarations are required")
    declared = {spec.product_id: {"product_id": spec.product_id, "kind": spec.kind,
                                 "interface": spec.interface, "variant": dict(spec.variant)}
                for spec in products}
    for product in node["products"]:
        if declared.get(product["product_id"]) != product:
            raise ReplayRefused("product_contract_mismatch", "required topology product contract changed")
    for spec in products:
        if dict(spec.variant) != dict(context.variant):
            raise ReplayRefused("product_variant_mismatch", "product variant differs from the failed node")


def _validate_candidate(context: ReplayContext, candidate: RecipeCandidate, run: Path,
                        graph: Mapping[str, Any]) -> tuple[ProductSpec, ...]:
    if (not isinstance(candidate.reason, str) or not candidate.reason.strip()
            or len(candidate.reason.encode()) > 4096 or not 1 <= len(candidate.evidence) <= 64):
        raise ReplayRefused("missing_candidate_evidence", "a bounded reason and accepted evidence are required")
    accepted_evidence = [*context.inputs.values(), *(item.reference for item in context.upstreams),
                         *_read(run, context.inputs["failure"])["evidence"]]
    accepted_identities = {canonical_json_sha256(dict(ref)) for ref in accepted_evidence}
    for ref in candidate.evidence:
        _verify_evidence(run, ref)
        if canonical_json_sha256(dict(ref)) not in accepted_identities:
            raise ReplayRefused("foreign_candidate_evidence", "candidate evidence is outside the frozen accepted context")
    recipe = candidate.recipe
    errors = validate_build_recipe(recipe, context.validation_unit)
    if errors:
        raise ReplayRefused("invalid_candidate_recipe", "; ".join(errors))
    for field in set(context.accepted_recipe) | set(recipe):
        if field not in _MUTABLE and recipe.get(field) != context.accepted_recipe.get(field):
            raise ReplayRefused("recipe_authority_changed", f"candidate cannot change {field}")
    previous_environment = context.accepted_recipe.get("image_repairs", {}).get("environment", {})
    repair_environment = recipe.get("image_repairs", {}).get("environment", {})
    expected_environment = {key: value for key, value in context.accepted_recipe["environment"].items()
                            if key not in previous_environment}
    if set(expected_environment) & set(repair_environment):
        raise ReplayRefused("unbounded_environment", "image repair cannot replace accepted environment")
    expected_environment.update(repair_environment)
    if recipe["environment"] != expected_environment:
        raise ReplayRefused("unbounded_environment", "environment changes require the closed image-repair contract")
    for argv in [*recipe["configure_commands"], *recipe["build_commands"]]:
        if (any(re.search(r"https?://|(?:token|password|credential)=", word, re.I) for word in argv)
                or argv[0] == "cmake" and any(word in {"-E", "-P", "--install"} for word in argv[1:])
                or argv[0] in {"python", "python3", "php", "node"} and any(
                    word in {"-c", "-e", "--eval", "-r"} for word in argv[1:])):
            raise ReplayRefused("unbounded_recipe_command", "inline scripts, fetch URLs and source patch commands are forbidden")
    products = context.products if candidate.products is None else candidate.products
    node = next(node for node in graph["nodes"] if node["build_unit_id"] == context.binding.node_id)
    _validate_products(products, context, node)
    if {spec.product_id for spec in products} != {spec.product_id for spec in context.products}:
        raise ReplayRefused("product_contract_mismatch", "candidate cannot add or remove accepted product declarations")
    baseline = {spec.product_id: spec for spec in context.products}
    if any((spec.kind, spec.interface, dict(spec.variant)) !=
           (baseline[spec.product_id].kind, baseline[spec.product_id].interface,
            dict(baseline[spec.product_id].variant)) for spec in products):
        raise ReplayRefused("product_contract_mismatch", "only evidence-backed product paths may change")
    return products


def _command_plan(recipe: Mapping[str, Any]) -> tuple[tuple[str, ...], ...]:
    return tuple(normalize_recipe_command(recipe, phase, argv)[0]
                 for phase in ("configure", "build") for argv in recipe[f"{phase}_commands"])


def _working_directories(recipe: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(normalize_recipe_command(recipe, phase, argv)[1]
                 for phase in ("configure", "build") for argv in recipe[f"{phase}_commands"])


def _commands(run: Path, invocation: ReplayInvocation, execution: TrialExecution) -> tuple[list[dict[str, Any]], list[str]]:
    expected = _command_plan(invocation.candidate.recipe)
    records: list[dict[str, Any]] = []
    gaps: list[str] = []
    if not execution.commands or len(execution.commands) > len(expected):
        raise ReplayRefused("command_mismatch", "trial must execute the bounded configure/build sequence")
    stopped = False
    scope = CaptureScope(invocation.context.run_id, "job_project_build", invocation.attempt_id,
                         invocation.context.binding.node_id, str(invocation.context.validation_unit["family"]))
    for ordinal, result in enumerate(execution.commands):
        if stopped or result.argv != expected[ordinal]:
            raise ReplayRefused("command_mismatch", "trial ran an unexpected command or continued after failure")
        if type(result.timed_out) is not bool or result.exit_code is not None and type(result.exit_code) is not int:
            raise ReplayRefused("invalid_command_outcome", "actual exit and timeout are required")
        stopped = result.timed_out or result.exit_code != 0
        if result.capture_record is None or result.stdout_file is None or result.stderr_file is None:
            raise ReplayRefused("missing_capture", "actual captured command and retained streams are required")
        for path in (result.capture_record, result.stdout_file, result.stderr_file):
            if not path.is_relative_to(invocation.capture_directory):
                raise ReplayRefused("foreign_capture", "trial evidence is outside its durable capture directory")
        verified = verify_capture_record(result.capture_record, run_root=run, scope=scope)
        command = verified.document["command"]
        if (command.get("argv") != list(result.argv)
                or command.get("working_directory") != invocation.working_directories[ordinal]
                or command.get("exit_code") != result.exit_code
                or command.get("timed_out") != result.timed_out
                or verified.document.get("collector", {}).get("image_id") != invocation.image_identity):
            raise ReplayRefused("capture_command_mismatch", "capture differs from the actual invocation/image")
        for name, path in (("stdout", result.stdout_file), ("stderr", result.stderr_file)):
            if path.resolve() != (result.capture_record.parent / verified.document["streams"][name]["uri"]).resolve():
                raise ReplayRefused("capture_stream_mismatch", "retained stream differs from captured command stream")
        if verified.gaps:
            gaps.extend(verified.gaps)
        if verified.findings["findings"]:
            gaps.append("capture_secret_findings")
        records.append({"ordinal": ordinal, "argv": list(result.argv),
                        "working_directory": invocation.working_directories[ordinal], "exit_code": result.exit_code,
                        "timed_out": result.timed_out,
                        "capture": reference(run, result.capture_record),
                        "stdout": reference(run, result.stdout_file),
                        "stderr": reference(run, result.stderr_file)})
    if stopped:
        gaps.append("command_failed")
    elif len(execution.commands) != len(expected):
        gaps.append("command_sequence_incomplete")
    return records, gaps


def replay_recipe(workspace: BuildWorkspace, context: ReplayContext, candidate: RecipeCandidate, *,
                  execute: ReplayExecutor, network_offline: bool = False,
                  approved_image_builder: ApprovedImageBuilder | None = None) -> dict[str, Any]:
    """Run exactly one candidate, under B's replay writer through mount closure.

    A stopped proposal returns an immutable STOPPED receipt without invoking Docker.
    Exceptions retain the unfinished intent; they never make retention eligible.
    """
    if type(network_offline) is not bool:
        raise ReplayRefused("invalid_network_mode", "network_offline must be a boolean")
    context = deepcopy(context)
    candidate = deepcopy(candidate)
    run = workspace.run_dir
    context_identity = canonical_json_sha256(context.view())
    key = canonical_json_sha256({"context": context_identity, "recipe": _recipe_key(candidate.recipe),
                                "products": _product_views(context.products if candidate.products is None else candidate.products),
                                "network_offline": network_offline})
    claim = safe_path(run, f"data/build/recipe-replay/{context_identity}.lock")
    with FileLock(claim):
        with workspace.writer() as writer:
            graph = _validate_context(workspace, context, writer)
            products = _validate_candidate(context, candidate, run, graph)
            context_ref = _publish(run, "contexts", context.view())
            candidate_ref = _publish(run, "candidates", candidate.view())
            base = {"schema": REPLAY_SCHEMA, "context": context_ref, "candidate": candidate_ref,
                    "candidate_key": key, "network": "none" if network_offline else "bridge"}
            seen = safe_path(run, f"{_ROOT}/selected/{key}.json")
            no_op = (_recipe_key(candidate.recipe) == _recipe_key(context.accepted_recipe)
                     and _product_views(products) == _product_views(context.products))
            if no_op or seen.exists():
                return _publish(run, "trials", {**base, "status": "STOPPED",
                    "reason": "normalized_no_op" if no_op else "normalized_duplicate"})
            immutable_bytes(run, f"{_ROOT}/selected/{key}.json", canonical_json(base))
            if network_offline and candidate.recipe["network_required"]:
                return _publish(run, "trials", {**base, "status": "BLOCKED",
                    "reason": "network_offline_requires_prepared_dependencies"})
            image_identity = context.binding.image_identity
            image_evidence = None
            image_profile = None
            if any(candidate.recipe.get(field) != context.accepted_recipe.get(field) for field in _IMAGE_FIELDS):
                if approved_image_builder is None:
                    return _publish(run, "trials", {**base, "status": "BLOCKED",
                        "reason": "derived_image_preparation_unavailable"})
                resolution = approved_image_builder(context, candidate, network_offline)
                receipt = _read(run, resolution.evidence)
                if (receipt.get("image_id") != resolution.profile.image_id
                        or receipt.get("profile") != asdict(resolution.profile)
                        or receipt.get("recipe_identity") != canonical_json_sha256(candidate.recipe)
                        or receipt.get("operator_approved") is not True
                        or resolution.profile.name != context.accepted_recipe["image_profile"]
                        or network_offline and (receipt.get("network") != "none"
                                                or receipt.get("prepared") is not True)):
                    raise ReplayRefused("unverified_image_preparation", "approved bounded image evidence is required")
                image_identity, image_evidence = resolution.profile.image_id, dict(resolution.evidence)
                image_profile = resolution.profile
            replay_id = f"recipe-{key}"
            replay = writer.create_replay(replay_id, context.generation_identity)
        attempt = f"replay-{key[:32]}"
        intent = _publish(run, "intents", {**base, "replay_id": replay_id, "attempt_id": attempt,
                          "image_identity": image_identity, "image_evidence": image_evidence,
                          "image_profile": None if image_profile is None else asdict(image_profile)})
        capture_dir = safe_path(run, f"{_ROOT}/captures/{key}")
        invocation = ReplayInvocation(context, candidate, replay.paths, capture_dir, attempt,
                                      base["network"], image_identity, image_profile)
        with replay.writer() as trial:
            interfaces: list[dict[str, Any]] = []
            producer_by_node = {item.binding.node_id: item for item in context.upstreams}
            for producer in context.upstreams:
                interfaces.extend(trial.product_interfaces(producer.reference, producer.binding))
            invocation = replace(invocation, interfaces=tuple(deepcopy(interfaces)))

            def verify(product: Mapping[str, Any]) -> bool:
                producer = producer_by_node[product["producer_build_unit_id"]]
                return trial.verify_product(product["workspace_product"], producer.binding).identity == producer.reference["sha256"]

            readiness = ready_build_units(graph, {node: "SUCCEEDED" for node in producer_by_node},
                                          products=interfaces, verify_product=verify)
            if context.binding.node_id not in readiness["ready"]:
                raise ReplayRefused("prerequisites_not_ready", str(readiness["blocked"]))
            binding = replace(context.binding, recipe_identity=canonical_json_sha256(candidate.recipe),
                              image_identity=image_identity)
            trial.begin_attempt(binding, attempt, context.generation_identity)
            invocation.prepare_command(0)
            execution = execute(invocation)
            if type(execution.cleanup_complete) is not bool:
                raise ReplayRefused("invalid_cleanup_proof", "worker cleanup must be explicitly confirmed")
            commands, gaps = _commands(run, invocation, execution)
            if not execution.cleanup_complete:
                gaps.append("worker_cleanup_unconfirmed")
            output = None
            if not gaps:
                for relative in candidate.recipe["expected_outputs"]:
                    path = safe_path(replay.paths.target, relative)
                    if not path.exists() or path.is_dir() and not any(path.rglob("*")):
                        gaps.append(f"required_output_missing:{relative}")
            if not gaps:
                try:
                    output = trial.commit(products)
                except WorkspaceError as error:
                    gaps.append(f"product_verification_failed:{error}")
                else:
                    before = trial.committed_generation(context.generation_identity)["entries"]
                    retained = _read(run, output.reference)["entries"]
                    if not any(item["kind"] == "file" and item.get("sha256") != before.get(path, {}).get("sha256")
                               for path, item in retained.items()):
                        gaps.append("no_new_or_changed_build_product")
                        output = None
                    else:
                        trial.product_interfaces(output, binding)
            if gaps and trial.state()["attempt"] is not None:
                trial.fail_attempt("; ".join(gaps))
            result = _publish(run, "trials", {**base, "intent": intent,
                "status": "SUCCEEDED" if not gaps else "FAILED" if execution.cleanup_complete else "UNFINISHED",
                "reason": None if not gaps else "; ".join(gaps), "commands": commands,
                "cleanup_complete": execution.cleanup_complete,
                "binding": binding.view(), "products": None if output is None else dict(output.reference),
                "verified_interfaces": [] if output is None else list(trial.product_interfaces(output, binding)),
                "generation_identity": trial.state()["generation"]})
            if gaps and execution.cleanup_complete:
                trial.restore(context.generation_identity)
        if execution.cleanup_complete:
            replay.mark_terminal(workers_stopped=True)
        return result


def _verified_trial(workspace: BuildWorkspace, context: ReplayContext,
                    trial_ref: Mapping[str, Any], writer: WorkspaceWriter
                    ) -> tuple[dict[str, Any], dict[str, Any], BuildProfile | None]:
    graph = _validate_context(workspace, context, writer)
    run = workspace.run_dir
    trial = _load(run, "trials", trial_ref)
    if (trial.get("schema") != REPLAY_SCHEMA or trial.get("status") != "SUCCEEDED"
            or trial.get("cleanup_complete") is not True
            or _load(run, "contexts", trial["context"]) != context.view()):
        raise ReplayRefused("unverified_trial", "only a successful, cleaned, exact-context trial can be promoted")
    intent = _load(run, "intents", trial["intent"])
    if any(intent.get(key) != trial.get(key) for key in ("context", "candidate", "candidate_key", "network")):
        raise ReplayRefused("trial_identity_mismatch", "trial differs from its immutable intent")
    value = _load(run, "candidates", trial["candidate"])
    if value.get("schema") != CANDIDATE_SCHEMA:
        raise ReplayRefused("candidate_schema", "candidate schema is unsupported")
    candidate = RecipeCandidate(value["recipe"], tuple(value["evidence"]), value["reason"],
                                None if value["products"] is None else
                                tuple(ProductSpec(**spec) for spec in value["products"]))
    products = _validate_candidate(context, candidate, run, graph)
    expected_binding = replace(context.binding, recipe_identity=canonical_json_sha256(candidate.recipe),
                               image_identity=intent["image_identity"])
    if trial.get("binding") != expected_binding.view():
        raise ReplayRefused("trial_binding_mismatch", "recipe, image or execution inputs changed")
    profile = None
    if intent.get("image_evidence") is not None:
        try:
            profile = BuildProfile(**intent["image_profile"])
        except (KeyError, TypeError, ValueError) as error:
            raise ReplayRefused("invalid_image_profile", "approved full image profile is required") from error
        image = _read(run, intent["image_evidence"])
        if (image.get("image_id") != expected_binding.image_identity or image.get("operator_approved") is not True
                or profile.name != context.accepted_recipe["image_profile"]
                or profile.image_id != expected_binding.image_identity or image.get("profile") != asdict(profile)
                or image.get("recipe_identity") != expected_binding.recipe_identity
                or trial["network"] == "none" and (image.get("network") != "none" or image.get("prepared") is not True)):
            raise ReplayRefused("image_mismatch", "image preparation evidence changed")
    elif (expected_binding.image_identity != context.binding.image_identity
          or intent.get("image_profile") is not None
          or any(candidate.recipe.get(field) != context.accepted_recipe.get(field) for field in _IMAGE_FIELDS)):
        raise ReplayRefused("image_mismatch", "changed image inputs require bounded preparation evidence")
    expected = _command_plan(candidate.recipe)
    if len(trial.get("commands", ())) != len(expected):
        raise ReplayRefused("command_sequence_incomplete", "the trial did not complete every required command")
    scope = CaptureScope(context.run_id, "job_project_build", intent["attempt_id"],
                         context.binding.node_id, str(context.validation_unit["family"]))
    for argv, cwd, result in zip(expected, _working_directories(candidate.recipe), trial["commands"], strict=True):
        for name in ("stdout", "stderr", "capture"):
            _verify_evidence(run, result[name])
        captured = verify_capture_record(verify_reference(run, result["capture"]), run_root=run, scope=scope)
        if (result["argv"] != list(argv) or result["exit_code"] != 0 or result["timed_out"] is not False
                or captured.gaps or captured.document["command"]["argv"] != list(argv)
                or captured.document["command"]["exit_code"] != 0
                or captured.document["command"]["timed_out"] is not False
                or captured.document["command"].get("working_directory") != cwd
                or result.get("working_directory", candidate.recipe["source_dir"]) != cwd
                or captured.findings["findings"]
                or captured.document.get("collector", {}).get("image_id") != expected_binding.image_identity):
            raise ReplayRefused("unverified_command", "actual captured command is not a successful exact trial")
    # Durable generation validation works after the disposable replay subtree is swept.
    generation = writer.committed_generation(trial["generation_identity"])
    product = _read(run, trial["products"])
    if (product.get("binding") != expected_binding.view()
            or generation["accepted"].get(context.binding.node_id) != trial["products"]
            or product.get("products") != [asdict(spec) for spec in products]
            or not trial.get("verified_interfaces")):
        raise ReplayRefused("unverified_products", "verified trial products/interfaces are missing or changed")
    interfaces = {item["product_id"]: item for item in trial["verified_interfaces"]}
    if len(interfaces) != len(products):
        raise ReplayRefused("unverified_interfaces", "trial interfaces do not exactly cover the product contract")
    for spec in products:
        interface = interfaces.get(spec.product_id, {})
        if any(interface.get(key) != value for key, value in {
            "producer_build_unit_id": context.binding.node_id, "kind": spec.kind,
            "interface": spec.interface, "variant": dict(spec.variant), "path": spec.container_path,
            "topology_id": expected_binding.graph_identity, "recipe_revision": expected_binding.recipe_identity,
            "workspace_product": trial["products"],
        }.items()):
            raise ReplayRefused("unverified_interfaces", "trial interface identity differs from verified products")
    return trial, dict(candidate.recipe), profile


def promote_recipe(workspace: BuildWorkspace, context: ReplayContext,
                   trial_ref: Mapping[str, Any]) -> dict[str, Any]:
    """Publish a recipe revision, not acceptance of replay products in production."""
    with workspace.writer() as writer:
        trial, recipe, profile = _verified_trial(workspace, context, trial_ref, writer)
        return _publish(workspace.run_dir, "promotions", {
            "schema": PROMOTION_SCHEMA, "context": trial["context"], "trial": dict(trial_ref),
            "recipe": recipe, "recipe_identity": canonical_json_sha256(recipe),
            "production_reexecution_required": True, "trial_products_reusable_in_production": False,
            "image_identity": trial["binding"]["image_identity"],
            "image_profile": None if profile is None else asdict(profile),
            "products": _read(workspace.run_dir, trial["products"])["products"],
        })


def load_promoted_revision(workspace: BuildWorkspace, context: ReplayContext,
                           promotion_ref: Mapping[str, Any]) -> PromotedRecipe:
    """Revalidate all inputs at consumption; stale upstreams are an explicit refusal."""
    with workspace.writer() as writer:
        promotion = _load(workspace.run_dir, "promotions", promotion_ref)
        if (promotion.get("schema") != PROMOTION_SCHEMA
                or promotion.get("production_reexecution_required") is not True
                or promotion.get("trial_products_reusable_in_production") is not False):
            raise ReplayRefused("invalid_promotion", "promotion is not a recipe-only reexecution input")
        trial, recipe, profile = _verified_trial(workspace, context, promotion["trial"], writer)
        if (promotion.get("context") != trial["context"] or promotion.get("recipe") != recipe
                or promotion.get("recipe_identity") != canonical_json_sha256(recipe)
                or promotion.get("image_identity") != trial["binding"]["image_identity"]
                or promotion.get("image_profile") != (None if profile is None else asdict(profile))
                or promotion.get("products") != _read(workspace.run_dir, trial["products"])["products"]):
            raise ReplayRefused("promotion_mismatch", "promotion differs from its verified trial")
        return PromotedRecipe(recipe, tuple(ProductSpec(**spec) for spec in promotion["products"]),
                              promotion["image_identity"], promotion["recipe_identity"], dict(promotion_ref), profile)


def load_promoted_recipe(workspace: BuildWorkspace, context: ReplayContext,
                         promotion_ref: Mapping[str, Any]) -> dict[str, Any]:
    """Compatibility convenience for callers that do not revise export paths."""
    return dict(load_promoted_revision(workspace, context, promotion_ref).recipe)
