"""Admission and observed reads at accepted evidence boundaries.

Verification walks are not semantic reads. Observations are made only by consumer readers,
never by manifest validators, and never assert model use or citation.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
import json
from pathlib import Path
import re
from threading import RLock
from typing import Any, Callable, Iterator, Mapping, ParamSpec, TypeVar

from appsec_review.runtime.contracts import (
    Availability, CoveragePolicy, InputChannel, InputRequirement, JobContract, MissingPolicy,
)
from appsec_review.runtime.datasets import DatasetDeclaration, read_dataset_contract, shard_owner
from appsec_review.storage import file_sha256
from appsec_review.storage.shared import safe_path, verify_handoff

INPUT_ADMISSION_SCHEMA = "appsec-review/input-admission/1"
INPUT_READS_SCHEMA = "appsec-review/input-reads/1"
EXTERNAL_SELECTION_SCHEMA = "appsec-review/external-input-selection/1"
PARENT_REEXECUTION_SCHEMA = "appsec-review/parent-reexecution/2"


def external_selection(rows: list[dict[str, Any]]) -> str:
    return json.dumps({"schema": EXTERNAL_SELECTION_SCHEMA, "inputs": rows},
                      sort_keys=True, separators=(",", ":"))


def read_external_selection(document: object, contract: JobContract | None) -> dict[str, Any]:
    if (not isinstance(document, dict) or set(document) != {"schema", "inputs"}
            or document["schema"] != EXTERNAL_SELECTION_SCHEMA or not isinstance(document["inputs"], list)
            or contract is None):
        raise ValueError("external input selection requires fresh typed admission")
    declared = {(item.producer, item.output_kind, item.schema) for item in contract.inputs
                if item.channel is InputChannel.EXTERNAL}
    seen = set()
    for row in document["inputs"]:
        if not isinstance(row, dict) or set(row) != {
                "producer", "output_kind", "schema", "selector", "status", "identity", "reason"}:
            raise ValueError("invalid external input selection fields")
        if not all(isinstance(row[key], str) for key in ("producer", "output_kind", "schema", "selector", "status")):
            raise ValueError("invalid external input selection identity")
        key = row["producer"], row["output_kind"], row["schema"]
        if key not in declared or not row["selector"] or (*key, row["selector"]) in seen:
            raise ValueError("undeclared or duplicate external input selection")
        seen.add((*key, row["selector"]))
        if row["status"] == "available":
            if (not isinstance(row["identity"], dict) or not row["identity"] or row["reason"] is not None
                    or not all(isinstance(key, str) and isinstance(value, str)
                               for key, value in row["identity"].items())):
                raise ValueError("invalid supplied external identity")
        elif row["status"] in {"unavailable", "not_applicable"}:
            if row["identity"] is not None or not isinstance(row["reason"], str) or not row["reason"]:
                raise ValueError("external absence requires a named reason")
        else:
            raise ValueError("invalid external input selection status")
    if {key[:3] for key in seen} != declared:
        raise ValueError("external selection omits a declared source")
    return document


def retained_parent_inputs(job: Any, root: Path, orchestration: Mapping[str, Any] | None) -> dict[str, str]:
    correlation = orchestration or {}
    identity = correlation.get("parent_reexecution_plan")
    if identity is None:
        return {}
    from appsec_review.runtime.release import digest, read_document
    if (correlation.get("system") != "dagster" or correlation.get("workflow") != "wave1_review"
            or not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{64}", identity)):
        raise ValueError("invalid parent re-execution input selection")
    plan = read_document(safe_path(root, f"data/recovery/reexecutions/{identity}.json"))
    if (plan.get("schema") != PARENT_REEXECUTION_SCHEMA or plan.get("sha256") != identity
            or digest({key: value for key, value in plan.items() if key != "sha256"}) != identity
            or plan.get("application_run_id") != root.name
            or plan.get("parent_run_id") != correlation.get("parent_run_id")
            or digest(plan.get("step_keys")) != correlation.get("reexecution_steps_sha256")
            or job.job_id.removeprefix("job_") + "__begin" not in plan.get("step_keys", [])):
        raise ValueError("parent re-execution inputs are not bound to this dispatch and job")
    from appsec_review.runtime.repair import current_binding
    binding = current_binding(root)
    if binding is None or binding["release_sha256"] != plan.get("release_sha256"):
        raise ValueError("parent re-execution source is not the admitted implementation")
    from appsec_review.runtime.configuration import admitted_configuration_sha256
    if admitted_configuration_sha256(root, binding) != plan.get("resolved_config_sha256"):
        raise ValueError("parent re-execution configuration is not admitted")
    repair = plan.get("source_repair")
    if repair is not None:
        if (not isinstance(repair, dict) or not binding.get("repair")
                or binding["repair"]["path"] != f"data/recovery/repairs/{repair.get('plan_sha256')}.json"):
            raise ValueError("parent re-execution source repair was not admitted")
    elif digest(binding) != plan.get("binding_sha256"):
        raise ValueError("parent re-execution implementation binding changed")
    pins = plan.get("retained_handoffs")
    if not isinstance(pins, dict) or any(
            not isinstance(producer, str) or not re.fullmatch(r"job_[a-z0-9_]+", producer)
            or not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
            for producer, value in pins.items()):
        raise ValueError("invalid retained parent handoff pins")
    return pins


def selected_handoffs(job: Any, root: Path, supplied: Mapping[str, str] | None, *,
                      enabled: set[str] | None = None,
                      retained: Mapping[str, str] | None = None) -> dict[str, str]:
    """An untagged single-job launch selects only its declared currently accepted inputs."""
    if job.contract is None:
        return dict(supplied or {})
    if supplied is not None:
        unknown = set(supplied) - set(job.consumes)
        if unknown:
            raise ValueError(f"undeclared supplied handoffs for {job.job_id}: {sorted(unknown)}")
        for producer, digest in supplied.items():
            pointer = safe_path(root, f"data/jobs/{producer}/latest.json")
            if not pointer.is_file() or json.loads(pointer.read_bytes()).get("handoff_sha256") != digest:
                if (retained or {}).get(producer) != digest:
                    raise ValueError(f"supplied handoff is stale or unavailable: {producer}")
                from appsec_review.retrieval.core import _accepted_handoff
                from appsec_review.runtime.repair import verify_publication
                original, _ = _accepted_handoff(root, producer, digest)
                verify_publication(root, original, digest)
        from appsec_review.retrieval.core import _accepted_handoff
        result = dict(supplied)
        pending = list(result.items())
        visited = set()
        while pending:
            producer, digest = pending.pop()
            if producer in visited:
                continue
            visited.add(producer)
            handoff, _ = _accepted_handoff(root, producer, digest)
            verify_handoff(root, handoff)
            for name, value in handoff["upstream_handoff_sha256"].items():
                if name not in job.consumes:
                    continue
                if name in result and result[name] != value:
                    raise ValueError(f"conflicting supplied input lineages: {name}")
                if name not in result:
                    result[name] = value
                    pending.append((name, value))
        return result
    result = {}
    for producer in job.consumes:
        if enabled is not None and producer not in enabled:
            continue
        pointer = safe_path(root, f"data/jobs/{producer}/latest.json")
        if pointer.is_file():
            value = json.loads(pointer.read_bytes())
            result[producer] = value["handoff_sha256"]
    return result


def producer_contract(root: Path, handoff: Mapping[str, Any]) -> tuple[DatasetDeclaration, ...]:
    claim = json.loads(safe_path(root, handoff["resolving_paths"]["attempt"] + "/claim.json").read_bytes())
    document = claim["dataset_contract"]
    if document["sha256"] != handoff["dataset_contract_sha256"]:
        raise ValueError("producer dataset contract differs from accepted handoff")
    return read_dataset_contract(document, handoff["job_id"])[1]


def resolve_job_inputs(
    config: Any,
    job: Any,
    run_root: Path,
    source_fingerprint: str,
    orchestration: Mapping[str, Any] | None,
    upstream_handoffs: Mapping[str, str] | None,
    *,
    enabled: set[str],
) -> tuple[dict[str, str], dict[str, str], Mapping[str, Any] | None, dict[str, str]]:
    """Resolve current-target ``upstream_handoffs`` separately from admitted ``optional_prior_handoffs``."""
    from appsec_review.retrieval.core import _accepted_handoff
    retained = retained_parent_inputs(job, run_root, orchestration)
    if job.job_id == "job_target_analysis_plan":
        from appsec_review.jobs.job_build_environment_analysis.job import (
            JOB_ID as ENV_JOB_ID,
            environment_contract,
            optional_prior_environment_handoffs,
            planning_environment_inputs,
        )
        correlation = dict(orchestration or {})
        if upstream_handoffs is not None:
            unknown = sorted(set(upstream_handoffs) - set(job.consumes))
            if unknown:
                raise ValueError(f"undeclared supplied handoffs: {', '.join(unknown)}")
            pre_contract = environment_contract(config, correlation, upstream_handoffs)
            if pre_contract["mode"] == "OPTIONAL_PRIOR":
                without_prior = {key: value for key, value in upstream_handoffs.items() if key != ENV_JOB_ID}
                selected = selected_handoffs(job, run_root, without_prior, enabled=enabled, retained=retained)
                candidate = {**selected, ENV_JOB_ID: str(pre_contract["reference"])}
            else:
                candidate = selected_handoffs(job, run_root, upstream_handoffs, enabled=enabled, retained=retained)
        else:
            candidate = selected_handoffs(job, run_root, None, enabled=enabled)
        contract, required_upstream = planning_environment_inputs(
            config, run_root, source_fingerprint, correlation, candidate)
        optional_prior = optional_prior_environment_handoffs(contract)
        return required_upstream, optional_prior, contract, candidate

    selected = selected_handoffs(job, run_root, upstream_handoffs, enabled=enabled, retained=retained)
    required_upstream = dict(selected)
    optional_prior: dict[str, str] = {}
    if "job_target_analysis_plan" in required_upstream and "job_build_environment_analysis" in job.consumes:
        plan_handoff, _ = _accepted_handoff(
            run_root, "job_target_analysis_plan", required_upstream["job_target_analysis_plan"])
        artifact_ref = plan_handoff.get("outputs", {}).get("plan_acceptance.publish_handoff", {}).get("artifact")
        if isinstance(artifact_ref, Mapping) and isinstance(artifact_ref.get("path"), str):
            plan_path = safe_path(run_root, artifact_ref["path"])
            if plan_path.is_file():
                plan_doc = json.loads(plan_path.read_bytes())
                bound_env = plan_doc.get("build_environment") if isinstance(plan_doc, Mapping) else None
                if (isinstance(bound_env, Mapping)
                        and bound_env.get("mode") == "OPTIONAL_PRIOR"
                        and isinstance(bound_env.get("reference"), str)):
                    if upstream_handoffs is None or "job_build_environment_analysis" not in upstream_handoffs:
                        required_upstream.pop("job_build_environment_analysis", None)
                    optional_prior["job_build_environment_analysis"] = bound_env["reference"]
    overlap = sorted(set(required_upstream) & set(optional_prior))
    if overlap:
        raise ValueError(f"conflicting current and optional-prior input lineages: {', '.join(overlap)}")
    return required_upstream, optional_prior, None, dict(required_upstream)


def admit_inputs(context: Any, enabled: set[str]) -> dict[str, Any]:
    """Pin supply, absence and coverage separately from subsequent observed reads."""
    from appsec_review.config.assurance import AssuranceMode
    from appsec_review.retrieval.core import _accepted_handoff
    contract = context.contract
    optional_prior = dict(getattr(context, "optional_prior_handoffs", None) or {})
    overlap = sorted(set(context.upstream_handoffs) & set(optional_prior))
    if overlap:
        raise ValueError(f"conflicting current and optional-prior input lineages: {', '.join(overlap)}")
    if contract is None:
        if optional_prior:
            raise ValueError("optional-prior inputs require a typed contract")
        return {"schema": INPUT_ADMISSION_SCHEMA, "requirements": []}
    handoffs = {}
    declarations = {}
    handoff: Mapping[str, Any] | None
    for producer, digest in sorted(context.upstream_handoffs.items()):
        if producer not in contract.consumes:
            raise ValueError(f"undeclared supplied producer: {producer}")
        handoff, _ = _accepted_handoff(context.run_root, producer, digest)
        verify_handoff(context.run_root, handoff)
        if handoff["target_snapshot"] not in {"none", context.evidence_target_snapshot}:
            raise ValueError(f"foreign target input: {producer}")
        handoffs[producer] = handoff
        declarations[producer] = {item.output_kind: item for item in producer_contract(context.run_root, handoff)}
    prior_rows = []
    from appsec_review.storage.validation import isolated_validation_scope
    for producer, digest in sorted(optional_prior.items()):
        if producer not in contract.consumes:
            raise ValueError(f"undeclared optional-prior producer: {producer}")
        prior_handoff, _ = _accepted_handoff(context.run_root, producer, digest)
        with isolated_validation_scope(context.run_root):
            verify_handoff(context.run_root, prior_handoff)
            if getattr(getattr(context, "review_policy", None), "mode", None) is AssuranceMode.FIRST_PARTY_MANAGED:
                from appsec_review.storage.admission import verify_optional_prior_admission
                verify_optional_prior_admission(context, prior_handoff)
        prior_decls = {item.output_kind: item for item in producer_contract(context.run_root, prior_handoff)}
        for requirement in contract.inputs:
            if requirement.producer != producer or requirement.channel is not InputChannel.HANDOFF:
                continue
            if requirement.output_kind == "handoff":
                if prior_handoff["schema"] != requirement.schema:
                    raise ValueError(f"input envelope schema mismatch: {producer}")
                prior_available = True
            else:
                declaration = prior_decls.get(requirement.output_kind)
                if declaration is None or declaration.schema != requirement.schema:
                    raise ValueError(f"producer output contract mismatch: {producer}/{requirement.output_kind}")
                if declaration.authority is None or declaration.authority != requirement.authority:
                    raise ValueError(f"producer evidence authority mismatch: {producer}/{requirement.output_kind}")
                prior_available = _has_output(context.run_root, prior_handoff, declaration,
                                              tuple(prior_decls.values()))
            coverage = prior_handoff["coverage"]
            if requirement.coverage is CoveragePolicy.REQUIRE_COMPLETE and coverage["disposition"] != "complete":
                raise ValueError(f"input coverage is not complete: {producer}")
            if requirement.coverage is CoveragePolicy.REQUIRE_NONRETRIABLE and coverage["retry_required"]:
                raise ValueError(f"input coverage requires retry: {producer}")
            prior_rows.append({
                "channel": requirement.channel.value, "producer": producer,
                "output_kind": requirement.output_kind, "schema": requirement.schema,
                "authority": requirement.authority.value, "available": prior_available,
                "supplied": prior_available, "read": False, "cited": None,
                "handoff_sha256": digest, "attempt_id": prior_handoff["attempt_id"],
                "target_snapshot": prior_handoff["target_snapshot"], "coverage": dict(coverage),
                "status": "supplied" if prior_available else "gap",
            })
    rows = []
    for requirement in contract.inputs:
        row: dict[str, Any] = {
            "channel": requirement.channel.value, "producer": requirement.producer,
            "output_kind": requirement.output_kind, "schema": requirement.schema,
            "authority": requirement.authority.value, "available": None, "supplied": False,
            "read": False, "cited": None,
        }
        if requirement.channel is not InputChannel.HANDOFF:
            row["status"] = "requires_channel_reader"
            if requirement.channel is InputChannel.EXTERNAL and context.external_input_selection is not None:
                selections = [item for item in context.external_input_selection["inputs"]
                              if (item["producer"], item["output_kind"]) == (
                                  requirement.producer, requirement.output_kind)]
                supplied = any(item["status"] == "available" for item in selections)
                missing = any(item["status"] == "unavailable" for item in selections)
                row.update(available=supplied, supplied=supplied, selections=selections,
                           status="partial" if supplied and missing else "supplied" if supplied else
                           "gap" if missing else "not_applicable")
                if not supplied and requirement.required(enabled) and requirement.missing is MissingPolicy.REJECT:
                    raise ValueError(f"required external input unavailable: {requirement.producer}/{requirement.output_kind}")
            rows.append(row)
            continue
        handoff = handoffs.get(requirement.producer)
        available = False
        if handoff is not None:
            if requirement.output_kind == "handoff":
                if handoff["schema"] != requirement.schema:
                    raise ValueError(f"input envelope schema mismatch: {requirement.producer}")
                available = True
            else:
                declaration = declarations[requirement.producer].get(requirement.output_kind)
                # Only explicit compatibility admits historical declaration absence. It grants no
                # read permission and never bypasses a present declaration's schema or authority.
                if declaration is not None or requirement.availability is not Availability.WHEN_DECLARED:
                    if declaration is None or declaration.schema != requirement.schema:
                        raise ValueError(f"producer output contract mismatch: {requirement.producer}/{requirement.output_kind}")
                    if declaration.authority is None or declaration.authority != requirement.authority:
                        raise ValueError(f"producer evidence authority mismatch: {requirement.producer}/{requirement.output_kind}")
                    # The accepted producer's artifacts/shards establish produced availability.
                    available = _has_output(context.run_root, handoff, declaration,
                                            tuple(declarations[requirement.producer].values()))
            row.update(handoff_sha256=context.upstream_handoffs[requirement.producer],
                       attempt_id=handoff["attempt_id"], target_snapshot=handoff["target_snapshot"],
                       coverage=dict(handoff["coverage"]))
            coverage = handoff["coverage"]
            if requirement.coverage is CoveragePolicy.REQUIRE_COMPLETE and coverage["disposition"] != "complete":
                raise ValueError(f"input coverage is not complete: {requirement.producer}")
            if requirement.coverage is CoveragePolicy.REQUIRE_NONRETRIABLE and coverage["retry_required"]:
                raise ValueError(f"input coverage requires retry: {requirement.producer}")
        row.update(available=available if handoff is not None else None, supplied=available)
        if not available:
            if requirement.required(enabled) and requirement.missing is MissingPolicy.REJECT:
                raise ValueError(f"required input unavailable: {requirement.producer}/{requirement.output_kind}")
            row["status"] = "not_applicable" if requirement.missing is MissingPolicy.NOT_APPLICABLE else "gap"
        else:
            row["status"] = "supplied"
        rows.append(row)
    document: dict[str, Any] = {
        "schema": INPUT_ADMISSION_SCHEMA, "contract_sha256": contract.document()["sha256"],
        "requirements": rows,
    }
    if prior_rows:
        document["optional_priors"] = prior_rows
    return document


def _has_output(root: Path, handoff: Mapping[str, Any], declaration: DatasetDeclaration,
                declarations: tuple[DatasetDeclaration, ...]) -> bool:
    from appsec_review.indexing.inventory import compile_glob
    for ref in handoff["artifacts"]:
        if any(compile_glob(pattern).fullmatch(ref["path"]) for pattern in declaration.artifacts):
            return True
    if declaration.indexes:
        from appsec_review.indexing.store import handoff_manifests
        return any(shard.get("producer", {}).get("job") == handoff["job_id"]
                   and shard_owner(declarations, shard["name"], shard.get("shard_id", "default")) == declaration
                   for manifest in handoff_manifests(root, handoff)
                   for shard in manifest["document"]["indexes"])
    return False


@dataclass
class InputReads:
    context: Any
    records: dict[str, Mapping[str, Any]] = field(default_factory=dict)
    lock: RLock = field(default_factory=RLock)
    producers: dict[str, tuple[Mapping[str, Any], tuple[DatasetDeclaration, ...]]] = field(default_factory=dict)
    prior_producers: dict[str, tuple[Mapping[str, Any], tuple[DatasetDeclaration, ...]]] = field(default_factory=dict)
    verified_shards: set[tuple[str, str, str, str]] = field(default_factory=set)
    violation: str | None = None

    def check(self) -> None:
        if self.violation is not None:
            raise ValueError(f"input contract violation: {self.violation}")

    def producer(self, producer: str, *, prior: bool = False) -> tuple[Mapping[str, Any], tuple[DatasetDeclaration, ...]]:
        from appsec_review.retrieval.core import _accepted_handoff
        with self.lock:
            prior_map = dict(getattr(self.context, "optional_prior_handoffs", None) or {})
            if producer in self.context.upstream_handoffs and producer in prior_map:
                raise ValueError(f"conflicting current and optional-prior input lineages: {producer}")
            cache = self.prior_producers if prior else self.producers
            source = prior_map if prior else self.context.upstream_handoffs
            if producer not in cache:
                digest = source.get(producer)
                if digest is None:
                    label = "optional-prior shard producer" if prior else "shard producer"
                    raise ValueError(f"undeclared or unsupplied {label}: {producer}")
                handoff, _ = _accepted_handoff(self.context.run_root, producer, digest)
                cache[producer] = handoff, producer_contract(self.context.run_root, handoff)
            return cache[producer]

    def requirement(self, producer: str, output_kind: str, channel: InputChannel) -> InputRequirement:
        contract = self.context.contract
        if not isinstance(contract, JobContract):
            raise ValueError("input reader has no typed contract")
        for item in contract.inputs:
            if (item.producer, item.output_kind, item.channel) == (producer, output_kind, channel):
                return item
        raise ValueError(f"undeclared consumption by {self.context.config.job_id}: {producer}/{output_kind}")

    def record(self, requirement: InputRequirement, identity: Mapping[str, Any]) -> None:
        if {"producer", "output_kind", "schema", "channel", "authority", "read", "cited"} & identity.keys():
            raise ValueError("input identity cannot override observation authority")
        value = {"producer": requirement.producer, "output_kind": requirement.output_kind,
                 "schema": requirement.schema, "channel": requirement.channel.value,
                 "authority": requirement.authority.value, "read": True, "cited": None, **identity}
        key = json.dumps(value, sort_keys=True)
        with self.lock:
            self.records[key] = value

    def document(self) -> dict[str, Any]:
        with self.lock:
            return {"schema": INPUT_READS_SCHEMA, "reads": [self.records[key] for key in sorted(self.records)],
                    "citation_observation": "not_observed"}


_READS: ContextVar[InputReads | None] = ContextVar("job_input_reads", default=None)


@contextmanager
def input_read_scope(context: Any) -> Iterator[InputReads | None]:
    if getattr(context, "contract", None) is None:
        yield None
        return
    current = _READS.get()
    if current is not None and current.context is context:
        yield current
        return
    reads = InputReads(context)
    token = _READS.set(reads)
    try:
        from appsec_review.runtime.consume import upstream_scope
        with upstream_scope(context.run_root, context.config.job_id, context.upstream_handoffs,
                            contract=context.contract,
                            optional_prior_handoffs=getattr(context, "optional_prior_handoffs", None)):
            yield reads
            reads.check()
    finally:
        _READS.reset(token)


P = ParamSpec("P")
T = TypeVar("T")


def _read_boundary(function: Callable[P, T]) -> Callable[P, T]:
    @wraps(function)
    def checked(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return function(*args, **kwargs)
        except (ValueError, OSError, KeyError, TypeError) as error:
            reads = _READS.get()
            if reads is not None:
                with reads.lock:
                    if reads.violation is None:
                        reads.violation = str(error)
            raise
    return checked


def check_input_reads() -> None:
    reads = _READS.get()
    if reads is not None:
        reads.check()


def supplied_named_receipts(
        root: Path, namespace: str, fingerprint: str, *,
        claim: Mapping[str, Any], cache: dict[tuple[str, str], Mapping[str, Any]],
) -> Iterator[tuple[Mapping[str, Any], str, Mapping[str, Any]]]:
    """Verification-only provenance candidates; this does not record a semantic input read."""
    from appsec_review.retrieval.core import _accepted_handoff
    reads = _READS.get()
    if reads is not None and Path(root).resolve() != reads.context.run_root.resolve():
        raise ValueError("named input metadata belongs to a foreign run")
    contract = claim.get("dataset_contract", {}).get("job_contract", {})
    declared = {item["producer"] for item in contract.get("inputs", ())
                if item["output_kind"] == "handoff" and item["channel"] == "handoff"}
    for producer, digest in sorted(claim.get("upstream_handoffs", {}).items()):
        if producer not in declared:
            continue
        key = producer, digest
        if key not in cache:
            if reads is not None and reads.context.config.job_id == claim["job_id"]:
                reads.requirement(producer, "handoff", InputChannel.HANDOFF)
                cache[key] = reads.producer(producer)[0]
            else:
                cache[key] = _accepted_handoff(root, producer, digest)[0]
        handoff = cache[key]
        if file_sha256(safe_path(root, handoff["resolving_paths"]["attempt"] + "/handoff.json")) != digest:
            raise ValueError("supplied named input publication changed")
        prefix = handoff["resolving_paths"]["attempt"] + "/shared/"
        exact = prefix + namespace + "/" + fingerprint + ".json"
        for ref in handoff["artifacts"]:
            if ref["path"] == exact or ref["path"].startswith(prefix + "shared-input/"):
                yield handoff, digest, ref


@_read_boundary
def input_shard_owner(root: Path, shard: Mapping[str, Any]) -> DatasetDeclaration:
    """Resolve source-view ownership against the same pinned producer used by observed reads."""
    producer = shard.get("producer", {}).get("job")
    reads = _READS.get()
    if reads is not None:
        if Path(root).resolve() != reads.context.run_root.resolve():
            raise ValueError("input producer contract belongs to a foreign run")
        declarations = reads.producer(producer)[1]
    else:
        from appsec_review.indexing.store import accepted_handoff
        accepted = accepted_handoff(root, producer)
        if accepted is None:
            raise ValueError(f"source shard producer has no accepted contract: {producer}")
        declarations = producer_contract(root, accepted.handoff)
    return shard_owner(declarations, shard["name"], shard.get("shard_id", "default"))


@_read_boundary
def observe_handoff(root: Path, handoff: Mapping[str, Any], *, prior: bool = False) -> None:
    reads = _READS.get()
    if reads is None or handoff["job_id"] == reads.context.config.job_id:
        return
    context = reads.context
    if Path(root).resolve() != context.run_root.resolve():
        raise ValueError("consumed handoff belongs to a foreign run")
    producer = handoff["job_id"]
    prior_map = dict(getattr(context, "optional_prior_handoffs", None) or {})
    if producer in context.upstream_handoffs and producer in prior_map:
        raise ValueError(f"conflicting current and optional-prior input lineages: {producer}")
    requirement = reads.requirement(producer, "handoff", InputChannel.HANDOFF)
    expected = prior_map.get(producer) if prior else context.upstream_handoffs.get(producer)
    path = safe_path(root, handoff["resolving_paths"]["attempt"] + "/handoff.json")
    if expected is None or file_sha256(path) != expected:
        raise ValueError(f"consumed handoff is not the supplied immutable input: {producer}")
    reads.record(requirement, {"handoff_sha256": expected, "attempt_id": handoff["attempt_id"],
                               "target_snapshot": handoff["target_snapshot"], "coverage": dict(handoff["coverage"])})


@_read_boundary
def observe_shard(root: Path, shard: Mapping[str, Any]) -> None:
    reads = _READS.get()
    if reads is None:
        return
    producer = shard.get("producer", {}).get("job")
    if producer == reads.context.config.job_id:
        return
    context = reads.context
    if Path(root).resolve() != context.run_root.resolve():
        raise ValueError("consumed shard belongs to a foreign run")
    digest = context.upstream_handoffs.get(producer)
    if digest is None:
        raise ValueError(f"undeclared or unsupplied shard producer: {producer}")
    relative, sha = shard["relative_path"], shard["sha256"]
    shard_key = (str(producer), str(digest), str(relative), str(sha))
    from appsec_review.storage.validation import observed_digest
    with reads.lock:
        already_verified = shard_key in reads.verified_shards
    if already_verified:
        if observed_digest(root, safe_path(root, relative)) != sha:
            raise ValueError("consumed shard bytes changed")
        return
    handoff, _declarations = reads.producer(producer)
    owned = input_shard_owner(root, shard)
    requirement = reads.requirement(producer, owned.output_kind, InputChannel.HANDOFF)
    if requirement.schema != owned.schema or requirement.authority != owned.authority:
        raise ValueError("consumed dataset schema or authority differs from input contract")
    if not any(ref["path"] == relative and ref["sha256"] == sha for ref in handoff["artifacts"]):
        raise ValueError("consumed shard is not bound to supplied producer output")
    if observed_digest(root, safe_path(root, relative)) != sha:
        raise ValueError("consumed shard bytes changed")
    reads.record(requirement, {"path": relative, "sha256": sha, "handoff_sha256": digest,
                               "attempt_id": handoff["attempt_id"], "target_snapshot": handoff["target_snapshot"]})
    with reads.lock:
        reads.verified_shards.add(shard_key)


@_read_boundary
def observe_external(root: Path, producer: str, output_kind: str, schema: str,
                     identity: Mapping[str, Any], *, channel: InputChannel = InputChannel.EXTERNAL) -> None:
    reads = _READS.get()
    if reads is None:
        return
    if root.resolve() != reads.context.run_root.resolve():
        raise ValueError("external input observation belongs to a foreign run")
    requirement = reads.requirement(producer, output_kind, channel)
    if schema != requirement.schema:
        raise ValueError("external input schema differs from contract")
    if channel is InputChannel.EXTERNAL:
        selected = reads.context.external_input_selection
        if selected is None:
            if not reads.context.contract.always_execute:
                raise ValueError("external reads require a claimed immutable selection")
        elif not any(
                (row["producer"], row["output_kind"], row["schema"]) == (producer, output_kind, schema)
                and row["status"] == "available"
                and all(identity.get(key) == value for key, value in row["identity"].items())
                for row in selected["inputs"]):
            raise ValueError("external input differs from its claimed immutable selection")
    reads.record(requirement, identity)


_ATTEMPT_CONTEXT: ContextVar[Any | None] = ContextVar("appsec_attempt_input_context", default=None)


@contextmanager
def attempt_input_scope(context: Any) -> Iterator[None]:
    token = _ATTEMPT_CONTEXT.set(context)
    try:
        yield
    finally:
        _ATTEMPT_CONTEXT.reset(token)


def upstream_development_tainted(
    run_root: Path,
    upstream_handoffs: Mapping[str, str],
    optional_prior_handoffs: Mapping[str, str] | None = None,
) -> bool:
    import re
    from appsec_review.interchange import decode_handoff
    from appsec_review.runtime.release import read_document
    from appsec_review.storage.shared import safe_path
    from appsec_review.storage.validation import observed_digest
    pairs = (*upstream_handoffs.items(), *(optional_prior_handoffs or {}).items())
    if not pairs:
        return False
    for producer, digest in pairs:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", producer):
            raise ValueError("invalid claimed upstream job identity")
        matched_doc = None
        latest = safe_path(run_root, f"data/jobs/{producer}/latest.json")
        if latest.is_file():
            pointer = read_document(latest)
            if pointer.get("handoff_sha256") == digest and isinstance(pointer.get("handoff_path"), str):
                candidate = safe_path(run_root, pointer["handoff_path"])
                if candidate.is_file() and observed_digest(run_root, candidate) == digest:
                    matched_doc = read_document(candidate)
        if matched_doc is None:
            attempts = safe_path(run_root, f"data/jobs/{producer}/attempts")
            matches = []
            if attempts.is_dir():
                for path in sorted(attempts.glob("attempt_*/handoff.json")):
                    path = safe_path(run_root, path.relative_to(run_root).as_posix())
                    if observed_digest(run_root, path) == digest:
                        matches.append(path)
            if len(matches) != 1:
                raise ValueError(f"expected exactly one accepted handoff for {producer}")
            matched_doc = read_document(matches[0])
        handoff = decode_handoff(matched_doc, run_id=run_root.name, job_id=producer)
        if handoff.get("development_tainted") is True:
            return True
    return False


@_read_boundary
def observe_output(root: Path, producer: str, output_kind: str, reference: Mapping[str, Any],
                   *, prior: bool = False, _resolved: bool = False) -> None:
    reads = _READS.get()
    if reads is None:
        attempt_ctx = _ATTEMPT_CONTEXT.get()
        if attempt_ctx is not None and Path(root).resolve() == attempt_ctx.run_root.resolve():
            development = None if prior else _development_record(
                attempt_ctx, producer, output_kind, str(reference.get("path", "")))
            if development is not None and not _resolved:
                raise ValueError(
                    f"development input override for {reference.get('path')} requires its consumer to open "
                    "the file through runtime.inputs.input_file; the original bytes were not read")
        return
    if root.resolve() != reads.context.run_root.resolve():
        raise ValueError("consumed output belongs to a foreign run")
    prior_map = dict(getattr(reads.context, "optional_prior_handoffs", None) or {})
    if producer in reads.context.upstream_handoffs and producer in prior_map:
        raise ValueError(f"conflicting current and optional-prior input lineages: {producer}")
    requirement = reads.requirement(producer, output_kind, InputChannel.HANDOFF)
    handoff, declarations = reads.producer(producer, prior=prior)
    if not any(item.output_kind == output_kind and item.schema == requirement.schema
               and item.authority == requirement.authority for item in declarations):
        raise ValueError("consumed output schema differs from input contract")
    path, sha = reference["path"], reference["sha256"]
    if not any(item["path"] == path and item["sha256"] == sha for item in handoff["artifacts"]):
        raise ValueError("consumed output is not bound to supplied producer")
    if file_sha256(safe_path(root, path)) != sha:
        raise ValueError("consumed output bytes changed")
    digest = prior_map[producer] if prior else reads.context.upstream_handoffs[producer]
    identity: dict[str, Any] = {"path": path, "sha256": sha, "handoff_sha256": digest,
                                "attempt_id": handoff["attempt_id"], "target_snapshot": handoff["target_snapshot"]}
    development = None if prior else _development_record(reads.context, producer, output_kind, path)
    if development is not None:
        if not _resolved:
            raise ValueError(f"development input override for {path} requires its consumer to open "
                             "the file through runtime.inputs.input_file; the original bytes were not read")
        identity["development_replacement"] = {
            key: development["replacement"][key] for key in ("root", "path", "sha256", "size_bytes")}
    reads.record(requirement, identity)


def _development_record(context: Any, producer: str, output_kind: str, path: str) -> Mapping[str, Any] | None:
    if not getattr(context, "development_inputs", ()):
        return None
    return context.development_input(producer, output_kind, path)


@_read_boundary
def input_file(root: Path, producer: str, output_kind: str, reference: Mapping[str, Any],
               *, prior: bool = False):
    """Observe one declared upstream output and return the file this attempt must open.

    The common reader for local and Dagster execution: ``observe_output`` admits the original
    pinned reference, then ``JobContext.input_file`` decides whether the attempt reads it or its
    development replacement snapshot. Readers verify the bytes they open against ``identity``.
    """
    from appsec_review.runtime.job import InputFile
    observe_output(root, producer, output_kind, reference, prior=prior, _resolved=True)
    reads = _READS.get()
    active_context = reads.context if reads is not None else _ATTEMPT_CONTEXT.get()
    if (active_context is not None
            and Path(root).resolve() == active_context.run_root.resolve()
            and getattr(active_context, "development_inputs", ())):
        return active_context.input_file(producer, output_kind, reference, prior=prior)
    original = {key: reference[key] for key in ("path", "sha256", "size_bytes") if key in reference}
    return InputFile(safe_path(root, str(reference.get("path", ""))), original, original, False)


@_read_boundary
def decode_consumed_handoff(value: Any, **expected: Any) -> dict[str, Any]:
    """Compatibility wiring for job-specific readers pending the shared artifact API."""
    from appsec_review.interchange import decode_handoff
    handoff = decode_handoff(value, **expected)
    reads = _READS.get()
    if reads is not None:
        observe_handoff(reads.context.run_root, handoff)
    return handoff


def read_input_observations(root: Path, handoff: Mapping[str, Any]) -> dict[str, Any] | None:
    """Retain actual read receipts, including the original computation behind a checkpoint."""
    from appsec_review.storage.shared import verify_reference
    from appsec_review.runtime.checkpoints import SCHEMA as CHECKPOINT_SCHEMA
    prefix = handoff["resolving_paths"]["attempt"] + "/steps/"
    records = []
    observed = False
    for ref in handoff["artifacts"]:
        if not ref["path"].startswith(prefix) or not ref["path"].endswith("/status.json"):
            continue
        seen = set()
        while ref is not None:
            identity = (ref["path"], ref["sha256"])
            if identity in seen or len(seen) >= 64:
                raise ValueError("checkpoint read provenance is cyclic or exceeds 64 attempts")
            seen.add(identity)
            status = json.loads(verify_reference(root, ref).read_bytes())
            document = status.get("input_consumption")
            if document is not None:
                if (set(document) != {"schema", "reads", "citation_observation"}
                        or document["schema"] != INPUT_READS_SCHEMA or not isinstance(document["reads"], list)
                        or document["citation_observation"] != "not_observed"):
                    raise ValueError("invalid input read observation receipt")
                observed = True
                records.extend(document["reads"])
            reused = status.get("reused_checkpoint")
            if reused is None:
                break
            checkpoint = json.loads(verify_reference(root, reused).read_bytes())
            if (checkpoint.get("schema") != CHECKPOINT_SCHEMA
                    or checkpoint["unit_id"] != status["unit_id"]
                    or status.get("status") != "SUCCEEDED"
                    or checkpoint["result"]["sha256"] != status.get("result_sha256")):
                raise ValueError("checkpoint read provenance differs from the reused result")
            original = json.loads(verify_reference(root, checkpoint["status"]).read_bytes())
            if (original.get("status") != "SUCCEEDED"
                    or original.get("unit_id") != checkpoint["unit_id"]
                    or original.get("result_sha256") != checkpoint["result"]["sha256"]):
                raise ValueError("checkpoint read provenance has no committed successful original unit")
            ref = checkpoint["status"]
    return {"schema": INPUT_READS_SCHEMA, "reads": records,
            "citation_observation": "not_observed"} if observed else None


def verify_external_inputs(context: Any, artifacts: list[dict[str, Any]]) -> None:
    """A required channel cannot be accepted without its validated reader receipt."""
    contract = context.contract
    if contract is None:
        return
    from appsec_review.runtime.selection import resolved_job_is_enabled
    document = json.loads(safe_path(context.run_root, "data/configuration/resolved.json").read_bytes())
    enabled = {name for name, value in document["jobs"].items() if resolved_job_is_enabled(name, value)}
    required = [item for item in contract.inputs if item.channel is not InputChannel.HANDOFF
                and item.required(enabled) and item.missing is MissingPolicy.REJECT]
    if not required:
        return
    observations = read_input_observations(context.run_root, {
        "resolving_paths": {"attempt": context.attempt_root.relative_to(context.run_root).as_posix()},
        "artifacts": artifacts})
    supplied = {(item["channel"], item["producer"], item["output_kind"])
                for item in observations["reads"]} if observations is not None else set()
    for requirement in required:
        if requirement.key not in supplied:
            raise ValueError(f"required external input was not validated: {requirement.producer}/{requirement.output_kind}")


def feed_input_identity(target: Path | None, run_root: Path, repository_root: Path) -> str:
    """Re-probe bounded local snapshot selections, without maintenance or network execution."""
    from appsec_review.jobs.job_review_data_indexing.job import _resolved_document
    from appsec_review.jobs.job_third_party_data_sync.publication import verify_current
    from appsec_review.storage.feed_provenance import STEPS
    document = _resolved_document(run_root)
    steps = document["jobs"].get("job_third_party_data_sync", {}).get("steps", {})
    rows: list[dict[str, Any]] = []
    for feed, step in sorted(STEPS.items()):
        row: dict[str, Any] = {"producer": "job_third_party_data_sync", "output_kind": "feed_snapshot",
               "schema": "appsec-review/public-feed-use/1", "selector": feed,
               "status": "unavailable", "identity": None, "reason": "feed root is not configured"}
        rows.append(row)
        configured = steps.get(step, {}).get("settings", {}).get("feed_root")
        if not configured:
            continue
        path = Path(configured)
        path = path if path.is_absolute() else repository_root / path
        try:
            relative = path.relative_to(repository_root).as_posix()
        except ValueError:
            raise ValueError("external feed selection is outside repository data") from None
        if not relative.startswith("data/"):
            raise ValueError("external feed selection is outside repository data")
        path = safe_path(repository_root, relative)
        try:
            value = verify_current(path, feed)
        except (OSError, ValueError, KeyError, TypeError) as error:
            row["reason"] = type(error).__name__
        else:
            row.update(status="available", identity={"feed_id": feed, "manifest_sha256": value["manifest_sha256"],
                                                    "snapshot_id": value["snapshot_id"]}, reason=None)
    return external_selection(rows)
