#!/usr/bin/env python3
"""Dispatch bounded OWASP validator cells, wait for all of them, and account for every row (T10).

For one engagement run and one exact newest accepted T06 handoff publication this worker

* re-validates the T06 lineage exactly as T07-T09 do (``owasp_validator_result._load_handoff``);
* maps every handoff to one validator cell in TRUSTED code: one C01 persona group per
  ``validator_contract_only`` handoff, never one for a ``request_authoring_only`` handoff;
* expands with ``pool_specification.expand_pool``, launches and waits with
  ``pool_rendezvous.run_rendezvous`` and afterwards reads only through ``load_verified_manifest``;
* hands every ``succeeded`` cell's output to T07 (``owasp_validator_result.publish``) as a
  CANDIDATE, and never decides itself what a valid result is;
* publishes one immutable accounting document in which every expected cell keeps its C02 state and
  every T05 worklist row is accounted exactly once.

:func:`derive_accounting` is THE accounting rule. The producer publishes what it derives and
:func:`verify_publication` re-derives it from the bytes on disk, so they cannot drift. T10 issues
no control status, joins nothing (T11), resolves no challenge and authorizes no dynamic or manual
work. It is not registered in Dagster, the lifecycle graph, the registry or the parity manifest.

No value read from a request, a handoff, evidence, a cell output or a lower layer's exception is
echoed into a message or a published document. T05-T07 identifiers (``handoff-<hex>`` and the
like) are published as digests and ordinals only: the V06 redactor replaces their shape.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import uuid
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import container_execution as ce  # noqa: E402
from execution_state import (  # noqa: E402
    Blocked, Lock, atomic_bytes, beneath, data_path, digest, identifier, run_path,
)
import owasp_batching  # noqa: E402
import owasp_validator_handoff  # noqa: E402
import owasp_validator_result  # noqa: E402
import permission_capabilities as pc  # noqa: E402
import persona_invocation as pi  # noqa: E402
import pool_rendezvous as pr  # noqa: E402
import pool_specification as ps  # noqa: E402
import resource_pools as rp  # noqa: E402
from schema_validate import SchemaStore, validate_document  # noqa: E402

JOB_ID = "04-owasp-validator-dispatch"
UPSTREAM_JOB = owasp_validator_handoff.JOB_ID
RESULT_JOB = owasp_validator_result.JOB_ID
LANE = "04-asvs-masvs"
POOL_ID = "owasp-validator-cells"
REPO_ROOT = ROOT.parent
CONFIG_ROOT = ROOT / "config" / "owasp-dispatch"

REQUEST_ID = "appsec-review/owasp-dispatch-request/1.0"
ATTEMPT_ID = "appsec-review/owasp-dispatch-attempt/1.0"
STATUS_ID = "appsec-review/owasp-dispatch-status/1.0"
ACCOUNTING_ID = "appsec-review/owasp-dispatch-accounting/1.0"
RULE_ID = "appsec-review/owasp-dispatch-accounting-rule/1.0"
ID_DIGEST_ID = "appsec-review/owasp-dispatch-id-digest/1.0"
REQUEST_SCHEMA = "owasp-dispatch-request.schema.json"
CONFIG_SCHEMA = "owasp-dispatch-config.schema.json"
ATTEMPT_SCHEMA = "owasp-dispatch-attempt.schema.json"
STATUS_SCHEMA = "owasp-dispatch-status.schema.json"
ACCOUNTING_SCHEMA = "owasp-dispatch-accounting.schema.json"

# The one file a validator cell must write at the top of its output root: a T07 candidate.
CANDIDATE_FILE = "control-assessment-result.json"
READABLE_ROOT = "run-data"
ATTEMPT_FILE, INPUTS_FILE, STATUS_FILE = "attempt.json", "inputs.json", "status.json"
POOLS_DIR, RENDEZVOUS_DIR, WORK_DIR, OUTPUTS_DIR = "pools", "rendezvous", "validation-requests", "outputs"
ACCOUNTING_FILE = "owasp-dispatch-accounting.json"
ACCOUNTING_ARTIFACT = f"{OUTPUTS_DIR}/{ACCOUNTING_FILE}"
ATTEMPT_ENTRIES = (ATTEMPT_FILE, INPUTS_FILE, OUTPUTS_DIR, POOLS_DIR, RENDEZVOUS_DIR, STATUS_FILE, WORK_DIR)

STATIC_MODE, REQUEST_MODE = "validator_contract_only", "request_authoring_only"
DISPATCHED, REQUEST_ONLY = "dispatched", "request_only_not_dispatched"
SUCCESS = ("OK", "OK_WITH_GAPS")
MAX_FILE_BYTES = ps.MAX_DOCUMENT_BYTES

# The task text's vocabulary, mapped onto C02's closed states. ``degraded`` is a pool outcome.
VOCABULARY: Mapping[str, tuple] = {
    "failed": (pr.FAILED, pr.BLOCKED, pr.CRASHED, pr.MISSING),
    "canceled": (pr.CANCELED,),
    "timed_out": (pr.INSTANCE_TIMED_OUT, pr.RENDEZVOUS_TIMED_OUT),
    "skipped": (pr.NOT_LAUNCHED_CANCELED, pr.NOT_LAUNCHED_RENDEZVOUS_TIMEOUT, pr.EMPTY),
    "invalid": (pr.INVALID, "succeeded_without_valid_result"),
    "degraded": (pr.DEGRADED,),
}
_STATE_CLASS = {state: name for name, states in VOCABULARY.items() for state in states if state in pr.STATES}

REFUSALS = ("lineage_refused", "config_refused", "registry_refused", "prompt_refused", "evidence_refused",
            "specification_refused", "runtime_refused", "publication_failed")
_TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_HEX32_RE = re.compile(r"[0-9a-f]{32}\Z")
_WAVE_RE = re.compile(r"wave-[0-9]{2}\Z")

freeze, thaw = pi.freeze, pi.thaw


class DispatchBlocked(Blocked):
    """A dispatch attempt that may not run. ``code`` is one of :data:`REFUSALS`; the message is
    fixed text and never carries a value read from a request, a handoff or a lower layer."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class DispatchRejected(RuntimeError):
    """A published dispatch attempt does not verify. Never a partial result."""


@dataclass(frozen=True)
class DispatchFacts:
    """The trusted, integrator-supplied facts a dispatch runs under AND is later verified under.
    Every field is required; there is no default anywhere."""
    registry_dir: Path
    allowed_models: tuple
    invoker_id: str
    source_snapshot_sha256: str
    registry_ceiling: list | None


@dataclass(frozen=True)
class DispatchRuntime:
    """Trusted side of one dispatch. ``invoker`` is the integrator's B14 ``PersonaInvoker``; this
    repository has no model client. ``cancel`` is the dispatch-wide :class:`pool_rendezvous.PoolCancel`.
    Every field is required."""
    facts: DispatchFacts
    invoker: Any
    clock: Callable[[], str]
    cancel: pr.PoolCancel
    stop_grace_seconds: int
    max_parallel: int
    wait_limit_seconds: float
    drain_seconds: int


# ---- small helpers -------------------------------------------------------------------------------

def _json_bytes(value: Any) -> bytes:
    """The one byte form of every JSON document this module writes (the T05-T09 house form)."""
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def id_digest(kind: str, value: str) -> str:
    """How a T05-T07 identifier is published: the V06 redactor replaces ``prefix-<hex>`` shapes, so
    a consumer matches ``id_digest(kind, its_id)`` instead of the identifier itself."""
    return digest([ID_DIGEST_ID, kind, value])


def accounting_sha256(accounting: Mapping[str, Any]) -> str:
    return digest({key: value for key, value in thaw(accounting).items() if key != "accounting_sha256"})


def _relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("path is not a nonempty POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("path is not a safe relative path")
    return path


def _read_regular(root: Path, path: Path) -> bytes:
    """One regular, singly linked, bounded file beneath ``root``, reached without crossing a link.
    The bytes returned are the bytes every later hash and parse is made of."""
    beneath(root, path)
    before = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("not a regular, singly linked file")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(MAX_FILE_BYTES + 1)
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or len(data) > MAX_FILE_BYTES:
        raise ValueError("file changed identity or is too large")
    return data


def _read_pinned(root: Path, relative: Any, sha256_hex: Any) -> tuple:
    """(path, bytes) of a run-owned file whose bytes have exactly the pinned sha256."""
    path = root.joinpath(*_relative(relative).parts)
    data = _read_regular(root, path)
    if _sha_hex(data) != sha256_hex:
        raise ValueError("pinned file hash mismatch")
    return path, data


def _listing(path: Path) -> list | None:
    try:
        if not ps._real_directory(path):
            return None
        with os.scandir(path) as entries:
            return sorted(entry.name for entry in entries)
    except OSError:
        return None


def wave_name(index: int) -> str:
    return f"wave-{index:02d}"


# ---- the plan: everything a dispatch derives from trusted inputs and verified bytes ---------------

@dataclass(frozen=True)
class Cell:
    ordinal: int                 # the T06 handoff-set ordinal (1-based)
    handoff_id: str
    batch_id: str
    member_relative: str         # run-data relative path of the handoff member
    member_sha256: str
    mode: str
    disposition: str
    fragments: tuple             # ((fragment_id, assignment_id, authority), ...)
    wave: int | None
    group_id: str | None
    handoff: Mapping[str, Any]


@dataclass(frozen=True)
class Plan:
    run_id: str
    request: Mapping[str, Any]
    data_root: Path
    pointer_sha256: str
    publication_attempt: str
    handoff_set_sha256: str
    worklist_sha256: str
    worklist: Mapping[str, Any]
    config: Mapping[str, Any]
    config_digest: str
    persona: Mapping[str, Any]
    composition_sha256: str
    allowed_claims: tuple
    prohibited_claims: tuple
    budget_name: str
    prompt: Mapping[str, Any] | None
    cells: tuple
    waves: tuple                 # tuple of tuples of cell indexes
    fingerprint: str


def _load_config(reference: Mapping[str, Any]) -> tuple:
    path = owasp_batching.tracked_file(_relative(reference["path"]), REPO_ROOT, ROOT)
    if path.parent.absolute() != CONFIG_ROOT.absolute():
        raise ValueError("config is not directly under the tracked dispatch config directory")
    config = ps.parse_document(_read_regular(CONFIG_ROOT, path))
    if validate_document(config, CONFIG_SCHEMA):
        raise ValueError("config fails its closed schema")
    if digest(config) != reference["config_digest"]:
        raise ValueError("config digest mismatch")
    if any(config[name] is not False for name in ("dynamic_execution", "manual_observation", "network_access")):
        raise ValueError("config widens a disabled capability")       # `const: false` also admits 0
    pool = config["pool"]
    if not 1 <= pool["max_cells_per_pool"] <= ps.MAX_GROUPS or not 1 <= pool["rendezvous_margin_seconds"] <= 86_400:
        raise ValueError("config pool bounds")
    classes = config["cell_claim_classes"]
    if classes != sorted(set(classes)) or config["required_claim_class"] not in classes:
        raise ValueError("config claim classes")
    mapped = [entry["handoff_class"] for entry in config["prohibited_claim_map"]]
    if mapped != sorted(set(mapped)):
        raise ValueError("config prohibited claim map")
    return config, reference["config_digest"]


def _composition(facts: DispatchFacts, config: Mapping[str, Any]) -> tuple:
    """The six-record composition block of the configured job template, from the registry BYTES, and
    the claim ceiling B14 derives from it. Nothing here is read from a handoff."""
    registry = Path(facts.registry_dir)
    template_path = registry / "job-templates" / (config["job_template_id"] + ".json")
    template = ps.parse_document(_read_regular(registry, template_path))
    block = {"job_template_id": config["job_template_id"], "job_template_sha256": pi._sha(template)}
    for name, directory, _, _ in pi.COMPOSITION_KINDS[1:]:
        record_id = template["composition"][name + "_id"]
        if not isinstance(record_id, str) or not pi._REG_RE.match(record_id):
            raise ValueError("composition id")
        record = ps.parse_document(_read_regular(registry, registry / directory / (record_id + ".json")))
        block[name + "_id"], block[name + "_sha256"] = record_id, pi._sha(record)
    records = pi.load_composition(registry, block, SchemaStore())
    if block["persona_id"] != config["persona_id"]:
        raise ValueError("the configured template does not compose the configured persona")
    ceiling = pi.claim_ceiling(records["role"], records["tooling_profile"])
    if config["required_claim_class"] not in ceiling["allowed"]:
        raise ValueError("the registered composition may not issue the required claim class")
    allowed = tuple(sorted(set(ceiling["allowed"]) & set(config["cell_claim_classes"])))
    prohibited = tuple(sorted(set(ceiling["prohibited"]) | (set(ceiling["allowed"]) - set(allowed))))
    return block, pi.composition_sha256(records), allowed, prohibited


def _publication(run_id: str, data_root: Path, reference: Mapping[str, Any]) -> tuple:
    """The exact newest accepted T06 publication: pointer, handoff set and every member. Every
    member goes through T07's own ``_load_handoff``, the rule T07-T09 share."""
    attempt_id = identifier(reference["attempt_id"])
    pointer_path, pointer_bytes = _read_pinned(data_root, reference["accepted_pointer_path"],
                                               reference["accepted_pointer_sha256"])
    if pointer_path.relative_to(data_root).parts != ("jobs", UPSTREAM_JOB, "whole", "accepted.json"):
        raise ValueError("not the T06 whole-scope accepted pointer")
    pointer = ps.parse_document(pointer_bytes)
    latest = ps.parse_document(_read_regular(data_root, pointer_path.with_name("latest.json")))
    if (pointer.get("status") not in SUCCESS or pointer.get("run_id") != run_id
            or pointer.get("job_id") != UPSTREAM_JOB or pointer.get("attempt_id") != attempt_id
            or latest.get("attempt_id") != attempt_id):
        raise ValueError("the T06 pointer is not the exact newest accepted publication")
    attempt = data_root / "jobs" / UPSTREAM_JOB / "whole" / "attempts" / attempt_id
    artifacts = pointer.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("T06 pointer artifacts")
    for relative, expected in artifacts.items():
        _read_pinned(attempt, relative, expected)
    set_path, set_bytes = _read_pinned(data_root, reference["handoff_set_path"], reference["handoff_set_sha256"])
    set_key = "outputs/owasp-validator-handoff-set.json"
    if set_path != attempt.joinpath(*set_key.split("/")) or artifacts.get(set_key) != reference["handoff_set_sha256"]:
        raise ValueError("the handoff set is not the accepted attempt's")
    handoff_set = ps.parse_document(set_bytes)
    if validate_document(handoff_set, "owasp-validator-handoff-set.schema.json") or handoff_set["run_id"] != run_id:
        raise ValueError("handoff set")
    entries = handoff_set["handoffs"]
    if [entry["ordinal"] for entry in entries] != list(range(1, len(entries) + 1)):
        raise ValueError("handoff set ordinals")
    if set(artifacts) != {set_key, "outputs/handoff-summary.md", *(entry["path"] for entry in entries)}:
        raise ValueError("the T06 pointer does not exactly publish the handoff set")
    members = []
    for entry in entries:
        member_relative = (attempt.relative_to(data_root) / PurePosixPath(*_relative(entry["path"]).parts)).as_posix()
        wrapper = {"handoff_id": entry["handoff_id"], "batch_id": entry["batch_id"],
                   "handoff": {**{name: reference[name] for name in (
                       "attempt_id", "accepted_pointer_path", "accepted_pointer_sha256", "handoff_set_path",
                       "handoff_set_sha256")}, "member_path": member_relative, "member_sha256": entry["sha256"]}}
        handoff, _, _ = owasp_validator_result._load_handoff(run_id, wrapper)
        members.append((entry, member_relative, handoff))
    publication_request = ps.parse_document(_read_regular(attempt, attempt / "inputs.json"))
    if validate_document(publication_request, "owasp-validator-handoff-request.schema.json"):
        raise ValueError("T06 attempt request")
    return pointer, handoff_set, members, publication_request


def _boundary_ok(handoff: Mapping[str, Any]) -> bool:
    """What T06 publishes, checked as JSON booleans: nothing in a handoff may have widened it."""
    boundaries = handoff["authorization_boundaries"]
    return (handoff["handoff_mode"] in (STATIC_MODE, REQUEST_MODE)
            and handoff["dispatch_ready"] is False and handoff["execution_authorized"] is False
            and boundaries["static_inspection"] is True
            and all(boundaries[name] is False for name in ("dynamic_execution", "manual_observation",
                                                           "network_access", "target_mutation"))
            and (handoff["handoff_mode"] == REQUEST_MODE) == (boundaries["declared"] == "dynamic_request_only"))


def load_plan(run_id: str, request: Mapping[str, Any], facts: DispatchFacts) -> Plan:
    """Everything a dispatch derives before anything is created. Shared by the producer and the
    verifier. Raises :class:`DispatchBlocked` with a fixed code and fixed text."""
    data_root = data_path(run_id)
    if os.path.realpath(data_root) != str(data_root):
        raise DispatchBlocked("runtime_refused", "the run data directory is not in its one real spelling")
    try:
        pointer, handoff_set, members, publication_request = _publication(run_id, data_root, request["handoffs"])
        reference = publication_request["batching"]
        _, worklist_bytes = _read_pinned(data_root, reference["worklist_path"], reference["worklist_sha256"])
        worklist = ps.parse_document(worklist_bytes)
        if validate_document(worklist, "owasp-validation-worklist.schema.json") or worklist["run_id"] != run_id:
            raise ValueError("worklist")
        budget_name = publication_request["budget"]
        cells = []
        for entry, member_relative, handoff in members:
            identity = handoff["worklist_identity"]
            if (identity["worklist_path"] != reference["worklist_path"]
                    or identity["worklist_sha256"] != reference["worklist_sha256"]
                    or handoff["budget"]["name"] != budget_name or not _boundary_ok(handoff)):
                raise ValueError("handoff identity or boundary")
            fragments = tuple((fragment["fragment_id"], fragment["assignment_id"],
                               fragment["final_control_status_authority"])
                              for fragment in handoff["assigned_fragments"])
            cells.append([entry, member_relative, handoff, fragments])
        _coverage(worklist, cells)
    except DispatchBlocked:
        raise
    except Exception:      # noqa: BLE001 - any refusal of the lineage is a refusal; its text is never kept
        raise DispatchBlocked("lineage_refused", "the T06 handoff publication is not the exact newest accepted "
                              "publication with a consistent T05 worklist") from None
    try:
        config, config_digest = _load_config(request["dispatch_config"])
    except Exception:      # noqa: BLE001
        raise DispatchBlocked("config_refused", "the dispatch configuration is not the tracked, versioned "
                              "configuration the request pins") from None
    try:
        persona, composition, allowed, prohibited = _composition(facts, config)
        mapping = {entry["handoff_class"]: entry["registry_classes"] for entry in config["prohibited_claim_map"]}
        for _, _, handoff, _ in cells:
            for name in handoff["prohibited_claim_classes"]:
                if not set(mapping[name]) <= set(prohibited):       # KeyError: an unmapped class
                    raise ValueError("a handoff prohibition is not enforced by the cell")
    except Exception:      # noqa: BLE001
        raise DispatchBlocked("registry_refused", "the registered composition cannot run a validator cell "
                              "inside the handoff's claim boundary") from None
    static = [cell for cell in cells if cell[2]["handoff_mode"] == STATIC_MODE]
    prompt = None
    if static:
        try:
            contracts = {(cell[2]["prompt_contract"]["path"], cell[2]["hashes"]["prompt_sha256"]) for cell in static}
            (identifier_path, prompt_sha), = contracts
            relative = _relative(identifier_path)
            if relative.parts[0] != owasp_batching.PROCESS_DIRECTORY:
                raise ValueError("prompt is outside the process tree")
            process_relative = PurePosixPath(*relative.parts[1:])
            data = _read_regular(ROOT, ROOT.joinpath(*process_relative.parts))
            if _sha_hex(data) != prompt_sha:
                raise ValueError("prompt bytes")
            prompt = {"path": process_relative.as_posix(), "sha256": "sha256:" + prompt_sha, "bytes": len(data)}
        except Exception:      # noqa: BLE001
            raise DispatchBlocked("prompt_refused", "the tracked validator prompt is not the bytes the handoffs "
                                  "pin") from None
    size = config["pool"]["max_cells_per_pool"]
    built, waves, position = [], [], 0
    for index, (entry, member_relative, handoff, fragments) in enumerate(cells):
        dispatched = handoff["handoff_mode"] == STATIC_MODE
        wave = position // size if dispatched else None
        if dispatched:
            if wave == len(waves):
                waves.append([])
            waves[wave].append(index)
            position += 1
        built.append(Cell(ordinal=entry["ordinal"], handoff_id=entry["handoff_id"], batch_id=entry["batch_id"],
                          member_relative=member_relative, member_sha256=entry["sha256"],
                          mode=handoff["handoff_mode"], disposition=DISPATCHED if dispatched else REQUEST_ONLY,
                          fragments=fragments, wave=wave, group_id=f"cell-{entry['ordinal']:04d}" if dispatched else None,
                          handoff=freeze(handoff)))
    if not waves:
        waves.append([])        # an EMPTY pool is a recorded state, not an absence
    fingerprint = digest({
        "rule": RULE_ID, "request": thaw(request), "pointer_sha256": request["handoffs"]["accepted_pointer_sha256"],
        "members": [[cell.ordinal, cell.member_sha256] for cell in built],
        "worklist_sha256": reference["worklist_sha256"], "config_digest": config_digest, "persona": persona,
        "allowed": allowed, "prohibited": prohibited, "prompt": prompt, "invoker_id": facts.invoker_id,
        "source_snapshot_sha256": facts.source_snapshot_sha256, "registry_ceiling": facts.registry_ceiling})
    return Plan(run_id=run_id, request=freeze(thaw(request)), data_root=data_root,
                pointer_sha256=request["handoffs"]["accepted_pointer_sha256"],
                publication_attempt=pointer["attempt_id"],
                handoff_set_sha256=request["handoffs"]["handoff_set_sha256"],
                worklist_sha256=reference["worklist_sha256"], worklist=freeze(worklist), config=freeze(config),
                config_digest=config_digest, persona=freeze(persona), composition_sha256=composition,
                allowed_claims=allowed, prohibited_claims=prohibited, budget_name=budget_name,
                prompt=freeze(prompt), cells=tuple(built), waves=tuple(tuple(wave) for wave in waves),
                fingerprint=fingerprint)


def _coverage(worklist: Mapping[str, Any], cells: list) -> None:
    """Every validator assignment of the worklist lies in exactly the batches whose handoffs carry
    one of its fragments, and every handoff fragment is one assignment's."""
    assignments = {item["assignment_id"]: item for item in worklist["assignments"]}
    if len(assignments) != len(worklist["assignments"]):
        raise ValueError("duplicate assignment")
    batches: dict = {key: set() for key, item in assignments.items() if item["disposition"] == "validator_assignment"}
    seen: set = set()
    if len({cell[0]["batch_id"] for cell in cells}) != len(cells):
        raise ValueError("duplicate batch")
    for entry, _, handoff, _ in cells:
        if handoff["batch_identity"]["batch_id"] != entry["batch_id"]:
            raise ValueError("batch identity")
        for fragment in handoff["assigned_fragments"]:
            assignment = assignments.get(fragment["assignment_id"])
            if (fragment["fragment_id"] in seen or assignment is None
                    or fragment["assignment_id"] not in batches or entry["batch_id"] in batches[fragment["assignment_id"]]
                    or any(fragment[name] != assignment[name] for name in ("target_id", "control_id", "component_id"))):
                raise ValueError("fragment coverage")
            seen.add(fragment["fragment_id"])
            batches[fragment["assignment_id"]].add(entry["batch_id"])
    if any(found != set(assignments[key]["batch_ids"]) for key, found in batches.items()):
        raise ValueError("assignment coverage")


# ---- handoff -> cell, in trusted code ------------------------------------------------------------

def _permission(plan: Plan, facts: DispatchFacts, decided_at: str) -> dict:
    """The B11 block of every cell: a requirement of NO capability and no grant. Default deny: a
    cell has no network, no mount, no dynamic or manual execution capability, ever."""
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": JOB_ID, "capabilities": []}
    decision = pc.evaluate(requirement, [], {
        "run_id": plan.run_id, "job_id": JOB_ID, "source_snapshot_sha256": facts.source_snapshot_sha256,
        "now": decided_at, "registry_ceiling": facts.registry_ceiling})
    if decision["decision"] != pc.GRANTED or decision["capabilities"]:
        raise ValueError("the empty requirement did not derive an empty grant")
    return {"requirement": requirement, "grants": [], "decision": decision}


def _readable_inputs(plan: Plan, cell: Cell) -> list:
    """The handoff itself (role ``handoff``), the T06 pointer and handoff set that publish it (role
    ``reference``: T07 requires a candidate to state their exact paths and hashes, and a cell can
    only state what it was handed), and exactly the accepted inputs the handoff names (role
    ``evidence``). Each is pinned to the bytes on disk now. A path is one file with one hash."""
    _, data = _read_pinned(plan.data_root, cell.member_relative, cell.member_sha256)
    inputs = [{"root": READABLE_ROOT, "path": cell.member_relative, "sha256": "sha256:" + cell.member_sha256,
               "bytes": len(data), "role": "handoff", "producer_request_sha256": None}]
    reference = plan.request["handoffs"]
    for path_name, hash_name in (("accepted_pointer_path", "accepted_pointer_sha256"),
                                 ("handoff_set_path", "handoff_set_sha256")):
        _, data = _read_pinned(plan.data_root, reference[path_name], reference[hash_name])
        inputs.append({"root": READABLE_ROOT, "path": reference[path_name], "sha256": "sha256:" + reference[hash_name],
                       "bytes": len(data), "role": "reference", "producer_request_sha256": None})
    pinned: dict = {}
    for entry in cell.handoff["accepted_inputs"]:
        artifact = entry["artifact"]
        if pinned.setdefault(artifact["path"], artifact["sha256"]) != artifact["sha256"]:
            raise ValueError("one evidence path with two hashes")
    for relative in sorted(pinned):
        _, data = _read_pinned(plan.data_root, relative, pinned[relative])
        inputs.append({"root": READABLE_ROOT, "path": relative, "sha256": "sha256:" + pinned[relative],
                       "bytes": len(data), "role": "evidence", "producer_request_sha256": None})
    return inputs


def build_specifications(plan: Plan, facts: DispatchFacts, *, attempt_id: str, decided_at: str) -> tuple:
    """One C01 pool specification per wave. Scope, permissions, claim classes, persona, model,
    budget and paths come from the registry, the tracked configuration and the trusted facts; a
    handoff contributes its own pinned bytes, the evidence it names, and limits that can only
    narrow (its timeout, its prohibited claims). Its text contributes nothing."""
    try:
        limits = plan.config["cell_budgets"][plan.budget_name]
        permission = _permission(plan, facts, decided_at)
        specs = []
        for members in plan.waves:
            groups = []
            for index in members:
                cell = plan.cells[index]
                timeout = min(cell.handoff["budget"]["timeout_seconds"], limits["max_timeout_seconds"])
                groups.append({
                    "group_id": cell.group_id, "worker_kind": ps.PERSONA, "count": 1, "memory_heavy": False,
                    "permission": permission, "tool_request": None,
                    "persona_request": {
                        "invocation_role": "produce", "invoker_id": facts.invoker_id,
                        "outer_prompt": thaw(plan.prompt), "persona": thaw(plan.persona),
                        "model": thaw(plan.request["model"]), "tools": [],
                        "budget": {**{name: limits[name] for name in (
                            "input_byte_limit", "input_unit_limit", "output_byte_limit", "output_unit_limit",
                            "output_file_limit")}, "tool_call_limit": 0, "timeout_seconds": timeout},
                        "readable_inputs": _readable_inputs(plan, cell),
                        "allowed_claim_classes": list(plan.allowed_claims),
                        "prohibited_claim_classes": list(plan.prohibited_claims), "producers": []}})
            groups.sort(key=lambda group: group["group_id"])
            timeouts = [group["persona_request"]["budget"]["timeout_seconds"] for group in groups]
            margin = plan.config["pool"]["rendezvous_margin_seconds"]
            if groups:
                reason = None
            elif plan.cells:
                reason = "scope_excluded"              # every handoff is request-only: nothing may be dispatched
            else:
                reason = "upstream_produced_no_work"   # T06 published no handoff at all
            specs.append(json.loads(json.dumps({
                "schema": ps.SPEC_ID, "pool_id": POOL_ID, "lane": LANE, "run_id": plan.run_id, "job_id": JOB_ID,
                "attempt_id": attempt_id, "budget_class": plan.config["budget_classes"][plan.budget_name],
                "pool_budget": {"max_instances": len(groups),
                                "max_persona_input_units": len(groups) * limits["input_unit_limit"],
                                "max_persona_output_units": len(groups) * limits["output_unit_limit"],
                                "max_total_timeout_seconds": sum(timeouts)},
                "resource_pool_policy": {"allowed_pools": [rp.PERSONA_LLM]}, "wait_all": True,
                "rendezvous_timeout_seconds": min(ps.MAX_TOTAL_TIMEOUT_SECONDS, sum(timeouts) + margin),
                "empty_pool_reason": reason, "worker_groups": groups})))
        return tuple(specs)
    except Exception:      # noqa: BLE001
        raise DispatchBlocked("evidence_refused", "a handoff or an accepted input it names is not the pinned "
                              "bytes on disk") from None


def pool_context(plan: Plan, facts: DispatchFacts, attempt: Path, wave: int) -> ps.PoolContext:
    return ps.PoolContext(
        pool_parent=attempt / POOLS_DIR / wave_name(wave), registry_dir=Path(facts.registry_dir),
        prompt_root=ROOT, readable_roots={READABLE_ROOT: plan.data_root}, allowed_models=facts.allowed_models,
        invoker_id=facts.invoker_id, images_dir=ce.IMAGES_DIR,
        host_flavor="windows" if os.name == "nt" else "posix", docker_host=None, mount_roots=(),
        source_snapshot_sha256=facts.source_snapshot_sha256, registry_ceiling=facts.registry_ceiling)


# ---- THE accounting rule: shared by the producer and the verifier ---------------------------------

def _validation_request(plan: Plan, cell: Cell, candidate: Mapping[str, Any]) -> dict:
    """The T07 request for one cell: the cell's own handoff member, and its output as the candidate."""
    reference = plan.request["handoffs"]
    return {"schema": owasp_validator_result.REQUEST_SCHEMA, "run_id": plan.run_id, "batch_id": cell.batch_id,
            "handoff_id": cell.handoff_id,
            "handoff": {**{name: reference[name] for name in (
                "attempt_id", "accepted_pointer_path", "accepted_pointer_sha256", "handoff_set_path",
                "handoff_set_sha256")}, "member_path": cell.member_relative, "member_sha256": cell.member_sha256},
            "candidate": {"path": candidate["run_path"], "sha256": candidate["sha256_hex"]}}


def _adapter_result(instance_root: Path, entry: Mapping[str, Any], item: ps.InstanceRequest,
                    context: ps.PoolContext) -> Mapping[str, Any]:
    """B14's own verifier for one instance's ids and the request the specification derives."""
    return pi.load_verified_result(
        instance_root, run_id=entry["run_id"], job_id=entry["job_id"], attempt_id=entry["attempt_id"],
        request=item.request, registry_dir=context.registry_dir, prompt_root=context.prompt_root,
        readable_roots=context.readable_roots, allowed_models=context.allowed_models,
        source_snapshot_sha256=context.source_snapshot_sha256, registry_ceiling=context.registry_ceiling)


def _cell_candidate(plan: Plan, attempt: Path, wave: int, pool_directory: str, item: ps.InstanceRequest,
                    entry: Mapping[str, Any], recorded: Mapping[str, Any], context: ps.PoolContext) -> tuple:
    """(candidate, reason) for a ``succeeded`` instance. The adapter's own verifier decides first;
    ANY exception from it is a refusal. The candidate is read once, and those bytes are what is
    hashed, parsed and bound to this instance."""
    instance_root = context.pool_parent / pool_directory / PurePosixPath(entry["attempt_root"])
    try:
        result = _adapter_result(instance_root, entry, item, context)
        log = instance_root.joinpath(*entry["log_path"].split("/")) / pi.RESULT_FILE
        if (result["execution_status"] != "OK" or recorded["result_file"] is None
                or pi._bytes_sha(_read_regular(instance_root, log)) != recorded["result_file"]["sha256"]):
            return None, "adapter_result_unverifiable"
    except Exception:      # noqa: BLE001 - a verifier that refuses, or cannot be called, verified nothing
        return None, "adapter_result_unverifiable"
    listed = [record for record in result["outputs"] if record["path"] == CANDIDATE_FILE]
    if len(listed) != 1:
        return None, "candidate_missing"
    path = instance_root.joinpath(*item.request["output_root"].split("/")) / CANDIDATE_FILE
    try:
        data = _read_regular(instance_root, path)
        if pi._bytes_sha(data) != listed[0]["sha256"] or len(data) != listed[0]["bytes"]:
            raise ValueError("candidate bytes")
        document = ps.parse_document(data)          # no repeated key: one reading only
    except Exception:      # noqa: BLE001
        return None, "candidate_unreadable"
    producer = document.get("producer")
    if not isinstance(producer, dict) or producer.get("producer_id") != entry["instance_id"]:
        return None, "candidate_identity"           # a candidate names the instance that wrote it
    relative = path.relative_to(attempt)
    return {"path": relative.as_posix(), "sha256": listed[0]["sha256"], "bytes": len(data),
            "sha256_hex": _sha_hex(data), "document": document,
            "run_path": path.relative_to(run_path(plan.run_id)).as_posix()}, None


def validation_outcome(plan: Plan, cell: Cell, candidate: Mapping[str, Any]) -> dict:
    """What T07 says NOW about exactly this candidate, from T07's own files. A value T07 returned
    is never used. ``accepted`` needs T07's newest attempt for the batch to be for this very
    request, accepted, with every published artifact intact and the result equal to the candidate."""
    empty = {"job_id": RESULT_JOB, "outcome": "unavailable", "attempt_id": None, "status": None,
             "accepted_pointer_sha256": None, "result_sha256": None}
    try:
        base = plan.data_root / "jobs" / RESULT_JOB / identifier(cell.batch_id)
        pointer_bytes = _read_regular(plan.data_root, base / "accepted.json")
        pointer = ps.parse_document(pointer_bytes)
        latest = ps.parse_document(_read_regular(plan.data_root, base / "latest.json"))
        attempt_id = pointer["attempt_id"]
        if not isinstance(attempt_id, str) or not _HEX32_RE.match(attempt_id) or latest["attempt_id"] != attempt_id:
            return empty
        attempt = base / "attempts" / attempt_id
        if ps.parse_document(_read_regular(plan.data_root, attempt / "inputs.json")) != _validation_request(
                plan, cell, candidate):
            return empty
        status = pointer["status"]
        if status in ("INVALID", "BLOCKED"):
            return {**empty, "outcome": "refused", "attempt_id": attempt_id, "status": status}
        if status not in SUCCESS or pointer["handoff_id"] != cell.handoff_id or pointer["run_id"] != plan.run_id:
            return empty
        artifacts = pointer["artifacts"]
        if set(artifacts) != {"outputs/" + name for name in (
                "control-assessment-result.json", "result-validation.json", "result-summary.md",
                "proposed-dynamic-test-candidates.json", "candidate-verification-routes.json")}:
            return empty
        for relative, expected in artifacts.items():
            _read_pinned(attempt, relative, expected)
        _, result_bytes = _read_pinned(attempt, "outputs/control-assessment-result.json",
                                       artifacts["outputs/control-assessment-result.json"])
        result = ps.parse_document(result_bytes)
        if (validate_document(result, "owasp-control-assessment-result.schema.json")
                or result != candidate["document"] or result["result_id"] != pointer["result_id"]):
            return empty
        return {"job_id": RESULT_JOB, "outcome": "accepted", "attempt_id": attempt_id, "status": status,
                "accepted_pointer_sha256": _sha_hex(pointer_bytes), "result_sha256": _sha_hex(result_bytes)}
    except Exception:      # noqa: BLE001 - anything unreadable is "unavailable", never a pass
        return empty


def terminal_class(state: str | None, valid: bool) -> str:
    if valid:
        return "valid_result"
    return _STATE_CLASS.get(state, "invalid")        # succeeded without a valid result, or unverifiable


def account_rows(worklist: Mapping[str, Any], cells: tuple, entries: list) -> list:
    """Every T05 worklist row, exactly once. A fragment defers to its cell's validated T07 result,
    is ``not_assessed`` with that cell's provenance, or is ``request_only``; a row is ``not_assessed``
    as soon as one of its dispatched fragments is. T10 never issues a control status, so no fragment
    (``obligation_fragment_only`` or not) issues a final one here: that is the T11 join."""
    by_fragment: dict = {}
    for cell, entry in zip(cells, entries):
        valid, validation = entry["valid_result"], entry["validation"]
        for position, (fragment_id, assignment_id, authority) in enumerate(cell.fragments):
            disposition = ("request_only" if cell.disposition == REQUEST_ONLY
                           else "deferred_to_validated_result" if valid else "not_assessed")
            by_fragment.setdefault(assignment_id, []).append({
                "fragment_digest": id_digest("fragment", fragment_id), "cell_ordinal": cell.ordinal,
                "fragment_index": position, "final_control_status_authority": authority,
                "disposition": disposition, "not_assessed_reason": entry["not_assessed_reason"],
                "instance_id": entry["instance_id"], "state": entry["state"],
                "adapter_status": entry["adapter_status"], "adapter_cause": entry["adapter_cause"],
                "validation_attempt_id": validation["attempt_id"] if valid else None,
                "result_sha256": validation["result_sha256"] if valid else None})
    rows = []
    for index, assignment in enumerate(worklist["assignments"]):
        fragments = sorted(by_fragment.get(assignment["assignment_id"], []),
                           key=lambda item: (item["cell_ordinal"], item["fragment_index"]))
        found = {fragment["disposition"] for fragment in fragments}
        if assignment["disposition"] != "validator_assignment":
            row = "not_a_validator_assignment"
        elif "not_assessed" in found or not fragments:
            row = "not_assessed"
        elif found == {"request_only"}:
            row = "request_only"
        elif "request_only" in found:
            row = "deferred_with_request_only_fragments"
        else:
            row = "deferred_to_validated_results"
        rows.append({"row_index": index, "assignment_digest": id_digest("assignment", assignment["assignment_id"]),
                     "source_row_hash": assignment["source_row_hash"],
                     "applicability_status": assignment["applicability_status"],
                     "worklist_disposition": assignment["disposition"], "join_required": assignment["join_required"],
                     "fragments": fragments, "row_disposition": row, "final_control_status_issued": False})
    return rows


def derive_accounting(plan: Plan, facts: DispatchFacts, *, attempt: Path, attempt_id: str,
                      specifications: tuple) -> dict:
    """THE rule. A pure function of the plan, the specifications and the disk now: C02's verified
    manifests, the adapters' verified results, the cells' candidate bytes and T07's own files. It
    never raises for something a lower layer refuses: that is ``not_assessed``."""
    pools, observed = [], {}
    for wave, spec in enumerate(specifications):
        context = pool_context(plan, facts, attempt, wave)
        directory, spec_digest = ps.pool_directory(ps.spec_sha256(spec)), ps.spec_sha256(spec)
        manifest = expansion = None
        try:
            manifest = pr.load_verified_manifest(
                context.pool_parent / directory, expected_spec=spec, context=context,
                rendezvous_parent=attempt / RENDEZVOUS_DIR / wave_name(wave), host_facts=None)
            expansion = ps.load_verified_expansion(context.pool_parent / directory, expected_spec=spec,
                                                   context=context)
            by_group = {record["group_id"]: (index, record) for index, record in enumerate(manifest["instances"])}
            if (len(by_group) != len(manifest["instances"]) or any(record["ordinal"] != 0 for _, record in by_group.values())
                    or set(by_group) != {plan.cells[index].group_id for index in plan.waves[wave]}):
                raise ValueError("the manifest is not one instance per expected cell")
        except Exception:      # noqa: BLE001 - no instance of this pool may be treated as assessed
            manifest = None
        pools.append({"wave": wave, "cells": len(plan.waves[wave]), "pool_directory": directory,
                      "spec_sha256": spec_digest, "manifest_verified": manifest is not None,
                      "expansion_state": manifest["expansion_state"] if manifest else None,
                      "empty_pool_reason": manifest["empty_pool_reason"] if manifest else None,
                      "outcome": manifest["outcome"] if manifest else None,
                      "degraded": bool(manifest) and manifest["outcome"] == pr.DEGRADED,
                      "manifest_sha256": manifest["manifest_sha256"] if manifest else None})
        for index in plan.waves[wave]:
            cell = plan.cells[index]
            if manifest is None:
                observed[index] = (None, None, "pool_unverifiable")
                continue
            position, record = by_group[cell.group_id]
            candidate, reason = None, "cell_state"
            if record["state"] == pr.SUCCEEDED:
                candidate, reason = _cell_candidate(plan, attempt, wave, directory, expansion.requests[position],
                                                    expansion.manifest["instances"][position], record, context)
            observed[index] = (record, candidate, reason)

    cells = []
    for index, cell in enumerate(plan.cells):
        record, candidate, reason = observed.get(index, (None, None, None))
        validation = {"job_id": RESULT_JOB, "outcome": "not_submitted", "attempt_id": None, "status": None,
                      "accepted_pointer_sha256": None, "result_sha256": None}
        if candidate is not None:
            validation = validation_outcome(plan, cell, candidate)
            reason = {"accepted": None, "refused": "validation_refused"}.get(validation["outcome"],
                                                                             "validation_unavailable")
        valid = cell.disposition == DISPATCHED and candidate is not None and validation["outcome"] == "accepted"
        state = record["state"] if record else None
        entry = {
            "cell_ordinal": cell.ordinal, "member_sha256": cell.member_sha256,
            "handoff_digest": id_digest("handoff", cell.handoff_id), "batch_digest": id_digest("batch", cell.batch_id),
            "handoff_mode": cell.mode, "disposition": cell.disposition, "fragments": len(cell.fragments),
            "wave": cell.wave, "group_id": cell.group_id, "instance_id": record["instance_id"] if record else None,
            "state": state, "adapter_status": record["adapter_status"] if record else None,
            "adapter_cause": record["adapter_cause"] if record else None,
            "invoker_stopped": record["invoker_stopped"] if record else None,
            "worker_stopped": record["worker_stopped"] if record else None,
            "result_file": thaw(record["result_file"]) if record else None,
            "terminal_class": "request_only" if cell.disposition == REQUEST_ONLY else terminal_class(state, valid),
            "candidate": ({name: candidate[name] for name in ("path", "sha256", "bytes")} if candidate else None),
            "validation": validation, "valid_result": valid,
            "not_assessed_reason": None if valid or cell.disposition == REQUEST_ONLY else reason}
        cells.append(entry)
    rows = account_rows(plan.worklist, plan.cells, cells)

    dispatched = [entry for entry in cells if entry["disposition"] == DISPATCHED]
    outcome = pr.pool_outcome([entry["state"] or pr.INVALID for entry in dispatched])
    classes = [entry["terminal_class"] for entry in cells]
    every = [fragment for row in rows for fragment in row["fragments"]]
    complete = bool(dispatched) and all(entry["valid_result"] for entry in cells)
    accounting = {
        "schema": ACCOUNTING_ID, "accounting_rule": RULE_ID, "run_id": plan.run_id, "job_id": JOB_ID,
        "attempt_id": attempt_id, "input_fingerprint": plan.fingerprint, "lane": LANE,
        "handoff_publication": {"job_id": UPSTREAM_JOB, "attempt_id": plan.publication_attempt,
                                "accepted_pointer_sha256": plan.pointer_sha256,
                                "handoff_set_sha256": plan.handoff_set_sha256, "handoffs": len(plan.cells)},
        "worklist": {"sha256": plan.worklist_sha256, "rows": len(rows)},
        "dispatch_config": {"config_id": plan.config["config_id"], "version": plan.config["version"],
                            "config_digest": plan.config_digest},
        "composition": {"composition_sha256": plan.composition_sha256, "persona_id": plan.persona["persona_id"],
                        "job_template_id": plan.persona["job_template_id"], "model": thaw(plan.request["model"]),
                        "invoker_id": facts.invoker_id},
        "cell_boundary": {"allowed_claim_classes": list(plan.allowed_claims),
                          "prohibited_claim_classes": list(plan.prohibited_claims), "tool_ids": [],
                          "granted_permission_kinds": [], "network_access": False, "dynamic_execution": False,
                          "manual_observation": False, "target_mutation": False},
        "claims_boundary": {name: False for name in (
            "control_status_issued", "results_joined", "challenges_resolved", "finding_or_severity_issued",
            "compliance_or_remediation_issued", "dynamic_or_manual_work_authorized", "older_attempt_consulted")},
        "vocabulary": {name: list(states) for name, states in VOCABULARY.items()},
        "pools": pools, "dispatch_outcome": outcome, "degraded": outcome == pr.DEGRADED,
        "status": "OK" if complete and outcome == pr.COMPLETE else "OK_WITH_GAPS",
        "cells": cells, "rows": rows,
        "counts": {
            "cells": len(cells), "dispatched": len(dispatched), "request_only": classes.count("request_only"),
            **{name: classes.count(name) for name in ("valid_result", "failed", "canceled", "timed_out", "skipped",
                                                      "invalid")},
            "rows": len(rows),
            "rows_deferred": sum(row["row_disposition"] == "deferred_to_validated_results" for row in rows),
            "rows_deferred_with_request_only": sum(
                row["row_disposition"] == "deferred_with_request_only_fragments" for row in rows),
            "rows_not_assessed": sum(row["row_disposition"] == "not_assessed" for row in rows),
            "rows_request_only": sum(row["row_disposition"] == "request_only" for row in rows),
            "rows_not_validator_assignment": sum(row["row_disposition"] == "not_a_validator_assignment" for row in rows),
            "fragments": len(every),
            "fragments_deferred": sum(item["disposition"] == "deferred_to_validated_result" for item in every),
            "fragments_not_assessed": sum(item["disposition"] == "not_assessed" for item in every),
            "fragments_request_only": sum(item["disposition"] == "request_only" for item in every)}}
    accounting["accounting_sha256"] = accounting_sha256(accounting)
    errors = validate_document(accounting, ACCOUNTING_SCHEMA)
    if errors:
        raise DispatchRejected(f"the derived accounting is outside its own closed schema ({len(errors)} errors)")
    return accounting


def _status(plan_fingerprint: str | None, run_id: str, attempt_id: str, status: str, *, outcome: str | None,
            accounting: str | None, refusal: str | None) -> dict:
    return {"schema": STATUS_ID, "status": status, "run_id": run_id, "job_id": JOB_ID, "attempt_id": attempt_id,
            "input_fingerprint": plan_fingerprint, "dispatch_outcome": outcome, "accounting_sha256": accounting,
            "refusal": refusal}


def _pointer(accounting: Mapping[str, Any], data: bytes) -> dict:
    """``accepted.json``. No timestamp: the verifier re-derives it byte for byte."""
    return {"status": accounting["status"], "run_id": accounting["run_id"], "job_id": JOB_ID,
            "attempt_id": accounting["attempt_id"], "input_fingerprint": accounting["input_fingerprint"],
            "dispatch_outcome": accounting["dispatch_outcome"], "artifacts": {ACCOUNTING_ARTIFACT: _sha_hex(data)}}


# ---- verification: a publication is a cache, never an authority -----------------------------------

def _base(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB_ID, "whole")


def _expected_files(plan: Plan, accounting: Mapping[str, Any], attempt: Path, specifications: tuple) -> dict:
    """Every file of a published attempt that this module wrote, as the bytes it must hold."""
    files = {INPUTS_FILE: _json_bytes(thaw(plan.request)),
             ACCOUNTING_ARTIFACT: _json_bytes(accounting),
             STATUS_FILE: _json_bytes(_status(plan.fingerprint, plan.run_id, accounting["attempt_id"],
                                              accounting["status"], outcome=accounting["dispatch_outcome"],
                                              accounting=accounting["accounting_sha256"], refusal=None))}
    for entry, cell in zip(accounting["cells"], plan.cells):
        if entry["candidate"] is not None:
            path = attempt.joinpath(*entry["candidate"]["path"].split("/"))
            candidate = {"run_path": path.relative_to(run_path(plan.run_id)).as_posix(),
                         "sha256_hex": entry["candidate"]["sha256"].split(":", 1)[1]}
            files[f"{WORK_DIR}/{cell.ordinal:04d}.json"] = _json_bytes(_validation_request(plan, cell, candidate))
    return files


def verify_publication(run_id: str, *, attempt_id: str, facts: DispatchFacts) -> list:
    """Re-derives one published dispatch attempt from the request it recorded, the exact newest
    accepted T06 publication, the tracked configuration, the registry and the disk. Read-only.
    Every argument is required. Every file it accounts for is READ and compared as bytes; no hash
    on disk is an input. Messages are fixed text."""
    return _verify(run_id, attempt_id, facts)[0]


def _verify(run_id: str, attempt_id: Any, facts: Any) -> tuple:
    if not isinstance(facts, DispatchFacts):
        raise TypeError("verification requires DispatchFacts")
    if not isinstance(attempt_id, str) or not _HEX32_RE.match(attempt_id):
        return ["attempt_id is not a dispatch attempt id"], None
    base = _base(identifier(run_id))
    attempt = base / "attempts" / attempt_id
    if _listing(attempt) != sorted(ATTEMPT_ENTRIES):
        return ["the attempt directory does not hold exactly the files of a published dispatch attempt"], None
    try:
        record_bytes = _read_regular(attempt, attempt / ATTEMPT_FILE)
        record = ps.parse_document(record_bytes)
        request_bytes = _read_regular(attempt, attempt / INPUTS_FILE)
        request = ps.parse_document(request_bytes)
    except Exception:      # noqa: BLE001
        return ["attempt.json or inputs.json is not a bounded JSON document with exactly one reading"], None
    if validate_document(record, ATTEMPT_SCHEMA) or validate_document(request, REQUEST_SCHEMA):
        return ["attempt.json or inputs.json fails its closed schema"], None
    if (record["run_id"], record["job_id"], record["attempt_id"]) != (run_id, JOB_ID, attempt_id) or (
            request["run_id"] != run_id) or record_bytes != _json_bytes(record):
        return ["attempt.json or inputs.json is bound to another run, job or attempt"], None
    try:
        plan = load_plan(run_id, request, facts)
        specifications = build_specifications(plan, facts, attempt_id=attempt_id, decided_at=record["decided_at"])
    except DispatchBlocked:
        return ["the recorded request no longer derives a dispatch plan: its T06 publication is not the exact "
                "newest accepted one, or the configuration, registry, prompt or evidence changed"], None
    if record["input_fingerprint"] != plan.fingerprint:
        return ["attempt.json input_fingerprint is not what the recorded request derives"], None
    errors = []
    try:
        accounting = derive_accounting(plan, facts, attempt=attempt, attempt_id=attempt_id,
                                       specifications=specifications)
    except Exception:      # noqa: BLE001
        return ["the accounting cannot be derived from the disk"], None
    found = None
    for relative, expected in sorted(_expected_files(plan, accounting, attempt, specifications).items()):
        try:
            data = _read_regular(attempt, attempt.joinpath(*relative.split("/")))
        except Exception:      # noqa: BLE001
            data = None
        if data != expected:
            errors.append("a file of the attempt is not the byte sequence the request and the disk derive")
        elif relative == ACCOUNTING_ARTIFACT:
            found = data
    expected_work = sorted(name.split("/", 1)[1] for name in _expected_files(plan, accounting, attempt, specifications)
                           if name.startswith(WORK_DIR + "/"))
    waves = [wave_name(index) for index in range(len(specifications))]
    if (_listing(attempt / WORK_DIR) != expected_work or _listing(attempt / OUTPUTS_DIR) != [ACCOUNTING_FILE]
            or _listing(attempt / POOLS_DIR) != waves or _listing(attempt / RENDEZVOUS_DIR) != waves):
        errors.append("a directory of the attempt holds something other than what the dispatch wrote")
    for wave, pool in enumerate(accounting["pools"]):
        names = [pool["pool_directory"], pool["pool_directory"] + pr.LOCK_SUFFIX]
        if (_listing(attempt / POOLS_DIR / wave_name(wave)) != names[:1]
                or _listing(attempt / RENDEZVOUS_DIR / wave_name(wave)) != names):
            errors.append("a wave directory holds something other than its one pool and its lock")
            continue
        try:        # execution_state.Lock writes exactly one NUL; a lock file carries nothing else
            lock = _read_regular(attempt, attempt / RENDEZVOUS_DIR / wave_name(wave) / names[1])
        except Exception:      # noqa: BLE001
            lock = None
        if lock != b"\0":
            errors.append("a rendezvous lock file holds something other than the lock byte")
    return sorted(set(errors)), (found if not errors else None)


def load_verified_accounting(run_id: str, *, facts: DispatchFacts) -> Mapping[str, Any]:
    """The accounting T11 may rely on: the NEWEST dispatch attempt, accepted and verified, deeply
    immutable and parsed from the very bytes that were verified. A newer attempt that was blocked,
    failed or is still running blocks it: there is no fallback to an older accounting."""
    run_id = identifier(run_id)
    base = _base(run_id)
    try:
        pointer_bytes = _read_regular(base, base / "accepted.json")
        pointer = ps.parse_document(pointer_bytes)
        latest = ps.parse_document(_read_regular(base, base / "latest.json"))
        attempt_id = pointer["attempt_id"]
    except Exception:      # noqa: BLE001
        raise DispatchRejected("there is no readable accepted dispatch accounting for this run") from None
    if latest.get("attempt_id") != attempt_id:
        raise DispatchRejected("the newest dispatch attempt is not the accepted one: a newer attempt was blocked, "
                               "failed or did not finish, and an older accounting is never used instead")
    errors, data = _verify(run_id, attempt_id, facts)
    if errors or data is None:
        raise DispatchRejected("dispatch accounting rejected: " + "; ".join(errors))
    accounting = ps.parse_document(data)
    if pointer_bytes != _json_bytes(_pointer(accounting, data)) or _json_bytes(latest) != _json_bytes(
            {"attempt_id": attempt_id}):
        raise DispatchRejected("accepted.json or latest.json is not what the verified accounting derives")
    return freeze(accounting)


def reusable(accounting: Mapping[str, Any]) -> bool:
    """An exact replay is reused only when the accepted attempt left nothing to retry: every
    dispatched cell has a valid result. Anything else is dispatched again as a new attempt."""
    return all(cell["valid_result"] for cell in accounting["cells"] if cell["disposition"] == DISPATCHED)


# ---- the producer --------------------------------------------------------------------------------

def _validate_runtime(runtime: Any) -> None:
    if not isinstance(runtime, DispatchRuntime) or not isinstance(runtime.facts, DispatchFacts):
        raise TypeError("a dispatch requires a DispatchRuntime with DispatchFacts")
    if type(runtime.cancel) is not pr.PoolCancel:
        raise TypeError("runtime.cancel must be a pool_rendezvous.PoolCancel")
    if getattr(runtime.invoker, "invoker_id", None) != runtime.facts.invoker_id:
        raise DispatchBlocked("runtime_refused", "runtime.invoker is not the invoker the dispatch facts name")


def _decided_at(runtime: DispatchRuntime) -> str:
    value = runtime.clock()
    if not isinstance(value, str) or not _TS_RE.match(value):
        raise DispatchBlocked("runtime_refused", "runtime.clock must return a UTC timestamp like "
                              "2026-01-01T00:00:00Z")
    return value


def _run_wave(plan: Plan, runtime: DispatchRuntime, attempt: Path, wave: int, spec: dict) -> BaseException | None:
    """Expand (once) and rendezvous one wave. Returns an interrupt to re-raise after accounting.
    Anything a lower layer refuses is left for the accounting rule to find on disk."""
    context = pool_context(plan, runtime.facts, attempt, wave)
    rendezvous_parent = attempt / RENDEZVOUS_DIR / wave_name(wave)
    for directory in (context.pool_parent, rendezvous_parent):
        directory.mkdir(parents=True, exist_ok=True)
    pool_root = context.pool_parent / ps.pool_directory(ps.spec_sha256(spec))
    # C02 sets a pool's cancel event when its own wait times out. Each wave therefore has its own
    # event, which the dispatch-wide cancel sets: one wave's timeout does not cancel the next.
    cancel = pr.PoolCancel()
    runtime.cancel.subscribe(cancel.set)
    try:
        if runtime.cancel.is_set():
            cancel.set()
        if not os.path.lexists(pool_root):
            ps.expand_pool(spec, context=context)       # a crashed coordinator's root is never repaired
        persona = pi.PersonaRuntime(
            invoker=runtime.invoker, registry_dir=context.registry_dir, prompt_root=context.prompt_root,
            readable_roots=context.readable_roots, allowed_models=context.allowed_models,
            source_snapshot_sha256=context.source_snapshot_sha256, registry_ceiling=context.registry_ceiling,
            clock=runtime.clock, cancel=cancel, stop_grace_seconds=runtime.stop_grace_seconds)
        pr.run_rendezvous(pool_root, expected_spec=spec, context=context, runtime=pr.RendezvousRuntime(
            rendezvous_parent=rendezvous_parent, container_runtime=None, persona_runtime=persona, cancel=cancel,
            max_parallel=runtime.max_parallel, wait_limit_seconds=runtime.wait_limit_seconds,
            drain_seconds=runtime.drain_seconds))
    except (KeyboardInterrupt, SystemExit) as interrupt:
        runtime.cancel.set()                            # later waves launch nothing
        return interrupt
    except pr.RendezvousPublishedError:
        pass                                            # a restart after publication: read it, never replace it
    except Exception:      # noqa: BLE001 - whatever is (not) on disk decides; its text is never kept
        pass
    finally:
        runtime.cancel.unsubscribe(cancel.set)
    return None


def _submit_candidates(plan: Plan, facts: DispatchFacts, attempt: Path, attempt_id: str, specifications: tuple
                       ) -> None:
    """Hands every candidate the rule finds to T07, the only judge of a valid result. T07's return
    value and its exception are both discarded: the rule reads T07's files afterwards."""
    preview = derive_accounting(plan, facts, attempt=attempt, attempt_id=attempt_id, specifications=specifications)
    for relative, data in sorted(_expected_files(plan, preview, attempt, specifications).items()):
        if not relative.startswith(WORK_DIR + "/"):
            continue
        path = attempt.joinpath(*relative.split("/"))
        atomic_bytes(path, data)
        try:
            owasp_validator_result.publish(plan.run_id, path)
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:      # noqa: BLE001 - T07 refused the candidate; T07 kept its own receipt
            pass


def _resumable(base: Path, fingerprint: str) -> tuple | None:
    """(attempt id, decided_at) of a newest attempt that a dead coordinator left RUNNING for
    exactly these inputs. Its instants come from its own allocation record, and C01 then refuses
    any specification those do not derive."""
    try:
        attempt_id = ps.parse_document(_read_regular(base, base / "latest.json"))["attempt_id"]
        if not isinstance(attempt_id, str) or not _HEX32_RE.match(attempt_id):
            return None
        attempt = base / "attempts" / attempt_id
        record = ps.parse_document(_read_regular(attempt, attempt / ATTEMPT_FILE))
        status = ps.parse_document(_read_regular(attempt, attempt / STATUS_FILE))
        if (validate_document(record, ATTEMPT_SCHEMA) or validate_document(status, STATUS_SCHEMA)
                or status["status"] != "RUNNING" or record["attempt_id"] != attempt_id
                or record["input_fingerprint"] != fingerprint):
            return None
        return attempt_id, record["decided_at"]
    except Exception:      # noqa: BLE001
        return None


def dispatch(run_id: str, request_path: Path, *, runtime: DispatchRuntime, force: bool) -> dict:
    """Dispatch every validator cell of one T06 publication, wait for all, account for every row.

    Every argument is required. Returns the accepted pointer plus ``reused``. A refusal before
    anything is dispatched leaves a BLOCKED attempt with a fixed refusal code, moves ``latest.json``
    (so the older accepted accounting is blocked, never silently current) and never replaces
    ``accepted.json``."""
    run_id = identifier(run_id)
    _validate_runtime(runtime)
    if force is not True and force is not False:
        raise TypeError("force must be a bool")
    root = run_path(run_id)
    if not (root / "run-status.json").is_file():
        raise Blocked("create the run through run_process.py --start first")
    try:
        request = ps.parse_document(_read_regular(root, beneath(root, Path(request_path))))
    except Exception:      # noqa: BLE001
        raise ValueError("the dispatch request is not a bounded JSON document with exactly one reading") from None
    if validate_document(request, REQUEST_SCHEMA) or request["run_id"] != run_id:
        raise ValueError("the dispatch request fails its closed schema or names another run")
    facts, base = runtime.facts, _base(run_id)
    with Lock(base / "job.lock"):
        plan = refusal = None
        try:
            plan = load_plan(run_id, request, facts)
        except DispatchBlocked as exc:
            refusal = exc
        resumed = None
        if plan is not None and not force:
            resumed = _resumable(base, plan.fingerprint)
            if resumed is None:
                try:
                    accounting = load_verified_accounting(run_id, facts=facts)
                    if accounting["input_fingerprint"] == plan.fingerprint and reusable(accounting):
                        data = _json_bytes(thaw(accounting))
                        return {**_pointer(accounting, data), "reused": True}
                except DispatchRejected:
                    pass
        attempt_id, decided_at = resumed or (uuid.uuid4().hex, _decided_at(runtime))
        attempt = beneath(base, base / "attempts" / attempt_id)
        if resumed is None:
            attempt.mkdir(parents=True, exist_ok=False)
            atomic_bytes(base / "latest.json", _json_bytes({"attempt_id": attempt_id}))
            atomic_bytes(attempt / ATTEMPT_FILE, _json_bytes({
                "schema": ATTEMPT_ID, "run_id": run_id, "job_id": JOB_ID, "attempt_id": attempt_id,
                "input_fingerprint": plan.fingerprint if plan else None, "decided_at": decided_at}))
            atomic_bytes(attempt / INPUTS_FILE, _json_bytes(request))
        fingerprint = plan.fingerprint if plan else None
        atomic_bytes(attempt / STATUS_FILE, _json_bytes(_status(
            fingerprint, run_id, attempt_id, "RUNNING", outcome=None, accounting=None, refusal=None)))
        try:
            if refusal is not None:
                raise refusal
            specifications = build_specifications(plan, facts, attempt_id=attempt_id, decided_at=decided_at)
            for wave, spec in enumerate(specifications):
                try:
                    ps.plan_expansion(spec, context=_planned_context(plan, facts, attempt, wave))
                except ps.PoolSpecError:
                    raise DispatchBlocked("specification_refused", "C01 or the persona adapter refuses a cell "
                                          "this dispatch derives") from None
        except DispatchBlocked as exc:
            atomic_bytes(attempt / STATUS_FILE, _json_bytes(_status(
                fingerprint, run_id, attempt_id, "BLOCKED", outcome=None, accounting=None, refusal=exc.code)))
            raise
        interrupt = None
        try:
            for name in (OUTPUTS_DIR, WORK_DIR):
                (attempt / name).mkdir(exist_ok=True)
            for wave, spec in enumerate(specifications):
                interrupt = _run_wave(plan, runtime, attempt, wave, spec) or interrupt
            _submit_candidates(plan, facts, attempt, attempt_id, specifications)
            accounting = derive_accounting(plan, facts, attempt=attempt, attempt_id=attempt_id,
                                           specifications=specifications)
            for relative, data in _expected_files(plan, accounting, attempt, specifications).items():
                atomic_bytes(attempt.joinpath(*relative.split("/")), data)
            errors = verify_publication(run_id, attempt_id=attempt_id, facts=facts)
            if errors:
                raise DispatchRejected("the dispatch attempt does not verify after it was written")
            data = _json_bytes(accounting)
            pointer = _pointer(accounting, data)
            atomic_bytes(base / "accepted.json", _json_bytes(pointer))
        except BaseException:
            atomic_bytes(attempt / STATUS_FILE, _json_bytes(_status(
                fingerprint, run_id, attempt_id, "FAILED", outcome=None, accounting=None,
                refusal="publication_failed")))
            raise
        if interrupt is not None:
            raise interrupt
        return {**pointer, "reused": False}


def _planned_context(plan: Plan, facts: DispatchFacts, attempt: Path, wave: int) -> ps.PoolContext:
    context = pool_context(plan, facts, attempt, wave)
    context.pool_parent.mkdir(parents=True, exist_ok=True)
    return context


def main(argv: list | None = None) -> int:
    """Read-only: verify the newest accepted dispatch accounting of a run. Dispatching needs an
    integrator-supplied ``PersonaInvoker``; this repository has no model client, so there is no
    command-line dispatch."""
    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--invoker-id", required=True)
    parser.add_argument("--source-snapshot-sha256", required=True)
    parser.add_argument("--registry-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        base = _base(identifier(args.run_id))
        pointer = ps.parse_document(_read_regular(base, base / "accepted.json"))
        attempt = base / "attempts" / identifier(pointer["attempt_id"])
        model = ps.parse_document(_read_regular(attempt, attempt / INPUTS_FILE))["model"]
        accounting = load_verified_accounting(args.run_id, facts=DispatchFacts(
            registry_dir=args.registry_dir, allowed_models=(model,), invoker_id=args.invoker_id,
            source_snapshot_sha256=args.source_snapshot_sha256, registry_ceiling=None))
    except Exception as exc:      # noqa: BLE001
        text = str(exc) if isinstance(exc, (DispatchRejected, DispatchBlocked)) else "not verifiable"
        print(f"OWASP_DISPATCH_REJECTED: {text}", file=sys.stderr)
        return 2
    print(json.dumps({name: accounting[name] for name in ("run_id", "attempt_id", "status", "dispatch_outcome")},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
