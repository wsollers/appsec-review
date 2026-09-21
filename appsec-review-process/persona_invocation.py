#!/usr/bin/env python3
"""Persona invocation adapter (backlog batch B14): ``appsec-review/persona-invocation-adapter/1.0``.

One request, one registry-composed persona, one exact model, one opaque invoker, one terminal
result. This is the dispatch protocol only: there is no model client and no network here. The
thing that talks to a model is an integrator-supplied :class:`PersonaInvoker` on the trusted
runtime. It is handed a frozen, already-verified :class:`InvocationPackage` (bytes, not paths) and
may write only beneath one output root that the adapter created.

* The request pins the outer prompt, the persona with its registry composition, the model, the
  allow-listed tool ids, a required budget, the exact readable inputs, the output root, the claim
  classes and the B11 permission fingerprint. Each pin is re-derived from the registry or from
  bytes on disk before anything is created.
* Prompt text, evidence bytes and invoker output are data. Nothing read from them reaches a path,
  an error message, the result or the worker envelope; they can change no pinned value.
* A reviewing invocation (verify, refute, judge) names the producer invocations it reads and is
  refused unless it is independent of each (``appsec-review/persona-independence/1.0``).
* The invoker's manifest is untrusted. The adapter re-derives or bounds every field, and a
  read-only verifier re-derives the whole attempt again from the expected request.

See ``docs/persona-invocation-adapter.md``.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from execution_state import atomic_bytes, beneath  # noqa: E402
import permission_capabilities as pc  # noqa: E402
from schema_validate import SchemaStore, validate_document  # noqa: E402
from tool_instance_shapes import output_path_errors  # noqa: E402

ADAPTER_ID = "appsec-review/persona-invocation-adapter/1.0"
REQUEST_ID = "appsec-review/persona-invocation-request/1.0"
OUTPUT_ID = "appsec-review/persona-invoker-output/1.0"
RECORD_ID = "appsec-review/persona-invocation-record/1.0"
RESULT_ID = "appsec-review/persona-invocation-result/1.0"
INDEPENDENCE_ID = "appsec-review/persona-independence/1.0"
FINGERPRINT_ID = "appsec-review/persona-invocation-fingerprint/1.0"
FIXTURE_NOTE_ID = "appsec-review/persona-fixture-note/1.0"

REQUEST_SCHEMA = "persona-invocation-request.schema.json"
OUTPUT_SCHEMA = "persona-invoker-output.schema.json"
RECORD_SCHEMA = "persona-invocation-record.schema.json"
RESULT_SCHEMA = "persona-invocation-result.schema.json"

REGISTRY_DIR = ROOT / "registry"
PROMPT_ROOT = ROOT          # outer prompts are named relative to the process tree, as the worker sees it
WORKER_KIND = "persona"
REQUEST_FILE = "request.json"
RECORD_FILE = "invocation.json"
RESULT_FILE = "invocation-result.json"
MANIFEST_FILE = "invoker-output.json"
LOG_FILES = (RECORD_FILE, REQUEST_FILE)

# name, registry directory, schema, the record's own id field
COMPOSITION_KINDS: tuple[tuple[str, str, str, str], ...] = (
    ("job_template", "job-templates", "job-template.schema.json", "job_template_id"),
    ("persona", "personas", "persona.schema.json", "persona_id"),
    ("role", "roles", "role.schema.json", "role_id"),
    ("domain", "domains", "domain.schema.json", "domain_id"),
    ("tooling_profile", "tooling-profiles", "tooling-profile.schema.json", "tooling_profile_id"),
    ("output_contract", "output-contracts", "output-contract.schema.json", "contract_id"),
)

REVIEW_ROLES = ("verify", "refute", "judge")
BUDGET_BOUNDS: Mapping[str, tuple[int, int]] = MappingProxyType({
    "input_byte_limit": (1, 64 * 1024 * 1024),
    "input_unit_limit": (1, 2_000_000),
    "output_byte_limit": (1, 16 * 1024 * 1024),
    "output_unit_limit": (1, 1_000_000),
    "output_file_limit": (1, 256),
    "tool_call_limit": (0, 10_000),
    "timeout_seconds": (1, 86_400),
})
STOP_GRACE_BOUNDS = (0, 60)
MAX_INPUTS = 256
MAX_PRODUCERS = 64
MAX_TOOLS = 64
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024
MAX_ATTEMPT_ENTRIES = 100_000
OUTPUT_SUFFIXES = (".json", ".md", ".txt")
MODEL_ALIAS_WORDS = ("latest", "default", "current", "stable", "auto", "preview", "newest", "any")

# Never emitted through this adapter, whatever a registry record says (ADR-0008 claim limits,
# ADR-0009 validator boundaries): promotions belong to refutation, verification, scoring and
# synthesis lanes, which do not exist as persona jobs yet.
BASELINE_PROHIBITED: tuple[str, ...] = (
    "compliance_score", "compliance_verdict", "exploitability_verdict", "final_severity",
    "malicious_intent", "observed_runtime_state", "remediation_status", "verified_finding",
    "verified_security_finding",
)
# Lexical backstop over every published text field and output file. A class has a rule or it does
# not; a rule applies whenever its class is prohibited for the request (the baseline always is).
CLAIM_TEXT_RULES: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "verified_finding": (r"\b(?:finding|vulnerability)\s+(?:is\s+)?(?:exists|confirmed|established|verified)\b",
                         r"\b(?:is|are|was|were)\s+(?:a\s+)?vulnerab"),
    "final_severity": (r"\b(?:critical|high|medium|low)\s+severity\b", r"\bseverity\s*(?:is|=|:)",
                       r"\bcvss\b"),
    "exploitability_verdict": (r"\bexploitable\b", r"\bexploitability\s*(?:is|=|:)"),
    "compliance_verdict": (r"\b(?:is|are)\s+(?:fully\s+)?(?:compliant|certified)\b", r"\bcertified\b"),
    "remediation_status": (r"\b(?:is|was|has\s+been)\s+(?:fixed|remediated)\b",),
    "observed_runtime_state": (r"\bobserved\s+(?:in|on)\s+(?:production|runtime|a\s+live|a\s+device)\b",),
    "malicious_intent": (r"\b(?:malicious|hostile)\s+intent\s+(?:is\s+)?(?:confirmed|established|proven)\b",),
})
_TEXT_RULES = {name: tuple(re.compile(p, re.IGNORECASE) for p in patterns)
               for name, patterns in CLAIM_TEXT_RULES.items()}

BLOCKED_CAUSES = ("PERMISSION_DENIED", "INVOKER_UNAVAILABLE")
OUTPUT_CAUSES = ("OUTPUT_ESCAPE", "MALFORMED_RESULT", "IDENTITY_MISMATCH", "BUDGET_EXCEEDED",
                 "UNDECLARED_TOOL", "PROHIBITED_CLAIM", "UNDECLARED_CITATION", "SELF_VERIFICATION")
STATUS_BY_CAUSE: Mapping[str | None, str] = MappingProxyType({
    None: "OK",
    **{cause: "BLOCKED" for cause in BLOCKED_CAUSES},
    "TIMEOUT": "FAILED", "INVOKER_EXCEPTION": "FAILED",
    **{cause: "FAILED" for cause in OUTPUT_CAUSES},
    "CANCELED": "CANCELED",
})
CAUSE_BY_OUTCOME: Mapping[str, str] = MappingProxyType({
    "not_invoked": "PERMISSION_DENIED", "unavailable": "INVOKER_UNAVAILABLE", "timed_out": "TIMEOUT",
    "canceled": "CANCELED", "raised": "INVOKER_EXCEPTION",
})
SUMMARIES: Mapping[str | None, str] = MappingProxyType({
    None: "the invoker returned and every output, identity, budget, claim and citation re-derived",
    "PERMISSION_DENIED": "the permission gate did not re-derive a GRANTED decision; the invoker was not called",
    "INVOKER_UNAVAILABLE": "the invoker reported that it cannot run; nothing was produced",
    "TIMEOUT": "the invoker exceeded the required wall-clock timeout; its output is not accepted",
    "CANCELED": "the invocation was canceled; its output is not accepted",
    "INVOKER_EXCEPTION": "the invoker raised; its output is not accepted",
    "OUTPUT_ESCAPE": "something outside the output root changed, or the output root holds a link, a special file or a path that leaves it",
    "MALFORMED_RESULT": "the invoker manifest or an output file is missing, extra, oversized, not UTF-8, not canonical or fails its closed schema",
    "IDENTITY_MISMATCH": "the invoker manifest names a different request, invoker, persona or model",
    "BUDGET_EXCEEDED": "the output or the reported usage exceeds the required budget",
    "UNDECLARED_TOOL": "the invoker manifest reports a tool that the request did not allow",
    "PROHIBITED_CLAIM": "the output carries a claim class that is not allowed, or text that asserts a prohibited claim",
    "UNDECLARED_CITATION": "a citation or a verified invocation is not a declared readable input or producer",
    "SELF_VERIFICATION": "the output claims to verify its own invocation, or a producing invocation claims a verification",
})

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,119}\Z")
_REG_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,95}\Z")
_SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_PATH_RE = re.compile(r"[A-Za-z0-9._ /-]{1,512}\Z")
_CLAIM_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_ACTION_TEXT_RE = re.compile(r"[^\x00-\x1f\x7f]{1,500}\Z")
_SCHEMA_PATH_RE = re.compile(r"\$[A-Za-z0-9_.\[\]]{0,200}\Z")


class PersonaRequestError(ValueError):
    """The request, the runtime, the registry or a pinned file is unacceptable. Raised before
    anything is created or called. Messages name positions and rules only; they never quote a
    value read from a request, a prompt, evidence, an attempt or invoker output."""


class PersonaExecutionError(RuntimeError):
    """The adapter could not persist its own terminal record. Never a success."""


class InvokerUnavailable(RuntimeError):
    """Raised by an invoker that cannot run at all (no client, no quota, no route)."""


# ---- small helpers -------------------------------------------------------------------------------

def _sha(value: Any) -> str:
    return "sha256:" + pc.digest(value)


def _bytes_sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    """The one byte form of every JSON document this adapter reads or writes."""
    return (json.dumps(thaw(document), indent=2, sort_keys=True) + "\n").encode("utf-8")


def request_sha256(request: Mapping[str, Any]) -> str:
    return _sha(thaw(request))


def result_sha256(result: Mapping[str, Any]) -> str:
    """Integrity hash over every other field. Not an authenticator: the verifier re-derives."""
    return _sha({key: value for key, value in thaw(result).items() if key != "result_sha256"})


def freeze(value: Any) -> Any:
    """Deeply immutable view, so a returned record cannot drift from what was verified."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(item) for item in value)
    return value


def thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [thaw(item) for item in value]
    return value


def _schema_locations(errors: list[str]) -> str:
    """Schema messages quote values; their ``$.a.b[0]`` prefix is built from declared property
    names and indices only, so that prefix (and nothing else) is safe to report."""
    places = sorted({error.split(":", 1)[0] for error in errors})
    safe = [place for place in places if _SCHEMA_PATH_RE.match(place)]
    return f"{len(errors)} errors at " + ", ".join(safe[:8]) if safe else f"{len(errors)} errors"


def _segments_ok(path: str) -> bool:
    """One spelling: no '.', '..', empty or leading-slash segment, and no segment that a Windows
    host would alias (outer space, trailing dot)."""
    if not isinstance(path, str) or not _PATH_RE.match(path) or output_path_errors(path):
        return False
    return all(segment == segment.strip() and not segment.endswith(".") for segment in path.split("/"))


# ---- registry: composition, tool ids and the claim-class ceiling ----------------------------------

def tool_ids(profile: Mapping[str, Any]) -> dict[str, str]:
    """Tooling profiles list ``allowed_actions`` as sentences. The adapter never accepts a
    sentence: each action is addressed by ``act-`` plus 24 hex digits of the sha256 of its exact
    text, so a request can only select actions the registry record already carries."""
    return {"act-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]: text
            for text in profile["allowed_actions"]}


def claim_ceiling(role: Mapping[str, Any], profile: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    """Persona records carry no claim-class field, so the ceiling is a conservative default-deny
    derived from what the composition does carry:

    allowed    = role.allowed_outputs, intersected with the profile's ``claim_limits.allowed`` list
                 when it has one, minus everything prohibited;
    prohibited = BASELINE_PROHIBITED + role.forbidden_outputs + the profile's
                 ``claim_limits.forbidden`` list + every ``claim_limits`` key whose value is
                 anything other than ``allowed`` or ``allowed_<qualifier>``.
    """
    limits = profile["claim_limits"]
    prohibited = set(BASELINE_PROHIBITED) | set(role["forbidden_outputs"])
    allowed = set(role["allowed_outputs"])
    for key, value in limits.items():
        if key == "forbidden" and isinstance(value, list):
            prohibited |= set(value)
        elif key == "allowed" and isinstance(value, list):
            allowed &= set(value)
        elif not (isinstance(value, str) and (value == "allowed" or value.startswith("allowed_"))):
            prohibited.add(key)
    return {"allowed": tuple(sorted(allowed - prohibited)), "prohibited": tuple(sorted(prohibited))}


def composition_errors(records: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """What this adapter relies on in a composition. Fixed text; registry ids are trusted names."""
    errors: list[str] = []
    role, profile = records["role"], records["tooling_profile"]
    for field in ("allowed_outputs", "forbidden_outputs"):
        values = role[field]
        if not all(isinstance(v, str) and _CLAIM_RE.match(v) for v in values) or len(values) != len(set(values)):
            errors.append(f"role.{field} must be unique claim-class ids")
    if set(role["allowed_outputs"]) & set(role["forbidden_outputs"]):
        errors.append("role allows and forbids one claim class")
    limits = profile["claim_limits"]
    for key, value in limits.items():
        if not isinstance(key, str) or not _CLAIM_RE.match(key):
            errors.append("tooling profile claim_limits key is not a claim-class id")
        elif key in ("allowed", "forbidden"):
            if not isinstance(value, list) or not all(isinstance(v, str) and _CLAIM_RE.match(v) for v in value):
                errors.append("tooling profile claim_limits list must hold claim-class ids")
        elif not isinstance(value, str) or not _CLAIM_RE.match(value):
            errors.append("tooling profile claim_limits value is free text, not a closed word")
    actions = profile["allowed_actions"]
    if (not actions or len(actions) > MAX_TOOLS or len(set(actions)) != len(actions)
            or not all(isinstance(a, str) and _ACTION_TEXT_RE.match(a) and a == a.strip() for a in actions)):
        errors.append("tooling profile allowed_actions must be 1..64 unique bounded single-line actions")
    elif len(tool_ids(profile)) != len(actions):
        errors.append("two tooling profile actions share one derived tool id")
    if not errors and set(role["allowed_outputs"]) & set(BASELINE_PROHIBITED):
        errors.append("role allows a claim class that no persona invocation may emit")
    return errors


def _load_record(registry_dir: Path, directory: str, schema: str, field: str, record_id: str,
                 store: SchemaStore) -> dict[str, Any]:
    try:
        path = beneath(registry_dir, registry_dir / directory / (record_id + ".json"))
        record = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, ValueError):
        raise PersonaRequestError(f"a {directory} record named by the request is missing, linked or unreadable") from None
    if validate_document(record, schema, store) or record.get(field) != record_id:
        raise PersonaRequestError(f"a {directory} record named by the request is invalid or misnamed")
    return record


def load_composition(registry_dir: Path, persona: Mapping[str, str], store: SchemaStore
                     ) -> dict[str, dict[str, Any]]:
    """The request names a job template and repeats the five ids that template composes; every id
    and every record hash must agree with the registry. The registry decides, not the request."""
    registry_dir = Path(registry_dir)
    records: dict[str, dict[str, Any]] = {}
    for name, directory, schema, field in COMPOSITION_KINDS:
        record_id = persona[name + "_id"]
        if not isinstance(record_id, str) or not _REG_RE.match(record_id):
            raise PersonaRequestError(f"persona.{name}_id is not a registry id")
        records[name] = _load_record(registry_dir, directory, schema, field, record_id, store)
        if persona[name + "_sha256"] != _sha(records[name]):
            raise PersonaRequestError(f"persona.{name}_sha256 is not the hash of the registered record")
    composed = records["job_template"]["composition"]
    for name, _, _, _ in COMPOSITION_KINDS[1:]:
        if composed[name + "_id"] != persona[name + "_id"]:
            raise PersonaRequestError(f"persona.{name}_id is not what the named job template composes")
    errors = composition_errors(records)
    if errors:
        raise PersonaRequestError("the named composition cannot be invoked: " + "; ".join(errors))
    if not claim_ceiling(records["role"], records["tooling_profile"])["allowed"]:
        # Default deny, not a registry defect: role and tooling profile agree on no claim class.
        raise PersonaRequestError("the named composition allows no claim class, so it cannot be invoked")
    return records


def composition_sha256(records: Mapping[str, Mapping[str, Any]]) -> str:
    return _sha({name: _sha(thaw(records[name])) for name, _, _, _ in COMPOSITION_KINDS})


def validate_persona_registry(registry_dir: Path) -> list[str]:
    """Every tracked persona record, and every job-template composition, checked for what this
    adapter relies on. Read-only. Names in messages are registry file stems (trusted). A
    composition whose ceiling is empty is not an error here: it is simply never invocable, and
    :func:`not_invocable_templates` lists it."""
    return _registry_survey(registry_dir)[0]


def not_invocable_templates(registry_dir: Path) -> list[str]:
    """Job templates whose role and tooling profile agree on no claim class (default deny)."""
    return _registry_survey(registry_dir)[1]


def _registry_survey(registry_dir: Path) -> tuple[list[str], list[str]]:
    registry_dir = Path(registry_dir)
    store = SchemaStore()
    errors: list[str] = []
    denied: list[str] = []
    personas = sorted((registry_dir / "personas").glob("*.json"))
    if not personas:
        return ["persona registry is missing or empty"], denied
    for path in personas:
        try:
            _load_record(registry_dir, "personas", "persona.schema.json", "persona_id", path.stem, store)
        except PersonaRequestError:
            errors.append(f"personas/{path.stem}: invalid, unreadable or misnamed")
    for path in sorted((registry_dir / "job-templates").glob("*.json")):
        try:
            template = _load_record(registry_dir, "job-templates", "job-template.schema.json",
                                    "job_template_id", path.stem, store)
            block = {"job_template_id": path.stem, "job_template_sha256": _sha(template)}
            for name, directory, schema, field in COMPOSITION_KINDS[1:]:
                record_id = template["composition"][name + "_id"]
                if not isinstance(record_id, str) or not _REG_RE.match(record_id):
                    raise PersonaRequestError("composition id is not a registry id")
                block[name + "_id"] = record_id
                block[name + "_sha256"] = _sha(_load_record(registry_dir, directory, schema, field, record_id, store))
            try:
                load_composition(registry_dir, block, store)
            except PersonaRequestError as exc:
                if "allows no claim class" not in str(exc):
                    raise
                denied.append(path.stem)
        except PersonaRequestError as exc:
            errors.append(f"job-templates/{path.stem}: {exc}")
    return errors, denied


# ---- request validation (pure) -------------------------------------------------------------------

def model_errors(model: Mapping[str, str], label: str) -> list[str]:
    """Shape is the schema's job. This rejects an alias where a pinned version must be."""
    errors = []
    snapshot, model_id = model["snapshot"], model["model_id"]
    words = set(re.split(r"[._-]", snapshot)) | set(re.split(r"[._-]", model_id))
    if words & set(MODEL_ALIAS_WORDS):
        errors.append(f"{label} names a moving alias; a model identity must be one immutable version")
    if not re.search(r"[0-9]", snapshot):
        errors.append(f"{label}.snapshot carries no version digits")
    return errors


def independence_errors(request: Mapping[str, Any]) -> list[str]:
    """``appsec-review/persona-independence/1.0``.

    A producing invocation names no producer and reads no producer output. A reviewing invocation
    (verify, refute, judge) names every producer invocation whose output it reads, and for each:
    it is a different attempt, a different persona and a different model family. Sources:
    design-v3 5.1 (not discovered, verified and adjudicated by the same agent), ADR-0008 claim
    limits (a different persona and, where B14 records it, a different model family; no cell
    verifies its own claim), design-parity plan (one worker result may not self-verify).
    """
    errors: list[str] = []
    role, producers = request["invocation_role"], request["producers"]
    reads = [entry["producer_request_sha256"] for entry in request["readable_inputs"]
             if entry["role"] == "producer_output"]
    if role not in REVIEW_ROLES:
        if producers or reads:
            errors.append("a producing invocation cannot name producers or read producer output")
        return errors
    if not producers or len(producers) > MAX_PRODUCERS:
        errors.append(f"a reviewing invocation must name 1..{MAX_PRODUCERS} producer invocations")
    named = [producer["request_sha256"] for producer in producers]
    if len(named) != len(set(named)):
        errors.append("producers repeat a request hash")
    if set(reads) != set(named):
        errors.append("every producer must be read, and every producer output must name a declared producer")
    for index, producer in enumerate(producers):
        if (producer["run_id"], producer["job_id"], producer["attempt_id"]) == (
                request["run_id"], request["job_id"], request["attempt_id"]):
            errors.append(f"self-verification: producers[{index}] is this attempt")
        if producer["persona_id"] == request["persona"]["persona_id"]:
            errors.append(f"self-verification: producers[{index}] is the same persona")
        if producer["model"]["family"] == request["model"]["family"]:
            errors.append(f"self-verification: producers[{index}] is the same model family")
        errors.extend(model_errors(producer["model"], f"producers[{index}].model"))
    return errors


def request_errors(request: Any, *, run_id: str, job_id: str, attempt_id: str,
                   store: SchemaStore | None = None) -> list[str]:
    """Closed schema first, then every bound the schema subset cannot express. Pure."""
    if not isinstance(request, Mapping):
        return ["request is not an object"]
    request = thaw(request)
    if not isinstance(request.get("model"), dict) or any(
            not isinstance(request["model"].get(part), str) or not request["model"].get(part)
            for part in ("provider", "family", "model_id", "snapshot")):
        return ["model identity is missing: provider, family, model_id and snapshot are all required"]
    budget = request.get("budget")
    if not isinstance(budget, dict) or any(not _is_int(budget.get(name)) for name in BUDGET_BOUNDS):
        return ["unbounded context: every budget limit is a required integer"]
    schema_errors = validate_document(request, REQUEST_SCHEMA, store or SchemaStore())
    if schema_errors:
        return ["request fails its closed schema (" + _schema_locations(schema_errors) + ")"]
    errors: list[str] = []
    for name, expected in (("run_id", run_id), ("job_id", job_id), ("attempt_id", attempt_id)):
        if request[name] != expected:
            errors.append(f"request.{name} is not the {name} of the worker request it arrived in")
    errors.extend(model_errors(request["model"], "model"))
    for name, (low, high) in BUDGET_BOUNDS.items():
        if not low <= budget[name] <= high:
            errors.append(f"unbounded context: budget.{name} must be an integer within {low}..{high}")
    tools = request["tools"]
    if tools != sorted(set(tools)) or len(tools) > MAX_TOOLS:
        errors.append(f"tools must be at most {MAX_TOOLS} sorted, unique tool ids")
    if (budget["tool_call_limit"] == 0) != (not tools):
        errors.append("budget.tool_call_limit must be zero exactly when no tool is allowed")
    for field in ("allowed_claim_classes", "prohibited_claim_classes"):
        if request[field] != sorted(set(request[field])):
            errors.append(f"{field} must be sorted and unique")
    if set(request["allowed_claim_classes"]) & set(request["prohibited_claim_classes"]):
        errors.append("a claim class cannot be both allowed and prohibited")
    for label in ("output_root", "log_path"):
        if not _segments_ok(request[label]):
            errors.append(f"{label} is not one normalized relative path inside the attempt")
    out, log = request["output_root"].lower().split("/"), request["log_path"].lower().split("/")
    shorter = min(len(out), len(log))
    if out[:shorter] == log[:shorter]:
        errors.append("output_root and log_path must not be equal or contain one another")
    if not _segments_ok(request["outer_prompt"]["path"]):
        errors.append("outer_prompt.path is not one normalized relative path")
    inputs = request["readable_inputs"]
    if len(inputs) > MAX_INPUTS:
        errors.append(f"more than {MAX_INPUTS} readable inputs")
    seen: set[tuple[str, str]] = set()
    total = request["outer_prompt"]["bytes"]
    if total < 1:
        errors.append("outer_prompt.bytes must be at least 1")
    for index, entry in enumerate(inputs):
        if not _segments_ok(entry["path"]):
            errors.append(f"readable_inputs[{index}].path is not one normalized relative path")
        key = (entry["root"], entry["path"].lower())
        if key in seen:
            errors.append(f"readable_inputs[{index}] repeats an earlier input")
        seen.add(key)
        if entry["bytes"] < 0:
            errors.append(f"readable_inputs[{index}].bytes is negative")
        total += max(entry["bytes"], 0)
        if (entry["role"] == "producer_output") != (entry["producer_request_sha256"] is not None):
            errors.append(f"readable_inputs[{index}].producer_request_sha256 is required exactly for producer output")
    if total > budget["input_byte_limit"]:
        errors.append("unbounded context: the prompt and readable inputs exceed budget.input_byte_limit")
    errors.extend(independence_errors(request))
    decision = request["permission"]["decision"]
    try:
        derived = pc.fingerprint_material(decision["decision"], decision["capabilities"])["sha256"]
    except (TypeError, ValueError, KeyError):
        derived = None
    if (request["permission_fingerprint_sha256"] != derived
            or decision["fingerprint_material"]["sha256"] != derived):
        errors.append("permission_fingerprint_sha256 is not the capability fingerprint the decision derives")
    return errors


# ---- filesystem identity and pinned reads ---------------------------------------------------------

def _identity(path: Path) -> tuple[int, int] | None:
    try:
        status = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    return (status.st_dev, status.st_ino)


def _checked_root(root: Any, label: str) -> Path:
    if not isinstance(root, Path) or not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise PersonaRequestError(f"{label} must be an absolute, existing, non-link directory")
    return root


def _read_pinned(root: Path, relative: str, *, sha256: str, size: int, attempt: tuple[int, int] | None,
                 label: str) -> tuple[bytes, tuple[int, int]]:
    """Reads one pinned file once. Identity is device+inode; the bytes that are hashed are the
    bytes that are handed over."""
    path = root.joinpath(*relative.split("/"))
    try:
        beneath(root, path)
    except ValueError:
        raise PersonaRequestError(f"{label}: leaves its root or crosses a link") from None
    try:
        before = os.stat(path, follow_symlinks=False)
    except OSError:
        raise PersonaRequestError(f"{label}: does not exist") from None
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise PersonaRequestError(f"{label}: is a link, a hard-linked file, a directory or a special file")
    expected = os.path.join(os.path.realpath(root), *relative.split("/"))
    if os.path.realpath(path) != expected:
        raise PersonaRequestError(f"{label}: is not the one real spelling of the file")
    if attempt is not None and attempt in {_identity(part) for part in path.parents}:
        raise PersonaRequestError(f"{label}: is inside the attempt; an attempt never reads itself")
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            data = stream.read(size + 1)
    except OSError:
        raise PersonaRequestError(f"{label}: is unreadable") from None
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
        raise PersonaRequestError(f"{label}: changed identity while it was opened")
    if len(data) != size or _bytes_sha(data) != sha256:
        raise PersonaRequestError(f"{label}: bytes on disk do not have the pinned size and sha256")
    return data, (before.st_dev, before.st_ino)


@dataclass(frozen=True)
class ReadableInput:
    root: str
    path: str
    role: str
    sha256: str
    producer_request_sha256: str | None
    data: bytes


@dataclass(frozen=True)
class InvocationPackage:
    """Everything an invoker receives. Bytes, not paths; frozen mappings and tuples only."""
    request: Mapping[str, Any]
    request_sha256: str
    package_sha256: str
    prompt: bytes
    composition: Mapping[str, Mapping[str, Any]]
    tool_actions: Mapping[str, str]
    allowed_claim_classes: tuple[str, ...]
    prohibited_claim_classes: tuple[str, ...]
    inputs: tuple[ReadableInput, ...]
    granted_capabilities: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class ResolvedRequest:
    request: Mapping[str, Any]
    request_sha256: str
    composition: Mapping[str, Mapping[str, Any]]
    composition_sha256: str
    tool_actions: Mapping[str, str]
    prompt: bytes
    inputs: tuple[ReadableInput, ...]
    input_bytes: int
    readable_inputs_sha256: str
    package_sha256: str
    permission_fingerprint_sha256: str


def resolve_request(request: Any, *, run_id: str, job_id: str, attempt_id: str, attempt_root: Path,
                    registry_dir: Path, prompt_root: Path, readable_roots: Mapping[str, Path],
                    allowed_models: tuple) -> ResolvedRequest:
    """Every pin re-derived: schema and bounds, the model allow-list, the registry composition,
    tool ids and claim ceiling, then the prompt and each readable input against bytes on disk.
    Creates nothing. Shared by the adapter and the verifier."""
    try:
        request = json.loads(json.dumps(thaw(request), allow_nan=False))
    except (TypeError, ValueError):
        raise PersonaRequestError("request is not a JSON document") from None
    errors = request_errors(request, run_id=run_id, job_id=job_id, attempt_id=attempt_id)
    if errors:
        raise PersonaRequestError("persona request rejected: " + "; ".join(errors))
    if request["model"] not in [thaw(model) for model in allowed_models]:
        raise PersonaRequestError("model is not on the runtime's model allow-list")
    records = load_composition(registry_dir, request["persona"], SchemaStore())
    actions = tool_ids(records["tooling_profile"])
    if not set(request["tools"]) <= set(actions):
        raise PersonaRequestError("tools names an id the tooling profile does not derive")
    ceiling = claim_ceiling(records["role"], records["tooling_profile"])
    allowed, prohibited = set(request["allowed_claim_classes"]), set(request["prohibited_claim_classes"])
    if not allowed <= set(ceiling["allowed"]):
        raise PersonaRequestError("allowed_claim_classes widens the claim-class ceiling of the composition")
    if not set(ceiling["prohibited"]) <= prohibited:
        raise PersonaRequestError("prohibited_claim_classes drops a class the composition prohibits")
    if not prohibited <= set(ceiling["prohibited"]) | set(ceiling["allowed"]):
        raise PersonaRequestError("prohibited_claim_classes names a class outside the composition's closed set")

    attempt_root = _checked_root(Path(attempt_root) if isinstance(attempt_root, (str, Path)) else attempt_root,
                                 "attempt_root")
    attempt = _identity(attempt_root)
    prompt_root = _checked_root(prompt_root, "prompt_root")
    prompt, prompt_identity = _read_pinned(
        prompt_root, request["outer_prompt"]["path"], sha256=request["outer_prompt"]["sha256"],
        size=request["outer_prompt"]["bytes"], attempt=attempt, label="outer_prompt")
    try:
        prompt.decode("utf-8")
    except UnicodeDecodeError:
        raise PersonaRequestError("outer_prompt: is not UTF-8") from None
    if not isinstance(readable_roots, Mapping) or not readable_roots:
        raise PersonaRequestError("readable_roots must name at least one root")
    roots = {name: _checked_root(path, "a readable root") for name, path in readable_roots.items()
             if isinstance(name, str) and _REG_RE.match(name)}
    if len(roots) != len(readable_roots):
        raise PersonaRequestError("readable_roots keys must be registry-style ids")
    seen = {prompt_identity}
    inputs: list[ReadableInput] = []
    for index, entry in enumerate(request["readable_inputs"]):
        label = f"readable_inputs[{index}]"
        if entry["root"] not in roots:
            raise PersonaRequestError(f"{label}: root is not a declared readable root")
        data, identity = _read_pinned(roots[entry["root"]], entry["path"], sha256=entry["sha256"],
                                      size=entry["bytes"], attempt=attempt, label=label)
        if identity in seen:
            raise PersonaRequestError(f"{label}: is the same file as the prompt or an earlier input")
        seen.add(identity)
        inputs.append(ReadableInput(entry["root"], entry["path"], entry["role"], entry["sha256"],
                                    entry["producer_request_sha256"], data))
    decision = request["permission"]["decision"]
    fingerprint = pc.fingerprint_material(decision["decision"], decision["capabilities"])["sha256"]
    inputs_sha = _sha(request["readable_inputs"])
    comp_sha = composition_sha256(records)
    package_sha = _sha({"schema": FINGERPRINT_ID, "adapter": ADAPTER_ID, "independence_rule": INDEPENDENCE_ID,
                        "request_sha256": request_sha256(request), "prompt_sha256": request["outer_prompt"]["sha256"],
                        "composition_sha256": comp_sha, "readable_inputs_sha256": inputs_sha,
                        "permission_fingerprint_sha256": fingerprint})
    return ResolvedRequest(
        request=freeze(request), request_sha256=request_sha256(request), composition=freeze(records),
        composition_sha256=comp_sha, tool_actions=MappingProxyType(dict(actions)), prompt=prompt,
        inputs=tuple(inputs), input_bytes=len(prompt) + sum(len(item.data) for item in inputs),
        readable_inputs_sha256=inputs_sha, package_sha256=package_sha,
        permission_fingerprint_sha256=fingerprint)


def fingerprint_material(resolved: ResolvedRequest) -> dict[str, Any]:
    """What an integrator folds into a job input fingerprint for one invocation. The permission
    block is represented by the B11 capability fingerprint (no grant ids or timestamps)."""
    request = thaw(resolved.request)
    body = {"schema": FINGERPRINT_ID, "adapter": ADAPTER_ID, "independence_rule": INDEPENDENCE_ID,
            "composition_sha256": resolved.composition_sha256,
            "permission_fingerprint_sha256": resolved.permission_fingerprint_sha256,
            "request_without_permission_sha256": _sha(
                {key: value for key, value in request.items() if key != "permission"})}
    return {**body, "sha256": _sha(body)}


# ---- runtime and invoker protocol -----------------------------------------------------------------

@runtime_checkable
class PersonaInvoker(Protocol):
    """The only thing that may talk to a model. It receives verified bytes, writes its files and
    then ``invoker-output.json`` beneath ``output_root`` and nowhere else, polls ``cancel``, and
    returns nothing: the adapter reads what is on disk, never a returned value."""
    invoker_id: str

    def invoke(self, package: InvocationPackage, *, output_root: Path, cancel: threading.Event) -> None: ...


@dataclass(frozen=True)
class PersonaRuntime:
    """Trusted, integrator-supplied side of one invocation. Every field is required."""
    invoker: Any
    registry_dir: Path
    prompt_root: Path
    readable_roots: Mapping[str, Path]
    allowed_models: tuple
    source_snapshot_sha256: str
    registry_ceiling: list | None
    clock: Callable[[], str]
    cancel: threading.Event
    stop_grace_seconds: int


def validate_runtime(runtime: Any) -> None:
    if not isinstance(runtime, PersonaRuntime):
        raise TypeError("persona invocation requires a PersonaRuntime")
    invoker = runtime.invoker
    if (not callable(getattr(invoker, "invoke", None)) or not isinstance(getattr(invoker, "invoker_id", None), str)
            or not _REG_RE.match(invoker.invoker_id)):
        raise PersonaRequestError("runtime.invoker must have an invoke method and a registry-style invoker_id")
    for name in ("registry_dir", "prompt_root"):
        if not isinstance(getattr(runtime, name), Path):
            raise PersonaRequestError(f"runtime.{name} must be a path")
    if not isinstance(runtime.readable_roots, Mapping) or not runtime.readable_roots or not all(
            isinstance(path, Path) for path in runtime.readable_roots.values()):
        raise PersonaRequestError("runtime.readable_roots must map at least one id to a path")
    models = runtime.allowed_models
    if not isinstance(models, tuple) or not models:
        raise PersonaRequestError("runtime.allowed_models must be a non-empty tuple; there is no default model")
    for model in models:
        if (not isinstance(model, Mapping) or validate_document(thaw(model), "persona-model-identity.schema.json")
                or model_errors(thaw(model), "model")):
            raise PersonaRequestError("runtime.allowed_models holds something that is not one exact model identity")
    if not isinstance(runtime.source_snapshot_sha256, str) or not _SHA_RE.match(runtime.source_snapshot_sha256):
        raise PersonaRequestError("runtime.source_snapshot_sha256 must be sha256:<64 hex>")
    if runtime.registry_ceiling is not None and not isinstance(runtime.registry_ceiling, list):
        raise PersonaRequestError("runtime.registry_ceiling must be null or a list")
    if not callable(runtime.clock):
        raise PersonaRequestError("runtime.clock must be callable")
    if not isinstance(runtime.cancel, threading.Event):
        raise PersonaRequestError("runtime.cancel must be a threading.Event")
    low, high = STOP_GRACE_BOUNDS
    if not _is_int(runtime.stop_grace_seconds) or not low <= runtime.stop_grace_seconds <= high:
        raise PersonaRequestError(f"runtime.stop_grace_seconds must be an integer within {low}..{high}")


def _now(runtime: PersonaRuntime) -> str:
    value = runtime.clock()
    if not isinstance(value, str) or not _TS_RE.match(value):
        raise PersonaRequestError("runtime.clock must return a UTC timestamp like 2026-01-01T00:00:00Z")
    return value


def _gate(request: Mapping[str, Any], *, run_id: str, job_id: str, now: str,
          source_snapshot_sha256: str, registry_ceiling: list | None) -> tuple | None:
    """The B11 gate at one instant. None means not granted."""
    permission = thaw(request["permission"])
    context = {"run_id": run_id, "job_id": job_id, "now": now,
               "source_snapshot_sha256": source_snapshot_sha256, "registry_ceiling": registry_ceiling}
    try:
        return freeze(pc.require_granted(permission["decision"], requirement=permission["requirement"],
                                         grants=permission["grants"], context=context))
    except pc.PermissionModelError:       # PermissionDenied, or a context the model refuses
        return None


# ---- output derivation: shared by the adapter and the verifier ------------------------------------

def _snapshot(attempt_root: Path, skip: Path) -> dict[str, tuple] | None:
    """Every entry of the attempt outside ``skip``. None when the tree is too large to compare."""
    found: dict[str, tuple] = {}
    for folder, directories, files in os.walk(attempt_root, followlinks=False):
        here = Path(folder)
        directories[:] = [name for name in directories if here / name != skip]
        for name in (*directories, *files):
            status = os.stat(here / name, follow_symlinks=False)
            found[str(here / name)] = (status.st_mode, status.st_size, status.st_mtime_ns, status.st_ino)
            if len(found) > MAX_ATTEMPT_ENTRIES:
                return None
    return found


def scan_output_tree(output_root: Path, budget: Mapping[str, int]
                     ) -> tuple[str, list[dict[str, Any]] | None, dict[str, bytes]]:
    """(state, records, bytes by path). ``irregular``: a link, a special or hard-linked file, an
    empty directory, a second spelling or a name outside the path alphabet. ``over_limit``: more
    files or bytes than the budget could ever admit, decided before reading."""
    contents: dict[str, bytes] = {}
    records: list[dict[str, Any]] = []
    total, ceiling = 0, budget["output_byte_limit"] + MAX_MANIFEST_BYTES
    try:
        if output_root.is_symlink() or not output_root.is_dir():
            return "irregular", None, {}
        for folder, directories, files in os.walk(output_root, followlinks=False):
            here = Path(folder)
            if not directories and not files and here != output_root:
                return "irregular", None, {}
            for name in directories:
                if (here / name).is_symlink():
                    return "irregular", None, {}
            for name in files:
                path = here / name
                relative = path.relative_to(output_root).as_posix()
                status = os.stat(path, follow_symlinks=False)
                if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or not _segments_ok(relative):
                    return "irregular", None, {}
                total += status.st_size
                if len(records) + 1 > budget["output_file_limit"] + 1 or total > ceiling:
                    return "over_limit", None, {}
                data = path.read_bytes()
                if len(data) != status.st_size:
                    return "irregular", None, {}
                contents[relative] = data
                records.append({"path": relative, "sha256": _bytes_sha(data), "bytes": len(data)})
    except OSError:
        return "irregular", None, {}
    lowered = [record["path"].lower() for record in records]
    if len(lowered) != len(set(lowered)):
        return "irregular", None, {}
    return "regular", sorted(records, key=lambda record: record["path"]), contents


def _strings(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, str):
        yield value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """A JSON object that repeats a key has two readings: the parser keeps the last value, a reader
    of the bytes sees both. Text that the claim check never saw must not be published."""
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _asserts_prohibited(texts, prohibited: set[str]) -> bool:
    rules = [rule for name in sorted(prohibited) for rule in _TEXT_RULES.get(name, ())]
    return any(rule.search(text) for text in texts for rule in rules)


def no_facts() -> dict[str, Any]:
    """What a result records about output when nothing is accepted from the output root."""
    return {"output_manifest_sha256": None, "outputs": [], "usage": None, "claim_classes": [],
            "claim_count": 0, "verified_invocations": []}


def derive_output(resolved: ResolvedRequest, state: str, tree: list[dict[str, Any]] | None,
                  contents: Mapping[str, bytes]) -> tuple[str | None, dict[str, Any]]:
    """(cause, facts) from the scanned output root and the expected request. The first failing
    rule, in this fixed order, names the cause. Nothing the invoker wrote is returned except
    hashes, sizes, counts and ids that were checked against the request."""
    request = thaw(resolved.request)
    budget = request["budget"]
    empty = no_facts()
    if state == "over_limit":
        return "BUDGET_EXCEEDED", empty
    if state != "regular" or tree is None:
        return "OUTPUT_ESCAPE", empty
    raw = contents.get(MANIFEST_FILE)
    if raw is None or len(raw) > MAX_MANIFEST_BYTES:
        return "MALFORMED_RESULT", empty
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return "MALFORMED_RESULT", empty
    if validate_document(manifest, OUTPUT_SCHEMA) or raw != canonical_bytes(manifest):
        return "MALFORMED_RESULT", empty
    if (manifest["request_sha256"] != resolved.request_sha256
            or manifest["invoker_id"] != request["invoker_id"]
            or manifest["persona_id"] != request["persona"]["persona_id"]
            or manifest["persona_sha256"] != request["persona"]["persona_sha256"]
            or manifest["model"] != request["model"]):
        return "IDENTITY_MISMATCH", empty
    listed = manifest["files"]
    paths = [entry["path"] for entry in listed]
    if any(path.startswith("/") or ".." in path.split("/") for path in paths):
        return "OUTPUT_ESCAPE", empty
    on_disk = {record["path"]: record for record in tree if record["path"] != MANIFEST_FILE}
    if (paths != sorted(set(paths)) or MANIFEST_FILE in paths or not all(_segments_ok(p) for p in paths)
            or set(paths) != set(on_disk) or any(on_disk[e["path"]] != e for e in listed)):
        return "MALFORMED_RESULT", empty
    # A published path is published text too: its separators are read as spaces.
    texts: list[str] = [re.sub(r"[-_./]+", " ", path) for path in paths]
    for path in paths:
        if not path.lower().endswith(OUTPUT_SUFFIXES):
            return "MALFORMED_RESULT", empty
        try:
            text = contents[path].decode("utf-8")
            texts.extend(_strings(json.loads(text, object_pairs_hook=_unique_object))
                         if path.lower().endswith(".json") else [text])
        except (ValueError, RecursionError):
            return "MALFORMED_RESULT", empty
    usage = manifest["usage"]
    output_bytes = sum(entry["bytes"] for entry in listed)
    if len(listed) > budget["output_file_limit"] or output_bytes > budget["output_byte_limit"]:
        return "BUDGET_EXCEEDED", empty
    if (min(usage.values()) < 0 or usage["output_bytes"] != output_bytes
            or usage["input_bytes"] != resolved.input_bytes):
        return "MALFORMED_RESULT", empty
    if (usage["input_units"] > budget["input_unit_limit"] or usage["output_units"] > budget["output_unit_limit"]
            or usage["tool_calls"] > budget["tool_call_limit"]):
        return "BUDGET_EXCEEDED", empty
    called = [entry["tool_id"] for entry in manifest["tool_calls"]]
    if not set(called) <= set(request["tools"]):
        return "UNDECLARED_TOOL", empty
    if (called != sorted(set(called)) or any(entry["calls"] < 1 for entry in manifest["tool_calls"])
            or sum(entry["calls"] for entry in manifest["tool_calls"]) != usage["tool_calls"]):
        return "MALFORMED_RESULT", empty
    verified = manifest["verified_invocations"]
    if verified != sorted(set(verified)):
        return "MALFORMED_RESULT", empty
    if resolved.request_sha256 in verified or (verified and request["invocation_role"] not in REVIEW_ROLES):
        return "SELF_VERIFICATION", empty
    if not set(verified) <= {producer["request_sha256"] for producer in request["producers"]}:
        return "UNDECLARED_CITATION", empty
    claims = manifest["claims"]
    identifiers = [claim["claim_id"] for claim in claims]
    if len(identifiers) != len(set(identifiers)) or any(
            claim["file"] is not None and claim["file"] not in on_disk for claim in claims):
        return "MALFORMED_RESULT", empty
    if not {claim["claim_class"] for claim in claims} <= set(request["allowed_claim_classes"]):
        return "PROHIBITED_CLAIM", empty
    declared = {(entry["root"], entry["path"], entry["sha256"]) for entry in request["readable_inputs"]}
    citations = [c for claim in claims for c in claim["citations"]] + manifest["injection_suspected"]
    if any((c["root"], c["path"], c["sha256"]) not in declared for c in citations):
        return "UNDECLARED_CITATION", empty
    texts += [claim["statement"] for claim in claims] + manifest["limitations"] + [c["locator"] for c in citations]
    if _asserts_prohibited(texts, set(request["prohibited_claim_classes"])):
        return "PROHIBITED_CLAIM", empty
    return None, {"output_manifest_sha256": _bytes_sha(raw), "outputs": tree, "usage": usage,
                  "claim_classes": sorted({claim["claim_class"] for claim in claims}),
                  "claim_count": len(claims), "verified_invocations": verified}


# ---- invocation ------------------------------------------------------------------------------------

def _call_invoker(runtime: PersonaRuntime, package: InvocationPackage, output_root: Path,
                  timeout_seconds: int) -> tuple[str, bool, BaseException | None]:
    """(outcome, invoker stopped, interrupt to re-raise). The invoker's exception text and return
    value are never kept."""
    if runtime.cancel.is_set():
        return "canceled", True, None
    inner = threading.Event()
    box: dict[str, BaseException] = {}

    def target() -> None:
        try:
            runtime.invoker.invoke(package, output_root=output_root, cancel=inner)
        except BaseException as exc:      # noqa: BLE001 - classified, never echoed
            box["error"] = exc

    thread = threading.Thread(target=target, name="persona-invoker", daemon=True)
    deadline = time.monotonic() + timeout_seconds
    outcome: str | None = None
    interrupt: BaseException | None = None
    thread.start()
    try:
        while thread.is_alive():
            if runtime.cancel.is_set():
                outcome = "canceled"
                break
            if time.monotonic() >= deadline:
                outcome = "timed_out"
                break
            thread.join(0.02)
    except (KeyboardInterrupt, SystemExit) as exc:
        interrupt, outcome = exc, "canceled"
    if outcome is not None:
        inner.set()
        thread.join(runtime.stop_grace_seconds)
        return outcome, not thread.is_alive(), interrupt
    error = box.get("error")
    if error is None:
        return "returned", True, None
    return ("unavailable" if isinstance(error, InvokerUnavailable) else "raised"), True, None


def run_invocation(runtime: PersonaRuntime, *, run_id: str, job_id: str, attempt_id: str,
                   attempt_root: Path, request: Any) -> Mapping[str, Any]:
    """Validate, gate, invoke, re-derive, record. Returns a deeply immutable terminal result."""
    validate_runtime(runtime)
    resolved = resolve_request(
        request, run_id=run_id, job_id=job_id, attempt_id=attempt_id, attempt_root=attempt_root,
        registry_dir=runtime.registry_dir, prompt_root=runtime.prompt_root,
        readable_roots=runtime.readable_roots, allowed_models=runtime.allowed_models)
    request = thaw(resolved.request)
    if runtime.invoker.invoker_id != request["invoker_id"]:
        raise PersonaRequestError("runtime.invoker is not the invoker the request pins")
    attempt_root = Path(attempt_root)
    try:
        output_root = beneath(attempt_root, attempt_root.joinpath(*request["output_root"].split("/")))
        log_dir = beneath(attempt_root, attempt_root.joinpath(*request["log_path"].split("/")))
    except ValueError:
        raise PersonaRequestError("output_root or log_path leaves the attempt or crosses a link") from None
    if os.path.lexists(output_root) or os.path.lexists(log_dir):
        raise PersonaRequestError("output_root and log_path must not exist: the adapter creates them")
    started_at = _now(runtime)

    # Nothing above created a file or called the invoker. From here on the attempt owns evidence.
    log_dir.parent.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(mode=0o700)
    atomic_bytes(log_dir / REQUEST_FILE, canonical_bytes(request))

    def finish(outcome: str, stopped: bool, state: str, tree: list | None, outside: bool, changed: bool,
               cause: str | None, facts: Mapping[str, Any]) -> Mapping[str, Any]:
        finished_at = max(started_at, _now(runtime))
        record = {"schema": RECORD_ID, "adapter": ADAPTER_ID, "request_sha256": resolved.request_sha256,
                  "package_sha256": resolved.package_sha256, "invoker_id": request["invoker_id"],
                  "outcome": outcome, "invoker_stopped": stopped,
                  "timeout_seconds": request["budget"]["timeout_seconds"], "started_at": started_at,
                  "finished_at": finished_at, "output_tree_state": state,
                  "output_tree": tree, "attempt_changed_outside_output_root": outside,
                  "inputs_changed": changed}
        try:
            atomic_bytes(log_dir / RECORD_FILE, canonical_bytes(record))
            files = []
            for name in sorted(LOG_FILES):
                data = beneath(log_dir, log_dir / name).read_bytes()
                files.append({"path": name, "sha256": _bytes_sha(data), "bytes": len(data)})
            result = {
                "schema": RESULT_ID, "adapter": ADAPTER_ID, "independence_rule": INDEPENDENCE_ID,
                "run_id": run_id, "job_id": job_id, "attempt_id": attempt_id,
                "request_sha256": resolved.request_sha256, "package_sha256": resolved.package_sha256,
                "invocation_role": request["invocation_role"], "invoker_id": request["invoker_id"],
                "prompt_sha256": request["outer_prompt"]["sha256"],
                "composition_sha256": resolved.composition_sha256, "model": request["model"],
                "permission_fingerprint_sha256": resolved.permission_fingerprint_sha256,
                "readable_inputs_sha256": resolved.readable_inputs_sha256,
                "input_bytes": resolved.input_bytes,
                "execution_status": STATUS_BY_CAUSE[cause], "cause": cause, "outcome": outcome,
                "invoker_stopped": stopped, "started_at": started_at,
                "finished_at": finished_at,
                "output_root": request["output_root"], "log_path": request["log_path"],
                **thaw(facts), "files": files,
            }
            result["result_sha256"] = result_sha256(result)
            atomic_bytes(log_dir / RESULT_FILE, canonical_bytes(result))
        except BaseException as exc:
            raise PersonaExecutionError("the invocation result could not be persisted") from exc
        return freeze(result)

    nothing = no_facts()
    granted = _gate(request, run_id=run_id, job_id=job_id, now=started_at,
                    source_snapshot_sha256=runtime.source_snapshot_sha256,
                    registry_ceiling=runtime.registry_ceiling)
    if granted is None:
        return finish("not_invoked", True, "not_scanned", None, False, False, "PERMISSION_DENIED", nothing)

    output_root.parent.mkdir(parents=True, exist_ok=True)
    output_root.mkdir(mode=0o700)
    before = _snapshot(attempt_root, output_root)
    package = InvocationPackage(
        request=resolved.request, request_sha256=resolved.request_sha256,
        package_sha256=resolved.package_sha256, prompt=resolved.prompt, composition=resolved.composition,
        tool_actions=MappingProxyType({tool: resolved.tool_actions[tool] for tool in request["tools"]}),
        allowed_claim_classes=tuple(request["allowed_claim_classes"]),
        prohibited_claim_classes=tuple(request["prohibited_claim_classes"]),
        inputs=resolved.inputs, granted_capabilities=granted)
    outcome, stopped, interrupt = _call_invoker(runtime, package, output_root, request["budget"]["timeout_seconds"])
    if outcome != "returned":
        result = finish(outcome, stopped, "not_scanned", None, False, False, CAUSE_BY_OUTCOME[outcome], nothing)
        if interrupt is not None:
            raise interrupt
        return result
    outside = before is None or _snapshot(attempt_root, output_root) != before
    try:
        resolve_request(request, run_id=run_id, job_id=job_id, attempt_id=attempt_id,
                        attempt_root=attempt_root, registry_dir=runtime.registry_dir,
                        prompt_root=runtime.prompt_root, readable_roots=runtime.readable_roots,
                        allowed_models=runtime.allowed_models)
        changed = False
    except PersonaRequestError:
        changed = True
    state, tree, contents = scan_output_tree(output_root, request["budget"])
    if outside or changed:
        cause, facts = "OUTPUT_ESCAPE", nothing
    else:
        cause, facts = derive_output(resolved, state, tree, contents)
    return finish(outcome, stopped, state, tree, outside, changed, cause, facts)


# ---- verification: a persisted result is a cache, never an authority -----------------------------

def _read_document(path: Path, schema: str, limit: int, label: str) -> tuple[dict | None, bytes, list[str]]:
    try:
        raw = path.read_bytes()
    except OSError:
        return None, b"", [f"{label} is missing or unreadable"]
    if len(raw) > limit:
        return None, raw, [f"{label} is larger than the adapter ever writes"]
    try:
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return None, raw, [f"{label} is not UTF-8 JSON"]
    errors = validate_document(document, schema)
    if errors:
        return None, raw, [f"{label} fails its closed schema ({len(errors)} errors)"]
    if raw != canonical_bytes(document):
        return document, raw, [f"{label} is not in the adapter's canonical byte form"]
    return document, raw, []


def verify_invocation_result(attempt_root: Path, *, run_id: str, job_id: str, attempt_id: str,
                             request: Any, registry_dir: Path, prompt_root: Path,
                             readable_roots: Mapping[str, Path], allowed_models: tuple,
                             source_snapshot_sha256: str, registry_ceiling: list | None) -> list[str]:
    """Re-derives the on-disk attempt from the expected request, the registry and the bytes.

    Every argument is required. Every file that is hashed is also read and cross-checked: the
    request copy against the expected request, ``invocation.json`` against the request, the result
    and the output root, the output root against the invoker manifest and the result. Messages are
    fixed text: nothing read from the attempt is echoed.
    """
    try:
        resolved = resolve_request(
            request, run_id=run_id, job_id=job_id, attempt_id=attempt_id, attempt_root=attempt_root,
            registry_dir=registry_dir, prompt_root=prompt_root, readable_roots=readable_roots,
            allowed_models=allowed_models)
    except PersonaRequestError as exc:
        return [f"the expected request does not resolve: {exc}"]
    request = thaw(resolved.request)
    attempt_root = Path(attempt_root)
    try:
        log_dir = beneath(attempt_root, attempt_root.joinpath(*request["log_path"].split("/")))
        output_root = beneath(attempt_root, attempt_root.joinpath(*request["output_root"].split("/")))
        present = set()
        for path in sorted(log_dir.iterdir()):
            beneath(log_dir, path)
            if not path.is_file() or os.stat(path, follow_symlinks=False).st_nlink != 1:
                return ["the log directory holds something that is not one regular file"]
            present.add(path.name)
    except (OSError, ValueError):
        return ["the log directory or the output root is missing, linked or unreadable"]
    if present != {*LOG_FILES, RESULT_FILE}:
        return ["the log directory does not hold exactly request.json, invocation.json and invocation-result.json"]
    result, _, errors = _read_document(log_dir / RESULT_FILE, RESULT_SCHEMA, MAX_RESULT_BYTES, RESULT_FILE)
    record, record_raw, record_errors = _read_document(log_dir / RECORD_FILE, RECORD_SCHEMA,
                                                       MAX_RESULT_BYTES, RECORD_FILE)
    errors += record_errors
    if result is None or record is None:
        return errors
    if result["result_sha256"] != result_sha256(result):
        errors.append("result_sha256 does not match the result record")
    expected = {
        "run_id": run_id, "job_id": job_id, "attempt_id": attempt_id,
        "request_sha256": resolved.request_sha256, "package_sha256": resolved.package_sha256,
        "invocation_role": request["invocation_role"], "invoker_id": request["invoker_id"],
        "prompt_sha256": request["outer_prompt"]["sha256"],
        "composition_sha256": resolved.composition_sha256, "model": request["model"],
        "permission_fingerprint_sha256": resolved.permission_fingerprint_sha256,
        "readable_inputs_sha256": resolved.readable_inputs_sha256, "input_bytes": resolved.input_bytes,
        "output_root": request["output_root"], "log_path": request["log_path"],
    }
    for field, value in expected.items():
        if result[field] != value:
            errors.append(f"{field} is not what the expected request, registry and inputs derive")
    cause, outcome = result["cause"], result["outcome"]
    if STATUS_BY_CAUSE[cause] != result["execution_status"]:
        errors.append("execution_status is not the status of this cause")
    if result["finished_at"] < result["started_at"]:
        errors.append("finished_at is before started_at")

    # request.json and invocation.json: read, compared with what they must say, then hashed.
    request_raw = b""
    try:
        request_raw = (log_dir / REQUEST_FILE).read_bytes()
    except OSError:
        errors.append("request.json is unreadable")
    if request_raw != canonical_bytes(request):
        errors.append("request.json is not the expected request")
    listed = [{"path": name, "sha256": _bytes_sha(data), "bytes": len(data)}
              for name, data in sorted(((RECORD_FILE, record_raw), (REQUEST_FILE, request_raw)))]
    if result["files"] != listed:
        errors.append("files is not the hashed request.json and invocation.json on disk")
    derived_record = {
        "request_sha256": resolved.request_sha256, "package_sha256": resolved.package_sha256,
        "invoker_id": request["invoker_id"], "timeout_seconds": request["budget"]["timeout_seconds"],
        "outcome": outcome, "invoker_stopped": result["invoker_stopped"],
        "started_at": result["started_at"], "finished_at": result["finished_at"],
    }
    for field, value in derived_record.items():
        if record[field] != value:
            errors.append(f"invocation.json {field} disagrees with the expected request or the result")
    if outcome in ("not_invoked", "returned", "raised", "unavailable") and not record["invoker_stopped"]:
        errors.append("this outcome cannot leave the invoker running")

    gate_at = result["started_at"]
    granted = _gate(request, run_id=run_id, job_id=job_id, now=gate_at,
                    source_snapshot_sha256=source_snapshot_sha256, registry_ceiling=registry_ceiling)
    if (granted is None) != (cause == "PERMISSION_DENIED"):
        errors.append("the permission gate, re-evaluated at started_at, does not agree with the cause")

    nothing = no_facts()
    if outcome != "returned":
        if CAUSE_BY_OUTCOME[outcome] != cause:
            errors.append("the cause is not the cause of the recorded invocation outcome")
        if (record["output_tree_state"] != "not_scanned" or record["output_tree"] is not None
                or record["attempt_changed_outside_output_root"] or record["inputs_changed"]):
            errors.append("an invocation that did not return cannot record an output scan")
        if outcome == "not_invoked" and os.path.lexists(output_root):
            errors.append("an invocation that was never made cannot have an output root")
        facts = nothing
    else:
        state, tree, contents = scan_output_tree(output_root, request["budget"])
        if record["output_tree_state"] != state or record["output_tree"] != tree:
            errors.append("the output root on disk is not the tree invocation.json recorded")
        if record["attempt_changed_outside_output_root"] or record["inputs_changed"]:
            derived_cause, facts = "OUTPUT_ESCAPE", nothing
        else:
            derived_cause, facts = derive_output(resolved, state, tree, contents)
        if derived_cause != cause:
            errors.append("the cause is not what the output root, the manifest and the request derive")
    for field, value in facts.items():
        if result[field] != value:
            errors.append(f"{field} is not what the output root and the invoker manifest derive")
    return errors


def load_verified_result(attempt_root: Path, *, run_id: str, job_id: str, attempt_id: str, request: Any,
                         registry_dir: Path, prompt_root: Path, readable_roots: Mapping[str, Path],
                         allowed_models: tuple, source_snapshot_sha256: str,
                         registry_ceiling: list | None) -> Mapping[str, Any]:
    errors = verify_invocation_result(
        attempt_root, run_id=run_id, job_id=job_id, attempt_id=attempt_id, request=request,
        registry_dir=registry_dir, prompt_root=prompt_root, readable_roots=readable_roots,
        allowed_models=allowed_models, source_snapshot_sha256=source_snapshot_sha256,
        registry_ceiling=registry_ceiling)
    if errors:
        raise PersonaRequestError("invocation result rejected: " + "; ".join(errors))
    path = Path(attempt_root).joinpath(*thaw(request)["log_path"].split("/")) / RESULT_FILE
    return freeze(json.loads(path.read_text(encoding="utf-8")))


# ---- common worker-result envelope ---------------------------------------------------------------

def to_worker_envelope(attempt_root: Path, *, run_id: str, job_id: str, attempt_id: str, request: Any,
                       registry_dir: Path, prompt_root: Path, readable_roots: Mapping[str, Path],
                       allowed_models: tuple, source_snapshot_sha256: str,
                       registry_ceiling: list | None, input_fingerprint: str,
                       resume_command: str | None) -> dict[str, Any]:
    """Maps the verified on-disk result into ``worker-result-envelope/1.0``.

    It reads the result from the attempt, never from a caller's copy, takes the output contract
    from the pinned composition, lists outputs only for ``OK``, and always reports
    ``NOT_ACCEPTED``: acceptance belongs to the publication boundary, not to an adapter.
    """
    from worker_result import artifact_records, terminal_envelope, validate_worker_result
    result = load_verified_result(
        attempt_root, run_id=run_id, job_id=job_id, attempt_id=attempt_id, request=request,
        registry_dir=registry_dir, prompt_root=prompt_root, readable_roots=readable_roots,
        allowed_models=allowed_models, source_snapshot_sha256=source_snapshot_sha256,
        registry_ceiling=registry_ceiling)
    relative = [f"{result['log_path']}/{entry['path']}" for entry in result["files"]]
    relative.append(f"{result['log_path']}/{RESULT_FILE}")
    relative += [f"{result['output_root']}/{entry['path']}" for entry in result["outputs"]]
    cause = result["cause"]
    retry = result["execution_status"] != "OK" and resume_command is not None
    envelope = terminal_envelope(
        run_id=run_id, job_id=job_id, attempt_id=attempt_id, worker_kind=WORKER_KIND,
        execution_status=result["execution_status"], acceptance_status="NOT_ACCEPTED",
        input_fingerprint=input_fingerprint,
        output_contract=thaw(request)["persona"]["output_contract_id"],
        started_at=result["started_at"], finished_at=result["finished_at"], summary=SUMMARIES[cause],
        artifacts=artifact_records(Path(attempt_root), relative), cause=cause, retry_allowed=retry,
        resume_command=resume_command)
    errors = validate_worker_result(envelope)
    if errors:
        raise PersonaRequestError(f"invocation result does not map to a valid envelope ({len(errors)} errors)")
    return envelope


# ---- what an invoker must write, and a deterministic model-free invoker ---------------------------

def output_file_record(output_root: Path, relative: str) -> dict[str, Any]:
    data = Path(output_root).joinpath(*relative.split("/")).read_bytes()
    return {"path": relative, "sha256": _bytes_sha(data), "bytes": len(data)}


def write_invoker_output(package: InvocationPackage, output_root: Path, *, files: list[str],
                         claims: list[dict[str, Any]], usage: Mapping[str, int],
                         tool_calls: list[dict[str, Any]], verified_invocations: list[str],
                         injection_suspected: list[dict[str, Any]], limitations: list[str]) -> None:
    """Writes ``invoker-output.json`` last, in the canonical byte form, echoing the identities the
    package pinned. This is the whole obligation of a real invoker beyond its own files."""
    request = thaw(package.request)
    records = [output_file_record(output_root, relative) for relative in sorted(files)]
    manifest = {
        "schema": OUTPUT_ID, "request_sha256": package.request_sha256, "invoker_id": request["invoker_id"],
        "persona_id": request["persona"]["persona_id"], "persona_sha256": request["persona"]["persona_sha256"],
        "model": request["model"],
        "usage": {**usage, "output_bytes": sum(record["bytes"] for record in records)},
        "tool_calls": tool_calls, "files": records, "claims": claims,
        "verified_invocations": sorted(verified_invocations), "injection_suspected": injection_suspected,
        "limitations": limitations,
    }
    atomic_bytes(Path(output_root) / MANIFEST_FILE, canonical_bytes(manifest))


class FixtureInvoker:
    """Deterministic and model-free. It never copies prompt or evidence text: it records hashes of
    what it was handed and emits one claim of the first allowed class citing the first input."""
    invoker_id = "fixture-invoker"

    def invoke(self, package: InvocationPackage, *, output_root: Path, cancel: threading.Event) -> None:
        note = {"schema": FIXTURE_NOTE_ID, "package_sha256": package.package_sha256,
                "prompt_sha256": _bytes_sha(package.prompt),
                "inputs_read": [{"root": item.root, "path": item.path, "sha256": _bytes_sha(item.data)}
                                for item in package.inputs]}
        target = Path(output_root) / "notes" / "fixture-note.json"
        atomic_bytes(target, canonical_bytes(note))
        first = package.inputs[0]
        read = len(package.prompt) + sum(len(item.data) for item in package.inputs)
        written = len(canonical_bytes(note))
        reviewing = package.request["invocation_role"] in REVIEW_ROLES
        write_invoker_output(
            package, output_root, files=["notes/fixture-note.json"],
            claims=[{"claim_id": "fixture-claim-1", "claim_class": package.allowed_claim_classes[0],
                     "statement": "Fixture invoker read the pinned inputs and produced no analysis.",
                     "file": "notes/fixture-note.json",
                     "citations": [{"root": first.root, "path": first.path, "sha256": first.sha256,
                                    "locator": "whole file"}]}],
            usage={"input_bytes": read, "input_units": (read + 3) // 4, "output_units": (written + 3) // 4,
                   "tool_calls": 0},
            tool_calls=[],
            verified_invocations=[p["request_sha256"] for p in package.request["producers"]] if reviewing else [],
            injection_suspected=[], limitations=["No model was called; this is a protocol fixture."])
