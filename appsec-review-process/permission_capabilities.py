#!/usr/bin/env python3
"""Permission-capability model (backlog batch B11): default deny, exact, fingerprinted.

Three record types, all closed schemas under ``schemas/``:

* capability *definition* -- versioned registry record under
  ``registry/permission-capabilities/`` naming the typed parameters one kind requires;
* job *requirement* -- the exact capabilities one lifecycle job needs;
* engagement *grant* -- an ALLOW or DENY issued by a named human authority, bound to one run and
  one source snapshot, with issue and expiry timestamps.

``evaluate(requirement, grants, context)`` is a pure function returning a decision record. It
never reads the clock, the filesystem (unless asked to load the default registry), the environment
or the target. The decision is ``GRANTED`` only when there are zero reasons; every problem anywhere
in the staged inputs denies the job before work. ``fingerprint_material.sha256`` is the value an
integrator folds into the job input fingerprint.

Nothing here is wired into a worker, the launcher, the graph or the handoff builder. See
``docs/permission-capabilities.md`` for the integration follow-ups.

Redaction rule: no string taken from a requirement or grant is echoed into a decision unless it
passed a closed pattern or enum first. Reason subjects are built from indices and schema-known
property names only, and reason details are fixed text.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from schema_validate import SchemaStore, validate_document  # noqa: E402

DEFINITIONS_DIR = ROOT / "registry" / "permission-capabilities"

DEFINITION_SCHEMA = "permission-capability.schema.json"
ENTRY_SCHEMA = "permission-capability-entry.schema.json"
REQUIREMENT_SCHEMA = "permission-requirement.schema.json"
GRANT_SCHEMA = "permission-grant.schema.json"
DECISION_SCHEMA = "permission-decision.schema.json"
DECISION_UI_SCHEMA = "permission-decision-ui.schema.json"

DECISION_ID = "appsec-review/permission-decision/1.0"
DECISION_UI_ID = "appsec-review/permission-decision-ui/1.0"
FINGERPRINT_ID = "appsec-review/permission-fingerprint/1.0"

GRANTED = "GRANTED"
DENIED = "DENIED"

INVALID_RECORD = "INVALID_RECORD"
SECRET_MATERIAL = "SECRET_MATERIAL"
CONTEXT_MISMATCH = "CONTEXT_MISMATCH"
UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
WIDENED_REQUIREMENT = "WIDENED_REQUIREMENT"
WIDENED_GRANT = "WIDENED_GRANT"
TARGET_CONTROLLED = "TARGET_CONTROLLED"
MISSING_GRANT = "MISSING_GRANT"
STALE_GRANT = "STALE_GRANT"
CONFLICTING_GRANTS = "CONFLICTING_GRANTS"
EXPLICIT_DENY = "EXPLICIT_DENY"

PARAMETER_NAMES = (
    "scheme", "host", "port", "command_profile_id", "target_path", "technique", "attach_mode",
    "credential_ref", "credential_scope", "ecosystem", "mutation_mode",
)
# Origins that can never supply a capability value. Anything not explicitly trusted is rejected
# too; this tuple only exists so documentation and tests can name the hostile ones.
TARGET_CONTROLLED_ORIGINS = ("target-repository", "target-evidence", "worker-output", "unknown")
CEILING_ORIGINS = ("registry",)

ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
SHA_RE = re.compile(r"sha256:[0-9a-f]{64}")
TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
CREDENTIAL_REF_RE = re.compile(r"cred:[a-z0-9][a-z0-9-]{0,39}")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
WILDCARD_RE = re.compile(r"[*?\[\]{},|\s]")
BROAD_WORDS = {"any", "all", "everything", "0.0.0.0", "::", "0.0.0.0/0", "::/0"}

# Small deliberate duplication of validate_job_output.py's negative secret-leak patterns so this
# module does not import a private helper from a shared runtime surface (integration follow-up).
SECRET_PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("api-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("basic-auth-url", re.compile(r"://[^/\s:@]+:[^/\s@]+@")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
)
SECRET_FIELD_RE = re.compile(
    r"(?i)(api[_-]?key|token|passw(?:or)?d|passphrase|secret|private[_-]?key|credential[_-]?value)")
HIGH_ENTROPY_RE = re.compile(r"(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9+/=_-]{32,}")


class PermissionModelError(ValueError):
    """Trusted-side misuse: bad context or a broken definition registry. Never echoes values."""


class PermissionDenied(PermissionModelError):
    """Raised by require_granted()/input_fingerprint_component() for a non-GRANTED decision."""


def digest(value: Any) -> str:
    """Byte-identical to execution_state.digest (canonical JSON, sorted keys, no whitespace)."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _parse_ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ---- secret and hygiene scanning ---------------------------------------------------------------

def secret_findings(value: Any, path: str = "$") -> list[tuple[str, str]]:
    """Returns (subject, label) pairs. Subjects use indices and ``*`` for non-schema keys, so a
    secret used as a property name is not echoed either."""
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            item = value[key]
            safe_key = key if isinstance(key, str) and key in _KNOWN_KEYS else "*"
            child = f"{path}.{safe_key}"
            if not isinstance(key, str):
                found.append((child, "non-string-key"))
                continue
            if safe_key == "*":
                found.extend((child, label) for label in _string_labels(key))
            if SECRET_FIELD_RE.search(key) and item not in (None, "", [], {}):
                found.append((child, "secret-named-field"))
            if key == "credential_ref" and item is not None and not (
                    isinstance(item, str) and CREDENTIAL_REF_RE.fullmatch(item)):
                found.append((child, "credential-value-in-reference-field"))
            found.extend(secret_findings(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(secret_findings(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        found.extend((path, label) for label in _string_labels(value))
    return found


def _string_labels(text: str) -> list[str]:
    labels = [label for label, pattern in SECRET_PATTERNS if pattern.search(text)]
    if any(HIGH_ENTROPY_RE.fullmatch(token) for token in text.split() if not token.startswith("sha256:")):
        labels.append("high-entropy-token")
    return labels


_KNOWN_KEYS = set(PARAMETER_NAMES) | {
    "schema", "job_id", "capabilities", "kind", "version", "parameters", "origin", "grant_id",
    "effect", "authority", "name", "role", "issued_at", "expires_at", "binding", "run_id",
    "source_snapshot_sha256", "justification", "decision", "evaluated_at", "valid_until", "inputs",
    "requirement_sha256", "grants_sha256", "definitions_sha256", "reasons", "code", "subject",
    "capability_key", "detail", "grants_applied", "fingerprint_material", "definition_sha256",
    "sha256", "capability_kind", "summary", "fingerprint_sha256", "now", "registry_ceiling",
}


def _control_findings(value: Any, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            safe_key = key if isinstance(key, str) and key in _KNOWN_KEYS else "*"
            if isinstance(key, str) and CONTROL_RE.search(key):
                found.append(f"{path}.{safe_key}")
            found.extend(_control_findings(item, f"{path}.{safe_key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_control_findings(item, f"{path}[{index}]"))
    elif isinstance(value, str) and CONTROL_RE.search(value):
        found.append(path)
    return found


def assert_no_secret_material(record: Any) -> None:
    """Fail closed if a record about to be tracked or shown carries secret-like material."""
    found = secret_findings(record)
    if found:
        raise PermissionModelError(
            "secret-like material in an output record at " + ", ".join(sorted({s for s, _ in found})))


# ---- definitions -----------------------------------------------------------------------------

def load_definitions(directory: Path | None = None, store: SchemaStore | None = None
                     ) -> dict[tuple[str, str], dict[str, Any]]:
    """Loads and validates the versioned capability definitions, keyed by (kind, version)."""
    directory = Path(directory) if directory is not None else DEFINITIONS_DIR
    store = store or SchemaStore()
    definitions: dict[tuple[str, str], dict[str, Any]] = {}
    paths = sorted(directory.glob("*.json"))
    if not paths:
        raise PermissionModelError("permission capability registry is empty")
    for path in paths:
        record = json.loads(path.read_text(encoding="utf-8"))
        errors = validate_document(record, DEFINITION_SCHEMA, store)
        if errors:
            raise PermissionModelError(f"{path.name}: invalid capability definition ({len(errors)} errors)")
        if record["capability_id"] != path.stem or record["kind"] != record["capability_id"]:
            raise PermissionModelError(f"{path.name}: capability_id, kind and file name must agree")
        required = record["required_parameters"]
        if len(set(required)) != len(required):
            raise PermissionModelError(f"{path.name}: duplicate required parameter")
        key = (record["kind"], record["version"])
        if key in definitions:
            raise PermissionModelError(f"{path.name}: duplicate capability kind/version")
        definitions[key] = record
    return definitions


# ---- entries -----------------------------------------------------------------------------------

def _reason(code: str, subject: str, detail: str, capability_key: str | None = None,
            grant_id: str | None = None) -> dict[str, Any]:
    return {"code": code, "subject": subject, "capability_key": capability_key,
            "grant_id": grant_id, "detail": detail}


def capability_key(kind: str, version: str, parameters: dict[str, Any]) -> str:
    bound = {name: parameters[name] for name in PARAMETER_NAMES if parameters.get(name) is not None}
    return f"{kind}@{version}:" + json.dumps(bound, sort_keys=True, separators=(",", ":"))


def _widening(parameters: dict[str, Any], required: list[str], partial: bool) -> str | None:
    """Names the first way a raw parameter set is broader than one exact value, else None."""
    for name in PARAMETER_NAMES:
        value = parameters.get(name)
        if isinstance(value, (list, dict)):
            return "a parameter carries a collection instead of one exact value"
        if isinstance(value, str):
            if WILDCARD_RE.search(value) or value.lower() in BROAD_WORDS:
                return "a parameter carries a wildcard, list, range or catch-all value"
            if name == "host" and ("/" in value or ":" in value or value.startswith(".")):
                return "host is a network range, suffix or host:port expression"
            if name == "target_path" and (
                    value == "" or value.startswith(("/", "\\", "~")) or "\\" in value or ":" in value
                    or ".." in value.split("/")):
                return "target_path escapes or is not a normalized repository-relative path"
            if name == "port":
                return "port is an expression instead of one integer"
        if name == "port" and isinstance(value, int) and not isinstance(value, bool) and value <= 0:
            return "port 0 or a negative port means any port"
    if not partial:
        for name in required:
            if name in parameters and parameters[name] is None:
                return "a required bound is null, which would mean any value"
    return None


def _check_entry(entry: Any, subject: str, role: str, definitions: dict, store: SchemaStore,
                 grant_id: str | None = None, partial: bool = False
                 ) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """role is 'requirement', 'grant' or 'ceiling'. partial=True (DENY grants) lets required
    parameters be null, which makes the deny broader -- always safe."""
    widened = WIDENED_REQUIREMENT if role in ("requirement", "ceiling") else WIDENED_GRANT
    reasons: list[dict[str, Any]] = []
    if not isinstance(entry, dict):
        return [_reason(INVALID_RECORD, subject, "capability entry is not an object", grant_id=grant_id)], None
    origin = entry.get("origin")
    kind, version, parameters = entry.get("kind"), entry.get("version"), entry.get("parameters")
    definition = definitions.get((kind, version)) if isinstance(kind, str) and isinstance(version, str) else None
    if role == "ceiling":
        trusted = CEILING_ORIGINS
    elif definition is not None:
        trusted = definition["allowed_requirement_origins" if role == "requirement" else "allowed_grant_origins"]
    else:
        trusted = ("registry", "operator", "staged-run-config") if role == "requirement" else (
            "operator", "staged-run-config")
    if origin not in trusted:
        reasons.append(_reason(
            TARGET_CONTROLLED, f"{subject}.origin",
            "capability value does not originate from the operator, staged run configuration or "
            "(requirements only) the trusted registry", grant_id=grant_id))
    if definition is None:
        reasons.append(_reason(UNKNOWN_CAPABILITY, subject,
                               "capability kind/version is not in the registry", grant_id=grant_id))
        return reasons, None
    if isinstance(parameters, dict):
        problem = _widening(parameters, definition["required_parameters"], partial)
        if problem:
            reasons.append(_reason(widened, f"{subject}.parameters", problem, grant_id=grant_id))
            return reasons, None
    errors = validate_document(entry, ENTRY_SCHEMA, store)
    if errors:
        reasons.append(_reason(INVALID_RECORD, subject,
                               f"capability entry fails its closed schema ({len(errors)} errors)",
                               grant_id=grant_id))
        return reasons, None
    required = set(definition["required_parameters"])
    for name in PARAMETER_NAMES:
        value = parameters[name]
        if name not in required and value is not None:
            reasons.append(_reason(INVALID_RECORD, f"{subject}.parameters.{name}",
                                   "parameter is not defined for this capability kind", grant_id=grant_id))
        if name in required and value is None and not partial:
            reasons.append(_reason(widened, f"{subject}.parameters.{name}",
                                   "a required bound is null", grant_id=grant_id))
    if parameters["host"] is not None and re.fullmatch(r"[0-9.]+", parameters["host"]):
        reasons.append(_reason(INVALID_RECORD, f"{subject}.parameters.host",
                               "host must be a DNS name, not an address literal", grant_id=grant_id))
    port = parameters["port"]
    if port is not None and port > 65535:
        reasons.append(_reason(INVALID_RECORD, f"{subject}.parameters.port", "port is out of range",
                               grant_id=grant_id))
    if reasons:
        return reasons, None
    canonical = {"kind": kind, "version": version, "definition_sha256": _sha(definition),
                 "parameters": {name: parameters[name] for name in PARAMETER_NAMES}}
    return reasons, canonical


def _record_errors(record: Any, schema: str, subject: str, store: SchemaStore,
                   grant_id: str | None = None) -> list[dict[str, Any]]:
    """Record-level closed-schema check. Entry errors are reported by _check_entry by name."""
    errors = [e for e in validate_document(record, schema, store) if not e.startswith("$.capabilities[")]
    if not errors:
        return []
    return [_reason(INVALID_RECORD, subject, f"record fails its closed schema ({len(errors)} errors)",
                    grant_id=grant_id)]


def _covers(grant_cap: dict[str, Any], required_cap: dict[str, Any]) -> bool:
    """True when a grant is strictly broader than a requirement (an ancestor target_path)."""
    if (grant_cap["kind"], grant_cap["version"]) != (required_cap["kind"], required_cap["version"]):
        return False
    gp, rp = grant_cap["parameters"], required_cap["parameters"]
    if any(gp[name] != rp[name] for name in PARAMETER_NAMES if name != "target_path"):
        return False
    g, r = gp["target_path"], rp["target_path"]
    if g is None or r is None or g == r:
        return False
    return g == "." or r.startswith(g + "/")


def _deny_matches(deny_cap: dict[str, Any], required_cap: dict[str, Any]) -> bool:
    if (deny_cap["kind"], deny_cap["version"]) != (required_cap["kind"], required_cap["version"]):
        return False
    return all(value is None or value == required_cap["parameters"][name]
               for name, value in deny_cap["parameters"].items())


def _key(cap: dict[str, Any]) -> str:
    return capability_key(cap["kind"], cap["version"], cap["parameters"])


# ---- evaluation --------------------------------------------------------------------------------

def _validated_context(context: Any) -> dict[str, Any]:
    expected = {"run_id", "job_id", "source_snapshot_sha256", "now", "registry_ceiling"}
    if not isinstance(context, dict) or set(context) != expected:
        raise PermissionModelError(
            "context must carry exactly run_id, job_id, source_snapshot_sha256, now, registry_ceiling")
    for name, pattern in (("run_id", ID_RE), ("job_id", ID_RE),
                          ("source_snapshot_sha256", SHA_RE), ("now", TS_RE)):
        if not isinstance(context[name], str) or not pattern.fullmatch(context[name]):
            raise PermissionModelError(f"context.{name} is malformed")
    try:
        _parse_ts(context["now"])
    except ValueError:
        raise PermissionModelError("context.now is not a real UTC timestamp") from None
    if context["registry_ceiling"] is not None and not isinstance(context["registry_ceiling"], list):
        raise PermissionModelError("context.registry_ceiling must be null or a list")
    if secret_findings({k: context[k] for k in ("run_id", "job_id", "now")}):
        raise PermissionModelError("context carries secret-like material")
    return context


def fingerprint_material(decision: str, capabilities: list[dict[str, Any]]) -> dict[str, Any]:
    """Canonical, order-independent identity of the exact capability set."""
    ordered = sorted(capabilities, key=lambda c: json.dumps(c, sort_keys=True, separators=(",", ":")))
    body = {"schema": FINGERPRINT_ID, "decision": decision, "capabilities": ordered}
    return {**body, "sha256": _sha(body)}


def evaluate(requirement: Any, grants: Any, context: dict[str, Any],
             definitions: dict[tuple[str, str], dict[str, Any]] | None = None,
             store: SchemaStore | None = None) -> dict[str, Any]:
    """(requirement, grants, context) -> decision record. Pure; default deny; never raises for
    untrusted input (only for a malformed trusted context or registry)."""
    store = store or SchemaStore()
    context = _validated_context(context)
    definitions = definitions if definitions is not None else load_definitions(store=store)
    reasons: list[dict[str, Any]] = []
    if isinstance(grants, list):
        unique = {digest(g): g for g in grants}           # identical duplicates collapse
        grants = [unique[k] for k in sorted(unique)]      # evaluation never depends on input order

    untrusted = {"requirement": requirement, "grants": grants, "registry_ceiling": context["registry_ceiling"]}
    for name in sorted(untrusted):
        for subject, label in secret_findings(untrusted[name], name):
            reasons.append(_reason(SECRET_MATERIAL, subject, f"{label} material is forbidden in a permission record"))
    if reasons:
        # Stop here: nothing from a record that carries secret material is parsed, hashed or echoed.
        return _decision(context, reasons, [], [], None, None, definitions, hashed=False)
    for name in sorted(untrusted):
        for subject in _control_findings(untrusted[name], name):
            reasons.append(_reason(INVALID_RECORD, subject, "control character in a permission record"))
    if reasons:
        return _decision(context, reasons, [], [], None, None, definitions, hashed=False)

    # -- requirement
    required: dict[str, dict[str, Any]] = {}
    reasons.extend(_record_errors(requirement, REQUIREMENT_SCHEMA, "requirement", store))
    if isinstance(requirement, dict):
        if requirement.get("job_id") != context["job_id"]:
            reasons.append(_reason(CONTEXT_MISMATCH, "requirement.job_id",
                                   "requirement is declared for a different job"))
        entries = requirement.get("capabilities")
        for index, entry in enumerate(entries if isinstance(entries, list) else []):
            subject = f"requirement.capabilities[{index}]"
            found, cap = _check_entry(entry, subject, "requirement", definitions, store)
            reasons.extend(found)
            if cap is not None:
                if _key(cap) in required:
                    reasons.append(_reason(INVALID_RECORD, subject, "duplicate required capability", _key(cap)))
                required[_key(cap)] = cap

    # -- registry ceiling (what the trusted job composition allows a requirement to ask for)
    if context["registry_ceiling"] is not None:
        ceiling: set[str] = set()
        for index, entry in enumerate(context["registry_ceiling"]):
            found, cap = _check_entry(entry, f"registry_ceiling[{index}]", "ceiling", definitions, store)
            reasons.extend(found)
            if cap is not None:
                ceiling.add(_key(cap))
        for key in sorted(set(required) - ceiling):
            reasons.append(_reason(WIDENED_REQUIREMENT, "requirement.capabilities",
                                   "requirement exceeds the registry ceiling for this job", key))

    # -- grants
    allow: dict[str, list[dict[str, Any]]] = {}
    deny: dict[str, list[dict[str, Any]]] = {}
    stale: dict[str, set[str]] = {}
    if not isinstance(grants, list):
        reasons.append(_reason(INVALID_RECORD, "grants", "grants must be a list"))
        grants = []
    ordered = grants
    seen_ids: set[str] = set()
    now = _parse_ts(context["now"])
    for index, grant in enumerate(ordered):
        raw_id = grant.get("grant_id") if isinstance(grant, dict) else None
        grant_id = raw_id if isinstance(raw_id, str) and ID_RE.fullmatch(raw_id) else None
        subject = f"grants[{grant_id}]" if grant_id else "grants[unidentified]"
        found = _record_errors(grant, GRANT_SCHEMA, subject, store, grant_id)
        if grant_id is not None:
            if grant_id in seen_ids:
                found.append(_reason(CONFLICTING_GRANTS, subject,
                                     "two different grants share one grant_id", grant_id=grant_id))
            seen_ids.add(grant_id)
        entries = grant.get("capabilities") if isinstance(grant, dict) else None
        effect = grant.get("effect") if isinstance(grant, dict) else None
        caps: list[dict[str, Any]] = []
        for position, entry in enumerate(entries if isinstance(entries, list) else []):
            entry_found, cap = _check_entry(entry, f"{subject}.capabilities[{position}]", "grant",
                                            definitions, store, grant_id, partial=effect == "DENY")
            found.extend(entry_found)
            if cap is not None:
                caps.append(cap)
        if not found:
            try:
                issued, expires = _parse_ts(grant["issued_at"]), _parse_ts(grant["expires_at"])
            except ValueError:
                found.append(_reason(INVALID_RECORD, subject, "grant timestamp is not a real UTC time",
                                     grant_id=grant_id))
            else:
                if expires <= issued:
                    found.append(_reason(INVALID_RECORD, subject, "grant expires at or before it is issued",
                                         grant_id=grant_id))
        reasons.extend(found)
        if found:
            continue
        binding = grant["binding"]
        if binding["job_id"] is not None and binding["job_id"] != context["job_id"]:
            continue  # a current grant for another job in the same run is simply not applicable
        staleness = []
        if binding["run_id"] != context["run_id"]:
            staleness.append("bound to a different run")
        if binding["source_snapshot_sha256"] != context["source_snapshot_sha256"]:
            staleness.append("bound to a different source snapshot")
        if issued > now:
            staleness.append("not yet valid")
        if expires <= now:
            staleness.append("expired")
        for cap in caps:
            if effect == "DENY":
                if not staleness:
                    for key, needed in required.items():
                        if _deny_matches(cap, needed):
                            deny.setdefault(key, []).append(grant)
                continue
            key = _key(cap)
            if key in required:
                if staleness:
                    stale.setdefault(key, set()).update(staleness)
                else:
                    allow.setdefault(key, []).append(grant)
            elif staleness:
                continue
            elif any(_covers(cap, needed) for needed in required.values()):
                reasons.append(_reason(WIDENED_GRANT, subject,
                                       "grant is broader than the required capability", key, grant_id))
            elif binding["job_id"] == context["job_id"]:
                reasons.append(_reason(WIDENED_GRANT, subject,
                                       "job-bound grant allows a capability the job does not require",
                                       key, grant_id))

    # -- per-capability resolution: explicit deny wins, then allow, then stale, then missing
    applied: dict[str, str] = {}
    for key in sorted(required):
        subject = "requirement.capabilities"
        if key in deny:
            deny_ids = sorted({g["grant_id"] for g in deny[key]})
            if key in allow:
                reasons.append(_reason(CONFLICTING_GRANTS, subject,
                                       "an ALLOW and a DENY disagree; the explicit deny wins", key, deny_ids[0]))
            for grant_id in deny_ids:
                reasons.append(_reason(EXPLICIT_DENY, subject, "explicitly denied by grant", key, grant_id))
        elif key in allow:
            for grant in allow[key]:
                applied[grant["grant_id"]] = grant["expires_at"]
        elif key in stale:
            reasons.append(_reason(STALE_GRANT, subject,
                                   "only stale grants match: " + "; ".join(sorted(stale[key])), key))
        else:
            reasons.append(_reason(MISSING_GRANT, subject,
                                   "no grant allows this capability (default deny)", key))

    return _decision(context, reasons, list(required.values()),
                     [{"grant_id": g, "expires_at": e} for g, e in sorted(applied.items())],
                     requirement, ordered, definitions, hashed=True)


def _decision(context, reasons, capabilities, applied, requirement, grants, definitions, hashed):
    unique = {json.dumps(r, sort_keys=True): r for r in reasons}
    reasons = [unique[k] for k in sorted(unique)]
    decision = DENIED if reasons else GRANTED
    if decision == DENIED:
        capabilities, applied = [], []
    material = fingerprint_material(decision, capabilities)
    record = {
        "schema": DECISION_ID,
        "decision": decision,
        "run_id": context["run_id"],
        "job_id": context["job_id"],
        "source_snapshot_sha256": context["source_snapshot_sha256"],
        "evaluated_at": context["now"],
        "valid_until": min((a["expires_at"] for a in applied), default=None),
        "inputs": {
            "requirement_sha256": _sha(requirement) if hashed else None,
            "grants_sha256": _sha(sorted(digest(g) for g in grants)) if hashed else None,
            "definitions_sha256": _sha(sorted(digest(d) for d in definitions.values())),
        },
        "reasons": reasons,
        "capabilities": material["capabilities"],
        "grants_applied": applied,
        "fingerprint_material": material,
    }
    assert_no_secret_material(record)
    return record


# ---- consumers ---------------------------------------------------------------------------------

def validate_decision(decision: Any, store: SchemaStore | None = None) -> list[str]:
    """Schema plus the cross-field rules a consumer must not take on trust."""
    errors = validate_document(decision, DECISION_SCHEMA, store or SchemaStore())
    if errors:
        return errors
    material = decision["fingerprint_material"]
    if material != fingerprint_material(decision["decision"], decision["capabilities"]):
        errors.append("fingerprint_material does not match the decision's capability set")
    if decision["decision"] == GRANTED and decision["reasons"]:
        errors.append("GRANTED decision carries reasons")
    if decision["decision"] == DENIED and (not decision["reasons"] or decision["capabilities"]):
        errors.append("DENIED decision must carry reasons and no capabilities")
    errors.extend(f"{subject}: {label}" for subject, label in secret_findings(decision))
    return errors


def require_granted(decision: dict[str, Any], *, run_id: str, job_id: str,
                    source_snapshot_sha256: str, now: str) -> list[dict[str, Any]]:
    """Pre-work gate for an integrator: returns the exact capability set or raises."""
    errors = validate_decision(decision)
    if errors:
        raise PermissionDenied("permission decision is invalid")
    if decision["decision"] != GRANTED:
        raise PermissionDenied("permission denied: " + ", ".join(sorted({r["code"] for r in decision["reasons"]})))
    if (decision["run_id"], decision["job_id"], decision["source_snapshot_sha256"]) != (
            run_id, job_id, source_snapshot_sha256):
        raise PermissionDenied("permission decision is bound to a different run, job or source snapshot")
    if decision["valid_until"] is not None and _parse_ts(decision["valid_until"]) <= _parse_ts(now):
        raise PermissionDenied("permission decision has expired; re-evaluate against current grants")
    return decision["capabilities"]


def input_fingerprint_component(decision: dict[str, Any]) -> str:
    """The exact string to add to a job's input-fingerprint identity. GRANTED decisions only."""
    if validate_decision(decision) or decision["decision"] != GRANTED:
        raise PermissionDenied("only a valid GRANTED decision contributes to an input fingerprint")
    return decision["fingerprint_material"]["sha256"]


def _summary(cap: dict[str, Any]) -> str:
    p = cap["parameters"]
    if cap["kind"] == "credential-use":
        return f"one operator credential reference, scope {p['credential_scope']}"
    if cap["kind"] == "fixed-network-destination":
        return f"{p['scheme']}://{p['host']}:{p['port']}"
    if cap["kind"] == "package-restore":
        return f"{p['ecosystem']} from {p['scheme']}://{p['host']}:{p['port']}"
    return ", ".join(f"{name}={p[name]}" for name in PARAMETER_NAMES if p[name] is not None)


def ui_safe_projection(decision: dict[str, Any]) -> dict[str, Any]:
    """Codes, kinds and non-sensitive parameters only. No credential reference ids, no free text."""
    errors = validate_decision(decision)
    if errors:
        raise PermissionModelError("refusing to project an invalid decision record")
    kinds = {_key(c): c["kind"] for c in decision["capabilities"]}
    reasons = []
    for reason in decision["reasons"]:
        key = reason["capability_key"]
        kind = kinds.get(key) or (key.split("@", 1)[0] if key else None)
        reasons.append({"code": reason["code"], "capability_kind": kind, "grant_id": reason["grant_id"]})
    unique = {json.dumps(r, sort_keys=True): r for r in reasons}
    projection = {
        "schema": DECISION_UI_ID,
        "decision": decision["decision"],
        "run_id": decision["run_id"],
        "job_id": decision["job_id"],
        "evaluated_at": decision["evaluated_at"],
        "valid_until": decision["valid_until"],
        "reasons": [unique[k] for k in sorted(unique)],
        "capabilities": [{"kind": c["kind"], "version": c["version"], "summary": _summary(c)}
                         for c in decision["capabilities"]],
        "fingerprint_sha256": decision["fingerprint_material"]["sha256"],
    }
    assert_no_secret_material(projection)
    return projection


# ---- CLI (read-only) ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate-registry")
    ev = sub.add_parser("evaluate")
    ev.add_argument("--requirement", required=True, type=Path)
    ev.add_argument("--grants", required=True, type=Path)
    ev.add_argument("--context", required=True, type=Path)
    ev.add_argument("--ui-safe", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "validate-registry":
        definitions = load_definitions()
        print(json.dumps({"permission_capability_definitions": len(definitions),
                          "kinds": sorted(k for k, _ in definitions)}, indent=2))
        return 0
    read = lambda p: json.loads(p.read_text(encoding="utf-8"))  # noqa: E731
    decision = evaluate(read(args.requirement), read(args.grants), read(args.context))
    print(json.dumps(ui_safe_projection(decision) if args.ui_safe else decision, indent=2, sort_keys=True))
    return 0 if decision["decision"] == GRANTED else 2


if __name__ == "__main__":
    raise SystemExit(main())
