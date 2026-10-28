"""``poc_candidates`` of the accepted inference-review handoff (review-judge-and-poc.md, section 4).

The producer is the judge work of ``job_inference_security_review``; this module only reads what that
section documents, strictly. A handoff without the field is an older run: the job completes with the
named gap ``no_poc_candidates``. A present but malformed field is an integrity failure, because the
handoff is hash-bound and an entry that does not match the documented shape cannot be repaired here.

Each entry carries ``claim_id``, ``package_id``, ``state``, ``judge_verdict``, the ``poc_basis``
(the bounded copy and its hash, which is the SHA-256 of the copy's canonical JSON), a reference to the
claim's finding package and the evidence the claim rests on. Nothing else about the claim is copied.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import re
from typing import Any

from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json

from .statuses import CLAIM_STATES, JUDGE_VERDICTS

FIELD = "poc_candidates"
MAX_CANDIDATES = 10_000
CLAIM_ID = re.compile(r"^claim-[0-9a-f]{64}$")
FINDING_ID = re.compile(r"^finding-[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_ID = re.compile(r"^[a-z][a-z0-9_]*-[0-9a-f]{64}$")
EVIDENCE_REF = re.compile(r"^(?:asr:[a-z][a-z0-9_]*:[0-9a-f]{64}|evrel-[0-9a-f]{64})$")
ENTITY_ID = re.compile(r"^asr:[a-z][a-z0-9_]*:[0-9a-f]{64}$")
TEXT_LIMIT = 240
LIST_LIMITS = {"entry": 8, "path": 16, "trigger": 8, "preconditions": 8, "unknowns": 8}
BASIS_KEYS = frozenset({"entry", "path", "trigger", "input_format", "preconditions", "expected_observation",
                        "unknowns"})
TRIGGER_KEYS = frozenset({"field", "where", "constraint", "why"})
ENTRY_KEYS = frozenset({"claim_id", "package_id", "state", "judge_verdict", "poc_basis", "finding_package",
                        "evidence_refs"})


@dataclass(frozen=True, slots=True)
class PocBasis:
    """The bounded brief red developed (review-protocol-v2.md, section 6.6)."""

    entry: tuple[str, ...]
    path: tuple[str, ...]
    trigger: tuple[Mapping[str, str], ...]
    input_format: str
    preconditions: tuple[str, ...]
    expected_observation: str
    unknowns: tuple[str, ...]
    sha256: str

    def record(self) -> dict[str, Any]:
        return {"entry": list(self.entry), "path": list(self.path), "trigger": [dict(item) for item in self.trigger],
                "input_format": self.input_format, "preconditions": list(self.preconditions),
                "expected_observation": self.expected_observation, "unknowns": list(self.unknowns)}

    @property
    def usable(self) -> bool:
        """A basis needs an entry, a call path and a trigger; without them there is nothing to demonstrate."""
        return bool(self.entry and self.path and self.trigger)


@dataclass(frozen=True, slots=True)
class PocCandidate:
    claim_id: str
    package_id: str
    state: str
    judge_verdict: str
    poc_basis: PocBasis
    finding_package_id: str
    finding_package_sha256: str
    evidence_refs: tuple[str, ...]


def _fail(index: int, message: str) -> IntegrityError:
    return IntegrityError(f"poc_candidates[{index}] {message}")


def _text(value: Any, index: int, name: str, *, empty: bool = True) -> str:
    if not isinstance(value, str) or len(value) > TEXT_LIMIT or (not empty and not value.strip()):
        raise _fail(index, f"{name} must be text of at most {TEXT_LIMIT} characters")
    return value


def _identities(value: Any, index: int, name: str, limit: int) -> tuple[str, ...]:
    if (not isinstance(value, list) or len(value) > limit
            or any(not isinstance(item, str) or not ENTITY_ID.fullmatch(item) for item in value)
            or len(set(value)) != len(value)):
        raise _fail(index, f"{name} must be at most {limit} unique entity identities")
    return tuple(value)


def parse_basis(value: Any, index: int) -> PocBasis:
    if not isinstance(value, Mapping) or set(value) != {"sha256", "brief"}:
        raise _fail(index, "poc_basis must hold exactly sha256 and brief")
    body = value["brief"]
    if not isinstance(body, Mapping) or set(body) != BASIS_KEYS:
        raise _fail(index, f"poc_basis.brief must define exactly {sorted(BASIS_KEYS)}")
    if not isinstance(value["sha256"], str) or not SHA256.match(value["sha256"]):
        raise _fail(index, "poc_basis.sha256 must be a SHA-256")
    if hashlib.sha256(canonical_json(body)).hexdigest() != value["sha256"]:
        raise _fail(index, "poc_basis.sha256 is not the SHA-256 of the canonical poc_basis.brief")
    triggers = body["trigger"]
    if not isinstance(triggers, list) or len(triggers) > LIST_LIMITS["trigger"]:
        raise _fail(index, "poc_basis.trigger must be at most 8 rows")
    rows = []
    for row in triggers:
        if not isinstance(row, Mapping) or set(row) != TRIGGER_KEYS:
            raise _fail(index, f"each trigger row must define exactly {sorted(TRIGGER_KEYS)}")
        rows.append({key: _text(row[key], index, f"trigger.{key}") for key in sorted(TRIGGER_KEYS)})
    texts = {}
    for key in ("preconditions", "unknowns"):
        items = body[key]
        if not isinstance(items, list) or len(items) > LIST_LIMITS[key]:
            raise _fail(index, f"poc_basis.{key} must be at most {LIST_LIMITS[key]} items")
        texts[key] = tuple(_text(item, index, key) for item in items)
    return PocBasis(_identities(body["entry"], index, "entry", LIST_LIMITS["entry"]),
                    _identities(body["path"], index, "path", LIST_LIMITS["path"]), tuple(rows),
                    _text(body["input_format"], index, "input_format"), texts["preconditions"],
                    _text(body["expected_observation"], index, "expected_observation"), texts["unknowns"],
                    value["sha256"])


def parse_candidates(value: Any) -> tuple[PocCandidate, ...]:
    """Validate the ``poc_candidates`` array; any deviation from the documented shape is an integrity error."""
    if not isinstance(value, list) or len(value) > MAX_CANDIDATES:
        raise IntegrityError("poc_candidates must be an array")
    parsed: list[PocCandidate] = []
    for index, entry in enumerate(value):
        if not isinstance(entry, Mapping) or set(entry) != ENTRY_KEYS:
            raise _fail(index, f"must define exactly {sorted(ENTRY_KEYS)}")
        if not isinstance(entry["claim_id"], str) or not CLAIM_ID.match(entry["claim_id"]):
            raise _fail(index, "claim_id is malformed")
        if not isinstance(entry["package_id"], str) or not PACKAGE_ID.match(entry["package_id"]):
            raise _fail(index, "package_id is malformed")
        if entry["state"] not in CLAIM_STATES:
            raise _fail(index, f"state must be one of {list(CLAIM_STATES)}")
        if entry["judge_verdict"] not in JUDGE_VERDICTS:
            raise _fail(index, f"judge_verdict must be one of {list(JUDGE_VERDICTS)}")
        package = entry["finding_package"]
        if (not isinstance(package, Mapping) or set(package) != {"finding_package_id", "sha256"}
                or not isinstance(package["finding_package_id"], str) or not FINDING_ID.match(package["finding_package_id"])
                or not isinstance(package["sha256"], str) or not SHA256.match(package["sha256"])):
            raise _fail(index, "finding_package must be {finding_package_id, sha256}")
        refs = entry["evidence_refs"]
        if (not isinstance(refs, list) or len(refs) > 256 or len(set(refs)) != len(refs)
                or any(not isinstance(item, str) or not EVIDENCE_REF.match(item) for item in refs)):
            raise _fail(index, "evidence_refs must be at most 256 unique evidence identities")
        parsed.append(PocCandidate(entry["claim_id"], entry["package_id"], entry["state"], entry["judge_verdict"],
                                   parse_basis(entry["poc_basis"], index), package["finding_package_id"],
                                   package["sha256"], tuple(refs)))
    if len({item.claim_id for item in parsed}) != len(parsed):
        raise IntegrityError("poc_candidates names a claim twice")
    return tuple(parsed)


def read_candidates(review_handoff: Mapping[str, Any]) -> tuple[PocCandidate, ...]:
    """Read the required candidates field of a verified review handoff."""
    if FIELD not in review_handoff:
        raise IntegrityError("the review handoff is missing required poc_candidates")
    return parse_candidates(review_handoff[FIELD])


def check_against_review(candidates: Sequence[PocCandidate], findings: Mapping[str, Mapping[str, Any]]
                         ) -> list[str]:
    """Disagreements between the candidates and the verified finding packages (claim, state, digest)."""
    errors = []
    for item in candidates:
        package = findings.get(item.finding_package_id)
        if package is None:
            errors.append(f"{item.claim_id}: finding package {item.finding_package_id} is not in the review handoff")
        elif package["sha256"] != item.finding_package_sha256:
            errors.append(f"{item.claim_id}: finding package digest differs from the review handoff")
        elif package["claim_id"] != item.claim_id or package["state"] != item.state:
            errors.append(f"{item.claim_id}: claim or state differs from its finding package")
    return errors
