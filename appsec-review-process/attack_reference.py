#!/usr/bin/env python3
"""Derived ATT&CK / CAPEC reference table and tag validator (brief O2, ADR-0026).

``derive(sources)`` turns the pinned MITRE STIX bundles that ``mitre_feed.py`` publishes into one
deterministic ``reference.json`` (sorted, no timestamps, no prose from a model): ATT&CK tactics,
techniques and sub-techniques (id, name, tactics, platforms, deprecated/revoked flag, url) and CAPEC
patterns (id, name, related CWE ids, related ATT&CK ids where MITRE gives them, url).

``Reference.validate_technique(id, tactic=None)`` and ``Reference.validate_capec(id)`` return one of
``OK`` / ``UNKNOWN_ID`` / ``DEPRECATED`` / ``TACTIC_MISMATCH`` against the resolved snapshot, in the
manner of ``cwe_catalog.py``.

ATT&CK and CAPEC ids are LABELS, never evidence: a tag never promotes, upgrades or supports a
finding. ``screen()`` is the one gate the claim path and lane 14 use. A missing, stale or invalid
snapshot is a recorded gap (``MITRE_REFERENCE_MISSING`` / ``MITRE_REFERENCE_STALE`` /
``MITRE_REFERENCE_INVALID``) that withholds every tag; it never lets an unvalidated id through and
never fails the run.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable

SCHEMA = "appsec-review/mitre-reference/1"
OK, UNKNOWN_ID, DEPRECATED, TACTIC_MISMATCH = "OK", "UNKNOWN_ID", "DEPRECATED", "TACTIC_MISMATCH"
STATUSES = (OK, UNKNOWN_ID, DEPRECATED, TACTIC_MISMATCH)
GAP_MISSING, GAP_STALE, GAP_INVALID = "MITRE_REFERENCE_MISSING", "MITRE_REFERENCE_STALE", "MITRE_REFERENCE_INVALID"
REFS_MAX = 8                                    # tags per claim or chain link; more are dropped with a gap
TECHNIQUE_ID = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")
TACTIC_ID = re.compile(r"TA[0-9]{4}")
CAPEC_ID = re.compile(r"CAPEC-[1-9][0-9]{0,4}")
CWE_ID = re.compile(r"CWE-[1-9][0-9]{0,4}")
_ATTACK_URL = re.compile(r"https://attack\.mitre\.org/[A-Za-z0-9/._-]{1,120}")
_CAPEC_URL = re.compile(r"https?://capec\.mitre\.org/[A-Za-z0-9/._-]{1,120}")
NAME_CHARS = 200
# Lane-14 chain stage -> ATT&CK Enterprise tactic shortnames a link's technique may carry (ADR-0026).
# Deliberately permissive: a mismatch only drops the label with a recorded gap.
CHAIN_STAGE_TACTICS = {
    "entry": ("initial-access", "reconnaissance", "resource-development"),
    "execution": ("execution", "stealth", "defense-impairment"),
    "privilege_gain": ("privilege-escalation", "credential-access"),
    "persistence": ("persistence", "stealth", "defense-impairment"),
    "lateral_movement": ("lateral-movement", "discovery"),
    "impact": ("impact", "exfiltration", "collection", "credential-access", "command-and-control"),
}


class MitreReferenceError(ValueError):
    """The STIX input or a reference.json does not have the expected shape."""


def _name(value: Any) -> str:
    text = " ".join(str(value or "").split())
    return text[:NAME_CHARS]


def _external(obj: dict[str, Any], source: str) -> dict[str, Any] | None:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == source and isinstance(ref.get("external_id"), str):
            return ref
    return None


def _url(ref: dict[str, Any] | None, pattern: re.Pattern[str]) -> str | None:
    url = (ref or {}).get("url")
    return url if isinstance(url, str) and pattern.fullmatch(url) else None


def _bundle(data: bytes | dict[str, Any]) -> list[dict[str, Any]]:
    bundle = json.loads(data.decode("utf-8-sig")) if isinstance(data, (bytes, bytearray)) else data
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise MitreReferenceError("not a STIX bundle")
    return [obj for obj in bundle["objects"] if isinstance(obj, dict)]


def summarize_attack(data: bytes | dict[str, Any]) -> dict[str, Any]:
    """Parse check for one ATT&CK domain bundle: its collection version and technique count."""
    objects = _bundle(data)
    collections = [obj for obj in objects if obj.get("type") == "x-mitre-collection"]
    if len(collections) != 1 or not isinstance(collections[0].get("x_mitre_version"), str):
        raise MitreReferenceError("ATT&CK bundle does not carry exactly one versioned x-mitre-collection")
    techniques = [obj for obj in objects if obj.get("type") == "attack-pattern"
                  and _external(obj, "mitre-attack") and TECHNIQUE_ID.fullmatch(_external(obj, "mitre-attack")["external_id"])]
    tactics = [obj for obj in objects if obj.get("type") == "x-mitre-tactic"]
    if not techniques or not tactics:
        raise MitreReferenceError("ATT&CK bundle has no techniques or no tactics")
    return {"upstream_version": collections[0]["x_mitre_version"], "record_count": len(techniques),
            "tactic_count": len(tactics), "marking_statements": _markings(objects)}


def summarize_capec(data: bytes | dict[str, Any]) -> dict[str, Any]:
    objects = _bundle(data)
    patterns = [obj for obj in objects if obj.get("type") == "attack-pattern" and _external(obj, "capec")]
    versions = sorted({str(obj.get("x_capec_version")) for obj in patterns if obj.get("x_capec_version")})
    if not patterns or len(versions) != 1:
        raise MitreReferenceError("CAPEC bundle has no patterns or no single x_capec_version")
    return {"upstream_version": versions[0], "record_count": len(patterns), "marking_statements": _markings(objects)}


def _markings(objects: list[dict[str, Any]]) -> list[str]:
    statements = {_name((obj.get("definition") or {}).get("statement"))[:400]
                  for obj in objects if obj.get("type") == "marking-definition"
                  and isinstance(obj.get("definition"), dict)}
    return sorted(statement for statement in statements if statement)


def _attack(domain: str, objects: list[dict[str, Any]], tactics: dict[str, dict[str, Any]],
            techniques: dict[str, dict[str, Any]]) -> None:
    for obj in objects:
        ref = _external(obj, "mitre-attack")
        if obj.get("type") == "x-mitre-tactic" and ref and TACTIC_ID.fullmatch(ref["external_id"]):
            row = tactics.setdefault(ref["external_id"], {
                "id": ref["external_id"], "shortname": _name(obj.get("x_mitre_shortname")), "name": _name(obj.get("name")),
                "url": _url(ref, _ATTACK_URL), "domains": []})
            row["domains"] = sorted(set(row["domains"]) | {domain})
        elif obj.get("type") == "attack-pattern" and ref and TECHNIQUE_ID.fullmatch(ref["external_id"]):
            identifier = ref["external_id"]
            phases = sorted({_name(phase.get("phase_name")) for phase in obj.get("kill_chain_phases") or []
                             if isinstance(phase, dict) and str(phase.get("kill_chain_name", "")).startswith("mitre-")})
            platforms = sorted({_name(item) for item in obj.get("x_mitre_platforms") or [] if isinstance(item, str)})
            row = {"id": identifier, "name": _name(obj.get("name")), "tactics": phases, "platforms": platforms,
                   "deprecated": bool(obj.get("x_mitre_deprecated")), "revoked": bool(obj.get("revoked")),
                   "subtechnique": "." in identifier, "parent": identifier.split(".")[0] if "." in identifier else None,
                   "url": _url(ref, _ATTACK_URL), "domains": [domain]}
            prior = techniques.get(identifier)
            if prior is not None:                   # same id in two domains: union, stay conservative
                row["tactics"] = sorted(set(prior["tactics"]) | set(row["tactics"]))
                row["platforms"] = sorted(set(prior["platforms"]) | set(row["platforms"]))
                row["domains"] = sorted(set(prior["domains"]) | {domain})
                row["deprecated"] = prior["deprecated"] or row["deprecated"]
                row["revoked"] = prior["revoked"] or row["revoked"]
            techniques[identifier] = row


def _capec(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = {}
    for obj in objects:
        ref = _external(obj, "capec")
        if obj.get("type") != "attack-pattern" or not ref or not CAPEC_ID.fullmatch(ref["external_id"]):
            continue
        refs = [item for item in obj.get("external_references") or [] if isinstance(item, dict)]
        cwe = sorted({item["external_id"] for item in refs if item.get("source_name") == "cwe"
                      and isinstance(item.get("external_id"), str) and CWE_ID.fullmatch(item["external_id"])},
                     key=lambda value: int(value[4:]))
        attack = sorted({item["external_id"] for item in refs if item.get("source_name") == "ATTACK"
                         and isinstance(item.get("external_id"), str) and TECHNIQUE_ID.fullmatch(item["external_id"])})
        status = _name(obj.get("x_capec_status")) or None
        rows[ref["external_id"]] = {"id": ref["external_id"], "name": _name(obj.get("name")), "status": status,
                                    "deprecated": bool(obj.get("revoked")) or status in ("Deprecated", "Obsolete"),
                                    "related_cwe": cwe, "related_attack": attack, "url": _url(ref, _CAPEC_URL)}
    return [rows[key] for key in sorted(rows, key=lambda value: int(value.split("-")[1]))]


def derive(sources: dict[str, tuple[str, bytes | dict[str, Any]]]) -> dict[str, Any]:
    """``sources``: name -> (kind, bundle bytes); kind is ``attack`` or ``capec``. Deterministic."""
    tactics: dict[str, dict[str, Any]] = {}
    techniques: dict[str, dict[str, Any]] = {}
    domains: dict[str, str] = {}
    capec = None
    for name in sorted(sources):
        kind, data = sources[name]
        objects = _bundle(data)
        if kind == "attack":
            domains[name] = summarize_attack({"type": "bundle", "objects": objects})["upstream_version"]
            _attack(name, objects, tactics, techniques)
        elif kind == "capec":
            capec = {"version": summarize_capec({"type": "bundle", "objects": objects})["upstream_version"],
                     "patterns": _capec(objects)}
        else:
            raise MitreReferenceError(f"unknown MITRE source kind {kind!r}")
    return {"schema": SCHEMA,
            "attack": ({"domains": dict(sorted(domains.items())),
                        "tactics": [tactics[key] for key in sorted(tactics)],
                        "techniques": [techniques[key] for key in sorted(techniques)]} if domains else None),
            "capec": capec,
            "limitations": ["ATT&CK and CAPEC ids are labels for a claim; they are never evidence and never "
                            "promote or upgrade a finding."]}


def reference_bytes(reference: dict[str, Any]) -> bytes:
    return (json.dumps(reference, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


# ---- validator (cwe_catalog pattern) ----------------------------------------------------------------

def _canonical(value: Any, pattern: re.Pattern[str], prefix: str = "") -> str | None:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        return None
    text = str(value).strip().upper()
    if prefix and text.isdigit():
        text = prefix + text
    return text if pattern.fullmatch(text) else None


class Reference:
    """Validator over one verified ``reference.json`` (``mitre_feed.resolve`` supplies the identity)."""

    def __init__(self, reference: dict[str, Any], identity: dict[str, Any] | None = None):
        if not isinstance(reference, dict) or reference.get("schema") != SCHEMA:
            raise MitreReferenceError("reference.json schema is not recognised")
        attack, capec = reference.get("attack"), reference.get("capec")
        self.identity = identity or {}
        self.has_attack, self.has_capec = attack is not None, capec is not None
        self.techniques = {row["id"]: row for row in (attack or {}).get("techniques", [])}
        self.tactics = {row["id"]: row for row in (attack or {}).get("tactics", [])}
        self.patterns = {row["id"]: row for row in (capec or {}).get("patterns", [])}
        self.attack_versions = dict((attack or {}).get("domains") or {})
        self.capec_version = (capec or {}).get("version")

    def _tactic_names(self, tactic: Any) -> set[str]:
        text = str(tactic).strip()
        if TACTIC_ID.fullmatch(text.upper()):
            row = self.tactics.get(text.upper())
            return {row["shortname"]} if row else set()
        slug = "-".join(text.lower().replace("_", " ").split())
        return {row["shortname"] for row in self.tactics.values()
                if slug in (row["shortname"], "-".join(row["name"].lower().split()))}

    def validate_technique(self, identifier: Any, tactic: Any = None) -> str:
        canonical = _canonical(identifier, TECHNIQUE_ID)
        row = self.techniques.get(canonical) if canonical else None
        if row is None:
            return UNKNOWN_ID
        if row["deprecated"] or row["revoked"]:
            return DEPRECATED
        if tactic is not None and not (self._tactic_names(tactic) & set(row["tactics"])):
            return TACTIC_MISMATCH
        return OK

    def validate_capec(self, identifier: Any) -> str:
        canonical = _canonical(identifier, CAPEC_ID, "CAPEC-")
        row = self.patterns.get(canonical) if canonical else None
        if row is None:
            return UNKNOWN_ID
        return DEPRECATED if row["deprecated"] else OK

    def technique(self, identifier: Any) -> dict[str, Any] | None:
        return self.techniques.get(_canonical(identifier, TECHNIQUE_ID) or "")

    def capec(self, identifier: Any) -> dict[str, Any] | None:
        return self.patterns.get(_canonical(identifier, CAPEC_ID, "CAPEC-") or "")


# ---- the one gate: resolve (age ceiling), validate, withhold on a gap ---------------------------------

_LOADED: dict[str, Reference] = {}


def load(root: Any = None, *, now: datetime | None = None,
         max_age_seconds: int | None = None) -> tuple[Reference | None, dict[str, Any] | None]:
    """(Reference, None) for a verified, in-ceiling snapshot, else (None, gap). Never raises for
    missing, stale or invalid data: those are the recorded gaps that withhold tags."""
    import mitre_feed
    from dependency_snapshot_registry import SnapshotBlocked, SnapshotInvalid, SnapshotStale
    now = now or datetime.now(timezone.utc)
    try:
        identity = mitre_feed.resolve(root, now=now, max_age_seconds=max_age_seconds)
    except SnapshotBlocked as exc:
        return None, {"code": GAP_MISSING, "detail": str(exc)[:300]}
    except SnapshotStale as exc:
        return None, {"code": GAP_STALE, "detail": str(exc)[:300]}
    except (SnapshotInvalid, OSError, ValueError) as exc:
        return None, {"code": GAP_INVALID, "detail": f"{type(exc).__name__}: {exc}"[:300]}
    key = identity["reference_sha256"]
    if key not in _LOADED:
        try:
            _LOADED.clear()
            _LOADED[key] = Reference(json.loads(Path(identity["reference_path"]).read_bytes()), identity)
        except (OSError, ValueError) as exc:
            return None, {"code": GAP_INVALID, "detail": f"reference.json unreadable: {type(exc).__name__}"}
    return _LOADED[key], None


def binding(root: Any = None, *, now: datetime | None = None) -> dict[str, Any]:
    """Stable identity of the reference a stage validated against, for its input fingerprint: the
    derived table's hash and upstream versions when the snapshot is in the ceiling (unchanged across
    re-syncs of the same pins), else only the gap code. Never raises."""
    return binding_of(*load(root, now=now))


def binding_of(reference: Reference | None, gap: dict[str, Any] | None) -> dict[str, Any]:
    """``binding`` of an already loaded ``(reference, gap)`` pair (one load serves several readers)."""
    if reference is None:
        return {"status": (gap or {}).get("code", GAP_INVALID)}
    return {"status": OK, "reference_sha256": reference.identity["reference_sha256"],
            "attack_versions": reference.attack_versions, "capec_version": reference.capec_version}


def bound(value: dict[str, Any], root: Any = None) -> tuple[Reference | None, dict[str, Any] | None]:
    """The Reference a recorded ``binding`` names, integrity-checked but not re-aged: the ceiling was
    applied when the binding was taken, so a re-validation reproduces the same result."""
    status = (value or {}).get("status")
    if status != OK:
        code = status if status in (GAP_MISSING, GAP_STALE, GAP_INVALID) else GAP_INVALID
        return None, {"code": code, "detail": "MITRE reference snapshot was not usable when this stage's inputs were bound"}
    reference, gap = load(root, now=datetime.now(timezone.utc), max_age_seconds=sys.maxsize)
    if reference is None or reference.identity.get("reference_sha256") != value.get("reference_sha256"):
        return None, {"code": GAP_INVALID, "detail": "the bound MITRE reference table is no longer published"}
    return reference, None


def _shown(value: Any) -> str:
    """Echo a model-supplied tag only when it is id-shaped; anything else is described, never copied."""
    text = str(value).strip().upper() if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
    if TECHNIQUE_ID.fullmatch(text) or CAPEC_ID.fullmatch(text) or TACTIC_ID.fullmatch(text):
        return text
    return f"<malformed id, {len(str(value))} chars>"


def _any_tactic(reference: Reference, value: Any, tactic: Any) -> str:
    tactics = [tactic] if tactic is None or isinstance(tactic, str) else (list(tactic) or [None])
    statuses = [reference.validate_technique(value, item) for item in tactics]
    return OK if OK in statuses else statuses[0]


def screen(attack_refs: Iterable[Any] | None = (), capec_refs: Iterable[Any] | None = (), *,
           tactic: Any = None, reference: Reference | None = None, gap: dict[str, Any] | None = None,
           root: Any = None, now: datetime | None = None) -> dict[str, Any]:
    """Validate optional tags. Returns ``{attack_refs, capec_refs, reference, gaps}`` where the ref
    lists hold only OK ids (canonical, sorted, de-duplicated) and every drop or withheld tag is a gap.
    ``tactic`` is one tactic or a sequence of acceptable tactics (any match is OK)."""
    attack_refs, capec_refs = list(attack_refs or []), list(capec_refs or [])
    if reference is None and gap is None and (attack_refs or capec_refs):
        reference, gap = load(root, now=now)
    result: dict[str, Any] = {"attack_refs": [], "capec_refs": [], "reference": None, "gaps": []}
    if not (attack_refs or capec_refs):
        return result
    if reference is None:
        result["gaps"].append({**(gap or {"code": GAP_MISSING, "detail": "no MITRE reference snapshot"}),
                               "withheld": sorted({_shown(item) for item in attack_refs + capec_refs})[:2 * REFS_MAX]})
        return result
    result["reference"] = {"reference_sha256": reference.identity.get("reference_sha256"),
                           "attack_versions": reference.attack_versions, "capec_version": reference.capec_version}
    for kind, values, available, check, canon in (
            ("attack", attack_refs, reference.has_attack, lambda v: _any_tactic(reference, v, tactic),
             lambda v: _canonical(v, TECHNIQUE_ID)),
            ("capec", capec_refs, reference.has_capec, reference.validate_capec,
             lambda v: _canonical(v, CAPEC_ID, "CAPEC-"))):
        if not values:
            continue
        if not available:
            result["gaps"].append({"code": GAP_MISSING, "detail": f"the snapshot has no {kind} source",
                                   "withheld": sorted({_shown(item) for item in values})[:REFS_MAX]})
            continue
        accepted = []
        for position, value in enumerate(values):
            if position >= REFS_MAX:
                result["gaps"].append({"code": "MITRE_REF_OVER_LIMIT", "ref": _shown(value),
                                       "detail": f"at most {REFS_MAX} {kind} refs"})
                continue
            status = check(value)
            if status == OK:
                accepted.append(canon(value))
            else:
                result["gaps"].append({"code": "MITRE_REF_" + status, "ref": _shown(value)})
        result[kind + "_refs"] = sorted(set(accepted))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    technique = sub.add_parser("technique"); technique.add_argument("id"); technique.add_argument("--tactic")
    pattern = sub.add_parser("capec"); pattern.add_argument("id")
    args = parser.parse_args(argv)
    reference, gap = load(args.root)
    if reference is None:
        print(json.dumps({"status": gap["code"], "detail": gap["detail"]}, sort_keys=True))
        return 3
    if args.command == "technique":
        status, row = reference.validate_technique(args.id, args.tactic), reference.technique(args.id)
    else:
        status, row = reference.validate_capec(args.id), reference.capec(args.id)
    print(json.dumps({"status": status, "entry": row, "snapshot_id": reference.identity.get("snapshot_id")},
                     sort_keys=True))
    return 0 if status == OK else 1


if __name__ == "__main__":
    sys.exit(main())
