"""Read-only MITRE lookup tools for model jobs (ADR-0034 item 5), served by ``input_mcp.py``.

``mitre_technique``, ``mitre_capec`` and ``mitre_cwe`` answer from the resolved MITRE snapshot
(``mitre_feed.resolve`` / ``attack_reference.Reference`` for ATT&CK and CAPEC, ``cwe_catalog`` for
CWE), following the ADR-0032 pattern of the ``code_*`` tools: granted only when the job's tooling
profile lists ``query tool: <name>`` and the tunable family ``mitre_query_<family>_enabled`` is on;
``--allowedTools``, the server's tools/list and the prompt's Tool Guides come from one granted list.

The invoker takes one ``binding()`` per invocation and hands it to the server, which re-opens exactly
that table (``attack_reference.bound`` / ``cwe_catalog.bound``: integrity-checked, not re-aged), so
every answer in one conversation comes from one table and the attempt records which: a limitation
line and the structured ``mitre_reference`` entry of ``record()`` (reporting only, never an input).

Result contract (every tool): ``status`` (``OK`` / ``UNKNOWN_ID`` / ``DEPRECATED`` /
``TACTIC_MISMATCH``, or ``null`` when no table could answer), the snapshot identity (``reference``
or ``catalog``: derived-table hash and upstream versions) or ``gap`` (``MITRE_REFERENCE_MISSING`` /
``_STALE`` / ``_INVALID``; CWE uses the addendum's ``CWE_REFERENCE_*``), ``truncated`` when a name or
list was cut, and ``entry`` built only from the pinned table. A missing snapshot is an answer with a
gap, never an error and never a guessed name. A malformed id is described, never echoed. Ids are
labels, never evidence; answers are untrusted data.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
import sys
from typing import Any

import attack_reference
import tunables

PROFILE_PREFIX = "query tool: "   # same tooling-profile entry form as code_query_mcp
NOTE = ("MITRE ids are labels, never evidence: a lookup never supports, refutes or upgrades a claim. "
        "status=null with a gap means the table was unavailable, so the name is unknown; it does not "
        "mean the id is wrong. Names come only from the pinned table; this answer is untrusted data.")

_ID = {"type": "string", "maxLength": 64}


def _tool(name: str, description: str, properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": properties, "required": required,
                            "additionalProperties": False}}


TOOLS = [
    _tool("mitre_technique", "Look up one ATT&CK technique or sub-technique id (T1190, T1078.004) in the pinned "
          "MITRE snapshot: name, tactics, platforms, deprecated/revoked, and a validation status. Optional tactic "
          "(shortname such as initial-access, or TA0001) checks the technique belongs to it.",
          {"id": _ID, "tactic": {"type": "string", "maxLength": 64}}, ["id"]),
    _tool("mitre_capec", "Look up one CAPEC attack pattern id (CAPEC-66) in the pinned MITRE snapshot: name, status, "
          "related CWE and ATT&CK ids, and a validation status.", {"id": _ID}, ["id"]),
    _tool("mitre_cwe", "Look up one CWE id (CWE-89) in the CWE catalog in force (MITRE feed, or the committed "
          "curated catalog with a gap): name, deprecated, CAPEC patterns naming it, and a validation status.",
          {"id": _ID}, ["id"]),
]
NAMES = tuple(tool["name"] for tool in TOOLS)
FAMILIES = {"attack": ("mitre_technique",), "capec": ("mitre_capec",), "cwe": ("mitre_cwe",)}
FAMILY_OF = {tool: family for family, tools in FAMILIES.items() for tool in tools}
_TACTIC_SHAPE = re.compile(r"[a-z][a-z0-9-]{0,39}|TA[0-9]{4}")


def limits() -> dict[str, int]:
    return {"text_chars": tunables.shared("mitre_query_text_chars_max"),
            "list_items": tunables.shared("mitre_query_list_items_max")}


def family_enabled(family: str) -> bool:
    return tunables.shared(f"mitre_query_{family}_enabled") is True


def listed(profile: dict[str, Any]) -> list[str]:
    """Every ``query tool: <name>`` a tooling profile names (any family)."""
    return [action[len(PROFILE_PREFIX):].strip() for action in profile.get("allowed_actions", [])
            if isinstance(action, str) and action.startswith(PROFILE_PREFIX)]


def profile_tools(profile: dict[str, Any]) -> list[str]:
    """MITRE lookup tools a tooling profile allows; a name no query family knows is an error."""
    import code_query_mcp
    wanted = listed(profile)
    unknown = sorted(set(wanted) - set(NAMES) - set(code_query_mcp.NAMES))
    if unknown:
        raise ValueError("tooling profile names unknown query tool(s): " + ", ".join(unknown))
    return [name for name in NAMES if name in wanted]


def grantable(profile: dict[str, Any]) -> list[str]:
    """The MITRE tools a job gets: listed by its profile and enabled by tunables. No per-job pin:
    the snapshot is host reference data, bound per invocation by ``binding()``."""
    return [name for name in profile_tools(profile) if family_enabled(FAMILY_OF[name])]


# ---- the table one invocation answers from ----------------------------------------------------------

def binding(root: Any = None, *, now: datetime | None = None) -> dict[str, Any]:
    """Stable identity of the tables in force (unchanged across re-syncs of the same pins): the
    ATT&CK/CAPEC ``attack_reference.binding`` and the CWE ``cwe_catalog`` identity. Never raises."""
    return take(root, now=now)[0]


def take(root: Any = None, *, now: datetime | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """(``binding()``, ``record()`` of it) from one load of each table. The record adds the snapshot
    id, which the binding leaves out so that it stays stable across re-syncs. Never raises."""
    import cwe_catalog
    now = now or datetime.now(timezone.utc)
    reference, gap = attack_reference.load(root, now=now)
    snapshot = reference.identity.get("snapshot_id") if reference is not None else None
    try:
        catalog = cwe_catalog.current(root, now=now)
        cwe, snapshot = catalog.identity, snapshot or catalog.snapshot_id
    except Exception as exc:   # the committed catalog itself failed its lock: no CWE table at all
        cwe = {"reference_gap": cwe_catalog.GAP_INVALID, "catalog_source": None,
               "detail": f"{type(exc).__name__}"}
    bound = {"mitre_reference": attack_reference.binding_of(reference, gap), "cwe_catalog": cwe}
    return bound, record(bound, snapshot_id=snapshot)


# The structured ``mitre_reference`` entry of a job's invoker output (ADR-0034 addendum item 3), closed
# by schemas/mitre-reference-record.schema.json. Reporting only: never input identity, never the prompt.
_SNAPSHOT_ID = re.compile(r"sha256-[0-9a-f]{16}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_REF64 = re.compile(r"sha256:[0-9a-f]{64}")
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z .()_+-]{0,79}")
_DOMAIN = re.compile(r"[a-z][a-z0-9-]{0,39}")
_CWE_SOURCES = ("mitre-feed", "committed-curated")


def _shaped(value: Any, pattern: re.Pattern[str]) -> str | None:
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def record(bound: dict[str, Any], *, snapshot_id: Any = None) -> dict[str, Any]:
    """The closed ``mitre_reference`` entry of a job granted MITRE lookups: snapshot id, derived-table
    hash, ATT&CK / CAPEC / CWE versions and the gap codes. A value of an unexpected shape is null."""
    import cwe_catalog
    attack = (bound or {}).get("mitre_reference") or {}
    cwe = (bound or {}).get("cwe_catalog") or {}
    ok = attack.get("status") == attack_reference.OK
    codes = (attack_reference.GAP_MISSING, attack_reference.GAP_STALE, attack_reference.GAP_INVALID)
    cwe_codes = (cwe_catalog.GAP_MISSING, cwe_catalog.GAP_STALE, cwe_catalog.GAP_INVALID)
    versions = attack.get("attack_versions") if ok and isinstance(attack.get("attack_versions"), dict) else {}
    source = cwe.get("catalog_source") if cwe.get("catalog_source") in _CWE_SOURCES else None
    cwe_gap = cwe.get("reference_gap") or (None if source else cwe_catalog.GAP_INVALID)
    return {
        "snapshot_id": _shaped(snapshot_id, _SNAPSHOT_ID),
        "reference_sha256": _shaped(attack.get("reference_sha256"), _HEX64) if ok else None,
        "versions": {"attack": {key: value for key, value in sorted(versions.items())
                                if _shaped(key, _DOMAIN) and _shaped(value, _VERSION)},
                     "capec": _shaped(attack.get("capec_version"), _VERSION) if ok else None,
                     "cwe": _shaped(cwe.get("catalog_version"), _VERSION) if source else None},
        "cwe_source": source,
        "cwe_catalog_sha256": _shaped(cwe.get("catalog_sha256"), _REF64) if source else None,
        "gap": None if ok else (attack.get("status") if attack.get("status") in codes
                                else attack_reference.GAP_INVALID),
        "cwe_gap": None if cwe_gap is None else (cwe_gap if cwe_gap in cwe_codes else cwe_catalog.GAP_INVALID),
    }


def _describe(value: Any) -> str:
    return f"<malformed id, {len(str(value))} chars>"


def _malformed_status(canonical: str | None) -> str | None:
    """A malformed id is UNKNOWN_ID whatever the table state; a well-formed one is not validated
    without a table (status null: the name is unknown, the id is not judged)."""
    return attack_reference.UNKNOWN_ID if canonical is None else None


class Lookup:
    """The bound ATT&CK/CAPEC reference and CWE catalog for one server process."""

    def __init__(self, bound: dict[str, Any] | None = None, root: Any = None):
        import cwe_catalog
        bound = bound if isinstance(bound, dict) else binding(root)
        self.binding = bound
        self.reference, self.gap = attack_reference.bound(bound.get("mitre_reference") or {}, root)
        if self.gap is not None:   # fixed wording only: a detail may carry host paths
            self.gap = {"code": self.gap["code"], "detail": _GAP_TEXT.get(self.gap["code"], "")}
        self.catalog = None
        self.cwe_gap: dict[str, Any] | None = None
        cwe = bound.get("cwe_catalog") or {}
        try:
            if cwe.get("catalog_source") is None:
                raise ValueError("no CWE catalog was bound")
            self.catalog = cwe_catalog.bound(cwe, root)
            self.cwe_gap = dict(self.catalog.gap) if self.catalog.gap else None
        except Exception:
            self.catalog, self.cwe_gap = None, {"code": cwe_catalog.GAP_INVALID}
        if self.cwe_gap is not None:
            self.cwe_gap = {"code": self.cwe_gap["code"], "detail": _CWE_GAP_TEXT.get(self.cwe_gap["code"], "")}

    # -- helpers ----------------------------------------------------------------------------------
    def _identity(self) -> dict[str, Any] | None:
        if self.reference is None:
            return None
        return {"reference_sha256": self.reference.identity.get("reference_sha256"),
                "attack_versions": self.reference.attack_versions, "capec_version": self.reference.capec_version}

    @staticmethod
    def _text(value: Any, cut: list[bool]) -> Any:
        if not isinstance(value, str):
            return value
        text = " ".join("".join(ch if ch.isprintable() else " " for ch in value).split())
        limit = limits()["text_chars"]
        if len(text) > limit:
            cut.append(True)
            return text[:limit]
        return text

    @staticmethod
    def _list(values: Any, cut: list[bool]) -> list[Any]:
        values = list(values or [])
        limit = limits()["list_items"]
        if len(values) > limit:
            cut.append(True)
        return values[:limit]

    def _answer(self, tool: str, query: dict[str, Any], status: str | None, entry: dict[str, Any] | None,
                cut: list[bool], *, gap: dict[str, Any] | None, identity_key: str, identity: Any,
                malformed: bool = False) -> dict[str, Any]:
        return {"tool": tool, "query": query, "status": status, "malformed": malformed, "entry": entry,
                identity_key: identity, "gap": gap, "truncated": bool(cut), "note": NOTE}

    # -- tools ------------------------------------------------------------------------------------
    def mitre_technique(self, args: dict[str, Any]) -> dict[str, Any]:
        raw, tactic = args["id"], args.get("tactic")
        canonical = attack_reference._canonical(raw, attack_reference.TECHNIQUE_ID)
        query: dict[str, Any] = {"id": canonical or _describe(raw)}
        if tactic is not None:
            query["tactic"] = tactic.strip() if _TACTIC_SHAPE.fullmatch(tactic.strip()) else _describe(tactic)
        cut: list[bool] = []
        gap = self.gap
        if self.reference is not None and not self.reference.has_attack:
            gap = {"code": attack_reference.GAP_MISSING, "detail": "the snapshot has no ATT&CK source"}
        if gap is not None:
            return self._answer("mitre_technique", query, _malformed_status(canonical), None, cut, gap=gap,
                                identity_key="reference", identity=self._identity(), malformed=canonical is None)
        if canonical is None:
            return self._answer("mitre_technique", query, attack_reference.UNKNOWN_ID, None, cut, gap=None,
                                identity_key="reference", identity=self._identity(), malformed=True)
        status = self.reference.validate_technique(canonical, tactic.strip() if tactic is not None else None)
        row = self.reference.technique(canonical)
        entry = None
        if row is not None:
            parent = self.reference.technique(row["parent"]) if row.get("parent") else None
            entry = {"id": row["id"], "name": self._text(row["name"], cut),
                     "tactics": self._list(row["tactics"], cut), "platforms": self._list(row["platforms"], cut),
                     "subtechnique": row["subtechnique"], "parent": row.get("parent"),
                     "parent_name": self._text(parent["name"], cut) if parent else None,
                     "deprecated": row["deprecated"], "revoked": row["revoked"],
                     "domains": self._list(row["domains"], cut), "url": row.get("url")}
        return self._answer("mitre_technique", query, status, entry, cut, gap=None, identity_key="reference",
                            identity=self._identity())

    def mitre_capec(self, args: dict[str, Any]) -> dict[str, Any]:
        raw = args["id"]
        canonical = attack_reference._canonical(raw, attack_reference.CAPEC_ID, "CAPEC-")
        query = {"id": canonical or _describe(raw)}
        cut: list[bool] = []
        gap = self.gap
        if self.reference is not None and not self.reference.has_capec:
            gap = {"code": attack_reference.GAP_MISSING, "detail": "the snapshot has no CAPEC source"}
        if gap is not None:
            return self._answer("mitre_capec", query, _malformed_status(canonical), None, cut, gap=gap,
                                identity_key="reference", identity=self._identity(), malformed=canonical is None)
        if canonical is None:
            return self._answer("mitre_capec", query, attack_reference.UNKNOWN_ID, None, cut, gap=None,
                                identity_key="reference", identity=self._identity(), malformed=True)
        status = self.reference.validate_capec(canonical)
        row = self.reference.capec(canonical)
        entry = None
        if row is not None:
            entry = {"id": row["id"], "name": self._text(row["name"], cut), "status": row.get("status"),
                     "deprecated": row["deprecated"], "related_cwe": self._list(row["related_cwe"], cut),
                     "related_attack": self._list(row["related_attack"], cut), "url": row.get("url")}
        return self._answer("mitre_capec", query, status, entry, cut, gap=None, identity_key="reference",
                            identity=self._identity())

    def mitre_cwe(self, args: dict[str, Any]) -> dict[str, Any]:
        raw = args["id"]
        canonical = attack_reference._canonical(raw, attack_reference.CWE_ID, "CWE-")
        query = {"id": canonical or _describe(raw)}
        cut: list[bool] = []
        catalog = self.catalog
        identity = ({**{key: catalog.identity.get(key) for key in (
            "catalog_source", "catalog_version", "catalog_as_of", "catalog_sha256")}, "catalog_used": catalog.used}
            if catalog is not None else None)
        if canonical is None:
            return self._answer("mitre_cwe", query, attack_reference.UNKNOWN_ID, None, cut,
                                gap=self.cwe_gap, identity_key="catalog", identity=identity, malformed=True)
        if catalog is None:
            return self._answer("mitre_cwe", query, None, None, cut, gap=self.cwe_gap, identity_key="catalog",
                                identity=None)
        if canonical not in catalog.names:
            # The curated fallback is a subset: an id it lacks is not known, not wrong.
            status = None if self.cwe_gap else attack_reference.UNKNOWN_ID
            return self._answer("mitre_cwe", query, status, None, cut, gap=self.cwe_gap, identity_key="catalog",
                                identity=identity)
        deprecated = canonical in catalog.deprecated
        related = []
        if self.reference is not None and self.reference.has_capec:
            related = sorted((row["id"] for row in self.reference.patterns.values()
                              if canonical in row["related_cwe"] and not row["deprecated"]),
                             key=lambda value: int(value.split("-")[1]))
        entry = {"id": canonical, "name": self._text(catalog.names[canonical], cut), "deprecated": deprecated,
                 "related_capec": self._list(related, cut),
                 "related_capec_source": "reference" if self.reference is not None and self.reference.has_capec
                 else "unavailable"}
        return self._answer("mitre_cwe", query, attack_reference.DEPRECATED if deprecated else attack_reference.OK,
                            entry, cut, gap=self.cwe_gap, identity_key="catalog", identity=identity)


_GAP_TEXT = {attack_reference.GAP_MISSING: "no usable MITRE ATT&CK/CAPEC snapshot is published on this host",
             attack_reference.GAP_STALE: "the MITRE snapshot is older than the reference age ceiling",
             attack_reference.GAP_INVALID: "the MITRE snapshot failed verification or is no longer published"}
_CWE_GAP_TEXT = {"CWE_REFERENCE_MISSING": "no usable MITRE CWE snapshot; answering from the committed curated subset",
                 "CWE_REFERENCE_STALE": "the MITRE CWE snapshot is stale; answering from the committed curated subset",
                 "CWE_REFERENCE_INVALID": "the MITRE CWE snapshot failed verification; answering from the committed "
                                          "curated subset when it loads"}


def call(lookup: Lookup | None, name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name not in NAMES:
        raise ValueError("unknown MITRE lookup tool")
    return getattr(lookup if lookup is not None else Lookup(), name)(args)


def summary(result: dict[str, Any]) -> dict[str, Any]:
    """Retrieval-audit row for one lookup answer."""
    identity = result.get("reference") or result.get("catalog") or {}
    return {"hits": 1 if result.get("entry") else 0, "refs": [result.get("query", {}).get("id")],
            "status": result.get("status"), "malformed": result.get("malformed"),
            "gap": (result.get("gap") or {}).get("code"), "truncated": result.get("truncated"),
            "table_sha256": identity.get("reference_sha256") or identity.get("catalog_sha256")}


def limitation(bound: dict[str, Any]) -> str:
    """One attempt-record line naming the tables the MITRE lookups answered from."""
    attack = bound.get("mitre_reference") or {}
    cwe = bound.get("cwe_catalog") or {}
    left = (f"reference {str(attack.get('reference_sha256'))[:16]} ATT&CK {attack.get('attack_versions')} "
            f"CAPEC {attack.get('capec_version')}" if attack.get("status") == attack_reference.OK
            else f"gap {attack.get('status', attack_reference.GAP_INVALID)}")
    right = (f"{cwe.get('catalog_source')} {cwe.get('catalog_version')} "
             f"{str(cwe.get('catalog_sha256') or '')[7:23]}" + (f" gap {cwe['reference_gap']}"
                                                                if cwe.get("reference_gap") else ""))
    return f"MITRE lookups answered from: {left}; CWE {right}"


if __name__ == "__main__":   # pragma: no cover - manual probe: python3 mitre_query_mcp.py mitre_technique T1190
    import json
    print(json.dumps(call(None, sys.argv[1], {"id": sys.argv[2]}), indent=1))
