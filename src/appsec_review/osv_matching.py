"""Match package versions against the synchronized OSV snapshot's own ``index/osv.sqlite``.

osv-scanner's offline mode loads every needed ecosystem archive whole. This module instead reads
only the advisories the index lists for one ``(ecosystem, name)`` and evaluates the OSV ``affected``
entries of each stored record against one version, so the cost follows the dependencies present.

The module is pure and deterministic: it never opens a snapshot, runs a tool or reads a target. A
caller hands it a read-only connection to a verified index (or one stored advisory record).

Every answer is one of four statuses:

``affected``      an explicit ``versions`` entry or an evaluated range contains the version; the
                  matched entry or range events are returned as resolving evidence.
``not_affected``  every ``affected`` entry of that package was evaluated and none contains it.
``withdrawn``     the index records the advisory as withdrawn.
``undetermined``  the version could not be decided. The named gaps say why. This is never "clean".

Version ordering is explicit (``ECOSYSTEM_ORDERINGS``). ``SEMVER`` ranges are ordered by Semantic
Versioning 2.0.0 in any ecosystem, as the OSV schema defines them. ``ECOSYSTEM`` ranges are
evaluated only for ecosystems in the table; every other ecosystem is the named gap
``range_ordering_unsupported:<ecosystem>``, including when its explicit ``versions`` list does not
hold the version, because equal versions may be spelled differently there. ``GIT`` ranges are not
evaluated: they are ignored beside version data of the same entry and are the gap
``range_type_unsupported:GIT`` when an entry has nothing else.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import json
import re
import sqlite3
from types import MappingProxyType
from typing import Any


SCHEMA = "appsec-review/osv-index-match/1"
MODES = ("disabled", "index")
SEMVER = "semver-2.0.0"
# OSV ecosystem (the part before any ``:`` release suffix) -> ordering of its ECOSYSTEM ranges.
# Only orderings implemented and tested here are listed. PyPI (PEP 440), Maven, Debian, RubyGems,
# NuGet, Packagist and the rest are named gaps until a comparator for them is implemented.
ECOSYSTEM_ORDERINGS: Mapping[str, str] = MappingProxyType({"Go": SEMVER, "crates.io": SEMVER, "npm": SEMVER})
# Ecosystems whose versions are written with a leading ``v`` outside OSV (module versions, purls).
_V_PREFIXED = frozenset({"Go"})
_REQUIRED_COLUMNS = MappingProxyType({"advisory": ("id", "withdrawn", "raw_json"),
                                      "package": ("advisory_id", "ecosystem", "name")})

_IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    rf"(?:-({_IDENTIFIER}(?:\.{_IDENTIFIER})*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", re.ASCII)
_EVENT_KINDS = ("introduced", "fixed", "last_affected", "limit")
# Events at one version: ``fixed`` closes before ``introduced`` reopens (adjacent intervals stay
# affected at the boundary), and ``last_affected`` closes only after ``introduced`` opened.
_EVENT_ORDER = {"fixed": 0, "introduced": 1, "last_affected": 2}


@dataclass(frozen=True, slots=True)
class Bounds:
    """Every limit the matcher applies. Reaching one is a named gap, never a shorter answer."""

    max_packages: int = 20_000
    max_advisories_per_package: int = 500
    max_raw_bytes: int = 8 * 1024 * 1024
    max_affected: int = 20_000
    max_ranges: int = 256
    max_events: int = 4_096
    max_versions: int = 200_000
    max_version_length: int = 256

    def __post_init__(self) -> None:
        for name in self.__slots__:
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"OSV matching bound {name} must be a positive integer")


DEFAULT_BOUNDS = Bounds()


def parse_mode(value: object, field: str) -> str:
    """Validate the ``osv_version_matching`` setting."""
    if not isinstance(value, str) or value not in MODES:
        raise ValueError(f"{field} must be one of {', '.join(MODES)}: {value!r}")
    return value


def ordering_for(ecosystem: str) -> str | None:
    """The implemented ordering of an ecosystem's ``ECOSYSTEM`` ranges, or ``None``."""
    return ECOSYSTEM_ORDERINGS.get(ecosystem.split(":", 1)[0])


def semver_key(text: str) -> tuple[Any, ...] | None:
    """Semantic Versioning 2.0.0 precedence key, or ``None`` when ``text`` is not strict SemVer.

    Build metadata does not take part in precedence. A release sorts after its pre-releases;
    numeric pre-release identifiers sort numerically and before alphanumeric ones.
    """
    match = _SEMVER.fullmatch(text)
    if match is None:
        return None
    release = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    if match.group(4) is None:
        return (*release, 1, ())
    identifiers = tuple((0, int(item), "") if item.isdigit() else (1, 0, item)
                        for item in match.group(4).split("."))
    return (*release, 0, identifiers)


def _key(text: str, ecosystem: str, bounds: Bounds) -> tuple[Any, ...] | None:
    if len(text) > bounds.max_version_length:
        return None
    if ecosystem.split(":", 1)[0] in _V_PREFIXED and text.startswith("v"):
        text = text[1:]
    return semver_key(text)


def _verdict(status: str, gaps: Iterable[str] = (), evidence: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {"status": status, "gaps": sorted(set(gaps)), "evidence": dict(evidence) if evidence else None}


def _range(value: Any, version_key: tuple[Any, ...] | None, ecosystem: str, bounds: Bounds,
           ) -> tuple[bool | None, str | None, dict[str, Any] | None]:
    """``(contains, gap, evidence)`` of one non-GIT range. ``contains`` is ``None`` with a gap."""
    kind = value.get("type")
    if kind == "SEMVER":
        ordering: str | None = SEMVER
    elif kind == "ECOSYSTEM":
        ordering = ordering_for(ecosystem)
        if ordering is None:
            return None, f"range_ordering_unsupported:{ecosystem}", None
    else:
        return None, f"range_type_unsupported:{str(kind)[:32]}", None
    events = value.get("events")
    if not isinstance(events, list) or not events:
        return None, "malformed_range:events", None
    if len(events) > bounds.max_events:
        return None, "advisory_bound_exceeded:events", None
    if version_key is None:
        return None, f"version_unparseable:{ecosystem}", None
    ordered: list[tuple[tuple[Any, ...], int, str, str]] = []
    limits: list[tuple[tuple[Any, ...], str]] = []
    for event in events:
        if not isinstance(event, Mapping) or len(event) != 1:
            return None, "malformed_range:event", None
        (name, text), = event.items()
        if name not in _EVENT_KINDS or not isinstance(text, str) or not text:
            return None, "malformed_range:event", None
        if name == "introduced" and text == "0":
            point: tuple[Any, ...] = (0,)
        elif name == "limit" and text == "*":
            point = (2,)
        else:
            parsed = _key(text, ecosystem, bounds)
            if parsed is None:
                return None, f"range_event_unparseable:{ecosystem}", None
            point = (1, parsed)
        if name == "limit":
            limits.append((point, text))
        else:
            ordered.append((point, _EVENT_ORDER[name], name, text))
    if not any(item[2] == "introduced" for item in ordered):
        return None, "malformed_range:no_introduced_event", None
    version_point = (1, version_key)
    if limits and not any(version_point < point for point, _ in limits):
        return False, None, None
    ordered.sort()
    contains = False
    opened: str | None = None
    for point, _, name, text in ordered:
        if name == "introduced":
            if version_point >= point:
                contains, opened = True, text
        elif name == "fixed":
            if version_point >= point:
                contains = False
        elif version_point > point:
            contains = False
    if not contains:
        return False, None, None
    # The event that ends the interval holding the version, when the range has one.
    closing = next((item for item in ordered if (item[2] == "fixed" and item[0] > version_point)
                    or (item[2] == "last_affected" and item[0] >= version_point)), None)
    evidence: dict[str, Any] = {"kind": "range", "range_type": kind, "ordering": ordering, "introduced": opened}
    if closing is not None:
        evidence[closing[2]] = closing[3]
    if limits:
        evidence["limits"] = sorted(text for _, text in limits)
    return True, None, evidence


def _entry(index: int, entry: Mapping[str, Any], version: str, version_key: tuple[Any, ...] | None,
           ecosystem: str, bounds: Bounds) -> tuple[dict[str, Any] | None, list[str]]:
    """``(evidence when the entry contains the version, gaps that left it undecided)``."""
    versions = entry.get("versions", [])
    ranges = entry.get("ranges", [])
    if not isinstance(versions, list) or not isinstance(ranges, list):
        return None, ["malformed_affected_entry"]
    gaps: list[str] = []
    if len(versions) > bounds.max_versions:
        gaps.append("advisory_bound_exceeded:versions")
    else:
        # Exact spelling in every ecosystem; equal precedence only where the ordering is implemented.
        equal = version_key is not None and ordering_for(ecosystem) is not None
        for listed in versions:
            if not isinstance(listed, str):
                gaps.append("malformed_affected_entry")
            elif listed == version or (equal and _key(listed, ecosystem, bounds) == version_key):
                return {"kind": "versions", "affected_index": index, "listed_version": listed[:256]}, []
    evaluated = 0
    git_only = bool(ranges)
    if len(ranges) > bounds.max_ranges:
        gaps.append("advisory_bound_exceeded:ranges")
        ranges = []
        git_only = False
    for position, value in enumerate(ranges):
        if not isinstance(value, Mapping):
            gaps.append("malformed_range:not_an_object")
            git_only = False
            continue
        if value.get("type") == "GIT":
            continue
        git_only = False
        contains, gap, evidence = _range(value, version_key, ecosystem, bounds)
        if contains:
            return {**(evidence or {}), "affected_index": index, "range_index": position}, []
        if gap is not None:
            gaps.append(gap)
        else:
            evaluated += 1
    if git_only and not versions:
        gaps.append("range_type_unsupported:GIT")
    elif not versions and not ranges and not gaps:
        gaps.append("affected_entry_has_no_version_data")
    elif versions and not evaluated and not gaps:
        # Only an explicit list (and at most GIT ranges). A miss is decisive only where version
        # equality is implemented for the ecosystem and the queried version parses under it.
        if ordering_for(ecosystem) is None:
            gaps.append(f"range_ordering_unsupported:{ecosystem}")
        elif version_key is None:
            gaps.append(f"version_unparseable:{ecosystem}")
    return None, gaps


def evaluate_record(raw_json: object, withdrawn: object, ecosystem: str, name: str, version: str, *,
                    bounds: Bounds = DEFAULT_BOUNDS) -> dict[str, Any]:
    """Decide one stored advisory record for one package version.

    ``raw_json`` and ``withdrawn`` are the index's ``advisory`` columns. Package names compare
    without case, like the index lookup that selected the record.
    """
    if not isinstance(version, str) or not version or len(version) > bounds.max_version_length:
        return _verdict("undetermined", ["version_unusable"])
    if withdrawn is not None and str(withdrawn).strip():
        return _verdict("withdrawn")
    if not isinstance(raw_json, str) or not raw_json:
        return _verdict("undetermined", ["advisory_record_missing"])
    if len(raw_json) > bounds.max_raw_bytes:
        return _verdict("undetermined", ["advisory_bound_exceeded:raw_bytes"])
    try:
        document = json.loads(raw_json)
    except (ValueError, RecursionError):
        return _verdict("undetermined", ["malformed_advisory_record"])
    if not isinstance(document, Mapping) or not isinstance(document.get("affected", []), list):
        return _verdict("undetermined", ["malformed_advisory_record"])
    if isinstance(document.get("withdrawn"), str) and document["withdrawn"].strip():
        return _verdict("withdrawn")
    affected = document.get("affected", [])
    if len(affected) > bounds.max_affected:
        return _verdict("undetermined", ["advisory_bound_exceeded:affected"])
    version_key = _key(version, ecosystem, bounds)
    wanted = name.casefold()
    gaps: list[str] = []
    seen = False
    for index, entry in enumerate(affected):
        package = entry.get("package") if isinstance(entry, Mapping) else None
        if not isinstance(package, Mapping):
            gaps.append("malformed_affected_entry")
            continue
        if package.get("ecosystem") != ecosystem or str(package.get("name", "")).casefold() != wanted:
            continue
        seen = True
        evidence, entry_gaps = _entry(index, entry, version, version_key, ecosystem, bounds)
        if evidence is not None:
            return _verdict("affected", (), evidence)
        gaps.extend(entry_gaps)
    if not seen:
        gaps.append("affected_entry_missing")
    return _verdict("undetermined", gaps) if gaps else _verdict("not_affected")


def require_index(connection: sqlite3.Connection) -> None:
    """Fail when the connection is not an OSV index of the shape the matcher reads."""
    for table, columns in _REQUIRED_COLUMNS.items():
        present = {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")}
        missing = [column for column in columns if column not in present]
        if missing:
            raise ValueError(f"OSV index table {table} lacks column(s): {', '.join(missing)}")


def indexed_ecosystems(connection: sqlite3.Connection) -> tuple[str, ...] | None:
    """Ecosystems whose whole archive the index was built from, or ``None`` when it does not say.

    ``package`` rows alone do not answer this: an advisory from one archive also lists its
    packages in other ecosystems. Indexes built before ``appsec-review/osv-index/2`` have no record.
    """
    try:
        row = connection.execute("SELECT value FROM metadata WHERE key='ecosystems'").fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    try:
        value = json.loads(row[0])
    except (TypeError, ValueError) as exc:
        raise ValueError("OSV index metadata 'ecosystems' is not JSON") from exc
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError("OSV index metadata 'ecosystems' is not a list of names")
    return tuple(sorted(set(value)))


def ecosystem_gap(ecosystem: str, indexed: Sequence[str] | None) -> str | None:
    """The named gap when the index cannot vouch for an ecosystem's complete advisory set."""
    if indexed is None:
        return "snapshot_ecosystems_unrecorded"
    if ecosystem in indexed or ecosystem.split(":", 1)[0] in indexed:
        return None
    return f"ecosystem_not_in_snapshot:{ecosystem}"


def match_package(connection: sqlite3.Connection, ecosystem: str, name: str, version: str, *,
                  bounds: Bounds = DEFAULT_BOUNDS) -> dict[str, Any]:
    """Every indexed advisory of ``(ecosystem, name)`` decided for ``version``.

    ``status`` is ``complete`` only when the index holds the ecosystem's whole archive and every
    listed advisory was decided. ``matches`` holds the affected advisories with their resolving
    evidence, ``undetermined`` the advisories that stay unverified leads with their named gaps.
    """
    require_index(connection)
    return _match(connection, indexed_ecosystems(connection), ecosystem, name, version, bounds)


def _match(connection: sqlite3.Connection, indexed: Sequence[str] | None, ecosystem: str, name: str,
           version: str, bounds: Bounds) -> dict[str, Any]:
    if not all(isinstance(item, str) and item.strip() for item in (ecosystem, name)):
        raise ValueError("OSV matching needs a package ecosystem and name")
    rows = connection.execute(
        "SELECT DISTINCT p.advisory_id FROM package p WHERE p.ecosystem=? AND p.name=? COLLATE NOCASE "
        "ORDER BY p.advisory_id LIMIT ?", (ecosystem, name, bounds.max_advisories_per_package + 1)).fetchall()
    gaps: list[str] = []
    missing = ecosystem_gap(ecosystem, indexed)
    if missing is not None:
        gaps.append(missing)
    if not isinstance(version, str) or not version or len(version) > bounds.max_version_length:
        gaps.append("version_unusable")
    if len(rows) > bounds.max_advisories_per_package:
        rows = rows[:bounds.max_advisories_per_package]
        gaps.append("truncated:advisories_per_package")
    matches: list[dict[str, Any]] = []
    undetermined: list[dict[str, Any]] = []
    counts = {"not_affected": 0, "withdrawn": 0}
    for (advisory,) in rows:
        record = connection.execute("SELECT withdrawn, raw_json FROM advisory WHERE id=?", (advisory,)).fetchone()
        verdict = (_verdict("undetermined", ["advisory_record_missing"]) if record is None else
                   evaluate_record(record[1], record[0], ecosystem, name, version, bounds=bounds))
        if verdict["status"] == "affected":
            matches.append({"advisory_id": str(advisory), "evidence": verdict["evidence"]})
        elif verdict["status"] == "undetermined":
            undetermined.append({"advisory_id": str(advisory), "gaps": verdict["gaps"]})
            gaps.extend(verdict["gaps"])
        else:
            counts[verdict["status"]] += 1
    return {"schema": SCHEMA, "query": {"ecosystem": ecosystem, "name": name, "version": version},
            "ordering": ordering_for(ecosystem), "status": "partial" if gaps else "complete",
            "matches": matches, "undetermined": undetermined, "not_affected_count": counts["not_affected"],
            "withdrawn_count": counts["withdrawn"], "advisory_count": len(rows), "gaps": sorted(set(gaps))}


def match_packages(connection: sqlite3.Connection, packages: Iterable[Sequence[str]], *,
                   bounds: Bounds = DEFAULT_BOUNDS) -> dict[str, Any]:
    """Match distinct ``(ecosystem, name, version)`` triples in sorted order, for any input order.

    Triples beyond ``max_packages`` are not matched and are counted in a named gap.
    """
    require_index(connection)
    indexed = indexed_ecosystems(connection)
    wanted = sorted({(str(item[0]), str(item[1]), str(item[2])) for item in packages})
    selected = wanted[:bounds.max_packages]
    results = [_match(connection, indexed, *item, bounds) for item in selected]
    gaps = sorted({gap for result in results for gap in result["gaps"]})
    if len(wanted) > len(selected):
        gaps.append(f"package_bound_exceeded: {len(wanted) - len(selected)} package version(s) were not matched")
    return {"schema": SCHEMA, "package_count": len(selected), "unmatched_package_count": len(wanted) - len(selected),
            "status": "partial" if gaps else "complete", "results": results, "gaps": gaps}
