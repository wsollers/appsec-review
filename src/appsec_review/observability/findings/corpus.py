"""Fix-pair corpora and the private holdout (finding-metrics.md section 6, T-067).

A fix pair is one real defect seen at two revisions of the same project: the revision before the
fix, where the defect is present, and the revision after it, where the same code is a negative
control. It yields two keyed expectations and one lifecycle expectation per side (``still_present``
before the fix, ``fixed`` after it).

Doctrine:

* Keys stay outside targets. A key is never written under a ``targets`` directory and never
  overwrites an existing file.
* This module ships no corpus data. Every advisory, project, revision, licence and source in a
  corpus file is supplied by whoever assembles the corpus; nothing here invents one.
* A private holdout corpus is never used for prompt or guidance tuning, and every use of it is
  recorded in an append-only ledger. Tuning to the key makes the key worthless as a measure.
* An unknown field, an open vocabulary or an inconsistent pair is refused, not repaired. Outputs
  are sorted and deterministic, and nothing reads a clock or a random source: dates are passed in.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import date
import json
import os
from pathlib import Path
import re
import tomllib
from typing import Any

from .contracts import SEVERITY_BANDS, AttackerPosition, LifecycleState, digest, is_sha256, normalize_cwe
from .contracts import normalize_path

HOLDOUT_LEDGER_SCHEMA = "appsec-review/holdout-usage/1"
MAX_PAIRS = 2000
MAX_HOLDOUT_USES = 10_000
REVISION_ROLES = ("post", "pre")
HOLDOUT_PURPOSE = "evaluation"

_ATTACKER_POSITIONS = tuple(item.value for item in AttackerPosition)
_CORPUS_KEYS = ("name", "holdout", "description")
_PAIR_REQUIRED = ("id", "project", "advisory", "license", "source", "pre_revision", "post_revision", "path", "line",
                  "cwe")
_PAIR_OPTIONAL = ("end_line", "scope_start", "scope_end", "severity", "attacker_position", "weakness_class")
_PAIR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_USE_KEYS = ("purpose", "run_id", "used_on")


@dataclass(frozen=True)
class FixPair:
    """One defect at its pre-fix revision and the same code at its post-fix revision."""

    id: str
    project: str
    advisory: str
    license: str
    source: str
    pre_revision: str
    post_revision: str
    path: str
    line: int
    end_line: int
    scope_start: int | None
    scope_end: int | None
    cwe: str
    severity: str | None
    attacker_position: str | None
    weakness_class: str | None

    @property
    def scope(self) -> tuple[int, int]:
        """The attribution range: the declared scope, else the target lines (as the key format does)."""
        if self.scope_start is None or self.scope_end is None:
            return (self.line, self.end_line)
        return (self.scope_start, self.scope_end)


@dataclass(frozen=True)
class FixPairCorpus:
    name: str
    holdout: bool
    description: str | None
    pairs: tuple[FixPair, ...]      # sorted by id
    sha256: str                     # digest of the normalized content above


def _text(value: Any, name: str, limit: int = 512) -> str:
    if (not isinstance(value, str) or not value.strip() or len(value) > limit
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ValueError(f"{name} must be a non-empty single-line string of at most {limit} characters")
    return value


def _positive(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _pair(item: Any) -> FixPair:
    if not isinstance(item, Mapping):
        raise ValueError("every [[pair]] must be a table")
    pair_id = item.get("id")
    if not isinstance(pair_id, str) or not _PAIR_ID.match(pair_id):
        raise ValueError(f"pair id {pair_id!r} must be 1 to 128 characters of letters, digits, '.', '_' or '-'")
    unknown = sorted(str(key) for key in set(item) - set(_PAIR_REQUIRED) - set(_PAIR_OPTIONAL))
    missing = sorted(set(_PAIR_REQUIRED) - set(item))
    if unknown or missing:
        raise ValueError(f"{pair_id}: unknown keys {unknown or 'none'}, missing keys {missing or 'none'}")
    for name in ("pre_revision", "post_revision"):
        if not isinstance(item[name], str) or not _REVISION.match(item[name]):
            raise ValueError(f"{pair_id}: {name} must be 40 lowercase hexadecimal characters")
    if item["pre_revision"] == item["post_revision"]:
        raise ValueError(f"{pair_id}: pre_revision and post_revision are the same revision")
    line = _positive(item["line"], f"{pair_id}: line")
    end_line = _positive(item.get("end_line", line), f"{pair_id}: end_line")
    if end_line < line:
        raise ValueError(f"{pair_id}: end_line precedes line")
    if ("scope_start" in item) != ("scope_end" in item):
        raise ValueError(f"{pair_id}: scope_start and scope_end go together")
    scope_start = scope_end = None
    if "scope_start" in item:
        scope_start = _positive(item["scope_start"], f"{pair_id}: scope_start")
        scope_end = _positive(item["scope_end"], f"{pair_id}: scope_end")
        if scope_start > line or scope_end < end_line:
            raise ValueError(f"{pair_id}: scope {scope_start}..{scope_end} does not contain its lines")
    cwe = normalize_cwe(item["cwe"])
    if cwe is None or cwe == "CWE-0":
        raise ValueError(f"{pair_id}: unrecognised cwe {item['cwe']!r}")
    severity, position = item.get("severity"), item.get("attacker_position")
    if severity is not None and severity not in SEVERITY_BANDS:
        raise ValueError(f"{pair_id}: severity is one of {', '.join(SEVERITY_BANDS)}")
    if position is not None and position not in _ATTACKER_POSITIONS:
        raise ValueError(f"{pair_id}: attacker_position is one of {', '.join(_ATTACKER_POSITIONS)}")
    try:
        path = normalize_path(item["path"])
    except ValueError as error:
        raise ValueError(f"{pair_id}: {error}") from error
    return FixPair(
        id=pair_id, project=_text(item["project"], f"{pair_id}: project"),
        advisory=_text(item["advisory"], f"{pair_id}: advisory"),
        license=_text(item["license"], f"{pair_id}: license"),
        source=_text(item["source"], f"{pair_id}: source", 2048),
        pre_revision=item["pre_revision"], post_revision=item["post_revision"], path=path,
        line=line, end_line=end_line, scope_start=scope_start, scope_end=scope_end, cwe=cwe,
        severity=severity, attacker_position=position,
        weakness_class=None if item.get("weakness_class") is None
        else _text(item["weakness_class"], f"{pair_id}: weakness_class"))


def load_fix_pairs(path: Path | str) -> FixPairCorpus:
    """Read ``[corpus]`` and ``[[pair]]`` of a fix-pair corpus file; refuse anything inconsistent."""
    path = Path(path)
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    unknown = sorted(set(document) - {"corpus", "pair"})
    if unknown:
        raise ValueError(f"{path}: unknown top-level keys: {', '.join(unknown)}")
    header = document.get("corpus")
    if not isinstance(header, dict):
        raise ValueError(f"{path}: [corpus] must be a table")
    unknown = sorted(set(header) - set(_CORPUS_KEYS))
    if unknown:
        raise ValueError(f"{path}: unknown [corpus] keys: {', '.join(unknown)}")
    if not isinstance(header.get("holdout"), bool):
        raise ValueError(f"{path}: [corpus] holdout must be true or false")
    items = document.get("pair", [])
    if not isinstance(items, list):
        raise ValueError(f"{path}: pair must be an array of tables")
    if not items:
        raise ValueError(f"{path} lists no fix pairs")
    if len(items) > MAX_PAIRS:
        raise ValueError(f"{path}: a fix-pair corpus holds at most {MAX_PAIRS} pairs")
    pairs = sorted((_pair(item) for item in items), key=lambda pair: pair.id)
    for first, second in zip(pairs, pairs[1:]):
        if first.id == second.id:
            raise ValueError(f"{path} repeats the pair id {first.id}")
    name = _text(header.get("name"), "[corpus] name")
    description = None if header.get("description") is None else _text(header["description"], "[corpus] description",
                                                                        2048)
    content = {"name": name, "holdout": header["holdout"], "description": description,
               "pairs": [asdict(pair) for pair in pairs]}
    return FixPairCorpus(name=name, holdout=header["holdout"], description=description, pairs=tuple(pairs),
                         sha256=digest(content))


# ---------------------------------------------------------------------------------- expansion

def _case(pair: FixPair, role: str) -> dict[str, Any]:
    return {"id": f"{pair.id}#{role}", "pair_id": pair.id, "project": pair.project, "advisory": pair.advisory,
            "revision": pair.pre_revision if role == "pre" else pair.post_revision, "path": pair.path,
            "line": pair.line, "end_line": pair.end_line, "scope": list(pair.scope), "cwe": pair.cwe,
            "severity": pair.severity, "attacker_position": pair.attacker_position,
            "weakness_class": pair.weakness_class}


def expand(corpus: FixPairCorpus) -> dict[str, Any]:
    """The keyed expectations of a corpus: a defect case before each fix and a control case after it."""
    defects = [_case(pair, "pre") for pair in corpus.pairs]
    controls = [_case(pair, "post") for pair in corpus.pairs]
    expected = {row["id"]: LifecycleState.STILL_PRESENT.value for row in defects}
    expected.update({row["id"]: LifecycleState.FIXED.value for row in controls})
    return {"corpus": corpus.name, "corpus_sha256": corpus.sha256, "holdout": corpus.holdout,
            "defects": defects, "controls": controls, "expected_recheck": dict(sorted(expected.items()))}


# ----------------------------------------------------------------------------------- key file

def _toml(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(value, ensure_ascii=False)     # control characters were refused at load


def write_scoring_key(corpus: FixPairCorpus, revision_role: str, path: Path | str, *,
                      project: str | None = None) -> Path:
    """Write one side of the corpus as an ``expectations.toml`` the existing scorer loads.

    ``"pre"`` writes ``[[defect]]`` entries, ``"post"`` writes ``[[control]]`` entries without
    ``pair`` (the counterpart lives in the other side's key). ``project`` restricts the key to one
    project, since a key describes one target. Cases of one path whose scopes overlap cannot share
    a key and are refused. Keys stay outside targets, and an existing file is never overwritten.
    """
    if revision_role not in REVISION_ROLES:
        raise ValueError(f"revision_role is one of {', '.join(REVISION_ROLES)}")
    path = Path(path)
    if any(part.lower() == "targets" for part in (*path.parts, *path.resolve().parts)):
        raise ValueError(f"keys stay outside targets: {path}")
    if path.exists() or path.is_symlink():
        raise ValueError(f"refusing to overwrite {path}")
    if not path.parent.is_dir():
        raise ValueError(f"the directory of {path} does not exist")
    pairs = [pair for pair in corpus.pairs if project is None or pair.project == project]
    if not pairs:
        raise ValueError(f"corpus {corpus.name} has no pair of project {project!r}")
    by_path: dict[str, list[FixPair]] = {}
    for pair in pairs:
        by_path.setdefault(pair.path, []).append(pair)
    for target_path, group in sorted(by_path.items()):
        ordered = sorted(group, key=lambda pair: (pair.scope, pair.id))
        for first, second in zip(ordered, ordered[1:]):
            if second.scope[0] <= first.scope[1]:
                raise ValueError(f"{target_path}: scopes of {first.id} and {second.id} overlap; "
                                 "write one key per project and revision")
    table = "defect" if revision_role == "pre" else "control"
    lines = ["[corpus]", f"name = {_toml(corpus.name + ':' + revision_role)}",
             f"fix_pair_corpus_sha256 = {_toml(corpus.sha256)}", f"revision_role = {_toml(revision_role)}",
             f"holdout = {_toml(corpus.holdout)}"]
    for pair in pairs:
        row = _case(pair, revision_role)
        fields: dict[str, Any] = {
            "id": row["id"], "path": pair.path, "line": pair.line, "end_line": pair.end_line,
            "scope_start": pair.scope[0], "scope_end": pair.scope[1], "cwe": pair.cwe,
            "summary": f"{pair.project} {pair.advisory} at {row['revision']}"}
        if table == "defect" and pair.severity is not None:
            fields["severity"] = pair.severity
        lines.extend(["", f"[[{table}]]", *(f"{name} = {_toml(value)}" for name, value in fields.items())])
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    return path


# ------------------------------------------------------------------------------ holdout ledger

def _use(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != set(_USE_KEYS):
        raise ValueError("a holdout use holds exactly purpose, run_id and used_on")
    if value["purpose"] != HOLDOUT_PURPOSE:
        raise ValueError("a holdout corpus is never used for tuning")
    used_on = value["used_on"]
    if not isinstance(used_on, str) or not _ISO_DATE.match(used_on):
        raise ValueError("used_on must be an ISO date (YYYY-MM-DD)")
    try:
        date.fromisoformat(used_on)
    except ValueError as error:
        raise ValueError(f"used_on is not a calendar date: {used_on}") from error
    return {"purpose": HOLDOUT_PURPOSE, "run_id": _text(value["run_id"], "run_id"), "used_on": used_on}


def _read_ledger(ledger_path: Path) -> dict[str, Any] | None:
    if not ledger_path.exists():
        return None
    document = json.loads(ledger_path.read_text(encoding="utf-8"))
    if (not isinstance(document, dict) or document.get("schema") != HOLDOUT_LEDGER_SCHEMA
            or set(document) != {"schema", "corpus_sha256", "uses"}):
        raise ValueError(f"{ledger_path}: not a {HOLDOUT_LEDGER_SCHEMA} ledger")
    if not is_sha256(document["corpus_sha256"]) or not isinstance(document["uses"], list):
        raise ValueError(f"{ledger_path}: corpus_sha256 or uses are invalid")
    if len(document["uses"]) > MAX_HOLDOUT_USES:
        raise ValueError(f"{ledger_path}: a holdout ledger holds at most {MAX_HOLDOUT_USES} uses")
    uses = [_use(item) for item in document["uses"]]
    if len({tuple(sorted(use.items())) for use in uses}) != len(uses):
        raise ValueError(f"{ledger_path}: a holdout use is recorded twice")
    return {"schema": HOLDOUT_LEDGER_SCHEMA, "corpus_sha256": document["corpus_sha256"], "uses": uses}


def holdout_uses(ledger_path: Path | str) -> list[dict[str, str]]:
    """The recorded uses of a holdout corpus, in recording order; a missing ledger has none."""
    document = _read_ledger(Path(ledger_path))
    return [] if document is None else document["uses"]


def record_holdout_use(ledger_path: Path | str, corpus: FixPairCorpus, *, purpose: str, run_id: str,
                       used_on: str) -> dict[str, Any]:
    """Append one evaluation use to the corpus's ledger and return the ledger document.

    Only ``purpose="evaluation"`` is ever recorded; tuning on a holdout is refused, not logged.
    Recording the same use twice changes nothing. The ledger is rewritten through a sibling
    temporary file and ``os.replace``, so a reader never sees a partial document.
    """
    if purpose != HOLDOUT_PURPOSE:
        raise ValueError("a holdout corpus is never used for tuning")
    if not isinstance(corpus, FixPairCorpus) or corpus.holdout is not True:
        raise ValueError("only a holdout corpus has a usage ledger")
    use = _use({"purpose": purpose, "run_id": run_id, "used_on": used_on})
    ledger_path = Path(ledger_path)
    document = _read_ledger(ledger_path) or {"schema": HOLDOUT_LEDGER_SCHEMA, "corpus_sha256": corpus.sha256,
                                            "uses": []}
    if document["corpus_sha256"] != corpus.sha256:
        raise ValueError(f"{ledger_path} is the ledger of a different corpus")
    if use in document["uses"]:
        return document
    if len(document["uses"]) >= MAX_HOLDOUT_USES:
        raise ValueError(f"{ledger_path}: a holdout ledger holds at most {MAX_HOLDOUT_USES} uses")
    document["uses"].append(use)
    temporary = ledger_path.with_name(ledger_path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, ledger_path)
    return document


__all__ = [
    "HOLDOUT_LEDGER_SCHEMA", "HOLDOUT_PURPOSE", "MAX_HOLDOUT_USES", "MAX_PAIRS", "REVISION_ROLES", "FixPair",
    "FixPairCorpus", "expand", "holdout_uses", "load_fix_pairs", "record_holdout_use", "write_scoring_key",
]
