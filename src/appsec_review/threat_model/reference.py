"""Versioned reference data of the generated threat model (T-107), loaded once and validated closed.

Three files under ``data/reference/threat-model/`` (design section 5): the interaction catalog maps
upstream evidence vocabularies to ``contract.Interaction``, the threat templates are STRIDE questions
per boundary crossing, and the crosswalk relates each template to the pinned OWASP catalogs. The data
is generic: it names no target. A file that does not match its closed shape raises ``ValueError``
naming the file and the field; nothing is repaired or defaulted.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping

from appsec_review.graph.contract import SinkClass, SourceClass
from appsec_review.observability.findings.contracts import AttackerPosition
from appsec_review.threat_model.contract import (
    CROSSWALK_SCHEMA, INTERACTION_CATALOG_SCHEMA, THREAT_TEMPLATES_SCHEMA, BoundaryKind, Interaction, Stride,
)

REFERENCE_DIRECTORY = Path("data/reference/threat-model")
INTERACTION_CATALOG_FILE = "interaction-catalog.json"
THREAT_TEMPLATES_FILE = "threat-templates.json"
CROSSWALK_FILE = "threat-crosswalk.json"
# The keys of ``contract.Origin.reference_data``, each with the file it hashes.
SHA256_KEYS: Mapping[str, str] = MappingProxyType({
    "interaction_catalog_sha256": INTERACTION_CATALOG_FILE,
    "threat_templates_sha256": THREAT_TEMPLATES_FILE,
    "crosswalk_sha256": CROSSWALK_FILE,
})

DEPENDENCY_CATEGORIES = frozenset({"database", "tls", "compression", "scripting", "http_client", "serialization"})
MITIGATION_EVIDENCE_KINDS = frozenset({"graph_guard", "graph_sanitizer", "owasp_control_result",
                                       "configuration_observation", "declared_security_state"})
DIRECTIONS = frozenset({"inbound", "outbound"})
CALLEE_LANGUAGES = frozenset({"c", "cpp", "csharp", "go", "java", "javascript", "php", "python", "ruby", "rust",
                              "swift", "tsx", "typescript"})
# Crosswalk catalog keys with the form of the chapter, group or entry ids each one holds.
CROSSWALK_CATALOGS: Mapping[str, re.Pattern[str]] = MappingProxyType({
    "asvs": re.compile(r"V[1-9][0-9]*"),
    "masvs": re.compile(r"MASVS-[A-Z]+"),
    "top10_2025": re.compile(r"A[0-9]{2}:2025"),
    "api_top10_2023": re.compile(r"API[1-9][0-9]*:2023"),
})

_CWE = re.compile(r"CWE-[1-9][0-9]*")
_TEMPLATE_ID = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*")
_KEY = re.compile(r"[a-z][a-z0-9_]*")
_CALLEE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_DEPENDENCY_MATCH = re.compile(r"[a-z0-9][a-z0-9+._-]*\*?")


@dataclass(frozen=True, slots=True)
class BoundaryRule:
    """The trust boundary a flow of one interaction crosses and the derived entity beyond it."""
    boundary_kind: BoundaryKind
    external_key: str
    external_name: str
    direction: str


@dataclass(frozen=True, slots=True)
class Template:
    """One STRIDE question for a flow of ``interaction`` crossing ``boundary_kind`` in ``direction``."""
    template_id: str
    stride: Stride
    interaction: Interaction
    boundary_kind: BoundaryKind
    direction: str
    title: str
    question: str
    obligations: tuple[str, ...]
    mitigation_evidence: tuple[str, ...]

    @property
    def applies_to(self) -> Mapping[str, str]:
        return MappingProxyType({"interaction": self.interaction.value, "boundary_kind": self.boundary_kind.value,
                                 "direction": self.direction})


@dataclass(frozen=True, slots=True)
class Reference:
    sha256s: Mapping[str, str]
    versions: Mapping[str, int]
    source_classes: Mapping[str, Interaction | None]
    sink_classes: Mapping[str, Interaction | None]
    signals: Mapping[tuple[str, str | None], Interaction]
    callees: Mapping[str, Interaction]
    callee_languages: Mapping[str, tuple[str, ...]]
    dependency_names: Mapping[str, str]
    dependency_prefixes: tuple[tuple[str, str], ...]
    boundaries: Mapping[Interaction, BoundaryRule | None]
    templates: tuple[Template, ...]
    untemplated: tuple[Interaction, ...]
    crosswalk: Mapping[str, Mapping[str, tuple[str, ...]]]
    unmapped: Mapping[str, tuple[str, ...]]

    def interaction_for_source_class(self, source_class: str) -> Interaction | None:
        return self.source_classes.get(str(source_class))

    def interaction_for_sink_class(self, sink_class: str) -> Interaction | None:
        return self.sink_classes.get(str(sink_class))

    def interaction_for_signal(self, category: str, surface: str | None = None) -> Interaction | None:
        """The exact ``(category, surface)`` row, else the category's row that names no surface."""
        exact = self.signals.get((category, surface))
        return exact if exact is not None else self.signals.get((category, None))

    def callee_names(self) -> tuple[str, ...]:
        return tuple(sorted(self.callees))

    def interaction_for_callee(self, name: str) -> Interaction | None:
        return self.callees.get(name)

    def languages_for_callee(self, name: str) -> tuple[str, ...]:
        return self.callee_languages.get(name, ())

    def dependency_category(self, name: str) -> str | None:
        """Exact lowercase name first, then the longest prefix rule; also tried on the last name segment."""
        normalized = name.strip().lower()
        candidates = [normalized]
        segment = re.split(r"[/:]", normalized)[-1]
        if segment and segment != normalized:
            candidates.append(segment)
        for candidate in candidates:
            if candidate in self.dependency_names:
                return self.dependency_names[candidate]
            for prefix, category in self.dependency_prefixes:
                if candidate.startswith(prefix):
                    return category
        return None

    def boundary_for(self, interaction: Interaction) -> BoundaryRule | None:
        return self.boundaries[Interaction(interaction)]

    def templates_for(self, interaction: Interaction, boundary_kind: BoundaryKind, direction: str) -> tuple[Template, ...]:
        return tuple(item for item in self.templates
                     if item.interaction == interaction and item.boundary_kind == boundary_kind
                     and item.direction == direction)

    def crosswalk_for(self, template_id: str) -> Mapping[str, tuple[str, ...]]:
        return self.crosswalk[template_id]


def _fail(file: str, field: str, problem: str) -> None:
    raise ValueError(f"{file}: {field}: {problem}")


def _object(file: str, field: str, value: Any, required: set[str], optional: frozenset[str] = frozenset()) -> dict:
    if not isinstance(value, dict):
        _fail(file, field, "must be an object")
    missing, unknown = required - set(value), set(value) - required - optional
    if missing:
        _fail(file, field, f"missing keys {sorted(missing)}")
    if unknown:
        _fail(file, field, f"unknown keys {sorted(unknown)}")
    return value


def _array(file: str, field: str, value: Any) -> list:
    if not isinstance(value, list):
        _fail(file, field, "must be an array")
    return value


def _text(file: str, field: str, value: Any, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        _fail(file, field, "must be nonempty trimmed text")
    if pattern is not None and not pattern.fullmatch(value):
        _fail(file, field, f"{value!r} does not have the required form")
    return value


def _member(file: str, field: str, value: Any, enum: Any) -> Any:
    if not isinstance(value, str):
        _fail(file, field, "must be text")
    try:
        return enum(value)
    except ValueError:
        _fail(file, field, f"unknown value {value!r}")


def _choice(file: str, field: str, value: Any, allowed: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        _fail(file, field, f"unknown value {value!r}")
    return value


def _texts(file: str, field: str, value: Any, *, pattern: re.Pattern[str] | None = None,
           allowed: frozenset[str] | None = None, nonempty: bool = False) -> tuple[str, ...]:
    items = _array(file, field, value)
    for index, item in enumerate(items):
        if allowed is not None:
            _choice(file, f"{field}[{index}]", item, allowed)
        else:
            _text(file, f"{field}[{index}]", item, pattern)
    if len(items) != len(set(items)):
        _fail(file, field, "repeats a value")
    if nonempty and not items:
        _fail(file, field, "must not be empty")
    return tuple(items)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _read(directory: Path, file: str, schema: str) -> tuple[dict, str]:
    try:
        data = (directory / file).read_bytes()
    except OSError as error:
        raise ValueError(f"{file}: file: cannot be read ({type(error).__name__})") from error
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except ValueError as error:
        raise ValueError(f"{file}: file: is not valid JSON ({error})") from error
    if not isinstance(document, dict):
        _fail(file, "file", "must be an object")
    if document.get("schema") != schema:
        _fail(file, "schema", f"must be {schema!r}")
    version = document.get("version")
    if type(version) is not int or version < 1:
        _fail(file, "version", "must be a positive integer")
    return document, hashlib.sha256(data).hexdigest()


def _class_map(file: str, field: str, value: Any, enum: Any) -> Mapping[str, Interaction | None]:
    expected = {item.value for item in enum}
    mapping = _object(file, field, value, expected)
    return MappingProxyType({key: None if mapping[key] is None else _member(file, f"{field}.{key}", mapping[key], Interaction)
                             for key in sorted(mapping)})


def _interaction_catalog(file: str, document: dict) -> dict[str, Any]:
    _object(file, "file", document, {"schema", "version", "graph_source_classes", "graph_sink_classes",
                                     "prioritization_signals", "callees", "dependency_categories", "boundary_for"})
    signals: dict[tuple[str, str | None], Interaction] = {}
    for index, row in enumerate(_array(file, "prioritization_signals", document["prioritization_signals"])):
        field = f"prioritization_signals[{index}]"
        _object(file, field, row, {"category", "interaction"}, frozenset({"surface"}))
        key = (_text(file, f"{field}.category", row["category"], _KEY),
               _text(file, f"{field}.surface", row["surface"], _KEY) if "surface" in row else None)
        if key in signals:
            _fail(file, field, f"repeats the signal {key[0]}/{key[1]}")
        signals[key] = _member(file, f"{field}.interaction", row["interaction"], Interaction)
    callees: dict[str, Interaction] = {}
    languages: dict[str, tuple[str, ...]] = {}
    for index, row in enumerate(_array(file, "callees", document["callees"])):
        field = f"callees[{index}]"
        _object(file, field, row, {"name", "interaction", "languages"})
        name = _text(file, f"{field}.name", row["name"], _CALLEE)
        if name in callees:
            _fail(file, f"{field}.name", f"repeats the callee {name!r}")
        callees[name] = _member(file, f"{field}.interaction", row["interaction"], Interaction)
        languages[name] = tuple(sorted(_texts(file, f"{field}.languages", row["languages"], allowed=CALLEE_LANGUAGES,
                                              nonempty=True)))
    names: dict[str, str] = {}
    prefixes: dict[str, str] = {}
    for index, row in enumerate(_array(file, "dependency_categories", document["dependency_categories"])):
        field = f"dependency_categories[{index}]"
        _object(file, field, row, {"match", "category"})
        match = _text(file, f"{field}.match", row["match"], _DEPENDENCY_MATCH)
        category = _choice(file, f"{field}.category", row["category"], DEPENDENCY_CATEGORIES)
        table, key = (prefixes, match[:-1]) if match.endswith("*") else (names, match)
        if key in table:
            _fail(file, f"{field}.match", f"repeats the rule {match!r}")
        table[key] = category
    rules = _object(file, "boundary_for", document["boundary_for"], {item.value for item in Interaction})
    boundaries: dict[Interaction, BoundaryRule | None] = {}
    entity_names: dict[str, str] = {}
    for interaction in Interaction:
        field, row = f"boundary_for.{interaction.value}", rules[interaction.value]
        if row is None:
            boundaries[interaction] = None
            continue
        _object(file, field, row, {"boundary_kind", "external_entity", "direction"})
        entity = _object(file, f"{field}.external_entity", row["external_entity"], {"key", "name"})
        key = _text(file, f"{field}.external_entity.key", entity["key"], _KEY)
        name = _text(file, f"{field}.external_entity.name", entity["name"])
        if entity_names.setdefault(key, name) != name:
            _fail(file, f"{field}.external_entity.name", f"the entity {key!r} has two names")
        boundaries[interaction] = BoundaryRule(_member(file, f"{field}.boundary_kind", row["boundary_kind"], BoundaryKind),
                                               key, name, _choice(file, f"{field}.direction", row["direction"], DIRECTIONS))
    return {
        "source_classes": _class_map(file, "graph_source_classes", document["graph_source_classes"], SourceClass),
        "sink_classes": _class_map(file, "graph_sink_classes", document["graph_sink_classes"], SinkClass),
        "signals": MappingProxyType(dict(sorted(signals.items(), key=lambda item: (item[0][0], item[0][1] or "")))),
        "callees": MappingProxyType(dict(sorted(callees.items()))),
        "callee_languages": MappingProxyType(dict(sorted(languages.items()))),
        "dependency_names": MappingProxyType(dict(sorted(names.items()))),
        "dependency_prefixes": tuple(sorted(prefixes.items(), key=lambda item: (-len(item[0]), item[0]))),
        "boundaries": MappingProxyType(boundaries),
    }


def _templates(file: str, document: dict, boundaries: Mapping[Interaction, BoundaryRule | None]
               ) -> tuple[tuple[Template, ...], tuple[Interaction, ...]]:
    _object(file, "file", document, {"schema", "version", "templates", "untemplated"})
    templates: dict[str, Template] = {}
    for index, row in enumerate(_array(file, "templates", document["templates"])):
        field = f"templates[{index}]"
        _object(file, field, row, {"template_id", "stride", "applies_to", "title", "question", "obligations",
                                   "mitigation_evidence"})
        template_id = _text(file, f"{field}.template_id", row["template_id"], _TEMPLATE_ID)
        if template_id in templates:
            _fail(file, f"{field}.template_id", f"repeats the template {template_id!r}")
        applies = _object(file, f"{field}.applies_to", row["applies_to"], {"interaction", "boundary_kind", "direction"})
        interaction = _member(file, f"{field}.applies_to.interaction", applies["interaction"], Interaction)
        kind = _member(file, f"{field}.applies_to.boundary_kind", applies["boundary_kind"], BoundaryKind)
        direction = _choice(file, f"{field}.applies_to.direction", applies["direction"], DIRECTIONS)
        rule = boundaries[interaction]
        if rule is None or (rule.boundary_kind, rule.direction) != (kind, direction):
            _fail(file, f"{field}.applies_to",
                  f"the interaction catalog has no {direction} {kind.value} boundary for {interaction.value}")
        templates[template_id] = Template(
            template_id, _member(file, f"{field}.stride", row["stride"], Stride), interaction, kind, direction,
            _text(file, f"{field}.title", row["title"]), _text(file, f"{field}.question", row["question"]),
            _texts(file, f"{field}.obligations", row["obligations"], nonempty=True),
            _texts(file, f"{field}.mitigation_evidence", row["mitigation_evidence"], allowed=MITIGATION_EVIDENCE_KINDS,
                   nonempty=True))
    untemplated = tuple(_member(file, f"untemplated[{index}]", item, Interaction)
                        for index, item in enumerate(_array(file, "untemplated", document["untemplated"])))
    if len(untemplated) != len(set(untemplated)):
        _fail(file, "untemplated", "repeats a value")
    templated = {item.interaction for item in templates.values()}
    for interaction in Interaction:
        if interaction in templated and interaction in untemplated:
            _fail(file, "untemplated", f"{interaction.value} has templates")
        if interaction not in templated and interaction not in untemplated:
            _fail(file, "untemplated", f"{interaction.value} has no template and is not listed")
    return tuple(templates[key] for key in sorted(templates)), tuple(sorted(untemplated))


def _crosswalk(file: str, document: dict, template_ids: frozenset[str]
               ) -> tuple[Mapping[str, Mapping[str, tuple[str, ...]]], Mapping[str, tuple[str, ...]]]:
    _object(file, "file", document, {"schema", "version", "templates", "unmapped"})
    rows = document["templates"]
    if not isinstance(rows, dict):
        _fail(file, "templates", "must be an object")
    unknown, missing = set(rows) - template_ids, template_ids - set(rows)
    if unknown:
        _fail(file, "templates", f"unknown template ids {sorted(unknown)}")
    if missing:
        _fail(file, "templates", f"templates without a crosswalk row {sorted(missing)}")
    positions = frozenset(item.value for item in AttackerPosition)
    crosswalk: dict[str, Mapping[str, tuple[str, ...]]] = {}
    mapped: dict[str, set[str]] = {catalog: set() for catalog in CROSSWALK_CATALOGS}
    for template_id in sorted(rows):
        field = f"templates.{template_id}"
        row = _object(file, field, rows[template_id], {*CROSSWALK_CATALOGS, "cwe_families", "attacker_positions"})
        entry = {catalog: _texts(file, f"{field}.{catalog}", row[catalog], pattern=pattern)
                 for catalog, pattern in CROSSWALK_CATALOGS.items()}
        for catalog, ids in entry.items():
            mapped[catalog].update(ids)
        entry["cwe_families"] = _texts(file, f"{field}.cwe_families", row["cwe_families"], pattern=_CWE)
        entry["attacker_positions"] = _texts(file, f"{field}.attacker_positions", row["attacker_positions"],
                                             allowed=positions, nonempty=True)
        crosswalk[template_id] = MappingProxyType(entry)
    lists = _object(file, "unmapped", document["unmapped"], set(CROSSWALK_CATALOGS))
    unmapped: dict[str, tuple[str, ...]] = {}
    for catalog, pattern in CROSSWALK_CATALOGS.items():
        unmapped[catalog] = _texts(file, f"unmapped.{catalog}", lists[catalog], pattern=pattern)
        both = mapped[catalog] & set(unmapped[catalog])
        if both:
            _fail(file, f"unmapped.{catalog}", f"{sorted(both)} are mapped by a template")
    return MappingProxyType(crosswalk), MappingProxyType(unmapped)


def load_reference_from(directory: Path) -> Reference:
    """Load and validate the three files from ``directory``."""
    directory = Path(directory)
    catalog_document, catalog_sha256 = _read(directory, INTERACTION_CATALOG_FILE, INTERACTION_CATALOG_SCHEMA)
    templates_document, templates_sha256 = _read(directory, THREAT_TEMPLATES_FILE, THREAT_TEMPLATES_SCHEMA)
    crosswalk_document, crosswalk_sha256 = _read(directory, CROSSWALK_FILE, CROSSWALK_SCHEMA)
    catalog = _interaction_catalog(INTERACTION_CATALOG_FILE, catalog_document)
    templates, untemplated = _templates(THREAT_TEMPLATES_FILE, templates_document, catalog["boundaries"])
    crosswalk, unmapped = _crosswalk(CROSSWALK_FILE, crosswalk_document,
                                     frozenset(item.template_id for item in templates))
    return Reference(
        sha256s=MappingProxyType({"interaction_catalog_sha256": catalog_sha256,
                                  "threat_templates_sha256": templates_sha256,
                                  "crosswalk_sha256": crosswalk_sha256}),
        versions=MappingProxyType({INTERACTION_CATALOG_FILE: catalog_document["version"],
                                   THREAT_TEMPLATES_FILE: templates_document["version"],
                                   CROSSWALK_FILE: crosswalk_document["version"]}),
        templates=templates, untemplated=untemplated, crosswalk=crosswalk, unmapped=unmapped, **catalog)


def load_reference(repository_root: Path) -> Reference:
    """Load the reference data of the checkout at ``repository_root``."""
    return load_reference_from(Path(repository_root) / REFERENCE_DIRECTORY)
