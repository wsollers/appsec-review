"""The versioned source/sink catalog ``appsec-review/graph-catalog/1`` (code-graph chunk C3).

``rules/codeql-graph-export/catalog.json`` classifies CodeQL graph-export ``sink_sites`` and
``source_sites`` rows into the closed ``SinkClass``/``SourceClass`` vocabularies of
``graph/contract.py`` (docs/architecture/code-graph-precomputation.md section 3.2 and
``rules/codeql-graph-export/README.md`` "Catalog semantics"). This module loads and validates the
catalog against ``catalog.schema.json`` and the contract, and classifies one export row.

Classification of one row tries, in order: API rules (``api``, the index and any comma-separated
``declared_in`` basename equal), model rules with ``source_type`` (sources only), model-only rules.
Within a tier the first rule in file order wins. A row no rule matches is ``unclassified`` and is
never direct-eligible. :attr:`Classification.rank` orders competing rows for one sink or source key:
the lower rank (earlier tier, then earlier rule) is kept.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from appsec_review.application_paths import application_root
from appsec_review.graph.contract import (
    ATTACKER_REACHABLE_SOURCES,
    CATALOG_SCHEMA,
    SinkClass,
    SourceClass,
)

RULES_ROOT = application_root("rules/codeql-graph-export/catalog.schema.json") / "rules" / "codeql-graph-export"
CATALOG_PATH = RULES_ROOT / "catalog.json"
CATALOG_SCHEMA_PATH = RULES_ROOT / "catalog.schema.json"

TIER_API = 1
TIER_MODEL_SOURCE_TYPE = 2
TIER_MODEL = 3
TIER_UNCLASSIFIED = 4
BASIS_API = "catalog-api"
BASIS_MODEL = "codeql-model"

# CodeQL scope language names that share one catalog language section.
LANGUAGE_ALIASES: Mapping[str, str] = {"cpp": "cpp", "c": "cpp", "c++": "cpp", "c/c++": "cpp"}


class CatalogError(ValueError):
    """The graph catalog violates its schema or the shared contract."""


@dataclass(frozen=True, slots=True)
class Classification:
    """The winning catalog rule for one row, or ``unclassified``."""

    klass: str
    rule_id: str | None
    tier: int
    position: int
    cwe_family: str | None = None

    @property
    def rank(self) -> tuple[int, int]:
        return self.tier, self.position

    @property
    def classified(self) -> bool:
        return self.rule_id is not None

    @property
    def basis(self) -> str:
        return BASIS_API if self.tier == TIER_API else BASIS_MODEL


def _declared(value: Any) -> frozenset[str]:
    return frozenset(item.strip() for item in str(value or "").split(",") if item.strip())


@dataclass(frozen=True, slots=True)
class LanguageCatalog:
    language: str
    model_library: str
    sinks: tuple[Mapping[str, Any], ...]
    sources: tuple[Mapping[str, Any], ...]
    sanitizers: tuple[Mapping[str, Any], ...]

    @property
    def sanitizer_apis(self) -> frozenset[str]:
        return frozenset(str(rule["api"]) for rule in self.sanitizers)

    def _classify(self, rules: tuple[Mapping[str, Any], ...], row: Mapping[str, Any], *, index_key: str,
                  class_key: str, unclassified: str) -> Classification:
        api = str(row.get("api") or "")
        declared = _declared(row.get("declared_in"))
        model = str(row.get("model") or "")
        source_type = str(row.get("source_type") or "")
        tiers: list[tuple[int, list[tuple[int, Mapping[str, Any]]]]] = [
            (TIER_API, [(position, rule) for position, rule in enumerate(rules)
                        if "api" in rule["match"] and api and rule["match"]["api"] == api
                        and rule["match"][index_key] == row.get(index_key)
                        and declared & set(rule["match"]["declared_in"])]),
            (TIER_MODEL_SOURCE_TYPE, [(position, rule) for position, rule in enumerate(rules)
                                      if "source_type" in rule["match"] and rule["match"]["model"] == model
                                      and rule["match"]["source_type"] == source_type]),
            (TIER_MODEL, [(position, rule) for position, rule in enumerate(rules)
                          if set(rule["match"]) == {"model"} and rule["match"]["model"] == model]),
        ]
        for tier, matches in tiers:
            if matches:
                position, rule = matches[0]
                return Classification(str(rule[class_key]), str(rule["rule_id"]), tier, position,
                                      str(rule["cwe_family"]) if "cwe_family" in rule else None)
        return Classification(unclassified, None, TIER_UNCLASSIFIED, 0)

    def classify_sink(self, row: Mapping[str, Any]) -> Classification:
        """Classify one ``sink_sites`` row (keys ``api``, ``declared_in``, ``argument_index``, ``model``)."""
        return self._classify(self.sinks, row, index_key="argument_index", class_key="sink_class",
                              unclassified=SinkClass.UNCLASSIFIED.value)

    def classify_source(self, row: Mapping[str, Any]) -> Classification:
        """Classify one ``source_sites`` row (keys ``api``, ``declared_in``, ``index``, ``model``, ``source_type``)."""
        return self._classify(self.sources, row, index_key="index", class_key="source_class",
                              unclassified=SourceClass.UNCLASSIFIED.value)


@dataclass(frozen=True, slots=True)
class Catalog:
    schema: str
    revision: int
    sha256: str
    attacker_reachable_sources: frozenset[str]
    languages: Mapping[str, LanguageCatalog]

    @property
    def version(self) -> str:
        return self.schema

    def language(self, name: str) -> LanguageCatalog:
        key = LANGUAGE_ALIASES.get(str(name).strip().lower())
        if key is None or key not in self.languages:
            raise CatalogError(f"the graph catalog has no section for language {name!r}")
        return self.languages[key]


def _unique(values: list[str], what: str) -> None:
    if len(values) != len(set(values)):
        raise CatalogError(f"graph catalog has duplicate {what}")


def validate_catalog(document: Mapping[str, Any], schema: Mapping[str, Any] | None = None) -> None:
    """Check the catalog against ``catalog.schema.json`` and the shared contract."""
    if schema is None:
        schema = json.loads(CATALOG_SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        Draft202012Validator(schema).validate(document)
    except ValidationError as error:
        raise CatalogError(f"graph catalog violates its schema: {error.message}") from error
    if document["schema"] != CATALOG_SCHEMA:
        raise CatalogError("graph catalog schema identity differs from the contract")
    if set(document["attacker_reachable_sources"]) != {value.value for value in ATTACKER_REACHABLE_SOURCES}:
        raise CatalogError("graph catalog attacker_reachable_sources differ from the contract")
    rule_ids: list[str] = []
    for language in document["languages"].values():
        for kind in ("sinks", "sources", "sanitizers"):
            rule_ids.extend(str(rule["rule_id"]) for rule in language[kind])
        for kind in ("sinks", "sources"):
            _unique([json.dumps(rule["match"], sort_keys=True) for rule in language[kind]], f"{kind} matches")
    _unique(rule_ids, "rule ids")


def parse_catalog(data: bytes, schema: Mapping[str, Any] | None = None) -> Catalog:
    """Validate and load catalog bytes; the result carries their SHA-256."""
    document = json.loads(data.decode("utf-8"))
    if not isinstance(document, Mapping):
        raise CatalogError("graph catalog must be a JSON object")
    validate_catalog(document, schema)
    languages = {
        name: LanguageCatalog(name, str(section["model_library"]), tuple(section["sinks"]), tuple(section["sources"]),
                              tuple(section["sanitizers"]))
        for name, section in sorted(document["languages"].items())}
    return Catalog(str(document["schema"]), int(document["revision"]), hashlib.sha256(data).hexdigest(),
                   frozenset(document["attacker_reachable_sources"]), languages)


def load_catalog(path: Path | None = None, schema_path: Path | None = None) -> Catalog:
    """Load and validate the repository catalog (or the one at ``path``)."""
    schema = json.loads((schema_path or CATALOG_SCHEMA_PATH).read_text(encoding="utf-8"))
    return parse_catalog((path or CATALOG_PATH).read_bytes(), schema)


__all__ = ["CATALOG_PATH", "CATALOG_SCHEMA_PATH", "Catalog", "CatalogError", "Classification", "LanguageCatalog",
           "load_catalog", "parse_catalog", "validate_catalog"]
