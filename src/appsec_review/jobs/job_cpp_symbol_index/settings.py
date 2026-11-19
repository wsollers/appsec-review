"""Declared clangd index bounds, without coercion or undeclared upper limits."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class CppSymbolIndexSettings:
    workers: int
    max_documents_per_scope: int
    max_symbols_per_scope: int
    max_relations_per_scope: int
    locations_per_relation: int

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"job_cpp_symbol_index.settings.{field.name} must be a positive integer")

    @classmethod
    def from_mapping(cls, settings: Mapping[str, Any]) -> CppSymbolIndexSettings:
        names = {field.name for field in fields(cls)}
        unknown = set(settings) - names - {"enabled", "source_dispositions"}
        if unknown:
            raise ValueError(f"unknown job_cpp_symbol_index settings: {sorted(unknown)}")
        return cls(**{name: settings.get(name) for name in sorted(names)})

    def limits(self) -> dict[str, int]:
        return asdict(self)
