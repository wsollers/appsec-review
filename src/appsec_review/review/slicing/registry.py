"""Slice strategy registry: configured names -> strategy factories.

The central TOML names the strategies (``packages.slice_strategies``) in documentation order; the composer
runs all of them and unions their lines, so the order only affects the record, not which line wins (a
line keeps its highest-precision basis). Add a strategy by implementing ``SliceStrategy`` in
``review.slicing.strategies`` and registering its name here; an unknown configured name fails
configuration validation.
"""
from __future__ import annotations

from importlib import import_module

from appsec_review.review.slicing.contract import SliceStrategy

# name -> "module:factory". Imported lazily so the contract does not depend on strategy implementations.
STRATEGIES: dict[str, str] = {
    "llvm_ir_def_use": "appsec_review.review.slicing.strategies.llvm_ir:LlvmIrDefUse",
    "svf_points_to": "appsec_review.review.slicing.strategies.svf:SvfPointsTo",
    "tree_sitter_references": "appsec_review.review.slicing.strategies.tree_sitter:TreeSitterReferences",
    "lexical_identifiers": "appsec_review.review.slicing.strategies.lexical:LexicalIdentifiers",
}
# Default: compiler facts, then syntax, then the lexical fallback (docs/architecture/review-protocol-v2.md
# section 4). Expected to change; it is configuration, not code.
DEFAULT_STRATEGIES: tuple[str, ...] = ("llvm_ir_def_use", "svf_points_to", "tree_sitter_references",
                                       "lexical_identifiers")


def validate_names(names: tuple[str, ...] | list[str], field: str = "slice_strategies") -> tuple[str, ...]:
    names = tuple(names)
    if not names:
        raise ValueError(f"{field} must name at least one strategy")
    if any(not isinstance(name, str) for name in names):
        raise ValueError(f"{field} entries must be strings")
    if len(set(names)) != len(names):
        raise ValueError(f"{field} must not repeat a strategy")
    unknown = sorted(set(names) - set(STRATEGIES))
    if unknown:
        raise ValueError(f"{field} names unknown strategies {unknown}; known: {sorted(STRATEGIES)}")
    return names


def load(name: str) -> SliceStrategy:
    if name not in STRATEGIES:
        raise KeyError(f"unknown slice strategy {name!r}")
    module, attribute = STRATEGIES[name].split(":", 1)
    strategy = getattr(import_module(module), attribute)()
    if strategy.name != name or not isinstance(strategy, SliceStrategy):
        raise TypeError(f"slice strategy {name!r} does not implement the SliceStrategy contract")
    return strategy


def load_all(names: tuple[str, ...]) -> tuple[SliceStrategy, ...]:
    return tuple(load(name) for name in validate_names(names))


__all__ = ["DEFAULT_STRATEGIES", "STRATEGIES", "load", "load_all", "validate_names"]
