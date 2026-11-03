"""package-slice/2 contract: record shape, registry, and central slice settings."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from appsec_review.config import load_config
from appsec_review.review.packages import PackageSettings
from appsec_review.review.slicing import registry
from appsec_review.review.slicing.contract import (
    Anchor, FunctionSpan, LineKey, PATH_BASIS, Precision, Reason, SLICE_RULE, SliceBudget, SliceContribution,
    SliceLine, SliceResult, StrategyOutcome, StrategyState,
)

ROOT = Path(__file__).parents[2]
SCHEMA = json.loads((ROOT / "docs" / "schemas" / "review-packages.schema.json").read_text(encoding="utf-8"))
SHA = "a" * 64
P1, P2 = "asr:dataflow_path:" + "1" * 64, "asr:dataflow_path:" + "2" * 64
FN = "asr:symbol:" + "3" * 64


def _slice_validator() -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator({"$defs": SCHEMA["$defs"], "$ref": "#/$defs/inference_package_slice"})


def _key(line: int, path: str = "src/a.c") -> LineKey:
    return LineKey(path, SHA, line)


def test_slice_record_is_deterministic_grouped_and_schema_valid() -> None:
    span = FunctionSpan("src/a.c", SHA, 10, 30, function=FN)
    other = FunctionSpan("src/b.c", SHA, 1, 5)
    lines = (SliceLine(_key(20), frozenset({Reason.SINK}), PATH_BASIS, Precision.PATH),
             SliceLine(_key(12), frozenset({Reason.BACKWARD_DEF, Reason.INTERACTER}), "lexical_identifiers",
                       Precision.LEXICAL),
             SliceLine(_key(3, "src/b.c"), frozenset({Reason.SOURCE}), PATH_BASIS, Precision.PATH))
    result = SliceResult(functions=(other, span), lines=lines,
                         strategies=(StrategyOutcome("lexical_identifiers", Precision.LEXICAL, StrategyState.APPLIED, 1),
                                     StrategyOutcome("llvm_ir_def_use", Precision.COMPILER,
                                                     StrategyState.NOT_APPLICABLE, 0,
                                                     ("slice_strategy_not_applicable: llvm_ir_def_use: no ir",))),
                         omitted_lines=2, gaps=("slice_truncated: x", "slice_truncated: x"), paths=(P2, P1))
    record = result.record()
    _slice_validator().validate(record)
    assert record["rule"] == SLICE_RULE and record["paths"] == [P1, P2]
    assert [item["path"] for item in record["functions"]] == ["src/a.c", "src/b.c"]
    assert [item["line"] for item in record["functions"][0]["lines"]] == [12, 20]
    assert record["functions"][0]["lines"][0]["reasons"] == ["backward_def", "interacter"]
    assert record["gaps"] == ["slice_truncated: x"] and record["omitted"] == {"lines": 2}
    assert json.dumps(record, sort_keys=True) == json.dumps(
        SliceResult(functions=(span, other), lines=tuple(reversed(lines)), strategies=result.strategies,
                    omitted_lines=2, gaps=result.gaps, paths=result.paths).record(), sort_keys=True)


def test_slice_record_rejects_a_line_outside_every_function() -> None:
    result = SliceResult(functions=(FunctionSpan("src/a.c", SHA, 1, 5),),
                         lines=(SliceLine(_key(9), frozenset({Reason.SINK}), PATH_BASIS, Precision.PATH),),
                         strategies=())
    with pytest.raises(ValueError, match="outside every function span"):
        result.record()


def test_contract_values_reject_invalid_inputs() -> None:
    with pytest.raises(ValueError):
        LineKey("src/a.c", SHA, 0)
    with pytest.raises(ValueError):
        Anchor(_key(1), Reason.INTERACTER, "ref")
    with pytest.raises(ValueError, match="must name a gap"):
        SliceContribution("x", Precision.LEXICAL, StrategyState.NOT_APPLICABLE)
    with pytest.raises(ValueError, match="must name a gap"):
        SliceContribution("x", Precision.LEXICAL, StrategyState.PARTIAL,
                          (SliceLine(_key(1), frozenset({Reason.INTERACTER}), "x", Precision.LEXICAL),))
    with pytest.raises(ValueError, match="contributes no lines"):
        SliceContribution("x", Precision.LEXICAL, StrategyState.FAILED,
                          (SliceLine(_key(1), frozenset({Reason.INTERACTER}), "x", Precision.LEXICAL),), ("g",))
    with pytest.raises(ValueError):
        SliceBudget(max_lines=10, max_lines_per_function=11)
    assert Precision.COMPILER > Precision.SYNTAX > Precision.LEXICAL and Precision.PATH.label == "path"


def test_registry_validates_configured_names() -> None:
    assert registry.validate_names(list(registry.DEFAULT_STRATEGIES)) == registry.DEFAULT_STRATEGIES
    assert set(registry.DEFAULT_STRATEGIES) == set(registry.STRATEGIES)
    for bad, message in (((), "at least one"), (("lexical_identifiers", "lexical_identifiers"), "repeat"),
                         (("joern_slice",), "unknown strategies")):
        with pytest.raises(ValueError, match=message):
            registry.validate_names(bad)
    with pytest.raises(KeyError):
        registry.load("joern_slice")


def test_central_toml_configures_the_slice_and_package_settings_carry_it(tmp_path: Path) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    packages = PackageSettings.from_review_settings(config.job("job_inference_security_review").typed_settings)
    assert packages.slice_strategies == registry.DEFAULT_STRATEGIES
    assert packages.slice_budget == SliceBudget(120, 40)
    assert packages.record()["slice_strategies"] == list(registry.DEFAULT_STRATEGIES)
    assert PackageSettings.from_mapping({"slice_strategies": ["lexical_identifiers"]}).slice_strategies == (
        "lexical_identifiers",)
    with pytest.raises(ValueError, match="unknown strategies"):
        PackageSettings(slice_strategies=("nope",))
    with pytest.raises(ValueError, match="must not exceed"):
        PackageSettings(max_slice_lines=10, max_slice_lines_per_function=20)

    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    for old, new, message in (
            ('slice_strategies = ["llvm_ir_def_use"', 'slice_strategies = ["joern", "llvm_ir_def_use"',
             "unknown strategies"),
            ("max_slice_lines_per_function = 40", "max_slice_lines_per_function = 400", "max_slice_lines_per_function")):
        assert old in source
        path = tmp_path / message / "appsec-review.toml"
        path.parent.mkdir(parents=True)
        path.write_text(source.replace(old, new, 1), encoding="utf-8")
        with pytest.raises(Exception, match=message):
            load_config(path)
