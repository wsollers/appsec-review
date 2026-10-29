from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.acceptance.staging import (
    STAGE_ENVIRONMENT, SeedInputs, StageContext, StageDeclaration, StageKind, stage_context,
)


def test_seed_inputs_pin_source_and_configuration_without_rewriting_paths() -> None:
    selected = SeedInputs("ci-positive", ("target", "appsec-review.toml", "runs/example/data/configuration"))
    assert SeedInputs.from_mapping(selected.record()) == selected
    for paths in ((), ("target", "target"), ("../target",), ("/target",), ("C:/target",), ("a\\b",)):
        with pytest.raises(ValueError):
            SeedInputs("ci-positive", paths)


def context(tmp_path: Path) -> StageContext:
    return StageContext(
        StageKind.PRODUCER, "ci-positive", "ci-review", "acceptance-example", "1" * 40,
        {"tests/fixture.py": "2" * 64}, tmp_path.resolve(), tmp_path.resolve() / "producer")


def test_stage_declaration_has_explicit_closed_identity() -> None:
    declaration = StageDeclaration.from_mapping({
        "kind": "producer", "variant": "ci-positive", "depends_on": ["ci-review"], "seals": True})
    assert declaration == StageDeclaration(StageKind.PRODUCER, "ci-positive", ("ci-review",), True)
    assert StageDeclaration.from_mapping({
        "kind": "consumer", "variant": "ci-positive", "depends_on": ["ci-report"]}).kind is StageKind.CONSUMER


@pytest.mark.parametrize("value", [
    {"kind": "unknown", "variant": "ci"},
    {"kind": "producer", "variant": "../ci"},
    {"kind": "producer", "variant": "ci", "depends_on": "review"},
    {"kind": "producer", "variant": "ci", "depends_on": ["review", "gate"]},
    {"kind": "producer", "variant": "ci", "seals": 1},
    {"kind": "consumer", "variant": "ci"},
    {"kind": "consumer", "variant": "ci", "depends_on": ["report"], "seals": True},
    {"kind": "producer", "variant": "ci", "fallback": "last-good"},
])
def test_invalid_stage_declarations_fail_explicitly(value) -> None:
    with pytest.raises(ValueError):
        StageDeclaration.from_mapping(value)


def test_stage_context_round_trip_pins_supervisor_identity(tmp_path: Path) -> None:
    selected = context(tmp_path)
    environment = {
        STAGE_ENVIRONMENT: json.dumps(selected.record()),
        "APPSEC_ACCEPTANCE_ROOT": str(tmp_path.resolve()),
        "APPSEC_ACCEPTANCE_INVOCATION": selected.invocation_id,
        "APPSEC_ACCEPTANCE_TESTED_COMMIT": selected.tested_commit,
    }
    assert stage_context(environment) == selected
    assert stage_context({}) is None
    for key in ("APPSEC_ACCEPTANCE_INVOCATION", "APPSEC_ACCEPTANCE_TESTED_COMMIT"):
        changed = dict(environment, **{key: "changed"})
        with pytest.raises(ValueError):
            stage_context(changed)


def test_consumer_requires_independent_copy_and_exact_seal(tmp_path: Path) -> None:
    producer = context(tmp_path)
    consumer = replace(
        producer, kind=StageKind.CONSUMER, work_root=tmp_path.resolve() / "consumer",
        seed_root=producer.work_root, manifest_path=tmp_path.resolve() / "sealed.json",
        manifest_sha256="3" * 64)
    assert StageContext.from_mapping(consumer.record()) == consumer
    with pytest.raises(ValueError, match="independent"):
        replace(consumer, work_root=producer.work_root / "copy")
    with pytest.raises(ValueError, match="sealed"):
        replace(consumer, manifest_sha256="wrong")
    with pytest.raises(ValueError, match="descendants"):
        replace(consumer, seed_root=tmp_path.resolve().parent / "other-invocation")


def test_producer_cannot_claim_consumer_seed_or_unpinned_sources(tmp_path: Path) -> None:
    selected = context(tmp_path)
    with pytest.raises(ValueError, match="sealed input"):
        replace(selected, seed_root=tmp_path.resolve() / "foreign")
    with pytest.raises(ValueError, match="pinned source"):
        replace(selected, source_identities={})
    with pytest.raises(ValueError, match="fields"):
        StageContext.from_mapping(dict(selected.record(), extra=True))
