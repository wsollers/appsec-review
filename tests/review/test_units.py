from __future__ import annotations

from pathlib import Path
import random

import pytest

from appsec_review.review.lead_families import collect_leads
from appsec_review.review.packages import PackageSettings, assemble_packages
from appsec_review.review.scope import accept_manifest
from appsec_review.review.units import CUTOFF_REASON, build_units, rank_units, select_hunts
from tests.fixtures.inference_review.builder import build_accepted_index_set


NATIVE = "unit:component:0002:-:native-main:r0000"
SVC = "unit:component:0001:-:py-svc:r0000"


@pytest.fixture(scope="module")
def scope(tmp_path_factory):
    return accept_manifest(build_accepted_index_set(tmp_path_factory.mktemp("units")).run_root)


def _signals(unit) -> dict:
    return {item.signal: item for item in unit.signals}


def test_units_follow_component_build_unit_and_entity_range(scope) -> None:
    units = build_units(scope, collect_leads(scope), unit_max_files=200)
    assert [unit.key for unit in units] == [
        "unit:component:0001:-:py-svc:r0000", "unit:component:0002:-:native-main:r0000",
        "unit:unassigned:-:-:r0000", "unit:unassigned:-:-:unlocated"]
    native = next(unit for unit in units if unit.key == NATIVE)
    assert native.paths == ("native/src/io.c", "native/src/parse.c")
    assert native.trust_boundary_id is None
    ranged = build_units(scope, collect_leads(scope), unit_max_files=1)
    assert [unit.key for unit in ranged if unit.component_id == "component:0002"] == [
        "unit:component:0002:-:native-main:r0000", "unit:component:0002:-:native-main:r0001"]
    assert sorted(lead for unit in ranged for lead in unit.lead_ids) == sorted(
        lead for unit in units for lead in unit.lead_ids)


def test_rank_is_deterministic_and_records_its_basis(scope) -> None:
    units = build_units(scope, collect_leads(scope), unit_max_files=200)
    ranked = rank_units(units)
    shuffled = list(units)
    random.Random(3).shuffle(shuffled)
    assert rank_units(shuffled) == ranked
    assert [item.unit.key for item in ranked][:2] == [NATIVE, SVC]
    native = _signals(ranked[0].unit)
    assert (native["lps"].value, native["sii"].value, native["hotspot"].value) == (550, 900, 800)
    assert native["tag_density"].value == 125 and native["lead_hints"].value == 0
    svc = _signals(ranked[1].unit)
    assert svc["lead_hints"].value == 160  # one medium SAST hint, one low SAST and one low advisory hint
    assert (svc["sii"].value, svc["sii"].state, svc["sii"].reason) == (None, "unknown", "no_record")
    record = ranked[0].rank_record()
    assert record["position"] == 1 and record["unit_count"] == 4
    assert [item["signal"] for item in record["basis"]] == ["lps", "sii", "hotspot", "tag_density", "lead_hints"]


def test_missing_signal_producers_are_unknown_not_zero(tmp_path: Path) -> None:
    scope = accept_manifest(build_accepted_index_set(tmp_path, omit=("priority", "history", "tags")).run_root)
    units = build_units(scope, collect_leads(scope), unit_max_files=200)
    for unit in units:
        signals = _signals(unit)
        for name in ("lps", "sii", "hotspot", "tag_density"):
            assert signals[name].value is None and signals[name].state == "unknown"
            assert signals[name].reason == "producer_unavailable"
    ranked = rank_units(units)
    assert ranked[0].rank_record()["basis"][0] == {"signal": "lps", "value": None, "state": "unknown",
                                                   "reason": "producer_unavailable"}
    assert ranked[0].unit.key == SVC  # only lead hints remain known


def test_units_below_cutoff_become_named_gaps(scope) -> None:
    ranked = rank_units(build_units(scope, collect_leads(scope), unit_max_files=200))
    hunted, gaps = select_hunts(ranked, 1)
    assert [item.unit.key for item in hunted] == [NATIVE]
    assert sorted(gap.scope for gap in gaps) == sorted(item.unit.key for item in ranked[1:])
    assert all(gap.state == "skipped" and gap.reason.startswith(CUTOFF_REASON) for gap in gaps)

    assembly = assemble_packages(scope, PackageSettings(hunt_max_units=1))
    hunts = [item for item in assembly.packages if item.kind == "hunt"]
    assert {item.unit_key for item in hunts} == {NATIVE}
    assert assembly.manifest["counts"]["units"] == {"total": 4, "hunted": 1, "below_cutoff": 3}
    assert sum(1 for gap in assembly.manifest["gaps"] if gap["reason"].startswith(CUTOFF_REASON)) == 3
    assert [item["hunted"] for item in assembly.manifest["units"]] == [True, False, False, False]
    document = hunts[0].document()
    assert document["rank"]["position"] == 1 and document["lane"] == "hunt"
    assert {entry["role"] for entry in document["context"]} >= {"priority", "history", "hotspot", "tag",
                                                               "component", "build_unit"}
    # Lane A is unaffected by the hunt cutoff.
    assert assembly.manifest["audit"]["lane_a"]["expected"] == 9
