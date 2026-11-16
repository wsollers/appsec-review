"""The hunting campaign plan: bounded brief, honest validation, clamping, fallback and plan-ordered selection."""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
from pathlib import Path
import re
from typing import Any

import pytest

from appsec_review.config.inference_review import ModelProfileSettings
from appsec_review.inference import ModelResult
from appsec_review.inference.errors import ProviderError
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review import hunt_plan
from appsec_review.review.hunt_plan import (
    ARTIFACT_SCHEMA, BRIEF_SCHEMA, RESULT_SCHEMA, Brief, BriefInputs, EntryFact, FileFact, FunctionFact,
    HuntSelection, PlannerGuidance, UnitFact, build_brief, run_planner, selection_from_document, validate_plan,
)
from appsec_review.review.hunt_plan_settings import BriefBounds, HuntingSettings
from appsec_review.review.units import RankedUnit, ReviewUnit

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = SchemaSet(ROOT / "docs" / "schemas" / "inference-security-review")
PROFILE = ModelProfileSettings("claude-cli", "claude-sonnet-5-5", "high", 128_000, 32_000, 0, 2, 60)
GUIDANCE = PlannerGuidance({"sha256": "a" * 64}, "bounded planner guidance")
SETTINGS = HuntingSettings(enabled=True, agents=3, max_areas=4, planner_profile="planner")
SHA = "1" * 64


def _identity(kind: str, number: int) -> str:
    return f"asr:{kind}:{number:064x}"


def inputs(*, functions: int = 5, files: int = 3) -> BriefInputs:
    paths = ["src/net/server.cpp", "src/parse/packet.cpp", "src/util/log.cpp", "src/extra/a.cpp", "src/extra/b.cpp"][:files]
    file_facts = tuple(FileFact(path, _identity("source_file", index), "C++", "component:0001",
                                1000 - 100 * index, None, 2 if index == 0 else 0, 1 if index == 1 else 0, index,
                                ("exposure:client-facing",) if index == 0 else (), ("capec:88",) if index == 0 else ())
                       for index, path in enumerate(paths))
    # Functions are spread over the files in index order (fn_0, fn_1 in the first file, ...), so the brief's N labels,
    # which follow (path, line) order, are N1 = fn_0, N2 = fn_1 and so on.
    function_facts = tuple(FunctionFact(_identity("symbol", index), f"fn_{index}", paths[min(index * files // functions, files - 1)],
                                        10 * index + 1, sinks=1 if index % 2 else 0, entries=1 if index < 2 else 0, leads=0)
                           for index in range(functions))
    entries = (EntryFact(_identity("entry_point", 1), paths[0], 1, "remote", "recv output argument", _identity("symbol", 0)),
               EntryFact(_identity("entry_point", 2), paths[0], 2, "argv", "**argv", None))
    units = (UnitFact("unit:component:0001:-:bu:r0000", 2, 700, tuple(paths), None, 3, True),
             UnitFact("unit:component:0001:-:bu:operation-1", 1, 900, (paths[0],), (paths[0], 1, 20), 2, True))
    return BriefInputs("2026-11-16-0005", SHA, (("component:0001", "."),), {"C++": files}, (("bu", ("C++",)),),
                       file_facts, function_facts, entries, units, ("code_graph: partial",))


def brief(**kwargs: Any) -> Brief:
    bounds = kwargs.pop("bounds", BriefBounds())
    return build_brief(inputs(**kwargs), bounds, agents=SETTINGS.agents, max_areas=SETTINGS.max_areas, hunt_max_units=10)


def plan(areas: list[dict[str, Any]], unassigned: list[dict[str, Any]] | None = None, gaps: list[str] | None = None) -> dict:
    return {"schema": RESULT_SCHEMA, "areas": areas, "unassigned": unassigned or [], "gaps": gaps or []}


def area(area_id: str, priority: int, agents: int, *, files=(), functions=(), entry_points=(), classes=("memory_corruption",)) -> dict:
    return {"area_id": area_id, "title": area_id.title(), "mission": f"Hunt {area_id}.", "weakness_classes": list(classes),
            "priority": priority, "agents": agents, "files": list(files), "functions": list(functions),
            "entry_points": list(entry_points), "rationale": f"because {area_id}"}


# ------------------------------------------------------------------------------------------------ brief

def test_brief_is_bounded_deterministic_and_carries_only_names_and_lines() -> None:
    first, second = brief(), brief()
    assert first.document == second.document and first.sha256 == second.sha256
    document = first.document
    assert document["schema"] == BRIEF_SCHEMA and document["budget"] == {"agents": 3, "max_areas": 4, "hunt_max_units": 10}
    assert [row["id"] for row in document["files"]] == ["F1", "F2", "F3"]
    assert document["files"][0]["path"] == "src/net/server.cpp" and document["files"][0]["entry_points"] == 2
    assert document["files"][0]["leads"] == {"admitted": 2, "excluded": 0, "other": 0}
    assert [row["id"] for row in document["functions"]] == ["N1", "N2", "N3", "N4", "N5"]
    assert document["entry_points"][0] == {"id": "E1", "file": "F1", "line": 1, "class": "remote", "function": "N1",
                                           "display": "recv output argument"}
    assert document["candidate_units"][0]["lines"] == [1, 20] and document["candidate_units"][1]["files"] == ["F1", "F2", "F3"]
    assert document["omitted"] == {"files": 0, "files_without_signal": 0, "functions": 0, "entry_points": 0,
                                   "lead_density_rows": 0}
    assert set(document["answer"]["weakness_classes"]) >= {"memory_corruption", "injection", "other"}
    # No target text: every string of the brief is a path, a name, a class, a tag, an id or the fixed notice.
    text = json.dumps(document)
    assert "scanner message" not in text and "int main" not in text
    assert SCHEMAS.errors("hunting-campaign-plan", {"schema": RESULT_SCHEMA, "areas": [], "unassigned": [], "gaps": []}) == []


def test_brief_bounds_truncate_by_priority_and_count_the_omissions() -> None:
    bounded = brief(functions=12, files=5, bounds=BriefBounds(max_functions=4, max_files=2, max_leads=1))
    document = bounded.document
    # The entry-point file comes first; files are then ordered by complexity points.
    assert [row["path"] for row in document["files"]] == ["src/net/server.cpp", "src/parse/packet.cpp"]
    assert len(document["functions"]) == 4 and all(row["file"] in {"F1", "F2"} for row in document["functions"])
    assert document["omitted"]["files"] == 3 and document["omitted"]["functions"] == 12 - 4
    assert len(document["lead_density"]) == 1 and document["omitted"]["lead_density_rows"] == 1
    assert bounded.counts["omitted_files"] == 3
    # Labels are stable: the same inputs and bounds give the same label for the same function.
    assert bounded.functions["N1"].identity == brief(functions=12, files=5, bounds=BriefBounds(4, 2, 1)).functions["N1"].identity


# ------------------------------------------------------------------------------------------- validation

def test_complete_plan_validates_resolves_labels_and_renumbers_priorities() -> None:
    current = brief()
    proposal = plan([area("decoders", 5, 1, files=["F2"], functions=["N3", "N4"]),
                     area("ingress", 2, 2, files=["F1"], functions=["N1", "N2"], entry_points=["E1", "E2"])],
                    unassigned=[{"id": "N5", "reason": "logging helper"}], gaps=["no hotspot points"])
    validated, errors = validate_plan(proposal, current, SETTINGS, schemas=SCHEMAS, salvage=False)
    assert errors == [] and validated is not None
    assert [item["area_id"] for item in validated.areas] == ["ingress", "decoders"]
    assert [item["priority"] for item in validated.areas] == [1, 2]
    assert validated.areas[0]["requested_priority"] == 2 and validated.areas[0]["status"] == "reached"
    assert validated.areas[0]["functions"][0] == {"id": "N1", "identity": _identity("symbol", 0), "name": "fn_0",
                                                   "path": "src/net/server.cpp", "line": 1}
    assert validated.areas[0]["entry_points"][1]["identity"] == _identity("entry_point", 2)
    assert validated.unassigned == ({"id": "N5", "identity": _identity("symbol", 4), "path": "src/util/log.cpp",
                                     "line": 41, "reason": "logging helper"},)
    assert validated.gaps == ("no hotspot points",) and validated.notes == ()


def test_unknown_identities_omissions_and_double_assignments_are_refused_then_salvaged() -> None:
    current = brief()
    proposal = plan([area("ingress", 1, 1, files=["F1", "F9"], functions=["N1", "N2", "N9"], entry_points=["E1", "E2"]),
                     area("decoders", 2, 1, files=["F2"], functions=["N2", "N4"])],
                    unassigned=[{"id": "N7", "reason": "unknown"}, {"id": "N4", "reason": "also assigned"}])
    validated, errors = validate_plan(proposal, current, SETTINGS, schemas=SCHEMAS, salvage=False)
    assert validated is None
    joined = "\n".join(errors)
    assert "F9, which is not an id" in joined and "N9, which is not an id" in joined
    assert "N2 is assigned to both ingress and decoders" in joined
    assert "N7, which is not an id" in joined and "N4 is both assigned to decoders and listed as unassigned" in joined
    assert "N3 is neither in an area nor in unassigned" in joined and "N5 is neither" in joined
    salvaged, errors = validate_plan(proposal, current, SETTINGS, schemas=SCHEMAS, salvage=True)
    assert errors == [] and salvaged is not None
    by_id = {item["area_id"]: item for item in salvaged.areas}
    assert [item["id"] for item in by_id["ingress"]["files"]] == ["F1"]
    assert [item["id"] for item in by_id["ingress"]["functions"]] == ["N1", "N2"]
    assert [item["id"] for item in by_id["decoders"]["functions"]] == ["N4"]
    assert {item["id"] for item in salvaged.unassigned} == {"N3", "N5"}
    assert all(item["reason"].startswith("planner_omitted") for item in salvaged.unassigned)
    assert any("files reference F9" in note and "dropped" in note for note in salvaged.notes)
    assert any("N2 assigned to areas ingress and decoders; kept in ingress" in note for note in salvaged.notes)
    assert any("2 brief ids the plan omitted" in note for note in salvaged.notes)
    # Both areas survived the salvage: a bad reference drops the reference, never the area.
    assert set(by_id) == {"ingress", "decoders"}


def test_agents_are_clamped_and_areas_beyond_the_budget_or_cap_are_not_reached() -> None:
    current = brief()
    proposal = plan([area("a", 1, 2, functions=["N1"]), area("b", 2, 2, functions=["N2"]), area("c", 3, 1, functions=["N3"]),
                     area("d", 4, 1, functions=["N4"]), area("e", 5, 1, functions=["N5"], files=["F3"])],
                    unassigned=[{"id": "E1", "reason": "x"}, {"id": "E2", "reason": "y"}])
    validated, errors = validate_plan(proposal, current, SETTINGS, schemas=SCHEMAS, salvage=False)
    assert errors == [] and validated is not None
    assert [(item["area_id"], item["agents"], item["status"]) for item in validated.areas] == [
        ("a", 2, "reached"), ("b", 1, "reached"), ("c", 0, "not_reached"), ("d", 0, "not_reached"), ("e", 0, "not_reached")]
    assert validated.areas[1]["requested_agents"] == 2
    assert sum(item["agents"] for item in validated.areas) == SETTINGS.agents
    assert any("area b asked for 2 agents and receives 1" in note for note in validated.notes)
    assert any("area e asked for 1 agents and receives 0" in note for note in validated.notes)
    # The not_reached areas keep their function lists: they are the named gaps.
    assert validated.areas[4]["functions"][0]["name"] == "fn_4" and validated.areas[4]["files"][0]["path"] == "src/util/log.cpp"


@pytest.mark.parametrize("proposal,fragment", [
    ({"schema": RESULT_SCHEMA, "areas": [{"area_id": "x"}], "unassigned": [], "gaps": []}, "missing required property"),
    (plan([area("a", 1, 1, functions=["N1"], classes=("buffer overflow",))]), "closed set"),
    ("not an object", "not a JSON object"),
])
def test_schema_violations_are_bounded_errors_for_the_repair_turn(proposal, fragment) -> None:
    validated, errors = validate_plan(proposal, brief(), SETTINGS, schemas=SCHEMAS, salvage=True)
    assert validated is None and errors and fragment in "\n".join(errors)


def test_a_plan_that_assigns_nothing_is_refused() -> None:
    current = brief()
    proposal = plan([area("void", 1, 1)], unassigned=[{"id": label, "reason": "r"} for label in (*current.functions, *current.entry_points)])
    validated, errors = validate_plan(proposal, current, SETTINGS, schemas=SCHEMAS, salvage=True)
    assert validated is None and errors == ["the plan assigns nothing: every area is empty"]


# --------------------------------------------------------------------------------------------- planner

def _good_plan(current: Brief) -> dict:
    return plan([area("ingress", 1, 2, files=["F1"], functions=["N1", "N4"], entry_points=list(current.entry_points)),
                 area("rest", 2, 1, files=["F2", "F3"], functions=[label for label in current.functions if label not in {"N1", "N4"}])])


def test_run_planner_repairs_once_and_records_the_plan() -> None:
    current = brief()
    calls = []

    def infer(request, **kwargs):
        calls.append(request)
        if len(calls) == 1:
            return ModelResult(plan([area("ingress", 1, 2, functions=["N1", "N99"])]), input_tokens=10, output_tokens=5)
        assert request.repair_errors and any("N99" in error for error in request.repair_errors)
        assert request.transcript and request.transcript[0]["from"] == "worker"
        return ModelResult(_good_plan(current), input_tokens=10, output_tokens=7)

    outcome = run_planner(current, settings=SETTINGS, profile=PROFILE, infer=infer, guidance=GUIDANCE, schemas=SCHEMAS)
    assert outcome.planned and outcome.model_calls == 2 and len(calls) == 2
    document = outcome.document
    assert document["schema"] == ARTIFACT_SCHEMA and document["status"] == "planned" and document["gap"] is None
    assert re.fullmatch(r"plan-[0-9a-f]{64}", document["plan_id"])
    assert document["brief"]["sha256"] == current.sha256 and document["guidance_bundle_sha256"] == "a" * 64
    assert [item["turn"] for item in document["attempts"]] == [1, 2] and document["attempts"][1]["valid"] is True
    assert document["attempts"][0]["errors"] and "usage" in document["attempts"][0]
    assert document["summary"] == {"areas": 2, "reached": 2, "not_reached": 0, "agents": 3, "unassigned": 0,
                                   "functions_assigned": 5, "entry_points_assigned": 2}
    assert calls[0].role == "hunt_planner" and calls[0].persona == "generalist" and calls[0].schema == RESULT_SCHEMA
    assert calls[0].task_input["brief"] == current.document
    assert calls[0].capability_artifact_card["citation_contract"]["id"] == "brief_id"


def test_run_planner_falls_back_to_the_rank_after_two_invalid_turns_or_an_empty_plan() -> None:
    current = brief()
    empty = plan([area("void", 1, 1)], unassigned=[{"id": label, "reason": "r"} for label in (*current.functions, *current.entry_points)])
    outcome = run_planner(current, settings=SETTINGS, profile=PROFILE, infer=lambda request, **kwargs: ModelResult(empty),
                          guidance=GUIDANCE, schemas=SCHEMAS)
    assert not outcome.planned and outcome.document["gap"] == "hunt_plan_unavailable:empty_plan"
    assert outcome.document["plan"] is None and outcome.document["plan_id"] is None
    assert selection_from_document(outcome.document) is None
    invalid = run_planner(current, settings=SETTINGS, profile=PROFILE,
                          infer=lambda request, **kwargs: ModelResult({"schema": RESULT_SCHEMA, "areas": "x"}),
                          guidance=GUIDANCE, schemas=SCHEMAS)
    assert invalid.document["gap"] == "hunt_plan_unavailable:invalid_output" and len(invalid.document["attempts"]) == 2


def test_run_planner_treats_provider_outages_as_gaps_and_programming_errors_as_failures() -> None:
    current = brief()

    def outage(request, **kwargs):
        raise ProviderError("scripted outage", retryable=True)

    outcome = run_planner(current, settings=SETTINGS, profile=PROFILE, infer=outage, guidance=GUIDANCE, schemas=SCHEMAS)
    assert outcome.document["status"] == "fallback" and outcome.document["gap"] == "hunt_plan_unavailable:provider_error"

    def bug(request, **kwargs):
        raise TypeError("contract bug")

    with pytest.raises(TypeError):
        run_planner(current, settings=SETTINGS, profile=PROFILE, infer=bug, guidance=GUIDANCE, schemas=SCHEMAS)


# -------------------------------------------------------------------------------------------- selection

def _unit(key: str, paths: tuple[str, ...], operation: dict | None = None) -> ReviewUnit:
    return ReviewUnit(key=key, component_id="component:0001", trust_boundary_id=None, build_unit_id="bu",
                      range_label="r0000", paths=paths, source_ids=(), leads=(), context=(), signals=(), operation=operation)


def _ranked(*units: ReviewUnit) -> tuple[RankedUnit, ...]:
    return tuple(RankedUnit(unit, position, len(units)) for position, unit in enumerate(units, 1))


def _planned_document(current: Brief, proposal: dict, settings: HuntingSettings = SETTINGS) -> dict:
    outcome = run_planner(current, settings=settings, profile=PROFILE,
                          infer=lambda request, **kwargs: ModelResult(proposal), guidance=GUIDANCE, schemas=SCHEMAS)
    assert outcome.planned, outcome.document["gap"]
    return dict(outcome.document)


def test_selection_orders_units_by_area_priority_then_rank_and_names_every_gap() -> None:
    current = brief()
    # Two reached areas and one beyond the budget; the rank would have put the whole-file unit second.
    proposal = plan([area("decoders", 2, 1, files=["F2"], functions=["N3", "N4"]),
                     area("ingress", 1, 2, files=["F1"], functions=["N1", "N2"], entry_points=["E1", "E2"]),
                     area("logging", 3, 1, files=["F3"], functions=["N5"])])
    document = _planned_document(current, proposal)
    selection = HuntSelection(document)
    assert [item["area_id"] for item in document["plan"]["areas"]] == ["ingress", "decoders", "logging"]
    assert document["plan"]["areas"][2]["status"] == "not_reached"
    server, packet, log = "src/net/server.cpp", "src/parse/packet.cpp", "src/util/log.cpp"
    operation = _unit("unit:op-server", (server,), {"path": server, "start_line": 1, "end_line": 20})
    whole_packet = _unit("unit:packet", (packet,))
    whole_log = _unit("unit:log", (log,))
    orphan = _unit("unit:orphan", ("src/other/none.cpp",))
    ranked = _ranked(whole_packet, whole_log, operation, orphan)
    hunted, gaps, areas, reasons = selection.select(ranked, hunt_max_units=10)
    assert [item.unit.key for item in hunted] == ["unit:op-server", "unit:packet"]
    assert areas == {"unit:op-server": "ingress", "unit:packet": "decoders"}
    assert reasons == {"unit:log": "not_reached:logging", "unit:orphan": "not_in_plan"}
    assert {gap.scope: gap.state for gap in gaps} == {"unit:log": "skipped", "unit:orphan": "skipped"}
    assert all(gap.producer == "lane_b_hunt" and document["plan_id"] in gap.reason for gap in gaps)
    campaign = selection.campaign(operation, "ingress")
    assert campaign["area_id"] == "ingress" and campaign["priority"] == 1 and campaign["agents"] == 2
    assert [item["name"] for item in campaign["functions"]] == ["fn_0", "fn_1"]   # lines 1 and 11 are inside 1..20
    assert len(campaign["entry_points"]) == 2 and campaign["authority"] == "routing_context"
    assert campaign["plan_id"] == document["plan_id"]
    # The hunt cap applies after the plan, in campaign order, and names the area it cut.
    capped, gaps, areas, reasons = selection.select(ranked, hunt_max_units=1)
    assert [item.unit.key for item in capped] == ["unit:op-server"]
    assert reasons["unit:packet"] == "beyond_hunt_max_units:decoders" and "unit:packet" not in areas


def test_selection_sets_aside_units_whose_members_were_unassigned() -> None:
    current = brief()
    proposal = plan([area("ingress", 1, 3, files=["F1"], functions=["N1", "N2"], entry_points=["E1", "E2"])],
                    unassigned=[{"id": label, "reason": "set aside"} for label in ("N3", "N4", "N5")])
    selection = HuntSelection(_planned_document(current, proposal))
    log = _unit("unit:log", ("src/util/log.cpp",))
    hunted, gaps, areas, reasons = selection.select(_ranked(log), hunt_max_units=10)
    assert hunted == () and reasons == {"unit:log": "unassigned"} and "set this unit aside" in gaps[0].reason
    with pytest.raises(ValueError):
        HuntSelection({"schema": ARTIFACT_SCHEMA, "status": "fallback"})


def test_settings_reject_unknown_keys_and_out_of_range_values() -> None:
    assert HuntingSettings.from_mapping(None, "x").enabled is False
    parsed = HuntingSettings.from_mapping({"enabled": True, "agents": 2, "brief_bounds": {"max_files": 10}}, "x")
    assert parsed.agents == 2 and parsed.brief_bounds.max_files == 10 and parsed.brief_bounds.max_functions == 400
    assert parsed.record()["brief_bounds"]["max_files"] == 10
    for value, fragment in (({"enabled": True, "spam": 1}, "unknown settings"), ({"agents": 1}, "missing settings: enabled"),
                            ({"enabled": True, "agents": 0}, "agents must be"), ({"enabled": "yes"}, "Boolean"),
                            ({"enabled": True, "brief_bounds": {"max_files": 0}}, "max_files must be"),
                            ({"enabled": True, "planner_profile": "Bad Name"}, "planner_profile")):
        with pytest.raises(ValueError, match=fragment):
            HuntingSettings.from_mapping(value, "x")
