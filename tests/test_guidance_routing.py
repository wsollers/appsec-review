from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.guidance import (
    GuidanceError, hunt_panel, load_registry, parse_fragment, partition_check, route_persona,
    route_stack,
)
from appsec_review.guidance.fragments import load_tool_names
from appsec_review.guidance.routing import STACK_IDS
from appsec_review.jobs.job_security_tagging.crosswalk import load_crosswalk
from appsec_review.jobs.job_security_tagging.taxonomy import load_vocabulary
from appsec_review.storage import file_sha256


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "guidance"
TAXONOMY = ROOT / "data" / "reference" / "taxonomy"

PERSONAS = {
    "memory_safety_native": ("cwe:119", "cwe:787", "func:exec:unmanaged-memory", "func:exec:ffi"),
    "injection_interpreters": ("cwe:78", "cwe:89", "func:data:sql-query", "func:exec:shell", "func:exec:*"),
    "network_api_surface": ("func:net:*", "cwe:918"),
    "authentication_session": ("func:authn:*", "func:session:*", "cwe:347"),
    "business_logic_abuse": (),
    "generalist": ("func:ai:*",),
}


@pytest.fixture(scope="module")
def taxonomy():
    vocabulary = load_vocabulary(TAXONOMY / "vocabulary.json", file_sha256(TAXONOMY / "vocabulary.json"))
    crosswalk = load_crosswalk(TAXONOMY / "crosswalk.json", file_sha256(TAXONOMY / "crosswalk.json"), vocabulary)
    return vocabulary, crosswalk


# --------------------------------------------------------------------------------------------- persona-routing/1

def test_persona_routing_prefers_lead_cwe_and_records_basis() -> None:
    route = route_persona(PERSONAS, lead_cwe="CWE-0787", location_tags=["func:net:http-route"])
    assert route == {"rule": "persona-routing/1", "persona": "memory_safety_native", "basis": "lead_cwe",
                     "matched_tags": ["cwe:787"], "routing_gap": False}


def test_persona_routing_falls_back_to_location_then_component_then_generalist() -> None:
    location = route_persona(PERSONAS, lead_cwe="CWE-20",
                             location_tags=["func:net:http-client", "func:net:tls-client", "func:exec:shell",
                                            "lang:cpp"],
                             component_tags=["func:exec:ffi"])
    assert (location["persona"], location["basis"]) == ("network_api_surface", "location_tags")
    assert location["matched_tags"] == ["func:net:http-client", "func:net:tls-client"]

    component = route_persona(PERSONAS, lead_cwe=None, location_tags=["lang:cpp"],
                              component_tags={"func:authn:jwt": 1, "func:exec:ffi": 3, "func:net:dns": 2})
    assert (component["persona"], component["basis"]) == ("memory_safety_native", "component_tags")

    fallback = route_persona(PERSONAS, lead_cwe="not-a-cwe", location_tags=["lang:cpp"],
                             component_tags=["platform:aws"])
    assert fallback["persona"] == "generalist" and fallback["basis"] == "generalist"
    assert fallback["routing_gap"] is True and fallback["gap_class"] == "routing_gap"


def test_persona_routing_specificity_and_tie_break_are_deterministic() -> None:
    # func:exec:ffi is covered exactly by memory_safety_native and by wildcard elsewhere.
    assert route_persona(PERSONAS, location_tags=["func:exec:ffi"])["persona"] == "memory_safety_native"
    assert route_persona(PERSONAS, location_tags=["func:exec:ipc"])["persona"] == "injection_interpreters"
    tie = route_persona(PERSONAS, location_tags=["func:session:cookie", "func:net:cors"])
    assert tie["persona"] == "authentication_session"  # equal weight: persona id order
    assert route_persona(PERSONAS, location_tags=["func:ai:llm-call"])["persona"] == "generalist"
    with pytest.raises(GuidanceError, match="generalist"):
        route_persona({"memory_safety_native": ("cwe:787",)}, lead_cwe="CWE-787")


# --------------------------------------------------------------------------------------------- stack-routing/1

@pytest.mark.parametrize(("facts", "stack", "basis"), [
    ({"languages": ["lang:cpp"], "subject_tags": ["func:net:grpc"]}, "cpp_rpc_service", ["func:net:grpc", "lang:cpp"]),
    ({"languages": ["lang:cpp", "lang:c-cpp-header"], "interfaces": ["protobuf"]}, "cpp_rpc_service",
     ["interface:protobuf", "lang:c-cpp-header", "lang:cpp"]),
    ({"languages": ["lang:cpp"], "components": ["component:network"]}, "cpp_native_service", ["lang:cpp"]),
    ({"languages": ["lang:c"], "build_facts": ["freestanding"], "interfaces": ["thrift"]}, "c_systems_embedded",
     ["build:freestanding", "lang:c"]),
    ({"languages": ["lang:kotlin"], "components": ["component:application-api-server"]}, "jvm_service",
     ["component:application-api-server", "lang:kotlin"]),
    ({"languages": {"lang:python": 1, "lang:typescript": 9}, "components": ["component:web-frontend"]}, "node_web",
     ["component:web-frontend", "lang:typescript"]),
    ({"languages": ["lang:go", "lang:rust"], "components": ["component:network"]}, "go_service",
     ["component:network", "lang:go"]),
    ({"languages": ["lang:kotlin"], "components": ["component:android-mobile"]}, "android",
     ["component:android-mobile"]),
    ({"languages": ["lang:swift"], "components": ["component:ios-mobile"]}, "ios", ["component:ios-mobile"]),
    ({"languages": ["lang:rust"], "build_facts": ["wasm"]}, "wasm", ["build:wasm"]),
    ({"languages": ["lang:shell"], "subject_tags": ["infra:ci:workflow", "infra:container:base-image"]},
     "ci_pipeline", ["infra:ci:workflow"]),
    ({"languages": ["lang:python"], "components": ["component:test-development-only"],
      "subject_tags": ["infra:kube:workload"]}, "iac_kubernetes", ["infra:kube:workload"]),
])
def test_stack_routing_table(facts, stack: str, basis: list[str]) -> None:
    route = route_stack(**facts)
    assert route == {"rule": "stack-routing/1", "stack": stack, "basis": basis, "routing_gap": False}


def test_stack_routing_generic_fallback_records_gap() -> None:
    route = route_stack(languages=["lang:python"], components=["component:test-development-only"])
    assert route["stack"] == "generic" and route["routing_gap"] is True and route["gap_class"] == "routing_gap"
    assert route_stack()["stack"] == "generic"


# --------------------------------------------------------------------------------------------- hunt-panel/1

UNIT = {"func:exec:unmanaged-memory": 5, "func:exec:shell": 2, "func:net:http-route": 1}


def test_panel_round_zero_uses_available_strategies_and_ranked_personas() -> None:
    panel = hunt_panel(PERSONAS, unit_tags=UNIT, available_sources=["source_sink_facts"])
    assert [(cell["strategy"], cell["persona"]) for cell in panel["cells"]] == [
        ("sink_up", "memory_safety_native"),
        ("persona_sweep", "injection_interpreters"),
        ("persona_sweep", "network_api_surface"),
    ]
    assert [gap["strategy"] for gap in panel["gaps"]] == ["entry_down", "control_gap"]
    assert all(gap["gap_class"] == "coverage_gap" for gap in panel["gaps"])
    assert panel["routing_gap"] is False and panel["rule"] == "hunt-panel/1"
    assert len({(cell["strategy"], cell["persona"]) for cell in panel["cells"]}) == 3


def test_panel_is_deterministic_under_input_order() -> None:
    reordered = dict(reversed(list(UNIT.items())))
    first = hunt_panel(PERSONAS, unit_tags=UNIT, available_sources=["owasp_workbench", "entry_point_catalog",
                                                                     "source_sink_facts"])
    second = hunt_panel(dict(reversed(list(PERSONAS.items()))), unit_tags=reordered,
                        available_sources=["source_sink_facts", "entry_point_catalog", "owasp_workbench"])
    assert first == second
    assert [cell["strategy"] for cell in first["cells"]] == ["sink_up", "entry_down", "control_gap"]
    assert first["gaps"] == []


def test_panel_variant_only_in_later_rounds() -> None:
    round_zero = hunt_panel(PERSONAS, unit_tags=UNIT, available_sources=["confirmed_claims", "source_sink_facts"])
    assert "variant" not in [cell["strategy"] for cell in round_zero["cells"]]
    assert all(gap["strategy"] != "variant" for gap in round_zero["gaps"])
    round_one = hunt_panel(PERSONAS, unit_tags=UNIT, available_sources=["confirmed_claims", "source_sink_facts"],
                           round_index=1)
    assert [cell["strategy"] for cell in round_one["cells"]] == ["variant", "sink_up", "persona_sweep"]
    missing = hunt_panel(PERSONAS, unit_tags=UNIT, available_sources=[], round_index=1)
    assert [gap["strategy"] for gap in missing["gaps"]] == ["variant", "sink_up", "entry_down"]
    assert [cell["strategy"] for cell in missing["cells"]] == ["persona_sweep"] * 3


def test_panel_fallback_personas_and_generalist_gap() -> None:
    panel = hunt_panel(PERSONAS, unit_tags={"func:exec:unmanaged-memory": 1}, available_sources=[])
    assert [cell["persona"] for cell in panel["cells"]] == ["memory_safety_native", "business_logic_abuse",
                                                            "generalist"]
    assert [cell["persona_basis"] for cell in panel["cells"]] == ["unit_tags", "panel_fallback", "panel_fallback"]
    assert panel["routing_gap"] is True
    # One persona still yields distinct pairs when every slot has a different strategy.
    tiny = hunt_panel({"generalist": ()}, unit_tags={},
                      available_sources=["source_sink_facts", "entry_point_catalog", "owasp_workbench"])
    assert [(cell["strategy"], cell["persona"]) for cell in tiny["cells"]] == [
        ("sink_up", "generalist"), ("entry_down", "generalist"), ("control_gap", "generalist")]


def test_panel_rejects_impossible_or_unknown_inputs() -> None:
    with pytest.raises(GuidanceError, match="distinct"):
        hunt_panel({"generalist": ()}, unit_tags={}, available_sources=[])
    with pytest.raises(GuidanceError, match="unknown"):
        hunt_panel(PERSONAS, unit_tags=UNIT, available_sources=["runtime_traces"])
    # Symbol links carry no source or sink fact; only accepted sink facts unlock sink_up.
    with pytest.raises(GuidanceError, match="unknown"):
        hunt_panel(PERSONAS, unit_tags=UNIT, available_sources=["symbol_links"])


# --------------------------------------------------------------------------------------------- partition

def test_partition_check_detects_orphans_and_double_claims(taxonomy) -> None:
    vocabulary, crosswalk = taxonomy
    covers = {}
    for kind in ("memory_safety_native", "injection_interpreters", "generalist"):
        fragment = parse_fragment((FIXTURES / "personas" / f"{kind}.md").read_text(), kind="persona",
                                  tools=load_tool_names(ROOT))
        covers[kind] = fragment.covers
    covers["shell_double"] = ("func:exec:shell", "cwe:787")
    result = partition_check(covers, vocabulary, crosswalk)
    assert result["ok"] is False
    assert result["double_claims"] == {"cwe:787": ["memory_safety_native", "shell_double"],
                                       "func:exec:shell": ["injection_interpreters", "shell_double"]}
    assert "func:net:grpc" in result["orphans"] and "data:pii" in result["orphans"]
    assert "cwe:611" in result["orphans"]  # crosswalk-named CWE nobody covers
    assert "func:ai:llm-call" not in result["orphans"]


def test_partition_check_accepts_a_complete_partition(taxonomy) -> None:
    vocabulary, crosswalk = taxonomy
    result = partition_check({"a": ("func:*", "data:*"), "b": ("infra:*", "cwe:*")}, vocabulary, crosswalk)
    assert result == {"checked": result["checked"], "orphans": [], "double_claims": {}, "ok": True}
    assert result["checked"] > 150


def test_registry_lists_every_routed_stack_and_partition_holds_once_personas_exist(taxonomy) -> None:
    vocabulary, crosswalk = taxonomy
    registry = load_registry(ROOT)
    assert set(registry["stacks"]) == set(STACK_IDS)
    paths = {name: ROOT / record["path"] for name, record in registry["personas"].items() if "path" in record}
    if not all(path.is_file() for path in paths.values()):
        pytest.skip("inference persona files are not all present yet")
    tools = load_tool_names(ROOT)
    covers = {name: parse_fragment(path.read_text(), kind="persona", tools=tools, expected_id=name).covers
              for name, path in paths.items()}
    result = partition_check(covers, vocabulary, crosswalk)
    assert result["orphans"] == [] and result["double_claims"] == {}
