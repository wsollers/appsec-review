"""The PoC validators: pure functions over recorded clang ASTs and the writer's text (spec section 5.3).

``tests/fixtures/poc_generation/ast/*.json`` are reduced ASTs recorded once from the local build image by
``record_ast.py`` for the hand-written relay reproducer and each bad variant of it. Nothing here needs Docker.
"""
from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_poc_generation import ast_reduce
from appsec_review.jobs.job_poc_generation.policy import (
    ALLOWED_KINDS, RULES, Expectation, check_ast, numeric_requirement,
)
from appsec_review.jobs.job_poc_generation.settings import matches
from appsec_review.jobs.job_poc_generation.source import WriterAnswer, check_answer, file_violations
from tests import poc_support
from tests.fixtures.poc_generation import relay

AST = poc_support.FIXTURES / "ast"
SETTINGS = poc_support.settings()
FUNCTIONS = (relay.TEST_NAME, relay.CONTROL_NAME)
EXPECTATION = Expectation(FUNCTIONS, (relay.SINK,), frozenset(), (numeric_requirement("greater than 16"),))


def rules(name: str, settings=SETTINGS, expectation: Expectation = EXPECTATION) -> list[str]:
    return [item.rule for item in check_ast(poc_support.ast_document(name), settings, expectation)]


def test_the_recorded_reproducer_passes_every_validator() -> None:
    assert check_ast(poc_support.ast_document("good"), SETTINGS, EXPECTATION) == []


ACCEPTED = {"good", "string_fill"}


@pytest.mark.parametrize("name", sorted(set(relay.VARIANTS) - ACCEPTED - {"syntax_error"}))
def test_each_bad_variant_is_refused_for_its_own_rule(name: str) -> None:
    expected = relay.VARIANTS[name][2]
    found = rules(name)
    assert expected in found, (name, found)
    assert set(found) <= set(RULES)


def test_a_function_that_builds_its_input_in_a_sized_string_with_a_literal_size_is_accepted() -> None:
    """Standard-library members resolve to qualified names (``std::basic_string::data``) on the allowlist prefix."""
    assert check_ast(poc_support.ast_document("string_fill"), SETTINGS, EXPECTATION) == []
    names = {info["qualified"] for info in poc_support.ast_document("string_fill")["declarations"].values()}
    assert "std::basic_string::data" in names and "memcpy" in names


def test_a_variant_that_does_not_parse_is_recorded_with_the_compiler_exit_code() -> None:
    assert poc_support.ast_document("syntax_error")["compiler_exit_code"] != 0


def test_violations_carry_a_line_and_the_function_and_are_ordered() -> None:
    found = check_ast(poc_support.ast_document("system_call"), SETTINGS, EXPECTATION)
    system = next(item for item in found if item.rule == "call_not_allowlisted")
    assert system.function == relay.TEST_NAME and system.line and "shell API" in system.message
    assert [(item.line or 0, item.rule) for item in found] == sorted((item.line or 0, item.rule) for item in found)


def test_the_allowlist_wins_over_the_denylist() -> None:
    table = poc_support.settings_table()
    assert "system" in table["policy"]["call_denylist"]["shell"]
    table["policy"]["call_allowlist"] = [*table["policy"]["call_allowlist"], "system"]
    permissive = type(SETTINGS).from_mapping(table)
    assert "call_not_allowlisted" not in rules("system_call", permissive)
    # a name on neither list is refused as unlisted, with no category
    message = next(item.message for item in check_ast(poc_support.ast_document("unlisted_call"), SETTINGS,
                                                      EXPECTATION) if item.rule == "call_not_allowlisted")
    assert "not on the closed call allowlist" in message and "API" not in message


def test_project_calls_outside_the_sink_and_path_are_refused_unless_configured() -> None:
    assert "call_not_allowlisted" in rules("project_call")
    table = poc_support.settings_table()
    table["policy"]["project_calls"] = "any_project_function"
    assert "call_not_allowlisted" not in rules("project_call", type(SETTINGS).from_mapping(table))
    on_path = Expectation(FUNCTIONS, (relay.SINK,), frozenset({"relay::probe_host"}), EXPECTATION.triggers)
    assert "call_not_allowlisted" not in rules("project_call", expectation=on_path)


def test_the_sink_name_matches_qualified_and_bare_spellings() -> None:
    for sink in ("relay::parse_header", "parse_header"):
        assert check_ast(poc_support.ast_document("good"), SETTINGS,
                         Expectation(FUNCTIONS, (sink,), frozenset(), EXPECTATION.triggers)) == []


def test_a_function_that_is_missing_or_defined_twice_is_a_violation() -> None:
    assert "missing_function" in rules("good", expectation=Expectation(
        (*FUNCTIONS, "poc_not_written"), (relay.SINK,), frozenset(), ()))
    document = poc_support.ast_document("good")
    document["nodes"].append(copy.deepcopy(document["nodes"][0]))
    assert "duplicate_function" in [item.rule for item in check_ast(document, SETTINGS, EXPECTATION)]


def test_an_unknown_node_kind_fails_closed() -> None:
    document = poc_support.ast_document("good")
    body = document["nodes"][0]["inner"][0]
    body["inner"].append({"kind": "CoawaitExpr", "line": 7})
    found = check_ast(document, SETTINGS, EXPECTATION)
    assert any(item.rule == "unsupported_construct" and "CoawaitExpr" in item.message for item in found)
    assert "CoawaitExpr" not in ALLOWED_KINDS


def test_a_reference_the_ast_cannot_resolve_fails_closed() -> None:
    document = poc_support.ast_document("good")
    document["declarations"] = {}
    assert "unresolved_reference" in [item.rule for item in check_ast(document, SETTINGS, EXPECTATION)]


def test_the_wrong_schema_is_refused() -> None:
    assert [item.rule for item in check_ast({"schema": "other/1"}, SETTINGS, EXPECTATION)] == ["ast_schema"]


def test_violations_are_capped() -> None:
    table = poc_support.settings_table()
    table["bounds"]["max_violations"] = 1
    capped = check_ast(poc_support.ast_document("main_defined"), type(SETTINGS).from_mapping(table), EXPECTATION)
    assert len(capped) == 2 and "too_many_violations" in [item.rule for item in capped]


def test_trigger_requirements_are_numeric_and_checked_on_the_ast() -> None:
    assert numeric_requirement("greater than 16").satisfied_by(20) and not numeric_requirement(
        "greater than 16").satisfied_by(16)
    cases = {"at least 17": (17, 16), "no more than 4": (4, 5), "less than 1": (0, 1), "between 10 and 12": (11, 13),
             "exactly 0x14": (20, 19), "length 20": (20, 21), "must exceed 255 bytes": (256, 255)}
    for text, (inside, outside) in cases.items():
        requirement = numeric_requirement(text)
        assert requirement.satisfied_by(inside) and not requirement.satisfied_by(outside), text
    assert numeric_requirement("contains a NUL byte") is None
    # the variant whose only literals are 8 and 12 does not carry the trigger value
    assert "trigger_absent" in rules("trigger_absent")
    # a trigger the brief cannot express numerically is not checked and not a violation
    assert "trigger_absent" not in rules("good", expectation=Expectation(FUNCTIONS, (relay.SINK,), frozenset(), ()))


def test_matches_supports_exact_names_and_scope_prefixes() -> None:
    assert matches("std::vector::push_back", ["std::vector::"]) and not matches("std::vectors", ["std::vector::"])
    assert matches("memcpy", ["memcpy"]) and not matches("memcpy2", ["memcpy"])


# -------------------------------------------------------------------------------- text checks (no compiler)


def answer(**changes) -> WriterAnswer:
    payload = relay.answer(**changes)["result"]
    return WriterAnswer.from_result(payload)


class Headers:
    def __init__(self, *known: str) -> None:
        self.known = set(known)

    def resolve(self, include: str):
        return include if include in self.known else None


def text_rules(item: WriterAnswer, headers=Headers("relay/relay.hpp")) -> list[str]:
    return [violation.rule for violation in check_answer(item, SETTINGS, headers)]


def test_the_recorded_answer_passes_the_text_checks() -> None:
    assert text_rules(answer()) == []


@pytest.mark.parametrize(("changes", "rule"), [
    ({"test_name": "main"}, "entry_point"),
    ({"test_name": "PocUpper"}, "name"),
    ({"control_name": relay.TEST_NAME}, "name"),
    ({"includes": ("relay/relay.hpp", "unistd.h")}, "include"),
    ({"includes": ("relay/missing.hpp",)}, "include"),
    ({"includes": ("../outside.hpp",)}, "include"),
    ({"includes": ("/etc/passwd.hpp",)}, "include"),
    ({"includes": ("relay/relay.hpp", "relay/relay.hpp")}, "include"),
    ({"test": relay.GOOD_TEST.replace("{\n", "{\n#include <stdlib.h>\n", 1)}, "preprocessor"),
    ({"test": relay.GOOD_TEST.replace("{\n", "{\n#pragma pack(1)\n", 1)}, "preprocessor"),
    ({"test": relay.GOOD_TEST.replace("{\n", "{\n/* */ %:include <x>\n", 1)}, "preprocessor"),
    ({"test": relay.GOOD_TEST.replace("{\n", "{\n??=include <x>\n", 1)}, "preprocessor"),
    ({"test": relay.GOOD_TEST.replace("{\n", '{\n_Pragma("omp parallel")\n', 1)}, "pragma"),
    ({"test": relay.GOOD_TEST.replace("{\n", '{\nasm("nop");\n', 1)}, "inline_asm"),
    ({"test": relay.GOOD_TEST.replace("{\n", "{\n// café\n", 1)}, "encoding"),
    ({"test": relay.GOOD_TEST.replace("{\n", "{\n\x00\n", 1)}, "encoding"),
    ({"test": "int unrelated() { return 0; }"}, "missing_function"),
    ({"test": relay.GOOD_TEST + "\n" * 90 + "// x"}, "size"),
])
def test_text_violations(changes, rule) -> None:
    assert rule in text_rules(answer(**changes))


def test_include_names_are_resolved_through_the_projects_headers_only() -> None:
    assert text_rules(answer(includes=("relay/relay.hpp",)), Headers()) == ["include"]
    assert text_rules(answer(includes=("relay/relay.hpp",)), None) == ["include"]


def test_long_prose_and_oversized_files_are_refused() -> None:
    assert "size" in text_rules(dataclasses.replace(answer(), expected_observation="x" * 700))
    big = file_violations("x" * (SETTINGS.bounds.max_file_bytes + 1), SETTINGS)
    assert [item.rule for item in big] == ["size"]


# ------------------------------------------------------------------------------------- the AST reduction


def test_the_reduction_keeps_only_the_poc_file_and_what_it_references() -> None:
    raw = json.loads((poc_support.FIXTURES / "raw" / "tiny_raw_ast.json").read_text(encoding="utf-8"))
    reduced = ast_reduce.reduce_ast(raw, source="/workspace/.appsec-poc/poc.cpp")
    assert [(node["kind"], node["name"]) for node in reduced["nodes"]] == [("FunctionDecl", "poc_tiny")]
    assert reduced["translation_unit_nodes"] > 3 and reduced["schema"] == ast_reduce.SCHEMA
    fill = next(item for item in reduced["declarations"].values() if item["name"] == "fill")
    assert fill["qualified"] == "lib::fill" and fill["file"] == "/workspace/include/tiny.h"
    assert {item["qualified"] for item in reduced["project_declarations"]} >= {"lib::Box", "lib::fill"}
    assert all(item["file"].startswith("/workspace/") for item in reduced["project_declarations"])
    assert all("range" not in node and "loc" not in node for node in reduced["nodes"])


def test_the_reduction_of_a_dump_without_the_source_has_no_nodes() -> None:
    raw = json.loads((poc_support.FIXTURES / "raw" / "tiny_raw_ast.json").read_text(encoding="utf-8"))
    assert ast_reduce.reduce_ast(raw, source="/workspace/other.cpp")["nodes"] == []


def test_canonical_names_drop_inline_namespaces() -> None:
    assert ast_reduce.canonical("std::__cxx11::basic_string::size") == "std::basic_string::size"
    assert ast_reduce.canonical("std::__1::vector") == "std::vector"


def test_recorded_documents_are_small_and_hold_no_host_paths() -> None:
    for path in AST.glob("*.json"):
        text = path.read_text(encoding="utf-8")
        assert len(text) < 80_000, path.name
        assert "/home/" not in text and "/mnt/" not in text, path.name


def test_recorded_variants_cover_every_declared_variant() -> None:
    assert {path.stem for path in AST.glob("*.json")} == set(relay.VARIANTS)
    assert Path(poc_support.FIXTURES / "record_ast.py").is_file()


@pytest.mark.parametrize(("name", "category"), [
    ("system", "shell"), ("popen", "shell"), ("fork", "process"), ("execve", "process"), ("socket", "network"),
    ("connect", "network"), ("dlopen", "dynamic loading"), ("fopen", "file system"), ("unlink", "file system"),
    ("getenv", "environment"), ("setenv", "environment"), ("exit", "control"), ("malloc", "control"),
])
def test_a_refused_call_is_named_by_the_category_of_the_closed_denylist(name, category) -> None:
    """The recorded reproducer with its memset reference renamed: the allowlist refuses, the denylist names."""
    document = poc_support.ast_document("good")
    for info in document["declarations"].values():
        if info["name"] == "memset":
            info.update(name=name, qualified=name)
    found = check_ast(document, SETTINGS, EXPECTATION)
    refused = [item for item in found if item.rule == "call_not_allowlisted"]
    assert refused and all(f"{category} API" in item.message for item in refused), (name, found)


def test_a_standard_scope_prefix_on_the_allowlist_admits_its_members() -> None:
    document = poc_support.ast_document("good")
    for info in document["declarations"].values():
        if info["name"] == "memset":
            info.update(name="push_back", qualified="std::vector::push_back")
    assert check_ast(document, SETTINGS, EXPECTATION) == []
    for info in document["declarations"].values():
        if info["name"] == "push_back":
            info.update(qualified="std::vectors::push_back")
    assert "call_not_allowlisted" in [item.rule for item in check_ast(document, SETTINGS, EXPECTATION)]
