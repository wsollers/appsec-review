"""Inert reduced-AST and brief regressions for T-5158; no source is compiled or executed."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from appsec_review.jobs.job_poc_generation import ast_reduce, brief, policy
from tests import poc_support
from tests.fixtures.poc_generation import relay


FUNCTIONS = (relay.TEST_NAME, relay.CONTROL_NAME)


def _integer(value):
    if isinstance(value, int) and value < 0:
        return {"kind": "UnaryOperator", "opcode": "-", "inner": [_integer(-value)]}
    return {"kind": "IntegerLiteral", "value": str(value), "type": {"qualType": "int"}}


def _reference(identity="sink", kind="FunctionDecl", name="parse_header"):
    return {"kind": "DeclRefExpr", "referencedDecl": {"id": identity, "kind": kind, "name": name}}


def _call():
    return {"kind": "CallExpr", "inner": [
        {"kind": "ImplicitCastExpr", "castKind": "FunctionToPointerDecay", "inner": [_reference()]}]}


def _document(*statements):
    return {
        "schema": ast_reduce.SCHEMA, "source": "/workspace/poc.cpp", "project_roots": ["/workspace/"],
        "declarations": {"sink": {"kind": "FunctionDecl", "name": "parse_header", "qualified": relay.SINK,
                                  "file": "/workspace/include/relay.hpp"}},
        "nodes": [{"kind": "FunctionDecl", "name": name, "type": {"qualType": "void ()"},
                   "inner": [{"kind": "CompoundStmt", "inner": deepcopy(list(statements))}]}
                  for name in FUNCTIONS],
    }


def _check(document, *, cap=4, triggers=()):
    settings = poc_support.settings()
    settings = replace(settings, bounds=replace(settings.bounds, max_loop_iterations=cap))
    return policy.check_ast(document, settings, policy.Expectation(FUNCTIONS, (relay.SINK,), triggers=triggers))


@pytest.mark.parametrize("kind", ["reference", "member", "address", "argument", "unevaluated", "declaration",
                                 "comment", "name"])
def test_required_sink_is_an_evaluated_call_not_a_reference(kind):
    ref = _reference()
    if kind == "member":
        ref = {"kind": "MemberExpr", "name": "parse_header", "referencedMemberDecl": "sink"}
    elif kind == "address":
        ref = {"kind": "UnaryOperator", "opcode": "&", "inner": [ref]}
    elif kind == "argument":
        ref = {"kind": "CallExpr", "inner": [_reference("other", name="memset"), ref]}
    elif kind == "unevaluated":
        ref = {"kind": "UnaryExprOrTypeTraitExpr", "name": "sizeof", "inner": [_call()]}
    elif kind == "declaration":
        ref = {"kind": "DeclStmt", "inner": [
            {"kind": "FunctionDecl", "name": "parse_header", "type": {"qualType": "void ()"}}]}
    elif kind == "comment":
        ref = {"kind": "FullComment", "text": "parse_header()"}
    elif kind == "name":
        ref = {"kind": "StringLiteral", "value": '"parse_header()"'}
    doc = _document(ref)
    if kind == "member":
        doc["declarations"]["sink"]["kind"] = "CXXMethodDecl"
    if kind == "argument":
        doc["declarations"]["other"] = {"kind": "FunctionDecl", "name": "memset", "qualified": "memset",
                                        "file": "/usr/include/string.h"}
    found = _check(doc)
    assert {v.function for v in found if v.rule == "sink_not_called"} == set(FUNCTIONS)


@pytest.mark.parametrize("kind", ["CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr"])
def test_resolved_direct_calls_satisfy_each_function(kind):
    call = _call()
    call["kind"] = kind
    doc = _document(call)
    if kind == "CXXMemberCallExpr":
        doc["declarations"]["sink"]["kind"] = "CXXMethodDecl"
        for node in doc["nodes"]:
            node["inner"][0]["inner"][0]["inner"] = [
                {"kind": "MemberExpr", "name": "parse_header", "referencedMemberDecl": "sink"}]
    assert _check(doc) == []
    doc["nodes"][1]["inner"][0]["inner"] = [_reference()]
    assert [v.function for v in _check(doc) if v.rule == "sink_not_called"] == [FUNCTIONS[1]]


@pytest.mark.parametrize("callee", [{}, {"kind": "ParenExpr", "inner": []},
                                    {"kind": "ParenExpr", "inner": [_reference(), _reference()]}],
                         ids=["absent", "empty-wrapper", "ambiguous-wrapper"])
def test_malformed_callees_never_count_as_a_sink_call(callee):
    found = _check(_document({"kind": "CallExpr", "inner": [callee]}))
    assert "indirect_call" in {v.rule for v in found}
    assert {v.function for v in found if v.rule == "sink_not_called"} == set(FUNCTIONS)


def _loop(start=0, compare="<", limit=4, step=1, *, identity="counter", type_name="int", body=None):
    ref = _reference(identity, "VarDecl", "i")
    variable = {"kind": "VarDecl", "id": identity, "name": "i", "type": {"qualType": type_name},
                "inner": [_integer(start)]}
    increment = ({"kind": "UnaryOperator", "opcode": "++" if step == 1 else "--", "inner": [deepcopy(ref)]}
                 if abs(step) == 1 else
                 {"kind": "CompoundAssignOperator", "opcode": "+=", "inner": [deepcopy(ref), _integer(step)]})
    return {"kind": "ForStmt", "inner": [
        {"kind": "DeclStmt", "inner": [variable]}, {},
        {"kind": "BinaryOperator", "opcode": compare, "inner": [
            {"kind": "ImplicitCastExpr", "castKind": "LValueToRValue", "inner": [deepcopy(ref)]}, _integer(limit)]},
        increment, body or {"kind": "CompoundStmt", "inner": []}]}


def _loop_document(loop):
    doc = _document(_call(), loop)

    def declarations(node):
        if node.get("kind") == "VarDecl":
            doc["declarations"][node["id"]] = {
                "kind": "VarDecl", "name": node["name"], "qualified": node["name"], "file": doc["source"]}
        for child in node.get("inner", []):
            declarations(child)

    declarations(loop)
    return doc


@pytest.mark.parametrize(("start", "compare", "limit", "step", "allowed"), [
    (0, "<", 4, 1, True), (0, "<=", 4, 1, False), (0, "<=", 3, 1, True),
    (4, ">", 0, -1, True), (4, ">=", 0, -1, False), (3, ">=", 0, -1, True),
    (0, "<", 4, -1, False), (4, ">", 0, 1, False), (0, "!=", 4, -1, False),
    (0, "<", 8, 2, True), (0, "<=", 8, 2, False), (8, ">", 0, -2, True),
    (0, "!=", 8, 2, True), (0, "!=", 7, 2, False), (0, "<", 4, 0, False),
    (4, "<", 0, 1, True), (4, "!=", 4, 1, True), (-4, "<", 0, 1, True),
], ids=["up-cap", "up-inclusive-over", "up-inclusive-cap", "down-cap", "down-inclusive-over",
        "down-inclusive-cap", "wrong-down", "wrong-up", "wrong-not-equal", "stride-cap",
        "stride-inclusive-over", "down-stride", "reachable-not-equal", "unreachable-not-equal",
        "zero-step", "initially-false", "initially-equal", "negative-initial"])
def test_loop_counts_include_direction_endpoint_and_stride(start, compare, limit, step, allowed):
    found = _check(_loop_document(_loop(start, compare, limit, step)))
    assert ("unbounded_loop" not in {v.rule for v in found}) is allowed
    if allowed:
        assert found == []


@pytest.mark.parametrize("kind", ["assignment", "increment", "address", "reference-argument", "alias"])
def test_loop_counter_mutation_or_escape_prevents_a_bound(kind):
    ref = _reference("counter", "VarDecl", "i")
    if kind == "assignment":
        body = {"kind": "BinaryOperator", "opcode": "=", "inner": [ref, _integer(0)]}
    elif kind == "increment":
        body = {"kind": "UnaryOperator", "opcode": "--", "inner": [ref]}
    elif kind == "address":
        body = {"kind": "UnaryOperator", "opcode": "&", "inner": [ref]}
    elif kind == "reference-argument":
        body = _call()
        body["inner"].append(ref)
    else:
        body = {"kind": "DeclStmt", "inner": [
            {"kind": "VarDecl", "id": "alias", "name": "alias", "type": {"qualType": "int &"}, "inner": [ref]}]}
    assert "unbounded_loop" in {v.rule for v in _check(_loop_document(_loop(body=body)))}


def test_loop_counter_read_and_nested_product_remain_bounded():
    ref = _reference("counter", "VarDecl", "i")
    read = {"kind": "ImplicitCastExpr", "castKind": "LValueToRValue", "inner": [ref]}
    assert _check(_loop_document(_loop(body=read))) == []
    assert _check(_loop_document(_loop(limit=2, body=_loop(limit=2, identity="nested")))) == []
    found = _check(_loop_document(_loop(limit=2, body=_loop(compare="<=", limit=2, identity="nested"))))
    assert "unbounded_loop" in {v.rule for v in found}


@pytest.mark.parametrize("mutation", ["narrow-init", "unsigned-condition", "missing-body", "ambiguous-step"])
def test_unsupported_loop_evidence_is_not_a_proven_bound(mutation):
    loop = _loop()
    if mutation == "narrow-init":
        loop["inner"][0]["inner"][0]["inner"] = [
            {"kind": "ImplicitCastExpr", "castKind": "IntegralCast",
             "type": {"qualType": "unsigned char"}, "inner": [_integer(256)]}]
    elif mutation == "unsigned-condition":
        loop["inner"][2]["inner"][0] = {
            "kind": "ImplicitCastExpr", "castKind": "IntegralCast", "type": {"qualType": "unsigned int"},
            "inner": [loop["inner"][2]["inner"][0]]}
    elif mutation == "missing-body":
        loop["inner"][4] = {}
    else:
        loop["inner"][3]["inner"].append(_integer(1))
    found = _check(_loop_document(loop))
    assert "unbounded_loop" in {v.rule for v in found}


@pytest.mark.parametrize(("type_name", "start", "compare", "limit", "step"), [
    ("unsigned char", 254, "<=", 255, 1), ("unsigned char", 1, ">=", 0, -1),
    ("int", 2147483646, "<=", 2147483647, 1), ("float", 0, "<", 4, 1),
    ("unknown_integer", 0, "<", 4, 1),
], ids=["unsigned-wrap", "unsigned-underflow", "signed-overflow", "non-integer", "unknown-width"])
def test_unprovable_counter_ranges_are_not_finite_bounds(type_name, start, compare, limit, step):
    found = _check(_loop_document(_loop(start, compare, limit, step, type_name=type_name)))
    assert "unbounded_loop" in {v.rule for v in found}


@pytest.mark.parametrize(("constraint", "operator", "low", "high"), [
    ("at least 08", ">=", 8, None), ("exactly -1", "==", -1, None),
    ("between -02 and +03", "between", -2, 3), ("at most -0x10", "<=", -16, None),
    ("length +08", "==", 8, None),
], ids=["leading-zero", "negative", "signed-range", "signed-hex", "bare-signed"])
def test_numeric_constraints_preserve_sign_and_decimal_base(constraint, operator, low, high):
    parsed = policy.numeric_requirement(constraint)
    assert parsed is not None
    assert (parsed.operator, parsed.low, parsed.high) == (operator, low, high)
    assert parsed.satisfied_by(low)


@pytest.mark.parametrize("constraint", [
    "exactly 1.5", "at least 1e3", "exactly 0xGG", "between 3 and -2",
    "at least 1 and less than 4", "not exactly 1", "exactly 1/2", "exactly - 1",
], ids=["fraction", "exponent", "bad-hex", "reversed-range", "compound", "negated", "ratio", "broken-sign"])
def test_unsupported_numeric_constraints_are_retained_as_unchecked(constraint):
    expectation = brief.Brief({}, {"triggers": [{"constraint": constraint}], "path_calls": []},
                              (relay.SINK,), ()).expectation(FUNCTIONS)
    assert expectation.triggers == ()
    assert expectation.unchecked_triggers == (constraint,)


def test_negative_literal_is_not_also_positive_trigger_evidence():
    doc = _document(_call(), _integer(-1))
    negative = policy.Requirement("==", -1, None, "exactly -1")
    positive = policy.Requirement("==", 1, None, "exactly 1")
    assert _check(doc, triggers=(negative,)) == []
    assert "trigger_absent" in {v.rule for v in _check(doc, triggers=(positive,))}


def test_malformed_integer_evidence_is_refused_not_silently_accepted():
    found = _check(_document(_call(), _integer("not-an-integer")))
    assert "unsupported_construct" in {v.rule for v in found}


def test_a_trailing_newline_is_not_part_of_an_admitted_function_name():
    from appsec_review.jobs.job_poc_generation.source import WriterAnswer, check_answer

    answer = WriterAnswer.from_result(relay.answer(
        test_name="poc_valid\n", test="void poc_valid\n() {}", includes=())["result"])
    assert "name" in {v.rule for v in check_answer(answer, poc_support.settings(), None)}
