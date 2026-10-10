"""Versioned per-grammar node mappings used by the complexity and heuristic extractors.

Each table names grammar-native Tree-sitter node types from the locked grammars in
``containers/tools/tree-sitter/assets.lock.json``.  A grammar revision change that renames node
types changes the accepted Tree-sitter identity and must be reviewed against these tables.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


MAPPING_IDENTITY = "appsec-review/review-prioritization-language-map/1"


@dataclass(frozen=True, slots=True)
class LanguageSpec:
    grammar: str
    language: str
    # Functional units: named functions, methods, constructors, lambdas, and closures.
    units: frozenset[str]
    # The subset of units that are anonymous expressions (lambdas, closures, function literals).
    anonymous: frozenset[str]
    # Declarations whose name qualifies nested units, mapped to the field holding the name.
    containers: Mapping[str, str]
    if_types: frozenset[str]
    else_wrappers: frozenset[str] = frozenset({"else_clause"})
    else_if_types: frozenset[str] = frozenset()
    loops: frozenset[str] = frozenset()
    # Cognitive "switch" structures (one increment for the whole construct).
    switches: frozenset[str] = frozenset()
    # Cyclomatic case clauses (one decision per non-default clause).
    cases: frozenset[str] = frozenset()
    # Exhaustive multiway expressions contribute (arms - 1) cyclomatic decisions.
    multiway: Mapping[str, frozenset[str]] = field(default_factory=dict)
    guards: frozenset[str] = frozenset()
    catches: frozenset[str] = frozenset()
    ternaries: frozenset[str] = frozenset()
    gotos: frozenset[str] = frozenset()
    labeled_jumps: frozenset[str] = frozenset()
    calls: Mapping[str, str] = field(default_factory=dict)
    # Constructs whose control flow the syntax tree cannot expose; reported as named gaps.
    unsupported: frozenset[str] = frozenset()


SHORT_CIRCUIT = frozenset({"&&", "||", "and", "or"})
NULL_COALESCING = frozenset({"??"})
SHORT_CIRCUIT_ASSIGNMENT = frozenset({"&&=", "||=", "??="})
BITWISE = frozenset({"&", "|", "^", "<<", ">>", ">>>", "&=", "|=", "^=", "<<=", ">>=", ">>>="})

_C_CALLS = {"call_expression": "function"}
_JS_CALLS = {"call_expression": "function", "new_expression": "constructor"}

SPECS: dict[str, LanguageSpec] = {
    "c": LanguageSpec(
        "c", "C", frozenset({"function_definition"}), frozenset(),
        {"struct_specifier": "name"}, frozenset({"if_statement"}),
        loops=frozenset({"for_statement", "while_statement", "do_statement"}),
        switches=frozenset({"switch_statement"}), cases=frozenset({"case_statement"}),
        ternaries=frozenset({"conditional_expression"}), gotos=frozenset({"goto_statement"}),
        calls=_C_CALLS,
        unsupported=frozenset({"preproc_if", "preproc_ifdef", "preproc_elif", "preproc_else"})),
    "cpp": LanguageSpec(
        "cpp", "C++", frozenset({"function_definition", "lambda_expression"}), frozenset({"lambda_expression"}),
        {"class_specifier": "name", "struct_specifier": "name", "namespace_definition": "name"},
        frozenset({"if_statement"}),
        loops=frozenset({"for_statement", "for_range_loop", "while_statement", "do_statement"}),
        switches=frozenset({"switch_statement"}), cases=frozenset({"case_statement"}),
        catches=frozenset({"catch_clause"}), ternaries=frozenset({"conditional_expression"}),
        gotos=frozenset({"goto_statement"}), calls={**_C_CALLS, "new_expression": "type"},
        unsupported=frozenset({"preproc_if", "preproc_ifdef", "preproc_elif", "preproc_else"})),
    "java": LanguageSpec(
        "java", "Java",
        frozenset({"method_declaration", "constructor_declaration", "compact_constructor_declaration",
                   "lambda_expression"}),
        frozenset({"lambda_expression"}),
        {"class_declaration": "name", "interface_declaration": "name", "enum_declaration": "name",
         "record_declaration": "name"},
        frozenset({"if_statement"}), else_wrappers=frozenset(),
        loops=frozenset({"for_statement", "enhanced_for_statement", "while_statement", "do_statement"}),
        switches=frozenset({"switch_expression"}), cases=frozenset({"switch_label"}),
        catches=frozenset({"catch_clause"}), ternaries=frozenset({"ternary_expression"}),
        labeled_jumps=frozenset({"break_statement", "continue_statement"}),
        calls={"method_invocation": "name", "object_creation_expression": "type"}),
    "csharp": LanguageSpec(
        "csharp", "C#",
        frozenset({"method_declaration", "constructor_declaration", "destructor_declaration",
                   "operator_declaration", "conversion_operator_declaration", "local_function_statement",
                   "accessor_declaration", "lambda_expression", "anonymous_method_expression"}),
        frozenset({"lambda_expression", "anonymous_method_expression"}),
        {"class_declaration": "name", "struct_declaration": "name", "interface_declaration": "name",
         "record_declaration": "name", "namespace_declaration": "name",
         "file_scoped_namespace_declaration": "name"},
        frozenset({"if_statement"}), else_wrappers=frozenset(),
        loops=frozenset({"for_statement", "foreach_statement", "while_statement", "do_statement"}),
        switches=frozenset({"switch_statement", "switch_expression"}), cases=frozenset({"switch_section"}),
        multiway={"switch_expression": frozenset({"switch_expression_arm"})},
        guards=frozenset({"when_clause", "catch_filter_clause"}),
        catches=frozenset({"catch_clause"}), ternaries=frozenset({"conditional_expression"}),
        gotos=frozenset({"goto_statement"}),
        calls={"invocation_expression": "function", "object_creation_expression": "type"},
        unsupported=frozenset({"preproc_if", "preproc_elif", "preproc_else"})),
    "go": LanguageSpec(
        "go", "Go", frozenset({"function_declaration", "method_declaration", "func_literal"}),
        frozenset({"func_literal"}), {}, frozenset({"if_statement"}), else_wrappers=frozenset(),
        loops=frozenset({"for_statement"}),
        switches=frozenset({"expression_switch_statement", "type_switch_statement", "select_statement"}),
        cases=frozenset({"expression_case", "type_case", "communication_case"}),
        gotos=frozenset({"goto_statement"}),
        labeled_jumps=frozenset({"break_statement", "continue_statement"}), calls=_C_CALLS),
    "javascript": LanguageSpec(
        "javascript", "JavaScript",
        frozenset({"function_declaration", "function_expression", "function", "generator_function_declaration",
                   "generator_function", "arrow_function", "method_definition"}),
        frozenset({"function_expression", "function", "generator_function", "arrow_function"}),
        {"class_declaration": "name", "class": "name"}, frozenset({"if_statement"}),
        loops=frozenset({"for_statement", "for_in_statement", "while_statement", "do_statement"}),
        switches=frozenset({"switch_statement"}), cases=frozenset({"switch_case"}),
        catches=frozenset({"catch_clause"}), ternaries=frozenset({"ternary_expression"}),
        labeled_jumps=frozenset({"break_statement", "continue_statement"}), calls=_JS_CALLS),
    "rust": LanguageSpec(
        "rust", "Rust", frozenset({"function_item", "closure_expression"}), frozenset({"closure_expression"}),
        {"impl_item": "type", "trait_item": "name", "mod_item": "name"}, frozenset({"if_expression"}),
        loops=frozenset({"for_expression", "while_expression", "loop_expression"}),
        switches=frozenset({"match_expression"}), multiway={"match_expression": frozenset({"match_arm"})},
        labeled_jumps=frozenset({"break_expression", "continue_expression"}),
        calls={"call_expression": "function", "macro_invocation": "macro"},
        unsupported=frozenset({"macro_invocation"})),
    "php": LanguageSpec(
        "php", "PHP",
        frozenset({"function_definition", "method_declaration", "anonymous_function",
                   "anonymous_function_creation_expression", "arrow_function"}),
        frozenset({"anonymous_function", "anonymous_function_creation_expression", "arrow_function"}),
        {"class_declaration": "name", "interface_declaration": "name", "trait_declaration": "name",
         "enum_declaration": "name"},
        frozenset({"if_statement"}), else_if_types=frozenset({"else_if_clause"}),
        loops=frozenset({"for_statement", "foreach_statement", "while_statement", "do_statement"}),
        switches=frozenset({"switch_statement", "match_expression"}), cases=frozenset({"case_statement"}),
        multiway={"match_expression": frozenset({"match_conditional_expression", "match_default_expression"})},
        catches=frozenset({"catch_clause"}), ternaries=frozenset({"conditional_expression"}),
        gotos=frozenset({"goto_statement"}),
        calls={"function_call_expression": "function", "member_call_expression": "name",
               "nullsafe_member_call_expression": "name", "scoped_call_expression": "name",
               "object_creation_expression": "type"}),
}
for _grammar, _language in (("typescript", "TypeScript"), ("tsx", "TSX")):
    _base = SPECS["javascript"]
    SPECS[_grammar] = LanguageSpec(
        _grammar, _language, _base.units, _base.anonymous,
        {**_base.containers, "abstract_class_declaration": "name", "internal_module": "name", "module": "name"},
        _base.if_types, loops=_base.loops, switches=_base.switches, cases=_base.cases,
        catches=_base.catches, ternaries=_base.ternaries, labeled_jumps=_base.labeled_jumps,
        calls=_base.calls)

# Grammars inside the Tree-sitter producer that this batch does not score.
UNSCORED_GRAMMARS = frozenset({"python"})
CONDITION_FIELDS = frozenset({"condition", "value", "initializer", "update", "right", "left", "subject"})
