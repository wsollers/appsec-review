"""Deterministic AST validators for a proof-of-concept function (spec section 5.3).

``check_ast`` is a pure function of the reduced clang AST (``ast_reduce.reduce_ast``), the typed
settings and what the brief expects. It is closed in both directions:

* every node kind inside the PoC functions must be on a short allowlist of kinds, so a construct the
  validator has no opinion about (inline assembly, a lambda, ``goto``, ``while``, an exception throw) is
  rejected rather than waved through;
* every function or variable the PoC references must be on the closed call allowlist (or be the
  sink, or a function the brief's path names); the denylist only names the category of what was
  refused, and the allowlist wins when a name is on both;
* a type constructed, declared or cast must be a builtin, a project type or on the type allowlist.

The model never repairs its way past a verdict: a violation is the candidate's status
``policy_denied``. Violations carry a rule from the closed ``RULES`` vocabulary, a bounded message
and the line in the generated file.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import re
from typing import Any

from .ast_reduce import SCHEMA as AST_SCHEMA, canonical
from .settings import PocGenerationSettings, matches

RULES = (
    "ast_schema", "entry_point", "unexpected_declaration", "missing_function", "duplicate_function", "signature",
    "unsupported_construct", "inline_asm", "pragma", "attribute", "unbounded_loop", "recursion",
    "call_not_allowlisted", "indirect_call", "global_variable", "unresolved_reference", "type_not_allowed",
    "array_size", "allocation_size", "string_literal", "secret_literal", "url_literal", "path_literal",
    "sink_not_called", "trigger_absent", "storage_class", "too_many_violations",
    "name", "size", "encoding", "preprocessor", "include",
)
ENTRY_NAMES = frozenset({"main", "wmain", "WinMain", "wWinMain", "DllMain", "_start", "_main", "DllEntryPoint"})
ALLOWED_KINDS = frozenset({
    "CompoundStmt", "DeclStmt", "VarDecl", "IntegerLiteral", "CharacterLiteral", "StringLiteral", "FloatingLiteral",
    "CXXBoolLiteralExpr", "CXXNullPtrLiteralExpr", "InitListExpr", "ImplicitValueInitExpr", "ImplicitCastExpr",
    "CStyleCastExpr", "CXXStaticCastExpr", "CXXReinterpretCastExpr", "CXXFunctionalCastExpr", "CXXConstCastExpr",
    "DeclRefExpr", "MemberExpr", "ArraySubscriptExpr", "CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr",
    "CXXConstructExpr", "CXXTemporaryObjectExpr", "CXXBindTemporaryExpr", "MaterializeTemporaryExpr",
    "ExprWithCleanups", "ParenExpr", "BinaryOperator", "CompoundAssignOperator", "UnaryOperator",
    "ConditionalOperator", "UnaryExprOrTypeTraitExpr", "CXXNewExpr", "CXXDeleteExpr", "CXXDefaultArgExpr",
    "CXXDefaultInitExpr", "CXXStdInitializerListExpr", "ConstantExpr", "ArrayInitLoopExpr", "ArrayInitIndexExpr",
    "ForStmt", "IfStmt", "ReturnStmt", "BreakStmt", "ContinueStmt", "NullStmt", "SwitchStmt", "CaseStmt",
    "DefaultStmt", "CXXTryStmt", "CXXCatchStmt", "StaticAssertDecl", "TypeAliasDecl", "TypedefDecl",
    "CompoundLiteralExpr", "DesignatedInitExpr", "DesignatedInitUpdateExpr", "SubstNonTypeTemplateParmExpr",
    "CXXScalarValueInitExpr", "PredefinedExpr", "ImplicitValueInitExpr", "OpaqueValueExpr", "FunctionDecl",
    "ParmVarDecl",
})
SPECIFIC_KINDS = {
    "GCCAsmStmt": "inline_asm", "MSAsmStmt": "inline_asm", "AsmStmt": "inline_asm",
    "WhileStmt": "unbounded_loop", "DoStmt": "unbounded_loop", "GotoStmt": "unbounded_loop",
    "IndirectGotoStmt": "unbounded_loop", "LabelStmt": "unbounded_loop", "CXXForRangeStmt": "unbounded_loop",
    "PragmaCommentDecl": "pragma", "PragmaDetectMismatchDecl": "pragma",
}
ALLOWED_ATTRIBUTES = frozenset({"UnusedAttr", "MaybeUnusedAttr"})
CHILD_LISTS = ("inner", "array_filler")
TYPE_DECLARATION_KINDS = frozenset({"CXXRecordDecl", "RecordDecl", "EnumDecl", "TypedefDecl", "TypeAliasDecl",
                                    "ClassTemplateSpecializationDecl"})
FUNCTION_KINDS = frozenset({"FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl",
                            "CXXConversionDecl"})
TYPE_BEARING_KINDS = frozenset({"VarDecl", "UnaryExprOrTypeTraitExpr", "CStyleCastExpr", "CXXStaticCastExpr", "CXXReinterpretCastExpr",
                                "CXXFunctionalCastExpr", "CXXConstCastExpr", "CXXConstructExpr",
                                "CXXTemporaryObjectExpr", "CXXNewExpr", "CompoundLiteralExpr"})
BUILTIN_WORDS = frozenset({
    "void", "bool", "char", "signed", "unsigned", "short", "int", "long", "float", "double", "wchar_t", "char8_t",
    "char16_t", "char32_t", "const", "volatile", "restrict", "__int128", "struct", "class", "enum", "union",
    "typename", "noexcept", "true", "false", "nullptr", "decltype", "auto", "__restrict", "__attribute__",
})
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*")
_SIGNATURE = re.compile(r"^void \((?:void)?\)( noexcept(\(true\))?)?$")
_ARRAY = re.compile(r"\[([^\]]*)\]")
_STD_ARRAY = re.compile(r"std::array<[^<>]*?,\s*(\d+)\s*>")
_SIZED_CONTAINER = re.compile(r"\b(?:vector|basic_string|deque|list)\b")
_SIZE_TYPES = frozenset({"std::size_t", "size_t", "unsigned long", "long", "int", "unsigned int", "size_type",
                         "std::vector::size_type", "std::string::size_type", "unsigned long long"})
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://|\bwww\.[A-Za-z0-9-]+\.")
_ADDRESS = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
_PATH = re.compile(r"^\"?(?:/[A-Za-z0-9_.~$-]|[A-Za-z]:[\\/]|~[/\\]|\.\.[/\\])|[/\\]\.\.[/\\]|\.\.[/\\]")
_SECRET = re.compile(r"(?i)(password|passwd|secret|api[_-]?key|private[_-]?key|credential|authorization:|bearer\s|"
                     r"BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")
_TOKEN_RUN = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
_INTEGER = r"[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)"
_NUMBER = r"(?<![\w.+-])(" + _INTEGER + r")(?![\w.+-])"
_NUMERIC_TOKEN = re.compile(r"[+-]?[0-9][A-Za-z0-9_.]*")
_UNSUPPORTED_CONSTRAINT = re.compile(
    r"[=<>!≤≥+\-*/%&|^~−±]|\b(?:not|no|except|unless|and|or|but|between|equal|exactly|than)\b")


@dataclass(frozen=True, slots=True)
class Violation:
    rule: str
    message: str
    line: int | None = None
    function: str | None = None

    def record(self) -> dict[str, Any]:
        return {"rule": self.rule, "message": self.message[:240], "line": self.line, "function": self.function}


@dataclass(frozen=True, slots=True)
class Requirement:
    """A numeric trigger constraint from the brief, such as "greater than 16"."""

    operator: str
    low: int
    high: int | None
    text: str

    def satisfied_by(self, value: int) -> bool:
        return {">": value > self.low, ">=": value >= self.low, "<": value < self.low, "<=": value <= self.low,
                "==": value == self.low,
                "between": self.high is not None and self.low <= value <= self.high}[self.operator]


@dataclass(frozen=True, slots=True)
class Expectation:
    """What the brief says the functions must do; none of it comes from the model's answer."""

    functions: tuple[str, ...]                 # test function, then negative control
    sink_names: tuple[str, ...]                # qualified or bare names of the sink function
    path_calls: frozenset[str] = frozenset()   # project functions the brief's call path names
    triggers: tuple[Requirement, ...] = ()
    unchecked_triggers: tuple[str, ...] = field(default=())


def numeric_requirement(constraint: str) -> Requirement | None:
    """One signed integer condition, or ``None`` to retain an unchecked qualification."""
    text = " ".join(str(constraint).split())
    lowered = text.lower()
    patterns = (
        (r"between\s+" + _NUMBER + r"\s+and\s+" + _NUMBER, "between"),
        (r"(?:greater than or equal to|at least|no less than|not less than|>=|≥)\s*" + _NUMBER, ">="),
        (r"(?:less than or equal to|at most|no more than|not more than|<=|≤)\s*" + _NUMBER, "<="),
        (r"(?:greater than|more than|larger than|bigger than|longer than|exceed(?:s|ing)?|over|above|>)\s*" + _NUMBER, ">"),
        (r"(?:less than|fewer than|smaller than|shorter than|below|under|<)\s*" + _NUMBER, "<"),
        (r"(?:equal(?:s| to)?|exactly|==|=)\s*" + _NUMBER, "=="),
        (_NUMBER, "=="),
    )
    tokens = list(_NUMERIC_TOKEN.finditer(lowered))
    for pattern, operator in patterns:
        found = re.search(pattern, lowered)
        if not found:
            continue
        groups = (1, 2) if operator == "between" else (1,)
        if ([token.span() for token in tokens] != [found.span(group) for group in groups]
                or _UNSUPPORTED_CONSTRAINT.search(lowered[:found.start()] + " " + lowered[found.end():])):
            return None
        low = _integer_value(found.group(1))
        high = _integer_value(found.group(2)) if operator == "between" else None
        if low is None or (operator == "between" and (high is None or high < low)):
            return None
        return Requirement(operator, low, high, text[:120])
    return None


# --------------------------------------------------------------------------------------------------


class _Checker:
    def __init__(self, reduced: Mapping[str, Any], settings: PocGenerationSettings, expectation: Expectation):
        self.reduced = reduced
        self.settings = settings
        self.expectation = expectation
        self.source = str(reduced.get("source", ""))
        self.roots = tuple(str(root) for root in reduced.get("project_roots", ("/workspace/",)))
        self.declarations: Mapping[str, Mapping[str, Any]] = reduced.get("declarations", {})
        self.violations: list[Violation] = []
        self.function = ""
        self.project_types = {str(item["qualified"]) for item in reduced.get("project_declarations", ())
                             if item.get("kind") in TYPE_DECLARATION_KINDS}
        self.sink_hits: dict[str, int] = {}
        self.values: dict[str, set[int]] = {}
        self.unevaluated = False
        self.denylist = {category: tuple(items) for category, items in settings.policy.call_denylist.items()}

    # -- reporting ---------------------------------------------------------------------------------
    def add(self, rule: str, message: str, node: Mapping[str, Any] | None = None) -> None:
        line = node.get("line") if node else None
        violation = Violation(rule, message, line if isinstance(line, int) else None, self.function or None)
        if violation not in self.violations:
            self.violations.append(violation)

    def category(self, name: str) -> str | None:
        base = name.rsplit("::", 1)[-1]
        for category, entries in self.denylist.items():
            if matches(name, entries) or matches(base, entries):
                return category
        return None

    def in_project(self, path: str) -> bool:
        return any(path.startswith(root) for root in self.roots)

    # -- traversal ---------------------------------------------------------------------------------
    def run(self) -> list[Violation]:
        if self.reduced.get("schema") != AST_SCHEMA:
            return [Violation("ast_schema", "the reduced AST does not carry the poc-ast/1 schema")]
        nodes = [node for node in self.reduced.get("nodes", ()) if isinstance(node, Mapping)]
        defined: dict[str, list[Mapping[str, Any]]] = {}
        for node in nodes:
            self.top_level(node, defined)
        for name in self.expectation.functions:
            found = defined.get(name, [])
            if not found:
                self.add("missing_function", f"the translation unit does not define the function {name}")
            elif len(found) > 1:
                self.add("duplicate_function", f"the function {name} is declared or defined more than once")
        for name in self.expectation.functions:
            for node in defined.get(name, [])[:1]:
                self.function = name
                self.check_function(node)
        self.function = ""
        self.check_sink_and_triggers()
        if len(self.violations) > self.settings.bounds.max_violations:
            del self.violations[self.settings.bounds.max_violations:]
            self.violations.append(Violation("too_many_violations",
                                             f"more than {self.settings.bounds.max_violations} violations"))
        return sorted(self.violations, key=lambda item: (item.line or 0, item.rule, item.message))

    def top_level(self, node: Mapping[str, Any], defined: dict[str, list[Mapping[str, Any]]]) -> None:
        kind, name = node.get("kind"), node.get("name")
        self.entry_names(node)
        if kind == "FunctionDecl" and name in self.expectation.functions:
            defined.setdefault(str(name), []).append(node)
            return
        if kind in SPECIFIC_KINDS:
            self.add(SPECIFIC_KINDS[str(kind)], f"{kind} is not allowed at file scope", node)
        else:
            self.add("unexpected_declaration",
                     f"the file may define only the two PoC functions; found {kind}{' ' + str(name) if name else ''}",
                     node)

    def entry_names(self, node: Mapping[str, Any]) -> None:
        if node.get("name") in ENTRY_NAMES and node.get("kind") in FUNCTION_KINDS:
            self.add("entry_point", f"a definition named {node['name']} is a program entry point", node)
        for child in node.get("inner", ()) if isinstance(node.get("inner"), list) else ():
            if isinstance(child, Mapping) and child.get("kind") in {"NamespaceDecl", "LinkageSpecDecl",
                                                                     "CXXRecordDecl", "RecordDecl"}:
                self.entry_names(child)
            elif isinstance(child, Mapping) and child.get("name") in ENTRY_NAMES:
                self.entry_names(child)

    def check_function(self, node: Mapping[str, Any]) -> None:
        children = [child for child in node.get("inner", ()) if isinstance(child, Mapping)]
        if not _SIGNATURE.match(str((node.get("type") or {}).get("qualType", ""))):
            self.add("signature", "a PoC function takes no arguments and returns nothing", node)
        if any(child.get("kind") == "ParmVarDecl" for child in children):
            self.add("signature", "a PoC function takes no arguments", node)
        if node.get("storageClass"):
            self.add("storage_class", f"a PoC function is not {node['storageClass']}", node)
        if node.get("constexpr") or node.get("variadic"):
            self.add("signature", "a PoC function is an ordinary function", node)
        bodies = [child for child in children if child.get("kind") == "CompoundStmt"]
        if len(bodies) != 1:
            self.add("missing_function", f"the function {self.function} has no body", node)
        for child in children:
            if child.get("kind") == "CompoundStmt":
                self.walk(child, 1)
            elif str(child.get("kind", "")).endswith("Attr"):
                self.attribute(child)
            elif child.get("kind") != "ParmVarDecl":
                self.add("unsupported_construct", f"{child.get('kind')} is not allowed on a PoC function", child)

    def attribute(self, node: Mapping[str, Any]) -> None:
        if node.get("isImplicit") or node.get("kind") in ALLOWED_ATTRIBUTES:
            return
        self.add("attribute", f"{node.get('kind')} is not allowed on a PoC function", node)

    def walk(self, node: Mapping[str, Any], multiplier: int) -> None:
        kind = node.get("kind")
        if not kind:
            return                                               # clang prints an absent child as {}
        text = str(kind)
        if text.endswith("Attr"):
            self.attribute(node)
            return
        if text.endswith("Comment"):
            return
        if text in SPECIFIC_KINDS or "Pragma" in text or text.startswith("OMP"):
            self.add(SPECIFIC_KINDS.get(text, "pragma"), f"{text} is not allowed", node)
        elif text not in ALLOWED_KINDS:
            self.add("unsupported_construct", f"{text} is not an allowed construct in a PoC function", node)
        handler = getattr(self, f"on_{text}", None)
        if text in TYPE_BEARING_KINDS:
            self.types(node)
        if handler is not None:
            if handler(node, multiplier) is False:
                return
        previous = self.unevaluated
        self.unevaluated |= text in {
            "UnaryExprOrTypeTraitExpr", "TypeAliasDecl", "TypedefDecl", "StaticAssertDecl", "FunctionDecl"}
        try:
            for key in CHILD_LISTS:                  # includes implicit filler elements of an array initializer
                for child in node.get(key, ()) if isinstance(node.get(key), list) else ():
                    if isinstance(child, Mapping):
                        self.walk(child, multiplier)
        finally:
            self.unevaluated = previous

    # -- per-kind rules ----------------------------------------------------------------------------
    def on_DeclRefExpr(self, node: Mapping[str, Any], _multiplier: int) -> None:
        reference = node.get("referencedDecl")
        if not isinstance(reference, Mapping):
            self.add("unresolved_reference", "a reference does not name its declaration", node)
            return
        self.reference(str(reference.get("id", "")), str(reference.get("kind", "")), str(reference.get("name", "")),
                       node)

    def on_MemberExpr(self, node: Mapping[str, Any], _multiplier: int) -> None:
        identity = node.get("referencedMemberDecl")
        info = self.declarations.get(str(identity)) if isinstance(identity, str) else None
        if info is None:
            self.add("unresolved_reference", f"member {node.get('name')} cannot be resolved", node)
            return
        self.reference(str(identity), str(info["kind"]), str(info["name"]), node)

    def reference(self, identity: str, kind: str, name: str, node: Mapping[str, Any]) -> None:
        info = self.declarations.get(identity)
        qualified = str(info["qualified"]) if info else name
        path = str(info["file"]) if info else ""
        if kind in FUNCTION_KINDS:
            self.function_reference(qualified, path, info is not None, node)
        elif kind == "VarDecl":
            if path != self.source and not matches(qualified, self.settings.policy.call_allowlist):
                self.add("global_variable", f"{qualified} is a variable the PoC may not reference", node)
        elif kind in {"EnumConstantDecl", "FieldDecl"}:
            return
        else:
            self.add("unresolved_reference", f"{kind} {qualified} is not a reference the PoC may make", node)

    def function_reference(self, qualified: str, path: str, resolved: bool, node: Mapping[str, Any]) -> None:
        if resolved and path == self.source:
            self.add("recursion", f"{qualified} is a PoC function; a PoC function calls nothing it defines", node)
            return
        if matches(qualified, self.settings.policy.call_allowlist):
            return
        if not resolved:
            self.add("unresolved_reference", f"{qualified} cannot be resolved to a declaration", node)
            return
        if self.in_project(path):
            if (self.is_sink(qualified) or qualified in self.expectation.path_calls
                    or self.settings.policy.project_calls == "any_project_function"):
                return
            self.add("call_not_allowlisted",
                     f"{qualified} is a project function that is neither the sink nor on the brief's call path", node)
            return
        category = self.category(qualified)
        self.add("call_not_allowlisted",
                 f"{qualified} is " + (f"a {category.replace('_', ' ')} API and not allowlisted" if category
                                      else "not on the closed call allowlist"), node)

    def is_sink(self, qualified: str) -> bool:
        return any(qualified == sink or qualified.endswith("::" + sink) or sink.endswith("::" + qualified)
                   for sink in self.expectation.sink_names)

    def on_CallExpr(self, node: Mapping[str, Any], _multiplier: int) -> None:
        children = _children(node)
        callee = _unwrapped(children[0]) if children else {}
        reference = callee.get("referencedDecl") if callee.get("kind") == "DeclRefExpr" else None
        identity = reference.get("id") if isinstance(reference, Mapping) else None
        if node.get("kind") == "CXXMemberCallExpr" and callee.get("kind") == "MemberExpr":
            identity = callee.get("referencedMemberDecl")
        elif not (isinstance(reference, Mapping) and reference.get("kind") in FUNCTION_KINDS):
            self.add("indirect_call", "a call must name its function directly", node)
            return
        info = self.declarations.get(str(identity))
        if not isinstance(info, Mapping) or info.get("kind") not in FUNCTION_KINDS:
            self.add("unresolved_reference", "the callee cannot be resolved to a function declaration", node)
            return
        if not self.unevaluated and self.is_sink(str(info.get("qualified", ""))):
            self.sink_hits[self.function] = self.sink_hits.get(self.function, 0) + 1

    on_CXXOperatorCallExpr = on_CallExpr
    on_CXXMemberCallExpr = on_CallExpr

    def on_StringLiteral(self, node: Mapping[str, Any], _multiplier: int) -> None:
        value = str(node.get("value", ""))
        body = value[1:-1] if len(value) >= 2 else value
        if len(body.encode("utf-8", "replace")) > self.settings.bounds.max_string_literal_bytes:
            self.add("string_literal", "a string literal exceeds the configured size", node)
        if _URL.search(body) or _ADDRESS.search(body):
            self.add("url_literal", "a string literal looks like a URL or network address", node)
        if _PATH.search(value):
            self.add("path_literal", "a string literal looks like a path outside the source tree", node)
        if _SECRET.search(body) or any(len(set(run)) >= 12 for run in _TOKEN_RUN.findall(body)):
            self.add("secret_literal", "a string literal looks like a secret", node)
        self.note(len(body.encode("utf-8", "replace")))

    def on_IntegerLiteral(self, node: Mapping[str, Any], _multiplier: int) -> None:
        value = _literal(node)
        if value is None:
            self.add("unsupported_construct", "an integer literal has no supported integer value", node)
        else:
            self.note(value)

    def on_UnaryOperator(self, node: Mapping[str, Any], _multiplier: int) -> bool:
        if node.get("opcode") in {"+", "-"}:
            return self.literal_expression(node)
        return True

    def on_ImplicitCastExpr(self, node: Mapping[str, Any], _multiplier: int) -> bool:
        return self.literal_expression(node)

    def literal_expression(self, node: Mapping[str, Any]) -> bool:
        value = _literal(node)
        if value is not None:
            self.note(value)
            return False
        # A known operand is not evidence of an unproven negation/conversion result. Nonliteral
        # operands still need traversal: their calls, references and arguments retain their checks.
        return _literal(_only_child(node)) is None

    def note(self, value: int) -> None:
        if not self.unevaluated:
            self.values.setdefault(self.function, set()).add(value)

    def on_VarDecl(self, node: Mapping[str, Any], _multiplier: int) -> None:
        if node.get("storageClass") in {"extern", "static"}:
            self.add("storage_class", f"a PoC variable is not {node['storageClass']}", node)
        qualified = str((node.get("type") or {}).get("qualType", ""))
        total = 1
        for size in _ARRAY.findall(qualified):
            if not size.isdigit():
                self.add("array_size", f"array size [{size}] is not a constant", node)
                return
            total *= int(size)
            self.note(int(size))
        for size in _STD_ARRAY.findall(qualified):
            total *= int(size)
            self.note(int(size))
        if total > self.settings.bounds.max_array_elements:
            self.add("array_size", f"array of {total} elements exceeds the configured bound", node)

    def on_CXXConstructExpr(self, node: Mapping[str, Any], _multiplier: int) -> None:
        """A sized container or string is built with a literal size within the same bound as an array."""
        type_text = str((node.get("type") or {}).get("desugaredQualType") or (node.get("type") or {}).get("qualType", ""))
        if not _SIZED_CONTAINER.search(type_text):
            return
        for child in node.get("inner", ()) if isinstance(node.get("inner"), list) else ():
            if not isinstance(child, Mapping):
                continue
            argument = str((child.get("type") or {}).get("qualType", ""))
            if argument in _SIZE_TYPES:
                count = _literal(child)
                if count is None or not 0 <= count <= self.settings.bounds.max_array_elements:
                    self.add("allocation_size", "a container or string size must be a literal within the array bound",
                             node)

    on_CXXTemporaryObjectExpr = on_CXXConstructExpr

    def on_CXXNewExpr(self, node: Mapping[str, Any], _multiplier: int) -> bool:
        if node.get("isArray"):
            children = [child for child in node.get("inner", ()) if isinstance(child, Mapping)]
            size = children[0] if children else {}
            while size.get("kind") == "ImplicitCastExpr" and size.get("inner"):
                size = size["inner"][0]
            try:
                count = int(str(size.get("value", "x")), 0) if size.get("kind") == "IntegerLiteral" else None
            except ValueError:
                count = None
            if count is None or count > self.settings.bounds.max_array_elements:
                self.add("allocation_size", "an array allocation must have a constant size within the bound", node)
        return True

    def on_ForStmt(self, node: Mapping[str, Any], multiplier: int) -> bool:
        parts = _children(node)
        if len(parts) != 5:
            self.add("unbounded_loop", "a for loop must have an initializer, a bound and a step", node)
            return True
        init, condition_variable, condition, step, body = parts
        bound = None if condition_variable else self.loop_bound(init, condition, step, body)
        if bound is None:
            self.add("unbounded_loop",
                     "a for loop needs a finite, non-overflowing local integer progression with no body mutation",
                     node)
        else:
            multiplier *= max(1, bound)
            if bound > self.settings.bounds.max_loop_iterations or multiplier > self.settings.bounds.max_loop_iterations:
                self.add("unbounded_loop",
                         f"loop iterations exceed the configured bound of {self.settings.bounds.max_loop_iterations}",
                         node)
        for child in (init, condition, step, body):
            if child.get("kind"):
                self.walk(child, multiplier)
        return False

    def loop_bound(self, init: Mapping[str, Any], condition: Mapping[str, Any], step: Mapping[str, Any],
                   body: Mapping[str, Any]
                   ) -> int | None:
        decls = _children(init)
        if init.get("kind") != "DeclStmt" or len(decls) != 1 or decls[0].get("kind") != "VarDecl":
            return None
        variable = decls[0]
        limits = _integer_range(variable)
        initial = _literal(_only_child(variable))
        if (not variable.get("id") or limits is None or initial is None or not body.get("kind")
                or not _counter_read_only(body, variable)
                or condition.get("kind") != "BinaryOperator" or condition.get("opcode") not in {
                "<", "<=", ">", ">=", "!="}):
            return None
        sides = _children(condition)
        if (len(sides) != 2 or not _loop_reference(sides[0], variable)
                or (limit := _literal(sides[1])) is None):
            return None
        parts = _children(step)
        if step.get("kind") == "UnaryOperator" and step.get("opcode") in {"++", "--"}:
            if len(parts) != 1 or not _loop_reference(parts[0], variable):
                return None
            stride = 1 if step["opcode"] == "++" else -1
        elif step.get("kind") == "CompoundAssignOperator" and step.get("opcode") in {"+=", "-="}:
            if (len(parts) != 2 or not _loop_reference(parts[0], variable)
                    or (stride := _literal(parts[1])) is None):
                return None
            stride *= 1 if step["opcode"] == "+=" else -1
        else:
            return None
        low, high = limits
        if stride == 0 or not all(low <= value <= high for value in (initial, limit)):
            return None
        operator = str(condition["opcode"])
        active = (initial != limit if operator == "!=" else
                  Requirement(operator, limit, None, "").satisfied_by(initial))
        if not active:
            return 0
        direction = 1 if operator in {"<", "<="} else -1 if operator in {">", ">="} else (
            1 if limit > initial else -1)
        if stride * direction <= 0:
            return None
        distance, magnitude = abs(limit - initial), abs(stride)
        if operator == "!=" and distance % magnitude:
            return None
        count = (distance // magnitude + 1 if operator in {"<=", ">="}
                 else (distance + magnitude - 1) // magnitude)
        # The final step happens before the failed condition, even at an inclusive endpoint.
        return count if low <= initial + count * stride <= high else None

    # -- types -------------------------------------------------------------------------------------
    def types(self, node: Mapping[str, Any]) -> None:
        for key in ("type", "argType"):
            value = node.get(key)
            if not isinstance(value, Mapping):
                continue
            for field_name in ("qualType", "desugaredQualType"):
                text = value.get(field_name)
                if isinstance(text, str):
                    self.type_text(text, node)

    def type_text(self, text: str, node: Mapping[str, Any]) -> None:
        for raw in _IDENTIFIER.findall(text):
            token = canonical(raw)
            if token in BUILTIN_WORDS:
                continue
            if matches(token, self.settings.policy.type_allowlist) or self.project_type(token):
                continue
            self.add("type_not_allowed", f"the type {token} is not on the type allowlist and is not a project type",
                     node)

    def project_type(self, token: str) -> bool:
        return token in self.project_types or any(item.endswith("::" + token) for item in self.project_types)

    # -- brief expectations ------------------------------------------------------------------------
    def check_sink_and_triggers(self) -> None:
        for name in self.expectation.functions:
            if not self.sink_hits.get(name):
                self.function = name
                self.add("sink_not_called",
                         f"{name} never calls the sink function {', '.join(self.expectation.sink_names)}")
        self.function = self.expectation.functions[0] if self.expectation.functions else ""
        present = self.values.get(self.function, set())
        for requirement in self.expectation.triggers:
            if not any(requirement.satisfied_by(value) for value in present):
                self.add("trigger_absent",
                         f"no value in {self.function} satisfies the brief's trigger '{requirement.text}'")
        self.function = ""


def _integer_value(value: str) -> int | None:
    if not re.fullmatch(_INTEGER, value):
        return None
    try:
        return int(value, 16 if value.lstrip("+-").lower().startswith("0x") else 10)
    except ValueError:
        return None


def _children(node: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    children = node.get("inner", [])
    return children if isinstance(children, list) and all(isinstance(item, Mapping) for item in children) else []


def _only_child(node: Mapping[str, Any]) -> Mapping[str, Any]:
    children = _children(node)
    return children[0] if len(children) == 1 else {}


def _unwrapped(node: Mapping[str, Any]) -> Mapping[str, Any]:
    while node.get("kind") in {"ImplicitCastExpr", "ParenExpr"}:
        node = _only_child(node)
    return node


def _literal(node: Mapping[str, Any]) -> int | None:
    if node.get("kind") in {"ImplicitCastExpr", "ParenExpr"}:
        if node.get("kind") == "ImplicitCastExpr" and node.get("castKind") not in {"IntegralCast", "NoOp"}:
            return None
        value = _literal(_only_child(node))
        if value is not None and node.get("castKind") == "IntegralCast":
            limits = _integer_range(node)
            if limits is None or not limits[0] <= value <= limits[1]:
                return None
        return value
    if node.get("kind") == "IntegerLiteral":
        return _integer_value(str(node.get("value", "")))
    if node.get("kind") == "UnaryOperator" and node.get("opcode") in {"+", "-"}:
        inner = _literal(_only_child(node))
        if inner is None:
            return None
        value = inner * (-1 if node["opcode"] == "-" else 1)
        limits = _integer_range(node)
        return value if limits is not None and limits[0] <= value <= limits[1] else None
    return None


def _refers_to(node: Mapping[str, Any], variable: Mapping[str, Any]) -> bool:
    node = _unwrapped(node)
    reference = node.get("referencedDecl") if node.get("kind") == "DeclRefExpr" else None
    return bool(variable.get("id")) and isinstance(reference, Mapping) and reference.get("id") == variable["id"]


def _loop_reference(node: Mapping[str, Any], variable: Mapping[str, Any]) -> bool:
    while node.get("kind") in {"ImplicitCastExpr", "ParenExpr"}:
        if node.get("castKind") not in (None, "LValueToRValue", "NoOp"):
            return False
        node = _only_child(node)
    return _refers_to(node, variable)


def _counter_read_only(node: Mapping[str, Any], variable: Mapping[str, Any], *, read: bool = False) -> bool:
    if node.get("kind") == "DeclRefExpr" and _refers_to(node, variable):
        return read
    if node.get("kind") != "ParenExpr":
        read = node.get("kind") == "ImplicitCastExpr" and node.get("castKind") == "LValueToRValue"
    for key in CHILD_LISTS:
        children = node.get(key, [])
        if not isinstance(children, list) or not all(isinstance(child, Mapping) for child in children):
            return False
        if not all(_counter_read_only(child, variable, read=read) for child in children):
            return False
    return True


def _integer_range(node: Mapping[str, Any]) -> tuple[int, int] | None:
    """Portable minimum ranges: the reduced AST has no target integer-width metadata."""
    type_info = node.get("type") or {}
    words = str(type_info.get("desugaredQualType") or type_info.get("qualType", "")).split()
    if not words or any(word not in {"signed", "unsigned", "short", "long", "int", "char"} for word in words):
        return None
    base = " ".join(word for word in words if word not in {"signed", "unsigned", "int"})
    bits = {"": 16, "char": 8, "short": 16, "long": 32, "long long": 64}.get(base)
    if bits is None:
        return None
    unsigned = "unsigned" in words
    high = 2 ** (bits if unsigned else bits - 1) - 1
    return (0 if unsigned or words == ["char"] else -high, high)


def check_ast(reduced: Mapping[str, Any], settings: PocGenerationSettings, expectation: Expectation
              ) -> list[Violation]:
    """Every violation of the PoC policy in the reduced AST, in a stable order (empty when it passes)."""
    return _Checker(reduced, settings, expectation).run()


__all__ = ["ALLOWED_KINDS", "ENTRY_NAMES", "Expectation", "RULES", "Requirement", "Violation", "check_ast",
           "numeric_requirement"]
