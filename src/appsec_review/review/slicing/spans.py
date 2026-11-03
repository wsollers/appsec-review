"""Function spans: the named function or method that encloses a source line, in every catalog language.

A slice stays inside the functions its dataflow path passes through, so every anchor line needs the extent of
its enclosing *named* function or method. Lambdas, closures, anonymous functions and blocks are part of the
named function around them. Function-valued bindings are the exception: in JavaScript, TypeScript and Go,
``const f = (...) => {...}`` and ``f := func(...) {...}`` count as named. :func:`resolve` tries four layers
in order, most precise first, and the first one that answers wins. The winning layer is the span's
``basis``:

1. ``tree_sitter``: the accepted ``ast_node`` rows of the file whose ``file_sha256`` equals the anchor's.
   The innermost row of a callable node type (:data:`CALLABLES`, or a function literal bound to a name)
   whose lines contain the anchor gives the extent. When the parse has no errors and the rows cover the
   anchor line, finding no callable is definitive and produces a gap. The text layers never override that
   answer. If the parse has errors near the anchor, or the rows do not cover the line (the parser's node
   bound cut the file), resolution falls back to the next layers and records a ``slice_function_fallback``
   gap.
2. ``graph_symbol``: the function-name lines of accepted graph symbols for the file (same hash). The
   anchor's step symbol is tried first, then the nearest preceding header. The extent comes from the
   language's text rule.
3. ``text``: the language's header patterns (:data:`LANGUAGES`, keyed by suffix), scanning upward from the
   anchor for at most ``max_lines`` lines. The innermost header whose extent contains the anchor wins.
4. Otherwise ``None`` with a reason that names the language and the layers tried. The caller records it as
   a ``slice_function_unresolved`` gap and never invents a window.

Extent rules: ``indent`` (Python) is the block below the header. ``brace`` (C family, Java, C#, JS/TS, Go,
Rust, PHP, Kotlin, Swift, Scala, Dart, Objective-C, Shell, PowerShell) runs from the first body ``{`` at
parenthesis depth 0 to its matching ``}``, ignoring braces in that language's strings, character literals
and comments. An expression body (``= expr``, ``=> expr``) ends at its statement's end, and a header with
no body is a declaration, not a function. ``keyword`` (Ruby) runs from ``def`` to the matching ``end``. An
extent longer than ``max_lines`` is cut and marked truncated.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
import re
from typing import Any

SPAN_TREE_SITTER = "tree_sitter"
SPAN_GRAPH_SYMBOL = "graph_symbol"
SPAN_TEXT = "text"
SPAN_BASES = (SPAN_TREE_SITTER, SPAN_GRAPH_SYMBOL, SPAN_TEXT)   # most precise first
GAP_FUNCTION_FALLBACK = "slice_function_fallback"
MAX_FUNCTION_LINES = 160
UNKNOWN_WINDOW = 40


@dataclass(frozen=True, slots=True)
class Extent:
    first: int
    last: int
    truncated: bool
    basis: str
    name: str | None = None


@dataclass(frozen=True, slots=True)
class Header:
    """A graph symbol's function-name line in one file."""

    line: int
    name: str | None = None
    identity: str | None = None


@dataclass(frozen=True, slots=True)
class Resolution:
    """The enclosing function's extent, or ``None`` with ``reason``. ``notes`` are gaps recorded either way."""

    extent: Extent | None
    reason: str | None = None
    notes: tuple[str, ...] = ()


# ------------------------------------------------------------------------------------------------
# Text rules


@dataclass(frozen=True, slots=True)
class _Lexis:
    line_comments: tuple[str, ...] = ("//",)
    block_comment: tuple[str, str] | None = ("/*", "*/")
    quotes: str = "\"'"
    char_quote: bool = False    # "'" quotes one character (C family, Java, C#, Go, Rust, Kotlin, Scala)
    escape: str = "\\"
    hash_comment: bool = False  # "#" starts a comment at line start or after whitespace (not "#[" or "${#")


@dataclass(frozen=True, slots=True)
class _Language:
    name: str
    extent: str                                 # "indent" | "brace" | "keyword"
    headers: tuple[re.Pattern[str], ...]
    lexis: _Lexis = _Lexis()


_C_LEXIS = _Lexis(char_quote=True)
_GO_LEXIS = _Lexis(quotes="\"'`", char_quote=True)
_JS_LEXIS = _Lexis(quotes="\"'`")
_SWIFT_LEXIS = _Lexis(quotes="\"")
_PHP_LEXIS = _Lexis(hash_comment=True)
_SHELL_LEXIS = _Lexis(line_comments=(), block_comment=None, hash_comment=True)
_POWERSHELL_LEXIS = _Lexis(line_comments=(), block_comment=("<#", "#>"), escape="`", hash_comment=True)
_CHAR = re.compile(r"'(?:\\[^']{1,10}|[^\\'])'")

_KEYWORDS = ("if|else|for|foreach|while|do|switch|case|return|throw|new|delete|sizeof|catch|try|finally|"
             "synchronized|using|lock|fixed|checked|unchecked|unsafe|when|match|with|await|yield|typeof|"
             "alignof|decltype|static_assert|assert|defined|elif|until|loop|select|go|defer|in|is|as|not|"
             "and|or|throws|requires|noexcept|template|operator\\s*[=!<>]")
_GENERIC = re.compile(rf"^\s*(?!\s|(?:{_KEYWORDS})\b)[^;{{}}()=]*?(?<![.>\w])(?<!->)([A-Za-z_~][\w:<>~]*)\s*\(")
_OBJC_METHOD = re.compile(r"^\s*[-+]\s*\([^)]*\)\s*(\w+)")
_JS_FUNCTION = re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:declare\s+)?(?:async\s+)?function\s*\*?\s*"
                          r"([A-Za-z_$][\w$]*)\s*[<(]")
_JS_BINDING = re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::.*?)?=\s*(?:async\s+)?"
                         r"(?:function\b|\(.*?\)\s*(?::[^=]*)?=>|[A-Za-z_$][\w$]*\s*=>)")
_JS_PROPERTY = re.compile(r"^\s*(?:(?:public|private|protected|static|readonly|override)\s+)*(?:this\.)?"
                          r"([A-Za-z_$#][\w$.]*)\s*(?::[^=(]*)?[:=]\s*(?:async\s+)?"
                          r"(?:function\b|\(.*?\)\s*(?::[^=]*)?=>|[A-Za-z_$][\w$]*\s*=>)")
_JS_METHOD = re.compile(r"^\s*(?:(?:public|private|protected|static|async|get|set|readonly|override|abstract|"
                        r"accessor)\s+)*\*?\s*(?!(?:if|for|while|switch|catch|function|return|with|await|yield|"
                        r"typeof|new|delete|void|super|import)\b)([A-Za-z_$#][\w$]*)\s*(?:<[^>]*>)?\s*\(")
_GO_FUNC = re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)")
_GO_BINDING = re.compile(r"^\s*(?:var\s+)?([A-Za-z_]\w*)(?:\s+[^=:]+)?\s*:?=\s*func\s*\(")
_RUST_FN = re.compile(r"^\s*(?:[\w\"()]+\s+)*?fn\s+([A-Za-z_]\w*)")
_KOTLIN_FUN = re.compile(r"^\s*(?:@?[\w.]+(?:\([^)]*\))?\s+)*?fun\s+(?:<[^>]*>\s*)?(?:[\w.<>?, ]+\.)?"
                         r"(\w+|`[^`]+`)\s*\(")
_KOTLIN_OTHER = re.compile(r"^\s*(?:@?\w+\s+)*?(constructor)\s*\(|^\s*(init)\s*\{|^\s*(?:@?\w+\s+)*?(get|set)\s*\(")
_SWIFT_FUNC = re.compile(r"^\s*(?:@?\w+(?:\([^)]*\))?\s+)*?(?:func\s+([^\s(<]+)|(init|deinit|subscript)\b)")
_SCALA_DEF = re.compile(r"^\s*(?:@?[\w\[\]]+\s+)*?def\s+([^\s(\[:=]+)")
_PHP_FUNCTION = re.compile(r"^\s*(?:(?:public|private|protected|static|final|abstract|readonly)\s+)*function\s+"
                           r"&?\s*([A-Za-z_]\w*)\s*\(")
_PYTHON_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)")
_RUBY_DEF = re.compile(r"^\s*def\s+(\S+?)(?=\(|\s|;|$)")
_SHELL_FUNCTION = re.compile(r"^\s*(?:function\s+([\w.:@+-]+)\s*(?:\(\s*\))?|([\w.:@+-]+)\s*\(\s*\))\s*"
                             r"(?:[{(].*|#.*)?$")
_POWERSHELL_FUNCTION = re.compile(r"^\s*(?:function|filter|workflow)\s+([\w.:-]+)", re.IGNORECASE)
_POWERSHELL_METHOD = re.compile(
    r"^\s*(?:(?:static|hidden)\s+)*\[[^\]]+\]\s*(\w+)\s*\(|^\s*(?:(?:static|hidden)\s+)+(\w+)\s*\(|"
    r"^\s*(?!(?:if|elseif|foreach|for|while|switch|catch|until|trap|param|return|do)\b)(\w+)\s*\([^)]*\$[^)]*\)\s*"
    r"(?:\{.*)?$", re.IGNORECASE)

_C_FAMILY = _Language("C/C++", "brace", (_GENERIC,), _C_LEXIS)
_JS = _Language("JavaScript/TypeScript", "brace", (_JS_FUNCTION, _JS_BINDING, _JS_PROPERTY, _JS_METHOD), _JS_LEXIS)
LANGUAGES: dict[str, _Language] = {
    **{suffix: _Language("Python", "indent", (_PYTHON_DEF,)) for suffix in (".py", ".pyi", ".pyw")},
    **{suffix: _C_FAMILY for suffix in (".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".h++",
                                        ".inl", ".ipp", ".tpp")},
    **{suffix: _Language("Objective-C", "brace", (_OBJC_METHOD, _GENERIC), _C_LEXIS) for suffix in (".m", ".mm")},
    ".java": _Language("Java", "brace", (_GENERIC,), _C_LEXIS),
    ".cs": _Language("C#", "brace", (_GENERIC,), _C_LEXIS),
    ".dart": _Language("Dart", "brace", (_GENERIC,), _JS_LEXIS),
    **{suffix: _JS for suffix in (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")},
    ".go": _Language("Go", "brace", (_GO_FUNC, _GO_BINDING), _GO_LEXIS),
    ".rs": _Language("Rust", "brace", (_RUST_FN,), _C_LEXIS),
    ".php": _Language("PHP", "brace", (_PHP_FUNCTION,), _PHP_LEXIS),
    **{suffix: _Language("Kotlin", "brace", (_KOTLIN_FUN, _KOTLIN_OTHER), _GO_LEXIS) for suffix in (".kt", ".kts")},
    ".swift": _Language("Swift", "brace", (_SWIFT_FUNC,), _SWIFT_LEXIS),
    **{suffix: _Language("Scala", "brace", (_SCALA_DEF,), _C_LEXIS) for suffix in (".scala", ".sc")},
    **{suffix: _Language("Shell", "brace", (_SHELL_FUNCTION,), _SHELL_LEXIS)
       for suffix in (".sh", ".bash", ".zsh", ".ksh")},
    **{suffix: _Language("PowerShell", "brace", (_POWERSHELL_FUNCTION, _POWERSHELL_METHOD), _POWERSHELL_LEXIS)
       for suffix in (".ps1", ".psm1")},
    ".rb": _Language("Ruby", "keyword", (_RUBY_DEF,)),
}
_CONTINUATION = (",", "(", "[", "=", "=>", "->", ":", "&&", "||", "+", "-", "*", "/", ".", "?", "\\", "|", "`")


def language_of(path: str) -> _Language | None:
    return LANGUAGES.get(PurePosixPath(path).suffix.lower())


def _indent(text: str) -> int:
    return len(text) - len(text.lstrip())


def _next_code_line(lines: Sequence[str], number: int, limit: int) -> str | None:
    for candidate in range(number + 1, limit + 1):
        if lines[candidate - 1].strip():
            return lines[candidate - 1]
    return None


def _indent_extent(lines: Sequence[str], start: int, limit: int) -> tuple[int, int, bool, str]:
    base = _indent(lines[start - 1])
    end = start
    for number in range(start + 1, limit + 1):
        text = lines[number - 1]
        if not text.strip():
            continue
        if _indent(text) <= base and not text.lstrip().startswith(("#", ")")):
            return start, end, False, "body"
        end = number
    following = _next_code_line(lines, limit, len(lines))
    return start, end, following is not None and _indent(following) > base, "body"


def _brace_extent(lines: Sequence[str], start: int, limit: int, lexis: _Lexis) -> tuple[int, int, bool, str]:
    """``(first, last, truncated, kind)``; kind is ``body``, ``expression``, ``declaration`` or ``none``."""
    base = _indent(lines[start - 1])
    depth = parens = 0
    opened = expression = params_closed = in_block = False
    block_open, block_close = lexis.block_comment or ("", "")
    for number in range(start, limit + 1):
        text = lines[number - 1]
        index, quote, last_code = 0, None, ""
        while index < len(text):
            char = text[index]
            if in_block:
                if text.startswith(block_close, index):
                    in_block, index = False, index + len(block_close) - 1
            elif quote:
                if char == lexis.escape:
                    index += 1
                elif char == quote:
                    quote = None
            elif any(text.startswith(token, index) for token in lexis.line_comments):
                break
            elif block_open and text.startswith(block_open, index):
                in_block, index = True, index + len(block_open) - 1
            elif (lexis.hash_comment and char == "#" and (index == 0 or text[index - 1].isspace())
                  and not text.startswith("#[", index)):
                break
            elif char == "'" and lexis.char_quote:
                literal = _CHAR.match(text, index)
                if literal:
                    index = literal.end() - 1
                last_code = char
            elif char in lexis.quotes:
                quote, last_code = char, char
            else:
                if not char.isspace():
                    last_code = text[index:index + 2] if text.startswith(("=>", "->"), index) else char
                if char == "(":
                    parens += 1
                elif char == ")":
                    parens = max(0, parens - 1)
                    params_closed = params_closed or parens == 0
                elif not opened and parens == 0 and text.startswith("=>", index):
                    expression = True
                elif (not opened and parens == 0 and params_closed and char == "="
                      and text[index - 1:index] not in ("=", "!", "<", ">", "+", "-", "*", "/", "%", "&", "|", "^",
                                                        ":", "?")
                      and text[index + 1:index + 2] not in ("=", ">")):
                    expression = True
                elif char in "{}" and not opened and parens > 0:
                    pass                    # a parameter type or a callback argument, never the body
                elif char == "{":
                    depth += 1
                    opened = opened or not expression
                elif char == "}":
                    depth -= 1
                    if opened and depth <= 0:
                        return start, number, False, "body"
                    depth = max(depth, 0)
                elif char == ";" and parens == 0 and depth == 0 and not opened:
                    return start, number, False, "expression" if expression else "declaration"
            index += 1
        if not opened and not in_block and parens == 0 and depth == 0 and not last_code.endswith(_CONTINUATION):
            following = _next_code_line(lines, number, len(lines))
            if following is None or (_indent(following) <= base and not following.lstrip().startswith("{")):
                return start, number, False, "expression" if expression else "declaration"
    return start, limit, limit < len(lines), "body" if opened or expression else "none"


_RUBY_STRING = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'")
_RUBY_OPENER = re.compile(r"^\s*(def|class|module|if|unless|while|until|case|begin|for)\b")
_RUBY_ASSIGNED = re.compile(r"=\s*(if|unless|case|begin|while|until)\b")
_RUBY_DO = re.compile(r"\bdo\b\s*(?:\|[^|]*\|)?\s*$")
_RUBY_END = re.compile(r"(?<![.\w])end\b(?![?!])")
_RUBY_ENDLESS = re.compile(r"^\s*def\s+[^\s(=;]+\s*(?:\([^)]*\))?\s*=(?!=)")


def _keyword_extent(lines: Sequence[str], start: int, limit: int) -> tuple[int, int, bool, str]:
    if _RUBY_ENDLESS.match(lines[start - 1]):
        return start, start, False, "expression"
    depth = 0
    for number in range(start, limit + 1):
        code = _RUBY_STRING.sub('""', lines[number - 1]).split("#", 1)[0]
        opener = _RUBY_OPENER.match(code)
        depth += bool(opener) + len(_RUBY_ASSIGNED.findall(code))
        if _RUBY_DO.search(code) and not (opener and opener.group(1) in ("while", "until", "for")):
            depth += 1
        depth -= len(_RUBY_END.findall(code))
        if depth <= 0:
            return start, number, False, "body"
    return start, limit, limit < len(lines), "body"


def _extent(lines: Sequence[str], start: int, language: _Language, max_lines: int) -> tuple[int, int, bool, str]:
    limit = min(len(lines), start + max_lines - 1)
    if language.extent == "indent":
        return _indent_extent(lines, start, limit)
    if language.extent == "keyword":
        return _keyword_extent(lines, start, limit)
    return _brace_extent(lines, start, limit, language.lexis)


def text_extent(lines: Sequence[str], start_line: int, path: str, *, max_lines: int = MAX_FUNCTION_LINES
                ) -> tuple[int, int, bool]:
    """``(first, last, truncated)`` of the definition whose header is on ``start_line``.

    Uses the path language's extent rule. For a language without one, the result is a fixed window of
    :data:`UNKNOWN_WINDOW` lines, which serves only as a display fallback; :func:`resolve` never uses it.
    """
    start = max(1, min(int(start_line), len(lines) or 1))
    language = language_of(path)
    if language is None or not lines:
        return start, min(len(lines), start + UNKNOWN_WINDOW), len(lines) > start + UNKNOWN_WINDOW
    first, last, truncated, _kind = _extent(lines, start, language, max_lines)
    return first, last, truncated


def _header_name(language: _Language, text: str) -> tuple[bool, str | None]:
    for pattern in language.headers:
        found = pattern.match(text)
        if found:
            return True, next((group for group in found.groups() if group), None)
    return False, None


def _contains(lines: Sequence[str], start: int, line: int, language: _Language, max_lines: int
              ) -> tuple[int, int, bool] | None:
    first, last, truncated, kind = _extent(lines, start, language, max_lines)
    if kind not in ("body", "expression") or not first <= line <= last:
        return None
    return first, last, truncated


def _text(lines: Sequence[str], line: int, language: _Language, max_lines: int) -> Extent | None:
    for candidate in range(line, max(1, line - max_lines + 1) - 1, -1):
        matched, name = _header_name(language, lines[candidate - 1])
        if not matched:
            continue
        found = _contains(lines, candidate, line, language, max_lines)
        if found:
            return Extent(*found, SPAN_TEXT, name)
    return None


def _graph(lines: Sequence[str], line: int, language: _Language, headers: Sequence[Header], function: str | None,
           max_lines: int) -> Extent | None:
    preceding = sorted((item for item in headers if 1 <= item.line <= min(line, len(lines))),
                       key=lambda item: (item.identity != function or function is None, -item.line))
    for header in preceding:
        found = _contains(lines, header.line, line, language, max_lines)
        if found:
            return Extent(*found, SPAN_GRAPH_SYMBOL, header.name)
    return None


# ------------------------------------------------------------------------------------------------
# Tree-sitter rows

# Catalog language -> locked grammar (containers/tools/tree-sitter/parser.py LANGUAGES).
GRAMMARS = {"C": "c", "C++": "cpp", "C/C++": "cpp", "Rust": "rust", "Go": "go", "Java": "java",
            "JavaScript": "javascript", "TypeScript": "typescript", "TSX": "tsx", "C#": "csharp",
            "Python": "python", "PHP": "php", "Kotlin": "kotlin", "PowerShell": "powershell", "Shell": "bash",
            "Ruby": "ruby"}
_JS_CALLABLES = frozenset({"function_declaration", "generator_function_declaration", "method_definition"})
CALLABLES: dict[str, frozenset[str]] = {
    "c": frozenset({"function_definition"}),
    "cpp": frozenset({"function_definition"}),
    "csharp": frozenset({"method_declaration", "constructor_declaration", "destructor_declaration",
                         "operator_declaration", "conversion_operator_declaration", "local_function_statement",
                         "accessor_declaration"}),
    "go": frozenset({"function_declaration", "method_declaration"}),
    "java": frozenset({"method_declaration", "constructor_declaration", "compact_constructor_declaration"}),
    "javascript": _JS_CALLABLES, "typescript": _JS_CALLABLES, "tsx": _JS_CALLABLES,
    "kotlin": frozenset({"function_declaration", "secondary_constructor", "anonymous_initializer", "getter",
                         "setter"}),
    "php": frozenset({"function_definition", "method_declaration"}),
    "powershell": frozenset({"function_statement", "class_method_definition"}),
    "python": frozenset({"function_definition"}),
    "ruby": frozenset({"method", "singleton_method"}),
    "rust": frozenset({"function_item"}),
    "bash": frozenset({"function_definition"}),
}
_JS_LITERALS = frozenset({"arrow_function", "function_expression", "function", "generator_function"})
BOUND_LITERALS: dict[str, frozenset[str]] = {"javascript": _JS_LITERALS, "typescript": _JS_LITERALS,
                                             "tsx": _JS_LITERALS, "go": frozenset({"func_literal"})}
BINDINGS = frozenset({"variable_declarator", "assignment_expression", "pair", "public_field_definition",
                      "field_definition", "short_var_declaration", "var_spec", "assignment_statement"})
_PASS_THROUGH = frozenset({"parenthesized_expression", "expression_list"})
_NAME_FIELDS = ("name", "declarator", "left", "key", "property")
_FIXED_NAMES = {"secondary_constructor": "constructor", "anonymous_initializer": "init", "getter": "get",
                "setter": "set", "destructor_declaration": "~", "operator_declaration": "operator"}


def _ordinal(row: Mapping[str, Any]) -> tuple[int, ...] | None:
    native = row.get("native_id")
    if native == "root":
        return ()
    try:
        return tuple(int(part) for part in str(native).split("/"))
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class _Node:
    ordinal: tuple[int, ...]
    kind: str
    field: str | None
    first: int
    last: int
    flags: Mapping[str, Any]
    written: str | None
    location: Mapping[str, Any]


def _nodes(rows: Sequence[Mapping[str, Any]], sha: str) -> dict[tuple[int, ...], _Node]:
    nodes: dict[tuple[int, ...], _Node] = {}
    for row in rows:
        location = row.get("location") or {}
        if location.get("file_sha256") != sha:
            continue
        ordinal = _ordinal(row)
        payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
        first, last = location.get("start_line"), location.get("end_line")
        if ordinal is None or type(first) is not int or type(last) is not int:
            continue
        syntax = payload.get("syntax") if isinstance(payload.get("syntax"), Mapping) else {}
        nodes[ordinal] = _Node(ordinal, str(payload.get("grammar_native_type") or row.get("name") or ""),
                               payload.get("field"), first, last, payload,
                               syntax.get("written_name") if isinstance(syntax.get("written_name"), str) else None,
                               location)
    return nodes


def _row_language(rows: Sequence[Mapping[str, Any]], sha: str) -> str | None:
    for row in rows:
        payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
        if (row.get("location") or {}).get("file_sha256") == sha and isinstance(payload.get("language"), str):
            return GRAMMARS.get(payload["language"])
    return None


def _binding(nodes: Mapping[tuple[int, ...], _Node], node: _Node) -> _Node | None:
    ordinal = node.ordinal
    while ordinal:
        parent = nodes.get(ordinal[:-1])
        if parent is None:
            return None
        if parent.kind in BINDINGS:
            return parent
        if parent.kind not in _PASS_THROUGH:
            return None
        ordinal = parent.ordinal
    return None


def _node_text(lines: Sequence[str], node: _Node) -> str | None:
    location = node.location
    start, end = location.get("start_column"), location.get("end_column")
    if node.first != node.last or type(start) is not int or type(end) is not int or node.first > len(lines):
        return None
    text = lines[node.first - 1][start - 1:end - 1].strip()
    return text or None


def _name(nodes: Mapping[tuple[int, ...], _Node], children: Mapping[tuple[int, ...], list[_Node]], node: _Node,
          lines: Sequence[str]) -> str | None:
    if node.kind in _FIXED_NAMES:
        return _FIXED_NAMES[node.kind]
    if node.written:
        return node.written
    current = node
    for _ in range(16):
        values = children.get(current.ordinal, [])
        found = next((child for field in _NAME_FIELDS for child in values if child.field == field), None)
        found = found or next((child for child in values if child.kind in ("function_name", "word", "identifier",
                                                                           "simple_identifier")), None)
        if found is None:
            return None
        if found.written or not children.get(found.ordinal):
            return found.written or _node_text(lines, found)
        current = found
    return None


def _syntax(rows: Sequence[Mapping[str, Any]], sha: str, line: int, lines: Sequence[str], max_lines: int
            ) -> tuple[str, Extent | str | None]:
    """``("found", Extent)``, ``("none", reason)`` (definitive) or ``("fallback", note | None)``."""
    grammar = _row_language(rows, sha)
    if grammar is None or grammar not in CALLABLES:
        return "fallback", None
    nodes = _nodes(rows, sha)
    root = nodes.get(())
    if root is None:
        return "fallback", None
    children: dict[tuple[int, ...], list[_Node]] = {}
    for ordinal, node in nodes.items():
        if ordinal:
            children.setdefault(ordinal[:-1], []).append(node)
    for values in children.values():
        values.sort(key=lambda item: item.ordinal)
    if not any(node.first <= line <= node.last and (node.first == line or not children.get(ordinal))
               for ordinal, node in nodes.items() if ordinal):
        return "fallback", (f"{GAP_FUNCTION_FALLBACK}: tree_sitter rows do not cover line {line} (the parser's node "
                            "bound may have cut the file); the text rules resolve it")
    best: tuple[_Node, int] | None = None
    for node in nodes.values():
        if not node.first <= line <= node.last:
            continue
        first = None
        if node.kind in CALLABLES[grammar]:
            first = node.first
        elif node.kind in BOUND_LITERALS.get(grammar, ()):
            binding = _binding(nodes, node)
            first = min(binding.first, node.first) if binding else None
        if first is not None and (best is None or len(node.ordinal) > len(best[0].ordinal)):
            best = (node, first)
    damaged = bool(root.flags.get("has_error")) and any(
        (node.flags.get("error") or node.flags.get("missing"))
        and node.first <= (best[0].last if best else line) and node.last >= (best[1] if best else line)
        for node in nodes.values())
    if damaged:
        return "fallback", (f"{GAP_FUNCTION_FALLBACK}: tree_sitter parse errors near line {line}; the graph symbol "
                            "and text rules resolve it")
    if best is None:
        return "none", f"tree_sitter places line {line} outside every named function or method ({grammar} grammar)"
    node, first = best
    last = node.last
    if node.kind in BOUND_LITERALS.get(grammar, ()):
        binding = _binding(nodes, node)
        target = binding if binding is not None else node
        name = _name(nodes, children, target, lines)
    else:
        name = _name(nodes, children, node, lines)
    truncated = last - first + 1 > max_lines
    if truncated:
        first = max(first, line - max_lines // 2)
        last = min(last, first + max_lines - 1)
    return "found", Extent(first, last, truncated, SPAN_TREE_SITTER, name)


# ------------------------------------------------------------------------------------------------


def resolve(lines: Sequence[str], line: int, path: str, file_sha256: str, *,
            rows: Sequence[Mapping[str, Any]] | None = None, headers: Sequence[Header] = (),
            function: str | None = None, max_lines: int = MAX_FUNCTION_LINES) -> Resolution:
    """The named function enclosing ``line`` of ``path`` (verified ``lines`` with hash ``file_sha256``)."""
    if isinstance(max_lines, bool) or not isinstance(max_lines, int) or max_lines < 1:
        raise ValueError("max_lines must be a positive integer")
    if not 1 <= line <= len(lines):
        return Resolution(None, f"line {line} is outside the file")
    notes: list[str] = []
    tried = []
    if rows:
        tried.append(SPAN_TREE_SITTER)
        state, value = _syntax(rows, file_sha256, line, lines, max_lines)
        if state == "found" and isinstance(value, Extent):
            return Resolution(value)
        if state == "none":
            return Resolution(None, str(value))
        if value:
            notes.append(str(value))
    language = language_of(path)
    suffix = PurePosixPath(path).suffix.lower() or "files without a suffix"
    if language is None:
        return Resolution(None, f"no function-span rule for {suffix} and no tree_sitter rows "
                                f"(tried: {', '.join(tried) or 'none'})", tuple(notes))
    if headers:
        tried.append(SPAN_GRAPH_SYMBOL)
        found = _graph(lines, line, language, headers, function, max_lines)
        if found:
            return Resolution(found, None, tuple(notes))
    tried.append(SPAN_TEXT)
    found = _text(lines, line, language, max_lines)
    if found:
        return Resolution(found, None, tuple(notes))
    return Resolution(None, f"no enclosing named {language.name} function found within {max_lines} lines "
                            f"(tried: {', '.join(tried)})", tuple(notes))


def basis_rank(basis: str) -> int:
    """Index in :data:`SPAN_BASES` (0 = most precise)."""
    return SPAN_BASES.index(basis)


__all__ = ["BINDINGS", "BOUND_LITERALS", "CALLABLES", "Extent", "GAP_FUNCTION_FALLBACK", "GRAMMARS", "Header",
           "LANGUAGES", "MAX_FUNCTION_LINES", "Resolution", "SPAN_BASES", "SPAN_GRAPH_SYMBOL", "SPAN_TEXT",
           "SPAN_TREE_SITTER", "UNKNOWN_WINDOW", "basis_rank", "language_of", "resolve", "text_extent"]
