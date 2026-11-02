"""Lexical fallback slice strategy (``lexical_identifiers``, precision ``lexical``).

Always available whenever verified source text is: it relates lines by identifier tokens only, so it is
the lowest-precision basis and the composer prefers any syntax or compiler basis for the same line.

Input consumed from ``SliceSources`` (nothing else):

``source_lines(path, file_sha256) -> (lines, reason)``
    ``lines`` is a sequence of ``str``; element ``i`` is line ``i + 1`` of the file whose verified hash
    is ``file_sha256`` (a trailing ``\\n``/``\\r\\n`` is tolerated and ignored). ``(None, reason)``
    means the text is unavailable; it is called once per distinct ``(path, file_sha256)`` of the
    request's function spans.

Method, per function span (lines ``first..last``; identifiers never cross spans, because the same name in
two functions is unrelated lexically):

1. Each line is sanitized: string/char literals become ``""`` and comments are dropped (``#`` for
   Python-like files; ``//``, ``/* */`` and whole ``#`` preprocessor lines for C-family files; all of
   them for unknown suffixes). Identifiers are ``[A-Za-z_][A-Za-z0-9_]*`` tokens not preceded by a word
   character (so ``0xFF`` yields nothing).
2. An anchor line's *followed identifiers* are its tokens minus ``IGNORED_IDENTIFIERS`` (keywords and
   builtin types/constants of C, C++, Python, Java/C#, JS/TS and Go) and minus call targets (a token
   directly followed by ``(``: a callee name relates calls, not data). Single-letter names are kept on
   purpose: ``n``, ``p`` and ``i`` are often exactly the length, pointer or index the path depends on.
   At most ``MAX_IDENTIFIERS_PER_LINE`` are followed per line, in order of appearance (gap if cut).
3. ``interacter``: every other span line containing a followed identifier as a whole word.
4. ``backward_def``: span lines *before the anchor line that uses the identifier* that assign or declare
   it: ``x = ``/``x += ``/``x := `` (never ``==``, ``<=``, ``>=``, ``!=``, ``=>``), ``x++``/``--x``, writes
   through ``x[...] =``/``x.f =``/``x->f =``, tuple targets ``a, x = ``, ``x: T = ``, declarations
   ``T x``/``T *x``/``T<U> x``/``T[] x`` followed by ``= ; , [ :`` or end of line, binding words
   (``var``/``let``/``const``/``static``/``import``/``as``/``global`` ... ``x``), Python ``for ... x ...
   in``, and parameters of the function header (the parenthesized list starting on ``span.first``,
   at most ``HEADER_MAX_LINES`` lines). Identifiers on the right-hand side of each new non-parameter
   definition line are then followed backwards for ``MAX_ROUNDS`` further round(s); if another round would
   still have added lines, a ``slice_truncated`` gap names the span.
5. ``function_header``: ``span.first`` of every readable span.

Limitations (why this is only ``lexical``): no scoping, shadowing, aliasing, reaching-definition or
control-flow information; multi-line strings, docstrings and raw strings are tokenized line by line;
macros and preprocessor conditionals are invisible; a name reused for different values within one
function is conflated; keyword arguments (``f(x=1)``) read as assignments; definitions after the use
(loop-carried) are not reported. Unavailable text,
spans or anchors beyond the file's end, and cut caps are named gaps and make the contribution
``partial``; if no span's text is available it is ``not_applicable``.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import PurePosixPath

from appsec_review.review.slicing.contract import (
    GAP_NOT_APPLICABLE, GAP_SOURCE_UNAVAILABLE, GAP_TRUNCATED, FunctionSpan, LineKey, Precision, Reason,
    SliceContribution, SliceLine, SliceRequest, StrategyState,
)

NAME = "lexical_identifiers"
MAX_ROUNDS = 1                  # transitive backward-definition rounds after the direct one
MAX_IDENTIFIERS_PER_LINE = 16   # identifiers followed per anchor or definition line
HEADER_MAX_LINES = 8            # lines scanned for a function's parameter list, from span.first

_C = frozenset("""
auto break case char const continue default do double else enum extern float for goto if inline int long
register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while
_Bool _Complex _Atomic _Noreturn _Static_assert _Thread_local _Alignas _Alignof bool true false NULL
size_t ssize_t ptrdiff_t intptr_t uintptr_t int8_t int16_t int32_t int64_t uint8_t uint16_t uint32_t
uint64_t off_t wchar_t FILE errno EOF stdin stdout stderr
""".split())
_CPP = frozenset("""
alignas alignof and and_eq asm bitand bitor catch char8_t char16_t char32_t class co_await co_return
co_yield compl concept consteval constexpr constinit const_cast decltype delete dynamic_cast explicit
export final friend mutable namespace new noexcept not not_eq nullptr operator or or_eq override private
protected public reinterpret_cast requires static_assert static_cast template this thread_local throw try
typeid typename using virtual xor xor_eq std string vector unique_ptr shared_ptr
""".split())
_PYTHON = frozenset("""
False None True and as assert async await break class continue def del elif else except finally for from
global if import in is lambda nonlocal not or pass raise return try while with yield self cls range str int
float bool bytes bytearray list dict set frozenset tuple object type
""".split())
_JAVA_CSHARP = frozenset("""
abstract boolean byte extends final finally implements import instanceof interface native package super
synchronized throws transient var String Object Integer Long Boolean Character Math System null base
checked decimal delegate event explicit fixed foreach implicit internal is lock object out params readonly
ref sbyte sealed stackalloc uint ulong unchecked unsafe ushort nameof
""".split())
_JS_TS = frozenset("""
function let const var undefined typeof instanceof yield await async this new null true false console any
number boolean unknown never interface type declare readonly keyof of in export import from default
extends implements arguments Symbol Array Object Promise JSON require module exports
""".split())
_GO = frozenset("""
break case chan const continue default defer else fallthrough for func go goto if import interface map
package range return select struct switch type var nil iota new error
rune byte string int int8 int16 int32 int64 uint uint8 uint16 uint32 uint64 uintptr float32 float64
complex64 complex128 bool true false fmt
""".split())
# Keywords and builtin types/constants of C, C++, Python, Java/C#, JS/TS and Go, plus the ``_`` discard name.
# They are never followed as data identifiers. Call-only builtins (``len(``, ``print(``, ``open(``,
# ``append(``) are not listed: the call-target rule already drops them, so the same words stay usable as
# variable names (``len``, ``cap`` are common C lengths). Frequent variable names (``next``, ``id``,
# ``copy``, ``value``, ``input``) are deliberately absent.
IGNORED_IDENTIFIERS = frozenset({"_"}).union(_C, _CPP, _PYTHON, _JAVA_CSHARP, _JS_TS, _GO)
# Ignored words that may still precede a declared name (``int x``, ``String s``, ``auto it``).
TYPE_WORDS = frozenset("""
void char short int long float double signed unsigned bool _Bool size_t ssize_t ptrdiff_t intptr_t uintptr_t
int8_t int16_t int32_t int64_t uint8_t uint16_t uint32_t uint64_t off_t wchar_t char8_t char16_t char32_t
FILE auto string String Object Integer Long Boolean Character byte boolean decimal sbyte uint ulong ushort
object rune int8 int16 int32 int64 uint8 uint16 uint32 uint64 uintptr float32 float64 complex64 complex128
error any number unknown
""".split())
_BINDING_WORDS = ("var", "let", "const", "val", "global", "nonlocal", "import", "as", "func", "def", "class",
                  "struct", "enum", "union", "typedef", "static", "extern", "register", "volatile", "final",
                  "readonly", "mutable")

_STRING = (r"""(?P<string>(?:(?<!\w)(?:[rRbBfFuU]{1,2}|L|u8|U))?"""
           r"""(?:"(?:\\.|[^"\\])*"?|'(?:\\.|[^'\\])*'?|`(?:\\.|[^`\\])*`?))""")
_TOKEN = re.compile(r"(?<!\w)[A-Za-z_]\w*")
_CALL_FOLLOWS = re.compile(r"\s*\(")
_ASSIGNMENT = re.compile(r"(?<![=!<>])(?:<<|>>>?)?=(?![=>])")
_FOR_IN = re.compile(r"(?<![\w.])for\b[^;]*?(?:\b(?:in|of)\b|(?<!:):(?!:))")
_ASSIGN_OP = r"(?:<<|>>>?|\*\*|//|\?\?|&&|\|\||[-+*/%&|^:])?=(?![=>])"
_HASH_SUFFIXES = frozenset({".py", ".pyi", ".pyw", ".rb", ".sh", ".bash", ".pl", ".pm"})
_SLASH_SUFFIXES = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".h++", ".ipp",
                             ".inl", ".m", ".mm", ".java", ".cs", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
                             ".go", ".rs", ".kt", ".kts", ".swift", ".scala", ".dart"})


@dataclass(frozen=True, slots=True)
class _Syntax:
    scanner: re.Pattern[str]
    preprocessor: bool


def _scanner(line_markers: tuple[str, ...], block: bool) -> re.Pattern[str]:
    parts = [r"(?P<block>/\*)"] if block else []
    parts.append("(?P<comment>" + "|".join(re.escape(marker) for marker in line_markers) + ")")
    parts += [_STRING, r"(?P<word>\w+)"]
    return re.compile("|".join(parts))


_HASH = _Syntax(_scanner(("#",), block=False), preprocessor=False)
_SLASH = _Syntax(_scanner(("//",), block=True), preprocessor=True)
_ANY = _Syntax(_scanner(("//", "#"), block=True), preprocessor=False)


def _syntax_for(path: str) -> _Syntax:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in _HASH_SUFFIXES:
        return _HASH
    if suffix in _SLASH_SUFFIXES:
        return _SLASH
    return _ANY


@dataclass(frozen=True, slots=True)
class _Line:
    text: str
    tokens: tuple[tuple[str, int, bool], ...]   # (name, start offset in text, is a call target)
    names: frozenset[str]


def _sanitize(raw: str, syntax: _Syntax, in_block: bool) -> tuple[str, bool]:
    """``raw`` with literals replaced by ``""`` and comments removed; returns the open-block-comment state."""
    text = raw.rstrip("\r\n")
    pos = 0
    out: list[str] = []
    if in_block:
        end = text.find("*/")
        if end < 0:
            return "", True
        pos = end + 2
        out.append(" ")
    elif syntax.preprocessor and text.lstrip().startswith("#"):
        return "", False
    while True:
        match = syntax.scanner.search(text, pos)
        if match is None:
            out.append(text[pos:])
            return "".join(out), False
        out.append(text[pos:match.start()])
        kind = match.lastgroup
        if kind == "comment":
            return "".join(out), False
        if kind == "block":
            end = text.find("*/", match.end())
            if end < 0:
                return "".join(out), True
            out.append(" ")
            pos = end + 2
            continue
        out.append('""' if kind == "string" else match.group())
        pos = match.end()


def _parse(lines: Sequence[str], first: int, last: int, syntax: _Syntax) -> dict[int, _Line]:
    parsed: dict[int, _Line] = {}
    in_block = False
    for number in range(first, last + 1):
        text, in_block = _sanitize(lines[number - 1], syntax, in_block)
        tokens = tuple((match.group(), match.start(), _CALL_FOLLOWS.match(text, match.end()) is not None)
                       for match in _TOKEN.finditer(text))
        parsed[number] = _Line(text, tokens, frozenset(name for name, _, _ in tokens))
    return parsed


def _data_names(tokens: Iterable[tuple[str, int, bool]]) -> list[str]:
    seen: list[str] = []
    for name, _, is_call in tokens:
        if not is_call and name not in IGNORED_IDENTIFIERS and name not in seen:
            seen.append(name)
    return seen


def _capped(names: list[str], where: str, gaps: set[str]) -> list[str]:
    if len(names) > MAX_IDENTIFIERS_PER_LINE:
        gaps.add(f"{GAP_TRUNCATED}: {NAME}: {where} has {len(names)} identifiers; only the first "
                 f"{MAX_IDENTIFIERS_PER_LINE} were followed")
        return names[:MAX_IDENTIFIERS_PER_LINE]
    return names


def _rhs_names(line: _Line) -> list[str]:
    match = _ASSIGNMENT.search(line.text) or _FOR_IN.search(line.text)
    if match is None:
        return []
    return _data_names(token for token in line.tokens if token[1] >= match.end())


@lru_cache(maxsize=4096)
def _definition_patterns(name: str) -> tuple[tuple[re.Pattern[str], ...], re.Pattern[str]]:
    x = re.escape(name)
    word = rf"(?<![\w.])(?<!->){x}(?!\w)"
    plain = (
        rf"{word}\s*{_ASSIGN_OP}",
        rf"{word}\s*(?:\[[^\]]*\]|(?:\.|->)\s*\w+)+\s*{_ASSIGN_OP}",
        rf"{word}\s*(?:\+\+|--)|(?:\+\+|--)\s*{x}(?!\w)",
        rf"^\s*[\w\s,.*]*?{word}[\w\s,.*]*=(?![=>])",
        rf"^\s*{x}\s*:\s*[\w\[\]., |]+=(?![=>])",
        rf"(?<![\w.])(?:{'|'.join(_BINDING_WORDS)})\b[\w\s,*&]*?(?<!\w){x}(?!\w)",
        rf"(?<![\w.])for\b[\w\s,()*&\[\]]*?{word}[\w\s,()\[\]]*?\b(?:in|of)\b",
    )
    declaration = (rf"(?<![\w.])(?P<type>[A-Za-z_]\w*)(?P<suffix>\s*<[\w\s:,<>*&]*>|\s*\[\s*\])?"
                   rf"(?:\s+[*&]*|[*&]+\s*){x}(?!\w)(?=\s*(?:=(?!=)|[;,\[:]|$))")
    return tuple(re.compile(pattern) for pattern in plain), re.compile(declaration)


def _defines(text: str, name: str) -> bool:
    plain, declaration = _definition_patterns(name)
    if any(pattern.search(text) for pattern in plain):
        return True
    return any(match.group("suffix") or match.group("type") in TYPE_WORDS
               or match.group("type") not in IGNORED_IDENTIFIERS for match in declaration.finditer(text))


def _header_params(parsed: Mapping[int, _Line], first: int, last: int) -> dict[int, frozenset[str]]:
    """Parameter names per header line: data tokens inside the parenthesized list opened on the header."""
    params: dict[int, frozenset[str]] = {}
    depth, opened = 0, False
    for number in range(first, min(last, first + HEADER_MAX_LINES - 1) + 1):
        line = parsed[number]
        names: set[str] = set()
        pos = 0
        for name, start, is_call in (*line.tokens, ("", len(line.text), True)):
            for char in line.text[pos:start]:
                if char == "(":
                    depth, opened = depth + 1, True
                elif char == ")":
                    depth -= 1
            pos = start
            if depth >= 1 and name and not is_call and name not in IGNORED_IDENTIFIERS:
                names.add(name)
        if names:
            params[number] = frozenset(names)
        if (opened and depth <= 0) or (not opened and ("{" in line.text or line.text.rstrip().endswith(":"))):
            break
    return params


def _definitions(frontier: Iterable[tuple[str, int]], parsed: Mapping[int, _Line],
                 params: Mapping[int, frozenset[str]], first: int, explored: dict[str, int]) -> set[int]:
    """Lines before each ``(name, limit)`` that define ``name``; ``explored`` records the scanned prefix."""
    found: set[int] = set()
    for name, limit in frontier:
        start = explored.get(name, first)
        if limit <= start:
            continue
        for number in range(start, limit):
            line = parsed[number]
            if name in line.names and (name in params.get(number, ()) or _defines(line.text, name)):
                found.add(number)
        explored[name] = limit
    return found


def _span_order(span: FunctionSpan) -> tuple[str, str, int, int, str]:
    return span.path, span.file_sha256, span.first, span.last, span.function or ""


class LexicalIdentifiers:
    """Interacting identifiers and backward definitions from identifier tokens (lowest precision)."""

    name = NAME
    precision = Precision.LEXICAL

    def expand(self, request: SliceRequest) -> SliceContribution:
        if not request.functions:
            return SliceContribution(NAME, Precision.LEXICAL, StrategyState.NOT_APPLICABLE,
                                     gaps=(f"{GAP_NOT_APPLICABLE}: {NAME}: the request names no function span",))
        anchors = request.anchor_lines()
        by_span: dict[FunctionSpan, list[LineKey]] = {}
        for key in anchors:
            span = request.span_for(key)
            if span is not None:
                by_span.setdefault(span, []).append(key)
        texts: dict[tuple[str, str], tuple[Sequence[str] | None, str | None]] = {}
        reasons: dict[LineKey, set[Reason]] = {}
        gaps: set[str] = set()
        readable = 0
        for span in sorted(set(request.functions), key=_span_order):
            identity = (span.path, span.file_sha256)
            if identity not in texts:
                texts[identity] = request.sources.source_lines(span.path, span.file_sha256)
            lines, why = texts[identity]
            if lines is None:
                gaps.add(f"{GAP_SOURCE_UNAVAILABLE}: {NAME}: {span.path}: {why or 'source text unavailable'}")
                continue
            readable += 1
            _expand_span(span, lines, by_span.get(span, []), reasons, gaps)
        if not readable:
            gaps.add(f"{GAP_NOT_APPLICABLE}: {NAME}: no verified source text for any function span")
            return SliceContribution(NAME, Precision.LEXICAL, StrategyState.NOT_APPLICABLE, gaps=tuple(sorted(gaps)))
        anchor_keys = frozenset(anchors)
        out = []
        for key in sorted(reasons):
            kept = reasons[key] - {Reason.INTERACTER} if key in anchor_keys else reasons[key]
            if kept:
                out.append(SliceLine(key, frozenset(kept), NAME, Precision.LEXICAL))
        state = StrategyState.PARTIAL if gaps else StrategyState.APPLIED
        return SliceContribution(NAME, Precision.LEXICAL, state, tuple(out), tuple(sorted(gaps)))


def _expand_span(span: FunctionSpan, lines: Sequence[str], anchors: list[LineKey],
                 reasons: dict[LineKey, set[Reason]], gaps: set[str]) -> None:
    count = len(lines)
    where = f"{span.path}:{span.first}-{span.last}"
    if span.first > count:
        gaps.add(f"{GAP_SOURCE_UNAVAILABLE}: {NAME}: {where} lies beyond the file's {count} lines")
        return
    last = min(span.last, count)
    if span.last > count:
        gaps.add(f"{GAP_SOURCE_UNAVAILABLE}: {NAME}: {where} extends beyond the file's {count} lines")

    def mark(number: int, reason: Reason) -> None:
        reasons.setdefault(LineKey(span.path, span.file_sha256, number), set()).add(reason)

    parsed = _parse(lines, span.first, last, _syntax_for(span.path))
    mark(span.first, Reason.FUNCTION_HEADER)
    params = _header_params(parsed, span.first, last)
    followed: set[str] = set()
    frontier: list[tuple[str, int]] = []
    anchor_numbers: set[int] = set()
    for key in sorted(anchors):
        if key.line > last:
            gaps.add(f"{GAP_SOURCE_UNAVAILABLE}: {NAME}: anchor {span.path}:{key.line} lies beyond the file's "
                     f"{count} lines")
            continue
        anchor_numbers.add(key.line)
        for name in _capped(_data_names(parsed[key.line].tokens), f"anchor {span.path}:{key.line}", gaps):
            followed.add(name)
            frontier.append((name, key.line))
    if followed:
        for number in range(span.first, last + 1):
            if number not in anchor_numbers and parsed[number].names & followed:
                mark(number, Reason.INTERACTER)
    explored: dict[str, int] = {}
    defined: set[int] = set()
    for depth in range(MAX_ROUNDS + 1):
        fresh = sorted(_definitions(frontier, parsed, params, span.first, explored) - defined)
        defined.update(fresh)
        for number in fresh:
            mark(number, Reason.BACKWARD_DEF)
        sink = gaps if depth < MAX_ROUNDS else set()
        frontier = [(name, number) for number in fresh if number not in params
                    for name in _capped(_rhs_names(parsed[number]), f"definition {span.path}:{number}", sink)]
        if not frontier:
            return
    if _definitions(frontier, parsed, params, span.first, dict(explored)) - defined:
        gaps.add(f"{GAP_TRUNCATED}: {NAME}: backward definitions in {where} stopped after {MAX_ROUNDS} "
                 f"transitive round(s)")


__all__ = ["HEADER_MAX_LINES", "IGNORED_IDENTIFIERS", "LexicalIdentifiers", "MAX_IDENTIFIERS_PER_LINE",
           "MAX_ROUNDS", "NAME", "TYPE_WORDS"]
