"""Conservative lexical anchors in Ghidra pseudo-C, not an address-to-source map."""

from __future__ import annotations

import re


_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_@$.]*")
_NON_CODE = re.compile(
    r'//(?:\\\n|[^\n])*|/\*[\s\S]*?(?:\*/|\Z)|'
    r'"(?:\\[\s\S]|[^"\\])*(?:"|\Z)|'
    r"'(?:\\[\s\S]|[^'\\])*(?:'|\Z)|"
    r"(?m:^[ \t]*\#(?:\\\n|[^\n])*)"
)
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_@$.]*|::|\S")
_UNEVALUATED = {"sizeof", "_Alignof", "alignof", "decltype"}
_EXPRESSION_PREFIX = {"return", "if", "while", "for", "switch", "else", "do", "case"}


def call_line(text: str, callee: str) -> tuple[int, int, int, int, bool] | None:
    """Return one candidate line and whether multiple expressions prevent a unique anchor."""
    if not _NAME.fullmatch(callee):
        return None
    code = _NON_CODE.sub(lambda match: re.sub(r"[^\n]", " ", match.group()), text)
    tokens = list(_TOKEN.finditer(code))
    values = [token.group() for token in tokens]
    closes, stack = {}, []
    for index, value in enumerate(values):
        if value == "(":
            stack.append(index)
        elif value == ")":
            if not stack:
                return None
            closes[stack.pop()] = index
    if stack:
        return None

    depth, statement, found = 0, 0, []
    enclosing: list[int] = []
    for index, value in enumerate(values):
        if value in ("{", "}", ";"):
            depth += (1 if value == "{" else -1 if value == "}" else 0)
            statement = index + 1
        if value == "(":
            enclosing.append(index)
        elif value == ")":
            enclosing.pop()
        if value != callee or depth < 1 or index + 1 not in closes:
            continue
        if any(start and values[start - 1] in _UNEVALUATED for start in enclosing):
            continue
        end = closes[index + 1]
        if end + 1 < len(values) and values[end + 1] == "{":
            continue
        prefix = values[statement:index]
        while len(prefix) >= 2 and prefix[-1] == "::" and _NAME.fullmatch(prefix[-2]):
            prefix = prefix[:-2]
        # A type/declarator prefix is not a call. Unknown type names are deliberately
        # conservative (e.g. "custom_type *sink(void)"), rather than guessed as expressions.
        if prefix and not _EXPRESSION_PREFIX.intersection(prefix) and all(
            _NAME.fullmatch(part) or part in ("*", "&", "::", "(", ")") for part in prefix
        ):
            continue
        found.append(tokens[index].start())
        if len(found) == 2:
            break
    if not found:
        return None
    position = found[0]
    start = text.rfind("\n", 0, position) + 1
    end = text.find("\n", position)
    if end < 0:
        end = len(text)
    return (text.count("\n", 0, start) + 1, len(text[:start].encode("utf-8")),
            len(text[:end].encode("utf-8")), end - start + 1, len(found) > 1)
