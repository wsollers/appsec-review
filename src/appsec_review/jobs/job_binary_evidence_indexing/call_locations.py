"""Conservative lexical anchors in Ghidra pseudo-C, not an address-to-source map."""

from __future__ import annotations

import re


_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_@$.]*")
_NON_CODE = re.compile(
    r'//(?:\\\r?\n|[^\n])*|/\*[\s\S]*?(?:\*/|\Z)|'
    r'"(?:\\[\s\S]|[^"\\])*(?:"|\Z)|'
    r"'(?:\\[\s\S]|[^'\\])*(?:'|\Z)|"
    r"(?m:^[ \t]*\#(?:\\\r?\n|[^\n])*)"
)
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_@$.]*|::|->|\+\+|--|\S")
_UNEVALUATED = {"sizeof", "_Alignof", "alignof", "decltype"}
_EXPRESSION_PREFIX = {"return", "if", "while", "for", "switch", "else", "do", "case"}


def _mask(match: re.Match[str]) -> str:
    value = re.sub(r"[^\n]", " ", match.group())
    # Keep a non-name primary-expression marker so sizeof "literal" does not absorb
    # the next evaluated operand. Neither literal contents nor this marker can match a callee.
    return "@" + value[1:] if match.group()[0] in ('"', "'") else value


def _operand_end(values: list[str], start: int, closes: dict[int, int]) -> int:
    """End of a unary/postfix operand, not the rest of its containing statement."""
    while start < len(values) and values[start] in _UNEVALUATED | {"+", "-", "!", "~", "*", "&", "++", "--", "::"}:
        start += 1
    if start == len(values):
        return start
    end = closes.get(start, start) + 1
    while end < len(values):
        if values[end] in ("(", "[") and end in closes:
            end = closes[end] + 1
        elif values[end] in ("::", "->", ".") and end + 1 < len(values):
            end += 2
        elif values[end] in ("++", "--"):
            end += 1
        else:
            break
    return end


def call_line(text: str, callee: str) -> tuple[int, int, int, int, bool] | None:
    """Return one candidate line and whether multiple expressions prevent a unique anchor."""
    if not _NAME.fullmatch(callee):
        return None
    code = _NON_CODE.sub(_mask, text)
    tokens = list(_TOKEN.finditer(code))
    values = [token.group() for token in tokens]
    closes, stack = {}, []
    for index, value in enumerate(values):
        if value in ("(", "["):
            stack.append(index)
        elif value in (")", "]"):
            if not stack or values[stack[-1]] != {")": "(", "]": "["}[value]:
                return None
            closes[stack.pop()] = index
    if stack:
        return None

    unevaluated: set[int] = set()
    index = 0
    while index < len(values):
        if values[index] in _UNEVALUATED:
            end = _operand_end(values, index + 1, closes)
            unevaluated.update(range(index + 1, end))
            index = end
        else:
            index += 1

    depth, statement, found = 0, 0, []
    for index, value in enumerate(values):
        if value in ("{", "}", ";"):
            depth += (1 if value == "{" else -1 if value == "}" else 0)
            statement = index + 1
        if (value != callee or depth < 1 or index + 1 not in closes
                or values[index + 1] != "("):
            continue
        if index in unevaluated:
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
            _NAME.fullmatch(part) or part in ("*", "&", "::", "(", ")", "@") for part in prefix
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
