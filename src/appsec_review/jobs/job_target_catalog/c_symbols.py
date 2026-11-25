"""Comment-, string-, preprocessor-, and scope-aware C/C++ declaration scanner for catalog indexing."""

from __future__ import annotations

from dataclasses import dataclass
import re


_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_NON_FUNCTION_NAMES = frozenset({
    "if", "else", "for", "while", "do", "switch", "case", "catch", "return",
    "sizeof", "alignof", "alignas", "decltype", "noexcept", "static_assert",
    "typedef", "using", "namespace", "extern", "template", "class", "struct",
    "union", "enum", "asm", "__asm", "__asm__", "__attribute", "__attribute__",
    "__declspec", "_Static_assert", "typeof", "__typeof__", "requires",
})


@dataclass(frozen=True, slots=True)
class CSymbolSpan:
    name: str
    kind: str
    line: int
    line_start_byte: int
    line_end_byte: int
    start_column: int
    end_column: int
    line_text: str


@dataclass(frozen=True, slots=True)
class _Tok:
    kind: str
    val: str
    line: int
    col: int


def _line_table(text: str) -> list[tuple[int, int, str]]:
    lines: list[tuple[int, int, str]] = []
    offset = 0
    for seg in text.splitlines(keepends=True):
        encoded = seg.encode("utf-8")
        lines.append((offset, offset + len(encoded), seg.rstrip("\r\n")))
        offset += len(encoded)
    return lines


def _tokenize(text: str) -> list[_Tok]:
    tokens: list[_Tok] = []
    n = len(text)
    i = 0
    line = 1
    col = 1
    at_bol = True

    while i < n:
        ch = text[i]
        if ch == "\n":
            i += 1
            line += 1
            col = 1
            at_bol = True
            continue
        if ch in " \t\r\f\v":
            i += 1
            col += 1
            continue
        if ch == "\\" and i + 1 < n and text[i + 1] == "\n":
            i += 2
            line += 1
            col = 1
            continue
        if ch == "\\" and i + 2 < n and text[i + 1] == "\r" and text[i + 2] == "\n":
            i += 3
            line += 1
            col = 1
            continue
        if at_bol and ch == "#":
            while i < n:
                if text[i] == "\\" and i + 1 < n and text[i + 1] == "\n":
                    i += 2
                    line += 1
                    col = 1
                    continue
                if text[i] == "\\" and i + 2 < n and text[i + 1] == "\r" and text[i + 2] == "\n":
                    i += 3
                    line += 1
                    col = 1
                    continue
                if text[i] == "/" and i + 1 < n and text[i + 1] == "*":
                    i += 2
                    col += 2
                    while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                        if text[i] == "\n":
                            line += 1
                            col = 1
                        else:
                            col += 1
                        i += 1
                    if i < n:
                        i += 2
                        col += 2
                    continue
                if text[i] == "/" and i + 1 < n and text[i + 1] == "/":
                    while i < n and text[i] != "\n":
                        i += 1
                    break
                if text[i] == "\n":
                    break
                i += 1
                col += 1
            continue

        at_bol = False

        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            col += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] == "\n":
                    line += 1
                    col = 1
                    at_bol = True
                else:
                    col += 1
                i += 1
            if i < n:
                i += 2
                col += 2
                at_bol = False
            continue

        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            col += 2
            while i < n:
                if text[i] == "\\" and i + 1 < n and text[i + 1] == "\n":
                    i += 2
                    line += 1
                    col = 1
                    continue
                if text[i] == "\n":
                    break
                i += 1
                col += 1
            continue

        if ch == "R" and i + 1 < n and text[i + 1] == '"':
            j = i + 2
            delim_end = text.find("(", j)
            if delim_end != -1 and "\n" not in text[j:delim_end] and len(text[j:delim_end]) <= 16:
                closing = ")" + text[j:delim_end] + '"'
                end_idx = text.find(closing, delim_end + 1)
                if end_idx != -1:
                    span = text[i:end_idx + len(closing)]
                    tokens.append(_Tok("LIT", '""', line, col))
                    nl = span.count("\n")
                    if nl:
                        line += nl
                        col = len(span) - span.rfind("\n")
                    else:
                        col += len(span)
                    i = end_idx + len(closing)
                    continue

        if ch in ('"', "'"):
            quote = ch
            start_line, start_col = line, col
            i += 1
            col += 1
            while i < n:
                c = text[i]
                if c == "\\":
                    if i + 1 < n and text[i + 1] == "\n":
                        i += 2
                        line += 1
                        col = 1
                    elif i + 2 < n and text[i + 1] == "\r" and text[i + 2] == "\n":
                        i += 3
                        line += 1
                        col = 1
                    else:
                        i += 2
                        col += 2
                    continue
                if c == "\n":
                    break
                i += 1
                col += 1
                if c == quote:
                    break
            tokens.append(_Tok("LIT", quote * 2, start_line, start_col))
            continue

        m = _IDENT_RE.match(text, i)
        if m:
            val = m.group(0)
            tokens.append(_Tok("IDENT", val, line, col))
            i = m.end()
            col += len(val)
            continue

        two = text[i:i + 2]
        if two in {"::", "->", "&&", "==", "!=", "<=", ">=", "<<", ">>"}:
            tokens.append(_Tok("PUNCT", two, line, col))
            i += 2
            col += 2
            continue

        tokens.append(_Tok("PUNCT", ch, line, col))
        i += 1
        col += 1

    return tokens


def _match_close(tokens: list[_Tok], open_idx: int, open_val: str, close_val: str) -> int:
    depth = 0
    for idx in range(open_idx, len(tokens)):
        v = tokens[idx].val
        if v == open_val:
            depth += 1
        elif v == close_val:
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _is_kr_param_list(tokens: list[_Tok], open_idx: int, close_idx: int) -> bool:
    inner = tokens[open_idx + 1:close_idx]
    if not inner:
        return False
    expect_ident = True
    for tok in inner:
        if expect_ident:
            if tok.kind != "IDENT" or tok.val == "void":
                return False
            expect_ident = False
        else:
            if tok.val != ",":
                return False
            expect_ident = True
    return not expect_ident


def _looks_like_post_params_before_body(tokens: list[_Tok], open_idx: int, close_idx: int) -> bool:
    after = tokens[close_idx + 1:]
    if not after:
        return True
    if after[0].val == ":":
        return True
    if any(tok.val == ";" for tok in after):
        if not _is_kr_param_list(tokens, open_idx, close_idx):
            return False
        return after[-1].val == ";" and not any(tok.val in {"=", "{", "}"} for tok in after)
    j = 0
    while j < len(after):
        tok = after[j]
        if tok.val == "(":
            end_p = _match_close(after, j, "(", ")")
            if end_p == -1:
                return False
            j = end_p + 1
            continue
        if tok.val == "->":
            j += 1
            while j < len(after):
                if after[j].val == "(":
                    end_p = _match_close(after, j, "(", ")")
                    if end_p == -1:
                        return False
                    j = end_p + 1
                else:
                    j += 1
            return True
        if tok.val in {"=", ",", ";"} or tok.kind == "LIT":
            return False
        j += 1
    return True


def _find_type_tag_before_brace(stmt: list[_Tok]) -> tuple[_Tok, str] | None:
    idx = -1
    kind = ""
    for k, tok in enumerate(stmt):
        if tok.kind == "IDENT" and tok.val in {"struct", "class", "union", "enum"}:
            angle = 0
            paren = 0
            for prev in stmt[:k]:
                if prev.val == "(":
                    paren += 1
                elif prev.val == ")":
                    paren = max(0, paren - 1)
                elif paren == 0 and prev.val == "<":
                    angle += 1
                elif paren == 0 and prev.val == ">":
                    angle = max(0, angle - 1)
            if angle == 0 and paren == 0:
                idx = k
                kind = tok.val
    if idx == -1:
        return None
    rest = stmt[idx + 1:]
    if kind == "enum" and rest and rest[0].kind == "IDENT" and rest[0].val in {"class", "struct"}:
        rest = rest[1:]
    if not rest:
        return None
    pos = 0
    candidates: list[_Tok] = []
    while pos < len(rest):
        tok = rest[pos]
        if tok.val == ":":
            break
        if tok.val in {"*", "&", "&&", "=", ";", ","}:
            return None
        if tok.val == "(":
            if candidates:
                candidates.pop()
            end_p = _match_close(rest, pos, "(", ")")
            if end_p == -1:
                return None
            pos = end_p + 1
            continue
        if tok.val == "<":
            end_a = _match_close(rest, pos, "<", ">")
            if end_a == -1:
                return None
            pos = end_a + 1
            continue
        if tok.kind == "IDENT" and tok.val != "final":
            candidates.append(tok)
        pos += 1
    if not candidates:
        return None
    return candidates[-1], kind


def _has_kr_header(stmt: list[_Tok]) -> bool:
    k = 0
    while k < len(stmt):
        if stmt[k].val == ";":
            break
        if stmt[k].val == "(":
            close_k = _match_close(stmt, k, "(", ")")
            if close_k == -1:
                return False
            if k >= 2 and _is_kr_param_list(stmt, k, close_k):
                after = stmt[close_k + 1:]
                if after and after[0].kind == "IDENT" and not any(t.val in {"=", "{"} for t in after):
                    return True
            k = close_k + 1
        else:
            k += 1
    return False


def _find_function_before_brace(stmt: list[_Tok], *, in_type_scope: bool) -> _Tok | None:
    paren = 0
    for idx, tok in enumerate(stmt):
        if tok.val == "(":
            paren += 1
        elif tok.val == ")":
            paren = max(0, paren - 1)
        elif paren == 0 and tok.val == ":":
            stmt = stmt[:idx]
            break
    paren = 0
    for idx, tok in enumerate(stmt):
        if tok.val == "(":
            paren += 1
        elif tok.val == ")":
            paren = max(0, paren - 1)
        elif paren == 0 and tok.val == "=":
            if not (idx >= 1 and stmt[idx - 1].val == "operator"):
                return None

    top_parens: list[tuple[int, int]] = []
    k = 0
    while k < len(stmt):
        if stmt[k].val == "(":
            close_k = _match_close(stmt, k, "(", ")")
            if close_k == -1:
                return None
            top_parens.append((k, close_k))
            k = close_k + 1
        else:
            k += 1

    for open_k, close_k in reversed(top_parens):
        if open_k == 0:
            continue
        if not _looks_like_post_params_before_body(stmt, open_k, close_k):
            continue
        name_idx = open_k - 1
        if name_idx >= 0 and stmt[name_idx].val == ">":
            depth = 0
            for p in range(name_idx, -1, -1):
                if stmt[p].val == ">":
                    depth += 1
                elif stmt[p].val == "<":
                    depth -= 1
                    if depth == 0:
                        name_idx = p - 1
                        break
        if name_idx < 0 or stmt[name_idx].kind != "IDENT":
            continue
        name_tok = stmt[name_idx]
        if name_tok.val in _NON_FUNCTION_NAMES:
            continue
        if name_tok.val in {"__attribute__", "__attribute", "__declspec", "alignas", "noexcept", "throw"}:
            continue
        prefix = stmt[:name_idx]
        if prefix and prefix[-1].val == "~":
            prefix = prefix[:-1]
        is_qualified = bool(prefix and prefix[-1].val == "::")
        if not in_type_scope and not is_qualified and not prefix:
            continue
        return name_tok
    return None


def extract_c_family_symbols(text: str, *, limit: int = 50_000) -> list[CSymbolSpan]:
    """Extract C/C++ type, typedef, and function/method definitions with exact line/byte spans."""
    lines = _line_table(text)
    if not lines:
        return []
    tokens = _tokenize(text)
    out: list[CSymbolSpan] = []
    seen: set[tuple[int, str]] = set()

    def emit(tok: _Tok, kind: str) -> None:
        if len(out) >= limit:
            return
        key = (tok.line, tok.val)
        if key in seen or not (1 <= tok.line <= len(lines)):
            return
        seen.add(key)
        start_b, end_b, line_txt = lines[tok.line - 1]
        out.append(CSymbolSpan(
            name=tok.val,
            kind=kind,
            line=tok.line,
            line_start_byte=start_b,
            line_end_byte=end_b,
            start_column=tok.col,
            end_column=tok.col + len(tok.val),
            line_text=line_txt,
        ))

    scope_stack: list[tuple[str, bool]] = []
    stmt: list[_Tok] = []
    after_typedef_brace = False

    def current_scope() -> str:
        return scope_stack[-1][0] if scope_stack else "file"

    i = 0
    n = len(tokens)
    while i < n and len(out) < limit:
        tok = tokens[i]
        scope = current_scope()

        if scope in {"block", "enum"}:
            if tok.val == "{":
                scope_stack.append(("block", False))
            elif tok.val == "}":
                _, was_typedef = scope_stack.pop()
                after_typedef_brace = was_typedef
                stmt.clear()
            i += 1
            continue

        if tok.val == "{":
            has_typedef = any(t.kind == "IDENT" and t.val == "typedef" for t in stmt)
            if (len(stmt) >= 2 and stmt[0].kind == "IDENT" and stmt[0].val == "extern"
                    and stmt[1].kind == "LIT"):
                scope_stack.append(("extern", False))
            elif stmt and stmt[0].kind == "IDENT" and stmt[0].val == "namespace":
                scope_stack.append(("namespace", False))
            else:
                tag_hit = _find_type_tag_before_brace(stmt)
                if tag_hit is not None:
                    tag_tok, tag_kind = tag_hit
                    emit(tag_tok, tag_kind)
                    scope_stack.append(("enum" if tag_kind == "enum" else "type", has_typedef))
                elif has_typedef and any(t.kind == "IDENT" and t.val in {"struct", "union", "enum"} for t in stmt):
                    scope_stack.append(("enum" if any(t.val == "enum" for t in stmt) else "type", True))
                else:
                    fn_tok = _find_function_before_brace(stmt, in_type_scope=(scope == "type"))
                    if fn_tok is not None:
                        emit(fn_tok, "function")
                    scope_stack.append(("block", False))
            stmt.clear()
            after_typedef_brace = False
            i += 1
            continue

        if tok.val == "}":
            if scope_stack:
                _, was_typedef = scope_stack.pop()
                after_typedef_brace = was_typedef
            else:
                after_typedef_brace = False
            stmt.clear()
            i += 1
            continue

        if tok.val == ";":
            if scope == "file" and _has_kr_header(stmt) and len(stmt) < 128:
                stmt.append(tok)
                i += 1
                continue
            if after_typedef_brace and stmt:
                for cand in stmt:
                    if cand.val == ",":
                        break
                    if cand.kind == "IDENT" and cand.val not in {"const", "volatile", "FAR", "ZEXPORT"}:
                        emit(cand, "typedef")
                        break
            elif stmt and stmt[0].kind == "IDENT" and stmt[0].val == "using":
                if len(stmt) >= 4 and stmt[1].kind == "IDENT" and stmt[2].val == "=":
                    emit(stmt[1], "typedef")
            after_typedef_brace = False
            stmt.clear()
            i += 1
            continue

        if (scope == "type" and tok.val == ":" and len(stmt) == 1
                and stmt[0].kind == "IDENT" and stmt[0].val in {"public", "private", "protected"}):
            stmt.clear()
            i += 1
            continue

        stmt.append(tok)
        i += 1

    return out
