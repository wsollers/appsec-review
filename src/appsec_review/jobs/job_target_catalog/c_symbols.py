"""Comment-, string-, preprocessor-, and scope-aware C/C++ declaration scanner for catalog indexing."""

from __future__ import annotations

from dataclasses import dataclass
import re


_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_RAW_STR_PREFIX_RE = re.compile(r'(?:u8|u|U|L)?R"([^()\\\s]{0,16})\(')
_STR_PREFIX_RE = re.compile(r"""(?:u8|u|U|L)(?=["'])""")
_PP_NUMBER_RE = re.compile(r"(?:\.[0-9]|[0-9])(?:[eEpP][+-]|'[0-9A-Za-z_]|[0-9A-Za-z_.])*")
_PP_DIRECTIVE_RE = re.compile(r"#[ \t]*([A-Za-z_][A-Za-z0-9_]*)")
_NON_FUNCTION_NAMES = frozenset({
    "if", "else", "for", "while", "do", "switch", "case", "catch", "return",
    "sizeof", "alignof", "alignas", "decltype", "noexcept", "static_assert",
    "typedef", "using", "namespace", "extern", "template", "class", "struct",
    "union", "enum", "asm", "__asm", "__asm__", "__attribute", "__attribute__",
    "__declspec", "_Static_assert", "typeof", "__typeof__", "requires",
})
_THREE_CHAR_OPS = frozenset({"<<=", ">>=", "<=>", "->*"})
_TWO_CHAR_OPS = frozenset({
    "::", "->", "&&", "||", "==", "!=", "<=", ">=", "<<", ">>",
    "+=", "-=", "*=", "/=", "%=", "^=", "&=", "|=", "++", "--",
})
_OVERLOADABLE_OP_TOKENS = frozenset({
    "+", "-", "*", "/", "%", "^", "&", "|", "~", "!", "=", "<", ">",
    "+=", "-=", "*=", "/=", "%=", "^=", "&=", "|=", "<<", ">>", "<<=", ">>=",
    "==", "!=", "<=", ">=", "<=>", "&&", "||", "++", "--", ",", "->*", "->",
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
    end_col: int = 0


def _line_table(text: str) -> list[tuple[int, int, str]]:
    if not text:
        return []
    lines: list[tuple[int, int, str]] = []
    start = 0
    offset = 0
    n = len(text)
    while start < n:
        nl = text.find("\n", start)
        if nl == -1:
            seg = text[start:]
            encoded = seg.encode("utf-8")
            clean = seg[:-1] if seg.endswith("\r") else seg
            lines.append((offset, offset + len(encoded), clean))
            break
        seg = text[start:nl + 1]
        encoded = seg.encode("utf-8")
        clean = seg[:-2] if seg.endswith("\r\n") else seg[:-1]
        lines.append((offset, offset + len(encoded), clean))
        offset += len(encoded)
        start = nl + 1
    return lines


def _advance_span(span: str, line: int, col: int) -> tuple[int, int]:
    nl = span.count("\n")
    if nl:
        return line + nl, len(span) - span.rfind("\n")
    return line, col + len(span)


def _scan_raw_string(text: str, i: int, line: int, col: int) -> tuple[int, int, int] | None:
    m = _RAW_STR_PREFIX_RE.match(text, i)
    if not m:
        return None
    closing = ")" + m.group(1) + '"'
    end_idx = text.find(closing, m.end())
    if end_idx == -1:
        return None
    end_pos = end_idx + len(closing)
    new_line, new_col = _advance_span(text[i:end_pos], line, col)
    return end_pos, new_line, new_col


def _scan_quoted_literal(text: str, i: int, quote: str, line: int, col: int) -> tuple[int, int, int]:
    n = len(text)
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
    return i, line, col


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
            dm = _PP_DIRECTIVE_RE.match(text, i)
            if dm:
                kw = dm.group(1)
                if kw in {"if", "ifdef", "ifndef"}:
                    tokens.append(_Tok("PP", "if", line, col))
                elif kw in {"else", "elif", "elifdef", "elifndef"}:
                    tokens.append(_Tok("PP", "else", line, col))
                elif kw == "endif":
                    tokens.append(_Tok("PP", "endif", line, col))
            while i < n:
                c = text[i]
                if c == "\\" and i + 1 < n and text[i + 1] == "\n":
                    i += 2
                    line += 1
                    col = 1
                    continue
                if c == "\\" and i + 2 < n and text[i + 1] == "\r" and text[i + 2] == "\n":
                    i += 3
                    line += 1
                    col = 1
                    continue
                if c == "/" and i + 1 < n and text[i + 1] == "*":
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
                if c == "/" and i + 1 < n and text[i + 1] == "/":
                    i += 2
                    col += 2
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
                        if text[i] == "\n":
                            break
                        i += 1
                        col += 1
                    break
                raw_pp = _scan_raw_string(text, i, line, col)
                if raw_pp is not None:
                    i, line, col = raw_pp
                    continue
                num_pp = _PP_NUMBER_RE.match(text, i)
                if num_pp:
                    span = num_pp.group(0)
                    i = num_pp.end()
                    col += len(span)
                    continue
                sp_pp = _STR_PREFIX_RE.match(text, i)
                if sp_pp:
                    plen = len(sp_pp.group(0))
                    i, line, col = _scan_quoted_literal(text, i + plen, text[i + plen], line, col + plen)
                    continue
                if c in ('"', "'"):
                    i, line, col = _scan_quoted_literal(text, i, c, line, col)
                    continue
                if c == "\n":
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
                if text[i] == "\\" and i + 2 < n and text[i + 1] == "\r" and text[i + 2] == "\n":
                    i += 3
                    line += 1
                    col = 1
                    continue
                if text[i] == "\n":
                    break
                i += 1
                col += 1
            continue

        raw_hit = _scan_raw_string(text, i, line, col)
        if raw_hit is not None:
            tokens.append(_Tok("LIT", '""', line, col))
            i, line, col = raw_hit
            continue

        num_m = _PP_NUMBER_RE.match(text, i)
        if num_m:
            val = num_m.group(0)
            tokens.append(_Tok("LIT", val, line, col))
            i = num_m.end()
            col += len(val)
            continue

        sp_m = _STR_PREFIX_RE.match(text, i)
        if sp_m:
            start_line, start_col = line, col
            plen = len(sp_m.group(0))
            quote = text[i + plen]
            i, line, col = _scan_quoted_literal(text, i + plen, quote, line, col + plen)
            tokens.append(_Tok("LIT", quote * 2, start_line, start_col))
            continue

        if ch in ('"', "'"):
            start_line, start_col = line, col
            i, line, col = _scan_quoted_literal(text, i, ch, line, col)
            tokens.append(_Tok("LIT", ch * 2, start_line, start_col))
            continue

        m = _IDENT_RE.match(text, i)
        if m:
            val = m.group(0)
            tokens.append(_Tok("IDENT", val, line, col))
            i = m.end()
            col += len(val)
            continue

        three = text[i:i + 3]
        if three in _THREE_CHAR_OPS:
            tokens.append(_Tok("PUNCT", three, line, col))
            i += 3
            col += 3
            continue

        two = text[i:i + 2]
        if two in _TWO_CHAR_OPS:
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
        elif open_val == "<" and close_val == ">" and v == ">>":
            depth -= 2
            if depth <= 0:
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
        if tok.val == "[":
            end_b = _match_close(after, j, "[", "]")
            if end_b == -1:
                return False
            j = end_b + 1
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
    angle = 0
    paren = 0
    bracket = 0
    for k, tok in enumerate(stmt):
        is_op_arg = k >= 1 and stmt[k - 1].kind == "IDENT" and stmt[k - 1].val == "operator"
        if tok.val == "(":
            paren += 1
        elif tok.val == ")":
            paren = max(0, paren - 1)
        elif tok.val == "[":
            bracket += 1
        elif tok.val == "]":
            bracket = max(0, bracket - 1)
        elif paren == 0 and bracket == 0 and not is_op_arg:
            if tok.val == "<":
                angle += 1
            elif tok.val == ">":
                angle = max(0, angle - 1)
            elif tok.val == ">>" and angle > 0:
                angle = max(0, angle - 2)
            elif angle == 0 and tok.kind == "IDENT" and tok.val in {"struct", "class", "union", "enum"}:
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
        if tok.val == "[":
            end_b = _match_close(rest, pos, "[", "]")
            if end_b == -1:
                return None
            pos = end_b + 1
            continue
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


def _skip_trailing_template_or_attrs(stmt: list[_Tok], end_exclusive: int) -> int:
    idx = end_exclusive - 1
    while idx >= 0:
        if stmt[idx].val == "]" and idx >= 1 and stmt[idx - 1].val == "]":
            depth = 0
            found = -1
            for p in range(idx, -1, -1):
                if stmt[p].val == "]":
                    depth += 1
                elif stmt[p].val == "[":
                    depth -= 1
                    if depth == 0:
                        found = p
                        break
            if found != -1 and found + 1 <= idx and stmt[found + 1].val == "[":
                idx = found - 1
                continue
        if stmt[idx].val in {">", ">>"} and not (
            idx >= 1 and stmt[idx - 1].kind == "IDENT" and stmt[idx - 1].val == "operator"
        ):
            depth = 0
            found = -1
            for p in range(idx, -1, -1):
                if p >= 1 and stmt[p - 1].kind == "IDENT" and stmt[p - 1].val == "operator":
                    break
                if stmt[p].val == ">>":
                    depth += 2
                elif stmt[p].val == ">":
                    depth += 1
                elif stmt[p].val == "<":
                    depth -= 1
                    if depth <= 0:
                        found = p
                        break
            if found != -1:
                idx = found - 1
                continue
        break
    return idx


def _build_operator_token(stmt: list[_Tok], op_idx: int, end_exclusive: int) -> _Tok | None:
    op_tok = stmt[op_idx]
    parts = stmt[op_idx + 1:end_exclusive]
    if not parts:
        return None
    last = parts[-1]
    end_col = last.col + len(last.val) if last.line == op_tok.line else op_tok.col + len(op_tok.val)
    if len(parts) == 1 and parts[0].val in _OVERLOADABLE_OP_TOKENS:
        return _Tok("IDENT", f"operator{parts[0].val}", op_tok.line, op_tok.col, end_col)
    if len(parts) == 2 and parts[0].val == "(" and parts[1].val == ")":
        return _Tok("IDENT", "operator()", op_tok.line, op_tok.col, end_col)
    if len(parts) == 2 and parts[0].val == "[" and parts[1].val == "]":
        return _Tok("IDENT", "operator[]", op_tok.line, op_tok.col, end_col)
    if parts[0].kind == "IDENT" and parts[0].val in {"new", "delete", "co_await"}:
        if len(parts) == 1:
            return _Tok("IDENT", f"operator {parts[0].val}", op_tok.line, op_tok.col, end_col)
        if len(parts) == 3 and parts[1].val == "[" and parts[2].val == "]":
            return _Tok("IDENT", f"operator {parts[0].val}[]", op_tok.line, op_tok.col, end_col)
    if len(parts) == 2 and parts[0].kind == "LIT" and parts[0].val == '""' and parts[1].kind == "IDENT":
        return _Tok("IDENT", f'operator""{parts[1].val}', op_tok.line, op_tok.col, end_col)
    if any(p.val in {";", ",", "=", "{", "}"} for p in parts):
        return None
    rendered: list[str] = []
    for p in parts:
        if rendered and rendered[-1][-1].isalnum() and p.val[0].isalnum():
            rendered.append(" " + p.val)
        else:
            rendered.append(p.val)
    return _Tok("IDENT", "operator " + "".join(rendered), op_tok.line, op_tok.col, end_col)


def _find_function_before_brace(stmt: list[_Tok], *, in_type_scope: bool) -> _Tok | None:
    paren = 0
    bracket = 0
    angle = 0
    for idx, tok in enumerate(stmt):
        is_op_arg = idx >= 1 and stmt[idx - 1].kind == "IDENT" and stmt[idx - 1].val == "operator"
        if tok.val == "(":
            paren += 1
        elif tok.val == ")":
            paren = max(0, paren - 1)
        elif tok.val == "[":
            bracket += 1
        elif tok.val == "]":
            bracket = max(0, bracket - 1)
        elif paren == 0 and bracket == 0 and not is_op_arg:
            if tok.val == "<":
                angle += 1
            elif tok.val == ">":
                angle = max(0, angle - 1)
            elif tok.val == ">>" and angle > 0:
                angle = max(0, angle - 2)
            elif angle == 0 and tok.val == ":":
                stmt = stmt[:idx]
                break

    paren = 0
    bracket = 0
    angle = 0
    top_parens: list[tuple[int, int]] = []
    op_indices: list[int] = []
    idx = 0
    while idx < len(stmt):
        tok = stmt[idx]
        is_op_arg = idx >= 1 and stmt[idx - 1].kind == "IDENT" and stmt[idx - 1].val == "operator"
        if tok.val == "(":
            if paren == 0 and bracket == 0 and angle == 0:
                close_k = _match_close(stmt, idx, "(", ")")
                if close_k == -1:
                    return None
                top_parens.append((idx, close_k))
                idx = close_k + 1
                continue
            paren += 1
        elif tok.val == ")":
            paren = max(0, paren - 1)
        elif tok.val == "[":
            bracket += 1
        elif tok.val == "]":
            bracket = max(0, bracket - 1)
        elif paren == 0 and bracket == 0:
            if not is_op_arg and tok.val == "<":
                angle += 1
            elif not is_op_arg and tok.val == ">" and angle > 0:
                angle -= 1
            elif not is_op_arg and tok.val == ">>" and angle > 0:
                angle = max(0, angle - 2)
            elif angle == 0:
                if tok.val == "=" and not is_op_arg:
                    return None
                if tok.kind == "IDENT" and tok.val == "operator":
                    op_indices.append(idx)
        idx += 1

    for open_k, close_k in reversed(top_parens):
        if open_k == 0:
            continue
        if not _looks_like_post_params_before_body(stmt, open_k, close_k):
            continue
        op_before = [oi for oi in op_indices if oi < open_k]
        if op_before:
            op_idx = op_before[-1]
            decl_end = open_k
            if not (op_idx + 1 == open_k - 1 and stmt[op_idx + 1].val in {">", ">>"}):
                adj = _skip_trailing_template_or_attrs(stmt, open_k)
                if adj >= op_idx + 1:
                    decl_end = adj + 1
            op_tok = _build_operator_token(stmt, op_idx, decl_end)
            if op_tok is not None:
                prefix = stmt[:op_idx]
                is_conversion = not (
                    (decl_end - op_idx == 2 and stmt[op_idx + 1].val in _OVERLOADABLE_OP_TOKENS)
                    or (decl_end - op_idx == 3 and stmt[op_idx + 1].val in {"(", "["})
                )
                is_qualified = bool(prefix and prefix[-1].val == "::")
                if in_type_scope or is_qualified or prefix or is_conversion:
                    return op_tok

        name_idx = _skip_trailing_template_or_attrs(stmt, open_k)
        prefix_end = -1
        if name_idx >= 0 and stmt[name_idx].val == ")":
            wrapped = next(((op, cl) for op, cl in top_parens if cl == name_idx), None)
            if wrapped is not None:
                op, cl = wrapped
                inner = stmt[op + 1:cl]
                if (len(inner) == 1 and inner[0].kind == "IDENT"
                        and not (op >= 1 and stmt[op - 1].kind == "IDENT"
                                 and stmt[op - 1].val in _NON_FUNCTION_NAMES)):
                    name_idx = op + 1
                    prefix_end = op
        if name_idx < 0 or stmt[name_idx].kind != "IDENT":
            continue
        name_tok = stmt[name_idx]
        if name_tok.val in _NON_FUNCTION_NAMES:
            continue
        if name_tok.val in {"__attribute__", "__attribute", "__declspec", "alignas", "noexcept", "throw"}:
            continue
        prefix = stmt[:name_idx if prefix_end == -1 else prefix_end]
        if prefix and prefix[-1].val == "~":
            prefix = prefix[:-1]
        is_qualified = bool(prefix and prefix[-1].val == "::")
        if not in_type_scope and not is_qualified and not prefix:
            continue
        return name_tok
    return None


_TYPEDEF_SKIP_CLAUSES = frozenset({
    "__attribute__", "__attribute", "__declspec", "alignas", "_Alignas",
})
_TYPEDEF_SKIP_QUALIFIERS = frozenset({
    "const", "volatile", "restrict", "__restrict", "__restrict__", "_Atomic",
    "FAR", "NEAR", "ZEXPORT", "ZEXTERN",
})


def _typedef_names_after_brace(stmt: list[_Tok]) -> list[_Tok]:
    names: list[_Tok] = []
    seg_start = 0
    depth = 0
    segments: list[list[_Tok]] = []
    for idx, tok in enumerate(stmt):
        if tok.val in {"(", "["}:
            depth += 1
        elif tok.val in {")", "]"}:
            depth = max(0, depth - 1)
        elif depth == 0 and tok.val == ",":
            segments.append(stmt[seg_start:idx])
            seg_start = idx + 1
    segments.append(stmt[seg_start:])
    for seg in segments:
        j = 0
        while j < len(seg):
            cand = seg[j]
            if cand.kind == "IDENT" and cand.val in _TYPEDEF_SKIP_CLAUSES:
                j += 1
                if j < len(seg) and seg[j].val == "(":
                    end_p = _match_close(seg, j, "(", ")")
                    j = len(seg) if end_p == -1 else end_p + 1
                continue
            if cand.val == "[":
                end_b = _match_close(seg, j, "[", "]")
                j = len(seg) if end_b == -1 else end_b + 1
                continue
            if cand.kind == "IDENT" and cand.val not in _TYPEDEF_SKIP_QUALIFIERS:
                names.append(cand)
                break
            j += 1
    return names


def _is_namespace_open(stmt: list[_Tok]) -> bool:
    if any(t.val == "=" for t in stmt):
        return False
    idx = 0
    while idx < len(stmt) and stmt[idx].kind == "IDENT" and stmt[idx].val in {"inline", "export"}:
        idx += 1
    return idx < len(stmt) and stmt[idx].kind == "IDENT" and stmt[idx].val == "namespace"


def _is_extern_linkage_open(stmt: list[_Tok]) -> bool:
    idx = 0
    while idx < len(stmt) and stmt[idx].kind == "IDENT" and stmt[idx].val == "export":
        idx += 1
    return (
        idx + 1 < len(stmt)
        and stmt[idx].kind == "IDENT"
        and stmt[idx].val == "extern"
        and stmt[idx + 1].kind == "LIT"
    )


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
        end_c = tok.end_col if tok.end_col else tok.col + len(tok.val)
        out.append(CSymbolSpan(
            name=tok.val,
            kind=kind,
            line=tok.line,
            line_start_byte=start_b,
            line_end_byte=end_b,
            start_column=tok.col,
            end_column=end_c,
            line_text=line_txt,
        ))

    scope_stack: list[tuple[str, bool]] = []
    stmt: list[_Tok] = []
    after_typedef_brace = False
    pp_stack: list[tuple[list[tuple[str, bool]], bool, list[_Tok]]] = []

    def current_scope() -> str:
        return scope_stack[-1][0] if scope_stack else "file"

    i = 0
    n = len(tokens)
    while i < n and len(out) < limit:
        tok = tokens[i]
        if tok.kind == "PP":
            if tok.val == "if":
                pp_stack.append((list(scope_stack), after_typedef_brace, list(stmt)))
            elif tok.val == "else":
                if pp_stack:
                    saved_scopes, saved_typedef, saved_stmt = pp_stack[-1]
                    scope_stack[:] = list(saved_scopes)
                    after_typedef_brace = saved_typedef
                    stmt[:] = list(saved_stmt)
            elif tok.val == "endif":
                if pp_stack:
                    pp_stack.pop()
            i += 1
            continue

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
            if _is_extern_linkage_open(stmt):
                scope_stack.append(("extern", False))
            elif _is_namespace_open(stmt):
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
                for cand in _typedef_names_after_brace(stmt):
                    emit(cand, "typedef")
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
