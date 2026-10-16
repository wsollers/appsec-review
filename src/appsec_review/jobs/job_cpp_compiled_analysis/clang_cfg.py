"""Source-level control-flow graphs from Clang's ``debug.DumpCFG`` text.

``clang++ --analyze -Xanalyzer -analyzer-checker=debug.DumpCFG`` prints one ``clang::CFG`` per function
definition of a translation unit to stderr (``containers/tools/native-cpp/native.py`` mode ``cfg``).
The graph is the one the Static Analyzer walks, so it models source constructs the LLVM IR flow graph has
already lowered away: ``&&``/``||`` short circuits, ``?:``, ``for``/``while``/``do``, ``switch`` and
destructor calls appear as blocks with a ``T:`` terminator whose condition is a source expression.

What the text does **not** carry is a source position: a block has no line number. The graph is therefore
matched to an IR function by name and published on the function's flow entry as ``source_cfg`` with the
named gap ``source_cfg_no_block_lines``. Overloads (two definitions of one tail name in a translation
unit) are never guessed apart; they stay unattached and are named in ``ambiguous``.

``parse_cfgs`` is a pure function of the text. Every cut it makes (block, element or text bound) is
named in ``CfgModule.gaps``; nothing here raises on malformed input, because a CFG that cannot be parsed
is a gap, not evidence.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import re

MAX_ELEMENTS = 40          # statements kept per block
MAX_TEXT = 240             # characters of one rendered statement or condition
MAX_FUNCTIONS = 4000       # functions read from one translation unit's dump
NO_BLOCK_LINES_GAP = "source_cfg_no_block_lines: Clang's CFG dump carries no source positions; blocks are not mapped to lines"

_BLOCK = re.compile(r"^ \[B(?P<id>\d+)(?: \((?P<role>ENTRY|EXIT)\))?\]$")
_ELEMENT = re.compile(r"^\s+(?P<index>\d+): (?P<text>.*)$")
_TERMINATOR = re.compile(r"^   T: (?P<text>.*)$")
_EDGES = re.compile(r"^   (?P<kind>Preds|Succs) \((?P<count>\d+)\):(?P<ids>(?: B\d+)*)\s*$")
_REF = re.compile(r"\[B(?P<block>\d+)\.(?P<index>\d+)\]")
_CAST = re.compile(r"^\[B\d+\.\d+\] \(\w*Cast\w*(?:, [^)]*)*\)$|^\[B\d+\.\d+\] \(ImplicitCastExpr, .*\)$")
_QUALIFIERS = re.compile(r"\s+(?:const|volatile|noexcept(?:\([^)]*\))?|override|final|&&|&)\s*$")
_IDENT = re.compile(r"((?:[~A-Za-z_]\w*(?:<[^()]*>)?::)*(?:operator\s*\S+|~?[A-Za-z_]\w*))\s*$")


@dataclass(frozen=True, slots=True)
class CfgBlock:
    block_id: str                 # "B3"
    role: str | None              # "entry" | "exit" | None
    statements: tuple[str, ...]   # rendered, unreferenced elements, in order
    calls: tuple[str, ...]        # rendered call expressions, in order
    terminator: str | None        # "if", "while", "for", "switch", "&&", "||", "?:" ...
    condition: str | None         # rendered condition of the terminator, when it has one
    successors: tuple[str, ...]   # branch order of clang: for a conditional, true target first
    predecessors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SourceCfg:
    signature: str
    name: str                     # tail name, "ns::f" -> "f"
    qualified_name: str
    parameters: int
    blocks: tuple[CfgBlock, ...]
    truncated: tuple[str, ...] = ()

    def to_payload(self) -> dict[str, object]:
        """The deterministic, JSON-ready ``source_cfg`` of an IR function's flow entry."""
        return {
            "producer": "clang-cfg",
            "signature": self.signature[:MAX_TEXT],
            "entry": next((b.block_id for b in self.blocks if b.role == "entry"), None),
            "exit": next((b.block_id for b in self.blocks if b.role == "exit"), None),
            "blocks": [{"id": b.block_id, "role": b.role, "statements": list(b.statements), "calls": list(b.calls),
                        "terminator": b.terminator, "condition": b.condition,
                        "successors": list(b.successors), "predecessors": list(b.predecessors)}
                       for b in self.blocks],
            "branches": sum(1 for b in self.blocks if len(b.successors) > 1),
            "truncated": list(self.truncated),
            "gaps": [NO_BLOCK_LINES_GAP],
        }


@dataclass(frozen=True, slots=True)
class CfgModule:
    functions: tuple[SourceCfg, ...]
    gaps: tuple[str, ...] = ()
    unparsed: int = 0


@dataclass(slots=True)
class _Raw:
    block_id: str
    role: str | None = None
    elements: dict[int, str] = field(default_factory=dict)
    order: list[int] = field(default_factory=list)
    terminator: str | None = None
    preds: list[str] = field(default_factory=list)
    succs: list[str] = field(default_factory=list)


def _signature_parts(signature: str) -> tuple[str, str, int] | None:
    """(qualified name, tail name, parameter count) of a function head such as ``static int f(int a)``."""
    text = signature.strip()
    while True:
        stripped = _QUALIFIERS.sub("", text)
        if stripped == text:
            break
        text = stripped
    if not text.endswith(")"):
        return None
    depth, start = 0, -1
    for position in range(len(text) - 1, -1, -1):
        char = text[position]
        depth += char == ")"
        depth -= char == "("
        if depth == 0:
            start = position
            break
    if start < 1:
        return None
    match = _IDENT.search(text[:start])
    if not match:
        return None
    inner = text[start + 1:-1].strip()
    level, parameters = 0, 0 if inner in ("", "void") else 1
    for char in inner:
        level += char in "(<[" 
        level -= char in ")>]"
        parameters += char == "," and level == 0
    qualified = match.group(1)
    return qualified, qualified.rsplit("::", 1)[-1], parameters


def _render(raw: Mapping[str, _Raw], block: str, index: int, seen: frozenset[tuple[str, int]], depth: int) -> str:
    """The source-like text of one element, with ``[Bx.y]`` references replaced by what they compute."""
    current = raw.get(block)
    text = current.elements.get(index) if current else None
    if text is None:
        return f"[{block}.{index}]"
    if _CAST.match(text) and depth < 24:
        operand = _REF.match(text)
        if operand:
            return _render(raw, operand.group("block") and f"B{operand.group('block')}",
                           int(operand.group("index")), seen | {(block, index)}, depth + 1)

    def replace(match: re.Match[str]) -> str:
        key = (f"B{match.group('block')}", int(match.group("index")))
        if key in seen or depth >= 24:
            return match.group(0)
        return _render(raw, key[0], key[1], seen | {(block, index)}, depth + 1)

    return _REF.sub(replace, text)


def _terminator(raw: Mapping[str, _Raw], block: str, text: str) -> tuple[str, str | None]:
    """(kind, condition) of a ``T:`` line: ``if [B3.4]``, ``for (...; [B2.3]; ...)``, ``[B1.2] && ...``."""
    if text.startswith("("):
        return text[:40], None
    word = re.match(r"([A-Za-z_][\w ]*?)(?=\s*[\[(]|\s*$|\s+\S)", text)
    if word and not text.startswith("["):
        kind, rest = word.group(1).strip(), text[word.end():].strip().rstrip(";").strip()
        if not rest:
            return kind, None

        def replace(match: re.Match[str]) -> str:
            return _render(raw, f"B{match.group('block')}", int(match.group('index')), frozenset(), 0)

        return kind, _REF.sub(replace, rest)[:MAX_TEXT]
    operator = next((op for op in ("&&", "||", "?") if op in text), text.split(" ", 1)[0])
    operand = _REF.search(text)
    return operator, (_render(raw, f"B{operand.group('block')}", int(operand.group("index")), frozenset(), 0)[:MAX_TEXT]
                      if operand else None)


def _build(raw: Mapping[str, _Raw], order: list[str], signature: str, parts: tuple[str, str, int],
           block_limit: int) -> SourceCfg:
    blocks, truncated = [], []
    for block_id in order[:block_limit]:
        current = raw[block_id]
        rendered = {index: _render(raw, block_id, index, frozenset(), 0)[:MAX_TEXT] for index in current.order}
        referenced = {int(match.group("index")) for index in current.order
                      for match in _REF.finditer(current.elements[index]) if f"B{match.group('block')}" == block_id}
        calls, statements = [], []
        for index in current.order:
            text = current.elements[index]
            if re.search(r"\[B\d+\.\d+\]\(", text) and not text.startswith("return"):
                calls.append(rendered[index])
            if index in referenced or _CAST.match(text):
                continue
            statements.append(rendered[index])
        statements = [text for position, text in enumerate(statements)
                      if not any(text != later and text in later for later in statements[position + 1:])]
        if len(statements) > MAX_ELEMENTS:
            truncated.append(f"{block_id} statements cut at {MAX_ELEMENTS}")
        terminator = condition = None
        if current.terminator:
            terminator, condition = _terminator(raw, block_id, current.terminator)
        blocks.append(CfgBlock(block_id, current.role, tuple(statements[:MAX_ELEMENTS]), tuple(calls[:MAX_ELEMENTS]),
                               terminator, condition, tuple(current.succs), tuple(current.preds)))
    if len(order) > block_limit:
        truncated.append(f"blocks cut at {block_limit} of {len(order)}")
    qualified, tail, parameters = parts
    return SourceCfg(signature.strip(), tail, qualified, parameters, tuple(blocks), tuple(truncated))


def parse_cfgs(text: str, *, block_limit: int = 2000) -> CfgModule:
    """Every function CFG of one ``debug.DumpCFG`` dump; ``block_limit`` bounds blocks per function."""
    functions: list[SourceCfg] = []
    gaps: list[str] = []
    unparsed = 0
    signature: str | None = None
    raw: dict[str, _Raw] = {}
    order: list[str] = []
    current: _Raw | None = None

    def close() -> None:
        nonlocal signature, raw, order, current, unparsed
        if signature is not None and raw:
            parts = _signature_parts(signature)
            if parts is None:
                unparsed += 1
            elif len(functions) < MAX_FUNCTIONS:
                functions.append(_build(raw, order, signature, parts, block_limit))
        signature, raw, order, current = None, {}, [], None

    for line in text.splitlines():
        if not line.strip():
            continue
        if not line.startswith(" "):
            close()
            signature = line
            continue
        if signature is None:
            continue
        block = _BLOCK.match(line)
        if block:
            block_id = f"B{block.group('id')}"
            current = raw.setdefault(block_id, _Raw(block_id, (block.group("role") or "").lower() or None))
            if block_id not in order:
                order.append(block_id)
            continue
        if current is None:
            continue
        edges = _EDGES.match(line)
        if edges:
            ids = edges.group("ids").split()
            (current.preds if edges.group("kind") == "Preds" else current.succs).extend(ids)
            continue
        terminator = _TERMINATOR.match(line)
        if terminator:
            current.terminator = terminator.group("text").strip()
            continue
        element = _ELEMENT.match(line)
        if element:
            index = int(element.group("index"))
            current.elements[index] = element.group("text").strip()
            current.order.append(index)
    close()
    if len(functions) >= MAX_FUNCTIONS:
        gaps.append(f"source_cfg_limit: only the first {MAX_FUNCTIONS} function CFGs of a translation unit are read")
    if unparsed:
        gaps.append(f"source_cfg_unparsed: {unparsed} function head(s) in the CFG dump could not be read")
    return CfgModule(tuple(functions), tuple(gaps), unparsed)
