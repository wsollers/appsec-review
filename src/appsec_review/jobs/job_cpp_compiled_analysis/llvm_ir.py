"""A bounded textual LLVM IR reader: functions, source ranges, CFG, dominance, def-use and calls.

The compiled-analysis job replays clang with ``-emit-llvm -S -g -O0``; this module turns that text
into facts a model can read without opening the IR. It is deliberately a *reader*, not a verifier:
it understands the constructs clang emits for ordinary functions (``br``, ``switch``, ``invoke``,
``ret``, direct ``call``) and reports everything else as unparsed rather than guessing.

Function names are the source-level, namespace-qualified names (``ns::Type::method``) taken from the
debug metadata (``DISubprogram`` plus its ``DINamespace``/``DICompositeType`` chain), so they can be
compared with the names CodeQL and clangd report. Callee names come from a small Itanium
demangler that covers plain, namespaced and member functions and constructors/destructors; a
template, operator or other mangling it does not cover keeps its linkage name and is counted.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

MAX_BLOCKS = 4000
MAX_DEF_USE = 400
MAX_CALLS = 2000

_META = re.compile(r"^!(\d+)\s*=\s*(?:distinct\s+)?!(\w+)\((.*)\)\s*$")
_FIELD = re.compile(r'(\w+):\s*("(?:[^"\\]|\\.)*"|[^,)]+)')
_DEFINE = re.compile(r'^define\b.*?@(?P<name>"[^"]+"|[\w.$-]+)\(.*?(?:!dbg !(?P<dbg>\d+))?\s*\{\s*$')
_LABEL = re.compile(r"^(?P<label>[\w.$-]+):(?:\s*;.*)?$")
_ASSIGN = re.compile(r"^\s*(%[\w.$-]+)\s*=\s*")
_LABEL_REF = re.compile(r"label %([\w.$-]+)")
_VALUE_REF = re.compile(r"%[\w.$-]+")
_DBG = re.compile(r"!dbg !(\d+)")
_CALL = re.compile(r'\b(?:call|invoke)\b[^(]*?(?:\([^)]*\)\s*)?@(?P<callee>"[^"]+"|[\w.$-]+)\s*\(')
_INDIRECT = re.compile(r"\b(?:call|invoke)\b[^@(]*%")
_TERMINATOR = re.compile(r"^\s*(?:%[\w.$-]+\s*=\s*)?(br|switch|invoke|ret|unreachable|resume|indirectbr|"
                         r"cleanupret|catchret|callbr)\b")


@dataclass(frozen=True, slots=True)
class IrBlock:
    block_id: str
    label: str
    start_line: int | None
    end_line: int | None
    successors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IrCall:
    callee: str
    callee_linkage: str
    line: int | None
    column: int | None
    block_id: str


@dataclass(frozen=True, slots=True)
class DefUse:
    value: str
    def_line: int | None
    use_lines: tuple[int, ...]
    use_count: int


@dataclass(frozen=True, slots=True)
class IrFunction:
    name: str
    linkage_name: str
    path: str
    start_line: int
    end_line: int
    internal: bool
    blocks: tuple[IrBlock, ...]
    dominators: Mapping[str, str | None]
    post_dominators: Mapping[str, str | None]
    calls: tuple[IrCall, ...]
    def_use: tuple[DefUse, ...]
    indirect_calls: int = 0
    truncated: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        """Identity within a module; internal-linkage functions are only unique per translation unit."""
        return self.linkage_name

    def flow(self) -> dict[str, object]:
        """The deterministic, JSON-ready flow summary stored on the entity payload."""
        return {
            "entry": self.blocks[0].block_id if self.blocks else None,
            "blocks": [{"id": b.block_id, "label": b.label, "start_line": b.start_line,
                        "end_line": b.end_line, "successors": list(b.successors)} for b in self.blocks],
            "dominators": {key: self.dominators[key] for key in sorted(self.dominators)},
            "post_dominators": {key: self.post_dominators[key] for key in sorted(self.post_dominators)},
            "def_use": [{"value": d.value, "def_line": d.def_line, "use_lines": list(d.use_lines),
                         "use_count": d.use_count} for d in self.def_use],
            "indirect_calls": self.indirect_calls,
            "truncated": list(self.truncated),
        }


@dataclass(frozen=True, slots=True)
class IrModule:
    functions: tuple[IrFunction, ...]
    declared: Mapping[str, str] = field(default_factory=dict)
    unparsed: tuple[str, ...] = ()
    undemangled: int = 0


def _fields(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in _FIELD.findall(raw):
        out[key] = value.strip()
    return out


def _string(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1].replace('\\"', '"').replace("\\5C", "\\")
    return value


def _ref(value: str | None) -> str | None:
    return value[1:] if value and value.startswith("!") and value[1:].isdigit() else None


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


class _Metadata:
    def __init__(self, lines: Iterable[str]) -> None:
        self.nodes: dict[str, tuple[str, dict[str, str]]] = {}
        for line in lines:
            match = _META.match(line.strip())
            if match:
                self.nodes[match.group(1)] = (match.group(2), _fields(match.group(3)))

    def kind(self, node: str | None) -> str | None:
        return self.nodes[node][0] if node in self.nodes else None

    def field(self, node: str | None, name: str) -> str | None:
        return self.nodes[node][1].get(name) if node in self.nodes else None

    def location(self, node: str | None) -> tuple[int | None, int | None]:
        if self.kind(node) != "DILocation":
            return None, None
        return _int(self.field(node, "line")), _int(self.field(node, "column"))

    def file_path(self, node: str | None) -> str | None:
        if self.kind(node) != "DIFile":
            return None
        name = _string(self.field(node, "filename")) or ""
        directory = _string(self.field(node, "directory")) or ""
        if name.startswith("/"):
            full = name
        else:
            full = f"{directory.rstrip('/')}/{name}" if directory else name
        return full

    def qualified_name(self, subprogram: str) -> str:
        parts = [_string(self.field(subprogram, "name")) or ""]
        scope = _ref(self.field(subprogram, "scope"))
        seen: set[str] = set()
        while scope and scope not in seen:
            seen.add(scope)
            kind = self.kind(scope)
            if kind in {"DINamespace", "DICompositeType"}:
                name = _string(self.field(scope, "name"))
                if name:
                    parts.append(name)
            elif kind not in {"DILexicalBlock", "DILexicalBlockFile", "DISubprogram"}:
                break
            scope = _ref(self.field(scope, "scope"))
        return "::".join(reversed([part for part in parts if part]))


def demangle(linkage: str) -> str | None:
    """Qualified name of a simple Itanium symbol, or ``None`` when it needs a full demangler."""
    if not linkage.startswith("_Z") or len(linkage) < 4:
        return None
    pos = 2
    if linkage[pos] == "L":
        pos += 1
    parts: list[str] = []

    def source_name(at: int) -> tuple[str, int] | None:
        digits = re.match(r"\d+", linkage[at:])
        if not digits:
            return None
        size = int(digits.group(0))
        start = at + len(digits.group(0))
        if size == 0 or start + size > len(linkage):
            return None
        return linkage[start:start + size], start + size

    if linkage[pos] == "N":
        pos += 1
        while pos < len(linkage) and linkage[pos] in "rVK":
            pos += 1
        while pos < len(linkage) and linkage[pos] != "E":
            if linkage[pos] == "C" and linkage[pos + 1:pos + 2] in {"1", "2", "3"}:
                if not parts:
                    return None
                parts.append(parts[-1])
                pos += 2
                continue
            if linkage[pos] == "D" and linkage[pos + 1:pos + 2] in {"0", "1", "2"}:
                if not parts:
                    return None
                parts.append("~" + parts[-1])
                pos += 2
                continue
            parsed = source_name(pos)
            if parsed is None:
                return None
            parts.append(parsed[0])
            pos = parsed[1]
        if not parts:
            return None
    else:
        parsed = source_name(pos)
        if parsed is None:
            return None
        parts.append(parsed[0])
        pos = parsed[1]
        if pos < len(linkage) and linkage[pos] == "I":
            return None
    return "::".join(parts)


def _split_functions(lines: Sequence[str]) -> list[tuple[str, str, list[str]]]:
    functions: list[tuple[str, str, list[str]]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("define "):
            match = _DEFINE.match(line)
            body: list[str] = []
            index += 1
            while index < len(lines) and lines[index].rstrip() != "}":
                body.append(lines[index])
                index += 1
            if match:
                name = match.group("name").strip('"')
                functions.append((name, line, body))
        index += 1
    return functions


def _dominators(order: Sequence[str], successors: Mapping[str, Sequence[str]], entry: str) -> dict[str, str | None]:
    preds: dict[str, list[str]] = {node: [] for node in order}
    for node in order:
        for succ in successors.get(node, ()):
            if succ in preds:
                preds[succ].append(node)
    # reverse post-order over the nodes reachable from the entry
    visited: set[str] = set()
    post: list[str] = []
    stack: list[tuple[str, int]] = [(entry, 0)]
    visited.add(entry)
    while stack:
        node, i = stack.pop()
        succs = [s for s in successors.get(node, ()) if s in preds]
        if i < len(succs):
            stack.append((node, i + 1))
            if succs[i] not in visited:
                visited.add(succs[i])
                stack.append((succs[i], 0))
        else:
            post.append(node)
    rpo = list(reversed(post))
    number = {node: idx for idx, node in enumerate(rpo)}
    idom: dict[str, str | None] = {entry: entry}

    def intersect(a: str, b: str) -> str:
        while a != b:
            while number[a] > number[b]:
                a = idom[a]  # type: ignore[assignment]
            while number[b] > number[a]:
                b = idom[b]  # type: ignore[assignment]
        return a

    changed = True
    while changed:
        changed = False
        for node in rpo[1:]:
            candidates = [p for p in preds[node] if p in idom]
            if not candidates:
                continue
            new = candidates[0]
            for other in candidates[1:]:
                new = intersect(new, other)
            if idom.get(node) != new:
                idom[node] = new
                changed = True
    result: dict[str, str | None] = {node: parent for node, parent in idom.items() if node != entry}
    result[entry] = None
    return result


def _post_dominators(order: Sequence[str], successors: Mapping[str, Sequence[str]]) -> dict[str, str | None]:
    exit_node = "<exit>"
    rev: dict[str, list[str]] = {node: [] for node in (*order, exit_node)}
    for node in order:
        succs = [s for s in successors.get(node, ()) if s in rev]
        if not succs:
            rev[exit_node].append(node)
        for succ in succs:
            rev[succ].append(node)
    result = _dominators((*order, exit_node), rev, exit_node)
    out: dict[str, str | None] = {}
    for node in order:
        parent = result.get(node)
        out[node] = None if parent in (None, exit_node) else parent
    return out


def parse_module(text: str, *, root: str = "/scratch/source", block_limit: int = MAX_BLOCKS) -> IrModule:
    """Parse one module's IR text. Paths are relative to ``root`` when they lie under it."""
    lines = text.splitlines()
    meta = _Metadata(line for line in lines if line.startswith("!"))
    declared: dict[str, str] = {}
    unparsed: list[str] = []
    functions: list[IrFunction] = []
    undemangled = 0
    prefix = root.rstrip("/") + "/"
    for name, header, body in _split_functions(lines):
        dbg = re.search(r"!dbg !(\d+)", header)
        if dbg is None or meta.kind(dbg.group(1)) != "DISubprogram":
            unparsed.append(f"{name}: no debug subprogram")
            continue
        sp = dbg.group(1)
        file_node = _ref(meta.field(sp, "file"))
        full = meta.file_path(file_node) or ""
        path = full[len(prefix):] if full.startswith(prefix) else full
        qualified = meta.qualified_name(sp) or (demangle(name) or name)
        start = _int(meta.field(sp, "line")) or 0
        internal = "DISPFlagLocalToUnit" in (meta.field(sp, "spFlags") or "") or " internal " in header
        # --- blocks
        blocks: list[dict[str, object]] = []
        current: dict[str, object] | None = None
        truncated: list[str] = []
        calls: list[IrCall] = []
        indirect = 0
        defs: dict[str, int | None] = {}
        uses: dict[str, list[int]] = {}
        use_counts: dict[str, int] = {}
        pending_switch: list[str] | None = None
        for raw in body:
            stripped = raw.strip()
            if not stripped or stripped.startswith(";"):
                continue
            if pending_switch is not None:
                pending_switch.append(stripped)
                if "]" in stripped:
                    assert current is not None
                    current["succ"].extend(_LABEL_REF.findall(" ".join(pending_switch)))  # type: ignore[union-attr]
                    pending_switch = None
                continue
            label = _LABEL.match(stripped)
            if label and not stripped.startswith(("%", "call", "store", "br ")):
                current = {"label": label.group("label"), "lines": [], "succ": []}
                blocks.append(current)
                continue
            if current is None:
                current = {"label": "entry", "lines": [], "succ": []}
                blocks.append(current)
            if len(blocks) > block_limit:
                if "blocks" not in truncated:
                    truncated.append("blocks")
                continue
            dbg_match = _DBG.search(stripped)
            line, column = meta.location(dbg_match.group(1)) if dbg_match else (None, None)
            if line:
                current["lines"].append(line)  # type: ignore[union-attr]
            assign = _ASSIGN.match(stripped)
            rest = stripped[assign.end():] if assign else stripped
            if assign:
                defs[assign.group(1)] = line
            for ref in _VALUE_REF.findall(re.sub(r"label %[\w.$-]+", "", rest.split("!dbg", 1)[0])):
                use_counts[ref] = use_counts.get(ref, 0) + 1
                if line:
                    uses.setdefault(ref, []).append(line)
            term = _TERMINATOR.match(stripped)
            if term:
                kind = term.group(1)
                if kind == "switch" and "]" not in stripped:
                    pending_switch = [stripped]  # the case list continues on following lines
                elif kind in {"br", "switch", "invoke", "callbr"}:
                    current["succ"].extend(_LABEL_REF.findall(stripped))  # type: ignore[union-attr]
            call = _CALL.search(stripped)
            if call:
                linkage = call.group("callee").strip('"')
                if linkage.startswith("llvm."):
                    continue
                shown = demangle(linkage)
                if shown is None and linkage.startswith("_Z"):
                    undemangled += 1
                if len(calls) >= MAX_CALLS:
                    if "calls" not in truncated:
                        truncated.append("calls")
                    continue
                calls.append(IrCall(shown or linkage, linkage, line, column, str(len(blocks) - 1)))
                declared.setdefault(linkage, shown or linkage)
            elif _INDIRECT.search(stripped):
                indirect += 1
        ids = [f"bb{i}" for i in range(len(blocks))]
        by_label = {str(b["label"]): ids[i] for i, b in enumerate(blocks)}
        successors = {ids[i]: tuple(dict.fromkeys(by_label[s] for s in b["succ"] if s in by_label))  # type: ignore[union-attr]
                      for i, b in enumerate(blocks)}
        out_blocks = tuple(
            IrBlock(ids[i], str(b["label"]), min(b["lines"]) if b["lines"] else None,  # type: ignore[arg-type]
                    max(b["lines"]) if b["lines"] else None, successors[ids[i]])  # type: ignore[arg-type]
            for i, b in enumerate(blocks))
        fixed_calls = tuple(IrCall(c.callee, c.callee_linkage, c.line, c.column, ids[int(c.block_id)])
                            for c in calls)
        all_lines = [line for b in blocks for line in b["lines"]]  # type: ignore[union-attr]
        end = max([start, *all_lines]) if all_lines else start
        doms = _dominators(ids, successors, ids[0]) if ids else {}
        pdoms = _post_dominators(ids, successors) if ids else {}
        def_use: list[DefUse] = []
        for value, def_line in defs.items():
            if use_counts.get(value) is None:
                continue
            if len(def_use) >= MAX_DEF_USE:
                truncated.append("def_use")
                break
            def_use.append(DefUse(value, def_line, tuple(sorted(set(uses.get(value, ())))), use_counts[value]))
        functions.append(IrFunction(
            name=qualified, linkage_name=name, path=path, start_line=start, end_line=end,
            internal=internal, blocks=out_blocks, dominators=doms, post_dominators=pdoms,
            calls=fixed_calls, def_use=tuple(def_use), indirect_calls=indirect,
            truncated=tuple(sorted(set(truncated)))))
    functions.sort(key=lambda f: (f.path, f.start_line, f.linkage_name))
    return IrModule(tuple(functions), dict(sorted(declared.items())), tuple(unparsed), undemangled)
