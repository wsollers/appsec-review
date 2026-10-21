"""Package neighborhood (``package-neighborhood/1``, docs/architecture/review-protocol-v2.md section 4).

The neighborhood is the part of a review package that is selected by *location and function scope* rather
than by a correlated dataflow path: the lead's function, every sink, range and guard fact in it, the callers
and callees of the function to the configured call depth, the flow and entry facts that touch those sinks,
the build command summary of the compilation that owns the file, and the other observations at the same
line. This module holds the pure pieces: the neighborhood record, the build summary, and the source-text
helpers the model-facing view uses (function extent, type names). ``GraphContext.neighborhood`` in
``review.packages`` selects the rows; ``review.package_view`` renders them.

Everything stored here is an identity plus a one-line summary (``review.fact_summary``); source text is read
when a cell's view is built, from the accepted source index and verified against the file hash recorded in
the package. Bounds are the code-graph settings (``max_call_depth``, ``max_neighbors_per_function``,
``max_paths_per_sink``, ``max_guards_per_sink``); whatever a bound removes is counted in ``omitted``.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
import re
from typing import Any

from appsec_review.review.scope import AcceptedScope

NEIGHBORHOOD_RULE = "appsec-review/package-neighborhood/1"
BUILD_RULE = "appsec-review/package-build-summary/1"
SECTIONS = ("sinks", "ranges", "guards", "callers", "callees", "flows", "entries", "corroboration")
# Token kinds of an ordered build command (``indexing.build_facts.classify_command``) shown as flags.
_FLAG_KINDS = frozenset({"optimization", "debug", "language_standard", "define", "undefine", "warning",
                         "security_flag", "flag"})
MAX_BUILD_FLAGS = 48
_BRACE_LANGUAGES = frozenset({".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp",
                              ".java", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".cs", ".php", ".kt", ".swift",
                              ".m", ".mm", ".scala"})
MAX_FUNCTION_LINES = 160


def empty_record(depth: int) -> dict[str, Any]:
    return {"rule": NEIGHBORHOOD_RULE, "call_depth": depth, "function": None,
            **{section: [] for section in SECTIONS}, "build": None,
            "chain": {"reached": False, "depth_limit": depth, "hops": [], "entries": []},
            "omitted": {section: 0 for section in SECTIONS}}


@dataclass(frozen=True, slots=True)
class NeighborhoodRow:
    """One neighborhood entry: a logical identity, its context role, and a fact summary."""

    ref: str
    role: str
    summary: str
    line: int | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def record(self) -> dict[str, Any]:
        return {"ref": self.ref, "line": self.line, "summary": self.summary, **self.extra}


class BuildContext:
    """Accepted ``build_provenance`` command facts indexed by the source files they compile."""

    def __init__(self, scope: AcceptedScope):
        self.by_path: dict[str, list[tuple[str, Mapping[str, Any]]]] = defaultdict(list)
        shards = scope.select(lambda shard: shard["name"] == "precomputed" and
                              (shard.get("producer") or {}).get("query_set") == "build_provenance")
        self.available = bool(shards)
        for row in scope.store.entities(shards, kinds=("precomputed_fact",)):
            payload = row["payload"] if isinstance(row["payload"], Mapping) else {}
            if payload.get("fact_type") != "build_action":
                continue
            result = payload.get("result") if isinstance(payload.get("result"), Mapping) else {}
            for source_input in result.get("source_inputs", ()):
                for prefix in ("relative:", "target:"):
                    if isinstance(source_input, str) and source_input.startswith(prefix):
                        self.by_path[source_input[len(prefix):]].append((str(row["identity"]), result))

    def summary(self, path: str | None) -> dict[str, Any] | None:
        """The compiler, ordered flags and hardening flags of the first (by identity) action compiling ``path``."""
        actions = sorted(self.by_path.get(str(path), ()), key=lambda item: item[0]) if path else []
        if not actions:
            return None
        identity, result = actions[0]
        commands = result.get("command_facts") if isinstance(result.get("command_facts"), list) else []
        tokens = [token for command in commands if isinstance(command, Mapping)
                  for token in command.get("ordered_tokens", ()) if isinstance(token, Mapping)]
        flags: list[str] = []
        for token in tokens:
            value = token.get("safe_value")
            if token.get("kind") in _FLAG_KINDS and isinstance(value, str) and value not in flags:
                flags.append(value)
        compiler = next((str(token["safe_value"]) for token in tokens
                         if token.get("kind") == "tool" and token.get("safe_value")), None) or result.get("tool")
        security = sorted({str(item) for item in result.get("security_flags", ()) if isinstance(item, str)})
        return {"rule": BUILD_RULE, "ref": identity, "compiler": compiler if isinstance(compiler, str) else None,
                "flags": flags[:MAX_BUILD_FLAGS], "flags_omitted": max(0, len(flags) - MAX_BUILD_FLAGS),
                "hardening": security,
                "actions": len(actions), "complete": not result.get("gaps")}


# ------------------------------------------------------------------------------------------------
# Source-text helpers (used by the model-facing view; pure functions of already-verified text)


def function_extent(lines: Sequence[str], start_line: int, path: str, *, max_lines: int = MAX_FUNCTION_LINES
                    ) -> tuple[int, int, bool]:
    """(first, last, truncated) 1-based lines of the function whose name is on ``start_line``.

    Brace languages: from the first ``{`` at or after the name to its matching ``}``, ignoring braces in
    string and character literals and in comments. Indentation languages: the block that follows the
    definition line. When no end is found within ``max_lines`` the extent is cut there and marked truncated.
    """
    start = max(1, min(int(start_line), len(lines) or 1))
    suffix = PurePosixPath(path).suffix.lower()
    limit = min(len(lines), start + max_lines - 1)
    if suffix == ".py":
        base = len(lines[start - 1]) - len(lines[start - 1].lstrip()) if lines else 0
        end = start
        for number in range(start + 1, limit + 1):
            text = lines[number - 1]
            if text.strip() and len(text) - len(text.lstrip()) <= base and not text.lstrip().startswith(("#", ")")):
                break
            end = number
        return start, end, end == limit and limit < len(lines)
    if suffix not in _BRACE_LANGUAGES:
        return start, min(len(lines), start + 40), len(lines) > start + 40
    depth, opened, in_block = 0, False, False
    for number in range(start, limit + 1):
        text = lines[number - 1]
        index, in_string = 0, None
        while index < len(text):
            char = text[index]
            pair = text[index:index + 2]
            if in_block:
                if pair == "*/":
                    in_block, index = False, index + 1
            elif in_string:
                if char == "\\":
                    index += 1
                elif char == in_string:
                    in_string = None
            elif pair == "//":
                break
            elif pair == "/*":
                in_block, index = True, index + 1
            elif char in "\"'":
                in_string = char
            elif char == "{":
                depth, opened = depth + 1, True
            elif char == "}":
                depth -= 1
                if opened and depth <= 0:
                    return start, number, False
            elif char == ";" and not opened:
                return start, number, False       # a declaration, not a definition
            index += 1
    return start, limit, True


_TYPE_KEYWORD = re.compile(r"\b(?:struct|class|union|enum)\s+([A-Za-z_]\w*)")
_PARAMETER_TYPE = re.compile(r"(?:^|[(,]\s*)(?:const\s+|volatile\s+|unsigned\s+)*([A-Za-z_][\w:]*)\s*[&*\s]\s*[A-Za-z_]\w*\s*(?=[,)])")
_BUILTIN_TYPES = frozenset({
    "void", "int", "char", "short", "long", "float", "double", "bool", "signed", "unsigned", "size_t", "ssize_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t", "auto", "const",
    "std::string", "string", "wchar_t", "uintptr_t", "intptr_t", "ptrdiff_t", "off_t", "FILE", "va_list", "self",
    "str", "bytes", "int", "dict", "list", "object", "String", "Object", "Integer"})


def type_names(lines: Sequence[str], first: int, last: int, *, limit: int = 8) -> list[str]:
    """Candidate user type names mentioned in a function's signature and body, in order of appearance.

    Heuristic and deterministic: ``struct|class|union|enum NAME`` mentions, and the type tokens of the
    declared parameters of the signature. A name is only a candidate; the view looks each one up in the
    accepted index and records a gap for every name it cannot locate.
    """
    text = "\n".join(lines[first - 1:last])
    signature = "\n".join(lines[first - 1:min(last, first + 3)]).split("{", 1)[0]
    found: list[str] = []
    for match in sorted([*_TYPE_KEYWORD.finditer(text), *_PARAMETER_TYPE.finditer(signature)],
                        key=lambda item: item.start()):
        name = match.group(1).split("::")[-1]
        if name and name not in _BUILTIN_TYPES and name not in found and not name.startswith("_"):
            found.append(name)
    return found[:limit]


def dedupe(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))


__all__ = ["BUILD_RULE", "BuildContext", "MAX_FUNCTION_LINES", "NEIGHBORHOOD_RULE", "NeighborhoodRow", "SECTIONS",
           "dedupe", "empty_record", "function_extent", "type_names"]
