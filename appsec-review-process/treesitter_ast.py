#!/usr/bin/env python3
"""Batch tree-sitter parse of a checkout into a deterministic, hash-bound AST summary (brief C step 5).

One process parses every supported file with py-tree-sitter (vendored in every compiler image at
/opt/treesitter; docs/language-servers.md §3) and writes ``appsec-review/treesitter-ast/1``
(schemas/treesitter-ast.schema.json): per file its language, sha256, size, named-node-kind
histogram, function definitions with spans, call sites and imports. It is an additional AST source
beside Joern/CPG, not a replacement, and nothing here executes or evaluates target code.

Determinism: files are sorted by path, rows by position, text is control-stripped and truncated,
and ``content_sha256`` is the sha256 of the canonical JSON of everything except itself. Timing and
memory go to ``--stats`` (not hashed). Coverage problems are ``gaps`` (oversized, unreadable,
symlinked, languages without a grammar, per-file row caps), never silent omissions; files without a
grammar are counted per suffix and listed by path (``NO_GRAMMAR_PATHS``, then one overflow gap). A
suffix-less file takes its grammar from its shebang (``#!/bin/sh``, ``#!/usr/bin/env python3``). Build scripts,
docs and config that are not program source (``NON_SOURCE_*``) are counted in ``totals.non_source``,
not reported as missing grammars.

    /opt/treesitter/bin/python treesitter_ast.py --root /workspace --out /scratch/treesitter-ast.json \\
        --stats /scratch/treesitter-ast.stats.json
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib
from importlib import metadata
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import time
from typing import Any, Callable, Iterable

SCHEMA = "appsec-review/treesitter-ast/1"
TEXT_LIMIT = 200
DEFAULT_LIMITS = {"max_file_bytes": 2 * 1024 * 1024, "max_files": 200_000, "max_rows_per_file": 5000}
SKIP_DIRS = {".git", ".hg", ".svn"}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
_SPACE = re.compile(r"\s+")

# language -> (python module, language() function, distribution name)
GRAMMARS = {
    "bash": ("tree_sitter_bash", "language", "tree-sitter-bash"),
    "c": ("tree_sitter_c", "language", "tree-sitter-c"),
    "c_sharp": ("tree_sitter_c_sharp", "language", "tree-sitter-c-sharp"),
    "cpp": ("tree_sitter_cpp", "language", "tree-sitter-cpp"),
    "go": ("tree_sitter_go", "language", "tree-sitter-go"),
    "java": ("tree_sitter_java", "language", "tree-sitter-java"),
    "javascript": ("tree_sitter_javascript", "language", "tree-sitter-javascript"),
    "json": ("tree_sitter_json", "language", "tree-sitter-json"),
    "php": ("tree_sitter_php", "language_php", "tree-sitter-php"),
    "python": ("tree_sitter_python", "language", "tree-sitter-python"),
    "ruby": ("tree_sitter_ruby", "language", "tree-sitter-ruby"),
    "rust": ("tree_sitter_rust", "language", "tree-sitter-rust"),
    "tsx": ("tree_sitter_typescript", "language_tsx", "tree-sitter-typescript"),
    "typescript": ("tree_sitter_typescript", "language_typescript", "tree-sitter-typescript"),
}
SUFFIXES = {
    ".sh": "bash", ".bash": "bash",
    ".c": "c", ".h": "c",
    ".cs": "c_sharp",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".c++": "cpp", ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".inl": "cpp", ".ipp": "cpp",
    ".go": "go", ".java": "java",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".json": "json", ".php": "php", ".py": "python", ".pyi": "python", ".rb": "ruby", ".rs": "rust",
    ".ts": "typescript", ".mts": "typescript", ".cts": "typescript", ".tsx": "tsx",
}
# Not program source: build-system inputs, docs and config. Counted (totals.non_source), not gaps.
NON_SOURCE_SUFFIXES = {".am", ".ac", ".in", ".m4", ".mk", ".md", ".rst", ".txt", ".texi", ".yml", ".yaml",
                       ".cfg", ".ini", ".toml"}
NON_SOURCE_NAMES = {"Makefile", "GNUmakefile", "makefile", "configure", "LICENSE", "COPYING", "AUTHORS",
                    "NEWS", "README", "ChangeLog", "INSTALL", "THANKS", "TODO", "NOTICE", ".gitignore",
                    ".gitattributes", ".editorconfig"}
# Suffix-less scripts: the shebang interpreter picks the grammar (02-language-census uses the same parser).
SHEBANG_LANGUAGES = {"sh": "bash", "bash": "bash", "dash": "bash", "zsh": "bash", "ksh": "bash", "ash": "bash",
                     "python": "python", "perl": "perl", "ruby": "ruby", "node": "javascript", "nodejs": "javascript",
                     "php": "php"}
SHEBANG_HEAD = 256
NO_GRAMMAR_PATHS = 500   # no-grammar files listed by path; the rest are one overflow gap
_SHEBANG = re.compile(rb"#![ \t]*(\S+)((?:[ \t]+\S+)*)")
_ENV_ARGUMENT = re.compile(r"-[A-Za-z]+|[A-Za-z_][A-Za-z0-9_]*=.*")
_VERSIONED = re.compile(r"([a-z]+?)(?:[0-9][0-9.]*)?(?:-[0-9.]+)?\Z")


def shebang_interpreter(head: bytes) -> str | None:
    """The interpreter a ``#!`` first line names (``env`` forms followed, version suffix dropped), or None."""
    match = _SHEBANG.match(head.split(b"\n", 1)[0].rstrip(b"\r"))
    if not match:
        return None
    words = [match.group(1).decode("utf-8", "replace")] + match.group(2).decode("utf-8", "replace").split()
    program = words[0].rsplit("/", 1)[-1]
    if program == "env":
        rest = [word for word in words[1:] if not _ENV_ARGUMENT.fullmatch(word)]
        if not rest:
            return None
        program = rest[0].rsplit("/", 1)[-1]
    versioned = _VERSIONED.match(program)
    return (versioned.group(1) if versioned else program)[:40] or None


def shebang_language(head: bytes) -> str | None:
    return SHEBANG_LANGUAGES.get(shebang_interpreter(head) or "")


def language_for(path: Path) -> str | None:
    """Grammar language of one file: its suffix, else (suffix-less, not a known build/doc name) its shebang."""
    language = SUFFIXES.get(path.suffix.lower())
    if language is None and not path.suffix and path.name not in NON_SOURCE_NAMES:
        try:
            with path.open("rb") as stream:
                language = shebang_language(stream.read(SHEBANG_HEAD))
        except OSError:
            return None
    return language if language in GRAMMARS else None


# Node types per language: function definitions, call sites, imports.
FUNCTIONS = {
    "bash": {"function_definition"},
    "c": {"function_definition"},
    "c_sharp": {"method_declaration", "constructor_declaration", "local_function_statement",
                "operator_declaration", "destructor_declaration"},
    "cpp": {"function_definition"},
    "go": {"function_declaration", "method_declaration"},
    "java": {"method_declaration", "constructor_declaration"},
    "javascript": {"function_declaration", "generator_function_declaration", "method_definition",
                   "function_expression", "arrow_function"},
    "php": {"function_definition", "method_declaration"},
    "python": {"function_definition"},
    "ruby": {"method", "singleton_method"},
    "rust": {"function_item"},
    "typescript": {"function_declaration", "generator_function_declaration", "method_definition",
                   "function_expression", "arrow_function", "function_signature", "method_signature"},
}
FUNCTIONS["tsx"] = FUNCTIONS["typescript"]
CALLS = {
    "bash": {"command"},
    "c": {"call_expression"},
    "c_sharp": {"invocation_expression", "object_creation_expression"},
    "cpp": {"call_expression", "new_expression"},
    "go": {"call_expression"},
    "java": {"method_invocation", "object_creation_expression"},
    "javascript": {"call_expression", "new_expression"},
    "php": {"function_call_expression", "member_call_expression", "scoped_call_expression",
            "object_creation_expression"},
    "python": {"call"},
    "ruby": {"call"},
    "rust": {"call_expression", "macro_invocation"},
    "typescript": {"call_expression", "new_expression"},
}
CALLS["tsx"] = CALLS["typescript"]
IMPORTS = {
    "c": {"preproc_include"},
    "c_sharp": {"using_directive"},
    "cpp": {"preproc_include", "using_declaration"},
    "go": {"import_spec"},
    "java": {"import_declaration"},
    "javascript": {"import_statement"},
    "php": {"namespace_use_declaration", "include_expression", "include_once_expression",
            "require_expression", "require_once_expression"},
    "python": {"import_statement", "import_from_statement", "future_import_statement"},
    "rust": {"use_declaration", "extern_crate_declaration"},
    "typescript": {"import_statement", "import_alias"},
}
IMPORTS["tsx"] = IMPORTS["typescript"]
CALLEE_FIELDS = ("function", "name", "method", "macro", "constructor", "type")


def clean(raw: bytes | str | None, limit: int = TEXT_LIMIT) -> str | None:
    if raw is None:
        return None
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    value = _SPACE.sub(" ", _CONTROL.sub(" ", text)).strip()
    return value[:limit] or None


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_languages(tree_sitter: Any = None) -> tuple[dict[str, Any], dict[str, str], list[dict[str, str]]]:
    """Grammar objects, pinned versions, and gaps for grammars that are not importable."""
    tree_sitter = tree_sitter or importlib.import_module("tree_sitter")
    languages, versions, gaps = {}, {}, []
    for name, (module, function, distribution) in sorted(GRAMMARS.items()):
        try:
            languages[name] = tree_sitter.Language(getattr(importlib.import_module(module), function)())
            versions[name] = metadata.version(distribution)
        except Exception as exc:  # noqa: BLE001 - any grammar failure is a recorded gap
            gaps.append({"kind": "grammar-unavailable", "path": None,
                         "detail": f"{name}: {type(exc).__name__}"})
    return languages, versions, gaps


def _declarator_name(node: Any) -> Any:
    """C/C++: follow declarator fields down to the identifier-like leaf."""
    seen = 0
    while node is not None and seen < 32:
        inner = node.child_by_field_name("declarator")
        if inner is None:
            return node
        node, seen = inner, seen + 1
    return node


def function_name(node: Any, language: str) -> str | None:
    if language in ("c", "cpp"):
        target = _declarator_name(node.child_by_field_name("declarator"))
        return clean(target.text) if target is not None else None
    name = node.child_by_field_name("name")
    if name is not None:
        return clean(name.text)
    if node.type in ("arrow_function", "function_expression"):
        parent = node.parent
        if parent is not None and parent.type in ("variable_declarator", "pair", "assignment_expression",
                                                  "public_field_definition", "field_definition"):
            for field in ("name", "key", "left", "property"):
                target = parent.child_by_field_name(field)
                if target is not None:
                    return clean(target.text)
        return None
    return None


RECEIVER_FIELDS = ("object", "scope", "receiver")


def callee_text(node: Any) -> str | None:
    """The called expression; member calls keep their receiver (``obj.method``)."""
    for field in CALLEE_FIELDS:
        target = node.child_by_field_name(field)
        if target is not None:
            if field in ("name", "method"):
                for receiver_field in RECEIVER_FIELDS:
                    receiver = node.child_by_field_name(receiver_field)
                    if receiver is not None:
                        return clean(receiver.text + b"." + target.text)
            return clean(target.text)
    return clean(node.children[0].text) if node.children else None


def summarize_tree(root: Any, language: str, limit: int) -> tuple[dict[str, Any], list[str]]:
    """Walk one tree with a cursor (no recursion); return the per-file record body and truncations."""
    functions_types, calls_types = FUNCTIONS.get(language, set()), CALLS.get(language, set())
    imports_types = IMPORTS.get(language, set())
    kinds: Counter = Counter()
    functions, calls, imports = [], [], []
    errors = 0
    cursor = root.walk()
    while True:
        node = cursor.node
        if node.is_error or node.is_missing:
            errors += 1
        if node.is_named:
            kind = node.type
            kinds[kind] += 1
            if kind in functions_types:
                functions.append({"name": function_name(node, language), "kind": kind,
                                  "start_line": node.start_point[0] + 1, "end_line": node.end_point[0] + 1})
            elif kind in calls_types:
                calls.append({"callee": callee_text(node), "line": node.start_point[0] + 1})
            elif kind in imports_types:
                imports.append({"text": clean(node.text), "line": node.start_point[0] + 1})
        if cursor.goto_first_child() or cursor.goto_next_sibling():
            continue
        while cursor.goto_parent():
            if cursor.goto_next_sibling():
                break
        else:
            break
    truncated = []
    for label, rows, key in (("functions", functions, lambda r: (r["start_line"], r["end_line"], r["name"] or "", r["kind"])),
                             ("calls", calls, lambda r: (r["line"], r["callee"] or "")),
                             ("imports", imports, lambda r: (r["line"], r["text"] or ""))):
        rows.sort(key=key)
        if len(rows) > limit:
            truncated.append(label)
            del rows[limit:]
    return {"node_kinds": [{"kind": kind, "count": count} for kind, count in sorted(kinds.items())],
            "error_nodes": errors, "functions": functions, "calls": calls, "imports": imports}, truncated


def iter_files(root: Path, file_list: Iterable[str] | None = None) -> Iterable[tuple[str, Path | None, str | None]]:
    """(relative posix path, real path or None, gap kind or None), sorted, never leaving root."""
    if file_list is not None:
        names = sorted({line.strip() for line in file_list if line.strip()})
    else:
        names = []
        for directory, subdirs, files in os.walk(root, followlinks=False):
            base = Path(directory).relative_to(root)
            # A symlinked directory is reported (as symlink-skipped below), never descended.
            names.extend((base / name).as_posix() for name in subdirs if (Path(directory) / name).is_symlink())
            subdirs[:] = sorted(name for name in subdirs
                                if name not in SKIP_DIRS and not (Path(directory) / name).is_symlink())
            names.extend((base / name).as_posix() for name in files)
        names.sort()
    for name in names:
        pure = PurePosixPath(name)
        if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
            yield name, None, "path-outside-root"
            continue
        path = root.joinpath(*pure.parts)
        if path.is_symlink():
            yield pure.as_posix(), None, "symlink-skipped"
        elif not path.is_file():
            yield pure.as_posix(), None, "not-a-file"
        else:
            yield pure.as_posix(), path, None


class Scan:
    """One pass over a checkout. ``records()`` yields file records in path order and keeps only
    counters, gaps and the running manifest hash, so a large tree streams in bounded memory."""

    def __init__(self, root: Path, *, file_list: Iterable[str] | None = None,
                 limits: dict[str, int] | None = None, tree_sitter: Any = None, label: str | None = None,
                 clock: Callable[[], float] = time.perf_counter):
        self.limits = {**DEFAULT_LIMITS, **(limits or {})}
        self.clock, self.started = clock, clock()
        self.tree_sitter = tree_sitter or importlib.import_module("tree_sitter")
        languages, self.versions, self.gaps = load_languages(self.tree_sitter)
        self.parsers = {name: self.tree_sitter.Parser(language) for name, language in languages.items()}
        self.root = root.resolve()
        self.label = label or self.root.name or "/"
        self.file_list = file_list
        self.totals = {"files": 0, "bytes": 0, "functions": 0, "calls": 0, "imports": 0, "error_nodes": 0,
                       "non_source": 0}
        self.parse_seconds = 0.0
        self._manifest = hashlib.sha256(b"[")

    def records(self) -> Iterable[dict[str, Any]]:
        unsupported: Counter = Counter()
        unlisted: list[str] = []
        seen = 0
        for relative, path, problem in iter_files(self.root, self.file_list):
            if problem:
                self.gaps.append({"kind": problem, "path": relative, "detail": problem})
                continue
            language = language_for(path)
            if language is None and (path.name in NON_SOURCE_NAMES or
                                     path.suffix.lower() in NON_SOURCE_SUFFIXES):
                self.totals["non_source"] += 1
                continue
            if language is None:
                unsupported[path.suffix.lower() or "(none)"] += 1
                if len(unlisted) < NO_GRAMMAR_PATHS:
                    unlisted.append(relative)
                continue
            seen += 1
            if seen > self.limits["max_files"]:
                self.gaps.append({"kind": "max-files", "path": relative, "detail": "max_files reached; file not parsed"})
                continue
            if language not in self.parsers:
                self.gaps.append({"kind": "grammar-unavailable", "path": relative, "detail": language})
                continue
            try:
                size = path.stat().st_size
                if size > self.limits["max_file_bytes"]:
                    self.gaps.append({"kind": "file-too-large", "path": relative,
                                      "detail": f"{size} bytes exceeds max_file_bytes"})
                    continue
                data = path.read_bytes()
            except OSError as exc:
                self.gaps.append({"kind": "unreadable", "path": relative, "detail": type(exc).__name__})
                continue
            tick = self.clock()
            tree = self.parsers[language].parse(data)
            body, truncated = summarize_tree(tree.root_node, language, self.limits["max_rows_per_file"])
            del tree
            self.parse_seconds += self.clock() - tick
            for label in truncated:
                self.gaps.append({"kind": "rows-truncated", "path": relative,
                                  "detail": f"{label} capped at max_rows_per_file"})
            record = {"path": relative, "language": language,
                      "sha256": "sha256:" + hashlib.sha256(data).hexdigest(), "bytes": len(data), **body}
            self._manifest.update((b"," if self.totals["files"] else b"") +
                                  canonical([record["path"], record["sha256"]]))
            self.totals["files"] += 1
            self.totals["bytes"] += len(data)
            self.totals["error_nodes"] += body["error_nodes"]
            for key in ("functions", "calls", "imports"):
                self.totals[key] += len(body[key])
            yield record
        for suffix, count in sorted(unsupported.items()):
            self.gaps.append({"kind": "no-grammar", "path": None, "detail": f"{count} file(s) with suffix {suffix}"})
        # The same files by path (bounded): consumers apply exclusions and the language census to them.
        for relative in unlisted:
            suffix = PurePosixPath(relative).suffix.lower() or "(none)"
            self.gaps.append({"kind": "no-grammar", "path": relative, "detail": f"no grammar for suffix {suffix}"})
        overflow = sum(unsupported.values()) - len(unlisted)
        if overflow:
            self.gaps.append({"kind": "no-grammar", "path": None, "detail": f"{overflow} more file(s) without a grammar "
                              f"are not listed by path (cap {NO_GRAMMAR_PATHS})"})

    def trailer(self) -> dict[str, Any]:
        """Every top-level member except files and content_sha256; valid once records() is exhausted."""
        gaps = sorted(self.gaps, key=lambda g: (g["kind"], g["path"] or "", g["detail"]))
        manifest = self._manifest.copy()
        manifest.update(b"]")
        return {"gaps": gaps,
                "generator": {"name": "treesitter_ast.py", "tree_sitter": metadata.version("tree-sitter"),
                              "grammars": [{"language": n, "version": self.versions[n]} for n in sorted(self.versions)],
                              "limits": dict(sorted(self.limits.items()))},
                "root": self.label, "schema": SCHEMA,
                "source_manifest_sha256": "sha256:" + manifest.hexdigest(),
                "totals": {**self.totals, "gaps": len(gaps)}}

    def stats(self) -> dict[str, Any]:
        return {"wall_seconds": round(self.clock() - self.started, 3),
                "parse_and_walk_seconds": round(self.parse_seconds, 3),
                "files": self.totals["files"], "bytes": self.totals["bytes"], "max_rss_kib": _max_rss_kib()}


def build(root: Path, **kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """(document, stats) in memory. The document is deterministic for the same bytes and pins."""
    scan = Scan(root, **kwargs)
    document = {"files": list(scan.records()), **scan.trailer()}
    document["content_sha256"] = "sha256:" + hashlib.sha256(canonical(document)).hexdigest()
    return document, scan.stats()


def write(root: Path, out: Path, **kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Stream the same document to ``out`` (one file record per line) in bounded memory; returns
    (totals with content_sha256, stats). ``content_sha256`` equals build()'s: the canonical form
    sorts top-level keys and ``files`` sorts first, so it is hashed incrementally in order."""
    scan = Scan(root, **kwargs)
    digest = hashlib.sha256(b'{"files":[')
    out.parent.mkdir(parents=True, exist_ok=True)
    temp = out.with_name("." + out.name + ".tmp")
    with temp.open("wb") as stream:
        stream.write(b'{"schema": ' + json.dumps(SCHEMA).encode() + b',\n"files": [\n')
        first = True
        for record in scan.records():
            digest.update((b"" if first else b",") + canonical(record))
            stream.write((b"" if first else b",\n") +
                         json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8"))
            first = False
        trailer = scan.trailer()
        for key in ("gaps", "generator", "root", "schema", "source_manifest_sha256", "totals"):
            digest.update(b"]," if key == "gaps" else b",")
            digest.update(json.dumps(key).encode() + b":" + canonical(trailer[key]))
        digest.update(b"}")
        content = "sha256:" + digest.hexdigest()
        stream.write(b"\n]")
        for key in ("gaps", "generator", "root", "source_manifest_sha256", "totals"):
            stream.write(b",\n" + json.dumps(key).encode() + b": " +
                         json.dumps(trailer[key], sort_keys=True, ensure_ascii=False).encode("utf-8"))
        stream.write(b',\n"content_sha256": ' + json.dumps(content).encode() + b"}\n")
    os.replace(temp, out)
    return {**trailer["totals"], "content_sha256": content}, scan.stats()


def verify(document: dict[str, Any]) -> bool:
    """True when content_sha256 still binds the document body."""
    body = {key: value for key, value in document.items() if key != "content_sha256"}
    return document.get("content_sha256") == "sha256:" + hashlib.sha256(canonical(body)).hexdigest()


def _max_rss_kib() -> int | None:
    try:
        import resource
        return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except (ImportError, OSError, ValueError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--file-list", type=Path, help="newline-separated paths relative to --root")
    parser.add_argument("--label", help="root label recorded in the document (default: the root's name)")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--stats", type=Path, help="write timing/memory here (not part of the hashed document)")
    for key, value in DEFAULT_LIMITS.items():
        parser.add_argument("--" + key.replace("_", "-"), type=int, default=value)
    args = parser.parse_args(argv)
    if not args.root.is_dir():
        parser.error("--root must be a directory")
    try:
        import tree_sitter  # noqa: F401
    except ImportError:
        parser.error("py-tree-sitter is not importable; run with /opt/treesitter/bin/python")
    listing = args.file_list.read_text(encoding="utf-8").splitlines() if args.file_list else None
    limits = {key: getattr(args, key) for key in DEFAULT_LIMITS}
    totals, stats = write(args.root, args.out, file_list=listing, limits=limits, label=args.label)
    if args.stats:
        args.stats.parent.mkdir(parents=True, exist_ok=True)
        args.stats.write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(args.out), **totals, **stats}, sort_keys=True), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
