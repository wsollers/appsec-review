"""Reduce a clang JSON AST to the declarations of one source file (stdlib only).

``clang -fsyntax-only -Xclang -ast-dump=json`` prints every declaration of every included header,
which for ``<string>`` alone is tens of megabytes. The PoC validators need only the nodes of the PoC
file and the identity of whatever those nodes reference. This module is therefore self-contained:
the job copies this file into the disposable compile workspace and runs it inside the build image
(``python3 ast_reduce.py ...``), where it starts the compiler, reads the whole dump and prints the
small ``appsec-review/poc-ast/1`` document that :mod:`.policy` checks. The same ``reduce_ast``
function is imported by the tests, so the reduction is verified on recorded dumps.

Clang prints a location's ``file`` and ``line`` only when they differ from the previously printed
location, so the reduction walks the dump in print order and tracks both. A node belongs to the PoC
file when its (expansion) location is in it; nodes that come from headers are never returned.
Referenced declarations are returned with their qualified name, kind and file so the policy can
tell a project function from a system one without trusting a spelling.
"""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "appsec-review/poc-ast/1"
CONTEXT_KINDS = frozenset({"NamespaceDecl", "CXXRecordDecl", "RecordDecl", "ClassTemplateSpecializationDecl",
                           "EnumDecl"})
RECORDED_KINDS = frozenset({
    "FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl", "CXXConversionDecl",
    "VarDecl", "FieldDecl", "CXXRecordDecl", "RecordDecl", "EnumDecl", "EnumConstantDecl", "TypedefDecl",
    "TypeAliasDecl", "ClassTemplateSpecializationDecl", "NamespaceDecl", "FunctionTemplateDecl",
    "ClassTemplateDecl"})
INLINE_NAMESPACES = frozenset({"__cxx11", "__1", "__detail"})
DROPPED_KEYS = frozenset({"definitionData", "valueCategory", "isUsed", "isReferenced", "ctorType", "bases",
                          "explicitCastType", "mangledName"})
KEPT_MANGLED = frozenset({"FunctionDecl"})
REFERENCE_KEYS = ("referencedDecl", "foundReferencedDecl", "operatorNewDecl", "operatorDeleteDecl")
CHILD_LISTS = ("inner", "array_filler")


class _Tracker:
    """Clang's last printed ``file`` and ``line``, advanced in print order."""

    def __init__(self) -> None:
        self.file = ""
        self.line = 0

    def location(self, value: Mapping[str, Any]) -> None:
        if "offset" in value:
            if "file" in value:
                self.file = str(value["file"])
            if "line" in value:
                self.line = int(value["line"])
            return
        for key in ("spellingLoc", "expansionLoc"):
            if isinstance(value.get(key), Mapping):
                self.location(value[key])

    def range(self, value: Mapping[str, Any]) -> tuple[str, int] | None:
        """Advance over a range; the position of its beginning."""
        begin = None
        for end in ("begin", "end"):
            if isinstance(value.get(end), Mapping):
                self.location(value[end])
                if begin is None:
                    begin = (self.file, self.line)
        return begin


class _Index(_Tracker):
    def __init__(self) -> None:
        super().__init__()
        self.decls: dict[str, dict[str, Any]] = {}
        self.contexts: dict[str, str] = {}
        self.top: list[tuple[Mapping[str, Any], str]] = []

    def walk(self, node: Mapping[str, Any], prefix: str) -> str:
        """Index ``node`` and its subtree; the file of the node's own location."""
        position = None
        for key, value in node.items():
            if key == "loc" and isinstance(value, Mapping):
                self.location(value)
                position = (self.file, self.line)
            elif key == "range" and isinstance(value, Mapping):
                begin = self.range(value)
                position = position or begin
        own = position[0] if position else ""
        kind, name, identity = node.get("kind"), node.get("name"), node.get("id")
        child_prefix = prefix
        if (isinstance(identity, str) and kind in RECORDED_KINDS and isinstance(name, str) and name
                and not (kind == "CXXRecordDecl" and node.get("isImplicit"))):
            parent = node.get("parentDeclContextId")
            context = self.contexts.get(parent, prefix) if isinstance(parent, str) else prefix
            qualified = context if name in INLINE_NAMESPACES else (f"{context}::{name}" if context else name)
            self.decls[identity] = {"kind": kind, "name": name, "qualified": qualified,
                                    "file": own, "line": position[1] if position else self.line}
            if kind in CONTEXT_KINDS:
                self.contexts[identity] = qualified
                child_prefix = qualified
        for child in node.get("inner", ()) if isinstance(node.get("inner"), list) else ():
            if isinstance(child, Mapping):
                self.walk(child, child_prefix)
        return own


def canonical(qualified: str) -> str:
    """The qualified name without inline namespaces (``std::__cxx11::basic_string`` is ``std::basic_string``)."""
    return "::".join(part for part in qualified.split("::") if part not in INLINE_NAMESPACES)


def _prune(node: Mapping[str, Any], tracker: _Tracker) -> dict[str, Any]:
    """A copy of ``node`` with locations replaced by a ``line`` and bulky attributes removed."""
    result: dict[str, Any] = {}
    for key, value in node.items():
        if key == "loc" and isinstance(value, Mapping):
            tracker.location(value)
            result.setdefault("line", tracker.line)
        elif key == "range" and isinstance(value, Mapping):
            begin = tracker.range(value)
            if begin is not None:
                result.setdefault("line", begin[1])
        elif key in DROPPED_KEYS and not (key == "mangledName" and node.get("kind") in KEPT_MANGLED):
            continue
        elif key in CHILD_LISTS and isinstance(value, list):
            result[key] = [_prune(child, tracker) if isinstance(child, Mapping) else child for child in value]
        else:
            result[key] = value
    return result


def _references(node: Any, found: set[str]) -> None:
    if isinstance(node, Mapping):
        for key in REFERENCE_KEYS:
            item = node.get(key)
            if isinstance(item, Mapping) and isinstance(item.get("id"), str):
                found.add(item["id"])
        member = node.get("referencedMemberDecl")
        if isinstance(member, str):
            found.add(member)
        alias = node.get("typeAliasDeclId")
        if isinstance(alias, str):
            found.add(alias)
        for value in node.values():
            if isinstance(value, (Mapping, list)):
                _references(value, found)
    elif isinstance(node, list):
        for item in node:
            _references(item, found)


def reduce_ast(ast: Mapping[str, Any], *, source: str, project_roots: Sequence[str] = ("/workspace/",),
               max_project_declarations: int = 4000) -> dict[str, Any]:
    """The ``poc-ast/1`` document for the nodes of ``source`` in a clang JSON dump."""
    index = _Index()
    selected: list[tuple[Mapping[str, Any], tuple[str, int]]] = []
    top_level = [child for child in ast.get("inner", ()) if isinstance(child, Mapping)]
    for child in top_level:
        # Replay the tracker on a copy so the pruned node sees the same state the dump had at it.
        snapshot = (index.file, index.line)
        own = index.walk(child, "")
        if own == source and not child.get("isImplicit"):
            selected.append((child, snapshot))
    nodes: list[dict[str, Any]] = []
    for child, (file, line) in selected:
        tracker = _Tracker()
        tracker.file, tracker.line = file, line
        nodes.append(_prune(child, tracker))
    referenced: set[str] = set()
    _references(nodes, referenced)
    declarations = {identity: {**info, "qualified": canonical(info["qualified"])}
                    for identity, info in sorted(index.decls.items()) if identity in referenced}
    project: list[dict[str, Any]] = []
    truncated = False
    skipped = {"NamespaceDecl", "FieldDecl", "EnumConstantDecl"}
    for info in sorted(index.decls.values(), key=lambda item: (item["file"], item["line"], item["qualified"])):
        if info["file"] == source or info["kind"] in skipped:
            continue
        if not any(info["file"].startswith(root) for root in project_roots):
            continue
        if len(project) >= max_project_declarations:
            truncated = True
            break
        project.append({"qualified": canonical(info["qualified"]), "kind": info["kind"], "file": info["file"],
                        "line": info["line"]})
    return {"schema": SCHEMA, "source": source, "project_roots": list(project_roots), "nodes": nodes, "declarations": declarations,
            "project_declarations": project, "project_declarations_truncated": truncated,
            "translation_unit_nodes": len(top_level)}


def _run(argv: Iterable[str]) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), stdout=subprocess.PIPE, stderr=sys.stderr, check=False)


def main(argv: Sequence[str]) -> int:
    """``ast_reduce.py --source FILE [--project-root DIR]... -- COMPILER ARGS...``"""
    arguments = list(argv)
    source = None
    roots: list[str] = []
    while arguments and arguments[0] != "--":
        flag = arguments.pop(0)
        if flag == "--source" and arguments:
            source = arguments.pop(0)
        elif flag == "--project-root" and arguments:
            roots.append(arguments.pop(0).rstrip("/") + "/")
        else:
            print(f"unknown argument: {flag}", file=sys.stderr)
            return 2
    if not arguments or arguments.pop(0) != "--" or not arguments or source is None:
        print("usage: ast_reduce.py --source FILE [--project-root DIR] -- COMPILER ARGS", file=sys.stderr)
        return 2
    version = _run([arguments[0], "--version"]).stdout.decode("utf-8", "replace").splitlines()
    completed = _run(arguments)
    try:
        ast = json.loads(completed.stdout.decode("utf-8", "replace")) if completed.stdout.strip() else {}
    except ValueError:
        ast = {}
    document = reduce_ast(ast, source=source, project_roots=roots or ["/workspace/"])
    document["compiler_exit_code"] = completed.returncode
    document["compiler_version"] = version[0] if version else ""
    sys.stdout.write(json.dumps(document, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
