"""Bounded, source-resolved import graph with afferent/efferent coupling.

Only edges whose target resolves to an accepted inventory file (or a locally declared Go package,
C# namespace, Java package, or PHP namespace) are counted.  Bare package names are external.  An
import that looks local but does not resolve, an alias the job cannot evaluate (tsconfig ``paths``,
include search paths), and any non-literal ``require``/``import()``/``include`` are retained as
explicit unresolved or dynamic records, so coupling is a lower bound wherever those exist.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
import posixpath
import re
from typing import Any

from .languages import LanguageSpec
from .syntax import Node, SourceFile


GRAPH_IDENTITY = "appsec-review/import-graph/1"
_JS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".d.ts")
_STRING_TYPES = frozenset({"string", "string_literal", "interpreted_string_literal", "raw_string_literal",
                           "template_string", "encapsed_string"})
_MODULE_LINE = re.compile(rb"^\s*module\s+(\S+)", re.M)


def _literal(source: SourceFile, node: Node | None) -> str | None:
    if node is None or node.type not in _STRING_TYPES:
        return None
    if node.type == "template_string" and any(item.type == "template_substitution" for item in node.children):
        return None
    if node.type == "encapsed_string" and any(item.type not in {"string_content", "string_value", "\""}
                                              for item in node.children if item.named):
        return None
    text = source.text(node, 1024).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'`":
        return text[1:-1]
    if text.startswith("<") and text.endswith(">"):
        return text[1:-1]
    return text


def _record(node: Node, kind: str, specifier: str | None, *, dynamic: bool = False, base: str | None = None) -> dict:
    return {"kind": kind, "specifier": specifier, "dynamic": dynamic, "base": base, "line": node.start_line}


def extract(source: SourceFile, spec: LanguageSpec) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return raw import records and the local declarations other files may import."""
    grammar = spec.grammar
    records: list[dict[str, Any]] = []
    declarations: dict[str, Any] = {"package": None, "namespaces": [], "types": []}
    text = source.text
    for node in source.root.walk():
        kind = node.type
        if grammar in {"c", "cpp"} and kind == "preproc_include":
            path = node.child("path")
            if path is not None:
                local = path.type == "string_literal"
                value = _literal(source, path) if local else text(path, 512).strip().lstrip("<").rstrip(">")
                records.append(_record(node, "include" if local else "system_include", value))
        elif grammar == "java":
            if kind == "package_declaration":
                named = node.named_children()
                declarations["package"] = text(named[0], 512).strip() if named else None
            elif kind == "import_declaration":
                body = text(node, 512).strip().removeprefix("import").strip().rstrip(";").strip()
                static = body.startswith("static ")
                records.append(_record(node, "java_static_import" if static else "java_import",
                                       body.removeprefix("static ").replace(" ", "")))
            elif kind in {"class_declaration", "interface_declaration", "enum_declaration", "record_declaration"} \
                    and node.parent is not None and node.parent.type == "program":
                name = node.child("name")
                if name is not None:
                    declarations["types"].append(text(name, 128))
        elif grammar == "csharp":
            if kind == "using_directive":
                names = [item for item in node.named_children() if item.type in {"qualified_name", "identifier"}]
                if names:
                    records.append(_record(node, "csharp_using", text(names[-1], 512).replace(" ", "")))
            elif kind in {"namespace_declaration", "file_scoped_namespace_declaration"}:
                name = node.child("name")
                if name is not None:
                    declarations["namespaces"].append(text(name, 512).replace(" ", ""))
        elif grammar == "go":
            if kind == "package_clause":
                named = node.named_children()
                declarations["package"] = text(named[0], 128) if named else None
            elif kind == "import_spec":
                records.append(_record(node, "go_import", _literal(source, node.child("path"))))
        elif grammar in {"javascript", "typescript", "tsx"}:
            if kind in {"import_statement", "export_statement"} and node.child("source") is not None:
                records.append(_record(node, "esm_import", _literal(source, node.child("source"))))
            elif kind == "call_expression":
                function = node.child("function")
                arguments = node.child("arguments")
                first = arguments.named_children()[0] if arguments is not None and arguments.named_children() else None
                if function is not None and function.type == "import":
                    value = _literal(source, first)
                    records.append(_record(node, "dynamic_import", value, dynamic=value is None))
                elif function is not None and function.type == "identifier" and text(function, 16) == "require":
                    value = _literal(source, first)
                    records.append(_record(node, "require", value, dynamic=value is None))
        elif grammar == "rust":
            if kind == "mod_item" and node.child("body") is None:
                name = node.child("name")
                if name is not None:
                    records.append(_record(node, "rust_mod", text(name, 128)))
            elif kind == "use_declaration":
                argument = node.child("argument")
                if argument is not None:
                    records.append(_record(node, "rust_use", text(argument, 512).replace(" ", "")))
            elif kind == "extern_crate_declaration":
                name = node.child("name")
                records.append(_record(node, "rust_extern_crate", text(name, 128) if name is not None else None))
        elif grammar == "php":
            if kind in {"require_expression", "require_once_expression", "include_expression",
                        "include_once_expression"}:
                named = node.named_children()
                argument = named[0] if named else None
                while argument is not None and argument.type == "parenthesized_expression" and argument.named_children():
                    argument = argument.named_children()[0]
                value = _literal(source, argument)
                base = None
                if value is None and argument is not None and argument.type == "binary_expression":
                    left, right = argument.child("left"), argument.child("right")
                    left_text = text(left, 64).replace(" ", "") if left is not None else ""
                    if left_text in {"__DIR__", "dirname(__FILE__)"}:
                        value, base = _literal(source, right), "dir"
                records.append(_record(node, "php_include", value, dynamic=value is None, base=base))
            elif kind == "namespace_definition":
                name = node.child("name")
                if name is not None:
                    declarations["package"] = text(name, 512).strip()
            elif kind == "namespace_use_clause":
                names = [item for item in node.named_children() if item.type in {"qualified_name", "name"}]
                if names:
                    records.append(_record(node, "php_use", text(names[0], 512).strip().lstrip("\\")))
            elif kind in {"class_declaration", "interface_declaration", "trait_declaration", "enum_declaration"}:
                name = node.child("name")
                if name is not None:
                    declarations["types"].append(text(name, 128))
    return records, declarations


def import_modules(records: Iterable[Mapping[str, Any]]) -> frozenset[str]:
    """Specifiers a file imports, used to qualify unqualified heuristic calls."""
    return frozenset(str(item["specifier"]) for item in records if item.get("specifier"))


def _rust_module_path(path: str, crate_src: str) -> list[str] | None:
    relative = posixpath.relpath(path, crate_src)
    if relative.startswith(".."):
        return None
    if relative in {"lib.rs", "main.rs"}:
        return []
    parts = relative[:-3].split("/") if relative.endswith(".rs") else relative.split("/")
    return parts[:-1] if parts and parts[-1] == "mod" else parts


class GraphBuilder:
    """Resolve raw import records against the accepted inventory and local declarations."""

    def __init__(self, files: Mapping[str, Mapping[str, Any]], inventory: Iterable[str],
                 read: Callable[[str], bytes], *, min_confidence: float, max_records: int):
        self.files = files
        self.inventory = set(inventory)
        self.min_confidence = min_confidence
        self.max_records = max_records
        self.go_modules: dict[str, str] = {}
        for path in sorted(self.inventory):
            if posixpath.basename(path) == "go.mod":
                match = _MODULE_LINE.search(read(path)[:65536])
                if match:
                    self.go_modules[posixpath.dirname(path)] = match.group(1).decode("utf-8", "replace")
        self.cargo_roots = sorted((posixpath.dirname(path) for path in self.inventory
                                   if posixpath.basename(path) == "Cargo.toml"), key=len, reverse=True)
        self.java_packages: dict[str, dict[str, str]] = defaultdict(dict)
        self.csharp_namespaces: dict[str, list[str]] = defaultdict(list)
        self.php_namespaces: dict[str, dict[str, str]] = defaultdict(dict)
        for path, value in files.items():
            declarations = value.get("declarations", {})
            grammar = value.get("grammar")
            if grammar == "java" and declarations.get("package"):
                for name in declarations.get("types", ()):
                    self.java_packages[declarations["package"]][name] = path
            elif grammar == "csharp":
                for namespace in declarations.get("namespaces", ()):
                    self.csharp_namespaces[namespace].append(path)
            elif grammar == "php":
                namespace = declarations.get("package") or ""
                for name in declarations.get("types", ()):
                    self.php_namespaces[namespace][name] = path

    # -- module identity -----------------------------------------------------------------------
    def module_of(self, path: str) -> str:
        value = self.files[path]
        if value.get("grammar") == "go":
            return "go-package:" + (posixpath.dirname(path) or ".")
        if value.get("grammar") == "csharp" and value.get("declarations", {}).get("namespaces"):
            return "csharp-namespace:" + value["declarations"]["namespaces"][0]
        return "file:" + path

    def _go_module(self, path: str) -> tuple[str, str] | None:
        directory = posixpath.dirname(path)
        while True:
            if directory in self.go_modules:
                return directory, self.go_modules[directory]
            if not directory:
                return None
            directory = posixpath.dirname(directory)

    def _crate_src(self, path: str) -> str | None:
        for root in self.cargo_roots:
            src = posixpath.join(root, "src") if root else "src"
            if path.startswith(src + "/"):
                return src
        return None

    def _rust_file(self, src: str, segments: list[str]) -> str | None:
        if not segments:
            for name in ("lib.rs", "main.rs"):
                if posixpath.join(src, name) in self.inventory:
                    return posixpath.join(src, name)
            return None
        base = posixpath.join(src, *segments)
        for candidate in (base + ".rs", posixpath.join(base, "mod.rs")):
            if candidate in self.inventory:
                return candidate
        return None

    # -- resolution ----------------------------------------------------------------------------
    def resolve_one(self, path: str, record: Mapping[str, Any]) -> dict[str, Any]:
        grammar = self.files[path].get("grammar")
        kind = record["kind"]
        specifier = record.get("specifier")
        outcome = {"specifier": specifier, "kind": kind, "line": record.get("line"), "targets": [],
                   "status": "unresolved", "method": None, "confidence": 0.0}
        if record.get("dynamic") or specifier is None:
            return {**outcome, "status": "dynamic", "method": "non_literal_specifier"}
        directory = posixpath.dirname(path)

        def found(targets: list[str], method: str, confidence: float) -> dict[str, Any]:
            return {**outcome, "targets": sorted(set(targets)), "status": "resolved", "method": method,
                    "confidence": confidence}

        if kind == "include":
            joined = posixpath.normpath(posixpath.join(directory, specifier))
            if joined in self.inventory:
                return found([joined], "include-relative", 1.0)
            matches = sorted(item for item in self.inventory if item.endswith("/" + specifier) or item == specifier)
            if len(matches) == 1:
                return found(matches, "include-unique-suffix", 0.8)
            return {**outcome, "method": "include-ambiguous" if matches else "include-not-found"}
        if kind == "system_include":
            return {**outcome, "status": "external", "method": "system-include"}
        if kind in {"esm_import", "require", "dynamic_import"}:
            if specifier.startswith((".", "/")):
                joined = posixpath.normpath(posixpath.join(directory, specifier)) if not specifier.startswith("/") \
                    else specifier.lstrip("/")
                candidates = [joined, *(joined + extension for extension in _JS_EXTENSIONS),
                              *(posixpath.join(joined, "index" + extension) for extension in _JS_EXTENSIONS)]
                for candidate in candidates:
                    if candidate in self.inventory:
                        return found([candidate], "module-relative", 1.0)
                return {**outcome, "method": "relative-not-found"}
            if specifier.startswith(("@/", "~/", "#")):
                return {**outcome, "method": "path-alias-not-evaluated"}
            return {**outcome, "status": "external", "method": "package"}
        if kind == "go_import":
            module = self._go_module(path)
            if module is not None:
                root, name = module
                if specifier == name or specifier.startswith(name + "/"):
                    target_dir = posixpath.normpath(posixpath.join(root, specifier[len(name):].lstrip("/"))) \
                        if specifier != name else (root or ".")
                    target_dir = "" if target_dir == "." else target_dir
                    targets = [item for item in self.inventory if posixpath.dirname(item) == target_dir and
                               item.endswith(".go") and not item.endswith("_test.go")]
                    if targets:
                        return found(targets, "go-module-package", 1.0)
                    return {**outcome, "method": "go-module-package-not-found"}
            return {**outcome, "status": "external", "method": "go-external-module" if "." in specifier.split("/")[0]
                    else "go-standard-library"}
        if kind in {"java_import", "java_static_import"}:
            parts = specifier.split(".")
            if parts[-1] == "*":
                package = ".".join(parts[:-1])
                if package in self.java_packages:
                    return found(list(self.java_packages[package].values()), "java-package-wildcard", 1.0)
            candidates = [(".".join(parts[:-1]), parts[-1])]
            if kind == "java_static_import" and len(parts) > 2:
                candidates.append((".".join(parts[:-2]), parts[-2]))
            for package, name in candidates:
                target = self.java_packages.get(package, {}).get(name)
                if target is not None:
                    return found([target], "java-package-declaration", 1.0)
            if any(package.startswith(".".join(parts[:2])) for package in self.java_packages if len(parts) > 2):
                return {**outcome, "method": "java-local-package-type-not-found"}
            return {**outcome, "status": "external", "method": "java-external"}
        if kind == "csharp_using":
            if specifier in self.csharp_namespaces:
                return found(self.csharp_namespaces[specifier], "csharp-namespace-declaration", 0.9)
            return {**outcome, "status": "external", "method": "csharp-external-namespace"}
        if kind == "php_include":
            joined = posixpath.normpath(posixpath.join(directory, specifier.lstrip("/") if record.get("base") else specifier))
            if joined in self.inventory:
                return found([joined], "php-dir-relative" if record.get("base") else "php-include-relative-guess",
                             1.0 if record.get("base") else 0.8)
            return {**outcome, "method": "php-include-not-found"}
        if kind == "php_use":
            namespace, _, name = specifier.rpartition("\\")
            target = self.php_namespaces.get(namespace, {}).get(name)
            if target is not None:
                return found([target], "php-namespace-declaration", 1.0)
            root = specifier.split("\\", 1)[0]
            if any(item == root or item.startswith(root + "\\") for item in self.php_namespaces if item):
                return {**outcome, "method": "php-local-namespace-type-not-found"}
            return {**outcome, "status": "external", "method": "php-external"}
        if kind == "rust_mod":
            name = posixpath.basename(path)
            base = directory if name in {"lib.rs", "main.rs", "mod.rs"} else posixpath.join(directory, name[:-3])
            for candidate in (posixpath.join(base, specifier + ".rs"), posixpath.join(base, specifier, "mod.rs")):
                if candidate in self.inventory:
                    return found([candidate], "rust-module-file", 1.0)
            return {**outcome, "method": "rust-module-file-not-found"}
        if kind == "rust_use":
            segments = re.split(r"::", specifier.split("{", 1)[0].split(" as ", 1)[0])
            segments = [item for item in segments if item and item != "*"]
            src = self._crate_src(path)
            if not segments or segments[0] not in {"crate", "self", "super"} or src is None:
                return {**outcome, "status": "external", "method": "rust-external-crate"}
            current = _rust_module_path(path, src)
            if current is None:
                return {**outcome, "method": "rust-module-path-unknown"}
            if segments[0] == "crate":
                base, rest = [], segments[1:]
            else:
                base, rest = list(current), list(segments)
                while rest and rest[0] in {"self", "super"}:
                    if rest.pop(0) == "super":
                        if not base:
                            return {**outcome, "method": "rust-super-beyond-crate"}
                        base.pop()
            for length in range(len(rest), -1, -1):
                target = self._rust_file(src, base + rest[:length])
                if target is not None and target != path:
                    return found([target], "rust-module-path", 1.0)
            return {**outcome, "method": "rust-module-path-not-found"}
        if kind == "rust_extern_crate":
            return {**outcome, "status": "external", "method": "rust-extern-crate"}
        return {**outcome, "status": "unresolved", "method": f"unsupported-import-kind:{grammar}"}

    def build(self, components: Mapping[str, str | None]) -> dict[str, Any]:
        resolved_records: dict[str, list[dict[str, Any]]] = {}
        total = 0
        truncated = False
        for path in sorted(self.files):
            outcomes = []
            for record in self.files[path].get("imports", ()):
                if total >= self.max_records:
                    truncated = True
                    break
                total += 1
                outcomes.append(self.resolve_one(path, record))
            resolved_records[path] = outcomes
        efferent: dict[str, set[str]] = defaultdict(set)
        afferent: dict[str, set[str]] = defaultdict(set)
        external: dict[str, set[str]] = defaultdict(set)
        component_out: dict[str, set[str]] = defaultdict(set)
        component_in: dict[str, set[str]] = defaultdict(set)
        edges: list[dict[str, Any]] = []
        for path, outcomes in resolved_records.items():
            source_module = self.module_of(path)
            for outcome in outcomes:
                if outcome["status"] == "external":
                    external[source_module].add(str(outcome["specifier"]))
                if outcome["status"] != "resolved" or outcome["confidence"] < self.min_confidence:
                    continue
                for target in outcome["targets"]:
                    if target not in self.files:
                        continue
                    target_module = self.module_of(target)
                    if target_module == source_module:
                        continue
                    efferent[source_module].add(target_module)
                    afferent[target_module].add(source_module)
                    edges.append({"from": path, "to": target, "from_module": source_module, "to_module": target_module,
                                  "method": outcome["method"], "confidence": outcome["confidence"],
                                  "line": outcome["line"]})
                    left, right = components.get(path), components.get(target)
                    if left and right and left != right:
                        component_out[left].add(right)
                        component_in[right].add(left)
        modules = sorted({self.module_of(path) for path in self.files})

        def coupling(outgoing: set[str], incoming: set[str]) -> dict[str, Any]:
            ce, ca = len(outgoing), len(incoming)
            return {"afferent_coupling": ca, "efferent_coupling": ce,
                    "instability": round(ce / (ca + ce), 6) if ca + ce else None}

        module_metrics = {module: {**coupling(efferent[module], afferent[module]),
                                   "external_dependency_count": len(external[module])} for module in modules}
        files: dict[str, dict[str, Any]] = {}
        for path, outcomes in resolved_records.items():
            module = self.module_of(path)
            unresolved = [item for item in outcomes if item["status"] == "unresolved"]
            dynamic = [item for item in outcomes if item["status"] == "dynamic"]
            low = [item for item in outcomes if item["status"] == "resolved" and item["confidence"] < self.min_confidence]
            files[path] = {"module": module, **module_metrics[module], "import_count": len(outcomes),
                           "unresolved_import_count": len(unresolved), "dynamic_import_count": len(dynamic),
                           "below_confidence_count": len(low),
                           "coupling_lower_bound": bool(unresolved or dynamic or low), "imports": outcomes}
        component_ids = sorted({value for value in components.values() if value})
        return {"identity": GRAPH_IDENTITY, "min_edge_confidence": self.min_confidence,
                "files": files, "modules": module_metrics, "edges": sorted(edges, key=lambda item: (
                    item["from"], item["to"], item["line"] or 0)),
                "components": {component: coupling(component_out[component], component_in[component])
                               for component in component_ids},
                "record_count": total, "truncated": truncated}
