from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import sys

from .baseline import Finding, finding
from .config import Config


@dataclass(frozen=True)
class Import:
    target: str
    line: int
    relative: bool = False
    package_guard: bool = False


def module_name(path: str) -> str:
    value = path.removeprefix("src/").removesuffix(".py").replace("/", ".")
    return value.removesuffix(".__init__")


def owner(module: str) -> str:
    parts = module.split(".")
    return ".".join(parts[:3] if parts[:2] == ["appsec_review", "jobs"] else parts[:2])


class Imports(ast.NodeVisitor):
    def __init__(self, module: str, *, package: bool = False) -> None:
        self.package = module if package else module.rpartition(".")[0]
        self.guarded = False
        self.edges: list[Import] = []
        self.aliases: dict[str, str] = {}
        self.origins: dict[str, Import] = {}

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        previous = self.guarded
        self.guarded = previous or isinstance(node.test, ast.Name) and node.test.id == "__package__"
        for child in node.body:
            self.visit(child)
        self.guarded = previous
        for child in node.orelse:
            self.visit(child)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            edge = Import(alias.name, node.lineno)
            self.edges.append(edge)
            local = alias.asname or alias.name.split(".")[0]
            self.aliases[local] = alias.name if alias.asname else alias.name.split(".")[0]
            self.origins[local] = edge

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        target = node.module or ""
        if node.level:
            parents = self.package.split(".")
            prefix = ".".join(parents[:len(parents) - node.level + 1])
            target = ".".join(part for part in (prefix, target) if part)
        for alias in node.names:
            qualified = f"{target}.{alias.name}"
            edge = Import(qualified, node.lineno, bool(node.level), self.guarded)
            self.edges.append(edge)
            self.aliases[alias.asname or alias.name] = qualified
            self.origins[alias.asname or alias.name] = edge

    def qualified(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{self.qualified(node.value)}.{node.attr}"
        return ""

    def visit_Attribute(self, node: ast.Attribute) -> None:
        target = self.qualified(node)
        if (node.attr.startswith("_") and not (node.attr.startswith("__") and node.attr.endswith("__"))
                and target.startswith("appsec_review.")):
            base: ast.expr = node
            while isinstance(base, ast.Attribute):
                base = base.value
            origin = self.origins.get(base.id) if isinstance(base, ast.Name) else None
            self.edges.append(Import(target, node.lineno, bool(origin and origin.relative),
                                     bool(origin and origin.package_guard)))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self.qualified(node.func) in {"importlib.import_module", "__import__"}:
            name = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "name"), None)
            if isinstance(name, ast.Constant) and isinstance(name.value, str):
                self.edges.append(Import(name.value, node.lineno))
            else:
                self.edges.append(Import("<dynamic-import>", node.lineno))
        self.generic_visit(node)


def scan_boundaries(root: Path, paths: tuple[str, ...], config: Config) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    stdlib = sys.stdlib_module_names | {"__future__"}
    for path in paths:
        module = module_name(path)
        try:
            tree = ast.parse((root / path).read_text(encoding="utf-8"), filename=path)
        except SyntaxError as error:
            findings.append(finding(root, path, "ARCH:syntax", str(error.msg), error.lineno or 1))
            continue
        imports = Imports(module, package=path.endswith("/__init__.py"))
        imports.visit(tree)
        seen: set[tuple[int, str, str]] = set()
        for edge in imports.edges:
            target = edge.target
            rule = ""
            if module in config.bootstrap_modules:
                allowed_sibling = (
                    edge.relative and edge.package_guard
                    and module not in {"appsec_review.signing.bootstrap", "appsec_review.signing.core",
                                       "appsec_review.signing.sitecustomize_shim"}
                    and any(target == sibling or target.startswith(sibling + ".")
                            for sibling in config.bootstrap_modules)
                )
                if not allowed_sibling and target.split(".")[0] not in stdlib:
                    rule = "ARCH:bootstrap-isolation"
            if module.startswith("appsec_review.") and target.startswith("tools."):
                rule = rule or "ARCH:runtime-development"
            if module in config.public_contracts and (
                target.startswith(("appsec_review.jobs.", "appsec_review.orchestration."))
            ):
                rule = rule or "ARCH:contract-direction"
            if (module.startswith("appsec_review.") and owner(module) != "appsec_review.inference"
                    and any(target == provider or target.startswith(provider + ".") for provider in (
                        "appsec_review.inference.anthropic_api", "appsec_review.inference.openai_api",
                        "appsec_review.inference.claude_cli", "appsec_review.inference.copilot_sdk",
                    ))):
                rule = rule or "ARCH:inference-api"
            if (target.startswith("appsec_review.") and owner(module) != owner(target)
                    and any(part.startswith("_") or part == "*" for part in target.split(".")[2:])):
                rule = rule or "ARCH:private-import"
            key = (edge.line, rule, target)
            if rule and key not in seen:
                seen.add(key)
                findings.append(finding(root, path, rule, f"{module} imports {target}", edge.line))
    return tuple(findings)
