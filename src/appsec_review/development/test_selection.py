"""Plan explicit pytest selections without importing tests or executing pytest."""

from __future__ import annotations

import argparse
import ast
from collections.abc import Iterable
import json
from pathlib import Path, PurePosixPath
import re
import sys
from uuid import uuid4


KINDS = ("unit", "integration", "acceptance", "live")
MAP_SCHEMA = "appsec-review/job-test-map/2"
SELECTION_SCHEMA = "appsec-review/job-test-selection/2"
_JOB_ID = re.compile(r"job_[a-z][a-z0-9_]*\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_REGISTRY = "src/appsec_review/runtime/registry.py"
_MAP = "tests/job-test-map.json"


class TestSelectionError(ValueError):
    """The requested selection or its checkout metadata is not safe to use."""

    __test__ = False


def _source_path(root: Path, relative: str) -> Path:
    path = root / relative
    if any(part.is_symlink() for part in (path, *path.parents) if part != root and root in part.parents):
        raise TestSelectionError(f"symlinked source path: {relative}")
    try:
        path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError, RuntimeError) as error:
        raise TestSelectionError(f"missing or escaping source path: {relative}") from error
    if not path.is_file():
        raise TestSelectionError(f"source is not a file: {relative}")
    return path


def _python_tree(root: Path, relative: str) -> ast.Module:
    try:
        return ast.parse(_source_path(root, relative).read_text(encoding="utf-8"), filename=relative)
    except (OSError, UnicodeError, SyntaxError) as error:
        raise TestSelectionError(f"cannot parse Python source: {relative}") from error


def _registered_jobs(root: Path) -> set[str]:
    tree = _python_tree(root, _REGISTRY)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name == "builtin_registry"]
    if len(functions) != 1:
        raise TestSelectionError("expected one explicit builtin_registry definition")
    jobs: set[str] = set()
    for node in ast.walk(functions[0]):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "registry"
                and node.func.attr == "register"):
            continue
        if not (node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str) and _JOB_ID.fullmatch(node.args[0].value)):
            raise TestSelectionError("job registrations must use literal job IDs")
        job_id = node.args[0].value
        if job_id in jobs:
            raise TestSelectionError(f"duplicate job registration: {job_id}")
        jobs.add(job_id)
    if not jobs:
        raise TestSelectionError("no explicit builtin job registrations found")
    return jobs


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TestSelectionError(f"duplicate metadata key: {key}")
        result[key] = value
    return result


def _markers(nodes: Iterable[ast.AST]) -> set[str]:
    return {
        node.attr
        for expression in nodes
        for node in ast.walk(expression)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name) and node.value.value.id == "pytest"
        and node.value.attr == "mark"
    }


def _scope_markers(node: ast.Module | ast.ClassDef) -> set[str]:
    expressions: list[ast.AST] = list(getattr(node, "decorator_list", []))
    for statement in node.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "pytestmark" for target in statement.targets
        ):
            expressions.append(statement.value)
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            if statement.target.id == "pytestmark" and statement.value is not None:
                expressions.append(statement.value)
    return _markers(expressions)


def _test_nodes(tree: ast.Module, relative: str) -> dict[tuple[str, ...], set[str]]:
    tests: dict[tuple[str, ...], set[str]] = {}
    module_markers = _scope_markers(tree)

    def add(body: list[ast.stmt], prefix: tuple[str, ...], inherited: set[str]) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                key = (*prefix, node.name)
                if key in tests:
                    raise TestSelectionError(f"duplicate test definition: {relative}::{'::'.join(key)}")
                tests[key] = inherited | _markers(node.decorator_list)
            elif isinstance(node, ast.ClassDef) and node.name.startswith("Test") and not prefix:
                add(node.body, (node.name,), inherited | _scope_markers(node))

    add(tree.body, (), module_markers)
    return tests


def _validate_selector(root: Path, selector: object, kind: str,
                       sources: dict[str, dict[tuple[str, ...], set[str]]]) -> str:
    if not isinstance(selector, str) or not selector or any(char.isspace() for char in selector):
        raise TestSelectionError(f"malformed selector: {selector!r}")
    parts = selector.split("::")
    relative, names = parts[0], tuple(parts[1:])
    path = PurePosixPath(relative)
    if (path.is_absolute() or len(path.parts) < 2 or path.parts[0] != "tests"
            or path.as_posix() != relative or any(part in {".", ".."} for part in path.parts)
            or not re.fullmatch(r"tests/[A-Za-z0-9_./-]+", relative)
            or not path.name.startswith("test_") or path.suffix != ".py"
            or len(names) > 2 or any(not _IDENTIFIER.fullmatch(name) for name in names)
            or names and not names[-1].startswith("test_")
            or len(names) == 2 and not names[0].startswith("Test")):
        raise TestSelectionError(f"malformed selector: {selector!r}")
    if relative not in sources:
        sources[relative] = _test_nodes(_python_tree(root, relative), relative)
    tests = sources[relative]
    if not tests or names and names not in tests:
        raise TestSelectionError(f"unknown test selector: {selector}")

    markers = tests[names] if names else set().union(*tests.values())
    required = markers.intersection(KINDS)
    if "requires_target" in markers:
        required.add("live")
    if path.parts[1] == "live" or path.stem.startswith("test_live_") or "_live" in path.stem:
        required.add("live")
    elif path.parts[1] in {"integration", "acceptance"}:
        required.add(path.parts[1])
    # Root files can mix unit and manual cases. Dedicated directories and explicit
    # markers cannot be silently downgraded by metadata.
    if "live" in required:
        required = {"live"}
    if required and required != {kind}:
        raise TestSelectionError(
            f"selector category mismatch: {selector} is {', '.join(sorted(required))}, not {kind}")
    return selector


def _load_map(root: Path, registered: set[str]) -> tuple[
    dict[str, dict[str, list[str]]], dict[str, dict[str, list[str]]],
]:
    try:
        document = json.loads(_source_path(root, _MAP).read_text(encoding="utf-8"),
                              object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TestSelectionError(f"cannot read {_MAP}") from error
    if (not isinstance(document, dict) or set(document) != {"schema", "jobs", "common_contracts"}
            or document["schema"] != MAP_SCHEMA or not isinstance(document["jobs"], dict)
            or not isinstance(document["common_contracts"], dict)):
        raise TestSelectionError(f"expected closed {MAP_SCHEMA} metadata")
    jobs = document["jobs"]
    unknown = sorted(set(jobs) - registered)
    if unknown:
        raise TestSelectionError(f"metadata names unregistered jobs: {', '.join(unknown)}")
    sources: dict[str, dict[tuple[str, ...], set[str]]] = {}
    categories: dict[str, tuple[str, str]] = {}

    def validate(label: str, mapping: object, *, scope: str) -> None:
        keys = set(KINDS) | ({"jobs"} if scope == "common" else set())
        if not isinstance(mapping, dict) or set(mapping) != keys:
            raise TestSelectionError(f"{label} must declare exactly {', '.join(sorted(keys))}")
        for kind in KINDS:
            selectors = mapping[kind]
            if not isinstance(selectors, list):
                raise TestSelectionError(f"{label}.{kind} must be a selector list")
            seen: set[str] = set()
            for value in selectors:
                selector = _validate_selector(root, value, kind, sources)
                if selector in seen:
                    raise TestSelectionError(f"duplicate selector in {label}.{kind}: {selector}")
                seen.add(selector)
                for other, (other_kind, other_scope) in categories.items():
                    overlaps = (
                        selector == other or selector.startswith(other + "::") or other.startswith(selector + "::")
                    )
                    if overlaps and kind != other_kind:
                        raise TestSelectionError(f"overlapping selector categories: {selector}, {other}")
                    if overlaps and scope != other_scope:
                        raise TestSelectionError(f"common/handler selector overlap: {selector}, {other}")
                categories[selector] = kind, scope

    for job_id, mapping in jobs.items():
        validate(job_id, mapping, scope="handler")
    contracts = document["common_contracts"]
    for contract_id, mapping in contracts.items():
        if not re.fullmatch(r"[a-z][a-z0-9-]*", contract_id):
            raise TestSelectionError(f"malformed common contract ID: {contract_id!r}")
        validate(contract_id, mapping, scope="common")
        applicable = mapping["jobs"]
        if (not isinstance(applicable, list) or not applicable
                or any(not isinstance(job, str) or job not in registered for job in applicable)):
            raise TestSelectionError(f"{contract_id}.jobs must list registered job IDs")
        if len(applicable) != len(set(applicable)):
            raise TestSelectionError(f"duplicate job ID in common contract: {contract_id}")
    return jobs, contracts


def _pytest_argv(root: Path, selectors: list[str]) -> list[str] | None:
    if not selectors:
        return None
    relative = f"test/tmp/job-selection-{uuid4().hex}"
    for parent in (root / "test", root / "test/tmp"):
        if parent.is_symlink() or parent.exists() and not parent.is_dir():
            raise TestSelectionError("pytest scratch parents must be real directories under test/tmp")
    if (root / relative).exists() or (root / relative).is_symlink():
        raise TestSelectionError("proposed pytest scratch directory already exists")
    return [sys.executable, "-m", "pytest", f"--basetemp={relative}", *selectors]


def select_tests(repository_root: str | Path, job_ids: Iterable[str], *,
                 kind: str = "unit") -> dict[str, object]:
    """Return a JSON-compatible plan; never import tests, collect pytest, or run commands."""
    if kind not in KINDS:
        raise TestSelectionError(f"unknown test kind: {kind!r}")
    if isinstance(job_ids, (str, bytes)):
        raise TestSelectionError("job_ids must be an iterable of job IDs, not a string")
    requested = list(job_ids)
    if not requested or any(not isinstance(job, str) or not _JOB_ID.fullmatch(job) for job in requested):
        raise TestSelectionError("at least one well-formed job ID is required")
    requested = sorted(set(requested))
    root = Path(repository_root).resolve()
    registered = _registered_jobs(root)
    unknown = sorted(set(requested) - registered)
    if unknown:
        raise TestSelectionError(f"unknown job IDs: {', '.join(unknown)}")
    mapping, contracts = _load_map(root, registered)
    selectors: set[str] = set()
    gaps: list[dict[str, str]] = []
    for job_id in requested:
        selected = mapping.get(job_id, {}).get(kind, [])
        selectors.update(selected)
        if not selected:
            gaps.append({
                "job_id": job_id, "kind": kind, "scope": "handler",
                "reason": (f"No explicit handler-specific {kind} selectors mapped for this registered job."
                           if job_id in mapping else "Registered job has no handler-specific test metadata."),
            })
    handler_selectors = sorted(selectors)
    common_contracts: list[dict[str, object]] = []
    for contract_id, contract in sorted(contracts.items()):
        applicable = sorted(set(requested).intersection(contract["jobs"]))
        selected = sorted(contract[kind])
        if applicable and selected:
            common_contracts.append({"contract_id": contract_id, "jobs": applicable, "selectors": selected})
            selectors.update(selected)
    ordered = sorted(selectors)
    return {
        "schema": SELECTION_SCHEMA,
        "repository_root": str(root),
        "jobs": requested,
        "kind": kind,
        "selectors": ordered,
        "handler_selectors": handler_selectors,
        "common_contracts": common_contracts,
        "gaps": gaps,
        "pytest_argv": _pytest_argv(root, ordered),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", action="append", required=True, help="registered job ID; repeatable")
    parser.add_argument("--kind", choices=KINDS, default="unit")
    parser.add_argument("--repository-root", type=Path, default=Path.cwd(),
                        help="source checkout root (default: current directory)")
    arguments = parser.parse_args(argv)
    try:
        result = select_tests(arguments.repository_root, arguments.job, kind=arguments.kind)
    except (TestSelectionError, OSError, RuntimeError) as error:
        print(json.dumps({"schema": SELECTION_SCHEMA, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
