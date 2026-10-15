"""Resolve and classify the package-script graph a Node build recipe will run.

A recipe command such as ``npm run build`` runs the named script with its ``pre``/``post`` hooks, and
those scripts may run further package scripts in the same package, another directory
(``--prefix``/``--dir``/``-C``/``--cwd``), or workspace members (npm ``-w``/``--workspaces``,
``pnpm -r``/``--filter``, ``yarn workspace``/``yarn workspaces foreach``, ``run-s``/``run-p``/
``npm-run-all``). Every script body reached is classified by the same rules at every depth, with
one depth bound, one visit bound, and cycle detection. Anything that cannot be resolved is a named
gap, never a pass.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from fnmatch import fnmatchcase
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
from typing import Any


MAX_SCRIPT_DEPTH = 8
MAX_SCRIPT_VISITS = 256
MAX_WORKSPACE_MEMBERS = 512
_MAX_GLOB_CANDIDATES = 4096
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024

MANAGERS = {"npm", "pnpm", "yarn"}
_SCRIPT_GROUP_RUNNERS = {"run-s", "run-p", "npm-run-all"}
_APPLICATION_RUNTIMES = {"node", "tsx", "ts-node"}
TEST_TOOLS = {"jest", "mocha", "vitest", "ava", "tap", "cypress", "playwright", "karma"}
_SEPARATORS = {"&&", "||", ";", "|", "&", "|&", ";;", "(", ")"}
_ENV_PREFIXES = {"env", "cross-env", "cross-env-shell"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_DIRECTORY_OPTIONS = {"--prefix", "--dir", "-C", "--cwd"}
_LIFECYCLE_ALIASES = {"test": "test", "t": "test", "tst": "test", "start": "start",
                      "stop": "stop", "restart": "restart"}
_NPM_RUN = {"run", "run-script", "rum", "urn"}
_NPM_VALUE_OPTIONS = {*_DIRECTORY_OPTIONS, "-w", "--workspace", "--userconfig", "--cache",
                      "--loglevel", "--script-shell"}
_PNPM_BUILTINS = {
    "install", "i", "add", "remove", "rm", "uninstall", "un", "update", "up", "upgrade", "exec",
    "dlx", "create", "init", "link", "ln", "unlink", "import", "rebuild", "rb", "prune", "fetch",
    "patch", "patch-commit", "publish", "pack", "list", "ls", "ll", "why", "outdated", "audit",
    "store", "root", "bin", "setup", "env", "config", "c", "deploy", "licenses", "server",
    "doctor", "install-test", "it", "dedupe", "approve-builds", "self-update", "help", "node",
}
_PNPM_VALUE_OPTIONS = {*_DIRECTORY_OPTIONS, "--filter", "-F", "--filter-prod",
                       "--workspace-concurrency", "--reporter", "--loglevel", "--test-pattern",
                       "--changed-files-ignore-pattern"}
_YARN_BUILTINS = {
    "install", "add", "remove", "up", "upgrade", "upgrade-interactive", "dlx", "exec", "node",
    "bin", "cache", "config", "constraints", "info", "init", "link", "unlink", "npm", "pack",
    "patch", "patch-commit", "plugin", "rebuild", "set", "unplug", "version", "why", "explain",
    "import", "global", "generate-lock-entry", "licenses", "list", "outdated", "owner", "publish",
    "tag", "team", "login", "logout", "check", "autoclean", "audit", "create", "policies", "dedupe",
    "help", "search", "stage", "sdks",
}
_YARN_VALUE_OPTIONS = {*_DIRECTORY_OPTIONS}
_FOREACH_VALUE_OPTIONS = {"--include", "--exclude", "--from", "-j", "--jobs"}
_NPM_RUN_ALL_VALUE_OPTIONS = {"--max-parallel", "--npm-path"}


class GraphError(Exception):
    """A script invocation that cannot be resolved to bounded package scripts."""


def _join(base: str, value: str) -> str:
    logical = PurePosixPath(value.replace("\\", "/"))
    if logical.is_absolute():
        raise GraphError(f"directory {value!r} is absolute")
    joined = posixpath.normpath(posixpath.join(base, logical.as_posix()))
    if joined == ".." or joined.startswith("../"):
        raise GraphError(f"directory {value!r} escapes the build workspace")
    return joined


def _label(directory: str, name: str) -> str:
    prefix = "" if directory == "." else directory + "/"
    return f"{prefix}package.json#scripts.{name}"


def split_segments(script: str) -> list[list[str]]:
    """Split a script into simple commands at shell control operators."""
    lexer = shlex.shlex(script, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    segments: list[list[str]] = [[]]
    for token in lexer:
        if token in _SEPARATORS:
            segments.append([])
        else:
            segments[-1].append(token)
    return [segment for segment in segments if segment]


def _command(segment: Sequence[str]) -> list[str]:
    """Drop leading environment assignments and environment-setting wrappers."""
    values = list(segment)
    while values and (_ASSIGNMENT.match(values[0]) or Path(values[0]).name in _ENV_PREFIXES):
        values.pop(0)
    return values


def _value(values: Sequence[str], index: int, name: str, inline: str | None) -> tuple[str, int]:
    if inline is not None:
        return inline, index
    if index + 1 >= len(values):
        raise GraphError(f"option {name} has no value")
    return values[index + 1], index + 1


def _scan(values: Sequence[str], value_options: set[str],
          stop_at_positional: bool = False) -> tuple[list[tuple[str, str | None]], list[str], int]:
    """Return (options, positionals, end index) for package-manager argv after the executable."""
    options: list[tuple[str, str | None]] = []
    positionals: list[str] = []
    index = 0
    while index < len(values):
        token = values[index]
        if token == "--":
            break
        if token.startswith("-") and token != "-":
            name, equals, inline = token.partition("=")
            if not token.startswith("--"):
                name, inline = token, None
            elif not equals:
                inline = None
            if name in value_options:
                value, index = _value(values, index, name, inline)
                options.append((name, value))
            else:
                options.append((name, inline))
        else:
            positionals.append(token)
            if stop_at_positional:
                return options, positionals, index
        index += 1
    return options, positionals, index


class ScriptGraph:
    """Bounded walk of the package scripts reachable from accepted recipe commands."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.gaps: list[str] = []
        self.visits = 0
        self._documents: dict[str, Mapping[str, Any] | None] = {}
        self._exhausted = False

    # -- package documents and workspace members ------------------------------------------

    def _path(self, directory: str) -> Path:
        return self.workspace / Path(*PurePosixPath(directory).parts) if directory != "." else self.workspace

    def document(self, directory: str) -> Mapping[str, Any] | None:
        if directory not in self._documents:
            path = self._path(directory) / "package.json"
            value: Mapping[str, Any] | None = None
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= _MAX_MANIFEST_BYTES:
                try:
                    loaded = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                    raise GraphError(f"{directory}/package.json is not readable JSON: "
                                     f"{type(exc).__name__}") from exc
                value = loaded if isinstance(loaded, Mapping) else None
            self._documents[directory] = value
        return self._documents[directory]

    def _require(self, directory: str) -> Mapping[str, Any]:
        document = self.document(directory)
        if document is None:
            raise GraphError(f"package directory {directory!r} has no bounded package.json")
        return document

    def scripts(self, directory: str) -> Mapping[str, Any]:
        scripts = self._require(directory).get("scripts", {})
        if not isinstance(scripts, Mapping):
            raise GraphError(f"{_label(directory, '')[:-1]} must be an object")
        return scripts

    def _ancestors(self, directory: str) -> list[str]:
        values = [directory]
        while directory != ".":
            directory = posixpath.dirname(directory) or "."
            values.append(directory)
        return values

    def _package_workspaces(self, directory: str) -> list[Any] | None:
        document = self.document(directory)
        if document is None or "workspaces" not in document:
            return None
        declared = document["workspaces"]
        if isinstance(declared, Mapping):
            declared = declared.get("packages")
        if not isinstance(declared, list):
            raise GraphError(f"{directory}/package.json workspaces is not a list of patterns")
        return declared

    def _pnpm_workspaces(self, directory: str) -> list[Any] | None:
        path = self._path(directory) / "pnpm-workspace.yaml"
        if not path.is_file() or path.is_symlink():
            return None
        if path.stat().st_size > _MAX_MANIFEST_BYTES:
            raise GraphError(f"{directory}/pnpm-workspace.yaml exceeds its size bound")
        return _pnpm_packages(path.read_text(encoding="utf-8", errors="replace"))

    def workspace_root(self, directory: str, manager: str) -> tuple[str, list[str]]:
        for candidate in self._ancestors(directory):
            patterns = (self._pnpm_workspaces(candidate) if manager == "pnpm"
                        else self._package_workspaces(candidate))
            if patterns is not None:
                return candidate, self._members(candidate, patterns)
        raise GraphError(f"no {manager} workspace declaration encloses {directory!r}")

    def _members(self, root: str, patterns: Sequence[Any]) -> list[str]:
        include: list[str] = []
        exclude: list[str] = []
        for pattern in patterns:
            if not isinstance(pattern, str) or not pattern.strip():
                raise GraphError(f"{root} declares a non-string workspace pattern")
            negated = pattern.startswith("!")
            text = pattern[1:] if negated else pattern
            text = text.strip().removeprefix("./").rstrip("/") or "."
            if PurePosixPath(text).is_absolute() or ".." in PurePosixPath(text).parts:
                raise GraphError(f"workspace pattern {pattern!r} escapes the build workspace")
            (exclude if negated else include).append(text)
        base = self._path(root)
        members: set[str] = set()
        candidates = 0
        for pattern in include:
            for path in base.glob(pattern):
                candidates += 1
                if candidates > _MAX_GLOB_CANDIDATES:
                    raise GraphError(f"workspace patterns under {root!r} exceed the "
                                     f"{_MAX_GLOB_CANDIDATES} candidate bound")
                if (path.is_symlink() or not path.is_dir() or "node_modules" in path.parts
                        or not (path / "package.json").is_file()):
                    continue
                relative = path.relative_to(base).as_posix()
                if any(fnmatchcase(relative, item) for item in exclude):
                    continue
                members.add(_join(root, relative))
        members.discard(root)
        if len(members) > MAX_WORKSPACE_MEMBERS:
            raise GraphError(f"workspace {root!r} exceeds the {MAX_WORKSPACE_MEMBERS} member bound")
        return sorted(members)

    def name(self, directory: str) -> str | None:
        document = self.document(directory)
        value = document.get("name") if document is not None else None
        return value if isinstance(value, str) else None

    # -- package-manager invocations --------------------------------------------------------

    def resolve(self, argv: Sequence[str], cwd: str, *, calling: tuple[str, str] | None = None
                ) -> list[tuple[str, str]] | None:
        """Return the (directory, script) runs an invocation requests, or None for a non-run."""
        tool = Path(str(argv[0])).name
        values = [str(value) for value in argv[1:]]
        if tool == "npm":
            return self._npm(values, cwd)
        if tool == "pnpm":
            return self._pnpm(values, cwd)
        if tool == "yarn":
            return self._yarn(values, cwd, calling)
        if tool in _SCRIPT_GROUP_RUNNERS:
            return self._run_all(values, cwd)
        return None

    def _npm(self, values: list[str], cwd: str) -> list[tuple[str, str]] | None:
        options, positionals, _ = _scan(values, _NPM_VALUE_OPTIONS)
        selectors: list[str] = []
        every = include_root = False
        for name, value in options:
            if name in _DIRECTORY_OPTIONS:
                cwd = _join(cwd, str(value))
            elif name in {"-w", "--workspace"}:
                selectors.append(str(value))
            elif name in {"-ws", "--workspaces"}:
                every = value not in {"false", "0"}
            elif name == "--include-workspace-root":
                include_root = value not in {"false", "0"}
        script = _lifecycle_script(positionals, _NPM_RUN)
        if script is None:
            return None
        directories = [cwd]
        if selectors or every:
            root, members = self.workspace_root(cwd, "npm")
            directories = members if every else []
            for selector in selectors:
                matched = [member for member in members
                           if self.name(member) == selector or _under(member, _join(cwd, selector))]
                if not matched:
                    raise GraphError(f"npm workspace {selector!r} matches no member of {root!r}")
                directories.extend(matched)
            if include_root:
                directories.insert(0, root)
        return [(directory, script) for directory in dict.fromkeys(directories)]

    def _pnpm(self, values: list[str], cwd: str) -> list[tuple[str, str]] | None:
        options, positionals, _ = _scan(values, _PNPM_VALUE_OPTIONS)
        selectors: list[str] = []
        recursive = include_root = workspace_root = False
        for name, value in options:
            if name in _DIRECTORY_OPTIONS:
                cwd = _join(cwd, str(value))
            elif name in {"--filter", "-F", "--filter-prod"}:
                selectors.append(str(value))
            elif name in {"-r", "--recursive"}:
                recursive = True
            elif name == "--include-workspace-root":
                include_root = True
            elif name in {"-w", "--workspace-root"}:
                workspace_root = True
        script = _lifecycle_script(positionals, {"run", "run-script"})
        if script is None and positionals and positionals[0] not in {"run", "run-script"} \
                and positionals[0] not in _PNPM_BUILTINS:
            script = positionals[0]
        if script is None:
            return None
        if workspace_root:
            cwd, _ = self.workspace_root(cwd, "pnpm")
        if not (recursive or selectors):
            return [(cwd, script)]
        root, members = self.workspace_root(cwd, "pnpm")
        directories = self._pnpm_filter(root, members, cwd, selectors) if selectors else list(members)
        if include_root:
            directories.insert(0, root)
        return [(directory, script) for directory in dict.fromkeys(directories)]

    def _pnpm_filter(self, root: str, members: list[str], cwd: str,
                     selectors: list[str]) -> list[str]:
        candidates = [root, *members]
        selected: list[str] = []
        for raw in selectors:
            selector = raw
            if selector.startswith("!") or "[" in selector:
                raise GraphError(f"pnpm filter {raw!r} is not a supported bounded selector")
            dependents = selector.startswith("...")
            selector = selector[3:] if dependents else selector
            dependencies = selector.endswith("...")
            selector = selector[:-3] if dependencies else selector
            exclude_seed = (dependents and selector.startswith("^")) or (
                dependencies and selector.endswith("^"))
            selector = selector.strip("^")
            if selector.startswith("{") and selector.endswith("}"):
                path_selector: str | None = selector[1:-1]
            elif selector.startswith(".") or selector.startswith("/"):
                path_selector = selector
            elif "{" in selector:
                raise GraphError(f"pnpm filter {raw!r} is not a supported bounded selector")
            else:
                path_selector = None
            if path_selector is not None:
                pattern = _join(cwd, path_selector)
                seeds = [item for item in candidates
                         if _under(item, pattern) or fnmatchcase(item, pattern)]
            else:
                seeds = [item for item in members
                         if (name := self.name(item)) is not None and fnmatchcase(name, selector)]
            if not seeds:
                raise GraphError(f"pnpm filter {raw!r} matches no member of {root!r}")
            chosen = set() if exclude_seed else set(seeds)
            if dependencies:
                chosen |= self._closure(seeds, members, forward=True)
            if dependents:
                chosen |= self._closure(seeds, members, forward=False)
            selected.extend(item for item in candidates if item in chosen)
        return list(dict.fromkeys(selected))

    def _closure(self, seeds: list[str], members: list[str], *, forward: bool) -> set[str]:
        by_name = {name: member for member in members if (name := self.name(member))}
        edges: dict[str, set[str]] = {member: set() for member in members}
        for member in members:
            document = self.document(member) or {}
            for field in ("dependencies", "devDependencies", "optionalDependencies",
                          "peerDependencies"):
                declared = document.get(field)
                for name in declared if isinstance(declared, Mapping) else ():
                    if name in by_name:
                        if forward:
                            edges[member].add(by_name[name])
                        else:
                            edges[by_name[name]].add(member)
        found: set[str] = set()
        pending = [edge for seed in seeds for edge in edges.get(seed, ())]
        while pending:
            item = pending.pop()
            if item not in found:
                found.add(item)
                pending.extend(edges.get(item, ()))
        return found

    def _yarn(self, values: list[str], cwd: str,
              calling: tuple[str, str] | None) -> list[tuple[str, str]] | None:
        options, positionals, index = _scan(values, _YARN_VALUE_OPTIONS, stop_at_positional=True)
        for name, value in options:
            if name in _DIRECTORY_OPTIONS:
                cwd = _join(cwd, str(value))
        if not positionals:
            return None
        command, rest = positionals[0], values[index + 1:]
        if command == "workspace":
            if not rest:
                raise GraphError("yarn workspace names no workspace")
            root, members = self.workspace_root(cwd, "yarn")
            matched = [member for member in members if self.name(member) == rest[0]]
            if not matched:
                raise GraphError(f"yarn workspace {rest[0]!r} matches no member of {root!r}")
            return self._yarn(rest[1:], matched[0], calling)
        if command == "workspaces":
            if not rest or rest[0] not in {"foreach", "run"}:
                return None
            root, members = self.workspace_root(cwd, "yarn")
            if rest[0] == "run":
                script = rest[1] if len(rest) > 1 else None
                return [(member, script) for member in members] if script else None
            return self._yarn_foreach(rest[1:], root, members, calling)
        if command == "run":
            script = next((value for value in rest if not value.startswith("-")), None)
            return [(cwd, script)] if script else None
        if command in _YARN_BUILTINS:
            return None
        return [(cwd, command)]

    def _yarn_foreach(self, values: list[str], root: str, members: list[str],
                      calling: tuple[str, str] | None) -> list[tuple[str, str]] | None:
        options, positionals, index = _scan(values, _FOREACH_VALUE_OPTIONS, stop_at_positional=True)
        directories = list(members)
        includes = [str(value) for name, value in options if name in {"--include", "--from"}]
        excludes = [str(value) for name, value in options if name == "--exclude"]
        if any(name in {"-A", "--all"} for name, _ in options):
            directories.insert(0, root)
        if not positionals:
            return None

        def matches(directory: str, pattern: str) -> bool:
            name = self.name(directory) or ""
            return fnmatchcase(name, pattern) or fnmatchcase(directory, pattern)

        if includes:
            directories = [item for item in directories if any(matches(item, p) for p in includes)]
        directories = [item for item in directories if not any(matches(item, p) for p in excludes)]
        runs: list[tuple[str, str]] = []
        for directory in directories:
            resolved = self._yarn(values[index:], directory, calling)
            if resolved is None:
                return None
            runs.extend(resolved)
        # Yarn skips the workspace whose own script started the same foreach run.
        return [run for run in runs if run != calling]

    def _run_all(self, values: list[str], cwd: str) -> list[tuple[str, str]]:
        _, positionals, _ = _scan(values, _NPM_RUN_ALL_VALUE_OPTIONS)
        scripts = self.scripts(cwd)
        runs: list[tuple[str, str]] = []
        for pattern in positionals:
            name = pattern.split(" ", 1)[0]
            expression = re.compile("^" + ".*".join(
                "[^:]*".join(re.escape(part) for part in piece.split("*"))
                for piece in name.split("**")) + "$")
            runs.extend((cwd, script) for script in scripts if expression.match(str(script)))
        return runs

    # -- graph walk ------------------------------------------------------------------------

    def walk_command(self, argv: Sequence[str], cwd: str) -> None:
        try:
            runs = self.resolve(argv, cwd)
        except GraphError as exc:
            self.gaps.append(f"package lifecycle command could not be resolved: {exc}")
            return
        for directory, script in runs or ():
            self._request(directory, script, [], set(), None)

    def _request(self, directory: str, script: str, chain: list[str],
                 active: set[tuple[str, str]], top: str | None) -> None:
        try:
            scripts = self.scripts(directory)
        except GraphError as exc:
            self._gap(top or script, "could not be resolved", [*chain, str(exc)])
            return
        for name in (f"pre{script}", script, f"post{script}"):
            body = scripts.get(name)
            if isinstance(body, str):
                self._visit(directory, name, body, chain, active, top or name)

    def _gap(self, top: str, problem: str, chain: Sequence[str]) -> None:
        self.gaps.append(f"package lifecycle script {top} {problem}: {' → '.join(chain)}")

    def _visit(self, directory: str, name: str, body: str, chain: list[str],
               active: set[tuple[str, str]], top: str) -> None:
        label = _label(directory, name)
        here = [*chain, label]
        if (directory, name) in active:
            self._gap(top, "forms a package-script cycle", here)
            return
        if len(here) > MAX_SCRIPT_DEPTH:
            self._gap(top, f"exceeds the package-script depth bound of {MAX_SCRIPT_DEPTH}", here)
            return
        self.visits += 1
        if self.visits > MAX_SCRIPT_VISITS:
            if not self._exhausted:
                self._exhausted = True
                self._gap(top, f"exceeds the package-script visit bound of {MAX_SCRIPT_VISITS}", here)
            return
        try:
            segments = split_segments(body)
        except ValueError:
            self._gap(top, "is not safely parseable", here)
            return
        active = {*active, (directory, name)}
        for segment in segments:
            command = _command(segment)
            if not command:
                continue
            try:
                runs = self.resolve(command, directory, calling=(directory, name))
            except GraphError as exc:
                self._gap(top, "could not be resolved", [*here, " ".join(command), str(exc)])
                continue
            if runs is not None:
                for target, script in runs:
                    self._request(target, script, here, active, top)
                continue
            leaf = [*here, " ".join(command)]
            basenames = [Path(value).name for value in command]
            if {value.lower() for value in basenames} & TEST_TOOLS:
                self._gap(top, "requests a test runner", leaf)
            for index, value in enumerate(basenames):
                if value in _APPLICATION_RUNTIMES and "--check" not in command[index + 1:]:
                    self._gap(top, "may execute a target application", leaf)
                    break


def _lifecycle_script(positionals: Sequence[str], run_commands: set[str]) -> str | None:
    if not positionals:
        return None
    if positionals[0] in run_commands:
        return positionals[1] if len(positionals) > 1 else None
    return _LIFECYCLE_ALIASES.get(positionals[0])


def _under(directory: str, base: str) -> bool:
    return base == "." or directory == base or directory.startswith(base + "/")


def _pnpm_packages(text: str) -> list[str]:
    """Read the ``packages`` list of a pnpm-workspace.yaml without a YAML dependency."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^packages\s*:\s*(.*?)\s*$", line)
        if match is None:
            continue
        inline = re.sub(r"\s+#.*$", "", match.group(1))
        if inline:
            if not (inline.startswith("[") and inline.endswith("]")):
                raise GraphError("pnpm-workspace.yaml packages is not a list")
            return [_scalar(item) for item in inline[1:-1].split(",") if item.strip()]
        values: list[str] = []
        for item in lines[index + 1:]:
            stripped = item.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not item[:1].isspace() and not stripped.startswith("-"):
                break
            if not stripped.startswith("- "):
                raise GraphError("pnpm-workspace.yaml packages is not a list of scalars")
            values.append(_scalar(re.sub(r"\s+#.*$", "", stripped[2:])))
        return values
    return []


def _scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return value


def classify(workspace: Path, source_dir: str, commands: Sequence[Sequence[str]]) -> list[str]:
    graph = ScriptGraph(workspace)
    for argv in commands:
        if argv and Path(str(argv[0])).name in MANAGERS:
            graph.walk_command(argv, source_dir)
    return list(dict.fromkeys(graph.gaps))
