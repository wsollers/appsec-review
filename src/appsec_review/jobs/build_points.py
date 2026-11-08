"""Build points: the named things a build system builds, read from a unit's descriptors.

``docs/plans/build-discovery-test-program-2026-11-08.md`` §1–2 and T-056.2. A build point is a CMake
target, a Make rule, a project a ``.sln`` lists, a Cargo package or binary, a Gradle project, a Maven
module, a Go module or package, an npm script or workspace member, a meson executable or library, an
automake program or library, an Xcode native target, a package. Each carries its kind, the descriptor
line that establishes it (``path:line``), the target-relative sources it names (literal paths and
expanded globs, or the sources contained in a member directory), the include directories it declares
and, when the declaration sits inside a condition, that condition's text. A member point (a listed
project, an included Gradle project, a workspace member, a Maven module) also carries ``path`` (the
member directory) and ``descriptor`` (the member's own build file, which is evidence of the point).

A unit also **drives** directories (plan §2.1 decision 1): ``drives`` entries are
``{path, via, evidence[, condition]}`` where ``via`` names the literal construct —
``add_subdirectory``, ``FetchContent``, ``ExternalProject_Add``, ``recursive_make`` (``$(MAKE) -C``),
``subdir`` (meson), ``SUBDIRS``/``AC_CONFIG_SUBDIRS`` (automake), ``solution_project``,
``settings_include`` (Gradle), ``externalNativeBuild``, ``workspace_member`` (Cargo, npm, pnpm),
``go_work_use``, ``pom_module`` — or ``invokes:<tool>`` when a recipe, custom command or script line
runs another build system's tool on a directory (``cmake -S dir``, ``meson setup dir``,
``wasm-pack build dir``, ``cargo build --manifest-path dir/Cargo.toml``, ``make -C dir``).
:mod:`appsec_review.jobs.build_discovery` folds a driven directory of the same build system into the
driving unit (its descriptor becomes the unit's and its points the unit's) and records a driven unit
of another build system as ``driven_by``.

Everything here is bounded, literal reading of descriptor text: variables that are not simple
assignments, generator expressions and dynamic constructs are left unresolved and recorded as
``unresolved`` facts, never guessed. The extractors take the unit's descriptor texts and the
inventory paths; they never touch the filesystem.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
import fnmatch
import posixpath
import re
import shlex
from typing import Any

SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".s", ".asm", ".cu", ".rs", ".go", ".java",
                             ".kt", ".cs", ".swift", ".f", ".f90"})
HEADER_SUFFIXES = frozenset({".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"})
# Sources a member directory contributes to its member point, by the unit's family.
MEMBER_SOURCE_SUFFIXES: dict[str, frozenset[str]] = {
    "java": frozenset({".java", ".kt", ".kts", ".scala", ".groovy"}),
    "node": frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte"}),
    "rust": frozenset({".rs"}),
    "go": frozenset({".go"}),
    "dotnet": frozenset({".cs", ".vb", ".fs"}),
    "native": frozenset({".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".h", ".hh", ".hpp", ".hxx"}),
}
_NATIVE_MEMBER_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"})
# Installed and generated trees inside a member directory are never its sources.
_INERT_DIRS = frozenset({"node_modules", "vendor", "target", "build", "dist", "obj", "bin", ".gradle", "buildSrc"})


def _norm(root: str, relative: str) -> str | None:
    """Target-relative normalised path for ``relative`` as written from ``root``; None if it escapes."""
    relative = relative.strip().strip('"').strip("'")
    if not relative or relative.startswith(("$", "@")):
        return None
    joined = posixpath.normpath(posixpath.join(root, relative)) if root not in ("", ".") else posixpath.normpath(relative)
    if joined == ".." or joined.startswith("../") or joined.startswith("/"):
        return None
    return joined


def _expand(pattern: str, inventory: Sequence[str]) -> list[str]:
    if "*" not in pattern and "?" not in pattern:
        return [pattern] if pattern in inventory else []
    # CMake GLOB and shell wildcards are directory-local unless recursive forms are used; a single
    # star never crosses a slash.
    if "**" in pattern:
        regex = re.compile("^" + re.escape(pattern).replace(r"\*\*/", "(?:.*/)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*").replace(r"\?", "[^/]") + "$")
        return sorted(path for path in inventory if regex.match(path))
    return sorted(path for path in inventory if fnmatch.fnmatchcase(path, pattern) and path.count("/") == pattern.count("/"))


def _point(name: str, kind: str, evidence: str, *, sources: Iterable[str] = (), include_dirs: Iterable[str] = (),
           condition: str | None = None, **extra: Any) -> dict[str, Any]:
    value: dict[str, Any] = {"name": name, "kind": kind, "evidence": evidence,
                             "sources": sorted(set(sources)), "include_dirs": sorted(set(include_dirs))}
    if condition:
        value["condition"] = condition
    value.update({key: item for key, item in extra.items() if item not in (None, [], {})})
    return value


def _under(path: str, directory: str) -> bool:
    return directory in ("", ".") or path == directory or path.startswith(directory + "/")


def _member_sources(directory: str, inventory: Sequence[str], suffixes: Iterable[str]) -> list[str]:
    """Sources of the given suffixes contained in a member directory, skipping installed/generated trees."""
    wanted = frozenset(suffixes)
    found = []
    prefix_len = 0 if directory in ("", ".") else len(directory) + 1
    for path in inventory:
        if not _under(path, directory) or posixpath.splitext(path)[1].lower() not in wanted:
            continue
        inner = path[prefix_len:].split("/")[:-1]
        if any(part in _INERT_DIRS for part in inner):
            continue
        found.append(path)
    return sorted(found)


def _line_of(text: str, needle: str, occurrence: int = 0) -> int | None:
    start = -1
    for _ in range(occurrence + 1):
        start = text.find(needle, start + 1)
        if start < 0:
            return None
    return text.count("\n", 0, start) + 1


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _drive(path: str, via: str, evidence: str, condition: str | None = None, **extra: Any) -> dict[str, Any]:
    value = {"path": path, "via": via, "evidence": evidence}
    if condition:
        value["condition"] = condition
    value.update({key: item for key, item in extra.items() if item not in (None, False, [], {})})
    return value


# ----------------------------------------------------------------------------- build-tool invocations

# A recipe, custom command or script that runs another build system's tool on a directory drives
# that directory. The directory argument is literal once the usual source-root variables are
# replaced; anything else dynamic is not a reference.
_ROOT_VARIABLES = re.compile(
    r"\$\{(?:CMAKE_SOURCE_DIR|CMAKE_CURRENT_SOURCE_DIR|PROJECT_SOURCE_DIR|CMAKE_CURRENT_LIST_DIR)\}"
    r"|\$\((?:top_srcdir|abs_top_srcdir|srcdir|CURDIR|PWD)\)")
_INVOCATION_TOOLS = {"cmake": ("CMakeLists.txt",), "meson": ("meson.build",), "wasm-pack": ("Cargo.toml",),
                     "cargo": ("Cargo.toml",), "make": ("Makefile", "makefile", "GNUmakefile"), "gmake": ("Makefile", "makefile", "GNUmakefile"),
                     "npm": ("package.json",), "pnpm": ("package.json",), "yarn": ("package.json",),
                     "gradle": ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"),
                     "gradlew": ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts")}
_SHELL_FOR_LOOP = re.compile(r"for\s+(\w+)\s+in\s+([^;]+);\s*do\b")


def _invocation_directory(tool: str, tokens: list[str]) -> str | None:
    """The directory a build-tool command line builds, from its tokens after the tool name."""
    def value_after(flags: tuple[str, ...]) -> str | None:
        for index, token in enumerate(tokens):
            for flag in flags:
                if token == flag and index + 1 < len(tokens):
                    return tokens[index + 1]
                if token.startswith(flag + "=") or (len(flag) == 2 and token.startswith(flag) and len(token) > 2 and not token.startswith("--")):
                    return token[len(flag):].lstrip("=")
        return None
    positionals = [t for t in tokens if not t.startswith("-")]
    if tool == "cmake":
        if "--build" in tokens or "--install" in tokens or "-E" in tokens or "-P" in tokens:
            return None
        explicit = value_after(("-S",))
        if explicit is not None:
            return explicit
        # cmake [options] <path-to-source>; -D/-G/-B take values that are not the source directory.
        skip = set()
        for index, token in enumerate(tokens):
            if token in {"-G", "-B", "-D", "-A", "-T", "-C", "--preset", "--toolchain", "--install-prefix"} and index + 1 < len(tokens):
                skip.add(index + 1)
        candidates = [t for index, t in enumerate(tokens) if index not in skip and not t.startswith("-")]
        return candidates[0] if candidates else None
    if tool == "meson":
        if positionals and positionals[0] in {"compile", "install", "test", "introspect", "configure", "dist", "wrap", "subprojects"}:
            return None
        if positionals and positionals[0] == "setup":
            positionals = positionals[1:]
        # meson setup <builddir> <sourcedir>: the source directory is the second positional.
        return positionals[1] if len(positionals) >= 2 else None
    if tool == "wasm-pack":
        if not positionals or positionals[0] != "build":
            return None
        return positionals[1] if len(positionals) >= 2 else None
    if tool == "cargo":
        manifest = value_after(("--manifest-path",))
        return (posixpath.dirname(manifest) or ".") if manifest else None
    if tool in {"make", "gmake"}:
        return value_after(("-C", "--directory"))
    if tool in {"npm", "pnpm", "yarn"}:
        return value_after(("--prefix", "-C", "--dir"))
    if tool in {"gradle", "gradlew"}:
        return value_after(("-p", "--project-dir"))
    return None


def invoked_build_directories(text: str, base: str, root: str) -> list[tuple[str, str, int]]:
    """``(tool, target-relative directory, line)`` for every build-tool invocation in ``text``.

    ``base`` is the directory the text's relative paths are resolved from and ``root`` the unit root
    the source-root variables stand for. ``cargo --manifest-path x/Cargo.toml`` yields ``x``. A
    ``for d in a b; do ... -C $$d`` shell loop yields one entry per word. Arguments that are not the
    built directory (``cmake --build``, option values) are not reported.
    """
    found: list[tuple[str, str, int]] = []
    seen: set[tuple[str, str]] = set()
    root_prefix = "" if root in ("", ".") else root + "/"
    for line_number, raw_line in enumerate(text.split("\n"), 1):
        line = raw_line
        if line.lstrip().startswith("#"):
            continue
        line = _ROOT_VARIABLES.sub("@ROOT@", line).replace("$(MAKE)", "make").replace("${MAKE}", "make")
        loop_words: dict[str, list[str]] = {}
        for match in _SHELL_FOR_LOOP.finditer(line):
            loop_words[match.group(1)] = match.group(2).split()
        cwd: str | None = base  # a cd earlier on the line moves the directory later segments resolve from
        for segment in re.split(r"&&|\|\||;|\|", line):
            try:
                tokens = shlex.split(segment, comments=False, posix=True)
            except ValueError:
                tokens = segment.split()
            while tokens and (tokens[0] in {"do", "then", "else", "{", "(", "@", "-", "+"} or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0])):
                tokens = tokens[1:]
            if tokens and tokens[0].lstrip("@-+") == "cd":
                target = tokens[1].strip("\"'") if len(tokens) > 1 else None
                if target and target.startswith("@ROOT@"):
                    cwd = _norm(".", root_prefix + target[len("@ROOT@"):].lstrip("/")) if target != "@ROOT@" else (root or ".")
                elif target and "$" not in target and cwd is not None:
                    cwd = _norm(cwd, target)
                else:
                    cwd = None  # a dynamic cd: nothing after it is literal
                continue
            if not tokens or cwd is None:
                continue
            tool = posixpath.basename(tokens[0].lstrip("@-+"))
            if tool.startswith("./"):
                tool = tool[2:]
            if tool not in _INVOCATION_TOOLS:
                continue
            argument = _invocation_directory(tool, tokens[1:])
            if argument is None:
                continue
            values = [argument]
            loop = re.fullmatch(r"\$\$?\{?(\w+)\}?", argument)
            if loop is not None:
                values = loop_words.get(loop.group(1), [])
            for value in values:
                value = value.strip("\"'")
                if value.startswith("@ROOT@"):
                    target = _norm(".", root_prefix + value[len("@ROOT@"):].lstrip("/")) if value != "@ROOT@" else (root if root else ".")
                elif "$" in value or "@" in value:
                    continue
                else:
                    target = _norm(cwd, value)
                if target is None or target == base or (tool, target) in seen:
                    continue
                seen.add((tool, target))
                found.append((tool, target, line_number))
    return found


def _invokes_marker(tool: str, directory: str, inventory: Sequence[str]) -> bool:
    """Whether the invoked directory holds a descriptor of the invoked tool (a literal drive, not a stray path)."""
    return any(((directory + "/" + name) if directory != "." else name) in inventory for name in _INVOCATION_TOOLS[tool])


def _invocation_drives(text: str, base: str, root: str, evidence_path: str, first_line: int, inventory: Sequence[str],
                       condition: str | None = None) -> list[dict[str, Any]]:
    """Drives from the build-tool invocations in ``text`` (whose first line is ``first_line`` of ``evidence_path``)."""
    drives = []
    for tool, directory, line in invoked_build_directories(text, base, root):
        if not _invokes_marker(tool, directory, inventory):
            continue
        via = "recursive_make" if tool in {"make", "gmake"} else f"invokes:{tool}"
        drives.append(_drive(directory, via, f"{evidence_path}:{first_line + line - 1}", condition))
    return drives


# ----------------------------------------------------------------------------- CMake

_CMAKE_CALL = re.compile(r"([A-Za-z_][A-Za-z_0-9]*)[ \t\r\n]*\(")
_CMAKE_SOURCE_LIKE = re.compile(r"\.(?:c|cc|cpp|cxx|m|mm|s|asm|cu|h|hh|hpp|hxx|inl|ipp)$", re.I)
_CMAKE_SOURCE_DIR_VARIABLES = ("${CMAKE_CURRENT_SOURCE_DIR}/", "${CMAKE_SOURCE_DIR}/", "${PROJECT_SOURCE_DIR}/",
                               "${CMAKE_CURRENT_LIST_DIR}/")


def _cmake_calls(text: str):
    """Yield (name, args, line, condition_stack_text, raw) for every top-level or nested call, with balanced parens."""
    conditions: list[str] = []
    pos = 0
    length = len(text)
    while pos < length:
        match = _CMAKE_CALL.search(text, pos)
        if match is None:
            return
        # Skip comments.
        line_start = text.rfind("\n", 0, match.start()) + 1
        if "#" in text[line_start:match.start()]:
            pos = text.find("\n", match.start())
            if pos < 0:
                return
            continue
        depth, i = 1, match.end()
        while i < length and depth:
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
            i += 1
        body = text[match.end():i - 1]
        name = match.group(1).lower()
        try:
            args = shlex.split(body.replace("\n", " "), comments=False, posix=True)
        except ValueError:
            args = body.split()
        line = text.count("\n", 0, match.start()) + 1
        condition = " && ".join(conditions) if conditions else None
        if name == "if":
            conditions.append(body.strip())
        elif name in {"elseif", "else"}:
            if conditions:
                conditions[-1] = f"NOT({conditions[-1]})" if name == "else" else body.strip()
        elif name == "endif":
            if conditions:
                conditions.pop()
        yield name, args, line, condition, body
        pos = i


def _cmake_dir(base: str, root: str, value: str) -> str | None:
    """A directory argument with the source-dir variables resolved; None when it stays dynamic."""
    for variable in _CMAKE_SOURCE_DIR_VARIABLES:
        if value.startswith(variable):
            anchor = root if variable in ("${CMAKE_SOURCE_DIR}/", "${PROJECT_SOURCE_DIR}/") else base
            return _norm(anchor, value[len(variable):])
    return _norm(base, value)


def _cmake_commands(body: str) -> str:
    """The body of a custom target/command with everything but its COMMAND clauses blanked, lines kept."""
    kept = []
    active = False
    for raw in body.split("\n"):
        words = raw.split()
        out = []
        for word in words:
            if word.upper() == "COMMAND":
                active = True
                continue
            if word.isupper() and word.isalpha() and word not in {"ALL"} and len(word) > 2:
                active = False  # another clause keyword (COMMENT, DEPENDS, WORKING_DIRECTORY, ...)
            if active:
                out.append(word)
        kept.append(" ".join(out))
    return "\n".join(kept)


def cmake_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    """Targets, subdirectories, includes, presets and unresolved constructs of one CMake unit."""
    points: list[dict[str, Any]] = []
    drives: list[dict[str, Any]] = []
    includes: list[str] = []
    unresolved: list[dict[str, Any]] = []
    variables: dict[str, list[str]] = {}
    by_name: dict[str, dict[str, Any]] = {}
    module_dirs: list[str] = []
    lists = sorted(path for path in descriptors if posixpath.basename(path) == "CMakeLists.txt")
    for path in lists:
        base = posixpath.dirname(path) or "."
        for name, args, line, condition, body in _cmake_calls(descriptors[path]):
            evidence = f"{path}:{line}"
            if "$<" in body:
                unresolved.append({"evidence": evidence, "reason": "generator expression"})
            if name == "set" and len(args) >= 2 and not args[0].startswith("$"):
                variables[args[0]] = args[1:]
                continue
            if name == "file" and len(args) >= 3 and args[0].upper() in {"GLOB", "GLOB_RECURSE"}:
                patterns = [a for a in args[2:] if not a.upper() in {"CONFIGURE_DEPENDS", "LIST_DIRECTORIES", "RELATIVE", "true", "false"}]
                resolved: list[str] = []
                for pattern in patterns:
                    target = _norm(base, pattern)
                    if target is not None:
                        resolved.extend(_expand(target.replace("**", "**") if args[0].upper() == "GLOB_RECURSE" else target, inventory)
                                        if args[0].upper() == "GLOB" else _expand(target.replace("*", "**/*", 1) if "**" not in target else target, inventory))
                variables[args[1]] = resolved
                continue
            if name == "add_subdirectory" and args:
                target = _cmake_dir(base, root, args[0])
                drives.append(_drive(target or args[0], "add_subdirectory", evidence, condition, unresolved=target is None))
                continue
            if name in {"externalproject_add", "fetchcontent_declare"} and args:
                source_dir = next((args[i + 1] for i, a in enumerate(args[:-1]) if a.upper() == "SOURCE_DIR"), None)
                via = "ExternalProject_Add" if name == "externalproject_add" else "FetchContent"
                if name == "externalproject_add":
                    points.append(_point(args[0], "external_project", evidence, condition=condition))
                if source_dir is not None:
                    target = _cmake_dir(base, root, source_dir)
                    drives.append(_drive(target or source_dir, via, evidence, condition, unresolved=target is None))
                elif name == "externalproject_add":
                    unresolved.append({"evidence": evidence, "reason": "ExternalProject_Add without an in-tree SOURCE_DIR"})
                continue
            if name == "list" and len(args) >= 3 and args[0].upper() == "APPEND" and args[1] == "CMAKE_MODULE_PATH":
                for value in args[2:]:
                    directory = _cmake_dir(base, root, value)
                    if directory is not None:
                        module_dirs.append(directory)
                continue
            if name == "include" and args:
                target = _norm(base, args[0])
                if target is not None and target in inventory:
                    includes.append(target)
                elif "/" not in args[0] and not args[0].startswith("$"):
                    # include(Module) resolves through CMAKE_MODULE_PATH; a built-in module (CTest,
                    # GNUInstallDirs) is not in the tree and is not recorded.
                    for directory in module_dirs:
                        candidate = f"{directory}/{args[0]}.cmake" if directory != "." else f"{args[0]}.cmake"
                        if candidate in inventory:
                            includes.append(candidate)
                continue
            if name in {"add_executable", "add_library", "add_custom_target"} and args:
                target_name = args[0]
                if any(a.upper() == "ALIAS" for a in args[1:]):
                    kind = "alias"
                elif name == "add_custom_target":
                    kind = "custom_target"
                elif name == "add_executable":
                    kind = "executable"
                else:
                    linkage = next((a.upper() for a in args[1:] if a.upper() in {"STATIC", "SHARED", "MODULE", "INTERFACE", "OBJECT"}), None)
                    kind = {"STATIC": "static_library", "SHARED": "shared_library", "MODULE": "module_library",
                            "INTERFACE": "interface_library", "OBJECT": "object_library"}.get(linkage or "", "library")
                sources = _cmake_sources(base, args[1:], variables, inventory, unresolved, evidence)
                point = _point(target_name, kind, evidence, sources=sources, condition=condition)
                if "IMPORTED" in {a.upper() for a in args[1:]}:
                    point["kind"] = "imported"
                points.append(point)
                by_name[target_name] = point
                if name == "add_custom_target":
                    # The COMMAND of a custom target may run another build system: a literal drive,
                    # recorded at the COMMAND's own line.
                    drives.extend(_invocation_drives(_cmake_commands(body), base, root, path, line, inventory, condition))
                continue
            if name == "add_custom_command":
                drives.extend(_invocation_drives(_cmake_commands(body), base, root, path, line, inventory, condition))
                unresolved.append({"evidence": evidence, "reason": "add_custom_command is a dynamic construct"})
                continue
            if name == "target_sources" and len(args) >= 2 and args[0] in by_name:
                point = by_name[args[0]]
                point["sources"] = sorted(set(point["sources"]) | set(
                    _cmake_sources(base, args[1:], variables, inventory, unresolved, evidence)))
                continue
            if name == "target_include_directories" and len(args) >= 2 and args[0] in by_name:
                dirs = [_cmake_dir(base, root, a) for a in args[1:] if a.upper() not in {"PUBLIC", "PRIVATE", "INTERFACE", "SYSTEM", "BEFORE", "AFTER"}]
                point = by_name[args[0]]
                point["include_dirs"] = sorted(set(point["include_dirs"]) | {d for d in dirs if d})
                continue
            if name == "project" and args:
                variables.setdefault("PROJECT_NAME", [args[0]])
            if name in {"execute_process", "configure_file"}:
                unresolved.append({"evidence": evidence, "reason": f"{name} is a dynamic construct"})
    for point in points:
        point["headers"] = _headers_under(point["include_dirs"], inventory) if point["include_dirs"] else []
    return {"build_points": points, "drives": drives, "includes": sorted(set(includes)), "unresolved": unresolved}


def _cmake_sources(base: str, args: Sequence[str], variables: Mapping[str, list[str]], inventory: Sequence[str],
                   unresolved: list[dict[str, Any]], evidence: str) -> list[str]:
    sources: list[str] = []
    for arg in args:
        if arg.upper() in {"STATIC", "SHARED", "MODULE", "INTERFACE", "OBJECT", "IMPORTED", "ALIAS", "GLOBAL",
                           "EXCLUDE_FROM_ALL", "WIN32", "MACOSX_BUNDLE", "PUBLIC", "PRIVATE", "ALL"}:
            continue
        reference = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z_0-9]*)\}", arg)
        if reference is not None:
            if reference.group(1) in variables:
                for value in variables[reference.group(1)]:
                    target = value if value in inventory else _norm(base, value)
                    if target and target in inventory:
                        sources.append(target)
            else:
                unresolved.append({"evidence": evidence, "reason": f"variable ${{{reference.group(1)}}} is not a literal assignment"})
            continue
        if "$" in arg:
            unresolved.append({"evidence": evidence, "reason": f"dynamic source argument {arg}"})
            continue
        if not _CMAKE_SOURCE_LIKE.search(arg):
            continue
        target = _norm(base, arg)
        if target is not None and target in inventory:
            sources.append(target)
    return sources


def _headers_under(include_dirs: Iterable[str], inventory: Sequence[str]) -> list[str]:
    found = []
    for directory in include_dirs:
        prefix = "" if directory in ("", ".") else directory.rstrip("/") + "/"
        found.extend(path for path in inventory if path.startswith(prefix) and posixpath.splitext(path)[1].lower() in HEADER_SUFFIXES)
    return sorted(set(found))


# ----------------------------------------------------------------------------- Make

_MAKE_RULE = re.compile(r"^([A-Za-z0-9_./$()%{}-][^:=\n#]*?)[ \t]*::?(?!=)[ \t]*([^#\n]*)$", re.M)
_MAKE_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*[:?+]?=\s*(.*)$", re.M)
_MAKE_SUBMAKE = re.compile(r"\$\(MAKE\)\s+(?:[^\n]*?\s)?-C\s+([^\s;&|]+)")
_MAKE_INCLUDE = re.compile(r"^-?include\s+(.+)$", re.M)
_MAKE_COND = re.compile(r"^(ifeq|ifneq|ifdef|ifndef)\s*(.*)$|^(else|endif)\b", re.M)
_MAKE_SOURCE_TOKEN = re.compile(r"(?<![\w/.-])((?:\.\./|\./)?[\w./*-]+\.(?:c|cc|cpp|cxx|m|mm|s|S|asm|cu))(?![\w.-])")
_MAKE_INCLUDE_FLAG = re.compile(r"-I\s*([^\s\"']+)")
_MAKE_OBJECT_TOKEN = re.compile(r"(?<![\w/.-])((?:\.\./|\./)?[\w./-]+\.(?:o|obj))(?![\w.-])")
_OBJECT_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".s", ".S", ".asm", ".cu"})


def _make_rules(root: str, path: str, text: str, inventory: Sequence[str], *, automake: bool = False
                ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    """Rules, drives, includes and unresolved constructs of one Makefile (or Makefile.am) text."""
    points: list[dict[str, Any]] = []
    drives: list[dict[str, Any]] = []
    includes: list[str] = []
    unresolved: list[dict[str, Any]] = []
    base = posixpath.dirname(path) or "."
    variables: dict[str, str] = {}
    for match in _MAKE_ASSIGN.finditer(text):
        variables[match.group(1)] = match.group(2).strip()

    def expand(value: str, depth: int = 0) -> str:
        if depth > 4:
            return value
        def repl(m: re.Match[str]) -> str:
            inner = m.group(1)
            wild = re.fullmatch(r"wildcard\s+(.*)", inner)
            if wild is not None:
                found = []
                for pattern in wild.group(1).split():
                    target = _norm(base, expand(pattern, depth + 1))
                    if target is not None:
                        # Results are re-relativized to the Makefile's directory so the later
                        # _norm(base, token) lands on the inventory path again.
                        found.extend(posixpath.relpath(hit, base) if base != "." else hit
                                     for hit in _expand(target, inventory))
                return " ".join(found)
            subst = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*):([^=]*)=(.*)", inner)
            if subst is not None and subst.group(1) in variables:
                # $(SRCS:.c=.o): substitution reference over the expanded variable.
                words = expand(variables[subst.group(1)], depth + 1).split()
                old_suffix, new_suffix = subst.group(2), subst.group(3)
                return " ".join(w[: -len(old_suffix)] + new_suffix if old_suffix and w.endswith(old_suffix) else w for w in words)
            if inner in variables:
                return expand(variables[inner], depth + 1)
            if inner == "MAKE":
                return "make"  # so a recipe's recursive make stays readable after expansion
            if inner in {"CC", "CXX", "RM", "AR", "CFLAGS", "CXXFLAGS", "LDFLAGS", "LDLIBS", "CPPFLAGS",
                         "top_srcdir", "top_builddir", "srcdir", "builddir", "abs_top_srcdir"}:
                return ""
            unresolved.append({"evidence": f"{path}", "reason": f"variable $({inner}) is not a literal assignment"})
            return ""
        return re.sub(r"\$\(([^()]*)\)", repl, value)

    if not automake:
        for match in _MAKE_INCLUDE.finditer(text):
            for raw_token in match.group(1).split():
                if "$(" in raw_token:
                    # include $(PLATFORM).mk: the value is decided at build time; every file the
                    # pattern could name is context (decision 2026-11-08, §2.1 item 9).
                    pattern = _norm(base, re.sub(r"\$\([^()]*\)", "*", raw_token))
                    if pattern is not None:
                        includes.extend(_expand(pattern, inventory))
                    continue
                target = _norm(base, raw_token)
                if target is not None and target in inventory:
                    includes.append(target)
    lines = text.split("\n")
    condition_stack: list[str] = []
    line_conditions: dict[int, str | None] = {}
    for number, line in enumerate(lines, 1):
        cond = _MAKE_COND.match(line.strip())
        if cond is not None:
            if cond.group(1):
                condition_stack.append(f"{cond.group(1)} {cond.group(2).strip()}".strip())
            elif cond.group(3) == "else" and condition_stack:
                condition_stack[-1] = f"NOT({condition_stack[-1]})"
            elif cond.group(3) == "endif" and condition_stack:
                condition_stack.pop()
        line_conditions[number] = " && ".join(condition_stack) if condition_stack else None
    for match in _MAKE_RULE.finditer(text):
        name_text, prereqs = match.group(1).strip(), match.group(2)
        if name_text.startswith(".") or "%" in name_text or "$" in name_text or name_text.startswith("\t"):
            if "%" in name_text:
                unresolved.append({"evidence": f"{path}:{_line_at(text, match.start())}", "reason": "pattern rule"})
            continue
        line = _line_at(text, match.start())
        recipe_lines = []
        index = line  # lines are 1-based; recipe follows the rule line
        while index < len(lines) and lines[index].startswith("\t"):
            recipe_lines.append(lines[index][1:])
            index += 1
        recipe = "\n".join(recipe_lines)
        raw = prereqs + "\n" + recipe
        expanded = expand(raw)
        # A recipe that runs another build system's tool on a directory drives it; a recursive make
        # whose directory came through a shell loop (for d in $(SUBDIRS); do $(MAKE) -C $$d) is read here.
        invoked = _invocation_drives(expanded, base, root, path, line, inventory, line_conditions.get(line))
        for item in invoked:
            if item["via"] == "recursive_make":
                item["evidence"] = f"{path}:{line}"  # a recursive make is recorded at its rule, like the direct form
        for sub in _MAKE_SUBMAKE.finditer(raw):
            target = _norm(base, expand(sub.group(1)))
            if target is None and "$$" in sub.group(1) and any(d["via"] == "recursive_make" for d in invoked):
                continue
            drives.append(_drive(target or sub.group(1), "recursive_make", f"{path}:{line}", line_conditions.get(line),
                                 unresolved=target is None))
        for drive in invoked:
            if not any(d["path"] == drive["path"] and d["via"] == drive["via"] for d in drives):
                drives.append(drive)
        sources = []
        for token in _MAKE_SOURCE_TOKEN.findall(expanded):
            target = _norm(base, token)
            if target is None:
                continue
            sources.extend(_expand(target, inventory))
        for token in _MAKE_OBJECT_TOKEN.findall(prereqs if "$" not in prereqs else expand(prereqs)):
            # An object prerequisite is compiled from the source of the same stem (a pattern or
            # suffix rule); the source in the tree is the evidence.
            stem = _norm(base, token[: -len(".o")] if token.endswith(".o") else token[: -len(".obj")])
            if stem is None:
                continue
            sources.extend(p for p in inventory if posixpath.splitext(p)[0] == stem
                           and posixpath.splitext(p)[1].lower() in _OBJECT_SOURCE_SUFFIXES)
        sources = sorted(dict.fromkeys(sources))
        include_dirs = [d for d in (_norm(base, flag) for flag in _MAKE_INCLUDE_FLAG.findall(expanded)) if d]
        for target_name in name_text.split():
            if automake and (target_name.endswith("_SOURCES") or target_name.isupper()):
                continue
            kind = "rule"
            if not recipe_lines and not sources and _MAKE_SUBMAKE.search(raw) is None:
                kind = "phony_or_aggregate"
            point = _point(target_name, kind, f"{path}:{line}", sources=sources, include_dirs=include_dirs,
                           condition=line_conditions.get(line))
            point["headers"] = _headers_under(include_dirs, inventory) if include_dirs else []
            if recipe_lines and not sources and _MAKE_SUBMAKE.search(raw):
                point["kind"] = "delegating"
            points.append(point)
    return points, drives, includes, unresolved


def make_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    """Rules, sub-makes, includes and conditions of one Make unit, with the sources each rule names."""
    points: list[dict[str, Any]] = []
    drives: list[dict[str, Any]] = []
    includes: list[str] = []
    unresolved: list[dict[str, Any]] = []
    for path in sorted(descriptors):
        if posixpath.basename(path) not in {"Makefile", "makefile", "GNUmakefile"} and not path.endswith(".mk"):
            continue
        found = _make_rules(root, path, descriptors[path], inventory)
        points.extend(found[0])
        drives.extend(found[1])
        includes.extend(found[2])
        unresolved.extend(found[3])
    return {"build_points": points, "drives": drives, "includes": sorted(set(includes)), "unresolved": unresolved}


# ----------------------------------------------------------------------------- others

def _toml(text: str) -> tuple[Mapping[str, Any] | None, str | None]:
    import tomllib
    try:
        return tomllib.loads(text), None
    except tomllib.TOMLDecodeError as exc:
        return None, str(exc)


def _cargo_package_points(manifest: str, text: str, document: Mapping[str, Any], inventory: Sequence[str]) -> list[dict[str, Any]]:
    """The package, lib, bin, build-script and test points one Cargo.toml declares."""
    base = posixpath.dirname(manifest) or "."
    package = document.get("package", {}) if isinstance(document.get("package"), Mapping) else {}
    if not package.get("name"):
        return []
    points: list[dict[str, Any]] = []
    name_line = _line_of(text, "name") or 1
    points.append(_point(str(package["name"]), "package", f"{manifest}:{name_line}", path=base, descriptor=manifest))
    srcs = [p for p in inventory if _under(p, posixpath.join(base, "src") if base != "." else "src") and p.endswith(".rs")]
    bins: list[tuple[str, str | None, int | None]] = []
    main = _norm(base, "src/main.rs")
    if main in inventory:
        bins.append((str(package["name"]), main, None))
    for index, binary in enumerate(document.get("bin", []) if isinstance(document.get("bin"), list) else []):
        if isinstance(binary, Mapping) and binary.get("name"):
            path = _norm(base, str(binary.get("path", f"src/bin/{binary['name']}.rs")))
            bins.append((str(binary["name"]), path, _line_of(text, "[[bin]]", index)))
    for path in sorted(p for p in srcs if _under(p, posixpath.join(base, "src/bin") if base != "." else "src/bin")):
        stem = posixpath.splitext(posixpath.basename(path))[0]
        if not any(b[1] == path for b in bins):
            bins.append((stem, path, None))  # Cargo's auto-discovered binaries
    bin_paths = {b[1] for b in bins if b[1]}
    lib = document.get("lib") if isinstance(document.get("lib"), Mapping) else {}
    lib_path = _norm(base, str(lib.get("path", "src/lib.rs")))
    if lib_path in inventory or lib:
        points.append(_point(str(lib.get("name", package["name"])), "lib",
                             f"{manifest}:{_line_of(text, '[lib]') or name_line}",
                             sources=[s for s in srcs if s not in bin_paths]))
    for bin_name, bin_path, line in bins:
        points.append(_point(bin_name, "bin", f"{manifest}:{line or name_line}" if line else (
            f"{manifest}:{name_line}" if bin_path == main else f"{bin_path}:1"), sources=[bin_path] if bin_path in inventory else []))
    build = package.get("build")
    if build is None and _norm(base, "build.rs") in inventory:
        build = "build.rs"  # Cargo's implicit build script
    if build:
        path = _norm(base, str(build))
        points.append(_point("build-script-build", "build_script",
                             f"{manifest}:{_line_of(text, 'build') or name_line}", sources=[path] if path in inventory else []))
    tests_dir = posixpath.join(base, "tests") if base != "." else "tests"
    for path in sorted(p for p in inventory if _under(p, tests_dir) and p.endswith(".rs") and p.count("/") == tests_dir.count("/") + 1):
        points.append(_point(posixpath.splitext(posixpath.basename(path))[0], "test", f"{path}:1", sources=[path]))
    return points


def cargo_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    manifests = sorted(p for p in descriptors if posixpath.basename(p) == "Cargo.toml")
    root_manifest = (root + "/Cargo.toml") if root != "." else "Cargo.toml"
    if root_manifest in descriptors:
        manifests = [root_manifest] + [m for m in manifests if m != root_manifest]
    points: list[dict[str, Any]] = []
    drives: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    for manifest in manifests:
        document, error = _toml(descriptors[manifest])
        if document is None:
            unresolved.append({"evidence": manifest, "reason": f"Cargo.toml: {error}"})
            continue
        points.extend(_cargo_package_points(manifest, descriptors[manifest], document, inventory))
        workspace = document.get("workspace") if isinstance(document.get("workspace"), Mapping) else None
        if workspace and manifest == root_manifest:
            base = posixpath.dirname(manifest) or "."
            excluded = [t for pattern in workspace.get("exclude", []) if isinstance(pattern, str)
                        for t in _expand(_norm(base, pattern) or "", [posixpath.dirname(p) or "." for p in inventory if posixpath.basename(p) == "Cargo.toml"])]
            line = _line_of(descriptors[manifest], "[workspace]") or 1
            for member in workspace.get("members", []):
                if not isinstance(member, str):
                    continue
                for target in _expand(_norm(base, member) or "", [posixpath.dirname(p) or "." for p in inventory if posixpath.basename(p) == "Cargo.toml"]):
                    if target != base and target not in excluded:
                        drives.append(_drive(target, "workspace_member", f"{manifest}:{line}"))
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": unresolved}


def go_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    prefix = "" if root == "." else root + "/"
    points: list[dict[str, Any]] = []
    drives: list[dict[str, Any]] = []
    modules: dict[str, str] = {}  # module directory -> module path
    for path in sorted(p for p in descriptors if posixpath.basename(p) == "go.mod"):
        text = descriptors[path]
        match = re.search(r"^\s*module\s+(\S+)", text, re.M)
        directory = posixpath.dirname(path) or "."
        if match is None:
            continue
        modules[directory] = match.group(1).strip('"')
        points.append(_point(match.group(1).strip('"'), "module", f"{path}:{_line_at(text, match.start())}",
                             path=directory, descriptor=path))
    go_files = [p for p in inventory if p.startswith(prefix) and p.endswith(".go") and "/vendor/" not in "/" + p[len(prefix):]
                and "/testdata/" not in "/" + p[len(prefix):]]
    by_dir: dict[str, list[str]] = {}
    for path in go_files:
        by_dir.setdefault(posixpath.dirname(path) or ".", []).append(path)
    for directory in sorted(by_dir):
        files = sorted(by_dir[directory])
        texts = [descriptors.get(p) for p in files]
        is_main = any(t and re.search(r"^\s*package\s+main\b", t, re.M) for t in texts)
        if directory == root:
            name = modules.get(directory, ".")  # the unit root's own module names its root package
        else:
            name = directory[len(prefix):]
        points.append(_point(name, "main_package" if is_main else "package", f"{files[0]}:1", sources=files))
    work = next((p for p in descriptors if posixpath.basename(p) == "go.work"), None)
    if work:
        for match in re.finditer(r"^[ \t]*use[ \t]*(?:\(\s*([^)]*)\)|(\S+))", descriptors[work], re.M | re.S):
            for token in (match.group(1).split("\n") if match.group(1) else [match.group(2)]):
                token = token.split("//", 1)[0].strip()
                if not token:
                    continue
                target = _norm(root, token)
                if target and target != root:
                    drives.append(_drive(target, "go_work_use", f"{work}:{_line_at(descriptors[work], match.start())}"))
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": []}


def _json(text: str) -> tuple[Any, str | None]:
    import json
    try:
        return json.loads(text), None
    except ValueError as exc:
        return None, str(exc)


def node_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    manifest = (root + "/package.json") if root != "." else "package.json"
    if manifest not in descriptors:
        manifest = next((p for p in sorted(descriptors) if posixpath.basename(p) == "package.json"), None)
    if manifest is None:
        return {"build_points": [], "drives": [], "includes": [], "unresolved": []}
    text = descriptors[manifest]
    document, error = _json(text)
    if not isinstance(document, Mapping):
        return {"build_points": [], "drives": [], "includes": [],
                "unresolved": [{"evidence": manifest, "reason": f"package.json: {error or 'not an object'}"}]}
    points: list[dict[str, Any]] = []
    drives: list[dict[str, Any]] = []
    base = posixpath.dirname(manifest) or "."
    if document.get("name"):
        points.append(_point(str(document["name"]), "package", f"{manifest}:{_line_of(text, '\"name\"') or 1}"))
    scripts = document.get("scripts") if isinstance(document.get("scripts"), Mapping) else {}
    for name in sorted(scripts):
        command = str(scripts[name])
        line = _line_of(text, f'"{name}"') or 1
        points.append(_point(str(name), "script", f"{manifest}:{line}", command=command))
        for drive in _invocation_drives(command, base, root, manifest, line, inventory):
            if not any(d["path"] == drive["path"] for d in drives):
                drives.append(drive)
    patterns: list[tuple[str, str, int]] = []  # (pattern, declaring descriptor, line)
    declared = document.get("workspaces")
    if isinstance(declared, Mapping):
        declared = declared.get("packages")
    if isinstance(declared, list):
        line = _line_of(text, "workspaces") or 1
        patterns.extend((str(p), manifest, line) for p in declared if isinstance(p, str))
    pnpm = (base + "/pnpm-workspace.yaml") if base != "." else "pnpm-workspace.yaml"
    if pnpm in descriptors:
        from appsec_review.jobs.build_discovery import _pnpm_workspace_patterns
        for pattern in _pnpm_workspace_patterns(descriptors[pnpm]) or []:
            patterns.append((pattern, pnpm, _line_of(descriptors[pnpm], pattern) or 1))
    member_dirs = [posixpath.dirname(p) or "." for p in inventory
                   if posixpath.basename(p) == "package.json" and "node_modules" not in p.split("/")]
    excluded = {t for pattern, _d, _l in patterns if pattern.startswith("!")
                for t in _expand(_norm(base, pattern[1:]) or "", member_dirs)}
    for pattern, declaring, line in patterns:
        if pattern.startswith("!"):
            continue
        for target in _expand(_norm(base, pattern) or "", member_dirs):
            if target == base or target in excluded or any(d["path"] == target for d in drives):
                continue
            drives.append(_drive(target, "workspace_member", f"{declaring}:{line}"))
    for drive in [d for d in drives if d["via"] == "workspace_member"]:
        member = (drive["path"] + "/package.json") if drive["path"] != "." else "package.json"
        member_text = descriptors.get(member)
        member_document, _error = _json(member_text) if member_text is not None else (None, None)
        name = str(member_document.get("name")) if isinstance(member_document, Mapping) and member_document.get("name") else posixpath.basename(drive["path"])
        evidence = f"{member}:{(_line_of(member_text, '\"name\"') if member_text else None) or 1}"
        points.append(_point(name, "workspace_member", evidence, path=drive["path"], descriptor=member,
                             sources=_member_sources(drive["path"], inventory, MEMBER_SOURCE_SUFFIXES["node"])))
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": []}


_GRADLE_INCLUDE = re.compile(r"(?<![\w.])include\s*\(?\s*((?:['\"]:?[\w:.-]+['\"]\s*,?\s*)+)\)?")
_GRADLE_NATIVE_PLUGINS = re.compile(r"['\"](?:cpp-library|cpp-application|c|cpp|swift-library|swift-application)['\"]|"
                                    r"\bid\s*\(?\s*['\"](?:cpp-library|cpp-application)['\"]")


def gradle_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    points: list[dict[str, Any]] = []
    drives: list[dict[str, Any]] = []
    settings = next((p for p in sorted(descriptors) if posixpath.basename(p) in {"settings.gradle", "settings.gradle.kts"}
                     and (posixpath.dirname(p) or ".") == root), None)
    if settings:
        text = descriptors[settings]
        for match in _GRADLE_INCLUDE.finditer(text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            if "//" in text[line_start:match.start()]:
                continue
            for module in re.findall(r"['\"]:?([\w:.-]+)['\"]", match.group(1)):
                path = _norm(root, module.replace(":", "/"))
                line = _line_at(text, match.start())
                descriptor = next((p for p in (f"{path}/build.gradle", f"{path}/build.gradle.kts") if path and p in inventory), None)
                languages: list[str] = []
                sources = _member_sources(path, inventory, MEMBER_SOURCE_SUFFIXES["java"]) if path else []
                if descriptor and descriptor in descriptors and _GRADLE_NATIVE_PLUGINS.search(descriptors[descriptor]):
                    languages = ["c++"]
                    sources = sorted(set(sources) | set(_member_sources(path, inventory, _NATIVE_MEMBER_SUFFIXES)))
                points.append(_point(module, "project", f"{settings}:{line}", path=path, descriptor=descriptor,
                                     sources=sources, language=languages[0] if languages else None))
                if path:
                    drives.append(_drive(path, "settings_include", f"{settings}:{line}"))
    build = next((p for p in sorted(descriptors) if posixpath.basename(p) in {"build.gradle", "build.gradle.kts"}
                  and (posixpath.dirname(p) or ".") == root), None)
    if build and not points:
        points.append(_point(posixpath.basename(root) if root != "." else "root", "project", f"{build}:1"))
    for path in sorted(descriptors):
        if posixpath.basename(path) in {"build.gradle", "build.gradle.kts"}:
            for match in re.finditer(r"externalNativeBuild\s*\{[^}]*?cmake\s*\{[^}]*?path\s*[=(]?\s*(?:file\()?['\"]([^'\"]+)['\"]", descriptors[path], re.S):
                target = _norm(posixpath.dirname(path) or ".", posixpath.dirname(match.group(1)) or ".")
                drives.append(_drive(target or match.group(1), "externalNativeBuild",
                                     f"{path}:{_line_at(descriptors[path], match.start())}", unresolved=target is None))
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": []}


def maven_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    pom = (root + "/pom.xml") if root != "." else "pom.xml"
    points: list[dict[str, Any]] = []
    drives: list[dict[str, Any]] = []
    if pom in descriptors:
        text = descriptors[pom]
        artifact = re.search(r"<artifactId>([^<]+)</artifactId>", text)
        points.append(_point(artifact.group(1) if artifact else "pom", "project", f"{pom}:{_line_at(text, artifact.start()) if artifact else 1}"))
        for match in re.finditer(r"<module>([^<]+)</module>", text):
            target = _norm(root, match.group(1))
            if target:
                line = _line_at(text, match.start())
                descriptor = f"{target}/pom.xml"
                points.append(_point(match.group(1).strip().strip("/"), "module", f"{pom}:{line}", path=target,
                                     descriptor=descriptor if descriptor in inventory else None,
                                     sources=_member_sources(target, inventory, MEMBER_SOURCE_SUFFIXES["java"])))
                drives.append(_drive(target, "pom_module", f"{pom}:{line}"))
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": []}


_SLN_PROJECT = re.compile(r'^Project\("\{[0-9A-Fa-f-]+\}"\)\s*=\s*"([^"]+)"\s*,\s*"([^"]+)"', re.M)
_MSBUILD_PROJECT_SUFFIXES = (".vcxproj", ".csproj", ".vbproj", ".fsproj", ".vcproj")


_PROJECT_LANGUAGE = {".vcxproj": "c++", ".vcproj": "c++", ".csproj": "c#", ".vbproj": "vb", ".fsproj": "f#"}


def _msbuild_project_items(path: str, text: str, inventory: Sequence[str]) -> tuple[list[str], list[str]]:
    base = posixpath.dirname(path) or "."
    sources: list[str] = []
    for match in re.finditer(r"<(?:ClCompile|ClInclude|Compile|None)\s+Include=\"([^\"]+)\"", text):
        target = _norm(base, match.group(1).replace("\\", "/"))
        if target:
            sources.extend(_expand(target, inventory))
    if path.endswith((".csproj", ".vbproj", ".fsproj")) and "Sdk=" in text and not sources:
        suffix = {".csproj": ".cs", ".vbproj": ".vb", ".fsproj": ".fs"}[posixpath.splitext(path)[1]]
        sources = _member_sources(base, inventory, {suffix})
    configurations = sorted(set(re.findall(r'<ProjectConfiguration Include="([^"]+)"', text)))
    return sorted(dict.fromkeys(sources)), configurations


def msbuild_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    points: list[dict[str, Any]] = []
    drives: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    listed: set[str] = set()
    for path in sorted(p for p in descriptors if p.lower().endswith(".sln")):
        text = descriptors[path]
        base = posixpath.dirname(path) or "."
        for match in _SLN_PROJECT.finditer(text):
            project_path = _norm(base, match.group(2).replace("\\", "/"))
            line = _line_at(text, match.start())
            if project_path and project_path in inventory and project_path.lower().endswith(_MSBUILD_PROJECT_SUFFIXES):
                listed.add(project_path)
                sources, configurations = _msbuild_project_items(project_path, descriptors[project_path], inventory) \
                    if project_path in descriptors else ([], [])
                points.append(_point(match.group(1), "project", f"{path}:{line}", sources=sources,
                                     path=posixpath.dirname(project_path) or ".", descriptor=project_path,
                                     configurations=configurations or None,
                                     language=_PROJECT_LANGUAGE.get(posixpath.splitext(project_path)[1].lower())))
                drives.append(_drive(posixpath.dirname(project_path) or ".", "solution_project", f"{path}:{line}", project=project_path))
            elif project_path and project_path.lower().endswith(_MSBUILD_PROJECT_SUFFIXES):
                unresolved.append({"evidence": f"{path}:{line}", "kind": "missing_project",
                                   "reason": f"solution lists a project that is not in the target: {match.group(2)}"})
    for path in sorted(p for p in descriptors if p.lower().endswith(_MSBUILD_PROJECT_SUFFIXES) and p not in listed):
        # A project no solution lists: its own file is the unit's marker and its one point, named by
        # <ProjectName> when present (that line is the evidence), else by the file stem at line 1.
        text = descriptors[path]
        sources, configurations = _msbuild_project_items(path, text, inventory)
        named = re.search(r"<ProjectName>([^<]+)</ProjectName>", text)
        name = named.group(1).strip() if named else posixpath.splitext(posixpath.basename(path))[0]
        evidence = f"{path}:{_line_at(text, named.start())}" if named else f"{path}:1"
        points.append(_point(name, "project", evidence, sources=sources, configurations=configurations or None,
                             language=_PROJECT_LANGUAGE.get(posixpath.splitext(path)[1].lower())))
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": unresolved}


def meson_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    points: list[dict[str, Any]] = []
    drives: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    for path in sorted(p for p in descriptors if posixpath.basename(p) == "meson.build"):
        text = descriptors[path]
        base = posixpath.dirname(path) or "."
        for match in re.finditer(r"(executable|library|shared_library|static_library|both_libraries|shared_module)\s*\(\s*'([^']+)'\s*,([^)]*)\)", text, re.S):
            kind = {"executable": "executable", "library": "library", "shared_library": "shared_library",
                    "static_library": "static_library", "both_libraries": "library", "shared_module": "module_library"}[match.group(1)]
            sources = []
            for token in re.findall(r"'([^']+)'", match.group(3)):
                target = _norm(base, token)
                if target and target in inventory:
                    sources.append(target)
            points.append(_point(match.group(2), kind, f"{path}:{_line_at(text, match.start())}", sources=sources))
        for match in re.finditer(r"subdir\s*\(\s*'([^']+)'\s*\)", text):
            target = _norm(base, match.group(1))
            drives.append(_drive(target or match.group(1), "subdir", f"{path}:{_line_at(text, match.start())}", unresolved=target is None))
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": unresolved}


def autotools_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    points: list[dict[str, Any]] = []
    drives: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    for path in sorted(p for p in descriptors if posixpath.basename(p) in {"Makefile.am", "configure.ac", "configure.in"}):
        text = descriptors[path]
        base = posixpath.dirname(path) or "."
        if posixpath.basename(path) == "Makefile.am":
            assigns = {m.group(1): m.group(2) for m in re.finditer(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\+?=\s*((?:[^\\\n]|\\\n)*)$", text, re.M)}
            for variable, kind in (("bin_PROGRAMS", "program"), ("noinst_PROGRAMS", "program"), ("lib_LTLIBRARIES", "libtool_library"),
                                   ("lib_LIBRARIES", "static_library"), ("noinst_LTLIBRARIES", "libtool_library"), ("check_PROGRAMS", "test_program")):
                for target_name in assigns.get(variable, "").replace("\\\n", " ").split():
                    key = re.sub(r"[^A-Za-z0-9_]", "_", target_name) + "_SOURCES"
                    sources = [t for t in (_norm(base, token) for token in assigns.get(key, "").replace("\\\n", " ").split()) if t and t in inventory]
                    points.append(_point(target_name, kind, f"{path}:{_line_of(text, variable) or 1}", sources=sources))
            for sub in assigns.get("SUBDIRS", "").replace("\\\n", " ").split():
                target = _norm(base, sub)
                if target and target != base:
                    drives.append(_drive(target, "SUBDIRS", f"{path}:{_line_of(text, 'SUBDIRS') or 1}"))
            # Hand-written rules in a Makefile.am (all-local, a vendored build) are rules like Make's.
            rules, rule_drives, _includes, rule_unresolved = _make_rules(root, path, text, inventory, automake=True)
            points.extend(rules)
            drives.extend(rule_drives)
            unresolved.extend(rule_unresolved)
        else:
            for match in re.finditer(r"AC_CONFIG_SUBDIRS\(\[?([^\])]+)\]?\)", text):
                for sub in match.group(1).split():
                    target = _norm(base, sub)
                    if target:
                        drives.append(_drive(target, "AC_CONFIG_SUBDIRS", f"{path}:{_line_at(text, match.start())}"))
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": unresolved}


def xcode_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    points = []
    for path in sorted(p for p in descriptors if posixpath.basename(p) == "project.pbxproj"):
        text = descriptors[path]
        for match in re.finditer(r"isa = PBXNativeTarget;.*?name = \"?([^\";]+)\"?;.*?productType = \"([^\"]+)\"", text, re.S):
            points.append(_point(match.group(1).strip(), "native_target", f"{path}:{_line_at(text, match.start())}",
                                 product_type=match.group(2)))
    return {"build_points": points, "drives": [], "includes": [], "unresolved": []}


def package_build_points(kind: str):
    def extract(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
        manifest = sorted(descriptors)[0] if descriptors else None
        name = posixpath.basename(root) if root != "." else "root"
        if manifest:
            match = re.search(r'"name"\s*:\s*"([^"]+)"|^name\s*=\s*"([^"]+)"', descriptors[manifest], re.M)
            if match:
                name = match.group(1) or match.group(2)
        return {"build_points": [_point(name, kind, f"{manifest}:1")] if manifest else [], "drives": [], "includes": [], "unresolved": []}
    return extract


EXTRACTORS: dict[str, Callable[[str, Mapping[str, str], Sequence[str]], dict[str, Any]]] = {
    "cmake": cmake_build_points, "make": make_build_points, "autotools": autotools_build_points,
    "meson": meson_build_points, "cargo": cargo_build_points, "go": go_build_points,
    "node": node_build_points, "npm": node_build_points, "pnpm": node_build_points, "yarn": node_build_points,
    "gradle": gradle_build_points, "maven": maven_build_points, "msbuild": msbuild_build_points,
    "dotnet": msbuild_build_points, "vcbuild": msbuild_build_points, "xcodebuild": xcode_build_points,
    "composer": package_build_points("package"), "pip": package_build_points("package"),
    "python": package_build_points("package"), "phpize": package_build_points("extension"),
    "wasm": package_build_points("wasm_module"), "unity": package_build_points("player"),
}

# Which drives fold a driven unit of the same build system into the driver (plan §2.1 decision 1).
# ``invokes:<tool>`` never folds: the driven tree is another build system's unit, recorded ``driven_by``.
FOLDING_VIAS = frozenset({"add_subdirectory", "FetchContent", "ExternalProject_Add", "recursive_make", "subdir",
                          "SUBDIRS", "AC_CONFIG_SUBDIRS", "solution_project", "settings_include", "workspace_member",
                          "go_work_use", "pom_module"})
# The build systems a fold may join: the driven unit's system must be one the driver's system reads.
FOLDABLE_SYSTEMS: dict[str, frozenset[str]] = {
    "cmake": frozenset({"cmake"}), "make": frozenset({"make"}), "meson": frozenset({"meson"}),
    "autotools": frozenset({"autotools", "make"}), "msbuild": frozenset({"msbuild", "dotnet", "vcbuild"}),
    "dotnet": frozenset({"msbuild", "dotnet", "vcbuild"}), "vcbuild": frozenset({"msbuild", "dotnet", "vcbuild"}),
    "gradle": frozenset({"gradle"}), "maven": frozenset({"maven"}), "cargo": frozenset({"cargo"}),
    "go": frozenset({"go"}), "node": frozenset({"node"}),
}


def extract_build_points(unit: Mapping[str, Any], descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    """Build points, drives, includes and unresolved constructs for one unit; empty when no extractor."""
    extractor = EXTRACTORS.get(str(unit.get("build_system")))
    if extractor is None:
        return {"build_points": [], "drives": [], "includes": [], "unresolved": []}
    return extractor(str(unit["root"]), descriptors, inventory)
