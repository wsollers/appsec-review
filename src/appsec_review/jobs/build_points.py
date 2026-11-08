"""Build points: the named things a build system builds, read from a unit's descriptors.

``docs/plans/build-discovery-test-program-2026-11-08.md`` §1–2 and T-056.2. A build point is a CMake
target, a Make rule, a project a ``.sln`` lists, a Cargo package or binary, a Gradle module, a Go
``main`` package, an npm script, a meson executable or library, an automake program or library, an
Xcode native target, a package. Each carries its kind, the descriptor line that establishes it
(``path:line``), the target-relative sources it names (literal paths and expanded globs), the include
directories it declares, the directories it drives (``add_subdirectory``, ``$(MAKE) -C``, ``subdir``,
``include``d modules) and, when the declaration sits inside a condition, that condition's text.

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


# ----------------------------------------------------------------------------- CMake

_CMAKE_CALL = re.compile(r"([A-Za-z_][A-Za-z_0-9]*)[ \t\r\n]*\(")
_CMAKE_SOURCE_LIKE = re.compile(r"\.(?:c|cc|cpp|cxx|m|mm|s|asm|cu|h|hh|hpp|hxx|inl|ipp)$", re.I)


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


def cmake_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    """Targets, subdirectories, includes, presets and unresolved constructs of one CMake unit."""
    points: list[dict[str, Any]] = []
    drives: list[dict[str, Any]] = []
    includes: list[str] = []
    unresolved: list[dict[str, Any]] = []
    variables: dict[str, list[str]] = {}
    by_name: dict[str, dict[str, Any]] = {}
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
                target = _norm(base, args[0])
                drives.append({"path": target or args[0], "via": "add_subdirectory", "evidence": evidence,
                               **({"condition": condition} if condition else {}), **({} if target else {"unresolved": True})})
                continue
            if name == "include" and args:
                target = _norm(base, args[0])
                if target is not None and target in inventory:
                    includes.append(target)
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
                continue
            if name == "target_sources" and len(args) >= 2 and args[0] in by_name:
                point = by_name[args[0]]
                point["sources"] = sorted(set(point["sources"]) | set(
                    _cmake_sources(base, args[1:], variables, inventory, unresolved, evidence)))
                continue
            if name == "target_include_directories" and len(args) >= 2 and args[0] in by_name:
                dirs = [_norm(base, a) for a in args[1:] if a.upper() not in {"PUBLIC", "PRIVATE", "INTERFACE", "SYSTEM", "BEFORE", "AFTER"}]
                point = by_name[args[0]]
                point["include_dirs"] = sorted(set(point["include_dirs"]) | {d for d in dirs if d})
                continue
            if name == "project" and args:
                variables.setdefault("PROJECT_NAME", [args[0]])
            if name in {"add_custom_command", "execute_process", "configure_file"}:
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


def make_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    """Rules, sub-makes, includes and conditions of one Make unit, with the sources each rule names."""
    points: list[dict[str, Any]] = []
    drives: list[dict[str, Any]] = []
    includes: list[str] = []
    unresolved: list[dict[str, Any]] = []
    for path in sorted(descriptors):
        text = descriptors[path]
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
                if inner in {"CC", "CXX", "MAKE", "RM", "AR", "CFLAGS", "CXXFLAGS", "LDFLAGS", "LDLIBS", "CPPFLAGS"}:
                    return ""
                unresolved.append({"evidence": f"{path}", "reason": f"variable $({inner}) is not a literal assignment"})
                return ""
            return re.sub(r"\$\(([^()]*)\)", repl, value)

        for match in _MAKE_INCLUDE.finditer(text):
            for token in expand(match.group(1)).split():
                target = _norm(base, token)
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
                    unresolved.append({"evidence": f"{path}:{text.count(chr(10), 0, match.start()) + 1}", "reason": "pattern rule"})
                continue
            line = text.count("\n", 0, match.start()) + 1
            recipe_lines = []
            index = line  # lines are 1-based; recipe follows the rule line
            while index < len(lines) and lines[index].startswith("\t"):
                recipe_lines.append(lines[index][1:])
                index += 1
            recipe = "\n".join(recipe_lines)
            raw = prereqs + "\n" + recipe
            expanded = expand(raw)
            for sub in _MAKE_SUBMAKE.finditer(raw):
                target = _norm(base, expand(sub.group(1)))
                drives.append({"path": target or sub.group(1), "via": "recursive_make", "evidence": f"{path}:{line}",
                               **({"condition": line_conditions.get(line)} if line_conditions.get(line) else {}),
                               **({} if target else {"unresolved": True})})
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
                kind = "rule"
                if not recipe_lines and not sources and _MAKE_SUBMAKE.search(raw) is None:
                    kind = "phony_or_aggregate"
                point = _point(target_name, kind, f"{path}:{line}", sources=sources, include_dirs=include_dirs,
                               condition=line_conditions.get(line))
                point["headers"] = _headers_under(include_dirs, inventory) if include_dirs else []
                if recipe_lines and not sources and _MAKE_SUBMAKE.search(raw):
                    point["kind"] = "delegating"
                points.append(point)
    return {"build_points": points, "drives": drives, "includes": sorted(set(includes)), "unresolved": unresolved}


# ----------------------------------------------------------------------------- others

def cargo_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    import tomllib
    manifest = next((p for p in descriptors if posixpath.basename(p) == "Cargo.toml"), None)
    if manifest is None:
        return {"build_points": [], "drives": [], "includes": [], "unresolved": []}
    try:
        document = tomllib.loads(descriptors[manifest])
    except tomllib.TOMLDecodeError as exc:
        return {"build_points": [], "drives": [], "includes": [], "unresolved": [{"evidence": manifest, "reason": f"Cargo.toml: {exc}"}]}
    points = []
    package = document.get("package", {}) if isinstance(document.get("package"), Mapping) else {}
    line = _line_of(descriptors[manifest], "[package]") or 1
    srcs = [p for p in inventory if p.startswith((root + "/src/") if root != "." else "src/") and p.endswith(".rs")]
    if package.get("name"):
        lib = document.get("lib") if isinstance(document.get("lib"), Mapping) else {}
        lib_path = _norm(root, str(lib.get("path", "src/lib.rs")))
        if lib_path in inventory or lib:
            points.append(_point(str(lib.get("name", package["name"])), "lib", f"{manifest}:{_line_of(descriptors[manifest], '[lib]') or line}",
                                 sources=[s for s in srcs if s != _norm(root, 'src/main.rs')]))
        main = _norm(root, "src/main.rs")
        if main in inventory:
            points.append(_point(str(package["name"]), "bin", f"{manifest}:{line}", sources=srcs))
        for index, binary in enumerate(document.get("bin", []) if isinstance(document.get("bin"), list) else []):
            if isinstance(binary, Mapping) and binary.get("name"):
                path = _norm(root, str(binary.get("path", f"src/bin/{binary['name']}.rs")))
                points.append(_point(str(binary["name"]), "bin", f"{manifest}:{_line_of(descriptors[manifest], '[[bin]]', index) or line}",
                                     sources=[path] if path in inventory else []))
        build = package.get("build")
        if build is None and _norm(root, "build.rs") in inventory:
            build = "build.rs"  # Cargo's implicit build script
        if build:
            path = _norm(root, str(build))
            points.append(_point("build-script", "build_script", f"{manifest}:{_line_of(descriptors[manifest], 'build') or line}",
                                 sources=[path] if path in inventory else []))
    drives = []
    workspace = document.get("workspace") if isinstance(document.get("workspace"), Mapping) else None
    if workspace:
        for member in workspace.get("members", []):
            for target in _expand(_norm(root, str(member)) or "", [posixpath.dirname(p) for p in inventory if posixpath.basename(p) == "Cargo.toml"]):
                drives.append({"path": target, "via": "workspace_member", "evidence": f"{manifest}:{_line_of(descriptors[manifest], '[workspace]') or 1}"})
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": []}


def go_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    prefix = "" if root == "." else root + "/"
    go_files = [p for p in inventory if p.startswith(prefix) and p.endswith(".go") and "/vendor/" not in "/" + p[len(prefix):]
                and "/testdata/" not in "/" + p[len(prefix):]]
    by_dir: dict[str, list[str]] = {}
    for path in go_files:
        by_dir.setdefault(posixpath.dirname(path) or ".", []).append(path)
    points = []
    mod = next((p for p in descriptors if posixpath.basename(p) == "go.mod"), None)
    for directory in sorted(by_dir):
        texts = [descriptors.get(p) for p in by_dir[directory]]
        is_main = any(t and re.search(r"^\s*package\s+main\b", t, re.M) for t in texts)
        rel = directory[len(prefix):] if directory != root else "."
        kind = "main_package" if is_main else "package"
        evidence = f"{mod}:1" if mod else f"{by_dir[directory][0]}:1"
        points.append(_point(rel, kind, evidence, sources=by_dir[directory]))
    drives = []
    work = next((p for p in descriptors if posixpath.basename(p) == "go.work"), None)
    if work:
        for match in re.finditer(r"^\s*use\s*(?:\(\s*([^)]*)\)|(\S+))", descriptors[work], re.M | re.S):
            for token in (match.group(1).split() if match.group(1) else [match.group(2)]):
                target = _norm(root, token.split("//", 1)[0].strip())
                if target:
                    drives.append({"path": target, "via": "go_work_use", "evidence": f"{work}:{descriptors[work].count(chr(10), 0, match.start()) + 1}"})
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": []}


def node_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    import json
    manifest = next((p for p in descriptors if posixpath.basename(p) == "package.json"), None)
    if manifest is None:
        return {"build_points": [], "drives": [], "includes": [], "unresolved": []}
    try:
        document = json.loads(descriptors[manifest])
    except ValueError as exc:
        return {"build_points": [], "drives": [], "includes": [], "unresolved": [{"evidence": manifest, "reason": f"package.json: {exc}"}]}
    points = []
    scripts = document.get("scripts") if isinstance(document.get("scripts"), Mapping) else {}
    for name in sorted(scripts):
        points.append(_point(str(name), "script", f"{manifest}:{_line_of(descriptors[manifest], f'\"{name}\"') or 1}",
                             command=str(scripts[name])))
    if document.get("name") and not scripts:
        points.append(_point(str(document["name"]), "package", f"{manifest}:1"))
    drives = []
    for pattern in (document.get("workspaces") if isinstance(document.get("workspaces"), list) else
                    (document.get("workspaces", {}).get("packages", []) if isinstance(document.get("workspaces"), Mapping) else [])):
        for target in _expand(_norm(root, str(pattern)) or "", [posixpath.dirname(p) for p in inventory if posixpath.basename(p) == "package.json"]):
            if target != root:
                drives.append({"path": target, "via": "workspace_member", "evidence": f"{manifest}:{_line_of(descriptors[manifest], 'workspaces') or 1}"})
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": []}


def gradle_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    points, drives = [], []
    settings = next((p for p in descriptors if posixpath.basename(p) in {"settings.gradle", "settings.gradle.kts"}), None)
    if settings:
        for match in re.finditer(r"include\s*\(?\s*((?:['\"]:?[\w:.-]+['\"]\s*,?\s*)+)\)?", descriptors[settings]):
            for module in re.findall(r"['\"]:?([\w:.-]+)['\"]", match.group(1)):
                path = _norm(root, module.replace(":", "/"))
                line = descriptors[settings].count("\n", 0, match.start()) + 1
                points.append(_point(":" + module, "module", f"{settings}:{line}"))
                if path:
                    drives.append({"path": path, "via": "settings_include", "evidence": f"{settings}:{line}"})
    build = next((p for p in descriptors if posixpath.basename(p) in {"build.gradle", "build.gradle.kts"}), None)
    if build and not points:
        points.append(_point(posixpath.basename(root) if root != "." else "root", "project", f"{build}:1"))
    for path in descriptors:
        if posixpath.basename(path) in {"build.gradle", "build.gradle.kts"}:
            for match in re.finditer(r"externalNativeBuild\s*\{[^}]*?cmake\s*\{[^}]*?path\s*[=(]?\s*(?:file\()?['\"]([^'\"]+)['\"]", descriptors[path], re.S):
                target = _norm(posixpath.dirname(path) or ".", posixpath.dirname(match.group(1)) or ".")
                drives.append({"path": target or match.group(1), "via": "externalNativeBuild",
                               "evidence": f"{path}:{descriptors[path].count(chr(10), 0, match.start()) + 1}"})
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": []}


def maven_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    pom = next((p for p in descriptors if posixpath.basename(p) == "pom.xml"), None)
    points, drives = [], []
    if pom:
        text = descriptors[pom]
        artifact = re.search(r"<artifactId>([^<]+)</artifactId>", text)
        points.append(_point(artifact.group(1) if artifact else "pom", "project", f"{pom}:{text.count(chr(10), 0, artifact.start()) + 1 if artifact else 1}"))
        for match in re.finditer(r"<module>([^<]+)</module>", text):
            target = _norm(root, match.group(1))
            if target:
                drives.append({"path": target, "via": "pom_module", "evidence": f"{pom}:{text.count(chr(10), 0, match.start()) + 1}"})
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": []}


_SLN_PROJECT = re.compile(r'^Project\("\{[0-9A-Fa-f-]+\}"\)\s*=\s*"([^"]+)"\s*,\s*"([^"]+)"', re.M)


def msbuild_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    points, drives, unresolved = [], [], []
    for path in sorted(descriptors):
        text = descriptors[path]
        name = posixpath.basename(path).lower()
        base = posixpath.dirname(path) or "."
        if name.endswith(".sln"):
            for match in _SLN_PROJECT.finditer(text):
                project_path = _norm(base, match.group(2).replace("\\", "/"))
                line = text.count("\n", 0, match.start()) + 1
                if project_path and project_path in inventory:
                    points.append(_point(match.group(1), "solution_project", f"{path}:{line}", project=project_path))
                    drives.append({"path": posixpath.dirname(project_path) or ".", "via": "solution_project", "evidence": f"{path}:{line}", "project": project_path})
                else:
                    unresolved.append({"evidence": f"{path}:{line}", "reason": f"solution lists a project that is not in the target: {match.group(2)}"})
        elif name.endswith((".vcxproj", ".csproj", ".vbproj", ".fsproj")):
            kind = "vcxproj" if name.endswith(".vcxproj") else "msbuild_project"
            sources = []
            for match in re.finditer(r"<(?:ClCompile|ClInclude|Compile|None)\s+Include=\"([^\"]+)\"", text):
                target = _norm(base, match.group(1).replace("\\", "/"))
                if target:
                    sources.extend(_expand(target, inventory))
            if name.endswith(".csproj") and "Sdk=" in text and not sources:
                sources = [p for p in inventory if p.startswith(base + "/" if base != "." else "") and p.endswith(".cs")
                           and "/obj/" not in p and "/bin/" not in p]
            configurations = sorted(set(re.findall(r'<ProjectConfiguration Include="([^"]+)"', text)))
            point = _point(posixpath.splitext(posixpath.basename(path))[0], kind, f"{path}:1", sources=sources,
                           configurations=configurations or None)
            points.append(point)
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": unresolved}


def meson_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    points, drives, unresolved = [], [], []
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
            points.append(_point(match.group(2), kind, f"{path}:{text.count(chr(10), 0, match.start()) + 1}", sources=sources))
        for match in re.finditer(r"subdir\s*\(\s*'([^']+)'\s*\)", text):
            target = _norm(base, match.group(1))
            drives.append({"path": target or match.group(1), "via": "subdir", "evidence": f"{path}:{text.count(chr(10), 0, match.start()) + 1}"})
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": unresolved}


def autotools_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    points, drives = [], []
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
                    drives.append({"path": target, "via": "SUBDIRS", "evidence": f"{path}:{_line_of(text, 'SUBDIRS') or 1}"})
        else:
            for match in re.finditer(r"AC_CONFIG_SUBDIRS\(\[?([^\])]+)\]?\)", text):
                for sub in match.group(1).split():
                    target = _norm(base, sub)
                    if target:
                        drives.append({"path": target, "via": "AC_CONFIG_SUBDIRS", "evidence": f"{path}:{text.count(chr(10), 0, match.start()) + 1}"})
    return {"build_points": points, "drives": drives, "includes": [], "unresolved": []}


def xcode_build_points(root: str, descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    points = []
    for path in sorted(p for p in descriptors if posixpath.basename(p) == "project.pbxproj"):
        text = descriptors[path]
        for match in re.finditer(r"isa = PBXNativeTarget;.*?name = \"?([^\";]+)\"?;.*?productType = \"([^\"]+)\"", text, re.S):
            points.append(_point(match.group(1).strip(), "native_target", f"{path}:{text.count(chr(10), 0, match.start()) + 1}",
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


def _line_of(text: str, needle: str, occurrence: int = 0) -> int | None:
    start = -1
    for _ in range(occurrence + 1):
        start = text.find(needle, start + 1)
        if start < 0:
            return None
    return text.count("\n", 0, start) + 1


def extract_build_points(unit: Mapping[str, Any], descriptors: Mapping[str, str], inventory: Sequence[str]) -> dict[str, Any]:
    """Build points, drives, includes and unresolved constructs for one unit; empty when no extractor."""
    extractor = EXTRACTORS.get(str(unit.get("build_system")))
    if extractor is None:
        return {"build_points": [], "drives": [], "includes": [], "unresolved": []}
    return extractor(str(unit["root"]), descriptors, inventory)
