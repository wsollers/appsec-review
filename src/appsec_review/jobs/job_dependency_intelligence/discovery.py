"""Bounded native identity observations over a finite, authenticated input catalog."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import fields
import hashlib
from pathlib import PurePosixPath
import re
from typing import Any

from appsec_review.storage import canonical_json

from .native import _build_context, _name_from_file
from .native_sbom_contracts import (
    DISCOVERY_COUNTERS, DISCOVERY_SCHEMA, Claim, CoverageGap, DiscoveryResult, NativeBounds,
    NativeCandidate, NativeEvidence, NativeFile, NativeInputIntegrityError,
    candidate_identity, evidence_identity,
)
from .resolution import repository_identity


_HASH = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+\-]{0,255}")
_VERSION = r"\d+(?:\.\d+){0,3}(?:[-+][A-Za-z0-9][A-Za-z0-9_.+\-]*)?"
_VENDOR = frozenset({"vendor", "vendors", "third_party", "third-party", "external",
                     "deps", "dependencies"})
_HEADERS = frozenset({".h", ".hh", ".hpp", ".hxx", ".inc"})
_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")
_KNOWN = {
    "ZLIB_VERSION": "zlib", "SQLITE_VERSION": "sqlite",
    "OPENSSL_VERSION_STR": "openssl", "OPENSSL_VERSION_TEXT": "openssl",
    "PNG_LIBPNG_VER_STRING": "libpng", "BOOST_LIB_VERSION": "boost", "BOOST_VERSION": "boost",
}
_PATH_FLAGS = ("-isystem", "-iquote", "-idirafter", "-I", "-L", "/external:I", "/LIBPATH:", "/I")
_OUTPUT_FLAGS = ("-o", "--output", "/Fo", "/Fe", "/Fd", "/OUT:")
_DIRECTIVE = re.compile(r"^\s*#\s*(\w+)\b(.*)")
_DEFINE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s+(.+?)\s*$")


def _relative(value: object, *, dot: bool = False) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise ValueError("native logical path must be a nonempty canonical relative path")
    if value == "." and dot:
        return value
    parts = value.split("/")
    if ("\\" in value or ":" in value or any(part in {"", ".", ".."} for part in parts)
            or value.startswith("/")):
        raise ValueError("native logical path must be a canonical relative POSIX path")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise ValueError(f"{label} must be a nonempty string without control characters")
    return value


def _reference(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("native artifact reference is required")
    _relative(value.get("path"))
    if not isinstance(value.get("sha256"), str) or not _HASH.fullmatch(value["sha256"]):
        raise ValueError("native artifact reference has an invalid sha256")
    if type(value.get("size_bytes")) is not int or value["size_bytes"] < 0:
        raise ValueError("native artifact reference has an invalid size_bytes")
    return value


def _domain(row: Mapping[str, Any]) -> str:
    domain = row.get("domain", "target" if row.get("root_id") == "target" else "workspace")
    if not isinstance(domain, str) or domain not in {"target", "workspace"}:
        raise ValueError("native domain must be target or workspace")
    return domain


def _pointer(value: object) -> str:
    if not isinstance(value, str) or (value and not value.startswith("/")):
        raise ValueError("evidence_source requires a JSON pointer")
    if re.search(r"~(?![01])", value) or any(ord(char) < 32 for char in value):
        raise ValueError("evidence_source has an invalid JSON pointer")
    return value


def _source(row: Mapping[str, Any]) -> None:
    source = row.get("evidence_source")
    if not isinstance(source, Mapping):
        raise ValueError("native command/artifact requires evidence_source")
    _reference(source.get("artifact"))
    _pointer(source.get("json_pointer"))
    _text(row.get("root_id"), "root_id")
    _domain(row)
    for key in ("command_id", "artifact_id"):
        if row.get(key) is not None:
            _text(row[key], key)


def _eligible(path: str) -> bool:
    name = PurePosixPath(path).name.casefold()
    return (PurePosixPath(name).suffix in _HEADERS or name.endswith((".pc", "config.cmake",
                                                                  "-config.cmake"))
            or name.startswith(("license", "copying", "notice", "readme", "version")))


def _within(path: str, root: str) -> bool:
    return root == "." or path == root or path.startswith(root + "/")


def _vendor_root(path: str) -> str | None:
    parts = path.split("/")
    roots = ["/".join(parts[:index + 2]) for index, part in enumerate(parts[:-2])
             if part.casefold() in _VENDOR]
    return roots[-1] if roots else None


def _locality(path: str) -> str:
    vendor = _vendor_root(path)
    if vendor:
        return vendor
    parts = path.split("/")[:-1]
    for index, part in enumerate(parts):
        if index and part.casefold() in {"include", "lib", "lib64", "cmake", "pkgconfig"}:
            return "/".join(parts[:index])
    return "/".join(parts) or "."


def _normalized_name(name: str) -> str:
    return name.strip().casefold().replace("_", "-")


def _option_prefix(value: str, option: str, *, msvc: bool) -> bool:
    if msvc and option.startswith("/"):
        return value.casefold().startswith(option.casefold())
    return value.startswith(option)


class _Discovery:
    def __init__(self, fingerprint: str, bounds: NativeBounds) -> None:
        self.fingerprint = fingerprint
        self.bounds = bounds
        self.metrics = dict.fromkeys(DISCOVERY_COUNTERS, 0)
        self.omissions = dict.fromkeys((field.name for field in fields(bounds)), 0)
        self.evidence: dict[str, NativeEvidence] = {}
        self.gaps: dict[bytes, CoverageGap] = {}
        self.bound_scopes: dict[tuple[str, str], int] = defaultdict(int)
        self.facts: list[dict[str, Any]] = []
        self.support: list[dict[str, Any]] = []
        self.unsupported: set[tuple[str, str, str]] = set()
        self.explicit_roots: dict[tuple[str, str], set[str]] = defaultdict(set)
        self.incomplete: set[tuple[str, str, str]] = set()
        self.release_incomplete: set[tuple[str, str, str]] = set()
        self.version_conflicts: set[tuple[str, str, str]] = set()
        self.conflict_evidence: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        self.allowed_roots: set[tuple[str, str, str]] = set()

    def gap(self, kind: str, scope: str, detail: str, evidence_ids: Sequence[str] = ()) -> None:
        # Detail text is diagnostic, never an identity. Oversized scopes retain an opaque digest.
        if len(scope) > self.bounds.path_chars:
            scope = "scope-" + hashlib.sha256(scope.encode()).hexdigest()
        detail = detail.encode()[:self.bounds.field_bytes].decode("utf-8", errors="ignore")
        gap: CoverageGap = {"kind": kind, "scope": scope, "detail": detail,
                            "evidence_ids": sorted(set(evidence_ids))}
        self.gaps[canonical_json(gap)] = gap

    def omit(self, bound: str, scope: str, count: int = 1) -> None:
        self.omissions[bound] += count
        self.bound_scopes[bound, scope] += count

    def scalar(self, value: str, scope: str, *, path: bool = False) -> bool:
        if path and len(value) > self.bounds.path_chars:
            self.omit("path_chars", scope)
            return False
        if len(value.encode()) > self.bounds.field_bytes:
            self.omit("field_bytes", scope)
            return False
        return True

    def add_evidence(self, record: dict[str, Any]) -> str | None:
        scope = record["path"]
        if (not self.scalar(record["path"], scope, path=True)
                or not self.scalar(record["value"], scope)
                or not self.scalar(record["root_id"], scope)):
            return None
        for key in ("upstream", "backing"):
            ref = record[key]
            if ref and not self.scalar(ref["path"], scope, path=True):
                return None
        pointer = record["selector"].get("json_pointer")
        if pointer is not None and not self.scalar(pointer, scope):
            return None
        identity = evidence_identity(record)
        if identity not in self.evidence:
            if len(self.evidence) >= self.bounds.evidence_limit:
                self.omit("evidence_limit", scope)
                return None
            record["evidence_id"] = identity
            self.evidence[identity] = record
        return identity

    def file_evidence(self, file: NativeFile, kind: str, value: str,
                      span: tuple[int, int, int, int]) -> str | None:
        start, end, first, last = span
        return self.add_evidence({
            "kind": kind, "value": value, "source_fingerprint": self.fingerprint,
            "domain": file["domain"], "root_id": file["root_id"], "path": file["path"],
            "sha256": file["sha256"], "upstream": dict(file["upstream"]),
            "backing": dict(file["backing"]) if file.get("backing") is not None else None,
            "selector": {"start_byte": start, "end_byte": end,
                         "start_line": first, "end_line": last},
        })

    def structured(self, row: Mapping[str, Any], kind: str, value: str, suffix: str) -> str | None:
        source = row["evidence_source"]
        ref = dict(source["artifact"])
        selector = {"json_pointer": source["json_pointer"] + suffix}
        for key in ("command_id", "argv_sha256", "expanded_argv_sha256", "artifact_id"):
            if row.get(key) is not None:
                if not self.scalar(str(row[key]), ref["path"]):
                    return None
                selector[key] = row[key]
        return self.add_evidence({
            "kind": kind, "value": value, "source_fingerprint": self.fingerprint,
            "domain": "run", "root_id": row["root_id"], "path": ref["path"],
            "sha256": ref["sha256"], "upstream": ref, "backing": ref, "selector": selector,
        })

    def fact(self, *, domain: str, root_id: str, root: str, name: str | None,
             evidence_id: str | None, role: str, field: str = "identity",
             value: str | None = None, strong: bool = False,
             observation: Mapping[str, Any] | None = None) -> None:
        if not evidence_id:
            return
        if name is not None and not _NAME.fullmatch(name):
            self.gap("unsupported_metadata", root, "package name is not a supported literal",
                     [evidence_id])
            return
        if not self.scalar(root, root, path=True) or (name and not self.scalar(name, root)):
            return
        if value is not None and not self.scalar(value, root):
            return
        self.facts.append({"domain": domain, "root_id": root_id, "root": root, "name": name,
                           "field": field, "value": value or name, "strong": strong,
                           "role": role, "evidence_id": evidence_id,
                           "observation": dict(observation or {})})

    def mapped_path(self, row: Mapping[str, Any], value: str) -> tuple[str, str, str] | None:
        if not self.scalar(value, row["evidence_source"]["artifact"]["path"], path=True):
            return None
        path = value.replace("\\", "/")
        if not path or "\x00" in path:
            self.gap("unmapped_path", value, "empty or invalid path argument")
            return None
        absolute = path.startswith("/") or re.match(r"^[A-Za-z]:", path)
        if absolute:
            mappings = row.get("path_mappings", {})
            matches = [(prefix, mapped) for prefix, mapped in mappings.items()
                       if path == prefix or path.startswith(prefix.rstrip("/") + "/")]
            if not matches:
                self.gap("unmapped_path", value, "absolute path has no authenticated mapping")
                return None
            prefix, mapped = max(matches, key=lambda item: len(item[0]))
            if isinstance(mapped, str):
                domain, root_id, base = _domain(row), row["root_id"], mapped
            else:
                domain, root_id, base = _domain(mapped), mapped["root_id"], mapped["path"]
            suffix = path[len(prefix):].lstrip("/")
            path = (base.rstrip("/") + "/" + suffix) if base != "." else suffix
        else:
            domain, root_id = _domain(row), row["root_id"]
            base = row.get("directory", ".")
            path = (base + "/" + path) if base != "." else path
        parts: list[str] = []
        for part in path.split("/"):
            if part in {"", "."}:
                continue
            if part == "..":
                if not parts:
                    self.gap("unmapped_path", value, "path escapes authenticated logical root")
                    return None
                parts.pop()
            elif ":" in part or any(ord(char) < 32 for char in part):
                self.gap("unmapped_path", value, "invalid mapped path")
                return None
            else:
                parts.append(part)
        result = "/".join(parts) or "."
        if not self.scalar(result, result, path=True):
            return None
        return domain, root_id, result

    def command(self, row: Mapping[str, Any]) -> None:
        self.metrics["commands_processed"] += 1
        expanded = row.get("expanded_argv")
        argv = expanded if expanded is not None else row["argv"]
        argv_field = "expanded_argv" if expanded is not None else "argv"
        if len(argv) > self.bounds.command_token_limit:
            self.metrics["commands_truncated"] += 1
            self.omit("command_token_limit", row["evidence_source"]["artifact"]["path"],
                      len(argv) - self.bounds.command_token_limit)
            argv = argv[:self.bounds.command_token_limit]
        context = _build_context(row, argv)
        compiler = PurePosixPath(argv[0].replace("\\", "/")).name.casefold().removesuffix(".exe")
        msvc = compiler in {"cl", "clang-cl", "link", "lld-link", "lib"}
        command_root = "@command/" + hashlib.sha256(canonical_json(row["evidence_source"])).hexdigest()[:24]
        self.scalar(argv[0], row["evidence_source"]["artifact"]["path"])
        index = 1
        while index < len(argv):
            value = argv[index]
            suffix = f"/{argv_field}/{index}"
            if not self.scalar(value, row["evidence_source"]["artifact"]["path"]):
                index += 1
                continue
            if value.startswith("@"):
                evidence = self.structured(row, "response_file", value, suffix)
                self.gap("unsupported_response_file", command_root,
                         "response files are not expanded or read", [evidence] if evidence else [])
                index += 1
                continue
            if any(len(value) == len(flag) and _option_prefix(value, flag, msvc=msvc)
                   for flag in _OUTPUT_FLAGS):
                index += 2
                continue
            if (any(_option_prefix(value, flag, msvc=msvc) and len(value) > len(flag)
                    for flag in _OUTPUT_FLAGS if flag.startswith("/"))
                    or value.startswith("--output=") or (value.startswith("-o") and len(value) > 2)):
                index += 1
                continue
            flag = next((flag for flag in _PATH_FLAGS
                         if _option_prefix(value, flag, msvc=msvc)), None)
            if flag:
                path = value[len(flag):]
                if not path and index + 1 < len(argv):
                    index += 1
                    suffix = f"/{argv_field}/{index}"
                    path = argv[index]
                if not path:
                    self.gap("unsupported_metadata", command_root, "path flag has no argument")
                else:
                    evidence = self.structured(row, "path_hint", path, suffix)
                    mapped = self.mapped_path(row, path)
                    if mapped and evidence:
                        domain, root_id, root = mapped
                        root = _vendor_root(root + "/_") or root
                        self.explicit_roots[domain, root_id].add(root)
                        name = PurePosixPath(root).name
                        if name != ".":
                            self.fact(domain=domain, root_id=root_id, root=root, name=name,
                                      role="path", evidence_id=evidence,
                                      observation={"kind": "path_hint", "value": path, **context})
                index += 1
                continue
            names: list[tuple[str, str, str]] = []
            if value in {"-l", "-framework"} and index + 1 < len(argv):
                kind = "link_flag" if value == "-l" else "framework"
                index += 1
                suffix = f"/{argv_field}/{index}"
                names.append((argv[index], kind, argv[index]))
            elif value.startswith("-l:"):
                parsed = _name_from_file(value[3:])
                if parsed:
                    names.append((parsed[0], "exact_library_name", value))
            elif value.startswith("-l") and _NAME.fullmatch(value[2:]):
                names.append((value[2:], "link_flag", value))
            elif value.startswith("-Wl,"):
                parts = value[4:].split(",")
                offset = 0
                while offset < len(parts):
                    part = parts[offset]
                    if part == "-l" and offset + 1 < len(parts):
                        offset += 1
                        names.append((parts[offset], "linker_forwarded_flag", parts[offset]))
                    elif part.startswith("-l:"):
                        parsed = _name_from_file(part[3:])
                        if parsed:
                            names.append((parsed[0], "exact_library_name", part))
                    elif part.startswith("-l") and _NAME.fullmatch(part[2:]):
                        names.append((part[2:], "linker_forwarded_flag", part))
                    offset += 1
            else:
                parsed = _name_from_file(value)
                if parsed:
                    names.append((parsed[0], parsed[1], value))
            for name, kind, literal in names:
                evidence = self.structured(row, kind, literal, suffix)
                domain, root_id, root = _domain(row), row["root_id"], command_root
                if "/" in literal or "\\" in literal:
                    mapped = self.mapped_path(row, literal)
                    if mapped:
                        domain, root_id, path = mapped
                        root = _locality(path)
                self.fact(domain=domain, root_id=root_id, root=root, name=name,
                          role="link", evidence_id=evidence,
                          observation={"kind": kind, "value": literal, **context})
            index += 1

    def artifact(self, row: Mapping[str, Any]) -> None:
        self.metrics["artifacts_inspected"] += 1
        path = row["path"]
        root = _locality(path)
        names = [(row["path"], "artifact_filename", "/path")]
        names.extend((value, "loader_needed", f"/loader_dependencies/{index}")
                     for index, value in enumerate(row.get("loader_dependencies", ()) or ()))
        if row.get("loader_soname"):
            names.append((row["loader_soname"], "soname", "/loader_soname"))
        elif "loader_dependencies" not in row:
            self.gap("unsupported_metadata", path, "accepted artifact has no supported loader metadata")
        for value, kind, suffix in names:
            parsed = _name_from_file(value)
            if not parsed:
                continue
            evidence = self.structured(row, kind, value, suffix)
            self.fact(domain=_domain(row), root_id=row["root_id"], root=root, name=parsed[0],
                      role="artifact", evidence_id=evidence,
                      observation={"kind": kind, "value": value,
                                   "artifact_sha256": row.get("sha256")})

    def file(self, file: NativeFile, data: bytes) -> None:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            self.gap("decode_failed", file["path"], "selected file is not valid UTF-8")
            self.unsupported.add((file["domain"], file["root_id"], file["path"]))
            return
        root = self.file_root(file)
        lines: list[tuple[str, tuple[int, int, int, int]]] = []
        start = 0
        for number, line in enumerate(text.splitlines(keepends=True), 1):
            end = start + len(line.encode("utf-8"))
            lines.append((line, (start, end, number, number)))
            start = end
        if not lines:
            lines.append(("", (0, 0, 1, 1)))
        name = PurePosixPath(file["path"]).name.casefold()
        if _vendor_root(file["path"]):
            evidence = self.file_evidence(file, "vendored_path", file["path"], (0, 0, 1, 1))
            self.fact(domain=file["domain"], root_id=file["root_id"], root=root,
                      name=PurePosixPath(root).name, role="path", evidence_id=evidence)
        if PurePosixPath(name).suffix in _HEADERS:
            self.header(file, root, lines)
        elif name.endswith((".pc", "config.cmake", "-config.cmake")):
            self.metadata(file, root, lines)
        else:
            self.document(file, root, lines)

    def file_root(self, file: NativeFile) -> str:
        root = _locality(file["path"])
        possible = self.explicit_roots[file["domain"], file["root_id"]]
        ancestors = [candidate for candidate in possible
                     if candidate != "." and _within(file["path"], candidate)]
        if ancestors and not _vendor_root(file["path"]):
            root = max([root, *ancestors], key=lambda value: (value.count("/"), value))
        return root

    def select_roots(self, files: Sequence[NativeFile]) -> None:
        roots = {(fact["domain"], fact["root_id"], fact["root"]) for fact in self.facts}
        roots.update((file["domain"], file["root_id"], self.file_root(file)) for file in files
                     if _eligible(file["path"]))
        ordered = sorted(roots)
        self.allowed_roots = set(ordered[:self.bounds.root_limit])
        self.metrics["roots_inspected"] = len(self.allowed_roots)
        for _, _, root in ordered[self.bounds.root_limit:]:
            self.omit("root_limit", root)

    def emit(self, file: NativeFile, root: str, name: str | None, kind: str, literal: str,
             span: tuple[int, int, int, int], *, role: str, release: str | None = None,
             strong: bool = False, upstream: str | None = None, identity: bool = True) -> None:
        evidence = self.file_evidence(file, kind, literal, span)
        if not evidence:
            self.incomplete.add((file["domain"], file["root_id"], root))
        common = {"domain": file["domain"], "root_id": file["root_id"], "root": root,
                  "name": name, "evidence_id": evidence, "role": role, "strong": strong}
        if name and identity:
            self.fact(**common)
        if release:
            self.fact(**common, field="release", value=release)
        if upstream:
            repo = repository_identity(upstream, supported_hosts=_HOSTS)
            if repo:
                self.fact(**{**common, "strong": False}, field="upstream", value=repo["url"])
            elif evidence:
                self.support.append({**common, "evidence_id": evidence})
        elif not name and not release and evidence:
            self.support.append({**common, "evidence_id": evidence})

    def unsupported_file(self, file: NativeFile, detail: str,
                         span: tuple[int, int, int, int], literal: str, *,
                         affects_release: bool = True) -> str | None:
        evidence = self.file_evidence(file, "unsupported_metadata", literal, span)
        self.unsupported.add((file["domain"], file["root_id"], file["path"]))
        if affects_release:
            self.release_incomplete.add((file["domain"], file["root_id"], self.file_root(file)))
        self.gap("unsupported_metadata", file["path"], detail, [evidence] if evidence else [])
        return evidence

    def header(self, file: NativeFile, root: str,
               lines: Sequence[tuple[str, tuple[int, int, int, int]]]) -> None:
        directives = [(index, _DIRECTIVE.match(line)) for index, (line, _) in enumerate(lines)]
        directives = [(index, match) for index, match in directives if match]
        guard = None
        if len(directives) >= 2:
            first, second = directives[0][1], directives[1][1]
            if (first[1] == "ifndef" and second[1] == "define"
                    and first[2].strip() == second[2].strip()
                    and "VERSION" not in first[2].upper()):
                guard = directives[0][0]
        conditions: list[bool] = []
        tuples: dict[str, dict[str, tuple[int, tuple[int, int, int, int], str]]] = defaultdict(dict)
        emitted = False
        for index, (line, span) in enumerate(lines):
            directive = _DIRECTIVE.match(line)
            if directive:
                operator = directive[1]
                if operator in {"if", "ifdef", "ifndef"}:
                    conditions.append(index == guard and not conditions)
                elif operator in {"else", "elif"} and conditions:
                    conditions[-1] = False
                elif operator == "endif" and conditions:
                    conditions.pop()
            match = _DEFINE.match(line)
            if not match:
                continue
            macro, raw = match.groups()
            if macro not in _KNOWN and not re.search(r"(?:^|_)VERSION(?:_|$)", macro):
                continue
            raw = re.sub(r"\s*(?://.*|/\*.*?\*/)\s*$", "", raw).strip()
            affects_release = macro in _KNOWN or bool(re.fullmatch(
                r".+_VERSION(?:_(?:MAJOR|MINOR|PATCH))?", macro))
            if any(not allowed for allowed in conditions):
                self.unsupported_file(file, "conditional version macro is not evaluated", span, line,
                                      affects_release=affects_release)
                continue
            name, version = _KNOWN.get(macro), None
            tuple_match = re.fullmatch(r"(.+)_VERSION_(MAJOR|MINOR|PATCH)", macro)
            if re.fullmatch(r"\d+", raw) and len(raw) > 9:
                self.unsupported_file(file, "numeric version literal exceeds the supported encoding",
                                      span, line, affects_release=affects_release)
                continue
            if tuple_match and re.fullmatch(r"\d+", raw):
                prior = tuples[tuple_match[1]].get(tuple_match[2])
                if prior is not None and prior[0] != int(raw):
                    key = file["domain"], file["root_id"], root
                    self.version_conflicts.add(key)
                    previous = self.file_evidence(file, "macro_version_component", prior[2], prior[1])
                    current = self.unsupported_file(file, "competing literal version tuple components",
                                                    span, line)
                    for evidence in (previous, current):
                        if evidence:
                            self.conflict_evidence[key].add(evidence)
                            self.support.append({"domain": file["domain"], "root_id": file["root_id"],
                                                 "root": root, "evidence_id": evidence})
                tuples[tuple_match[1]][tuple_match[2]] = (int(raw), span, line)
                continue
            if macro == "BOOST_VERSION" and re.fullmatch(r"\d+", raw):
                packed = int(raw)
                version = f"{packed // 100000}.{packed // 100 % 1000}.{packed % 100}"
            elif macro == "BOOST_LIB_VERSION" and re.fullmatch(r'"\d+_\d+(?:_\d+)?"', raw):
                parts = raw.strip('"').split("_")
                version = ".".join([*parts, "0"] if len(parts) == 2 else parts)
            elif macro == "OPENSSL_VERSION_TEXT":
                literal = re.fullmatch(r'"OpenSSL (' + _VERSION + r')(?: [^"\\]*)?"', raw)
                version = literal[1] if literal else None
            else:
                literal = re.fullmatch(r'"(' + _VERSION + r')"', raw)
                if literal:
                    version = literal[1]
                    generic = re.fullmatch(r"(.+)_VERSION", macro)
                    name = name or (generic[1].casefold() if generic else None)
            if name and version:
                self.emit(file, root, name, "macro_version", line, span, role="header",
                          release=version, strong=macro in _KNOWN)
                emitted = True
            else:
                self.unsupported_file(file, "version macro is not a supported literal", span, line,
                                      affects_release=affects_release)
        for prefix, values in sorted(tuples.items()):
            if set(values) != {"MAJOR", "MINOR", "PATCH"}:
                for _, span, line in values.values():
                    self.unsupported_file(file, "incomplete literal version tuple", span, line)
                continue
            ordered = [values[part] for part in ("MAJOR", "MINOR", "PATCH")]
            span = (min(value[1][0] for value in ordered), max(value[1][1] for value in ordered),
                    min(value[1][2] for value in ordered), max(value[1][3] for value in ordered))
            literal = "".join(line for line, location in lines
                              if span[0] <= location[0] and location[1] <= span[1])
            self.emit(file, root, prefix.casefold(), "macro_version_tuple", literal, span,
                      role="header", release=".".join(str(value[0]) for value in ordered))
            emitted = True
        if not emitted:
            name = PurePosixPath(root).name if root != "." else PurePosixPath(file["path"]).stem
            self.emit(file, root, name, "header_path", file["path"], (0, 0, 1, 1), role="path")

    def metadata(self, file: NativeFile, root: str,
                 lines: Sequence[tuple[str, tuple[int, int, int, int]]]) -> None:
        if file["path"].casefold().endswith(".pc"):
            entries = []
            for line, span in lines:
                match = re.match(r"^\s*(Name|Version|URL|Repository)\s*:\s*(.*?)\s*$", line, re.I)
                if match:
                    entries.append((match[1].casefold(), match[2], line, span))
            names = [entry[1] for entry in entries if entry[0] == "name"]
            name = names[0] if len(set(names)) == 1 and _NAME.fullmatch(names[0]) else None
            for field, value, line, span in entries:
                if "$" in value or "\\" in value:
                    self.unsupported_file(file, "pkg-config expansion is not evaluated", span, line)
                    continue
                if field == "version" and not re.fullmatch(_VERSION, value):
                    self.unsupported_file(file, "pkg-config version is not a supported literal", span, line)
                    continue
                self.emit(file, root, value if field == "name" else name, "pkg_config", line, span,
                          role="pkg-config", strong=name is not None,
                          release=value if field == "version" else None,
                          upstream=value if field in {"url", "repository"} else None,
                          identity=field == "name")
            return
        basename = PurePosixPath(file["path"]).name
        package = re.sub(r"(?:-config|Config)\.cmake$", "", basename, flags=re.I)
        evidence = self.file_evidence(file, "cmake_filename", file["path"], (0, 0, 1, 1))
        self.fact(domain=file["domain"], root_id=file["root_id"], root=root, name=package,
                  role="path", evidence_id=evidence)
        conditional = 0
        for line, span in lines:
            if re.match(r"^\s*(?:if|foreach|function|macro)\s*\(", line, re.I):
                conditional += 1
            if re.match(r"^\s*end(?:if|foreach|function|macro)\s*\(", line, re.I):
                conditional = max(0, conditional - 1)
            match = re.fullmatch(
                r'\s*set\s*\(\s*([A-Za-z0-9_+\-]+)_VERSION(?:_STRING)?\s+"?('
                + _VERSION + r')"?\s*\)\s*(?:#.*)?\s*', line, re.I)
            project = re.fullmatch(
                r'\s*project\s*\(\s*([A-Za-z0-9_.+\-]+)\s+VERSION\s+"?('
                + _VERSION + r')"?\s*\)\s*(?:#.*)?\s*', line, re.I)
            recognized = match or project
            if recognized and not conditional:
                name = recognized[1]
                self.emit(file, root, name, "cmake_package", line, span, role="cmake",
                          release=recognized[2], strong=bool(project) or
                          _normalized_name(name) == _normalized_name(package))
            elif re.search(r"VERSION|REPOSITORY", line, re.I) and not line.lstrip().startswith("#"):
                self.unsupported_file(file, "CMake construct is not a supported unconditional literal",
                                      span, line)

    def document(self, file: NativeFile, root: str,
                 lines: Sequence[tuple[str, tuple[int, int, int, int]]]) -> None:
        basename = PurePosixPath(file["path"]).name.casefold()
        if basename.startswith(("license", "copying")):
            self.emit(file, root, None, "license_observation", file["path"], lines[0][1],
                      role="license")
            return
        declarations = [(line, span, re.fullmatch(
            r"\s*(?:Package|Name)\s*:\s*([A-Za-z0-9_.+\-]+)\s*", line, re.I))
            for line, span in lines]
        names = {match[1] for _, _, match in declarations if match}
        associated = next(iter(names)) if len(names) == 1 else None
        for line, span in lines:
            package = re.fullmatch(r"\s*(?:Package|Name)\s*:\s*([A-Za-z0-9_.+\-]+)\s*", line, re.I)
            release = re.fullmatch(r"\s*Version\s*:\s*(" + _VERSION + r")\s*", line, re.I)
            repository = re.fullmatch(r"\s*Repository\s*:\s*(https://\S+)\s*", line, re.I)
            title = re.fullmatch(r"\s*#*\s*([A-Za-z0-9_.+\-]+)\s+(?:version\s+|v)?("
                                 + _VERSION + r")\s*", line, re.I)
            bare = (re.fullmatch(r"\s*(" + _VERSION + r")\s*", line)
                    if basename.startswith("version") else None)
            if package:
                self.emit(file, root, package[1], "package_declaration", line, span, role="document")
            elif title:
                self.emit(file, root, title[1], "package_declaration", line, span, role="document",
                          release=title[2])
            elif release or bare:
                self.emit(file, root, associated, "release_declaration", line, span, role="document",
                          release=(release or bare)[1], identity=False)
            elif repository:
                self.emit(file, root, associated, "repository_declaration", line, span,
                          role="document", upstream=repository[1], identity=False)
            elif re.match(r"\s*(?:Package|Name|Version|Repository)\s*:", line, re.I):
                self.unsupported_file(file, "declaration is not a supported literal", span, line)

    def finish(self) -> DiscoveryResult:
        grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for fact in self.facts:
            key = fact["domain"], fact["root_id"], fact["root"]
            if key in self.allowed_roots:
                grouped[key].append(fact)
        for key, facts in grouped.items():
            if key[2] != "." and not any(fact["field"] == "identity" for fact in facts):
                name = PurePosixPath(key[2]).name
                facts.append({**facts[0], "field": "identity", "value": name,
                              "name": name, "role": "path", "strong": False})
        # A document at a nearer cataloged ancestor can support a header-only include subtree.
        for key in list(grouped):
            if key not in grouped:
                continue
            domain, root_id, root = key
            parents = [other for other in grouped if other[:2] == key[:2] and other[2] != "."
                       and other != key and _within(root, other[2])]
            if parents and not _vendor_root(root + "/_"):
                parent = max(parents, key=lambda other: (other[2].count("/"), other[2]))
                children = [other for other in grouped if other != parent
                            and other[:2] == parent[:2] and _within(other[2], parent[2])]
                local_names = {_normalized_name(fact["value"]) for fact in grouped[key]
                               if fact["field"] == "identity"}
                parent_names = {_normalized_name(fact["value"]) for fact in grouped[parent]
                                if fact["field"] == "identity"}
                compatible = not parent_names or local_names == parent_names
                if (len(children) == 1 and compatible
                        and all(fact["role"] in {"header", "path"} for fact in grouped[key])):
                    grouped[parent].extend(grouped.pop(key))
                    if key in self.incomplete:
                        self.incomplete.add(parent)
                    if key in self.release_incomplete:
                        self.release_incomplete.add(parent)
                    if key in self.version_conflicts:
                        self.version_conflicts.add(parent)
                        self.conflict_evidence[parent].update(self.conflict_evidence[key])
                else:
                    self.gap("ambiguous_root", root, "overlapping localities retained independently")
        roots = sorted(grouped)
        candidates: list[NativeCandidate] = []
        for domain, root_id, root in roots:
            facts = grouped[domain, root_id, root]
            identities = [fact for fact in facts if fact["field"] == "identity"]
            # Directory hints never conflict with a self-declared package name.
            named = [fact for fact in identities if fact["role"] not in {"path", "link", "artifact"}]
            semantic_names = sorted({_normalized_name(fact["value"]) for fact in named})
            non_path = [fact for fact in identities if fact["role"] != "path"]
            names = sorted({_normalized_name(fact["value"]) for fact in non_path or identities})
            if len(names) > 1 and any(fact["name"] is None for fact in facts):
                self.gap("ambiguous_root", root, "unassociated metadata cannot identify one package")
            for name in names:
                if len(candidates) >= self.bounds.candidate_limit:
                    self.omit("candidate_limit", root)
                    continue
                conflicted_identity = len(semantic_names) > 1 and name in semantic_names
                related = [fact for fact in facts if (fact["name"] is None and len(names) == 1)
                           or (fact["name"] is not None and _normalized_name(fact["name"]) == name)
                           or fact["role"] == "path"
                           or (conflicted_identity and fact["field"] == "identity"
                               and fact["role"] not in {"path", "link", "artifact"})]
                supporting = [fact for fact in self.support if fact["domain"] == domain
                              and fact["root_id"] == root_id and fact["root"] == root]
                evidence_ids = sorted({fact["evidence_id"] for fact in [*related, *supporting]})
                if len(evidence_ids) > self.bounds.evidence_per_candidate:
                    self.omit("evidence_per_candidate", root,
                              len(evidence_ids) - self.bounds.evidence_per_candidate)
                evidence_ids = evidence_ids[:self.bounds.evidence_per_candidate]
                complete_related = related
                related = [fact for fact in related if fact["evidence_id"] in evidence_ids]
                if not related:
                    continue
                identity = self.claim([fact for fact in related if fact["field"] == "identity"
                                       and fact["role"] != "path"] or
                                      [fact for fact in related if fact["field"] == "identity"],
                                      root, "identity_conflict", normalize=True)
                if conflicted_identity:
                    identity = {"value": None, "status": "conflicted",
                                "alternatives": semantic_names, "evidence_ids": evidence_ids}
                    self.gap("identity_conflict", root, "multiple package names at one locality",
                             evidence_ids)
                    self.gap("ambiguous_root", root, "multiple package identities share a locality",
                             evidence_ids)
                release = self.claim([fact for fact in related if fact["field"] == "release"],
                                     root, "version_conflict")
                upstream = self.claim([fact for fact in related if fact["field"] == "upstream"],
                                      root, "repository_conflict")
                for field, claim, conflict in (("release", release, "version_conflict"),
                                                ("upstream", upstream, "repository_conflict")):
                    full = self.claim([fact for fact in complete_related if fact["field"] == field],
                                      root, conflict)
                    if full["status"] == "conflicted":
                        claim.update(full, evidence_ids=[value for value in full["evidence_ids"]
                                                         if value in evidence_ids])
                if (domain, root_id, root) in self.version_conflicts:
                    release.update(value=None, status="conflicted")
                    self.gap("version_conflict", root, "competing literal tuple components",
                             sorted(self.conflict_evidence[domain, root_id, root]))
                if (domain, root_id, root) in self.incomplete:
                    for claim in (identity, release, upstream):
                        if claim["status"] == "corroborated":
                            claim["status"] = "inferred"
                if ((domain, root_id, root) in self.release_incomplete
                        and release["status"] == "corroborated"):
                    release["status"] = "inferred"
                observations = [{"kind": self.evidence[value]["kind"],
                                 "value": self.evidence[value]["value"], "evidence_id": value}
                                for value in evidence_ids]
                for fact in related:
                    if fact["observation"]:
                        observations.append({**fact["observation"],
                                             "evidence_id": fact["evidence_id"]})
                unique = {canonical_json(value): value for value in observations}
                metadata: dict[str, Any] = {}
                if release["status"] == "corroborated":
                    metadata["version"] = release["value"]
                if upstream["value"]:
                    metadata["repository_url"] = upstream["value"]
                candidate: NativeCandidate = {
                    "candidate_id": candidate_identity(self.fingerprint, root_id, root, name),
                    "native_name": name, "root_id": root_id, "package_root": root,
                    "identity": identity, "release": release, "upstream": upstream,
                    "evidence_ids": evidence_ids, "observations": [unique[key] for key in sorted(unique)],
                    "metadata": metadata, "repository": None,
                }
                candidates.append(candidate)
        for (bound, scope), count in sorted(self.bound_scopes.items()):
            self.gap("bounds", scope, f"{bound}: omitted {count}")
        self.metrics["candidates_total"] = len(candidates)
        self.metrics["unsupported_files"] = len(self.unsupported)
        for candidate in candidates:
            self.metrics["identities_" + candidate["identity"]["status"]] += 1
            self.metrics["releases_" + candidate["release"]["status"]] += 1
        return {
            "schema": DISCOVERY_SCHEMA, "candidates": candidates,
            "evidence": [self.evidence[key] for key in sorted(self.evidence)],
            "gaps": [self.gaps[key] for key in sorted(self.gaps)],
            "coverage": {**self.metrics, "omission_counts": self.omissions,
                         "commands_available": self.metrics["commands_available"],
                         "artifacts_available": self.metrics["artifacts_inspected"],
                         "configured_exclusions": [], "inherited_catalog_gaps": []},
            "metrics": dict(self.metrics),
        }

    def claim(self, facts: Sequence[Mapping[str, Any]], root: str, conflict: str, *,
              normalize: bool = False) -> Claim:
        values: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for fact in facts:
            value = _normalized_name(fact["value"]) if normalize else fact["value"]
            values[value].append(fact)
        evidence = sorted({fact["evidence_id"] for fact in facts})
        if not values:
            return {"value": None, "status": "unknown", "evidence_ids": [], "alternatives": []}
        if len(values) > 1:
            self.gap(conflict, root, "incompatible literal claims retained", evidence)
            return {"value": None, "status": "conflicted", "evidence_ids": evidence,
                    "alternatives": sorted(values)}
        value, records = next(iter(values.items()))
        # Different headers (or repeated identical bytes) are not independent roles.
        roles = {record["role"] for record in records}
        identities = {self.evidence[record["evidence_id"]]["sha256"] for record in records}
        strong = any(record["strong"] for record in records)
        corroborated = strong or (len(roles - {"path", "link", "artifact", "license"}) >= 2
                                  and len(identities) >= 2)
        return {"value": value, "status": "corroborated" if corroborated else "inferred",
                "evidence_ids": evidence, "alternatives": []}


def discover_native_dependencies(
    *, source_fingerprint: str, files: Sequence[NativeFile],
    invocations: Sequence[Mapping[str, Any]], artifacts: Sequence[Mapping[str, Any]],
    read_file: Callable[[NativeFile, int], bytes], bounds: NativeBounds,
) -> DiscoveryResult:
    """Discover claims without walking, executing, or opening anything outside ``read_file``.

    Invocation mappings use absolute prefixes to relative strings or
    ``{domain, root_id, path}`` objects. Relative argv paths resolve against ``directory``.
    Structured inputs require ``evidence_source={artifact, json_pointer}``. The authenticated
    reader may fill a workspace record's exact-byte ``backing`` before returning its bytes.
    """
    _text(source_fingerprint, "source_fingerprint")
    if not isinstance(bounds, NativeBounds) or not callable(read_file):
        raise ValueError("NativeBounds and a read_file callback are required")
    for values in (files, invocations, artifacts):
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
            raise ValueError("native inputs must be finite sequences")
    accepted: dict[tuple[str, str, str], NativeFile] = {}
    for file in files:
        if not isinstance(file, Mapping):
            raise ValueError("native file must be a mapping")
        _domain(file)
        if "domain" not in file:
            raise ValueError("native file requires domain")
        _text(file.get("root_id"), "root_id")
        _reference(file)
        _reference(file.get("upstream"))
        if "backing" not in file:
            raise ValueError("native file requires backing (null for target files)")
        if file.get("backing") is not None:
            backing = _reference(file["backing"])
            if (backing["sha256"], backing["size_bytes"]) != (file["sha256"], file["size_bytes"]):
                raise NativeInputIntegrityError("native backing identity differs from accepted file")
        key = file["domain"], file["root_id"], file["path"]
        if key in accepted and canonical_json(accepted[key]) != canonical_json(file):
            raise NativeInputIntegrityError("conflicting accepted native file records")
        accepted[key] = file
    for row in invocations:
        if not isinstance(row, Mapping):
            raise ValueError("native invocation must be a mapping")
        _source(row)
        _relative(row.get("directory", "."), dot=True)
        argv = row.get("argv")
        if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)) or not argv:
            raise ValueError("native invocation requires nonempty argv")
        if any(not isinstance(value, str) or "\x00" in value for value in argv):
            raise ValueError("native argv must contain strings without NUL")
        if row.get("argv_sha256") is not None:
            if row["argv_sha256"] != hashlib.sha256(canonical_json(list(argv))).hexdigest():
                raise NativeInputIntegrityError("native argv identity mismatch")
        expanded = row.get("expanded_argv")
        if expanded is not None:
            if (not isinstance(expanded, Sequence) or isinstance(expanded, (str, bytes))
                    or not expanded or any(not isinstance(value, str) or "\x00" in value
                                           for value in expanded)):
                raise ValueError("native expanded_argv must be a nonempty string sequence")
            if (row.get("expanded_argv_sha256") is not None and row["expanded_argv_sha256"] !=
                    hashlib.sha256(canonical_json(list(expanded))).hexdigest()):
                raise NativeInputIntegrityError("native expanded argv identity mismatch")
        mappings = row.get("path_mappings", {})
        if not isinstance(mappings, Mapping):
            raise ValueError("path_mappings must be a mapping")
        for prefix, mapped in mappings.items():
            _text(prefix, "mapping prefix")
            if (not (prefix.startswith("/") or re.match(r"^[A-Za-z]:/", prefix))
                    or "\\" in prefix or any(part in {".", ".."} for part in prefix.split("/"))
                    or "//" in prefix):
                raise ValueError("path mapping prefix must be canonical absolute")
            if isinstance(mapped, str):
                _relative(mapped, dot=True)
            elif isinstance(mapped, Mapping):
                if "domain" not in mapped:
                    raise ValueError("cross-root path mapping requires domain")
                _domain(mapped)
                _text(mapped.get("root_id"), "mapping root_id")
                _relative(mapped.get("path"), dot=True)
            else:
                raise ValueError("path mapping requires a logical prefix")
    for row in artifacts:
        if not isinstance(row, Mapping):
            raise ValueError("native artifact must be a mapping")
        _source(row)
        _relative(row.get("path"))
        if row.get("sha256") is not None and not _HASH.fullmatch(str(row["sha256"])):
            raise ValueError("native artifact sha256 is invalid")
        loader = row.get("loader_dependencies", ())
        if loader is not None and (not isinstance(loader, Sequence) or isinstance(loader, (str, bytes))
                                   or any(not isinstance(value, str) for value in loader)):
            raise ValueError("loader_dependencies must be a string sequence")
        if row.get("loader_soname") is not None and not isinstance(row["loader_soname"], str):
            raise ValueError("loader_soname must be a string")
    discovery = _Discovery(source_fingerprint, bounds)
    discovery.metrics["commands_available"] = len(invocations)
    for row in sorted(invocations, key=canonical_json):
        discovery.command(row)
    for row in sorted(artifacts, key=canonical_json):
        discovery.artifact(row)
    discovery.select_roots(list(accepted.values()))
    for key, file in sorted(accepted.items()):
        if not _eligible(file["path"]):
            continue
        discovery.metrics["eligible_files"] += 1
        if not discovery.scalar(file["path"], file["path"], path=True):
            continue
        if (file["domain"], file["root_id"], discovery.file_root(file)) not in discovery.allowed_roots:
            continue
        if discovery.metrics["selected_files"] >= bounds.file_limit:
            discovery.omit("file_limit", file["path"])
            continue
        if file["size_bytes"] > bounds.bytes_per_file:
            discovery.omit("bytes_per_file", file["path"])
            continue
        if file["size_bytes"] > bounds.source_bytes_limit - discovery.metrics["bytes_read"]:
            discovery.omit("source_bytes_limit", file["path"])
            continue
        discovery.metrics["selected_files"] += 1
        identity = canonical_json({key: value for key, value in file.items() if key != "backing"})
        try:
            data = read_file(file, file["size_bytes"] + 1)
        except OSError as exc:
            if identity != canonical_json({key: value for key, value in file.items() if key != "backing"}):
                raise NativeInputIntegrityError("failed reader changed accepted file identity") from exc
            discovery.gap("read_failed", file["path"], f"authenticated read failed: {type(exc).__name__}")
            continue
        if identity != canonical_json({key: value for key, value in file.items() if key != "backing"}):
            raise NativeInputIntegrityError("authenticated reader changed accepted file identity")
        if not isinstance(data, bytes):
            raise ValueError("read_file must return bytes")
        if len(data) != file["size_bytes"] or hashlib.sha256(data).hexdigest() != file["sha256"]:
            raise NativeInputIntegrityError("native file size or sha256 mismatch")
        if file.get("backing") is not None:
            backing = _reference(file["backing"])
            if (backing["sha256"], backing["size_bytes"]) != (file["sha256"], file["size_bytes"]):
                raise NativeInputIntegrityError("reader backing identity mismatch")
        elif file["domain"] == "workspace":
            raise ValueError("authenticated workspace read requires an exact detached backing")
        discovery.metrics["read_files"] += 1
        discovery.metrics["bytes_read"] += len(data)
        discovery.file(file, data)
    discovery.metrics["omitted_files"] = (
        discovery.metrics["eligible_files"] - discovery.metrics["selected_files"])
    return discovery.finish()


__all__ = ["discover_native_dependencies"]
