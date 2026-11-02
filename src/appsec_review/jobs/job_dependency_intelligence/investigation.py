"""Evidence-bound metadata proposals over a finite authenticated native catalog."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re
import tomllib
from typing import Any, Literal
from urllib.parse import quote, unquote, urlsplit
import xml.etree.ElementTree as ET

from appsec_review.storage import canonical_json

from .discovery import _Discovery, _domain, _normalized_name, _reference, _relative, _text, _within
from .native_inference_contracts import (
    INVESTIGATION_SCHEMA, METADATA_SCHEMA, PLAN_SCHEMA, InvestigationResult,
    NativeInferenceBounds, NativeInferenceError, Propose,
)
from .native_sbom_contracts import (
    Claim, CoverageGap, DiscoveryResult, NativeBounds, NativeCandidate, NativeEvidence,
    NativeFile, NativeInputIntegrityError, evidence_identity,
)
from .sbom import _valid_purl


_FIELDS = ("version", "purl", "supplier", "download_location", "license_declared", "upstream")
_COUNTERS = (
    "input_candidates", "roots_investigated", "files_read", "bytes_read", "version_claims",
    "versions_corroborated", "purl_claims", "purls_corroborated", "conflicts",
    "omitted_candidates", "omitted_files",
)
_VERSION = re.compile(r"\d+(?:\.\d+){0,3}(?:[-+][A-Za-z0-9][A-Za-z0-9_.+\-]*)?")
_LABELS = {
    "purl": "purl", "supplier": "supplier", "license": "license_declared",
    "license-declared": "license_declared", "download": "download_location",
    "download-location": "download_location", "repository": "upstream", "upstream": "upstream",
}


@dataclass(frozen=True)
class _Fact:
    field: str
    value: str
    spans: tuple[tuple[str, int, int], ...]
    basis: str
    direct: bool = True


@dataclass
class _Read:
    record: NativeFile
    data: bytes
    text: str
    lines: list[str]
    offsets: list[int]
    shown: int = 0


def _unknown() -> Claim:
    return {"value": None, "status": "unknown", "evidence_ids": [], "alternatives": []}


def _literal(value: object, limit: int, *, multiline: bool = False) -> bool:
    return (isinstance(value, str) and bool(value.strip()) and len(value.encode("utf-8")) <= limit
            and all(ord(char) >= 32 or (multiline and char in "\r\n\t") for char in value))


def _eligible(path: str) -> bool:
    name = PurePosixPath(path).name.casefold()
    return (PurePosixPath(path).suffix.casefold() in {".h", ".hh", ".hpp", ".hxx", ".inc", ".pc"}
            or name in {"info.plist", "package.json", "cargo.toml", "pyproject.toml"}
            or name.endswith(("config.cmake", "-config.cmake"))
            or name.startswith(("readme", "version", "license", "copying", "notice")))


def _catalog_order(file: NativeFile) -> tuple[int, str]:
    path = file["path"]
    name = PurePosixPath(path).name.casefold()
    priority = (name in {"info.plist", "package.json", "cargo.toml", "pyproject.toml"}
                or name.startswith(("version", "readme")) or name.endswith(".pc"))
    return (0 if priority else 1), path


def _owner(root: str, name: str) -> str:
    parts = root.split("/")
    frameworks = [index for index, part in enumerate(parts) if part.casefold().endswith(".framework")]
    if frameworks:
        return "/".join(parts[:frameworks[-1] + 1])
    if (len(parts) > 1 and parts[-1].casefold() in {"headers", "include"}
            and _normalized_name(parts[-2]) == _normalized_name(name)):
        return "/".join(parts[:-1])
    return root


def _local(path: str, owner: str, root: str, other_roots: set[str]) -> bool:
    if not _within(path, owner):
        return False
    if any(other != root and other != owner and _within(other, owner)
           and _within(path, other) for other in other_roots):
        return False
    suffix = path[len(owner) + 1:] if owner != "." else path
    parents = suffix.split("/")[:-1]
    return not any(part.casefold() in {
        "vendor", "vendors", "third_party", "third-party", "external", "deps", "dependencies",
        "frameworks", "libraries",
    } or part.casefold().endswith((".framework", ".xcframework")) for part in parents)


def _url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return (parsed.scheme in {"https", "http", "git", "ssh"} and bool(parsed.hostname)
                and not parsed.username and not parsed.password
                and not any(char.isspace() for char in value))
    except ValueError:
        return False


def _purl_parts(value: str) -> tuple[str, str, str | None] | None:
    try:
        if not _valid_purl(value):
            return None
        unquote(value, errors="strict")
        parsed = urlsplit(value)
        package_type, package = parsed.path.split("/", 1)
        version = None
        if "@" in package:
            package, version = package.rsplit("@", 1)
            version = unquote(version, errors="strict")
        names = [unquote(part, errors="strict") for part in package.split("/")]
        name = names[-1]
        if any("/" in part or "\\" in part for part in names):
            return None
        if parsed.fragment and any(unquote(part, errors="strict") in {"", ".", ".."}
                                   for part in parsed.fragment.split("/")):
            return None
    except (ValueError, UnicodeDecodeError):
        return None
    if any(char in name for char in "/\\@?#") or not name:
        return None
    return package_type, name, version


def _json_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest key")
        result[key] = value
    return result


def _manifest(read: _Read, name: str) -> list[_Fact]:
    """Parse only supported, literal package coordinates; never evaluate a manifest."""
    basename = PurePosixPath(read.record["path"]).name.casefold()
    if basename not in {"package.json", "cargo.toml", "pyproject.toml"}:
        return []
    if basename == "package.json":
        package = json.loads(read.text, object_pairs_hook=_json_unique)
        package_type = "npm"
    else:
        document = tomllib.loads(read.text)
        package = document.get("package" if basename == "cargo.toml" else "project")
        package_type = "cargo" if basename == "cargo.toml" else "pypi"
    if not isinstance(package, dict) or not isinstance(package.get("name"), str):
        return []
    coordinate = package["name"]
    leaf = coordinate.rsplit("/", 1)[-1]
    if _normalized_name(leaf) != _normalized_name(name):
        return []
    # Whole-manifest selectors bind fields to the package object, not unrelated nested keys.
    spans = ((read.record["path"], 1, len(read.lines)),)
    facts: list[_Fact] = []
    version = package.get("version")
    if isinstance(version, str) and _VERSION.fullmatch(version):
        facts.append(_Fact("version", version, spans, "literal_manifest"))
        if package_type == "npm":
            if re.fullmatch(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", coordinate):
                purl = "pkg:npm/" + quote(coordinate, safe="/") + "@" + quote(version, safe=".+-")
                facts.append(_Fact("purl", purl, spans, "manifest_coordinates"))
        elif re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", coordinate):
            if package_type == "pypi":
                coordinate = re.sub(r"[-_.]+", "-", coordinate).lower()
            purl = f"pkg:{package_type}/{quote(coordinate, safe='.-_')}@{quote(version, safe='.+-')}"
            facts.append(_Fact("purl", purl, spans, "manifest_coordinates"))
    fields = {
        "license": "license_declared", "supplier": "supplier", "purl": "purl",
        "download_location": "download_location", "repository": "upstream",
    }
    for key, field in fields.items():
        value = package.get(key)
        if isinstance(value, str) and value.strip():
            facts.append(_Fact(field, value, spans, "literal_manifest"))
    return facts


def _plist(read: _Read, name: str) -> list[_Fact]:
    if PurePosixPath(read.record["path"]).name.casefold() != "info.plist":
        return []
    # ElementTree does not fetch external entities; reject declarations as unsupported input.
    if "<!ENTITY" in read.text:
        raise ValueError("plist entities are unsupported")
    root = ET.fromstring(read.text)
    if root.tag != "plist" or len(root) != 1 or root[0].tag != "dict":
        return []
    children = list(root[0])
    if len(children) % 2:
        return []
    entries: dict[str, str] = {}
    for index in range(0, len(children), 2):
        key, value = children[index:index + 2]
        if key.tag != "key" or key.text is None or key.text in entries:
            return []
        if value.tag == "string" and len(value) == 0:
            entries[key.text] = value.text or ""
    names = [entries[key] for key in ("CFBundleName", "CFBundleExecutable") if entries.get(key)]
    bundle_id = entries.get("CFBundleIdentifier", "")
    if any(_normalized_name(value) != _normalized_name(name) for value in names):
        return []
    if not bundle_id or any(char.isspace() for char in bundle_id) or "." not in bundle_id:
        return []
    if not names:
        framework_names = [part[:-len(".framework")] for part in read.record["path"].split("/")
                           if part.casefold().endswith(".framework")]
        if (not framework_names or _normalized_name(framework_names[-1]) != _normalized_name(name)
                or _normalized_name(bundle_id.rsplit(".", 1)[-1]) != _normalized_name(name)):
            return []
    version = entries.get("CFBundleShortVersionString", "")
    if not _VERSION.fullmatch(version):
        return []
    return [_Fact("version", version, ((read.record["path"], 1, len(read.lines)),),
                  "framework_bundle_identity")]


def _header_lines(lines: list[tuple[str, tuple[int, int, int, int]]]
                  ) -> tuple[list[tuple[str, tuple[int, int, int, int]]], bool]:
    """Mask comments and spliced physical lines without evaluating C expressions."""
    masked = []
    block = False
    continued = False
    malformed = False
    for line, span in lines:
        if continued:
            continued = line.rstrip("\r\n").endswith("\\")
            masked.append(("\n", span))
            continue
        continued = line.rstrip("\r\n").endswith("\\")
        chars = []
        index = 0
        quoted = None
        while index < len(line):
            char = line[index]
            if block:
                if line.startswith("*/", index):
                    chars.extend("  ")
                    index += 2
                    block = False
                    continue
                chars.append(char if char in "\r\n" else " ")
            elif quoted:
                chars.append(char)
                if char == "\\" and index + 1 < len(line):
                    index += 1
                    chars.append(line[index])
                elif char == quoted:
                    quoted = None
            elif line.startswith("//", index):
                chars.extend("\n" if value == "\n" else " " for value in line[index:])
                break
            elif line.startswith("/*", index):
                chars.extend("  ")
                index += 2
                block = True
                continue
            else:
                chars.append(char)
                if char in "\"'":
                    quoted = char
            index += 1
        malformed |= quoted is not None
        masked.append(("".join(chars), span))
    return masked, malformed or block or continued


def _facts(read: _Read, name: str, fingerprint: str, bounds: NativeInferenceBounds,
           report: Callable[[str, str, str, Sequence[str]], None]) -> tuple[list[_Fact], bool]:
    path = read.record["path"]
    basename = PurePosixPath(path).name.casefold()
    result: list[_Fact] = []
    if basename in {"info.plist", "package.json", "cargo.toml", "pyproject.toml"}:
        try:
            result = _plist(read, name) if basename == "info.plist" else _manifest(read, name)
        except (ValueError, ET.ParseError, RecursionError):
            report("unsupported_metadata", path, "unsupported or ambiguous literal manifest", ())
        return result, False
    native_bounds = NativeBounds(
        candidate_limit=1, command_token_limit=1, file_limit=1, root_limit=1,
        bytes_per_file=bounds.bytes_per_file, source_bytes_limit=bounds.source_bytes_limit,
        evidence_limit=max(1, len(read.data)), evidence_per_candidate=max(1, len(read.data)),
        field_bytes=bounds.field_bytes, path_chars=bounds.field_bytes,
    )
    parser = _Discovery(fingerprint, native_bounds)
    lines = [(line, (read.offsets[index], read.offsets[index + 1], index + 1, index + 1))
             for index, line in enumerate(read.lines)]
    root = str(PurePosixPath(path).parent)
    suffix = PurePosixPath(path).suffix.casefold()
    lexical_incomplete = False
    try:
        if suffix in {".h", ".hh", ".hpp", ".hxx", ".inc"}:
            header_lines, lexical_incomplete = _header_lines(lines)
            if lexical_incomplete:
                report("unsupported_metadata", path, "incomplete header comment/string/continuation", ())
            parser.header(read.record, root, header_lines)
        elif suffix == ".pc" or basename.endswith(("config.cmake", "-config.cmake")):
            parser.metadata(read.record, root, lines)
        else:
            parser.document(read.record, root, lines)
    except ValueError:
        report("unsupported_metadata", path, "literal parser rejected malformed native metadata", ())
    matching = [fact for fact in parser.facts if fact["name"] is not None
                and _normalized_name(fact["name"]) == _normalized_name(name)]
    identity_spans = []
    for fact in matching:
        if fact["field"] == "identity":
            selector = parser.evidence[fact["evidence_id"]]["selector"]
            identity_spans.append((path, selector["start_line"], selector["end_line"]))
    is_header = suffix in {".h", ".hh", ".hpp", ".hxx", ".inc"}
    for fact in matching:
        if fact["field"] != "release":
            continue
        selector = parser.evidence[fact["evidence_id"]]["selector"]
        span = (path, selector["start_line"], selector["end_line"])
        spans = (span,) if is_header or suffix == ".cmake" else tuple(sorted(set([span, *identity_spans])))
        direct = not parser.release_incomplete and not parser.version_conflicts and not lexical_incomplete
        if (fact["role"] == "document" and "." not in fact["value"]
                and re.fullmatch(r"\d{4}", fact["value"])
                and not re.search(r"\b(?:Version\s*:|version\s+|v\d)", read.lines[span[1] - 1], re.I)):
            direct = False
            report("unsupported_metadata", path, "bare year-like title is not a release declaration", ())
        result.append(_Fact("version", fact["value"], spans, "literal_" + fact["role"],
                            direct))
    for gap in parser.gaps.values():
        report(gap["kind"], path, gap["detail"], ())
    for evidence_ids in parser.conflict_evidence.values():
        for evidence_id in sorted(evidence_ids):
            item = parser.evidence[evidence_id]
            selector = item["selector"]
            result.append(_Fact("version", item["value"],
                                ((path, selector["start_line"], selector["end_line"]),),
                                "tuple_component_conflict", False))
    for bound, count in parser.omissions.items():
        if count:
            report("bounds", path, f"{bound}: literal parser omitted {count}", ())
    # Labeled document fields require a self-identifying declaration in these same bytes.
    if identity_spans and not is_header:
        for number, line in enumerate(read.lines, 1):
            match = re.fullmatch(
                r"\s*(Purl|Supplier|License|License-Declared|Download|Download-Location|Repository|Upstream)"
                r"\s*:\s*(\S.*?)\s*", line, re.I,
            )
            if match:
                spans = tuple(sorted(set([(path, number, number), *identity_spans])))
                result.append(_Fact(_LABELS[match[1].casefold()], match[2], spans, "literal_declaration"))
    return result, bool(parser.version_conflicts)


def _merge(original: Claim, proposals: Sequence[tuple[str, bool, list[str]]]) -> Claim:
    known = {value for value, direct, _ in proposals if direct}
    inferred = {value for value, direct, _ in proposals if not direct}
    if original["value"]:
        (known if original["status"] == "corroborated" else inferred).add(original["value"])
    evidence = sorted(set(original["evidence_ids"]).union(
        *(set(ids) for _, _, ids in proposals)))
    alternatives = set(original["alternatives"])
    if original["status"] == "conflicted" or len(known) > 1 or (not known and len(inferred) > 1):
        return {"value": None, "status": "conflicted", "evidence_ids": evidence,
                "alternatives": sorted(alternatives | known | inferred)}
    values = known or inferred
    if not values:
        return deepcopy(original)
    value = next(iter(values))
    return {"value": value, "status": "corroborated" if known else "inferred",
            "evidence_ids": evidence, "alternatives": sorted((alternatives | inferred) - {value})}


def _combine(left: Claim, right: Claim) -> Claim:
    merged = _merge(left, [(right["value"], right["status"] == "corroborated",
                            right["evidence_ids"])] if right["value"] else [])
    merged["evidence_ids"] = sorted(set(merged["evidence_ids"]) | set(right["evidence_ids"]))
    merged["alternatives"] = sorted(set(merged["alternatives"]) | set(right["alternatives"]))
    if right["status"] == "conflicted":
        if merged["value"]:
            merged["alternatives"] = sorted(set(merged["alternatives"]) | {merged["value"]})
        merged.update(value=None, status="conflicted")
    return merged


class _Investigation:
    def __init__(self, discovery: DiscoveryResult, files: Sequence[NativeFile], *,
                 read_file: Callable[[NativeFile, int], bytes], propose: Propose | None,
                 bounds: NativeInferenceBounds) -> None:
        self.discovery = deepcopy(discovery)
        self.read_file, self.propose, self.bounds = read_file, propose, bounds
        self.metrics = dict.fromkeys(_COUNTERS, 0)
        self.calls = 0
        self.gaps: dict[bytes, CoverageGap] = {}
        self.findings: list[dict[str, Any]] = []
        self.evidence = {item["evidence_id"]: item for item in self.discovery["evidence"]}
        self.domains: dict[int, str] = {}
        self.files: dict[tuple[str, str, str], NativeFile] = {}
        for source in files:
            file = deepcopy(source)
            _domain(file)
            if "domain" not in file or "backing" not in file:
                raise ValueError("native file requires domain and backing")
            _text(file.get("root_id"), "root_id")
            _reference(file)
            _reference(file.get("upstream"))
            self.check_backing(file)
            key = file["domain"], file["root_id"], file["path"]
            if key in self.files and canonical_json(self.files[key]) != canonical_json(file):
                raise NativeInputIntegrityError("conflicting accepted native file records")
            self.files[key] = file

    def check_backing(self, file: NativeFile) -> None:
        if "backing" not in file:
            raise NativeInputIntegrityError("native reader removed backing identity")
        if file["backing"] is not None:
            try:
                ref = _reference(file["backing"])
            except ValueError as exc:
                raise NativeInputIntegrityError("native backing identity is invalid") from exc
            if (ref["sha256"], ref["size_bytes"]) != (file["sha256"], file["size_bytes"]):
                raise NativeInputIntegrityError("native backing identity differs from accepted file")

    def gap(self, kind: str, scope: str, detail: str, evidence_ids: Sequence[str] = ()) -> None:
        gap: CoverageGap = {
            "kind": kind, "scope": scope,
            "detail": detail.encode()[:self.bounds.field_bytes].decode("utf-8", errors="ignore"),
            "evidence_ids": sorted(set(evidence_ids)),
        }
        self.gaps[canonical_json(gap)] = gap

    def request(self, stage: Literal["plan", "metadata"], payload: dict[str, Any]) -> Mapping[str, Any] | None:
        scope = payload["candidate_id"]
        if self.propose is None:
            self.gap("input_missing", scope, "metadata investigation model is unavailable")
            return None
        if self.calls >= self.bounds.max_calls:
            self.gap("bounds", scope, f"max_calls: {stage} request omitted")
            return None
        if len(canonical_json(payload)) > self.bounds.max_payload_bytes:
            self.gap("bounds", scope, f"max_payload_bytes: {stage} request omitted")
            return None
        self.calls += 1
        try:
            result = self.propose(stage, deepcopy(payload))
        except NativeInferenceError as exc:
            self.gap("upstream_partial", scope, f"{stage} proposal failed ({exc.kind}): {exc}")
            return None
        try:
            response_bytes = canonical_json(result)
        except (TypeError, ValueError, UnicodeEncodeError):
            self.gap("unsupported_metadata", scope, f"{stage} response is not a JSON value")
            return None
        if not isinstance(result, Mapping) or len(response_bytes) > self.bounds.max_payload_bytes:
            self.gap("unsupported_metadata", scope, f"invalid or oversized {stage} response")
            return None
        return result

    def domain(self, candidate: NativeCandidate) -> str | None:
        domains = {self.evidence[key]["domain"] for key in candidate["evidence_ids"]
                   if key in self.evidence and self.evidence[key]["root_id"] == candidate["root_id"]
                   and self.evidence[key]["domain"] in {"target", "workspace"}}
        curated = candidate["metadata"].get("curation", {}).get("domain")
        if curated is not None:
            if curated not in {"target", "workspace"} or domains - {curated}:
                self.gap("ambiguous_root", candidate["candidate_id"],
                         "curated domain conflicts with authenticated native evidence")
                return None
            domains = {curated}
        if not domains:
            owner = _owner(candidate["package_root"], candidate["native_name"])
            domains = {domain for domain, root_id, path in self.files
                       if root_id == candidate["root_id"] and _within(path, owner)}
        if len(domains) != 1:
            self.gap("ambiguous_root", candidate["candidate_id"],
                     "candidate has no unambiguous authenticated native domain")
            return None
        return next(iter(domains))

    def read(self, record: NativeFile) -> _Read | None:
        path, size = record["path"], record["size_bytes"]
        if size > self.bounds.bytes_per_file:
            self.gap("bounds", path, "bytes_per_file: selected file omitted")
            self.metrics["omitted_files"] += 1
            return None
        if size > self.bounds.source_bytes_limit - self.metrics["bytes_read"]:
            self.gap("bounds", path, "source_bytes_limit: selected file omitted")
            self.metrics["omitted_files"] += 1
            return None
        identity = canonical_json({key: value for key, value in record.items() if key != "backing"})
        try:
            data = self.read_file(record, self.bounds.bytes_per_file)
        except OSError as exc:
            if identity != canonical_json({key: value for key, value in record.items() if key != "backing"}):
                raise NativeInputIntegrityError("failed reader changed accepted file identity") from exc
            self.gap("read_failed", path, f"authenticated read failed: {type(exc).__name__}")
            return None
        if identity != canonical_json({key: value for key, value in record.items() if key != "backing"}):
            raise NativeInputIntegrityError("authenticated reader changed accepted file identity")
        if not isinstance(data, bytes):
            raise ValueError("read_file must return bytes")
        if len(data) != size or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise NativeInputIntegrityError("native file size or sha256 mismatch")
        self.check_backing(record)
        if record["domain"] == "workspace" and record["backing"] is None:
            raise NativeInputIntegrityError("authenticated workspace read requires an exact detached backing")
        self.metrics["files_read"] += 1
        self.metrics["bytes_read"] += len(data)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            self.gap("decode_failed", path, "selected metadata is not valid UTF-8")
            return None
        lines = re.findall(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+$", text)
        offsets = [0]
        for line in lines:
            offsets.append(offsets[-1] + len(line.encode("utf-8")))
        return _Read(record, data, text, lines, offsets)

    def file_evidence(self, read: _Read, first: int, last: int) -> str:
        start, end = read.offsets[first - 1], read.offsets[last]
        record: NativeEvidence = {
            "evidence_id": "", "kind": "native_metadata_citation",
            "value": read.data[start:end].decode("utf-8"),
            "source_fingerprint": self.fingerprint, "domain": read.record["domain"],
            "root_id": read.record["root_id"], "path": read.record["path"], "sha256": read.record["sha256"],
            "upstream": deepcopy(read.record["upstream"]), "backing": deepcopy(read.record["backing"]),
            "selector": {"start_byte": start, "end_byte": end, "start_line": first, "end_line": last},
        }
        record["evidence_id"] = evidence_identity(record)
        self.evidence[record["evidence_id"]] = record
        return record["evidence_id"]

    def citation(self, value: Any, reads: Mapping[str, _Read]) -> tuple[str, int, int, str] | None:
        if not isinstance(value, Mapping) or set(value) != {"path", "start_line", "end_line", "quote"}:
            return None
        path, first, last, quotation = (value.get(key) for key in (
            "path", "start_line", "end_line", "quote"))
        if (not isinstance(path, str) or path not in reads or type(first) is not int
                or type(last) is not int or first < 1 or last < first or last > reads[path].shown
                or not _literal(quotation, self.bounds.field_bytes, multiline=True)):
            return None
        read = reads[path]
        start, end = read.offsets[first - 1], read.offsets[last]
        exact = read.data[start:end].decode("utf-8")
        without_eol = exact.removesuffix("\n").removesuffix("\r")
        if quotation not in {exact, without_eol} or len(exact.encode("utf-8")) > self.bounds.field_bytes:
            return None
        return path, first, last, self.file_evidence(read, first, last)

    def root(self, candidates: list[NativeCandidate], domain: str) -> None:
        candidate = candidates[0]
        scope, root, name = (candidate["candidate_id"], candidate["package_root"], candidate["native_name"])
        if len({_normalized_name(item["native_name"]) for item in candidates}) != 1:
            self.gap("ambiguous_root", scope, "multiple named components share one physical package root")
            return
        self.metrics["roots_investigated"] += 1
        owner = _owner(root, name)
        other_roots = {item["package_root"] for item in self.discovery["candidates"]
                       if item["root_id"] == candidate["root_id"] and item not in candidates
                       and self.domains.get(id(item)) == domain}
        catalog = [file for (file_domain, root_id, path), file in sorted(self.files.items())
                   if file_domain == domain and root_id == candidate["root_id"]
                   and _local(path, owner, root, other_roots) and _eligible(path)]
        catalog.sort(key=_catalog_order)
        if not catalog:
            self.gap("input_missing", scope, "no in-scope metadata in the authenticated catalog")
            return
        payload = {
            "schema": PLAN_SCHEMA, "candidate_id": scope,
            "candidate": {"name": name, "domain": domain, "root_id": candidate["root_id"],
                          "package_root": root, "metadata_root": owner},
            "available_files": [], "version_patterns_are_inert": True,
        }
        for file in catalog:
            if (len(payload["available_files"]) >= self.bounds.files_per_root
                    or not _literal(file["path"], self.bounds.field_bytes)):
                self.metrics["omitted_files"] += 1
                continue
            payload["available_files"].append(file["path"])
            if len(canonical_json(payload)) > self.bounds.max_payload_bytes:
                payload["available_files"].pop()
                self.metrics["omitted_files"] += 1
        if len(payload["available_files"]) < len(catalog):
            self.gap("bounds", scope, "files_per_root/field_bytes/max_payload_bytes: catalog paths omitted")
        plan = self.request("plan", payload)
        if plan is None:
            return
        if (set(plan) != {"schema", "candidate_id", "files", "version_patterns"}
                or plan["schema"] != PLAN_SCHEMA or plan["candidate_id"] != scope
                or not isinstance(plan["files"], list)
                or len(plan["files"]) > self.bounds.files_per_root
                or not isinstance(plan["version_patterns"], list)
                or len(plan["version_patterns"]) > self.bounds.files_per_root
                or any(not _literal(value, self.bounds.field_bytes) for value in plan["version_patterns"])):
            self.gap("unsupported_metadata", scope, "invalid metadata investigation plan")
            return
        selected = []
        for path in plan["files"]:
            if not isinstance(path, str) or path not in payload["available_files"]:
                self.gap("unsupported_metadata", scope, "plan selected an uncataloged or out-of-scope path")
            elif path not in selected:
                selected.append(path)
        unselected = len(payload["available_files"]) - len(selected)
        if unselected:
            self.metrics["omitted_files"] += unselected
            self.gap("upstream_partial", scope, f"metadata plan left {unselected} catalog files unread")
        metadata_payload = {
            "schema": METADATA_SCHEMA, "candidate_id": scope, "candidate": payload["candidate"],
            "version_patterns": plan["version_patterns"], "files": [],
            "source_content_is_untrusted_data": True,
        }
        reads: dict[str, _Read] = {}
        for path in selected:
            read = self.read(self.files[domain, candidate["root_id"], path])
            if read is None:
                continue
            reads[path] = read
            entry = {"path": path, "sha256": read.record["sha256"],
                     "size_bytes": len(read.data), "lines": []}
            metadata_payload["files"].append(entry)
            used = len(canonical_json(metadata_payload))
            for number, line in enumerate(read.lines, 1):
                rendered = {"line": number, "text": line}
                extra = len(canonical_json(rendered)) - 1 + (1 if entry["lines"] else 0)
                if used + extra > self.bounds.max_payload_bytes:
                    break
                entry["lines"].append(rendered)
                read.shown += 1
                used += extra
            if read.shown < len(read.lines):
                self.gap("bounds", path, "max_payload_bytes: source lines omitted from model evidence")
            if not read.shown:
                metadata_payload["files"].pop()
        if not metadata_payload["files"]:
            self.gap("input_missing", scope, "no readable metadata fits the evidence payload")
            return
        response = self.request("metadata", metadata_payload)
        if response is None:
            return
        if (set(response) != {"schema", "candidate_id", "claims"} or response["schema"] != METADATA_SCHEMA
                or response["candidate_id"] != scope or not isinstance(response["claims"], list)
                or len(response["claims"]) > self.bounds.files_per_root * len(_FIELDS)):
            self.gap("unsupported_metadata", scope, "invalid metadata proposal")
            return
        if not response["claims"]:
            self.gap("unsupported_metadata", scope, "metadata proposal returned no claims")
        facts: list[_Fact] = []
        tuple_conflict = False
        for read in reads.values():
            parsed, conflict = _facts(read, name, self.fingerprint, self.bounds, self.gap)
            facts.extend(parsed)
            tuple_conflict |= conflict
        direct_versions = {fact.value for fact in facts if fact.field == "version" and fact.direct}
        proposals: dict[str, list[tuple[str, bool, list[str]]]] = defaultdict(list)
        for claim in response["claims"]:
            if (not isinstance(claim, Mapping) or set(claim) != {"field", "value", "citations"}
                    or claim.get("field") not in _FIELDS
                    or not _literal(claim.get("value"), self.bounds.field_bytes)
                    or not isinstance(claim.get("citations"), list)
                    or not 1 <= len(claim["citations"]) <= self.bounds.files_per_root):
                self.gap("unsupported_metadata", scope, "invalid or unbounded metadata claim")
                continue
            field, value = claim["field"], claim["value"]
            if field in {"version", "purl"}:
                self.metrics[field + "_claims"] += 1
            citations = [self.citation(item, reads) for item in claim["citations"]]
            valid = all(item is not None for item in citations)
            ids = sorted({item[3] for item in citations if item is not None})
            supports = [
                fact for fact in facts if fact.field == field and fact.value == value and fact.direct
                and all(any(item is not None and item[0] == path and item[1] <= first and last <= item[2]
                            for item in citations) for path, first, last in fact.spans)
            ] if valid else []
            direct = bool(supports)
            if field == "purl":
                parsed_purl = _purl_parts(value)
                versions = set(direct_versions)
                if candidate["release"]["status"] == "corroborated" and candidate["release"]["value"]:
                    versions.add(candidate["release"]["value"])
                direct &= (parsed_purl is not None
                           and _normalized_name(parsed_purl[1]) == _normalized_name(name)
                           and (parsed_purl[2] is None or not versions or versions == {parsed_purl[2]}))
            if field in {"download_location", "upstream"}:
                direct &= _url(value)
            if field == "supplier":
                direct &= bool(re.fullmatch(r"(?:Organization|Person): \S.*", value))
            if field == "license_declared":
                direct &= value not in {"NOASSERTION", "NONE"}
            proposals[field].append((value, direct, ids if valid else []))
            finding = {"candidate_id": scope, "field": field, "value": value,
                       "status": "corroborated" if direct else "inferred", "evidence_ids": ids if valid else [],
                       "basis": sorted({fact.basis for fact in supports}) if direct else [],
                       "reason": "direct literal identity-bound evidence" if direct else
                                 "proposal lacks direct identity-bound evidence or exact citations"}
            self.findings.append(finding)
            if not direct:
                self.gap("unsupported_metadata", scope, f"{field}: {finding['reason']}", ids if valid else [])
        # Contradictory retrieved literals are evidence even when the model omits one.
        conflict_ids = []
        prior_versions = {item["release"]["value"] for item in candidates
                          if item["release"]["status"] == "corroborated" and item["release"]["value"]}
        if len(direct_versions | prior_versions) > 1 or tuple_conflict:
            for fact in facts:
                if fact.field != "version":
                    continue
                for path, first, last in fact.spans:
                    read = reads[path]
                    if read.offsets[last] - read.offsets[first - 1] <= self.bounds.field_bytes:
                        conflict_ids.append(self.file_evidence(read, first, last))
        for item in candidates:
            self.apply(item, proposals, facts, tuple_conflict, conflict_ids)

    def apply(self, candidate: NativeCandidate, proposals: Mapping[str, list[tuple[str, bool, list[str]]]],
              facts: Sequence[_Fact], tuple_conflict: bool, conflict_ids: list[str]) -> None:
        previous = candidate["metadata"].get("sbom_claims", {})
        claims = {}
        for field in _FIELDS:
            original = previous.get(field, _unknown())
            if field == "version":
                original = _combine(candidate["release"], original)
            elif field == "upstream":
                original = _combine(candidate["upstream"], original)
            elif field == "purl" and candidate.get("purl") and not original["value"]:
                original = {"value": candidate["purl"], "status": "inferred",
                            "evidence_ids": [], "alternatives": []}
            claims[field] = _merge(original, proposals.get(field, ()))
        versions = {fact.value for fact in facts if fact.field == "version" and fact.direct}
        if candidate["release"]["status"] == "corroborated" and candidate["release"]["value"]:
            versions.add(candidate["release"]["value"])
        if len(versions) > 1 or tuple_conflict:
            claim = claims["version"]
            claim["alternatives"] = sorted(set(claim["alternatives"]) | versions |
                                           ({claim["value"]} if claim["value"] else set()))
            claim.update(value=None, status="conflicted")
            claim["evidence_ids"] = sorted(set(claim["evidence_ids"]) | set(conflict_ids))
        purl = claims["purl"]
        if purl["status"] == "corroborated" and purl["value"]:
            parsed = _purl_parts(purl["value"])
            release = claims["version"]
            if (parsed is None or _normalized_name(parsed[1]) != _normalized_name(candidate["native_name"])
                    or (parsed[2] is not None and
                        (release["status"] == "conflicted" or
                         (release["status"] == "corroborated" and release["value"] != parsed[2])))):
                purl["alternatives"] = sorted(set(purl["alternatives"]) | {purl["value"]})
                purl.update(value=None, status="conflicted")
        for field, claim in claims.items():
            if claim["status"] == "conflicted":
                self.metrics["conflicts"] += 1
                kind = "version_conflict" if field == "version" else (
                    "repository_conflict" if field == "upstream" else "identity_conflict")
                self.gap(kind, candidate["candidate_id"], f"incompatible {field} claims retained",
                         claim["evidence_ids"])
        candidate["metadata"]["sbom_claims"] = claims
        if claims["version"]["status"] in {"corroborated", "conflicted"}:
            candidate["release"] = deepcopy(claims["version"])
            candidate["metadata"].pop("version", None)
            if candidate["release"]["status"] == "corroborated":
                candidate["metadata"]["version"] = candidate["release"]["value"]
                self.metrics["versions_corroborated"] += 1
        if claims["upstream"]["status"] in {"corroborated", "conflicted"}:
            candidate["upstream"] = deepcopy(claims["upstream"])
        direct_ids = sorted({evidence for values in proposals.values() for _, direct, ids in values
                             if direct for evidence in ids})
        if direct_ids:
            identity = candidate["identity"]
            identity_value = candidate["native_name"]
            if identity["value"] and _normalized_name(identity["value"]) == _normalized_name(identity_value):
                identity_value = identity["value"]
            candidate["identity"] = _merge(identity, [(identity_value, True, direct_ids)])
        candidate.pop("purl", None)
        if claims["purl"]["status"] == "corroborated":
            if candidate["identity"]["status"] == "conflicted":
                purl = claims["purl"]
                purl["alternatives"] = sorted(set(purl["alternatives"]) | {purl["value"]})
                purl.update(value=None, status="conflicted")
                self.metrics["conflicts"] += 1
                self.gap("identity_conflict", candidate["candidate_id"],
                         "PURL withheld because component identity is conflicted", purl["evidence_ids"])
            else:
                candidate["purl"] = claims["purl"]["value"]
                self.metrics["purls_corroborated"] += 1
        candidate["evidence_ids"] = sorted(set(candidate["evidence_ids"]) |
                                           {key for claim in claims.values() for key in claim["evidence_ids"]})

    def run(self) -> InvestigationResult:
        candidates = self.discovery["candidates"]
        self.metrics["input_candidates"] = len(candidates)
        fingerprints = {item["source_fingerprint"] for item in self.evidence.values()}
        if len(fingerprints) > 1:
            raise NativeInputIntegrityError("discovery contains multiple source fingerprints")
        self.fingerprint = next(iter(fingerprints), "")
        groups: dict[tuple[str, str, str], list[NativeCandidate]] = defaultdict(list)
        for candidate in sorted(candidates, key=lambda item: item["candidate_id"]):
            _relative(candidate["package_root"], dot=True)
            if any(not _literal(candidate[key], self.bounds.field_bytes) for key in (
                    "candidate_id", "native_name", "root_id", "package_root")):
                self.gap("bounds", candidate["candidate_id"], "field_bytes: candidate omitted")
                self.metrics["omitted_candidates"] += 1
                continue
            if not self.fingerprint:
                self.gap("input_missing", candidate["candidate_id"], "discovery lacks source fingerprint evidence")
                continue
            domain = self.domain(candidate)
            if domain is not None:
                self.domains[id(candidate)] = domain
                groups[domain, candidate["root_id"], candidate["package_root"]].append(candidate)
        for index, ((domain, _, _), group) in enumerate(sorted(groups.items())):
            if index >= self.bounds.component_limit:
                self.metrics["omitted_candidates"] += len(group)
                self.gap("bounds", group[0]["candidate_id"], "component_limit: investigation omitted")
            else:
                self.root(group, domain)
        for candidate in candidates:
            purl = candidate.get("purl")
            if purl is None:
                continue
            claims = candidate["metadata"].setdefault("sbom_claims", {})
            observed = claims.get("purl", _unknown())
            parsed = _purl_parts(purl) if isinstance(purl, str) else None
            release = candidate["release"]
            eligible = (
                observed["status"] == "corroborated" and observed["value"] == purl
                and bool(observed["evidence_ids"])
                and set(observed["evidence_ids"]) <= self.evidence.keys()
                and candidate["identity"]["status"] == "corroborated"
                and parsed is not None
                and _normalized_name(parsed[1]) == _normalized_name(candidate["native_name"])
                and (parsed[2] is None or (
                    release["status"] != "conflicted" and
                    (release["status"] != "corroborated" or release["value"] == parsed[2])))
            )
            if not eligible:
                claims["purl"] = _merge(observed, [(purl, False, [])])
                if claims["purl"]["status"] == "corroborated":
                    claims["purl"]["status"] = "inferred"
                candidate.pop("purl")
                self.gap("unsupported_metadata", candidate["candidate_id"],
                         "unsubstantiated or inconsistent existing PURL retained only as a claim")
        self.discovery["evidence"] = [self.evidence[key] for key in sorted(self.evidence)]
        gaps = [self.gaps[key] for key in sorted(self.gaps)]
        self.discovery["gaps"] = list({canonical_json(item): item for item in [
            *self.discovery["gaps"], *gaps,
        ]}.values())
        for field, prefix in (("identity", "identities_"), ("release", "releases_")):
            for status in ("unknown", "inferred", "corroborated", "conflicted"):
                key = prefix + status
                if key in self.discovery["metrics"]:
                    count = sum(item[field]["status"] == status for item in candidates)
                    self.discovery["metrics"][key] = count
                    if key in self.discovery["coverage"]:
                        self.discovery["coverage"][key] = count
        return {"schema": INVESTIGATION_SCHEMA, "discovery": self.discovery,
                "findings": self.findings, "gaps": gaps, "metrics": self.metrics}


def investigate_native_metadata(
    discovery: DiscoveryResult, files: Sequence[NativeFile], *,
    read_file: Callable[[NativeFile, int], bytes], propose: Propose | None,
    bounds: NativeInferenceBounds,
) -> InvestigationResult:
    """Investigate each physical root once; callback retries and usage belong to transport.

    Catalog paths and target contents are data. Plans can select only exact, bounded catalog
    entries. Inferred proposals remain in ``metadata.sbom_claims`` and findings, never as an
    SPDX-eligible PURL or a promoted release. Reader custody/integrity errors propagate.
    """
    if not isinstance(bounds, NativeInferenceBounds) or not callable(read_file):
        raise ValueError("NativeInferenceBounds and read_file are required")
    if not isinstance(files, Sequence) or isinstance(files, (str, bytes)):
        raise ValueError("native files must be a finite sequence")
    return _Investigation(discovery, files, read_file=read_file, propose=propose, bounds=bounds).run()


__all__ = ["investigate_native_metadata"]
