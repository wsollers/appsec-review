"""Bounded document-to-source candidates and evidence-qualified adjudication.

Declarations are navigation evidence. This module never infers a missing guard from a
missing search result, nor treats a scanner report as an independently verified issue.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from appsec_review.indexing import document_interfaces as interfaces
from appsec_review.indexing.products_base import AcceptedShards
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.model import canonical_json
from appsec_review.retrieval.source_resolution import read_source_bytes
from appsec_review.review_packages import verify_review_packages
from appsec_review.storage import file_sha256


SCHEMA = "appsec-review/document-issue-ledger/1"
RULE = "appsec-review/document-source-mapping/1"
_ROUTE = re.compile(r"\b(?:app|router|server)\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
_NON_IMPLEMENTATION = re.compile(r"(^|/)(?:test|tests|spec|specs|docs|fixtures|__tests__)(/|$)|(?:\.test|\.spec)\.[^/]+$", re.I)
_PARAMETER = re.compile(r"(?<=/)(?::([A-Za-z_][\w]*)|\{([A-Za-z_][\w]*)\})")


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _route_key(value: str) -> str:
    return _PARAMETER.sub(lambda match: "{" + (match.group(1) or match.group(2)) + "}", value.rstrip("/") or "/")


def _source_lines(core: RetrievalCore, max_files: int, max_file_bytes: int) -> tuple[list[dict[str, Any]], list[str]]:
    view = AcceptedShards(core.run_root, core.manifest["indexes"], core.manifest["target_snapshot"])
    source = view.select("source", job="job_target_catalog")
    if not source:
        return [], ["accepted source index is unavailable"]
    rows = sorted(view.entities(source, ("source_file",)), key=lambda row: row.identity)
    gaps = []
    if len(rows) > max_files:
        gaps.append(f"source mapping truncated: {len(rows) - max_files} accepted file(s) exceeded bound")
        rows = rows[:max_files]
    result = []
    for row in rows:
        location = row.location
        if (not location or row.payload.get("language") is None or
                _NON_IMPLEMENTATION.search(location["path"])):
            continue
        path = (core.target_root / location["path"]).resolve()
        if core.target_root not in path.parents or path.is_symlink() or not path.is_file():
            raise ValueError("accepted source path is missing or escaped")
        if file_sha256(path) != location["file_sha256"]:
            raise ValueError("accepted source bytes changed after catalog publication")
        if path.stat().st_size > max_file_bytes:
            gaps.append(f"source mapping skipped oversized file: {location['path']}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            gaps.append(f"source mapping skipped undecodable file: {location['path']}")
            continue
        masked = _code_mask(text, _EXT_LANG.get(path.suffix.lower(), "")).splitlines()
        for number, line in enumerate(text.splitlines(), 1):
            for match in _ROUTE.finditer(line):
                if not masked[number - 1][match.start():match.start() + 1].strip():
                    continue
                result.append({"entity_id": row.identity, "shard_id": row.shard_id,
                               "shard_sha256": row.shard_sha256, "path": location["path"],
                               "file_sha256": location["file_sha256"], "line": number,
                               "column": match.start() + 1,
                               "method": match.group(1).upper(), "route": match.group(2)})
    return sorted(result, key=lambda item: (item["method"], item["route"], item["path"],
                                          item["line"], item["column"])), gaps


def adjudicate(candidate: Mapping[str, Any], *, core: RetrievalCore | None = None,
               red: Mapping[str, Any] | None = None,
               blue: Mapping[str, Any] | None = None,
               verifier: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """A narrow deterministic gate for independently reviewed source/tool evidence.

    A caller may propose a supported security claim, but all three reviews must cite
    the same resolving accepted evidence and blue must have no unresolved refutation.
    This gate intentionally does not manufacture reviews from document text.
    """
    evidence = candidate.get("proof_evidence", [])
    ids = {f"{item['entity_id']}:{item['line']}" for item in evidence
           if item.get("resolution") == "source_line"
           and item.get("file_sha256") and item.get("line", 0) > 0}
    reviews = (red, blue, verifier)
    supported = core is not None and bool(ids) and all(isinstance(item, Mapping) for item in reviews)
    if supported:
        view = AcceptedShards(core.run_root, core.manifest["indexes"], core.manifest["target_snapshot"])
        accepted = {row.identity: row for row in view.entities(
            view.select("source", job="job_target_catalog"), ("source_file",))}
        for item in evidence:
            row = accepted.get(item["entity_id"])
            if row is None or row.location is None or row.shard_sha256 != item["shard_sha256"] or (
                row.location["path"], row.location["file_sha256"]
            ) != (item["path"], item["file_sha256"]):
                raise ValueError("candidate source evidence does not resolve to accepted source")
            path = (core.target_root / item["path"]).resolve()
            if (core.target_root not in path.parents or path.is_symlink() or
                    file_sha256(path) != item["file_sha256"]):
                raise ValueError("candidate source evidence bytes changed")
            lines = path.read_text(encoding="utf-8").splitlines()
            if not 1 <= item["line"] <= len(lines):
                raise ValueError("candidate source line is outside accepted bytes")
            if not lines[item["line"] - 1].strip():
                raise ValueError("candidate proof cites an empty source line")
        supported = (red.get("decision") == "supported" and blue.get("decision") == "not_refuted"
                     and verifier.get("decision") == "independently_supported"
                     and all(set(item.get("evidence_refs", ())) & ids for item in reviews)
                     and not blue.get("unresolved_refutations")
                     and candidate.get("mapping_status") == "unique"
                     and all(any(item["entity_id"] == route_item["entity_id"] and
                                      route_item["line"] < item["line"] <= route_item["line"] + 100
                                      for route_item in candidate.get("implementation_evidence", ()))
                             for item in evidence)
                     and bool(red.get("security_claim")) and bool(verifier.get("security_claim"))
                     and red["security_claim"] == verifier["security_claim"])
    return {"state": "supported" if supported else "insufficient_evidence",
            "finding": ({"candidate_id": candidate["candidate_id"],
                         "claim": red["security_claim"], "route_or_boundary": candidate["subject"],
                         "evidence": [*candidate["implementation_evidence"], *evidence],
                         "coverage_gaps": candidate["coverage_gaps"],
                         "score_input": {"state": "supported", "claim": red["security_claim"],
                                         "evidence_refs": sorted(ids)}} if supported else None)}


def verify_document_issue_inputs(core: RetrievalCore, package_directory: Path, *, max_files: int,
                                 max_file_bytes: int) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    """Recheck every bounded input, including unmapped sources, before computing or reusing."""
    manifest = verify_review_packages(core, package_directory)
    source_routes, source_gaps = _source_lines(core, max_files, max_file_bytes)
    return manifest, source_routes, source_gaps


def analyze_document_hunts(core: RetrievalCore, package_directory: Path, *, max_files: int = 20000,
                           max_file_bytes: int = 1048576) -> dict[str, Any]:
    manifest, source_routes, source_gaps = verify_document_issue_inputs(
        core, package_directory, max_files=max_files, max_file_bytes=max_file_bytes)
    candidates = []
    for entry in manifest["packages"]:
        if entry["kind"] != "document_hunt":
            continue
        path = package_directory / f"{entry['package_id']}.json"
        package = json.loads(path.read_text(encoding="utf-8"))
        subject = package["scope"]["partition_key"]
        matches = []
        if subject.startswith("route:"):
            method, _, route = subject.removeprefix("route:").partition(" ")
            matches = [item for item in source_routes if item["method"] == method and
                       _route_key(item["route"]) == _route_key(route)]
        status = "unique" if len(matches) == 1 else "ambiguous" if matches else "unmapped"
        gaps = list(package["coverage_gaps"])
        gaps.extend({"gap_id": _hash([RULE, reason]), "producer": RULE,
                     "scope": "source-inventory", "state": "partial", "reason": reason}
                    for reason in source_gaps)
        # The package's pre-mapping gap is superseded only by a unique, verified link.
        if status == "unique":
            gaps = [gap for gap in gaps if not (gap["producer"] == "document_context" and
                     "has not been mapped" in gap["reason"])]
        else:
            gaps.append({"gap_id": _hash([subject, status]), "producer": RULE,
                         "scope": subject, "state": "partial",
                         "reason": f"implementation mapping {status}; no behavior conclusion"})
        evidence = [{"entity_id": item["entity_id"], "shard_id": item["shard_id"],
                     "shard_sha256": item["shard_sha256"], "path": item["path"],
                     "file_sha256": item["file_sha256"], "line": item["line"],
                     "resolution": "source_line"} for item in matches]
        candidate = {"candidate_id": _hash([package["package_id"], matches, RULE]),
                     "package_id": package["package_id"], "subject": subject,
                     "mapping_status": status, "implementation_evidence": evidence,
                     "proof_evidence": [],
                     "document_evidence": package["evidence"],
                     "proof_obligations": package["proof_obligations"],
                     "coverage_gaps": sorted(gaps, key=lambda item: item["gap_id"]),
                     "hypothesis": "verify declared route or boundary behavior in implementation"}
        decision = adjudicate(candidate, core=core)
        candidate["state"] = decision["state"]
        candidates.append(candidate)
    ledger = {"schema": SCHEMA, "rule": RULE, "run_id": core.run_id,
              "accepted_manifest_sha256": core.manifest_sha256,
              "review_package_manifest_sha256": file_sha256(package_directory / "manifest.json"),
              "target_snapshot": core.manifest["target_snapshot"], "candidates": candidates,
              "findings": [], "scoring_inputs": [],
              "counts": {"candidates": len(candidates), "supported": 0,
                         "unmapped": sum(item["mapping_status"] == "unmapped" for item in candidates),
                         "ambiguous": sum(item["mapping_status"] == "ambiguous" for item in candidates)}}
    ledger["content_sha256"] = _hash(ledger)
    return ledger


def verify_document_issue_ledger(core: RetrievalCore, path: Path) -> dict[str, Any]:
    from appsec_review.storage.shared import OBJECTS, safe_path
    path = safe_path(core.run_root, Path(path).relative_to(core.run_root).as_posix())
    content_addressed = path.parent == core.run_root / OBJECTS
    if not content_addressed and path.parent.parent != core.run_root / "data" / "document-issues":
        raise ValueError("document issue ledger escapes its run")
    if content_addressed and file_sha256(path) != path.name:
        raise ValueError("document issue ledger object hash mismatch")
    ledger = json.loads(path.read_text(encoding="utf-8"))
    if path.read_bytes() != canonical_json(ledger) + b"\n":
        raise ValueError("document issue ledger byte integrity mismatch")
    digest = ledger.pop("content_sha256", None)
    if (digest != _hash(ledger) or (not content_addressed and path.parent.name != digest) or
            ledger.get("run_id") != core.run_id or
            ledger.get("accepted_manifest_sha256") != core.manifest_sha256 or
            ledger.get("target_snapshot") != core.manifest["target_snapshot"]):
        raise ValueError("document issue ledger identity mismatch")
    ledger["content_sha256"] = digest
    if ledger["counts"]["candidates"] != len(ledger["candidates"]):
        raise ValueError("document issue ledger count mismatch")
    if ledger["findings"] or ledger["scoring_inputs"] or ledger["counts"]["supported"]:
        raise ValueError("unreviewed document issues cannot be published as findings")
    return ledger


DRIFT_SCHEMA = "appsec-review/document-drift-issue/1"
DRIFT_AUTHORITY = "provisional_navigation_lead"
DRIFT_KINDS = frozenset({
    "missing_auth_middleware",
    "undocumented_route",
    "unmapped_declared_operation",
    "parameter_constraint_drift",
    "role_or_scope_mismatch",
})

# Multi-language route handler patterns across all 9 smoke/target languages:
# JS/TS, Python, Java, Go, C#, Ruby, Rust, PHP, C/C++.
_MULTILANG_ROUTE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # JS/TS (Express / Fastify / Koa / Hono)
    ("javascript", re.compile(
        r"""(?:app|router|server|api)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"`](/[^'"`\s)]*)['"`]""",
        re.IGNORECASE,
    )),
    # Python (Flask / FastAPI / Starlette / Bottle)
    ("python", re.compile(
        r"""@\s*[A-Za-z0-9_.]+\s*\.\s*(route|get|post|put|patch|delete)\s*\(\s*['"](/[^'"\s)]*)['"](?:[^)]*?methods\s*=\s*\[([^\]]+)\])?""",
        re.IGNORECASE,
    )),
    # Python Django path('api/...', view)
    ("python", re.compile(
        r"""\b(?:re_)?path\s*\(\s*['"]/?([A-Za-z0-9_./<>:{}-]+)['"]\s*,""",
    )),
    # Java Spring (@GetMapping, @PostMapping, @PutMapping, @DeleteMapping, @PatchMapping, @RequestMapping)
    ("java", re.compile(
        r"""@\s*(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:(?:value|path)\s*=\s*)?"(/[^"\s)]*)"\s*(?:,[^)]*)?\)""",
    )),
    # Go (net/http HandleFunc, Gin/Echo/Fiber/Chi r.GET / r.POST / mux.HandleFunc)
    ("go", re.compile(
        r"""\b(?:HandleFunc|Handle)\s*\(\s*"(?:(GET|POST|PUT|PATCH|DELETE)\s+)?(/[^"\s)]*)"\s*,""",
    )),
    ("go", re.compile(
        r"""\.\s*(GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete)\s*\(\s*"(/[^"\s)]*)"\s*,""",
    )),
    # C# ASP.NET Core ([HttpGet("/...")], [HttpPost("...")], [Route("api/...")])
    ("csharp", re.compile(
        r"""\[\s*Http(Get|Post|Put|Patch|Delete)\s*(?:\(\s*"/?([^"\s)]*)"\s*\))?\s*\]""",
        re.IGNORECASE,
    )),
    # Ruby (Sinatra / Rails get '/path', post '/path')
    ("ruby", re.compile(
        r"""^\s*(get|post|put|patch|delete)\s+['"](/[^'"\s]+)['"]""",
        re.IGNORECASE | re.MULTILINE,
    )),
    # Rust (Actix-web #[get("/...")], Axum .route("/...", get(...)))
    ("rust", re.compile(
        r"""#\[\s*(get|post|put|patch|delete)\s*\(\s*"(/[^"\s)]*)"\s*\)\s*\]""",
        re.IGNORECASE,
    )),
    ("rust", re.compile(
        r"""\.route\s*\(\s*"(/[^"\s)]*)"\s*,\s*(get|post|put|patch|delete)\s*\(""",
        re.IGNORECASE,
    )),
    # PHP (Laravel / Slim Route::get('/...', ...))
    ("php", re.compile(
        r"""Route\s*::\s*(get|post|put|patch|delete)\s*\(\s*['"](/[^'"\s)]*)['"]""",
        re.IGNORECASE,
    )),
    # C / C++ (Crow / Pistache / Drogon / cpp-httplib)
    ("cpp", re.compile(
        r"""(?:CROW_ROUTE|CROW_BP_ROUTE)\s*\([^,]+,\s*"(/[^"\s)]*)"\s*\)(?:\s*\.\s*methods\s*\(\s*"([A-Z]+)"_method\s*\))?""",
    )),
    ("cpp", re.compile(
        r"""\b(?:svr|server|Routes)\s*(?:\.|::)\s*(Get|Post|Put|Patch|Delete)\s*\(\s*"(/[^"\s)]*)"\s*,""",
    )),
)

_AUTH_GUARD_RE = re.compile(
    r"""(?ix)
    \b(
        require_?auth|require_?role|require_?admin|is_?authenticated|login_required|
        jwt_required|token_required|verify_?token|verify_?jwt|authenticate|auth_middleware|
        PreAuthorize|RolesAllowed|Secured|Authorize|RequireAuthorization|
        Depends\s*\(\s*[A-Za-z0-9_]*(?:auth|user|admin|token|role)[A-Za-z0-9_]*|
        middleware\s*\(\s*['"](?:auth|sanctum|jwt|can:|role:)[^'"]*['"]|
        before_action\s+:authenticate|AuthGuard|BearerAuth
    )
    """
)
_ALLOW_ANON_RE = re.compile(r"(?i)\b(AllowAnonymous|PermitAll|public_endpoint|skip_before_action\s+:authenticate)\b")
_ROLE_TOKEN_RE = re.compile(r"(?i)\b(admin|moderator|staff|owner|write|read|superuser|operator|service)\b")
_PARAM_SEGMENT_RE = re.compile(r"(?:\{[^{}/]+\}|:[A-Za-z_][A-Za-z0-9_]*|<[^>/]+>)")

_EXT_LANG: dict[str, str] = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".py": "python",
    ".java": "java", ".kt": "java",
    ".go": "go",
    ".cs": "csharp",
    ".rb": "ruby",
    ".rs": "rust",
    ".php": "php",
    ".c": "cpp", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".h": "cpp", ".hpp": "cpp",
}


def normalize_route_template(route: str) -> str:
    cleaned = "/" + str(route or "/").strip().lstrip("/")
    if len(cleaned) > 1 and cleaned.endswith("/"):
        cleaned = cleaned.rstrip("/")
    return _PARAM_SEGMENT_RE.sub("{param}", cleaned)


def _code_mask(text: str, language: str, *, comments_only: bool = False) -> str:
    """Keep offsets while excluding comments and string contents from identifier matches."""
    single_quoted = r"'(?:\\.|[^'\\])*'"
    if language == "rust":
        # A Rust lifetime/label has no closing quote; character literals contain
        # exactly one scalar or escape, not everything up to the next lifetime.
        single_quoted = r"""'(?:\\(?:[nrt\\0'"]|x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\})|[^'\\\r\n])'"""
    pattern = single_quoted + r"""|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`|//[^\n]*|/\*[\s\S]*?\*/"""
    if language in {"python", "ruby"}:
        pattern += r"|#[^\n]*"

    def mask(match: re.Match[str]) -> str:
        value = match.group()
        if comments_only and not value.startswith(("//", "/*", "#")):
            return value
        return "".join("\n" if char == "\n" else " " for char in value)

    return re.sub(pattern, mask, text)


def _call_end(mask: str, start: int) -> int:
    opening = mask.find("(", start)
    if opening < 0:
        return start
    depth = 0
    for offset in range(opening, len(mask)):
        if mask[offset] == "(":
            depth += 1
        elif mask[offset] == ")":
            depth -= 1
            if not depth:
                return offset + 1
    return start


def _annotation_contexts(text: str, mask: str, language: str) -> dict[int, tuple[int, int]]:
    if language in {"python", "java"}:
        pattern = r"@\s*[A-Za-z_][\w.]*"
    elif language == "csharp":
        pattern = r"\["
    elif language == "rust":
        pattern = r"#\["
    else:
        return {}
    separators = _code_mask(text, language, comments_only=True)
    groups: list[list[tuple[int, int]]] = []
    previous_end = 0
    for match in re.finditer(pattern, mask):
        if match.start() < previous_end:
            continue
        end = match.end()
        if language in {"python", "java"}:
            if mask[end:].lstrip().startswith("("):
                end = max(end, _call_end(mask, match.start()))
        else:
            depth = 1
            while end < len(mask) and depth:
                depth += (mask[end] == "[") - (mask[end] == "]")
                end += 1
        if not groups or separators[previous_end:match.start()].strip():
            groups.append([])
        groups[-1].append((match.start(), end))
        previous_end = end
    return {start: (group[0][0], group[-1][1]) for group in groups for start, _ in group}


def _route_context(text: str, mask: str, start: int, end: int, language: str,
                   annotations: Mapping[int, tuple[int, int]]) -> str:
    # Only the registration expression or its contiguous annotation group is local.
    # Arbitrary nearby statements and other methods are not evidence of enforcement.
    if start in annotations:
        first, last = annotations[start]
        return text[first:last]
    if language == "ruby":
        last = text.find("\n", end)
        return text[start:len(text) if last < 0 else last]
    registration_end = max(end, _call_end(mask, start))
    last = registration_end
    if language == "php":
        while chain := re.match(r"\s*->\s*[A-Za-z_]\w*\s*\(", mask[last:]):
            chain_end = _call_end(mask, last + chain.start())
            if chain_end <= last:
                break
            last = chain_end
    local_end = registration_end
    callback_pattern = {
        "javascript": r"=>|\bfunction\b",
        "go": r"\bfunc\s*\(",
        "php": r"\b(?:function|fn)\s*\(",
    }.get(language)
    if callback_pattern:
        callback = re.search(callback_pattern, mask[end:registration_end])
        if callback:
            local_end = end + callback.start()
    return text[start:local_end] + text[registration_end:last]


def extract_multilang_route_handlers(path: str, text: str, *, source_id: str | None = None) -> list[dict[str, Any]]:
    """Extract route handler declarations and local auth guards across all 9 target languages."""
    suffix = Path(path).suffix.lower()
    file_lang = _EXT_LANG.get(suffix)
    nl = chr(10)
    mask = _code_mask(text, file_lang or "")
    annotations = _annotation_contexts(text, mask, file_lang or "")
    found: dict[tuple[str, str, int], dict[str, Any]] = {}

    csharp_prefix = ""
    if file_lang == "csharp":
        ctrl_route = re.search(r'\[\s*Route\s*\(\s*"([^"]+)"\s*\)\s*\]', text)
        if ctrl_route:
            raw_prefix = ctrl_route.group(1).replace("[controller]", Path(path).stem.lower().removesuffix("controller"))
            csharp_prefix = "/" + raw_prefix.strip("/")

    for pattern_lang, regex in _MULTILANG_ROUTE_PATTERNS:
        if file_lang is not None and not (
            file_lang == pattern_lang or (file_lang == "typescript" and pattern_lang == "javascript")
        ):
            continue
        for match in regex.finditer(text):
            if not mask[match.start():match.end()].strip():
                continue
            groups = match.groups()
            line_no = text.count(nl, 0, match.start()) + 1
            if pattern_lang == "rust" and regex.pattern.startswith(r"\.route"):
                raw_route, raw_method = groups[0], groups[1]
                methods = [raw_method.upper()]
            elif pattern_lang == "python" and len(groups) == 3:
                verb, raw_route, methods_list = groups
                if verb.lower() == "route":
                    parsed_methods = re.findall(r"[A-Za-z]+", methods_list or "")
                    methods = [m.upper() for m in parsed_methods] or ["GET"]
                else:
                    methods = [verb.upper()]
            elif pattern_lang == "python" and len(groups) == 1:
                raw_route = "/" + groups[0].lstrip("/")
                methods = ["ANY"]
            elif pattern_lang == "java":
                verb, raw_route = groups[0], groups[1]
                methods = ["ANY"] if verb.lower() == "request" else [verb.upper()]
            elif pattern_lang == "csharp":
                verb = groups[0].upper()
                sub = (groups[1] or "").strip("/")
                raw_route = f"{csharp_prefix}/{sub}".rstrip("/") if sub else (csharp_prefix or "/")
                if not raw_route.startswith("/"):
                    raw_route = "/" + raw_route
                methods = [verb]
            elif pattern_lang == "cpp" and "CROW_" in regex.pattern:
                raw_route = groups[0]
                methods = [(groups[1] or "GET").upper()]
            elif pattern_lang == "go" and len(groups) == 2 and groups[1] and groups[1].startswith("/"):
                raw_method, raw_route = groups[0], groups[1]
                methods = [(raw_method or "ANY").upper()]
            else:
                raw_method, raw_route = groups[0], groups[1]
                methods = [(raw_method or "GET").upper()]

            window_text = _route_context(text, mask, match.start(), match.end(), pattern_lang, annotations)
            window_mask = _code_mask(window_text, pattern_lang)
            guards = [m for m in _AUTH_GUARD_RE.finditer(window_text)
                      if window_mask[m.start():m.start() + 1].strip()
                      and (m.group(1).lower() not in {"secured", "authorize", "preauthorize", "rolesallowed"}
                           or pattern_lang in {"java", "csharp"})]
            anon_override = any(window_mask[m.start():m.start() + 1].strip()
                                for m in _ALLOW_ANON_RE.finditer(window_text))
            effective_guards = [] if anon_override else sorted({m.group(1) for m in guards})
            role_contexts = []
            for guard in guards:
                after = window_mask[guard.end():]
                if after.lstrip().startswith("("):
                    role_contexts.append(window_text[guard.start():_call_end(window_mask, guard.start())])
            observed_roles = sorted({m.group(1).lower() for context in role_contexts
                                     for m in _ROLE_TOKEN_RE.finditer(context)})

            for method in methods:
                key = (method, raw_route, match.start())
                if key in found:
                    continue
                found[key] = {
                    "method": method,
                    "route": raw_route,
                    "normalized_route": normalize_route_template(raw_route),
                    "path": path,
                    "line": line_no,
                    "column": match.start() - text.rfind(nl, 0, match.start()),
                    "language": file_lang or pattern_lang,
                    "source_id": source_id,
                    "observed_guards": effective_guards,
                    "observed_roles": observed_roles,
                    "allow_anonymous": anon_override,
                    "has_inline_guard": bool(effective_guards),
                    "window_excerpt": window_text[:400],
                }
    return [found[k] for k in sorted(found)]


def _parse_openapi_spec_operations(text: str, spec_path: str, spec_source_id: str | None,
                                   *, gaps: list[str] | None = None) -> list[dict[str, Any]]:
    """Use the catalog's bounded composition and security-alternative interpretation."""
    from yaml.nodes import MappingNode, SequenceNode

    root = interfaces._compose(text, max_depth=64, max_nodes=200_000)
    top = interfaces._mapping(root)
    child, scalar, mapping = interfaces._child, interfaces._scalar, interfaces._mapping
    version = scalar(child(root, "openapi") or child(root, "swagger"))
    if not (version.startswith("3.") or version == "2.0") or "paths" not in top:
        raise interfaces.DocumentParseError("expected OpenAPI 3 or Swagger 2 paths")
    pending = [root]
    while pending:
        node = pending.pop()
        if isinstance(node, MappingNode):
            values = mapping(node)
            if "$ref" in values and gaps is not None:
                gaps.append(f"unresolved specification reference: {scalar(values['$ref'][1])[:200]}")
            pending.extend(value for _, value in values.values())
        elif isinstance(node, SequenceNode):
            pending.extend(node.value)

    ops = []
    for route, (_, path) in sorted(mapping(child(root, "paths")).items()):
        if route.startswith("x-"):
            continue
        if not route.startswith("/"):
            raise interfaces.DocumentParseError("expected an absolute OpenAPI route")
        for method_key, (key, operation) in sorted(mapping(path).items()):
            method = method_key.upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}:
                continue
            fields = mapping(operation)
            security = fields["security"][1] if "security" in fields else child(root, "security")
            state, schemes = interfaces._security(security)
            declared_security = list(schemes)
            role_alternatives = []
            if security is not None:
                for entry in security.value:
                    roles = set()
                    for scheme, (_, scopes) in mapping(entry).items():
                        if not isinstance(scopes, SequenceNode):
                            raise interfaces.DocumentParseError("security scopes must be a sequence")
                        for scope in scopes.value:
                            value = scalar(scope)
                            declared_security.append(f"{scheme}:{value}")
                            roles.update(match.group(1).lower() for match in _ROLE_TOKEN_RE.finditer(value))
                    role_alternatives.append(roles)
            # Alternatives are OR, not a union of mandatory roles.
            required_roles = set.intersection(*role_alternatives) if role_alternatives else set()
            required_parameters = []
            for owner in (path, operation):
                parameters = child(owner, "parameters")
                if parameters is not None and not isinstance(parameters, SequenceNode):
                    raise interfaces.DocumentParseError("parameters must be a sequence")
                for parameter in parameters.value if parameters is not None else ():
                    if scalar(child(parameter, "required")) == "true":
                        required_parameters.append(scalar(child(parameter, "name")))
            ops.append({
                "spec_format": "openapi", "spec_path": spec_path, "spec_source_id": spec_source_id,
                "method": method, "route": route, "normalized_route": normalize_route_template(route),
                "declared_security": sorted(set(declared_security)), "declared_roles": sorted(required_roles),
                "requires_auth": state == "required", "public_explicit": state in {"none", "optional"},
                "required_parameters": sorted(set(required_parameters)),
                "start_line": key.start_mark.line + 1,
            })
    return ops


def _parse_graphql_or_proto_operations(doc_payload: Mapping[str, Any], text: str | None,
                                       *, gaps: list[str] | None = None) -> list[dict[str, Any]]:
    """Retain the canonical root type/service context; these are not HTTP handlers."""
    fmt = str(doc_payload.get("document_kind") or doc_payload.get("format") or "")
    spec_path = str(doc_payload.get("path") or "")
    spec_source_id = str(doc_payload.get("source_file_id") or "") or None
    operations, limitations = interfaces.idl_operations(text or "", fmt, max_depth=64, max_nodes=200_000)
    if gaps is not None:
        gaps.extend(limitations)
    return [{
        **operation, "spec_format": fmt, "spec_path": spec_path, "spec_source_id": spec_source_id,
        "normalized_route": operation["route"], "declared_security": [], "declared_roles": [],
        "requires_auth": False, "public_explicit": False, "required_parameters": [],
    } for operation in operations]


def analyze_api_spec_drift(
    core: RetrievalCore,
    *,
    max_files: int = 20000,
    max_file_bytes: int = 1048576,
) -> dict[str, Any]:
    """Compare accepted HTTP declarations, preserving non-HTTP mapping and read gaps."""
    if max_files < 1 or max_file_bytes < 1:
        raise ValueError("drift analysis bounds must be positive")
    gaps: list[str] = []
    view = AcceptedShards(core.run_root, core.manifest["indexes"], core.manifest["target_snapshot"])
    source_shards = view.select("source", job="job_target_catalog")
    doc_shards = view.select("documents", job="job_target_catalog")

    for shards, name in ((source_shards, "source"), (doc_shards, "documents")):
        if not shards:
            gaps.append(f"drift accepted {name} index is unavailable")
        for shard in shards:
            gaps.extend(str(gap) for gap in shard.get("gaps", ()))
        for coverage in view.coverage(shards):
            if coverage["gap"] or coverage["status"] != "complete":
                gaps.append(f"drift upstream {name} {coverage['area']}: "
                            f"{coverage['gap'] or coverage['status']}")

    source_rows = sorted(view.entities(source_shards, ("source_file",)), key=lambda row: row.identity)
    doc_rows = sorted(view.entities(doc_shards, ("document_record", "target_document")), key=lambda row: row.identity)
    documents: dict[tuple[str, str, str], list[Any]] = {}
    locations: dict[str, Mapping[str, Any]] = {}
    sources: dict[str, Any] = {}

    def admit(row: Any) -> tuple[str, str] | None:
        loc = row.location or {}
        path, digest = loc.get("path"), loc.get("file_sha256")
        if not path or not digest:
            gaps.append(f"drift input has no resolving path/hash: {row.identity}")
            return None
        if path in locations and locations[path]["file_sha256"] != digest:
            raise ValueError(f"accepted source/document hashes conflict: {path}")
        locations.setdefault(path, loc)
        return path, digest

    for row in source_rows:
        identity = admit(row)
        if identity:
            sources.setdefault(identity[0], row)
    for row in doc_rows:
        fmt = str(row.payload.get("document_kind") or row.payload.get("format") or "")
        if fmt not in {"openapi", "graphql", "protobuf", "asyncapi", "postman"}:
            continue
        identity = admit(row)
        if identity:
            documents.setdefault((*identity, fmt), []).append(row)

    # One shared, attempted-file budget: a failed read or document-only fallback
    # cannot reopen the budget, and a document/source alias is read just once.
    texts = {}
    for index, (path, location) in enumerate(sorted(locations.items())):
        if index >= max_files:
            gaps.append(f"drift file bound reached: {path}")
            continue
        try:
            raw = read_source_bytes(
                core.run_root, core.target_root, target_snapshot=core.manifest["target_snapshot"],
                path=path, sha256=location["file_sha256"], native=location.get("producer_location"),
                limit=max_file_bytes)
        except ValueError as exc:
            if "changed" in str(exc):
                raise ValueError(f"accepted source/document bytes changed after catalog publication: {path}") from exc
            gaps.append(f"drift input unavailable: {path}: {exc}")
            continue
        except OSError as exc:
            gaps.append(f"drift input unavailable: {path}: {type(exc).__name__}")
            continue
        try:
            texts[path] = raw.decode("utf-8-sig")
        except UnicodeError:
            gaps.append(f"drift input undecodable: {path}")

    all_handlers: list[dict[str, Any]] = []
    for path, row in sorted(sources.items()):
        if path in texts and Path(path).suffix.lower() in _EXT_LANG and not _NON_IMPLEMENTATION.search(path):
            all_handlers.extend(extract_multilang_route_handlers(path, texts[path], source_id=row.identity))
    if all_handlers:
        gaps.append("drift auth enforcement unresolved: literal registration/annotation heuristics do not "
                    "establish global middleware, handler behavior, mounts or effective role enforcement")
    for handler in all_handlers:
        if handler["method"] == "ANY":
            gaps.append(f"drift handler method coverage unresolved: {handler['path']}:{handler['line']}")

    spec_ops: list[dict[str, Any]] = []
    specs_parsed = 0
    for (path, digest, fmt), records in sorted(documents.items()):
        if path not in texts:
            continue
        limitations: list[str] = []
        try:
            if fmt == "openapi":
                extracted = _parse_openapi_spec_operations(texts[path], path, records[0].identity, gaps=limitations)
            elif fmt in {"graphql", "protobuf"}:
                extracted = _parse_graphql_or_proto_operations(
                    {"document_kind": fmt, "path": path, "source_file_id": records[0].identity},
                    texts[path], gaps=limitations)
                limitations.append(f"{fmt} implementation mapping is unsupported")
            else:
                gaps.append(f"drift unsupported specification format: {path}: {fmt}")
                continue
        except interfaces.DocumentParseError as exc:
            gaps.append(f"drift specification parse failed: {path}: {exc}")
            continue
        specs_parsed += 1
        if not extracted:
            limitations.append("no supported interface operation")
        gaps.extend(f"drift specification coverage: {path}: {reason}" for reason in limitations)
        operation_records = {}
        file_records = []
        for row in records:
            fields = row.payload.get("fields", {})
            operation_records.setdefault((fields.get("method"), fields.get("route")), row)
            if row.payload.get("subtype") != "operation":
                file_records.append(row)
        for operation in extracted:
            matching = operation_records.get((operation["method"], operation["route"]))
            if matching is None:
                # Whole-file fixture/legacy records still resolve the accepted file,
                # but an operation record must never be cited for a different operation.
                matching = file_records[0] if file_records else None
            if matching is None:
                gaps.append(f"drift operation has no accepted document record: {path}: "
                            f"{operation['method']} {operation['route']}")
                continue
            operation["spec_source_id"] = matching.identity
            operation["spec_file_sha256"] = digest
            spec_ops.append(operation)

    handlers_by_norm: dict[tuple[str, str], list[dict[str, Any]]] = {}
    handlers_by_route_any: dict[str, list[dict[str, Any]]] = {}
    for h in all_handlers:
        handlers_by_norm.setdefault((h["method"], h["normalized_route"]), []).append(h)
        handlers_by_route_any.setdefault(h["normalized_route"], []).append(h)

    mismatches: list[dict[str, Any]] = []
    matched_handler_keys: set[tuple[str, str, str, int, int]] = set()

    def handler_key(handler: Mapping[str, Any]) -> tuple[str, str, str, int, int]:
        return (handler["path"], handler["method"], handler["route"], handler["line"], handler["column"])

    for op in sorted(spec_ops, key=lambda item: (item["method"], item["normalized_route"], item["spec_path"])):
        if op["spec_format"] != "openapi":
            continue
        spec_identity = {"spec": op["spec_path"], "spec_source_id": op["spec_source_id"],
                         "spec_sha256": op["spec_file_sha256"]}
        candidates = list(handlers_by_norm.get((op["method"], op["normalized_route"]), ()))
        if not candidates:
            candidates = [h for h in handlers_by_route_any.get(op["normalized_route"], ()) if h["method"] == "ANY"]
        if not candidates:
            if op["spec_format"] == "openapi":
                seed = {**spec_identity, "kind": "unmapped_declared_operation",
                        "method": op["method"], "route": op["route"]}
                mismatches.append({
                    "drift_id": "drift:" + _hash(seed)[:24],
                    "drift_kind": "unmapped_declared_operation",
                    "method": op["method"],
                    "route": op["route"],
                    "spec_format": op["spec_format"],
                    "spec_path": op["spec_path"],
                    "spec_source_id": op["spec_source_id"],
                    "handler_path": None,
                    "handler_line": None,
                    "handler_language": None,
                    "handler_source_id": None,
                    "authority": DRIFT_AUTHORITY,
                    "auth_mismatch": False,
                    "declared_security": op["declared_security"],
                    "observed_guards": [],
                    "summary": f"Declared {op['method']} {op['route']} in {op['spec_path']} has no matching literal registration in the bounded source scan.",
                })
            continue

        for h in candidates:
            matched_handler_keys.add(handler_key(h))
            if op["requires_auth"] and (not h["observed_guards"] or h["allow_anonymous"]):
                seed = {**spec_identity, "kind": "missing_auth_middleware",
                        "method": op["method"], "route": op["route"], "handler": handler_key(h)}
                mismatches.append({
                    "drift_id": "drift:" + _hash(seed)[:24],
                    "drift_kind": "missing_auth_middleware",
                    "method": op["method"],
                    "route": op["route"],
                    "spec_format": op["spec_format"],
                    "spec_path": op["spec_path"],
                    "spec_source_id": op["spec_source_id"],
                    "handler_path": h["path"],
                    "handler_line": h["line"],
                    "handler_language": h["language"],
                    "handler_source_id": h["source_id"],
                    "authority": DRIFT_AUTHORITY,
                    "auth_mismatch": True,
                    "declared_security": op["declared_security"],
                    "observed_guards": h["observed_guards"],
                    "summary": (f"Spec {op['spec_path']} declares security {op['declared_security']} on "
                                f"{op['method']} {op['route']}, but no local guard was observed at "
                                f"{h['path']}:{h['line']}; effective enforcement is unresolved."),
                })
            elif op["requires_auth"] and op["declared_roles"] and h["observed_guards"] and not set(op["declared_roles"]).intersection(h["observed_roles"]):
                seed = {**spec_identity, "kind": "role_or_scope_mismatch",
                        "method": op["method"], "route": op["route"], "handler": handler_key(h)}
                mismatches.append({
                    "drift_id": "drift:" + _hash(seed)[:24],
                    "drift_kind": "role_or_scope_mismatch",
                    "method": op["method"],
                    "route": op["route"],
                    "spec_format": op["spec_format"],
                    "spec_path": op["spec_path"],
                    "spec_source_id": op["spec_source_id"],
                    "handler_path": h["path"],
                    "handler_line": h["line"],
                    "handler_language": h["language"],
                    "handler_source_id": h["source_id"],
                    "authority": DRIFT_AUTHORITY,
                    "auth_mismatch": True,
                    "declared_security": op["declared_security"],
                    "observed_guards": h["observed_guards"],
                    "summary": (f"Spec {op['spec_path']} requires role/scope {op['declared_roles']} on "
                                f"{op['method']} {op['route']}, which was not observed at {h['path']}:{h['line']}."),
                })

    if specs_parsed > 0 and any(op["spec_format"] == "openapi" for op in spec_ops):
        openapi_spec = next(op for op in spec_ops if op["spec_format"] == "openapi")
        for h in all_handlers:
            if handler_key(h) in matched_handler_keys or h["method"] == "ANY":
                continue
            seed = {"kind": "undocumented_route", "method": h["method"], "route": h["route"],
                    "handler": handler_key(h), "spec_source_id": openapi_spec["spec_source_id"]}
            mismatches.append({
                "drift_id": "drift:" + _hash(seed)[:24],
                "drift_kind": "undocumented_route",
                "method": h["method"],
                "route": h["route"],
                "spec_format": "openapi",
                "spec_path": openapi_spec["spec_path"],
                "spec_source_id": openapi_spec["spec_source_id"],
                "handler_path": h["path"],
                "handler_line": h["line"],
                "handler_language": h["language"],
                "handler_source_id": h["source_id"],
                "authority": DRIFT_AUTHORITY,
                "auth_mismatch": False,
                "declared_security": [],
                "observed_guards": h["observed_guards"],
                "summary": f"Literal registration {h['method']} {h['route']} at {h['path']}:{h['line']} was not found in the parsed OpenAPI operations; specification coverage may be incomplete.",
            })

    mismatches = list({item["drift_id"]: item for item in mismatches}.values())
    mismatches.sort(key=lambda item: (item["drift_kind"], item["method"], item["route"],
                                     str(item.get("handler_path") or ""), item["drift_id"]))
    return {
        "schema": DRIFT_SCHEMA,
        "run_id": core.run_id,
        "target_snapshot": str(core.manifest["target_snapshot"]),
        "accepted_manifest_sha256": core.manifest_sha256,
        "authority": DRIFT_AUTHORITY,
        "specs_parsed": specs_parsed,
        "handlers_scanned": len(all_handlers),
        "mismatches": mismatches,
        "gaps": sorted(set(gaps)),
        "telemetry": {
            "doc_drift.specs_parsed": specs_parsed,
            "doc_drift.handler_mismatches_found": len(mismatches),
        },
    }


def verify_document_drift_issues(core: RetrievalCore, path: Path) -> dict[str, Any]:
    """Verify that a published drift-issues artifact matches the run's accepted manifest and schema."""
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema") != DRIFT_SCHEMA:
        raise ValueError("document drift report schema mismatch")
    if report.get("accepted_manifest_sha256") != core.manifest_sha256:
        raise ValueError("document drift report manifest mismatch")
    if report.get("target_snapshot") != core.manifest["target_snapshot"]:
        raise ValueError("document drift report target snapshot mismatch")
    if report.get("authority") != DRIFT_AUTHORITY:
        raise ValueError("document drift report authority must be provisional_navigation_lead")
    return report
