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

from appsec_review.indexing.products_base import AcceptedShards
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.model import canonical_json
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
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeError:
            gaps.append(f"source mapping skipped undecodable file: {location['path']}")
            continue
        for number, line in enumerate(lines, 1):
            match = _ROUTE.search(line)
            if match:
                result.append({"entity_id": row.identity, "shard_id": row.shard_id,
                               "shard_sha256": row.shard_sha256, "path": location["path"],
                               "file_sha256": location["file_sha256"], "line": number,
                               "method": match.group(1).upper(), "route": match.group(2)})
    return sorted(result, key=lambda item: (item["method"], item["route"], item["path"], item["line"])), gaps


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


DRIFT_SCHEMA = "appsec-review/document-drift-issue/2"
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


def extract_multilang_route_handlers(path: str, text: str, *, source_id: str | None = None) -> list[dict[str, Any]]:
    """Extract route handler declarations and local auth guards across all 9 target languages."""
    suffix = Path(path).suffix.lower()
    file_lang = _EXT_LANG.get(suffix)
    nl = chr(10)
    lines = text.splitlines()
    file_level_guards = sorted({m.group(1) for m in _AUTH_GUARD_RE.finditer(nl.join(lines[:35]))})
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

            win_start = max(0, line_no - 6)
            win_end = min(len(lines), line_no + 12)
            window_text = nl.join(lines[win_start:win_end])
            local_guards = sorted({m.group(1) for m in _AUTH_GUARD_RE.finditer(window_text)})
            anon_override = bool(_ALLOW_ANON_RE.search(window_text))
            effective_guards = [] if anon_override else sorted(set(local_guards or file_level_guards))
            observed_roles = sorted({m.group(1).lower() for m in _ROLE_TOKEN_RE.finditer(window_text)})
            line_text = lines[line_no - 1] if 1 <= line_no <= len(lines) else ""

            for method in methods:
                key = (method, raw_route, line_no)
                if key in found:
                    continue
                found[key] = {
                    "method": method,
                    "route": raw_route,
                    "normalized_route": normalize_route_template(raw_route),
                    "path": path,
                    "line": line_no,
                    "language": file_lang or pattern_lang,
                    "source_id": source_id,
                    "observed_guards": effective_guards,
                    "observed_roles": observed_roles,
                    "allow_anonymous": anon_override,
                    "has_inline_guard": bool(effective_guards) or ("auth" in line_text.lower() and not anon_override),
                    "window_excerpt": window_text[:400],
                }
    return [found[k] for k in sorted(found)]


def _parse_openapi_spec_operations(text: str, spec_path: str, spec_source_id: str | None) -> list[dict[str, Any]]:
    """Deterministically extract declared routes, security schemes/scopes, and required parameters from OpenAPI JSON or YAML."""
    ops: list[dict[str, Any]] = []
    parsed: Any = None
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
    if parsed is None:
        try:
            import yaml  # type: ignore[import-untyped]
            parsed = yaml.safe_load(text)
        except Exception:
            parsed = None
    if not isinstance(parsed, Mapping):
        return ops
    if not any(k in parsed for k in ("openapi", "swagger", "paths")):
        return ops
    global_sec = parsed.get("security")
    paths_obj = parsed.get("paths")
    if not isinstance(paths_obj, Mapping):
        return ops
    for route, item in sorted(paths_obj.items(), key=lambda kv: str(kv[0])):
        if not isinstance(item, Mapping) or not str(route).startswith("/"):
            continue
        path_params = item.get("parameters") if isinstance(item.get("parameters"), list) else []
        for method_key, op in sorted(item.items(), key=lambda kv: str(kv[0])):
            method = str(method_key).upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                continue
            if not isinstance(op, Mapping):
                continue
            op_sec = op.get("security", global_sec)
            declared_security: list[str] = []
            declared_roles: list[str] = []
            public_explicit = op_sec == []
            if isinstance(op_sec, list):
                for entry in op_sec:
                    if isinstance(entry, Mapping):
                        for scheme, scopes in sorted(entry.items()):
                            declared_security.append(str(scheme))
                            if isinstance(scopes, list):
                                for sc in scopes:
                                    declared_security.append(f"{scheme}:{sc}")
                                    for role_m in _ROLE_TOKEN_RE.finditer(str(sc)):
                                        declared_roles.append(role_m.group(1).lower())
            req_params: list[str] = []
            for p in [*path_params, *(op.get("parameters") if isinstance(op.get("parameters"), list) else [])]:
                if isinstance(p, Mapping) and p.get("required") is True and p.get("name"):
                    req_params.append(str(p["name"]))
            ops.append({
                "spec_format": "openapi",
                "spec_path": spec_path,
                "spec_source_id": spec_source_id,
                "method": method,
                "route": str(route),
                "normalized_route": normalize_route_template(str(route)),
                "declared_security": sorted(set(declared_security)),
                "declared_roles": sorted(set(declared_roles)),
                "requires_auth": bool(declared_security) and not public_explicit,
                "public_explicit": public_explicit,
                "required_parameters": sorted(set(req_params)),
            })
    return ops


def _parse_graphql_or_proto_operations(doc_payload: Mapping[str, Any], text: str | None) -> list[dict[str, Any]]:
    """Extract GraphQL/Protobuf interface operations and @auth/@hasRole directives."""
    fmt = str(doc_payload.get("format") or "")
    spec_path = str(doc_payload.get("path") or "")
    spec_source_id = str(doc_payload.get("source_file_id") or "") or None
    ops: list[dict[str, Any]] = []
    if fmt == "graphql" and text:
        for m in re.finditer(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*:\s*[^\n#]+", text):
            field_name = m.group(1)
            if field_name in {"type", "input", "enum", "interface", "union", "scalar", "schema", "Query", "Mutation"}:
                continue
            line = m.group(0)
            directives = re.findall(r"@(auth|authenticated|hasRole|requires)\b(?:\s*\(([^)]*)\))?", line, flags=re.I)
            sec = [f"@{d[0]}" + (f"({d[1]})" if d[1] else "") for d in directives]
            roles = sorted({rm.group(1).lower() for d in directives for rm in _ROLE_TOKEN_RE.finditer(d[1] or "")})
            ops.append({
                "spec_format": "graphql",
                "spec_path": spec_path,
                "spec_source_id": spec_source_id,
                "method": "POST",
                "route": f"/graphql#{field_name}",
                "normalized_route": f"/graphql#{field_name}",
                "declared_security": sorted(set(sec)),
                "declared_roles": roles,
                "requires_auth": bool(sec),
                "public_explicit": False,
                "required_parameters": [],
            })
    elif fmt == "protobuf" and text:
        service_name = "Service"
        svc_m = re.search(r"\bservice\s+([A-Za-z_][A-Za-z0-9_]*)", text)
        if svc_m:
            service_name = svc_m.group(1)
        for m in re.finditer(r"\brpc\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
            rpc_name = m.group(1)
            ops.append({
                "spec_format": "protobuf",
                "spec_path": spec_path,
                "spec_source_id": spec_source_id,
                "method": "POST",
                "route": f"/{service_name}/{rpc_name}",
                "normalized_route": f"/{service_name}/{rpc_name}",
                "declared_security": [],
                "declared_roles": [],
                "requires_auth": False,
                "public_explicit": False,
                "required_parameters": [],
            })
    return ops


def analyze_api_spec_drift(
    core: RetrievalCore,
    *,
    max_files: int = 20000,
    max_file_bytes: int = 1048576,
) -> dict[str, Any]:
    """Compare structured API specs (OpenAPI, GraphQL, Protobuf) against 9-language route handlers."""
    gaps: list[str] = []
    view = AcceptedShards(core.run_root, core.manifest["indexes"], core.manifest["target_snapshot"])
    source_shards = view.select("source", job="job_target_catalog")
    doc_shards = view.select("documents", job="job_target_catalog")

    source_by_path: dict[str, tuple[str, str]] = {}
    all_handlers: list[dict[str, Any]] = []
    scanned_files = 0
    rows = sorted(view.entities(source_shards, ("source_file",)), key=lambda r: r.identity) if source_shards else []
    for row in rows:
        location = row.location or {}
        rel_path = str(location.get("path") or row.payload.get("path") or "")
        if not rel_path:
            continue
        if scanned_files >= max_files:
            gaps.append("drift_source_file_bound_reached")
            break
        full_path = (core.target_root / rel_path).resolve()
        if core.target_root not in full_path.parents or full_path.is_symlink() or not full_path.is_file():
            continue
        expected_sha = location.get("file_sha256")
        if expected_sha and file_sha256(full_path) != expected_sha:
            raise ValueError("accepted source bytes changed after catalog publication")
        if full_path.stat().st_size > max_file_bytes:
            gaps.append(f"drift mapping skipped oversized file: {rel_path}")
            continue
        try:
            text = full_path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        scanned_files += 1
        source_by_path[rel_path] = (row.identity, text)
        if not _NON_IMPLEMENTATION.search(rel_path):
            all_handlers.extend(extract_multilang_route_handlers(rel_path, text, source_id=row.identity))

    spec_ops: list[dict[str, Any]] = []
    specs_parsed = 0
    seen_spec_paths: set[str] = set()
    doc_rows = sorted(view.entities(doc_shards, ("document_record", "target_document")), key=lambda r: r.identity) if doc_shards else []
    for doc_row in doc_rows:
        dp = doc_row.payload
        loc = doc_row.location or {}
        fmt = str(dp.get("format") or "")
        doc_class = str(dp.get("document_class") or "")
        doc_path = str(loc.get("path") or dp.get("path") or "")
        if doc_class != "interface_specification" and fmt not in {"openapi", "asyncapi", "graphql", "protobuf", "postman"}:
            continue
        src_tuple = source_by_path.get(doc_path)
        raw_text = src_tuple[1] if src_tuple else None
        src_id = src_tuple[0] if src_tuple else (str(dp.get("source_file_id") or "") or doc_row.identity)
        if raw_text is None and doc_path:
            candidate_file = (core.target_root / doc_path).resolve()
            if core.target_root in candidate_file.parents and candidate_file.is_file() and not candidate_file.is_symlink():
                if candidate_file.stat().st_size <= max_file_bytes:
                    try:
                        raw_text = candidate_file.read_text(encoding="utf-8")
                    except UnicodeError:
                        raw_text = None
        extracted: list[dict[str, Any]] = []
        if fmt == "openapi" and raw_text:
            extracted = _parse_openapi_spec_operations(raw_text, doc_path, src_id)
        elif fmt in {"graphql", "protobuf"}:
            extracted = _parse_graphql_or_proto_operations(dp, raw_text)
        if not extracted and isinstance(dp.get("operations"), list):
            for op_str in dp["operations"]:
                parts = str(op_str).strip().split(None, 1)
                if len(parts) == 2 and parts[1].startswith("/"):
                    extracted.append({
                        "spec_format": fmt or "openapi",
                        "spec_path": doc_path,
                        "spec_source_id": src_id,
                        "method": parts[0].upper(),
                        "route": parts[1],
                        "normalized_route": normalize_route_template(parts[1]),
                        "declared_security": [],
                        "declared_roles": [],
                        "requires_auth": False,
                        "public_explicit": False,
                        "required_parameters": [],
                    })
        if doc_path and doc_path not in seen_spec_paths and (extracted or raw_text is not None):
            seen_spec_paths.add(doc_path)
            specs_parsed += 1
        spec_ops.extend(extracted)

    handlers_by_norm: dict[tuple[str, str], list[dict[str, Any]]] = {}
    handlers_by_route_any: dict[str, list[dict[str, Any]]] = {}
    for h in all_handlers:
        handlers_by_norm.setdefault((h["method"], h["normalized_route"]), []).append(h)
        handlers_by_route_any.setdefault(h["normalized_route"], []).append(h)

    mismatches: list[dict[str, Any]] = []
    matched_handler_keys: set[tuple[str, str, int]] = set()

    for op in sorted(spec_ops, key=lambda item: (item["method"], item["normalized_route"], item["spec_path"])):
        candidates = list(handlers_by_norm.get((op["method"], op["normalized_route"]), ()))
        if not candidates:
            candidates = [h for h in handlers_by_route_any.get(op["normalized_route"], ()) if h["method"] == "ANY"]
        if not candidates:
            if op["spec_format"] == "openapi":
                seed = {"kind": "unmapped_declared_operation", "method": op["method"], "route": op["route"], "spec": op["spec_path"]}
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
                    "summary": f"Declared {op['method']} {op['route']} in {op['spec_path']} has no matching route handler.",
                })
            continue

        for h in candidates:
            matched_handler_keys.add((h["path"], h["route"], h["line"]))
            if op["requires_auth"] and (not h["observed_guards"] or h["allow_anonymous"]):
                seed = {"kind": "missing_auth_middleware", "method": op["method"], "route": op["route"],
                        "handler": h["path"], "line": h["line"]}
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
                                f"{op['method']} {op['route']}, but handler at {h['path']}:{h['line']} lacks observed auth guard."),
                })
            elif op["declared_roles"] and h["observed_guards"] and not set(op["declared_roles"]).intersection(h["observed_roles"]):
                seed = {"kind": "role_or_scope_mismatch", "method": op["method"], "route": op["route"],
                        "handler": h["path"], "line": h["line"]}
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
            if (h["path"], h["route"], h["line"]) in matched_handler_keys:
                continue
            seed = {"kind": "undocumented_route", "method": h["method"], "route": h["route"],
                    "handler": h["path"], "line": h["line"]}
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
                "auth_mismatch": not bool(h["observed_guards"]),
                "declared_security": [],
                "observed_guards": h["observed_guards"],
                "summary": f"Route handler {h['method']} {h['route']} at {h['path']}:{h['line']} is undocumented in {openapi_spec['spec_path']}.",
            })

    mismatches.sort(key=lambda item: (item["drift_kind"], item["method"], item["route"], str(item.get("handler_path") or "")))
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
