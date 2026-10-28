"""Versioned proof questions for named source sites, not compliance certification.

Recognition is deliberately limited to Python AST sites: calls with visible SQL templates,
password-length comparisons in validation functions, and literal HTTP route decorators. It
neither executes target code nor establishes any predicate. Other languages, hidden query
builders, implicit policies and the rest of the catalog remain unresolved.

``subjects`` retains the assessment acceptance API (a list of IDs). Version 2 binds those IDs
to immutable file content, absolute site spans and run/component/build scope, rather than a
whole retrieval entity. Different accepted references to the same site can bind the same ID;
different sites in one reference cannot. Citation authenticity remains the resolver's job.
"""
from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
import textwrap
from typing import Any, Mapping, Sequence

from .standards import digest


VERSION = "owasp-proof-obligations/2"
_ASVS_COMMIT = "5cf9b032440be53ce345ab3c130fda46ba1ce7a2"
_MASVS_COMMIT = "8e133d09f4140518ed04cc254b18be9ff4990ffc"
_STATIC_LIMITS = (
    "A recognized site is a review question, never evidence that its invariant holds or fails.",
    "Bounded static source cannot establish runtime/deployment state, exploitability, absence of "
    "unseen alternate paths, component-wide safety or certification.",
    "Only the named site and its resolved context are in scope; unknown coverage is not clean.",
)


@dataclass(frozen=True, slots=True)
class Procedure:
    family: str
    version: str
    control: str
    control_text: str
    upstream_commit: str
    invariant: str
    recognizer: str
    subject_scope: str
    prerequisites: tuple[str, ...]
    support: str
    contradiction: str
    effective_control_questions: tuple[str, ...]
    satisfied: tuple[str, ...]
    not_satisfied: tuple[str, ...]
    cannot_verify: tuple[str, ...]
    static_limits: tuple[str, ...]
    required_categories: tuple[str, ...] = ("source",)
    evidence_mode: str = "static_source"
    procedure_version: str = VERSION


_UNKNOWN = (
    "Missing, truncated, redacted, ambiguous, declaration-only or non-resolving evidence cannot "
    "establish a decisive outcome.",
    "Unresolved prerequisites, effective controls or materially relevant alternate paths require "
    "cannot_verify, not an assumption of compliance or a failure inferred from absence.",
)
_AUTH_PREREQUISITES = (
    "Resolve the named route, its implemented operation and the consumers allowed to invoke it.",
    "Resolve the required permission policy, consumer identity and the service/client trust boundary.",
    "Resolve invoked guards, middleware and default policy before deciding whether access is permitted.",
)
_AUTH_QUESTIONS = (
    "Does a trusted middleware or service guard enforce the policy before the protected effect?",
    "Can alternate routes, method dispatch, direct service calls or policy defaults bypass that guard?",
    "Does the evidence show explicit authorization rather than only authentication, a route name "
    "or a client-supplied role?",
)
_AUTH_LIMITS = (
    "Literal Python route decorators identify entry-point candidates, not inherently protected operations.",
    "No object-level, tenant-wide, deployed-middleware or complete route-inventory claim is made.",
)

PROCEDURES = (
    Procedure(
        family="ASVS", version="5.0.0", control="V1.2.4",
        control_text="Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) "
        "use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL "
        "Injection and other database injection attacks. This is also relevant when writing stored procedures.",
        upstream_commit=_ASVS_COMMIT,
        invariant="The named database query site separates query structure from untrusted data.",
        recognizer="python_sql_call/1",
        subject_scope="One Python query/prepare call with a visible SQL template, not every query "
        "in the function, ORM, stored procedure or component.",
        prerequisites=(
            "Resolve the query API/driver semantics, query construction, parameters and their provenance.",
            "Establish which values an untrusted consumer can influence, including identifiers and fragments.",
            "Resolve helper construction, validation and the relevant alternate path to this exact call.",
        ),
        support="Resolved query construction and actual binding semantics separate structure from data, "
        "or establish a concrete bounded safe alternative.",
        contradiction="A resolved path inserts untrusted input into query structure without an effective "
        "binding, structural allowlist or other demonstrated protection.",
        effective_control_questions=(
            "Do parameters bind data at the driver boundary, rather than interpolate a string first?",
            "Do dynamic identifiers/fragments use a finite trusted mapping rather than purported data binding?",
            "Do upstream validation, ORM behavior, trusted-only provenance or stored-procedure internals "
            "contradict the proposed failure? Resolve them rather than infer their absence.",
        ),
        satisfied=(
            "Cited construction and driver semantics establish data binding for each untrusted value at "
            "the named site, or a demonstrated finite structural allowlist/safe ORM alternative.",
            "All material prerequisites and contradictory alternate constructions for this site are resolved.",
        ),
        not_satisfied=(
            "Cited source traces a concrete untrusted value into query structure at this call.",
            "The relevant effective-control and alternate-path evidence establishes that this path is "
            "not protected; concatenation or an API name alone is insufficient.",
        ),
        cannot_verify=_UNKNOWN + ("Opaque builders, unresolved variable queries or unknown driver "
                                 "semantics do not establish separation or injection.",),
        static_limits=("Recognition covers SQL-prefixed literal, f-string, concatenation, formatting "
                       "or one local assignment at selected Python call sites; it is not taint analysis.",
                       "Non-SQL query languages and implicit ORM construction are not recognized."),
    ),
    Procedure(
        family="ASVS", version="5.0.0", control="V6.2.1",
        control_text="Verify that user set passwords are at least 8 characters in length although "
        "a minimum of 15 characters is strongly recommended.",
        upstream_commit=_ASVS_COMMIT,
        invariant="The named user-set password validation site enforces at least eight characters.",
        recognizer="python_password_comparison/1",
        subject_scope="One password-length comparison in a named enrollment/change/reset/validation "
        "function, not all password acceptance paths.",
        prerequisites=(
            "Establish that the value is a user-set password, not a machine credential or test fixture.",
            "Resolve the comparison, length/counting semantics and rejecting/accepting branches.",
            "Resolve callers, upstream validators and active registration, reset and change-password "
            "paths relevant to this subject.",
        ),
        support="The implemented named acceptance path rejects user-set passwords shorter than eight characters.",
        contradiction="A concrete implemented path accepts a user-set password shorter than eight "
        "characters despite the relevant effective policy.",
        effective_control_questions=(
            "Does the check actually gate acceptance, including fall-through and error handling?",
            "Does upstream validation enforce a stronger minimum before this site can be reached?",
            "Can reset/change/import paths bypass the check? Are assertions disabled or configuration "
            "overrides relevant to the effective check?",
        ),
        satisfied=(
            "Cited control flow and effective length semantics reject every shorter-than-eight "
            "user-set password on the named path before acceptance.",
            "Material upstream policy and alternate paths for this site are resolved; fifteen is "
            "a recommendation, not the mandatory minimum for this control.",
        ),
        not_satisfied=(
            "Cited control flow demonstrates acceptance of a concrete user-set password length below eight.",
            "The cited caller/upstream policy does not reject that path; a low constant, omitted "
            "snippet or disabled assertion alone is not proof of acceptance.",
        ),
        cannot_verify=_UNKNOWN + ("A policy declaration, byte count of unknown encoding, unresolved "
                                 "configuration or unshown caller cannot establish the effective minimum.",),
        static_limits=("Only Python len(password/passwd), including named fields/subscripts, compared "
                       "with an integer in a recognized validation function is a candidate.",
                       "External identity providers, generated validators and deployment policy are unverified."),
    ),
    Procedure(
        family="ASVS", version="5.0.0", control="V8.2.1",
        control_text="Verify that the application ensures that function-level access is restricted "
        "to consumers with explicit permissions.",
        upstream_commit=_ASVS_COMMIT,
        invariant="The named function-level operation restricts access to explicitly permitted consumers.",
        recognizer="python_http_operation/1",
        subject_scope="One literal route and implemented function, conditionally subject to its "
        "resolved function-level permission policy.",
        prerequisites=_AUTH_PREREQUISITES,
        support="The operation and its invoked guards restrict function access to explicit permissions.",
        contradiction="A concrete path reaches the protected function without the required explicit permission.",
        effective_control_questions=_AUTH_QUESTIONS,
        satisfied=("Cited trusted control flow enforces the explicit permission policy before this "
                   "operation's protected effect on the named entry path.",
                   "Material middleware, policy defaults and alternate entry paths for the subject are resolved."),
        not_satisfied=("A cited path reaches the named protected function with a consumer that lacks "
                       "the required explicit permission.",
                       "Relevant upstream/service guards and alternate policy enforcement do not block "
                       "that path; missing checks in one excerpt are not proof."),
        cannot_verify=_UNKNOWN + ("An unresolved required permission or consumer identity cannot "
                                 "establish function-level access failure.",),
        static_limits=_AUTH_LIMITS,
    ),
    Procedure(
        family="ASVS", version="5.0.0", control="V8.3.1",
        control_text="Verify that the application enforces authorization rules at a trusted service "
        "layer and doesn't rely on controls that an untrusted consumer could manipulate, such as "
        "client-side JavaScript.",
        upstream_commit=_ASVS_COMMIT,
        invariant="The named operation's authorization rules are enforced at a trusted service layer, "
        "not solely by a manipulable consumer.",
        recognizer="python_http_operation/1",
        subject_scope="The trusted-service boundary for one literal route and implemented operation; "
        "distinct from V8.2.1's explicit function-permission requirement.",
        prerequisites=_AUTH_PREREQUISITES,
        support="Resolved service-side enforcement applies the operation's authorization rule "
        "independently of consumer-manipulable checks or decisions.",
        contradiction="A concrete path relies solely on a consumer-manipulable authorization decision "
        "and reaches the operation without trusted-service enforcement.",
        effective_control_questions=_AUTH_QUESTIONS,
        satisfied=("Cited trusted service code independently applies the resolved authorization rule "
                   "before the named protected effect.",
                   "Material middleware and alternate entry paths for this operation are resolved."),
        not_satisfied=("Cited control flow establishes a consumer-controlled decision reaching the "
                       "protected operation without effective trusted-service authorization.",
                       "Relevant middleware/service guards have been resolved; client-side code or "
                       "an absent local guard alone is insufficient."),
        cannot_verify=_UNKNOWN + ("A route decorator or guard declaration alone does not establish "
                                 "the trusted enforcement boundary.",),
        static_limits=_AUTH_LIMITS,
    ),
    Procedure(
        family="MASVS", version="2.1.0", control="MASVS-NETWORK-1",
        control_text="The app secures all network traffic according to the current best practices.",
        upstream_commit=_MASVS_COMMIT,
        invariant="The named mobile network connection protects traffic in the observed environment.",
        recognizer="unsupported_runtime_adapter/1",
        subject_scope="One environment-bound connection; this cannot establish the control's all-traffic scope.",
        prerequisites=("An authorized accepted runtime evidence adapter must bind an observed "
                       "connection to app build, endpoint, platform, environment and observation time.",
                       "Resolve applicable platform trust/transport configuration and supporting MASTG tests; "
                       "the crosswalk is test guidance, not proof."),
        support="Accepted environment-bound observations establish effective transport protection "
        "and endpoint verification for the named connection.",
        contradiction="Accepted environment-bound observations establish an unprotected or "
        "improperly verified connection despite relevant platform protections.",
        effective_control_questions=("Resolve platform transport policy, trust configuration, "
                                     "endpoint verification and alternate network paths.",),
        satisfied=("Reserved for accepted runtime observations plus effective configuration; "
                   "no supported adapter currently permits this outcome.",),
        not_satisfied=("Reserved for accepted runtime contradiction and effective-control analysis; "
                       "no supported adapter currently permits this outcome.",),
        cannot_verify=("Always cannot_verify: no accepted environment-bound runtime evidence adapter "
                       "is available. Static HTTPS/TLS strings and MASTG mappings are not runtime proof.",),
        static_limits=("Static source cannot establish negotiated transport, endpoint identity, "
                       "platform trust or protection of all network traffic.",),
        required_categories=("runtime_observation", "platform_configuration"),
        evidence_mode="dynamic_runtime",
    ),
)


def procedure_for(control: Mapping[str, Any]) -> Procedure | None:
    family = control.get("family", control.get("standard"))
    native = control.get("id", control.get("control_id"))
    return next((rule for rule in PROCEDURES if (rule.family, rule.version, rule.control)
                 == (family, control.get("version"), native)
                 and ("text" not in control or control["text"] == rule.control_text)), None)


_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_PASSWORD_FUNCTIONS = {
    "register", "register_user", "create_user", "signup", "sign_up", "reset_password",
    "change_password", "set_password", "validate_password",
}
_QUERY_METHODS = {"execute", "executemany", "executescript", "raw", "query", "prepare"}
_SQL_PREFIXES = {"SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "CREATE", "ALTER", "DROP",
                 "CALL", "EXEC", "EXPLAIN", "PRAGMA", "REPLACE"}
_HTTP_METHODS = {"route", "get", "post", "put", "patch", "delete", "head", "options"}


def _owner(node: ast.AST, parents: Mapping[ast.AST, ast.AST]) -> ast.AST | None:
    while node in parents:
        node = parents[node]
        if isinstance(node, (*_FUNCTIONS, ast.ClassDef, ast.Module)):
            return node
    return None


def _template(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(part.value for part in node.values
                       if isinstance(part, ast.Constant) and isinstance(part.value, str))
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _template(node.left)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"):
        return _template(node.func.value)
    return ""


def _sql_call(node: ast.AST, parents: Mapping[ast.AST, ast.AST]) -> bool:
    if (not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute)
            or node.func.attr not in _QUERY_METHODS or not node.args):
        return False
    query = node.args[0]
    if isinstance(query, ast.Name):
        owner = _owner(node, parents)
        assignments = [item for item in ast.walk(owner) if isinstance(item, ast.Assign)
                       and item.lineno < node.lineno and _owner(item, parents) is owner
                       and any(isinstance(target, ast.Name) and target.id == query.id
                               for target in item.targets)] if owner else []
        if not assignments:
            return False
        query = max(assignments, key=lambda item: (item.lineno, item.col_offset)).value
    words = _template(query).lstrip().split(None, 1)
    return bool(words and words[0].upper() in _SQL_PREFIXES)


def _password_value(node: ast.AST) -> bool:
    return (isinstance(node, ast.Name) and node.id in {"password", "passwd"}
            or isinstance(node, ast.Attribute) and node.attr in {"password", "passwd"}
            or isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant)
            and node.slice.value in ("password", "passwd"))


def _password_comparison(node: ast.AST, parents: Mapping[ast.AST, ast.AST]) -> bool:
    owner = _owner(node, parents)
    if (not isinstance(node, ast.Compare) or not isinstance(owner, _FUNCTIONS)
            or owner.name not in _PASSWORD_FUNCTIONS):
        return False
    operands = [node.left, *node.comparators]
    length = any(isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                 and value.func.id == "len" and len(value.args) == 1
                 and _password_value(value.args[0]) for value in operands)
    threshold = any(isinstance(value, ast.Constant) and type(value.value) is int for value in operands)
    parent = parents.get(node)
    return length and threshold and isinstance(parent, (ast.If, ast.Assert, ast.Return, ast.BoolOp))


def _route(node: ast.AST) -> str | None:
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in _HTTP_METHODS and node.args
            and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
            and node.args[0].value.startswith("/")):
        return f"{node.func.attr.upper()} {node.args[0].value}"
    return None


def _sites(rule: Procedure, evidence: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    if rule.evidence_mode != "static_source" or evidence.get("category") != "source":
        return [], []
    ref = evidence.get("reference")
    locator = ref.get("locator") if isinstance(ref, Mapping) else None
    excerpt = evidence.get("excerpt")
    if not isinstance(locator, Mapping) or locator.get("kind") != "source":
        return [], ["source evidence lacks a resolving source locator"]
    path, span, sha = locator.get("path"), locator.get("lines"), locator.get("file_sha256")
    if (not isinstance(path, str) or not path or not isinstance(sha, str) or len(sha) != 64
            or any(char not in "0123456789abcdef" for char in sha)
            or not isinstance(span, list) or len(span) != 2 or any(type(n) is not int for n in span)
            or not 1 <= span[0] <= span[1]
            or any(not ref.get(key) for key in ("run_id", "target_snapshot", "component_id", "source_identity"))):
        return [], ["source evidence has incomplete immutable file/span/scope identity"]
    if PurePosixPath(path.replace("\\", "/")).suffix != ".py":
        return [], [f"{path}: reviewed site recognition supports only Python source"]
    if (not isinstance(excerpt, str) or not excerpt or len(excerpt) > 16000
            or len(excerpt.splitlines()) != span[1] - span[0] + 1):
        return [], [f"{path}: excerpt does not resolve its complete bounded line span"]
    if (evidence.get("truncated") or evidence.get("redaction", {}).get("applied")
            or any("ambiguous" in str(gap).lower() for gap in evidence.get("limitations", ()))):
        return [], [f"{path}: truncated, redacted or ambiguous source cannot define a proof subject"]
    source = textwrap.dedent(excerpt)
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return [], [f"{path}: excerpt is not a complete parseable Python source unit"]
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    original_lines, parsed_lines = excerpt.splitlines(), source.splitlines()

    def location(node: ast.AST) -> tuple[dict[str, Any], str]:
        start, end = node.lineno - 1, node.end_lineno - 1
        left = node.col_offset + len(original_lines[start].encode()) - len(parsed_lines[start].encode())
        right = node.end_col_offset + len(original_lines[end].encode()) - len(parsed_lines[end].encode())
        pieces = [line.encode() for line in original_lines[start:end + 1]]
        pieces[-1] = pieces[-1][:right]
        pieces[0] = pieces[0][left:]
        return ({"kind": "source", "path": path, "file_sha256": sha,
                 "source_custody": locator.get("source_custody"),
                 "lines": [span[0] + start, span[0] + end], "columns": [left, right],
                 "column_unit": "zero-based UTF-8 bytes; end exclusive"},
                digest({"source": b"\n".join(pieces).decode("utf-8")}))

    candidates: list[tuple[ast.AST, str, ast.AST | None]] = []
    for node in ast.walk(tree):
        if rule.recognizer == "python_sql_call/1" and _sql_call(node, parents):
            candidates.append((node, f"query call {ast.unparse(node.func)}", None))
        elif rule.recognizer == "python_password_comparison/1" and _password_comparison(node, parents):
            candidates.append((node, f"password comparison in {_owner(node, parents).name}", None))
        elif rule.recognizer == "python_http_operation/1" and isinstance(node, _FUNCTIONS):
            for decorator in node.decorator_list:
                route = _route(decorator)
                if route:
                    candidates.append((decorator, f"{route} -> {node.name}", node))
    result = []
    for node, name, operation in sorted(candidates, key=lambda item: (item[0].lineno, item[0].col_offset)):
        site_locator, content = location(node)
        identity = {"rule_version": VERSION, "procedure": asdict(rule),
                    "scope": {key: ref.get(key) for key in (
                        "run_id", "target_snapshot", "component_id", "build_unit_id", "environment")},
                    "locator": site_locator, "content_sha256": content}
        if operation is not None:
            operation_locator, operation_content = location(operation)
            identity["operation"] = {"locator": operation_locator, "content_sha256": operation_content}
        result.append({"subject_id": digest(identity), "name": name,
                       "source_identity": ref["source_identity"],
                       **{key: identity[key] for key in ("scope", "locator", "content_sha256")},
                       **({"operation": identity["operation"]} if operation is not None else {})})
    return result, [str(gap) for gap in evidence.get("limitations", ())]


def subjects(rule: Procedure, evidence: Mapping[str, Any]) -> list[str]:
    """Return site-bound IDs only; recognition is not an evidence-acceptance decision."""
    return [site["subject_id"] for site in _sites(rule, evidence)[0]]


def instantiate(control: Mapping[str, Any], row: Mapping[str, Any],
                evidence: Sequence[Mapping[str, Any]], *, max_subjects: int) -> list[dict[str, Any]]:
    if type(max_subjects) is not int or max_subjects < 1:
        raise ValueError("max_subjects must be a positive integer")
    rule = procedure_for(control)
    common = {
        "rule_version": VERSION, "control_identity": row["control_identity"],
        "component_id": row["component_id"], "scope": {
            "run_id": row.get("run_id"), "target_snapshot": row.get("target_id"),
            "component_id": row["component_id"], "build_scope": "per-source-site; no deployment claim",
        },
        "static_limits": list(_STATIC_LIMITS),
    }
    if rule is not None:
        common.update({"procedure": asdict(rule), "invariant": rule.invariant,
                       "prerequisites": list(rule.prerequisites), "subject_scope": rule.subject_scope,
                       "criteria": {key: list(getattr(rule, key)) for key in (
                           "satisfied", "not_satisfied", "cannot_verify")},
                       "evidence_mode": rule.evidence_mode,
                       "required_categories": list(rule.required_categories),
                       "static_limits": [*_STATIC_LIMITS, *rule.static_limits]})
    else:
        common.update({"evidence_mode": row["evidence_mode"], "required_categories": []})

    def unresolved(suffix: str, reason: str, **extra: Any) -> dict[str, Any]:
        return {**common, "obligation_id": f"{row['row_id']}:{suffix}", "subject_id": None,
                "supported": False, "material": True, "reason": reason, "evidence_ids": [],
                "required_outcome": "cannot_verify", **extra}

    if rule is None:
        return [unresolved("unsupported", "no reviewed versioned proof procedure for this exact control/text")]
    if row["control_identity"] != f"{rule.family}:{rule.version}:{rule.control}":
        return [unresolved("unsupported", "row identity does not match the reviewed standard/control/version")]
    if rule.evidence_mode != "static_source":
        return [unresolved("unsupported", "no accepted environment-bound runtime evidence adapter is available")]
    candidates: dict[str, tuple[dict[str, Any], list[str]]] = {}
    gaps = []
    for item in evidence:
        ref = item.get("reference", {})
        if not isinstance(ref, Mapping):
            gaps.append("evidence lacks a resolving typed reference")
            continue
        if item.get("category") == "source" and any(
                row.get(row_key) is not None and row[row_key] != ref.get(ref_key)
                for row_key, ref_key in (("run_id", "run_id"), ("target_id", "target_snapshot"),
                                         ("component_id", "component_id"))):
            gaps.append("source evidence is outside the row's run/target/component scope")
            continue
        sites, limitations = _sites(rule, item)
        gaps.extend(limitations)
        for site in sites:
            if not isinstance(item.get("evidence_id"), str) or not item["evidence_id"]:
                gaps.append("source site lacks an accepted evidence identity")
                continue
            current, evidence_ids = candidates.setdefault(site["subject_id"], (site, []))
            if (site["source_identity"], site["name"]) < (current["source_identity"], current["name"]):
                candidates[site["subject_id"]] = (site, evidence_ids)
            if item["evidence_id"] not in evidence_ids:
                evidence_ids.append(item["evidence_id"])
    ordered = sorted(candidates.values(), key=lambda value: (
        value[0]["locator"]["path"], *value[0]["locator"]["lines"],
        *value[0]["locator"]["columns"], value[0]["subject_id"]))
    obligations = []
    for site, evidence_ids in ordered[:max_subjects]:
        obligations.append({
            **common, "obligation_id": f"{row['row_id']}:{site['subject_id']}",
            "subject_id": site["subject_id"], "subject": site, "supported": True, "material": True,
            "scope": {**common["scope"], **site["scope"], "source": site["locator"]},
            "evidence_ids": sorted(evidence_ids),
            "insufficient": "Recognition does not decide the outcome. Apply all versioned criteria "
                            "and resolve effective controls and material alternate paths.",
        })
    omitted = ordered[max_subjects:]
    if omitted:
        gaps.append(f"{len(omitted)} subjects omitted by max_subjects_per_control")
    if not ordered:
        gaps.append("no resolving subject/evidence for this bounded procedure")
    if gaps:
        obligations.append(unresolved("coverage", "; ".join(sorted(set(gaps))),
                                      omitted_subject_count=len(omitted),
                                      omitted_subject_ids=[site["subject_id"]
                                                           for site, _ in omitted[:max_subjects]],
                                      omitted_ids_truncated=len(omitted) > max_subjects))
    return obligations
