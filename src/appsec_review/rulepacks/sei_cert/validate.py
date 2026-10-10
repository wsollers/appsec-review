"""Static validation of the SEI CERT rule pack.

Validation needs no engine. It rejects duplicate rule IDs, unknown or unmapped CERT identifiers,
missing or mismatched official URLs, unsupported languages, invalid severity and confidence
values, non-portable or autofix rule syntax, malformed YAML, rules without positive and negative
fixtures, fixtures that do not resolve, mappings that claim full support for a tested subset,
unexplained engine-specific expectations, unsafe paths, and files the content lock does not name.
"""

from __future__ import annotations

from collections import defaultdict
import re
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from .fixtures import EXCEPTION_PREFIX, UNMODELED_EXCEPTION_PREFIX, Expectation, parse_expectations
from .pack import PACK_ROOT, REPOSITORY_ROOT, Pack, PackError, load_pack, safe_relative, verify_lock

STATUSES = ("SUPPORTED", "PARTIAL", "UNSUPPORTED_SEMANTIC", "UNSUPPORTED_LANGUAGE",
            "DUPLICATE_EXISTING_RULE", "REQUIRES_DATAFLOW", "REQUIRES_COMPILER_OR_IR",
            "REQUIRES_CODEQL", "REQUIRES_MANUAL_REVIEW")
IMPLEMENTED_STATUSES = ("SUPPORTED", "PARTIAL")
ANALYSIS_CLASSES = ("construct-use", "local-syntactic", "type-semantic", "intraprocedural-dataflow",
                    "interprocedural-dataflow", "concurrency-semantic", "build-or-whole-program",
                    "design-or-manual")
EXCEPTION_HANDLING = ("excluded-by-rule", "reported-for-review", "outside-implemented-subset",
                      "not-implemented")
CONFIDENCE = ("HIGH", "MEDIUM", "LOW")
SEVERITY = ("ERROR", "WARNING", "INFO")
PRECISION = ("high", "medium", "low")
FIXTURE_SUFFIXES = {"c": {".c", ".h"}, "cpp": {".cpp", ".cc", ".cxx", ".hpp", ".hh"}, "java": {".java"}}
RULE_ID = re.compile(r"^appsec-review\.sei-cert\.(?P<lang>c|cpp|java)\.(?P<cert>[a-z]{3}\d{2}-(?:c|cpp|j))\.[a-z0-9]+(?:-[a-z0-9]+)*$")
REQUIRED_METADATA = ("pack", "cert", "cert_standard", "source_language", "cert_url", "cwe", "confidence",
                     "precision", "coverage", "technology", "min_engine_versions",
                     "implementation_notes", "license")
REQUIRED_MAPPING = ("key", "id", "language", "category", "title", "source", "summary",
                    "noncompliant_concept", "compliant_concept", "cwe", "analysis_class", "status",
                    "confidence", "exceptions", "false_positive_risks", "false_negative_risks",
                    "implementation", "delegation")
DETECTION_KEYS = ("pattern", "patterns", "pattern-either", "pattern-regex", "pattern-sinks")
POSITIVE_CASES = ("positive", "variant")
NEGATIVE_CASES = ("negative", "safe-alternative")


def _walk_operators(node: Any, allowed: set[str], where: str, errors: list[str]) -> None:
    if isinstance(node, Mapping):
        for key, value in node.items():
            if key in ("metavariable", "regex", "pattern") and not isinstance(value, (Mapping, list)):
                continue
            if key not in allowed and key not in ("metavariable-regex", "metavariable-pattern",
                                                   "metavariable", "regex"):
                errors.append(f"{where}: operator {key!r} is outside the portable Semgrep/OpenGrep subset")
            _walk_operators(value, allowed, where, errors)
    elif isinstance(node, list):
        for item in node:
            _walk_operators(item, allowed, where, errors)


def _check_rule_syntax(pack: Pack, errors: list[str]) -> None:
    portable = pack.manifest.get("portable_syntax", {})
    rule_keys = set(portable.get("rule_keys", ()))
    forbidden = set(portable.get("forbidden_keys", ()))
    operators = set(portable.get("operators", ()))
    for rule in pack.rules:
        where = f"{rule.file}:{rule.rule_id}"
        keys = set(rule.document)
        for key in sorted(keys & forbidden):
            errors.append(f"{where}: key {key!r} is not allowed (autofix or non-portable engine feature)")
        for key in sorted(keys - rule_keys - forbidden):
            errors.append(f"{where}: unknown rule key {key!r}")
        if not keys & set(DETECTION_KEYS):
            errors.append(f"{where}: rule has no detection pattern")
        mode = rule.document.get("mode", "search")
        if mode not in portable.get("modes", ()):
            errors.append(f"{where}: mode {mode!r} is not portable")
        if mode == "taint" and not {"pattern-sources", "pattern-sinks"} <= keys:
            errors.append(f"{where}: taint rules need sources and sinks")
        for key in ("pattern", "patterns", "pattern-either", "pattern-sources", "pattern-sinks",
                    "pattern-sanitizers"):
            if key in rule.document:
                _walk_operators(rule.document[key], operators | {"pattern-sources", "pattern-sinks"},
                                where, errors)


def _check_rules(pack: Pack, errors: list[str]) -> None:
    manifest = pack.manifest
    expected_files = sorted(p.relative_to(pack.root).as_posix() for p in (pack.root / "rules").rglob("*")
                            if p.is_file())
    if sorted(manifest.get("rule_files", [])) != expected_files:
        errors.append("pack.json rule_files does not list exactly the files under rules/")
    for relative in expected_files:
        if not relative.endswith(".yml"):
            errors.append(f"{relative}: rule files must use the .yml extension")
    seen: dict[str, str] = {}
    index_by_id = {entry["id"]: entry for entry in pack.index.get("entries", [])}
    entries = pack.entries_by_id
    engines = {name: spec["version"] for name, spec in manifest.get("engines", {}).items()}
    for rule in pack.rules:
        where = f"{rule.file}:{rule.rule_id}"
        if rule.rule_id in seen:
            errors.append(f"duplicate rule id {rule.rule_id} in {seen[rule.rule_id]} and {rule.file}")
        seen[rule.rule_id] = rule.file
        match = RULE_ID.match(rule.rule_id)
        if match is None:
            errors.append(f"{where}: id does not follow appsec-review.sei-cert.<language>.<cert>.<variant>")
            continue
        meta = rule.metadata
        for field in REQUIRED_METADATA:
            if field not in meta:
                errors.append(f"{where}: metadata.{field} is required")
        cert = meta.get("cert")
        if not isinstance(cert, str) or cert not in index_by_id:
            errors.append(f"{where}: unknown CERT identifier {cert!r}")
            continue
        if cert not in entries:
            errors.append(f"{where}: CERT identifier {cert} has no mapping entry")
            continue
        source = index_by_id[cert]
        standard = source["language"]
        if match.group("cert") != cert.lower():
            errors.append(f"{where}: id names {match.group('cert')} but metadata.cert is {cert}")
        if rule.file != f"rules/{standard}/{cert.lower()}.yml":
            errors.append(f"{where}: rules for {cert} belong in rules/{standard}/{cert.lower()}.yml")
        if meta.get("cert_standard") != standard:
            errors.append(f"{where}: cert_standard must be {standard}")
        languages = rule.document.get("languages")
        allowed_languages = set(manifest["standards"].get(standard, {}).get("engine_languages", ()))
        if not isinstance(languages, list) or not languages or not set(languages) <= allowed_languages:
            errors.append(f"{where}: languages {languages!r} are not supported for the {standard} standard")
        elif languages != [match.group("lang")] or meta.get("source_language") != match.group("lang"):
            errors.append(f"{where}: languages, source_language, and the id language segment must agree")
        if standard == "c" and match.group("lang") == "cpp" and not source.get("applies_to_cpp"):
            errors.append(f"{where}: the CERT C++ standard does not list {cert} as applying to C++")
        if meta.get("cert_url") != source["url"]:
            errors.append(f"{where}: cert_url does not match the official URL {source['url']}")
        cwe = meta.get("cwe")
        if not isinstance(cwe, list) or not set(cwe) <= set(source["cwe"]):
            errors.append(f"{where}: cwe must be a subset of the CWE identifiers on the official page")
        supplemental = meta.get("supplemental_cwe", [])
        if not isinstance(supplemental, list) or set(supplemental) & set(source["cwe"]):
            errors.append(f"{where}: supplemental_cwe must list only identifiers absent from the official page")
        if rule.document.get("severity") not in SEVERITY:
            errors.append(f"{where}: invalid severity {rule.document.get('severity')!r}")
        if meta.get("confidence") not in CONFIDENCE:
            errors.append(f"{where}: invalid confidence {meta.get('confidence')!r}")
        if meta.get("precision") not in PRECISION:
            errors.append(f"{where}: invalid precision {meta.get('precision')!r}")
        if meta.get("pack") != manifest.get("id") or meta.get("license") != manifest.get("license"):
            errors.append(f"{where}: pack and license metadata must match pack.json")
        if dict(meta.get("min_engine_versions", {})) != engines:
            errors.append(f"{where}: min_engine_versions must equal the pinned engines {engines}")
        mapping_status = entries[cert][0].get("status")
        if meta.get("coverage") != mapping_status:
            errors.append(f"{where}: coverage {meta.get('coverage')!r} differs from the mapping status {mapping_status!r}")
        message = rule.document.get("message")
        if not isinstance(message, str) or not message.strip() or cert not in message:
            errors.append(f"{where}: message must be non-empty and name {cert}")
        if not isinstance(meta.get("technology"), list) or not meta.get("technology"):
            errors.append(f"{where}: technology constraints are required")
        for extra in meta.get("cert_also", []):
            if extra not in entries:
                errors.append(f"{where}: cert_also names unknown CERT identifier {extra}")
            elif extra not in index_by_id or not (index_by_id[extra]["language"] == standard or
                                                   index_by_id[extra].get("applies_to_cpp")):
                errors.append(f"{where}: cert_also {extra} does not apply to {standard} code")


def _check_index(pack: Pack, errors: list[str]) -> None:
    index = pack.index
    if index.get("schema") != "appsec-review/sei-cert-source-index/1":
        errors.append("source index: unexpected schema")
    if not re.fullmatch(r"[0-9a-f]{40}", str(index.get("source_revision", ""))):
        errors.append("source index: source_revision must be a full commit hash")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(index.get("retrieved", ""))):
        errors.append("source index: retrieved must be an ISO date")
    keys: set[str] = set()
    root = str(index.get("site_root", ""))
    for entry in index.get("entries", []):
        if entry["key"] in keys:
            errors.append(f"source index: duplicate key {entry['key']}")
        keys.add(entry["key"])
        if not str(entry.get("url", "")).startswith(root + "/") or not root.startswith("https://"):
            errors.append(f"source index: {entry['key']} has no official URL")
        if not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("source_sha256", ""))):
            errors.append(f"source index: {entry['key']} lacks a source page hash")


def _check_mappings(pack: Pack, errors: list[str]) -> None:
    index = {entry["key"]: entry for entry in pack.index.get("entries", [])}
    covered: set[str] = set()
    rules_by_cert: dict[str, set[str]] = defaultdict(set)
    files_by_cert: dict[str, set[str]] = defaultdict(set)
    for rule in pack.rules:
        for cert in rule.certs:
            rules_by_cert[cert].add(rule.rule_id)
            files_by_cert[cert].add(rule.file)
    all_rule_ids = {rule.rule_id for rule in pack.rules}
    for language, document in pack.mappings.items():
        if document.get("schema") != "appsec-review/sei-cert-mapping/1" or document.get("language") != language:
            errors.append(f"mappings/{language}.json: unexpected schema or language")
        for entry in document.get("rules", []):
            key = entry.get("key")
            where = f"mappings/{language}.json:{key}"
            for field in REQUIRED_MAPPING:
                if field not in entry:
                    errors.append(f"{where}: {field} is required")
            if key not in index:
                errors.append(f"{where}: unknown CERT identifier")
                continue
            if key in covered:
                errors.append(f"{where}: duplicate mapping entry")
            covered.add(key)
            source = index[key]
            if entry.get("language") != source["language"] or source["language"] != language:
                errors.append(f"{where}: language does not match the official standard")
            if entry.get("id") != source["id"] or entry.get("title") != source["title"]:
                errors.append(f"{where}: identifier or title differs from the official source")
            src = entry.get("source", {})
            expected = {"url": source["url"], "retrieved": pack.index.get("retrieved"),
                        "revision": pack.index.get("source_revision"), "path": source["source_path"],
                        "sha256": source["source_sha256"]}
            for field, value in expected.items():
                if src.get(field) != value:
                    errors.append(f"{where}: source.{field} must be {value!r}")
            if entry.get("cwe") != source["cwe"]:
                errors.append(f"{where}: cwe must equal the official CWE identifiers")
            status = entry.get("status")
            if status not in STATUSES:
                errors.append(f"{where}: invalid status {status!r}")
            if entry.get("analysis_class") not in ANALYSIS_CLASSES:
                errors.append(f"{where}: invalid analysis_class {entry.get('analysis_class')!r}")
            if entry.get("confidence") not in CONFIDENCE:
                errors.append(f"{where}: invalid confidence {entry.get('confidence')!r}")
            if not entry.get("summary") or not entry.get("false_negative_risks") or not entry.get("false_positive_risks"):
                errors.append(f"{where}: summary and false-positive/false-negative risks are required")
            exception_ids = [item.get("id") for item in entry.get("exceptions", [])]
            if exception_ids != source["exceptions"]:
                errors.append(f"{where}: exceptions must list exactly the official exceptions {source['exceptions']}")
            for item in entry.get("exceptions", []):
                if item.get("handling") not in EXCEPTION_HANDLING or not item.get("summary"):
                    errors.append(f"{where}: exception {item.get('id')} needs a summary and valid handling")
            delegation = entry.get("delegation") or {}
            if not delegation.get("recommended"):
                errors.append(f"{where}: an alternative analyzer recommendation is required")
            for query in delegation.get("codeql_queries", []):
                try:
                    if not safe_relative(REPOSITORY_ROOT, query).is_file():
                        errors.append(f"{where}: CodeQL query {query} does not exist")
                except PackError as exc:
                    errors.append(f"{where}: {exc}")
            implementation = entry.get("implementation")
            cert = source["id"]
            if status in IMPLEMENTED_STATUSES:
                if not isinstance(implementation, Mapping):
                    errors.append(f"{where}: {status} requires an implementation")
                    continue
                for engine in ("semgrep", "opengrep"):
                    listed = set(implementation.get(f"{engine}_rule_ids", []))
                    if listed != rules_by_cert.get(cert, set()):
                        errors.append(f"{where}: {engine}_rule_ids must equal the pack rules mapped to {cert}")
                    if not listed <= all_rule_ids:
                        errors.append(f"{where}: {engine}_rule_ids names unknown rules")
                if set(implementation.get("rule_files", [])) != files_by_cert.get(cert, set()):
                    errors.append(f"{where}: rule_files must list the files that implement {cert}")
                engines = {name: spec["version"] for name, spec in pack.manifest["engines"].items()}
                if implementation.get("engine_versions") != engines:
                    errors.append(f"{where}: engine_versions must equal the pinned engines")
                if entry.get("analysis_class") is None:
                    errors.append(f"{where}: analysis_class is required")
                for item in entry.get("exceptions", []):
                    if item.get("handling") == "not-implemented":
                        errors.append(f"{where}: implemented rules must state how exception {item['id']} is handled")
            else:
                if implementation is not None:
                    errors.append(f"{where}: status {status} must not carry an implementation")
                if rules_by_cert.get(cert):
                    errors.append(f"{where}: {cert} has pack rules but status {status}")
                if status == "DUPLICATE_EXISTING_RULE" and not entry.get("duplicate_of"):
                    errors.append(f"{where}: DUPLICATE_EXISTING_RULE must name duplicate_of")
    for key in sorted(set(index) - covered):
        errors.append(f"official CERT rule {key} has no mapping status")


def _fixture_language(path: str) -> str | None:
    suffix = PurePosixPath(path).suffix
    for language, suffixes in FIXTURE_SUFFIXES.items():
        if suffix in suffixes:
            return language
    return None


def collect_expectations(pack: Pack) -> list[Expectation]:
    root = pack.root / pack.manifest.get("fixture_root", "fixtures")
    expectations: list[Expectation] = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            relative = path.relative_to(pack.root).as_posix()
            expectations.extend(parse_expectations(path, relative))
    return expectations


def _check_fixtures(pack: Pack, errors: list[str]) -> list[Expectation]:
    root = pack.root / pack.manifest.get("fixture_root", "fixtures")
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(pack.root).as_posix()
        if path.is_symlink():
            errors.append(f"{relative}: fixtures must not be symlinks")
        elif path.is_file() and _fixture_language(relative) is None:
            errors.append(f"{relative}: unsupported fixture type")
    try:
        expectations = collect_expectations(pack)
    except (ValueError, OSError) as exc:
        errors.append(f"fixtures: {exc}")
        return []
    rules = pack.rules_by_id()
    entries = pack.entries_by_id
    by_rule: dict[str, list[Expectation]] = defaultdict(list)
    for item in expectations:
        where = f"{item.path}:{item.annotation_line}"
        rule = rules.get(item.rule_id)
        if rule is None:
            errors.append(f"{where}: annotation names unknown rule {item.rule_id}")
            continue
        language = _fixture_language(item.path)
        if language not in rule.document.get("languages", []):
            errors.append(f"{where}: fixture language {language} is not a language of {item.rule_id}")
        if item.engines is not None:
            unknown = set(item.engines) - set(pack.manifest["engines"])
            if unknown:
                errors.append(f"{where}: unknown engines {sorted(unknown)}")
            explained = any(item.path in str(note)
                            for cert in rule.certs for entry in entries.get(cert, [])
                            for note in (entry.get("implementation") or {}).get("engine_differences", []))
            if not explained:
                errors.append(f"{where}: engine-specific expectation is not explained in the mapping engine_differences")
        exception = item.exception_id
        if exception is not None:
            official = {ex["id"] for cert in rule.certs for entry in entries.get(cert, [])
                        for ex in entry.get("exceptions", [])}
            if exception not in official:
                errors.append(f"{where}: {exception} is not an official exception of {', '.join(rule.certs)}")
        by_rule[item.rule_id].append(item)
    for rule in pack.rules:
        kinds = {item.kind for item in by_rule.get(rule.rule_id, [])}
        missing = []
        if not kinds & {"positive"}:
            missing.append("positive")
        if not kinds & {"variant"}:
            missing.append("syntactic variant")
        if not kinds & set(NEGATIVE_CASES):
            missing.append("negative")
        if "near-miss" not in kinds:
            missing.append("near-miss negative")
        if missing:
            errors.append(f"{rule.rule_id}: missing fixture cases: {', '.join(missing)}")
    for cert_entries in entries.values():
        for entry in cert_entries:
            implementation = entry.get("implementation")
            if not isinstance(implementation, Mapping):
                continue
            rule_ids = set(implementation.get("semgrep_rule_ids", []))
            cert_items = [item for rule_id in rule_ids for item in by_rule.get(rule_id, [])]
            listed = set(implementation.get("fixtures", []))
            referenced = {item.path for item in cert_items}
            if listed != referenced:
                errors.append(f"{entry['key']}: implementation.fixtures must equal the fixtures that annotate its rules")
            for path in listed:
                try:
                    if not safe_relative(pack.root, path).is_file():
                        errors.append(f"{entry['key']}: fixture {path} does not resolve")
                except PackError as exc:
                    errors.append(f"{entry['key']}: {exc}")
            for exception in entry.get("exceptions", []):
                handling = exception.get("handling")
                kinds = {item.kind for item in cert_items}
                if handling == "excluded-by-rule" and f"{EXCEPTION_PREFIX}{exception['id']}" not in kinds:
                    errors.append(f"{entry['key']}: {exception['id']} is excluded but has no exception fixture")
                if handling == "reported-for-review" and f"{UNMODELED_EXCEPTION_PREFIX}{exception['id']}" not in kinds:
                    errors.append(f"{entry['key']}: {exception['id']} is reported for review but has no unmodeled-exception fixture")
            if entry.get("status") == "SUPPORTED":
                if any(item.kind == "known-false-negative" for item in cert_items):
                    errors.append(f"{entry['key']}: SUPPORTED conflicts with a known-false-negative fixture; use PARTIAL")
                if any(ex.get("handling") == "outside-implemented-subset" for ex in entry.get("exceptions", [])):
                    errors.append(f"{entry['key']}: SUPPORTED conflicts with exceptions outside the implemented subset")
                for rule_id in rule_ids:
                    rule_kinds = {item.kind for item in by_rule.get(rule_id, [])}
                    if not {"positive", "variant", "near-miss"} <= rule_kinds:
                        errors.append(f"{entry['key']}: SUPPORTED requires complete case coverage for {rule_id}")
    return expectations


def _check_multivuln(pack: Pack, errors: list[str]) -> None:
    document = pack.multivuln
    if document.get("schema") != "appsec-review/sei-cert-multivuln-expectations/1":
        errors.append("multivuln.json: unexpected schema")
    target = document.get("target", {})
    if not re.fullmatch(r"[0-9a-f]{40}", str(target.get("commit", ""))):
        errors.append("multivuln.json: target commit must be a full hash")
    rules = pack.rules_by_id()
    entries = pack.entries_by_id
    seen: set[tuple[str, str, int]] = set()
    for section in ("expected_findings", "expected_exclusions", "known_false_negatives"):
        for item in document.get(section, []):
            path = PurePosixPath(str(item.get("path", "")))
            if path.is_absolute() or ".." in path.parts or not path.parts:
                errors.append(f"multivuln.json: unsafe path {item.get('path')!r}")
            if not isinstance(item.get("line"), int) or item["line"] < 1:
                errors.append(f"multivuln.json: {item.get('path')} needs a positive line")
            cert = item.get("cert")
            if cert not in entries:
                errors.append(f"multivuln.json: unknown CERT identifier {cert!r}")
                continue
            if section == "expected_findings":
                rule = rules.get(item.get("rule_id", ""))
                if rule is None or cert not in rule.certs:
                    errors.append(f"multivuln.json: {item.get('rule_id')} is unknown or not mapped to {cert}")
                key = (item.get("rule_id"), str(path), item.get("line"))
                if key in seen:
                    errors.append(f"multivuln.json: duplicate expectation {key}")
                seen.add(key)
            if section == "known_false_negatives":
                status = entries[cert][0].get("status")
                if status == "SUPPORTED":
                    errors.append(f"multivuln.json: {cert} is SUPPORTED but has a known false negative")
                if item.get("delegated_to") not in STATUSES:
                    errors.append(f"multivuln.json: known false negative for {cert} needs a delegation status")


def validate(root: Path = PACK_ROOT) -> list[str]:
    """Return every validation error; an empty list means the pack is internally consistent."""
    errors: list[str] = []
    try:
        pack = load_pack(root)
    except (PackError, KeyError, OSError) as exc:
        return [str(exc)]
    statuses = tuple(pack.manifest.get("statuses", ()))
    if statuses != STATUSES:
        errors.append("pack.json statuses differ from the validator's status vocabulary")
    if tuple(pack.manifest.get("severity_values", ())) != SEVERITY or \
            tuple(pack.manifest.get("confidence_values", ())) != CONFIDENCE or \
            tuple(pack.manifest.get("precision_values", ())) != PRECISION:
        errors.append("pack.json value vocabularies differ from the validator")
    _check_index(pack, errors)
    _check_rule_syntax(pack, errors)
    _check_rules(pack, errors)
    _check_mappings(pack, errors)
    _check_fixtures(pack, errors)
    _check_multivuln(pack, errors)
    errors.extend(verify_lock(root))
    return errors


def implemented_certs(pack: Pack) -> Iterable[Mapping[str, Any]]:
    return (entry for entry in pack.entries.values() if entry.get("status") in IMPLEMENTED_STATUSES)
